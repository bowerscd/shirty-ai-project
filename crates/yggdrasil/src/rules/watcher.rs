//! Hot-reload watcher for `/etc/yggdrasil/conf.d/*.toml`.
//!
//! The watcher emits a stream of [`RuleUpdate`]s on every successful reload.
//! Reloads are triggered by:
//!
//! 1. `notify` filesystem events on the rules directory (debounced via
//!    `notify-debouncer-mini`, default 300 ms).
//! 2. Explicit [`RuleWatcher::force_reload`] calls, e.g. from the
//!    `yggdrasilctl local rules reload` admin command.
//!
//! On startup the watcher emits one [`RuleUpdate`] immediately with the
//! initial set treated as "everything added", so downstream consumers don't
//! need a separate bootstrap path.
//!
//! Reload failures (bad TOML, permission errors, cross-file validation
//! failures) are logged at `warn` and the previous good set is retained — a
//! single malformed file must never take down the running proxy.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebouncedEvent, Debouncer};
use tokio::sync::{mpsc, watch};

use ratatoskr::rule::{RuleDiff, RuleSet};

use super::load_dir;

/// A single reload event delivered to the supervisor.
#[derive(Debug, Clone)]
pub struct RuleUpdate {
    /// The new, validated set as currently on disk.
    pub set: RuleSet,
    /// What changed since the previous successful update.
    pub diff: RuleDiff,
}

/// Hot-reload watcher handle. Drop to stop watching.
pub struct RuleWatcher {
    updates_rx: mpsc::Receiver<RuleUpdate>,
    reload_tx: mpsc::Sender<()>,
    /// Monotonic counter ticking on every reload-attempt completion
    /// regardless of outcome (successful reload, no-op reload, parse
    /// error). Lets `RulesReload` over UDS block until the worker has
    /// drained the trigger and either applied a new set or established
    /// that none was needed.
    reload_completion_rx: watch::Receiver<u64>,
    dir: PathBuf,
    // Order matters: the debouncer holds the notify watcher which feeds the
    // std::sync::mpsc bridge; dropping it closes the bridge, which closes the
    // reload channel, which lets the worker task exit cleanly.
    _debouncer: Debouncer<notify::RecommendedWatcher>,
    _bridge: std::thread::JoinHandle<()>,
    _worker: tokio::task::JoinHandle<()>,
}

impl RuleWatcher {
    /// Spawn the watcher. Performs an initial successful [`load_dir`] before
    /// returning, so callers can assume the first [`RuleWatcher::recv`] will
    /// resolve to a valid update.
    pub fn spawn(dir: impl Into<PathBuf>, debounce: Duration) -> Result<Self> {
        let dir: PathBuf = dir.into();

        // Initial load — propagate parse/validation errors so the daemon
        // refuses to start with a broken rules directory rather than running
        // with an empty set.
        let initial =
            load_dir(&dir).with_context(|| format!("initial rule load from {}", dir.display()))?;

        // Bounded so multiple rapid events collapse to a single pending reload.
        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(1);
        let (updates_tx, updates_rx) = mpsc::channel::<RuleUpdate>(8);
        // Bumps after each reload-attempt iteration regardless of
        // outcome. Consumers that need to block until a reload
        // request has been processed (e.g. `RulesReload` over UDS)
        // borrow_and_update + force_reload + .changed() this watch.
        let (reload_completion_tx, reload_completion_rx) = watch::channel::<u64>(0);

        // notify → std mpsc → tokio mpsc bridge.
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<NotifyResult>();
        let mut debouncer =
            new_debouncer(debounce, notify_tx).context("failed to construct notify debouncer")?;
        debouncer
            .watcher()
            .watch(&dir, RecursiveMode::NonRecursive)
            .with_context(|| format!("failed to watch {}", dir.display()))?;

        let bridge_reload_tx = reload_tx.clone();
        let bridge_dir = dir.clone();
        let bridge = std::thread::Builder::new()
            .name("rule-watch-bridge".into())
            .spawn(move || bridge_notify_events(notify_rx, bridge_reload_tx, bridge_dir))
            .context("failed to spawn watcher bridge thread")?;

        let worker_dir = dir.clone();
        let worker = tokio::spawn(async move {
            // Emit the initial state eagerly so consumers don't need a separate
            // bootstrap path.
            let init = RuleUpdate {
                diff: initial.as_initial_diff(),
                set: initial.clone(),
            };
            if updates_tx.send(init).await.is_err() {
                tracing::debug!("rule update receiver dropped before initial emit");
                return;
            }

            let mut current = initial;
            let mut completion_gen: u64 = 0;
            while let Some(()) = reload_rx.recv().await {
                match load_dir(&worker_dir) {
                    Ok(next) => {
                        let diff = current.diff(&next);
                        if diff.is_noop() {
                            tracing::trace!(
                                dir = %worker_dir.display(),
                                "rule reload: no semantic change"
                            );
                            // Still bump the completion counter so
                            // RPC waiters unblock on no-op reloads.
                            completion_gen = completion_gen.wrapping_add(1);
                            let _ = reload_completion_tx.send(completion_gen);
                            continue;
                        }
                        tracing::info!(
                            dir = %worker_dir.display(),
                            added = diff.added.len(),
                            removed = diff.removed.len(),
                            changed = diff.changed.len(),
                            unchanged = diff.unchanged.len(),
                            "rule set reloaded"
                        );
                        current = next.clone();
                        if updates_tx
                            .send(RuleUpdate { set: next, diff })
                            .await
                            .is_err()
                        {
                            tracing::debug!("rule update receiver dropped; watcher exiting");
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            dir = %worker_dir.display(),
                            "rule reload failed; keeping previous set"
                        );
                    }
                }
                // Bump after every attempt (success or failure) so
                // RPC waiters unblock on validation errors too.
                completion_gen = completion_gen.wrapping_add(1);
                let _ = reload_completion_tx.send(completion_gen);
            }
        });

        Ok(Self {
            updates_rx,
            reload_tx,
            reload_completion_rx,
            dir,
            _debouncer: debouncer,
            _bridge: bridge,
            _worker: worker,
        })
    }

    /// Receive the next [`RuleUpdate`]. Returns `None` when the watcher's
    /// internal channels are closed (e.g. the worker has exited).
    pub async fn recv(&mut self) -> Option<RuleUpdate> {
        self.updates_rx.recv().await
    }

    /// Request a reload now. Coalesces silently if one is already pending.
    pub fn force_reload(&self) {
        let _ = self.reload_tx.try_send(());
    }

    /// Clone-friendly trigger that callers outside this struct can use to
    /// request a reload (e.g. `yggdrasilctl rules reload`). Safe to share
    /// across threads.
    pub fn reload_trigger(&self) -> ReloadTrigger {
        ReloadTrigger {
            tx: self.reload_tx.clone(),
            completion_rx: self.reload_completion_rx.clone(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Lightweight, cheap-to-clone handle for requesting rule reloads from
/// other subsystems (e.g. the UDS control surface).
#[derive(Debug, Clone)]
pub struct ReloadTrigger {
    tx: mpsc::Sender<()>,
    /// Receiver for the watcher's reload-completion counter. Bumps once
    /// per drained reload attempt regardless of outcome (successful
    /// apply, no-op, parse error). Lets callers `block_on_reload` to
    /// wait for the worker to drain a triggered reload before returning
    /// to the operator.
    completion_rx: watch::Receiver<u64>,
}

impl ReloadTrigger {
    pub fn force_reload(&self) {
        let _ = self.tx.try_send(());
    }

    /// Trigger a reload and block until the worker drains it (success,
    /// no-op, or load error). Returns the post-reload completion
    /// counter, or `Err` on timeout.
    ///
    /// The wait is bounded so a stuck worker (e.g. blocked on a
    /// pathological `load_dir`) cannot hang the control socket. The
    /// caller is responsible for any subsequent supervisor-swap wait
    /// — this only confirms the watcher itself processed the trigger.
    pub async fn force_reload_and_wait(
        &self,
        timeout: Duration,
    ) -> Result<u64, tokio::time::error::Elapsed> {
        let mut rx = self.completion_rx.clone();
        // Mark the current value as already seen so .changed() fires on
        // the next bump, not on a stale value.
        rx.borrow_and_update();
        self.force_reload();
        tokio::time::timeout(timeout, rx.changed())
            .await
            .map(|_changed| *rx.borrow())
    }
}

type NotifyResult = Result<Vec<DebouncedEvent>, notify::Error>;

fn bridge_notify_events(
    rx: std::sync::mpsc::Receiver<NotifyResult>,
    reload_tx: mpsc::Sender<()>,
    dir: PathBuf,
) {
    while let Ok(batch) = rx.recv() {
        match batch {
            Ok(events) if !events.is_empty() => {
                tracing::trace!(
                    dir = %dir.display(),
                    events = events.len(),
                    "rules dir change"
                );
            }
            Ok(_) => continue, // empty batch — debouncer occasionally emits
            Err(e) => {
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "notify error; will still attempt reload"
                );
            }
        }
        if reload_tx.try_send(()).is_err() {
            // Either a reload is already pending (Full — fine, coalesced) or
            // the worker has exited (Closed — we're done).
            match reload_tx.capacity() {
                0 => continue, // Full path
                _ => break,    // Closed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write_file(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write fixture");
    }

    /// Wait up to `timeout` for the next [`RuleUpdate`], failing the test
    /// with a clear message on timeout instead of hanging.
    async fn next_update(w: &mut RuleWatcher, timeout: Duration, ctx: &str) -> RuleUpdate {
        tokio::time::timeout(timeout, w.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {ctx}"))
            .unwrap_or_else(|| panic!("watcher closed unexpectedly while waiting for {ctx}"))
    }

    #[tokio::test]
    async fn initial_update_for_empty_directory() {
        let d = tempfile::tempdir().unwrap();
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let init = next_update(&mut w, Duration::from_secs(2), "initial").await;
        assert!(init.set.is_empty());
        assert!(init.diff.is_noop());
    }

    #[tokio::test]
    async fn initial_update_includes_preexisting_files() {
        let d = tempfile::tempdir().unwrap();
        write_file(
            d.path(),
            "a.toml",
            r#"[[rule]]
            name = "a"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 1
            "#,
        );
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let init = next_update(&mut w, Duration::from_secs(2), "initial").await;
        assert_eq!(init.set.len(), 1);
        assert_eq!(init.diff.added.len(), 1);
        assert_eq!(init.diff.added[0].name, "a");
    }

    #[tokio::test]
    async fn detects_added_file() {
        let d = tempfile::tempdir().unwrap();
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let _init = next_update(&mut w, Duration::from_secs(2), "initial").await;

        write_file(
            d.path(),
            "new.toml",
            r#"[[rule]]
            name = "new"
            listen = "0.0.0.0:2222"
            protocol = "udp"
            target_port = 53
            "#,
        );

        let upd = next_update(&mut w, Duration::from_secs(5), "added-file event").await;
        assert_eq!(upd.diff.added.len(), 1);
        assert_eq!(upd.diff.added[0].name, "new");
        assert!(upd.diff.removed.is_empty());
        assert!(upd.diff.changed.is_empty());
    }

    #[tokio::test]
    async fn detects_changed_file() {
        let d = tempfile::tempdir().unwrap();
        write_file(
            d.path(),
            "r.toml",
            r#"[[rule]]
            name = "r"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 22
            "#,
        );
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let _init = next_update(&mut w, Duration::from_secs(2), "initial").await;

        write_file(
            d.path(),
            "r.toml",
            r#"[[rule]]
            name = "r"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 23
            "#,
        );

        let upd = next_update(&mut w, Duration::from_secs(5), "changed event").await;
        assert!(upd.diff.added.is_empty());
        assert!(upd.diff.removed.is_empty());
        assert_eq!(upd.diff.changed.len(), 1);
        assert_eq!(upd.diff.changed[0].old.target_port, Some(22));
        assert_eq!(upd.diff.changed[0].new.target_port, Some(23));
    }

    #[tokio::test]
    async fn detects_removed_file() {
        let d = tempfile::tempdir().unwrap();
        write_file(
            d.path(),
            "g.toml",
            r#"[[rule]]
            name = "g"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 1
            "#,
        );
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let _init = next_update(&mut w, Duration::from_secs(2), "initial").await;

        std::fs::remove_file(d.path().join("g.toml")).unwrap();
        let upd = next_update(&mut w, Duration::from_secs(5), "remove event").await;
        assert_eq!(upd.diff.removed.len(), 1);
        assert_eq!(upd.diff.removed[0].name, "g");
        assert!(upd.set.is_empty());
    }

    #[tokio::test]
    async fn bad_toml_does_not_replace_previous_set() {
        let d = tempfile::tempdir().unwrap();
        write_file(
            d.path(),
            "good.toml",
            r#"[[rule]]
            name = "good"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            target_port = 1
            "#,
        );
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(50)).unwrap();
        let init = next_update(&mut w, Duration::from_secs(2), "initial").await;
        assert_eq!(init.set.len(), 1);

        // Write a broken file. The watcher should log + skip + retain the
        // previous good set. We then write a real change to confirm the
        // watcher is still functional and picks up the good change.
        write_file(d.path(), "broken.toml", "[[rule\nname=oops");
        // Give the broken-load attempt time to be processed.
        tokio::time::sleep(Duration::from_millis(400)).await;

        write_file(
            d.path(),
            "second.toml",
            r#"[[rule]]
            name = "second"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            target_port = 2
            "#,
        );

        // The next *successful* update should still be missing `broken` but
        // include the new `second`. The `good` rule remains.
        // Note: a broken-then-good sequence can collapse via the debouncer; in
        // that case the worker sees only the final state which fails to load
        // (because `broken.toml` is still in the dir). Remove the broken file
        // before asserting to avoid that ambiguity.
        std::fs::remove_file(d.path().join("broken.toml")).unwrap();
        let upd = next_update(&mut w, Duration::from_secs(5), "second add").await;
        let names: Vec<&str> = upd.set.rules().iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"good"));
        assert!(names.contains(&"second"));
    }

    #[tokio::test]
    async fn force_reload_triggers_an_emit_when_state_changed() {
        let d = tempfile::tempdir().unwrap();
        let mut w = RuleWatcher::spawn(d.path(), Duration::from_millis(500)).unwrap();
        let _init = next_update(&mut w, Duration::from_secs(2), "initial").await;

        // Write a file then immediately force a reload, bypassing the debouncer.
        write_file(
            d.path(),
            "f.toml",
            r#"[[rule]]
            name = "forced"
            listen = "0.0.0.0:9999"
            protocol = "tcp"
            target_port = 1
            "#,
        );
        w.force_reload();

        let upd = next_update(&mut w, Duration::from_secs(2), "forced reload").await;
        assert_eq!(upd.diff.added.len(), 1);
        assert_eq!(upd.diff.added[0].name, "forced");
    }

    #[tokio::test]
    async fn missing_directory_at_spawn_is_an_error() {
        let err = RuleWatcher::spawn("/this/does/not/exist/rules", Duration::from_millis(50)).err();
        assert!(err.is_some());
    }
}
