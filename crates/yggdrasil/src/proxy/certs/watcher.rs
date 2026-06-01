//! Filesystem watcher for disk-backed certificate PEM files.
//!
//! Sits
//! next to the rule-file watcher in [`ProxySupervisor`]: each HTTPS rule
//! that loads at least one disk-backed route registers its
//! `(hostname, [cert_path, key_path])` pairs via
//! [`CertWatcher::register`]. When notify-debouncer-mini reports a
//! change inside a watched parent directory, the watcher looks up every
//! host whose PEM lives in that directory and asks
//! [`CertStore::reload_host`] to re-resolve it.
//!
//! Watch handles are reference-counted per parent directory: a single
//! `cert_dir` shared by N routes uses one inotify watch, not N. Dropping
//! the watcher tears down the debouncer thread, the bridge thread, and
//! the consumer task.
//!
//! [`ProxySupervisor`]: crate::proxy::supervisor::ProxySupervisor
//! [`CertStore::reload_host`]: super::store::CertStore::reload_host

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread;
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebouncedEvent, Debouncer};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::store::CertStore;

type NotifyResult = Result<Vec<DebouncedEvent>, notify::Error>;

pub struct CertWatcher {
    inner: Arc<WatcherShared>,
    // Order matters: the debouncer holds the notify watcher which feeds
    // the std::sync::mpsc bridge; dropping it closes the bridge, which
    // closes the reload channel, which lets the worker task exit cleanly.
    _debouncer: Mutex<Debouncer<notify::RecommendedWatcher>>,
    _bridge: thread::JoinHandle<()>,
    _worker: tokio::task::JoinHandle<()>,
}

struct WatcherShared {
    store: Arc<CertStore>,
    state: Mutex<WatcherState>,
}

#[derive(Default)]
struct WatcherState {
    /// Hostname → list of cert/key paths the host depends on. Mirrors
    /// the disk paths from each host's `CertOrigin`.
    host_paths: HashMap<String, Vec<PathBuf>>,
    /// Parent directory → refcount. We watch parent directories (not
    /// individual files) so atomic-rename replacements
    /// (`mv tmp.pem cert.pem`) are observable. Refcount lets us share
    /// one inotify watch across hosts that live in the same cert_dir.
    watched_dirs: HashMap<PathBuf, usize>,
}

impl CertWatcher {
    /// Spawn the watcher.
    ///
    /// `debounce` is the coalescing window for filesystem events; the
    /// supervisor passes the same value the rule watcher uses (typically
    /// 250 ms). `shutdown` is observed cooperatively — cancelling it
    /// stops the consumer task; dropping the watcher tears the rest down.
    pub fn spawn(
        store: Arc<CertStore>,
        debounce: Duration,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let (notify_tx, notify_rx) = std_mpsc::channel::<NotifyResult>();
        let debouncer = new_debouncer(debounce, notify_tx).map_err(io::Error::other)?;

        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<HashSet<String>>(32);

        let shared = Arc::new(WatcherShared {
            store: Arc::clone(&store),
            state: Mutex::new(WatcherState::default()),
        });

        let bridge_shared = Arc::clone(&shared);
        let bridge = thread::Builder::new()
            .name("cert-watch-bridge".into())
            .spawn(move || bridge_cert_events(notify_rx, bridge_shared, reload_tx))
            .map_err(io::Error::other)?;

        let worker_shared = Arc::clone(&shared);
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        tracing::debug!("cert watcher: shutdown signalled");
                        break;
                    }
                    msg = reload_rx.recv() => {
                        let hosts = match msg {
                            Some(h) => h,
                            None => {
                                tracing::debug!(
                                    "cert watcher: bridge channel closed; exiting"
                                );
                                break;
                            }
                        };
                        for host in hosts {
                            match worker_shared.store.reload_host(&host) {
                                Ok(()) => tracing::info!(
                                    route = %host,
                                    "cert hot-reload: refreshed from disk"
                                ),
                                Err(e) => tracing::warn!(
                                    route = %host,
                                    error = %e,
                                    "cert hot-reload: reload failed; keeping previous cert in service"
                                ),
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner: shared,
            _debouncer: Mutex::new(debouncer),
            _bridge: bridge,
            _worker: worker,
        })
    }

    /// Register a hostname and its current set of disk paths with the
    /// watcher. Safe to call repeatedly for the same host: any previously
    /// watched paths that are no longer in `paths` are released, and any
    /// new directories are added to the inotify set.
    ///
    /// Hosts with no disk paths (i.e. ephemeral) are skipped — there's
    /// nothing to watch.
    pub fn register(&self, hostname: &str, paths: &[PathBuf]) {
        if paths.is_empty() {
            return;
        }
        let key = hostname.to_ascii_lowercase();
        let mut state = self.inner.state.lock();
        // Compute the diff vs. whatever this host was previously
        // watching, so we don't churn inotify watches across spurious
        // re-registers.
        let prev: Vec<PathBuf> = state.host_paths.remove(&key).unwrap_or_default();
        let prev_dirs: HashSet<PathBuf> = prev
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();
        let new_dirs: HashSet<PathBuf> = paths
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();
        // Add new directories.
        for dir in new_dirs.difference(&prev_dirs) {
            let count = state.watched_dirs.entry(dir.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                if let Err(e) = self
                    ._debouncer
                    .lock()
                    .watcher()
                    .watch(dir, RecursiveMode::NonRecursive)
                {
                    tracing::warn!(
                        dir   = %dir.display(),
                        error = %e,
                        "cert watcher: failed to watch cert directory"
                    );
                    // Roll back the refcount so we don't leak the slot.
                    *count -= 1;
                    if *count == 0 {
                        state.watched_dirs.remove(dir);
                    }
                }
            }
        }
        // Drop directories no longer needed by this host.
        for dir in prev_dirs.difference(&new_dirs) {
            decrement_watched_dir(&mut state, dir, &self._debouncer);
        }
        state.host_paths.insert(key, paths.to_vec());
    }

    /// Unregister a hostname. Drops it from the path index and releases
    /// any inotify watches that were only held on this host's behalf.
    pub fn unregister(&self, hostname: &str) {
        let key = hostname.to_ascii_lowercase();
        let mut state = self.inner.state.lock();
        let Some(paths) = state.host_paths.remove(&key) else {
            return;
        };
        let dirs: HashSet<PathBuf> = paths
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();
        for dir in dirs {
            decrement_watched_dir(&mut state, &dir, &self._debouncer);
        }
    }

    /// Number of hostnames currently registered. Test/observability aid.
    pub fn host_count(&self) -> usize {
        self.inner.state.lock().host_paths.len()
    }
}

impl std::fmt::Debug for CertWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertWatcher")
            .field("hosts", &self.host_count())
            .finish()
    }
}

fn decrement_watched_dir(
    state: &mut WatcherState,
    dir: &Path,
    debouncer: &Mutex<Debouncer<notify::RecommendedWatcher>>,
) {
    let Some(count) = state.watched_dirs.get_mut(dir) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        state.watched_dirs.remove(dir);
        if let Err(e) = debouncer.lock().watcher().unwatch(dir) {
            tracing::debug!(
                dir   = %dir.display(),
                error = %e,
                "cert watcher: unwatch failed (already gone?)"
            );
        }
    }
}

/// Bridge thread: turns notify-debouncer batches into "reload these
/// hosts" messages on the tokio side.
fn bridge_cert_events(
    rx: std_mpsc::Receiver<NotifyResult>,
    shared: Arc<WatcherShared>,
    reload_tx: tokio::sync::mpsc::Sender<HashSet<String>>,
) {
    while let Ok(batch) = rx.recv() {
        let events = match batch {
            Ok(events) if !events.is_empty() => events,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "cert watcher: notify error");
                continue;
            }
        };
        // Map every event path back to one or more affected hostnames.
        // We compare full paths so a sibling file in the same cert_dir
        // doesn't accidentally trigger an unrelated reload.
        let hosts = {
            let state = shared.state.lock();
            let mut hits: HashSet<String> = HashSet::new();
            for ev in &events {
                for (host, paths) in &state.host_paths {
                    if paths.iter().any(|p| p == &ev.path) {
                        hits.insert(host.clone());
                    }
                }
            }
            hits
        };
        if hosts.is_empty() {
            continue;
        }
        tracing::debug!(
            hosts = hosts.len(),
            "cert watcher: fs event affected loaded routes"
        );
        if reload_tx.blocking_send(hosts).is_err() {
            // Worker has exited.
            break;
        }
    }
}
