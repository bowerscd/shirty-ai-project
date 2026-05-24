//! Dev-only in-process CPU profiler.
//!
//! Compiled in only when the `profile` Cargo feature is enabled — the
//! production binary has zero overhead from this module (the
//! re-exports below resolve to the stub, which is also a zero-cost
//! `Option<()>` in disguise).
//!
//! ## Why this exists
//!
//! The bench harness can tell you yggdrasil is `N%` slower than
//! nginx on a given workload, but it can't tell you *why*. The
//! Prometheus metrics yggdrasil emits are business-level (rules
//! loaded, heartbeats received) — they don't sample the hot path.
//! A real CPU profile is the only way to see whether the gap is
//! syscall overhead, allocator pressure, tokio scheduler bookkeeping,
//! or something else.
//!
//! This module wraps [`pprof`] (a pure-userspace SIGPROF-based
//! sampler — works without root, doesn't need `perf` installed) so
//! a bench script or a developer can:
//!
//! 1. Build with `cargo build --release -p yggdrasil --features profile`
//! 2. Set `YGGDRASIL_PROFILE_OUTPUT=/tmp/yggd.svg` (or `.pb`)
//! 3. Run the daemon under the bench
//! 4. On daemon shutdown the guard flushes either a flamegraph SVG
//!    (extension `.svg`) or a pprof binary (extension `.pb` /
//!    `.pprof`, consume with `go tool pprof`).
//!
//! Optional knobs:
//!
//! * `YGGDRASIL_PROFILE_FREQUENCY=<Hz>` (default `99`) — sampling
//!   frequency. Higher = finer-grained, more overhead.
//! * `YGGDRASIL_PROFILE_DURATION=<humantime>` — flush after this long
//!   instead of waiting for shutdown. Useful when you want to bound
//!   profile size on a long-running daemon.
//!
//! ## Stack depth caveat
//!
//! pprof-rs's signal-based unwinder (we enable the `frame-pointer`
//! feature so it walks `%rbp` chains directly rather than going
//! through libgcc's `_Unwind_Backtrace`) reliably attributes each
//! sample to the leaf function — typically a libc syscall name
//! like `epoll_wait` / `recvmmsg` / `sendmmsg` — but does not
//! always walk back into the calling Rust frames. SIGPROF often
//! lands while the thread is inside a syscall, where `%rbp` is
//! kernel-managed and the unwinder gives up after one frame.
//!
//! In practice this is enough for the "where is CPU going by
//! syscall mix" question (the leaf is informative on its own and
//! tells you e.g. "20 % of CPU is in epoll_wait"). For
//! "which Rust function called this syscall" you'll want either
//! per-section `Instant::now()` instrumentation in the hot path
//! or `perf record -g` on a host with a permissive
//! `kernel.perf_event_paranoid`.
//!
//! Build with `cargo build --release -p yggdrasil --features profile`.
//! Frame pointers are emitted by default for the `profile` build via
//! `bench/profile.sh` (which sets
//! `RUSTFLAGS="-C force-frame-pointers=yes"`).
//!
//! ## What is NOT in scope
//!
//! * Operator-visible profiling in production (would need
//!   authentication, file-rotation, security review of what
//!   user-space samples can reveal). Filed as a separate concern.
//! * Async-aware flamegraphs (each tokio task gets its own
//!   "what's blocking" hierarchy). Would need `tokio-console` /
//!   `tracing-flame` — out of scope here; `pprof` gives raw CPU
//!   samples which is the right starting point.
//! * Heap profiling. Use `heaptrack` separately if needed.

#[cfg(feature = "profile")]
mod real {
    use std::env;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use pprof::ProfilerGuard;
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    /// Activated profiler. Drop or call [`Profiler::flush`] to
    /// materialise the output file. The daemon's main `run_*` keeps
    /// the guard alive for the lifetime of the process so the file
    /// only lands on shutdown (or after the configured duration).
    pub struct Profiler {
        guard: ProfilerGuard<'static>,
        output: PathBuf,
        deadline_notifier: Arc<Notify>,
    }

    impl Profiler {
        /// Look for `YGGDRASIL_PROFILE_OUTPUT` in the environment.
        /// Returns `Ok(None)` if unset — the daemon is then a no-op
        /// from a profiling perspective. Returns `Err` only on a
        /// real activation failure (e.g. SIGPROF handler couldn't
        /// be installed). Misconfigurations (bad path extension,
        /// unparseable duration) are warn-logged + ignored.
        pub fn start_if_configured(shutdown: CancellationToken) -> Result<Option<Self>> {
            let Some(output) = env::var_os("YGGDRASIL_PROFILE_OUTPUT") else {
                return Ok(None);
            };
            let output: PathBuf = output.into();

            let frequency: i32 = env::var("YGGDRASIL_PROFILE_FREQUENCY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(99);
            tracing::warn!(
                output = %output.display(),
                frequency_hz = frequency,
                "CPU profiler ACTIVE (dev-only build); flushes on shutdown"
            );

            let guard = pprof::ProfilerGuardBuilder::default()
                .frequency(frequency)
                .build()
                .context("build pprof::ProfilerGuard")?;

            let deadline_notifier = Arc::new(Notify::new());
            if let Ok(duration_str) = env::var("YGGDRASIL_PROFILE_DURATION") {
                match humantime::parse_duration(&duration_str) {
                    Ok(d) => Self::spawn_deadline_task(
                        d,
                        shutdown.clone(),
                        Arc::clone(&deadline_notifier),
                    ),
                    Err(e) => tracing::warn!(
                        value = %duration_str,
                        error = %e,
                        "ignoring unparseable YGGDRASIL_PROFILE_DURATION"
                    ),
                }
            }

            Ok(Some(Self {
                guard,
                output,
                deadline_notifier,
            }))
        }

        fn spawn_deadline_task(
            duration: Duration,
            shutdown: CancellationToken,
            notifier: Arc<Notify>,
        ) {
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(duration) => {
                        tracing::warn!(
                            "YGGDRASIL_PROFILE_DURATION elapsed; flushing profile (daemon continues)"
                        );
                        notifier.notify_one();
                    }
                    _ = shutdown.cancelled() => {}
                }
            });
        }

        /// Returns when either the deadline notifier fires OR the
        /// outer shutdown cancels — whichever comes first. The
        /// daemon's main can `tokio::select!` on this alongside its
        /// other shutdown sources.
        pub async fn wait_for_deadline(&self) {
            self.deadline_notifier.notified().await;
        }

        /// Flush the accumulated samples to the configured output
        /// file. Format is chosen by the path extension:
        ///
        /// * `.svg` → Brendan-Gregg-style flamegraph (renderable in
        ///   any browser).
        /// * `.pb` / `.pprof` → pprof protobuf binary (consume with
        ///   `go tool pprof <file>`).
        ///
        /// Other extensions default to flamegraph SVG with a warn.
        pub fn flush(self) -> Result<()> {
            let report = self.guard.report().build().context("build pprof report")?;

            let path = &self.output;
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            match ext.as_str() {
                "pb" | "pprof" => {
                    use pprof::protos::Message;
                    let profile = report.pprof().context("convert report to pprof")?;
                    let mut buf = Vec::new();
                    profile.encode(&mut buf).context("encode pprof")?;
                    std::fs::write(path, &buf)
                        .with_context(|| format!("write pprof to {}", path.display()))?;
                    tracing::warn!(
                        path = %path.display(),
                        size_bytes = buf.len(),
                        "wrote pprof profile (consume with `go tool pprof`)"
                    );
                }
                other => {
                    if other != "svg" {
                        tracing::warn!(
                            extension = other,
                            "unknown profile output extension; writing SVG flamegraph"
                        );
                    }
                    let file = std::fs::File::create(path)
                        .with_context(|| format!("create flamegraph at {}", path.display()))?;
                    report.flamegraph(file).context("emit flamegraph")?;
                    tracing::warn!(
                        path = %path.display(),
                        "wrote flamegraph SVG (open in any browser)"
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(feature = "profile"))]
mod stub {
    use anyhow::Result;
    use tokio_util::sync::CancellationToken;

    pub struct Profiler;

    impl Profiler {
        pub fn start_if_configured(_shutdown: CancellationToken) -> Result<Option<Self>> {
            if std::env::var_os("YGGDRASIL_PROFILE_OUTPUT").is_some() {
                tracing::warn!(
                    "YGGDRASIL_PROFILE_OUTPUT is set but yggdrasil was built without \
                     the `profile` Cargo feature; profile request ignored"
                );
            }
            Ok(None)
        }
        pub async fn wait_for_deadline(&self) {
            std::future::pending::<()>().await;
        }
        pub fn flush(self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(feature = "profile")]
pub use real::Profiler;

#[cfg(not(feature = "profile"))]
pub use stub::Profiler;
