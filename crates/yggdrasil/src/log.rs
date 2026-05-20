//! Tracing/logging setup. JSON for production (journald), pretty for terminals.
//!
//! Exposes a runtime-reload handle so `yggdrasilctl local trace` can bump the
//! filter without a daemon restart. The startup directive (from `YGGDRASIL_LOG`
//! or the built-in `info` default) is captured so a `--reset` round-trip can
//! restore the original filter.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter};

use crate::cli::LogFormat;

/// Default filter directive when `YGGDRASIL_LOG` is unset.
const DEFAULT_DIRECTIVE: &str = "info";

/// Global controller stashed at `init_tracing` time so the control-socket
/// dispatcher can mutate the filter at runtime.
static TRACE_CONTROLLER: OnceLock<TraceController> = OnceLock::new();

struct TraceController {
    /// Closure that wraps the type-erased reload-handle write so the
    /// public surface doesn't have to mention the registry's full
    /// layered type.
    apply: Box<dyn Fn(EnvFilter) -> std::result::Result<(), String> + Send + Sync>,
    /// Directive the daemon was launched with. A `--reset` restores this.
    default: String,
    /// Directive currently in effect. Tracked here because `EnvFilter`'s
    /// own `Display` reflects only the parsed-back form, which can lose
    /// the operator's original whitespace/comments.
    current: Mutex<String>,
}

/// Initialise `tracing` exactly once. Reads `YGGDRASIL_LOG` for the level filter,
/// falling back to `info` when unset.
pub fn init_tracing(format: LogFormat) -> Result<()> {
    let directive =
        std::env::var("YGGDRASIL_LOG").unwrap_or_else(|_| DEFAULT_DIRECTIVE.to_string());
    let env_filter =
        EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new(DEFAULT_DIRECTIVE));

    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);

    let registry = tracing_subscriber::registry().with(filter_layer);
    match format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(false)
                    .with_span_list(false),
            )
            .try_init()
            .context("install JSON tracing subscriber")?,
        LogFormat::Pretty => registry
            .with(fmt::layer().with_target(true))
            .try_init()
            .context("install pretty tracing subscriber")?,
    }

    let apply = Box::new(move |filter: EnvFilter| -> std::result::Result<(), String> {
        reload_handle
            .modify(|f| *f = filter)
            .map_err(|e| e.to_string())
    });

    let _ = TRACE_CONTROLLER.set(TraceController {
        apply,
        default: directive.clone(),
        current: Mutex::new(directive),
    });
    Ok(())
}

/// Apply a new tracing directive at runtime. Returns the directive now in
/// effect on success, or a parse/install diagnostic on failure.
pub fn set_trace_directive(directive: &str) -> std::result::Result<String, String> {
    let ctrl = TRACE_CONTROLLER
        .get()
        .ok_or_else(|| "tracing not initialised".to_string())?;
    let filter = EnvFilter::try_new(directive).map_err(|e| e.to_string())?;
    (ctrl.apply)(filter)?;
    *ctrl.current.lock() = directive.to_string();
    Ok(directive.to_string())
}

/// Restore the directive captured at startup. Returns the restored directive.
pub fn reset_trace_directive() -> std::result::Result<String, String> {
    let ctrl = TRACE_CONTROLLER
        .get()
        .ok_or_else(|| "tracing not initialised".to_string())?;
    let filter = EnvFilter::try_new(&ctrl.default).map_err(|e| e.to_string())?;
    (ctrl.apply)(filter)?;
    *ctrl.current.lock() = ctrl.default.clone();
    Ok(ctrl.default.clone())
}

/// `(active, default)` directives. Returns `None` only when tracing was
/// never initialised (tests that bypass `init_tracing`).
pub fn trace_directives() -> Option<(String, String)> {
    let ctrl = TRACE_CONTROLLER.get()?;
    Some((ctrl.current.lock().clone(), ctrl.default.clone()))
}
