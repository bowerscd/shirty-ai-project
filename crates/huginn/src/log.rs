//! Tracing/logging setup for the huginn client.

use anyhow::{Context, Result};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::cli::LogFormat;

pub fn init_tracing(format: LogFormat) -> Result<()> {
    let env_filter = EnvFilter::try_from_env("HUGINN_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(env_filter);
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
    Ok(())
}
