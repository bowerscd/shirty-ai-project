//! ratatoskr — heartbeat client for yggdrasil.

mod cli;
mod commands;
mod config;
mod heartbeat;
mod log;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;

use yggdrasil_proto::auth::{StaticKeyPair, PUBLIC_KEY_LEN};

use crate::heartbeat::{HeartbeatClient, HeartbeatClientConfig};

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    log::init_tracing(args.log_format)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    runtime.block_on(async move {
        match args.command {
            cli::Command::Run(run_args)        => run(run_args).await,
            cli::Command::Keygen(a)            => commands::keygen(a),
            cli::Command::Pubkey(a)            => commands::pubkey(a),
            cli::Command::Fingerprint(a)       => commands::fingerprint(a),
            cli::Command::Enroll(a)            => commands::enroll(a),
            cli::Command::Version              => print_version(),
        }
    })
}

async fn run(args: cli::RunArgs) -> Result<()> {
    let config = config::ClientConfig::load(&args.config)
        .with_context(|| format!("loading client config from {}", args.config.display()))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        endpoint = %config.client.yggdrasil_endpoint,
        heartbeat_interval = ?config.client.heartbeat_interval,
        rekey_interval = ?config.client.rekey_interval,
        "ratatoskr starting"
    );

    let local_keys = StaticKeyPair::load_from_file(&config.client.identity_file)
        .with_context(|| {
            format!(
                "loading client identity from {}",
                config.client.identity_file.display()
            )
        })?;

    let server_pubkey = decode_pubkey_hex(&config.client.yggdrasil_pubkey_hex)
        .context("decoding client.yggdrasil_pubkey_hex")?;

    let cancel = CancellationToken::new();
    let client = HeartbeatClient::new(
        HeartbeatClientConfig {
            endpoint:           config.client.yggdrasil_endpoint.clone(),
            server_pubkey,
            local_keys,
            heartbeat_interval: config.client.heartbeat_interval,
            rekey_interval:     config.client.rekey_interval,
        },
        cancel.clone(),
    );

    let client_handle = tokio::spawn(async move { client.run().await });

    wait_for_shutdown().await;
    tracing::info!("ratatoskr shutting down");
    cancel.cancel();
    match client_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => tracing::error!(error = %e, "client task join error"),
    }
    Ok(())
}

async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGTERM handler");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = sigterm.recv()          => tracing::info!("received SIGTERM"),
    }
}

fn decode_pubkey_hex(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_str).context("not valid hex")?;
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected exactly {PUBLIC_KEY_LEN} bytes, got {}", bytes.len()))?;
    Ok(arr)
}

fn print_version() -> Result<()> {
    println!("ratatoskr {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

