//! Downstream-approve flow: pop a candidate from the pending store,
//! rewrite `[accept].pubkey` in the daemon config, and swap the live
//! `PeerState`'s peer-static-key.
//!

use std::path::Path;

use anyhow::{Context, Result};

use ratatoskr::control::{error_codes, Response};

use super::super::ControlState;
use super::terminal_mode_unsupported;

pub(in crate::control) fn approve_downstream(state: &ControlState, fingerprint: &str) -> Response {
    let (peer_state, pending_store) = match (&state.peer_state, &state.pending_store) {
        (Some(ps), Some(store)) => (ps, store),
        _ => return terminal_mode_unsupported("downstream approve"),
    };
    let (resolved_fp, key) = match pending_store.approve(fingerprint) {
        crate::pending_peers::ApproveOutcome::Approved { fingerprint, key } => (fingerprint, key),
        crate::pending_peers::ApproveOutcome::NotFound => {
            return Response::Error {
                code: error_codes::NO_SUCH_FINGERPRINT.into(),
                message: format!("no pending candidate matches fingerprint prefix {fingerprint:?}"),
            };
        }
        crate::pending_peers::ApproveOutcome::Ambiguous { matches } => {
            return Response::Error {
                code: error_codes::AMBIGUOUS_FINGERPRINT.into(),
                message: format!(
                    "fingerprint prefix {fingerprint:?} is ambiguous; matches {} candidates: {}. \
                     Re-run `local accept approve` with a longer prefix.",
                    matches.len(),
                    matches.join(", ")
                ),
            };
        }
        crate::pending_peers::ApproveOutcome::PrefixTooShort { provided, required } => {
            return Response::Error {
                code: error_codes::AMBIGUOUS_FINGERPRINT.into(),
                message: format!(
                    "fingerprint prefix {fingerprint:?} is too short ({provided} hex chars); \
                     a minimum of {required} hex chars is required to disambiguate."
                ),
            };
        }
    };
    let tagged = key.to_string();
    if let Err(e) = update_downstream_pubkey(&state.config_path, &tagged) {
        return Response::Error {
            code: error_codes::CONFIG_WRITE_FAILED.into(),
            message: format!(
                "approve: failed to write {} ({e:#}). \
                 Candidate has been removed from the pending queue; \
                 set `accept.pubkey = \"{tagged}\"` manually.",
                state.config_path.display()
            ),
        };
    }
    peer_state.set_peer_static_key(key);
    tracing::info!(
        fingerprint = %resolved_fp,
        "downstream approved via control surface; key is now live"
    );
    Response::DownstreamApproved {
        fingerprint: resolved_fp,
    }
}

/// Atomic rewrite of `[accept].pubkey` in `config_path`. Round-trips
/// the file through `toml::Value` so other keys are preserved
/// (formatting and comments are lost — acceptable trade-off; explicit
/// `*.tmp` + rename keeps the change crash-safe).
fn update_downstream_pubkey(config_path: &Path, tagged_pubkey: &str) -> Result<()> {
    let text = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let mut doc: toml::Value = text
        .parse()
        .with_context(|| format!("parse {}", config_path.display()))?;
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a TOML table", config_path.display()))?;
    let accept_entry = table
        .entry("accept".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
    let accept_table = accept_entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("`accept` in {} is not a table", config_path.display()))?;
    accept_table.insert(
        "pubkey".to_string(),
        toml::Value::String(tagged_pubkey.to_string()),
    );
    let serialised = toml::to_string_pretty(&doc).context("serialise updated config")?;
    let tmp = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialised).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, config_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), config_path.display()))?;
    Ok(())
}
