//! Shared error types for the yggdrasil heartbeat protocol crate.

use std::io;
use std::path::PathBuf;

/// All recoverable errors raised inside `ratatoskr`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ---- I/O & filesystem ----
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to read {path}: {source}")]
    ReadFile { path: PathBuf, source: io::Error },

    #[error("failed to write {path}: {source}")]
    WriteFile { path: PathBuf, source: io::Error },

    // ---- Encoding / decoding ----
    #[error("toml parse error in {path}: {source}")]
    TomlParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("postcard decode error: {0}")]
    Postcard(#[from] postcard::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    // ---- Configuration / validation ----
    #[error("invalid rule configuration: {0}")]
    InvalidRule(String),

    #[error("invalid enrollment token: {0}")]
    InvalidEnrollmentToken(String),

    #[error("invalid pubkey: {0}")]
    InvalidPubKey(String),

    // ---- Crypto ----
    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("authentication failure: {0}")]
    Auth(&'static str),

    #[error("replay detected: counter {counter} <= last_seen {last_seen}")]
    Replay { counter: u64, last_seen: u64 },

    // ---- Wire format ----
    #[error("malformed wire packet: {0}")]
    MalformedPacket(&'static str),

    #[error("unknown packet type: 0x{0:02x}")]
    UnknownPacketType(u8),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
