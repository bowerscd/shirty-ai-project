#![no_main]
//! libFuzzer target for the pre-auth wire-frame parser.
//!
//! Calls [`ratatoskr::wire::parse`] on arbitrary bytes. This is the
//! exact code path that runs on every UDP datagram received on the
//! chain listener *before* authentication completes — i.e. the most
//! exposed attack surface in the daemon.
//!
//! The harness discards both `Ok` and `Err` results; libFuzzer only
//! cares about whether the parser panics, aborts, or hits an
//! uncaught arithmetic / index error. The `PacketView` returned on
//! success borrows from `data`, so dropping it at function end is
//! correct and Rust enforces the lifetime.

use libfuzzer_sys::fuzz_target;
use ratatoskr::wire;

fuzz_target!(|data: &[u8]| {
    let _ = wire::parse(data);
});
