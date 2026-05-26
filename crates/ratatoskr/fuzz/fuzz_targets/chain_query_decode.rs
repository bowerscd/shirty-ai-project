#![no_main]
//! libFuzzer target for postcard-encoded chain query / reply bodies.
//!
//! `ChainHopQuery` and `ChainHopReply` ride inside `ChainHopQuery` /
//! `ChainHopReply` control envelopes routed across chain hops. Each
//! is decoded into the typed body before dispatch; this target
//! exercises both decoders independently over the same input.

use libfuzzer_sys::fuzz_target;
use ratatoskr::chain_query::{ChainHopQuery, ChainHopReply};

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<ChainHopQuery>(data);
    let _ = postcard::from_bytes::<ChainHopReply>(data);
});
