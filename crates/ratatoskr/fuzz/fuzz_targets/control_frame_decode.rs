#![no_main]
//! libFuzzer target for postcard-encoded control envelopes / acks.
//!
//! Calls [`postcard::from_bytes::<ControlEnvelope>`] *and* the matching
//! [`ControlAck`] on the same input. Each variant runs over the full
//! input independently — libFuzzer can therefore find a single input
//! that exercises either parser's pathological case.
//!
//! These types ride inside the AEAD ciphertext of a Control / ControlAck
//! packet (see `ratatoskr::wire`), so a malicious peer needs to complete
//! the Noise handshake first. The handshake itself is fuzzed transitively
//! via `wire_parse`, but defence-in-depth: the post-auth parser should
//! also not panic on adversarial input from a key-compromised peer.

use libfuzzer_sys::fuzz_target;
use ratatoskr::control_frame::{ControlAck, ControlEnvelope};

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<ControlEnvelope>(data);
    let _ = postcard::from_bytes::<ControlAck>(data);
});
