#![no_main]
//! libFuzzer target for postcard-encoded predicate sets.
//!
//! Calls [`postcard::from_bytes::<PredicateSet>`] on arbitrary bytes.
//! `PredicateSet` is the body of every `PredicateSetUpdate` control
//! envelope pushed from a downstream terminal toward its upstream
//! relay — the relay parses these on every successful push, so a
//! key-compromised terminal could throw adversarial inputs at the
//! relay's predicate decoder.

use libfuzzer_sys::fuzz_target;
use ratatoskr::predicate::PredicateSet;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<PredicateSet>(data);
});
