#![no_main]
//! libFuzzer target for enrollment request / grant document parsing.
//!
//! Enrollment documents are TOML files exchanged out-of-band between
//! a terminal (request) and its upstream relay (grant) during the
//! request/grant ceremony (`yggdrasilctl identity export-request` /
//! `identity add-accept` / `identity add-dial`). The files are
//! operator-controlled, so the attack surface is narrower than the
//! on-wire surfaces above — but a malformed file shipped via a buggy
//! provisioning script shouldn't panic the CLI.
//!
//! Input is interpreted as UTF-8 (lossy on invalid sequences). Both
//! the `RequestFile` and `GrantFile` parsers are exercised
//! independently over the same input.

use libfuzzer_sys::fuzz_target;
use ratatoskr::enrollment::{GrantFile, RequestFile};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = toml::from_str::<RequestFile>(&s);
    let _ = toml::from_str::<GrantFile>(&s);
});
