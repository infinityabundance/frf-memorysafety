//! Phase 7.2 checked-in FRF-Fuzz fixture target for the live bridge chain.
//!
//! This is a deliberately tiny, deterministic target: an eight-byte
//! const-comparison gate aborts the process with no stdout, no stderr, and
//! signal 6. Unlike a `panic!` target, the raw streams carry no dynamic
//! thread id, so FRF's strict "raw outcome" replay comparison can reproduce
//! byte-for-byte. The const comparison also feeds FRF-Fuzz's compare-guided
//! dictionary, so the campaign discovers the gate from a non-crashing
//! near-miss seed instead of being handed the crashing input.
//!
//! `ci/bridge-gate.sh` copies this file into a writable copy of the pinned
//! `frf-fuzz` example directory and builds it with the pinned nightly and the
//! exact SanitizerCoverage flags. The pinned clone itself is never modified.

use frf_fuzz::target_runtime::FuzzContext;

/// The exact little-endian value that aborts the process (`BRIDGEFE`).
const MAGIC: u64 = u64::from_le_bytes(*b"BRIDGEFE");

frf_fuzz::fuzz_target!(|data: &[u8], _cx: &mut FuzzContext| {
    if data.len() >= 8 {
        let value = u64::from_le_bytes(data[..8].try_into().expect("eight bytes"));
        if value == MAGIC {
            std::process::abort();
        }
    }
});
