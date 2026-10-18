//! Phase 9.1 evaluation harness binary.
//!
//! All work is delegated to [`frf_memorysafety::evaluation`]. The binary is a
//! thin argument boundary so the harness logic is testable from the library.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(frf_memorysafety::evaluation::cli(std::env::args().skip(1)));
}
