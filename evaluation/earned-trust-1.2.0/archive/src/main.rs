//! Thin CLI entry point.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(frf_memorysafety::cli::run(std::env::args().skip(1)));
}
