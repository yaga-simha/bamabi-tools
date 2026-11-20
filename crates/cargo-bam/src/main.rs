#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Binary entrypoint for `cargo-bam` (`cargo bam <subcommand>` / `cargo-bam <subcommand>`).
//!
//! Delegates CLI parsing and execution to [`cargo_bam::run_from_args`].

use std::process::ExitCode;

fn main() -> ExitCode {
    cargo_bam::run_from_args(std::env::args_os())
}
