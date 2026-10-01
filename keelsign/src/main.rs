//! The `keelsign` command-line tool (see `docs/keys.md`).
#![forbid(unsafe_code)]

use clap::Parser as _;
use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = keelsign::cli::Cli::parse();
    match keelsign::cli::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr().lock(), "error: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
