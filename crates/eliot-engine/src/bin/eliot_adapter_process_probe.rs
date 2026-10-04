//! Deterministic child process for the `I10.17` deterministic process adapter.
//!
//! # Why this exists
//!
//! Acceptance for issue #1819 (A1) requires a **registered** deterministic
//! process adapter to be invoked with a path containing shell metacharacters and
//! to prove that the metacharacters reached the child verbatim. A mock cannot
//! prove that: only a real OS process launch can. This binary is that child.
//!
//! It is the fixture half of the acceptance proof, not a product route. The
//! adapter (`eliot_engine::adapter::ProcessAdapter`) is the product half, and it
//! is what owns executable/argv admission, the cwd and environment allowlist,
//! the resource profile, the bounded Blob Store spill and the exit/protocol
//! receipt.
//!
//! # Protocol (stdout, one record per line, deterministic order)
//!
//! ```text
//! PROBE_V1
//! ARG[0]=<value>          one per `--echo-arg`, in argv order
//! CWD=<path>              only with `--print-cwd`
//! ENV:<NAME>=<value>      only per `--echo-env`, in argv order
//! RAW=<n bytes>           only with `--raw-bytes <n>`
//! ```
//!
//! Exit code is `0` unless `--exit <n>` is given. Nothing here is time,
//! locale, network or environment dependent beyond the values the adapter
//! explicitly allowlisted, so two identical invocations produce identical
//! bytes.

// `clippy::print_stdout` / `clippy::print_stderr` escape hatch. Owner: the issue
// #1819 A1 acceptance fixture in this crate's bin surface. Operation: this
// TEST-ONLY probe writes its receipt to stdout/stderr, which is the channel the
// adapter captures, bounds and spills to Blob Store; there is no other channel.
// Removal condition: deleted with the A1 acceptance proof, never promoted to a
// product route.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::env;
use std::process::ExitCode;

/// Deterministic filler byte for `--raw-bytes`.
const RAW_BYTE: u8 = b'R';

/// Streams one line to stdout. `print_stdout` is allowed for the whole binary
/// (see `main`): stdout IS this probe's receipt channel, and the acceptance
/// proof reads it back through the adapter's bounded Blob Store spill.
fn emit(line: &str) {
    println!("{line}");
}

fn main() -> ExitCode {
    emit("PROBE_V1");
    if let Ok(cwd) = env::current_dir() {
        emit(&format!("CWD={}", cwd.display()));
    }

    let mut exit_code: u8 = 0;
    let mut raw_bytes: usize = 0;
    let mut stderr_bytes: usize = 0;
    let mut arguments = env::args().skip(1);
    let mut argument_index = 0_usize;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--print-cwd" => {}
            "--echo-arg" => {
                if let Some(value) = arguments.next() {
                    emit(&format!("ARG[{argument_index}]={value}"));
                    argument_index += 1;
                }
            }
            "--echo-env" => {
                if let Some(name) = arguments.next() {
                    let value = env::var(&name).unwrap_or_else(|_| "<unset>".to_owned());
                    emit(&format!("ENV:{name}={value}"));
                }
            }
            "--raw-bytes" => {
                if let Some(value) = arguments.next()
                    && let Ok(parsed) = value.parse::<usize>()
                {
                    raw_bytes = parsed;
                }
            }
            "--stderr-bytes" => {
                if let Some(value) = arguments.next()
                    && let Ok(parsed) = value.parse::<usize>()
                {
                    stderr_bytes = parsed;
                }
            }
            "--exit" => {
                if let Some(value) = arguments.next()
                    && let Ok(parsed) = value.parse::<i32>()
                {
                    exit_code = u8::try_from(parsed).unwrap_or(1);
                }
            }
            other => emit(&format!("UNRECOGNIZED={other}")),
        }
    }

    if raw_bytes > 0 {
        emit(&format!("RAW={raw_bytes}"));
        let filler: Vec<u8> = std::iter::repeat_n(RAW_BYTE, raw_bytes).collect();
        // `write_all` on a locked stdout cannot be reported more precisely than
        // "the probe failed"; the adapter sees a short read and records it.
        let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), &filler);
        emit("RAW_END");
    }
    if stderr_bytes > 0 {
        let filler: Vec<u8> = std::iter::repeat_n(RAW_BYTE, stderr_bytes).collect();
        let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), &filler);
        let _ = std::io::Write::write_all(&mut std::io::stderr().lock(), b"\n");
    }

    ExitCode::from(exit_code)
}
