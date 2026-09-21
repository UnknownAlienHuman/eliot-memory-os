//! One-shot P03-admitted guest execution (issue #1955, I14.19).
//!
//! This is how an admitted guest executes INSIDE the reaped process
//! boundary instead of beside it: the P03 lane spawns this binary with the
//! admitted argv, the child compiles the artifact bytes, runs the `run`
//! export over the input bytes under Store-enforced ceilings, and emits
//! raw output bytes on stdout — the same bytes the parent observes through
//! P03 capture and compares against the oracle reference. Stdout carries
//! ONLY those bytes on success; every failure writes one stderr line and
//! exits nonzero with empty stdout, so a partial or failed execution can
//! never be mistaken for guest output.
//!
//! Trust model: every value arrives via the P03 staged intent argv (the
//! Kernel-issued admission), never ambient input. The artifact digest is
//! rechecked against the bytes actually read (TOCTOU closure); limits are
//! enforced by the Store/epoch driver, not trusted. The manifest gate
//! stays parent-side (admitted port path); this child proves execution
//! inside containment, and the parent differential proves it matches the
//! reference transform.

use std::collections::BTreeSet;
use std::io::Write;

use eliot_wasm_runtime::{
    ArtifactAccessLimits, CancellationPolicy, EngineTermination, EpochPolicy, InvocationLimits,
    Sha256Digest,
};

use crate::artifact_preflight::read_bounded_artifact;
use crate::cli_contract::GuestExecArgs;
use crate::wasmtime_provider::WasmtimeComponentEngine;

/// Input file ceiling: guest inputs are small framed vectors, never dumps.
const MAX_GUEST_INPUT_BYTES: u64 = 65_536;

/// Component configuration bound into child-built engines (distinct constant
/// so the digest binding is exercised, never echoed; recomputed at build).
const GUEST_EXEC_COMPONENT_CONFIGURATION: &[u8] =
    b"component=guest-exec;world=eliot:wasm/guest;export=run;imports=closed";

/// Exit status when the guest completed and stdout carries its output.
pub const EXIT_COMPLETED: i32 = 0;
/// Exit status for admission/argument failures (nothing executed).
pub const EXIT_DENIED: i32 = 1;
/// Exit status when the guest ran but did not complete (no output).
pub const EXIT_NOT_COMPLETED: i32 = 2;
/// Exit status when the engine itself could not be built.
pub const EXIT_ENGINE_FAILED: i32 = 3;

/// Validation failures, all pre-invoke. Codes only — no paths or payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestExecRejection {
    /// Artifact file unreadable, empty, or over the artifact ceiling.
    BadArtifact(String),
    /// Input file unreadable or over the input ceiling.
    BadInput(String),
    /// Artifact bytes do not match the admitted digest (TOCTOU/tamper).
    DigestMismatch,
    /// A numeric ceiling is zero or the epoch ticks exceed the admitted max.
    BadLimits(String),
}

impl GuestExecRejection {
    /// Stable code plus process exit status for this rejection.
    #[must_use]
    pub const fn code(&self) -> (&'static str, i32) {
        match self {
            Self::BadArtifact(_) => ("GUEST_EXEC_BAD_ARTIFACT", EXIT_DENIED),
            Self::BadInput(_) => ("GUEST_EXEC_BAD_INPUT", EXIT_DENIED),
            Self::DigestMismatch => ("GUEST_EXEC_ARTIFACT_DIGEST_MISMATCH", EXIT_DENIED),
            Self::BadLimits(_) => ("GUEST_EXEC_BAD_LIMITS", EXIT_DENIED),
        }
    }
}

/// Validated child request: real bytes plus enforced ceilings.
pub struct GuestExecRequest {
    /// Artifact bytes actually read (digest-verified below).
    pub artifact: Vec<u8>,
    /// Input bytes actually read.
    pub input: Vec<u8>,
    /// Store-enforced per-invocation ceilings from the admitted argv.
    pub limits: InvocationLimits,
}

/// Validates pre-read bytes and argv ceilings without executing anything.
pub fn validate_request(
    args: &GuestExecArgs,
    artifact: Vec<u8>,
    input: Vec<u8>,
) -> Result<GuestExecRequest, GuestExecRejection> {
    if artifact.is_empty() {
        return Err(GuestExecRejection::BadArtifact("empty".to_owned()));
    }
    if input.len() as u64 > MAX_GUEST_INPUT_BYTES {
        return Err(GuestExecRejection::BadInput("over-ceiling".to_owned()));
    }
    let actual = Sha256Digest::of_bytes(&artifact);
    if actual.as_str() != args.artifact_digest.as_str() {
        return Err(GuestExecRejection::DigestMismatch);
    }
    if args.max_output_bytes == 0
        || args.max_fuel == 0
        || args.max_memory_bytes == 0
        || args.wall_deadline_ms == 0
        || args.epoch_deadline_ticks == 0
    {
        return Err(GuestExecRejection::BadLimits("zero-ceiling".to_owned()));
    }
    if args.epoch_deadline_ticks > eliot_wasm_runtime::MAX_EPOCH_DEADLINE_TICKS {
        return Err(GuestExecRejection::BadLimits("epoch-ceiling".to_owned()));
    }
    let limits = InvocationLimits {
        max_input_bytes: MAX_GUEST_INPUT_BYTES,
        max_output_bytes: args.max_output_bytes,
        max_host_calls: 0,
        max_fuel: args.max_fuel,
        max_memory_bytes: args.max_memory_bytes,
        max_table_elements: 64,
        max_instances: 2,
        max_stack_bytes: 8_192,
        wall_deadline_ms: args.wall_deadline_ms,
        epoch: EpochPolicy {
            deadline_ticks: args.epoch_deadline_ticks,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: BTreeSet::from([actual]),
            max_reads: 1,
            max_bytes: artifact.len() as u64,
        },
    };
    Ok(GuestExecRequest {
        artifact,
        input,
        limits,
    })
}

/// Runs one admitted guest execution in this process: reads and validates,
/// builds the digest-bound engine, invokes, and projects the outcome onto
/// stdio. Returns the process exit status; stdout carries raw guest output
/// bytes if and only if the guest completed.
#[must_use]
pub fn run_guest_exec(args: &GuestExecArgs) -> i32 {
    let (artifact, preflight) = match read_bounded_artifact(&args.artifact) {
        Ok(pair) => pair,
        Err(error) => return fail(&format!("GUEST_EXEC_BAD_ARTIFACT:{error:?}"), EXIT_DENIED),
    };
    if preflight.digest.as_str() != args.artifact_digest.as_str() {
        return fail("GUEST_EXEC_ARTIFACT_DIGEST_MISMATCH", EXIT_DENIED);
    }
    let input = match std::fs::read(&args.input) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(
                &format!("GUEST_EXEC_BAD_INPUT:{kind}", kind = error.kind()),
                EXIT_DENIED,
            );
        }
    };
    let request = match validate_request(args, artifact, input) {
        Ok(request) => request,
        Err(rejection) => {
            let (code, status) = rejection.code();
            return fail(code, status);
        }
    };
    let engine = match WasmtimeComponentEngine::new_for_admitted_bytes(
        &request.artifact,
        GUEST_EXEC_COMPONENT_CONFIGURATION,
    ) {
        Ok(engine) => engine,
        Err(error) => {
            return fail(
                &format!("GUEST_EXEC_ENGINE_FAILED:{error:?}"),
                EXIT_ENGINE_FAILED,
            );
        }
    };
    let Ok(report) = engine.invoke_bytes(
        &Sha256Digest::of_bytes(&request.input),
        &request.limits,
        &request.input,
    ) else {
        return fail("GUEST_EXEC_INVOKE_DENIED", EXIT_NOT_COMPLETED);
    };
    if !matches!(report.termination, EngineTermination::Completed) {
        return fail(
            &format!(
                "GUEST_EXEC_TERMINATION:{termination:?}",
                termination = report.termination
            ),
            EXIT_NOT_COMPLETED,
        );
    }
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&report.output).is_err() || stdout.flush().is_err() {
        return fail("GUEST_EXEC_OUTPUT_FAILED", EXIT_NOT_COMPLETED);
    }
    EXIT_COMPLETED
}

/// Emits one stderr line; stdout stays empty by construction (this function
/// never touches stdout, so partial output cannot leak through it).
fn fail(code: &str, status: i32) -> i32 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{code}");
    status
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_args() -> GuestExecArgs {
        GuestExecArgs {
            artifact: std::path::PathBuf::from("artifact.bin"),
            input: std::path::PathBuf::from("input.bin"),
            artifact_digest: Sha256Digest::of_bytes(b"artifact-bytes")
                .as_str()
                .to_owned(),
            max_output_bytes: 64,
            max_fuel: 10_000,
            max_memory_bytes: 65_536,
            wall_deadline_ms: 500,
            epoch_deadline_ticks: 100,
        }
    }

    #[test]
    fn valid_bytes_validate_with_enforced_ceilings() {
        let args = test_args();
        let request = validate_request(&args, b"artifact-bytes".to_vec(), b"input".to_vec())
            .expect("valid request");
        assert_eq!(request.limits.max_output_bytes, 64);
        assert_eq!(request.limits.max_fuel, 10_000);
        assert_eq!(request.limits.epoch.deadline_ticks, 100);
        assert!(
            request
                .limits
                .artifact_access
                .allowed_digests
                .contains(&Sha256Digest::of_bytes(b"artifact-bytes"))
        );
    }

    #[test]
    fn tampered_bytes_and_bad_limits_fail_closed() {
        let args = test_args();
        assert_eq!(
            validate_request(&args, b"tampered".to_vec(), b"input".to_vec())
                .map(|_| ())
                .map_err(|rejection| rejection.code().0),
            Err("GUEST_EXEC_ARTIFACT_DIGEST_MISMATCH")
        );
        assert_eq!(
            validate_request(&args, Vec::new(), b"input".to_vec())
                .map(|_| ())
                .map_err(|rejection| rejection.code().0),
            Err("GUEST_EXEC_BAD_ARTIFACT")
        );
        let mut zeroed = test_args();
        zeroed.max_fuel = 0;
        assert_eq!(
            validate_request(&zeroed, b"artifact-bytes".to_vec(), b"input".to_vec())
                .map(|_| ())
                .map_err(|rejection| rejection.code().0),
            Err("GUEST_EXEC_BAD_LIMITS")
        );
        let mut over_ticks = test_args();
        over_ticks.epoch_deadline_ticks = eliot_wasm_runtime::MAX_EPOCH_DEADLINE_TICKS + 1;
        assert_eq!(
            validate_request(&over_ticks, b"artifact-bytes".to_vec(), b"input".to_vec())
                .map(|_| ())
                .map_err(|rejection| rejection.code().0),
            Err("GUEST_EXEC_BAD_LIMITS")
        );
    }
}
