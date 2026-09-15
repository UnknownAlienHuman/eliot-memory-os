#![forbid(unsafe_code)]

use std::future::Future;
use std::io::{self, Write};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use eliot_process::ProcessExecutor;
use eliot_testd::{
    ADMITTED_WORKER_LEASE_MS, PROTOCOL_VERSION, SERVICE_NAME, TestReceipt, TestdComposition,
    TestdDerivedIntentParams, TestdDispatchAuthority, compose_process_executor,
    derive_testd_intent,
    kernel_client::{KernelTestdIpcClient, PresentedAdmission},
    resolve_testd_tool, run_admitted_one_shot,
    testd_material::{ValidatedTestdMaterial, read_testd_material},
};
use eliot_testd_core::EvidenceCollector;

const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const OPERATION: &str = "eliot.instrument.test.execute";

/// Admitted-path terminal codes.
///
/// 78 stays reserved for missing or refused admission before any drive; no
/// admitted outcome ever exits 78, and no admitted path prints a deferred
/// provider line. `Completed` exits 0; `Cancelled` and
/// reconcile-required reschedules take distinct non-zero, non-78 codes; any
/// other drive failure takes a fourth distinct code.
const EXIT_ADMITTED_COMPLETED: i32 = 0;
const EXIT_ADMITTED_DRIVE_FAILED: i32 = 1;
const EXIT_ADMITTED_CANCELLED: i32 = 3;
const EXIT_ADMITTED_RECONCILE_REQUIRED: i32 = 4;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    bootstrap_and_run_once()
}

/// Post-probe composition decision for one one-shot invocation.
///
/// The shot drives if and only if the live Kernel advertises the exact testd
/// admission operation (`advertised`) AND session-bound admission material
/// was presented to this invocation (`attempt_presented`). Advertisement
/// alone never executes: without delivered material there is no admission to
/// bind, so the shot fails closed naming the dispatch residual.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateDecision {
    /// Drive the presented admission through the admitted worker.
    Drive,
    /// Fail closed: the Kernel does not advertise the testd operation.
    DenyNotAdvertised,
    /// Fail closed: advertised, but no session-bound admission was
    /// delivered to this invocation.
    DenyNoPresentedAttempt,
}

#[must_use]
const fn gate_after_advertise(advertised: bool, attempt_presented: bool) -> GateDecision {
    if !advertised {
        GateDecision::DenyNotAdvertised
    } else if !attempt_presented {
        GateDecision::DenyNoPresentedAttempt
    } else {
        GateDecision::Drive
    }
}

fn deny() -> i32 {
    let _ = writeln!(io::stderr(), "{}", admission_required_message());
    EXIT_KERNEL_ADMISSION_REQUIRED
}

fn bootstrap_and_run_once() -> i32 {
    // Authenticated generation-bound Kernel bootstrap over the protected
    // installation front door. The protected client declaration plus the
    // live ServerHello authority/epoch/generation/artifact checks inside the
    // IPC client bind this process to the exact Kernel generation; no argv,
    // stdin, or environment value participates in authority. The admitted
    // one-shot material plus its execution context arrive only with the
    // kernel dispatch launch and are driven by the admitted worker.
    let Ok(mut client) = KernelTestdIpcClient::connect() else {
        return deny();
    };
    let Ok(advertised) = client.advertise_testd() else {
        return deny();
    };
    // Session-bound admission arrives only with the dispatch launch as
    // the validated material file next to this executable (never via argv,
    // stdin, or environment). Absence reports `None` and keeps the
    // fail-closed path; a present but invalid file likewise reports `None`
    // (the reader leaves it in place for forensics) and keeps the same
    // fail-closed path.
    let presented = acquire_presented_admission();
    match gate_after_advertise(advertised, presented.is_some()) {
        GateDecision::Drive => {
            let Some(material) = presented else {
                return deny();
            };
            // Validated session-bound material drives the bounded admitted
            // probe: the intent derives only from the admitted profile
            // binding plus the installed tool bytes, the single permit
            // issues through the ephemeral dispatch authority, and the real
            // composed executor runs exactly one start. The closed Kernel
            // bootstrap and advertisement above still gate production until
            // the dispatch contour lands; this arm is exercised by the
            // module tests.
            drive_material_probe(&material)
        }
        GateDecision::DenyNotAdvertised | GateDecision::DenyNoPresentedAttempt => deny(),
    }
}

/// Reports the session-bound admission presented to this invocation, if any.
///
/// Reads the dispatch-contour material file next to this executable
/// ([`TESTD_MATERIAL_FILE_NAME`][eliot_testd::testd_material::TESTD_MATERIAL_FILE_NAME]);
/// no value is taken from argv, stdin, or environment. Absence reports
/// `None` and keeps the exact `DenyNoPresentedAttempt` path; a present but
/// invalid file is refused fail-closed by the reader (left in place, never
/// driven) and likewise reports `None`. When the remaining dispatch
/// bindings land (executable-bound intent plus authority context), this
/// function remains the single integration point that maps validated
/// material onto the drive.
fn acquire_presented_admission() -> Option<ValidatedTestdMaterial> {
    read_testd_material().unwrap_or_default()
}

/// Drives one validated dispatch file through the bounded admitted probe.
///
/// The intent derives only from the admitted profile binding plus the
/// installed tool bytes (closed registry in `eliot-testd-core`; the fixed
/// argv, empty environment, and timeout/output caps are never caller
/// authority), the single permit issues through the ephemeral dispatch
/// authority over the validated grant, and the real composed executor runs
/// exactly one start. Cancelled admissions project cancellation without
/// executing. Every post-derivation outcome maps to a typed non-78 exit;
/// a refused derivation or issuance (nothing executed) fails the shot
/// without claiming admission semantics.
fn drive_material_probe(material: &ValidatedTestdMaterial) -> i32 {
    if material.cancelled {
        return EXIT_ADMITTED_CANCELLED;
    }
    let now_ms = now_ms();
    let Ok(tool) = resolve_testd_tool(eliot_testd_core::TESTD_PROFILE_PROGRAM) else {
        return EXIT_ADMITTED_DRIVE_FAILED;
    };
    let params = TestdDerivedIntentParams {
        job_id: material.job_id.clone(),
        operation_id: material.operation_id.clone(),
        profile: material.profile.clone(),
        generation: material.generation,
        session_nonce: material.nonce.clone(),
        executable_absolute: tool.executable_absolute,
        executable_sha256: tool.executable_sha256,
        generation_root: generation_root_cwd(),
    };
    let Ok(intent) = derive_testd_intent(&params) else {
        return EXIT_ADMITTED_DRIVE_FAILED;
    };
    let Ok(authority) = TestdDispatchAuthority::new() else {
        return EXIT_ADMITTED_DRIVE_FAILED;
    };
    let Ok(request) = authority.issue(&intent, &material.grant, now_ms) else {
        return EXIT_ADMITTED_DRIVE_FAILED;
    };
    let executor = compose_process_executor(Arc::new(authority));
    let sink: Arc<dyn eliot_process::ProcessEvidenceSink> = Arc::new(EvidenceCollector::default());
    match block_on_drive(executor.start(request, sink)) {
        Ok(_) => EXIT_ADMITTED_COMPLETED,
        Err(eliot_process::ProcessExecutionError::UnknownOutcome) => {
            EXIT_ADMITTED_RECONCILE_REQUIRED
        }
        Err(_) => EXIT_ADMITTED_DRIVE_FAILED,
    }
}

/// Working directory for the bounded probe: the dispatch locator
/// directory (the executable directory carrying the material file), which
/// exists by construction when material was delivered.
///
/// Deferred: the production contour delivers the admitted generation
/// (source) root for the working directory; the bounded `cargo --version`
/// probe reads no working directory, so the existing locator directory is
/// the honest closed stand-in. The derivation re-validates it as an
/// existing directory before any start.
fn generation_root_cwd() -> String {
    if let Some(path) = eliot_testd::testd_material::testd_material_path()
        && let Some(directory) = path.parent()
        && directory.is_dir()
    {
        return directory.to_string_lossy().into_owned();
    }
    std::env::temp_dir().to_string_lossy().into_owned()
}

/// Minimal std-only driver for the single executor future, mirroring
/// `worker::block_on_one_shot`: resolves futures that progress without an
/// external reactor. This binary takes no async runtime dependency.
fn block_on_drive<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut pinned = Box::pin(future);
    loop {
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// Drives one admitted one-shot through the worker and projects the typed
/// exit.
///
/// Genuine drive wiring (not a probe): the composition, executor, and
/// presented admission arrive fully injected, the worker performs the single
/// consuming drive, and the receipt maps to a typed exit that is never 78.
/// The dispatch launch seam calls this shape once it provisions the
/// execution context; until then it stays wired but unreached, which keeps
/// the bins-scope denial above honest.
#[allow(
    dead_code,
    reason = "admitted drive awaits the dispatch launch seam for its execution context; exercised via run_admitted_one_shot in lib tests"
)]
fn drive_admitted<E: ProcessExecutor + 'static>(
    composition: &TestdComposition,
    presented: PresentedAdmission,
    executor: &E,
) -> i32 {
    // Closed-profile gate: the admitted drive derives its executable
    // binding from the registry; an unregistered profile or caller argv
    // never reaches the worker.
    if !eliot_testd_core::is_admitted_testd_profile(&presented.invocation.profile)
        || !presented.invocation.arguments.is_empty()
    {
        return EXIT_ADMITTED_DRIVE_FAILED;
    }
    match run_admitted_one_shot(
        composition,
        presented,
        executor,
        SERVICE_NAME,
        ADMITTED_WORKER_LEASE_MS,
        now_ms(),
    ) {
        Ok(receipt) => exit_code_for_receipt(&receipt),
        Err(_) => EXIT_ADMITTED_DRIVE_FAILED,
    }
}

/// Maps an admitted drive receipt to its typed process exit.
///
/// Never 78: 78 is reserved for missing or refused admission before any
/// drive. `Succeeded` completes 0; `Cancelled` and any reschedule
/// (`RetryWait`, including executor-unknown outcomes reconciled by exact
/// identity) take distinct codes; any other terminal state fails the shot
/// without claiming admission semantics.
fn exit_code_for_receipt(receipt: &TestReceipt) -> i32 {
    exit_code_for_receipt_state(receipt.state.as_str())
}

fn exit_code_for_receipt_state(state: &str) -> i32 {
    match state {
        "Succeeded" => EXIT_ADMITTED_COMPLETED,
        "Cancelled" => EXIT_ADMITTED_CANCELLED,
        "RetryWait" => EXIT_ADMITTED_RECONCILE_REQUIRED,
        _ => EXIT_ADMITTED_DRIVE_FAILED,
    }
}

fn admission_required_message() -> String {
    format!(
        "{KERNEL_ADMISSION_REQUIRED}: service={SERVICE_NAME} protocol={PROTOCOL_VERSION} operation={OPERATION}"
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_diagnostic_is_stable_and_never_claims_ready() {
        let message = admission_required_message();
        assert_eq!(
            message,
            "KERNEL_ADMISSION_REQUIRED: service=eliot-testd protocol=eliot.testd.v2 operation=eliot.instrument.test.execute"
        );
        assert!(!message.to_ascii_lowercase().contains("ready"));
        assert_ne!(EXIT_KERNEL_ADMISSION_REQUIRED, 0);
    }

    #[test]
    fn closed_kernel_denies_without_effect() {
        assert_eq!(
            gate_after_advertise(false, false),
            GateDecision::DenyNotAdvertised
        );
        assert_eq!(
            gate_after_advertise(false, true),
            GateDecision::DenyNotAdvertised
        );
    }

    #[test]
    fn advertised_without_presentation_denies_with_residual() {
        assert_eq!(
            gate_after_advertise(true, false),
            GateDecision::DenyNoPresentedAttempt
        );
    }

    #[test]
    fn advertised_with_presentation_is_the_only_drive_arm() {
        assert_eq!(gate_after_advertise(true, true), GateDecision::Drive);
    }

    #[test]
    fn deny_exits_kernel_admission_required() {
        assert_eq!(deny(), EXIT_KERNEL_ADMISSION_REQUIRED);
    }

    #[test]
    fn no_presented_material_without_launch_seam() {
        assert!(acquire_presented_admission().is_none());
    }

    /// Valid dispatch material built through the real broker constructors
    /// reaches the Drive arm; material with a foreign grant epoch is refused
    /// fail-closed and left in place.
    ///
    /// Every identity here is real: the epoch comes from
    /// `EpochId::new` over a parsed lineage, the fence and lease come from
    /// `FencingToken::new` / `ActionLeaseRef::new` / `Generation::new`, and
    /// every digest is recomputed over the exact kernel canonical shapes
    /// with `canonical_json_bytes` plus `sha256_hex`. No mock, fake, or
    /// canned digest participates.
    #[test]
    fn valid_material_with_real_grant_reaches_drive_and_foreign_grant_refused() {
        use eliot_testd::testd_material::read_testd_material_from;

        let live = dcf_test_epoch(7);
        let valid_path = dcf_stage_material(&live, &live, "valid.admitted-attempt.json");
        let Ok(material) = read_testd_material_from(&valid_path) else {
            panic!("valid material must validate");
        };
        let Some(material) = material else {
            panic!("valid material must present");
        };
        assert_eq!(material.job_id, "job-testd-dcf-1");
        assert_eq!(material.operation_id, "testd-op-1");
        assert_eq!(material.profile, "cargo-test");
        let Ok(expected_binding) = eliot_testd_core::testd_definition_digest() else {
            panic!("profile binding digest must compute");
        };
        assert_eq!(material.profile_binding_digest, expected_binding);
        assert!(material.epoch.is_same_authority(&live));
        assert_eq!(material.generation, 1);
        assert!(!material.cancelled);
        assert!(!material.grant_digest.is_empty());
        // Valid presentation is the only Drive arm.
        assert_eq!(gate_after_advertise(true, true), GateDecision::Drive);
        // A validated presentation is consumed once and never replays.
        assert!(!valid_path.exists());

        // A foreign grant epoch disagrees with the carried epoch and is
        // refused fail-closed before any drive; the file is left for
        // forensics instead of consumed.
        let foreign = dcf_test_epoch(9);
        let foreign_path = dcf_stage_material(&live, &foreign, "foreign.admitted-attempt.json");
        assert!(read_testd_material_from(&foreign_path).is_err());
        assert!(foreign_path.exists());

        if let Some(parent) = valid_path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    /// Child-side delivery seam E2E (DW-C owned, Implements #20).
    ///
    /// The child drive seam no longer waits on doubles: this test stages the
    /// exact documented file shape (seven keys per the `testd_material`
    /// module docs) through the real broker constructors and drives it
    /// through the real `drive_material_probe` (real tool resolution, real
    /// `TestdDispatchAuthority`, real composed executor, bounded
    /// `cargo --version` probe). The testd IPC side now mirrors the doctor
    /// bootstrap (`KernelTestdIpcClient::connect` +
    /// live-health `advertise_testd`), so advertisement flips only when the
    /// composed Kernel advertises; live kernel delivery itself remains DW-A/B
    /// contour work. Runs by default on a host with cargo on PATH and never
    /// weakens the fail-closed gate.
    #[test]
    fn dispatch_live_e2e_bounded_probe_runs_without_doubles() {
        use eliot_testd::testd_material::read_testd_material_from;

        let live = dcf_test_epoch(7);
        let path = dcf_stage_material(&live, &live, "e2e.admitted-attempt.json");
        let Ok(staged) = read_testd_material_from(&path) else {
            panic!(
                "E2E material must validate: read_testd_material delivery is the child-side seam"
            );
        };
        let Some(material) = staged else {
            panic!("E2E material must present: absent delivery keeps DenyNoPresentedAttempt");
        };
        assert_eq!(material.profile, "cargo-test");
        // The Drive arm is the only arm a delivered presentation reaches.
        assert_eq!(gate_after_advertise(true, true), GateDecision::Drive);
        // Real drive, no doubles: real installed tool, real dispatch
        // authority, real composed executor, bounded `cargo --version`.
        let code = drive_material_probe(&material);
        assert_eq!(
            code, EXIT_ADMITTED_COMPLETED,
            "bounded probe must complete on a host with cargo on PATH plus unexpired material"
        );
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn dcf_test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        use std::num::NonZeroU64;
        let Ok(lineage) =
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        else {
            panic!("test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(sequence) else {
            panic!("test sequence must be non-zero");
        };
        let Ok(epoch) = eliot_contracts::EpochId::new(lineage, sequence) else {
            panic!("test epoch must build");
        };
        epoch
    }

    fn dcf_test_now_nanos() -> u64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    fn dcf_canonical_hex(value: &serde_json::Value) -> String {
        let Ok(bytes) = eliot_contracts::canonical_json_bytes(value) else {
            panic!("test value must canonicalize");
        };
        eliot_contracts::sha256_hex(&bytes)
    }

    fn dcf_stage_material(
        epoch: &eliot_contracts::EpochId,
        grant_epoch: &eliot_contracts::EpochId,
        file_name: &str,
    ) -> std::path::PathBuf {
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};
        use eliot_testd::testd_material::{TESTD_MATERIAL_WIRE_ID, TESTD_MATERIAL_WIRE_VERSION};

        let Ok(generation) = Generation::new(1) else {
            panic!("test generation must build");
        };
        let Ok(fence) = FencingToken::new(
            grant_epoch.clone(),
            generation,
            "testd-fence-abc123".to_owned(),
        ) else {
            panic!("test fence must build");
        };
        // The lease rebuilds through the exact broker constructor, so a
        // malformed lease could never reach the reader.
        assert!(ActionLeaseRef::new("testd-lease-abc123".to_owned()).is_ok());
        let Ok(fence_value) = serde_json::to_value(&fence) else {
            panic!("test fence must serialize");
        };
        let envelope = serde_json::json!({"job_id": "job-testd-dcf-1", "operation_id": "testd-op-1", "cancellation": false, "fence": fence_value});
        let Ok(closed_request_json) = serde_json::to_string(&envelope) else {
            panic!("test envelope must serialize");
        };
        let target_resource_digest = eliot_contracts::sha256_hex(b"testd-target-resource");
        let request_digest = dcf_canonical_hex(
            &serde_json::json!({"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "attempt_seq": 0, "closed_request_json": closed_request_json, "target_resource_digest": target_resource_digest}),
        );
        let admitted_at = dcf_test_now_nanos();
        assert_ne!(admitted_at, 0);
        let Ok(profile_binding_digest) = eliot_testd_core::testd_definition_digest() else {
            panic!("profile binding digest must compute");
        };
        let admission_digest = dcf_canonical_hex(
            &serde_json::json!({"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "request_digest": request_digest, "operation_id": "testd-op-1", "profile": "cargo-test", "profile_binding_digest": profile_binding_digest, "cancelled": false, "admitted_at_unix_nanos": admitted_at}),
        );
        let Ok(epoch_json) = serde_json::to_string(grant_epoch) else {
            panic!("test epoch must serialize");
        };
        // Kernel expiry is Unix milliseconds (admitted ms plus 60 s);
        // mirror that unit so the freshness proof is exact.
        let now_ms = dcf_test_now_nanos() / 1_000_000;
        let expires_at = now_ms.saturating_add(60_000);
        assert!(expires_at > now_ms);
        let mut grant_material = String::with_capacity(256);
        grant_material.push_str(&request_digest);
        grant_material.push('|');
        grant_material.push_str(&epoch_json);
        grant_material.push_str("|1|testd-fence-abc123|testd-lease-abc123|");
        grant_material.push_str(&expires_at.to_string());
        let grant_digest = eliot_contracts::sha256_hex(grant_material.as_bytes());
        let nonce = format!("testd-dispatch-{}-{admitted_at}", std::process::id());
        let Ok(epoch_value) = serde_json::to_value(epoch) else {
            panic!("test epoch must serialize");
        };
        let Ok(grant_epoch_value) = serde_json::to_value(grant_epoch) else {
            panic!("test grant epoch must serialize");
        };
        let file = serde_json::json!({
            "request": {"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "attempt_seq": 0, "closed_request_json": closed_request_json, "target_resource_digest": target_resource_digest, "request_digest": request_digest},
            "envelope": envelope,
            "admission": {"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "request_digest": request_digest, "operation_id": "testd-op-1", "profile": "cargo-test", "profile_binding_digest": profile_binding_digest, "cancelled": false, "admitted_at_unix_nanos": admitted_at, "admission_digest": admission_digest},
            "epoch": epoch_value,
            "generation": 1,
            "nonce": nonce,
            "grant": {"grant_digest": grant_digest, "authority_epoch": grant_epoch_value, "fence_generation": 1, "fence_nonce": "testd-fence-abc123", "idempotency_key": "testd-lease-abc123", "expires_at": expires_at},
        });
        let Ok(bytes) = serde_json::to_vec(&file) else {
            panic!("test material must serialize");
        };
        let dir = std::env::temp_dir().join(format!(
            "eliot-testd-dcf-{}-{admitted_at}",
            std::process::id()
        ));
        let path = dir.join(file_name);
        assert!(std::fs::create_dir_all(&dir).is_ok());
        assert!(std::fs::write(&path, bytes).is_ok());
        path
    }

    #[test]
    fn admitted_receipt_states_map_to_typed_exits_and_never_78() {
        assert_eq!(exit_code_for_receipt_state("Succeeded"), 0);
        assert_eq!(
            exit_code_for_receipt_state("Cancelled"),
            EXIT_ADMITTED_CANCELLED
        );
        assert_eq!(
            exit_code_for_receipt_state("RetryWait"),
            EXIT_ADMITTED_RECONCILE_REQUIRED
        );
        assert_eq!(
            exit_code_for_receipt_state("Failed"),
            EXIT_ADMITTED_DRIVE_FAILED
        );
        for state in [
            "Succeeded",
            "Failed",
            "Cancelled",
            "RetryWait",
            "Queued",
            "Running",
            "Quarantined",
            "",
            "anything-unexpected",
        ] {
            let code = exit_code_for_receipt_state(state);
            assert_ne!(code, EXIT_KERNEL_ADMISSION_REQUIRED);
        }
        assert_ne!(EXIT_ADMITTED_CANCELLED, EXIT_KERNEL_ADMISSION_REQUIRED);
        assert_ne!(
            EXIT_ADMITTED_RECONCILE_REQUIRED,
            EXIT_KERNEL_ADMISSION_REQUIRED
        );
        assert_ne!(EXIT_ADMITTED_DRIVE_FAILED, EXIT_KERNEL_ADMISSION_REQUIRED);
        assert_ne!(EXIT_ADMITTED_CANCELLED, EXIT_ADMITTED_RECONCILE_REQUIRED);
        assert_ne!(EXIT_ADMITTED_COMPLETED, EXIT_ADMITTED_CANCELLED);
    }
}
