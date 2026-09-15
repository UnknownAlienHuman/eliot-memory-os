#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_process::ProcessExecutor;
use eliot_testd::{
    ADMITTED_WORKER_LEASE_MS, PROTOCOL_VERSION, SERVICE_NAME, TestReceipt, TestdComposition,
    kernel_client::{KernelTestdIpcClient, PresentedAdmission},
    run_admitted_one_shot,
    testd_material::{ValidatedTestdMaterial, read_testd_material},
};

const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const OPERATION: &str = "eliot.instrument.test.execute";

/// Residual: the admitted material carries no executable binding, so no
/// [`ProcessIntent`][eliot_process::ProcessIntent] can be derived without
/// inventing authority. The kernel `TestdAdmissionEnvelope` is exactly
/// `{job_id, operation_id, cancellation, fence}` (no executable, argv,
/// working directory, environment, or limits;
/// `crates/kernel/eliot-kernel-service/src/testd_front_door.rs`), the
/// concrete [`ProcessRequest`][eliot_process::ProcessRequest] is
/// `Serialize`-only by design (neither `Clone` nor `Deserialize`, so the
/// contour never serializes it and this child never deserializes it;
/// `crates/kernel/eliot-process/src/lib.rs`), and this binary owns no
/// registry mapping an admitted profile to an executable binding.
const TESTD_INTENT_RESIDUAL: &str = "issue-20 testd dispatch: admitted material carries no executable binding for ProcessIntent (envelope is job/operation/cancellation/fence only; ProcessRequest is Serialize-only; no profile registry in this binary)";
/// Residual: the broker-mirror dispatch authority cannot be constructed in
/// this composition root. `DispatchValidationContext::new` requires
/// `eliot_platform::ClockObservation`
/// (`crates/kernel/eliot-process/src/lib.rs`), and this binary has no
/// `eliot-platform` dependency and takes none; any `validate_and_consume`
/// without that context would forge validation.
const TESTD_AUTHORITY_RESIDUAL: &str = "issue-20 testd dispatch: DispatchValidationContext requires eliot_platform::ClockObservation, which this composition root does not depend on; no validate_and_consume without it";

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
            // The file validated, so this invocation carries admitted
            // session-bound material. Dispatch still cannot drive: building
            // the in-process permit needs an executable-bound ProcessIntent
            // plus a ClockObservation-bound validation context, and the
            // admitted material supplies neither (see TESTD_INTENT_RESIDUAL
            // and TESTD_AUTHORITY_RESIDUAL). The denial below names both
            // exact absences instead of the former generic dispatch
            // residual; the worker itself stays the admitted one-shot driver
            // and is exercised through `run_admitted_one_shot`.
            deny_presented_without_dispatch(&material)
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

/// Denies a presented-but-undrivable admission without effect.
///
/// The material validated, so admission is genuinely presented; execution is
/// refused only because the two remaining dispatch bindings are absent (see
/// `TESTD_INTENT_RESIDUAL` and `TESTD_AUTHORITY_RESIDUAL`). Prints the
/// exact residuals instead of the former generic dispatch residual and exits
/// 78 like every other pre-drive denial. No admitted outcome ever exits 78.
fn deny_presented_without_dispatch(material: &ValidatedTestdMaterial) -> i32 {
    let _ = writeln!(
        io::stderr(),
        "{KERNEL_ADMISSION_REQUIRED}: service={SERVICE_NAME} protocol={PROTOCOL_VERSION} operation={OPERATION} job={} presented=admitted-material residual_intent={TESTD_INTENT_RESIDUAL} residual_authority={TESTD_AUTHORITY_RESIDUAL}",
        material.job_id,
    );
    EXIT_KERNEL_ADMISSION_REQUIRED
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
        let admission_digest = dcf_canonical_hex(
            &serde_json::json!({"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "request_digest": request_digest, "operation_id": "testd-op-1", "cancelled": false, "admitted_at_unix_nanos": admitted_at}),
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
            "admission": {"wire_id": TESTD_MATERIAL_WIRE_ID, "wire_version": TESTD_MATERIAL_WIRE_VERSION, "job_id": "job-testd-dcf-1", "request_digest": request_digest, "operation_id": "testd-op-1", "cancelled": false, "admitted_at_unix_nanos": admitted_at, "admission_digest": admission_digest},
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
