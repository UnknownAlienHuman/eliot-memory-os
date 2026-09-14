#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_process::ProcessExecutor;
use eliot_testd::{
    ADMITTED_WORKER_LEASE_MS, PROTOCOL_VERSION, SERVICE_NAME, TestReceipt, TestdComposition,
    kernel_client::{KernelTestdIpcClient, PresentedAdmission, TESTD_DISPATCH_RESIDUAL},
    run_admitted_one_shot,
};

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
    // in-memory state (the concrete process request is never deserialized,
    // so no byte surface can present it). Until that seam lands, every
    // invocation reports absence and keeps the fail-closed path.
    let presented = acquire_presented_admission();
    match gate_after_advertise(advertised, presented.is_some()) {
        GateDecision::Drive => {
            let Some(material) = presented else {
                return deny();
            };
            // The dispatch launch seam provisions the execution context
            // (durable store handle plus bound executor) alongside the
            // material; this binary invents neither a store path nor
            // executor authority, so the drive below stays wired but
            // unreached until that delivery lands
            // (residual=`TESTD_DISPATCH_RESIDUAL`). Drive still denies in
            // bins scope; the worker itself is the admitted one-shot driver
            // and is exercised through `run_admitted_one_shot`.
            let _ = material;
            let _ = TESTD_DISPATCH_RESIDUAL;
            deny()
        }
        GateDecision::DenyNotAdvertised | GateDecision::DenyNoPresentedAttempt => deny(),
    }
}

/// Reports the session-bound admission presented to this invocation, if any.
///
/// The envelope plus the concrete in-memory process request plus the live
/// epoch arrive only with the kernel dispatch launch as process-inherited
/// state, never via argv, stdin, environment, or files. Until that launch
/// seam lands ([`TESTD_DISPATCH_RESIDUAL`]), no invocation presents material
/// and this reports absence, keeping the exact `DenyNoPresentedAttempt` path.
/// When the seam lands, this function is its single integration point: it
/// will return the delivered [`PresentedAdmission`] instead of absence.
fn acquire_presented_admission() -> Option<PresentedAdmission> {
    None
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
