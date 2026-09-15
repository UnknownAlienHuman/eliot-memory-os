#![forbid(unsafe_code)]

//! Governed one-shot Doctor composition root.
//!
//! Argument and config decoding, authenticated Kernel bootstrap, one-shot
//! lifecycle, typed shutdown, and terminal receipt projection live here.
//! Deterministic mechanics live in the owner crates (`eliot-doctor-core`
//! for the closed contract, `eliot-process` for the governed contour); the
//! single narrow adapter lives in the adjacent `admitted_effect` module and
//! the authenticated exchange plus the one-shot driver live in the adjacent
//! `kernel_client` module. This root never launches a native process
//! directly, never accepts recipe or effect authority from argv, stdin, or
//! environment, and never claims a repair: without a Kernel-issued admission
//! it exits 78.

mod dispatch_authority;
mod dispatched_material;
mod kernel_client;

use std::io::Write as _;

use eliot_doctor::admitted_effect::{
    BootstrapAction, EXIT_EVIDENCE_FLUSH_FAILED, EXIT_KERNEL_ADMISSION_REQUIRED, EvidenceCollector,
    admission_required_line, decode_bootstrap_args, help_text, version_line,
};
use eliot_doctor_core::KernelDoctorClient;

use kernel_client::KernelDoctorIpcClient;

fn main() {
    std::process::exit(run(&std::env::args().collect::<Vec<String>>()));
}

fn run(argv: &[String]) -> i32 {
    match decode_bootstrap_args(argv) {
        Ok(BootstrapAction::Help) => emit_text(&help_text()),
        Ok(BootstrapAction::Version) => emit_text(&version_line()),
        Ok(BootstrapAction::Run(_)) => bootstrap_and_run_once(),
        Err(error) => {
            deny(&error.to_string());
            error.exit_code()
        }
    }
}

fn emit_text(text: &str) -> i32 {
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{text}") {
        Ok(()) => match stdout.flush() {
            Ok(()) => 0,
            Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
        },
        Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
    }
}

fn deny(detail: &str) -> i32 {
    let line = admission_required_line(detail);
    let _ = writeln!(std::io::stderr(), "{line}");
    EXIT_KERNEL_ADMISSION_REQUIRED
}

/// Post-probe composition decision for one one-shot invocation.
///
/// The shot drives if and only if the live Kernel advertises the exact
/// doctor repair-attempt operation (`advertised`) AND the dispatch contour
/// delivered a session-bound attempt presentation to this invocation
/// (`attempt_presented`: a dispatch file validated against the live
/// bootstrap epoch, carrying the envelope bytes plus the session binding
/// the real effect adapter binds). Advertisement alone never executes:
/// without delivered bytes there is no admission to bind, so the shot
/// fails closed naming the dispatch residual. The presentation is read from
/// the bins-local dispatch file next to this executable (see
/// `dispatched_material`), never from argv, stdin, or environment; an
/// absent or invalid file presents `false` (invalid files additionally deny
/// with their typed detail before the gate is reached). The `Drive` arm
/// names the rule the dispatch contour must satisfy, and
/// `drive_validated_dispatched_attempt` is the only production driver
/// (`drive_admitted_attempt` remains as the test-reference legacy path).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateDecision {
    /// Drive the delivered attempt through `drive_validated_dispatched_attempt`.
    Drive,
    /// Fail closed: the Kernel does not advertise the doctor operation.
    DenyNotAdvertised,
    /// Fail closed: advertised, but no session-bound attempt was
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

fn bootstrap_and_run_once() -> i32 {
    // Authenticated generation-bound Kernel bootstrap over the protected
    // installation front door. The protected client declaration plus the
    // live ServerHello authority/epoch/generation/artifact checks inside
    // the IPC client bind this process to the exact Kernel generation; no
    // argv, stdin, or environment value participates in authority.
    // The admitted attempt envelope plus the Kernel-issued launch grant
    // arrive with the dispatch contour and are validated by
    // `dispatched_material`; the concrete process intent is derived
    // in-process ONLY from the Kernel-admitted executable binding, issued
    // by the local dispatch authority, and driven on the real
    // `WindowsProcessExecutor` (broker-mirror).
    let mut client = match KernelDoctorIpcClient::connect() {
        Ok(client) => client,
        Err(error) => return deny(&error.to_string()),
    };
    match client.advertise_doctor() {
        Ok(advertised) => {
            // Session-bound attempt material arrives only over the
            // bins-local dispatch file next to this executable (see
            // `dispatched_material`): envelope bytes plus the session
            // nonce/generation/epoch binding, validated against the live
            // bootstrap epoch before the gate is reached. Never argv,
            // stdin, or environment. A missing file presents nothing; a
            // present but invalid file denies here with its typed detail.
            let live_epoch = client.live_epoch().cloned();
            let validated = match live_epoch {
                Some(ref epoch) => match dispatched_material::read_dispatched_material(epoch) {
                    Ok(material) => material,
                    Err(error) => return deny(&error.to_string()),
                },
                None => None,
            };
            match gate_after_advertise(advertised, validated.is_some()) {
                GateDecision::Drive => {
                    let Some(material) = validated else {
                        return deny(
                            "kernel advertises the doctor operation but no session-bound attempt envelope was presented to this one-shot invocation",
                        );
                    };
                    drive_presented_attempt(&mut client, &material)
                }
                GateDecision::DenyNotAdvertised => {
                    deny("kernel does not advertise the doctor operation")
                }
                GateDecision::DenyNoPresentedAttempt => deny(
                    "kernel advertises the doctor operation but no session-bound attempt envelope was presented to this one-shot invocation",
                ),
            }
        }
        Err(error) => deny(&error.to_string()),
    }
}

/// Drives one validated session-bound presentation to exactly one typed
/// outcome: the intent derives ONLY from the admitted binding, the permit
/// issues through the child dispatch authority, and the effect runs on the
/// real governed executor. Missing/refused admission stays exit 78 without
/// effect; post-admission outcomes emit their typed report and exit.
fn drive_presented_attempt(
    client: &mut KernelDoctorIpcClient,
    material: &dispatched_material::ValidatedDispatchedAttempt,
) -> i32 {
    use std::sync::Arc;

    use eliot_process_executor::WindowsProcessExecutor;

    use dispatch_authority::DoctorDispatchAuthority;
    use kernel_client::drive_validated_dispatched_attempt;

    let Some(generation_root) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
    else {
        return deny("dispatch executable locator is unavailable");
    };
    let authority = match DoctorDispatchAuthority::new() {
        Ok(authority) => Arc::new(authority),
        Err(error) => return deny(&error.to_string()),
    };
    let concrete_clone = Arc::clone(&authority);
    let executor_authority: Arc<dyn eliot_process_executor::DispatchValidationPort> =
        concrete_clone;
    let executor = WindowsProcessExecutor::new(executor_authority);
    let sink = Arc::new(EvidenceCollector::new());
    let now_ms = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        Err(_) => return deny("dispatch clock is unavailable"),
    };
    let now = time::OffsetDateTime::now_utc();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return deny(&error.to_string()),
    };
    match runtime.block_on(drive_validated_dispatched_attempt(
        client,
        &authority,
        Arc::new(executor),
        sink,
        material,
        &generation_root,
        now,
        now_ms,
    )) {
        Ok(outcome) => {
            let code = outcome.exit_code();
            let mut stdout = std::io::stdout().lock();
            match writeln!(stdout, "{}", outcome.wire) {
                Ok(()) => match stdout.flush() {
                    Ok(()) => code,
                    Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
                },
                Err(_) => EXIT_EVIDENCE_FLUSH_FAILED,
            }
        }
        Err(error) => {
            let code = error.exit_code();
            if code == EXIT_KERNEL_ADMISSION_REQUIRED {
                deny(&error.to_string())
            } else {
                let _ = writeln!(std::io::stderr(), "doctor drive failed: {error}");
                code
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn advertised_without_presentation_denies() {
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
        assert_eq!(deny("test detail"), EXIT_KERNEL_ADMISSION_REQUIRED);
    }
}
