use std::io::{self, Write};
use std::process::ExitCode;

use eliot_dreamer::{
    AuthenticatedKernelJobPort, DreamerError, JobState, JobView, KernelSupervisedComposition,
};
use serde::Serialize;

const KERNEL_ADMISSION_EXIT: u8 = 78;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    #[allow(
        dead_code,
        reason = "retained for the success_response_projects_proved_state proof; the binary edge emits the JobView receipt instead"
    )]
    Success { job_id: String, state: String },
    Error { code: &'static str, error: String },
}

fn main() -> ExitCode {
    // Slice-8 terminal channel split (issue #702):
    // - stdout carries exactly one JSONL [`JobView`] receipt line on success
    //   (via `write_view`), and nothing on failure;
    // - stderr carries the [`Response`] error JSON (via `write_error_stderr`)
    //   plus human/log diagnostics, never a receipt.
    // A log line can therefore never be mistaken for a receipt. No process is
    // launched and no file is written here.
    let mut output = io::BufWriter::new(io::stdout().lock());
    let port = match AuthenticatedKernelJobPort::connect() {
        Ok(port) => port,
        Err(error) => {
            write_error_stderr(&error);
            return ExitCode::from(KERNEL_ADMISSION_EXIT);
        }
    };
    // The claim (`LeaseExact` then `Start`) already proved admission. The
    // supervised loop confirms the live Kernel-proved disposition through
    // `Status` and projects exactly that: no hardcoded state, no local
    // terminal invention. Any denial fails closed with exit 78.
    let admission = port.claimed_admission().clone();
    let mut service = match KernelSupervisedComposition::connect(port) {
        Ok(service) => service,
        Err(error) => {
            write_error_stderr(&error);
            return ExitCode::from(KERNEL_ADMISSION_EXIT);
        }
    };
    match service.status(&admission) {
        Ok(view) => {
            if !write_view(&mut output, &view) {
                write_error_stderr(&DreamerError::InvalidAdmission("result encoding failure"));
                return ExitCode::from(KERNEL_ADMISSION_EXIT);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            write_error_stderr(&error);
            ExitCode::from(KERNEL_ADMISSION_EXIT)
        }
    }
}

/// Test-pinned success receipt projection: retained so the proved-state
/// rendering stays covered by proof while the binary edge emits the
/// [`JobView`] receipt line.
#[allow(
    dead_code,
    reason = "retained for the success_response_projects_proved_state proof; the binary edge emits the JobView receipt instead"
)]
fn success_response(view: &eliot_dreamer::JobView) -> Response {
    Response::Success {
        job_id: view.job_id.clone(),
        state: state_name(view.state).to_owned(),
    }
}

/// Projects the proved local disposition. Exhaustive: a new lifecycle state
/// fails compilation here instead of rendering a wrong receipt.
#[allow(
    dead_code,
    reason = "retained for the success_response_projects_proved_state proof alongside success_response"
)]
fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Completed => "completed",
        JobState::Cancelled => "cancelled",
        JobState::Rejected => "rejected",
        JobState::Partial => "partial",
        JobState::Failed => "failed",
        JobState::Reconciling => "reconciling",
    }
}

fn error_response(error: &DreamerError) -> Response {
    Response::Error {
        code: error.code(),
        error: error.to_string(),
    }
}

/// Writes one receipt line (`line` + `\n`) to the locked stdout, flushed.
///
/// The caller supplies the already-serialized single line so stdout carries
/// machine-readable receipt bytes only; diagnostics and logs belong on stderr
/// (`eprintln!`) at call sites.
fn write_response(output: &mut impl Write, line: &str) -> bool {
    output.write_all(line.as_bytes()).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

/// Serializes one Kernel-proved [`JobView`] as exactly one JSONL line on
/// stdout and nothing else.
///
/// [`serde_json::to_string`] emits no literal newlines (control characters
/// inside strings are escaped), so the receipt is a single line that
/// round-trips to the identical view. An encoding failure returns `false` so
/// the caller can refuse fail-closed on stderr with exit 78; stdout then
/// carries no partial receipt.
fn write_view(output: &mut impl Write, view: &JobView) -> bool {
    match serde_json::to_string(view) {
        Ok(line) => write_response(output, &line),
        Err(_) => false,
    }
}

/// Reports a fail-closed refusal on stderr as [`Response`] error JSON.
///
/// Stdout carries nothing on failure: exactly one receipt line on success,
/// zero lines otherwise. A broken stderr cannot be refused through (there is
/// no further channel); the process exit code remains the refusal signal.
#[allow(
    clippy::print_stderr,
    reason = "the Slice-8 channel split requires diagnostics on stderr so stdout carries receipts only"
)]
fn write_error_stderr(error: &DreamerError) {
    match serde_json::to_string(&error_response(error)) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!(
            r#"{{"status":"error","code":"DREAMER_REQUEST_REJECTED","error":"result encoding failure"}}"#
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_dreamer::{
        DreamJobInput, JobClass, JobState, JobView, KernelJobAdmission, KernelSupervisedComposition,
    };
    use std::collections::VecDeque;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    struct ClosedKernel {
        handshake: Result<eliot_dreamer::KernelHandshake, DreamerError>,
        responses: VecDeque<Result<JobView, DreamerError>>,
    }

    impl eliot_dreamer::KernelJobPort for ClosedKernel {
        fn handshake(&mut self) -> Result<eliot_dreamer::KernelHandshake, DreamerError> {
            match &self.handshake {
                Ok(handshake) => Ok(*handshake),
                Err(error) => Err(DreamerError::KernelAdmissionRequired(error.to_string())),
            }
        }

        fn submit(
            &mut self,
            _admission: &KernelJobAdmission,
            _job: &DreamJobInput,
        ) -> Result<JobView, DreamerError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(DreamerError::KernelAdmissionRequired("closed".to_owned())))
        }

        fn cancel(&mut self, _admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(DreamerError::KernelAdmissionRequired("closed".to_owned())))
        }

        fn status(&mut self, _admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(DreamerError::KernelAdmissionRequired("closed".to_owned())))
        }

        fn reconcile(&mut self, _admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(DreamerError::KernelAdmissionRequired("closed".to_owned())))
        }
    }

    fn admission() -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            request_id: "request-1".to_owned(),
            idempotency_key: "job-1:attempt-1".to_owned(),
            cancellation_id: "cancel-1".to_owned(),
            deadline_unix_ms: u64::MAX,
            state_fence: StateFence::new(test_epoch(1), ResourceGeneration::genesis()),
        }
    }

    #[test]
    fn missing_kernel_handshake_never_constructs_ready_service() {
        let result = KernelSupervisedComposition::connect(ClosedKernel {
            handshake: Err(DreamerError::KernelAdmissionRequired("missing".to_owned())),
            responses: VecDeque::new(),
        });
        assert!(matches!(
            result,
            Err(DreamerError::KernelAdmissionRequired(_))
        ));
    }

    #[test]
    fn bad_kernel_handshake_never_constructs_ready_service() {
        let result = KernelSupervisedComposition::connect(ClosedKernel {
            handshake: Ok(eliot_dreamer::KernelHandshake {
                authority_epoch: 0,
                dreamer_claim_supported: true,
            }),
            responses: VecDeque::new(),
        });
        assert!(matches!(
            result,
            Err(DreamerError::KernelAdmissionRequired(_))
        ));
    }

    #[test]
    fn open_health_without_dreamer_claim_never_constructs_ready_service() {
        let result = KernelSupervisedComposition::connect(ClosedKernel {
            handshake: Ok(eliot_dreamer::KernelHandshake {
                authority_epoch: 1,
                dreamer_claim_supported: false,
            }),
            responses: VecDeque::new(),
        });
        assert!(matches!(
            result,
            Err(DreamerError::KernelAdmissionRequired(_))
        ));
    }

    #[test]
    fn replay_and_cancel_are_fail_closed_without_local_terminal_state() {
        let result = KernelSupervisedComposition::connect(ClosedKernel {
            handshake: Ok(eliot_dreamer::KernelHandshake {
                authority_epoch: 1,
                dreamer_claim_supported: true,
            }),
            responses: VecDeque::from([
                Err(DreamerError::KernelAdmissionRequired(
                    "replay unavailable".to_owned(),
                )),
                Err(DreamerError::KernelAdmissionRequired(
                    "cancel unavailable".to_owned(),
                )),
            ]),
        });
        assert!(result.is_ok());
        let Ok(mut service) = result else {
            return;
        };
        let admission = admission();
        assert_eq!(
            service.status(&admission).map_err(|error| error.code()),
            Err(eliot_dreamer::KERNEL_ADMISSION_REQUIRED)
        );
        assert_eq!(
            service.cancel(&admission).map_err(|error| error.code()),
            Err(eliot_dreamer::KERNEL_ADMISSION_REQUIRED)
        );
    }

    #[test]
    fn caller_cannot_switch_admitted_job_or_fence() {
        let result = KernelSupervisedComposition::connect(ClosedKernel {
            handshake: Ok(eliot_dreamer::KernelHandshake {
                authority_epoch: 1,
                dreamer_claim_supported: true,
            }),
            responses: VecDeque::from([Err(DreamerError::KernelAdmissionRequired(
                "not reached".to_owned(),
            ))]),
        });
        let Ok(mut service) = result else {
            return;
        };
        let admission = admission();
        let mut job = DreamJobInput {
            job_id: admission.job_id.clone(),
            job_class: JobClass::Orientation,
            exact_question: "question".to_owned(),
            requester: "requester".to_owned(),
            scope_id: admission.scope_id.clone(),
            task_id: None,
            state_fence: "kernel-owned".to_owned(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["kernel-route".to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "candidate".to_owned(),
            forbidden_effects: Vec::new(),
        };
        job.job_id = "caller-switched-job".to_owned();
        assert_eq!(
            service
                .submit(&admission, &job)
                .map_err(|error| error.code()),
            Err(eliot_dreamer::KERNEL_ADMISSION_REQUIRED)
        );
        let mut switched = admission;
        let switched_epoch = test_epoch(2);
        switched.state_fence.authority_epoch = switched_epoch;
        assert_eq!(
            service.status(&switched).map_err(|error| error.code()),
            Err(eliot_dreamer::KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// The terminal receipt projects the Kernel-proved disposition: every
    /// lifecycle state renders under its own name, so a reconciling or
    /// failed job can never masquerade as running.
    #[test]
    fn success_response_projects_proved_state() {
        for (state, name) in [
            (JobState::Queued, "queued"),
            (JobState::Running, "running"),
            (JobState::Completed, "completed"),
            (JobState::Cancelled, "cancelled"),
            (JobState::Rejected, "rejected"),
            (JobState::Partial, "partial"),
            (JobState::Failed, "failed"),
            (JobState::Reconciling, "reconciling"),
        ] {
            let response = success_response(&JobView {
                job_id: "job-1".to_owned(),
                state,
                result: None,
            });
            let Response::Success {
                job_id,
                state: projected,
            } = response
            else {
                panic!("proved view must project a success receipt");
            };
            assert_eq!(job_id, "job-1");
            assert_eq!(projected, name);
        }
    }

    #[test]
    fn stale_deadline_is_rejected_before_kernel_dispatch() {
        let mut stale = admission();
        stale.deadline_unix_ms = 1;
        assert!(matches!(
            stale.validate(),
            Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
        ));
    }

    /// The stdout receipt is exactly one JSONL [`JobView`] line: a single
    /// `\n`-terminated line with no embedded carriage returns that decodes to
    /// the identical view. Nothing but the receipt reaches stdout on success.
    #[test]
    fn stdout_receipt_is_one_jobview_line() {
        let view = JobView {
            job_id: "job-1".to_owned(),
            state: JobState::Completed,
            result: None,
        };
        let mut buf = Vec::new();
        assert!(write_view(&mut buf, &view), "stdout receipt must emit");
        let line = String::from_utf8(buf).expect("receipt is UTF-8");
        assert!(line.ends_with('\n'), "receipt must be newline terminated");
        let body = line.trim_end_matches('\n');
        assert!(
            !body.contains('\n') && !body.contains('\r'),
            "receipt must be a single line, got {line:?}"
        );
        let back: JobView = serde_json::from_str(body).expect("receipt must decode");
        assert_eq!(back, view);
    }

    /// The stderr refusal keeps the [`Response`] error shape: an
    /// `error`-tagged object carrying the typed refusal code, so a failure
    /// line is never mistaken for a receipt.
    #[test]
    fn stderr_error_renders_response_error_shape() {
        let error = DreamerError::KernelAdmissionRequired("closed".to_owned());
        let line = serde_json::to_string(&error_response(&error)).expect("error must render");
        let value: serde_json::Value = serde_json::from_str(&line).expect("error must decode");
        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("error")
        );
        assert_eq!(
            value.get("code").and_then(serde_json::Value::as_str),
            Some(error.code())
        );
    }
}
