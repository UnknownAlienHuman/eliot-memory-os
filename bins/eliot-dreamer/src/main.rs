use std::io::{self, Write};
use std::process::ExitCode;

use eliot_dreamer::{AuthenticatedKernelJobPort, DreamerError};
use serde::Serialize;

const KERNEL_ADMISSION_EXIT: u8 = 78;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Success { job_id: String, state: String },
    Error { code: &'static str, error: String },
}

fn main() -> ExitCode {
    let mut output = io::BufWriter::new(io::stdout().lock());
    match AuthenticatedKernelJobPort::connect() {
        Ok(port) => {
            let _ = write_response(&mut output, &success_response(port.claimed_view()));
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = write_response(&mut output, &error_response(&error));
            ExitCode::from(KERNEL_ADMISSION_EXIT)
        }
    }
}

fn success_response(view: &eliot_dreamer::JobView) -> Response {
    Response::Success {
        job_id: view.job_id.clone(),
        state: "running".to_owned(),
    }
}

fn error_response(error: &DreamerError) -> Response {
    Response::Error {
        code: error.code(),
        error: error.to_string(),
    }
}

fn write_response(output: &mut impl Write, response: &Response) -> bool {
    serde_json::to_writer(&mut *output, response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_dreamer::{
        DreamJobInput, JobClass, JobView, KernelJobAdmission, KernelSupervisedComposition,
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

    #[test]
    fn stale_deadline_is_rejected_before_kernel_dispatch() {
        let mut stale = admission();
        stale.deadline_unix_ms = 1;
        assert!(matches!(
            stale.validate(),
            Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
        ));
    }
}
