use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use eliot_dreamer::{
    AuthenticatedKernelJobPort, DreamJobInput, DreamerError, JobView, KernelJobAdmission,
    KernelSupervisedComposition, PROTOCOL_VERSION, SERVICE_NAME,
};
use serde::{Deserialize, Serialize};

const KERNEL_ADMISSION_EXIT: u8 = 78;
const MAX_REQUESTS: usize = 128;
const IDLE_EXIT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "Request is a public JSON protocol surface; boxing would change its deserialized API shape"
)]
enum Request {
    Submit {
        admission: KernelJobAdmission,
        job: DreamJobInput,
    },
    Cancel {
        admission: KernelJobAdmission,
    },
    Status {
        admission: KernelJobAdmission,
    },
    Reconcile {
        admission: KernelJobAdmission,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "Response is a public JSON protocol surface; boxing would change its serialized API shape"
)]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
        transport: &'static str,
    },
    Job {
        view: JobView,
    },
    Error {
        code: &'static str,
        error: String,
    },
}

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let port = match AuthenticatedKernelJobPort::connect() {
        Ok(port) => port,
        Err(error) => {
            let _ = write_response(&mut output, &error_response(&error));
            return ExitCode::from(KERNEL_ADMISSION_EXIT);
        }
    };
    let mut service = match KernelSupervisedComposition::connect(port) {
        Ok(service) => service,
        Err(error) => {
            let _ = write_response(&mut output, &error_response(&error));
            return ExitCode::from(KERNEL_ADMISSION_EXIT);
        }
    };
    if !write_response(
        &mut output,
        &Response::Ready {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            transport: "authenticated_kernel_front_door",
        },
    ) {
        return ExitCode::SUCCESS;
    }

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in stdin.lock().lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    for _ in 0..MAX_REQUESTS {
        let line = match receiver.recv_timeout(IDLE_EXIT) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => {
                if !write_response(&mut output, &error_response(&io_error(&error))) {
                    break;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = dispatch(&mut service, &line);
        if !write_response(&mut output, &response) {
            break;
        }
    }
    ExitCode::SUCCESS
}

fn dispatch(
    service: &mut KernelSupervisedComposition<AuthenticatedKernelJobPort>,
    line: &str,
) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                code: "DREAMER_REQUEST_REJECTED",
                error: format!("request: {error}"),
            };
        }
    };
    let result = match request {
        Request::Submit { admission, job } => service.submit(&admission, &job),
        Request::Cancel { admission } => service.cancel(&admission),
        Request::Status { admission } => service.status(&admission),
        Request::Reconcile { admission } => service.reconcile(&admission),
    };
    result.map_or_else(
        |error| error_response(&error),
        |view| Response::Job { view },
    )
}

fn error_response(error: &DreamerError) -> Response {
    Response::Error {
        code: error.code(),
        error: error.to_string(),
    }
}

fn io_error(error: &io::Error) -> DreamerError {
    DreamerError::KernelAdmissionRequired(format!("control transport: {error}"))
}

fn write_response(output: &mut impl Write, response: &Response) -> bool {
    serde_json::to_writer(&mut *output, response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use std::collections::VecDeque;

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
            deadline_unix_ms: 1,
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
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
            handshake: Ok(eliot_dreamer::KernelHandshake { authority_epoch: 0 }),
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
            handshake: Ok(eliot_dreamer::KernelHandshake { authority_epoch: 1 }),
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
}
