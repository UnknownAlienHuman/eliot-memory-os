use std::io::{self, BufRead, Write};

use eliot_dreamer::{DreamJobInput, DreamerComposition, DreamerError, JobView};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Submit { job: DreamJobInput },
    Cancel { job_id: String },
    Status { job_id: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    Job {
        view: JobView,
    },
    Error {
        error: String,
    },
}

fn main() {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut service = DreamerComposition::default();
    write_response(
        &mut output,
        Response::Ready {
            service: eliot_dreamer::SERVICE_NAME,
            protocol: eliot_dreamer::PROTOCOL_VERSION,
        },
    );
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut service, &line),
            Err(error) => Response::Error {
                error: format!("input: {error}"),
            },
        };
        if !write_response(&mut output, response) {
            break;
        }
    }
}

fn dispatch(service: &mut DreamerComposition, line: &str) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                error: format!("request: {error}"),
            };
        }
    };
    let result: Result<JobView, DreamerError> = match request {
        Request::Submit { job } => service.submit(job),
        Request::Cancel { job_id } => service.cancel(&job_id),
        Request::Status { job_id } => service.status(&job_id),
    };
    result
        .map(|view| Response::Job { view })
        .unwrap_or_else(|error| Response::Error {
            error: error.to_string(),
        })
}

fn write_response(output: &mut impl Write, response: Response) -> bool {
    serde_json::to_writer(&mut *output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
