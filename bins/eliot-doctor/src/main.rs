use std::io::{self, BufRead, Write};

use eliot_doctor::{DoctorComposition, DoctorJob, DoctorReport, PROTOCOL_VERSION, SERVICE_NAME};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "Request is a public JSON protocol surface; boxing would change its deserialized API shape"
)]
enum Request {
    Run { job: DoctorJob },
    Status { job_id: String },
    Cancel { job_id: String },
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
    },
    Report {
        report: DoctorReport,
    },
    Error {
        error: String,
    },
}

fn main() {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut doctor = DoctorComposition::default();
    if !write_response(
        &mut output,
        &Response::Ready {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
        },
    ) {
        return;
    }
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut doctor, &line),
            Err(error) => Response::Error {
                error: format!("input: {error}"),
            },
        };
        if !write_response(&mut output, &response) {
            break;
        }
    }
}

fn dispatch(doctor: &mut DoctorComposition, line: &str) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                error: format!("request: {error}"),
            };
        }
    };
    let result = match request {
        Request::Run { job } => doctor.run(job),
        Request::Status { job_id } => doctor.status(&job_id),
        Request::Cancel { job_id } => doctor.cancel(&job_id),
    };
    result.map_or_else(
        |error| Response::Error {
            error: error.to_string(),
        },
        |report| Response::Report { report },
    )
}

fn write_response(output: &mut impl Write, response: &Response) -> bool {
    serde_json::to_writer(&mut *output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
