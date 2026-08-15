use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use eliot_testd::{
    PROTOCOL_VERSION, SERVICE_NAME, TestReceipt, TestdComposition, TestdJobRequest,
    UnavailableProcessIssuer,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Submit { request: TestdJobRequest },
    Status { job_id: String },
    Cancel { job_id: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
    },
    Receipt {
        receipt: TestReceipt,
    },
    Error {
        error: String,
    },
}

fn main() {
    let state_path = std::env::var_os("ELIOT_TESTD_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".eliot-testd.redb"));
    let mut output = io::BufWriter::new(io::stdout().lock());
    let daemon = match TestdComposition::open(state_path, Arc::new(UnavailableProcessIssuer)) {
        Ok(daemon) => daemon,
        Err(error) => {
            let _ = write_response(
                &mut output,
                Response::Error {
                    error: error.to_string(),
                },
            );
            return;
        }
    };
    if !write_response(
        &mut output,
        Response::Ready {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
        },
    ) {
        return;
    }
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&daemon, &line),
            Err(error) => Response::Error {
                error: format!("input: {error}"),
            },
        };
        if !write_response(&mut output, response) {
            break;
        }
    }
}

fn dispatch(daemon: &TestdComposition, line: &str) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                error: format!("request: {error}"),
            };
        }
    };
    let result = match request {
        Request::Submit { request } => daemon.submit(request),
        Request::Status { job_id } => daemon.status(&job_id),
        Request::Cancel { job_id } => daemon.cancel(&job_id),
    };
    result
        .map(|receipt| Response::Receipt { receipt })
        .unwrap_or_else(|error| Response::Error {
            error: error.to_string(),
        })
}

fn write_response(output: &mut impl Write, response: Response) -> bool {
    serde_json::to_writer(&mut *output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
