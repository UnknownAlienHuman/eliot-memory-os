use std::io::{self, BufRead, Write};

use eliot_testd::{
    TestReceipt, TestRequest, TestdComposition, TestdError, PROTOCOL_VERSION, SERVICE_NAME,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Submit { request: TestRequest },
    Status { request_id: String },
    Cancel { request_id: String },
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
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut daemon = TestdComposition::default();
    if !write_response(
        &mut output,
        Response::Ready {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
        },
    ) {
        return;
    }
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&mut daemon, &line),
            Err(error) => Response::Error {
                error: format!("input: {error}"),
            },
        };
        if !write_response(&mut output, response) {
            break;
        }
    }
}

fn dispatch(daemon: &mut TestdComposition, line: &str) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                error: format!("request: {error}"),
            }
        }
    };
    let result = match request {
        Request::Submit { request } => daemon.submit(request),
        Request::Status { request_id } => daemon.status(&request_id),
        Request::Cancel { request_id } => daemon.cancel(&request_id),
    };
    result
        .map(|receipt| Response::Receipt { receipt })
        .map_err(|error: TestdError| error.to_string())
        .unwrap_or_else(|error| Response::Error { error })
}

fn write_response(output: &mut impl Write, response: Response) -> bool {
    serde_json::to_writer(&mut *output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
