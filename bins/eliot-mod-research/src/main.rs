use std::io::{self, BufRead, Write};

use eliot_contracts::StateFence;
use eliot_mod_research::{cancel, compose_from_environment, submit};
use eliot_research_exchange_api::ResearchQueryRequest;
use serde::{Deserialize, Serialize};

/// JSON request envelope; inline submit preserves the established wire layout.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Submit {
        request: ResearchQueryRequest,
    },
    Cancel {
        job_id: String,
        state_fence: StateFence,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Accepted {
        job: eliot_research_exchange::ExchangeJob,
    },
    Cancelled {
        job: eliot_research_exchange::ExchangeJob,
    },
    Error {
        error: String,
    },
}

fn main() {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut researcher = compose_from_environment();

    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => handle(&mut researcher, &line),
            Err(error) => Response::Error {
                error: format!("input: {error}"),
            },
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || output.write_all(b"\n").is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
}

fn handle(researcher: &mut eliot_mod_research::ResearchComposition, line: &str) -> Response {
    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(error) => {
            return Response::Error {
                error: format!("request: {error}"),
            };
        }
    };
    match request {
        Request::Submit { request } => submit(researcher, request)
            .map(|job| Response::Accepted { job })
            .unwrap_or_else(|error| Response::Error {
                error: error.to_string(),
            }),
        Request::Cancel {
            job_id,
            state_fence,
        } => cancel(researcher, &job_id, state_fence)
            .map(|job| Response::Cancelled { job })
            .unwrap_or_else(|error| Response::Error {
                error: error.to_string(),
            }),
    }
}
