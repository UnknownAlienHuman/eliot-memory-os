use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use eliot_store_surreal::{load_config, Response, StoreComposition, PROTOCOL_VERSION, SERVICE_NAME};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Health,
    Smoke,
    Migrate,
    Stop,
}

#[tokio::main]
async fn main() {
    let config_path = match parse_config_path() {
        Ok(path) => path,
        Err(error) => {
            write_response(Response::Error { error });
            return;
        }
    };
    let config = match load_config(config_path.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            write_response(Response::Error { error });
            return;
        }
    };
    let composition = match StoreComposition::new(config) {
        Ok(composition) => composition,
        Err(error) => {
            write_response(Response::Error { error });
            return;
        }
    };
    if !write_response(Response::Ready { service: SERVICE_NAME, protocol: PROTOCOL_VERSION }) {
        return;
    }
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => dispatch(&composition, &line).await,
            Err(error) => Response::Error { error: error.to_string() },
        };
        let stop = matches!(response, Response::Stopped);
        if !write_response(response) || stop {
            break;
        }
    }
}

fn parse_config_path() -> Result<Option<PathBuf>, String> {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => Ok(None),
        Some(value) if value == "--config" => match args.next() {
            Some(path) if args.next().is_none() => Ok(Some(PathBuf::from(path))),
            _ => Err("--config requires exactly one path".to_owned()),
        },
        Some(value) => Err(format!("unknown argument: {}", value.to_string_lossy())),
    }
}

async fn dispatch(composition: &StoreComposition, line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(Request::Health) => composition
            .health()
            .await
            .map(|record| Response::Health { record })
            .unwrap_or_else(|error| Response::Error { error: error.to_string() }),
        Ok(Request::Smoke) => composition
            .smoke()
            .await
            .map(|report| Response::Smoke { report })
            .unwrap_or_else(|error| Response::Error { error: error.to_string() }),
        Ok(Request::Migrate) => composition
            .migrate()
            .await
            .map(|records| Response::Migrated { records })
            .unwrap_or_else(|error| Response::Error { error: error.to_string() }),
        Ok(Request::Stop) => Response::Stopped,
        Err(error) => Response::Error { error: error.to_string() },
    }
}

fn write_response(response: Response) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}
