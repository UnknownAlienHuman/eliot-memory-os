use std::io::{self, Write};
use std::path::PathBuf;

use eliot_user_broker::{canonical_root, BrokerComposition, BrokerConfig, PLAN_GAP_EXIT};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Message {
    PlanGap {
        service: &'static str,
        detail: String,
    },
    Error {
        error: String,
    },
}

fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit(Message::Error { error }),
    };
    if let Err(error) = std::fs::create_dir_all(&root) {
        exit(Message::Error {
            error: format!("create data root {}: {error}", root.display()),
        });
    }
    let root = match canonical_root(&root) {
        Ok(root) => root,
        Err(error) => exit(Message::Error {
            error: error.to_string(),
        }),
    };
    let composition = match BrokerComposition::start(BrokerConfig::from_root(root)) {
        Ok(composition) => composition,
        Err(error) => exit(Message::Error {
            error: error.to_string(),
        }),
    };
    let readiness = composition.readiness();
    let detail = serde_json::to_string(&readiness).unwrap_or_else(|error| error.to_string());
    exit(Message::PlanGap {
        service: "eliot-user-broker",
        detail,
    });
}

fn parse_root() -> Result<PathBuf, String> {
    let mut root = None;
    let mut values = std::env::args_os().skip(1);
    while let Some(value) = values.next() {
        if value == "--data-root" {
            root = Some(
                values
                    .next()
                    .ok_or_else(|| "--data-root requires a value".to_owned())
                    .map(PathBuf::from)?,
            );
        } else {
            return Err(format!("unknown argument: {}", value.to_string_lossy()));
        }
    }
    Ok(root
        .or_else(|| std::env::var_os("ELIOT_DATA_ROOT").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("data")))
}

fn exit(message: Message) -> ! {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = serde_json::to_writer(&mut output, &message);
    let _ = output.write_all(b"\n");
    let _ = output.flush();
    std::process::exit(PLAN_GAP_EXIT);
}
