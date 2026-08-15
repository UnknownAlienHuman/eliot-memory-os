use std::io::{self, Write};
use std::path::PathBuf;

use eliotd::{DaemonComposition, DaemonConfig, PROTOCOL_VERSION, SERVICE_NAME, canonical_root};
use serde::Serialize;

#[derive(Debug, Default)]
struct Args {
    data_root: Option<PathBuf>,
    work_root: Option<PathBuf>,
    pipe_name: Option<String>,
    instance: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ReadyMessage<'a> {
    Ready {
        service: &'a str,
        protocol: &'a str,
        pid: u32,
        ipc: &'a str,
    },
    Error {
        error: String,
    },
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => exit_error(error),
    };
    let data_root = match configured_root(args.data_root, "ELIOT_DATA_ROOT", "data") {
        Ok(root) => root,
        Err(error) => exit_error(error),
    };
    let work_root = match configured_root(args.work_root, "ELIOT_WORK_ROOT", ".") {
        Ok(root) => root,
        Err(error) => exit_error(error),
    };
    let mut config = DaemonConfig::from_roots(data_root, work_root);
    config.instance_id = args.instance;
    if let Some(pipe_name) = args.pipe_name {
        config.pipe_name = pipe_name;
    }
    let daemon = match DaemonComposition::start(config).await {
        Ok(daemon) => daemon,
        Err(error) => exit_error(error.to_string()),
    };
    if !write_json(&ReadyMessage::Ready {
        service: SERVICE_NAME,
        protocol: PROTOCOL_VERSION,
        pid: std::process::id(),
        ipc: daemon.ipc_name(),
    }) {
        let _ = daemon.shutdown().await;
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
    let _ = daemon.shutdown().await;
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        instance: "default".to_owned(),
        ..Args::default()
    };
    let mut values = std::env::args_os().skip(1);
    while let Some(value) = values.next() {
        let name = value.to_string_lossy();
        let target = match name.as_ref() {
            "--data-root" => &mut args.data_root,
            "--work-root" => &mut args.work_root,
            _ => {
                if name == "--instance" {
                    args.instance = values
                        .next()
                        .ok_or_else(|| "--instance requires a value".to_owned())?
                        .to_string_lossy()
                        .into_owned();
                    continue;
                }
                if name == "--pipe-name" {
                    args.pipe_name = Some(
                        values
                            .next()
                            .ok_or_else(|| "--pipe-name requires a value".to_owned())?
                            .to_string_lossy()
                            .into_owned(),
                    );
                    continue;
                }
                return Err(format!("unknown argument: {name}"));
            }
        };
        *target = Some(PathBuf::from(
            values
                .next()
                .ok_or_else(|| format!("{name} requires a value"))?,
        ));
    }
    if args.instance.trim().is_empty() {
        return Err("--instance must not be empty".to_owned());
    }
    Ok(args)
}

fn configured_root(
    explicit: Option<PathBuf>,
    variable: &str,
    fallback: &str,
) -> Result<PathBuf, String> {
    let path = explicit
        .or_else(|| std::env::var_os(variable).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(fallback));
    canonical_root(&path).map_err(|error| error.to_string())
}

fn write_json(message: &ReadyMessage<'_>) -> bool {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, message).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok()
}

fn exit_error(error: impl Into<String>) -> ! {
    let _ = write_json(&ReadyMessage::Error {
        error: error.into(),
    });
    std::process::exit(78);
}
