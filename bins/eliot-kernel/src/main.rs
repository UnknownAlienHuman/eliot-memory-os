use std::io::{self, Write};

use eliot_kernel::{
    KernelBuildError, KernelComposition, KernelConfig, PROTOCOL_VERSION, SERVICE_NAME,
    default_work_root,
};

#[tokio::main]
async fn main() {
    let root = match parse_root() {
        Ok(root) => root,
        Err(error) => exit_error("INVALID_CONFIGURATION", &error.to_string()),
    };
    let kernel = match KernelComposition::new(KernelConfig::new(root)) {
        Ok(kernel) => kernel,
        Err(error) => exit_build_error(error),
    };
    #[cfg(windows)]
    let mut front_door = match kernel.bind_authenticated_front_door() {
        Ok(server) => server,
        Err(error) => exit_build_error(error),
    };
    #[cfg(windows)]
    let principal = match eliot_platform_windows::current_process_named_pipe_expectation() {
        Ok(expectation) => expectation,
        Err(error) => exit_error("PRINCIPAL_FAILURE", &error.to_string()),
    };
    let ready = format!(
        "{{\"service\":\"{SERVICE_NAME}\",\"protocol\":\"{PROTOCOL_VERSION}\",\"ipc\":\"{}\"}}",
        kernel.ipc().name()
    );
    if !write_line(&ready) {
        return;
    }
    #[cfg(windows)]
    tokio::select! {
        result = front_door.wait_for_authenticated_client(
            std::time::Duration::from_secs(86_400),
            &principal,
        ) => {
            if let Err(error) = result {
                exit_error("FRONT_DOOR_FAILURE", &error.to_string());
            }
        }
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                exit_error("SIGNAL_FAILURE", &error.to_string());
            }
        }
    }
    #[cfg(not(windows))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        exit_error("SIGNAL_FAILURE", &error.to_string());
    }
    let _ = kernel.shutdown().await;
}

fn parse_root() -> Result<std::path::PathBuf, std::io::Error> {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        None => default_work_root(),
        Some(value) if value == "--work-root" => match args.next() {
            Some(root) if args.next().is_none() => std::fs::canonicalize(root),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--work-root requires exactly one path",
            )),
        },
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown argument: {}", value.to_string_lossy()),
        )),
    }
}

fn exit_build_error(error: KernelBuildError) -> ! {
    exit_error("COMPOSITION_FAILURE", &error.to_string())
}

fn exit_error(code: &str, detail: &str) -> ! {
    let _ = writeln!(
        io::stderr().lock(),
        "{{\"error\":\"{code}\",\"detail\":{detail:?}}}"
    );
    std::process::exit(1);
}

fn write_line(line: &str) -> bool {
    let mut stdout = io::stdout().lock();
    stdout.write_all(line.as_bytes()).is_ok()
        && stdout.write_all(b"\n").is_ok()
        && stdout.flush().is_ok()
}
