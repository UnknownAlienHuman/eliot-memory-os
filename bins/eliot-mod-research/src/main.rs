#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use eliot_mod_research::{
    R6ResearchRequest, compose_r6_request, compose_with_bridge, task_owner_from_snapshot,
};
use serde_json::json;

const SERVICE_NAME: &str = "eliot-mod-research";
const PROTOCOL_VERSION: &str = "eliot.research.provider.v1";
const OPERATION: &str = "eliot.research.provider.execute";
const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;

fn main() {
    let mut request_path = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        if argument.as_str() == "--request" {
            request_path = args.next();
        } else {
            emit_error(
                "R6_REQUEST_ARGUMENT_INVALID",
                "usage: --request <json-file>",
            );
            std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
        }
    }

    let Some(path) = request_path else {
        let _ = writeln!(io::stderr(), "{}", admission_required_message());
        std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
    };

    match run_request(Path::new(&path)) {
        Ok(true) => {}
        Ok(false) => std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED),
        Err((code, detail)) => {
            emit_error(code, &detail);
            std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);
        }
    }
}

fn run_request(path: &Path) -> Result<bool, (&'static str, String)> {
    let bytes = fs::read(path).map_err(|error| {
        (
            "R6_REQUEST_READ_FAILED",
            format!("request file could not be read: {error}"),
        )
    })?;
    let request: R6ResearchRequest = serde_json::from_slice(&bytes).map_err(|error| {
        (
            "R6_REQUEST_INVALID",
            format!("request JSON is invalid: {error}"),
        )
    })?;
    let snapshot = request.task_snapshot.clone().ok_or_else(|| {
        (
            "KERNEL_ADMISSION_REQUIRED",
            "an explicit Task Controller lifecycle snapshot is required; no owner was invented"
                .to_owned(),
        )
    })?;
    let task_owner =
        task_owner_from_snapshot(snapshot, &request.task_context).map_err(|error| {
            (
                "R6_TASK_OWNER_REJECTED",
                format!("Task Controller snapshot was rejected: {error}"),
            )
        })?;
    let mut researcher = compose_with_bridge(request.bridge_identity.clone());
    let output = compose_r6_request(&mut researcher, &task_owner, request).map_err(|error| {
        (
            "R6_COMPOSITION_REJECTED",
            format!("R6 composition was rejected: {error}"),
        )
    })?;
    let encoded = serde_json::to_string_pretty(&output).map_err(|error| {
        (
            "R6_OUTPUT_INVALID",
            format!("R6 output could not be encoded: {error}"),
        )
    })?;
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{encoded}");
    Ok(output.exchange_job.is_some())
}

fn emit_error(code: &str, detail: &str) {
    let payload = json!({
        "status": "REJECTED",
        "code": code,
        "detail": detail,
        "service": SERVICE_NAME,
        "protocol": PROTOCOL_VERSION,
        "operation": OPERATION,
        "candidate_only": true,
        "canonical_write_authorized": false,
    });
    let _ = writeln!(io::stderr(), "{payload}");
}

fn admission_required_message() -> String {
    format!(
        "{KERNEL_ADMISSION_REQUIRED}: service={SERVICE_NAME} protocol={PROTOCOL_VERSION} operation={OPERATION}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_diagnostic_is_stable_and_never_claims_readiness() {
        let message = admission_required_message();
        assert_eq!(
            message,
            "KERNEL_ADMISSION_REQUIRED: service=eliot-mod-research protocol=eliot.research.provider.v1 operation=eliot.research.provider.execute"
        );
        assert!(!message.to_ascii_lowercase().contains("ready"));
        assert_ne!(EXIT_KERNEL_ADMISSION_REQUIRED, 0);
    }
}
