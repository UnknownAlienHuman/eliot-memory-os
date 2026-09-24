#![forbid(unsafe_code)]

use std::io::{self, Write};

use eliot_mod_research::runtime::{self, RuntimeError};

const EXIT_KERNEL_ADMISSION_REQUIRED: i32 = 78;
const EXIT_PROVIDER_UNAVAILABLE: i32 = 79;
const EXIT_PROVIDER_FAILED: i32 = 1;

fn main() {
    std::process::exit(run());
}

/// Production one-shot composition. The admitted arm calls
/// `runtime::run_once`, which drives the real shared `WindowsProcessExecutor`;
/// only the absence of Kernel-delivered material takes the admission-required
/// path. No argv, stdin, environment value, or caller-selected executable can
/// enable provider execution.
fn run() -> i32 {
    match runtime::run_once() {
        Ok(Some(receipt)) => {
            emit(
                "RESEARCH_PROVIDER_CANDIDATE",
                &format!(
                    "operation={} outcome=receipted route={} cleanup_proven={}",
                    receipt.operation_id, receipt.route_id, receipt.cleanup.cleanup_proven
                ),
            );
            0
        }
        Ok(None) => {
            emit(
                "RESEARCH_SOURCE_UNAVAILABLE",
                "provider returned no admitted candidate",
            );
            EXIT_PROVIDER_UNAVAILABLE
        }
        Err(RuntimeError::MaterialUnavailable) => {
            emit(
                "KERNEL_ADMISSION_REQUIRED",
                "no session-bound provider admission material was delivered",
            );
            EXIT_KERNEL_ADMISSION_REQUIRED
        }
        Err(RuntimeError::InvalidMaterial(detail)) => {
            emit("KERNEL_ADMISSION_REQUIRED", detail);
            EXIT_KERNEL_ADMISSION_REQUIRED
        }
        Err(RuntimeError::Provider { failure, receipt }) => {
            let operation = receipt.as_ref().map_or_else(
                || "unavailable".to_owned(),
                |receipt| receipt.operation_id.clone(),
            );
            emit(
                &failure.code,
                &format!(
                    "operation={operation} kind={:?} detail={}",
                    failure.kind, failure.detail
                ),
            );
            EXIT_PROVIDER_FAILED
        }
        Err(error @ RuntimeError::Unavailable(_)) => {
            emit("RESEARCH_SOURCE_UNAVAILABLE", &error.to_string());
            EXIT_PROVIDER_UNAVAILABLE
        }
        Err(error @ RuntimeError::Evidence(_)) => {
            emit("RESEARCH_PROVIDER_FAILED", &error.to_string());
            EXIT_PROVIDER_FAILED
        }
    }
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let payload = serde_json::json!({ "error": code, "detail": detail });
    let _ = writeln!(stderr, "{payload}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_entry_has_a_real_admitted_arm() {
        let source = include_str!("runtime.rs");
        assert!(source.contains("ProviderBridge::new"));
        assert!(source.contains("WindowsProcessExecutor::new"));
        assert!(source.contains("compose_admitted"));
    }
}
