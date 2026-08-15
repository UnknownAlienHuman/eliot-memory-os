//! Composition root for the production research exchange process.
//!
//! The process owns only exchange admission and lifecycle.  Acquisition is
//! delegated to the configured bridge executable; returned research remains a
//! candidate until an authority outside this package admits it.

#![forbid(unsafe_code)]

use std::process::Command;

use eliot_contracts::StateFence;
use eliot_research_exchange::{ExchangeError, ExchangeJob, GovernedExchange, ResearchBridge};
use eliot_research_exchange_api::ResearchQueryRequest;
use eliot_researcher::Researcher;
use serde::Serialize;
use thiserror::Error;

const BRIDGE_ENV: &str = "ELIOT_RESEARCH_BRIDGE";

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("{BRIDGE_ENV} is not configured")]
    NotConfigured,
    #[error("research bridge could not start: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("research bridge exited unsuccessfully: {0}")]
    Exit(std::process::ExitStatus),
    #[error("research bridge returned an empty job id")]
    EmptyJobId,
    #[error("research bridge returned invalid JSON: {0}")]
    InvalidResponse(#[source] serde_json::Error),
    #[error("research bridge response was missing job_id")]
    MissingJobId,
}

#[derive(Debug, Serialize)]
struct SubmitEnvelope<'a> {
    request: &'a ResearchQueryRequest,
}

#[derive(Debug, Serialize)]
struct CancelEnvelope<'a> {
    job_id: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct SubmitResponse {
    job_id: Option<String>,
}

/// A native-process bridge. The executable path is supplied by the runtime
/// environment, and arguments are passed without shell interpretation.
pub struct ProcessResearchBridge {
    executable: Option<String>,
}

impl ProcessResearchBridge {
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            executable: std::env::var(BRIDGE_ENV).ok(),
        }
    }

    fn invoke<T: Serialize>(&self, operation: &str, payload: &T) -> Result<Vec<u8>, BridgeError> {
        let executable = self
            .executable
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(BridgeError::NotConfigured)?;
        let input = serde_json::to_vec(payload).map_err(BridgeError::InvalidResponse)?;
        let output = Command::new(executable)
            .arg(operation)
            .arg("--json")
            .env_remove("ELIOT_RESEARCH_BRIDGE")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(BridgeError::Spawn)
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .ok_or(BridgeError::NotConfigured)
                    .and_then(|mut stdin| stdin.write_all(&input).map_err(BridgeError::Spawn))?;
                let output = child.wait_with_output().map_err(BridgeError::Spawn)?;
                if !output.status.success() {
                    return Err(BridgeError::Exit(output.status));
                }
                Ok(output.stdout)
            })?;
        Ok(output)
    }
}

impl ResearchBridge for ProcessResearchBridge {
    type Error = BridgeError;

    fn submit(&mut self, request: &ResearchQueryRequest) -> Result<String, Self::Error> {
        let response = self.invoke("submit", &SubmitEnvelope { request })?;
        let response: SubmitResponse =
            serde_json::from_slice(&response).map_err(BridgeError::InvalidResponse)?;
        let job_id = response.job_id.ok_or(BridgeError::MissingJobId)?;
        if job_id.trim().is_empty() {
            return Err(BridgeError::EmptyJobId);
        }
        Ok(job_id)
    }

    fn cancel(&mut self, job_id: &str) -> Result<(), Self::Error> {
        self.invoke("cancel", &CancelEnvelope { job_id })?;
        Ok(())
    }
}

pub type ResearchComposition = Researcher<ProcessResearchBridge>;

#[must_use]
pub fn compose_from_environment() -> ResearchComposition {
    Researcher::new(ProcessResearchBridge::from_environment())
}

pub fn submit(
    researcher: &mut ResearchComposition,
    request: ResearchQueryRequest,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.submit_query(request)
}

pub fn cancel(
    researcher: &mut ResearchComposition,
    job_id: &str,
    fence: StateFence,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.exchange_mut().cancel(job_id, &fence)
}

#[must_use]
pub fn exchange_snapshot(
    researcher: &ResearchComposition,
) -> &eliot_research_exchange::ExchangeSnapshot {
    researcher.exchange().snapshot()
}
