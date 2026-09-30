//! Task-relative consumption of Blob-owner-authenticated LSP observations.

use eliot_code_cortex::{CapturedLspObservation, CodeCortexError, CodeCortexService};
use eliot_instrument_api::NormalizedEvidence;
use eliot_receipts::{CausalBinding, TaskBinding};
use thiserror::Error;

/// Typed refusal from the captured-observation semantic consumer.
#[derive(Debug, Error)]
pub enum CapturedLspEvidenceError {
    /// The live Governor owner is not ready for semantic evidence adoption.
    #[error("Governor composition is not ready")]
    GovernorNotReady,
    /// CodeCortex rejected the exact captured envelope/chunk/task/causal join.
    #[error("CodeCortex refused captured LSP evidence: {0}")]
    CodeCortex(#[from] CodeCortexError),
}

/// Revalidates each exact retained record using its authenticated Blob read
/// chunk and projects only its bounded historical evidence.
pub(crate) fn consume_captured_lsp_observations(
    current_read_task_binding: TaskBinding,
    current_read_causal_binding: CausalBinding,
    observations: Vec<CapturedLspObservation>,
) -> Result<Vec<NormalizedEvidence>, CapturedLspEvidenceError> {
    let service = CodeCortexService::with_captured_lsp_observations(
        current_read_task_binding,
        current_read_causal_binding,
        observations,
    )?;
    Ok(service.index().snapshot().instrument_evidence)
}
