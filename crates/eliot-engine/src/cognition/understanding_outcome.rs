//! Pure understanding-outcome validation extracted from `crates/eliot-engine/src/cognition.rs:18-90` at `0577520da9e7d95090525469afebc9fc53387713`.
//!
//! Architecture: `A6` Understanding State + `A7.1` Active Understanding View (`ARCH-UND-01`, `ARCH-UND-02`).
//! Implementation: `I6.12`/`I6.16` scoped understanding assessment, verifier contract `I6.7`/`I18`.
//! Types anchored at `crates/eliot-types/src/cognition.rs:177-208` (`UnderstandingOutcome`, `UnderstandingOutcomeRecord`, `VerificationResult`).
//! Ownership: `eliot-engine` crate, `cognition` subdomain (`crates/eliot-engine/src/cognition.rs`); this child owns only pure validation (`UnderstandingOutcomeService::validate` + owned `normalize_path`) with no admission/provider/authority/write semantics. Parent retains private `mod understanding_outcome` seam and exact `pub use` re-export.

use crate::EngineError;
use eliot_types::{UnderstandingOutcome, UnderstandingOutcomeRecord, VerificationResult};

#[derive(Clone, Copy, Debug, Default)]
pub struct UnderstandingOutcomeService;

impl UnderstandingOutcomeService {
    pub fn validate(record: &UnderstandingOutcomeRecord) -> Result<(), EngineError> {
        for (field, value) in [
            ("packet_id", record.packet_id.as_str()),
            (
                "selected_owner_or_module",
                record.selected_owner_or_module.as_str(),
            ),
            ("predicted_observable", record.predicted_observable.as_str()),
            (
                "selected_probe_or_action",
                record.selected_probe_or_action.as_str(),
            ),
            ("selected_verifier", record.selected_verifier.as_str()),
            ("actual_observation", record.actual_observation.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EngineError::WriteRejected(format!(
                    "understanding outcome is missing {field}"
                )));
            }
        }
        if record.proposed_causal_bridge.is_empty()
            || record.exact_handles_used.is_empty()
            || record.evidence_refs.is_empty()
        {
            return Err(EngineError::WriteRejected(
                "understanding outcome requires a causal bridge, exact handles, and observable evidence"
                    .to_owned(),
            ));
        }
        let selected = record
            .selected_write_set
            .iter()
            .map(|path| normalize_path(path))
            .collect::<Vec<_>>();
        if record
            .actual_changed_artifacts
            .iter()
            .map(|path| normalize_path(path))
            .any(|path| !selected.contains(&path))
        {
            return Err(EngineError::WriteRejected(
                "actual changed artifact escaped the selected write set".to_owned(),
            ));
        }
        match record.outcome {
            UnderstandingOutcome::Validated => {
                if record.verifier_result != VerificationResult::Passed
                    || !record.causal_bridge_validated
                    || record.expected_owner_or_module != record.selected_owner_or_module
                {
                    return Err(EngineError::WriteRejected(
                        "validated understanding must match the expected owner and pass its causal verifier"
                            .to_owned(),
                    ));
                }
            }
            UnderstandingOutcome::Revised if !record.revision_required => {
                return Err(EngineError::WriteRejected(
                    "revised understanding must mark revision_required".to_owned(),
                ));
            }
            UnderstandingOutcome::Revised
            | UnderstandingOutcome::Refuted
            | UnderstandingOutcome::Inconclusive => {}
        }
        Ok(())
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}
