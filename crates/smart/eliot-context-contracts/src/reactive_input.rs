//! Immutable joins shared by the reactive-planning input projections.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, OperationId, RequestId, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use thiserror::Error;

use crate::{ActiveUnderstandingView, AdmittedContextSet, ContextError};

/// Maximum canonical bytes retained by one immutable planning input.
pub const MAX_REACTIVE_INPUT_BYTES: usize = 256 * 1024;
/// Maximum members retained by one planning projection.
pub const MAX_REACTIVE_INPUT_ITEMS: usize = 256;
/// Maximum references retained by one planning projection.
pub const MAX_REACTIVE_INPUT_REFS: usize = 512;

/// Intrinsic validation failures for the A15 handoff projections.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveInputError {
    /// An existing Context contract rejected a retained value.
    #[error("context contract: {0}")]
    Context(#[from] ContextError),
    /// A retained protocol, receipt, or evidence contract rejected a value.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// Canonical bytes do not match the retained identity.
    #[error("{field} does not match canonical bytes")]
    DigestMismatch { field: &'static str },
    /// A cross-projection identity relation is false.
    #[error("{field} does not match its binding")]
    BindingMismatch { field: &'static str },
}

fn text(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

struct CappedWriter {
    written: usize,
    cap: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("bounded serialization overflow"))?;
        if next > self.cap {
            return Err(io::Error::other("bounded serialization exceeded cap"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Bound a borrowed graph before cloning or canonicalizing it.
pub(crate) fn bounded_preflight<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<usize, ReactiveInputError> {
    let mut sink = CappedWriter {
        written: 0,
        cap: MAX_REACTIVE_INPUT_BYTES,
    };
    serde_json::to_writer(&mut sink, value).map_err(|_| ReactiveInputError::InvalidField {
        field,
        reason: "borrowed input exceeds bounded serialized bytes",
    })?;
    Ok(sink.written)
}

fn checked_reference_add(total: &mut usize, count: usize) -> Result<(), ReactiveInputError> {
    *total = total
        .checked_add(count)
        .ok_or(ReactiveInputError::InvalidField {
            field: "bindings.input_references",
            reason: "reference accounting overflowed",
        })?;
    Ok(())
}

fn count_retained_references(view: &ContextPlanningView) -> Result<usize, ReactiveInputError> {
    // Count retained membership, selection, omission, rule, dependency,
    // predecessor, proof, and measurement handle collections explicitly.
    let mut references = 0usize;
    for count in [
        view.view.admitted_ids.len(),
        view.view.rendered.len(),
        view.view.selection.admitted_ids.len(),
        view.view.selection.rendered_ids.len(),
        view.view.selection.omission_evidence.len(),
        view.admitted.records.len(),
        view.admitted.admissions.len(),
        view.admitted.floor.members.len(),
        view.admitted.floor.mandatory_atoms.len(),
        view.admitted.floor.mandatory_roles.len(),
        view.admitted.economy.requested.len(),
        view.admitted.economy.admitted.len(),
        view.admitted.economy.displaced.len(),
        view.admitted.economy.omissions.len(),
        view.admitted.floor.providers.requested.len(),
        view.admitted.floor.providers.dispositions.len(),
        view.view.quality.results.len(),
    ] {
        checked_reference_add(&mut references, count)?;
    }
    checked_reference_add(&mut references, 1)?; // economy.applied_rule
    checked_reference_add(&mut references, 1)?; // floor.rule_evidence
    checked_reference_add(
        &mut references,
        view.admitted.floor.interpretation_dependencies.len(),
    )?;
    for item in &view.view.rendered {
        checked_reference_add(&mut references, 1)?; // rendered.source_id
        checked_reference_add(&mut references, item.dependencies.len())?;
        checked_reference_add(
            &mut references,
            usize::from(item.source_predecessor.is_some()),
        )?;
        checked_reference_add(&mut references, 1)?; // rendered.measurement
        checked_reference_add(&mut references, 1)?; // rendered.proof evidence
    }
    for record in &view.admitted.records {
        checked_reference_add(&mut references, 1)?; // candidate.source.snapshot_id
        checked_reference_add(&mut references, record.candidate.dependencies.len())?;
        checked_reference_add(
            &mut references,
            usize::from(record.candidate.source.predecessor.is_some()),
        )?;
        checked_reference_add(&mut references, 1)?; // record.rule_evidence
        checked_reference_add(&mut references, 1)?; // record.proof evidence
        checked_reference_add(&mut references, 1)?; // record.measurement
    }
    for member in &view.admitted.floor.members {
        checked_reference_add(&mut references, member.required_dependencies.len())?;
        checked_reference_add(&mut references, usize::from(member.measurement.is_some()))?;
    }
    for _admission in &view.admitted.admissions {
        checked_reference_add(&mut references, 1)?; // admission.rule_evidence
    }
    for disposition in &view.admitted.floor.providers.dispositions {
        checked_reference_add(&mut references, usize::from(disposition.evidence.is_some()))?;
    }
    for result in &view.view.quality.results {
        checked_reference_add(&mut references, result.evidence.len())?;
        checked_reference_add(&mut references, result.measurements.len())?;
        checked_reference_add(&mut references, result.unknown_evidence.len())?;
        checked_reference_add(
            &mut references,
            usize::from(result.failed_invariant.is_some()),
        )?;
        checked_reference_add(&mut references, usize::from(result.invalidation.is_some()))?;
    }
    for omission in &view.admitted.economy.omissions {
        checked_reference_add(&mut references, 2)?; // omission.source_id and decision
        checked_reference_add(&mut references, usize::from(omission.expires.is_some()))?;
        checked_reference_add(
            &mut references,
            usize::from(omission.invalidation.is_some()),
        )?;
        if omission.expansion.is_some() {
            checked_reference_add(&mut references, 6)?;
            // handle_id, atom_id, source_id, decision, expiry, invalidation
        }
    }
    Ok(references)
}

/// Explicit finite limits for a single planning handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactivePlanningBounds {
    /// Maximum retained input bytes.
    pub max_input_bytes: u64,
    /// Maximum considered semantic members.
    pub max_items: u64,
    /// Maximum retained references and handles.
    pub max_references: u64,
}

impl ReactivePlanningBounds {
    /// Validate that every independent bound is finite and non-zero.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        if self.max_input_bytes == 0
            || self.max_input_bytes > MAX_REACTIVE_INPUT_BYTES as u64
            || self.max_items == 0
            || self.max_items > MAX_REACTIVE_INPUT_ITEMS as u64
            || self.max_references == 0
            || self.max_references > MAX_REACTIVE_INPUT_REFS as u64
        {
            return Err(ReactiveInputError::InvalidField {
                field: "bounds",
                reason: "all limits must be finite and within the contract ceiling",
            });
        }
        Ok(())
    }
}

/// Exact operation, Context, and fence joins for one planning invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactivePlanningBindings {
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub task_id: TaskId,
    pub attempt_id: AgentAttemptId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub view_id: ArtifactId,
    pub view_digest: String,
    pub admitted_set_digest: String,
    pub assembly_digest: String,
    pub measurement_digest: String,
    pub input_digest: String,
    pub bounds: ReactivePlanningBounds,
}

impl ReactivePlanningBindings {
    /// Validate exact identity and digest joins without authenticating callers.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        bounded_preflight(self, "bindings.preflight")?;
        for (value, field) in [
            (self.request_id.as_str(), "bindings.request_id"),
            (self.operation_id.as_str(), "bindings.operation_id"),
            (self.task_id.as_str(), "bindings.task_id"),
            (self.attempt_id.as_str(), "bindings.attempt_id"),
            (self.scope_id.as_str(), "bindings.scope_id"),
            (self.view_id.as_str(), "bindings.view_id"),
        ] {
            text(value, field)?;
        }
        text(&self.idempotency_key, "bindings.idempotency_key")?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "bindings.state_fence",
                reason: "invalid State Fence",
            })?;
        for (value, field) in [
            (&self.view_digest, "bindings.view_digest"),
            (&self.admitted_set_digest, "bindings.admitted_set_digest"),
            (&self.assembly_digest, "bindings.assembly_digest"),
            (&self.measurement_digest, "bindings.measurement_digest"),
            (&self.input_digest, "bindings.input_digest"),
        ] {
            digest(value, field)?;
        }
        self.bounds.validate()
    }

    /// Validate digest joins against one retained A15 Context closure.
    pub fn validate_against(&self, view: &ContextPlanningView) -> Result<(), ReactiveInputError> {
        self.validate()?;
        // Stream the complete retained view, including nested graphs and both
        // original byte payloads, before invoking the expensive Context
        // validators or any canonicalizing helper.
        let serialized_bytes = bounded_preflight(view, "bindings.input_preflight")?;
        if serialized_bytes as u64 > self.bounds.max_input_bytes {
            return Err(ReactiveInputError::InvalidField {
                field: "bindings.input_bytes",
                reason: "retained input exceeds declared byte bound",
            });
        }
        view.validate()?;
        let items = view
            .view
            .rendered
            .len()
            .max(view.admitted.records.len())
            .max(view.admitted.admissions.len());
        if items as u64 > self.bounds.max_items {
            return Err(ReactiveInputError::InvalidField {
                field: "bindings.input_items",
                reason: "retained input exceeds declared item bound",
            });
        }
        let references = count_retained_references(view)?;
        if references as u64 > self.bounds.max_references {
            return Err(ReactiveInputError::InvalidField {
                field: "bindings.input_references",
                reason: "retained input exceeds declared reference bound",
            });
        }
        if self.view_id != view.view_id
            || self.view_digest != view.view.output_digest
            || self.admitted_set_digest != view.admitted_canonical_sha256
            || self.assembly_digest != view.view.selection.output_digest
            || self.task_id != view.view.binding.task_id
            || self.attempt_id != view.view.binding.attempt_id
            || self.scope_id != view.view.binding.scope_id
            || self.state_fence != view.view.binding.state_fence
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "bindings.view_closure",
            });
        }
        let measurement_digest = canonical_planning_digest(&view.view.measurement)?;
        if self.measurement_digest != measurement_digest {
            return Err(ReactiveInputError::BindingMismatch {
                field: "bindings.measurement",
            });
        }
        let expected = canonical_planning_digest(&(
            &self.request_id,
            &self.operation_id,
            &self.idempotency_key,
            &self.task_id,
            &self.attempt_id,
            &self.scope_id,
            &self.state_fence,
            &self.view_id,
            &self.view_digest,
            &self.admitted_set_digest,
            &self.assembly_digest,
            &self.measurement_digest,
            &self.bounds,
        ))?;
        if self.input_digest != expected {
            return Err(ReactiveInputError::DigestMismatch {
                field: "bindings.input_digest",
            });
        }
        Ok(())
    }
}

/// Complete immutable A15 Context closure supplied to the future planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextPlanningView {
    pub view_id: ArtifactId,
    pub view: ActiveUnderstandingView,
    pub admitted: AdmittedContextSet,
    /// Canonical bytes of the rendered view payload.
    pub canonical_bytes: Vec<u8>,
    pub canonical_sha256: String,
    /// Canonical bytes of the admitted payload used to assemble the view.
    pub admitted_canonical_bytes: Vec<u8>,
    pub admitted_canonical_sha256: String,
}

fn preflight_view(
    view: &ActiveUnderstandingView,
    admitted: &AdmittedContextSet,
    canonical_bytes: &[u8],
    admitted_canonical_bytes: &[u8],
) -> Result<(), ReactiveInputError> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > MAX_REACTIVE_INPUT_BYTES
        || admitted_canonical_bytes.is_empty()
        || admitted_canonical_bytes.len() > MAX_REACTIVE_INPUT_BYTES
        || view.rendered.len() > MAX_REACTIVE_INPUT_ITEMS
        || admitted.records.len() > MAX_REACTIVE_INPUT_ITEMS
        || admitted.admissions.len() > MAX_REACTIVE_INPUT_ITEMS
        || admitted.economy.omissions.len() > MAX_REACTIVE_INPUT_ITEMS
    {
        return Err(ReactiveInputError::InvalidField {
            field: "view.preflight",
            reason: "input graph or canonical bytes exceed bounded limits",
        });
    }
    Ok(())
}

impl ContextPlanningView {
    /// Build and intrinsically validate a retained view closure.
    pub fn new(
        view_id: ArtifactId,
        view: ActiveUnderstandingView,
        admitted: AdmittedContextSet,
        canonical_bytes: Vec<u8>,
        admitted_canonical_bytes: Vec<u8>,
    ) -> Result<Self, ReactiveInputError> {
        bounded_preflight(&(&view, &admitted), "view.preflight")?;
        preflight_view(
            &view,
            &admitted,
            &canonical_bytes,
            &admitted_canonical_bytes,
        )?;
        let value = Self {
            view_id,
            canonical_sha256: sha256_hex(&canonical_bytes),
            admitted_canonical_sha256: sha256_hex(&admitted_canonical_bytes),
            view,
            admitted,
            canonical_bytes,
            admitted_canonical_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate that both original payloads and all A15 closure fields agree.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        text(self.view_id.as_str(), "view.view_id")?;
        bounded_preflight(&(&self.view, &self.admitted), "view.preflight")?;
        preflight_view(
            &self.view,
            &self.admitted,
            &self.canonical_bytes,
            &self.admitted_canonical_bytes,
        )?;
        self.admitted.validate()?;
        self.view.validate_against(&self.admitted)?;
        let rendered_digest = ActiveUnderstandingView::canonical_output_digest(
            &self.view.binding,
            &self.view.recipe_digest,
            &self.view.fence_digest,
            &self.view.rendered,
        )?;
        let rendered_bytes = ActiveUnderstandingView::canonical_output_utf8_bytes(
            &self.view.binding,
            &self.view.recipe_digest,
            &self.view.fence_digest,
            &self.view.rendered,
        )?;
        if self.canonical_sha256 != sha256_hex(&self.canonical_bytes)
            || self.canonical_sha256 != rendered_digest
            || self.canonical_bytes.len() as u64 != rendered_bytes
            || self.view.measurement.envelope_digest != rendered_digest
            || self.view.measurement.rendered_utf8_bytes != rendered_bytes
        {
            return Err(ReactiveInputError::DigestMismatch {
                field: "view.canonical_bytes",
            });
        }
        let admitted_digest = self.admitted.canonical_payload_digest()?;
        let admitted_bytes = self.admitted.canonical_payload_utf8_bytes()?;
        if self.admitted_canonical_sha256 != sha256_hex(&self.admitted_canonical_bytes)
            || self.admitted_canonical_sha256 != admitted_digest
            || self.admitted_canonical_bytes.len() as u64 != admitted_bytes
        {
            return Err(ReactiveInputError::DigestMismatch {
                field: "view.admitted_canonical_bytes",
            });
        }
        Ok(())
    }
}

/// Compute a digest for any closed planning value.
pub fn canonical_planning_digest<T: Serialize>(value: &T) -> Result<String, ReactiveInputError> {
    bounded_preflight(value, "canonical_value")?;
    let bytes = canonical_json_bytes(value).map_err(|_| ReactiveInputError::InvalidField {
        field: "canonical_value",
        reason: "canonical serialization failed",
    })?;
    if bytes.len() > MAX_REACTIVE_INPUT_BYTES {
        return Err(ReactiveInputError::InvalidField {
            field: "canonical_value",
            reason: "canonical value exceeds bounded bytes",
        });
    }
    Ok(sha256_hex(&bytes))
}
