//! Grounded relation draft: the caller-owned semantic content of one relation
//! proposal with the endpoint, registry and neighborhood records held as
//! separate typed inputs.
//!
//! A [`GroundedRelationDraft`] carries everything the relation handler needs
//! except the already-admitted endpoint pair, the registry snapshot and the
//! existing neighborhood. Endpoints are never created, admitted or
//! reclassified here; they arrive as [`RelationEndpoint`] inputs owned by
//! their admission authority and are only referenced by identity, revision,
//! digest and admission receipt.

use eliot_contracts::StateFence;
use eliot_dreamer_contracts::{
    ContractViolation, RelationAlternative, RelationDirection, RelationDisclosureEvidence,
    RelationEndpoint, RelationEvidence, RelationFamily, RelationInput, RelationNeighborhood,
    RelationPreservation, RelationRegistrySnapshot, RelationTemporalEvidence, RelationVerifier,
    ScreenBinding, ValidatedCurationItem,
    error::{check_fence, check_text, is_hex64_lower},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;
const MAX_TEXT: usize = 1024;

/// Caller-supplied grounded content for one typed directed relation proposal.
///
/// Identity (operation/request/idempotency/task/scope/fence), the relation
/// family and direction, the retained screen binding, the full evidence and
/// alternative closure, temporal readings, the optional verifier, the
/// association disclosure decision and the preservation record travel in this
/// draft. The source endpoint, target endpoint, registry snapshot and
/// existing neighborhood are separate typed arguments to
/// [`crate::propose_relation`], never fields smuggled inside this draft.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroundedRelationDraft {
    pub schema_version: u32,
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub policy_digest: String,
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub screen: ScreenBinding,
    pub evidence: Vec<RelationEvidence>,
    pub counterevidence: Vec<RelationEvidence>,
    pub rivals: Vec<RelationAlternative>,
    pub no_relation_alternative: Option<RelationAlternative>,
    pub temporal: RelationTemporalEvidence,
    pub verifier: Option<RelationVerifier>,
    pub disclosure_evidence: Option<RelationDisclosureEvidence>,
    pub preservation: RelationPreservation,
}

impl GroundedRelationDraft {
    /// Checks the draft header shape. Full cross-record joins (endpoint
    /// identity, registry vocabulary, evidence predicates, acceptance) are
    /// validated on the assembled [`RelationInput`] closure.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "relation.draft.schema_version",
                min: 1,
                max: 1,
                got: i64::from(self.schema_version),
            });
        }
        for (value, field) in [
            (&self.operation_id, "relation.draft.operation_id"),
            (&self.request_id, "relation.draft.request_id"),
            (&self.idempotency_key, "relation.draft.idempotency_key"),
            (&self.task_id, "relation.draft.task_id"),
            (&self.scope_id, "relation.draft.scope_id"),
        ] {
            check_text(value, field, MAX_TEXT)?;
        }
        if !is_hex64_lower(&self.policy_digest) {
            return Err(ContractViolation::Malformed {
                field: "relation.draft.policy_digest",
                reason: "must be lowercase sha256".to_owned(),
            });
        }
        check_fence(&self.state_fence)?;
        Ok(())
    }

    /// Assembles the closed [`RelationInput`] from this draft plus the
    /// separately supplied validated item, endpoint pair, registry snapshot
    /// and neighborhood. Assembly copies caller-owned records; it admits,
    /// creates or reclassifies nothing.
    #[must_use]
    pub fn assemble(
        &self,
        validated: &ValidatedCurationItem,
        source: &RelationEndpoint,
        target: &RelationEndpoint,
        registry: &RelationRegistrySnapshot,
        neighborhood: &RelationNeighborhood,
    ) -> RelationInput {
        RelationInput {
            schema_version: self.schema_version,
            operation_id: self.operation_id.clone(),
            request_id: self.request_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            task_id: self.task_id.clone(),
            scope_id: self.scope_id.clone(),
            state_fence: self.state_fence.clone(),
            policy_digest: self.policy_digest.clone(),
            item: validated.clone(),
            source: source.clone(),
            target: target.clone(),
            family: self.family,
            direction: self.direction,
            registry: registry.clone(),
            neighborhood: neighborhood.clone(),
            screen: self.screen.clone(),
            evidence: self.evidence.clone(),
            counterevidence: self.counterevidence.clone(),
            rivals: self.rivals.clone(),
            no_relation_alternative: self.no_relation_alternative.clone(),
            temporal: self.temporal.clone(),
            verifier: self.verifier.clone(),
            disclosure_evidence: self.disclosure_evidence.clone(),
            preservation: self.preservation.clone(),
        }
    }
}
