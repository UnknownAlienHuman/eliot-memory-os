//! Typed relation-edge inputs supplied by the relation-registry owner.

use eliot_evidence::{EvidenceEnvelope, RelationKind};
use serde::{Deserialize, Serialize};

use crate::{CueContractError, Digest, RelationEdgeId, TargetHandle, bounds};

/// One immutable relation edge offered to bounded activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RelationEdge {
    /// Registry identity of this edge.
    pub relation_edge_id: RelationEdgeId,
    /// Canonical relation family supplied by the registry owner.
    pub kind: RelationKind,
    /// Edge source endpoint.
    pub from: TargetHandle,
    /// Edge destination endpoint.
    pub to: TargetHandle,
    /// Registry revision under which direction and kind were resolved.
    pub registry_revision: String,
    /// Digest of the immutable edge record.
    pub edge_digest: Digest,
    /// Evidence lineage and epistemic/proof ceiling for the edge.
    pub evidence: EvidenceEnvelope,
}

impl RelationEdge {
    /// Constructs an edge from registry and evidence-owned fields.
    #[must_use]
    pub const fn new(
        relation_edge_id: RelationEdgeId,
        kind: RelationKind,
        from: TargetHandle,
        to: TargetHandle,
        registry_revision: String,
        edge_digest: Digest,
        evidence: EvidenceEnvelope,
    ) -> Self {
        Self {
            relation_edge_id,
            kind,
            from,
            to,
            registry_revision,
            edge_digest,
            evidence,
        }
    }

    /// Validates edge shape and lower-level provenance/fence contracts.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(self.from.as_str(), "relation.from")?;
        bounds::text(self.to.as_str(), "relation.to")?;
        bounds::text(&self.registry_revision, "relation.registry_revision")?;
        if self.edge_digest.as_str().len() != 64 {
            return Err(CueContractError::InvalidText {
                field: "relation.edge_digest",
            });
        }
        bounds::provenance(&self.evidence.provenance, "relation.evidence.provenance")?;
        if let Some(binding) = self.evidence.verification.as_ref() {
            bounds::text(
                binding.contract_id.as_str(),
                "relation.evidence.verification",
            )?;
            bounds::text(binding.run_id.as_str(), "relation.evidence.verification")?;
            bounds::text(&binding.revision, "relation.evidence.verification")?;
        }
        self.evidence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "relation.evidence",
            })?;
        self.evidence
            .state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "relation.state_fence",
            })?;
        Ok(())
    }
}
