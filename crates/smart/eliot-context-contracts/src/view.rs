//! Assembled view and intrinsic selection-integrity proof.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmittedAtom, AdmittedContextSet, AuthorityClass, ContextBinding, ContextError, LossPolicy,
    PrivacyClass, QualityScorecard, SerializedContextMeasurement,
};

/// Rendered projection of one admitted atom, retaining all load-bearing fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderedAtom {
    pub atom_id: ArtifactId,
    pub role: crate::SemanticRole,
    pub source_id: ArtifactId,
    pub provider: crate::ProviderId,
    pub representation: crate::AtomRepresentation,
    pub protected: bool,
    pub privacy: PrivacyClass,
    pub authority: AuthorityClass,
    pub loss_policy: LossPolicy,
}

impl RenderedAtom {
    fn from_admitted(atom: &AdmittedAtom) -> Self {
        Self {
            atom_id: atom.candidate.atom_id.clone(),
            role: atom.candidate.provider_role.role,
            source_id: atom.candidate.source.snapshot_id.clone(),
            provider: atom.candidate.provider_role.provider.clone(),
            representation: atom.candidate.representation.clone(),
            protected: atom.candidate.protected,
            privacy: atom.candidate.privacy,
            authority: atom.candidate.authority,
            loss_policy: atom.candidate.loss_policy,
        }
    }
}

/// Proof that rendered membership is exactly admitted membership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionIntegrityProof {
    pub binding: ContextBinding,
    pub admitted_ids: Vec<ArtifactId>,
    pub rendered_ids: Vec<ArtifactId>,
    pub omission_evidence: Vec<ArtifactId>,
    pub output_digest: String,
}

impl SelectionIntegrityProof {
    /// Validate exact set equality with one occurrence per identity.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        let admitted: BTreeSet<_> = self.admitted_ids.iter().cloned().collect();
        let rendered: BTreeSet<_> = self.rendered_ids.iter().cloned().collect();
        if admitted.len() != self.admitted_ids.len()
            || rendered.len() != self.rendered_ids.len()
            || admitted != rendered
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        if self.omission_evidence.len() > 256 {
            return Err(ContextError::Bounds {
                field: "selection.omission_evidence",
            });
        }
        crate::validate_digest(&self.output_digest, "selection.output_digest")
    }
}

/// Immutable Active Understanding View assembled from an admitted set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveUnderstandingView {
    pub binding: ContextBinding,
    pub admitted_ids: Vec<ArtifactId>,
    pub rendered: Vec<RenderedAtom>,
    pub selection: SelectionIntegrityProof,
    pub quality: QualityScorecard,
    pub measurement: SerializedContextMeasurement,
    pub output_digest: String,
    pub recipe_digest: String,
    pub fence_digest: String,
}

impl ActiveUnderstandingView {
    /// Assemble a view by projection only; membership is never selected here.
    pub fn assemble(
        admitted: &AdmittedContextSet,
        quality: QualityScorecard,
        measurement: SerializedContextMeasurement,
        output_digest: String,
        recipe_digest: String,
        fence_digest: String,
    ) -> Result<Self, ContextError> {
        admitted.validate()?;
        quality.validate()?;
        measurement.validate()?;
        if quality.binding != admitted.binding || measurement.context != admitted.binding {
            return Err(ContextError::InvalidFence);
        }
        let selected: Vec<_> = admitted
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.disposition,
                    crate::AdmissionDisposition::Include | crate::AdmissionDisposition::HandleOnly
                )
            })
            .map(RenderedAtom::from_admitted)
            .collect();
        let ids = selected
            .iter()
            .map(|atom| atom.atom_id.clone())
            .collect::<Vec<_>>();
        let selection = SelectionIntegrityProof {
            binding: admitted.binding.clone(),
            admitted_ids: ids.clone(),
            rendered_ids: ids.clone(),
            omission_evidence: admitted.economy.displaced.clone(),
            output_digest: output_digest.clone(),
        };
        selection.validate()?;
        crate::validate_digest(&output_digest, "view.output_digest")?;
        crate::validate_digest(&recipe_digest, "view.recipe_digest")?;
        crate::validate_digest(&fence_digest, "view.fence_digest")?;
        let view = Self {
            binding: admitted.binding.clone(),
            admitted_ids: ids,
            rendered: selected,
            selection,
            quality,
            measurement,
            output_digest,
            recipe_digest,
            fence_digest,
        };
        view.validate_against(admitted)?;
        Ok(view)
    }

    /// Validate every rendered field against the exact admitted record.
    pub fn validate_against(&self, admitted: &AdmittedContextSet) -> Result<(), ContextError> {
        self.validate()?;
        if self.binding != admitted.binding {
            return Err(ContextError::InvalidFence);
        }
        let expected_omissions: BTreeSet<_> = admitted.economy.displaced.iter().cloned().collect();
        let actual_omissions: BTreeSet<_> =
            self.selection.omission_evidence.iter().cloned().collect();
        if expected_omissions != actual_omissions {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        let expected: Vec<_> = admitted
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.disposition,
                    crate::AdmissionDisposition::Include | crate::AdmissionDisposition::HandleOnly
                )
            })
            .collect();
        if expected.len() != self.rendered.len() {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        for record in expected {
            let rendered = self
                .rendered
                .iter()
                .find(|atom| atom.atom_id == record.candidate.atom_id)
                .ok_or(ContextError::SelectionIntegrityMismatch)?;
            if rendered.role != record.candidate.provider_role.role
                || rendered.provider != record.candidate.provider_role.provider
                || rendered.source_id != record.candidate.source.snapshot_id
                || rendered.representation != record.candidate.representation
                || rendered.protected != record.candidate.protected
                || rendered.privacy != record.candidate.privacy
                || rendered.authority != record.candidate.authority
                || rendered.loss_policy != record.candidate.loss_policy
            {
                return Err(ContextError::SelectionIntegrityMismatch);
            }
        }
        Ok(())
    }

    /// Detect any post-assembly mutation or injected non-admitted content.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.binding.validate()?;
        self.selection.validate()?;
        if self.selection.output_digest != self.output_digest {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        self.quality.validate()?;
        self.measurement.validate()?;
        if self.selection.binding != self.binding
            || self.quality.binding != self.binding
            || self.measurement.context != self.binding
        {
            return Err(ContextError::InvalidFence);
        }
        let rendered_ids = self
            .rendered
            .iter()
            .map(|atom| atom.atom_id.clone())
            .collect::<Vec<_>>();
        if rendered_ids != self.selection.rendered_ids
            || self.admitted_ids != self.selection.admitted_ids
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        if self
            .rendered
            .iter()
            .any(|atom| atom.representation.validate().is_err())
        {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        crate::validate_digest(&self.output_digest, "view.output_digest")?;
        crate::validate_digest(&self.recipe_digest, "view.recipe_digest")?;
        crate::validate_digest(&self.fence_digest, "view.fence_digest")
    }
}
