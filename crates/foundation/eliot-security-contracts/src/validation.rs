//! Bounded validation for the C0-12 contract surface.

use std::collections::BTreeSet;

use eliot_contracts::{ContractError, StateFence, canonical_json_bytes, sha256_hex};
use thiserror::Error;

use crate::{
    ClosureCompleteness, DeclassificationReceipt, DisclosureDecision, DisclosureDecisionKind,
    DisclosureDependencyClosure, InfluenceDependencyClosure, InfluenceState, ObservationDomainRef,
    PurgeLedgerEntry, PurgeState, SelectionIntegrityReceipt, SourceAssurance,
    TransformationLineage,
};

/// Validation failure that never carries protected payload content.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SecurityContractError {
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must not contain duplicate references")]
    DuplicateReference { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("state fence is invalid for {field}")]
    InvalidFence { field: &'static str },
    #[error("state fence differs across security contract lineage")]
    FenceMismatch,
    #[error("disclosure closure is incomplete")]
    DisclosureClosureIncomplete,
    #[error("disclosure decision does not cover every domain")]
    DisclosureCoverageGap,
    #[error("taint was cleared without a declassification receipt")]
    TaintLaundering,
    #[error("revoked influence is still marked active")]
    RevokedInfluenceActive,
    #[error("revoked influence has no invalidation reason")]
    RevocationMissingReason,
    #[error("purged content cannot be restored as current")]
    PurgeResurrection,
    #[error("selection integrity lineage is invalid")]
    SelectionIntegrityViolation,
    #[error("canonical security contract serialization failed: {0}")]
    Serialization(String),
}

fn text(value: &str, field: &'static str) -> Result<(), SecurityContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SecurityContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), SecurityContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(SecurityContractError::InvalidText { field });
    }
    Ok(())
}

fn unique<'a, I>(values: I, field: &'static str) -> Result<(), SecurityContractError>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(SecurityContractError::DuplicateReference { field });
    }
    Ok(())
}

fn fence(value: &StateFence, field: &'static str) -> Result<(), SecurityContractError> {
    value
        .validate()
        .map_err(|_| SecurityContractError::InvalidFence { field })
}

impl SourceAssurance {
    /// Validates origin, taint and effect ceilings without granting authority.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.source_ref, "source_ref")?;
        text(&self.provenance_ref, "provenance_ref")?;
        if self.allowed_epistemic_use.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "allowed_epistemic_use",
            });
        }
        if self.allowed_effects.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "allowed_effects",
            });
        }
        if let Some(verifier) = &self.required_verifier {
            text(verifier, "required_verifier")?;
        }
        fence(&self.state_fence, "source_assurance.state_fence")
    }
}

impl ObservationDomainRef {
    /// Validates opaque domain identity and the policy-facing boundary fields.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.domain_id, "domain_id")?;
        text(&self.authority_root, "authority_root")?;
        text(&self.resource_scope, "resource_scope")?;
        text(
            &self.visibility_and_export_rule,
            "visibility_and_export_rule",
        )?;
        text(&self.model_route_rule, "model_route_rule")?;
        fence(&self.state_fence, "domain.state_fence")
    }
}

impl DisclosureDependencyClosure {
    /// Validates explicit disclosure lineage and fence binding.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.closure_id, "closure_id")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.policy_snapshot_id, "policy_snapshot_id")?;
        if self.direct_domain_refs.is_empty() && self.inherited_closure_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "closure_domains",
            });
        }
        unique(
            self.direct_domain_refs.iter().map(|item| &item.domain_id),
            "direct_domain_refs",
        )?;
        unique(self.inherited_closure_refs.iter(), "inherited_closure_refs")?;
        unique(
            self.derivation_or_transformation_refs.iter(),
            "derivation_or_transformation_refs",
        )?;
        fence(&self.state_fence, "disclosure_closure.state_fence")?;
        for domain in &self.direct_domain_refs {
            domain.validate()?;
            if domain.state_fence != self.state_fence {
                return Err(SecurityContractError::FenceMismatch);
            }
        }
        Ok(())
    }
}

impl DeclassificationReceipt {
    /// Validates the non-content proof that permits a closure/taint reduction.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.input_closure_ref, "input_closure_ref")?;
        text(
            &self.transformation_id_and_version,
            "transformation_id_and_version",
        )?;
        validate_digest(&self.exact_input_hash, "exact_input_hash")?;
        validate_digest(&self.exact_output_hash, "exact_output_hash")?;
        text(&self.verifier_and_property, "verifier_and_property")?;
        text(&self.authority_and_policy_ref, "authority_and_policy_ref")?;
        if self.removed_or_generalized_domains.is_empty() && self.preserved_domains.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "declassification.domain_sets",
            });
        }
        unique(
            self.removed_or_generalized_domains.iter(),
            "removed_or_generalized_domains",
        )?;
        unique(self.preserved_domains.iter(), "preserved_domains")?;
        fence(&self.state_fence, "declassification.state_fence")
    }
}

impl DisclosureDecision {
    /// Validates that remote disclosure is never inferred from an incomplete closure.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.subject_and_closure_ref, "subject_and_closure_ref")?;
        text(
            &self.recipient_principal_or_route,
            "recipient_principal_or_route",
        )?;
        text(&self.receipt_ref, "receipt_ref")?;
        text(
            &self.policy_snapshot_and_state_fence.policy_snapshot_id,
            "policy_snapshot_id",
        )?;
        fence(
            &self.policy_snapshot_and_state_fence.state_fence,
            "disclosure_decision.state_fence",
        )?;
        unique(self.covered_domains.iter(), "covered_domains")?;
        unique(self.uncovered_domains.iter(), "uncovered_domains")?;
        if matches!(
            self.decision,
            DisclosureDecisionKind::Allow | DisclosureDecisionKind::AllowRedacted
        ) && (self.closure_completeness != ClosureCompleteness::Complete
            || !self.uncovered_domains.is_empty())
        {
            return Err(
                if self.closure_completeness != ClosureCompleteness::Complete {
                    SecurityContractError::DisclosureClosureIncomplete
                } else {
                    SecurityContractError::DisclosureCoverageGap
                },
            );
        }
        Ok(())
    }
}

impl TransformationLineage {
    /// Validates taint conservation across a structural transformation.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.transformation_id, "transformation_id")?;
        text(&self.output_ref, "output_ref")?;
        if self.input_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "input_refs",
            });
        }
        unique(self.input_refs.iter(), "input_refs")?;
        fence(&self.state_fence, "transformation.state_fence")?;
        if self.output_taint < self.input_taint && self.declassification_receipt_ref.is_none() {
            return Err(SecurityContractError::TaintLaundering);
        }
        Ok(())
    }
}

impl InfluenceDependencyClosure {
    /// Validates explicit revocation closure and prevents active revoked views.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.closure_id, "closure_id")?;
        text(&self.root_ref, "root_ref")?;
        if self.dependent_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "dependent_refs",
            });
        }
        unique(self.dependent_refs.iter(), "dependent_refs")?;
        fence(&self.state_fence, "influence.state_fence")?;
        if self.current_influence == InfluenceState::Revoked && self.invalidation_reason.is_none() {
            return Err(SecurityContractError::RevocationMissingReason);
        }
        if self.invalidation_reason.is_some() && self.current_influence == InfluenceState::Active {
            return Err(SecurityContractError::RevokedInfluenceActive);
        }
        Ok(())
    }
}

impl PurgeLedgerEntry {
    /// Validates non-revealing purge state and rejects restore resurrection.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.purge_id, "purge_id")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.scope, "scope")?;
        if self.purged_locations.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "purged_locations",
            });
        }
        let digest_ok = self.tombstone_digest.len() == 64
            && self
                .tombstone_digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !digest_ok {
            return Err(SecurityContractError::InvalidText {
                field: "tombstone_digest",
            });
        }
        fence(&self.state_fence, "purge.state_fence")
    }

    /// A purged entry is terminal for current availability.
    pub fn validate_restore(&self) -> Result<(), SecurityContractError> {
        self.validate()?;
        if self.state == PurgeState::Purged {
            return Err(SecurityContractError::PurgeResurrection);
        }
        Ok(())
    }
}

impl SelectionIntegrityReceipt {
    /// Validates candidate membership and every declared transformation stage.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.selection_id, "selection_id")?;
        if self.initial_candidate_refs.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "initial_candidate_refs",
            });
        }
        unique(self.initial_candidate_refs.iter(), "initial_candidate_refs")?;
        unique(
            self.admitted_candidate_refs.iter(),
            "admitted_candidate_refs",
        )?;
        unique(
            self.rejected_candidate_refs.iter(),
            "rejected_candidate_refs",
        )?;
        unique(self.final_output_refs.iter(), "final_output_refs")?;
        fence(&self.state_fence, "selection.state_fence")?;
        if self
            .admitted_candidate_refs
            .iter()
            .any(|item| self.rejected_candidate_refs.contains(item))
        {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        if self.initial_candidate_refs.iter().any(|item| {
            !self.admitted_candidate_refs.contains(item)
                && !self.rejected_candidate_refs.contains(item)
        }) {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        for stage in &self.transformation_stages {
            if stage.input_refs.is_empty()
                || stage.output_refs.is_empty()
                || stage.disclosure_closure_ref.trim().is_empty()
            {
                return Err(SecurityContractError::SelectionIntegrityViolation);
            }
            fence(&stage.state_fence, "selection.stage.state_fence")?;
            if stage.state_fence != self.state_fence {
                return Err(SecurityContractError::FenceMismatch);
            }
            if stage
                .input_refs
                .iter()
                .any(|item| !self.admitted_candidate_refs.contains(item))
            {
                return Err(SecurityContractError::SelectionIntegrityViolation);
            }
        }
        if self.final_output_refs.iter().any(|item| {
            !self.admitted_candidate_refs.contains(item)
                && !self
                    .transformation_stages
                    .iter()
                    .any(|stage| stage.output_refs.contains(item))
        }) {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        if self.untrusted_structure_changed_membership {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        Ok(())
    }
}

/// Validates one selection receipt and returns a digest suitable for lineage.
pub fn validate_selection_pipeline(
    receipt: &SelectionIntegrityReceipt,
) -> Result<String, SecurityContractError> {
    receipt.validate()?;
    canonical_json_bytes(receipt)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SecurityContractError::Serialization(error.to_string()))
}
