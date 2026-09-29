//! Bounded validation for the C0-12 contract surface.

use std::collections::BTreeSet;

use eliot_contracts::{ContractError, StateFence, canonical_json_bytes, sha256_hex};
use thiserror::Error;

use crate::{
    ClosureCompleteness, DeclassificationReceipt, DisclosureDecision, DisclosureDecisionKind,
    DisclosureDependencyClosure, InfluenceDependencyClosure, InfluenceState,
    LegacySelectionIntegrityReceiptV1, MAX_SELECTION_MEMBERS, MAX_SELECTION_STAGES,
    ObservationDomainRef, PurgeLedgerEntry, PurgeState, SELECTION_INTEGRITY_SCHEMA,
    SelectionChainHead, SelectionChainSeal, SelectionInfluenceState, SelectionIntegrityReceipt,
    SelectionMember, SelectionMemberDisposition, SelectionMemberDispositionKind, SelectionStage,
    SelectionStageLink, SourceAssurance, TransformationLineage,
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
    #[error("selection integrity schema or contract version is unsupported")]
    SelectionSchemaUnsupported,
    #[error("selection chain declares {count} stages, above the bound {bound}")]
    SelectionStageLimitExceeded { count: usize, bound: usize },
    #[error("selection {field} declares {count} members, above the bound {bound}")]
    SelectionMemberLimitExceeded {
        field: &'static str,
        count: usize,
        bound: usize,
    },
    #[error(
        "selection stage {stage_id} is at ordinal {ordinal}, outside the contiguous chain order"
    )]
    SelectionStageOrder { stage_id: String, ordinal: usize },
    #[error("selection stage {stage_id} at ordinal {ordinal} conflicts with an earlier stage")]
    SelectionStageConflict { stage_id: String, ordinal: usize },
    #[error(
        "selection stage {stage_id} at ordinal {ordinal} does not continue its declared input link"
    )]
    SelectionStageLinkBroken { stage_id: String, ordinal: usize },
    #[error(
        "selection stage {stage_id} at ordinal {ordinal} does not bind its {digest} membership"
    )]
    SelectionStageMembershipDigest {
        stage_id: String,
        ordinal: usize,
        digest: &'static str,
    },
    #[error("selection initial candidate membership does not bind its {field} digest")]
    SelectionInitialMembershipDigest { field: &'static str },
    #[error(
        "selection stage {stage_id} at ordinal {ordinal} introduces member {member_ref} without admitted source evidence"
    )]
    SelectionMemberFabricated {
        stage_id: String,
        ordinal: usize,
        member_ref: String,
    },
    #[error(
        "selection stage {stage_id} at ordinal {ordinal} drops member {member_ref} without a disposition"
    )]
    SelectionMemberLoss {
        stage_id: String,
        ordinal: usize,
        member_ref: String,
    },
    #[error(
        "selection stage {stage_id} at ordinal {ordinal} records a disposition that contradicts the membership of {member_ref}"
    )]
    SelectionMemberDisposition {
        stage_id: String,
        ordinal: usize,
        member_ref: String,
    },
    #[error(
        "selection chain claims {claimed:?} untrusted influence while a stage records {observed:?}"
    )]
    SelectionInfluenceUnderstated {
        claimed: SelectionInfluenceState,
        observed: SelectionInfluenceState,
    },
    #[error(
        "legacy selection member {member_ref} has no owner-supplied revision and representation binding"
    )]
    SelectionLegacyMemberUnbound { member_ref: String },
    #[error("legacy selection stage at ordinal {ordinal} is not attributable to its input members")]
    SelectionLegacyStageUnattributable { ordinal: usize },
    #[error(
        "selection chain head names ordinal {expected}, but this chain carries {observed} stages"
    )]
    SelectionChainHeadOrdinal { expected: usize, observed: usize },
    #[error("selection chain head does not bind the digest of its own stage prefix")]
    SelectionChainHeadDigest,
    #[error("selection chain head does not name the chain it belongs to")]
    SelectionChainHeadIdentity,
    #[error("selection chain head carries no stable append idempotency identity")]
    SelectionChainHeadIdempotency,
    #[error(
        "selection seal is taken against chain head {expected}, but the chain head recomputes to {observed}"
    )]
    SelectionSealChainSubstituted { expected: String, observed: String },
    #[error("selection seal does not name the chain or recipe revision it was taken for")]
    SelectionSealIdentity,
    #[error(
        "selection seal final membership does not bind its ordered digest, or its order is not the chain's final order"
    )]
    SelectionSealFinalMembership,
    #[error("selection seal does not bind the exact delivered packet or export bytes")]
    SelectionSealPacketBytes,
    #[error("selection seal does not bind the exact expansion handles delivered with it")]
    SelectionSealExpansionHandles,
    #[error("selection seal declares a membership page without a complete closure reference")]
    SelectionSealPageClosureMissing,
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
    ///
    /// # Errors
    ///
    /// Returns an error when source identity, effect ceilings, or its state fence
    /// is invalid.
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
    ///
    /// # Errors
    ///
    /// Returns an error when a domain identity, policy field, or state fence is
    /// invalid.
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
    ///
    /// # Errors
    ///
    /// Returns an error when lineage references are missing, duplicated, or do
    /// not share the declared state fence.
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
    ///
    /// # Errors
    ///
    /// Returns an error when hashes, references, domain sets, or the state fence
    /// are invalid.
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
    ///
    /// # Errors
    ///
    /// Returns an error when policy fencing is invalid or a permitted decision has
    /// incomplete coverage.
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
                if self.closure_completeness == ClosureCompleteness::Complete {
                    SecurityContractError::DisclosureCoverageGap
                } else {
                    SecurityContractError::DisclosureClosureIncomplete
                },
            );
        }
        Ok(())
    }
}

impl TransformationLineage {
    /// Validates taint conservation across a structural transformation.
    ///
    /// # Errors
    ///
    /// Returns an error when transformation references, fencing, or taint
    /// declassification requirements are invalid.
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
    ///
    /// # Errors
    ///
    /// Returns an error when dependent references, fencing, or revocation state
    /// is inconsistent.
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
    ///
    /// # Errors
    ///
    /// Returns an error when purge identity, tombstone digest, location set, or
    /// state fencing is invalid.
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
    ///
    /// # Errors
    ///
    /// Returns an error when the entry is invalid or already purged.
    pub fn validate_restore(&self) -> Result<(), SecurityContractError> {
        self.validate()?;
        if self.state == PurgeState::Purged {
            return Err(SecurityContractError::PurgeResurrection);
        }
        Ok(())
    }
}

/// Computes the canonical digest of one selection membership collection.
///
/// The digest binds member identity, revision and representation in declared
/// order, so it proves the exact ordered membership a stage consumed or
/// produced. A display label, a count or an order-insensitive set digest is not
/// a substitute for it (#1728 step 2).
///
/// # Errors
///
/// Returns an error when the membership cannot be serialized canonically.
pub fn selection_member_digest(
    members: &[SelectionMember],
) -> Result<String, SecurityContractError> {
    canonical_json_bytes(&members)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SecurityContractError::Serialization(error.to_string()))
}

fn member_refs(members: &[SelectionMember]) -> BTreeSet<&str> {
    members
        .iter()
        .map(|member| member.member_ref.as_str())
        .collect()
}

fn validate_members(
    members: &[SelectionMember],
    field: &'static str,
) -> Result<(), SecurityContractError> {
    if members.len() > MAX_SELECTION_MEMBERS {
        return Err(SecurityContractError::SelectionMemberLimitExceeded {
            field,
            count: members.len(),
            bound: MAX_SELECTION_MEMBERS,
        });
    }
    unique(members.iter().map(|member| &member.member_ref), field)?;
    for member in members {
        text(&member.member_ref, "selection.member.member_ref")?;
        text(&member.member_revision, "selection.member.member_revision")?;
        text(
            &member.representation_ref,
            "selection.member.representation_ref",
        )?;
    }
    Ok(())
}

fn validate_disposition(
    stage: &SelectionStage,
    ordinal: usize,
    disposition: &SelectionMemberDisposition,
) -> Result<(), SecurityContractError> {
    text(
        &disposition.member_ref,
        "selection.member_disposition.member_ref",
    )?;
    if let Some(reason) = &disposition.reason {
        text(reason, "selection.member_disposition.reason")?;
    }
    if let Some(derived) = &disposition.derived_output_ref {
        text(derived, "selection.member_disposition.derived_output_ref")?;
    }
    if let Some(evidence) = &disposition.source_evidence_ref {
        text(evidence, "selection.member_disposition.source_evidence_ref")?;
    }
    let conflict = || SecurityContractError::SelectionMemberDisposition {
        stage_id: stage.stage_id.clone(),
        ordinal,
        member_ref: disposition.member_ref.clone(),
    };
    let derived_is_output = disposition
        .derived_output_ref
        .as_deref()
        .is_some_and(|derived| {
            stage
                .output_members
                .iter()
                .any(|member| member.member_ref == derived)
        });
    let coherent = match disposition.disposition {
        SelectionMemberDispositionKind::Retained => {
            disposition.reason.is_none()
                && disposition.derived_output_ref.is_none()
                && disposition.source_evidence_ref.is_none()
        }
        SelectionMemberDispositionKind::Removed => {
            disposition.reason.is_some()
                && disposition.derived_output_ref.is_none()
                && disposition.source_evidence_ref.is_none()
        }
        SelectionMemberDispositionKind::Derived => {
            disposition.derived_output_ref.is_some()
                && derived_is_output
                && disposition.source_evidence_ref.is_none()
        }
        SelectionMemberDispositionKind::Admitted => {
            disposition.source_evidence_ref.is_some()
                && disposition.derived_output_ref.is_none()
                && disposition.reason.is_none()
        }
    };
    if coherent { Ok(()) } else { Err(conflict()) }
}

/// Validates one stage's declared input link against the earlier stages.
///
/// Ordinal zero starts from the declared initial set. Every later ordinal either
/// names the immediately preceding stage and reproduces its complete output
/// membership, or names a join over the complete output memberships of two or
/// more earlier stages.
fn validate_stage_link(
    receipt: &SelectionIntegrityReceipt,
    stage: &SelectionStage,
    ordinal: usize,
) -> Result<(), SecurityContractError> {
    let broken = || SecurityContractError::SelectionStageLinkBroken {
        stage_id: stage.stage_id.clone(),
        ordinal,
    };
    let input = member_refs(&stage.input_members);
    let Some(link) = &stage.input_link else {
        return if ordinal == 0 && stage.input_members == receipt.initial_candidate_members {
            Ok(())
        } else {
            Err(broken())
        };
    };
    if ordinal == 0 {
        return Err(broken());
    }
    match link {
        SelectionStageLink::FromPredecessor {
            predecessor_stage_id,
        } => {
            let Some(predecessor) = receipt.transformation_stages.get(ordinal - 1) else {
                return Err(broken());
            };
            if predecessor.stage_id != *predecessor_stage_id
                || stage.input_members != predecessor.output_members
            {
                return Err(broken());
            }
            Ok(())
        }
        SelectionStageLink::FromJoin { parent_stage_ids } => {
            if parent_stage_ids.len() < 2
                || unique(parent_stage_ids.iter(), "parent_stage_ids").is_err()
            {
                return Err(broken());
            }
            let mut covered = BTreeSet::new();
            for parent_stage_id in parent_stage_ids {
                let Some(parent) = receipt
                    .transformation_stages
                    .iter()
                    .find(|candidate| candidate.stage_id == *parent_stage_id)
                else {
                    return Err(broken());
                };
                if parent.ordinal >= ordinal {
                    return Err(broken());
                }
                covered.extend(member_refs(&parent.output_members));
            }
            if covered == input {
                Ok(())
            } else {
                Err(broken())
            }
        }
    }
}

/// Validates one disposition row against the stage membership it accounts for.
fn validate_disposition_placement(
    stage: &SelectionStage,
    ordinal: usize,
    disposition: &SelectionMemberDisposition,
    input: &BTreeSet<&str>,
    output: &BTreeSet<&str>,
) -> Result<(), SecurityContractError> {
    let member_ref = disposition.member_ref.as_str();
    let contradiction = || SecurityContractError::SelectionMemberDisposition {
        stage_id: stage.stage_id.clone(),
        ordinal,
        member_ref: disposition.member_ref.clone(),
    };
    if input.contains(member_ref) {
        let reaches_output = output.contains(member_ref);
        return match (disposition.disposition, reaches_output) {
            (SelectionMemberDispositionKind::Retained, true)
            | (
                SelectionMemberDispositionKind::Removed | SelectionMemberDispositionKind::Derived,
                false,
            ) => Ok(()),
            _ => Err(contradiction()),
        };
    }
    if output.contains(member_ref)
        && disposition.disposition == SelectionMemberDispositionKind::Admitted
    {
        Ok(())
    } else {
        Err(contradiction())
    }
}

/// Validates one stage's membership accounting: exact digests, a disposition
/// for every input member, admitted source evidence for every newly introduced
/// output member, and no unexplained loss.
fn validate_stage_membership(
    stage: &SelectionStage,
    ordinal: usize,
) -> Result<(), SecurityContractError> {
    for (members, declared, digest) in [
        (&stage.input_members, &stage.input_digest, "input_digest"),
        (&stage.output_members, &stage.output_digest, "output_digest"),
    ] {
        if declared != &selection_member_digest(members)? {
            return Err(SecurityContractError::SelectionStageMembershipDigest {
                stage_id: stage.stage_id.clone(),
                ordinal,
                digest,
            });
        }
    }
    if stage.member_dispositions.len() > MAX_SELECTION_MEMBERS {
        return Err(SecurityContractError::SelectionMemberLimitExceeded {
            field: "stage.member_dispositions",
            count: stage.member_dispositions.len(),
            bound: MAX_SELECTION_MEMBERS,
        });
    }
    let input = member_refs(&stage.input_members);
    let output = member_refs(&stage.output_members);
    let mut accounted = BTreeSet::new();
    let mut introduced = BTreeSet::new();
    for disposition in &stage.member_dispositions {
        validate_disposition(stage, ordinal, disposition)?;
        if !accounted.insert(disposition.member_ref.as_str()) {
            return Err(SecurityContractError::DuplicateReference {
                field: "stage.member_dispositions",
            });
        }
        if let Some(derived) = &disposition.derived_output_ref {
            introduced.insert(derived.as_str());
        }
        if disposition.disposition == SelectionMemberDispositionKind::Admitted {
            introduced.insert(disposition.member_ref.as_str());
        }
        validate_disposition_placement(stage, ordinal, disposition, &input, &output)?;
    }
    for member in &stage.input_members {
        if !accounted.contains(member.member_ref.as_str()) {
            return Err(SecurityContractError::SelectionMemberLoss {
                stage_id: stage.stage_id.clone(),
                ordinal,
                member_ref: member.member_ref.clone(),
            });
        }
    }
    for member in &stage.output_members {
        let member_ref = member.member_ref.as_str();
        if !input.contains(member_ref) && !introduced.contains(member_ref) {
            return Err(SecurityContractError::SelectionMemberFabricated {
                stage_id: stage.stage_id.clone(),
                ordinal,
                member_ref: member.member_ref.clone(),
            });
        }
    }
    Ok(())
}

impl SelectionIntegrityReceipt {
    /// Validates candidate membership and stage-to-stage continuity of the
    /// declared transformation chain.
    ///
    /// Structural validation accepts a well-formed record of known or unknown
    /// untrusted influence so the history can be audited; it never discards a
    /// history because the recorded outcome is unsafe. Whether the recorded
    /// membership may be relied on is a separate selection, disclosure and
    /// admission decision.
    ///
    /// # Errors
    ///
    /// Returns a typed error naming the exact stage ordinal, stage identity or
    /// member that failed.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        self.validate_header()?;
        self.validate_stages()?;
        self.validate_outcome()
    }

    /// Validates the chain identity, the immutable initial membership and the
    /// candidate-level admission partition.
    fn validate_header(&self) -> Result<(), SecurityContractError> {
        if self.schema != SELECTION_INTEGRITY_SCHEMA
            || self.contract_version != crate::CONTRACT_VERSION
        {
            return Err(SecurityContractError::SelectionSchemaUnsupported);
        }
        text(&self.selection_id, "selection_id")?;
        text(&self.root_context_ref, "root_context_ref")?;
        text(&self.recipe_revision, "recipe_revision")?;
        fence(&self.state_fence, "selection.state_fence")?;
        if self.initial_candidate_members.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "initial_candidate_members",
            });
        }
        validate_members(&self.initial_candidate_members, "initial_candidate_members")?;
        if self.initial_candidate_digest
            != selection_member_digest(&self.initial_candidate_members)?
        {
            return Err(SecurityContractError::SelectionInitialMembershipDigest {
                field: "initial_candidate_digest",
            });
        }
        unique(
            self.admitted_candidate_refs.iter(),
            "admitted_candidate_refs",
        )?;
        unique(
            self.rejected_candidate_refs.iter(),
            "rejected_candidate_refs",
        )?;
        unique(self.final_output_refs.iter(), "final_output_refs")?;
        if self
            .admitted_candidate_refs
            .iter()
            .any(|item| self.rejected_candidate_refs.contains(item))
        {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        let initial = member_refs(&self.initial_candidate_members);
        if initial.iter().any(|item| {
            !self.admitted_candidate_refs.contains(&(*item).to_owned())
                && !self.rejected_candidate_refs.contains(&(*item).to_owned())
        }) {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        Ok(())
    }

    /// Validates the bounded, contiguously ordered stage chain and every stage
    /// against the initial set and its declared predecessor.
    fn validate_stages(&self) -> Result<(), SecurityContractError> {
        if self.transformation_stages.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "transformation_stages",
            });
        }
        if self.transformation_stages.len() > MAX_SELECTION_STAGES {
            return Err(SecurityContractError::SelectionStageLimitExceeded {
                count: self.transformation_stages.len(),
                bound: MAX_SELECTION_STAGES,
            });
        }
        let mut seen_stage_ids = BTreeSet::new();
        for (ordinal, stage) in self.transformation_stages.iter().enumerate() {
            self.validate_stage_shape(stage, ordinal, &mut seen_stage_ids)?;
            validate_members(&stage.input_members, "stage.input_members")?;
            validate_members(&stage.output_members, "stage.output_members")?;
            validate_stage_link(self, stage, ordinal)?;
            validate_stage_membership(stage, ordinal)?;
        }
        Ok(())
    }

    /// Validates one stage's identity, order, transformer binding, evidence
    /// references and fence before its membership is accounted for.
    fn validate_stage_shape<'a>(
        &self,
        stage: &'a SelectionStage,
        ordinal: usize,
        seen_stage_ids: &mut BTreeSet<&'a str>,
    ) -> Result<(), SecurityContractError> {
        text(&stage.stage_id, "stage.stage_id")?;
        if stage.ordinal != ordinal {
            return Err(SecurityContractError::SelectionStageOrder {
                stage_id: stage.stage_id.clone(),
                ordinal,
            });
        }
        if !seen_stage_ids.insert(stage.stage_id.as_str()) {
            return Err(SecurityContractError::SelectionStageConflict {
                stage_id: stage.stage_id.clone(),
                ordinal,
            });
        }
        text(
            &stage.transformer_identity_and_config_revision,
            "stage.transformer_identity_and_config_revision",
        )?;
        text(
            &stage.disclosure_closure_ref,
            "stage.disclosure_closure_ref",
        )?;
        for (refs, field) in [
            (
                &stage.suppressed_counterevidence_refs,
                "stage.suppressed_counterevidence_refs",
            ),
            (
                &stage.budget_or_policy_omission_refs,
                "stage.budget_or_policy_omission_refs",
            ),
            (
                &stage.influence_evidence_refs,
                "stage.influence_evidence_refs",
            ),
        ] {
            unique(refs.iter(), field)?;
            for reference in refs {
                text(reference, "stage.evidence_ref")?;
            }
        }
        fence(&stage.state_fence, "selection.stage.state_fence")?;
        if stage.state_fence != self.state_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        Ok(())
    }

    /// Validates the final membership backing and the chain influence ceiling.
    fn validate_outcome(&self) -> Result<(), SecurityContractError> {
        if self.final_output_refs.iter().any(|item| {
            !self.admitted_candidate_refs.contains(item)
                && !self.transformation_stages.iter().any(|stage| {
                    stage
                        .output_members
                        .iter()
                        .any(|member| &member.member_ref == item)
                })
        }) {
            return Err(SecurityContractError::SelectionIntegrityViolation);
        }
        let observed = self
            .transformation_stages
            .iter()
            .map(|stage| stage.untrusted_input_influenced_membership)
            .max();
        if let Some(observed) = observed
            && self.chain_untrusted_influence < observed
        {
            return Err(SecurityContractError::SelectionInfluenceUnderstated {
                claimed: self.chain_untrusted_influence,
                observed,
            });
        }
        Ok(())
    }
}

/// Reason recorded for a member the legacy v1 shape dropped without one.
const LEGACY_V1_MISSING_REASON: &str = "legacy v1 recorded no disposition for this member";
/// Reason recorded for a member legacy v1 listed as rejected.
const LEGACY_V1_REJECTED_REASON: &str = "legacy v1 listed this member in rejected_candidate_refs";

/// Builds the versioned stage that accounts for the v1 admission boundary.
///
/// v1 stated the admission outcome exactly as `initial_candidate_refs`,
/// `admitted_candidate_refs` and `rejected_candidate_refs`, but recorded no
/// stage for it and validated stage inputs against the admitted set instead of
/// the initial set. Projecting that boundary as ordinal zero is the only way a
/// v1 record can state where its chain starts; no member is invented.
fn import_legacy_admission_stage_v1(
    initial_candidate_members: &[SelectionMember],
    admitted_candidate_refs: &[String],
    state_fence: &StateFence,
) -> Result<SelectionStage, SecurityContractError> {
    let admitted = admitted_candidate_refs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let output_members = initial_candidate_members
        .iter()
        .filter(|member| admitted.contains(member.member_ref.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let member_dispositions = initial_candidate_members
        .iter()
        .map(|member| {
            let admitted_here = admitted.contains(member.member_ref.as_str());
            SelectionMemberDisposition {
                member_ref: member.member_ref.clone(),
                disposition: if admitted_here {
                    SelectionMemberDispositionKind::Retained
                } else {
                    SelectionMemberDispositionKind::Removed
                },
                reason: (!admitted_here).then(|| LEGACY_V1_REJECTED_REASON.to_owned()),
                derived_output_ref: None,
                source_evidence_ref: None,
            }
        })
        .collect();
    Ok(SelectionStage {
        stage_id: "legacy-v1-admission".to_owned(),
        ordinal: 0,
        input_link: None,
        stage: crate::SelectionStageKind::Prune,
        transformer_identity_and_config_revision: "unrecorded-in-legacy-v1".to_owned(),
        input_digest: selection_member_digest(initial_candidate_members)?,
        input_members: initial_candidate_members.to_vec(),
        output_digest: selection_member_digest(&output_members)?,
        output_members,
        member_dispositions,
        suppressed_counterevidence_refs: Vec::new(),
        budget_or_policy_omission_refs: Vec::new(),
        untrusted_input_influenced_membership: SelectionInfluenceState::Unknown,
        influence_evidence_refs: Vec::new(),
        disclosure_closure_ref: "unrecorded-in-legacy-v1".to_owned(),
        state_fence: state_fence.clone(),
    })
}

/// Projects one legacy v1 stage onto the versioned stage shape.
///
/// v1 recorded no relation for an output member it did not consume, so such a
/// stage is refused rather than attributed to a member v1 never named.
fn import_legacy_stage_v1(
    legacy_stage: &crate::LegacySelectionStageV1,
    legacy_index: usize,
    predecessor_stage_id: &str,
    bind: &dyn Fn(&str) -> Result<SelectionMember, SecurityContractError>,
) -> Result<SelectionStage, SecurityContractError> {
    let input_members = legacy_stage
        .input_refs
        .iter()
        .map(|member_ref| bind(member_ref))
        .collect::<Result<Vec<_>, _>>()?;
    let output_members = legacy_stage
        .output_refs
        .iter()
        .map(|member_ref| bind(member_ref))
        .collect::<Result<Vec<_>, _>>()?;
    let input = member_refs(&input_members);
    if legacy_stage
        .output_refs
        .iter()
        .any(|member_ref| !input.contains(member_ref.as_str()))
    {
        return Err(SecurityContractError::SelectionLegacyStageUnattributable {
            ordinal: legacy_index,
        });
    }
    let member_dispositions = input_members
        .iter()
        .map(|member| {
            let reaches_output = output_members
                .iter()
                .any(|output| output.member_ref == member.member_ref);
            SelectionMemberDisposition {
                member_ref: member.member_ref.clone(),
                disposition: if reaches_output {
                    SelectionMemberDispositionKind::Retained
                } else {
                    SelectionMemberDispositionKind::Removed
                },
                reason: (!reaches_output).then(|| LEGACY_V1_MISSING_REASON.to_owned()),
                derived_output_ref: None,
                source_evidence_ref: None,
            }
        })
        .collect();
    Ok(SelectionStage {
        stage_id: format!("legacy-v1-stage-{}", legacy_index + 1),
        ordinal: legacy_index + 1,
        input_link: Some(SelectionStageLink::FromPredecessor {
            predecessor_stage_id: predecessor_stage_id.to_owned(),
        }),
        stage: legacy_stage.stage,
        transformer_identity_and_config_revision: "unrecorded-in-legacy-v1".to_owned(),
        input_digest: selection_member_digest(&input_members)?,
        input_members,
        output_digest: selection_member_digest(&output_members)?,
        output_members,
        member_dispositions,
        suppressed_counterevidence_refs: Vec::new(),
        budget_or_policy_omission_refs: Vec::new(),
        untrusted_input_influenced_membership: SelectionInfluenceState::Unknown,
        influence_evidence_refs: Vec::new(),
        disclosure_closure_ref: legacy_stage.disclosure_closure_ref.clone(),
        state_fence: legacy_stage.state_fence.clone(),
    })
}

/// Imports one legacy v1 selection receipt as an explicitly unverified chain.
///
/// The migration is one-directional and loss-visible, exactly as
/// [`crate::SELECTION_INTEGRITY_LEGACY_V1_DISPOSITION`] records. v1 recorded no
/// stage identity, ordinal, membership digest, per-member disposition or
/// stage-level influence, so every imported stage is
/// [`SelectionInfluenceState::Unknown`]: a v1
/// `untrusted_structure_changed_membership` of `false` never becomes
/// [`SelectionInfluenceState::Absent`], and a v1 `true` is not attributed to any
/// stage v1 never named, so the chain ceiling stays `Unknown` too.
/// `bindings` supplies the member revision and representation that v1 did not
/// record; an unbound member is refused rather than filled with a placeholder.
/// A v1 stage that emitted a member it did not consume is refused as
/// unattributable, because v1 recorded no relation for it.
///
/// The imported record is validated before it is returned, so this function can
/// never manufacture a stage-continuous chain.
///
/// # Errors
///
/// Returns a typed error when a member lacks an owner-supplied binding, a
/// legacy stage is not attributable to its input members, or the projected
/// record fails [`SelectionIntegrityReceipt::validate`].
pub fn import_legacy_selection_receipt_v1(
    legacy: &LegacySelectionIntegrityReceiptV1,
    bindings: &[SelectionMember],
) -> Result<SelectionIntegrityReceipt, SecurityContractError> {
    let bound = |member_ref: &str| -> Result<SelectionMember, SecurityContractError> {
        bindings
            .iter()
            .find(|member| member.member_ref == member_ref)
            .cloned()
            .ok_or_else(|| SecurityContractError::SelectionLegacyMemberUnbound {
                member_ref: member_ref.to_owned(),
            })
    };
    let initial_candidate_members = legacy
        .initial_candidate_refs
        .iter()
        .map(|member_ref| bound(member_ref))
        .collect::<Result<Vec<_>, _>>()?;
    let mut stages = vec![import_legacy_admission_stage_v1(
        &initial_candidate_members,
        &legacy.admitted_candidate_refs,
        &legacy.state_fence,
    )?];
    for (index, legacy_stage) in legacy.transformation_stages.iter().enumerate() {
        let predecessor_stage_id = if index == 0 {
            "legacy-v1-admission".to_owned()
        } else {
            format!("legacy-v1-stage-{}", index - 1)
        };
        stages.push(import_legacy_stage_v1(
            legacy_stage,
            index,
            &predecessor_stage_id,
            &bound,
        )?);
    }
    let receipt = SelectionIntegrityReceipt {
        schema: SELECTION_INTEGRITY_SCHEMA.to_owned(),
        contract_version: crate::CONTRACT_VERSION,
        selection_id: legacy.selection_id.clone(),
        root_context_ref: "unrecorded-in-legacy-v1".to_owned(),
        recipe_revision: "unrecorded-in-legacy-v1".to_owned(),
        initial_candidate_digest: selection_member_digest(&initial_candidate_members)?,
        initial_candidate_members,
        admitted_candidate_refs: legacy.admitted_candidate_refs.clone(),
        rejected_candidate_refs: legacy.rejected_candidate_refs.clone(),
        transformation_stages: stages,
        final_output_refs: legacy.final_output_refs.clone(),
        chain_untrusted_influence: SelectionInfluenceState::Unknown,
        state_fence: legacy.state_fence.clone(),
        revision: legacy.revision,
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Validates one selection receipt and returns a digest suitable for lineage.
///
/// # Errors
///
/// Returns an error when selection validation fails or canonical serialization
/// cannot be produced.
pub fn validate_selection_pipeline(
    receipt: &SelectionIntegrityReceipt,
) -> Result<String, SecurityContractError> {
    receipt.validate()?;
    canonical_json_bytes(receipt)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SecurityContractError::Serialization(error.to_string()))
}

/// Computes the digest of one chain head over its own stage prefix.
///
/// The digest is recomputed from the stages it names, never taken on trust
/// from a caller: an append that re-derives it over the exact stage prefix it
/// added is what makes the head a projection of the immutable history rather
/// than a second, self-asserted authority (#1728 step 4).
///
/// # Errors
///
/// Returns an error when the prefix cannot be serialized canonically.
pub fn selection_chain_head_digest(
    receipt: &SelectionIntegrityReceipt,
    chain_head_ordinal: usize,
) -> Result<String, SecurityContractError> {
    #[derive(serde::Serialize)]
    struct ChainHeadPrefix<'a> {
        selection_id: &'a str,
        schema: &'a str,
        contract_version: &'a eliot_contracts::ContractVersion,
        root_context_ref: &'a str,
        recipe_revision: &'a str,
        chain_head_ordinal: usize,
        stages: &'a [SelectionStage],
    }
    let prefix = receipt
        .transformation_stages
        .get(..=chain_head_ordinal)
        .ok_or(SecurityContractError::SelectionChainHeadOrdinal {
            expected: chain_head_ordinal,
            observed: receipt.transformation_stages.len(),
        })?;
    let view = ChainHeadPrefix {
        selection_id: &receipt.selection_id,
        schema: &receipt.schema,
        contract_version: &receipt.contract_version,
        root_context_ref: &receipt.root_context_ref,
        recipe_revision: &receipt.recipe_revision,
        chain_head_ordinal,
        stages: prefix,
    };
    canonical_json_bytes(&view)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SecurityContractError::Serialization(error.to_string()))
}

impl SelectionIntegrityReceipt {
    /// Derives the rebuildable chain head of this chain.
    ///
    /// The head is computed from the immutable stages themselves. The caller
    /// supplies only the stable append identity and the chain revision the
    /// append advanced to; neither can substitute for the recomputed digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the append identity text is unusable or the
    /// prefix cannot be serialized canonically.
    pub fn derive_chain_head(
        &self,
        chain_revision: u64,
        append_idempotency_key: &str,
    ) -> Result<SelectionChainHead, SecurityContractError> {
        text(
            append_idempotency_key,
            "selection.chain_head.append_idempotency_key",
        )?;
        let chain_head_ordinal = self.transformation_stages.len().checked_sub(1).ok_or(
            SecurityContractError::SelectionChainHeadOrdinal {
                expected: 0,
                observed: 0,
            },
        )?;
        Ok(SelectionChainHead {
            selection_id: self.selection_id.clone(),
            chain_head_ordinal,
            chain_head_digest: selection_chain_head_digest(self, chain_head_ordinal)?,
            chain_revision,
            append_idempotency_key: append_idempotency_key.to_owned(),
        })
    }

    /// Verifies one presented chain head against the stages it names.
    ///
    /// The head must name this chain, address a real stage prefix, and bind
    /// the digest recomputed from that prefix. A head that merely exists, or
    /// that carries a well-formed digest for a different chain, is refused.
    ///
    /// # Errors
    ///
    /// Returns a typed error naming the exact failed binding.
    pub fn verify_chain_head(
        &self,
        head: &SelectionChainHead,
    ) -> Result<(), SecurityContractError> {
        if head.selection_id != self.selection_id {
            return Err(SecurityContractError::SelectionChainHeadIdentity);
        }
        text(
            &head.append_idempotency_key,
            "selection.chain_head.append_idempotency_key",
        )?;
        if head.chain_head_ordinal >= self.transformation_stages.len() {
            return Err(SecurityContractError::SelectionChainHeadOrdinal {
                expected: head.chain_head_ordinal,
                observed: self.transformation_stages.len(),
            });
        }
        let observed = selection_chain_head_digest(self, head.chain_head_ordinal)?;
        if head.chain_head_digest != observed {
            return Err(SecurityContractError::SelectionChainHeadDigest);
        }
        Ok(())
    }
}

impl SelectionChainSeal {
    /// Verifies this seal against the exact chain and output it was taken for.
    ///
    /// The authoritative side is the chain: the presented
    /// `chain_head_digest` is compared with the digest recomputed from the
    /// receipt's own stages, the sealed final membership is compared with the
    /// receipt's own final membership **in order** (so a changed packet with
    /// the same member count fails), and the recipe revision is compared with
    /// the chain's own recipe revision. `packet_bytes_digest` is bound to the
    /// delivered bytes by this call's `delivered_packet_bytes`, which is the
    /// content the consumer is about to act on.
    ///
    /// # Errors
    ///
    /// Returns a typed error naming the exact failed binding.
    pub fn verify_against(
        &self,
        receipt: &SelectionIntegrityReceipt,
        delivered_packet_bytes: &[u8],
        delivered_expansion_handle_ids: &[String],
    ) -> Result<(), SecurityContractError> {
        self.validate()?;
        receipt.validate()?;
        let head_digest = selection_chain_head_digest(
            receipt,
            receipt.transformation_stages.len().checked_sub(1).ok_or(
                SecurityContractError::SelectionChainHeadOrdinal {
                    expected: 0,
                    observed: 0,
                },
            )?,
        )?;
        if self.selection_id != receipt.selection_id
            || self.recipe_revision != receipt.recipe_revision
        {
            return Err(SecurityContractError::SelectionSealIdentity);
        }
        if self.chain_head_digest != head_digest {
            return Err(SecurityContractError::SelectionSealChainSubstituted {
                expected: self.chain_head_digest.clone(),
                observed: head_digest,
            });
        }
        // Order is part of the claim: the sealed ordered membership must be
        // exactly the chain's declared final membership, and its digest must
        // recompute from those very members.
        if self.final_output_refs != receipt.final_output_refs
            || self.final_output_digest != selection_member_digest(&self.final_output_members)?
            || self.final_output_refs
                != member_refs(&self.final_output_members)
                    .iter()
                    .map(|member| (*member).to_owned())
                    .collect::<Vec<String>>()
        {
            return Err(SecurityContractError::SelectionSealFinalMembership);
        }
        if self.packet_bytes_digest != sha256_hex(delivered_packet_bytes) {
            return Err(SecurityContractError::SelectionSealPacketBytes);
        }
        if self.expansion_handle_ids != delivered_expansion_handle_ids {
            return Err(SecurityContractError::SelectionSealExpansionHandles);
        }
        Ok(())
    }

    /// Validates the seal's own shape before it is compared with any chain.
    ///
    /// # Errors
    ///
    /// Returns a typed error naming the exact failed field.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        text(&self.selection_id, "selection.seal.selection_id")?;
        text(&self.recipe_revision, "selection.seal.recipe_revision")?;
        text(&self.chain_head_digest, "selection.seal.chain_head_digest")?;
        text(
            &self.packet_bytes_digest,
            "selection.seal.packet_bytes_digest",
        )?;
        validate_digest(&self.chain_head_digest, "selection.seal.chain_head_digest")?;
        validate_digest(
            &self.packet_bytes_digest,
            "selection.seal.packet_bytes_digest",
        )?;
        validate_members(&self.final_output_members, "seal.final_output_members")?;
        unique(self.final_output_refs.iter(), "seal.final_output_refs")?;
        unique(
            self.expansion_handle_ids.iter(),
            "seal.expansion_handle_ids",
        )?;
        unique(
            self.membership_page_refs.iter(),
            "seal.membership_page_refs",
        )?;
        for reference in self
            .expansion_handle_ids
            .iter()
            .chain(self.membership_page_refs.iter())
        {
            text(reference, "selection.seal.evidence_ref")?;
        }
        // A page reference is only honest when it also names its verified
        // complete closure: a page cap is never permission to declare the
        // chain complete over an unbounded denominator.
        if !self.membership_page_refs.len().is_multiple_of(2) {
            return Err(SecurityContractError::SelectionSealPageClosureMissing);
        }
        Ok(())
    }
}

/// Claim ceiling a chain's untrusted influence permits for a dependent packet.
///
/// I12.13 `Selection integrity` makes `unknown` an admissible finding that
/// "lowers the claim ceiling of the resulting packet instead of being resolved
/// by assumption". The chain's own rolled-up state is authoritative here: a
/// later clean stage cannot raise it, and `Unknown` never becomes `Absent` or a
/// zero risk.
#[must_use]
pub fn selection_claim_ceiling(receipt: &SelectionIntegrityReceipt) -> SelectionInfluenceState {
    receipt.chain_untrusted_influence
}
