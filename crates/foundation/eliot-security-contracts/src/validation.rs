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
    #[error("assessed source or profile is no longer current at the use boundary: {field}")]
    StaleSourceAssessment { field: &'static str },
    #[error("security indicator {indicator} does not accept {evidence} evidence")]
    SecurityIndicatorMismatch {
        indicator: &'static str,
        evidence: &'static str,
    },
    #[error("security indicator evidence does not establish its own class: {field}")]
    IndicatorEvidenceUnproven { field: &'static str },
    #[error("quarantine admission closure does not cover its affected source: {field}")]
    QuarantineClosureScope { field: &'static str },
    #[error("quarantine admission does not bind its expected state revision: {field}")]
    QuarantineRevisionUnbound { field: &'static str },
    #[error("quarantine admission owner is not the owner its decision was bound to: {field}")]
    QuarantineOwnerMismatch { field: &'static str },
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
        "selection final membership declares {declared} members, but the chain's last stage outputs {staged} in its final order"
    )]
    SelectionFinalMembershipBroken { staged: usize, declared: usize },
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
    #[error("selection seal does not bind the exact delivered expansion handles")]
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

/// Member identities in the exact order the producer emitted them.
///
/// [`member_refs`] is order-insensitive because most questions about membership
/// are about the set. A question about what a producer *emitted* is not, so the
/// declared final membership ([`SelectionIntegrityReceipt::validate`]) and the
/// seal's own ordered membership ([`SelectionChainSeal::verify_against`]) both
/// compare this view. The chain-head digest is a third, independent binding: it
/// digests the whole ordered stage list, so member order is covered there by
/// recomputation rather than by calling this helper.
fn ordered_member_refs(members: &[SelectionMember]) -> Vec<String> {
    members
        .iter()
        .map(|member| member.member_ref.clone())
        .collect()
}

/// Reports whether `expected` appears in `observed` as an exact ordered
/// subsequence.
///
/// Every member must match by identity, revision and representation, and none
/// may be reordered within the run it is taken from. This is the ordering half
/// of the join check: a join may interleave its parents' contributions, but it
/// may not silently reorder, re-revise or re-represent a member inside one
/// parent's contribution, because that is the same breaking linkage change a
/// predecessor link already refuses (#1728 step 2). Which stages may be joined
/// at all is a separate question answered in [`validate_stage_link`].
fn membership_is_ordered_subsequence(
    expected: &[SelectionMember],
    observed: &[SelectionMember],
) -> bool {
    let mut cursor = 0;
    for member in expected {
        let Some(offset) = observed[cursor..]
            .iter()
            .position(|candidate| candidate == member)
        else {
            return false;
        };
        cursor += offset + 1;
    }
    true
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
///
/// Both forms are exact, but not equally new. The predecessor form was already
/// exact before #1728 step 2: it compares the whole ordered member list against
/// the named predecessor's output and refuses any addition, loss or
/// re-revision. What step 2 closed is the join form, which previously compared
/// only the union of the named parents' *member references* against the join
/// input and so accepted a join that re-revised a parent member or reversed one
/// parent's contribution inside the interleaved input. A join now requires each
/// parent's complete output membership to appear in the join input unchanged
/// and in the same relative order, with nothing outside the named parents, and
/// every named parent to be a live contribution that continues the chain head.
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
            // A join continues the chain it sits in. The stage immediately
            // before it is the chain's current membership, so leaving it out of
            // the parents abandons that membership's decisions and re-derives
            // the input from older history instead (#1728 step 2).
            let Some(head) = receipt.transformation_stages.get(ordinal - 1) else {
                return Err(broken());
            };
            if !parent_stage_ids
                .iter()
                .any(|parent| parent == &head.stage_id)
            {
                return Err(broken());
            }
            let mut covered = BTreeSet::new();
            let mut memberships = Vec::with_capacity(parent_stage_ids.len());
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
                // Each parent contributes its complete output membership, in
                // that parent's order, with every member's identity, revision
                // and representation intact. Interleaving parents is allowed;
                // reordering, re-revising or dropping part of one parent's
                // contribution is the same breaking linkage change a
                // predecessor link refuses.
                if !membership_is_ordered_subsequence(&parent.output_members, &stage.input_members)
                {
                    return Err(broken());
                }
                let membership = member_refs(&parent.output_members);
                covered.extend(membership.iter().copied());
                memberships.push(membership);
            }
            // Every named parent must be a live contribution: no parent's output
            // membership may be contained in another's. A nested parent
            // contributes nothing to this join's union, so the membership the
            // join assembles is reachable without naming it at all - and the
            // only members naming it can add beyond its superset are exactly
            // the ones a later stage already removed with a recorded reason.
            // Naming it therefore re-attributes those removals to the older
            // stage, which is a stage overwriting an earlier membership
            // decision.
            //
            // I12.13 `Selection integrity` (line 163): "A stage may append but
            // never overwrite an earlier membership decision." Requiring the
            // immediately preceding stage above is necessary but not
            // sufficient: a join may name the head *and* a stale ancestor, and
            // the constructed chain `prune(a,b,c) -> (a,b); expand(a,b) -> (b);
            // join(stage-prune, stage-branch)` still resurrects `a` over the
            // branch's recorded `Removed("branch did not carry a")`. Liveness is
            // what separates that from a real merge.
            //
            // The boundary this leaves is deliberate and is what a merge is: a
            // join over two live branches may restore a member one branch
            // dropped, because the other branch still holds it and both parents
            // contribute members the other lacks. There is no way inside the
            // existing disposition algebra to say "re-admitted", so a join that
            // does that honestly has to express the restoration as an `Admitted`
            // disposition with source evidence on a member the join did *not*
            // receive, which keeps the head as the only source of its input.
            for (index, membership) in memberships.iter().enumerate() {
                let nested = memberships
                    .iter()
                    .enumerate()
                    .any(|(other, candidate)| other != index && membership.is_subset(candidate));
                if nested {
                    return Err(broken());
                }
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
        // The reference lists are membership collections too: an unbounded
        // admitted, rejected or final list would make the evidence a chain
        // carries finite in its stages but open in its own header (#1728
        // step 7).
        for (refs, field) in [
            (&self.admitted_candidate_refs, "admitted_candidate_refs"),
            (&self.rejected_candidate_refs, "rejected_candidate_refs"),
            (&self.final_output_refs, "final_output_refs"),
        ] {
            if refs.len() > MAX_SELECTION_MEMBERS {
                return Err(SecurityContractError::SelectionMemberLimitExceeded {
                    field,
                    count: refs.len(),
                    bound: MAX_SELECTION_MEMBERS,
                });
            }
        }
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
    ///
    /// The final membership is not a free-standing claim: it is the chain's
    /// last stage output, in the order that stage emitted it. Every membership
    /// change belongs to a stage (I12.13 line 145), so a receipt whose declared
    /// final list is not exactly that membership would drop or introduce
    /// members at the last boundary with nothing to account for it. An
    /// all-rejected chain is honest about this by ending on an empty output
    /// membership.
    ///
    /// This check compares declared refs against staged refs only. It never
    /// sees a rendered atom, so it does **not** prove admitted/rendered
    /// equality at the delivery boundary; that equality is proved at the
    /// assembly boundary by
    /// `eliot_context_contracts::SelectionIntegrityProof::validate` and, for
    /// the bytes a consumer acts on, by `SelectionChainSeal`'s
    /// `packet_bytes_digest`.
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
        // Redundant, not live: `validate_stages` owns the empty-list refusal
        // for `transformation_stages` and `validate` runs it before this
        // function, so a validated receipt always has a last stage. This arm
        // keeps the projection total without a panic should that ordering ever
        // change.
        let Some(last_stage) = self.transformation_stages.last() else {
            return Err(SecurityContractError::EmptyCollection {
                field: "transformation_stages",
            });
        };
        let staged_final_refs = ordered_member_refs(&last_stage.output_members);
        if self.final_output_refs != staged_final_refs {
            return Err(SecurityContractError::SelectionFinalMembershipBroken {
                staged: staged_final_refs.len(),
                declared: self.final_output_refs.len(),
            });
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
/// The v1 wire's own `final_output_refs` list is **not** authoritative and is
/// not copied verbatim. Its order is derived instead: the imported record's
/// final membership is the projected last stage's ordered output, which is the
/// only order the projected stages actually emitted and the order
/// [`SelectionIntegrityReceipt::validate`] and [`SelectionChainSeal`] bind. A v1
/// receipt whose `final_output_refs` is a permutation of that membership
/// therefore imports with the derived order instead of being refused for an
/// order mismatch, so the migration stays consistent rather than judging an
/// input class its own contract never described. Membership is still checked:
/// a v1 `final_output_refs` naming a different set of members than the
/// projected chain is refused with
/// [`SecurityContractError::SelectionIntegrityViolation`] rather than silently
/// rewritten.
///
/// The imported record is validated before it is returned, so this function can
/// never manufacture a stage-continuous chain.
///
/// # Errors
///
/// Returns a typed error when a member lacks an owner-supplied binding, a
/// legacy stage is not attributable to its input members, the legacy final
/// membership disagrees with the projected chain's members, or the projected
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
    // The v1 wire's own `final_output_refs` list is no longer copied verbatim.
    // It is an unverified peer claim whose order v1 recorded independently of
    // the stage list it also recorded, while every membership change belongs to
    // a stage (I12.13 line 145). The imported chain therefore states its final
    // membership as the projected last stage's ordered output - the same order
    // `validate_outcome` and `SelectionChainSeal` bind - and the legacy list is
    // used only as a membership claim to check against it. Copying it would make
    // the imported record order-inconsistent with its own history, and refusing
    // order-mismatched bytes would reject a class of v1 input this migration is
    // meant to import rather than judge.
    let Some(last_stage) = stages.last() else {
        return Err(SecurityContractError::EmptyCollection {
            field: "transformation_stages",
        });
    };
    let final_output_refs = ordered_member_refs(&last_stage.output_members);
    // Order is not authoritative in the legacy field; membership is. A v1 final
    // list whose members differ from the projected chain is a disagreement
    // about membership, not about order, so it is refused rather than silently
    // rewritten into a membership the source never claimed.
    let legacy_final: BTreeSet<&str> = legacy
        .final_output_refs
        .iter()
        .map(String::as_str)
        .collect();
    let derived_final: BTreeSet<&str> = final_output_refs.iter().map(String::as_str).collect();
    if legacy_final != derived_final {
        return Err(SecurityContractError::SelectionIntegrityViolation);
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
        final_output_refs,
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
        //
        // The third clause binds the seal's own ordered refs to its own
        // ordered members, so it must compare the members in the order they
        // were emitted. A sorted view (`member_refs`, a `BTreeSet`) would be
        // the wrong comparison here: the chain's last stage emits the admitted
        // ranking order, which is normally not lexicographic, so requiring a
        // sorted match would refuse every honest non-alphabetical admission at
        // the delivery boundary. The comparison is still exact - order and
        // count must both agree - so a seal whose refs do not correspond to its
        // own members is still refused.
        if self.final_output_refs != receipt.final_output_refs
            || self.final_output_digest != selection_member_digest(&self.final_output_members)?
            || self.final_output_refs != ordered_member_refs(&self.final_output_members)
        {
            return Err(SecurityContractError::SelectionSealFinalMembership);
        }
        if self.packet_bytes_digest != sha256_hex(delivered_packet_bytes) {
            return Err(SecurityContractError::SelectionSealPacketBytes);
        }
        // The expansion handles are their own binding, not another name for the
        // packet bytes: a seal that proves which members were delivered says
        // nothing about which retrievable expansions travelled with them, and a
        // swapped handle set must be reported as the handle failure it is.
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
        // A seal is evidence a consumer must read back, so its own reference
        // lists are bounded by the same existing constant as the membership
        // they accompany: a page cap bounds what is named, never what a chain
        // may drop to stay under it.
        for (refs, field) in [
            (&self.final_output_refs, "seal.final_output_refs"),
            (&self.expansion_handle_ids, "seal.expansion_handle_ids"),
            (&self.membership_page_refs, "seal.membership_page_refs"),
        ] {
            if refs.len() > MAX_SELECTION_MEMBERS {
                return Err(SecurityContractError::SelectionMemberLimitExceeded {
                    field,
                    count: refs.len(),
                    bound: MAX_SELECTION_MEMBERS,
                });
            }
        }
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

/// Negative and boundary fixtures for the selection-chain refusals of #1728.
///
/// Every fixture builds its digests with the production
/// [`selection_member_digest`], [`selection_chain_head_digest`] and
/// [`ordered_member_refs`] functions, and every counterexample recomputes the
/// digest of the membership it tampers with. A refusal asserted here is
/// therefore attributable to the linkage, membership or bound under test, not
/// to an incidental digest mismatch.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "these are fixtures whose whole subject is a refusal: a fixture that unwrapped instead would not be able to state which variant it expected"
)]
mod selection_chain_continuity_fixtures {
    use super::*;
    use crate::SelectionStageKind;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const STAGE_ONE: &str = "stage-1";
    const STAGE_TWO: &str = "stage-2";

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
                NonZeroU64::new(1).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            ResourceGeneration::genesis(),
        )
    }

    fn member(member_ref: &str) -> SelectionMember {
        SelectionMember {
            member_ref: member_ref.to_owned(),
            member_revision: format!("{member_ref}-rev-1"),
            representation_ref: format!("{member_ref}-repr-1"),
        }
    }

    fn members(member_refs: &[&str]) -> Vec<SelectionMember> {
        member_refs.iter().map(|item| member(item)).collect()
    }

    fn digest(members: &[SelectionMember]) -> String {
        selection_member_digest(members).expect("canonical membership digest")
    }

    fn retained(member_ref: &str) -> SelectionMemberDisposition {
        SelectionMemberDisposition {
            member_ref: member_ref.to_owned(),
            disposition: SelectionMemberDispositionKind::Retained,
            reason: None,
            derived_output_ref: None,
            source_evidence_ref: None,
        }
    }

    fn removed(member_ref: &str, reason: &str) -> SelectionMemberDisposition {
        SelectionMemberDisposition {
            // The kind must be set here, not inherited: `Retained` with a
            // reason is exactly the incoherent pair `validate_disposition`
            // refuses, so inheriting it from `retained` would make every
            // removal in this module malformed.
            disposition: SelectionMemberDispositionKind::Removed,
            reason: Some(reason.to_owned()),
            ..retained(member_ref)
        }
    }

    fn admitted(member_ref: &str, evidence_ref: &str) -> SelectionMemberDisposition {
        SelectionMemberDisposition {
            member_ref: member_ref.to_owned(),
            disposition: SelectionMemberDispositionKind::Admitted,
            reason: None,
            derived_output_ref: None,
            source_evidence_ref: Some(evidence_ref.to_owned()),
        }
    }

    fn stage(
        stage_id: &str,
        ordinal: usize,
        input_link: Option<SelectionStageLink>,
        kind: SelectionStageKind,
        input_members: &[SelectionMember],
        output_members: &[SelectionMember],
        dispositions: Vec<SelectionMemberDisposition>,
    ) -> SelectionStage {
        SelectionStage {
            stage_id: stage_id.to_owned(),
            ordinal,
            input_link,
            stage: kind,
            transformer_identity_and_config_revision: format!("transformer-{stage_id}-rev-1"),
            input_digest: digest(input_members),
            input_members: input_members.to_vec(),
            output_digest: digest(output_members),
            output_members: output_members.to_vec(),
            member_dispositions: dispositions,
            suppressed_counterevidence_refs: Vec::new(),
            budget_or_policy_omission_refs: Vec::new(),
            untrusted_input_influenced_membership: SelectionInfluenceState::Absent,
            influence_evidence_refs: Vec::new(),
            disclosure_closure_ref: format!("closure-{stage_id}"),
            state_fence: fence(),
        }
    }

    fn predecessor(stage_id: &str) -> SelectionStageLink {
        SelectionStageLink::FromPredecessor {
            predecessor_stage_id: stage_id.to_owned(),
        }
    }

    /// Assembles a receipt whose declared final membership is the chain's own
    /// last stage output, which is the shape every honest producer emits.
    fn chain(
        transformation_stages: Vec<SelectionStage>,
        initial_candidate_members: &[SelectionMember],
    ) -> SelectionIntegrityReceipt {
        let final_output_refs = transformation_stages
            .last()
            .map(|last| ordered_member_refs(&last.output_members))
            .unwrap_or_default();
        SelectionIntegrityReceipt {
            schema: SELECTION_INTEGRITY_SCHEMA.to_owned(),
            contract_version: crate::CONTRACT_VERSION,
            selection_id: "selection-1".to_owned(),
            root_context_ref: "root-context-1".to_owned(),
            recipe_revision: "recipe-rev-1".to_owned(),
            initial_candidate_digest: digest(initial_candidate_members),
            initial_candidate_members: initial_candidate_members.to_vec(),
            admitted_candidate_refs: ordered_member_refs(initial_candidate_members),
            rejected_candidate_refs: Vec::new(),
            transformation_stages,
            final_output_refs,
            chain_untrusted_influence: SelectionInfluenceState::Absent,
            state_fence: fence(),
            revision: 1,
        }
    }

    /// Prune-then-compile chain: ordinal zero drops `doc-c`, ordinal one hands
    /// the surviving pair to context compilation unchanged.
    fn prune_chain() -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a", "doc-b", "doc-c"]);
        let pruned = members(&["doc-a", "doc-b"]);
        chain(
            vec![
                stage(
                    STAGE_ONE,
                    0,
                    None,
                    SelectionStageKind::Prune,
                    &initial,
                    &pruned,
                    vec![
                        retained("doc-a"),
                        retained("doc-b"),
                        removed("doc-c", "policy budget ceiling"),
                    ],
                ),
                stage(
                    STAGE_TWO,
                    1,
                    Some(predecessor(STAGE_ONE)),
                    SelectionStageKind::ContextCompile,
                    &pruned,
                    &pruned,
                    vec![retained("doc-a"), retained("doc-b")],
                ),
            ],
            &initial,
        )
    }

    /// Renders the tampered `input_members` as ordinal one. The stage's own
    /// digest is recomputed from them, so a refusal can only come from the
    /// linkage and not from a stale digest.
    fn with_second_stage_input(
        receipt: &SelectionIntegrityReceipt,
        input: &[SelectionMember],
    ) -> SelectionIntegrityReceipt {
        let mut tampered = receipt.clone();
        tampered.transformation_stages[1] = stage(
            STAGE_TWO,
            1,
            Some(predecessor(STAGE_ONE)),
            SelectionStageKind::ContextCompile,
            input,
            input,
            input
                .iter()
                .map(|member| retained(&member.member_ref))
                .collect(),
        );
        tampered.final_output_refs = ordered_member_refs(input);
        tampered
    }

    fn link_broken(stage_id: &str, ordinal: usize) -> SecurityContractError {
        SecurityContractError::SelectionStageLinkBroken {
            stage_id: stage_id.to_owned(),
            ordinal,
        }
    }

    #[test]
    fn predecessor_link_refuses_every_breaking_membership_change() {
        let valid = prune_chain();
        assert!(
            valid.validate().is_ok(),
            "the fixture chain is the honest case"
        );

        let dropped = with_second_stage_input(&valid, &members(&["doc-a"]));
        assert_eq!(
            validate_selection_pipeline(&dropped).expect_err("dropped member"),
            link_broken(STAGE_TWO, 1)
        );

        let re_admitted = members(&["doc-a", "doc-b", "doc-c"]);
        let added = with_second_stage_input(&valid, &re_admitted);
        assert_eq!(
            validate_selection_pipeline(&added).expect_err("re-added member"),
            link_broken(STAGE_TWO, 1)
        );

        let reordered_input = members(&["doc-b", "doc-a"]);
        let reordered = with_second_stage_input(&valid, &reordered_input);
        assert_eq!(
            validate_selection_pipeline(&reordered).expect_err("reordered membership"),
            link_broken(STAGE_TWO, 1)
        );

        let mut mutated_member = member("doc-b");
        mutated_member.member_revision = "doc-b-rev-2".to_owned();
        let mut mutated_input = members(&["doc-a"]);
        mutated_input.push(mutated_member);
        let mutated = with_second_stage_input(&valid, &mutated_input);
        assert_eq!(
            validate_selection_pipeline(&mutated).expect_err("re-revised member"),
            link_broken(STAGE_TWO, 1)
        );
    }

    #[test]
    fn predecessor_link_refuses_a_wrong_predecessor_and_a_link_at_ordinal_zero() {
        let mut wrong_predecessor = prune_chain();
        wrong_predecessor.transformation_stages[1].input_link = Some(predecessor("stage-unknown"));
        assert_eq!(
            wrong_predecessor
                .validate()
                .expect_err("unknown predecessor"),
            link_broken(STAGE_TWO, 1)
        );

        let mut link_at_zero = prune_chain();
        link_at_zero.transformation_stages[0].input_link = Some(predecessor(STAGE_ONE));
        assert_eq!(
            link_at_zero.validate().expect_err("link at ordinal zero"),
            link_broken(STAGE_ONE, 0)
        );
    }

    /// Branch then join: ordinal zero reranks to `[doc-a, doc-c]`, ordinal one
    /// expands that branch to `[doc-c, doc-b]` from named evidence, and ordinal
    /// two joins both parents back into one membership.
    fn join_chain() -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a", "doc-b", "doc-c"]);
        let reranked = members(&["doc-a", "doc-c"]);
        let expanded = members(&["doc-c", "doc-b"]);
        let joined = members(&["doc-a", "doc-c", "doc-b"]);
        chain(
            vec![
                stage(
                    "stage-rerank",
                    0,
                    None,
                    SelectionStageKind::Rerank,
                    &initial,
                    &reranked,
                    vec![
                        retained("doc-a"),
                        removed("doc-b", "rerank displaced doc-b"),
                        retained("doc-c"),
                    ],
                ),
                stage(
                    "stage-expansion",
                    1,
                    Some(predecessor("stage-rerank")),
                    SelectionStageKind::ClusterExpansion,
                    &reranked,
                    &expanded,
                    vec![
                        removed("doc-a", "expansion branch dropped doc-a"),
                        retained("doc-c"),
                        admitted("doc-b", "evidence-doc-b"),
                    ],
                ),
                stage(
                    "stage-join",
                    2,
                    Some(join_link()),
                    SelectionStageKind::ContextCompile,
                    &joined,
                    &joined,
                    vec![retained("doc-a"), retained("doc-b"), retained("doc-c")],
                ),
            ],
            &initial,
        )
    }

    fn join_link() -> SelectionStageLink {
        SelectionStageLink::FromJoin {
            parent_stage_ids: vec!["stage-rerank".to_owned(), "stage-expansion".to_owned()],
        }
    }

    /// Renders the tampered `input` as the joining ordinal. As with
    /// [`with_second_stage_input`], the stage digests are recomputed, so the
    /// join link is the only thing left that can refuse.
    fn with_join_input(
        receipt: &SelectionIntegrityReceipt,
        input: &[SelectionMember],
    ) -> SelectionIntegrityReceipt {
        let mut tampered = receipt.clone();
        tampered.transformation_stages[2] = stage(
            "stage-join",
            2,
            Some(join_link()),
            SelectionStageKind::ContextCompile,
            input,
            input,
            input
                .iter()
                .map(|member| retained(&member.member_ref))
                .collect(),
        );
        tampered.final_output_refs = ordered_member_refs(input);
        tampered
    }

    #[test]
    fn join_link_preserves_each_parents_complete_contribution() {
        let valid = join_chain();
        assert!(valid.validate().is_ok(), "interleaving parents is a join");

        let dropped = with_join_input(&valid, &members(&["doc-a", "doc-c"]));
        assert_eq!(
            validate_selection_pipeline(&dropped).expect_err("join dropped a parent member"),
            link_broken("stage-join", 2)
        );

        let foreign = with_join_input(&valid, &members(&["doc-a", "doc-c", "doc-b", "doc-d"]));
        assert_eq!(
            validate_selection_pipeline(&foreign).expect_err("join added a foreign member"),
            link_broken("stage-join", 2)
        );

        // Same membership set, but `doc-c` now precedes `doc-b`, which reverses
        // the order the expansion parent emitted. The union of the parents is
        // unchanged, so a set comparison alone would accept this chain.
        let reordered = with_join_input(&valid, &members(&["doc-a", "doc-b", "doc-c"]));
        assert_eq!(
            validate_selection_pipeline(&reordered)
                .expect_err("join reordered a parent contribution"),
            link_broken("stage-join", 2)
        );

        // Same member identities, but `doc-c` is carried at a revision no
        // parent ever emitted.
        let mut mutated_input = members(&["doc-a", "doc-c", "doc-b"]);
        mutated_input[1].member_revision = "doc-c-rev-2".to_owned();
        let mutated = with_join_input(&valid, &mutated_input);
        assert_eq!(
            validate_selection_pipeline(&mutated).expect_err("join re-revised a parent member"),
            link_broken("stage-join", 2)
        );
    }

    #[test]
    fn final_membership_is_the_last_stage_output_in_order() {
        let valid = prune_chain();
        let staged = ordered_member_refs(&valid.transformation_stages[1].output_members);
        assert!(valid.validate().is_ok());

        let mut truncated = valid.clone();
        truncated.final_output_refs = staged[..1].to_vec();
        assert_eq!(
            validate_selection_pipeline(&truncated).expect_err("final membership truncated"),
            SecurityContractError::SelectionFinalMembershipBroken {
                staged: staged.len(),
                declared: staged.len() - 1,
            }
        );

        // A member the receipt admits but no stage ever produced reaches the
        // final set through the admitted-candidate escape only.
        let mut forged = valid.clone();
        forged.admitted_candidate_refs.push("doc-forged".to_owned());
        forged.final_output_refs.push("doc-forged".to_owned());
        assert_eq!(
            validate_selection_pipeline(&forged).expect_err("forged final member"),
            SecurityContractError::SelectionFinalMembershipBroken {
                staged: staged.len(),
                declared: staged.len() + 1,
            }
        );

        let mut reordered = valid;
        reordered.final_output_refs = staged.iter().rev().cloned().collect();
        assert_eq!(
            reordered
                .validate()
                .expect_err("reordered final membership"),
            SecurityContractError::SelectionFinalMembershipBroken {
                staged: staged.len(),
                declared: staged.len(),
            }
        );
    }

    #[test]
    fn a_final_member_no_stage_produced_stays_an_integrity_violation() {
        let mut unknown = prune_chain();
        unknown.final_output_refs.push("doc-unknown".to_owned());
        assert_eq!(
            unknown.validate().expect_err("undeclared final member"),
            SecurityContractError::SelectionIntegrityViolation
        );
    }

    #[test]
    fn an_all_rejected_chain_records_an_empty_final_membership() {
        let initial = members(&["doc-a", "doc-b"]);
        let mut rejected = chain(
            vec![stage(
                STAGE_ONE,
                0,
                None,
                SelectionStageKind::Prune,
                &initial,
                &[],
                vec![
                    removed("doc-a", "policy ceiling"),
                    removed("doc-b", "policy ceiling"),
                ],
            )],
            &initial,
        );
        rejected.admitted_candidate_refs = Vec::new();
        rejected.rejected_candidate_refs = ordered_member_refs(&initial);
        rejected.final_output_refs = Vec::new();
        assert!(rejected.final_output_refs.is_empty());
        assert!(rejected.validate().is_ok());
    }

    #[test]
    fn chain_evidence_is_finite() {
        let bounded = retained_chain(MAX_SELECTION_STAGES);
        assert!(bounded.validate().is_ok());

        let over = retained_chain(MAX_SELECTION_STAGES + 1);
        assert_eq!(
            over.validate().expect_err("stage count above the bound"),
            SecurityContractError::SelectionStageLimitExceeded {
                count: MAX_SELECTION_STAGES + 1,
                bound: MAX_SELECTION_STAGES,
            }
        );

        let oversized: Vec<SelectionMember> = (0..=MAX_SELECTION_MEMBERS)
            .map(|index| member(&format!("doc-{index}")))
            .collect();
        let mut wide = prune_chain();
        wide.transformation_stages[1] = stage(
            STAGE_TWO,
            1,
            Some(predecessor(STAGE_ONE)),
            SelectionStageKind::ContextCompile,
            &oversized,
            &oversized,
            vec![retained("doc-0")],
        );
        assert_eq!(
            wide.validate()
                .expect_err("stage membership above the bound"),
            SecurityContractError::SelectionMemberLimitExceeded {
                field: "stage.input_members",
                count: MAX_SELECTION_MEMBERS + 1,
                bound: MAX_SELECTION_MEMBERS,
            }
        );

        let mut unbounded_header = prune_chain();
        unbounded_header.admitted_candidate_refs = (0..=MAX_SELECTION_MEMBERS)
            .map(|index| format!("admitted-{index}"))
            .collect();
        assert_eq!(
            unbounded_header
                .validate()
                .expect_err("header above the bound"),
            SecurityContractError::SelectionMemberLimitExceeded {
                field: "admitted_candidate_refs",
                count: MAX_SELECTION_MEMBERS + 1,
                bound: MAX_SELECTION_MEMBERS,
            }
        );
    }

    /// Builds a chain of `stage_count` no-op rerank stages over one member, each
    /// continuing exactly its predecessor.
    fn retained_chain(stage_count: usize) -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a"]);
        let carried = members(&["doc-a"]);
        let stages = (0..stage_count)
            .map(|ordinal| {
                let stage_id = format!("stage-{ordinal}");
                let input_link =
                    (ordinal > 0).then(|| predecessor(&format!("stage-{}", ordinal - 1)));
                stage(
                    &stage_id,
                    ordinal,
                    input_link,
                    SelectionStageKind::Rerank,
                    &carried,
                    &carried,
                    vec![retained("doc-a")],
                )
            })
            .collect();
        chain(stages, &initial)
    }

    fn seal_of(
        receipt: &SelectionIntegrityReceipt,
        delivered: &[u8],
        handles: &[String],
    ) -> SelectionChainSeal {
        let final_output_members = receipt
            .transformation_stages
            .last()
            .expect("a validated chain carries a last stage")
            .output_members
            .clone();
        SelectionChainSeal {
            selection_id: receipt.selection_id.clone(),
            chain_head_digest: selection_chain_head_digest(
                receipt,
                receipt.transformation_stages.len() - 1,
            )
            .expect("chain head digest"),
            recipe_revision: receipt.recipe_revision.clone(),
            final_output_refs: receipt.final_output_refs.clone(),
            final_output_digest: digest(&final_output_members),
            final_output_members,
            packet_bytes_digest: sha256_hex(delivered),
            expansion_handle_ids: handles.to_vec(),
            membership_page_refs: Vec::new(),
        }
    }

    #[test]
    fn chain_head_and_seal_are_private_to_their_owning_attempt() {
        let base = prune_chain();
        let delivered = b"packet-bytes";
        let handles = vec!["expansion-1".to_owned()];
        let base_seal = seal_of(&base, delivered, &handles);
        assert!(base_seal.verify_against(&base, delivered, &handles).is_ok());

        let mut foreign = prune_chain();
        foreign.selection_id = "selection-2".to_owned();
        foreign.root_context_ref = "root-context-2".to_owned();
        let foreign_head = foreign
            .derive_chain_head(foreign.revision, "append-foreign")
            .expect("foreign chain head");
        assert_eq!(
            base.verify_chain_head(&foreign_head)
                .expect_err("another attempt's head"),
            SecurityContractError::SelectionChainHeadIdentity
        );

        // The same chain identity compiled for a different root context is
        // still another attempt's history: the recomputed head digest binds the
        // root context, so the head cannot travel between them.
        let mut sibling = prune_chain();
        sibling.root_context_ref = "root-context-2".to_owned();
        let sibling_head = sibling
            .derive_chain_head(sibling.revision, "append-sibling")
            .expect("sibling chain head");
        assert_eq!(
            base.verify_chain_head(&sibling_head)
                .expect_err("another root context's head"),
            SecurityContractError::SelectionChainHeadDigest
        );

        let mut beyond = base
            .derive_chain_head(base.revision, "append-base")
            .expect("base chain head");
        beyond.chain_head_ordinal = base.transformation_stages.len();
        assert_eq!(
            base.verify_chain_head(&beyond)
                .expect_err("head past the chain"),
            SecurityContractError::SelectionChainHeadOrdinal {
                expected: base.transformation_stages.len(),
                observed: base.transformation_stages.len(),
            }
        );

        let foreign_seal = seal_of(&foreign, delivered, &handles);
        assert_eq!(
            foreign_seal
                .verify_against(&base, delivered, &handles)
                .expect_err("another attempt's seal"),
            SecurityContractError::SelectionSealIdentity
        );

        let mut swapped_bytes = base_seal;
        swapped_bytes.packet_bytes_digest = sha256_hex(b"other-packet-bytes");
        assert_eq!(
            swapped_bytes
                .verify_against(&base, b"packet-bytes", &handles)
                .expect_err("changed packet bytes"),
            SecurityContractError::SelectionSealPacketBytes
        );
    }

    /// The constructed resurrection of #1728: ordinal zero prunes `doc-c`,
    /// ordinal one drops `doc-a` from the live membership and records why, and
    /// ordinal two joins ordinal zero with ordinal one to put `doc-a` back.
    fn resurrection_chain() -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a", "doc-b", "doc-c"]);
        let pruned = members(&["doc-a", "doc-b"]);
        let branch = members(&["doc-b"]);
        chain(
            vec![
                stage(
                    "stage-prune",
                    0,
                    None,
                    SelectionStageKind::Prune,
                    &initial,
                    &pruned,
                    vec![
                        retained("doc-a"),
                        retained("doc-b"),
                        removed("doc-c", "policy ceiling"),
                    ],
                ),
                stage(
                    "stage-branch",
                    1,
                    Some(predecessor("stage-prune")),
                    SelectionStageKind::ClusterExpansion,
                    &pruned,
                    &branch,
                    vec![
                        removed("doc-a", "branch did not carry doc-a"),
                        retained("doc-b"),
                    ],
                ),
                stage(
                    "stage-join",
                    2,
                    Some(SelectionStageLink::FromJoin {
                        parent_stage_ids: vec!["stage-prune".to_owned(), "stage-branch".to_owned()],
                    }),
                    SelectionStageKind::ContextCompile,
                    &pruned,
                    &pruned,
                    vec![retained("doc-a"), retained("doc-b")],
                ),
            ],
            &initial,
        )
    }

    #[test]
    fn a_join_may_not_resurrect_a_member_the_head_removed() {
        let forged = resurrection_chain();
        // I12.13 line 163: "A stage may append but never overwrite an earlier
        // membership decision." The head is ordinal one, whose own output is
        // the membership after it decided against `doc-a`; the joining ordinal
        // re-attributes `doc-a` to ordinal zero instead.
        let head = member_refs(&forged.transformation_stages[1].output_members);
        assert!(!head.contains("doc-a"), "the head removed doc-a");
        assert!(
            member_refs(&forged.transformation_stages[2].input_members).contains("doc-a"),
            "the join puts doc-a back"
        );
        // Ordinal one is a strict narrowing of ordinal zero, so it is not a
        // live branch: it holds nothing ordinal zero does not already hold.
        let pruned = member_refs(&forged.transformation_stages[0].output_members);
        assert!(head.is_subset(&pruned) && head != pruned);
        assert_eq!(
            validate_selection_pipeline(&forged).expect_err("resurrected member"),
            link_broken("stage-join", 2)
        );
    }

    #[test]
    fn a_join_of_two_live_branches_still_merges() {
        let live = join_chain();
        // The two parents each hold a member the other does not, so there is a
        // merge to perform and neither parent is redundant.
        let reranked = member_refs(&live.transformation_stages[0].output_members);
        let expanded = member_refs(&live.transformation_stages[1].output_members);
        assert!(!reranked.is_subset(&expanded) && !expanded.is_subset(&reranked));
        assert!(
            live.validate().is_ok(),
            "interleaving two live parents is still a join"
        );
    }

    /// Ordinal zero prunes `doc-c`, ordinal one branches to `[doc-b, doc-d]`,
    /// ordinal two narrows that branch to `[doc-d]`, and ordinal three joins
    /// the two *ancestors* while leaving ordinal two's decision behind.
    fn head_skipping_join_chain() -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a", "doc-b", "doc-c"]);
        let pruned = members(&["doc-a", "doc-b"]);
        let branch_one = members(&["doc-b", "doc-d"]);
        let branch_two = members(&["doc-d"]);
        let rejoined = members(&["doc-a", "doc-b", "doc-d"]);
        chain(
            vec![
                stage(
                    "stage-prune",
                    0,
                    None,
                    SelectionStageKind::Prune,
                    &initial,
                    &pruned,
                    vec![
                        retained("doc-a"),
                        retained("doc-b"),
                        removed("doc-c", "policy ceiling"),
                    ],
                ),
                stage(
                    "stage-branch-one",
                    1,
                    Some(predecessor("stage-prune")),
                    SelectionStageKind::ClusterExpansion,
                    &pruned,
                    &branch_one,
                    vec![
                        removed("doc-a", "branch one dropped doc-a"),
                        retained("doc-b"),
                        admitted("doc-d", "evidence-doc-d"),
                    ],
                ),
                stage(
                    "stage-branch-two",
                    2,
                    Some(predecessor("stage-branch-one")),
                    SelectionStageKind::Rerank,
                    &branch_one,
                    &branch_two,
                    vec![
                        removed("doc-b", "branch two dropped doc-b"),
                        retained("doc-d"),
                    ],
                ),
                stage(
                    "stage-join",
                    3,
                    Some(SelectionStageLink::FromJoin {
                        parent_stage_ids: vec![
                            "stage-prune".to_owned(),
                            "stage-branch-one".to_owned(),
                        ],
                    }),
                    SelectionStageKind::ContextCompile,
                    &rejoined,
                    &rejoined,
                    vec![retained("doc-a"), retained("doc-b"), retained("doc-d")],
                ),
            ],
            &initial,
        )
    }

    #[test]
    fn a_join_must_continue_the_chain_head() {
        let skipping = head_skipping_join_chain();
        // Neither named parent is nested in the other, so redundancy is not the
        // cause of this refusal: the joining ordinal simply drops the head.
        let pruned = member_refs(&skipping.transformation_stages[0].output_members);
        let branch_one = member_refs(&skipping.transformation_stages[1].output_members);
        assert!(!pruned.is_subset(&branch_one) && !branch_one.is_subset(&pruned));
        assert_eq!(
            validate_selection_pipeline(&skipping).expect_err("join past the head"),
            link_broken("stage-join", 3)
        );
    }

    /// Ordinal zero reranks to a deliberately non-lexicographic admitted order
    /// and ordinal one hands it to context compilation unchanged. This is the
    /// shape a production compile stage emits: the chain's last stage carries
    /// the admitted ranking order, not a sorted list.
    fn non_sorted_admitted_chain() -> SelectionIntegrityReceipt {
        let initial = members(&["doc-a", "doc-b", "doc-c"]);
        let reranked = members(&["doc-c", "doc-a"]);
        chain(
            vec![
                stage(
                    "stage-rerank",
                    0,
                    None,
                    SelectionStageKind::Rerank,
                    &initial,
                    &reranked,
                    vec![
                        retained("doc-a"),
                        removed("doc-b", "rerank displaced doc-b"),
                        retained("doc-c"),
                    ],
                ),
                stage(
                    "stage-compile",
                    1,
                    Some(predecessor("stage-rerank")),
                    SelectionStageKind::ContextCompile,
                    &reranked,
                    &reranked,
                    vec![retained("doc-c"), retained("doc-a")],
                ),
            ],
            &initial,
        )
    }

    #[test]
    fn a_seal_binds_the_admitted_order_not_a_sorted_order() {
        let receipt = non_sorted_admitted_chain();
        assert!(receipt.validate().is_ok(), "the chain is the honest case");
        let delivered = b"non-sorted-packet-bytes";
        let handles: Vec<String> = Vec::new();
        let seal = seal_of(&receipt, delivered, &handles);

        let mut sorted = seal.final_output_refs.clone();
        sorted.sort();
        assert_ne!(
            sorted, seal.final_output_refs,
            "the fixture must carry a non-lexicographic admitted order"
        );
        assert_eq!(
            seal.final_output_refs,
            ordered_member_refs(&seal.final_output_members),
            "the seal binds its own emitted order"
        );
        assert!(
            seal.verify_against(&receipt, delivered, &handles).is_ok(),
            "a non-sorted admitted order seals"
        );

        // Same members, reversed: the sealed refs still name the chain's
        // declared final membership, and the digest is recomputed over the
        // reversed members, so only the ordered correspondence between the
        // seal's refs and its own members can refuse this.
        let mut reversed = seal_of(&receipt, delivered, &handles);
        reversed.final_output_members.reverse();
        reversed.final_output_digest = digest(&reversed.final_output_members);
        assert_eq!(reversed.final_output_refs, receipt.final_output_refs);
        assert_eq!(
            reversed
                .verify_against(&receipt, delivered, &handles)
                .expect_err("sealed refs do not match its own members in order"),
            SecurityContractError::SelectionSealFinalMembership
        );
    }

    /// One v1 receipt whose final membership the projected chain agrees with.
    fn legacy_v1(
        initial: &[&str],
        admitted: &[&str],
        final_output_refs: &[&str],
    ) -> LegacySelectionIntegrityReceiptV1 {
        LegacySelectionIntegrityReceiptV1 {
            selection_id: "selection-legacy-1".to_owned(),
            initial_candidate_refs: initial.iter().map(|item| (*item).to_owned()).collect(),
            admitted_candidate_refs: admitted.iter().map(|item| (*item).to_owned()).collect(),
            rejected_candidate_refs: Vec::new(),
            transformation_stages: Vec::new(),
            final_output_refs: final_output_refs
                .iter()
                .map(|item| (*item).to_owned())
                .collect(),
            untrusted_structure_changed_membership: false,
            state_fence: fence(),
            revision: 1,
        }
    }

    #[test]
    fn a_legacy_final_membership_imports_in_the_derived_order() {
        let legacy = legacy_v1(
            &["doc-a", "doc-b"],
            &["doc-a", "doc-b"],
            // A permutation of the same membership: order only.
            &["doc-b", "doc-a"],
        );
        let bindings = members(&["doc-a", "doc-b"]);
        let imported = import_legacy_selection_receipt_v1(&legacy, &bindings)
            .expect("an order-mismatched v1 final membership still imports");
        let projected = ordered_member_refs(
            &imported
                .transformation_stages
                .last()
                .expect("the projection always has a last stage")
                .output_members,
        );
        assert_eq!(imported.final_output_refs, projected);
        assert_eq!(
            imported.final_output_refs,
            ordered_member_refs(&imported.initial_candidate_members),
            "the derived order is the projected chain's emitted order"
        );
        assert_ne!(
            imported.final_output_refs, legacy.final_output_refs,
            "the v1 list's own order must not be copied verbatim"
        );
        // The one-way legacy disposition is untouched by this change.
        assert_eq!(
            imported.chain_untrusted_influence,
            SelectionInfluenceState::Unknown
        );
        assert!(imported.validate().is_ok());
    }

    #[test]
    fn a_legacy_migration_still_refuses_an_unbound_member() {
        let legacy = legacy_v1(
            &["doc-a", "doc-b"],
            &["doc-a", "doc-b"],
            &["doc-a", "doc-b"],
        );
        let bindings = members(&["doc-a"]);
        assert_eq!(
            import_legacy_selection_receipt_v1(&legacy, &bindings).expect_err("an unbound member"),
            SecurityContractError::SelectionLegacyMemberUnbound {
                member_ref: "doc-b".to_owned(),
            }
        );
    }

    #[test]
    fn a_legacy_final_membership_that_disagrees_on_members_is_refused() {
        // `doc-z` is a membership claim the projected chain never produced; only
        // the list's ORDER is not authoritative, so this is a refusal rather
        // than a silent rewrite.
        let legacy = legacy_v1(&["doc-a", "doc-b"], &["doc-a"], &["doc-a", "doc-z"]);
        let bindings = members(&["doc-a", "doc-b"]);
        assert_eq!(
            import_legacy_selection_receipt_v1(&legacy, &bindings)
                .expect_err("final membership the chain never produced"),
            SecurityContractError::SelectionIntegrityViolation
        );
    }
}
