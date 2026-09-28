//! Kernel pre-stage contract-rejection gate for issue #1796 (I6.8).
//!
//! Architecture traceability: `I6.8` owns typed `ContractError` and
//! `AdmissionRejection` semantics in Governor (`eliot-canonical`). This module
//! is the Kernel mechanical recheck at the pre-stage admission boundary only:
//! it validates the exact transported values about to be staged, accumulates
//! every defect into one typed rejection, preserves canonical-bytes plus
//! idempotency-key retry identity, and never allocates an ordering sequence,
//! mints a `write_intent_id`, or records an effect. It owns no semantic
//! admission, no ORS lifecycle, and no store execution.
//!
//! The typed shape here mirrors the Governor owner field-for-field on the
//! pre-stage invariants (`stage_state: none`,
//! `ordering_sequence_assigned: false`, `write_mutation_status:
//! NOT_ATTEMPTED`, no `write_intent_id`). It duplicates no semantic decision:
//! defect classification stays Governor-owned; this gate only rechecks the
//! mechanical transport bindings before any staging work.
//!
//! The corrected operation identity is the owner's, not prose. The Governor
//! owner in `eliot-canonical` issues it (`derive_corrected_operation_id`)
//! and verifies lineage against the refusals it retained
//! (`RetainedRejections::verify_correction_lineage`); this gate never rebuilds
//! that semantic decision. The derivation itself is the one shared
//! `eliot-store-api` primitive both layers call, so the identity this gate
//! stamps on its live refusals is exactly the identity the owner issues.
//! What the gate can and does enforce mechanically is the identity half it
//! can see on the wire: it records every operation identity it refused, and
//! a resubmission that still wears one is refused here instead of committing
//! under the rejected identity. It also retains the corrected identity each
//! refusal issued, so a corrected resubmission presenting exactly that
//! identity is admitted with a verified [`VerifiedCorrectionLink`] binding
//! the committed write to the rejected operation it corrects. The rule
//! string below stays as the stated rule; it is no longer the only
//! statement of the rule.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{RequestMetadata, sha256_hex};
use eliot_store_api::{
    CanonicalRequestView, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation,
    derive_corrected_operation_id, verify_canonical_request_hash,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable retry-identity rule mirrored from the Governor owner.
pub const PRE_STAGE_RETRY_RULE: &str = "corrected payload requires a new operation identity and normally a new idempotency key with corrected_from_operation_id lineage; exact same-hash retry returns the same rejection; changed bytes under one idempotency key is IDENTITY_CONFLICT";

/// Typed pre-stage decision mirrored from the Governor owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreStageDecision {
    /// Refused before staging.
    NotAccepted,
    /// Idempotency key reused with different canonical bytes.
    Conflict,
}

/// Pre-stage stage state. The only representable value is `none`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum PreStageState {
    /// No stage was entered.
    #[serde(rename = "none")]
    None,
}

/// Typed Kernel pre-stage rejection.
///
/// Mechanical mirror of the Governor `AdmissionRejection` pre-stage
/// invariants. Carries defect codes only; full per-defect detail stays
/// Governor-owned. Never carries an ordering sequence or a write intent.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreStageRejection {
    /// Request identity from the transported context.
    pub request_id: String,
    /// Proposed operation under test.
    pub proposed_operation_id: String,
    /// Stable logical retry identity.
    pub idempotency_key: String,
    /// Canonical request hash of the exact transported bytes.
    pub canonical_request_hash: String,
    /// Stable rejection identity for exact same-hash retry.
    pub rejection_id: String,
    /// Operation identity a corrected resubmission must use.
    ///
    /// Derived through the one shared `eliot-store-api` primitive from the
    /// inputs this refusal is already fixed by (the rejected operation
    /// identity and the rejection identity), so it is exactly the identity
    /// the Governor owner issues for the same refusal.
    pub corrected_operation_id: String,
    /// Always `none` pre-stage.
    pub stage_state: PreStageState,
    /// Always `false` pre-stage.
    pub ordering_sequence_assigned: bool,
    /// `not_accepted` for defects, `conflict` for identity reuse.
    pub decision: PreStageDecision,
    /// Every detected mechanical defect code in one response.
    pub defect_codes: Vec<String>,
    /// Always `NOT_ATTEMPTED` pre-stage.
    pub write_mutation_status: String,
    /// Always `None` pre-stage; no write intent is consumed.
    pub write_intent_id: Option<String>,
    /// Safe capture pointer for semantic ambiguity, when applicable.
    pub safe_capture_fallback: Option<String>,
    /// Retry identity rule for corrected payloads.
    pub corrected_retry_identity_rule: String,
    /// Next allowed caller action.
    pub next_allowed_action: String,
}

impl PreStageRejection {
    /// Validates the pre-stage invariants.
    pub fn validate(&self) -> Result<(), PreStageGateError> {
        if self.request_id.trim().is_empty() {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.request_id",
                reason: "must be non-blank",
            });
        }
        if self.proposed_operation_id.trim().is_empty() {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.proposed_operation_id",
                reason: "must be non-blank",
            });
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.idempotency_key",
                reason: "must be non-blank",
            });
        }
        if self.canonical_request_hash.len() != 64
            || self
                .canonical_request_hash
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.canonical_request_hash",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.rejection_id
            != derive_rejection_id(&self.idempotency_key, &self.canonical_request_hash)
        {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.rejection_id",
                reason: "must derive from the idempotency key and canonical hash",
            });
        }
        if self.corrected_operation_id
            != derive_corrected_operation_id(&self.proposed_operation_id, &self.rejection_id)
            || self.corrected_operation_id == self.proposed_operation_id
        {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.corrected_operation_id",
                reason: "must carry the corrected operation identity issued for this refusal, which differs from the rejected one",
            });
        }
        if !matches!(self.stage_state, PreStageState::None) {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.stage_state",
                reason: "pre-stage rejection must report none",
            });
        }
        if self.ordering_sequence_assigned {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.ordering_sequence_assigned",
                reason: "pre-stage rejection must not assign an ordering sequence",
            });
        }
        if self.defect_codes.is_empty() {
            return Err(PreStageGateError::Empty {
                field: "rejection.defect_codes",
            });
        }
        if self
            .defect_codes
            .iter()
            .any(|code| code.trim().is_empty() || code.chars().any(char::is_control))
        {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.defect_codes",
                reason: "every defect code must be non-blank bounded text",
            });
        }
        if self.write_mutation_status != "NOT_ATTEMPTED" {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.write_mutation_status",
                reason: "pre-stage rejection must report NOT_ATTEMPTED",
            });
        }
        if self.write_intent_id.is_some() {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.write_intent_id",
                reason: "pre-stage rejection must not consume a write intent",
            });
        }
        if self.corrected_retry_identity_rule.trim().is_empty()
            || self.next_allowed_action.trim().is_empty()
        {
            return Err(PreStageGateError::InvalidField {
                field: "rejection.retry_rule",
                reason: "must carry the corrected retry identity rule and next action",
            });
        }
        Ok(())
    }
}

/// Fail-closed errors for the gate projection itself.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreStageGateError {
    /// A rejection field violates its pre-stage invariant.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required collection was empty.
    #[error("empty field {field}")]
    Empty {
        /// Field path of the empty collection.
        field: &'static str,
    },
}

/// Derives the stable rejection identity from the retry identity and hash.
#[must_use]
pub fn derive_rejection_id(idempotency_key: &str, canonical_request_hash: &str) -> String {
    sha256_hex(format!("{idempotency_key}:{canonical_request_hash}").as_bytes())
}

/// Verified correction lineage for one admitted resubmission.
///
/// Every field comes from the gate's own retained refusal record: the
/// presented operation identity matched a corrected identity this cache
/// retained, so the recorded rejected operation is the proven parent of the
/// committed write. No caller assertion is believed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCorrectionLink {
    /// Admitted operation identity: exactly the corrected identity issued.
    pub corrected_operation_id: String,
    /// Rejected operation identity this correction was issued for.
    pub corrected_from_operation_id: String,
    /// Rejection identity that issued the correction.
    pub correction_rejection_id: String,
}

/// One refusal this gate kept, bound to the operation identity it refused.
#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedCorrection {
    /// Operation identity this gate refused.
    rejected_operation_id: String,
    /// Stable rejection identity returned for it.
    rejection_id: String,
}

/// In-memory pre-stage identity cache.
///
/// Preserves exact same-hash retry identity and `IDENTITY_CONFLICT` without
/// touching ORS, the store, or any sequence allocator. It also records every
/// operation identity it refused, so corrected bytes can never come back still
/// wearing a rejected operation identity, and retains the corrected identity
/// each refusal issued, so a resubmission presenting exactly that identity is
/// admitted with its lineage proven instead of committing unlinked. The
/// corrected identity itself is the one shared `eliot-store-api` derivation
/// the Governor owner also issues: this cache retains it, it never invents a
/// divergent one.
#[derive(Clone, Debug, Default)]
pub struct PreStageIdentityCache {
    entries: BTreeMap<String, (String, PreStageRejection)>,
    refused_operations: BTreeSet<String>,
    issued_corrections: BTreeMap<String, IssuedCorrection>,
}

impl PreStageIdentityCache {
    /// Retains one refusal under its idempotency key and under the operation
    /// identity it refused.
    ///
    /// The keyed entry keeps exact same-hash retry on the identical rejection
    /// identity; the refused-identity set is the gate's own record that this
    /// operation identity never reached the store, so a later correction
    /// carrying it is refused here instead of being reinterpreted downstream.
    fn retain_refusal(
        &mut self,
        proposed_operation_id: &str,
        key: &str,
        canonical_hash: &str,
        rejection: &PreStageRejection,
    ) {
        self.entries.insert(
            key.to_owned(),
            (canonical_hash.to_owned(), rejection.clone()),
        );
        self.retain_refused_operation(proposed_operation_id, rejection);
    }

    /// Retains the refused operation identity without touching the keyed retry
    /// entry: a changed-bytes `IDENTITY_CONFLICT` refusal must never overwrite
    /// the stored rejection for that key.
    ///
    /// Every refusal retains its own correction, not only the first.
    ///
    /// Each corrected identity is derived from the rejected operation identity
    /// together with that refusal's own rejection identity, so a second refusal
    /// of the same operation identity issues a distinct corrected identity.
    /// Retaining only the first would leave every later corrected identity
    /// unprovable: the gate would hand a client an identity whose
    /// `corrected_from_operation_id` it could not confirm, so a resubmission
    /// obeying that rejection's own `next_allowed_action` would commit with no
    /// lineage. I6.8 requires that `corrected_from_operation_id` preserves
    /// lineage, and it states no first-refusal-only exception.
    fn retain_refused_operation(
        &mut self,
        proposed_operation_id: &str,
        rejection: &PreStageRejection,
    ) {
        self.refused_operations
            .insert(proposed_operation_id.to_owned());
        self.issued_corrections.insert(
            rejection.corrected_operation_id.clone(),
            IssuedCorrection {
                rejected_operation_id: proposed_operation_id.to_owned(),
                rejection_id: rejection.rejection_id.clone(),
            },
        );
    }

    /// Verifies a presented operation identity against this cache's own record.
    ///
    /// Returns the verified link only when the presented identity is exactly
    /// a corrected identity a retained refusal issued. A fresh unrelated
    /// operation yields `None`: it is an ordinary new write, and stamping it
    /// with lineage would stamp unproven lineage.
    fn verified_correction_for(
        &self,
        presented_operation_id: &str,
    ) -> Option<VerifiedCorrectionLink> {
        self.issued_corrections
            .get(presented_operation_id)
            .map(|issued| VerifiedCorrectionLink {
                corrected_operation_id: presented_operation_id.to_owned(),
                corrected_from_operation_id: issued.rejected_operation_id.clone(),
                correction_rejection_id: issued.rejection_id.clone(),
            })
    }
}

/// Mechanically rechecks one staged write before any ORS or store mutation.
///
/// Accumulates context/transition validation, fence equality, canonical
/// request-hash recompute, scope coverage, and head fences into one typed
/// rejection. Takes no sequence allocator and mints no write intent: a
/// refusal always carries `stage_state: none`,
/// `ordering_sequence_assigned: false`, `write_mutation_status:
/// NOT_ATTEMPTED`, and no `write_intent_id`. A resubmission that still carries
/// an operation identity this gate already refused is refused too, so
/// corrected bytes never commit under a rejected operation identity.
///
/// An admitted resubmission presenting exactly the corrected identity a
/// retained refusal issued returns the verified [`VerifiedCorrectionLink`]
/// binding the committed write to the rejected operation it corrects; any
/// other admitted write returns `None` and commits unlinked.
#[allow(
    clippy::too_many_lines,
    reason = "each mechanical gate pushes its own defect code so one request reports every defect"
)]
#[allow(
    clippy::result_large_err,
    reason = "the typed pre-stage rejection travels by value so one invalid request carries every defect"
)]
pub fn pre_stage_check(
    cache: &mut PreStageIdentityCache,
    context: &RequestMetadata,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<Option<VerifiedCorrectionLink>, PreStageRejection> {
    let view = CanonicalRequestView::from_apply(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    let canonical_hash =
        eliot_store_api::canonical_request_hash(&view).unwrap_or_else(|_| "0".repeat(64));
    let key = transition.identity.idempotency_key.clone();
    if let Some((stored_hash, stored)) = cache.entries.get(&key) {
        if stored_hash == &canonical_hash {
            return Err(stored.clone());
        }
        let rejection = conflict_rejection(context, transition, &canonical_hash);
        // The changed bytes under this key are refused, so their operation
        // identity never reached the store; the keyed entry stays untouched, so
        // the first rejection for the key is still the one an exact retry
        // replays.
        cache.retain_refused_operation(transition.identity.operation_id.as_str(), &rejection);
        return Err(rejection);
    }

    // I6.8: a corrected payload normally receives a NEW operation identity.
    // This cache records every operation identity it refused, so a
    // resubmission that still wears one is refused here instead of committing
    // under the rejected identity. The transported apply request carries no
    // lineage field, so the gate believes no caller assertion: the presented
    // operation identity itself is the proof exactly when it equals a
    // corrected identity this cache retained.
    if cache
        .refused_operations
        .contains(transition.identity.operation_id.as_str())
    {
        let rejection = refused_operation_identity_rejection(context, transition, &canonical_hash);
        cache.retain_refusal(
            transition.identity.operation_id.as_str(),
            &key,
            &canonical_hash,
            &rejection,
        );
        return Err(rejection);
    }

    let mut defects: Vec<String> = Vec::new();
    if context.validate().is_err() {
        defects.push("INVALID_FIELD:request".to_owned());
    }
    if transition.validate().is_err() {
        defects.push("INVALID_FIELD:transition".to_owned());
    }
    if transition.state_fence != context.state_fence {
        defects.push("STATE_FENCE_MISMATCH".to_owned());
    }
    if verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash).is_err() {
        defects.push("TRANSITION_DIGEST_MISMATCH".to_owned());
    }
    {
        let mut declared: Vec<&str> = transition
            .ordering_scopes
            .iter()
            .map(eliot_store_api::OrderingScopeId::as_str)
            .collect();
        declared.sort_unstable();
        declared.dedup();
        let mut expected: Vec<&str> = expected_ordering_heads
            .iter()
            .map(|head| head.scope.as_str())
            .collect();
        expected.sort_unstable();
        if expected != declared || declared.len() != transition.ordering_scopes.len() {
            defects.push("ORDERING_CONFLICT".to_owned());
        }
    }
    for head in expected_ordering_heads {
        if head.validate().is_err() || head.state_fence != context.state_fence {
            defects.push("ORDERING_CONFLICT:head".to_owned());
            break;
        }
    }
    for head in expected_revision_heads {
        if head.validate().is_err() || head.state_fence != context.state_fence {
            defects.push("REVISION_CONFLICT:head".to_owned());
            break;
        }
    }

    if defects.is_empty() {
        return Ok(cache.verified_correction_for(transition.identity.operation_id.as_str()));
    }
    let semantic = defects.iter().any(|code| {
        code.contains("FENCE") || code.contains("REVISION") || code.contains("ORDERING")
    });
    let rejection_id = derive_rejection_id(&key, &canonical_hash);
    let rejection = PreStageRejection {
        request_id: context.request_id.as_str().to_owned(),
        proposed_operation_id: transition.identity.operation_id.as_str().to_owned(),
        idempotency_key: key.clone(),
        canonical_request_hash: canonical_hash.clone(),
        rejection_id: rejection_id.clone(),
        corrected_operation_id: derive_corrected_operation_id(
            transition.identity.operation_id.as_str(),
            &rejection_id,
        ),
        stage_state: PreStageState::None,
        ordering_sequence_assigned: false,
        decision: PreStageDecision::NotAccepted,
        defect_codes: defects,
        write_mutation_status: "NOT_ATTEMPTED".to_owned(),
        write_intent_id: None,
        safe_capture_fallback: semantic.then(|| {
            format!(
                "ObservationCandidate:cold:{}",
                transition.identity.operation_id.as_str()
            )
        }),
        corrected_retry_identity_rule: PRE_STAGE_RETRY_RULE.to_owned(),
        next_allowed_action:
            "correct the bounded defects and resubmit with a new operation identity".to_owned(),
    };
    cache.retain_refusal(
        transition.identity.operation_id.as_str(),
        &key,
        &canonical_hash,
        &rejection,
    );
    Err(rejection)
}

fn conflict_rejection(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    canonical_hash: &str,
) -> PreStageRejection {
    let key = transition.identity.idempotency_key.clone();
    let rejection_id = derive_rejection_id(&key, canonical_hash);
    PreStageRejection {
        request_id: context.request_id.as_str().to_owned(),
        proposed_operation_id: transition.identity.operation_id.as_str().to_owned(),
        idempotency_key: key.clone(),
        canonical_request_hash: canonical_hash.to_owned(),
        rejection_id: rejection_id.clone(),
        corrected_operation_id: derive_corrected_operation_id(
            transition.identity.operation_id.as_str(),
            &rejection_id,
        ),
        stage_state: PreStageState::None,
        ordering_sequence_assigned: false,
        decision: PreStageDecision::Conflict,
        defect_codes: vec!["IDENTITY_CONFLICT".to_owned()],
        write_mutation_status: "NOT_ATTEMPTED".to_owned(),
        write_intent_id: None,
        safe_capture_fallback: None,
        corrected_retry_identity_rule: PRE_STAGE_RETRY_RULE.to_owned(),
        next_allowed_action:
            "resubmit the changed bytes under a new idempotency key with corrected_from_operation_id lineage"
                .to_owned(),
    }
}

/// Refuses corrected bytes that still carry an operation identity this gate
/// already refused.
///
/// The refusal is pre-stage like every other one here: `stage_state: none`, no
/// ordering sequence, `write_mutation_status: NOT_ATTEMPTED`, no
/// `write_intent_id`. The corrected operation identity is the one shared
/// derivation the Governor owner also issues, so the caller is told the exact
/// identity to resubmit under.
fn refused_operation_identity_rejection(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    canonical_hash: &str,
) -> PreStageRejection {
    let key = transition.identity.idempotency_key.clone();
    let rejection_id = derive_rejection_id(&key, canonical_hash);
    PreStageRejection {
        request_id: context.request_id.as_str().to_owned(),
        proposed_operation_id: transition.identity.operation_id.as_str().to_owned(),
        idempotency_key: key.clone(),
        canonical_request_hash: canonical_hash.to_owned(),
        rejection_id: rejection_id.clone(),
        corrected_operation_id: derive_corrected_operation_id(
            transition.identity.operation_id.as_str(),
            &rejection_id,
        ),
        stage_state: PreStageState::None,
        ordering_sequence_assigned: false,
        decision: PreStageDecision::Conflict,
        defect_codes: vec!["IDENTITY_CONFLICT:operation_id".to_owned()],
        write_mutation_status: "NOT_ATTEMPTED".to_owned(),
        write_intent_id: None,
        safe_capture_fallback: None,
        corrected_retry_identity_rule: PRE_STAGE_RETRY_RULE.to_owned(),
        next_allowed_action:
            "resubmit the corrected bytes under a new operation identity with a new idempotency key and corrected_from_operation_id lineage"
                .to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
        StateFence,
    };
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, OperationIdentity, OperationManifestDigest,
        OrderingScopeId, ScopeId, SecurityContext, TransitionClass,
    };
    use std::num::NonZeroU64;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nz")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn context() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-gate-1796").expect("req"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-gate").expect("product"),
            source_id: SourceId::new("source-gate").expect("source"),
            state_fence: fence(),
            clock: eliot_contracts::ClockReading::default(),
        }
    }

    fn transition(op: &str, idem: &str, hash: &str) -> PreparedTransition {
        let mut transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new(op).expect("op"),
                idempotency_key: idem.to_owned(),
                canonical_request_hash: hash.to_owned(),
            },
            state_fence: fence(),
            scope_id: ScopeId::new("scope-gate").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-gate").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "c".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-gate")
                .expect("manifest"),
            // Issue-#18 digests are derived, never defaulted; no semantic
            // source is bound here (`[]`). The caller-supplied hash stays
            // untouched: this fixture probes hash-mismatch refusal.
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: Vec::new(),
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    #[test]
    fn pre_stage_gate_assigns_no_sequence_or_intent_with_stable_retry_identity() {
        let ctx = context();
        let bad = transition("op-gate-bad", "idem-gate-a", &"0".repeat(64));
        let heads = vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-gate").expect("ordering scope"),
            expected_sequence: 1,
            state_fence: fence(),
        }];
        let mut cache = PreStageIdentityCache::default();
        let Err(first) = pre_stage_check(&mut cache, &ctx, &bad, &[], &heads) else {
            panic!("invalid transported values must be refused pre-stage");
        };
        assert!(!first.ordering_sequence_assigned);
        assert!(first.write_intent_id.is_none());
        assert_eq!(first.write_mutation_status, "NOT_ATTEMPTED");
        assert!(!first.defect_codes.is_empty());
        first.validate().expect("gate rejection validates");

        let Err(second) = pre_stage_check(&mut cache, &ctx, &bad, &[], &heads) else {
            panic!("identical canonical-bytes retry must replay the same rejection");
        };
        assert_eq!(second.rejection_id, first.rejection_id);

        let mut changed = transition("op-gate-bad", "idem-gate-a", &"1".repeat(64));
        changed.scope_id = ScopeId::new("scope-gate-changed").expect("changed scope");
        let Err(conflict) = pre_stage_check(&mut cache, &ctx, &changed, &[], &heads) else {
            panic!("changed bytes under one key must conflict");
        };
        assert!(matches!(conflict.decision, PreStageDecision::Conflict));
        assert!(
            conflict
                .defect_codes
                .contains(&"IDENTITY_CONFLICT".to_owned())
        );
    }
}
