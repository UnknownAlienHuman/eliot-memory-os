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

use std::collections::BTreeMap;

use eliot_contracts::{RequestMetadata, sha256_hex};
use eliot_store_api::{
    CanonicalRequestView, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation,
    verify_canonical_request_hash,
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
        if self.canonical_request_hash.len() != 64 {
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

/// In-memory pre-stage identity cache.
///
/// Preserves exact same-hash retry identity and `IDENTITY_CONFLICT` without
/// touching ORS, the store, or any sequence allocator.
#[derive(Clone, Debug, Default)]
pub struct PreStageIdentityCache {
    entries: BTreeMap<String, (String, PreStageRejection)>,
}

/// Mechanically rechecks one staged write before any ORS or store mutation.
///
/// Accumulates context/transition validation, fence equality, canonical
/// request-hash recompute, scope coverage, and head fences into one typed
/// rejection. Takes no sequence allocator and mints no write intent: a
/// refusal always carries `stage_state: none`,
/// `ordering_sequence_assigned: false`, `write_mutation_status:
/// NOT_ATTEMPTED`, and no `write_intent_id`.
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
) -> Result<(), PreStageRejection> {
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
        return Err(conflict_rejection(context, transition, &canonical_hash));
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
        return Ok(());
    }
    let semantic = defects.iter().any(|code| {
        code.contains("FENCE") || code.contains("REVISION") || code.contains("ORDERING")
    });
    let rejection = PreStageRejection {
        request_id: context.request_id.as_str().to_owned(),
        proposed_operation_id: transition.identity.operation_id.as_str().to_owned(),
        idempotency_key: key.clone(),
        canonical_request_hash: canonical_hash.clone(),
        rejection_id: derive_rejection_id(&key, &canonical_hash),
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
    cache
        .entries
        .insert(key, (canonical_hash, rejection.clone()));
    Err(rejection)
}

fn conflict_rejection(
    context: &RequestMetadata,
    transition: &PreparedTransition,
    canonical_hash: &str,
) -> PreStageRejection {
    let key = transition.identity.idempotency_key.clone();
    PreStageRejection {
        request_id: context.request_id.as_str().to_owned(),
        proposed_operation_id: transition.identity.operation_id.as_str().to_owned(),
        idempotency_key: key.clone(),
        canonical_request_hash: canonical_hash.to_owned(),
        rejection_id: derive_rejection_id(&key, canonical_hash),
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
        PreparedTransition {
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
            named_operations: Vec::new(),
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        }
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
