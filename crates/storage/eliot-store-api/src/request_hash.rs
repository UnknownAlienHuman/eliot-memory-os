//! Provider-neutral canonical request hash for issue #63 (RECHECK-63, wave 1).
//!
//! This module owns the ONE shared executable-request digest recomputed by
//! Governor, Kernel and store. It covers the exact executable request:
//! operation/idempotency identity; the authenticated [`RequestMeta`] (which
//! carries the State Fence); scope/task/class/effect ceiling; the
//! contract-set and operation-manifest digests; named operations plus
//! event/projection/relation intents; the security/provenance closure plus
//! proof/approval refs; and the expected revision and ordering heads.
//!
//! The input [`CanonicalRequestView`] is the full envelope-equivalent shape:
//! Governor builds it from [`crate`] admission values, while Kernel/store
//! build the identical view from their transported
//! [`crate::StoreRequest::Apply`] values (`context` + `transition` +
//! expected heads) via [`CanonicalRequestView::from_apply`]. The transition's
//! own `identity.canonical_request_hash` is the digest output and is never
//! part of the hashed input (it must not recursively include itself).
//!
//! Canonicalization reuses the workspace helper
//! [`crate::canonical_json_bytes`] (sorted object keys, no new dependency)
//! and the digest is lowercase SHA-256 hex via [`crate::sha256_hex`].
//! There is exactly one hash owner and no provider-specific or
//! daemon-specific encoding.
//!
//! # Set-ordering rule (issue #63)
//!
//! Semantically set-like collections are sorted into canonical order before
//! hashing, so producer emission order cannot fork the digest:
//! `expected_revision_heads` by key, `expected_ordering_heads` by scope,
//! `required_proof_and_approval_refs` lexicographically, and each
//! event/projection/relation intent list (`event_ids` by id,
//! `projection_kinds` / `relation_kinds` lexicographically).
//!
//! `semantic_commands` (the prepared `named_operations`) keep execution
//! order significant and are never reordered here: plan commands resolve in
//! order against the catalogue and "plan commands are never reordered" (see
//! [`crate::PreparedTransition::validate_against_catalogue`]. Likewise the
//! `security` provenance/lineage vectors are ordered chains and keep their
//! order. Reordering a set-like collection therefore yields the identical
//! hash, while reordering `semantic_commands` yields a different hash.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EffectClass, EventProjectionRelationIntents, NamedMutationRequest, OperationId,
    OperationManifestDigest, OrderingHeadExpectation, PreparedTransition, RequestMeta,
    RevisionHeadExpectation, ScopeId, SecurityContext, StoreError, TransitionClass,
    canonical_json_bytes, sha256_hex,
};

/// Maximum characters of each digest carried by [`StoreError::TransitionDigestMismatch`].
///
/// Digests are fixed 64-character lowercase hex; the bound only truncates a
/// malformed claimant so the error itself stays bounded.
pub const MAX_DIGEST_DETAIL_CHARS: usize = 64;

/// Full envelope-equivalent canonical hash input for issue #63.
///
/// The serde shape is intentionally field-identical to the Governor
/// `CanonicalWriteEnvelope` (same names, same shared types), so hashing this
/// view yields byte-identical bytes to hashing the admitted envelope.
/// Kernel/store construct the same view from their transported apply values;
/// no wire change is required because `StoreRequest::Apply` already carries
/// every field (context, transition, expected revision heads, expected
/// ordering heads).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRequestView {
    /// Operation identity used for retries and receipt lookup.
    pub operation_id: OperationId,
    /// Authenticated request metadata and the caller's State Fence.
    pub request: RequestMeta,
    /// Stable logical retry identity.
    pub idempotency_key: String,
    /// Scope addressed by the transition.
    pub scope_id: ScopeId,
    /// Optional task binding; unbound capture remains cold evidence.
    pub task_id: Option<String>,
    /// Closed transition family selected by admission.
    pub transition_class: TransitionClass,
    /// Effect ceiling requested by the candidate, never an authority grant.
    pub requested_effect_ceiling: EffectClass,
    /// Digest of the admitted semantic contract set.
    pub admission_contract_set_digest: String,
    /// Digest of the named store operation manifest.
    pub operation_manifest_digest: OperationManifestDigest,
    /// Bounded named commands sharing one causal transition. Execution order
    /// is significant and is preserved verbatim by the hash.
    pub semantic_commands: Vec<NamedMutationRequest>,
    /// Event, projection, and typed-relation intents committed atomically.
    pub event_projection_relation_intents: EventProjectionRelationIntents,
    /// Provenance, disclosure, taint, and influence metadata (ordered chains).
    pub security: SecurityContext,
    /// Exact proof or approval handles required by this transition.
    pub required_proof_and_approval_refs: Vec<String>,
    /// Compare-and-swap expectations for affected revision heads.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Compare-and-swap expectations for affected ordering heads.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

impl CanonicalRequestView {
    /// Builds the shared view from separately transported apply values.
    ///
    /// This is the Kernel/store construction path: the prepared transition
    /// drops the full request metadata (it keeps only the fence) and the
    /// expected heads, so both are rebound here from the transported
    /// `context` and head lists. The transition's stored
    /// `identity.canonical_request_hash` is the claimed digest under test and
    /// is never copied into the hashed input.
    pub fn from_apply(
        context: &RequestMeta,
        transition: &PreparedTransition,
        expected_revision_heads: &[RevisionHeadExpectation],
        expected_ordering_heads: &[OrderingHeadExpectation],
    ) -> Self {
        Self {
            operation_id: transition.identity.operation_id.clone(),
            request: context.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            scope_id: transition.scope_id.clone(),
            task_id: transition.task_id.clone(),
            transition_class: transition.transition_class,
            requested_effect_ceiling: transition.requested_effect_ceiling,
            admission_contract_set_digest: transition.admission_contract_set_digest.clone(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            semantic_commands: transition.named_operations.clone(),
            event_projection_relation_intents: transition.event_projection_relation_intents.clone(),
            security: transition.security.clone(),
            required_proof_and_approval_refs: transition.required_proof_and_approval_refs.clone(),
            expected_revision_heads: expected_revision_heads.to_vec(),
            expected_ordering_heads: expected_ordering_heads.to_vec(),
        }
    }
}

/// Returns the deterministic bytes covered by [`canonical_request_hash`].
///
/// Set-like collections are normalized per the module-level ordering rule
/// before canonical JSON encoding; `semantic_commands` and the `security`
/// chains keep their order.
pub fn canonical_request_bytes(view: &CanonicalRequestView) -> Result<Vec<u8>, StoreError> {
    let mut normalized = view.clone();
    normalized
        .expected_revision_heads
        .sort_by(|left, right| left.key.cmp(&right.key));
    normalized
        .expected_ordering_heads
        .sort_by(|left, right| left.scope.cmp(&right.scope));
    normalized.required_proof_and_approval_refs.sort();
    normalized
        .event_projection_relation_intents
        .event_ids
        .sort();
    normalized
        .event_projection_relation_intents
        .projection_kinds
        .sort();
    normalized
        .event_projection_relation_intents
        .relation_kinds
        .sort();
    canonical_json_bytes(&normalized).map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Computes the provider-neutral canonical request hash (lowercase SHA-256).
pub fn canonical_request_hash(view: &CanonicalRequestView) -> Result<String, StoreError> {
    Ok(sha256_hex(&canonical_request_bytes(view)?))
}

/// Recomputes the hash and rejects divergence with the typed mismatch error.
///
/// Both digests in the error are secret-free (hex digests only) and bounded
/// to [`MAX_DIGEST_DETAIL_CHARS`] characters each.
pub fn verify_canonical_request_hash(
    view: &CanonicalRequestView,
    expected_hex: &str,
) -> Result<(), StoreError> {
    let observed = canonical_request_hash(view)?;
    if observed == expected_hex {
        Ok(())
    } else {
        Err(StoreError::TransitionDigestMismatch {
            expected: bound_digest(expected_hex),
            observed: bound_digest(&observed),
        })
    }
}

fn bound_digest(value: &str) -> String {
    value.chars().take(MAX_DIGEST_DETAIL_CHARS).collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        EffectClass, EventId, NamedMutationOperation, OperationIdentity, OrderingScopeId,
        RevisionKey, TransitionClass,
    };
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
        StateFence,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    fn fence() -> StateFence {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn context() -> RequestMeta {
        RequestMeta {
            request_id: RequestId::new("request-golden-1").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-golden").expect("product id"),
            source_id: SourceId::new("source-golden").expect("source id"),
            state_fence: fence(),
            clock: ClockReading::default(),
        }
    }

    fn security_fixture() -> SecurityContext {
        use eliot_security_contracts::{
            CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
            InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState,
        };
        SecurityContext {
            source_assurance: vec![crate::SourceAssurance {
                source_ref: "source-golden-1".to_owned(),
                provenance_ref: "provenance-golden-1".to_owned(),
                integrity: IntegrityStatus::Verified,
                freshness: FreshnessStatus::Current,
                competence: CompetenceLevel::Attributed,
                independence: IndependenceLevel::Independent,
                privacy_class: PrivacyClass::Internal,
                instruction_taint: InstructionTaint::DataOnly,
                allowed_epistemic_use: vec![EpistemicUse::Observation],
                allowed_effects: vec![EffectCeiling::CandidateOnly],
                required_verifier: None,
                quarantine: QuarantineState::None,
                state_fence: fence(),
            }],
            disclosure_closure: None,
            transformation_lineage: Vec::new(),
            influence_closure: None,
            purge_entry: None,
            selection_integrity: None,
        }
    }

    fn golden_view() -> CanonicalRequestView {
        let fence = fence();
        CanonicalRequestView {
            operation_id: OperationId::new("op-golden-1").expect("operation id"),
            request: context(),
            idempotency_key: "idem-golden-1".to_owned(),
            scope_id: ScopeId::new("scope-golden").expect("scope"),
            task_id: Some("task-golden-1".to_owned()),
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "c".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-golden-1")
                .expect("manifest digest"),
            semantic_commands: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-golden-1"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: vec![
                    EventId::new("event-golden-1").expect("event id"),
                    EventId::new("event-golden-2").expect("event id"),
                ],
                projection_kinds: vec![
                    "projection-golden-1".to_owned(),
                    "projection-golden-2".to_owned(),
                ],
                relation_kinds: vec![
                    "relation-golden-1".to_owned(),
                    "relation-golden-2".to_owned(),
                ],
            },
            security: security_fixture(),
            required_proof_and_approval_refs: vec![
                "approval-golden-1".to_owned(),
                "proof-golden-1".to_owned(),
            ],
            expected_revision_heads: vec![
                RevisionHeadExpectation {
                    key: RevisionKey::new("revision-a").expect("key"),
                    expected_revision: 1,
                    state_fence: fence.clone(),
                },
                RevisionHeadExpectation {
                    key: RevisionKey::new("revision-b").expect("key"),
                    expected_revision: 2,
                    state_fence: fence.clone(),
                },
            ],
            expected_ordering_heads: vec![OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope-golden").expect("ordering scope"),
                expected_sequence: 1,
                state_fence: fence,
            }],
        }
    }

    #[test]
    fn golden_request_hash_is_stable_across_crates() {
        let view = golden_view();
        assert_eq!(
            canonical_request_hash(&view).expect("golden hash computes"),
            "55e62e405f35c7f137fe9fcdf177c66a1cba54a5b75fb547deaa11f001a89ec1"
        );
    }

    #[test]
    fn load_bearing_mutations_change_the_hash_and_map_to_the_typed_error() {
        let view = golden_view();
        let golden = canonical_request_hash(&view).expect("golden hash computes");
        assert!(verify_canonical_request_hash(&view, &golden).is_ok());

        // One expected head.
        let mut head = view.clone();
        head.expected_revision_heads[0].expected_revision = 99;
        assert_ne!(
            canonical_request_hash(&head).expect("mutated hash computes"),
            golden
        );
        assert!(matches!(
            verify_canonical_request_hash(&head, &golden),
            Err(StoreError::TransitionDigestMismatch { expected, observed })
                if expected == golden
                    && observed == canonical_request_hash(&head).expect("observed hash")
        ));

        // One manifest digest.
        let mut manifest = view.clone();
        manifest.operation_manifest_digest =
            OperationManifestDigest::new("manifest-mutated").expect("manifest digest");
        assert_ne!(
            canonical_request_hash(&manifest).expect("mutated hash computes"),
            golden
        );
        assert!(matches!(
            verify_canonical_request_hash(&manifest, &golden),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));

        // One security field.
        let mut security = view.clone();
        security.security.source_assurance[0].provenance_ref = "provenance-mutated".to_owned();
        assert_ne!(
            canonical_request_hash(&security).expect("mutated hash computes"),
            golden
        );
        assert!(matches!(
            verify_canonical_request_hash(&security, &golden),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));
    }

    #[test]
    fn exact_replay_of_identical_bytes_yields_the_identical_hash() {
        let view = golden_view();
        let first = canonical_request_hash(&view).expect("first hash computes");
        let bytes = canonical_request_bytes(&view).expect("canonical bytes compute");
        let replay: CanonicalRequestView =
            serde_json::from_slice(&bytes).expect("canonical bytes replay");
        assert_eq!(replay, view);
        assert_eq!(
            canonical_request_hash(&replay).expect("replay hash computes"),
            first
        );
        assert_eq!(
            canonical_request_bytes(&replay).expect("replay bytes compute"),
            bytes
        );
    }

    #[test]
    fn reordering_set_like_collections_keeps_the_hash() {
        let canonical = golden_view();
        let canonical_hash = canonical_request_hash(&canonical).expect("canonical hash computes");
        let mut reordered = golden_view();
        reordered.expected_revision_heads.reverse();
        reordered.required_proof_and_approval_refs.reverse();
        reordered
            .event_projection_relation_intents
            .event_ids
            .reverse();
        reordered
            .event_projection_relation_intents
            .projection_kinds
            .reverse();
        reordered
            .event_projection_relation_intents
            .relation_kinds
            .reverse();
        assert_eq!(
            canonical_request_hash(&reordered).expect("reordered hash computes"),
            canonical_hash
        );
    }

    #[test]
    fn reordering_semantic_commands_forks_the_hash() {
        let mut reordered = golden_view();
        reordered.semantic_commands.push(NamedMutationRequest {
            operation: NamedMutationOperation::AppendAuditEvent,
            parameters: BTreeMap::from([("note".to_owned(), serde_json::json!("audit-golden-1"))]),
        });
        // Swap execution order: content-identical, order-significant.
        reordered.semantic_commands.rotate_right(1);
        let mut ordered = golden_view();
        ordered.semantic_commands = reordered.semantic_commands.clone();
        ordered.semantic_commands.rotate_left(1);
        assert_ne!(
            canonical_request_hash(&reordered).expect("reordered hash computes"),
            canonical_request_hash(&ordered).expect("ordered hash computes")
        );
    }

    #[test]
    fn from_apply_rebinds_context_and_expected_heads() {
        let view = golden_view();
        let transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: view.operation_id.clone(),
                idempotency_key: view.idempotency_key.clone(),
                canonical_request_hash: "d".repeat(64),
            },
            state_fence: fence(),
            scope_id: view.scope_id.clone(),
            task_id: view.task_id.clone(),
            ordering_scopes: vec![OrderingScopeId::new("scope-golden").expect("ordering")],
            transition_class: view.transition_class,
            requested_effect_ceiling: view.requested_effect_ceiling,
            admission_contract_set_digest: view.admission_contract_set_digest.clone(),
            operation_manifest_digest: view.operation_manifest_digest.clone(),
            named_operations: view.semantic_commands.clone(),
            event_projection_relation_intents: view.event_projection_relation_intents.clone(),
            security: view.security.clone(),
            required_proof_and_approval_refs: view.required_proof_and_approval_refs.clone(),
        };
        let rebuilt = CanonicalRequestView::from_apply(
            &view.request,
            &transition,
            &view.expected_revision_heads,
            &view.expected_ordering_heads,
        );
        assert_eq!(rebuilt, view);
    }
}
