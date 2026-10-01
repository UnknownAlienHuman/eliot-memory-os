//! Provider-neutral canonical request hash for issue #63 (RECHECK-63, wave 1).
//!
//! This module owns the ONE shared executable-request digest recomputed by
//! Governor, Kernel and store. It covers the exact executable request:
//! operation/idempotency identity; the authenticated [`RequestMeta`] (which
//! carries the State Fence); scope/task/class/effect ceiling; the
//! contract-set and operation-manifest digests; named operations plus
//! event/projection/relation intents; the security/provenance closure plus
//! proof/approval refs; the expected revision and ordering heads; and the
//! carried ordering scopes bound as set-like input.
//!
//! The transition's `ordering_scopes` are hash-bound as a separate set-like
//! field: every gate binds the complete carried scope set (sorted,
//! duplicate-rejecting) into the digest via
//! [`CanonicalRequestView::from_apply`], including on legs carrying no
//! ordering CAS expectations, so a post-admission scope addition, removal,
//! or substitution forks the recomputed digest into the typed mismatch
//! before any idempotency lookup, transaction, or receipt (see the
//! set-ordering rule below). Governor populates the hashed field from the
//! same scope set it places into the prepared transition; Kernel/store
//! rebind it from the carried transition. The exact set-equality between
//! carried scopes and hashed expected ordering heads stays enforced through
//! [`verify_ordering_scope_binding`] on legs carrying an ordering contract;
//! a content commitment and a CAS expectation are different obligations.
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
//! `ordering_scopes` by scope text,
//! `semantic_source_revisions` lexicographically (`key@revision` heads),
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
//!
//! The transition's `ordering_scopes` follow the same set semantics as
//! hashed view input: [`CanonicalRequestView::from_apply`] rebinds the
//! carried scopes verbatim and [`canonical_request_bytes`] sorts them into
//! canonical order (duplicates rejected with the typed error), so adding,
//! removing, or substituting that executable set forks the digest into
//! [`StoreError::TransitionDigestMismatch`] — including on legs carrying no
//! ordering CAS expectations, where the plan still advances one ordering
//! head and one chain link per declared scope. [`verify_ordering_scope_binding`]
//! additionally requires the carried scopes to equal the hashed expected
//! ordering heads as sets (sorted, duplicates rejected) on every path
//! carrying an ordering contract.
//!
//! The transition's `semantic_source_revisions` ARE hash-bound set-like
//! input (issue #63 cross-check): I1.8 names them part of the load-bearing
//! identity across the eliotd→Kernel→store boundary, and the store copies
//! them into the committed receipt and envelope, so a post-admission edit
//! that left the digest unchanged could commit substituted lineage. They
//! render as `key@revision` heads via
//! [`crate::render_semantic_source_revisions`] (canonically sorted) and are
//! sorted again here before hashing, so producer emission order cannot fork
//! the digest while any content edit forks it into the typed mismatch.
//!
//! Hash-version and legacy-replay discipline: the canonical bytes above ARE
//! the versioned encoding — there is no separate hash-version field and no
//! migration or restamp path. Extending the hashed input (as this module did
//! for `semantic_source_revisions` and now for `ordering_scopes`) changes
//! the digest by design: a retained digest computed under pre-binding bytes
//! is never reinterpreted under the new bytes, so its recompute diverges
//! into [`StoreError::TransitionDigestMismatch`], and the same
//! operation/idempotency key with forked executable bytes resolves through
//! the existing stored-vs-recomputed `IdentityConflict` arm with no
//! transaction — never a silent replay. Contract-revision support stays
//! with the existing exact gate (`PreparedTransition::validate` admits only
//! the recorded [`crate::CONTRACT_VERSION`], so an unsupported revision
//! fails before any content is interpreted). Genesis keeps its separately
//! defined request identity (`StoreGenesisRequest` digest and validation);
//! this family adds no genesis branch.
//!
//! Issue #1925 (write-intent carry) extends the hashed input with the two
//! write-intent identity members `write_intent_id` and
//! `write_envelope_protocol_version`, under exactly the discipline stated
//! above: the pinned golden vector below is re-pinned once to the new bytes,
//! and no retained pre-carry digest is reinterpreted under them. Neither
//! member is derived from `operation_id` or `idempotency_key` — they are a
//! third, distinct identity (see
//! [`crate::PreparedTransition::write_intent_id`]) — and neither has a
//! default, an `Option`, or a serde default, so a missing owner value is a
//! compile error at every construction site and a typed refusal at every
//! validating gate rather than a manufactured value.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EffectClass, EventProjectionRelationIntents, NamedMutationRequest, OperationId,
    OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    RequestMeta, RevisionHeadExpectation, ScopeId, SecurityContext, StoreError, TransitionClass,
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
    /// Stable user/agent write intent of the admitted submission.
    ///
    /// The third, distinct write identity beside `operation_id` (per attempt)
    /// and `idempotency_key` (per typed correction); see
    /// [`crate::PreparedTransition::write_intent_id`]. It is hash-bound
    /// request identity, so a post-admission edit of the admitted intent
    /// forks the recomputed digest into the typed mismatch at every gate.
    pub write_intent_id: String,
    /// Write-envelope protocol version of the admitted submission.
    ///
    /// Hash-bound beside the intent it was admitted under, so the exact
    /// protocol revision cannot be swapped after admission without forking the
    /// digest. See [`crate::PreparedTransition::write_envelope_protocol_version`].
    pub write_envelope_protocol_version: u32,
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
    /// Bound semantic source revisions rendered as `key@revision` heads.
    ///
    /// Set-like hash input (issue #63 cross-check): sorted into canonical
    /// order by [`canonical_request_bytes`] before hashing, so producer
    /// emission order cannot fork the digest while any content edit forks
    /// it. Governor renders these from the admitted expected revision heads
    /// and Kernel/store rebind them from the carried transition via
    /// [`CanonicalRequestView::from_apply`].
    pub semantic_source_revisions: Vec<String>,
    /// Carried ordering scopes bound as set-like hash input (issue #63
    /// audit 5870555183).
    ///
    /// Sorted into canonical order by [`canonical_request_bytes`] before
    /// hashing (duplicates rejected with the typed error), so producer
    /// emission order cannot fork the digest while any scope
    /// addition/removal/substitution forks it — including on legs carrying
    /// no ordering CAS expectations (empty `expected_ordering_heads`), where
    /// the scopes previously travelled outside request identity while the
    /// plan still advanced one ordering head and one chain link per declared
    /// scope. Governor populates this from the same scope set it places
    /// into the prepared transition; Kernel/store rebind it from the
    /// carried transition via [`CanonicalRequestView::from_apply`]. This is
    /// the content commitment; the CAS expectation stays the exact-equality
    /// check in [`verify_ordering_scope_binding`].
    pub ordering_scopes: Vec<OrderingScopeId>,
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
    /// is never copied into the hashed input. The transition's own
    /// `ordering_scopes` are rebound verbatim into the hash-bound
    /// [`CanonicalRequestView::ordering_scopes`] set: a post-admission scope
    /// edit forks the recomputed digest into the typed mismatch at every
    /// gate, including when no ordering CAS expectations travel alongside.
    /// The transition's
    /// `semantic_source_revisions` are rebound verbatim: they are hash-bound
    /// set-like input, so a post-admission edit forks the recomputed digest
    /// into the typed mismatch at every gate.
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
            write_intent_id: transition.write_intent_id.clone(),
            write_envelope_protocol_version: transition.write_envelope_protocol_version,
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
            semantic_source_revisions: transition.semantic_source_revisions.clone(),
            ordering_scopes: transition.ordering_scopes.clone(),
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
    // Bound source lineage is set-like (`key@revision` heads): canonical
    // order before hashing so emission order cannot fork the digest.
    normalized.semantic_source_revisions.sort();
    // Carried ordering scopes are execution-bearing set-like input (issue
    // #63 audit 5870555183): canonical order before hashing so emission
    // order cannot fork the digest, while any scope addition, removal, or
    // substitution forks it. Duplicates are rejected on the carried values
    // (the same typed refusal `PreparedTransition::validate` issues), so a
    // post-admission scope duplication fails here before any
    // lookup/transaction as well.
    normalized.ordering_scopes.sort();
    if normalized
        .ordering_scopes
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(StoreError::Duplicate {
            field: "ordering_scopes",
        });
    }
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

/// Domain separator for the corrected operation identity (issue #1796, I6.8).
const CORRECTED_OPERATION_ID_DOMAIN: &str = "eliot.contract_rejection.corrected_operation_id.v1";

/// Derives the corrected operation identity one refusal issues (issue #1796, I6.8).
///
/// `I6.8` requires the corrected request to receive a new operation ID while
/// `corrected_from_operation_id` preserves lineage, and requires an exact
/// retry of the same request hash to return the same rejection. Both inputs
/// here are already fixed by the refusal being returned: the rejected
/// operation identity, and the rejection identity, which is itself derived
/// only from the idempotency key and the canonical request hash. The same
/// refusal therefore always derives the same corrected identity, and a
/// different refusal always derives a different one. No nonce, clock,
/// counter, or new input participates.
///
/// This is the ONE shared derivation behind both the Governor owner
/// (`eliot-canonical::derive_corrected_operation_id`) and the Kernel
/// mechanical gate (`eliot-kernel-service` pre-stage rejection), so the
/// identity the live path stamps is exactly the identity the owner issues:
/// there is no second issuer to diverge from it.
#[must_use]
pub fn derive_corrected_operation_id(rejected_operation_id: &str, rejection_id: &str) -> String {
    let digest = sha256_hex(
        format!("{CORRECTED_OPERATION_ID_DOMAIN}:{rejected_operation_id}:{rejection_id}")
            .as_bytes(),
    );
    format!("corrected-{digest}")
}

/// Verifies that the transition-carried ordering scopes are the exact
/// execution of the hashed expected ordering heads (issue #63).
///
/// [`CanonicalRequestView`] covers both the expected heads and the carried
/// `ordering_scopes` (audit 5870555183), which the store executes: the plan
/// advances one ordering head per declared scope
/// (`surreal plan.rs`, `memory transaction_plan`) and the attempt reads the
/// union of declared and expected scopes. Governor derives the carried
/// scopes from the admitted heads (`prepare()`), so on any path carrying an
/// ordering contract (non-empty `expected_ordering_heads`) the two sets must
/// still coincide here: a post-admission scope addition, removal, or
/// substitution fails closed with
/// [`StoreError::TransitionDigestMismatch`] before any idempotency lookup,
/// transaction, or receipt — and independently forks the shared digest
/// through the hash-bound scopes, so an unchanged claimed hash is also
/// rejected by [`verify_canonical_request_hash`]. The comparison is
/// set-like (sorted, duplicates rejected), matching the module ordering rule
/// and the Kernel staging admission (`validate_admitted`,
/// `pre_stage_check`).
///
/// Legs carrying no ordering contract (empty `expected_ordering_heads` —
/// Kernel-direct automation/notification/reactive/lifecycle writes) carry no
/// CAS expectation to equate against, so they are never rejected here for
/// being expectation-free; their carried scopes are still content-committed
/// through the shared digest, and their set shape (no duplicated scope) is
/// enforced here. Their transitions are admitted by their owning legs.
/// Callers must invoke this
/// BEFORE any idempotency-lookup success is returned and BEFORE any
/// transaction/receipt, next to [`verify_canonical_request_hash`].
pub fn verify_ordering_scope_binding(
    transition: &PreparedTransition,
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), StoreError> {
    if expected_ordering_heads.is_empty() {
        // No CAS expectation to contradict — but the carried scopes remain
        // hash-bound request identity, so a duplicated scope is still a
        // post-admission edit and fails typed before any lookup/transaction.
        // Legitimate first-write/no-CAS legs carry each scope once and pass.
        let mut ordered = transition.ordering_scopes.clone();
        ordered.sort();
        if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StoreError::Duplicate {
                field: "ordering_scopes",
            });
        }
        return Ok(());
    }
    let mut declared: Vec<&str> = transition
        .ordering_scopes
        .iter()
        .map(OrderingScopeId::as_str)
        .collect();
    declared.sort_unstable();
    declared.dedup();
    // A repeated scope can never be admitted (`PreparedTransition::validate`
    // rejects it), so a duplicate here is a post-admission edit.
    if declared.len() != transition.ordering_scopes.len() {
        return Err(scope_binding_mismatch(expected_ordering_heads, &declared));
    }
    let mut expected: Vec<&str> = expected_ordering_heads
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    expected.sort_unstable();
    if expected != declared {
        return Err(scope_binding_mismatch(expected_ordering_heads, &declared));
    }
    Ok(())
}

/// Builds the typed mismatch for a scope-binding divergence.
///
/// Both digests are secret-free SHA-256 hex over the canonical (sorted,
/// comma-joined) scope sets: the admitted contract first, the executed
/// declaration second.
fn scope_binding_mismatch(
    expected_ordering_heads: &[OrderingHeadExpectation],
    declared: &[&str],
) -> StoreError {
    let mut expected: Vec<&str> = expected_ordering_heads
        .iter()
        .map(|head| head.scope.as_str())
        .collect();
    expected.sort_unstable();
    StoreError::TransitionDigestMismatch {
        expected: bound_digest(&sha256_hex(expected.join(",").as_bytes())),
        observed: bound_digest(&sha256_hex(declared.join(",").as_bytes())),
    }
}

/// Canonical admission-decision view hashed by [`admission_digest_hex`]
/// (issue #18 W2/W3/A1/A2/A3).
///
/// Documented byte layout of the I05-06 step-12 admission-DECISION digest:
/// canonical JSON (keys sorted recursively, arrays order-significant) of
/// exactly these bound values, in any key order after canonicalization:
/// `contract_set_digest` (the admitted contract-set INPUT digest, carried on
/// the transition as `admission_contract_set_digest`), `transition_class`
/// (snake case), `requested_effect_ceiling` (screaming case),
/// `scope_id` (transparent text), and `task_id` (string or null).
/// The named-operation plan is NOT repeated here: it is bound separately by
/// [`mutation_plan_digest_hex`]. The digest is lowercase SHA-256 hex over
/// those canonical bytes.
#[derive(Serialize)]
struct CanonicalAdmissionDecision<'a> {
    contract_set_digest: &'a str,
    transition_class: TransitionClass,
    requested_effect_ceiling: EffectClass,
    scope_id: &'a str,
    task_id: Option<&'a str>,
}

/// Computes the I05-06 step-12 admission-DECISION digest (issue #18).
///
/// This binds the admission DECISION (contract-set input plus the admitted
/// class, ceiling, scope, and task binding) and is distinct from the
/// contract-set input digest it covers. Every input is already covered by
/// [`canonical_request_bytes`], so the canonical request hash coverage is
/// unchanged; this binding only names the decision digest explicitly.
pub fn admission_digest_hex(transition: &PreparedTransition) -> Result<String, StoreError> {
    let view = CanonicalAdmissionDecision {
        contract_set_digest: &transition.admission_contract_set_digest,
        transition_class: transition.transition_class,
        requested_effect_ceiling: transition.requested_effect_ceiling,
        scope_id: transition.scope_id.as_str(),
        task_id: transition.task_id.as_deref(),
    };
    let bytes = canonical_json_bytes(&view)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Computes the I05-06 YAML `mutation_plan_hash` equivalent (issue #18).
///
/// Lowercase hex SHA-256 over the canonical bytes of the exact ordered
/// [`NamedMutationRequest`] plan. Execution order is significant: the plan
/// is hashed verbatim and never reordered (canonicalization sorts object
/// keys only, never arrays). This binds the authorized plan content and is
/// distinct from the authorizing catalogue manifest digest carried as
/// `operation_manifest_digest`. The plan content is already covered by
/// [`canonical_request_bytes`] via `semantic_commands`, so canonical
/// request hash coverage is unchanged.
pub fn mutation_plan_digest_hex(
    named_operations: &[NamedMutationRequest],
) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(&named_operations)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Recomputes the mutation-plan digest and rejects divergence with the typed
/// mismatch error (issue #18).
pub fn verify_mutation_plan_digest(transition: &PreparedTransition) -> Result<(), StoreError> {
    let observed = mutation_plan_digest_hex(&transition.named_operations)?;
    if observed == transition.mutation_plan_digest {
        Ok(())
    } else {
        Err(StoreError::TransitionDigestMismatch {
            expected: bound_digest(&transition.mutation_plan_digest),
            observed: bound_digest(&observed),
        })
    }
}

/// Recomputes the admission-decision digest and rejects divergence with the
/// typed mismatch error (issue #18).
pub fn verify_admission_digest(transition: &PreparedTransition) -> Result<(), StoreError> {
    let observed = admission_digest_hex(transition)?;
    if observed == transition.admission_digest {
        Ok(())
    } else {
        Err(StoreError::TransitionDigestMismatch {
            expected: bound_digest(&transition.admission_digest),
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
            selection_chain_head: None,
            selection_chain_seal: None,
        }
    }

    fn golden_view() -> CanonicalRequestView {
        let fence = fence();
        CanonicalRequestView {
            operation_id: OperationId::new("op-golden-1").expect("operation id"),
            request: context(),
            idempotency_key: "idem-golden-1".to_owned(),
            write_intent_id: "intent-golden-1".to_owned(),
            write_envelope_protocol_version: 1,
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
            // Bound source lineage mirrors the Governor envelope path: the
            // admitted expected revision heads rendered as `key@revision`.
            // Multi-element and already sorted, so the pinned bytes also
            // cover the set-like ordering rule.
            semantic_source_revisions: vec!["revision-a@1".to_owned(), "revision-b@2".to_owned()],
            // Carried ordering scopes are hash-bound set-like input, so this
            // golden view declares the same scope its expected ordering head
            // names, mirroring the Governor derivation: the same scope set the
            // admitted expected ordering heads render. It is not decoration:
            // `from_apply_rebinds_context_and_expected_heads` asserts that
            // rebuilding the view from the prepared transition reproduces this
            // one exactly, and the transition carries exactly this scope set,
            // so any other value here would fail that identity rather than this
            // fixture's subject.
            ordering_scopes: vec![OrderingScopeId::new("scope-golden").expect("ordering scope")],
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
        // #1925 RE-PIN — the literal below is the value
        // `canonical_request_hash` EMITTED over the current fixture, read off
        // the owner's own failure output. It was not derived by reading this
        // file and it was not invented; see the discipline note below.
        //
        // The previously pinned
        // `55e62e405f35c7f137fe9fcdf177c66a1cba54a5b75fb547deaa11f001a89ec1`
        // was ALREADY stale on `main` before this change: commit `2c22f4b45`
        // (#4728) added `ordering_scopes` to the hashed request input and
        // re-pinned neither this assertion nor the two comments that mirrored
        // it, and it left this file's own `golden_view` literal missing the
        // new field so the whole lib test target did not compile. #1925 fixes
        // the literal and adds the two write-intent identity members, moving
        // the digest again.
        //
        // Both moves follow this module's documented discipline: a retained
        // digest computed under pre-binding bytes is never reinterpreted
        // under the new bytes. The value cannot be derived by reading this
        // file; it is whatever the shared owner function emits, so it was
        // MEASURED from that function's own assertion output rather than
        // written by hand.
        assert_eq!(
            canonical_request_hash(&view).expect("golden hash computes"),
            "05cedc381edc6a841ee071f1fd5eaba6c667dac0c14fa4262c94a740aaac51f7"
        );
    }
    // #1925: the #3977 regeneration pinned
    // `21b8b2be1415dae7f905e202725e0eb02c953d06afef64a946db7d2a19bd601c`
    // over a `golden_view` that did not yet carry the two write-intent identity
    // members, so that literal was stale again here: both members are hash-bound
    // and this fixture declares them, and the assertion above now pins the value
    // the owner function emits over the merged fixture rather than either
    // predecessor — a retained digest computed under pre-binding bytes is never
    // reinterpreted under the new bytes. See issue #3977 for the original
    // regeneration.
    //
    // #3977 also required the two cross-crate references that cite this vector
    // by name (`eliot-store-surreal-adapter/src/plan.rs`,
    // `eliot-store-memory/src/lib.rs`) to move with the re-pin. Both now name
    // this owning assertion as the single place the golden vector is pinned
    // instead of restating a literal here that nobody has recomputed.

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
            contract_version: crate::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: view.operation_id.clone(),
                idempotency_key: view.idempotency_key.clone(),
                canonical_request_hash: "d".repeat(64),
            },
            write_intent_id: view.write_intent_id.clone(),
            write_envelope_protocol_version: view.write_envelope_protocol_version,
            state_fence: fence(),
            scope_id: view.scope_id.clone(),
            task_id: view.task_id.clone(),
            ordering_scopes: vec![OrderingScopeId::new("scope-golden").expect("ordering")],
            transition_class: view.transition_class,
            requested_effect_ceiling: view.requested_effect_ceiling,
            admission_contract_set_digest: view.admission_contract_set_digest.clone(),
            operation_manifest_digest: view.operation_manifest_digest.clone(),
            admission_digest: "e".repeat(64),
            mutation_plan_digest: "f".repeat(64),
            semantic_source_revisions: view.semantic_source_revisions.clone(),
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

    fn bound_transition() -> PreparedTransition {
        let view = golden_view();
        let mut transition = PreparedTransition {
            contract_version: crate::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: view.operation_id.clone(),
                idempotency_key: view.idempotency_key.clone(),
                canonical_request_hash: "d".repeat(64),
            },
            write_intent_id: view.write_intent_id.clone(),
            write_envelope_protocol_version: view.write_envelope_protocol_version,
            state_fence: fence(),
            scope_id: view.scope_id.clone(),
            task_id: view.task_id.clone(),
            ordering_scopes: vec![OrderingScopeId::new("scope-golden").expect("ordering")],
            transition_class: view.transition_class,
            requested_effect_ceiling: view.requested_effect_ceiling,
            admission_contract_set_digest: view.admission_contract_set_digest.clone(),
            operation_manifest_digest: view.operation_manifest_digest.clone(),
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: view.semantic_commands.clone(),
            event_projection_relation_intents: view.event_projection_relation_intents.clone(),
            security: view.security.clone(),
            required_proof_and_approval_refs: view.required_proof_and_approval_refs.clone(),
        };
        crate::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    #[test]
    fn issue18_digests_bind_derived_content_and_verify() {
        let transition = bound_transition();
        // The mutation-plan digest binds the exact ordered plan and forks
        // when execution order changes.
        let plan_digest =
            mutation_plan_digest_hex(&transition.named_operations).expect("plan digest computes");
        assert_eq!(transition.mutation_plan_digest, plan_digest);
        let mut two_command = transition.named_operations.clone();
        two_command.push(NamedMutationRequest {
            operation: NamedMutationOperation::AppendAuditEvent,
            parameters: BTreeMap::from([("note".to_owned(), serde_json::json!("audit-golden-1"))]),
        });
        let ordered_digest =
            mutation_plan_digest_hex(&two_command).expect("ordered digest computes");
        let mut reordered = two_command.clone();
        reordered.rotate_right(1);
        assert_ne!(
            mutation_plan_digest_hex(&reordered).expect("reordered digest computes"),
            ordered_digest
        );
        assert!(verify_mutation_plan_digest(&transition).is_ok());
        // The admission-decision digest binds the decision, never the bare
        // contract-set input: it differs from the input digest and forks
        // when the admitted class changes.
        let decision_digest = admission_digest_hex(&transition).expect("decision digest computes");
        assert_eq!(transition.admission_digest, decision_digest);
        assert_ne!(decision_digest, transition.admission_contract_set_digest);
        let mut reclassed = transition.clone();
        reclassed.transition_class = TransitionClass::Epistemic;
        assert_ne!(
            admission_digest_hex(&reclassed).expect("reclassed digest computes"),
            decision_digest
        );
        assert!(verify_admission_digest(&transition).is_ok());
    }

    #[test]
    fn issue18_digest_tampering_maps_to_the_typed_mismatch() {
        let transition = bound_transition();
        let mut tampered_plan = transition.clone();
        tampered_plan.mutation_plan_digest = "0".repeat(64);
        assert!(matches!(
            verify_mutation_plan_digest(&tampered_plan),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));
        let mut tampered_admission = transition.clone();
        tampered_admission.admission_digest = "1".repeat(64);
        assert!(matches!(
            verify_admission_digest(&tampered_admission),
            Err(StoreError::TransitionDigestMismatch { .. })
        ));
    }
}
