//! The I5.6 admission sequence `eliotd` performs before a `PreparedTransition`
//! leaves this process (issue #1927).
//!
//! `docs/architecture/I05-06-admission-and-staging.md` fixes the daemon's
//! obligation: "`eliotd` produces a deterministic, immutable execution plan
//! after semantic admission", over the eighteen named plan keys, and it fixes
//! the sequence that ends in the plan (steps 1-12 of the admission list; step
//! 13 stages, and staging/execution belong to Kernel and the store bridge, not
//! to this module). This file is that step 1-12 sequence for the daemon's
//! production `NotificationState` write legs, in one place, so the eighteen
//! keys are bound by a single owner instead of being restated by each leg.
//!
//! # The plan is a pure function of the admitted inputs
//!
//! [`NotificationPlanAdmission`] carries only state that was already admitted
//! before this function runs: the authenticated ingress identity the leg
//! derived from observed store state, the operation text that identity is keyed
//! by, the leg's own contract-set input digest, the closed leg's exact
//! named-operation parameters, and the live ordering head the leg
//! compare-and-swaps. Nothing here reads a clock, draws a random value, reads
//! the environment, or iterates an unordered collection:
//!
//! * `parameters` is a [`BTreeMap`], so the leg's parameter order is key order
//!   and cannot vary between two runs of the same admission;
//! * every digest below is taken over `canonical_json_bytes`, which sorts
//!   object keys recursively and preserves array order, so a JSON value's
//!   map-iteration order cannot fork a digest either;
//! * the one list the plan carries in execution order — the named operations —
//!   is a single command built here, and `CanonicalWriteEnvelope::prepare`
//!   copies it verbatim without sorting, so execution order is declared, not
//!   derived.
//!
//! Two runs over the same admitted state therefore produce a byte-identical
//! plan, including `identity.canonical_request_hash`,
//! `mutation_plan_digest`, `admission_digest` and — because
//! `prepared_transition_digest` hashes this whole value — the staged plan
//! digest.
//!
//! # Each digest is computed over the bytes it names
//!
//! * `operation_manifest_digest` is
//!   `operation_manifest_set_digest` over the generated catalogue set, i.e. the
//!   digest of the manifests that authorize the leg. It is not a copied
//!   constant and not a digest of the caller's own list.
//! * `mutation_plan_digest` and `admission_digest` are bound by
//!   `CanonicalWriteEnvelope::prepare` over the exact ordered
//!   `NamedMutationRequest` plan and the exact admitted decision tuple, from
//!   the carried content. They are never accepted from a caller.
//! * `admission_contract_set_digest` is the leg's admitted contract-set INPUT
//!   digest, supplied by the leg because only the leg knows which contract set
//!   it admits under. It is validated as a digest and is hash-bound downstream;
//!   it is NOT claimed here to be compared against a live catalogue, because
//!   `docs/architecture/I05-15-canonical-contract-catalogue.md` records that
//!   catalogue as `ImplementationSupport = TARGET`, so no such live value
//!   exists to compare it to and inventing one would be exactly the invented
//!   authority this boundary must not create.
//!
//! # The recorded values are checked before the plan is transportable
//!
//! Two checks run here, at the producing edge, and neither is a recompute
//! compared against itself:
//!
//! 1. [`PreparedTransition::validate_against_catalogue`] against a SECOND,
//!    independently generated catalogue set. It revalidates the recorded
//!    contract revision, the plan's own bound digests, the class/effect
//!    ceiling, and every named operation's typed parameters, then binds the
//!    recorded `operation_manifest_digest` by content to the current table. An
//!    unsupported or widened plan is refused here and never leaves the daemon.
//! 2. `verify_canonical_request_hash` over [`CanonicalRequestView::from_apply`]
//!    — the Kernel/store CONSTRUCTION path, not this crate's producing
//!    derivation — compared against the RECORDED
//!    `transition.identity.canonical_request_hash`. This is what makes
//!    [`VerifiedNotificationPlan`] meaningful: the context, plan and head
//!    lists the leg transports are the exact values the recorded digest was
//!    verified against, so the submission cannot be assembled a second time
//!    from something else.
//!
//! # What this module does not claim
//!
//! The three I5.6 plan keys with no home on the plan today are absent here for
//! a stated reason each, not silently:
//!
//! * `policy_config_schema_snapshots` — the live identity is
//!   `eliot_store_api::PolicyConfigSchemaVersions`, bound onto the WRITE
//!   RECEIPT from the admitted transition and enforced by equality at the
//!   receipt-issuing path. Moving it onto the plan changes the plan's byte
//!   layout and therefore the `prepared_transition_digest` of every staged
//!   plan, and that is a store-api contract decision, not a daemon one.
//! * `proposing_daemon_generation` — the daemon generation is minted by Kernel
//!   generation control (`bins/eliot-kernel/src/generation_control.rs`), and
//!   the daemon has no admissible source for it. Minting one here would
//!   fabricate authority lineage.
//! * `receipt_and_outbox_intents` — the outbox row's identity and sequence
//!   are minted at COMMIT, not at admission:
//!   `OutboxIntentKind::outbox_id(operation_key, index)` over an index the
//!   store walks, paired with a sequence taken from the store's own
//!   `next_outbox_sequence` cursor
//!   (`crates/storage/eliot-store-surreal-adapter/src/plan.rs`, checked
//!   through `checked_increment(.., "outbox.sequence", ..)`). Declaring the
//!   intent on the plan would pre-consume an identity and a sequence the store
//!   has not allocated.
//!
//! `privacy_origin_taint_metadata` is carried, on `SecurityContext`, as
//! recorded provenance. This leg binds the empty chain explicitly rather than
//! synthesizing source assurance it did not observe.
//!
//! Forbidden authority: no Store or provider client, no alternate transport,
//! no retry or default synthesis, no second notification model, and no semantic
//! decision this module did not receive from its owner.
//!
//! Governed by `AGENTS.md`, `bins/AGENTS.md`, and
//! `docs/architecture/READING_PROTOCOL.md`. Implementation: I5.6, I5.7, I1.8,
//! I11.5. Architecture: A2.3, A12.3, A13.2.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{OperationId, RequestMetadata};
use eliot_governor::{CanonicalWriteEnvelope, CompositionError};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CanonicalRequestView, EffectClass, EventProjectionRelationIntents, NOTIFICATION_STATE_SCOPE,
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, ScopeId, SecurityContext,
    StoreError, TransitionClass, generated_operation_manifests, notification_mutation_request,
    operation_manifest_set_digest, verify_canonical_request_hash,
};

use super::notification_state_emit::NotificationEmitError;

/// The admitted inputs of one `NotificationState` lifecycle leg.
///
/// This is the whole input of the I5.6 admission sequence. Every member is
/// already admitted state, so the plan this produces is a pure function of it
/// (see the module documentation). Nothing here is a default, a guess, or a
/// value read from the environment.
pub struct NotificationPlanAdmission<'a> {
    /// The authenticated ingress identity, already derived by the leg from the
    /// store state it observed. Its request metadata supplies the
    /// `principal_session_scope_task` half of the plan's identity and is the
    /// `context` half of the canonical request hash; it is never re-derived
    /// here.
    pub identity: &'a RequestIdentity,
    /// The operation text that identity is keyed by. `CanonicalWriteEnvelope::
    /// prepare` binds it to `identity.operation_id`, so the plan's operation
    /// and idempotency identity is a function of the admitted identity rather
    /// than a second formatting of it.
    pub operation_text: &'a str,
    /// The digest of the semantic contract set this leg admits under.
    ///
    /// Supplied by the leg because only the leg knows which contract set its
    /// own admission was made against. It is recorded, never re-derived, and
    /// the module documentation states plainly which check is and is not
    /// claimed for it.
    pub admission_contract_set_digest: &'a str,
    /// The closed leg's exact named-operation parameters, in canonical key
    /// order.
    ///
    /// This is the leg's whole parameter set; a key the leg does not name
    /// cannot ride along, and one it names cannot be reordered.
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// The live ordering head this leg compare-and-swaps.
    ///
    /// `CanonicalWriteEnvelope::prepare` DERIVES the plan's `ordering_scopes`
    /// from this head, so the plan cannot declare a scope set the leg never
    /// observed.
    pub ordering_head: &'a OrderingHeadExpectation,
}

/// The plan `eliotd` produced, together with the exact submission inputs its
/// recorded canonical request hash was verified against.
///
/// This is the exact four-field flat apply contract
/// `bins/eliotd/src/kernel_transition_client.rs`'s `apply_prepared` transports,
/// field for field. It exists so the transported context, plan and head lists
/// cannot be a second assembly of values other than the ones the recorded
/// digest was checked against: a caller submits these four fields or it does
/// not submit a verified plan.
pub struct VerifiedNotificationPlan {
    /// The immutable plan. Its contents, effect ceiling, scope set, named
    /// operation parameters and admission digest are fixed at admission; any
    /// later change to them is refused by the recompute gates rather than
    /// re-derived.
    pub transition: PreparedTransition,
    /// The request metadata the recorded canonical request hash was verified
    /// against.
    pub context: RequestMetadata,
    /// The revision heads the recorded canonical request hash was verified
    /// against. Empty for this class: the notification record is not derived
    /// from a canonical revision head, and the store's revision advance for
    /// the fixed notification scope is driven by the ordering head alone.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// The ordering heads the recorded canonical request hash was verified
    /// against.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

/// Performs the I5.6 admission sequence for one `NotificationState` lifecycle
/// leg and returns the immutable plan plus its verified submission.
///
/// The sequence, in the order I5.6 fixes:
///
/// 1. the authenticated identity is taken as given and is never re-derived;
/// 2. the envelope is validated and its canonical request identity computed
///    (I5.6 step 2) inside `CanonicalWriteEnvelope::prepare`;
/// 3. the authenticated `WorkScope` and the Ordering Scopes are resolved from
///    the fixed notification scope and the live head (I5.6 step 3) — the scope
///    is a contract constant and the ordering scopes are derived from the
///    head, never chosen;
/// 4. the leg is not task-relative, so no task selection or task-contract
///    compatibility is resolved and `task_id` stays `None`;
/// 5. the State Fence travels inside the admitted identity and the expected
///    current ordering sequence is the observed head (I5.6 step 5);
/// 6. the exact evidence handles the leg carries are its own closed
///    named-operation parameters (I5.6 step 6);
/// 7. paths and resources are the fixed notification scope and scope key, and
///    privacy/source visibility is the empty declared chain
///    (`SecurityContext::default()`, recorded explicitly, never synthesized);
/// 8. instruction taint/origin/disclosure metadata is that same recorded chain
///    (I5.6 step 8) — the leg observed no source assurance, so it records
///    none rather than inventing competence, independence or quarantine
///    values it has no evidence for;
/// 9. the impact class and the requested semantic effect are the closed
///    `NotificationState` class and exactly its class maximum, never a wider
///    ceiling (I5.6 step 9);
/// 10. freshness and post-commit revisions are not normalized here because this
///     leg is not a reusable candidate: it is admitted once against one
///     observed ordering sequence and never promoted to a hot candidate;
/// 11. the plan is built deterministically and its admission-decision digest is
///     derived over the carried content (I5.6 step 12) inside
///     `CanonicalWriteEnvelope::prepare`.
/// 12. the produced plan is then checked against current admissible support
///     and against its own recorded canonical request hash before it can be
///     transported (see the module documentation).
///
/// # Errors
///
/// Returns [`NotificationEmitError`] with its owner's own typed failure: a
/// [`StoreError`] for a refused contract value, refused catalogue binding,
/// refused digest binding or refused parameter set, and the composition's own
/// `Admission` channel when canonical admission refuses the prepared
/// transition. No code is folded into prose between layers.
pub fn admit_notification_transition(
    admission: &NotificationPlanAdmission<'_>,
) -> Result<VerifiedNotificationPlan, NotificationEmitError> {
    // The authorizing catalogue set is read once here and hashed into the
    // plan. It is read AGAIN below, from a separate generated table read, to
    // check the produced plan against current support: validating the plan
    // against the very slice its own digest was taken from would be comparing
    // a value with itself.
    let authorizing_manifests = generated_operation_manifests()?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: OperationId::new(admission.operation_text).map_err(StoreError::Foundation)?,
        request: admission.identity.request.metadata.clone(),
        idempotency_key: admission.identity.idempotency_key.clone(),
        // The fixed notification scope: a contract constant, never a value
        // this leg chooses.
        scope_id: ScopeId::new(NOTIFICATION_STATE_SCOPE)?,
        // Not task-relative: a notification record carries no task binding,
        // which is also what keeps this leg out of the task-scope and
        // `CaptureObservation` admission rules.
        task_id: None,
        transition_class: TransitionClass::NotificationState,
        // Exactly the class maximum, never a wider ceiling.
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: admission.admission_contract_set_digest.to_owned(),
        operation_manifest_digest: operation_manifest_set_digest(&authorizing_manifests)?,
        // Exactly one named command, built by the store's own closed request
        // builder from the leg's own parameters.
        semantic_commands: vec![notification_mutation_request(admission.parameters.clone())],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        // Recorded provenance, not inferred at consume time: this leg observed
        // no source assurance, so it records the empty chain explicitly rather
        // than synthesizing taint, origin or disclosure values.
        security: SecurityContext::default(),
        // Proof/approval handles are an erasure-only requirement; this
        // reversible class carries none.
        required_proof_and_approval_refs: Vec::new(),
        // No revision head is compared: the notification record is not derived
        // from a canonical revision head, and declaring one would bind a head
        // this transition does not compare-and-swap.
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![admission.ordering_head.clone()],
    };
    // `prepare` validates the envelope, derives the ordering scopes, computes
    // the canonical request hash over the envelope-equivalent view, binds
    // `mutation_plan_digest` and `admission_digest` from the carried content,
    // and revalidates the result. Every digest in the returned plan is
    // therefore already derived, never supplied.
    let transition = envelope.prepare().map_err(|error| {
        NotificationEmitError::Admission(CompositionError::Owner(error.to_string()))
    })?;
    // Current admissible support, from a second read of the generated table.
    // This compares the recorded contract revision, the recorded manifest-set
    // digest and the recorded class/effect ceiling BY CONTENT, and refuses an
    // extra or unactivated command, so a plan this build cannot execute
    // support for is refused here and never leaves the daemon.
    let current_support = generated_operation_manifests()?;
    transition
        .validate_against_catalogue(&current_support)
        .map_err(NotificationEmitError::Store)?;
    // The submission inputs are assembled ONCE and are the values the recorded
    // digest is checked against. The view is built through
    // `CanonicalRequestView::from_apply`, the Kernel/store construction path,
    // so this compares the recorded ORIGINAL against a recompute that does not
    // share this crate's producing derivation.
    let context = admission.identity.request.metadata.clone();
    let expected_revision_heads: Vec<RevisionHeadExpectation> = Vec::new();
    let expected_ordering_heads = vec![admission.ordering_head.clone()];
    let view = CanonicalRequestView::from_apply(
        &context,
        &transition,
        &expected_revision_heads,
        &expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)?;
    Ok(VerifiedNotificationPlan {
        transition,
        context,
        expected_revision_heads,
        expected_ordering_heads,
    })
}
