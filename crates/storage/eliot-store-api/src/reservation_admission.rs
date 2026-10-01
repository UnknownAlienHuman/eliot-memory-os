//! Canonical `ADMITTED` transition for one staged admission reservation
//! (issue #1678 W3/REQ4, I10.15 step 3).
//!
//! This module owns the single deterministic builder that turns the staged
//! reservation facts into the admitted [`PreparedTransition`] carrying the
//! Governor `ApplySwarmOwnerRevisions` record with
//! disposition `ADMITTED`. There is exactly one path and no second admission
//! scheme: the caller supplies the staged facts, and every digest on the
//! returned plan is derived here, never supplied.
//!
//! # What the record states, exactly
//!
//! The admission record is the work-item half of I10.15 step 3 ("Governor
//! commits the canonical `SwarmPlanAdmission`/work-item `ADMITTED`
//! transition, admitted attempt identity and launch outbox, referencing the
//! reservation receipt"):
//!
//! - `admission_id` is the canonical operation identity itself. The admission
//!   stream is therefore keyed by the same identity the saga reconciles, so a
//!   retry after a lost response re-addresses this exact stream rather than
//!   minting a second admission.
//! - `definition_id` is the admitted work item. A work-item admission names no
//!   `SwarmPlanDefinition`: the admitted definition is the staged claim set,
//!   and `definition_digest` binds exactly that — the reservation, work-item
//!   and proposed-attempt identities, the five staged claim references with
//!   their digests, and the expiry boundary, hashed over canonical JSON in the
//!   documented [`RESERVATION_DEFINITION_DIGEST_DOMAIN`]. Anyone holding the
//!   staged row recomputes the same digest; nothing here is a Governor policy
//!   value the caller does not hold.
//! - `receipt` is the canonical JSON of the staged ORS receipt, carried
//!   verbatim. That is the reservation-receipt reference I10.15 step 3 names.
//! - `admitted_ceilings` carries the staged claims as opaque handles, admitted
//!   as-is: the route class is the staged lane claim, the budget handle is the
//!   staged pessimistic quota-view claim, and the privacy-class handle is the
//!   staged environment claim confining the admitted work. The numeric bounds
//!   are the unit envelope (one item, no delegation, one fenced WIP unit).
//!   No Governor narrowing is claimed: a work-item admission has no definition
//!   ceilings to narrow from.
//! - `disposition` is `ADMITTED`, and `state_fence` is the live fence the
//!   submitter presents, which the store compares against the transition fence.
//!
//! # What the transition does and does not bind
//!
//! The plan is [`TransitionClass::TaskControl`] with exactly the class-maximum
//! effect ceiling, one named command, empty event/projection/relation intents,
//! the default (empty) security chain recorded explicitly, and no
//! proof/approval handles. It declares no revision CAS: the admission binds no
//! canonical revision head, and declaring one would bind a head this
//! transition does not compare-and-swap. It declares exactly one ordering CAS
//! — the admission stream's own scope at sequence one — because the stream is
//! fresh per reservation. The owner-stream compare-and-set itself
//! (`expected_predecessor: None`, revision one) is enforced inside the store
//! transaction by the swarm statements, and the store commits exactly one
//! [`OutboxIntentKind::Launch`] row beside the receipt for every committed
//! transition, which is the launch-outbox intent the reservation saga reads
//! back.
//!
//! [`OutboxIntentKind::Launch`]: crate::OutboxIntentKind::Launch

use serde_json::{Map, Value};

use super::{CanonicalRequestView, SwarmOwnerAuthorization, SwarmOwnerRevisionBatch};
use super::{
    EventProjectionRelationIntents, OperationId, OperationIdentity, OrderingHeadExpectation,
    PreparedTransition, RequestMeta, ScopeId, SecurityContext, StoreError, TransitionClass,
    canonical_request_hash, generated_operation_manifests, operation_manifest_set_digest,
    swarm_owner_revisions_request, validate_digest, validate_text, verify_canonical_request_hash,
};
use super::{SwarmOwnerRevision, SwarmSemanticOwnerKind, canonical_json_bytes, sha256_hex};

/// Domain separator for the admitted-definition digest: the staged claim set
/// a work-item admission binds in place of a `SwarmPlanDefinition` digest.
pub const RESERVATION_DEFINITION_DIGEST_DOMAIN: &str = "eliot.reservation-admission.definition.v1";

/// Disposition the builder records: the canonical `ADMITTED` decision.
pub const RESERVATION_ADMISSION_DISPOSITION_ADMITTED: &str = "ADMITTED";

/// Scope addressed by one reservation admission transition.
///
/// The transition addresses exactly this admission's saga scope: it is derived
/// from the canonical operation identity, so two reservations never share a
/// scope and no real `WorkScope` is claimed.
pub fn reservation_admission_scope(operation_id: &OperationId) -> Result<ScopeId, StoreError> {
    ScopeId::new(format!("admission-reservation:{operation_id}"))
}

/// One staged claim reference carried into the admitted definition.
#[derive(Clone, Debug)]
pub struct ReservationAdmissionClaim {
    /// Owner-scoped immutable claim identity, carried verbatim.
    pub reference: String,
    /// Digest of the exact owner-defined claim bytes, carried verbatim.
    pub digest: String,
}

impl ReservationAdmissionClaim {
    /// Validates the opaque identity and its content digest shape.
    fn validate(&self, field: &'static str) -> Result<(), StoreError> {
        validate_text(&self.reference, field)?;
        validate_digest(&self.digest, field)?;
        Ok(())
    }
}

/// Complete staged claim set one reservation admission binds.
#[derive(Clone, Debug)]
pub struct ReservationAdmissionClaims {
    /// Complete resource-claim set reference.
    pub resources: ReservationAdmissionClaim,
    /// Scheduler lane claim reference (also the admitted route class).
    pub lane: ReservationAdmissionClaim,
    /// Environment claim reference (also the admitted privacy-class handle).
    pub environment: ReservationAdmissionClaim,
    /// Complete effect-claim set reference.
    pub effects: ReservationAdmissionClaim,
    /// Pessimistic cost and quota view claim reference (also the budget handle).
    pub quota_view: ReservationAdmissionClaim,
}

impl ReservationAdmissionClaims {
    /// Validates every staged claim reference without interpreting owners.
    fn validate(&self) -> Result<(), StoreError> {
        self.resources
            .validate("reservation_admission.claims.resources")?;
        self.lane.validate("reservation_admission.claims.lane")?;
        self.environment
            .validate("reservation_admission.claims.environment")?;
        self.effects
            .validate("reservation_admission.claims.effects")?;
        self.quota_view
            .validate("reservation_admission.claims.quota_view")?;
        Ok(())
    }
}

/// Admitted inputs of one reservation admission leg.
///
/// Every member is already-staged state: the canonical operation identity, the
/// staged reservation/work/attempt bindings, the complete staged claim set,
/// the staged expiry and receipt, and the authenticated request context the
/// submitter will execute under. Nothing here is a default, a guess, or a
/// value read from the environment.
#[derive(Clone, Debug)]
pub struct ReservationAdmissionRequest {
    /// Canonical operation identity (the reservation's stage operation).
    /// Keys the admission stream, the transition identity and the receipt.
    pub operation_id: OperationId,
    /// Stable logical retry identity. The submitter passes the reservation
    /// identity, so a retry after a lost response resubmits the same key.
    pub idempotency_key: String,
    /// Authenticated request context the submitter executes under. Supplies
    /// the transition fence and the canonical-request-hash context half.
    pub request: RequestMeta,
    /// Stable reservation identity the admission covers.
    pub reservation_id: String,
    /// Admitted work item identity.
    pub work_item_id: String,
    /// Proposed attempt identity the reservation covers.
    pub proposed_attempt_id: String,
    /// Complete staged claim set the admission binds.
    pub claims: ReservationAdmissionClaims,
    /// Inactive reservation expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Canonical JSON of the staged ORS receipt, carried verbatim as the
    /// reservation-receipt reference.
    pub reservation_receipt_json: String,
    /// Authenticated presenting source. Must equal the request source: the
    /// store binds the Governor evidence to the authenticated request at
    /// commit, so a foreign presenter is refused here rather than at execute.
    pub presenter: String,
    /// Owner epoch the presenter claims. Must be non-zero.
    pub presenter_epoch: u64,
}

impl ReservationAdmissionRequest {
    /// Validates the admitted-input shape without issuing any authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(
            &self.idempotency_key,
            "reservation_admission.idempotency_key",
        )?;
        self.request.validate().map_err(StoreError::Foundation)?;
        validate_text(&self.reservation_id, "reservation_admission.reservation_id")?;
        validate_text(&self.work_item_id, "reservation_admission.work_item_id")?;
        validate_text(
            &self.proposed_attempt_id,
            "reservation_admission.proposed_attempt_id",
        )?;
        self.claims.validate()?;
        if self.expires_at_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "reservation_admission.expires_at_ms",
                reason: "expiry boundary must be positive",
            });
        }
        validate_text(
            &self.reservation_receipt_json,
            "reservation_admission.reservation_receipt_json",
        )?;
        validate_text(&self.presenter, "reservation_admission.presenter")?;
        if self.presenter != self.request.source_id.as_str() {
            return Err(StoreError::InvalidField {
                field: "reservation_admission.presenter",
                reason: "does not match the authenticated request source",
            });
        }
        if self.presenter_epoch == 0 {
            return Err(StoreError::InvalidField {
                field: "reservation_admission.presenter_epoch",
                reason: "owner epoch is never zero",
            });
        }
        Ok(())
    }
}

/// The admitted plan together with its exact submission inputs.
///
/// The heads are part of the submission, not advisory: the recorded canonical
/// request hash is computed over them, and the store compares them by exact
/// equality before executing.
pub struct ReservationAdmissionSubmission {
    /// The immutable admitted plan.
    pub transition: PreparedTransition,
    /// Revision CAS expectations. Empty: the admission binds no canonical
    /// revision head, and declaring one would bind a head this transition
    /// does not compare-and-swap.
    pub expected_revision_heads: Vec<crate::RevisionHeadExpectation>,
    /// Ordering CAS expectations: exactly the admission stream's own scope at
    /// sequence one, which is fresh per reservation.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

/// Computes the admitted-definition digest: the staged claim set a work-item
/// admission binds in place of a `SwarmPlanDefinition` digest.
///
/// The preimage is canonical JSON of the reservation/work/attempt bindings,
/// the five staged `reference:digest` claim pairs and the expiry boundary
/// under [`RESERVATION_DEFINITION_DIGEST_DOMAIN`]. Anyone holding the staged
/// row recomputes the same digest from the same staged values.
fn reservation_definition_digest(
    request: &ReservationAdmissionRequest,
) -> Result<String, StoreError> {
    let mut preimage = Map::new();
    preimage.insert(
        "domain".to_owned(),
        Value::String(RESERVATION_DEFINITION_DIGEST_DOMAIN.to_owned()),
    );
    preimage.insert(
        "reservation_id".to_owned(),
        Value::String(request.reservation_id.clone()),
    );
    preimage.insert(
        "work_item_id".to_owned(),
        Value::String(request.work_item_id.clone()),
    );
    preimage.insert(
        "proposed_attempt_id".to_owned(),
        Value::String(request.proposed_attempt_id.clone()),
    );
    for (name, claim) in [
        ("resources", &request.claims.resources),
        ("lane", &request.claims.lane),
        ("environment", &request.claims.environment),
        ("effects", &request.claims.effects),
        ("quota_view", &request.claims.quota_view),
    ] {
        preimage.insert(
            name.to_owned(),
            Value::String(format!("{}:{}", claim.reference, claim.digest)),
        );
    }
    preimage.insert(
        "expires_at_ms".to_owned(),
        Value::Number(serde_json::Number::from(request.expires_at_ms)),
    );
    let bytes = canonical_json_bytes(&preimage)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Builds the Governor admission record for one staged reservation.
///
/// The record carries the seven closed admission fields and nothing else; its
/// bytes are canonical JSON and its digest binds those bytes. Validation runs
/// through the owner's own closed request builder.
fn reservation_admission_record(
    request: &ReservationAdmissionRequest,
    definition_digest: &str,
) -> Result<SwarmOwnerRevisionBatch, StoreError> {
    let mut ceilings = Map::new();
    ceilings.insert(
        "privacy_class".to_owned(),
        Value::String(request.claims.environment.reference.clone()),
    );
    ceilings.insert(
        "budget_ref".to_owned(),
        Value::String(request.claims.quota_view.reference.clone()),
    );
    ceilings.insert(
        "route_classes".to_owned(),
        Value::Array(vec![Value::String(request.claims.lane.reference.clone())]),
    );
    for name in ["max_depth", "max_fanout", "max_wip"] {
        ceilings.insert(name.to_owned(), Value::Number(serde_json::Number::from(1)));
    }
    let mut record = Map::new();
    record.insert(
        "admission_id".to_owned(),
        Value::String(request.operation_id.to_string()),
    );
    record.insert(
        "definition_id".to_owned(),
        Value::String(request.work_item_id.clone()),
    );
    record.insert(
        "definition_digest".to_owned(),
        Value::String(definition_digest.to_owned()),
    );
    record.insert(
        "disposition".to_owned(),
        Value::String(RESERVATION_ADMISSION_DISPOSITION_ADMITTED.to_owned()),
    );
    record.insert("admitted_ceilings".to_owned(), Value::Object(ceilings));
    record.insert(
        "receipt".to_owned(),
        Value::String(request.reservation_receipt_json.clone()),
    );
    record.insert(
        "state_fence".to_owned(),
        serde_json::to_value(&request.request.state_fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    let record_json = String::from_utf8(
        canonical_json_bytes(&record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let content_digest = sha256_hex(record_json.as_bytes());
    let batch = SwarmOwnerRevisionBatch {
        record: SwarmOwnerRevision {
            owner_kind: SwarmSemanticOwnerKind::Governor,
            authorization: SwarmOwnerAuthorization {
                owner_kind: SwarmSemanticOwnerKind::Governor,
                presenter: request.presenter.clone(),
                epoch: request.presenter_epoch,
            },
            owner_id: request.operation_id.to_string(),
            revision: 1,
            expected_predecessor: None,
            content_digest,
            record_json,
        },
    };
    batch.validate()?;
    Ok(batch)
}

/// Builds the deterministic admitted `ADMITTED` transition for one staged
/// reservation.
///
/// Same staged inputs always yield the same transition bytes: the admission
/// stream, scope and record identities derive from the canonical operation
/// identity, the record travels as canonical JSON, and every digest is
/// derived here, never supplied. The result still requires catalogue
/// admission and canonical-request-hash binding before staging; this builder
/// issues no authority and performs no store effect.
///
/// # Errors
///
/// Returns [`StoreError`] for a refused input shape, a refused catalogue
/// binding or a refused digest binding. No failure is folded into prose.
pub fn prepare_reservation_admission_transition(
    request: &ReservationAdmissionRequest,
) -> Result<ReservationAdmissionSubmission, StoreError> {
    request.validate()?;
    // The authorizing catalogue set is read once here and hashed into the
    // plan. It is read AGAIN below, from a separate generated table read, to
    // check the produced plan against current support: validating the plan
    // against the very slice its own digest was taken from would be comparing
    // a value with itself.
    let authorizing_manifests = generated_operation_manifests()?;
    let set_digest = operation_manifest_set_digest(&authorizing_manifests)?;
    let definition_digest = reservation_definition_digest(request)?;
    let batch = reservation_admission_record(request, &definition_digest)?;
    // The ordering scope is read off the validated record itself, never
    // re-spelled here, so the plan cannot declare a scope set the record
    // does not name.
    let ordering_scope = batch.record.ordering_scope()?;
    let named_operation = swarm_owner_revisions_request(batch)?;
    let scope_id = reservation_admission_scope(&request.operation_id)?;
    let expected_ordering_heads = vec![OrderingHeadExpectation {
        scope: ordering_scope.clone(),
        expected_sequence: 1,
        state_fence: request.request.state_fence.clone(),
    }];
    let expected_revision_heads = Vec::new();
    let mut transition = PreparedTransition {
        contract_version: crate::CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            // Bound below over the exact submission inputs, never defaulted.
            canonical_request_hash: String::new(),
        },
        state_fence: request.request.state_fence.clone(),
        scope_id,
        // Not task-relative: the reservation binds a work item, not a task,
        // so no task binding is claimed.
        task_id: None,
        ordering_scopes: vec![ordering_scope],
        transition_class: TransitionClass::TaskControl,
        // Exactly the class maximum, never a wider ceiling.
        requested_effect_ceiling: TransitionClass::TaskControl.maximum_effect(),
        admission_contract_set_digest: set_digest.as_str().to_owned(),
        operation_manifest_digest: set_digest,
        // The decision/plan digests are derived below, never defaulted.
        // No semantic source is rendered: the admission binds no canonical
        // revision head.
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![named_operation],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        // Recorded provenance, not inferred at consume time: the leg observed
        // no source assurance, so it records the empty chain explicitly rather
        // than synthesizing values it has no evidence for.
        security: SecurityContext::default(),
        // Proof/approval handles are an erasure-only requirement; this
        // reversible class carries none.
        required_proof_and_approval_refs: Vec::new(),
    };
    super::bind_issue18_digests(&mut transition)?;
    transition.identity.canonical_request_hash = canonical_request_hash(&CanonicalRequestView {
        operation_id: transition.identity.operation_id.clone(),
        request: request.request.clone(),
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
        semantic_source_revisions: transition.semantic_source_revisions.clone(),
        ordering_scopes: transition.ordering_scopes.clone(),
        expected_revision_heads: expected_revision_heads.clone(),
        expected_ordering_heads: expected_ordering_heads.clone(),
    })?;
    transition.validate()?;
    // Current admissible support, from a second read of the generated table.
    // A plan this build cannot execute support for is refused here and never
    // leaves the caller.
    let current_support = generated_operation_manifests()?;
    transition.validate_against_catalogue(&current_support)?;
    verify_canonical_request_hash(
        &CanonicalRequestView::from_apply(
            &request.request,
            &transition,
            &expected_revision_heads,
            &expected_ordering_heads,
        ),
        &transition.identity.canonical_request_hash,
    )?;
    Ok(ReservationAdmissionSubmission {
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    })
}
