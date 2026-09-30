//! Persist-before-acknowledgement trigger intake derivation (issue #1694 W2).
//!
//! When the Governor evaluator is unavailable, an admitted maintenance trigger
//! must be staged through the ORS owner before any acknowledgement advances
//! the producer cursor (I14.22: "if the evaluator is unavailable, the relevant
//! trigger remains durable and is surfaced on the next startup"). This module
//! derives the deterministic intake statement the daemon caller (STITCH) maps
//! onto the provider-neutral wire record (`MaintenanceTriggerRecord`, step 1)
//! and the ORS staging owner. It evaluates nothing and persists nothing: the
//! Governor-owned evaluator (#1688) keeps trigger interpretation, the policy
//! owner (#1692) keeps mode/route/session checks, and the Kernel/ORS owners
//! keep intake, claims, receipts, and startup delivery.
//!
//! The derivation is pure and deterministic: the same validated input always
//! yields the same intake statement, so an exact identity/hash replay
//! converges on the same staging result while changed content under the same
//! identity conflicts downstream. The wire `operation_hash` is attested, never
//! minted here: the source owner hashes its exact producer operation bytes and
//! this derivation carries that digest verbatim after checking its shape, so
//! the staged, recorded, claimed, and receipted hash stay one value from
//! intake to acknowledgement. Only complete durable
//! payloads are representable: a retained canonical source reference the ORS
//! owner can resolve, or the complete opaque input bytes. An in-memory
//! pointer, an ephemeral file, or an inaccessible source reference cannot be
//! constructed here — empty bytes and blank references are rejected — and
//! resolvability of a retained reference is proven by the ORS owner's
//! read-back, not by this module. Semantic payload bytes stay opaque: they
//! are hashed for the derivation-local payload binding and never parsed.
//!
//! Every failure is a typed [`MaintenanceError`]; the producer keeps its
//! retry identity (trigger identity, operation hash, source cursor) on all of
//! them, and no acknowledgement may be emitted from an error.
//!
//! The persist entry is [`MaintenanceTriggerIntake::persist_before_ack`]:
//! it re-checks the derived statement, invokes the durability owner's staging
//! seam exactly once, and returns the bound [`TriggerIntakePersistReceipt`]
//! that alone may advance the producer cursor. The seam performs the
//! owner-side durable write the Governor must not perform itself — reusing a
//! retained canonical source event where one exists and storing its delivery
//! obligation, otherwise staging the complete opaque input through the ORS
//! owner — and binds the owner-issued envelope reference and payload digest
//! through [`MaintenanceTriggerIntake::bind_staging_proof`], so unbound owner
//! output can never become a receipt.

use eliot_contracts::sha256_hex;

use super::{MaintenanceError, MaintenanceTriggerInput};

/// Stable source event identity attested by the trigger's source owner.
///
/// The producer generation is separate from any State Fence: it identifies
/// the source generation that emitted the event, so a replacement generation
/// never replays under a stale identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakeSourceEvent {
    /// Producer module identity from the source event envelope.
    pub producer_id: String,
    /// Producer generation from the source event envelope; must be nonzero.
    pub producer_generation: u64,
    /// Source event stream identity.
    pub stream_id: String,
    /// Source event identity within `stream_id`.
    pub event_id: String,
}

/// Durable source position paired with the producer generation.
///
/// A monotonic cursor in the source stream, or the owner-accepted occurrence
/// identity when the source has no cursor. The producer cursor advances only
/// on a staging receipt; it never advances on an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerIntakePosition {
    /// Monotonic cursor in the identified source event stream; nonzero.
    Cursor {
        /// Cursor value.
        value: u64,
    },
    /// Owner-accepted occurrence identity; nonblank.
    AcceptedOccurrence {
        /// Occurrence identity.
        occurrence_id: String,
    },
}

/// Producer operation that yielded the trigger.
///
/// The operation label names the source owner's operation (for example the
/// Watchdog problem opening or the scheduler wake occurrence). The operation
/// hash is attested by the source owner — the lowercase SHA-256 of its exact
/// producer operation bytes — and is carried verbatim after a shape check, so
/// it equals the wire record, staging request, claim, and receipt hash for
/// this trigger. This derivation never recomputes it from other fields: a
/// second digest under the same name would fork the replay/conflict identity
/// the whole chain compares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakeOperation {
    /// Producer operation name; nonblank.
    pub operation_label: String,
    /// Lowercase SHA-256 of the exact producer operation bytes, attested by
    /// the source owner.
    pub operation_hash: String,
    /// Stable source event identity attested by the source owner.
    pub source_event: TriggerIntakeSourceEvent,
    /// Durable source position paired with the producer generation.
    pub source_position: TriggerIntakePosition,
}

/// Complete durable payload for one trigger intake.
///
/// Only durable forms exist. `RetainedCanonicalSource` names a retained
/// canonical source the ORS owner resolves by read-back; `CompleteOpaqueInput`
/// carries the full opaque bytes to stage. Anything less — an in-memory
/// pointer, an ephemeral file path, an inaccessible reference — is rejected
/// during derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerIntakePayload {
    /// Reference to a retained canonical source event; nonblank.
    ///
    /// Resolvability is proven by the ORS owner's read-back at staging time.
    RetainedCanonicalSource {
        /// Opaque durable source reference.
        source_reference: String,
    },
    /// Complete opaque input bytes; non-empty.
    ///
    /// The bytes stay encrypted/opaque under the existing
    /// `RecoveryPayloadEnvelope` rules; only their digest is bound here.
    CompleteOpaqueInput {
        /// Full opaque payload bytes.
        payload_bytes: Vec<u8>,
    },
}

/// Owner-issued protected-routing classification binding.
///
/// `Protected` safety/recovery routing is admitted only with the issuing
/// owner's classification for one registered route. Shape is checked here;
/// the exact binding to the derived trigger identity and operation hash, and
/// owner-signature verification, belong to the issuing owner, the step-1 wire
/// grant, and the Kernel intake path — never to this derivation. An
/// `Ordinary` intake must not carry a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriggerIntakeRouting {
    /// Ordinary maintenance delivery through its existing policy owner.
    Ordinary,
    /// Safety/recovery delivery through a registered owner route with a
    /// bound owner-issued classification.
    Protected {
        /// Owner principal that issued the classification.
        owner_id: String,
        /// Registered protected route this classification opens.
        route: String,
        /// Opaque owner key reference the verifier resolves.
        key_id: String,
        /// Lowercase SHA-256 digest of the owner's canonical grant bytes.
        grant_digest: String,
    },
}

/// Opaque privacy/visibility references carried through ORS staging.
///
/// The references are owner-issued identifiers only; the original privacy,
/// visibility, taint, and retention travel with the staged payload itself
/// (I5.2), never as interpreted content here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakeClasses {
    /// Opaque owner-issued privacy-class reference; nonblank.
    pub privacy_class_reference: String,
    /// Opaque owner-issued visibility-class reference; nonblank.
    pub visibility_reference: String,
}

/// Creation/applicability window for one trigger intake.
///
/// Expiry withdraws eligibility only; it never deletes an unresolved trigger
/// or its retained effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TriggerIntakeWindow {
    /// Creation time as Unix milliseconds.
    pub created_at_ms: i64,
    /// Latest time the trigger remains eligible for applicability.
    pub applicable_until_ms: i64,
}

/// One validated intake derivation request.
///
/// Bundles the evaluator input, the source-attested operation, the durable
/// payload, the carried classes, the routing classification, and the
/// applicability window so derivation stays one call with named fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakeRequest {
    /// Validated deterministic trigger input from the source owner.
    pub input: MaintenanceTriggerInput,
    /// Producer operation that yielded the trigger.
    pub operation: TriggerIntakeOperation,
    /// Complete durable payload for the intake.
    pub payload: TriggerIntakePayload,
    /// Opaque privacy/visibility references carried through staging.
    pub classes: TriggerIntakeClasses,
    /// Routing classification with its owner-issued binding.
    pub routing: TriggerIntakeRouting,
    /// Creation/applicability window.
    pub window: TriggerIntakeWindow,
}

/// One derived persist-before-ack intake statement.
///
/// The daemon caller copies these fields verbatim onto the step-1 wire record
/// and the ORS staging request: stable source event/trigger identity,
/// generation and cursor-or-occurrence position, the source-attested operation
/// label and content hash, opaque family/scope references, evidence locators,
/// privacy/visibility references, creation/applicability expiry, and the
/// protected-routing classification. `operation_hash` is the attested
/// producer-bytes digest, identical to the wire value — it is never
/// recomputed here. `payload_binding` is derivation-local convergence
/// evidence, not the staged envelope hash: the semantic payload stays opaque
/// and only digests travel here besides the complete bytes themselves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTriggerIntake {
    /// Stable trigger identity from the source owner; never reinvented.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes, carried
    /// verbatim from the source-attested operation.
    pub operation_hash: String,
    /// Producer operation name.
    pub operation_label: String,
    /// Stable source event identity.
    pub source_event: TriggerIntakeSourceEvent,
    /// Durable source position.
    pub source_position: TriggerIntakePosition,
    /// Opaque maintenance-family reference.
    pub family_ref: String,
    /// Opaque affected-scope reference.
    pub scope_ref: String,
    /// Evidence locators needed by the owning evaluator; never content.
    pub evidence_locators: Vec<String>,
    /// Opaque owner-issued privacy-class reference.
    pub privacy_class_reference: String,
    /// Opaque owner-issued visibility-class reference.
    pub visibility_reference: String,
    /// Creation time as Unix milliseconds.
    pub created_at_ms: i64,
    /// Latest time the trigger remains eligible for applicability.
    pub applicable_until_ms: i64,
    /// Routing classification with its owner-issued binding.
    pub routing: TriggerIntakeRouting,
    /// Complete durable payload for the intake.
    pub payload: TriggerIntakePayload,
    /// Lowercase SHA-256 binding the exact durable payload content.
    ///
    /// For opaque bytes this digests the bytes; for a retained source it
    /// digests the source reference. Changed content yields a changed
    /// binding, so it conflicts under the same trigger identity instead of
    /// replaying.
    pub payload_binding: String,
}

/// Derives one persist-before-ack intake statement from validated input.
///
/// Reuses [`MaintenanceTriggerInput::validate`] for the trigger identity,
/// scope, evidence, and expiry dimensions, then binds the source-attested
/// operation (including its verbatim operation hash), the complete durable
/// payload, the carried classes, the routing classification, and the
/// applicability window into one deterministic statement. Exact replays carry
/// the same attested hash and payload binding and converge downstream, while
/// changed content arrives under a different attested hash or binding and
/// conflicts instead of replaying. Any failure returns a typed
/// [`MaintenanceError`] with no statement: the producer keeps its retry
/// identity and its cursor must not advance.
pub fn derive_trigger_intake(
    request: &TriggerIntakeRequest,
) -> Result<MaintenanceTriggerIntake, MaintenanceError> {
    request.input.validate()?;
    validate_operation(&request.operation)?;
    validate_payload(&request.payload)?;
    validate_classes(&request.classes)?;
    validate_window(&request.window, request.input.now_ms)?;
    validate_routing(&request.routing)?;

    let payload_binding = payload_binding(&request.payload);

    Ok(MaintenanceTriggerIntake {
        trigger_id: request.input.trigger_id.clone(),
        operation_hash: request.operation.operation_hash.clone(),
        operation_label: request.operation.operation_label.clone(),
        source_event: request.operation.source_event.clone(),
        source_position: request.operation.source_position.clone(),
        family_ref: request.input.family.to_string(),
        scope_ref: request.input.scope_ref.clone(),
        evidence_locators: request.input.evidence_refs.clone(),
        privacy_class_reference: request.classes.privacy_class_reference.clone(),
        visibility_reference: request.classes.visibility_reference.clone(),
        created_at_ms: request.window.created_at_ms,
        applicable_until_ms: request.window.applicable_until_ms,
        routing: request.routing.clone(),
        payload: request.payload.clone(),
        payload_binding,
    })
}

/// Durable persist-before-ack receipt for one retained trigger intake.
///
/// Issued only after the complete opaque input is committed through the ORS
/// owner. An exact identity/hash replay returns the same receipt; changed
/// content under the same identity never reaches one. The receipt proves
/// staging only: it is not a decision, an execution, or a delivery
/// acknowledgement. The producer cursor advances only on this receipt; every
/// error leaves the retry identity (trigger identity, operation hash, source
/// cursor or occurrence) with the producer and the cursor unmoved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakePersistReceipt {
    /// Stable trigger identity that was staged; echoed from the intake
    /// statement by construction, never re-derived or re-attested.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes; echoed from
    /// the intake statement by construction.
    pub operation_hash: String,
    /// Owner-issued reference to the staged envelope: the delivery
    /// obligation the Kernel intake path re-proves before acknowledging.
    pub envelope_reference: String,
    /// Owner-issued digest of the exact staged envelope payload bytes, bound
    /// to the presented durable payload by
    /// [`MaintenanceTriggerIntake::bind_staging_proof`].
    pub payload_hash: String,
}

impl MaintenanceTriggerIntake {
    /// Persists this derived intake through the durability owner before any
    /// acknowledgement.
    ///
    /// Re-checks the statement shape and content binding, then invokes the
    /// staging seam exactly once. The seam is the production intake path's
    /// durable write: it reuses a retained canonical source event where one
    /// exists and stores its delivery obligation, otherwise it stages the
    /// complete opaque input through the ORS owner, and it binds the
    /// owner-issued envelope reference and payload digest through
    /// [`MaintenanceTriggerIntake::bind_staging_proof`]. The returned
    /// [`TriggerIntakePersistReceipt`] is the only value that may advance the
    /// producer cursor. In-memory pointers, ephemeral files, and inaccessible
    /// source references cannot reach the seam: they are unrepresentable in
    /// the statement, whose shape check refuses them before any write.
    ///
    /// Replay and conflict behaviour is deterministic end to end. Derivation
    /// is pure, so an exact identity/hash replay addresses the same durable
    /// row and returns the same receipt, while changed content under the same
    /// identity conflicts instead of replaying. The Governor side of that
    /// contract is enforced here and in
    /// [`MaintenanceTriggerIntake::bind_staging_proof`]; row identity, the
    /// envelope-to-obligation binding, and ledger admission stay with the ORS
    /// owner and the Kernel delivery ledger, which re-prove staging before
    /// any intake acknowledgement is issued.
    ///
    /// The seam keeps every owner failure typed: capacity, key, integrity,
    /// and durable-write failures arrive as [`MaintenanceError::Store`] with
    /// the owner's detail preserved, and changed content under the same
    /// identity arrives as [`MaintenanceError::IdentityConflict`]. Any error
    /// means nothing was acknowledged: the producer keeps its retry identity
    /// and its cursor must not advance.
    ///
    /// Production caller (STITCH, issue #1694): the authenticated daemon
    /// intake-staging path in `bins/eliotd` (sibling to
    /// `commit_maintenance_trigger_decision`), which copies this statement
    /// verbatim onto the provider-neutral wire record and the ORS staging
    /// request and sends the intake operation over the authenticated daemon
    /// transport through the existing Kernel intake ports. No production
    /// caller exists yet and none is faked here; the `lib.rs` re-export of
    /// [`TriggerIntakePersistReceipt`] rides with that stitch.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed statement,
    /// [`MaintenanceError::IdentityConflict`] when the statement's content
    /// binding no longer matches its payload, or the seam's typed owner
    /// failure. Every error acknowledges nothing.
    pub fn persist_before_ack(
        &self,
        stage: &mut impl FnMut(
            &MaintenanceTriggerIntake,
        ) -> Result<TriggerIntakePersistReceipt, MaintenanceError>,
    ) -> Result<TriggerIntakePersistReceipt, MaintenanceError> {
        check_intake_shape(self)?;
        stage(self)
    }

    /// Binds owner-issued staging output into the persist receipt.
    ///
    /// The seam calls this with the envelope reference and payload digest
    /// the durable write actually committed; only this binding can produce a
    /// [`TriggerIntakePersistReceipt`], so unbound owner output — a predicted
    /// reference, a guessed digest, or bytes staged beside the obligation —
    /// can never become one. The trigger identity and operation hash echo the
    /// intake statement by construction. For a complete opaque input the
    /// owner digest must equal the digest of the presented bytes; for a
    /// retained canonical source it must be a staged envelope digest, never
    /// the derivation-local payload binding, which is replay evidence only
    /// and must not be copied into the staged record. A mismatch is changed
    /// content under this identity and conflicts instead of replaying.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a blank reference or a
    /// malformed digest, [`MaintenanceError::IdentityConflict`] when the
    /// owner digest does not bind the presented durable payload. Every error
    /// acknowledges nothing.
    pub fn bind_staging_proof(
        &self,
        envelope_reference: &str,
        payload_hash: &str,
    ) -> Result<TriggerIntakePersistReceipt, MaintenanceError> {
        require_text(envelope_reference, "persist.envelope_reference")?;
        require_digest(payload_hash, "persist.payload_hash")?;
        match &self.payload {
            TriggerIntakePayload::CompleteOpaqueInput { payload_bytes } => {
                if sha256_hex(payload_bytes) != payload_hash {
                    return Err(MaintenanceError::IdentityConflict);
                }
            }
            TriggerIntakePayload::RetainedCanonicalSource { .. } => {
                if payload_hash == self.payload_binding {
                    return Err(MaintenanceError::IdentityConflict);
                }
            }
        }
        Ok(TriggerIntakePersistReceipt {
            trigger_id: self.trigger_id.clone(),
            operation_hash: self.operation_hash.clone(),
            envelope_reference: envelope_reference.to_owned(),
            payload_hash: payload_hash.to_owned(),
        })
    }
}

/// Re-checks one derived intake statement before it may reach the seam.
///
/// Statements normally arrive from [`derive_trigger_intake`], which already
/// validated every dimension; the fields stay public, so a hand-built
/// statement must prove the same shape here before any durable write. The
/// content binding is recomputed from the payload and compared, so bytes
/// changed after derivation conflict instead of replaying. Expiry against the
/// live clock stays with the delivery ledger, which refuses stale
/// eligibility at admission with the time it owns.
fn check_intake_shape(intake: &MaintenanceTriggerIntake) -> Result<(), MaintenanceError> {
    require_text(&intake.trigger_id, "persist.trigger_id")?;
    require_digest(&intake.operation_hash, "persist.operation_hash")?;
    require_text(&intake.operation_label, "persist.operation")?;
    require_text(
        &intake.source_event.producer_id,
        "persist.source_event.producer_id",
    )?;
    if intake.source_event.producer_generation == 0 {
        return Err(MaintenanceError::InvalidField(
            "persist.source_event.producer_generation",
        ));
    }
    require_text(
        &intake.source_event.stream_id,
        "persist.source_event.stream_id",
    )?;
    require_text(
        &intake.source_event.event_id,
        "persist.source_event.event_id",
    )?;
    match &intake.source_position {
        TriggerIntakePosition::Cursor { value } => {
            if *value == 0 {
                return Err(MaintenanceError::InvalidField("persist.source_position.cursor"));
            }
        }
        TriggerIntakePosition::AcceptedOccurrence { occurrence_id } => {
            require_text(
                occurrence_id,
                "persist.source_position.occurrence_id",
            )?;
        }
    }
    require_text(&intake.family_ref, "persist.family.reference")?;
    require_text(&intake.scope_ref, "persist.scope.reference")?;
    if intake.evidence_locators.is_empty() {
        return Err(MaintenanceError::InvalidField("persist.evidence_locators"));
    }
    for locator in &intake.evidence_locators {
        require_text(locator, "persist.evidence_locators")?;
    }
    require_text(
        &intake.privacy_class_reference,
        "persist.privacy_class_reference",
    )?;
    require_text(
        &intake.visibility_reference,
        "persist.visibility_reference",
    )?;
    if intake.applicable_until_ms <= intake.created_at_ms {
        return Err(MaintenanceError::InvalidField("persist.applicable_until_ms"));
    }
    validate_routing(&intake.routing)?;
    validate_payload(&intake.payload)?;
    require_digest(&intake.payload_binding, "persist.payload_binding")?;
    if payload_binding(&intake.payload) != intake.payload_binding {
        return Err(MaintenanceError::IdentityConflict);
    }
    Ok(())
}

fn validate_operation(operation: &TriggerIntakeOperation) -> Result<(), MaintenanceError> {
    require_text(&operation.operation_label, "operation")?;
    // The hash is attested by the source owner that holds the exact producer
    // operation bytes; this derivation checks its shape and binds it into the
    // statement verbatim, so the whole chain compares one hash value.
    require_digest(&operation.operation_hash, "operation.operation_hash")?;
    require_text(
        &operation.source_event.producer_id,
        "source_event.producer_id",
    )?;
    if operation.source_event.producer_generation == 0 {
        return Err(MaintenanceError::InvalidField(
            "source_event.producer_generation",
        ));
    }
    require_text(&operation.source_event.stream_id, "source_event.stream_id")?;
    require_text(&operation.source_event.event_id, "source_event.event_id")?;
    match &operation.source_position {
        TriggerIntakePosition::Cursor { value } => {
            if *value == 0 {
                return Err(MaintenanceError::InvalidField("source_position.cursor"));
            }
        }
        TriggerIntakePosition::AcceptedOccurrence { occurrence_id } => {
            require_text(occurrence_id, "source_position.occurrence_id")?;
        }
    }
    Ok(())
}

fn validate_payload(payload: &TriggerIntakePayload) -> Result<(), MaintenanceError> {
    match payload {
        TriggerIntakePayload::RetainedCanonicalSource { source_reference } => {
            // The reference must name a durable retained source. Whether it
            // resolves is proven by the ORS owner's read-back at staging
            // time; a blank or control-carrying value is not a reference at
            // all, so it fails here before any cursor could advance.
            require_text(source_reference, "payload_source")?;
        }
        TriggerIntakePayload::CompleteOpaqueInput { payload_bytes } => {
            // Only the complete bytes count. Empty bytes carry no payload —
            // an in-memory pointer, an ephemeral file path, or any other
            // non-durable handle cannot satisfy this arm by construction.
            if payload_bytes.is_empty() {
                return Err(MaintenanceError::InvalidField("payload_source"));
            }
        }
    }
    Ok(())
}

fn validate_classes(classes: &TriggerIntakeClasses) -> Result<(), MaintenanceError> {
    require_text(&classes.privacy_class_reference, "privacy_class_reference")?;
    require_text(&classes.visibility_reference, "visibility_reference")?;
    Ok(())
}

fn validate_window(window: &TriggerIntakeWindow, now_ms: i64) -> Result<(), MaintenanceError> {
    if window.applicable_until_ms <= window.created_at_ms {
        return Err(MaintenanceError::InvalidField("applicable_until_ms"));
    }
    // Expiry withdraws eligibility; it never deletes the unresolved trigger.
    // An already-ineligible intake is refused now so its cursor cannot
    // advance past work that must record a terminal expiry disposition.
    if now_ms >= window.applicable_until_ms {
        return Err(MaintenanceError::Expired);
    }
    Ok(())
}

fn validate_routing(routing: &TriggerIntakeRouting) -> Result<(), MaintenanceError> {
    match routing {
        TriggerIntakeRouting::Ordinary => Ok(()),
        TriggerIntakeRouting::Protected {
            owner_id,
            route,
            key_id,
            grant_digest,
        } => {
            require_text(owner_id, "route_grant.owner_id")?;
            require_text(route, "route_grant.route")?;
            require_text(key_id, "route_grant.key_id")?;
            require_digest(grant_digest, "route_grant.grant_digest")?;
            Ok(())
        }
    }
}

/// Binds the exact durable payload content to one digest.
///
/// Opaque bytes digest directly; a retained reference digests as the
/// attested reference string whose resolution the ORS owner proves. Either
/// way a content change changes the binding, so it cannot replay as the
/// same intake. This binding is derivation-local replay evidence: it is not
/// the staged envelope hash the ORS owner issues at staging time, and the
/// daemon caller must not copy it into the wire `payload_hash`.
fn payload_binding(payload: &TriggerIntakePayload) -> String {
    match payload {
        TriggerIntakePayload::RetainedCanonicalSource { source_reference } => {
            sha256_hex(source_reference.as_bytes())
        }
        TriggerIntakePayload::CompleteOpaqueInput { payload_bytes } => sha256_hex(payload_bytes),
    }
}

fn require_text(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}

fn require_digest(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}
