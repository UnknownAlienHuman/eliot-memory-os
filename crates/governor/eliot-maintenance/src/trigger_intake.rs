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
//! yields the same trigger identity and operation hash, so an exact
//! identity/hash replay converges on the same staging result while changed
//! content under the same identity conflicts downstream. Only complete durable
//! payloads are representable: a retained canonical source reference the ORS
//! owner can resolve, or the complete opaque input bytes. An in-memory
//! pointer, an ephemeral file, or an inaccessible source reference cannot be
//! constructed here — empty bytes and blank references are rejected — and
//! resolvability of a retained reference is proven by the ORS owner's
//! read-back, not by this module. Semantic payload bytes stay opaque: they
//! are hashed for identity binding and never parsed.
//!
//! Every failure is a typed [`MaintenanceError`]; the producer keeps its
//! retry identity (trigger identity, operation hash, source cursor) on all of
//! them, and no acknowledgement may be emitted from an error.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde_json::Value;

use super::{MaintenanceError, MaintenanceTriggerInput};

/// Stable domain label bound into the operation projection digest.
const TRIGGER_INTAKE_DIGEST_DOMAIN: &str = "eliot.maintenance.trigger-intake";
/// Current revision of the operation projection digest.
const TRIGGER_INTAKE_DIGEST_VERSION: u32 = 1;

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

/// Producer operation that yielded the trigger, without its content hash.
///
/// The operation label names the source owner's operation (for example the
/// Watchdog problem opening or the scheduler wake occurrence); the content
/// hash is derived, never caller-supplied, so replays converge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerIntakeOperation {
    /// Producer operation name; nonblank.
    pub operation_label: String,
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
/// The daemon caller maps these fields onto the step-1 wire record and the
/// ORS staging request: stable source event/trigger identity, generation and
/// cursor-or-occurrence position, operation label and content hash, opaque
/// family/scope references, evidence locators, privacy/visibility references,
/// creation/applicability expiry, and the protected-routing classification.
/// The semantic payload stays opaque; only digests travel here besides the
/// complete bytes themselves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTriggerIntake {
    /// Stable trigger identity from the source owner; never reinvented.
    pub trigger_id: String,
    /// Lowercase SHA-256 over the canonical operation projection.
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
/// operation, the complete durable payload, the carried classes, the routing
/// classification, and the applicability window into one deterministic
/// statement. The operation hash digests the canonical projection of every
/// bound field, so exact replays converge and changed content conflicts. Any
/// failure returns a typed [`MaintenanceError`] with no statement: the
/// producer keeps its retry identity and its cursor must not advance.
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
    let operation_hash = operation_digest(request, &payload_binding)
        .map_err(|_| MaintenanceError::InvalidField("operation"))?;

    Ok(MaintenanceTriggerIntake {
        trigger_id: request.input.trigger_id.clone(),
        operation_hash,
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

fn validate_operation(operation: &TriggerIntakeOperation) -> Result<(), MaintenanceError> {
    require_text(&operation.operation_label, "operation")?;
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
/// same intake.
fn payload_binding(payload: &TriggerIntakePayload) -> String {
    match payload {
        TriggerIntakePayload::RetainedCanonicalSource { source_reference } => {
            sha256_hex(source_reference.as_bytes())
        }
        TriggerIntakePayload::CompleteOpaqueInput { payload_bytes } => sha256_hex(payload_bytes),
    }
}

/// Digests the canonical projection of every bound intake field.
///
/// The projection carries the stable source event/trigger identity, the
/// generation and cursor-or-occurrence position, the operation label, the
/// opaque family/scope references, the evidence locators, the
/// privacy/visibility references, the creation/applicability window, the
/// routing classification, and the payload binding. Canonical JSON keeps
/// field order deterministic so exact replays hash identically.
fn operation_digest(
    request: &TriggerIntakeRequest,
    payload_binding: &str,
) -> Result<String, serde_json::Error> {
    let position = match &request.operation.source_position {
        TriggerIntakePosition::Cursor { value } => Value::from(format!("CURSOR:{value}")),
        TriggerIntakePosition::AcceptedOccurrence { occurrence_id } => {
            Value::from(format!("OCCURRENCE:{occurrence_id}"))
        }
    };
    let routing = match &request.routing {
        TriggerIntakeRouting::Ordinary => Value::from("ORDINARY"),
        TriggerIntakeRouting::Protected {
            owner_id,
            route,
            key_id,
            grant_digest,
        } => Value::from(format!(
            "PROTECTED:{owner_id}:{route}:{key_id}:{grant_digest}:{trigger_id}",
            trigger_id = request.input.trigger_id
        )),
    };
    let projection = serde_json::json!({
        "domain": TRIGGER_INTAKE_DIGEST_DOMAIN,
        "version": TRIGGER_INTAKE_DIGEST_VERSION,
        "trigger_id": request.input.trigger_id,
        "operation_label": request.operation.operation_label,
        "producer_id": request.operation.source_event.producer_id,
        "producer_generation": request.operation.source_event.producer_generation,
        "stream_id": request.operation.source_event.stream_id,
        "event_id": request.operation.source_event.event_id,
        "source_position": position,
        "family_ref": request.input.family.to_string(),
        "scope_ref": request.input.scope_ref,
        "evidence_locators": request.input.evidence_refs,
        "privacy_class_reference": request.classes.privacy_class_reference,
        "visibility_reference": request.classes.visibility_reference,
        "created_at_ms": request.window.created_at_ms,
        "applicable_until_ms": request.window.applicable_until_ms,
        "routing": routing,
        "payload_binding": payload_binding,
    });
    Ok(sha256_hex(&canonical_json_bytes(&projection)?))
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
