//! Persist-before-acknowledgement maintenance-trigger staging (issue #1694 W2).
//!
//! When the Governor evaluator is unavailable, an admitted maintenance trigger
//! must be staged durably before any acknowledgement advances the producer
//! cursor (I14.22: "if the evaluator is unavailable, the relevant trigger
//! remains durable and is surfaced on the next startup"). This module is the
//! ORS owner's staging extension for that intake: it validates the closed
//! step-1 contract fields, proves the durable payload, and stages the
//! complete opaque input through the existing recovery-inbox owner.
//!
//! Two payload paths exist. Where a retained canonical source envelope is
//! already staged, the module reads it back through the existing owner and
//! stores only the delivery obligation: an immutable-locator envelope naming
//! that retained envelope, so no payload byte is duplicated. Otherwise the
//! caller presents the complete opaque envelope and the module stages it as
//!-is. An in-memory pointer, an ephemeral file, or an inaccessible source
//! reference is not a complete durable payload: the retained path fails when
//! the referenced envelope is missing or its hash mismatches, and the opaque
//! path fails when the envelope itself does not validate.
//!
//! Durability, replay, and conflict semantics come from the existing owner:
//! [`OperationalRecoveryStore::import_recovery_inbox`] commits the signed
//! inbox item atomically, an exact identity/hash replay returns the same
//! staging receipt, and changed content under the same identity fails with
//! [`OrsError::DuplicateConflict`]. This module adds no table, no second
//! trigger database, and no poller: inbox rows are opaque staged envelopes
//! indexed by item identity like every other inbox obligation, while trigger
//! delivery metadata (claims, decisions, acknowledgements) stays with the
//! Kernel delivery ledger, which indexes delivery metadata only.
//!
//! I5.2 governs the payload: ORS "indexes only operational metadata and
//! stores either an opaque serialized canonical envelope or an immutable
//! encrypted/local payload locator; it never parses that payload as project
//! meaning", and "original privacy, visibility, taint and retention travel
//! with the pending payload" inside the envelope. I5.2's rule applies
//! verbatim: "if ORS cannot durably stage the complete opaque operation,
//! `accepted_pending` is forbidden" — here, no staging receipt is issued and
//! the producer keeps its retry identity (trigger identity, operation hash,
//! source cursor) with the exact bounded failure. Capacity, key, integrity,
//! and durable-write failures stay typed [`OrsError`]s; signer trust stays
//! delegated to the bound evidence provider, whose refusal fails closed.
//!
//! Retention note: a locator envelope names its retained envelope but does
//! not pin it beyond existing ORS retention. Unresolved referenced envelopes
//! must survive under the terminal-disposition retention rules (W7); expiry of
//! a trigger's applicability withdraws eligibility only and never deletes an
//! unresolved obligation.

use eliot_platform::PlatformHandle;

use crate::model::{validate_digest, validate_text};
use crate::{
    OpaqueLabel, OperationIdentity, OperationalRecoveryStore, OrsError, RecoveryEnvelopeContext,
    RecoveryInboxItem, RecoveryPayloadEnvelope,
};

/// Stable inbox item identity namespace for staged trigger intakes.
///
/// Item identities share one inbox across all users, so trigger stagings are
/// namespaced under this prefix plus the stable trigger identity. The mapping
/// is deterministic: an exact replay addresses the same row.
const MAINTENANCE_TRIGGER_INBOX_PREFIX: &str = "maintenance-trigger";
/// Stable locator namespace naming a retained ORS envelope.
const RETAINED_ENVELOPE_LOCATOR_PREFIX: &str = "ors-envelope";

/// Durable source position paired with the producer generation.
///
/// A monotonic cursor in the source event stream, or the owner-accepted
/// occurrence identity when the source has no cursor. The producer cursor
/// advances only on a staging receipt; it never advances on an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerStagingPosition {
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

/// Complete durable payload for one staged intake.
///
/// `RetainedCanonicalSource` reuses an already-staged canonical source
/// envelope by identity; `CompleteOpaqueInput` stages the full opaque
/// envelope supplied by the caller. The envelope stays encrypted/opaque under
/// the existing envelope rules in both arms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerStagingPayload {
    /// Identity of the retained canonical source envelope to reuse.
    ///
    /// Existence and hash equality are proven by the owner's read-back at
    /// staging time; only the delivery obligation is stored.
    RetainedCanonicalSource {
        /// Operation identity of the already-staged source envelope.
        operation_id: OperationIdentity,
    },
    /// Complete opaque envelope to stage.
    CompleteOpaqueInput {
        /// Full staged envelope; validated before any write (boxed: the
        /// envelope is the large arm beside the small identity arm).
        envelope: Box<RecoveryPayloadEnvelope>,
    },
}

/// Routing classification for one staged intake.
///
/// `Protected` safety/recovery routing is representable only with the
/// issuing owner's classification for one registered route. Shape is checked
/// here; owner-signature verification belongs to the issuing owner and the
/// Kernel intake path. An `Ordinary` intake must not carry a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerStagingRoute {
    /// Ordinary maintenance delivery through its existing policy owner.
    Ordinary,
    /// Safety/recovery delivery through a registered owner route.
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

/// One persist-before-ack staging request.
///
/// Carries the closed step-1 contract fields with ORS-native types only: no
/// Governor semantic type crosses this boundary. Stable source event/trigger
/// identity, producer generation and cursor-or-occurrence position, the
/// operation label and content hash, opaque family/scope references, evidence
/// locators, creation/applicability expiry, and the protected-routing
/// classification travel here; privacy, visibility, taint, and retention
/// travel inside the staged envelope itself. The signer identity and
/// signature authenticate the intake producer through the existing signer
/// seam; the signature scheme is the caller's, verification is the bound
/// evidence provider's, and this module invents neither.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTriggerStagingRequest {
    /// Stable trigger identity from the source owner; never reinvented.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Producer module identity from the source event envelope.
    pub producer_id: String,
    /// Producer generation from the source event envelope; nonzero and
    /// separate from any State Fence.
    pub producer_generation: u64,
    /// Source event stream identity.
    pub stream_id: String,
    /// Source event identity within `stream_id`.
    pub event_id: String,
    /// Durable source position paired with the producer generation.
    pub position: MaintenanceTriggerStagingPosition,
    /// Producer operation name; nonblank.
    pub operation_label: String,
    /// Opaque maintenance-family reference.
    pub family_ref: String,
    /// Opaque affected-scope reference.
    pub scope_ref: String,
    /// Evidence locators needed by the owning evaluator; never content.
    pub evidence_locators: Vec<String>,
    /// Opaque reference to the staged envelope.
    ///
    /// Must equal the staged envelope's operation identity: the delivery
    /// obligation may not point beside the bytes it claims.
    pub envelope_reference: String,
    /// Lowercase SHA-256 of the exact staged envelope payload bytes.
    ///
    /// Must equal the staged envelope's payload digest.
    pub payload_hash: String,
    /// Creation time as Unix milliseconds.
    pub created_at_ms: i64,
    /// Latest time the trigger remains eligible for applicability.
    ///
    /// Checked as a well-formed window only; eligibility enforcement and
    /// terminal expiry belong to the delivery ledger, and expiry never
    /// deletes an unresolved obligation.
    pub applicable_until_ms: i64,
    /// Routing classification with its owner-issued binding.
    pub routing: MaintenanceTriggerStagingRoute,
    /// Complete durable payload for the intake.
    pub payload: MaintenanceTriggerStagingPayload,
    /// Intake producer authenticated through the existing signer seam.
    pub signer_id: OpaqueLabel,
    /// Producer signature over the staged item; verified by the bound
    /// evidence provider.
    pub signature: Vec<u8>,
    /// Intake arrival time as Unix milliseconds.
    pub arrived_at_ms: i64,
}

/// Durable staging receipt for one retained trigger intake.
///
/// Issued only after the complete opaque input is committed through the ORS
/// owner. An exact identity/hash replay returns the same receipt (the owner
/// issues it from the same durable row); changed content under the same
/// identity never reaches a receipt. The receipt proves staging only: it is
/// not a decision, an execution, or a delivery acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTriggerStagingReceipt {
    /// Stable trigger identity that was staged.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Opaque reference to the staged envelope.
    pub envelope_reference: String,
    /// Lowercase SHA-256 of the exact staged envelope payload bytes.
    pub payload_hash: String,
    /// Durable inbox operation order that holds the staged item.
    pub inbox_operation_order: u64,
    /// Digest of the exact staged inbox bytes.
    pub inbox_state_digest: String,
}

/// Stages one complete opaque trigger intake before any acknowledgement.
///
/// Validates the closed request shape, proves the durable payload (retained
/// envelope read-back with hash equality, or full envelope validation), binds
/// the delivery-obligation reference to the staged bytes, and commits the
/// signed item through [`OperationalRecoveryStore::import_recovery_inbox`].
/// Any failure — capacity, key/signer, integrity, or durable write — returns
/// the exact bounded [`OrsError`] with no receipt: the producer keeps its
/// retry identity and its cursor must not advance.
pub fn stage_maintenance_trigger_intake(
    store: &impl OperationalRecoveryStore,
    request: &MaintenanceTriggerStagingRequest,
) -> Result<MaintenanceTriggerStagingReceipt, OrsError> {
    validate_request(request)?;
    let envelope = resolve_payload(store, request)?;
    bind_obligation_reference(request, &envelope)?;
    let item = RecoveryInboxItem::bind(
        inbox_item_id(&request.trigger_id)?,
        request.signer_id.clone(),
        envelope,
        request.signature.clone(),
        request.arrived_at_ms,
    )?;
    let receipt = store.import_recovery_inbox(item)?;
    let staged = receipt.receipt();
    Ok(MaintenanceTriggerStagingReceipt {
        trigger_id: request.trigger_id.clone(),
        operation_hash: request.operation_hash.clone(),
        envelope_reference: request.envelope_reference.clone(),
        payload_hash: request.payload_hash.clone(),
        inbox_operation_order: staged.operation_order(),
        inbox_state_digest: staged.state_sha256().to_owned(),
    })
}

fn validate_request(request: &MaintenanceTriggerStagingRequest) -> Result<(), OrsError> {
    validate_text(&request.trigger_id, "maintenance_trigger.trigger_id")?;
    validate_digest(
        &request.operation_hash,
        "maintenance_trigger.operation_hash",
    )?;
    validate_text(
        &request.producer_id,
        "maintenance_trigger.source_event.producer_id",
    )?;
    if request.producer_generation == 0 {
        return Err(OrsError::InvalidField {
            field: "maintenance_trigger.source_event.producer_generation",
            reason: "must be nonzero",
        });
    }
    validate_text(
        &request.stream_id,
        "maintenance_trigger.source_event.stream_id",
    )?;
    validate_text(
        &request.event_id,
        "maintenance_trigger.source_event.event_id",
    )?;
    match &request.position {
        MaintenanceTriggerStagingPosition::Cursor { value } => {
            if *value == 0 {
                return Err(OrsError::InvalidField {
                    field: "maintenance_trigger.source_position.cursor",
                    reason: "must be nonzero",
                });
            }
        }
        MaintenanceTriggerStagingPosition::AcceptedOccurrence { occurrence_id } => {
            validate_text(
                occurrence_id,
                "maintenance_trigger.source_position.occurrence_id",
            )?;
        }
    }
    validate_text(&request.operation_label, "maintenance_trigger.operation")?;
    validate_text(&request.family_ref, "maintenance_trigger.family.reference")?;
    validate_text(&request.scope_ref, "maintenance_trigger.scope.reference")?;
    if request.evidence_locators.is_empty() {
        return Err(OrsError::InvalidField {
            field: "maintenance_trigger.evidence_locators",
            reason: "must identify at least one evidence locator",
        });
    }
    for locator in &request.evidence_locators {
        validate_text(locator, "maintenance_trigger.evidence_locators")?;
    }
    validate_text(
        &request.envelope_reference,
        "maintenance_trigger.payload.envelope_reference",
    )?;
    validate_digest(
        &request.payload_hash,
        "maintenance_trigger.payload.payload_hash",
    )?;
    if request.applicable_until_ms <= request.created_at_ms {
        return Err(OrsError::InvalidExpiry);
    }
    validate_routing(&request.routing)?;
    Ok(())
}

fn validate_routing(route: &MaintenanceTriggerStagingRoute) -> Result<(), OrsError> {
    match route {
        MaintenanceTriggerStagingRoute::Ordinary => Ok(()),
        MaintenanceTriggerStagingRoute::Protected {
            owner_id,
            route,
            key_id,
            grant_digest,
        } => {
            validate_text(owner_id, "maintenance_trigger.route_grant.owner_id")?;
            validate_text(route, "maintenance_trigger.route_grant.route")?;
            validate_text(key_id, "maintenance_trigger.route_grant.key_id")?;
            validate_digest(grant_digest, "maintenance_trigger.route_grant.grant_digest")?;
            Ok(())
        }
    }
}

/// Proves the durable payload and returns the envelope to stage.
///
/// The retained path reads the referenced envelope back through the existing
/// owner: a missing envelope means the source is inaccessible, and a digest
/// mismatch means the bytes are not the attested content, so both fail
/// without staging. The stored envelope is an immutable locator naming the
/// retained envelope, built over its exact access class, epoch, fence, and
/// retention horizon — the delivery obligation without duplicated bytes. The
/// opaque path validates the complete caller-supplied envelope as-is.
fn resolve_payload(
    store: &impl OperationalRecoveryStore,
    request: &MaintenanceTriggerStagingRequest,
) -> Result<RecoveryPayloadEnvelope, OrsError> {
    match &request.payload {
        MaintenanceTriggerStagingPayload::RetainedCanonicalSource { operation_id } => {
            let retained = store
                .get_envelope(operation_id)?
                .ok_or(OrsError::IntegrityProblem {
                    record_type: "maintenance_trigger_source",
                    reason: "retained canonical source envelope is not staged".to_owned(),
                })?;
            retained.validate()?;
            if retained.payload_sha256 != request.payload_hash {
                return Err(OrsError::PayloadIntegrityMismatch);
            }
            let locator = PlatformHandle::new(format!(
                "{RETAINED_ENVELOPE_LOCATOR_PREFIX}:{}",
                operation_id.as_str()
            ))
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "maintenance_trigger_locator",
                reason: error.to_string(),
            })?;
            RecoveryPayloadEnvelope::immutable_locator(
                RecoveryEnvelopeContext {
                    operation_or_checkpoint_id: retained.operation_or_checkpoint_id.clone(),
                    privacy_and_visibility_class: retained.privacy_and_visibility_class.clone(),
                    authority_epoch: retained.authority_epoch.clone(),
                    state_fence: retained.state_fence.clone(),
                    created_at_ms: retained.created_at_ms,
                    known_at_ms: retained.known_at_ms,
                    expires_at_ms: retained.expires_at_ms,
                },
                locator,
                retained.payload_sha256.clone(),
                retained.payload_length,
            )
        }
        MaintenanceTriggerStagingPayload::CompleteOpaqueInput { envelope } => {
            envelope.validate()?;
            Ok(envelope.as_ref().clone())
        }
    }
}

/// Binds the delivery-obligation reference to the staged bytes.
///
/// The recorded envelope reference and payload hash must equal the staged
/// envelope's own identity and digest. A staging that pointed beside its
/// bytes would acknowledge the wrong obligation, so it fails here before any
/// write.
fn bind_obligation_reference(
    request: &MaintenanceTriggerStagingRequest,
    envelope: &RecoveryPayloadEnvelope,
) -> Result<(), OrsError> {
    if envelope.operation_or_checkpoint_id.as_str() != request.envelope_reference
        || envelope.payload_sha256 != request.payload_hash
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "maintenance_trigger_staging",
            reason: "delivery obligation reference does not match the staged envelope".to_owned(),
        });
    }
    Ok(())
}

/// Proves one staged trigger intake is durably retained before intake ack.
///
/// Reads the trigger's staged inbox obligation back through the existing
/// owner by its deterministic item identity and binds the staged envelope's
/// identity and payload digest to the presented reference and hash. The
/// read-back addresses the inbox row itself, so both payload paths prove:
/// a retained-source staging proves through its stored locator envelope,
/// and a complete-opaque-input staging proves through its staged envelope
/// bytes, which live inside the inbox row and never in the envelope table.
/// A missing row means the obligation names nothing durable — an
/// inaccessible source reference is not a complete durable payload — and
/// an identity or digest mismatch means the staged bytes are not the
/// claimed content, so changed content conflicts instead of replaying. Any
/// failure is a typed [`OrsError`] with no receipt: the producer keeps its
/// retry identity (trigger identity, operation hash, source cursor) and its
/// cursor must not advance. This proves staging only; ledger admission
/// stays with the Kernel delivery ledger, which indexes delivery metadata
/// alone.
pub fn prove_maintenance_trigger_staging(
    store: &impl OperationalRecoveryStore,
    trigger_id: &str,
    envelope_reference: &str,
    payload_hash: &str,
) -> Result<(), OrsError> {
    let staged = store
        .load_recovery_inbox_envelope(&inbox_item_id(trigger_id)?)?
        .ok_or(OrsError::IntegrityProblem {
            record_type: "maintenance_trigger_staging",
            reason: "trigger delivery obligation names no staged inbox item".to_owned(),
        })?;
    staged.validate()?;
    if staged.operation_or_checkpoint_id.as_str() != envelope_reference
        || staged.payload_sha256.as_str() != payload_hash
    {
        return Err(OrsError::PayloadIntegrityMismatch);
    }
    Ok(())
}

/// Derives the deterministic inbox item identity for one trigger.
///
/// The same trigger identity always addresses the same inbox row, so an
/// exact replay converges on the owner's existing receipt instead of
/// staging a duplicate.
fn inbox_item_id(trigger_id: &str) -> Result<OperationIdentity, OrsError> {
    OpaqueLabel::new(format!("{MAINTENANCE_TRIGGER_INBOX_PREFIX}:{trigger_id}")).map_err(|error| {
        OrsError::IntegrityProblem {
            record_type: "maintenance_trigger_staging",
            reason: error.to_string(),
        }
    })
}
