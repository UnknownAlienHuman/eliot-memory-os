//! Provider-neutral retained maintenance-trigger wire contract.
//!
//! This module describes the operational identity and opaque payload reference
//! for a maintenance trigger plus the closed delivery family that moves one
//! retained trigger from intake to acknowledgement: owner-issued route grant,
//! intake receipt, fenced claim, bounded pending page with explicit gaps,
//! decision receipt, delivery acknowledgement, consumer revocation, and
//! terminal disposition.
//!
//! The family carries only delivery bookkeeping. It does not persist records,
//! interpret payloads, evaluate policy, or authorize delivery. The existing
//! ORS owner remains responsible for staging a `RecoveryPayloadEnvelope`;
//! this contract carries only its opaque reference and integrity hash. ORS
//! must retain the envelope's privacy, visibility, fence, and expiry metadata
//! without indexing its semantic contents. The Governor-owned evaluator
//! (`#1688`) owns trigger interpretation, the policy owner (`#1692`) owns
//! current mode/route/session checks, and the Kernel owners intake, claims,
//! revocation, receipts, and startup delivery. Kernel indexes only the
//! operational delivery metadata carried here; it must not query the trigger
//! as semantic memory or evaluate its policy.
//!
//! Source-to-ack mapping:
//!
//! ```text
//! source event (stream/event identity + producer generation + cursor/occurrence)
//! → MaintenanceTriggerRecord (stable trigger identity + operation hash + opaque refs)
//! → MaintenanceTriggerIntakeReceipt (exact replay returns the same result)
//! → MaintenanceTriggerClaim (finite, generation/session bound)
//! → MaintenanceTriggerDecisionReceipt (content-bound canonical receipt, not an ID)
//! → MaintenanceTriggerAck (exact receipt content plus claim echo)
//! → MaintenanceTriggerDisposition::Acknowledged, or a terminal/gap record.
//! ```
//!
//! Protected safety/recovery routing is admitted only with an owner-issued
//! [`MaintenanceTriggerRouteGrant`] bound to the exact trigger identity and
//! operation hash. An `Ordinary` record must not carry a grant, and a
//! `Protected` record without a bound grant is rejected. The grant carries
//! the owner's classification; this module checks the binding shape, never
//! the owner's signature. Ordinary pending debt never keeps a runtime alive:
//! that scheduling decision belongs to the daemon/Kernel owners, not this wire.

use eliot_contracts::{
    ContractIdentity, ContractVersion, ResourceGeneration, StateFence, contract_identity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EventIdentityKey, ProtocolError};

/// Stable identity of the retained maintenance-trigger contract family.
pub const MAINTENANCE_TRIGGER_CONTRACT_NAME: &str = "eliot.foundation.maintenance-trigger";
/// Current semantic revision of the retained maintenance-trigger contract.
///
/// Minor revision 1 adds owner-issued protected routing and the closed
/// intake/claim/decision/ack delivery family around the unchanged v1 identity
/// core.
pub const MAINTENANCE_TRIGGER_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);
/// Stable wire identity for one retained maintenance trigger.
pub const MAINTENANCE_TRIGGER_WIRE_ID: &str = "eliot.protocol.retained-maintenance-trigger";
/// Current wire version for a retained maintenance trigger.
///
/// Version 2 adds the mandatory `route_grant` binding slot. Version 1 bytes
/// without it are rejected rather than upgraded silently.
pub const MAINTENANCE_TRIGGER_WIRE_VERSION: u16 = 2;
/// Stable wire identity for one owner-issued protected-route grant.
pub const MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_ID: &str =
    "eliot.protocol.maintenance-trigger-route-grant";
/// Current wire version for a protected-route grant.
pub const MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one trigger intake receipt.
pub const MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID: &str =
    "eliot.protocol.maintenance-trigger-intake-receipt";
/// Current wire version for a trigger intake receipt.
pub const MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one fenced trigger claim.
pub const MAINTENANCE_TRIGGER_CLAIM_WIRE_ID: &str = "eliot.protocol.maintenance-trigger-claim";
/// Current wire version for a fenced trigger claim.
pub const MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one bounded pending-trigger page.
pub const MAINTENANCE_TRIGGER_PAGE_WIRE_ID: &str = "eliot.protocol.maintenance-trigger-page";
/// Current wire version for a bounded pending-trigger page.
pub const MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one trigger decision receipt.
pub const MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID: &str =
    "eliot.protocol.maintenance-trigger-decision-receipt";
/// Current wire version for a trigger decision receipt.
pub const MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one trigger delivery acknowledgement.
pub const MAINTENANCE_TRIGGER_ACK_WIRE_ID: &str = "eliot.protocol.maintenance-trigger-ack";
/// Current wire version for a trigger delivery acknowledgement.
pub const MAINTENANCE_TRIGGER_ACK_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one daemon-consumer revocation.
pub const MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID: &str =
    "eliot.protocol.maintenance-trigger-revocation";
/// Current wire version for a daemon-consumer revocation.
pub const MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one terminal trigger disposition.
pub const MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID: &str =
    "eliot.protocol.maintenance-trigger-terminal-disposition";
/// Current wire version for a terminal trigger disposition.
pub const MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION: u16 = 1;
/// Maximum members carried by one pending-trigger page.
pub const MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS: usize = 64;
/// Maximum explicit gap records carried by one pending-trigger page.
pub const MAX_MAINTENANCE_TRIGGER_PAGE_GAPS: usize = 16;

/// Returns the deterministic identity of the retained maintenance-trigger contract.
pub fn maintenance_trigger_contract_identity() -> Result<ContractIdentity, ProtocolError> {
    let shape = schemars::schema_for!(MaintenanceTriggerRecord);
    Ok(contract_identity(
        MAINTENANCE_TRIGGER_CONTRACT_NAME,
        MAINTENANCE_TRIGGER_CONTRACT_VERSION,
        &shape,
    )?)
}

/// Stable provider-neutral identity of the source event that produced a trigger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerSourceEvent {
    /// Producer module identity from the source event envelope.
    pub producer_id: String,
    /// Producer generation from the source event envelope, separate from its State Fence.
    pub producer_generation: ResourceGeneration,
    /// Source event stream identity.
    pub stream_id: String,
    /// Source event identity within `stream_id`.
    pub event_id: String,
}

impl MaintenanceTriggerSourceEvent {
    /// Projects this wire identity to the existing protocol replay key.
    #[must_use]
    pub fn identity_key(&self) -> EventIdentityKey {
        EventIdentityKey::new(&self.stream_id, &self.event_id)
    }
}

/// Durable source position paired with the producer generation in the source event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MaintenanceTriggerPosition {
    /// Monotonic cursor in the identified source event stream.
    Cursor { value: u64 },
    /// Owner-accepted occurrence identity when the source has no cursor.
    AcceptedOccurrence { occurrence_id: String },
}

/// Opaque reference to an owner-defined maintenance family or affected scope.
///
/// The reference is an identifier only; the protocol and Kernel do not resolve
/// it to semantic memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerContentRef {
    /// Stable owner-issued identifier for the family or scope.
    pub reference: String,
}

/// Opaque reference and digest for an existing encrypted ORS payload envelope.
///
/// `envelope_reference` must resolve to an existing `RecoveryPayloadEnvelope`
/// managed by ORS. This protocol does not carry ciphertext or plaintext and
/// does not define another encryption or storage format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerPayloadRef {
    /// Opaque reference to the ORS-owned recovery payload envelope.
    pub envelope_reference: String,
    /// Lowercase SHA-256 of the exact envelope payload bytes.
    pub payload_hash: String,
}

/// Registered protected route that may carry a safety/recovery trigger.
///
/// Only routes owned by these principals are representable. Ordinary
/// maintenance never uses this enum; it travels as
/// [`MaintenanceTriggerRoutingClass::Ordinary`] with no grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerRoute {
    /// Host-owned safety/recovery route.
    Host,
    /// Kernel-owned safety/recovery route.
    Kernel,
    /// Watchdog-owned safety/recovery route.
    Watchdog,
    /// Doctor-owned safety/recovery route.
    Doctor,
}

/// Owner-issued authenticated classification for protected trigger routing.
///
/// The grant binds one owner to one trigger identity and operation hash for
/// one registered route and validity window. This module checks shape,
/// digest format, and content binding; owner-signature verification belongs
/// to the issuing owner and the Kernel intake path, never to this wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerRouteGrant {
    /// Must equal [`MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Owner principal that issued this classification.
    pub owner_id: String,
    /// Registered protected route this grant opens for the bound trigger.
    pub route: MaintenanceTriggerRoute,
    /// Stable trigger identity this grant classifies.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Opaque owner key reference the verifier resolves for issuance proof.
    pub key_id: String,
    /// Lowercase SHA-256 digest of the owner's canonical grant bytes.
    pub grant_digest: String,
    /// Creation time as Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Latest time at which this classification may authorize routing.
    pub expires_at_unix_ms: u64,
}

impl MaintenanceTriggerRouteGrant {
    /// Validates the closed grant shape, bindings, and validity window.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_route_grant.wire_id",
                "must be the route-grant identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_ROUTE_GRANT_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_route_grant.wire_version",
                "must be the current route-grant version",
            ));
        }
        required_text(&self.owner_id, "maintenance_trigger_route_grant.owner_id")?;
        required_text(
            &self.trigger_id,
            "maintenance_trigger_route_grant.trigger_id",
        )?;
        valid_hash(
            &self.operation_hash,
            "maintenance_trigger_route_grant.operation_hash",
        )?;
        required_text(&self.key_id, "maintenance_trigger_route_grant.key_id")?;
        valid_hash(
            &self.grant_digest,
            "maintenance_trigger_route_grant.grant_digest",
        )?;
        if self.expires_at_unix_ms <= self.created_at_unix_ms {
            return Err(invalid(
                "maintenance_trigger_route_grant.expires_at_unix_ms",
                "must be later than the creation time",
            ));
        }
        Ok(())
    }

    /// Validates the grant and rejects it for routing after its expiry.
    ///
    /// Expiry withdraws the classification only; it never deletes the bound
    /// trigger or its retained effects.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(invalid(
                "expires_at_unix_ms",
                "route grant is no longer valid at the supplied time",
            ));
        }
        Ok(())
    }

    /// Returns whether this grant classifies `trigger_id`/`operation_hash`.
    ///
    /// Both values must already be validated; this is a pure content
    /// comparison, not a re-validation or an issuance proof.
    #[must_use]
    pub fn binds(&self, trigger_id: &str, operation_hash: &str) -> bool {
        self.trigger_id == trigger_id && self.operation_hash == operation_hash
    }
}

/// Routing classification for a retained trigger.
///
/// `Protected` is representable only with a bound owner-issued
/// [`MaintenanceTriggerRouteGrant`]. Accepting an unverified protected tag
/// would widen authority, so the record validation below rejects it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerRoutingClass {
    /// Ordinary maintenance delivery through its existing policy owner.
    Ordinary,
    /// Safety/recovery delivery through a registered owner route with a grant.
    Protected,
}

/// Closed wire record for one retained maintenance trigger.
///
/// Stable source event and trigger identities make exact replay addressable.
/// Producer generation comes from `source_event`; the authority/resource fence
/// comes from `source_state_fence`. Source position is a cursor or an accepted
/// occurrence ID. `operation` plus `operation_hash`
/// binds the producer's exact operation bytes. Kernel may use these fields and
/// the opaque references for delivery bookkeeping only; it cannot use the
/// payload as semantic memory or run maintenance policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerRecord {
    /// Must equal [`MAINTENANCE_TRIGGER_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable source event identity.
    pub source_event: MaintenanceTriggerSourceEvent,
    /// Stable identity of this trigger derived by the source owner.
    pub trigger_id: String,
    /// Cursor or accepted occurrence ID for the source event.
    pub source_position: MaintenanceTriggerPosition,
    /// Source authority and resource fence; producer generation is separate in `source_event`.
    pub source_state_fence: StateFence,
    /// Producer operation whose exact bytes are identified by `operation_hash`.
    pub operation: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Opaque maintenance-family reference.
    pub family: MaintenanceTriggerContentRef,
    /// Opaque affected-scope reference.
    pub scope: MaintenanceTriggerContentRef,
    /// Evidence locators needed by the owning evaluator; never evidence content.
    pub evidence_locators: Vec<String>,
    /// Opaque owner-issued privacy-class reference carried through ORS staging.
    pub privacy_class_reference: String,
    /// Opaque owner-issued visibility-class reference carried through ORS staging.
    pub visibility_reference: String,
    /// Reference and integrity hash for the encrypted ORS payload envelope.
    pub payload: MaintenanceTriggerPayloadRef,
    /// Route category with its owner-issued classification binding.
    ///
    /// `Ordinary` carries no grant. `Protected` requires `route_grant` bound
    /// to this record's exact trigger identity and operation hash.
    pub routing_class: MaintenanceTriggerRoutingClass,
    /// Owner-issued protected-route classification; present only for `Protected`.
    pub route_grant: Option<MaintenanceTriggerRouteGrant>,
    /// Creation time as Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Latest time at which the trigger remains eligible for applicability.
    /// ORS retention expiry remains governed by its envelope and terminal-disposition rules.
    pub applicable_until_unix_ms: u64,
}

impl MaintenanceTriggerRecord {
    /// Validates the closed wire shape, mandatory identities, hashes, and applicability window.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger.wire_id",
                "must be the retained maintenance-trigger identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger.wire_version",
                "must be the current maintenance-trigger version",
            ));
        }

        for (field, value) in [
            (
                "maintenance_trigger.source_event.producer_id",
                self.source_event.producer_id.as_str(),
            ),
            (
                "maintenance_trigger.source_event.stream_id",
                self.source_event.stream_id.as_str(),
            ),
            (
                "maintenance_trigger.source_event.event_id",
                self.source_event.event_id.as_str(),
            ),
            ("maintenance_trigger.trigger_id", self.trigger_id.as_str()),
            ("maintenance_trigger.operation", self.operation.as_str()),
            (
                "maintenance_trigger.privacy_class_reference",
                self.privacy_class_reference.as_str(),
            ),
            (
                "maintenance_trigger.visibility_reference",
                self.visibility_reference.as_str(),
            ),
        ] {
            required_text(value, field)?;
        }
        if self.source_event.producer_generation.value() == 0 {
            return Err(invalid(
                "maintenance_trigger.source_event.producer_generation",
                "must be nonzero",
            ));
        }
        self.source_state_fence.validate()?;
        valid_hash(&self.operation_hash, "maintenance_trigger.operation_hash")?;
        required_text(
            &self.payload.envelope_reference,
            "maintenance_trigger.payload.envelope_reference",
        )?;
        valid_hash(
            &self.payload.payload_hash,
            "maintenance_trigger.payload.payload_hash",
        )?;
        required_text(
            &self.family.reference,
            "maintenance_trigger.family.reference",
        )?;
        required_text(&self.scope.reference, "maintenance_trigger.scope.reference")?;
        if self.evidence_locators.is_empty() {
            return Err(invalid(
                "maintenance_trigger.evidence_locators",
                "must identify at least one evidence locator",
            ));
        }
        for locator in &self.evidence_locators {
            required_text(locator, "maintenance_trigger.evidence_locators")?;
        }
        match &self.source_position {
            MaintenanceTriggerPosition::Cursor { value } if *value == 0 => {
                return Err(invalid(
                    "maintenance_trigger.source_position.cursor",
                    "must be nonzero",
                ));
            }
            MaintenanceTriggerPosition::AcceptedOccurrence { occurrence_id } => {
                required_text(
                    occurrence_id,
                    "maintenance_trigger.source_position.occurrence_id",
                )?;
            }
            MaintenanceTriggerPosition::Cursor { .. } => {}
        }
        if self.applicable_until_unix_ms <= self.created_at_unix_ms {
            return Err(invalid(
                "maintenance_trigger.applicable_until_unix_ms",
                "must be later than the creation time",
            ));
        }
        self.validate_routing()?;
        Ok(())
    }

    /// Validates the routing-class/grant binding without touching digests twice.
    fn validate_routing(&self) -> Result<(), ProtocolError> {
        match (&self.routing_class, &self.route_grant) {
            (MaintenanceTriggerRoutingClass::Ordinary, None) => Ok(()),
            (MaintenanceTriggerRoutingClass::Ordinary, Some(_)) => Err(invalid(
                "maintenance_trigger.route_grant",
                "ordinary routing must not carry a protected grant",
            )),
            (MaintenanceTriggerRoutingClass::Protected, None) => Err(invalid(
                "maintenance_trigger.route_grant",
                "protected routing requires an owner-issued grant",
            )),
            (MaintenanceTriggerRoutingClass::Protected, Some(grant)) => {
                grant.validate()?;
                if !grant.binds(&self.trigger_id, &self.operation_hash) {
                    return Err(invalid(
                        "maintenance_trigger.route_grant",
                        "grant must bind this trigger identity and operation hash",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Validates the record and rejects it for applicability after its expiry.
    ///
    /// Expiry affects eligibility only; the ORS owner retains unresolved records
    /// until terminal disposition under the recovery-envelope retention rules.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        self.validate()?;
        if now_unix_ms >= self.applicable_until_unix_ms {
            return Err(invalid(
                "applicable_until_unix_ms",
                "trigger is no longer applicable at the supplied time",
            ));
        }
        if let (MaintenanceTriggerRoutingClass::Protected, Some(grant)) =
            (&self.routing_class, &self.route_grant)
        {
            grant.validate_at(now_unix_ms)?;
        }
        Ok(())
    }

    /// Returns the existing provider-neutral source-event replay key.
    #[must_use]
    pub fn source_event_identity(&self) -> EventIdentityKey {
        self.source_event.identity_key()
    }

    /// Returns the source producer generation carried by the source event identity.
    #[must_use]
    pub fn source_generation(&self) -> ResourceGeneration {
        self.source_event.producer_generation
    }
}

fn required_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must be nonblank and contain no control characters",
        ));
    }
    Ok(())
}

fn valid_hash(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(field, "must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField { field, reason }
}

/// Intake outcome for one durably staged trigger.
///
/// `ReplaySame` is returned when the exact trigger identity and content hash
/// replay an already staged trigger. Changed content under the same identity
/// is never an outcome: it fails with [`ProtocolError::ReplayConflict`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerIntakeOutcome {
    /// First durable staging of this exact trigger.
    StagedNew,
    /// Exact identity/hash replay of an already staged trigger.
    ReplaySame,
}

/// Durable-intake receipt for one retained trigger.
///
/// The receipt is issued only after the complete opaque input is staged
/// through the ORS owner. Capacity, key, integrity, or durable-write failure
/// produces no receipt: the producer keeps its retry identity and its cursor
/// does not advance. A receipt never proves decision, execution, or delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerIntakeReceipt {
    /// Must equal [`MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable trigger identity that was staged.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Opaque reference to the staged ORS recovery payload envelope.
    pub envelope_reference: String,
    /// Lowercase SHA-256 of the exact staged envelope payload bytes.
    pub payload_hash: String,
    /// Whether this intake staged new bytes or replayed identical ones.
    pub outcome: MaintenanceTriggerIntakeOutcome,
}

impl MaintenanceTriggerIntakeReceipt {
    /// Validates the closed receipt shape and digest formats.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_intake_receipt.wire_id",
                "must be the intake-receipt identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_intake_receipt.wire_version",
                "must be the current intake-receipt version",
            ));
        }
        required_text(
            &self.trigger_id,
            "maintenance_trigger_intake_receipt.trigger_id",
        )?;
        valid_hash(
            &self.operation_hash,
            "maintenance_trigger_intake_receipt.operation_hash",
        )?;
        required_text(
            &self.envelope_reference,
            "maintenance_trigger_intake_receipt.envelope_reference",
        )?;
        valid_hash(
            &self.payload_hash,
            "maintenance_trigger_intake_receipt.payload_hash",
        )?;
        Ok(())
    }

    /// Validates that this receipt answers `record` with identical content.
    ///
    /// The original record is validated first, so its digests are checked by
    /// the existing [`MaintenanceTriggerRecord::validate`]. A matching
    /// identity with different operation or payload content fails with
    /// [`ProtocolError::ReplayConflict`]; a receipt for another trigger fails
    /// as an invalid field.
    pub fn validate_for(&self, record: &MaintenanceTriggerRecord) -> Result<(), ProtocolError> {
        record.validate()?;
        self.validate()?;
        if self.trigger_id != record.trigger_id {
            return Err(invalid(
                "maintenance_trigger_intake_receipt.trigger_id",
                "receipt answers a different trigger",
            ));
        }
        if self.operation_hash != record.operation_hash
            || self.envelope_reference != record.payload.envelope_reference
            || self.payload_hash != record.payload.payload_hash
        {
            return Err(ProtocolError::ReplayConflict);
        }
        Ok(())
    }
}

/// Fenced bounded claim for one retained trigger.
///
/// The claim binds the exact trigger revision and delivery identity to the
/// current compatible daemon generation and session. It is finite: the
/// daemon must deliver or release before `claim_deadline_unix_ms`. Timeout
/// permits owner-mediated redelivery under the same trigger identity, never
/// a new trigger ID and never authority to repeat an uncertain effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerClaim {
    /// Must equal [`MAINTENANCE_TRIGGER_CLAIM_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable trigger identity being claimed.
    pub trigger_id: String,
    /// Retained revision of the trigger; concurrent claims share one revision.
    pub revision: u64,
    /// Stable delivery identity for this claim epoch.
    pub delivery_id: String,
    /// Claiming daemon's authority fence; must match the current generation.
    pub daemon_fence: StateFence,
    /// Claiming daemon's session identity within its generation.
    pub daemon_session: String,
    /// Latest time at which this claim authorizes delivery.
    pub claim_deadline_unix_ms: u64,
}

impl MaintenanceTriggerClaim {
    /// Validates the closed claim shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_CLAIM_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_claim.wire_id",
                "must be the claim identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_claim.wire_version",
                "must be the current claim version",
            ));
        }
        required_text(&self.trigger_id, "maintenance_trigger_claim.trigger_id")?;
        if self.revision == 0 {
            return Err(invalid(
                "maintenance_trigger_claim.revision",
                "must be nonzero",
            ));
        }
        required_text(&self.delivery_id, "maintenance_trigger_claim.delivery_id")?;
        self.daemon_fence.validate()?;
        required_text(
            &self.daemon_session,
            "maintenance_trigger_claim.daemon_session",
        )?;
        if self.claim_deadline_unix_ms == 0 {
            return Err(invalid(
                "maintenance_trigger_claim.claim_deadline_unix_ms",
                "must be nonzero",
            ));
        }
        Ok(())
    }

    /// Authorizes this claim for `record` under the current Kernel fence.
    ///
    /// Old-generation claims fail after revocation: the epoch must be the
    /// exact current authority tuple and the generation must be equal.
    /// Expired claims fail without creating a new trigger or delivery ID.
    pub fn authorize_for(
        &self,
        record: &MaintenanceTriggerRecord,
        current_fence: &StateFence,
        now_unix_ms: u64,
    ) -> Result<(), ProtocolError> {
        record.validate()?;
        self.validate()?;
        current_fence.validate()?;
        if self.trigger_id != record.trigger_id {
            return Err(invalid(
                "maintenance_trigger_claim.trigger_id",
                "claim answers a different trigger",
            ));
        }
        if !self
            .daemon_fence
            .authority_epoch
            .is_same_authority(&current_fence.authority_epoch)
            || self.daemon_fence.resource_generation != current_fence.resource_generation
        {
            return Err(invalid(
                "maintenance_trigger_claim.daemon_fence",
                "claim generation is stale or revoked",
            ));
        }
        if now_unix_ms >= self.claim_deadline_unix_ms {
            return Err(invalid(
                "claim_deadline_unix_ms",
                "claim expired before delivery",
            ));
        }
        Ok(())
    }

    /// Returns whether `other` is an exact retry of this claim.
    ///
    /// Exact retries share trigger identity, revision, delivery identity,
    /// fence, and session, so they cannot produce competing decisions.
    #[must_use]
    pub fn is_exact_retry_of(&self, other: &Self) -> bool {
        self.trigger_id == other.trigger_id
            && self.revision == other.revision
            && self.delivery_id == other.delivery_id
            && self.daemon_fence == other.daemon_fence
            && self.daemon_session == other.daemon_session
    }
}

/// Lifecycle disposition of one retained trigger.
///
/// `Reconciling` marks a lost or ambiguous commit response: receipt absence
/// during an outage is not proof of non-commit, so the trigger must be
/// reconciled by receipt lookup, never blindly re-executed. Terminal states
/// preserve the trigger identity; they never delete unresolved effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerDisposition {
    /// Retained and awaiting a first claim.
    Pending,
    /// Held under one finite generation-bound claim.
    Claimed,
    /// Decision committed; delivery acknowledgement still outstanding.
    DecisionRecorded,
    /// Exact decision receipt acknowledged; delivery complete.
    Acknowledged,
    /// Commit outcome ambiguous; reconcile by receipt before any effect.
    Reconciling,
    /// Eligibility expired; identity and evidence preserved.
    Expired,
    /// Replaced by an explicitly linked successor evaluation revision.
    Superseded,
}

impl MaintenanceTriggerDisposition {
    /// Returns whether the disposition may advance from `from` to `to`.
    ///
    /// Claim timeout returns to `Pending` under the same trigger identity;
    /// it never mints a new trigger ID. Terminal and acknowledged states
    /// are sinks.
    #[must_use]
    pub const fn can_advance(from: Self, to: Self) -> bool {
        matches!(
            (from, to),
            (
                Self::Pending,
                Self::Claimed | Self::Expired | Self::Superseded
            ) | (
                Self::Claimed,
                Self::DecisionRecorded
                    | Self::Pending
                    | Self::Reconciling
                    | Self::Expired
                    | Self::Superseded
            ) | (
                Self::DecisionRecorded,
                Self::Acknowledged | Self::Reconciling | Self::Expired | Self::Superseded
            ) | (
                Self::Reconciling,
                Self::Claimed | Self::DecisionRecorded | Self::Expired | Self::Superseded
            )
        )
    }

    /// Validates a disposition advance without changing any state.
    pub fn validate_advance(from: Self, to: Self) -> Result<(), ProtocolError> {
        if Self::can_advance(from, to) {
            Ok(())
        } else {
            Err(invalid(
                "maintenance_trigger.disposition",
                "illegal disposition transition",
            ))
        }
    }
}

/// Bounded pending-set member carried by a trigger page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerPendingSummary {
    /// Stable trigger identity.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Retained revision of the trigger.
    pub revision: u64,
    /// Current lifecycle disposition.
    pub disposition: MaintenanceTriggerDisposition,
    /// Latest time at which the trigger remains eligible for applicability.
    pub applicable_until_unix_ms: u64,
}

impl MaintenanceTriggerPendingSummary {
    /// Validates the closed pending-summary shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        required_text(
            &self.trigger_id,
            "maintenance_trigger_pending_summary.trigger_id",
        )?;
        valid_hash(
            &self.operation_hash,
            "maintenance_trigger_pending_summary.operation_hash",
        )?;
        if self.revision == 0 {
            return Err(invalid(
                "maintenance_trigger_pending_summary.revision",
                "must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Class of visible recovery gap attached to a trigger or a page.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerGapKind {
    /// Required decryption key is missing; no plaintext fallback exists.
    MissingKey,
    /// Staged payload fails integrity validation.
    CorruptPayload,
    /// Referenced source event or evidence cannot be reached.
    InaccessibleSource,
    /// Pending enumeration is provably incomplete past this point.
    IncompleteEnumeration,
    /// Commit response was lost; the outcome is unknown, not absent.
    AmbiguousCommit,
}

/// Visible recovery/gap record for one damaged or incomplete trigger.
///
/// Missing keys, corrupt payloads, inaccessible sources, and incomplete
/// enumeration produce this record — never plaintext fallback, silent
/// deletion, or a bare `no_action`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerGap {
    /// Stable gap identity.
    pub gap_id: String,
    /// Affected trigger identity, when the gap is trigger-scoped.
    pub trigger_id: Option<String>,
    /// Gap class.
    pub kind: MaintenanceTriggerGapKind,
    /// Evidence locator or reason reference; never payload content.
    pub detail: String,
    /// Recording time as Unix milliseconds.
    pub recorded_at_unix_ms: u64,
}

impl MaintenanceTriggerGap {
    /// Validates the closed gap shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        required_text(&self.gap_id, "maintenance_trigger_gap.gap_id")?;
        if let Some(trigger_id) = &self.trigger_id {
            required_text(trigger_id, "maintenance_trigger_gap.trigger_id")?;
        }
        required_text(&self.detail, "maintenance_trigger_gap.detail")?;
        Ok(())
    }
}

/// Bounded pending-trigger page with stable continuation and explicit gaps.
///
/// A reconnect resumes from `continuation`; it never resets progress to a
/// guessed complete-empty set. An empty member list is admitted only with a
/// closed page and at least one gap explaining the absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerPage {
    /// Must equal [`MAINTENANCE_TRIGGER_PAGE_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION`].
    pub wire_version: u16,
    /// At most [`MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS`] pending summaries.
    pub members: Vec<MaintenanceTriggerPendingSummary>,
    /// Opaque resume cursor; present exactly when more pages follow.
    pub continuation: Option<String>,
    /// Whether further pages follow this one.
    pub has_more: bool,
    /// At most [`MAX_MAINTENANCE_TRIGGER_PAGE_GAPS`] explicit gap records.
    pub gaps: Vec<MaintenanceTriggerGap>,
}

impl MaintenanceTriggerPage {
    /// Validates bounds, continuation discipline, and every member and gap.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_PAGE_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_page.wire_id",
                "must be the page identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_page.wire_version",
                "must be the current page version",
            ));
        }
        if self.members.len() > MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS {
            return Err(invalid(
                "maintenance_trigger_page.members",
                "page exceeds the member bound",
            ));
        }
        for member in &self.members {
            member.validate()?;
        }
        if self.gaps.len() > MAX_MAINTENANCE_TRIGGER_PAGE_GAPS {
            return Err(invalid(
                "maintenance_trigger_page.gaps",
                "page exceeds the gap bound",
            ));
        }
        for gap in &self.gaps {
            gap.validate()?;
        }
        match (&self.continuation, self.has_more) {
            (Some(cursor), true) => {
                required_text(cursor, "maintenance_trigger_page.continuation")?;
            }
            (None, false) => {}
            (Some(_), false) | (None, true) => {
                return Err(invalid(
                    "maintenance_trigger_page.continuation",
                    "continuation must be present exactly when more pages follow",
                ));
            }
        }
        if self.members.is_empty() && self.gaps.is_empty() {
            return Err(invalid(
                "maintenance_trigger_page.members",
                "an empty page must carry at least one explicit gap",
            ));
        }
        Ok(())
    }
}

/// Durable decision receipt bound to one retained trigger.
///
/// The receipt binds trigger identity and operation hash, the exact
/// evaluation and policy revisions consumed, the affected scope, at least one
/// durable downstream intent reference, and the canonical Store receipt. It
/// carries the full receipt content: accepting an arbitrary receipt ID or a
/// transport `Ok` is insufficient for acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerDecisionReceipt {
    /// Must equal [`MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable trigger identity this decision answers.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Retained trigger revision this decision was evaluated against.
    pub revision: u64,
    /// Opaque evaluator revision that produced this decision.
    pub evaluation_revision: String,
    /// Opaque policy revision resolved at decision time.
    pub policy_revision: String,
    /// Opaque affected-scope reference.
    pub scope_ref: String,
    /// Durable job intent reference, when the decision admits a job.
    pub job_ref: Option<String>,
    /// Durable recommendation reference, when the decision suggests.
    pub recommendation_ref: Option<String>,
    /// Durable wake intent reference, when the decision schedules a wake.
    pub wake_ref: Option<String>,
    /// Canonical Store receipt reference for the committed decision.
    pub canonical_receipt_ref: String,
    /// Lowercase SHA-256 digest of the canonical receipt bytes.
    pub receipt_digest: String,
}

impl MaintenanceTriggerDecisionReceipt {
    /// Validates the closed receipt shape, intent presence, and digests.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_decision_receipt.wire_id",
                "must be the decision-receipt identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_decision_receipt.wire_version",
                "must be the current decision-receipt version",
            ));
        }
        required_text(
            &self.trigger_id,
            "maintenance_trigger_decision_receipt.trigger_id",
        )?;
        valid_hash(
            &self.operation_hash,
            "maintenance_trigger_decision_receipt.operation_hash",
        )?;
        if self.revision == 0 {
            return Err(invalid(
                "maintenance_trigger_decision_receipt.revision",
                "must be nonzero",
            ));
        }
        required_text(
            &self.evaluation_revision,
            "maintenance_trigger_decision_receipt.evaluation_revision",
        )?;
        required_text(
            &self.policy_revision,
            "maintenance_trigger_decision_receipt.policy_revision",
        )?;
        required_text(
            &self.scope_ref,
            "maintenance_trigger_decision_receipt.scope_ref",
        )?;
        let mut intents = 0;
        for intent in [&self.job_ref, &self.recommendation_ref, &self.wake_ref]
            .into_iter()
            .flatten()
        {
            required_text(intent, "maintenance_trigger_decision_receipt.intent_ref")?;
            intents += 1;
        }
        if intents == 0 {
            return Err(invalid(
                "maintenance_trigger_decision_receipt.intent_ref",
                "a decision requires at least one durable intent reference",
            ));
        }
        required_text(
            &self.canonical_receipt_ref,
            "maintenance_trigger_decision_receipt.canonical_receipt_ref",
        )?;
        valid_hash(
            &self.receipt_digest,
            "maintenance_trigger_decision_receipt.receipt_digest",
        )?;
        Ok(())
    }

    /// Validates that this receipt answers `record` with identical content.
    ///
    /// The original record is validated first, so its digests are checked by
    /// the existing [`MaintenanceTriggerRecord::validate`]. Commit-before-ack
    /// recovery reuses this receipt instead of duplicating downstream effects.
    pub fn matches_trigger(&self, record: &MaintenanceTriggerRecord) -> Result<(), ProtocolError> {
        record.validate()?;
        self.validate()?;
        if self.trigger_id != record.trigger_id {
            return Err(invalid(
                "maintenance_trigger_decision_receipt.trigger_id",
                "receipt answers a different trigger",
            ));
        }
        if self.operation_hash != record.operation_hash || self.scope_ref != record.scope.reference
        {
            return Err(ProtocolError::ReplayConflict);
        }
        Ok(())
    }
}

/// Delivery acknowledgement for one retained trigger.
///
/// The ack embeds the full bound decision receipt plus the claim echo, so a
/// stale consumer or an arbitrary receipt ID cannot complete delivery. After
/// commit but before ack, the owner looks up this exact receipt and reuses it
/// without another job, recommendation, or wake.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerAck {
    /// Must equal [`MAINTENANCE_TRIGGER_ACK_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_ACK_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable trigger identity being acknowledged.
    pub trigger_id: String,
    /// Delivery identity of the claim being acknowledged.
    pub delivery_id: String,
    /// Acknowledging daemon's authority fence; must equal the claim fence.
    pub daemon_fence: StateFence,
    /// Acknowledging daemon's session identity; must equal the claim session.
    pub daemon_session: String,
    /// Full content of the bound durable decision receipt.
    pub decision_receipt: MaintenanceTriggerDecisionReceipt,
}

impl MaintenanceTriggerAck {
    /// Validates the closed ack shape and its embedded receipt.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_ACK_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_ack.wire_id",
                "must be the ack identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_ACK_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_ack.wire_version",
                "must be the current ack version",
            ));
        }
        required_text(&self.trigger_id, "maintenance_trigger_ack.trigger_id")?;
        required_text(&self.delivery_id, "maintenance_trigger_ack.delivery_id")?;
        self.daemon_fence.validate()?;
        required_text(
            &self.daemon_session,
            "maintenance_trigger_ack.daemon_session",
        )?;
        self.decision_receipt.validate()?;
        Ok(())
    }

    /// Validates this ack against its claim, trigger, and current fence.
    ///
    /// The claim must still authorize under the current generation, the ack
    /// must echo the claim's delivery identity, fence, and session exactly,
    /// and the embedded receipt must content-match the trigger. A stale
    /// consumer cannot ack after its authority was revoked.
    pub fn validate_for_claim(
        &self,
        claim: &MaintenanceTriggerClaim,
        record: &MaintenanceTriggerRecord,
        current_fence: &StateFence,
        now_unix_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        claim.authorize_for(record, current_fence, now_unix_ms)?;
        self.decision_receipt.matches_trigger(record)?;
        if self.trigger_id != claim.trigger_id || self.delivery_id != claim.delivery_id {
            return Err(invalid(
                "maintenance_trigger_ack.delivery_id",
                "ack answers a different claim",
            ));
        }
        if self.daemon_session != claim.daemon_session || self.daemon_fence != claim.daemon_fence {
            return Err(invalid(
                "maintenance_trigger_ack.daemon_fence",
                "ack consumer differs from the claiming consumer",
            ));
        }
        Ok(())
    }
}

/// Revocation of one daemon generation's trigger-consumer authority.
///
/// Pending claims survive daemon loss; this wire lets the Kernel owner revoke
/// the old consumer fence so a replacement generation can reclaim the same
/// triggers without competing with a stale consumer. Enforcement belongs to
/// the Kernel owner; this module fixes the revoked identity exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerRevocation {
    /// Must equal [`MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Exact daemon fence whose consumer authority is revoked.
    pub daemon_fence: StateFence,
    /// Daemon session identity whose consumer authority is revoked.
    pub daemon_session: String,
    /// Kernel owner principal that issued the revocation.
    pub revoking_owner: String,
    /// Stable reason reference for the revocation.
    pub reason: String,
    /// Revocation time as Unix milliseconds.
    pub revoked_at_unix_ms: u64,
}

impl MaintenanceTriggerRevocation {
    /// Validates the closed revocation shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_revocation.wire_id",
                "must be the revocation identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_revocation.wire_version",
                "must be the current revocation version",
            ));
        }
        self.daemon_fence.validate()?;
        required_text(
            &self.daemon_session,
            "maintenance_trigger_revocation.daemon_session",
        )?;
        required_text(
            &self.revoking_owner,
            "maintenance_trigger_revocation.revoking_owner",
        )?;
        required_text(&self.reason, "maintenance_trigger_revocation.reason")?;
        if self.revoked_at_unix_ms == 0 {
            return Err(invalid(
                "maintenance_trigger_revocation.revoked_at_unix_ms",
                "must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Terminal disposition class for one retained trigger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerTerminalKind {
    /// Eligibility expired; execution is blocked, identity preserved.
    Expired,
    /// Replaced by an explicitly linked successor evaluation revision.
    Superseded,
}

/// Terminal expiry/supersession disposition for one retained trigger.
///
/// Expired eligibility blocks execution but never deletes the unresolved
/// trigger or its effects: source and evidence stay under the retention
/// policy. A supersession links the successor trigger explicitly instead of
/// overwriting the old result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerTerminalDisposition {
    /// Must equal [`MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable trigger identity receiving its terminal disposition.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes.
    pub operation_hash: String,
    /// Terminal class.
    pub kind: MaintenanceTriggerTerminalKind,
    /// Successor trigger identity; required for supersession, absent for expiry.
    pub successor_trigger_id: Option<String>,
    /// Stable reason reference for the disposition.
    pub reason: String,
    /// Recording time as Unix milliseconds.
    pub recorded_at_unix_ms: u64,
}

impl MaintenanceTriggerTerminalDisposition {
    /// Validates the closed terminal-disposition shape and successor rule.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID {
            return Err(invalid(
                "maintenance_trigger_terminal_disposition.wire_id",
                "must be the terminal-disposition identity",
            ));
        }
        if self.wire_version != MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION {
            return Err(invalid(
                "maintenance_trigger_terminal_disposition.wire_version",
                "must be the current terminal-disposition version",
            ));
        }
        required_text(
            &self.trigger_id,
            "maintenance_trigger_terminal_disposition.trigger_id",
        )?;
        valid_hash(
            &self.operation_hash,
            "maintenance_trigger_terminal_disposition.operation_hash",
        )?;
        match (&self.kind, &self.successor_trigger_id) {
            (MaintenanceTriggerTerminalKind::Superseded, Some(successor)) => {
                required_text(
                    successor,
                    "maintenance_trigger_terminal_disposition.successor_trigger_id",
                )?;
            }
            (MaintenanceTriggerTerminalKind::Superseded, None) => {
                return Err(invalid(
                    "maintenance_trigger_terminal_disposition.successor_trigger_id",
                    "supersession requires an explicit successor",
                ));
            }
            (MaintenanceTriggerTerminalKind::Expired, Some(_)) => {
                return Err(invalid(
                    "maintenance_trigger_terminal_disposition.successor_trigger_id",
                    "expiry must not name a successor",
                ));
            }
            (MaintenanceTriggerTerminalKind::Expired, None) => {}
        }
        required_text(
            &self.reason,
            "maintenance_trigger_terminal_disposition.reason",
        )?;
        if self.recorded_at_unix_ms == 0 {
            return Err(invalid(
                "maintenance_trigger_terminal_disposition.recorded_at_unix_ms",
                "must be nonzero",
            ));
        }
        Ok(())
    }
}
