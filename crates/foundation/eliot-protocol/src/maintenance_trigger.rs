//! Provider-neutral retained maintenance-trigger wire contract.
//!
//! This module describes the operational identity and opaque payload reference
//! for a maintenance trigger. It does not persist records, interpret payloads,
//! evaluate policy, or authorize delivery. The existing ORS owner remains
//! responsible for staging a `RecoveryPayloadEnvelope`; this contract carries
//! only its opaque reference and integrity hash. ORS must retain the envelope's
//! privacy, visibility, fence, and expiry metadata without indexing its semantic
//! contents.
//!
//! Protected safety/recovery routing is intentionally outside this contract's
//! admitted scope until an owner-issued authenticated route classification is
//! available. `Ordinary` is the only representable routing class, so this type
//! cannot assert protected-route authentication or substitute a new authority.

use eliot_contracts::{
    ContractIdentity, ContractVersion, ResourceGeneration, StateFence, contract_identity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EventIdentityKey, ProtocolError};

/// Stable identity of the retained maintenance-trigger contract family.
pub const MAINTENANCE_TRIGGER_CONTRACT_NAME: &str = "eliot.foundation.maintenance-trigger";
/// Current semantic revision of the retained maintenance-trigger contract.
pub const MAINTENANCE_TRIGGER_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Stable wire identity for one retained maintenance trigger.
pub const MAINTENANCE_TRIGGER_WIRE_ID: &str = "eliot.protocol.retained-maintenance-trigger";
/// Current wire version for a retained maintenance trigger.
pub const MAINTENANCE_TRIGGER_WIRE_VERSION: u16 = 1;

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

/// Routing classification available to this contract revision.
///
/// Protected safety/recovery routes are not representable until their existing
/// owner supplies an authenticated classification contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTriggerRoutingClass {
    /// Ordinary maintenance delivery through its existing policy owner.
    Ordinary,
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
    /// Route category; this revision admits ordinary maintenance only.
    pub routing_class: MaintenanceTriggerRoutingClass,
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
        Ok(())
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
