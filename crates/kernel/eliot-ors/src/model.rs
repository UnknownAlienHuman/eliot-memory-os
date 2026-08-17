use std::collections::BTreeSet;

use eliot_platform::{PlatformHandle, SecretReference};
use eliot_receipts::ReceiptEnvelope;
use eliot_runtime_contracts::GenerationCutoverRecord as RuntimeGenerationCutoverRecord;
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CONTRACT_VERSION, MAX_RECOVERY_PAGE};

/// A validated opaque label that carries no semantic authority.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueLabel(String);

impl OpaqueLabel {
    /// Constructs a non-blank, non-control label.
    pub fn new(value: impl Into<String>) -> Result<Self, OrsError> {
        let value = value.into();
        validate_text(&value, "opaque_label")?;
        Ok(Self(value))
    }

    /// Returns the wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OpaqueLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Caller-defined visibility policy label preserved without interpretation.
pub type VisibilityClass = OpaqueLabel;
/// Stable ordering-scope identity preserved without interpreting its prefix.
pub type OrderingScope = OpaqueLabel;
/// Recovery owner identity preserved without granting it authority.
pub type RecoveryOwner = OpaqueLabel;
/// Operation/checkpoint identity preserved without creating an authority owner.
pub type OperationIdentity = OpaqueLabel;

/// Durable one-shot process-start replay state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartReplayRecord {
    pub operation_id: OperationIdentity,
    pub admission_digest: String,
    pub owner: eliot_process::ProcessOwnerBinding,
    pub state: ProcessStartReplayState,
    pub receipt: Option<eliot_process::ProcessStartReceipt>,
}

/// Process-start replay disposition persisted by ORS.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStartReplayState {
    Reserved,
    Completed,
    Unknown,
}

/// Exact canonical snapshot of a provider-owned State Fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFenceSnapshot {
    pub canonical_json: String,
    pub sha256: String,
    pub observed_authority_epoch: u64,
}

impl StateFenceSnapshot {
    /// Captures any serializable provider fence without redefining its fields.
    pub fn capture<T: Serialize>(
        provider_fence: &T,
        observed_authority_epoch: u64,
    ) -> Result<Self, OrsError> {
        if observed_authority_epoch == 0 {
            return Err(OrsError::InvalidField {
                field: "observed_authority_epoch",
                reason: "must be greater than zero",
            });
        }
        let value = serde_json::to_value(provider_fence)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let canonical_json = serde_json::to_string(&canonicalize(value))
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        let sha256 = sha256_hex(canonical_json.as_bytes());
        Ok(Self {
            canonical_json,
            sha256,
            observed_authority_epoch,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.sha256, "state_fence_sha256")?;
        if self.observed_authority_epoch == 0
            || sha256_hex(self.canonical_json.as_bytes()) != self.sha256
        {
            return Err(OrsError::FenceMismatch);
        }
        let parsed: Value = serde_json::from_str(&self.canonical_json)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if serde_json::to_string(&canonicalize(parsed))
            .map_err(|error| OrsError::Encoding(error.to_string()))?
            != self.canonical_json
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }
}

/// Exact epoch identity, including its lineage namespace.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochIdentity {
    pub lineage_id: OpaqueLabel,
    pub epoch: u64,
}

/// One current epoch plus the exact predecessor that authorizes its succession.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLineage {
    pub current: EpochIdentity,
    pub predecessor: Option<EpochIdentity>,
}

impl EpochLineage {
    /// Validates the explicit lineage edge.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.current.validate()?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        if let Some(predecessor) = &self.predecessor
            && predecessor.lineage_id == self.current.lineage_id
            && predecessor.epoch >= self.current.epoch
        {
            return Err(OrsError::InvalidEpochLineage);
        }
        Ok(())
    }

    pub(crate) fn succeeds(&self, prior: &EpochIdentity) -> bool {
        self.current == *prior
            || self
                .predecessor
                .as_ref()
                .is_some_and(|value| value == prior)
    }
}

impl EpochIdentity {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        if self.epoch == 0 {
            return Err(OrsError::InvalidEpochLineage);
        }
        Ok(())
    }
}

/// Opaque payload representation. ORS owns neither keys nor locator contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum RecoveryPayload {
    Encrypted {
        key: SecretReference,
        ciphertext: Vec<u8>,
    },
    ImmutableLocator {
        locator: PlatformHandle,
    },
}

/// Required privacy and visibility metadata that travels with a pending value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAccessClass {
    pub privacy: PrivacyClass,
    pub visibility: VisibilityClass,
}

/// Versioned opaque recovery envelope required at the ORS boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPayloadEnvelope {
    pub contract_version: u16,
    pub operation_or_checkpoint_id: OperationIdentity,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub payload: RecoveryPayload,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// Metadata shared by encrypted and immutable-locator recovery envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEnvelopeContext {
    pub operation_or_checkpoint_id: OperationIdentity,
    pub privacy_and_visibility_class: RecoveryAccessClass,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub known_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

impl RecoveryPayloadEnvelope {
    /// Constructs an encrypted envelope and binds its exact ciphertext bytes.
    pub fn encrypted(
        context: RecoveryEnvelopeContext,
        key: SecretReference,
        ciphertext: Vec<u8>,
    ) -> Result<Self, OrsError> {
        let payload_length =
            u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        let payload_sha256 = sha256_hex(&ciphertext);
        let envelope = Self {
            contract_version: CONTRACT_VERSION,
            operation_or_checkpoint_id: context.operation_or_checkpoint_id,
            privacy_and_visibility_class: context.privacy_and_visibility_class,
            payload: RecoveryPayload::Encrypted { key, ciphertext },
            payload_sha256,
            payload_length,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            created_at_ms: context.created_at_ms,
            known_at_ms: context.known_at_ms,
            expires_at_ms: context.expires_at_ms,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Constructs a locator envelope. The caller supplies the immutable object's binding.
    pub fn immutable_locator(
        context: RecoveryEnvelopeContext,
        locator: PlatformHandle,
        payload_sha256: String,
        payload_length: u64,
    ) -> Result<Self, OrsError> {
        let envelope = Self {
            contract_version: CONTRACT_VERSION,
            operation_or_checkpoint_id: context.operation_or_checkpoint_id,
            privacy_and_visibility_class: context.privacy_and_visibility_class,
            payload: RecoveryPayload::ImmutableLocator { locator },
            payload_sha256,
            payload_length,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            created_at_ms: context.created_at_ms,
            known_at_ms: context.known_at_ms,
            expires_at_ms: context.expires_at_ms,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates version, integrity bindings, fence, epoch lineage, and time bounds.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        validate_digest(&self.payload_sha256, "payload_sha256")?;
        if self.payload_length == 0 {
            return Err(OrsError::InvalidField {
                field: "payload_length",
                reason: "must be greater than zero",
            });
        }
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.state_fence.observed_authority_epoch != self.authority_epoch.current.epoch {
            return Err(OrsError::FenceMismatch);
        }
        if self.known_at_ms < self.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        if let Some(expires) = self.expires_at_ms
            && expires <= self.created_at_ms
        {
            return Err(OrsError::InvalidExpiry);
        }
        match &self.payload {
            RecoveryPayload::Encrypted { key, ciphertext } => {
                validate_text(key.provider.as_str(), "secret_provider")?;
                validate_text(key.key.as_str(), "secret_key")?;
                let length =
                    u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
                if length > crate::MAX_INLINE_RECOVERY_BYTES {
                    return Err(OrsError::PayloadTooLarge);
                }
                if length != self.payload_length || sha256_hex(ciphertext) != self.payload_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
            }
            RecoveryPayload::ImmutableLocator { locator } => {
                validate_text(locator.as_str(), "immutable_locator")?;
            }
        }
        Ok(())
    }
}

/// Canonical head expected before a transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOrderingHead {
    pub sequence: u64,
    pub head_sha256: String,
    pub revision_head: Option<String>,
}

impl ExpectedOrderingHead {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.head_sha256, "head_sha256")?;
        if let Some(revision) = &self.revision_head {
            validate_text(revision, "revision_head")?;
        }
        Ok(())
    }
}

/// One requested scope and the canonical head it must extend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReservationRequest {
    pub scope: OrderingScope,
    pub expected_head: ExpectedOrderingHead,
}

/// Atomic reservation request. All scopes are reserved or none are.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: OperationIdentity,
    pub envelope: RecoveryPayloadEnvelope,
    pub writer_epoch: EpochLineage,
    pub scopes: Vec<ScopeReservationRequest>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

impl ReservationRequest {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.envelope.validate()?;
        self.writer_epoch.validate()?;
        validate_digest(
            &self.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        if self.writer_epoch.current != self.envelope.authority_epoch.current {
            return Err(OrsError::EpochMismatch);
        }
        if self.scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        if self.scopes.len() > usize::from(MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let mut seen = BTreeSet::new();
        for scope in &self.scopes {
            scope.expected_head.validate()?;
            if !seen.insert(scope.scope.clone()) {
                return Err(OrsError::DuplicateScope);
            }
        }
        if self.expires_at_ms <= self.envelope.created_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        Ok(())
    }
}

/// One scope sequence allocated by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedScope {
    pub scope: OrderingScope,
    pub reserved_sequence: u64,
    pub expected_head: ExpectedOrderingHead,
}

/// Immutable token checked throughout the writer lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterReservationToken {
    pub reservation_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub writer_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub reservation_order: u64,
    pub scopes: Vec<ReservedScope>,
    pub prepared_transition_sha256: String,
    pub expires_at_ms: i64,
    pub recovery_owner: RecoveryOwner,
}

/// Durable reservation lifecycle. Terminal states never become executable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReservationState {
    Reserved,
    Eligible,
    Executing,
    Reconciling,
    Finalized,
    Released,
}

impl ReservationState {
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Released)
    }
}

/// Durable reservation record recovered after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRecord {
    pub token: WriterReservationToken,
    pub state: ReservationState,
    pub unknown_reason: Option<OpaqueLabel>,
    pub terminal_receipt_id: Option<OpaqueLabel>,
}

/// Bounded restart-recovery cursor. `after_order` is exclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCursor {
    pub after_order: u64,
    pub limit: u16,
}

impl RecoveryCursor {
    /// Constructs a cursor under the hard page ceiling.
    pub fn new(after_order: u64, limit: u16) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self { after_order, limit })
    }
}

/// One bounded recovery page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPage {
    pub records: Vec<ReservationRecord>,
    pub next_after_order: Option<u64>,
}

/// Canonical head observation supplied alongside a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalScopeObservation {
    pub scope: OrderingScope,
    pub prior_head: ExpectedOrderingHead,
    pub committed_sequence: u64,
    pub committed_head_sha256: String,
    pub committed_revision_head: Option<String>,
    pub receipt_id: OpaqueLabel,
}

/// Terminal disposition established by the canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalDisposition {
    Committed,
    Rejected,
}

/// Exact receipt/read-back evidence used to close one ORS reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalReconciliation {
    pub reservation_id: OperationIdentity,
    pub operation_id: OperationIdentity,
    pub reservation_order: u64,
    pub state_fence: StateFenceSnapshot,
    pub recovery_owner: RecoveryOwner,
    pub scopes: Vec<CanonicalScopeObservation>,
    pub receipt: ReceiptEnvelope,
    pub disposition: CanonicalDisposition,
}

/// One provider-neutral opaque operational input. The bytes are never interpreted by ORS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRecordInput {
    pub record_id: OperationIdentity,
    pub subject_id: OperationIdentity,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub payload: RecoveryPayload,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
}

/// Metadata shared by encrypted and immutable-locator operational records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalRecordContext {
    pub record_id: OperationIdentity,
    pub subject_id: OperationIdentity,
    pub authority_epoch: EpochLineage,
    pub state_fence: StateFenceSnapshot,
    pub created_at_ms: i64,
    pub cleanup_after_ms: Option<i64>,
}

impl OperationalRecordInput {
    /// Creates an encrypted integrity-bound operational input.
    pub fn encrypted(
        context: OperationalRecordContext,
        key: SecretReference,
        ciphertext: Vec<u8>,
    ) -> Result<Self, OrsError> {
        let payload_length =
            u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        let payload_sha256 = sha256_hex(&ciphertext);
        let value = Self {
            record_id: context.record_id,
            subject_id: context.subject_id,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            payload: RecoveryPayload::Encrypted { key, ciphertext },
            payload_sha256,
            payload_length,
            created_at_ms: context.created_at_ms,
            cleanup_after_ms: context.cleanup_after_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Creates an integrity-bound immutable-locator operational input.
    pub fn immutable_locator(
        context: OperationalRecordContext,
        locator: PlatformHandle,
        payload_sha256: String,
        payload_length: u64,
    ) -> Result<Self, OrsError> {
        let value = Self {
            record_id: context.record_id,
            subject_id: context.subject_id,
            authority_epoch: context.authority_epoch,
            state_fence: context.state_fence,
            payload: RecoveryPayload::ImmutableLocator { locator },
            payload_sha256,
            payload_length,
            created_at_ms: context.created_at_ms,
            cleanup_after_ms: context.cleanup_after_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.authority_epoch.current.epoch != self.state_fence.observed_authority_epoch {
            return Err(OrsError::FenceMismatch);
        }
        validate_digest(&self.payload_sha256, "operational_payload_sha256")?;
        if self.payload_length == 0 {
            return Err(OrsError::InvalidField {
                field: "operational_payload_length",
                reason: "must be greater than zero",
            });
        }
        match &self.payload {
            RecoveryPayload::Encrypted { key, ciphertext } => {
                validate_text(key.provider.as_str(), "operational_secret_provider")?;
                validate_text(key.key.as_str(), "operational_secret_key")?;
                let length =
                    u64::try_from(ciphertext.len()).map_err(|_| OrsError::PayloadTooLarge)?;
                if length > crate::MAX_INLINE_RECOVERY_BYTES {
                    return Err(OrsError::PayloadTooLarge);
                }
                if length != self.payload_length || sha256_hex(ciphertext) != self.payload_sha256 {
                    return Err(OrsError::PayloadIntegrityMismatch);
                }
            }
            RecoveryPayload::ImmutableLocator { locator } => {
                validate_text(locator.as_str(), "operational_immutable_locator")?;
            }
        }
        if self
            .cleanup_after_ms
            .is_some_and(|cleanup_after| cleanup_after <= self.created_at_ms)
        {
            return Err(OrsError::InvalidExpiry);
        }
        Ok(())
    }
}

macro_rules! operational_input {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub OperationalRecordInput);

        impl $name {
            pub fn new(record: OperationalRecordInput) -> Result<Self, OrsError> {
                record.validate()?;
                Ok(Self(record))
            }

            pub fn record(&self) -> &OperationalRecordInput {
                &self.0
            }
        }
    };
}

operational_input!(StagedOperation);
operational_input!(RetryState);
operational_input!(JobCheckpoint);
operational_input!(DeliveryCursorState);
operational_input!(DeliveryAcknowledgement);
operational_input!(AdmissionReservation);
operational_input!(AdmissionReservationActivation);
operational_input!(AdmissionReservationRelease);
operational_input!(GenerationTransition);
operational_input!(GenerationCutoverRecord);
operational_input!(ActiveSessionBinding);
operational_input!(SessionDetach);
operational_input!(UserBrokerRegistration);
operational_input!(UserBrokerFence);
operational_input!(KernelAuthoritySnapshot);
operational_input!(AuthorityRevocation);
operational_input!(CapabilityGrantActivation);
operational_input!(CapabilityGrantRevocation);
operational_input!(CapabilityIntroductionActivation);
operational_input!(CapabilityIntroductionFence);

/// Read-only ORS evidence for one Kernel generation transition or committed
/// cutover.  The runtime contract and its integrity-bound ORS receipt are
/// projected from the canonical operational current/history tables; ORS does
/// not grant authority or interpret the route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GenerationCutoverSnapshot {
    /// The validated transition/cutover contract.
    pub record: RuntimeGenerationCutoverRecord,
    /// Monotonic ORS order at which this value was written.
    pub operation_order: u64,
    /// Receipt over the exact canonical operational record.
    pub receipt: GenerationCutoverReceipt,
}

impl GenerationCutoverSnapshot {
    pub(crate) fn new(
        record: RuntimeGenerationCutoverRecord,
        operation_order: u64,
        receipt: GenerationCutoverReceipt,
    ) -> Self {
        Self {
            record,
            operation_order,
            receipt,
        }
    }

    /// Returns the typed generation/cutover contract.
    pub const fn record(&self) -> &RuntimeGenerationCutoverRecord {
        &self.record
    }

    /// Returns the ORS ordering value for this evidence.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the integrity-bound receipt for this canonical record.
    pub const fn receipt(&self) -> &GenerationCutoverReceipt {
        &self.receipt
    }
}

/// Persisted non-semantic phase for a P.4 operational subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationalPhase {
    Staged,
    Applying,
    Active,
    Suspended,
    Reconciling,
    Terminal,
    Released,
    Fenced,
}

/// Integrity-bound receipt created only by the durable store implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationalMutationReceipt {
    record_id: OperationIdentity,
    subject_id: OperationIdentity,
    operation_order: u64,
    phase: OperationalPhase,
    state_sha256: String,
}

impl OperationalMutationReceipt {
    pub fn record_id(&self) -> &OperationIdentity {
        &self.record_id
    }

    pub fn subject_id(&self) -> &OperationIdentity {
        &self.subject_id
    }

    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    pub const fn phase(&self) -> OperationalPhase {
        self.phase
    }

    pub fn state_sha256(&self) -> &str {
        &self.state_sha256
    }

    pub(crate) fn issue(
        record_id: OperationIdentity,
        subject_id: OperationIdentity,
        operation_order: u64,
        phase: OperationalPhase,
        state_sha256: String,
    ) -> Result<Self, OrsError> {
        if operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "operational_receipt",
                reason: "operation order is zero".to_owned(),
            });
        }
        validate_digest(&state_sha256, "operational_state_sha256")?;
        Ok(Self {
            record_id,
            subject_id,
            operation_order,
            phase,
            state_sha256,
        })
    }
}

macro_rules! operational_receipt {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(OperationalMutationReceipt);

        impl $name {
            pub fn receipt(&self) -> &OperationalMutationReceipt {
                &self.0
            }

            pub(crate) const fn from_receipt(receipt: OperationalMutationReceipt) -> Self {
                Self(receipt)
            }
        }
    };
}

operational_receipt!(StageReceipt);
operational_receipt!(DeliveryCursorReceipt);
operational_receipt!(AdmissionReservationReceipt);
operational_receipt!(GenerationTransitionReceipt);
operational_receipt!(GenerationCutoverReceipt);
operational_receipt!(SessionBindingReceipt);
operational_receipt!(UserBrokerRegistrationReceipt);
operational_receipt!(AuthoritySnapshotReceipt);
operational_receipt!(AuthorityRevocationReceipt);
operational_receipt!(AuthorityActivationReceipt);
operational_receipt!(CapabilityIntroductionReceipt);

/// Integrity-checked active authority snapshot read back from ORS.
///
/// This value proves only that P-06 recovered the exact opaque record it had
/// durably committed. ORS never decrypts or interprets the payload and this
/// value grants no Kernel or process authority. The P-07 owner must resolve
/// the payload through its platform secret/artifact port and revalidate the
/// decoded authority state against the expected active identity and fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredAuthoritySnapshot {
    snapshot: KernelAuthoritySnapshot,
    operation_order: u64,
    receipt: AuthoritySnapshotReceipt,
}

impl RecoveredAuthoritySnapshot {
    pub(crate) const fn from_store(
        snapshot: KernelAuthoritySnapshot,
        operation_order: u64,
        receipt: AuthoritySnapshotReceipt,
    ) -> Self {
        Self {
            snapshot,
            operation_order,
            receipt,
        }
    }

    /// Returns the validated opaque authority-snapshot record.
    pub const fn snapshot(&self) -> &KernelAuthoritySnapshot {
        &self.snapshot
    }

    /// Returns the monotonic ORS operation order at which it became active.
    pub const fn operation_order(&self) -> u64 {
        self.operation_order
    }

    /// Returns the store-issued integrity receipt for the recovered record.
    pub const fn receipt(&self) -> &AuthoritySnapshotReceipt {
        &self.receipt
    }
}

/// Signed/hashed recovery-inbox item. ORS verifies bindings and delegates signer trust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInboxItem {
    pub item_id: OperationIdentity,
    pub signer_id: OpaqueLabel,
    pub envelope: RecoveryPayloadEnvelope,
    pub envelope_sha256: String,
    pub signature: Vec<u8>,
    pub signature_sha256: String,
    pub arrived_at_ms: i64,
}

impl RecoveryInboxItem {
    pub fn bind(
        item_id: OperationIdentity,
        signer_id: OpaqueLabel,
        envelope: RecoveryPayloadEnvelope,
        signature: Vec<u8>,
        arrived_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let envelope_bytes =
            serde_json::to_vec(&envelope).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let value = Self {
            item_id,
            signer_id,
            envelope,
            envelope_sha256: sha256_hex(&envelope_bytes),
            signature_sha256: sha256_hex(&signature),
            signature,
            arrived_at_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        self.envelope.validate()?;
        validate_digest(&self.envelope_sha256, "inbox_envelope_sha256")?;
        validate_digest(&self.signature_sha256, "inbox_signature_sha256")?;
        if self.signature.is_empty()
            || self.signature.len() > crate::MAX_INBOX_SIGNATURE_BYTES
            || sha256_hex(&self.signature) != self.signature_sha256
            || sha256_hex(
                &serde_json::to_vec(&self.envelope)
                    .map_err(|error| OrsError::Encoding(error.to_string()))?,
            ) != self.envelope_sha256
        {
            return Err(OrsError::InboxIntegrityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryInboxDisposition {
    Imported,
    Applied,
    Rejected,
    DeadLetter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryInboxReceipt(OperationalMutationReceipt);

impl RecoveryInboxReceipt {
    pub fn receipt(&self) -> &OperationalMutationReceipt {
        &self.0
    }

    pub(crate) const fn from_receipt(receipt: OperationalMutationReceipt) -> Self {
        Self(receipt)
    }
}

/// Bounded logical ORS export request. It never copies a live redb file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrsSnapshotRequest {
    pub after_order: u64,
    pub limit: u16,
    pub snapshot_at_ms: i64,
}

impl OrsSnapshotRequest {
    pub fn new(after_order: u64, limit: u16, snapshot_at_ms: i64) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self {
            after_order,
            limit,
            snapshot_at_ms,
        })
    }
}

/// Store-issued logical snapshot receipt with retained evidence bindings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrsSnapshotReceipt {
    snapshot_at_ms: i64,
    entry_refs: Vec<String>,
    snapshot_sha256: String,
    next_after_order: Option<u64>,
}

impl OrsSnapshotReceipt {
    pub const fn snapshot_at_ms(&self) -> i64 {
        self.snapshot_at_ms
    }

    pub fn entry_refs(&self) -> &[String] {
        &self.entry_refs
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub const fn next_after_order(&self) -> Option<u64> {
        self.next_after_order
    }

    pub(crate) fn issue(
        snapshot_at_ms: i64,
        entry_refs: Vec<String>,
        snapshot_sha256: String,
        next_after_order: Option<u64>,
    ) -> Result<Self, OrsError> {
        validate_digest(&snapshot_sha256, "ors_snapshot_sha256")?;
        Ok(Self {
            snapshot_at_ms,
            entry_refs,
            snapshot_sha256,
            next_after_order,
        })
    }
}

/// Exact terminal reservation sequence disposition retained for gap/readback proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeTerminalReceipt {
    pub scope: OrderingScope,
    pub reserved_sequence: u64,
    pub disposition: CanonicalDisposition,
    pub gap: bool,
    pub receipt_id: OpaqueLabel,
    pub receipt_sha256: String,
}

/// Read-only terminal/gap evidence; it has no public constructor or deserializer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScopeTerminalView {
    scope: OrderingScope,
    reserved_sequence: u64,
    disposition: CanonicalDisposition,
    gap: bool,
    receipt_id: OpaqueLabel,
    receipt_sha256: String,
}

impl ScopeTerminalView {
    pub fn scope(&self) -> &OrderingScope {
        &self.scope
    }

    pub const fn reserved_sequence(&self) -> u64 {
        self.reserved_sequence
    }

    pub const fn disposition(&self) -> CanonicalDisposition {
        self.disposition
    }

    pub const fn is_gap(&self) -> bool {
        self.gap
    }

    pub fn receipt_id(&self) -> &OpaqueLabel {
        &self.receipt_id
    }

    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }

    pub(crate) fn from_persisted(value: &ScopeTerminalReceipt) -> Self {
        Self {
            scope: value.scope.clone(),
            reserved_sequence: value.reserved_sequence,
            disposition: value.disposition,
            gap: value.gap,
            receipt_id: value.receipt_id.clone(),
            receipt_sha256: value.receipt_sha256.clone(),
        }
    }
}

/// Bounded alias matching Appendix P.4 terminology.
pub type PendingOperationPage = RecoveryPage;

/// Bounded non-authoritative control projection rebuilt from validated durable records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalControlProjection {
    pub authority_lineage: EpochLineage,
    pub pending_operation_refs: Vec<String>,
    pub active_generation_refs: Vec<String>,
    pub active_session_refs: Vec<String>,
    pub active_user_broker_refs: Vec<String>,
    pub active_capability_refs: Vec<String>,
    pub job_checkpoint_refs: Vec<String>,
    pub delivery_cursor_refs: Vec<String>,
    pub recovery_inbox_refs: Vec<String>,
}

/// Typed ORS failures. None grants semantic or completion authority.
#[derive(Debug, Error)]
pub enum OrsError {
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("foundation contract rejected ORS input: {0}")]
    Contract(String),
    #[error("unsupported recovery envelope contract version {0}")]
    UnsupportedContractVersion(u16),
    #[error("payload length exceeds the supported counter")]
    PayloadTooLarge,
    #[error("payload bytes do not match their declared length and SHA-256")]
    PayloadIntegrityMismatch,
    #[error("authority epoch does not match the State Fence")]
    FenceMismatch,
    #[error("authority epoch does not match the recovery envelope")]
    EpochMismatch,
    #[error("epoch lineage does not strictly advance its same-lineage predecessor")]
    InvalidEpochLineage,
    #[error("expiry must be strictly later than creation")]
    InvalidExpiry,
    #[error("at least one Ordering Scope is required")]
    EmptyScopeSet,
    #[error("an Ordering Scope occurs more than once")]
    DuplicateScope,
    #[error("recovery cursor limit must be between 1 and {MAX_RECOVERY_PAGE}")]
    InvalidCursorLimit,
    #[error("duplicate identity conflicts with durable ORS state")]
    DuplicateConflict,
    #[error("reservation was not found")]
    ReservationNotFound,
    #[error("reservation lifecycle transition is invalid")]
    InvalidTransition,
    #[error("writer epoch is stale or does not own the reservation")]
    StaleWriterEpoch,
    #[error("an earlier reservation blocks this scope")]
    PredecessorPending,
    #[error("scope requires receipt reconciliation before new allocation")]
    ScopeRecoveryRequired,
    #[error("recovery owner does not match the token")]
    RecoveryOwnerMismatch,
    #[error("active or unknown work cannot expire without canonical reconciliation")]
    UnsafeExpiry,
    #[error(
        "canonical reconciliation does not exactly bind receipt, operation, scopes, order, heads, and fence"
    )]
    ReconciliationMismatch,
    #[error("an UNKNOWN receipt cannot resolve an unknown operation")]
    UnknownReceiptCannotResolve,
    #[error("canonical evidence provider rejected or could not authenticate evidence: {0}")]
    CanonicalEvidence(String),
    #[error("canonical ordering head does not match durable ORS state")]
    OrderingHeadMismatch,
    #[error("recovery inbox signature or envelope binding is invalid")]
    InboxIntegrityMismatch,
    #[error("active authority snapshot is unavailable")]
    AuthoritySnapshotUnavailable,
    #[error("operational projection exceeds its declared bound")]
    ProjectionLimitExceeded,
    #[error("durable ORS integrity problem in {record_type}: {reason}")]
    IntegrityProblem {
        record_type: &'static str,
        reason: String,
    },
    #[error("durable ORS storage failed: {0}")]
    Storage(String),
    #[error("durable ORS encoding failed: {0}")]
    Encoding(String),
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.trim().is_empty() {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > 1_024 {
        return Err(OrsError::InvalidField {
            field,
            reason: "must not exceed 1024 UTF-8 bytes",
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}
