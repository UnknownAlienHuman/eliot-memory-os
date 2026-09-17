//! Store-neutral canonical storage contracts for ELIOT S-01.
//!
//! This crate defines the typed boundary between Governor/Kernel admission and
//! a canonical store.  It deliberately contains no database, filesystem,
//! process, credential, provider or proof-authority implementation.  A store
//! may persist a valid plan, but it cannot create semantic commands, widen an
//! effect ceiling, or turn a transport receipt into a completion decision.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, ContractId, ResourceGeneration, TransactionSequence};
pub use eliot_contracts::{
    ContractError, ContractVersion, ErrorCode, OperationId, RequestMetadata, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptKind, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding,
    contract_identity as receipt_contract_identity,
};
pub use eliot_receipts::{EffectClass, ReceiptEnvelope};
pub use eliot_security_contracts::{
    DisclosureDependencyClosure, InfluenceDependencyClosure, InfluenceState, PurgeLedgerEntry,
    RevocationReason, SelectionIntegrityReceipt, SourceAssurance, TransformationLineage,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

mod dreamer_job;
pub mod epistemic_revision;
pub mod erasure_admission;
mod payload_authority;
mod request_hash;
mod store_failure;
mod wire;

pub use dreamer_job::{
    DREAMER_JOB_LEDGER_SCHEMA, DreamerJobExpectedState, DreamerJobLedgerEvent,
    DreamerJobLedgerRecord, DreamerJobMutationIdentity, MAX_DREAMER_JOB_HISTORY,
    MAX_DREAMER_JOB_QUEUE_KEY_BYTES, MAX_DREAMER_JOB_TEXT_BYTES, dreamer_job_queue_key,
    map_durable_error, validate_ledger_bundle,
};

pub use payload_authority::{
    CONTROL_FIELD_DENYLIST, CanonicalJson, ExactJsonBytes, MAX_EXACT_JSON_BYTES,
    PAYLOAD_AUTHORITY_VERSION, PayloadEncoding, PayloadSource, json_shape_name,
    number_token_would_narrow, reject_control_parameter_name,
};

pub use request_hash::{
    CanonicalRequestView, MAX_DIGEST_DETAIL_CHARS, canonical_request_bytes, canonical_request_hash,
    verify_canonical_request_hash,
};

pub use store_failure::{
    ErasureFailureKind, MAX_STORE_FAILURE_DETAIL_LEN,
    MAX_STORE_FAILURE_EVIDENCE_HANDLES, MAX_STORE_FAILURE_REFERENCE_LEN,
    MAX_STORE_FAILURE_RETRY_AFTER_MS, MAX_STORE_REASON_CODE_LEN, STORE_FAILURE_CONTRACT_REVISION,
    StoreConflictObservation, StoreEvidenceHandles, StoreFailure, StoreFailureContractError,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreFailureRequestContext,
    StoreMutationDisposition, StoreReasonCode, StoreRecoveryAction, StoreRetryDirective,
    erasure_store_failure,
};

pub use wire::{
    CAPABILITIES, CAPABILITY_APPLY, CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
    CAPABILITY_DREAMER_JOB_CHECKPOINT, CAPABILITY_DREAMER_JOB_LEASE_EXACT,
    CAPABILITY_DREAMER_JOB_LEASE_NEXT, CAPABILITY_DREAMER_JOB_PUBLISH,
    CAPABILITY_DREAMER_JOB_RECONCILE, CAPABILITY_DREAMER_JOB_RENEW,
    CAPABILITY_DREAMER_JOB_REQUEST_CANCEL, CAPABILITY_DREAMER_JOB_RESUME,
    CAPABILITY_DREAMER_JOB_START, CAPABILITY_DREAMER_JOB_STATUS, CAPABILITY_DREAMER_JOB_SUBMIT,
    CAPABILITY_ERASURE_INTENT, CAPABILITY_HEALTH, CAPABILITY_INITIALIZE_GENESIS,
    CAPABILITY_NAMED_READ, CAPABILITY_ORDERING_HEADS, CAPABILITY_READINESS, CAPABILITY_RECEIPT,
    CAPABILITY_RECOVERY, CAPABILITY_REVISION_HEADS, CAPABILITY_VALIDATION_SNAPSHOT, EFFECTS,
    ErasureSurfaceRequest, ReadinessReceipt, ReadinessStatus, StoreRequest, StoreResponse,
    StoreWireError, decode_request_frame, decode_request_frame_with_authority,
    decode_response_frame, dreamer_job_capability, request_frame,
    request_frame_with_payload_authority, response_frame,
};

mod operation_catalogue;
mod operation_parameters;
mod revocation_history;

pub use erasure_admission::{
    ERASURE_PARAM_OPERATION_ID, ERASURE_PARAM_REASON, ERASURE_PARAM_REQUESTER,
    ERASURE_PARAM_SUBJECT, ERASURE_PARAM_SURFACES, ERASURE_SURFACE_SEPARATOR,
    ErasureAdmissionRequest, admit_erasure_transition, decode_erasure_surfaces,
    encode_erasure_surfaces,
};

pub use operation_catalogue::{
    ACTIVATED_READ_OWNING_SECTION, EVIDENCE_PACK_MAX_RECORDS, GENESIS_OWNING_SECTION,
    MINIMUM_COMPATIBLE_VERSION, OPERATION_CATALOGUE_PROFILE, OperationKind, READ_MAX_INPUT_BYTES,
    READ_MAX_OUTPUT_BYTES, READ_TIMEOUT_MS, SCOPE_KIND_NONE, SCOPE_KIND_SCOPE,
    SINGLE_MANIFEST_OWNING_SECTION, activated_read_operations, generated_operation_manifests,
    operation_manifest_set_digest,
};

pub use operation_parameters::{
    ParameterDeclaration, ParameterSchemaField, ParameterShape, declared_read_parameters,
    named_mutation_operation_by_name, named_mutation_operation_name, named_read_operation_by_name,
    named_read_operation_name, parameter_schema_digest, project_parameter_schema,
    validate_typed_read_parameters,
};

pub use revocation_history::{
    REVOCATION_HISTORY_MAX_RECORDS, REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation,
    RevocationHistoryPayload, parse_revocation_history_payload,
};

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.storage.store-api";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Versioned schema for store recovery packets.
pub const RECOVERY_PACKET_SCHEMA: &str = "eliot.storage.recovery.v1";
/// Versioned schema for opaque Governor owner snapshots.
pub const OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.owner.snapshot.v1";
/// Maximum number of owner records in one recovery/genesis operation.
pub const MAX_RECOVERY_OWNER_RECORDS: usize = 16;
/// Maximum exact payload size of one recovered record.
pub const MAX_RECOVERY_RECORD_BYTES: usize = 512 * 1024;
/// Maximum canonical JSON packet size for recovery contracts.
pub const MAX_RECOVERY_PACKET_BYTES: usize = 3 * 1024 * 1024;
/// Maximum number of replayable receipts in one recovery snapshot.
pub const MAX_RECOVERY_RECEIPTS: usize = 256;
/// Maximum number of durable jobs in one recovery snapshot.
pub const MAX_RECOVERY_JOBS: usize = 256;
/// Fixed neutral receipt scope placeholder for genesis envelopes. This is
/// required by the universal receipt core only; it is not a Governor
/// semantic `WorkScope` and is never persisted or advanced as a store head.
pub const GENESIS_RECEIPT_SCOPE_ID: &str = "store";
/// Fixed neutral ordering placeholder for genesis envelopes. It is never
/// persisted or advanced as a revision/order head.
pub const GENESIS_RECEIPT_ORDERING_SCOPE: &str = "store";
/// Stable neutral manifest name used for every provider's genesis receipt.
pub const GENESIS_MANIFEST_NAME: &str = "eliot.storage.genesis";

/// Compatibility spelling used by the store boundary.
pub type RequestMeta = RequestMetadata;

/// Deterministic address of one opaque store recovery record.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecordKey {
    pub namespace: String,
    pub key: String,
}

impl RecoveryRecordKey {
    /// Constructs and validates one recovery record address.
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> Result<Self, StoreError> {
        let record = Self {
            namespace: namespace.into(),
            key: key.into(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the non-semantic address fields.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.namespace, "recovery.namespace")?;
        validate_text(&self.key, "recovery.key")
    }
}

/// One opaque, fenced, content-addressed recovery record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub namespace: String,
    pub key: String,
    pub state_fence: StateFence,
    /// Durable outer revision of this record, not an inner payload revision.
    pub revision: u64,
    pub schema: String,
    /// Exact canonical payload bytes; the store does not interpret them.
    pub payload: Vec<u8>,
    pub value_digest: String,
}

impl RecoveryRecord {
    /// Returns the deterministic record address.
    #[must_use]
    pub fn record_key(&self) -> RecoveryRecordKey {
        RecoveryRecordKey {
            namespace: self.namespace.clone(),
            key: self.key.clone(),
        }
    }

    /// Validates one record without assigning meaning to its namespace/key/schema.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record_key().validate()?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.revision == 0 {
            return Err(StoreError::InvalidField {
                field: "recovery.revision",
                reason: "must be non-zero",
            });
        }
        validate_text(&self.schema, "recovery.schema")?;
        if self.payload.is_empty() {
            return Err(StoreError::Empty {
                field: "recovery.payload",
            });
        }
        if self.payload.len() > MAX_RECOVERY_RECORD_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        validate_digest(&self.value_digest, "recovery.value_digest")?;
        if sha256_hex(&self.payload) != self.value_digest {
            return Err(StoreError::InvalidField {
                field: "recovery.value_digest",
                reason: "does not match payload",
            });
        }
        Ok(())
    }

    fn validate_for_fence(&self, expected: &StateFence) -> Result<(), StoreError> {
        self.validate()?;
        ensure_same_fence(expected, &self.state_fence)
    }
}

/// Request for one same-fence recovery observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRecoveryRequest {
    pub contract_version: ContractVersion,
    pub state_fence: StateFence,
    pub records: Vec<RecoveryRecordKey>,
    pub include_receipts: bool,
    pub include_jobs: bool,
}

impl StoreRecoveryRequest {
    /// Validates bounded deterministic selection state and packet size.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_recovery_contract_version(self.contract_version)?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.records.len() > MAX_RECOVERY_OWNER_RECORDS {
            return Err(StoreError::PayloadTooLarge);
        }
        for record in &self.records {
            record.validate()?;
        }
        unique(self.records.iter().cloned(), "recovery.records")?;
        validate_recovery_packet_size(self)
    }
}

/// Same-fence store recovery result containing opaque owner/job records and
/// canonical replay evidence. The store never interprets record payloads.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRecoverySnapshot {
    pub contract_version: ContractVersion,
    pub state_fence: StateFence,
    pub validation_revision: u64,
    pub canonical_scope: ScopeRevisionView,
    pub owner_records: Vec<RecoveryRecord>,
    pub job_records: Vec<RecoveryRecord>,
    pub receipts: Vec<WriteReceipt>,
}

impl StoreRecoverySnapshot {
    /// Validates one complete, bounded, same-fence recovery snapshot.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_recovery_contract_version(self.contract_version)?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.validation_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "recovery.validation_revision",
                reason: "must be non-zero",
            });
        }
        self.canonical_scope.validate()?;
        ensure_same_fence(&self.state_fence, &self.canonical_scope.state_fence)?;
        if self.owner_records.len() > MAX_RECOVERY_OWNER_RECORDS {
            return Err(StoreError::PayloadTooLarge);
        }
        if self.job_records.len() > MAX_RECOVERY_JOBS {
            return Err(StoreError::PayloadTooLarge);
        }
        if self.receipts.len() > MAX_RECOVERY_RECEIPTS {
            return Err(StoreError::PayloadTooLarge);
        }

        let mut record_keys = BTreeSet::new();
        for record in self.owner_records.iter().chain(self.job_records.iter()) {
            record.validate_for_fence(&self.state_fence)?;
            if !record_keys.insert(record.record_key()) {
                return Err(StoreError::Duplicate {
                    field: "recovery.record_keys",
                });
            }
        }
        let mut receipt_operations = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.validate()?;
            ensure_same_fence(&self.state_fence, &receipt.state_fence)?;
            if !receipt_operations.insert(receipt.operation_id.clone()) {
                return Err(StoreError::Duplicate {
                    field: "recovery.receipts",
                });
            }
        }
        validate_recovery_packet_size(self)
    }
}

/// Atomic all-absent genesis seed request. The seed must contain at least one
/// opaque owner record, while owner keys and payload schemas remain
/// intentionally semantic-neutral at this Store layer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreGenesisRequest {
    pub contract_version: ContractVersion,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub state_fence: StateFence,
    pub owner_records: Vec<RecoveryRecord>,
}

impl StoreGenesisRequest {
    /// Returns the deterministic bytes covered by `canonical_request_hash`.
    ///
    /// The digest field is cleared before canonicalization so the digest does
    /// not recursively include itself.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let mut unsigned = self.clone();
        unsigned.canonical_request_hash.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| StoreError::Serialization(error.to_string()))
    }

    /// Computes the canonical request hash over every genesis request field
    /// except `canonical_request_hash` itself.
    pub fn compute_digest(&self) -> Result<String, StoreError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical request hash for an explicitly constructed
    /// genesis request.
    pub fn with_computed_digest(mut self) -> Result<Self, StoreError> {
        self.canonical_request_hash = self.compute_digest()?;
        Ok(self)
    }

    /// Validates an atomic, bounded, same-fence genesis seed request.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_recovery_contract_version(self.contract_version)?;
        validate_text(&self.idempotency_key, "idempotency_key")?;
        validate_digest(&self.canonical_request_hash, "canonical_request_hash")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if !is_genesis_fence(&self.state_fence) {
            return Err(StoreError::FenceMismatch);
        }
        if self.owner_records.is_empty() {
            return Err(StoreError::Empty {
                field: "genesis.owner_records",
            });
        }
        if self.owner_records.len() > MAX_RECOVERY_OWNER_RECORDS {
            return Err(StoreError::PayloadTooLarge);
        }
        let mut record_keys = BTreeSet::new();
        for record in &self.owner_records {
            record.validate_for_fence(&self.state_fence)?;
            if !record_keys.insert(record.record_key()) {
                return Err(StoreError::Duplicate {
                    field: "genesis.owner_records",
                });
            }
        }

        if self.canonical_request_hash != self.compute_digest()? {
            return Err(StoreError::InvalidField {
                field: "canonical_request_hash",
                reason: "does not match canonical genesis request",
            });
        }
        validate_recovery_packet_size(self)
    }

    /// Validates this seed against the caller context's empty task/session
    /// semantics and exact genesis fence.
    pub fn validate_for_context(&self, context: &RequestMeta) -> Result<(), StoreError> {
        context.validate().map_err(StoreError::Foundation)?;
        self.validate()?;
        if context.task_id.is_some() || context.session_id.is_some() {
            return Err(StoreError::InvalidField {
                field: "genesis.context",
                reason: "genesis context must not carry task or session identity",
            });
        }
        ensure_same_fence(&context.state_fence, &self.state_fence)
    }
}

fn validate_recovery_contract_version(version: ContractVersion) -> Result<(), StoreError> {
    if version != CONTRACT_VERSION {
        return Err(StoreError::InvalidField {
            field: "contract_version",
            reason: "does not match the store API contract",
        });
    }
    Ok(())
}

fn validate_recovery_packet_size<T: Serialize>(value: &T) -> Result<(), StoreError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_RECOVERY_PACKET_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Returns whether a fence is the only accepted empty-genesis fence.
///
/// Genesis is lineage-agnostic: any lineage at sequence 1 with genesis
/// resources and no bound revisions qualifies. Epoch lineage itself is never
/// compared by scalar ordering; only the genesis sequence position is checked.
#[must_use]
pub fn is_genesis_fence(fence: &StateFence) -> bool {
    fence.authority_epoch.sequence.get() == 1
        && fence.resource_generation == ResourceGeneration::genesis()
        && fence.task_revision.is_none()
        && fence.policy_revision.is_none()
        && fence.integration_revision.is_none()
}

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a non-blank, non-control-character identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
                let value = value.into();
                validate_text(&value, $field)?;
                if value.trim().len() != value.len() {
                    return Err(StoreError::InvalidField {
                        field: $field,
                        reason: "blank or control character",
                    });
                }
                Ok(Self(value))
            }

            /// Returns the stable identifier text.
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(/// Scope whose revision and ordering state is addressed.
    ScopeId, "scope_id");
opaque_id!(/// One revision dependency key.
    RevisionKey, "revision_key");
opaque_id!(/// One ordering stream.
    OrderingScopeId, "ordering_scope");
opaque_id!(/// Digest/identity of one named operation.
    OperationManifestDigest, "operation_manifest_digest");
opaque_id!(/// Store commit identity.
    CommitId, "commit_id");
opaque_id!(/// Canonical event identity.
    EventId, "event_id");
opaque_id!(/// Projection publication identity.
    ProjectionPublicationId, "projection_publication_id");
opaque_id!(/// Outbox item identity.
    OutboxId, "outbox_id");

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(StoreError::Duplicate { field });
    }
    Ok(())
}

fn validate_parameters(parameters: &BTreeMap<String, Value>) -> Result<(), StoreError> {
    for (name, value) in parameters {
        validate_text(name, "operation.parameter_name")?;
        if value.is_null() {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "null is not a canonical parameter",
            });
        }
    }
    Ok(())
}

/// A bounded semantic transition family.  This is a ceiling discriminator,
/// not semantic admission and not an authority grant.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TransitionClass {
    CaptureCandidate,
    Epistemic,
    TaskControl,
    LifecyclePolicy,
    RecoverySchema,
    /// Explicit user-requested canonical erasure/disposition (issue #1712).
    ///
    /// Irreversible deletion semantics inside the canonical store: admitted
    /// only through the named erasure transaction carrying explicit
    /// user-initiated identity (identity + exact scope + reason) and
    /// non-empty proof/approval handles. Maintenance, curation, Dreamer, and
    /// scheduler paths never carry those handles, so no automatic trigger can
    /// reach this class. The ceiling stays the maximum store-allowed effect;
    /// existing class maxima are unchanged.
    Erasure,
}

impl TransitionClass {
    /// Maximum canonical effect the store may persist for this class.
    pub const fn maximum_effect(self) -> EffectClass {
        match self {
            Self::CaptureCandidate | Self::Epistemic => EffectClass::Candidate,
            Self::TaskControl | Self::LifecyclePolicy | Self::RecoverySchema | Self::Erasure => {
                EffectClass::ReversibleMutation
            }
        }
    }
}

/// Returns whether an effect is no stronger than the declared ceiling.
pub const fn effect_is_at_most(effect: EffectClass, ceiling: EffectClass) -> bool {
    const fn rank(value: EffectClass) -> u8 {
        match value {
            EffectClass::Read => 0_u8,
            EffectClass::Candidate => 1,
            EffectClass::ReversibleMutation => 2,
            EffectClass::ExternalEffect => 3,
        }
    }
    rank(effect) <= rank(ceiling)
}

/// Read consistency requested from a named read.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, Serialize, Deserialize, PartialEq, PartialOrd,
)]
#[serde(rename_all = "snake_case")]
pub enum ReadConsistency {
    Eventual,
    AtLeastRevision,
    StableScope,
    ExactFence,
}

/// Closed named read catalogue.  Physical query names never cross this API.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum NamedReadOperation {
    GetRevisionHeads,
    GetScopeRevisionView,
    GetOrderingHeads,
    GetTaskState,
    GetCurrentEpistemicPosition,
    GetEvidencePack,
    GetUnderstandingProjectionInputs,
    GetAttentionAndProblems,
    GetModuleCatalogState,
    GetCapabilityEvidenceState,
    GetConformanceState,
    GetMailbox,
    GetAuditRange,
    ResolveWriteReceipt,
    /// CURRENT authority revocation history (issue #686). Known-but-
    /// unsupported until a store-owned slice activates its catalogue row
    /// with proven handlers; the typed parameters and payload contract
    /// (`revocation_history`) are already closed.
    GetAuthorityRevocationHistory,
}

/// Closed mutation catalogue activated by the current contract catalogue.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, Serialize, Deserialize, PartialEq, PartialOrd,
)]
#[serde(rename_all = "PascalCase")]
pub enum NamedMutationOperation {
    CaptureObservation,
    ApplyEpistemicRevision,
    UpdateTaskState,
    ApplyLifecyclePolicy,
    ReconcileRecovery,
    AppendAuditEvent,
    /// Durable authority-revocation record (issue #686). Known-but-
    /// unsupported until a store-owned slice activates its catalogue row
    /// with proven handlers; the typed parameters are already closed.
    RecordAuthorityRevocation,
    /// Named canonical erasure/disposition transaction (issue #1712).
    ///
    /// Explicit user request ONLY, never automatic: the prepared transition
    /// must carry [`TransitionClass::Erasure`], the declared erasure effect
    /// ceiling, the closed erasure typed parameters (exact subject, surface
    /// denominator, explicit reason, user-initiated requester identity, and
    /// the stable intent identity), and non-empty proof/approval handles.
    /// The store bridge applies only the recorded plan; it never derives
    /// deletion semantics.
    ApplyErasure,
}

impl NamedMutationOperation {
    /// Transition family owned by this named mutation.
    pub const fn transition_class(self) -> TransitionClass {
        match self {
            Self::CaptureObservation | Self::AppendAuditEvent => TransitionClass::CaptureCandidate,
            Self::ApplyEpistemicRevision => TransitionClass::Epistemic,
            Self::UpdateTaskState => TransitionClass::TaskControl,
            Self::ApplyLifecyclePolicy => TransitionClass::LifecyclePolicy,
            Self::ReconcileRecovery | Self::RecordAuthorityRevocation => {
                TransitionClass::RecoverySchema
            }
            Self::ApplyErasure => TransitionClass::Erasure,
        }
    }
}

/// Named operation parameters and identity used by a prepared transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedMutationRequest {
    pub operation: NamedMutationOperation,
    pub parameters: BTreeMap<String, Value>,
}

impl NamedMutationRequest {
    /// Validates the closed operation and canonical parameter map.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_parameters(&self.parameters)
    }
}

/// Store-neutral named read request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedReadRequest {
    pub operation: NamedReadOperation,
    pub scope_id: Option<ScopeId>,
    pub consistency: ReadConsistency,
    pub state_fence: StateFence,
    pub parameters: BTreeMap<String, Value>,
}

impl NamedReadRequest {
    /// Validates request metadata without interpreting semantic payload.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_parameters(&self.parameters)
    }

    /// Validates this request against a generated operation catalogue set.
    ///
    /// This is the pre-dispatch authority for named reads: catalogue
    /// membership, typed parameters, scope declaration, and declared input
    /// bounds. It issues no authority; scope, role, fence, and expiry
    /// enforcement stay in slice C2.
    pub fn validate_against_catalogue(
        &self,
        entries: &[NamedOperationManifest],
    ) -> Result<(), StoreError> {
        operation_catalogue::validate_read_against_catalogue(self, entries)
    }
}

/// Named read response.  The payload is opaque to the store and typed by the
/// active contract catalogue at the consumer boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedReadResponse {
    pub operation: NamedReadOperation,
    pub state_fence: StateFence,
    pub revision_heads: Vec<RevisionHead>,
    pub payload: Value,
}

impl NamedReadResponse {
    /// Rejects a response that silently changes the requested fence.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        unique(
            self.revision_heads.iter().map(|head| head.key.clone()),
            "revision_heads",
        )?;
        for head in &self.revision_heads {
            head.validate()?;
        }
        Ok(())
    }
}

/// Revision head observed or required by a transaction/read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionHead {
    pub key: RevisionKey,
    pub revision: u64,
    pub state_fence: StateFence,
}

impl RevisionHead {
    /// Validates explicit non-zero revision and fence metadata.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.revision == 0 {
            return Err(StoreError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate().map_err(StoreError::Foundation)
    }
}

/// One coherent canonical-store validation observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalValidationSnapshot {
    pub state_fence: StateFence,
    pub revision_heads: Vec<RevisionHead>,
    pub validation_revision: u64,
    pub observed_at_unix_ms: i64,
}

impl CanonicalValidationSnapshot {
    /// Validates the complete, same-fence snapshot before it is consumed.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.validation_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "validation_revision",
                reason: "must be non-zero",
            });
        }
        if self.observed_at_unix_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "observed_at_unix_ms",
                reason: "must be a positive Unix timestamp",
            });
        }
        unique(
            self.revision_heads.iter().map(|head| head.key.clone()),
            "revision_heads",
        )?;
        if self.revision_heads.len() > 128 {
            return Err(StoreError::PayloadTooLarge);
        }
        for head in &self.revision_heads {
            head.validate()?;
            ensure_same_fence(&self.state_fence, &head.state_fence)?;
        }
        Ok(())
    }
}

/// Compare-and-swap expectation for one revision dependency.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionHeadExpectation {
    pub key: RevisionKey,
    pub expected_revision: u64,
    pub state_fence: StateFence,
}

impl RevisionHeadExpectation {
    /// Validates a non-zero expected revision.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.expected_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "expected_revision",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate().map_err(StoreError::Foundation)
    }
}

/// Ordering head for one conflict-serialization scope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderingHead {
    pub scope: OrderingScopeId,
    pub sequence: u64,
    pub state_fence: StateFence,
}

impl OrderingHead {
    /// Validates one explicit ordering head.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "ordering.sequence",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate().map_err(StoreError::Foundation)
    }
}

/// Compare-and-swap expectation for one ordering head.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderingHeadExpectation {
    pub scope: OrderingScopeId,
    pub expected_sequence: u64,
    pub state_fence: StateFence,
}

impl OrderingHeadExpectation {
    /// Validates one explicit ordering expectation.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.expected_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "expected_sequence",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate().map_err(StoreError::Foundation)
    }
}

/// Rebuildable scope projection; it never authorizes a write.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRevisionView {
    pub scope_id: ScopeId,
    pub revision_heads: Vec<RevisionHead>,
    pub ordering_heads: Vec<OrderingHead>,
    pub state_fence: StateFence,
}

impl ScopeRevisionView {
    /// Rejects duplicate keys and mismatched fences in a coherent view.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        unique(
            self.revision_heads.iter().map(|head| head.key.clone()),
            "revision_heads",
        )?;
        unique(
            self.ordering_heads.iter().map(|head| head.scope.clone()),
            "ordering_heads",
        )?;
        for head in &self.revision_heads {
            head.validate()?;
            ensure_same_fence(&self.state_fence, &head.state_fence)?;
        }
        for head in &self.ordering_heads {
            head.validate()?;
            ensure_same_fence(&self.state_fence, &head.state_fence)?;
        }
        Ok(())
    }
}

fn ensure_same_fence(left: &StateFence, right: &StateFence) -> Result<(), StoreError> {
    if left == right {
        Ok(())
    } else {
        Err(StoreError::FenceMismatch)
    }
}

/// Security/provenance material carried through a prepared transition.
#[derive(Clone, Debug, Eq, JsonSchema, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityContext {
    pub source_assurance: Vec<SourceAssurance>,
    pub disclosure_closure: Option<DisclosureDependencyClosure>,
    pub transformation_lineage: Vec<TransformationLineage>,
    pub influence_closure: Option<InfluenceDependencyClosure>,
    pub purge_entry: Option<PurgeLedgerEntry>,
    pub selection_integrity: Option<SelectionIntegrityReceipt>,
}

impl SecurityContext {
    /// Validates the direct C0-12 provider closure and fence alignment.
    pub fn validate(&self, state_fence: &StateFence) -> Result<(), StoreError> {
        for source in &self.source_assurance {
            source.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &source.state_fence)?;
        }
        if let Some(closure) = &self.disclosure_closure {
            closure.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &closure.state_fence)?;
        }
        for lineage in &self.transformation_lineage {
            lineage.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &lineage.state_fence)?;
        }
        if let Some(closure) = &self.influence_closure {
            closure.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &closure.state_fence)?;
        }
        if let Some(entry) = &self.purge_entry {
            entry.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &entry.state_fence)?;
        }
        if let Some(selection) = &self.selection_integrity {
            selection.validate().map_err(StoreError::Security)?;
            ensure_same_fence(state_fence, &selection.state_fence)?;
        }
        Ok(())
    }
}

/// Atomic event/projection/relation intent carried by one transaction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProjectionRelationIntents {
    pub event_ids: Vec<EventId>,
    pub projection_kinds: Vec<String>,
    pub relation_kinds: Vec<String>,
}

impl EventProjectionRelationIntents {
    /// Rejects duplicate identities and blank kind labels.
    pub fn validate(&self) -> Result<(), StoreError> {
        unique(self.event_ids.iter().cloned(), "event_ids")?;
        unique(self.projection_kinds.iter().cloned(), "projection_kinds")?;
        unique(self.relation_kinds.iter().cloned(), "relation_kinds")?;
        for value in self.projection_kinds.iter().chain(&self.relation_kinds) {
            validate_text(value, "relation_or_projection_kind")?;
        }
        Ok(())
    }
}

/// One named operation manifest entry.  Its digest binds the ceiling and
/// compatibility range to a prepared transition.
///
/// An entry describes exactly one operation: the operation identity in
/// `name`, its [`OperationKind`], the owning architecture section, the exact
/// parameter-schema revision and digest, the scope declaration, and the
/// compatibility range together with the input/output/timeout bounds. Read
/// entries persist no effect (`maximum_effect` is `Read`) and carry no
/// transition classes; a non-empty transition-class set is required only for
/// mutations. Entries hash without their own digest; the catalogue set digest
/// binds the ordered entries (see [`operation_manifest_set_digest`]).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedOperationManifest {
    pub name: String,
    pub version: ContractVersion,
    #[serde(default = "default_manifest_operation_kind")]
    pub operation_kind: OperationKind,
    #[serde(default)]
    pub owning_section: String,
    #[serde(default = "default_manifest_schema_revision")]
    pub schema_revision: ContractVersion,
    #[serde(default)]
    pub parameter_schema: Vec<ParameterSchemaField>,
    #[serde(default)]
    pub schema_digest: String,
    #[serde(default)]
    pub requires_scope_id: bool,
    #[serde(default)]
    pub scope_kind: String,
    #[serde(default = "default_manifest_minimum_compatible")]
    pub minimum_compatible_version: ContractVersion,
    pub transition_classes: Vec<TransitionClass>,
    pub maximum_effect: EffectClass,
    pub max_input_bytes: u32,
    pub max_output_bytes: u32,
    pub timeout_ms: u32,
    pub digest: OperationManifestDigest,
}

fn default_manifest_operation_kind() -> OperationKind {
    OperationKind::Mutation
}

fn default_manifest_schema_revision() -> ContractVersion {
    CONTRACT_VERSION
}

fn default_manifest_minimum_compatible() -> ContractVersion {
    ContractVersion::new(1, 0, 0)
}

/// Complete pre-digest construction spec for one manifest entry.
///
/// Every manifest, whether built through the legacy [`NamedOperationManifest::new`]
/// or generated from the operation catalogue table, flows through
/// [`NamedOperationManifest::from_spec`] so schema and entry digests are
/// derived in exactly one place.
#[derive(Clone, Debug)]
pub struct OperationManifestSpec {
    /// Canonical operation identity (a closed operation name).
    pub name: String,
    /// Manifest revision of this entry.
    pub version: ContractVersion,
    /// Whether this entry describes a read or a mutation.
    pub operation_kind: OperationKind,
    /// Owning architecture section for the operation's meaning.
    pub owning_section: String,
    /// Revision of the declared parameter schema.
    pub schema_revision: ContractVersion,
    /// Owner-approved parameter schema projection.
    pub parameter_schema: Vec<ParameterSchemaField>,
    /// Whether callers must address a scope for this operation.
    pub requires_scope_id: bool,
    /// Scope kind paired with `requires_scope_id` (`"none"` or `"scope"`).
    pub scope_kind: String,
    /// Oldest compatible manifest version.
    pub minimum_compatible_version: ContractVersion,
    /// Allowed transition families (empty for reads, non-empty for mutations).
    pub transition_classes: Vec<TransitionClass>,
    /// Maximum canonical effect (`Read` for read entries).
    pub maximum_effect: EffectClass,
    /// Maximum canonical input bytes.
    pub max_input_bytes: u32,
    /// Maximum canonical output bytes.
    pub max_output_bytes: u32,
    /// Admission timeout in milliseconds.
    pub timeout_ms: u32,
}

impl NamedOperationManifest {
    /// Builds a manifest from a complete spec and derives its digests.
    pub fn from_spec(spec: OperationManifestSpec) -> Result<Self, StoreError> {
        validate_text(&spec.name, "manifest.name")?;
        let schema_digest = parameter_schema_digest(&spec.parameter_schema)?;
        let mut manifest = Self {
            name: spec.name,
            version: spec.version,
            operation_kind: spec.operation_kind,
            owning_section: spec.owning_section,
            schema_revision: spec.schema_revision,
            parameter_schema: spec.parameter_schema,
            schema_digest,
            requires_scope_id: spec.requires_scope_id,
            scope_kind: spec.scope_kind,
            minimum_compatible_version: spec.minimum_compatible_version,
            transition_classes: spec.transition_classes,
            maximum_effect: spec.maximum_effect,
            max_input_bytes: spec.max_input_bytes,
            max_output_bytes: spec.max_output_bytes,
            timeout_ms: spec.timeout_ms,
            digest: OperationManifestDigest::new("pending")?,
        };
        let digest = manifest_digest(&manifest)?;
        manifest.digest = OperationManifestDigest::new(digest)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Builds a manifest and derives its canonical digest.
    ///
    /// Legacy single-manifest constructor retained for the genesis/bootstrap
    /// path and already-deployed single manifests. The catalogue-owned fields
    /// take neutral single-manifest values owned by the catalogue mechanism
    /// itself; per-operation entries are generated from the catalogue table.
    pub fn new(
        name: impl Into<String>,
        version: ContractVersion,
        transition_classes: Vec<TransitionClass>,
        maximum_effect: EffectClass,
        max_input_bytes: u32,
        max_output_bytes: u32,
        timeout_ms: u32,
    ) -> Result<Self, StoreError> {
        Self::from_spec(OperationManifestSpec {
            name: name.into(),
            version,
            operation_kind: OperationKind::Mutation,
            owning_section: SINGLE_MANIFEST_OWNING_SECTION.to_owned(),
            schema_revision: version,
            parameter_schema: Vec::new(),
            requires_scope_id: false,
            scope_kind: SCOPE_KIND_NONE.to_owned(),
            minimum_compatible_version: ContractVersion::new(1, 0, 0),
            transition_classes,
            maximum_effect,
            max_input_bytes,
            max_output_bytes,
            timeout_ms,
        })
    }

    /// Validates the closed manifest and its self-digest.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.name, "manifest.name")?;
        validate_text(&self.owning_section, "manifest.owning_section")?;
        if self.minimum_compatible_version > self.version {
            return Err(StoreError::InvalidField {
                field: "manifest.compatibility",
                reason: "minimum compatible version exceeds manifest version",
            });
        }
        match self.operation_kind {
            OperationKind::Read => {
                if !self.transition_classes.is_empty() {
                    return Err(StoreError::InvalidField {
                        field: "manifest.transition_classes",
                        reason: "read entries carry no transition class",
                    });
                }
                if self.maximum_effect != EffectClass::Read {
                    return Err(StoreError::InvalidField {
                        field: "manifest.maximum_effect",
                        reason: "read entries persist no effect",
                    });
                }
            }
            OperationKind::Mutation => {
                if self.transition_classes.is_empty() {
                    return Err(StoreError::Empty {
                        field: "manifest.transition_classes",
                    });
                }
                unique(
                    self.transition_classes.iter().copied(),
                    "manifest.transition_classes",
                )?;
                if self.maximum_effect == EffectClass::ExternalEffect {
                    return Err(StoreError::EffectCeilingExceeded);
                }
            }
        }
        let scope_pair_ok = (self.requires_scope_id && self.scope_kind == SCOPE_KIND_SCOPE)
            || (!self.requires_scope_id && self.scope_kind == SCOPE_KIND_NONE);
        if !scope_pair_ok {
            return Err(StoreError::InvalidField {
                field: "manifest.scope",
                reason: "scope declaration must pair requires_scope_id with its scope kind",
            });
        }
        if self.max_input_bytes == 0 || self.max_output_bytes == 0 || self.timeout_ms == 0 {
            return Err(StoreError::InvalidField {
                field: "manifest.limits",
                reason: "must be non-zero",
            });
        }
        validate_digest(&self.schema_digest, "manifest.schema_digest")?;
        let schema_digest = parameter_schema_digest(&self.parameter_schema)?;
        if self.schema_digest != schema_digest {
            return Err(StoreError::ManifestMismatch);
        }
        let digest = manifest_digest(self)?;
        if self.digest.as_str() != digest {
            return Err(StoreError::ManifestMismatch);
        }
        Ok(())
    }

    /// Returns whether this manifest admits the requested transition/ceiling.
    pub fn admits(&self, class: TransitionClass, effect: EffectClass) -> bool {
        self.transition_classes.contains(&class)
            && effect_is_at_most(effect, self.maximum_effect)
            && effect_is_at_most(effect, class.maximum_effect())
    }
}

fn manifest_digest(manifest: &NamedOperationManifest) -> Result<String, StoreError> {
    let shape = (
        &manifest.name,
        manifest.version,
        manifest.operation_kind,
        &manifest.owning_section,
        manifest.schema_revision,
        &manifest.parameter_schema,
        &manifest.schema_digest,
        manifest.requires_scope_id,
        &manifest.scope_kind,
        manifest.minimum_compatible_version,
        &manifest.transition_classes,
        manifest.maximum_effect,
        manifest.max_input_bytes,
        manifest.max_output_bytes,
        manifest.timeout_ms,
    );
    let bytes = canonical_json_bytes(&shape)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Canonical operation/idempotency identity used by retries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIdentity {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
}

impl OperationIdentity {
    /// Validates the identity without making it an authority token.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.idempotency_key, "idempotency_key")?;
        validate_digest(&self.canonical_request_hash, "canonical_request_hash")
    }
}

/// Immutable plan emitted by semantic admission and mechanically checked by
/// Kernel/store.  The store never constructs this from an untyped request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTransition {
    pub identity: OperationIdentity,
    pub state_fence: StateFence,
    pub scope_id: ScopeId,
    pub task_id: Option<String>,
    pub ordering_scopes: Vec<OrderingScopeId>,
    pub transition_class: TransitionClass,
    pub requested_effect_ceiling: EffectClass,
    pub admission_contract_set_digest: String,
    pub operation_manifest_digest: OperationManifestDigest,
    pub named_operations: Vec<NamedMutationRequest>,
    pub event_projection_relation_intents: EventProjectionRelationIntents,
    pub security: SecurityContext,
    pub required_proof_and_approval_refs: Vec<String>,
}

impl PreparedTransition {
    /// Validates identity, operation closure, fences and effect ceilings.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.identity.validate()?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        self.scope_id.as_str();
        if let Some(task_id) = &self.task_id {
            validate_text(task_id, "task_id")?;
        }
        if self.ordering_scopes.is_empty() {
            return Err(StoreError::Empty {
                field: "ordering_scopes",
            });
        }
        unique(self.ordering_scopes.iter().cloned(), "ordering_scopes")?;
        if !effect_is_at_most(
            self.requested_effect_ceiling,
            self.transition_class.maximum_effect(),
        ) {
            return Err(StoreError::TransitionClassExceeded);
        }
        // Issue #1712: erasure travels under exactly one operation identity.
        // Bundling the irreversible deletion with any other command (or
        // splitting it across commands) is rejected pre-execution, and the
        // plan must carry the explicit user approval handles: automatic
        // maintenance, curation, Dreamer, and scheduler paths furnish none,
        // so they can never reach the erasure transaction.
        if self.transition_class == TransitionClass::Erasure {
            if self.named_operations.len() != 1 {
                return Err(StoreError::TransitionClassExceeded);
            }
            if self.required_proof_and_approval_refs.is_empty() {
                return Err(StoreError::InvalidField {
                    field: "proof_or_approval_ref",
                    reason: "erasure requires explicit user approval",
                });
            }
        }
        validate_digest(
            &self.admission_contract_set_digest,
            "admission_contract_set_digest",
        )?;
        self.event_projection_relation_intents.validate()?;
        unique(
            self.required_proof_and_approval_refs.iter().cloned(),
            "proof_and_approval_refs",
        )?;
        for reference in &self.required_proof_and_approval_refs {
            validate_text(reference, "proof_or_approval_ref")?;
        }
        unique(
            self.named_operations
                .iter()
                .map(|operation| operation.operation),
            "named_operations",
        )?;
        for operation in &self.named_operations {
            operation.validate()?;
            if operation.operation.transition_class() != self.transition_class {
                return Err(StoreError::TransitionClassExceeded);
            }
        }
        self.security.validate(&self.state_fence)
    }

    /// Checks this plan against a closed named-operation manifest.
    ///
    /// Bootstrap/single-manifest check retained for the genesis path and
    /// already-deployed single manifests. Named operations validate against
    /// the generated catalogue set instead (see
    /// [`PreparedTransition::validate_against_catalogue`]); both mechanisms
    /// derive from the same generated table, so there are no competing
    /// manifest authorities.
    pub fn validate_against_manifest(
        &self,
        manifest: &NamedOperationManifest,
    ) -> Result<(), StoreError> {
        self.validate()?;
        manifest.validate()?;
        if self.operation_manifest_digest != manifest.digest {
            return Err(StoreError::ManifestMismatch);
        }
        if !manifest.admits(self.transition_class, self.requested_effect_ceiling) {
            return Err(StoreError::TransitionClassExceeded);
        }
        Ok(())
    }

    /// Checks this plan against a generated operation catalogue set.
    ///
    /// Pre-dispatch authority for prepared transitions: the genesis/bootstrap
    /// shape binds to the genesis entry, while a plan carrying named
    /// operations binds to the whole set digest with every command resolved
    /// in order against a mutation entry. Plan commands are never reordered.
    pub fn validate_against_catalogue(
        &self,
        entries: &[NamedOperationManifest],
    ) -> Result<(), StoreError> {
        operation_catalogue::validate_transition_against_catalogue(self, entries)
    }
}

/// Builds the one provider-independent manifest admitted for Store genesis.
/// The digest is derived from the complete manifest shape and is shared by
/// every adapter; no provider name or zero digest is accepted as a substitute.
///
/// The entry is sourced from the generated operation catalogue
/// ([`generated_operation_manifests`]), so the genesis path and the named
/// operation catalogue share one authority.
pub fn genesis_manifest() -> Result<NamedOperationManifest, StoreError> {
    generated_operation_manifests()?
        .into_iter()
        .find(|entry| entry.name == GENESIS_MANIFEST_NAME)
        .ok_or(StoreError::UnknownOperation)
}

/// Derives the canonical neutral transition used to issue and validate every
/// genesis receipt. The fixed scope/order values exist only because the
/// universal `ReceiptCore` requires them: they are not a Governor `WorkScope`
/// and must never be persisted or advanced as a revision/order head.
pub fn genesis_transition(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
) -> Result<PreparedTransition, StoreError> {
    request.validate_for_context(context)?;
    let manifest = genesis_manifest()?;
    let transition = PreparedTransition {
        identity: OperationIdentity {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_hash: request.canonical_request_hash.clone(),
        },
        state_fence: request.state_fence.clone(),
        scope_id: ScopeId::new(GENESIS_RECEIPT_SCOPE_ID)?,
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(GENESIS_RECEIPT_ORDERING_SCOPE)?],
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: manifest.digest.as_str().to_owned(),
        operation_manifest_digest: manifest.digest.clone(),
        named_operations: Vec::new(),
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition.validate_against_manifest(&manifest)?;
    Ok(transition)
}

/// Projection publication status, with explicit lag and split-view states.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionStatus {
    Pending,
    Current,
    Stale,
    Failed,
    Inconclusive,
}

/// Projection update strategy.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionMode {
    Full,
    Delta,
    ReferenceFallback,
}

/// Split-view marker for a projection publication.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SplitView {
    None,
    Detected,
    Reconciling,
}

/// A same-fence publication record for a rebuildable projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionPublicationRecord {
    pub publication_id: ProjectionPublicationId,
    pub projection_kind: String,
    pub projection_generation: u64,
    pub source_generation: u64,
    pub source_cursor: u64,
    pub state_fence: StateFence,
    pub mode: ProjectionMode,
    pub source_revision_heads: Vec<RevisionHead>,
    pub atomic_data_commit: CommitId,
    pub provenance_manifest_ref: String,
    pub visible_lag_checkpoint: Option<String>,
    pub split_view: SplitView,
    pub status: ProjectionStatus,
}

impl ProjectionPublicationRecord {
    /// Validates publication identity and same-fence source heads.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.projection_kind, "projection_kind")?;
        validate_text(&self.provenance_manifest_ref, "provenance_manifest_ref")?;
        if self.projection_generation == 0 || self.source_generation == 0 {
            return Err(StoreError::InvalidField {
                field: "projection_generation",
                reason: "must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        unique(
            self.source_revision_heads
                .iter()
                .map(|head| head.key.clone()),
            "source_revision_heads",
        )?;
        for head in &self.source_revision_heads {
            head.validate()?;
            ensure_same_fence(&self.state_fence, &head.state_fence)?;
        }
        if matches!(self.status, ProjectionStatus::Current)
            && matches!(
                self.split_view,
                SplitView::Detected | SplitView::Reconciling
            )
        {
            return Err(StoreError::InvalidProjection);
        }
        Ok(())
    }
}

/// Durable outbox delivery state.  Sender commit is not sink acceptance.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutboxState {
    Arrived,
    Claimed,
    Applied,
    Rejected,
    Unknown,
    ReadbackConfirmed,
    Irreconcilable,
}

/// One atomic outbox intent linked to the canonical transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxIntent {
    pub outbox_id: OutboxId,
    pub operation_id: OperationId,
    pub sequence: u64,
    pub payload_digest: String,
    pub state_fence: StateFence,
    pub arrival_fence: String,
    pub claim_fence: Option<String>,
    pub state: OutboxState,
}

impl OutboxIntent {
    /// Validates delivery identity and prevents fabricated sink confirmation.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "outbox.sequence",
                reason: "must be non-zero",
            });
        }
        validate_digest(&self.payload_digest, "outbox.payload_digest")?;
        validate_text(&self.arrival_fence, "outbox.arrival_fence")?;
        if matches!(
            self.state,
            OutboxState::Claimed | OutboxState::Applied | OutboxState::ReadbackConfirmed
        ) && self.claim_fence.is_none()
        {
            return Err(StoreError::InvalidOutbox);
        }
        self.state_fence.validate().map_err(StoreError::Foundation)
    }
}

/// Terminal canonical receipt status.  ORS transient states do not cross this
/// boundary as receipt statuses.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WriteReceiptStatus {
    Committed,
    Rejected,
    DeadLetter,
    Cancelled,
}

/// Resubmission disposition for a terminal receipt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Resubmission {
    None,
    NewIdentityAfterCondition,
}

/// One revision change committed by a transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionDelta {
    pub key: RevisionKey,
    pub before: u64,
    pub after: u64,
}

/// Immutable canonical write receipt.  It proves durable store transport only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteReceipt {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub transition_class: TransitionClass,
    pub status: WriteReceiptStatus,
    pub commit_id: Option<CommitId>,
    pub state_fence: StateFence,
    pub ordering_sequences: Vec<OrderingHead>,
    pub revision_before_after: Vec<RevisionDelta>,
    pub applied_command_ids: Vec<String>,
    pub emitted_event_ids: Vec<EventId>,
    pub projection_refs: Vec<ProjectionPublicationId>,
    pub outbox_refs: Vec<OutboxId>,
    pub operation_manifest_digest: OperationManifestDigest,
    pub error_code: Option<ErrorCode>,
    pub resubmission: Resubmission,
    pub committed_at: Option<String>,
    pub envelope: Option<ReceiptEnvelope>,
}

impl WriteReceipt {
    /// Validates terminal status/error and identity invariants.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.idempotency_key, "idempotency_key")?;
        validate_digest(&self.canonical_request_hash, "canonical_request_hash")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        unique(
            self.ordering_sequences
                .iter()
                .map(|head| head.scope.clone()),
            "ordering_sequences",
        )?;
        for head in &self.ordering_sequences {
            head.validate()?;
            ensure_same_fence(&self.state_fence, &head.state_fence)?;
        }
        unique(
            self.revision_before_after
                .iter()
                .map(|delta| delta.key.clone()),
            "revision_before_after",
        )?;
        for delta in &self.revision_before_after {
            if delta.before == 0 || delta.after == 0 || delta.after <= delta.before {
                return Err(StoreError::InvalidField {
                    field: "revision_before_after",
                    reason: "must advance non-zero revision",
                });
            }
        }
        unique(
            self.applied_command_ids.iter().cloned(),
            "applied_command_ids",
        )?;
        unique(self.emitted_event_ids.iter().cloned(), "emitted_event_ids")?;
        unique(self.projection_refs.iter().cloned(), "projection_refs")?;
        unique(self.outbox_refs.iter().cloned(), "outbox_refs")?;
        let terminal_error = matches!(
            self.status,
            WriteReceiptStatus::Rejected
                | WriteReceiptStatus::DeadLetter
                | WriteReceiptStatus::Cancelled
        );
        if terminal_error != self.error_code.is_some() {
            return Err(StoreError::InvalidReceipt);
        }
        if self.status == WriteReceiptStatus::Committed {
            if self.commit_id.is_none() || self.committed_at.is_none() {
                return Err(StoreError::InvalidReceipt);
            }
            if self.applied_command_ids.is_empty() {
                return Err(StoreError::InvalidReceipt);
            }
        }
        if let Some(at) = &self.committed_at {
            validate_text(at, "committed_at")?;
        }
        if let Some(envelope) = &self.envelope {
            envelope.validate().map_err(StoreError::Receipt)?;
            if envelope.core.operation.operation_id != self.operation_id
                || envelope.core.operation.idempotency_key != self.idempotency_key
                || envelope.core.request.state_fence != self.state_fence
                || envelope.core.operation.state_fence != self.state_fence
            {
                return Err(StoreError::InvalidReceipt);
            }
        }
        Ok(())
    }

    /// Requires the signed receipt envelope used by Kernel reconciliation.
    /// A transport receipt without this envelope is explicitly unknown to the
    /// reconciler and must never be reported as a successful write.
    pub fn require_reconciliation_envelope(&self) -> Result<&ReceiptEnvelope, StoreError> {
        self.envelope
            .as_ref()
            .ok_or(StoreError::MissingReceiptEnvelope)
    }
}

/// Issues the one store-owned receipt envelope for a planned committed write.
///
/// The adapters call this after deriving the complete top-level receipt and
/// before sending their atomic transaction.  The envelope binds the exact
/// request metadata, prepared transition, derived plan fields and durable
/// commit sequence.  No caller-provided envelope is accepted, and no clock or
/// environment value is consulted while issuing it.
pub fn issue_store_receipt_envelope(
    context: &RequestMeta,
    transition: &PreparedTransition,
    receipt: &WriteReceipt,
    commit_sequence: u64,
) -> Result<ReceiptEnvelope, StoreError> {
    validate_receipt_inputs(context, transition, receipt, commit_sequence)?;

    let state_fence = context.state_fence.clone();
    let task = receipt_task(context, transition, &state_fence)?;
    let session = receipt_session(context, &state_fence);
    let artifacts = receipt_artifacts(transition, receipt, commit_sequence)?;
    let operation_id = transition.identity.operation_id.clone();
    let operation_kind = operation_kind(transition.transition_class);
    let proof_ceiling = proof_ceiling_for(transition.requested_effect_ceiling);

    ReceiptEnvelope::issue(ReceiptCore {
        contract: receipt_contract_identity().map_err(StoreError::Receipt)?,
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id: eliot_receipts::WorkScopeId::new(transition.scope_id.to_string())
                .map_err(StoreError::Receipt)?,
            product_id: context.product_id.clone(),
            resource_generation: state_fence.resource_generation,
            state_fence: state_fence.clone(),
        },
        task,
        session,
        causal: CausalBinding {
            state_fence: state_fence.clone(),
            // Store commit order is bound by the plan artifact above.  The
            // receipt causal chain remains a valid genesis chain because the
            // current store plan has no authoritative predecessor receipt id.
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata: context.clone(),
            state_fence: state_fence.clone(),
        },
        operation: OperationBinding {
            operation_id,
            request_id: context.request_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            operation_kind: operation_kind.to_owned(),
            effect: transition.requested_effect_ceiling,
            state_fence: state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new(format!(
                "eliot-store-manifest:{}",
                transition.operation_manifest_digest
            ))
            .map_err(StoreError::Foundation)?,
            authority_owner: context.source_id.to_string(),
            authority_epoch: state_fence.authority_epoch.clone(),
            state_fence: state_fence.clone(),
            allowed_effect: transition.requested_effect_ceiling,
            proof_ceiling,
        },
        artifacts,
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: proof_ceiling,
        },
    })
    .map_err(StoreError::Receipt)
}

/// Issues the canonical Store-owned envelope for a genesis receipt. Adapter
/// implementations supply only durable commit identity/sequence fields; the
/// manifest, transition class, neutral `ReceiptCore` scope and authority
/// binding all come from [`genesis_transition`].
pub fn issue_genesis_receipt_envelope(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
    receipt: &WriteReceipt,
    commit_sequence: u64,
) -> Result<ReceiptEnvelope, StoreError> {
    let transition = genesis_transition(context, request)?;
    validate_genesis_receipt_shape(receipt)?;
    receipt.validate()?;
    issue_store_receipt_envelope(context, &transition, receipt, commit_sequence)
}

/// Validates a recovered genesis receipt against the canonical neutral
/// transition and its exact Store-owned envelope.
pub fn validate_genesis_receipt_envelope(
    context: &RequestMeta,
    request: &StoreGenesisRequest,
    receipt: &WriteReceipt,
) -> Result<(), StoreError> {
    let transition = genesis_transition(context, request)?;
    validate_genesis_receipt_shape(receipt)?;
    receipt.validate()?;
    validate_store_receipt_envelope(context, &transition, receipt)
}

fn validate_genesis_receipt_shape(receipt: &WriteReceipt) -> Result<(), StoreError> {
    if receipt.transition_class != TransitionClass::RecoverySchema {
        return Err(StoreError::InvalidField {
            field: "transition_class",
            reason: "genesis receipt must use RecoverySchema",
        });
    }
    if receipt.ordering_sequences.is_empty()
        && receipt.revision_before_after.is_empty()
        && receipt.emitted_event_ids.is_empty()
        && receipt.projection_refs.is_empty()
        && receipt.outbox_refs.is_empty()
    {
        Ok(())
    } else {
        Err(StoreError::InvalidField {
            field: "genesis.receipt",
            reason: "genesis receipt must not imply revision/order or side effects",
        })
    }
}

fn validate_receipt_inputs(
    context: &RequestMeta,
    transition: &PreparedTransition,
    receipt: &WriteReceipt,
    commit_sequence: u64,
) -> Result<(), StoreError> {
    context.validate().map_err(StoreError::Foundation)?;
    transition.validate()?;
    if receipt.envelope.is_some() {
        return Err(StoreError::InvalidReceipt);
    }
    let expected_committed_at = format!("commit-sequence-{commit_sequence:016}");
    let identity_matches = context.state_fence == transition.state_fence
        && context.state_fence == receipt.state_fence
        && receipt.operation_id == transition.identity.operation_id
        && receipt.idempotency_key == transition.identity.idempotency_key
        && receipt.canonical_request_hash == transition.identity.canonical_request_hash
        && receipt.transition_class == transition.transition_class
        && receipt.operation_manifest_digest == transition.operation_manifest_digest
        && receipt.status == WriteReceiptStatus::Committed
        && receipt.commit_id.is_some()
        && receipt.committed_at.as_deref() == Some(expected_committed_at.as_str())
        && transition.task_id.as_deref()
            == context
                .task_id
                .as_ref()
                .map(eliot_contracts::TaskId::as_str);
    if identity_matches {
        Ok(())
    } else {
        Err(StoreError::InvalidReceipt)
    }
}

fn receipt_task(
    context: &RequestMeta,
    transition: &PreparedTransition,
    state_fence: &StateFence,
) -> Result<Option<TaskBinding>, StoreError> {
    if transition.task_id.as_deref()
        != context
            .task_id
            .as_ref()
            .map(eliot_contracts::TaskId::as_str)
    {
        return Err(StoreError::InvalidReceipt);
    }
    // Epistemic admission carries its exact task revision in the frozen
    // payload. The daemon generation fence may deliberately be unscoped;
    // do not substitute the independently advancing Store/position revision.
    let task_revision =
        match epistemic_revision::EpistemicCommit::from_prepared(context, transition)? {
            Some(commit) => {
                let revision = commit.payload.candidate.revision;
                if state_fence
                    .task_revision
                    .is_some_and(|bound| bound != revision)
                {
                    return Err(StoreError::InvalidReceipt);
                }
                Some(revision)
            }
            None => state_fence.task_revision,
        };
    match (&context.task_id, task_revision) {
        (Some(task_id), Some(task_revision)) => Ok(Some(TaskBinding {
            task_id: task_id.clone(),
            task_revision,
            state_fence: state_fence.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(StoreError::InvalidReceipt),
    }
}

fn receipt_session(context: &RequestMeta, state_fence: &StateFence) -> Option<SessionBinding> {
    context.session_id.clone().map(|session_id| SessionBinding {
        session_id,
        authority_epoch: state_fence.authority_epoch.clone(),
        state_fence: state_fence.clone(),
    })
}

fn receipt_artifacts(
    transition: &PreparedTransition,
    receipt: &WriteReceipt,
    commit_sequence: u64,
) -> Result<Vec<ArtifactBinding>, StoreError> {
    let transition_digest = digest_for_receipt(transition)?;
    let plan_digest = digest_for_receipt(&(
        &receipt.commit_id,
        commit_sequence,
        &receipt.ordering_sequences,
        &receipt.revision_before_after,
        &receipt.applied_command_ids,
        &receipt.emitted_event_ids,
        &receipt.projection_refs,
        &receipt.outbox_refs,
        &receipt.operation_manifest_digest,
        &receipt.committed_at,
    ))?;
    let operation_id = transition.identity.operation_id.clone();
    let commit_id = receipt
        .commit_id
        .as_ref()
        .ok_or(StoreError::InvalidReceipt)?;
    Ok(vec![
        ArtifactBinding {
            artifact_id: ArtifactId::new(format!("store-transition:{operation_id}"))
                .map_err(StoreError::Foundation)?,
            sha256: transition_digest,
            role: ReceiptKind::Operation,
            source_revision: Some(transition.operation_manifest_digest.to_string()),
        },
        ArtifactBinding {
            artifact_id: ArtifactId::new(format!("store-plan:{commit_id}"))
                .map_err(StoreError::Foundation)?,
            sha256: plan_digest,
            role: ReceiptKind::Artifact,
            source_revision: Some(format!("commit-sequence-{commit_sequence:016}")),
        },
    ])
}

fn operation_kind(class: TransitionClass) -> &'static str {
    match class {
        TransitionClass::CaptureCandidate => "store.apply.capture_candidate",
        TransitionClass::Epistemic => "store.apply.epistemic",
        TransitionClass::TaskControl => "store.apply.task_control",
        TransitionClass::LifecyclePolicy => "store.apply.lifecycle_policy",
        TransitionClass::RecoverySchema => "store.apply.recovery_schema",
        TransitionClass::Erasure => "store.apply.erasure",
    }
}

/// Rebuilds the store-owned envelope from a durable receipt and rejects any
/// substitution, duplicate or payload/hash mismatch observed during replay.
///
/// The commit sequence is recovered only from the receipt's deterministic
/// `committed_at` marker; malformed markers fail closed rather than falling
/// back to a clock, environment or caller value.
pub fn validate_store_receipt_envelope(
    context: &RequestMeta,
    transition: &PreparedTransition,
    receipt: &WriteReceipt,
) -> Result<(), StoreError> {
    let commit_sequence = receipt_commit_sequence(receipt)?;
    let mut candidate = receipt.clone();
    candidate.envelope = None;
    let expected = issue_store_receipt_envelope(context, transition, &candidate, commit_sequence)?;
    match receipt.envelope.as_ref() {
        Some(actual) if actual == &expected => Ok(()),
        Some(_) => Err(StoreError::InvalidReceipt),
        None => Err(StoreError::MissingReceiptEnvelope),
    }
}

fn receipt_commit_sequence(receipt: &WriteReceipt) -> Result<u64, StoreError> {
    let value = receipt
        .committed_at
        .as_deref()
        .and_then(|value| value.strip_prefix("commit-sequence-"))
        .ok_or(StoreError::InvalidReceipt)?;
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StoreError::InvalidReceipt);
    }
    value.parse().map_err(|_| StoreError::InvalidReceipt)
}

fn digest_for_receipt<T: Serialize>(value: &T) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn proof_ceiling_for(effect: EffectClass) -> ProofCeiling {
    match effect {
        EffectClass::Read => ProofCeiling::Observation,
        EffectClass::Candidate => ProofCeiling::CandidateArtifact,
        EffectClass::ReversibleMutation => ProofCeiling::ScopedVerification,
        EffectClass::ExternalEffect => ProofCeiling::ObservedExternalEffect,
    }
}

/// Full transaction intent.  Implementations must commit all members or none.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreTransaction {
    pub transition: PreparedTransition,
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pub projections: Vec<ProjectionPublicationRecord>,
    pub outbox: Vec<OutboxIntent>,
}

impl StoreTransaction {
    /// Validates atomicity, identity uniqueness and expected fence alignment.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.transition.validate()?;
        unique(
            self.expected_revision_heads
                .iter()
                .map(|head| head.key.clone()),
            "expected_revision_heads",
        )?;
        unique(
            self.expected_ordering_heads
                .iter()
                .map(|head| head.scope.clone()),
            "expected_ordering_heads",
        )?;
        for head in &self.expected_revision_heads {
            head.validate()?;
            ensure_same_fence(&self.transition.state_fence, &head.state_fence)?;
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
            ensure_same_fence(&self.transition.state_fence, &head.state_fence)?;
        }
        for projection in &self.projections {
            projection.validate()?;
            ensure_same_fence(&self.transition.state_fence, &projection.state_fence)?;
        }
        for outbox in &self.outbox {
            outbox.validate()?;
            ensure_same_fence(&self.transition.state_fence, &outbox.state_fence)?;
        }
        Ok(())
    }
}

/// Store health is an observation, not a semantic readiness/authority verdict.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StoreHealthStatus {
    Ready,
    Degraded,
    Unavailable,
}

/// Bounded store health response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreHealth {
    pub status: StoreHealthStatus,
    pub contract_version: ContractVersion,
    pub manifest_digest: OperationManifestDigest,
}

impl StoreHealth {
    /// Validates the neutral health identity before it crosses the wire.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(StoreError::InvalidField {
                field: "contract_version",
                reason: "does not match the store API contract",
            });
        }
        self.manifest_digest.as_str();
        Ok(())
    }
}

/// Store API failure without provider or secret payloads.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("empty field {field}")]
    Empty { field: &'static str },
    #[error("duplicate values in {field}")]
    Duplicate { field: &'static str },
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    #[error("security contract: {0}")]
    Security(eliot_security_contracts::SecurityContractError),
    #[error("receipt contract: {0}")]
    Receipt(eliot_receipts::ReceiptError),
    #[error("unknown named operation")]
    UnknownOperation,
    #[error("operation manifest digest mismatch")]
    ManifestMismatch,
    #[error("transition class ceiling exceeded")]
    TransitionClassExceeded,
    #[error("effect ceiling exceeded")]
    EffectCeilingExceeded,
    #[error("state fence mismatch")]
    FenceMismatch,
    #[error("revision conflict")]
    RevisionConflict,
    #[error("ordering conflict")]
    OrderingConflict,
    #[error("invalid projection publication")]
    InvalidProjection,
    #[error("invalid outbox intent")]
    InvalidOutbox,
    #[error("invalid terminal receipt")]
    InvalidReceipt,
    #[error("identity conflict")]
    IdentityConflict,
    #[error("transition digest mismatch: expected {expected}, observed {observed}")]
    TransitionDigestMismatch {
        /// Claimed digest, bounded to [`MAX_DIGEST_DETAIL_CHARS`] characters.
        expected: String,
        /// Recomputed digest, bounded to [`MAX_DIGEST_DETAIL_CHARS`] characters.
        observed: String,
    },
    #[error("receipt not found")]
    ReceiptNotFound,
    #[error("receipt envelope is missing; write outcome is unknown")]
    MissingReceiptEnvelope,
    #[error("payload exceeds named-operation limit")]
    PayloadTooLarge,
    #[error("store unavailable")]
    Unavailable,
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

/// Closed canonical store surfaces covered by one erasure intent (issue #688).
///
/// These are the only surfaces the neutral store port addresses. They restate
/// the I05-14 retention-and-erasure enumeration in store-neutral vocabulary
/// without importing the erasure orchestration crate: the orchestration layer
/// depends on this neutral port, never the reverse. Declaration order is the
/// deterministic canonical order.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ErasureSurfaceKind {
    /// Observations and canonical payload.
    Observations,
    /// Projections, indexes and derived material.
    Projections,
    /// Caches, ORS copies, checkpoints and pending transitions.
    Caches,
    /// Backups, snapshots and restore-suppression state.
    Backups,
    /// Provider-side copies.
    ProviderCopies,
    /// Route residues and logs.
    RouteResidues,
}

/// Durable neutral erasure intent recorded before any destructive dispatch.
///
/// The store never invents this record: it carries the stable operation
/// identity, the digest binding the exact admitted request bytes, the subject,
/// the surface plan in deterministic canonical order, and the
/// policy/closure/fence binding. Every planned surface starts `NotAttempted`
/// (see [`ErasureIntentRecord::initial_state`]) and advances only through
/// owner-reported [`ErasureSurfaceOutcome`] values aggregated by
/// [`aggregate_erasure_outcomes`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureIntentRecord {
    pub operation_id: OperationId,
    pub request_digest: String,
    pub subject: String,
    pub surfaces: Vec<ErasureSurfaceKind>,
    pub policy_digest: String,
    pub closure_digest: String,
    pub state_fence: StateFence,
}

impl ErasureIntentRecord {
    /// Validates the frozen intent without performing any destructive effect.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(self.operation_id.as_str(), "erasure.operation_id")?;
        validate_digest(&self.request_digest, "erasure.request_digest")?;
        validate_text(&self.subject, "erasure.subject")?;
        if self.surfaces.is_empty() {
            return Err(StoreError::Empty {
                field: "erasure.surfaces",
            });
        }
        let mut seen = BTreeSet::new();
        for surface in &self.surfaces {
            if !seen.insert(*surface) {
                return Err(StoreError::Duplicate {
                    field: "erasure.surfaces",
                });
            }
        }
        if self.surfaces.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(StoreError::InvalidField {
                field: "erasure.surfaces",
                reason: "must be deterministic canonical surface order",
            });
        }
        validate_digest(&self.policy_digest, "erasure.policy_digest")?;
        validate_digest(&self.closure_digest, "erasure.closure_digest")?;
        self.state_fence.validate().map_err(StoreError::Foundation)
    }

    /// Returns the NotAttempted-per-surface initial state in canonical order.
    ///
    /// This is the only state a freshly recorded intent may carry: no surface
    /// is attempted before the intent is durable.
    #[must_use]
    pub fn initial_state(&self) -> Vec<(ErasureSurfaceKind, StoreMutationDisposition)> {
        self.surfaces
            .iter()
            .map(|surface| (*surface, StoreMutationDisposition::NotAttempted))
            .collect()
    }
}

/// Per-surface erasure outcome reported by the owning surface.
///
/// Mirrors the `{Purged, Incomplete, Unknown}` domain: `Purged` proves removal
/// of the named surface, while `Incomplete` and `Unknown` preserve the surface
/// that must block a complete result. An `Unknown` surface keeps its possible
/// effect explicit so the same operation is reconciled before retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ErasureSurfaceOutcome {
    Purged { surface: ErasureSurfaceKind },
    Incomplete { surface: ErasureSurfaceKind },
    Unknown { surface: ErasureSurfaceKind },
}

impl ErasureSurfaceOutcome {
    /// Returns the surface this outcome reports on.
    #[must_use]
    pub const fn surface(self) -> ErasureSurfaceKind {
        match self {
            Self::Purged { surface } | Self::Incomplete { surface } | Self::Unknown { surface } => {
                surface
            }
        }
    }
}

/// Fail-closed aggregation over per-surface erasure outcomes.
///
/// Returns the committed surfaces in deterministic canonical order only when
/// every planned surface reports [`ErasureSurfaceOutcome::Purged`] with no
/// extras and no duplicates. Any `Unknown` surface refuses with
/// [`ErasureFailureKind::Unknown`], which takes precedence over
/// [`ErasureFailureKind::Incomplete`]; any `Incomplete` surface — including an
/// empty, duplicate, misordered, missing, extra, or duplicated outcome entry —
/// refuses with `Incomplete`. Either refusal must prevent a complete purge
/// result; callers never map these refusals to success.
#[must_use = "an erasure refusal must never be dropped"]
pub fn aggregate_erasure_outcomes(
    planned: &[ErasureSurfaceKind],
    outcomes: &[ErasureSurfaceOutcome],
) -> Result<Vec<ErasureSurfaceKind>, ErasureFailureKind> {
    if planned.is_empty() {
        return Err(ErasureFailureKind::Incomplete);
    }
    let mut seen = BTreeSet::new();
    for surface in planned {
        if !seen.insert(*surface) {
            return Err(ErasureFailureKind::Incomplete);
        }
    }
    if planned.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(ErasureFailureKind::Incomplete);
    }
    let mut by_surface = BTreeMap::new();
    for outcome in outcomes {
        if by_surface.insert(outcome.surface(), *outcome).is_some() {
            return Err(ErasureFailureKind::Incomplete);
        }
    }
    if by_surface.len() != planned.len() {
        return Err(ErasureFailureKind::Incomplete);
    }
    for surface in planned {
        if !by_surface.contains_key(surface) {
            return Err(ErasureFailureKind::Incomplete);
        }
    }
    if by_surface
        .values()
        .any(|outcome| matches!(outcome, ErasureSurfaceOutcome::Unknown { .. }))
    {
        return Err(ErasureFailureKind::Unknown);
    }
    if by_surface
        .values()
        .any(|outcome| matches!(outcome, ErasureSurfaceOutcome::Incomplete { .. }))
    {
        return Err(ErasureFailureKind::Incomplete);
    }
    Ok(planned.to_vec())
}

/// Canonical store boundary.  Only these store-neutral types cross into an
/// adapter; SDK/query/credential/table types remain adapter-private.
#[allow(async_fn_in_trait)]
pub trait CanonicalStoreClient: Send + Sync {
    /// Atomically applies one prepared transition and its expected heads.
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError>;

    /// Reads one bounded, same-fence recovery snapshot. Wave 1 keeps the
    /// provider/state implementation out of this neutral contract crate.
    async fn recovery(
        &self,
        request: StoreRecoveryRequest,
    ) -> Result<StoreRecoverySnapshot, StoreError> {
        request.validate()?;
        Err(StoreError::Unavailable)
    }

    /// Atomically seeds an all-absent store genesis state. Wave 1 only
    /// defines the contract; adapters may opt in when state support lands.
    async fn initialize_genesis(
        &self,
        context: &RequestMeta,
        request: StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        request.validate_for_context(context)?;
        Err(StoreError::Unavailable)
    }

    /// Resolves a final receipt by operation identity.
    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError>;
    /// Reads revision heads by stable key.
    async fn revision_heads(&self, keys: Vec<RevisionKey>)
    -> Result<Vec<RevisionHead>, StoreError>;
    /// Reads one coherent store fence/revision validation snapshot.
    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError>;
    /// Reads a rebuildable scope revision view.
    async fn scope_revision_view(&self, scope_id: ScopeId)
    -> Result<ScopeRevisionView, StoreError>;
    /// Reads ordering heads for declared conflict scopes.
    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError>;
    /// Executes one closed named read; raw query strings are impossible here.
    async fn execute_named(&self, query: NamedReadRequest)
    -> Result<NamedReadResponse, StoreError>;
    /// Reports bounded store health and active manifest identity.
    async fn health(&self) -> Result<StoreHealth, StoreError>;
    /// Applies one closed Dreamer ledger operation (S0 named family).
    ///
    /// The default body validates the K0 request shape and then refuses with
    /// [`StoreError::Unavailable`] without manufacturing durable evidence.
    /// Unadvertised per-operation capabilities fail as
    /// [`StoreError::UnknownOperation`] through the K0 role check; no
    /// successful default body exists. Real persistence lands in S1 (#775).
    async fn dreamer_job(
        &self,
        ctx: &RequestMeta,
        request: eliot_protocol::dreamer_job::DurableJobRequest,
    ) -> Result<eliot_protocol::dreamer_job::DurableJobResponse, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        request.validate().map_err(map_durable_error)?;
        if ctx.state_fence != request.request_identity.operation.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        Err(StoreError::Unavailable)
    }
}

/// Narrow read-only capability over the canonical store boundary.
///
/// Read-only consumers (notably the Governor `ReadService`) depend on this
/// trait instead of the full [`CanonicalStoreClient`] write capability. The
/// two methods carry the exact signatures and fail-closed semantics of the
/// matching [`CanonicalStoreClient`] declarations: `revision_heads` reads
/// revision heads by stable key, and `execute_named` executes one closed
/// named read (raw query strings remain impossible here).
#[allow(async_fn_in_trait)]
pub trait CanonicalReadClient: Send + Sync {
    /// Reads revision heads by stable key.
    async fn revision_heads(&self, keys: Vec<RevisionKey>)
    -> Result<Vec<RevisionHead>, StoreError>;
    /// Executes one closed named read; raw query strings are impossible here.
    async fn execute_named(&self, query: NamedReadRequest)
    -> Result<NamedReadResponse, StoreError>;
}

/// Every full store client satisfies the narrow read capability.
///
/// This blanket implementation delegates to the matching
/// [`CanonicalStoreClient`] read declarations, which are retained so the
/// existing cross-lane `impl CanonicalStoreClient for EbpCanonicalStoreClient`
/// keeps compiling untouched (blanket impl instead of declaration removal).
impl<T: CanonicalStoreClient + ?Sized> CanonicalReadClient for T {
    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        CanonicalStoreClient::revision_heads(self, keys).await
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        CanonicalStoreClient::execute_named(self, query).await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, ResourceGeneration};

    fn test_epoch(sequence: u64) -> EpochId {
        use eliot_contracts::EpochLineageId;
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    fn id(value: &str) -> Result<OperationId, StoreError> {
        OperationId::new(value).map_err(StoreError::Foundation)
    }

    fn validation_snapshot() -> Result<CanonicalValidationSnapshot, StoreError> {
        Ok(CanonicalValidationSnapshot {
            state_fence: fence(),
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new("scope:one")?,
                revision: 1,
                state_fence: fence(),
            }],
            validation_revision: 2,
            observed_at_unix_ms: 1_000,
        })
    }

    #[test]
    fn manifest_digest_is_stable_and_ceiling_is_narrowing() -> Result<(), Box<dyn std::error::Error>>
    {
        let manifest = NamedOperationManifest::new(
            "capture_observation",
            CONTRACT_VERSION,
            vec![TransitionClass::CaptureCandidate],
            EffectClass::Candidate,
            1024,
            1024,
            100,
        )?;
        assert!(manifest.admits(TransitionClass::CaptureCandidate, EffectClass::Candidate));
        assert!(!manifest.admits(TransitionClass::TaskControl, EffectClass::Candidate));
        assert!(manifest.validate().is_ok());
        Ok(())
    }

    #[test]
    fn malformed_and_duplicate_operation_state_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let malformed = serde_json::json!({
            "operation": "GetRevisionHeads",
            "scope_id": null,
            "consistency": "eventual",
            "state_fence": {"authority_epoch": 1, "resource_generation": 1, "unexpected": true},
            "parameters": {}
        });
        assert!(serde_json::from_value::<NamedReadRequest>(malformed).is_err());

        let mut operations = BTreeMap::new();
        operations.insert("subject".to_owned(), serde_json::json!("observation-1"));
        let transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: id("op-1")?,
                idempotency_key: "retry-1".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence(),
            scope_id: ScopeId::new("scope-1")?,
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-1")?],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")?,
            named_operations: vec![
                NamedMutationRequest {
                    operation: NamedMutationOperation::CaptureObservation,
                    parameters: operations.clone(),
                },
                NamedMutationRequest {
                    operation: NamedMutationOperation::CaptureObservation,
                    parameters: operations,
                },
            ],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: vec![],
                projection_kinds: vec![],
                relation_kinds: vec![],
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: vec![],
        };
        assert!(matches!(
            transition.validate(),
            Err(StoreError::Duplicate {
                field: "named_operations"
            })
        ));
        Ok(())
    }

    #[test]
    fn external_effect_and_wrong_class_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = NamedOperationManifest::new(
            "capture_observation",
            CONTRACT_VERSION,
            vec![TransitionClass::CaptureCandidate],
            EffectClass::Candidate,
            1,
            1,
            1,
        )?;
        assert!(!manifest.admits(
            TransitionClass::CaptureCandidate,
            EffectClass::ExternalEffect
        ));
        assert!(!manifest.admits(TransitionClass::TaskControl, EffectClass::Candidate));
        Ok(())
    }

    #[test]
    fn canonical_validation_snapshot_rejects_corrupt_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = validation_snapshot()?;
        assert!(valid.validate().is_ok());

        let mut duplicate = valid.clone();
        duplicate.revision_heads.push(RevisionHead {
            key: RevisionKey::new("scope:one")?,
            revision: 2,
            state_fence: fence(),
        });
        assert!(matches!(
            duplicate.validate(),
            Err(StoreError::Duplicate {
                field: "revision_heads"
            })
        ));

        let mut mixed_fence = valid.clone();
        mixed_fence.revision_heads[0].state_fence =
            StateFence::new(test_epoch(2), ResourceGeneration::genesis());
        assert_eq!(mixed_fence.validate(), Err(StoreError::FenceMismatch));

        let mut zero_revision = valid.clone();
        zero_revision.validation_revision = 0;
        assert!(matches!(
            zero_revision.validate(),
            Err(StoreError::InvalidField {
                field: "validation_revision",
                ..
            })
        ));

        let mut invalid_time = valid.clone();
        invalid_time.observed_at_unix_ms = 0;
        assert!(invalid_time.validate().is_err());

        let mut unknown = serde_json::to_value(valid)?;
        unknown["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CanonicalValidationSnapshot>(unknown).is_err());
        Ok(())
    }

    fn recovery_record(key: &str, payload: &[u8]) -> RecoveryRecord {
        RecoveryRecord {
            namespace: "owner".to_owned(),
            key: key.to_owned(),
            state_fence: fence(),
            revision: 1,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            payload: payload.to_vec(),
            value_digest: sha256_hex(payload),
        }
    }

    fn recovery_snapshot(records: Vec<RecoveryRecord>) -> StoreRecoverySnapshot {
        StoreRecoverySnapshot {
            contract_version: CONTRACT_VERSION,
            state_fence: fence(),
            validation_revision: 1,
            canonical_scope: ScopeRevisionView {
                scope_id: ScopeId::new("governor").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: fence(),
            },
            owner_records: records,
            job_records: Vec::new(),
            receipts: Vec::new(),
        }
    }

    #[test]
    fn recovery_record_rejects_unknown_fields_digest_case_and_revision() {
        let valid = recovery_record("one", b"canonical-owner");
        let mut unknown = serde_json::to_value(&valid).expect("serialize");
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RecoveryRecord>(unknown).is_err());

        let mut digest = valid.clone();
        digest.value_digest = digest.value_digest.to_uppercase();
        assert!(digest.validate().is_err());
        digest.value_digest = sha256_hex(b"different");
        assert!(digest.validate().is_err());

        let mut zero_revision = valid;
        zero_revision.revision = 0;
        assert!(matches!(
            zero_revision.validate(),
            Err(StoreError::InvalidField {
                field: "recovery.revision",
                ..
            })
        ));
    }

    #[test]
    fn recovery_snapshot_rejects_duplicate_and_mixed_fence_records() {
        let record = recovery_record("one", b"payload");
        let duplicate = recovery_snapshot(vec![record.clone(), record]);
        assert!(matches!(
            duplicate.validate(),
            Err(StoreError::Duplicate {
                field: "recovery.record_keys"
            })
        ));

        let mut stale = recovery_record("one", b"payload");
        stale.state_fence = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
        assert_eq!(
            recovery_snapshot(vec![stale]).validate(),
            Err(StoreError::FenceMismatch)
        );
    }

    #[test]
    fn recovery_bounds_count_record_bytes_and_total_packet() {
        let too_many = recovery_snapshot(
            (0..=MAX_RECOVERY_OWNER_RECORDS)
                .map(|index| recovery_record(&index.to_string(), b"payload"))
                .collect(),
        );
        assert_eq!(too_many.validate(), Err(StoreError::PayloadTooLarge));

        let too_large = recovery_record("large", &vec![b'x'; MAX_RECOVERY_RECORD_BYTES + 1]);
        assert_eq!(too_large.validate(), Err(StoreError::PayloadTooLarge));

        let packet = recovery_snapshot(
            (0..7)
                .map(|index| {
                    recovery_record(&index.to_string(), &vec![b'x'; MAX_RECOVERY_RECORD_BYTES])
                })
                .collect(),
        );
        assert_eq!(packet.validate(), Err(StoreError::PayloadTooLarge));
    }

    #[test]
    fn recovery_wire_variants_round_trip_and_deny_unknown_fields() {
        let request = StoreRequest::Recovery {
            request: StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: fence(),
                records: vec![RecoveryRecordKey::new("owner", "one").expect("key")],
                include_receipts: true,
                include_jobs: true,
            },
        };
        let encoded = serde_json::to_value(&request).expect("encode request");
        assert_eq!(
            serde_json::from_value::<StoreRequest>(encoded.clone()).expect("decode request"),
            request
        );
        let mut unknown = encoded;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<StoreRequest>(unknown).is_err());

        let response = StoreResponse::Recovery {
            snapshot: recovery_snapshot(vec![recovery_record("one", b"payload")]),
        };
        let encoded = serde_json::to_value(&response).expect("encode response");
        assert_eq!(
            serde_json::from_value::<StoreResponse>(encoded).expect("decode response"),
            response
        );
    }

    fn genesis_request() -> Result<StoreGenesisRequest, StoreError> {
        StoreGenesisRequest {
            contract_version: CONTRACT_VERSION,
            operation_id: OperationId::new("genesis-1").map_err(StoreError::Foundation)?,
            idempotency_key: "genesis-retry-1".to_owned(),
            canonical_request_hash: String::new(),
            state_fence: fence(),
            owner_records: vec![recovery_record("current", br#"{"current_plan":null}"#)],
        }
        .with_computed_digest()
    }

    fn genesis_context() -> Result<RequestMeta, StoreError> {
        Ok(RequestMeta {
            request_id: eliot_contracts::RequestId::new("genesis-request")
                .map_err(StoreError::Foundation)?,
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product")
                .map_err(StoreError::Foundation)?,
            source_id: eliot_contracts::SourceId::new("source").map_err(StoreError::Foundation)?,
            state_fence: fence(),
            clock: eliot_contracts::ClockReading::default(),
        })
    }

    fn genesis_receipt(
        context: &RequestMeta,
        request: &StoreGenesisRequest,
        commit_sequence: u64,
    ) -> Result<WriteReceipt, StoreError> {
        let transition = genesis_transition(context, request)?;
        let mut receipt = WriteReceipt {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            canonical_request_hash: request.canonical_request_hash.clone(),
            transition_class: TransitionClass::RecoverySchema,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-genesis")?),
            state_fence: request.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["genesis-seed".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest,
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some(format!("commit-sequence-{commit_sequence:016}")),
            envelope: None,
        };
        receipt.envelope = Some(issue_genesis_receipt_envelope(
            context,
            request,
            &receipt,
            commit_sequence,
        )?);
        receipt.validate()?;
        Ok(receipt)
    }

    #[test]
    fn genesis_requires_a_nonempty_opaque_owner_seed() -> Result<(), StoreError> {
        let request = genesis_request()?;
        request.validate()?;

        let mut empty = request;
        empty.owner_records.clear();
        assert!(matches!(
            empty.validate(),
            Err(StoreError::Empty {
                field: "genesis.owner_records"
            })
        ));
        Ok(())
    }

    #[test]
    fn genesis_derivation_is_deterministic_and_uses_a_real_manifest_digest()
    -> Result<(), StoreError> {
        let context = genesis_context()?;
        let request = genesis_request()?;
        assert_eq!(request.canonical_request_hash, request.compute_digest()?);
        let first = genesis_transition(&context, &request)?;
        let second = genesis_transition(&context, &request)?;
        assert_eq!(first, second);
        assert_eq!(first.transition_class, TransitionClass::RecoverySchema);
        assert_eq!(
            first.requested_effect_ceiling,
            EffectClass::ReversibleMutation
        );
        assert_eq!(
            first.admission_contract_set_digest,
            first.operation_manifest_digest.as_str()
        );
        assert_ne!(first.operation_manifest_digest.as_str(), "0".repeat(64));
        assert_ne!(
            first.operation_manifest_digest.as_str(),
            "memory-genesis-v1"
        );
        assert!(genesis_manifest()?.validate().is_ok());
        assert!(first.named_operations.is_empty());
        assert!(first.event_projection_relation_intents.event_ids.is_empty());
        assert!(
            first
                .event_projection_relation_intents
                .projection_kinds
                .is_empty()
        );
        assert!(
            first
                .event_projection_relation_intents
                .relation_kinds
                .is_empty()
        );
        assert!(first.required_proof_and_approval_refs.is_empty());
        assert_eq!(first.security, SecurityContext::default());
        assert_eq!(first.scope_id.as_str(), GENESIS_RECEIPT_SCOPE_ID);
        assert_eq!(
            first.ordering_scopes[0].as_str(),
            GENESIS_RECEIPT_ORDERING_SCOPE
        );
        Ok(())
    }

    #[test]
    fn genesis_rejects_stale_digest_after_owner_record_mutations() -> Result<(), StoreError> {
        let request = genesis_request()?;

        let mut payload = request.clone();
        payload.owner_records[0].payload = br#"{"current_plan":"changed"}"#.to_vec();
        payload.owner_records[0].value_digest = sha256_hex(&payload.owner_records[0].payload);
        assert_eq!(
            payload.validate(),
            Err(StoreError::InvalidField {
                field: "canonical_request_hash",
                reason: "does not match canonical genesis request",
            })
        );

        let mut key = request.clone();
        key.owner_records[0].key = "other".to_owned();
        assert_eq!(
            key.validate(),
            Err(StoreError::InvalidField {
                field: "canonical_request_hash",
                reason: "does not match canonical genesis request",
            })
        );

        let mut schema = request;
        schema.owner_records[0].schema = "opaque-owner-v2".to_owned();
        assert_eq!(
            schema.validate(),
            Err(StoreError::InvalidField {
                field: "canonical_request_hash",
                reason: "does not match canonical genesis request",
            })
        );
        Ok(())
    }

    #[test]
    fn genesis_rejects_task_session_and_semantic_or_stale_fences()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = genesis_request()?;
        let mut context = genesis_context()?;

        context.task_id = Some(eliot_contracts::TaskId::new("task")?);
        assert!(matches!(
            request.validate_for_context(&context),
            Err(StoreError::InvalidField {
                field: "genesis.context",
                ..
            })
        ));

        context.task_id = None;
        context.session_id = Some(eliot_contracts::SessionId::new("session")?);
        assert!(matches!(
            request.validate_for_context(&context),
            Err(StoreError::InvalidField {
                field: "genesis.context",
                ..
            })
        ));

        let mut stale = request.clone();
        stale.state_fence = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
        assert_eq!(stale.validate(), Err(StoreError::FenceMismatch));

        let mut semantic = request;
        semantic.state_fence.task_revision = Some(eliot_contracts::TaskRevision::new(1)?);
        assert_eq!(semantic.validate(), Err(StoreError::FenceMismatch));
        Ok(())
    }

    #[test]
    fn genesis_envelope_is_shared_fenced_and_has_no_head_deltas() -> Result<(), StoreError> {
        let context = genesis_context()?;
        let request = genesis_request()?;
        let receipt = genesis_receipt(&context, &request, 1)?;
        assert!(receipt.ordering_sequences.is_empty());
        assert!(receipt.revision_before_after.is_empty());
        assert!(receipt.emitted_event_ids.is_empty());
        assert!(receipt.projection_refs.is_empty());
        assert!(receipt.outbox_refs.is_empty());
        validate_genesis_receipt_envelope(&context, &request, &receipt)?;

        let mut substituted = receipt;
        substituted
            .envelope
            .as_mut()
            .ok_or(StoreError::MissingReceiptEnvelope)?
            .core
            .operation
            .operation_id = OperationId::new("substituted").map_err(StoreError::Foundation)?;
        assert!(validate_genesis_receipt_envelope(&context, &request, &substituted).is_err());
        Ok(())
    }

    #[test]
    fn recovery_and_genesis_caps_are_advertised_after_validation_snapshot() {
        assert_eq!(
            &CAPABILITIES[8..10],
            &[CAPABILITY_RECOVERY, CAPABILITY_INITIALIZE_GENESIS]
        );
        assert_eq!(
            &CAPABILITIES[10..],
            &[
                CAPABILITY_DREAMER_JOB_SUBMIT,
                CAPABILITY_DREAMER_JOB_LEASE_NEXT,
                CAPABILITY_DREAMER_JOB_LEASE_EXACT,
                CAPABILITY_DREAMER_JOB_RENEW,
                CAPABILITY_DREAMER_JOB_START,
                CAPABILITY_DREAMER_JOB_CHECKPOINT,
                CAPABILITY_DREAMER_JOB_RESUME,
                CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
                CAPABILITY_DREAMER_JOB_PUBLISH,
                CAPABILITY_DREAMER_JOB_STATUS,
                CAPABILITY_DREAMER_JOB_REQUEST_CANCEL,
                CAPABILITY_DREAMER_JOB_RECONCILE,
            ]
        );
    }

    #[test]
    fn genesis_identity_mismatch_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let request = genesis_request()?;
        let metadata = RequestMeta {
            request_id: eliot_contracts::RequestId::new("request-1")?,
            session_id: None,
            task_id: None,
            product_id: eliot_contracts::ProductId::new("product")?,
            source_id: eliot_contracts::SourceId::new("source")?,
            state_fence: fence(),
            clock: eliot_contracts::ClockReading::default(),
        };
        let identity = eliot_protocol::RequestIdentity {
            request: eliot_receipts::RequestBinding {
                metadata: metadata.clone(),
                state_fence: fence(),
            },
            idempotency_key: "different-retry".to_owned(),
            deadline_unix_ms: 1,
            cancellation_id: "cancel-1".to_owned(),
        };
        let wire_request = StoreRequest::InitializeGenesis {
            context: metadata.clone(),
            request,
        };
        assert!(matches!(
            wire_request.validate_for_identity(&metadata.request_id, &identity),
            Err(StoreWireError::Identity(_))
        ));
        Ok(())
    }

    #[test]
    fn genesis_response_rejects_non_recovery_transition_class() -> Result<(), StoreError> {
        let receipt = WriteReceipt {
            operation_id: OperationId::new("genesis-1").map_err(StoreError::Foundation)?,
            idempotency_key: "genesis-retry-1".to_owned(),
            canonical_request_hash: "a".repeat(64),
            transition_class: TransitionClass::CaptureCandidate,
            status: WriteReceiptStatus::Rejected,
            commit_id: None,
            state_fence: fence(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: Vec::new(),
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("manifest")?,
            error_code: Some(ErrorCode::Conflict),
            resubmission: Resubmission::None,
            committed_at: None,
            envelope: None,
        };
        assert!(matches!(
            StoreResponse::Genesis { receipt }.validate(),
            Err(StoreWireError::Store(StoreError::InvalidField {
                field: "transition_class",
                ..
            }))
        ));
        Ok(())
    }

    fn erasure_test_fence() -> StateFence {
        fence()
    }

    fn erasure_intent_record() -> ErasureIntentRecord {
        ErasureIntentRecord {
            operation_id: id("erasure-op-1").expect("operation id"),
            request_digest: "c".repeat(64),
            subject: "subject-1".to_owned(),
            surfaces: vec![
                ErasureSurfaceKind::Observations,
                ErasureSurfaceKind::Projections,
                ErasureSurfaceKind::Caches,
            ],
            policy_digest: "d".repeat(64),
            closure_digest: "e".repeat(64),
            state_fence: erasure_test_fence(),
        }
    }

    #[test]
    fn erasure_aggregate_is_fail_closed_with_unknown_precedence() {
        let planned = vec![
            ErasureSurfaceKind::Observations,
            ErasureSurfaceKind::Projections,
        ];
        let purged: Vec<ErasureSurfaceOutcome> = planned
            .iter()
            .map(|surface| ErasureSurfaceOutcome::Purged { surface: *surface })
            .collect();
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &purged).expect("all purged commits"),
            planned
        );

        let unknown_mixed = vec![
            ErasureSurfaceOutcome::Unknown {
                surface: ErasureSurfaceKind::Observations,
            },
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Projections,
            },
        ];
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &unknown_mixed),
            Err(crate::ErasureFailureKind::Unknown)
        );

        let incomplete_only = vec![
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Observations,
            },
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Projections,
            },
        ];
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &incomplete_only),
            Err(crate::ErasureFailureKind::Incomplete)
        );

        let missing = vec![ErasureSurfaceOutcome::Purged {
            surface: ErasureSurfaceKind::Observations,
        }];
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &missing),
            Err(crate::ErasureFailureKind::Incomplete)
        );

        let duplicate = vec![
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Observations,
            },
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Observations,
            },
        ];
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &duplicate),
            Err(crate::ErasureFailureKind::Incomplete)
        );

        let extra = vec![
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Observations,
            },
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Projections,
            },
            ErasureSurfaceOutcome::Purged {
                surface: ErasureSurfaceKind::Caches,
            },
        ];
        assert_eq!(
            aggregate_erasure_outcomes(&planned, &extra),
            Err(crate::ErasureFailureKind::Incomplete)
        );

        assert_eq!(
            aggregate_erasure_outcomes(&[], &[]),
            Err(crate::ErasureFailureKind::Incomplete)
        );

        let intent = erasure_intent_record();
        let initial: Vec<ErasureSurfaceKind> = intent
            .initial_state()
            .iter()
            .map(|(surface, _)| *surface)
            .collect();
        assert_eq!(initial, intent.surfaces);
        assert!(
            intent
                .initial_state()
                .iter()
                .all(|(_, disposition)| *disposition == StoreMutationDisposition::NotAttempted)
        );
    }

    #[test]
    fn erasure_surface_request_validates_plan_and_intent_capability() -> Result<(), StoreError> {
        use crate::ErasureSurfaceRequest;
        let intent = erasure_intent_record();
        let request = ErasureSurfaceRequest {
            identity: OperationIdentity {
                operation_id: intent.operation_id.clone(),
                idempotency_key: "erasure-retry-1".to_owned(),
                canonical_request_hash: intent.request_digest.clone(),
            },
            surfaces: intent.surfaces.clone(),
            intent,
        };
        request.validate()?;
        request.validate_for_dispatch(&[crate::CAPABILITY_ERASURE_INTENT])?;

        assert_eq!(
            request.validate_for_dispatch(&[]),
            Err(StoreError::UnknownOperation)
        );

        let mut narrowed = request.clone();
        narrowed.surfaces.pop();
        assert!(narrowed.validate().is_err());

        let mut conflicted = request.clone();
        conflicted.identity.canonical_request_hash = "f".repeat(64);
        assert_eq!(conflicted.validate(), Err(StoreError::IdentityConflict));
        Ok(())
    }
}
