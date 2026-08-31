//! Stable, ELIOT-owned primitives shared by the C0 contract crates.
//!
//! This crate deliberately contains no domain policy, storage, process, Tokio,
//! provider, or framework types.  It provides validated identifiers, revision
//! and fence metadata, deterministic contract identity helpers, and the small
//! status/decision/receipt vocabulary that other contract crates compose.

#![forbid(unsafe_code)]

use std::{borrow::Cow, fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The current wire revision of this foundation surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.contracts";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A validation failure for a contract primitive.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ContractError {
    /// A required value is empty or consists only of whitespace.
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    /// A value contains a control character that cannot be part of an identity.
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    /// A value is outside the range admitted by a typed counter.
    #[error("{field} must be greater than zero")]
    Zero { field: &'static str },
    /// A timestamp interval is inverted.
    #[error("{field} has an invalid interval")]
    InvalidInterval { field: &'static str },
    /// A state fence has no identity-bearing dependency.
    #[error("state fence must contain at least one dependency")]
    EmptyFence,
    /// A request has no request identity.
    #[error("request metadata must contain a request id")]
    MissingRequestId,
    /// A digest does not have the canonical hexadecimal form.
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    /// A contract version component is too large for its wire form.
    #[error("contract version component is out of range")]
    VersionOutOfRange,
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::ControlCharacter { field });
    }
    Ok(())
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
        #[schemars(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_text(&value, $label)?;
                Ok(Self(value))
            }

            /// Returns the canonical identifier text.
            pub fn as_str(&self) -> &str { &self.0 }

            /// Consumes this identifier and returns its text.
            pub fn into_string(self) -> String { self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }

        impl FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer { serializer.serialize_str(&self.0) }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

string_id!(/// Stable product/source tree identity.
    ProductId, "product_id");
string_id!(/// Identity of a source or evidence origin.
    SourceId, "source_id");
string_id!(/// Identity of a task or durable work item.
    TaskId, "task_id");
string_id!(/// Identity of an attached semantic session.
    SessionId, "session_id");
string_id!(/// Idempotency identity of a caller request.
    RequestId, "request_id");
string_id!(/// Identity of one effect-capable operation.
    OperationId, "operation_id");
string_id!(/// Identity of a durable decision.
    DecisionId, "decision_id");
string_id!(/// Identity of a durable receipt.
    ReceiptId, "receipt_id");
string_id!(/// Identity of an immutable artifact or generation.
    ArtifactId, "artifact_id");
string_id!(/// Identity of a contract surface.
    ContractId, "contract_id");

/// Stable contract name for the owner-neutral `WorkLease` identity family.
pub const WORK_LEASE_CONTRACT_NAME: &str = "eliot.foundation.work-lease-id";
/// Exact namespace tag carried by every `WorkLease` wire value.
pub const WORK_LEASE_NAMESPACE: &str = "eliot.governor.work-lease";
/// Exact version tag carried by every `WorkLease` wire value.
pub const WORK_LEASE_WIRE_REVISION: &str = "v1";
/// Semantic version of the `WorkLease` contract surface.
pub const WORK_LEASE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum `WorkLease` value length, measured in Unicode scalar values.
pub const WORK_LEASE_MAX_VALUE_LENGTH: usize = 128;
/// Legacy scalar and wrong-domain `WorkLease` wires are rejected at this boundary.
pub const WORK_LEASE_LEGACY_WIRE_DISPOSITION: &str =
    "rejected: unversioned scalar and wrong-domain legacy wire";

/// Shape-only validation failure for an owner-neutral `WorkLease` value.
///
/// Errors identify only the failing field and never include the supplied value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkLeaseIdError {
    /// The value is empty or consists only of whitespace.
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    /// The value contains a control character.
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    /// The value has whitespace at either boundary.
    #[error("{field} must not have boundary whitespace")]
    BoundaryWhitespace { field: &'static str },
    /// The value exceeds the bounded opaque-text limit.
    #[error("{field} exceeds the maximum Unicode scalar value length")]
    TooLong { field: &'static str },
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
enum WorkLeaseNamespace {
    #[serde(rename = "eliot.governor.work-lease")]
    #[schemars(rename = "eliot.governor.work-lease")]
    GovernorWorkLease,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
enum WorkLeaseWireRevision {
    #[serde(rename = "v1")]
    #[schemars(rename = "v1")]
    V1,
}

/// Owner-neutral identity for one bounded unit of work.
///
/// The value is opaque text accepted only through this exact versioned wire.
/// This contract validates shape only; it cannot prove or promote a UUID,
/// provider, process, session, `StateFence`, map-key, API, coordination, or
/// legacy identity. The namespace tag—not the spelling of the value—determines
/// this identity family.
///
/// # Compatibility
///
/// Issue #378 intentionally exposes no string-only issuance or promotion
/// constructor. Issue #368 owns issuance and provenance-preserving consumer
/// migration.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseId {
    namespace: WorkLeaseNamespace,
    revision: WorkLeaseWireRevision,
    #[schemars(length(min = 1, max = 128))]
    value: String,
}

fn validate_work_lease_value(value: &str) -> Result<(), WorkLeaseIdError> {
    const FIELD: &str = "work_lease_id.value";
    if value.trim().is_empty() {
        return Err(WorkLeaseIdError::Blank { field: FIELD });
    }
    if value.chars().any(char::is_control) {
        return Err(WorkLeaseIdError::ControlCharacter { field: FIELD });
    }
    if value != value.trim() {
        return Err(WorkLeaseIdError::BoundaryWhitespace { field: FIELD });
    }
    if value.chars().count() > WORK_LEASE_MAX_VALUE_LENGTH {
        return Err(WorkLeaseIdError::TooLong { field: FIELD });
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkLeaseIdWire {
    namespace: WorkLeaseNamespace,
    revision: WorkLeaseWireRevision,
    value: String,
}

impl<'de> Deserialize<'de> for WorkLeaseId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WorkLeaseIdWire::deserialize(deserializer)?;
        validate_work_lease_value(&wire.value).map_err(de::Error::custom)?;
        Ok(Self {
            namespace: wire.namespace,
            revision: wire.revision,
            value: wire.value,
        })
    }
}

/// Returns the deterministic contract/schema identity for `WorkLeaseId`.
pub fn work_lease_contract_identity() -> Result<ContractIdentity, ContractError> {
    contract_identity(
        WORK_LEASE_CONTRACT_NAME,
        WORK_LEASE_CONTRACT_VERSION,
        &serde_json::json!({
            "contract_name": WORK_LEASE_CONTRACT_NAME,
            "contract_version": WORK_LEASE_CONTRACT_VERSION,
            "legacy_wire_disposition": WORK_LEASE_LEGACY_WIRE_DISPOSITION,
            "max_value_length": WORK_LEASE_MAX_VALUE_LENGTH,
            "namespace": WORK_LEASE_NAMESPACE,
            "schema": schemars::schema_for!(WorkLeaseId),
            "wire_revision": WORK_LEASE_WIRE_REVISION,
        }),
    )
}

macro_rules! counter {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        #[schemars(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Creates a counter, rejecting zero because zero is reserved for an absent value.
            pub const fn new(value: u64) -> Result<Self, ContractError> {
                if value == 0 { Err(ContractError::Zero { field: $label }) } else { Ok(Self(value)) }
            }
            /// Creates the genesis counter used for an explicit initial state.
            pub const fn genesis() -> Self { Self(1) }
            /// Returns the numeric value.
            pub const fn value(self) -> u64 { self.0 }
            /// Returns the next counter without wrapping.
            pub const fn next(self) -> Result<Self, ContractError> {
                match self.0.checked_add(1) {
                    Some(value) => Ok(Self(value)),
                    None => Err(ContractError::VersionOutOfRange),
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = u64::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

counter!(/// Authority epoch used to fence old capabilities.
    AuthorityEpoch, "authority_epoch");
counter!(/// Monotonic resource-generation identity.
    ResourceGeneration, "resource_generation");
counter!(/// Task plan revision.
    TaskRevision, "task_revision");
counter!(/// Policy revision.
    PolicyRevision, "policy_revision");
counter!(/// Integration-owner revision.
    IntegrationRevision, "integration_revision");
counter!(/// Canonical transaction sequence.
    TransactionSequence, "transaction_sequence");

/// General epoch spelling used by compact coordination records.
pub type Epoch = AuthorityEpoch;
/// General revision spelling for task-bound records.
pub type Revision = TaskRevision;
/// Compatibility spelling for the stable status algebra.
pub type OperationStatus = Status;
/// Compatibility spelling for a decision receipt.
pub type DecisionReceipt = Receipt;

/// A semantic version used by a public contract.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct ContractVersion {
    /// Breaking contract component.
    pub major: u16,
    /// Additive contract component.
    pub minor: u16,
    /// Backwards-compatible correction component.
    pub patch: u16,
}

impl ContractVersion {
    /// Creates a semantic contract version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
    /// Returns the canonical `major.minor.patch` representation.
    pub fn as_string(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A content-addressed public contract identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContractIdentity {
    /// Stable contract name.
    pub name: ContractId,
    /// Semantic wire revision.
    pub version: ContractVersion,
    /// Lowercase SHA-256 digest of the canonical contract shape.
    pub shape_sha256: String,
}

impl ContractIdentity {
    /// Validates the identity without re-reading the source shape.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest(&self.shape_sha256, "shape_sha256")
    }
}

/// Builds a deterministic identity from any serializable contract shape.
pub fn contract_identity<T: Serialize>(
    name: impl Into<String>,
    version: ContractVersion,
    shape: &T,
) -> Result<ContractIdentity, ContractError> {
    let name = ContractId::new(name)?;
    let bytes = canonical_json_bytes(shape).map_err(|_| ContractError::Blank { field: "shape" })?;
    Ok(ContractIdentity {
        name,
        version,
        shape_sha256: sha256_hex(&bytes),
    })
}

/// Returns deterministic JSON bytes with object keys sorted recursively.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    let canonical = canonicalize(value);
    serde_json::to_vec(&canonical)
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

/// Computes a lowercase SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::InvalidDigest { field });
    }
    Ok(())
}

/// Point-in-time values kept separate so an external timestamp cannot become causal order.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ClockReading {
    /// Wall-clock time observed by the host, in Unix milliseconds.
    pub valid_time_ms: Option<i64>,
    /// Time at which the observation became known to ELIOT, in Unix milliseconds.
    pub known_time_ms: Option<i64>,
    /// Governor-assigned causal transaction sequence.
    pub transaction_sequence: Option<TransactionSequence>,
    /// Monotonic host reading, in nanoseconds when available.
    pub monotonic_ns: Option<u64>,
}

impl ClockReading {
    /// Validates that supplied timestamps are ordered where both are known.
    pub fn validate(&self) -> Result<(), ContractError> {
        if let (Some(valid), Some(known)) = (self.valid_time_ms, self.known_time_ms)
            && known < valid
        {
            return Err(ContractError::InvalidInterval {
                field: "clock_reading",
            });
        }
        Ok(())
    }
}

/// A compact, dependency-only state fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateFence {
    /// Current authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Resource generation relevant to the decision.
    pub resource_generation: ResourceGeneration,
    /// Current task-plan revision, when task-bound.
    pub task_revision: Option<TaskRevision>,
    /// Current policy revision, when policy-bound.
    pub policy_revision: Option<PolicyRevision>,
    /// Current integration revision, when an integration lease is involved.
    pub integration_revision: Option<IntegrationRevision>,
}

impl StateFence {
    /// Constructs a fence with the minimum authority and resource dependencies.
    pub const fn new(
        authority_epoch: AuthorityEpoch,
        resource_generation: ResourceGeneration,
    ) -> Self {
        Self {
            authority_epoch,
            resource_generation,
            task_revision: None,
            policy_revision: None,
            integration_revision: None,
        }
    }
    /// Returns whether two fences can safely share a decision scope.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.authority_epoch == other.authority_epoch
            && self.resource_generation == other.resource_generation
            && (self.task_revision.is_none() || self.task_revision == other.task_revision)
            && (self.policy_revision.is_none() || self.policy_revision == other.policy_revision)
            && (self.integration_revision.is_none()
                || self.integration_revision == other.integration_revision)
    }
    /// Validates the fence's required dependencies.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.authority_epoch.value() == 0 || self.resource_generation.value() == 0 {
            return Err(ContractError::EmptyFence);
        }
        Ok(())
    }
}

/// Metadata attached to every request crossing a contract boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestMetadata {
    /// Idempotency identity.
    pub request_id: RequestId,
    /// Caller session, if attached.
    pub session_id: Option<SessionId>,
    /// Task binding, if semantic work is selected.
    pub task_id: Option<TaskId>,
    /// Product/source identity used to bind the request.
    pub product_id: ProductId,
    /// Source identity used to bind the request.
    pub source_id: SourceId,
    /// Fencing metadata captured before external work.
    pub state_fence: StateFence,
    /// Host and Governor time observations.
    pub clock: ClockReading,
}

impl RequestMetadata {
    /// Validates request identity, fence and clock invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.request_id.as_str().trim().is_empty() {
            return Err(ContractError::MissingRequestId);
        }
        self.state_fence.validate()?;
        self.clock.validate()
    }
}

/// Stable machine-readable error code for a typed failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidRequest,
    InvalidIdentity,
    StaleEpoch,
    StaleRevision,
    FenceMismatch,
    Conflict,
    NotFound,
    Unavailable,
    Timeout,
    Cancelled,
    UnknownOutcome,
    Internal,
}

impl ErrorCode {
    /// Returns the stable wire code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InvalidIdentity => "INVALID_IDENTITY",
            Self::StaleEpoch => "STALE_EPOCH",
            Self::StaleRevision => "STALE_REVISION",
            Self::FenceMismatch => "FENCE_MISMATCH",
            Self::Conflict => "CONFLICT",
            Self::NotFound => "NOT_FOUND",
            Self::Unavailable => "UNAVAILABLE",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::UnknownOutcome => "UNKNOWN_OUTCOME",
            Self::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable status algebra shared by contract boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Accepted,
    Running,
    Succeeded,
    Rejected,
    Failed,
    Cancelled,
    Expired,
    UnknownOutcome,
    Unavailable,
}

impl Status {
    /// Whether this status is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Rejected
                | Self::Failed
                | Self::Cancelled
                | Self::Expired
                | Self::UnknownOutcome
        )
    }
}

/// A bounded decision with explicit status and fencing context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Decision identity.
    pub decision_id: DecisionId,
    /// Request that caused the decision.
    pub request_id: RequestId,
    /// Stable outcome status.
    pub status: Status,
    /// Typed failure, when status is failed/rejected/unavailable.
    pub error_code: Option<ErrorCode>,
    /// Fence at which the decision was made.
    pub state_fence: StateFence,
}

impl Decision {
    /// Validates the status/error relationship and fence.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.state_fence.validate()?;
        if matches!(
            self.status,
            Status::Failed | Status::Rejected | Status::Unavailable
        ) != self.error_code.is_some()
        {
            return Err(ContractError::InvalidInterval {
                field: "decision.status/error_code",
            });
        }
        Ok(())
    }
}

/// A durable receipt proving observation of a decision or operation outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Receipt identity.
    pub receipt_id: ReceiptId,
    /// Operation identity, if this receipt belongs to an effect-capable operation.
    pub operation_id: Option<OperationId>,
    /// Decision identity that this receipt reports.
    pub decision_id: DecisionId,
    /// Final or observed status.
    pub status: Status,
    /// Fence under which the outcome was reconciled.
    pub state_fence: StateFence,
    /// Time observations attached to the receipt.
    pub clock: ClockReading,
}

impl Receipt {
    /// Validates receipt metadata and clock invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.state_fence.validate()?;
        self.clock.validate()
    }
}

/// Convenience conversion for preserving a borrowed stable identifier in logs.
pub fn identifier_text<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<Cow<'a, str>, ContractError> {
    validate_text(value, field)?;
    Ok(Cow::Borrowed(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn decode_test_wire(value: &str) -> Result<WorkLeaseId, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "namespace": WORK_LEASE_NAMESPACE,
            "revision": WORK_LEASE_WIRE_REVISION,
            "value": value,
        }))
    }

    #[test]
    fn identifiers_reject_blank_and_controls() -> TestResult {
        assert!(ProductId::new(" ").is_err());
        assert!(SourceId::new("source\n1").is_err());
        assert_eq!(ProductId::new("product-1")?.as_str(), "product-1");
        Ok(())
    }

    #[test]
    fn counters_are_nonzero_and_monotonic() -> TestResult {
        assert!(AuthorityEpoch::new(0).is_err());
        let epoch = AuthorityEpoch::new(4)?;
        assert_eq!(epoch.next()?.value(), 5);
        Ok(())
    }

    #[test]
    fn canonical_identity_is_order_independent() -> TestResult {
        let left = serde_json::json!({"z": 1, "a": {"b": true, "a": null}});
        let right = serde_json::json!({"a": {"a": null, "b": true}, "z": 1});
        assert_eq!(canonical_json_bytes(&left)?, canonical_json_bytes(&right)?);
        let a = contract_identity("shape", CONTRACT_VERSION, &left)?;
        let b = contract_identity("shape", CONTRACT_VERSION, &right)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn request_roundtrip_and_schema_are_stable() -> TestResult {
        let request = RequestMetadata {
            request_id: RequestId::new("req-1")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1")?,
            source_id: SourceId::new("source-1")?,
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            clock: ClockReading {
                valid_time_ms: Some(10),
                known_time_ms: Some(11),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: Some(12),
            },
        };
        request.validate()?;
        let encoded = serde_json::to_string(&request)?;
        assert_eq!(serde_json::from_str::<RequestMetadata>(&encoded)?, request);
        let schema = schemars::schema_for!(RequestMetadata);
        let schema_bytes = serde_json::to_vec(&schema)?;
        assert!(!schema_bytes.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_unknown_fields_fail_closed() {
        let value = serde_json::json!({
            "request_id": "req-1", "product_id": "p", "source_id": "s",
            "state_fence": {"authority_epoch": 1, "resource_generation": 1, "unexpected": true},
            "clock": {}
        });
        assert!(serde_json::from_value::<RequestMetadata>(value).is_err());
    }

    #[test]
    fn valid_identifier_text_roundtrips() -> TestResult {
        let mut corpus = vec![
            "a".to_owned(),
            "A9._:/-".to_owned(),
            "product/source:revision-1".to_owned(),
        ];
        corpus.extend((1..=64).map(|length| "x".repeat(length)));
        for value in corpus {
            let id = ProductId::new(value.clone())?;
            let wire = serde_json::to_string(&id)?;
            let decoded: ProductId = serde_json::from_str(&wire)?;
            assert_eq!(decoded.as_str(), value);
        }
        Ok(())
    }

    #[test]
    fn work_lease_wire_schema_roundtrip_and_identity_are_stable() -> TestResult {
        assert_eq!(WORK_LEASE_CONTRACT_NAME, "eliot.foundation.work-lease-id");
        assert_eq!(WORK_LEASE_NAMESPACE, "eliot.governor.work-lease");
        assert_eq!(WORK_LEASE_WIRE_REVISION, "v1");
        assert_eq!(WORK_LEASE_CONTRACT_VERSION, ContractVersion::new(1, 0, 0));
        assert_eq!(WORK_LEASE_MAX_VALUE_LENGTH, 128);
        assert!(WORK_LEASE_LEGACY_WIRE_DISPOSITION.contains("unversioned scalar"));
        assert!(WORK_LEASE_LEGACY_WIRE_DISPOSITION.contains("wrong-domain legacy wire"));

        let id = decode_test_wire("owner-a")?;
        let encoded = serde_json::to_string(&id)?;
        assert_eq!(
            encoded,
            r#"{"namespace":"eliot.governor.work-lease","revision":"v1","value":"owner-a"}"#
        );
        assert_eq!(serde_json::from_str::<WorkLeaseId>(&encoded)?, id);

        let schema = serde_json::to_value(schemars::schema_for!(WorkLeaseId))?;
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"].as_object().map(Map::len), Some(3));
        assert_eq!(schema["required"].as_array().map(Vec::len), Some(3));
        assert_eq!(schema["properties"]["value"]["minLength"], 1);
        assert_eq!(
            schema["properties"]["value"]["maxLength"],
            WORK_LEASE_MAX_VALUE_LENGTH
        );
        assert_eq!(
            schema["$defs"]["WorkLeaseNamespace"]["enum"],
            serde_json::json!([WORK_LEASE_NAMESPACE])
        );
        assert_eq!(
            schema["$defs"]["WorkLeaseWireRevision"]["enum"],
            serde_json::json!([WORK_LEASE_WIRE_REVISION])
        );
        let schema_bytes = serde_json::to_vec(&schema)?;
        let repeated_schema_bytes =
            serde_json::to_vec(&serde_json::to_value(schemars::schema_for!(WorkLeaseId))?)?;
        assert_eq!(schema_bytes, repeated_schema_bytes);
        assert_eq!(schema.to_string().matches(WORK_LEASE_NAMESPACE).count(), 1);
        assert_eq!(
            schema.to_string().matches(WORK_LEASE_WIRE_REVISION).count(),
            1
        );

        let first = work_lease_contract_identity()?;
        let second = work_lease_contract_identity()?;
        assert_eq!(first, second);
        assert_eq!(first.name, ContractId::new(WORK_LEASE_CONTRACT_NAME)?);
        assert_eq!(first.version, WORK_LEASE_CONTRACT_VERSION);
        assert_eq!(
            first.shape_sha256,
            "abd7f2032837bb968b78072102f633e3b0871d856c40845008d225162b7c11d4"
        );
        Ok(())
    }

    #[test]
    fn work_lease_value_validation_is_bounded_and_field_only() {
        assert!(matches!(
            validate_work_lease_value(""),
            Err(WorkLeaseIdError::Blank {
                field: "work_lease_id.value"
            })
        ));
        assert!(matches!(
            validate_work_lease_value("   "),
            Err(WorkLeaseIdError::Blank {
                field: "work_lease_id.value"
            })
        ));
        assert!(matches!(
            validate_work_lease_value("owner\u{7}value"),
            Err(WorkLeaseIdError::ControlCharacter {
                field: "work_lease_id.value"
            })
        ));
        assert!(matches!(
            validate_work_lease_value(" owner"),
            Err(WorkLeaseIdError::BoundaryWhitespace {
                field: "work_lease_id.value"
            })
        ));
        assert!(matches!(
            validate_work_lease_value("owner "),
            Err(WorkLeaseIdError::BoundaryWhitespace {
                field: "work_lease_id.value"
            })
        ));
        assert!(matches!(
            validate_work_lease_value(&"x".repeat(WORK_LEASE_MAX_VALUE_LENGTH + 1)),
            Err(WorkLeaseIdError::TooLong {
                field: "work_lease_id.value"
            })
        ));
        assert!(validate_work_lease_value(&"🙂".repeat(WORK_LEASE_MAX_VALUE_LENGTH)).is_ok());
        assert!(decode_test_wire(&"🙂".repeat(WORK_LEASE_MAX_VALUE_LENGTH)).is_ok());
    }

    #[test]
    fn work_lease_wire_rejects_legacy_wrong_domain_and_malformed_objects() {
        let legacy_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let legacy_forms = [
            "lease-1".to_owned(),
            String::new(),
            legacy_uuid.to_owned(),
            legacy_uuid.replace('-', ""),
            format!("urn:uuid:{legacy_uuid}"),
            format!("{{{legacy_uuid}}}"),
        ];
        for legacy in legacy_forms {
            assert!(serde_json::from_value::<WorkLeaseId>(serde_json::json!(legacy)).is_err());
        }

        let malformed = [
            serde_json::json!({
                "namespace": "other.domain.work-lease",
                "revision": WORK_LEASE_WIRE_REVISION,
                "value": "owner"
            }),
            serde_json::json!({
                "namespace": WORK_LEASE_NAMESPACE,
                "revision": "v2",
                "value": "owner"
            }),
            serde_json::json!({
                "namespace": WORK_LEASE_NAMESPACE,
                "revision": WORK_LEASE_WIRE_REVISION,
                "value": "owner",
                "unknown": true
            }),
            serde_json::json!({
                "namespace": WORK_LEASE_NAMESPACE,
                "revision": WORK_LEASE_WIRE_REVISION
            }),
            serde_json::json!({
                "namespace": WORK_LEASE_NAMESPACE,
                "value": "owner"
            }),
            serde_json::json!({
                "revision": WORK_LEASE_WIRE_REVISION,
                "value": "owner"
            }),
        ];
        for value in malformed {
            assert!(serde_json::from_value::<WorkLeaseId>(value).is_err());
        }
    }

    #[test]
    fn work_lease_deserializer_revalidates_value_shape() {
        let cases = [
            (
                serde_json::json!(""),
                "work_lease_id.value must be non-blank",
            ),
            (
                serde_json::json!(" "),
                "work_lease_id.value must be non-blank",
            ),
            (
                serde_json::json!(" owner"),
                "work_lease_id.value must not have boundary whitespace",
            ),
            (
                serde_json::json!("owner "),
                "work_lease_id.value must not have boundary whitespace",
            ),
            (
                serde_json::json!("owner\u{7}value"),
                "work_lease_id.value contains a control character",
            ),
            (
                serde_json::json!("x".repeat(WORK_LEASE_MAX_VALUE_LENGTH + 1)),
                "work_lease_id.value exceeds the maximum Unicode scalar value length",
            ),
        ];

        for (value, expected_error) in cases {
            let wire = serde_json::json!({
                "namespace": WORK_LEASE_NAMESPACE,
                "revision": WORK_LEASE_WIRE_REVISION,
                "value": value,
            });
            let Err(error) = serde_json::from_value::<WorkLeaseId>(wire) else {
                panic!("invalid value must be rejected by custom deserializer")
            };
            assert_eq!(error.to_string(), expected_error);
        }
    }

    #[test]
    fn work_lease_uuid_spelling_does_not_gain_legacy_equivalence() -> TestResult {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let id = decode_test_wire(uuid)?;
        let wire = serde_json::to_value(&id)?;
        assert_eq!(wire["namespace"], WORK_LEASE_NAMESPACE);
        assert_eq!(wire["revision"], WORK_LEASE_WIRE_REVISION);
        assert!(serde_json::from_value::<WorkLeaseId>(serde_json::json!(uuid)).is_err());
        // The namespace tag, not UUID spelling, determines this distinct identity.
        Ok(())
    }
}
