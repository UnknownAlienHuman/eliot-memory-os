use std::{fmt, str::FromStr};

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{OperationId, ProductId, RequestId, SourceId, StateFence, TaskId};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{ContractError, text};

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema)]
        #[schemars(transparent)]
        pub struct $name(String);
        impl $name {
            /// Creates an identity after shape validation.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                text(&value, $field)?;
                if value.chars().count() > 256 { return Err(ContractError::Bound { field: $field }); }
                Ok(Self(value))
            }
            /// Returns the canonical text.
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Display for $name { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) } }
        impl FromStr for $name { type Err = ContractError; fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) } }
        impl Serialize for $name { fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer { serializer.serialize_str(&self.0) } }
        impl<'de> Deserialize<'de> for $name { fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> { Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom) } }
    };
}

id_type!(/// Identity of a query projection.
    QueryId, "query_id");
id_type!(/// Identity of an immutable source snapshot.
    SnapshotId, "snapshot_id");
id_type!(/// Identity of one source member.
    MemberId, "member_id");
id_type!(/// Identity of a screening profile.
    ProfileId, "profile_id");
id_type!(/// Identity of one deterministic screening rule.
    RuleId, "rule_id");
id_type!(/// Identity of one finding.
    FindingId, "finding_id");
id_type!(/// Identity of one protection evidence record.
    ProtectionEvidenceId, "protection_evidence_id");

/// A canonical lowercase SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, JsonSchema)]
#[schemars(transparent)]
pub struct Digest(String);
impl Digest {
    /// Validates a lowercase SHA-256 digest.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ContractError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }
    /// Hashes bytes with foundation SHA-256.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        Self::new(eliot_contracts::sha256_hex(bytes))
    }
    /// Returns hexadecimal form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Immutable source and query binding shared by all records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Product owning the projection.
    pub product_id: ProductId,
    /// Source owner identity.
    pub source_id: SourceId,
    /// Immutable snapshot identity.
    pub snapshot_id: SnapshotId,
    /// Query identity used to select the projection.
    pub query: QueryIdentity,
    /// Revision of the immutable snapshot.
    pub revision: u64,
    /// Digest of the immutable snapshot.
    pub digest: Digest,
    /// Scope used for the query.
    pub scope: WorkScopeId,
    /// Fence captured by the source owner.
    pub state_fence: StateFence,
}
impl SourceIdentity {
    /// Validates the complete source identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.revision == 0 {
            return Err(ContractError::Zero {
                field: "source.revision",
            });
        }
        self.query.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::BindingMismatch {
                field: "source.state_fence",
            })
    }
}

/// Immutable query identity and query result digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryIdentity {
    /// Query identity.
    pub query_id: QueryId,
    /// Query digest.
    pub query_digest: Digest,
}
impl QueryIdentity {
    /// Validates query identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Request identity retained when a cursor or result is resumed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    /// Idempotency identity.
    pub request_id: RequestId,
    /// Operation identity for the bounded screen.
    pub operation_id: OperationId,
    /// Optional task identity.
    pub task_id: Option<TaskId>,
    /// Cumulative attempt number.
    pub attempt_id: AgentAttemptId,
    /// Scope and fence captured with the request.
    pub scope: WorkScopeId,
    /// Fence used for every page.
    pub state_fence: StateFence,
}
impl RequestBinding {
    /// Validates request identity and cumulative attempt shape.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.state_fence
            .validate()
            .map_err(|_| ContractError::BindingMismatch {
                field: "request.state_fence",
            })
    }
}
