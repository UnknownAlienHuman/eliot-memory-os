//! Stable, store-neutral contracts for the ELIOT Research federation channel.
//!
//! These records deliberately do not contain provider credentials, arbitrary
//! URLs as authority, or promotion decisions.  A bridge may acquire material,
//! while Governor-owned code remains responsible for admission and lifecycle.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{ClockReading, ContractVersion, EpochId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.research.exchange-api";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ResearchContractError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("{field} contains a duplicate identity")]
    DuplicateIdentity { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("state fence is not valid or does not match")]
    InvalidFence,
    #[error("citation references a source outside the allowed manifest")]
    CitationNotAllowed,
    #[error("citation precision exceeds the declared source anchor")]
    UnsupportedPrecision,
    #[error("bundle disposition is incompatible with its evidence")]
    InvalidDisposition,
}

fn text(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ResearchContractError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn texts(values: &[String], field: &'static str) -> Result<(), ResearchContractError> {
    if values.is_empty() {
        return Err(ResearchContractError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ResearchContractError::DuplicateIdentity { field });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Err(ResearchContractError::InvalidDigest { field })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    Paper,
    Documentation,
    Dataset,
    Repository,
    Web,
    Report,
    ServiceDossier,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    Private,
    ProjectBound,
    ExportableRedacted,
    Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    AnsweredWithSupportedResult,
    NoMatchInCompleteScope,
    NoNewUsefulEvidence,
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    IncompleteCoverage,
    Inconclusive,
    Cancelled,
}

impl CompletionDisposition {
    #[must_use]
    pub const fn may_close_inquiry(self) -> bool {
        matches!(
            self,
            Self::AnsweredWithSupportedResult | Self::NoMatchInCompleteScope
        )
    }

    #[must_use]
    pub const fn requires_typed_coverage_gaps(self) -> bool {
        matches!(
            self,
            Self::SourceUnavailable | Self::StaleSourceOrIndex | Self::IncompleteCoverage
        )
    }
}

/// Typed reason one source contributes no evidence. Timeout, cancellation,
/// crash-adjacent unavailability, stale indexes, policy denial and unknown
/// provider outcomes remain distinct: an unavailable source never decodes as
/// an empty-but-complete scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    BudgetExhausted,
    Timeout,
    Cancelled,
    Unknown,
}

/// One typed coverage gap: an unavailable source identity plus the distinct
/// reason it yields no evidence. Gaps are degradation evidence, not
/// absence/completeness claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub source_handle: String,
    pub kind: CoverageGapKind,
    pub detail: String,
}

/// Stable provider/acquisition failure projection carried by the exchange.
///
/// The provider bridge owns the physical failure and its evidence.  The
/// exchange carries only this typed, coverage-scoped projection so an
/// unavailable source cannot be collapsed into a generic transition error or
/// presented as an empty-but-complete inquiry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchProviderFailure {
    /// Stable machine-readable reason code.
    pub code: String,
    /// Coverage dimension affected by this provider failure.
    pub kind: CoverageGapKind,
    /// Opaque source/provider handle used for the gap record.
    pub source_handle: String,
    /// Sanitized detail; raw provider bytes remain in evidence custody.
    pub detail: String,
}

impl fmt::Display for ResearchProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl ResearchProviderFailure {
    /// Builds a validated provider failure projection.
    pub fn new(
        code: impl Into<String>,
        kind: CoverageGapKind,
        source_handle: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            kind,
            source_handle: source_handle.into(),
            detail: detail.into(),
        }
    }

    /// Projects this failure into a typed coverage gap.
    #[must_use]
    pub fn coverage_gap(&self) -> CoverageGap {
        CoverageGap {
            source_handle: self.source_handle.clone(),
            kind: self.kind,
            detail: self.detail.clone(),
        }
    }
}

impl CoverageGap {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.source_handle, "gap.source_handle")?;
        text(&self.detail, "gap.detail")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowedReferenceManifest {
    pub run_id: String,
    pub state_fence: StateFence,
    pub source_handles: Vec<String>,
    pub evidence_handles: Vec<String>,
    pub artifact_handles: Vec<String>,
    pub allowed_anchor_precision: AnchorPrecision,
    pub stale_or_revoked_handles: Vec<String>,
    pub digest: String,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AnchorPrecision {
    Source,
    Document,
    Page,
    Section,
    Paragraph,
    Line,
    ByteRange,
}

impl AnchorPrecision {
    fn permits(self, requested: Self) -> bool {
        self >= requested
    }
}

impl AllowedReferenceManifest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.run_id, "manifest.run_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        texts(&self.source_handles, "manifest.source_handles")?;
        for values in [&self.evidence_handles, &self.artifact_handles] {
            if !values.is_empty() {
                texts(values, "manifest.handles")?;
            }
        }
        for value in &self.stale_or_revoked_handles {
            text(value, "manifest.stale_or_revoked_handles")?;
        }
        digest(&self.digest, "manifest.digest")
    }
    #[must_use]
    pub fn allows(&self, handle: &str) -> bool {
        (self
            .source_handles
            .iter()
            .chain(&self.evidence_handles)
            .chain(&self.artifact_handles))
        .any(|candidate| candidate == handle)
            && !self.stale_or_revoked_handles.iter().any(|x| x == handle)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchQueryRequest {
    pub exchange_id: String,
    pub protocol_revision: ContractVersion,
    pub bridge_generation: String,
    pub idempotency_key: String,
    pub requester_principal: String,
    pub state_fence: StateFence,
    pub question: String,
    pub question_scope: String,
    pub expected_decision: String,
    pub source_classes: Vec<SourceClass>,
    pub coverage_goal: String,
    pub allowed_references: AllowedReferenceManifest,
    pub disclosure: DisclosureClass,
    pub retention: String,
    pub license_policy: String,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub required_schema: String,
}

impl ResearchQueryRequest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "exchange_id"),
            (&self.bridge_generation, "bridge_generation"),
            (&self.idempotency_key, "idempotency_key"),
            (&self.requester_principal, "requester_principal"),
            (&self.question, "question"),
            (&self.question_scope, "question_scope"),
            (&self.expected_decision, "expected_decision"),
            (&self.coverage_goal, "coverage_goal"),
            (&self.retention, "retention"),
            (&self.license_policy, "license_policy"),
            (&self.required_schema, "required_schema"),
        ] {
            text(value, field)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        self.allowed_references.validate()?;
        if self.allowed_references.state_fence != self.state_fence
            || self.budget_units == 0
            || self.deadline_ms <= 0
            || self.source_classes.is_empty()
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

/// Wire identity for the Kernel-delivered research dispatch route.
pub const RESEARCH_DISPATCH_WIRE_ID: &str = "eliot.kernel.research-dispatch";
/// Current research dispatch wire revision.
pub const RESEARCH_DISPATCH_WIRE_VERSION: u16 = 1;
/// Maximum size of the protected dispatch envelope and its request channel.
pub const RESEARCH_DISPATCH_MAX_BYTES: usize = 1_048_576;

fn claim_text(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(ResearchContractError::InvalidText { field });
    }
    Ok(())
}

fn claim_digest<T: Serialize>(value: &T) -> Result<String, ResearchContractError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|_| ResearchContractError::InvalidText { field: "canonical_dispatch_json" })?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn claim_nonce(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if !(16..=256).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ResearchContractError::InvalidText { field });
    }
    Ok(())
}

fn set_json_field(
    object: &mut serde_json::Value,
    key: &str,
    value: serde_json::Value,
) -> Result<(), ResearchContractError> {
    let Some(map) = object.as_object_mut() else {
        return Err(ResearchContractError::InvalidText {
            field: "provider_contract",
        });
    };
    if !map.contains_key(key) {
        return Err(ResearchContractError::InvalidText {
            field: "provider_contract",
        });
    }
    map.insert(key.to_owned(), value);
    Ok(())
}

fn set_nested_json_field(
    object: &mut serde_json::Value,
    path: &[&str],
    value: serde_json::Value,
) -> Result<(), ResearchContractError> {
    let Some((last, parents)) = path.split_last() else {
        return Err(ResearchContractError::InvalidText {
            field: "provider_contract",
        });
    };
    let mut current = object;
    for key in parents {
        current = current.get_mut(*key).ok_or(ResearchContractError::InvalidText {
            field: "provider_contract",
        })?;
    }
    set_json_field(current, last, value)
}

fn json_text(value: Option<&serde_json::Value>, field: &'static str) -> Result<String, ResearchContractError> {
    let value = value
        .and_then(serde_json::Value::as_str)
        .ok_or(ResearchContractError::InvalidText { field })?;
    claim_text(value, field)?;
    Ok(value.to_owned())
}

fn json_digest(value: Option<&serde_json::Value>, field: &'static str) -> Result<String, ResearchContractError> {
    let value = json_text(value, field)?;
    digest(&value, field)?;
    Ok(value)
}

/// Closed provider registration delivered by Host and pinned by Kernel.
///
/// The registration is not a request envelope. It is read once from the
/// protected Host descriptor, validated, and then used to issue claims for
/// authenticated requests. The provider-specific contract and registry remain
/// typed JSON at this wire boundary; the research provider adapter validates
/// them again against its closed `BridgeContract`/`ProviderRegistry` types
/// before any process effect.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchProviderRegistration {
    pub registration_id: String,
    pub registration_sha256: String,
    pub provider_contract: serde_json::Value,
    pub provider_registry: serde_json::Value,
    pub provider_contract_sha256: String,
    pub provider_registry_sha256: String,
    pub provider_executable: String,
    pub provider_executable_sha256: String,
    pub route_id: String,
    pub provider_id: String,
    pub module_id: String,
    pub module_generation_id: String,
    pub bridge_generation: String,
    pub protocol_revision: ContractVersion,
    pub required_schema: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub process_generation: u64,
    pub disclosure: DisclosureClass,
    pub data_class: String,
    pub credential_binding_id: String,
    pub credential_owner_principal: String,
    pub budget_ceiling: u64,
    pub deadline_ceiling_unix_ms: i64,
    pub owner_principal_digest: String,
}

impl ResearchProviderRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: impl Into<String>,
        provider_contract: serde_json::Value,
        provider_registry: serde_json::Value,
        provider_executable: impl Into<String>,
        provider_executable_sha256: impl Into<String>,
        route_id: impl Into<String>,
        provider_id: impl Into<String>,
        module_id: impl Into<String>,
        module_generation_id: impl Into<String>,
        bridge_generation: impl Into<String>,
        protocol_revision: ContractVersion,
        required_schema: impl Into<String>,
        authority_epoch: EpochId,
        state_fence: StateFence,
        process_generation: u64,
        disclosure: DisclosureClass,
        data_class: impl Into<String>,
        credential_binding_id: impl Into<String>,
        credential_owner_principal: impl Into<String>,
        budget_ceiling: u64,
        deadline_ceiling_unix_ms: i64,
        owner_principal_digest: impl Into<String>,
    ) -> Result<Self, ResearchContractError> {
        let value = Self {
            registration_id: registration_id.into(),
            registration_sha256: String::new(),
            provider_contract_sha256: claim_digest(&provider_contract)?,
            provider_registry_sha256: claim_digest(&provider_registry)?,
            provider_contract,
            provider_registry,
            provider_executable: provider_executable.into(),
            provider_executable_sha256: provider_executable_sha256.into(),
            route_id: route_id.into(),
            provider_id: provider_id.into(),
            module_id: module_id.into(),
            module_generation_id: module_generation_id.into(),
            bridge_generation: bridge_generation.into(),
            protocol_revision,
            required_schema: required_schema.into(),
            authority_epoch,
            state_fence,
            process_generation,
            disclosure,
            data_class: data_class.into(),
            credential_binding_id: credential_binding_id.into(),
            credential_owner_principal: credential_owner_principal.into(),
            budget_ceiling,
            deadline_ceiling_unix_ms,
            owner_principal_digest: owner_principal_digest.into(),
        };
        let mut value = value;
        value.registration_sha256 = claim_digest(&value)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.registration_id, "registration_id"),
            (&self.provider_executable, "provider_executable"),
            (&self.route_id, "route_id"),
            (&self.provider_id, "provider_id"),
            (&self.module_id, "module_id"),
            (&self.module_generation_id, "module_generation_id"),
            (&self.bridge_generation, "bridge_generation"),
            (&self.required_schema, "required_schema"),
            (&self.data_class, "data_class"),
            (&self.credential_binding_id, "credential_binding_id"),
            (&self.credential_owner_principal, "credential_owner_principal"),
            (&self.owner_principal_digest, "owner_principal_digest"),
        ] {
            claim_text(value, field)?;
        }
        if !std::path::Path::new(&self.provider_executable).is_absolute() {
            return Err(ResearchContractError::InvalidText {
                field: "provider_executable",
            });
        }
        digest(&self.provider_executable_sha256, "provider_executable_sha256")?;
        digest(&self.provider_contract_sha256, "provider_contract_sha256")?;
        digest(&self.provider_registry_sha256, "provider_registry_sha256")?;
        digest(&self.registration_sha256, "registration_sha256")?;
        if self.process_generation == 0
            || self.budget_ceiling == 0
            || self.deadline_ceiling_unix_ms <= 0
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        if !self.authority_epoch.is_same_authority(&self.state_fence.authority_epoch) {
            return Err(ResearchContractError::InvalidFence);
        }
        if self.claim_digest_without_registration()?
            != self.registration_sha256
        {
            return Err(ResearchContractError::InvalidDigest {
                field: "registration_sha256",
            });
        }
        if self.provider_contract_sha256 != claim_digest(&self.provider_contract)?
            || self.provider_registry_sha256 != claim_digest(&self.provider_registry)?
        {
            return Err(ResearchContractError::InvalidDigest {
                field: "provider_registration_digest",
            });
        }
        self.validate_contract_shape()
    }

    fn claim_digest_without_registration(&self) -> Result<String, ResearchContractError> {
        let mut copy = self.clone();
        copy.registration_sha256 = String::new();
        claim_digest(&copy)
    }

    fn validate_contract_shape(&self) -> Result<(), ResearchContractError> {
        let contract = &self.provider_contract;
        if json_text(contract.get("module_id"), "contract.module_id")? != self.module_id
            || json_text(contract.get("module_generation_id"), "contract.module_generation_id")?
                != self.module_generation_id
            || json_text(contract.get("bridge_generation"), "contract.bridge_generation")?
                != self.bridge_generation
            || json_text(contract.get("required_schema"), "contract.required_schema")?
                != self.required_schema
            || json_text(contract.get("data_class"), "contract.data_class")? != self.data_class
            || json_digest(
                contract.pointer("/bridge/executable_sha256"),
                "contract.bridge.executable_sha256",
            )? != self.provider_executable_sha256
            || json_text(contract.pointer("/bridge/executable"), "contract.bridge.executable")?
                != self.provider_executable
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        if contract.pointer("/route/route_id").and_then(serde_json::Value::as_str)
            != Some(self.route_id.as_str())
            || contract.pointer("/route/provider_id").and_then(serde_json::Value::as_str)
                != Some(self.provider_id.as_str())
            || contract.pointer("/route/credential_binding/binding_id")
                .and_then(serde_json::Value::as_str)
                != Some(self.credential_binding_id.as_str())
            || contract.pointer("/route/credential_binding/owner_principal")
                .and_then(serde_json::Value::as_str)
                != Some(self.credential_owner_principal.as_str())
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let records = self
            .provider_registry
            .get("records")
            .and_then(serde_json::Value::as_array)
            .ok_or(ResearchContractError::InvalidDisposition)?;
        let Some(record) = records.iter().find(|record| {
            record.get("module_id").and_then(serde_json::Value::as_str)
                == Some(self.module_id.as_str())
                && record.get("generation_id").and_then(serde_json::Value::as_str)
                    == Some(self.module_generation_id.as_str())
                && record.get("artifact_sha256").and_then(serde_json::Value::as_str)
                    == Some(self.provider_executable_sha256.as_str())
                && record.get("evidence_sha256").and_then(serde_json::Value::as_str)
                    == contract
                        .get("registry_evidence_sha256")
                        .and_then(serde_json::Value::as_str)
        }) else {
            return Err(ResearchContractError::InvalidDigest {
                field: "provider_registry",
            });
        };
        if record.get("route") != contract.get("route")
            || record.get("state_fence") != contract.get("fence")
        {
            return Err(ResearchContractError::InvalidDigest {
                field: "provider_registry",
            });
        }
        Ok(())
    }

    fn contract_for_request(
        &self,
        request: &ResearchQueryRequest,
        operation_id: &str,
        cancellation_id: &str,
    ) -> Result<serde_json::Value, ResearchContractError> {
        self.validate()?;
        request.validate()?;
        claim_text(operation_id, "operation_id")?;
        claim_nonce(cancellation_id, "cancellation_id")?;
        if request.state_fence != self.state_fence
            || request.bridge_generation != self.bridge_generation
            || request.protocol_revision != self.protocol_revision
            || request.required_schema != self.required_schema
            || request.disclosure != self.disclosure
            || request.budget_units > self.budget_ceiling
            || request.deadline_ms > self.deadline_ceiling_unix_ms
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let mut contract = self.provider_contract.clone();
        set_json_field(
            &mut contract,
            "process_generation",
            serde_json::json!(self.process_generation),
        )?;
        set_json_field(
            &mut contract,
            "epoch",
            serde_json::to_value(&self.authority_epoch).map_err(|_| {
                ResearchContractError::InvalidText {
                    field: "authority_epoch",
                }
            })?,
        )?;
        set_json_field(
            &mut contract,
            "fence",
            serde_json::to_value(&self.state_fence).map_err(|_| {
                ResearchContractError::InvalidText {
                    field: "state_fence",
                }
            })?,
        )?;
        set_json_field(
            &mut contract,
            "budget_units",
            serde_json::json!(request.budget_units),
        )?;
        set_json_field(
            &mut contract,
            "deadline_ms",
            serde_json::json!(request.deadline_ms),
        )?;
        set_json_field(
            &mut contract,
            "required_schema",
            serde_json::json!(request.required_schema),
        )?;
        set_json_field(
            &mut contract,
            "bridge_generation",
            serde_json::json!(request.bridge_generation),
        )?;
        set_nested_json_field(
            &mut contract,
            &["route", "data_class"],
            serde_json::json!(self.data_class),
        )?;
        set_nested_json_field(
            &mut contract,
            &["route", "credential_binding", "acting_principal"],
            serde_json::json!(request.requester_principal),
        )?;
        set_nested_json_field(
            &mut contract,
            &["cancellation", "operation_id"],
            serde_json::json!(operation_id),
        )?;
        set_nested_json_field(
            &mut contract,
            &["cancellation", "cancellation_id"],
            serde_json::json!(cancellation_id),
        )?;
        set_nested_json_field(
            &mut contract,
            &["cancellation", "owner_principal"],
            serde_json::json!(self.credential_owner_principal),
        )?;
        set_nested_json_field(
            &mut contract,
            &["cancellation", "deadline_unix_ms"],
            serde_json::json!(request.deadline_ms),
        )?;
        Ok(contract)
    }
}

/// Authenticated claim issued by Kernel for one authenticated research request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDispatchClaim {
    pub claim_version: u16,
    pub claim_sha256: String,
    pub registration_sha256: String,
    pub operation_id: String,
    pub request: ResearchQueryRequest,
    pub request_sha256: String,
    pub issuer_principal_digest: String,
    pub owner_principal_digest: String,
    pub session_id: String,
    pub session_nonce: String,
    pub authority_epoch: EpochId,
    pub state_fence: StateFence,
    pub process_generation: u64,
    pub provider_contract: serde_json::Value,
    pub provider_registry: serde_json::Value,
    pub provider_contract_sha256: String,
    pub provider_registry_sha256: String,
    pub provider_executable: String,
    pub provider_executable_sha256: String,
    pub budget_units: u64,
    pub deadline_unix_ms: i64,
    pub cancellation_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub claim_nonce: String,
}

impl ResearchDispatchClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn from_registration(
        registration: &ResearchProviderRegistration,
        request: ResearchQueryRequest,
        operation_id: impl Into<String>,
        issuer_principal_digest: impl Into<String>,
        owner_principal_digest: impl Into<String>,
        session_id: impl Into<String>,
        session_nonce: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<Self, ResearchContractError> {
        registration.validate()?;
        request.validate()?;
        let operation_id = operation_id.into();
        claim_text(&operation_id, "operation_id")?;
        let short = &claim_digest(&operation_id)?[..16];
        let cancellation_id = format!("research-cancel-{short}");
        let provider_contract = registration.contract_for_request(
            &request,
            &operation_id,
            &cancellation_id,
        )?;
        let mut provider_registry = registration.provider_registry.clone();
        let bound_route = provider_contract
            .get("route")
            .cloned()
            .ok_or(ResearchContractError::InvalidDisposition)?;
        let bound_fence = provider_contract
            .get("fence")
            .cloned()
            .ok_or(ResearchContractError::InvalidDisposition)?;
        if let Some(records) = provider_registry
            .get_mut("records")
            .and_then(serde_json::Value::as_array_mut)
        {
            for record in records.iter_mut() {
                if record.get("module_id").and_then(serde_json::Value::as_str)
                    == Some(registration.module_id.as_str())
                    && record.get("generation_id").and_then(serde_json::Value::as_str)
                        == Some(registration.module_generation_id.as_str())
                {
                    let Some(object) = record.as_object_mut() else {
                        return Err(ResearchContractError::InvalidDisposition);
                    };
                    object.insert("route".to_owned(), bound_route.clone());
                    object.insert("state_fence".to_owned(), bound_fence.clone());
                }
            }
        }
        let provider_registry_sha256 = claim_digest(&provider_registry)?;
        let expires_at_unix_ms = now_unix_ms
            .checked_add(60_000)
            .ok_or(ResearchContractError::InvalidDisposition)?;
        let value = Self {
            claim_version: RESEARCH_DISPATCH_WIRE_VERSION,
            claim_sha256: String::new(),
            registration_sha256: registration.registration_sha256.clone(),
            operation_id,
            request_sha256: claim_digest(&request)?,
            request,
            issuer_principal_digest: issuer_principal_digest.into(),
            owner_principal_digest: owner_principal_digest.into(),
            session_id: session_id.into(),
            session_nonce: session_nonce.into(),
            authority_epoch: registration.authority_epoch.clone(),
            state_fence: registration.state_fence.clone(),
            process_generation: registration.process_generation,
            provider_contract_sha256: claim_digest(&provider_contract)?,
            provider_registry_sha256,
            provider_contract,
            provider_registry,
            provider_executable: registration.provider_executable.clone(),
            provider_executable_sha256: registration.provider_executable_sha256.clone(),
            budget_units: registration.budget_ceiling,
            deadline_unix_ms: registration.deadline_ceiling_unix_ms,
            cancellation_id,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            claim_nonce: format!("research-claim-{short}"),
        };
        let mut value = value;
        value.budget_units = value.request.budget_units;
        value.deadline_unix_ms = value.request.deadline_ms;
        value.claim_sha256 = claim_digest(&value)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ResearchContractError> {
        if self.claim_version != RESEARCH_DISPATCH_WIRE_VERSION {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.request.validate()?;
        for (value, field) in [
            (&self.operation_id, "operation_id"),
            (&self.issuer_principal_digest, "issuer_principal_digest"),
            (&self.owner_principal_digest, "owner_principal_digest"),
            (&self.session_id, "session_id"),
            (&self.session_nonce, "session_nonce"),
            (&self.provider_executable, "provider_executable"),
            (&self.cancellation_id, "cancellation_id"),
            (&self.claim_nonce, "claim_nonce"),
        ] {
            claim_text(value, field)?;
        }
        claim_nonce(&self.session_nonce, "session_nonce")?;
        claim_nonce(&self.claim_nonce, "claim_nonce")?;
        if self.claim_sha256 != claim_digest(self)? {
            return Err(ResearchContractError::InvalidDigest {
                field: "claim_sha256",
            });
        }
        if self.request_sha256 != claim_digest(&self.request)?
            || self.budget_units != self.request.budget_units
            || self.deadline_unix_ms != self.request.deadline_ms
            || self.state_fence != self.request.state_fence
            || self.authority_epoch != self.request.state_fence.authority_epoch
            || self.process_generation == 0
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        digest(&self.claim_sha256, "claim_sha256")?;
        digest(&self.request_sha256, "request_sha256")?;
        digest(&self.registration_sha256, "registration_sha256")?;
        digest(&self.provider_contract_sha256, "provider_contract_sha256")?;
        digest(&self.provider_registry_sha256, "provider_registry_sha256")?;
        if self.provider_contract_sha256 != claim_digest(&self.provider_contract)?
            || self.provider_registry_sha256 != claim_digest(&self.provider_registry)?
            || !std::path::Path::new(&self.provider_executable).is_absolute()
            || self.provider_executable_sha256
                != json_digest(
                    self.provider_contract.pointer("/bridge/executable_sha256"),
                    "provider_executable_sha256",
                )?
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

/// Kernel launch grant carried beside the claim in the protected material file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDispatchGrant {
    pub grant_sha256: String,
    pub claim_sha256: String,
    pub authority_epoch: EpochId,
    pub fence_generation: u64,
    pub fence_nonce: String,
    pub idempotency_key: String,
    pub expires_at_unix_ms: u64,
}

/// Exact protected material consumed by `eliot-mod-research`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDispatchMaterial {
    pub material_version: u16,
    pub claim: ResearchDispatchClaim,
    pub grant: ResearchDispatchGrant,
}

impl ResearchDispatchMaterial {
    pub fn from_claim(claim: ResearchDispatchClaim) -> Result<Self, ResearchContractError> {
        claim.validate()?;
        let short = &claim.claim_sha256[..16];
        let fence_nonce = format!("research-dispatch-fence-{short}");
        let idempotency_key = format!("research-dispatch-lease-{short}");
        let expires_at_unix_ms = claim
            .expires_at_unix_ms
            .min(u64::try_from(claim.deadline_unix_ms).unwrap_or(u64::MAX));
        if expires_at_unix_ms <= claim.issued_at_unix_ms {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let epoch_json = serde_json::to_string(&claim.authority_epoch).map_err(|_| {
            ResearchContractError::InvalidText {
                field: "authority_epoch",
            }
        })?;
        let grant_material = format!(
            "{}|{}|{}|{}|{}|{}",
            claim.claim_sha256,
            epoch_json,
            claim.process_generation,
            fence_nonce,
            idempotency_key,
            expires_at_unix_ms
        );
        let grant = ResearchDispatchGrant {
            grant_sha256: eliot_contracts::sha256_hex(grant_material.as_bytes()),
            claim_sha256: claim.claim_sha256.clone(),
            authority_epoch: claim.authority_epoch.clone(),
            fence_generation: claim.process_generation,
            fence_nonce,
            idempotency_key,
            expires_at_unix_ms,
        };
        let value = Self {
            material_version: RESEARCH_DISPATCH_WIRE_VERSION,
            claim,
            grant,
        };
        value.validate(0)?;
        Ok(value)
    }

    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ResearchContractError> {
        if self.material_version != RESEARCH_DISPATCH_WIRE_VERSION {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.claim.validate()?;
        if self.grant.claim_sha256 != self.claim.claim_sha256
            || self.grant.authority_epoch != self.claim.authority_epoch
            || self.grant.fence_generation != self.claim.process_generation
            || self.grant.expires_at_unix_ms == 0
            || self.grant.expires_at_unix_ms > self.claim.expires_at_unix_ms
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let epoch_json = serde_json::to_string(&self.grant.authority_epoch).map_err(|_| {
            ResearchContractError::InvalidText {
                field: "authority_epoch",
            }
        })?;
        let material = format!(
            "{}|{}|{}|{}|{}|{}",
            self.claim.claim_sha256,
            epoch_json,
            self.grant.fence_generation,
            self.grant.fence_nonce,
            self.grant.idempotency_key,
            self.grant.expires_at_unix_ms
        );
        if self.grant.grant_sha256 != eliot_contracts::sha256_hex(material.as_bytes()) {
            return Err(ResearchContractError::InvalidDigest {
                field: "grant_sha256",
            });
        }
        if now_unix_ms != 0 && now_unix_ms >= self.grant.expires_at_unix_ms {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

/// Wire operation for an authenticated research lifecycle/reconcile request.
pub const RESEARCH_RECONCILE_OPERATION: &str = "eliot.kernel.research-reconcile";

/// Closed Kernel frame payload for a new research dispatch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchDispatchRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub request: ResearchQueryRequest,
    pub request_sha256: String,
}

impl ResearchDispatchRequest {
    pub fn new(request: ResearchQueryRequest) -> Result<Self, ResearchContractError> {
        let value = Self {
            wire_id: RESEARCH_DISPATCH_WIRE_ID.to_owned(),
            wire_version: RESEARCH_DISPATCH_WIRE_VERSION,
            request_sha256: claim_digest(&request)?,
            request,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ResearchContractError> {
        if self.wire_id != RESEARCH_DISPATCH_WIRE_ID
            || self.wire_version != RESEARCH_DISPATCH_WIRE_VERSION
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.request.validate()?;
        if self.request_sha256 != claim_digest(&self.request)? {
            return Err(ResearchContractError::InvalidDigest {
                field: "research_dispatch_request_sha256",
            });
        }
        Ok(())
    }
}

/// Closed Kernel frame payload for reconciling one retained operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchReconcileRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub operation_id: String,
    pub request_sha256: String,
}

impl ResearchReconcileRequest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        if self.wire_id != RESEARCH_RECONCILE_OPERATION
            || self.wire_version != RESEARCH_DISPATCH_WIRE_VERSION
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        claim_text(&self.operation_id, "operation_id")?;
        digest(&self.request_sha256, "request_sha256")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub source_handle: String,
    pub class: SourceClass,
    pub title: String,
    pub locator: String,
    pub snapshot_digest: String,
    pub captured_at: ClockReading,
    pub coverage: String,
    pub disclosure: DisclosureClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactCitation {
    pub source_handle: String,
    pub anchor: String,
    pub precision: AnchorPrecision,
    pub excerpt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaim {
    pub claim_id: String,
    pub statement: String,
    pub citations: Vec<ExactCitation>,
    pub counterclaim_ids: Vec<String>,
    pub confidence_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvidenceBundle {
    pub exchange_id: String,
    pub job_id: String,
    pub system_generation: String,
    pub immutable_bundle_digest: String,
    pub origin_authentication: String,
    pub state_fence: StateFence,
    pub sources: Vec<SourceSnapshot>,
    pub claims: Vec<ResearchClaim>,
    pub bounded_excerpts: Vec<String>,
    pub artifact_handles: Vec<String>,
    pub coverage_unknowns: Vec<String>,
    pub failed_acquisition: Vec<String>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
    pub disposition: CompletionDisposition,
    pub synthesis_is_candidate: bool,
    pub disclosure: DisclosureClass,
    pub invalidation: Option<String>,
}

impl ResearchEvidenceBundle {
    pub fn validate_against(
        &self,
        request: &ResearchQueryRequest,
    ) -> Result<(), ResearchContractError> {
        if self.exchange_id != request.exchange_id
            || self.state_fence != request.state_fence
            || !self.synthesis_is_candidate
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        digest(
            &self.immutable_bundle_digest,
            "bundle.immutable_bundle_digest",
        )?;
        text(&self.job_id, "bundle.job_id")?;
        text(&self.system_generation, "bundle.system_generation")?;
        text(&self.origin_authentication, "bundle.origin_authentication")?;
        for unknown in &self.coverage_unknowns {
            text(unknown, "bundle.coverage_unknowns")?;
        }
        for failed in &self.failed_acquisition {
            text(failed, "bundle.failed_acquisition")?;
        }
        let mut seen_gaps = BTreeSet::new();
        for gap in &self.coverage_gaps {
            gap.validate()?;
            if !seen_gaps.insert(&gap.source_handle) {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "bundle.coverage_gaps",
                });
            }
        }
        if self.coverage_gaps.iter().any(|gap| {
            self.sources
                .iter()
                .any(|s| s.source_handle == gap.source_handle)
        }) {
            return Err(ResearchContractError::InvalidDisposition);
        }
        if self.disposition == CompletionDisposition::AnsweredWithSupportedResult {
            if self.sources.is_empty() || self.claims.is_empty() {
                return Err(ResearchContractError::InvalidDisposition);
            }
            if !self.coverage_gaps.is_empty()
                || !self.coverage_unknowns.is_empty()
                || !self.failed_acquisition.is_empty()
            {
                return Err(ResearchContractError::InvalidDisposition);
            }
        }
        if self.disposition.requires_typed_coverage_gaps() && self.coverage_gaps.is_empty() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        for source in &self.sources {
            text(&source.source_handle, "source.source_handle")?;
            digest(&source.snapshot_digest, "source.snapshot_digest")?;
            source
                .captured_at
                .validate()
                .map_err(|_| ResearchContractError::InvalidDisposition)?;
        }
        for claim in &self.claims {
            text(&claim.claim_id, "claim.claim_id")?;
            text(&claim.statement, "claim.statement")?;
            text(&claim.confidence_note, "claim.confidence_note")?;
            if claim.citations.is_empty()
                && self.disposition == CompletionDisposition::AnsweredWithSupportedResult
            {
                return Err(ResearchContractError::CitationNotAllowed);
            }
            for citation in &claim.citations {
                if !request.allowed_references.allows(&citation.source_handle)
                    || !request
                        .allowed_references
                        .allowed_anchor_precision
                        .permits(citation.precision)
                    || !self
                        .sources
                        .iter()
                        .any(|s| s.source_handle == citation.source_handle)
                {
                    return Err(ResearchContractError::CitationNotAllowed);
                }
                text(&citation.anchor, "citation.anchor")?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn has_typed_coverage_gaps(&self) -> bool {
        !self.coverage_gaps.is_empty()
    }

    /// Whether the bundle carries an explicit budget-exhaustion gap entry.
    /// A13.11 keeps verified partial work AND the coverage gap on budget
    /// exhaustion; a close that hides exhaustion behind other gap kinds
    /// violates ARCH-RES-04 (degradation visible and local).
    #[must_use]
    pub fn has_budget_exhausted_gap(&self) -> bool {
        self.coverage_gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::BudgetExhausted)
    }

    #[must_use]
    pub fn typed_gap_handles(&self) -> Vec<&str> {
        let mut handles: Vec<&str> = self
            .coverage_gaps
            .iter()
            .map(|gap| gap.source_handle.as_str())
            .collect();
        handles.sort_unstable();
        handles
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchExportBundle {
    pub exchange_id: String,
    pub product_identity: String,
    pub payload_handle: String,
    pub source_handles: Vec<String>,
    pub redactions: Vec<String>,
    pub purpose: String,
    pub allowed_use: String,
    pub retention: String,
    pub return_channel: String,
    pub disclosure_decision: String,
}

impl ResearchExportBundle {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "export.exchange_id"),
            (&self.product_identity, "export.product_identity"),
            (&self.payload_handle, "export.payload_handle"),
            (&self.purpose, "export.purpose"),
            (&self.allowed_use, "export.allowed_use"),
            (&self.retention, "export.retention"),
            (&self.return_channel, "export.return_channel"),
            (&self.disclosure_decision, "export.disclosure_decision"),
        ] {
            text(value, field)?;
        }
        texts(&self.source_handles, "export.source_handles")
    }
}
