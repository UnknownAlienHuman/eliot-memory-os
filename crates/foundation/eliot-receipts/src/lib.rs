//! Immutable, store-neutral receipt contracts for ELIOT C0-02.
//!
//! This crate describes what a receipt binds and what it can prove.  It does
//! not persist receipts, execute effects, decide task completion, or issue
//! authority.  A caller must validate the same envelope after every transport
//! or storage boundary; constructors never infer missing authority or proof.

#![forbid(unsafe_code)]

use std::{fmt, str::FromStr};

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractError, ContractId, ContractIdentity, ContractVersion,
    ErrorCode, OperationId, ProductId, ReceiptId, RequestId, RequestMetadata, ResourceGeneration,
    SessionId, StateFence, TaskId, TaskRevision, TransactionSequence, canonical_json_bytes,
    contract_identity as make_contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable wire name for this C0-02 contract family.
pub const CONTRACT_NAME: &str = "eliot.foundation.receipts";
/// Current wire revision for this contract family.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A receipt-contract validation failure.  No variant contains raw provider or
/// secret material, so it can safely cross an agent boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReceiptError {
    /// A shared C0-01 primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// Canonical JSON serialization failed.
    #[error("canonical receipt serialization failed: {0}")]
    Serialization(String),
    /// A required receipt field was absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// Two bindings that must share one fence disagree.
    #[error("{left} and {right} have different State Fences")]
    FenceMismatch {
        left: &'static str,
        right: &'static str,
    },
    /// The operation binding is not the request it claims to report.
    #[error("operation request binding does not match request metadata")]
    RequestMismatch,
    /// The parent/predecessor chain is not a valid immutable chain.
    #[error("receipt causal chain is invalid: {0}")]
    InvalidChain(&'static str),
    /// The verifier names an artifact absent from the envelope.
    #[error("verifier references an artifact that is not bound by the receipt")]
    VerifierArtifactMismatch,
    /// A disposition claims a proof ceiling it cannot support.
    #[error("disposition exceeds its permitted proof ceiling")]
    ProofOverclaim,
    /// The supplied identity does not match canonical receipt bytes.
    #[error("receipt identity does not match canonical receipt bytes")]
    IdentityMismatch,
}

fn text(value: &str, field: &'static str) -> Result<(), ReceiptError> {
    if value.trim().is_empty() {
        return Err(ReceiptError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ReceiptError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ReceiptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReceiptError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 hex digest",
        });
    }
    Ok(())
}

/// Stable scope identity used by a receipt without making a filesystem path
/// or repository display name authoritative.
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct WorkScopeId(String);

impl WorkScopeId {
    /// Creates a validated scope identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is blank or contains control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ReceiptError> {
        let value = value.into();
        text(&value, "work_scope_id")?;
        Ok(Self(value))
    }

    /// Returns the stable text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkScopeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for WorkScopeId {
    type Err = ReceiptError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Why a receipt exists in a coordination chain.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptKind {
    Request,
    Operation,
    Artifact,
    Verification,
    Coordination,
    Problem,
}

/// The strongest proof interpretation a receipt is allowed to carry.
///
/// There is intentionally no task-finish or release verdict here.  Those are
/// owned by higher-level acceptance and release contracts.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofCeiling {
    Observation,
    CandidateArtifact,
    ScopedVerification,
    ObservedExternalEffect,
}

impl ProofCeiling {
    /// Whether `self` is no stronger than `other`.
    #[must_use]
    pub const fn is_at_most(self, other: Self) -> bool {
        self as u8 <= other as u8
    }
}

/// The bounded effect class named by an operation or authority binding.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    Read,
    Candidate,
    ReversibleMutation,
    ExternalEffect,
}

/// The outcome class of the one operation observation represented by a
/// receipt.  The enum does not imply task completion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ReceiptDisposition {
    /// The bounded operation produced the expected scoped observation.
    Success { proof: ProofCeiling },
    /// Some sub-effects or artifacts are known, while named gaps remain.
    Partial {
        proof: ProofCeiling,
        unresolved: Vec<String>,
    },
    /// The operation failed with a typed error code.
    Failure {
        code: ErrorCode,
        proof: ProofCeiling,
    },
    /// The external state cannot yet be classified safely.
    Unknown { reason: String },
    /// The operation was cancelled before the receipt was emitted.
    Cancelled { reason: String },
}

impl ReceiptDisposition {
    /// Returns the stable disposition class.
    #[must_use]
    pub const fn kind(&self) -> ReceiptDispositionKind {
        match self {
            Self::Success { .. } => ReceiptDispositionKind::Success,
            Self::Partial { .. } => ReceiptDispositionKind::Partial,
            Self::Failure { .. } => ReceiptDispositionKind::Failure,
            Self::Unknown { .. } => ReceiptDispositionKind::Unknown,
            Self::Cancelled { .. } => ReceiptDispositionKind::Cancelled,
        }
    }

    fn validate(&self) -> Result<(), ReceiptError> {
        match self {
            Self::Success { proof } | Self::Failure { proof, .. } => {
                if *proof > ProofCeiling::ObservedExternalEffect {
                    return Err(ReceiptError::ProofOverclaim);
                }
            }
            Self::Partial { proof, unresolved } => {
                if unresolved.is_empty()
                    || unresolved
                        .iter()
                        .any(|item| text(item, "unresolved").is_err())
                {
                    return Err(ReceiptError::InvalidField {
                        field: "unresolved",
                        reason: "partial receipts require non-blank unresolved items",
                    });
                }
                if *proof > ProofCeiling::ScopedVerification {
                    return Err(ReceiptError::ProofOverclaim);
                }
            }
            Self::Unknown { reason } | Self::Cancelled { reason } => {
                text(reason, "disposition.reason")?;
            }
        }
        Ok(())
    }

    fn proof_ceiling(&self) -> ProofCeiling {
        match self {
            Self::Success { proof } | Self::Partial { proof, .. } | Self::Failure { proof, .. } => {
                *proof
            }
            Self::Unknown { .. } | Self::Cancelled { .. } => ProofCeiling::Observation,
        }
    }
}

/// Stable class projection for indexing without matching payload fields.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptDispositionKind {
    Success,
    Partial,
    Failure,
    Unknown,
    Cancelled,
}

/// `WorkScope` binding captured when the receipt was produced.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeBinding {
    pub scope_id: WorkScopeId,
    pub product_id: ProductId,
    pub resource_generation: ResourceGeneration,
    pub state_fence: StateFence,
}

impl WorkScopeBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.state_fence.validate()?;
        if self.state_fence.resource_generation != self.resource_generation {
            return Err(ReceiptError::FenceMismatch {
                left: "work_scope.resource_generation",
                right: "work_scope.state_fence",
            });
        }
        Ok(())
    }
}

/// Task identity and plan revision bound to a receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBinding {
    pub task_id: TaskId,
    pub task_revision: TaskRevision,
    pub state_fence: StateFence,
}

impl TaskBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        Ok(self.state_fence.validate()?)
    }
}

/// Session identity bound to the authority epoch observed by the receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBinding {
    pub session_id: SessionId,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
}

impl SessionBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.state_fence.validate()?;
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ReceiptError::FenceMismatch {
                left: "session.authority_epoch",
                right: "session.state_fence",
            });
        }
        Ok(())
    }
}

/// Causal predecessor and sequence binding.  A receipt is a node in an
/// append-only chain, not an invitation to rewrite earlier history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalBinding {
    pub state_fence: StateFence,
    pub transaction_sequence: TransactionSequence,
    pub parent_receipt_id: Option<ReceiptId>,
    pub predecessor_receipt_ids: Vec<ReceiptId>,
}

impl CausalBinding {
    fn validate(&self, receipt_id: Option<&ReceiptId>) -> Result<(), ReceiptError> {
        self.state_fence.validate()?;
        let mut seen = std::collections::BTreeSet::new();
        for predecessor in &self.predecessor_receipt_ids {
            if !seen.insert(predecessor) {
                return Err(ReceiptError::InvalidChain("duplicate predecessor"));
            }
            if receipt_id.is_some_and(|current| current == predecessor) {
                return Err(ReceiptError::InvalidChain("receipt cannot precede itself"));
            }
        }
        if let Some(parent) = &self.parent_receipt_id {
            if receipt_id.is_some_and(|current| current == parent) {
                return Err(ReceiptError::InvalidChain("receipt cannot parent itself"));
            }
            if !self
                .predecessor_receipt_ids
                .iter()
                .any(|item| item == parent)
            {
                return Err(ReceiptError::InvalidChain("parent must be a predecessor"));
            }
        }
        if self.transaction_sequence.value() > 1 && self.parent_receipt_id.is_none() {
            return Err(ReceiptError::InvalidChain(
                "non-genesis receipt requires a parent",
            ));
        }
        Ok(())
    }
}

/// Request binding copied from the C0-01 request metadata.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    pub metadata: RequestMetadata,
    pub state_fence: StateFence,
}

impl RequestBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.metadata.validate()?;
        if self.metadata.state_fence != self.state_fence {
            return Err(ReceiptError::FenceMismatch {
                left: "request.metadata",
                right: "request.state_fence",
            });
        }
        Ok(())
    }
}

/// Effect identity and idempotency binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBinding {
    pub operation_id: OperationId,
    pub request_id: RequestId,
    pub idempotency_key: String,
    pub operation_kind: String,
    pub effect: EffectClass,
    pub state_fence: StateFence,
}

impl OperationBinding {
    fn validate(&self, request: &RequestBinding) -> Result<(), ReceiptError> {
        text(&self.idempotency_key, "operation.idempotency_key")?;
        text(&self.operation_kind, "operation.operation_kind")?;
        self.state_fence.validate()?;
        if self.request_id != request.metadata.request_id {
            return Err(ReceiptError::RequestMismatch);
        }
        Ok(())
    }
}

/// Explicit authority and proof ceiling observed by the operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    pub authority_id: ContractId,
    pub authority_owner: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub allowed_effect: EffectClass,
    pub proof_ceiling: ProofCeiling,
}

impl AuthorityBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        text(&self.authority_owner, "authority.authority_owner")?;
        self.state_fence.validate()?;
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ReceiptError::FenceMismatch {
                left: "authority.authority_epoch",
                right: "authority.state_fence",
            });
        }
        Ok(())
    }
}

/// Immutable artifact observed by an operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub artifact_id: ArtifactId,
    pub sha256: String,
    pub role: ReceiptKind,
    pub source_revision: Option<String>,
}

impl ArtifactBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        digest(&self.sha256, "artifact.sha256")?;
        if let Some(revision) = &self.source_revision {
            text(revision, "artifact.source_revision")?;
        }
        Ok(())
    }
}

/// Verifier and exact artifact references.  This records verification scope;
/// it does not set task completion or release status.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierBinding {
    pub verifier_id: ContractId,
    pub verifier_revision: ContractVersion,
    pub artifact_ids: Vec<ArtifactId>,
    pub proof_ceiling: ProofCeiling,
    pub state_fence: StateFence,
}

impl VerifierBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        self.state_fence.validate()?;
        if self.artifact_ids.is_empty() {
            return Err(ReceiptError::InvalidField {
                field: "verifier.artifact_ids",
                reason: "must contain at least one artifact",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        if self.artifact_ids.iter().any(|id| !seen.insert(id)) {
            return Err(ReceiptError::InvalidField {
                field: "verifier.artifact_ids",
                reason: "must not contain duplicates",
            });
        }
        Ok(())
    }
}

/// A Problem binding preserves an unresolved issue without turning it into a
/// finish or release verdict.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBinding {
    pub problem_id: ContractId,
    pub code: ErrorCode,
    pub state_fence: StateFence,
}

impl ProblemBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        Ok(self.state_fence.validate()?)
    }
}

/// Optional durable coordination event binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationBinding {
    pub event_id: ContractId,
    pub idempotency_key: String,
    pub state_fence: StateFence,
}

impl CoordinationBinding {
    fn validate(&self) -> Result<(), ReceiptError> {
        text(&self.idempotency_key, "coordination.idempotency_key")?;
        Ok(self.state_fence.validate()?)
    }
}

/// Fields whose canonical bytes define immutable receipt identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCore {
    pub contract: ContractIdentity,
    pub kind: ReceiptKind,
    pub work_scope: WorkScopeBinding,
    pub task: Option<TaskBinding>,
    pub session: Option<SessionBinding>,
    pub causal: CausalBinding,
    pub request: RequestBinding,
    pub operation: OperationBinding,
    pub authority: AuthorityBinding,
    pub artifacts: Vec<ArtifactBinding>,
    pub verifier: Option<VerifierBinding>,
    pub problem: Option<ProblemBinding>,
    pub coordination: Option<CoordinationBinding>,
    pub disposition: ReceiptDisposition,
}

/// Deterministic identity for one canonical receipt core.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIdentity {
    pub receipt_id: ReceiptId,
    pub canonical_sha256: String,
}

impl ReceiptIdentity {
    fn validate(&self) -> Result<(), ReceiptError> {
        digest(&self.canonical_sha256, "identity.canonical_sha256")
    }
}

/// Immutable receipt envelope.  Clone/serialization only copy the already
/// issued value; they do not make a second authority or storage owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEnvelope {
    pub identity: ReceiptIdentity,
    pub core: ReceiptCore,
}

/// Compatibility name used by consumers that refer to a receipt directly.
pub type Receipt = ReceiptEnvelope;
/// Compatibility name for the immutable receipt contract surface.
pub type ReceiptContract = ReceiptEnvelope;
/// Short names for the bound contract records.
pub type WorkScope = WorkScopeBinding;
/// Short name for the task binding.
pub type Task = TaskBinding;
/// Short name for the session binding.
pub type Session = SessionBinding;
/// Short name for the authority binding.
pub type Authority = AuthorityBinding;
/// Short name for the operation binding.
pub type Operation = OperationBinding;
/// Short name for the artifact binding.
pub type Artifact = ArtifactBinding;
/// Short name for the verifier binding.
pub type Verifier = VerifierBinding;
/// Short name for the problem binding.
pub type Problem = ProblemBinding;

impl ReceiptEnvelope {
    /// Issues a receipt from a complete immutable core and derives its identity
    /// from canonical core bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when a binding, chain, disposition, or canonical
    /// serialization is invalid.
    pub fn issue(core: ReceiptCore) -> Result<Self, ReceiptError> {
        validate_core(&core, None)?;
        let bytes = canonical_json_bytes(&core)
            .map_err(|error| ReceiptError::Serialization(error.to_string()))?;
        let canonical_sha256 = sha256_hex(&bytes);
        let receipt_id = ReceiptId::new(format!("receipt-{canonical_sha256}"))?;
        Ok(Self {
            identity: ReceiptIdentity {
                receipt_id,
                canonical_sha256,
            },
            core,
        })
    }

    /// Alias for [`Self::issue`] for consumers that use constructor wording.
    ///
    /// # Errors
    ///
    /// Returns the same validation or serialization errors as [`Self::issue`].
    pub fn new(core: ReceiptCore) -> Result<Self, ReceiptError> {
        Self::issue(core)
    }

    /// Validates all bindings, identity, causal links and proof ceilings.
    ///
    /// # Errors
    ///
    /// Returns an error when any binding, chain, proof ceiling, or derived
    /// identity does not match the immutable core.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        self.identity.validate()?;
        validate_core(&self.core, Some(&self.identity.receipt_id))?;
        let bytes = canonical_json_bytes(&self.core)
            .map_err(|error| ReceiptError::Serialization(error.to_string()))?;
        let digest = sha256_hex(&bytes);
        if digest != self.identity.canonical_sha256
            || self.identity.receipt_id.as_str() != format!("receipt-{digest}")
        {
            return Err(ReceiptError::IdentityMismatch);
        }
        Ok(())
    }

    /// Returns deterministic bytes used for identity and tamper checks.
    ///
    /// # Errors
    ///
    /// Returns an error when receipt validation fails or canonical serialization
    /// cannot be produced.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        self.validate()?;
        canonical_json_bytes(&self.core)
            .map_err(|error| ReceiptError::Serialization(error.to_string()))
    }

    /// Returns the stable receipt identity digest.
    #[must_use]
    pub fn canonical_sha256(&self) -> &str {
        &self.identity.canonical_sha256
    }

    /// Returns the operation's idempotency identity.  This is a locator for
    /// deduplication; it does not authorize replay or mutate a store.
    ///
    /// # Errors
    ///
    /// Returns an error when receipt validation fails.
    pub fn idempotency_identity(&self) -> Result<String, ReceiptError> {
        self.validate()?;
        let value = (
            self.core.operation.operation_id.as_str(),
            self.core.request.metadata.request_id.as_str(),
            self.core.operation.idempotency_key.as_str(),
        );
        let bytes = canonical_json_bytes(&value)
            .map_err(|error| ReceiptError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Returns the immutable identity of this receipt contract family.
///
/// # Errors
///
/// Returns an error if the contract shape cannot be serialized canonically.
pub fn contract_identity() -> Result<ContractIdentity, ReceiptError> {
    #[derive(Serialize)]
    struct Shape {
        kind: &'static str,
        version: ContractVersion,
        identity: &'static str,
        proof_ceiling: &'static str,
    }
    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            kind: "immutable_receipt_envelope",
            version: CONTRACT_VERSION,
            identity: "sha256(canonical_core)",
            proof_ceiling: "observation|candidate_artifact|scoped_verification|observed_external_effect",
        },
    )
        .map_err(ReceiptError::Foundation)
}

fn validate_core(core: &ReceiptCore, receipt_id: Option<&ReceiptId>) -> Result<(), ReceiptError> {
    core.contract.validate()?;
    if core.contract.name.as_str() != CONTRACT_NAME || core.contract.version != CONTRACT_VERSION {
        return Err(ReceiptError::InvalidField {
            field: "contract",
            reason: "wrong receipt contract identity",
        });
    }
    core.work_scope.validate()?;
    if let Some(task) = &core.task {
        task.validate()?;
    }
    if let Some(session) = &core.session {
        session.validate()?;
    }
    core.causal.validate(receipt_id)?;
    core.request.validate()?;
    core.operation.validate(&core.request)?;
    core.authority.validate()?;
    core.disposition.validate()?;

    let fences = [
        ("work_scope", &core.work_scope.state_fence),
        ("causal", &core.causal.state_fence),
        ("request", &core.request.state_fence),
        ("operation", &core.operation.state_fence),
        ("authority", &core.authority.state_fence),
    ];
    let first = fences[0].1;
    for (name, fence) in fences.iter().skip(1) {
        if *fence != first {
            return Err(ReceiptError::FenceMismatch {
                left: "work_scope",
                right: name,
            });
        }
    }
    if let Some(task) = &core.task
        && task.state_fence != *first
    {
        return Err(ReceiptError::FenceMismatch {
            left: "work_scope",
            right: "task",
        });
    }
    if let Some(session) = &core.session
        && session.state_fence != *first
    {
        return Err(ReceiptError::FenceMismatch {
            left: "work_scope",
            right: "session",
        });
    }
    for artifact in &core.artifacts {
        artifact.validate()?;
    }
    if let Some(verifier) = &core.verifier {
        verifier.validate()?;
        if verifier.state_fence != *first {
            return Err(ReceiptError::FenceMismatch {
                left: "work_scope",
                right: "verifier",
            });
        }
        if verifier.artifact_ids.iter().any(|id| {
            !core
                .artifacts
                .iter()
                .any(|artifact| &artifact.artifact_id == id)
        }) {
            return Err(ReceiptError::VerifierArtifactMismatch);
        }
        if verifier.proof_ceiling > core.disposition.proof_ceiling() {
            return Err(ReceiptError::ProofOverclaim);
        }
    }
    if let Some(problem) = &core.problem {
        problem.validate()?;
        if problem.state_fence != *first {
            return Err(ReceiptError::FenceMismatch {
                left: "work_scope",
                right: "problem",
            });
        }
    }
    if let Some(coordination) = &core.coordination {
        coordination.validate()?;
        if coordination.state_fence != *first {
            return Err(ReceiptError::FenceMismatch {
                left: "work_scope",
                right: "coordination",
            });
        }
    }
    Ok(())
}

/// Builds the smallest valid test receipt without IO or external state.
#[cfg(test)]
fn fixture_core() -> Result<ReceiptCore, ReceiptError> {
    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    let request_id = RequestId::new("request-1")?;
    let metadata = RequestMetadata {
        request_id: request_id.clone(),
        session_id: Some(SessionId::new("session-1")?),
        task_id: Some(TaskId::new("task-1")?),
        product_id: ProductId::new("product-1")?,
        source_id: eliot_contracts::SourceId::new("source-1")?,
        state_fence: fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(10),
            known_time_ms: Some(11),
            transaction_sequence: Some(TransactionSequence::genesis()),
            monotonic_ns: Some(12),
        },
    };
    let artifact_id = ArtifactId::new("artifact-1")?;
    Ok(ReceiptCore {
        contract: contract_identity()?,
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-1")?,
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::genesis(),
            state_fence: fence.clone(),
        },
        task: Some(TaskBinding {
            task_id: TaskId::new("task-1")?,
            task_revision: TaskRevision::genesis(),
            state_fence: fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: SessionId::new("session-1")?,
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata,
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: OperationId::new("operation-1")?,
            request_id,
            idempotency_key: "idempotency-1".to_owned(),
            operation_kind: "verify".to_owned(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-1")?,
            authority_owner: "governor".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: artifact_id.clone(),
            sha256: sha256_hex(b"artifact-1"),
            role: ReceiptKind::Artifact,
            source_revision: Some("source-rev-1".to_owned()),
        }],
        verifier: Some(VerifierBinding {
            verifier_id: ContractId::new("verifier-1")?,
            verifier_revision: ContractVersion::new(1, 0, 0),
            artifact_ids: vec![artifact_id],
            proof_ceiling: ProofCeiling::ScopedVerification,
            state_fence: fence,
        }),
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::ScopedVerification,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn issue_roundtrips_and_identity_is_deterministic() -> TestResult {
        let first = ReceiptEnvelope::issue(fixture_core()?)?;
        let second = ReceiptEnvelope::issue(fixture_core()?)?;
        assert_eq!(first, second);
        first.validate()?;
        let wire = serde_json::to_string(&first)?;
        let decoded: ReceiptEnvelope = serde_json::from_str(&wire)?;
        assert_eq!(decoded, first);
        assert!(!first.canonical_bytes()?.is_empty());
        Ok(())
    }

    #[test]
    fn tampered_identity_and_core_are_rejected() -> TestResult {
        let mut receipt = ReceiptEnvelope::issue(fixture_core()?)?;
        receipt.identity.canonical_sha256 = sha256_hex(b"tampered");
        assert_eq!(receipt.validate(), Err(ReceiptError::IdentityMismatch));

        let mut receipt = ReceiptEnvelope::issue(fixture_core()?)?;
        receipt.core.operation.idempotency_key = "changed".to_owned();
        assert_eq!(receipt.validate(), Err(ReceiptError::IdentityMismatch));
        Ok(())
    }

    #[test]
    fn stale_fence_and_request_mismatch_fail_closed() -> TestResult {
        let mut core = fixture_core()?;
        core.operation.state_fence =
            StateFence::new(AuthorityEpoch::new(2)?, ResourceGeneration::genesis());
        assert!(matches!(
            ReceiptEnvelope::issue(core),
            Err(ReceiptError::FenceMismatch { .. })
        ));

        let mut core = fixture_core()?;
        core.operation.request_id = RequestId::new("other-request")?;
        assert_eq!(
            ReceiptEnvelope::issue(core),
            Err(ReceiptError::RequestMismatch)
        );
        Ok(())
    }

    #[test]
    fn invalid_chain_and_verifier_reference_are_rejected() -> TestResult {
        let mut core = fixture_core()?;
        let parent = ReceiptId::new("receipt-parent")?;
        core.causal.parent_receipt_id = Some(parent.clone());
        core.causal.predecessor_receipt_ids = vec![parent];
        core.causal.transaction_sequence = TransactionSequence::new(2)?;
        let receipt = ReceiptEnvelope::issue(core)?;
        assert!(receipt.validate().is_ok());

        let mut core = fixture_core()?;
        core.verifier = Some(VerifierBinding {
            verifier_id: ContractId::new("verifier-2")?,
            verifier_revision: ContractVersion::new(1, 0, 0),
            artifact_ids: vec![ArtifactId::new("missing")?],
            proof_ceiling: ProofCeiling::ScopedVerification,
            state_fence: core.work_scope.state_fence.clone(),
        });
        assert_eq!(
            ReceiptEnvelope::issue(core),
            Err(ReceiptError::VerifierArtifactMismatch)
        );
        Ok(())
    }

    #[test]
    fn unknown_and_partial_preserve_uncertainty() -> TestResult {
        let mut core = fixture_core()?;
        core.disposition = ReceiptDisposition::Unknown {
            reason: "external outcome not observable".to_owned(),
        };
        core.verifier = None;
        let receipt = ReceiptEnvelope::issue(core)?;
        assert_eq!(
            receipt.core.disposition.kind(),
            ReceiptDispositionKind::Unknown
        );
        assert_eq!(
            receipt.core.disposition.proof_ceiling(),
            ProofCeiling::Observation
        );

        let mut core = fixture_core()?;
        core.disposition = ReceiptDisposition::Partial {
            proof: ProofCeiling::ScopedVerification,
            unresolved: vec!["second artifact".to_owned()],
        };
        let receipt = ReceiptEnvelope::issue(core)?;
        assert_eq!(
            receipt.core.disposition.kind(),
            ReceiptDispositionKind::Partial
        );
        Ok(())
    }

    #[test]
    fn duplicate_predecessor_and_blank_idempotency_fail() -> TestResult {
        let mut core = fixture_core()?;
        let parent = ReceiptId::new("receipt-parent")?;
        core.causal.parent_receipt_id = Some(parent.clone());
        core.causal.predecessor_receipt_ids = vec![parent.clone(), parent];
        core.causal.transaction_sequence = TransactionSequence::new(2)?;
        assert_eq!(
            ReceiptEnvelope::issue(core),
            Err(ReceiptError::InvalidChain("duplicate predecessor"))
        );

        let mut core = fixture_core()?;
        core.operation.idempotency_key = " ".to_owned();
        assert!(matches!(
            ReceiptEnvelope::issue(core),
            Err(ReceiptError::InvalidField {
                field: "operation.idempotency_key",
                ..
            })
        ));
        Ok(())
    }
}
