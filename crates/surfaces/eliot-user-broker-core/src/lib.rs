//! A-09 provider-neutral interactive user-broker core.
//!
//! This crate owns admission and lifecycle composition only.  G-01 supplies
//! authenticated grants, P-04 supplies the physical implementation behind the
//! P-03 process contract, and durable registration state is injected.  No
//! Windows API, SCM, process, credential, or storage implementation lives here.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_process::{
    CancellationReceipt, EnvironmentProjection, Generation, ImageId, JobId, OperationId,
    ProcessExecutionView, ProcessLifecycle, ProcessStartReceipt, ProcessTreeId, ResourceLimits,
    SecretRef, SessionId,
};
use eliot_protocol::ProtocolVersion;
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::EffectCeiling;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(test)]
use uuid::Uuid;

pub const CONTRACT_NAME: &str = "eliot.surfaces.user-broker-core/v1";
pub const OPERATOR_ROLE: &str = "human_operator";
pub const OPERATOR_CAPABILITIES: [&str; 2] = ["controlboard.read", "operator.command"];
pub const OPERATOR_HANDOFF_TTL_MS: u64 = 5_000;
pub const OPERATOR_PIPE_NAME: &str = r"\\.\pipe\eliot\operator\one-shot";

/// Broker-to-Operator handoff bound to one interactive session and epoch.
/// This envelope contains no bearer credential or filesystem auth reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorEndpoint {
    pub pipe_name: String,
    pub broker_epoch: u64,
    pub interactive_session_id: String,
    pub handoff_nonce: String,
    pub role: String,
    pub capabilities: Vec<String>,
}

impl OperatorEndpoint {
    pub fn validate(&self) -> Result<(), BrokerError> {
        text(&self.pipe_name, "pipe_name")?;
        text(&self.interactive_session_id, "interactive_session_id")?;
        text(&self.handoff_nonce, "handoff_nonce")?;
        if self.broker_epoch == 0
            || self.role != OPERATOR_ROLE
            || !exact_operator_capabilities(&self.capabilities)
        {
            return Err(BrokerError::InvalidField("operator_endpoint_binding"));
        }
        Ok(())
    }
}

fn exact_operator_capabilities(values: &[String]) -> bool {
    values.len() == OPERATOR_CAPABILITIES.len()
        && values
            .iter()
            .zip(OPERATOR_CAPABILITIES)
            .all(|(actual, expected)| actual == expected)
}

/// Installation-approved immutable Operator image.  A caller can request
/// only this exact path, image identity, and artifact digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorArtifact {
    pub image_id: String,
    pub executable: String,
    pub artifact_digest: String,
}

impl OperatorArtifact {
    pub fn validate(&self) -> Result<(), BrokerError> {
        text(&self.image_id, "operator_image_id")?;
        text(&self.executable, "operator_executable")?;
        text(&self.artifact_digest, "operator_artifact_digest")?;
        hex_digest(&self.artifact_digest, "operator_artifact_digest")
    }
}

/// Request accepted by the broker launch boundary.  It deliberately has no
/// executable or capability fields: those are selected by the broker policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorHandoffRequest {
    pub role: String,
    pub capabilities: Vec<String>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct HandoffState {
    endpoint: OperatorEndpoint,
    expires_at: u64,
    consumed: bool,
}

/// One-shot broker handoff authority.  The nonce is an authenticator for one
/// inherited endpoint parse, not a reconnect token or durable credential.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct OperatorHandoffAuthority {
    artifact: OperatorArtifact,
    pipe_name: String,
    broker_epoch: u64,
    interactive_session_id: String,
    handoffs: BTreeMap<String, HandoffState>,
}

#[cfg(test)]
impl OperatorHandoffAuthority {
    pub(crate) fn new(
        artifact: OperatorArtifact,
        pipe_name: String,
        broker_epoch: u64,
        interactive_session_id: String,
    ) -> Result<Self, BrokerError> {
        artifact.validate()?;
        if pipe_name != OPERATOR_PIPE_NAME || broker_epoch == 0 {
            return Err(BrokerError::InvalidField("operator_handoff_policy"));
        }
        text(&interactive_session_id, "interactive_session_id")?;
        Ok(Self {
            artifact,
            pipe_name,
            broker_epoch,
            interactive_session_id,
            handoffs: BTreeMap::new(),
        })
    }

    pub(crate) fn issue(
        &mut self,
        request: &OperatorHandoffRequest,
        observed_at: u64,
    ) -> Result<OperatorEndpoint, BrokerError> {
        if request.role != OPERATOR_ROLE
            || !exact_operator_capabilities(&request.capabilities)
            || observed_at == 0
        {
            return Err(BrokerError::Denied);
        }
        let expires_at = observed_at
            .checked_add(OPERATOR_HANDOFF_TTL_MS)
            .ok_or(BrokerError::Denied)?;
        let nonce = Uuid::new_v4().simple().to_string();
        text(&nonce, "handoff_nonce")?;
        let endpoint = OperatorEndpoint {
            pipe_name: self.pipe_name.clone(),
            broker_epoch: self.broker_epoch,
            interactive_session_id: self.interactive_session_id.clone(),
            handoff_nonce: nonce.clone(),
            role: OPERATOR_ROLE.to_owned(),
            capabilities: OPERATOR_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        endpoint.validate()?;
        if self.handoffs.contains_key(&nonce) {
            return Err(BrokerError::ReplayConflict);
        }
        self.handoffs.insert(
            nonce,
            HandoffState {
                endpoint: endpoint.clone(),
                expires_at,
                consumed: false,
            },
        );
        Ok(endpoint)
    }

    pub(crate) fn consume(
        &mut self,
        endpoint: &OperatorEndpoint,
        now: u64,
    ) -> Result<&OperatorArtifact, BrokerError> {
        endpoint.validate()?;
        {
            let state = self
                .handoffs
                .get_mut(&endpoint.handoff_nonce)
                .ok_or(BrokerError::ReplayConflict)?;
            if state.consumed || now >= state.expires_at || state.endpoint != *endpoint {
                return Err(if now >= state.expires_at {
                    BrokerError::StaleLease
                } else {
                    BrokerError::ReplayConflict
                });
            }
            state.consumed = true;
        }
        Ok(&self.artifact)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), BrokerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BrokerError::InvalidField(field));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<String, BrokerError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| BrokerError::Provider(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn unique(values: &[String], field: &'static str) -> Result<(), BrokerError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(BrokerError::Duplicate(field));
        }
    }
    Ok(())
}

fn hex_digest(value: &str, field: &'static str) -> Result<(), BrokerError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrokerError::InvalidField(field));
    }
    Ok(())
}

fn path_is_within_root(executable: &str, root: &str) -> bool {
    executable
        .strip_prefix(root)
        .is_some_and(|rest| rest.starts_with(['\\', '/']))
}

/// A typed provider gap; A-09 never substitutes a local authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredProvider {
    G01Authority,
    P03Process,
    DurableRegistration,
}

/// Provider outcome that cannot be reinterpreted as successful launch.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "detail")]
pub enum PortError {
    #[error("provider denied")]
    Denied,
    #[error("provider unavailable")]
    Unavailable,
    #[error("provider outcome unknown")]
    Unknown,
    #[error("invalid provider contract: {0}")]
    Invalid(String),
}

/// One exact interactive identity tuple.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub boot_session_id: String,
    pub broker_process_id: String,
    pub broker_artifact_digest: String,
    pub protocol_generation: ProtocolVersion,
    pub launch_nonce: String,
    pub observed_at: u64,
    pub lease_expires_at: u64,
}

impl RegistrationRequest {
    pub fn validate(&self) -> Result<(), BrokerError> {
        text(&self.installation_id, "installation_id")?;
        text(&self.windows_sid, "windows_sid")?;
        text(&self.interactive_session_id, "interactive_session_id")?;
        text(&self.boot_session_id, "boot_session_id")?;
        text(&self.broker_process_id, "broker_process_id")?;
        text(&self.broker_artifact_digest, "broker_artifact_digest")?;
        hex_digest(&self.broker_artifact_digest, "broker_artifact_digest")?;
        text(&self.launch_nonce, "launch_nonce")?;
        self.protocol_generation
            .validate()
            .map_err(|error| BrokerError::Provider(error.to_string()))?;
        if self.observed_at == 0 || self.lease_expires_at <= self.observed_at {
            return Err(BrokerError::StaleLease);
        }
        Ok(())
    }
}

/// Provider-issued registration grant.  A-09 validates and seals it before use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationGrant {
    pub registration: RegistrationRequest,
    pub authority_epoch: u64,
    pub user_broker_epoch: u64,
    pub fence_id: String,
    pub expires_at: u64,
    pub grant_digest: String,
}

/// Public registration observation returned only after a provider grant is sealed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: String,
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub boot_session_id: String,
    pub broker_process_id: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: u64,
    pub fence_id: String,
    pub expires_at: u64,
    pub status: RegistrationStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationStatus {
    Active,
    Draining,
    Closed,
}

/// Exact heartbeat context; it cannot mint or widen a registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub registration_digest: String,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatReceipt {
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub fence_id: String,
    pub expires_at: u64,
}

/// Exact ORS/Kernel fence request used when an interactive broker leaves its
/// registration contour.  The operation identity is deterministic for the
/// registration/status pair, so a lost response can be retried without
/// creating a second detach/fence effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationFenceRequest {
    pub registration: RegistrationReceipt,
    pub status: RegistrationStatus,
    pub operation_id: OperationId,
}

/// Authoritative fence receipt.  A local snapshot may be projected Closed or
/// Draining only after this exact ORS/Kernel identity is returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationFenceReceipt {
    pub registration_digest: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: u64,
    pub fence_id: String,
    pub operation_id: OperationId,
    pub status: RegistrationStatus,
}

/// The exact approved launch projection.  Credential material is never present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedLaunch {
    pub operation_id: OperationId,
    pub process_tree_id: ProcessTreeId,
    /// Kernel/N4-owned Job contour identity.  It is never inferred by the
    /// broker from a path, process id, or caller supplied text.
    pub job_id: JobId,
    /// Kernel/N4-owned immutable image identity.
    pub image_id: ImageId,
    /// Kernel/N4-owned interactive session identity.
    pub session_id: SessionId,
    pub request_id: String,
    pub route_fingerprint: String,
    pub artifact_digest: String,
    pub executable: String,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub root: String,
    pub effect_ceiling: EffectCeiling,
    pub tool: String,
    pub credential_handle: Option<SecretRef>,
    pub dependency_closure: Vec<String>,
    pub idempotency_key: String,
    pub generation: Generation,
    pub process_fence_nonce: String,
    pub environment: EnvironmentProjection,
    pub resource_limits: ResourceLimits,
}

/// Caller request that must be exactly approved by G-01.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    pub approved: ApprovedLaunch,
    pub observed_at: u64,
    pub lease_expires_at: u64,
}

impl LaunchRequest {
    pub fn validate(&self) -> Result<(), BrokerError> {
        text(&self.approved.request_id, "request_id")?;
        text(&self.approved.route_fingerprint, "route_fingerprint")?;
        text(&self.approved.artifact_digest, "artifact_digest")?;
        hex_digest(&self.approved.artifact_digest, "artifact_digest")?;
        text(&self.approved.executable, "executable")?;
        text(&self.approved.working_directory, "working_directory")?;
        text(&self.approved.root, "root")?;
        text(&self.approved.tool, "tool")?;
        text(&self.approved.idempotency_key, "idempotency_key")?;
        text(&self.approved.process_fence_nonce, "process_fence_nonce")?;
        if self.approved.executable.contains('*')
            || self.approved.executable.contains('?')
            || self.approved.root.contains('*')
            || self.approved.root.contains('?')
            || !path_is_within_root(&self.approved.executable, &self.approved.root)
        {
            return Err(BrokerError::InvalidField("exact_artifact_root"));
        }
        unique(&self.approved.dependency_closure, "dependency_closure")?;
        if self.observed_at == 0 || self.lease_expires_at <= self.observed_at {
            return Err(BrokerError::StaleLease);
        }
        Ok(())
    }
}

/// Provider-issued exact launch approval; never accepted directly by public APIs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchGrant {
    pub approved: ApprovedLaunch,
    pub proof_ceiling: ProofCeiling,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: u64,
    pub fence_id: String,
    pub expires_at: u64,
    pub grant_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchReceipt {
    pub operation_id: OperationId,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub fence_id: String,
    pub process_receipt: ProcessStartReceipt,
    pub proof_ceiling: ProofCeiling,
    pub operation_permit: OperationPermit,
    pub lineage_verified: bool,
    pub disposition: LaunchDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaunchDisposition {
    Active,
    Unknown,
}

/// Private operation authority issued only after G-01/P-04 positive proof.
/// It intentionally has no serde implementation or public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPermit {
    operation_id: OperationId,
    request_digest: String,
    registration_digest: String,
    user_broker_epoch: u64,
    authority_epoch: u64,
    fence_id: String,
    lease_expires_at: u64,
}

/// Durable restart cursor owned by the injected registration provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSnapshot {
    pub registration: Option<RegistrationReceipt>,
    pub user_broker_epoch: u64,
    pub operation_cursors: Vec<OperationCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCursor {
    pub idempotency_key: String,
    pub operation_id: OperationId,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: u64,
    pub fence_id: String,
    pub lease_expires_at: u64,
    pub process_tree_id: ProcessTreeId,
    pub generation: Generation,
    pub process_fence_nonce: String,
    pub process_request_digest: String,
    pub state: OperationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Active,
    Unknown,
    Reconciled,
}

impl OperationCursor {
    fn validate(&self) -> Result<(), BrokerError> {
        text(self.operation_id.as_str(), "operation_id")?;
        text(&self.idempotency_key, "idempotency_key")?;
        text(&self.request_digest, "request_digest")?;
        text(&self.registration_digest, "registration_digest")?;
        text(&self.fence_id, "fence_id")?;
        text(&self.process_request_digest, "process_request_digest")?;
        text(self.process_tree_id.as_str(), "process_tree_id")?;
        if self.user_broker_epoch == 0 || self.lease_expires_at == 0 || self.generation.get() == 0 {
            return Err(BrokerError::InvalidField("operation_cursor"));
        }
        text(&self.process_fence_nonce, "process_fence_nonce")?;
        Ok(())
    }
}

pub trait AuthorityPort: Send {
    fn register(&mut self, request: &RegistrationRequest) -> Result<RegistrationGrant, PortError>;
    fn heartbeat(
        &mut self,
        receipt: &RegistrationReceipt,
        observed_at: u64,
    ) -> Result<RegistrationGrant, PortError>;
    fn authorize_launch(
        &mut self,
        receipt: &RegistrationReceipt,
        request: &LaunchRequest,
    ) -> Result<LaunchGrant, PortError>;
    /// Fences/detaches the exact ORS registration before local close state is
    /// projected.  Implementations must preserve Unknown for lost replies.
    fn fence(
        &mut self,
        request: &RegistrationFenceRequest,
    ) -> Result<RegistrationFenceReceipt, PortError>;
}

pub trait DurableRegistrationPort: Send {
    fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError>;
    fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError>;
}

/// One physical start result.  The request digest is retained even when the
/// external process outcome is unknown, so reconciliation can bind evidence to
/// the exact one-shot invocation without transporting sealed P-03 authority.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ProcessStartOutcome {
    Started {
        /// Digest returned by the provider for the sealed one-shot request.
        /// Core compares it with the independently precommitted digest before
        /// accepting the receipt.
        request_digest: String,
        receipt: ProcessStartReceipt,
    },
    Unknown {
        request_digest: String,
    },
}

/// P-04 adapter boundary owned by the interactive broker composition.
///
/// Only the public, serializable grant crosses this surface.  The provider
/// implementation must validate it and construct/consume the sealed P-03
/// request locally; `ProcessRequest` and `ValidatedDispatch` never cross the
/// broker or IPC boundary.
pub trait ProcessPort: Send {
    /// Prepares the exact sealed request without crossing the physical start
    /// boundary.  The returned digest is durably recorded before `start` is
    /// called, so a crash cannot orphan an effect with no recovery cursor.
    fn prepare_start(
        &mut self,
        grant: &LaunchGrant,
        registration: &RegistrationReceipt,
    ) -> Result<String, PortError>;
    fn start(
        &mut self,
        grant: &LaunchGrant,
        registration: &RegistrationReceipt,
        expected_request_digest: &str,
    ) -> Result<ProcessStartOutcome, PortError>;
    fn inspect(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError>;
    fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError>;
    /// Reconciliation is a distinct provider operation.  The default keeps
    /// compatibility with a provider that exposes an already reconciled view;
    /// production P-04 adapters override it to run their evidence pass first.
    fn reconcile(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        self.inspect(operation_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationRecord {
    cursor: OperationCursor,
    permit: OperationPermit,
    receipt: Option<LaunchReceipt>,
}

pub struct UserBroker {
    authority: Option<Box<dyn AuthorityPort>>,
    process: Option<Box<dyn ProcessPort>>,
    durable: Option<Box<dyn DurableRegistrationPort>>,
    registration: Option<RegistrationReceipt>,
    registration_reconciled: bool,
    broker_epoch: u64,
    operations: BTreeMap<String, OperationRecord>,
}

impl UserBroker {
    pub fn new(
        authority: Option<Box<dyn AuthorityPort>>,
        process: Option<Box<dyn ProcessPort>>,
        durable: Option<Box<dyn DurableRegistrationPort>>,
    ) -> Self {
        Self {
            authority,
            process,
            durable,
            registration: None,
            registration_reconciled: false,
            broker_epoch: 0,
            operations: BTreeMap::new(),
        }
    }

    pub fn recover(&mut self) -> Result<(), BrokerError> {
        let snapshot = self
            .durable
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?
            .load()
            .map_err(|error| map_port(RequiredProvider::DurableRegistration, error))?
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?;
        self.registration = snapshot.registration;
        self.registration_reconciled = self.registration.is_none();
        self.broker_epoch = snapshot.user_broker_epoch;
        let Some(registration) = self.registration.as_ref() else {
            if snapshot.operation_cursors.is_empty() {
                self.operations.clear();
                return Ok(());
            }
            return Err(BrokerError::InvalidField("operation_cursor.registration"));
        };
        let mut operations = BTreeMap::new();
        let mut operation_ids = BTreeSet::new();
        for cursor in snapshot.operation_cursors {
            cursor.validate()?;
            if cursor.registration_digest != registration.registration_digest
                || cursor.user_broker_epoch != registration.user_broker_epoch
                || cursor.authority_epoch != registration.authority_epoch
                || cursor.fence_id != registration.fence_id
                || cursor.lease_expires_at > registration.expires_at
            {
                return Err(BrokerError::GrantBindingMismatch);
            }
            if !operation_ids.insert(cursor.operation_id.clone()) {
                return Err(BrokerError::Duplicate("operation_cursor.operation_id"));
            }
            let permit = permit_from_cursor(&cursor);
            if operations
                .insert(
                    cursor.idempotency_key.clone(),
                    OperationRecord {
                        cursor,
                        permit,
                        receipt: None,
                    },
                )
                .is_some()
            {
                return Err(BrokerError::Duplicate("operation_cursor.idempotency_key"));
            }
        }
        self.operations = operations;
        Ok(())
    }

    /// Returns the currently recovered registration binding without exposing
    /// any provider authority or mutable registration state.
    pub fn registration_digest(&self) -> Option<&str> {
        self.registration
            .as_ref()
            .map(|registration| registration.registration_digest.as_str())
    }

    pub fn broker_epoch(&self) -> u64 {
        self.broker_epoch
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn register(
        &mut self,
        request: RegistrationRequest,
    ) -> Result<RegistrationReceipt, BrokerError> {
        request.validate()?;
        if let Some(current) = &self.registration
            && current.status == RegistrationStatus::Active
            && current.installation_id == request.installation_id
            && current.windows_sid == request.windows_sid
            && current.interactive_session_id == request.interactive_session_id
        {
            return Err(BrokerError::DuplicateRegistration);
        }
        let grant = self
            .authority
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .register(&request)
            .map_err(|error| map_port(RequiredProvider::G01Authority, error))?;
        let sealed = seal_registration(&request, &grant)?;
        if sealed.user_broker_epoch <= self.broker_epoch {
            return Err(BrokerError::StaleEpoch);
        }
        self.broker_epoch = sealed.user_broker_epoch;
        self.registration = Some(sealed.clone());
        self.registration_reconciled = true;
        self.persist()?;
        Ok(sealed)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn heartbeat(
        &mut self,
        request: HeartbeatRequest,
    ) -> Result<HeartbeatReceipt, BrokerError> {
        text(&request.registration_digest, "registration_digest")?;
        let current = if self.registration_reconciled {
            self.active_registration(request.observed_at)?.clone()
        } else {
            let current = self
                .registration
                .as_ref()
                .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
                .clone();
            if current.status != RegistrationStatus::Active {
                return Err(BrokerError::LeaseExpired);
            }
            if request.observed_at >= current.expires_at {
                return Err(BrokerError::LeaseExpired);
            }
            current
        };
        if current.registration_digest != request.registration_digest {
            return Err(BrokerError::GrantBindingMismatch);
        }
        let grant = self
            .authority
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .heartbeat(&current, request.observed_at)
            .map_err(|error| map_port(RequiredProvider::G01Authority, error))?;
        let refreshed = match seal_registration_from_grant(&current, &grant, request.observed_at) {
            Ok(refreshed) => refreshed,
            Err(error) => {
                self.close(RegistrationStatus::Closed)?;
                return Err(error);
            }
        };
        self.registration = Some(refreshed.clone());
        self.registration_reconciled = true;
        self.persist()?;
        Ok(HeartbeatReceipt {
            registration_digest: refreshed.registration_digest,
            user_broker_epoch: refreshed.user_broker_epoch,
            fence_id: refreshed.fence_id,
            expires_at: refreshed.expires_at,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_lines)]
    pub fn launch(&mut self, request: LaunchRequest) -> Result<LaunchReceipt, BrokerError> {
        request.validate()?;
        let current = self.active_registration(request.observed_at)?.clone();
        let request_digest = digest(&request)?;
        if let Some(record) = self.operations.get(&request.approved.idempotency_key) {
            if record.cursor.request_digest != request_digest {
                return Err(BrokerError::ReplayConflict);
            }
            if let Some(receipt) = &record.receipt {
                return Ok(receipt.clone());
            }
            return Err(BrokerError::UnknownOutcome);
        }
        let grant = self
            .authority
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .authorize_launch(&current, &request)
            .map_err(|error| map_port(RequiredProvider::G01Authority, error))?;
        if let Err(error) = validate_launch_grant(&current, &request, &grant) {
            self.close(RegistrationStatus::Closed)?;
            return Err(error);
        }
        let process_operation_id = grant.approved.operation_id.clone();
        let process_generation = grant.approved.generation;
        let permit = permit_from_grant(&grant, &current, &request_digest);
        let expected_process_request_digest = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .prepare_start(&grant, &current)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        hex_digest(&expected_process_request_digest, "process_request_digest")?;
        let cursor = cursor_from_grant(
            &grant,
            &current,
            &request_digest,
            &expected_process_request_digest,
            OperationState::Unknown,
        );
        let unknown_record = OperationRecord {
            cursor: cursor.clone(),
            permit: permit.clone(),
            receipt: None,
        };
        self.operations.insert(
            request.approved.idempotency_key.clone(),
            unknown_record.clone(),
        );
        // This is the last durable boundary before the provider can create a
        // process.  Any save error leaves the exact Unknown cursor in memory
        // and prevents crossing the physical start boundary.
        self.persist()?;
        let outcome = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .start(&grant, &current, &expected_process_request_digest)
            .map_err(|error| {
                if matches!(error, PortError::Unknown) {
                    BrokerError::UnknownOutcome
                } else {
                    map_port(RequiredProvider::P03Process, error)
                }
            })?;
        let receipt = match outcome {
            ProcessStartOutcome::Started {
                request_digest,
                receipt,
            } => {
                if request_digest != expected_process_request_digest
                    || receipt.request_digest() != expected_process_request_digest
                {
                    return Err(BrokerError::ProcessBindingMismatch);
                }
                receipt
            }
            ProcessStartOutcome::Unknown { request_digest } => {
                if request_digest != expected_process_request_digest {
                    return Err(BrokerError::ProcessBindingMismatch);
                }
                return Err(BrokerError::UnknownOutcome);
            }
        };
        if receipt.operation_id() != &process_operation_id
            || receipt.accepted_generation() != process_generation
        {
            return Err(BrokerError::ProcessBindingMismatch);
        }
        let view = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .inspect(&process_operation_id)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        verify_cursor_lineage(&unknown_record.cursor, &view)?;
        let mut active_cursor = unknown_record.cursor.clone();
        active_cursor.state = OperationState::Active;
        let launch_receipt = LaunchReceipt {
            operation_id: process_operation_id,
            request_digest,
            registration_digest: current.registration_digest.clone(),
            user_broker_epoch: current.user_broker_epoch,
            fence_id: current.fence_id.clone(),
            process_receipt: receipt,
            proof_ceiling: grant.proof_ceiling,
            operation_permit: permit.clone(),
            lineage_verified: true,
            disposition: LaunchDisposition::Active,
        };
        self.operations.insert(
            request.approved.idempotency_key.clone(),
            OperationRecord {
                cursor: active_cursor,
                permit,
                receipt: Some(launch_receipt.clone()),
            },
        );
        if let Err(error) = self.persist() {
            // The physical start is already real but the Active publication
            // was not durably acknowledged.  Restore the pre-effect Unknown
            // cursor so restart/reconciliation cannot lose the lineage.
            self.operations
                .insert(request.approved.idempotency_key, unknown_record);
            return Err(error);
        }
        Ok(launch_receipt)
    }

    pub fn cancel(&mut self, permit: &OperationPermit) -> Result<CancellationReceipt, BrokerError> {
        let operation_id = self
            .validate_operation_permit(permit)?
            .permit
            .operation_id
            .clone();
        self.process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .cancel(&operation_id)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))
    }

    /// Cancels a previously admitted operation by its broker-issued public
    /// operation identity.  The private one-shot permit remains broker-owned;
    /// stdin/UI callers cannot manufacture or widen it.
    pub fn cancel_operation(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<CancellationReceipt, BrokerError> {
        let permit = self
            .operations
            .values()
            .find(|record| record.permit.operation_id == *operation_id)
            .map(|record| record.permit.clone())
            .ok_or(BrokerError::OperationNotFound)?;
        self.cancel(&permit)
    }

    pub fn reconcile(
        &mut self,
        permit: &OperationPermit,
    ) -> Result<ProcessExecutionView, BrokerError> {
        let cursor = self.validate_operation_permit(permit)?.cursor.clone();
        let operation_id = cursor.operation_id.clone();
        let view = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .reconcile(&operation_id)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        verify_cursor_lineage(&cursor, &view)?;
        if let Some(record) = self
            .operations
            .values_mut()
            .find(|record| record.permit.operation_id == operation_id)
        {
            record.cursor.state = match view.lifecycle() {
                eliot_process::ProcessLifecycle::Running
                | eliot_process::ProcessLifecycle::Starting
                | eliot_process::ProcessLifecycle::Cancelling => OperationState::Active,
                eliot_process::ProcessLifecycle::UnknownOutcome
                | eliot_process::ProcessLifecycle::Created => OperationState::Unknown,
                eliot_process::ProcessLifecycle::Exited
                | eliot_process::ProcessLifecycle::Failed
                | eliot_process::ProcessLifecycle::Reconciled
                | eliot_process::ProcessLifecycle::Quarantined => OperationState::Reconciled,
            };
            if record.cursor.state == OperationState::Reconciled {
                record.receipt = None;
            }
        }
        self.persist()?;
        Ok(view)
    }

    /// Reconciles a broker-owned operation without transporting its sealed
    /// process permit across the stdin/UI boundary.
    pub fn reconcile_operation(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<ProcessExecutionView, BrokerError> {
        let permit = self
            .operations
            .values()
            .find(|record| record.permit.operation_id == *operation_id)
            .map(|record| record.permit.clone())
            .ok_or(BrokerError::OperationNotFound)?;
        self.reconcile(&permit)
    }

    pub fn logoff(&mut self) -> Result<(), BrokerError> {
        self.close(RegistrationStatus::Closed)
    }
    pub fn drain(&mut self) -> Result<(), BrokerError> {
        self.close(RegistrationStatus::Draining)
    }
    pub fn suspend(&mut self) -> Result<(), BrokerError> {
        self.close(RegistrationStatus::Draining)
    }
    pub fn hibernate(&mut self) -> Result<(), BrokerError> {
        self.close(RegistrationStatus::Draining)
    }
    pub fn revoke(&mut self) -> Result<(), BrokerError> {
        self.close(RegistrationStatus::Closed)
    }
    pub fn boot_session_changed(&mut self, boot_session_id: &str) -> Result<(), BrokerError> {
        text(boot_session_id, "boot_session_id")?;
        if self
            .registration
            .as_ref()
            .is_some_and(|registration| registration.boot_session_id != boot_session_id)
        {
            self.close(RegistrationStatus::Closed)
        } else {
            Ok(())
        }
    }

    fn validate_operation_permit(
        &self,
        permit: &OperationPermit,
    ) -> Result<&OperationRecord, BrokerError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?;
        if permit.registration_digest != registration.registration_digest
            || permit.user_broker_epoch != registration.user_broker_epoch
            || permit.authority_epoch != registration.authority_epoch
            || permit.fence_id != registration.fence_id
        {
            return Err(BrokerError::GrantBindingMismatch);
        }
        let record = self
            .operations
            .values()
            .find(|record| record.permit == *permit)
            .ok_or(BrokerError::OperationNotFound)?;
        if record.cursor.state == OperationState::Reconciled {
            return Err(BrokerError::OperationNotFound);
        }
        Ok(record)
    }

    fn active_registration(
        &mut self,
        observed_at: u64,
    ) -> Result<&RegistrationReceipt, BrokerError> {
        if !self.registration_reconciled {
            return Err(BrokerError::PlanGap(RequiredProvider::G01Authority));
        }
        let expired = {
            let registration = self
                .registration
                .as_ref()
                .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?;
            registration.status != RegistrationStatus::Active
                || observed_at >= registration.expires_at
        };
        if expired {
            if let Some(registration) = &mut self.registration {
                registration.status = RegistrationStatus::Closed;
            }
            self.persist()?;
            return Err(BrokerError::LeaseExpired);
        }
        self.registration
            .as_ref()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))
    }

    fn close(&mut self, status: RegistrationStatus) -> Result<(), BrokerError> {
        let current = self
            .registration
            .as_ref()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .clone();
        let already_projected = current.status == status;
        if !already_projected {
            let operation_id = fence_operation_id(&current, status)?;
            let request = RegistrationFenceRequest {
                registration: current.clone(),
                status,
                operation_id,
            };
            let receipt = self
                .authority
                .as_mut()
                .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
                .fence(&request)
                .map_err(|error| map_port(RequiredProvider::G01Authority, error))?;
            validate_fence_receipt(&request, &receipt)?;
        }
        let mut desired = current;
        desired.status = status;
        self.registration = Some(desired.clone());
        self.registration_reconciled = true;
        match self.persist() {
            Ok(()) => Ok(()),
            Err(error) => {
                // The authoritative fence is already known, but the local
                // projection is not durably acknowledged.  Keep the fenced
                // in-memory state so no new launch can cross the closed
                // contour; the caller must retry persistence/reconciliation.
                self.registration = Some(desired);
                let reconciled = match self.durable.as_mut() {
                    Some(durable) => match durable.load() {
                        Ok(Some(snapshot)) => snapshot == self.snapshot(),
                        Ok(None) | Err(_) => false,
                    },
                    None => false,
                };
                if reconciled { Ok(()) } else { Err(error) }
            }
        }
    }

    fn snapshot(&self) -> BrokerSnapshot {
        BrokerSnapshot {
            registration: self.registration.clone(),
            user_broker_epoch: self.broker_epoch,
            operation_cursors: self
                .operations
                .values()
                .map(|record| record.cursor.clone())
                .collect(),
        }
    }

    fn persist(&mut self) -> Result<(), BrokerError> {
        let snapshot = self.snapshot();
        self.durable
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?
            .save(&snapshot)
            .map_err(|error| map_port(RequiredProvider::DurableRegistration, error))
    }
}

fn seal_registration(
    request: &RegistrationRequest,
    grant: &RegistrationGrant,
) -> Result<RegistrationReceipt, BrokerError> {
    if grant.registration != *request {
        return Err(BrokerError::GrantBindingMismatch);
    }
    text(&grant.fence_id, "fence_id")?;
    if grant.authority_epoch == 0
        || grant.user_broker_epoch == 0
        || grant.expires_at <= request.observed_at
        || grant.expires_at > request.lease_expires_at
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    let expected = digest(&(
        request,
        grant.authority_epoch,
        grant.user_broker_epoch,
        &grant.fence_id,
        grant.expires_at,
    ))?;
    if grant.grant_digest != expected {
        return Err(BrokerError::GrantBindingMismatch);
    }
    Ok(RegistrationReceipt {
        registration_digest: digest(&(
            request,
            grant.user_broker_epoch,
            grant.authority_epoch,
            &grant.fence_id,
        ))?,
        installation_id: request.installation_id.clone(),
        windows_sid: request.windows_sid.clone(),
        interactive_session_id: request.interactive_session_id.clone(),
        boot_session_id: request.boot_session_id.clone(),
        broker_process_id: request.broker_process_id.clone(),
        user_broker_epoch: grant.user_broker_epoch,
        authority_epoch: grant.authority_epoch,
        fence_id: grant.fence_id.clone(),
        expires_at: grant.expires_at,
        status: RegistrationStatus::Active,
    })
}

fn fence_operation_id(
    registration: &RegistrationReceipt,
    status: RegistrationStatus,
) -> Result<OperationId, BrokerError> {
    let status = match status {
        RegistrationStatus::Active => "active",
        RegistrationStatus::Draining => "draining",
        RegistrationStatus::Closed => "closed",
    };
    OperationId::new(format!(
        "user-broker-fence-{}-{status}",
        registration.registration_digest
    ))
    .map_err(|error| BrokerError::Provider(error.to_string()))
}

fn validate_fence_receipt(
    request: &RegistrationFenceRequest,
    receipt: &RegistrationFenceReceipt,
) -> Result<(), BrokerError> {
    if receipt.registration_digest != request.registration.registration_digest
        || receipt.windows_sid != request.registration.windows_sid
        || receipt.interactive_session_id != request.registration.interactive_session_id
        || receipt.user_broker_epoch != request.registration.user_broker_epoch
        || receipt.authority_epoch != request.registration.authority_epoch
        || receipt.fence_id != request.registration.fence_id
        || receipt.operation_id != request.operation_id
        || receipt.status != request.status
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    text(&receipt.registration_digest, "registration_digest")?;
    text(&receipt.windows_sid, "windows_sid")?;
    text(&receipt.interactive_session_id, "interactive_session_id")?;
    text(&receipt.fence_id, "fence_id")?;
    if receipt.user_broker_epoch == 0 || receipt.authority_epoch == 0 {
        return Err(BrokerError::GrantBindingMismatch);
    }
    Ok(())
}

fn seal_registration_from_grant(
    current: &RegistrationReceipt,
    grant: &RegistrationGrant,
    observed_at: u64,
) -> Result<RegistrationReceipt, BrokerError> {
    let request = &grant.registration;
    if digest(&(
        request,
        grant.user_broker_epoch,
        grant.authority_epoch,
        &grant.fence_id,
    ))? != current.registration_digest
        || grant.user_broker_epoch != current.user_broker_epoch
        || grant.authority_epoch != current.authority_epoch
        || grant.fence_id != current.fence_id
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    if grant.expires_at <= observed_at {
        return Err(BrokerError::StaleLease);
    }
    seal_registration(request, grant)
}

fn validate_launch_grant(
    current: &RegistrationReceipt,
    request: &LaunchRequest,
    grant: &LaunchGrant,
) -> Result<(), BrokerError> {
    if grant.registration_digest != current.registration_digest
        || grant.user_broker_epoch != current.user_broker_epoch
        || grant.authority_epoch != current.authority_epoch
        || grant.fence_id != current.fence_id
        || grant.approved != request.approved
        || grant.request_digest != digest(request)?
        || grant.proof_ceiling != ProofCeiling::Observation
        || grant.expires_at <= request.observed_at
        || grant.expires_at > request.lease_expires_at
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    let expected = digest(&(
        grant.registration_digest.clone(),
        &grant.approved,
        grant.proof_ceiling,
        grant.request_digest.clone(),
        grant.user_broker_epoch,
        grant.authority_epoch,
        &grant.fence_id,
        grant.expires_at,
    ))?;
    if grant.grant_digest != expected {
        return Err(BrokerError::GrantBindingMismatch);
    }
    Ok(())
}

fn permit_from_grant(
    grant: &LaunchGrant,
    registration: &RegistrationReceipt,
    request_digest: &str,
) -> OperationPermit {
    OperationPermit {
        operation_id: grant.approved.operation_id.clone(),
        request_digest: request_digest.to_owned(),
        registration_digest: registration.registration_digest.clone(),
        user_broker_epoch: registration.user_broker_epoch,
        authority_epoch: registration.authority_epoch,
        fence_id: registration.fence_id.clone(),
        lease_expires_at: grant.expires_at,
    }
}

fn cursor_from_grant(
    grant: &LaunchGrant,
    registration: &RegistrationReceipt,
    request_digest: &str,
    process_request_digest: &str,
    state: OperationState,
) -> OperationCursor {
    OperationCursor {
        idempotency_key: grant.approved.idempotency_key.clone(),
        operation_id: grant.approved.operation_id.clone(),
        request_digest: request_digest.to_owned(),
        registration_digest: registration.registration_digest.clone(),
        user_broker_epoch: registration.user_broker_epoch,
        authority_epoch: registration.authority_epoch,
        fence_id: registration.fence_id.clone(),
        lease_expires_at: grant.expires_at,
        process_tree_id: grant.approved.process_tree_id.clone(),
        generation: grant.approved.generation,
        process_fence_nonce: grant.approved.process_fence_nonce.clone(),
        process_request_digest: process_request_digest.to_owned(),
        state,
    }
}

fn permit_from_cursor(cursor: &OperationCursor) -> OperationPermit {
    OperationPermit {
        operation_id: cursor.operation_id.clone(),
        request_digest: cursor.request_digest.clone(),
        registration_digest: cursor.registration_digest.clone(),
        user_broker_epoch: cursor.user_broker_epoch,
        authority_epoch: cursor.authority_epoch,
        fence_id: cursor.fence_id.clone(),
        lease_expires_at: cursor.lease_expires_at,
    }
}

fn verify_cursor_lineage(
    cursor: &OperationCursor,
    view: &ProcessExecutionView,
) -> Result<(), BrokerError> {
    let identity = view.identity().ok_or(BrokerError::ProcessLineageMismatch)?;
    if view.lifecycle() != ProcessLifecycle::Running
        || view.operation_id() != &cursor.operation_id
        || view.request_digest() != cursor.process_request_digest
        || view.fence().authority_epoch() != cursor.authority_epoch
        || view.fence().nonce() != cursor.process_fence_nonce
        || identity.process_tree_id() != &cursor.process_tree_id
        || identity.generation() != cursor.generation
    {
        return Err(BrokerError::ProcessLineageMismatch);
    }
    Ok(())
}

fn map_port(provider: RequiredProvider, error: PortError) -> BrokerError {
    match error {
        PortError::Denied => BrokerError::Denied,
        PortError::Unavailable => BrokerError::PlanGap(provider),
        PortError::Unknown => BrokerError::UnknownOutcome,
        PortError::Invalid(detail) => BrokerError::Provider(detail),
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BrokerError {
    #[error("PLAN_GAP: {0:?}")]
    PlanGap(RequiredProvider),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate value in {0}")]
    Duplicate(&'static str),
    #[error("stale lease")]
    StaleLease,
    #[error("lease expired")]
    LeaseExpired,
    #[error("duplicate active registration")]
    DuplicateRegistration,
    #[error("stale broker epoch")]
    StaleEpoch,
    #[error("registration or launch grant binding mismatch")]
    GrantBindingMismatch,
    #[error("process contract binding mismatch")]
    ProcessBindingMismatch,
    #[error("process lineage evidence mismatch")]
    ProcessLineageMismatch,
    #[error("provider denied")]
    Denied,
    #[error("provider outcome unknown")]
    UnknownOutcome,
    #[error("idempotency replay conflict")]
    ReplayConflict,
    #[error("operation not found or already reconciled")]
    OperationNotFound,
    #[error("provider contract failure: {0}")]
    Provider(String),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        FencingToken, KernelDispatchKey, PermitIssuance, ProcessHealth, ProcessId, ProcessIntent,
        ProcessRequest, ProcessState, SuspendedProcessIdentity,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn operator_endpoint_is_role_filtered_and_credential_free() {
        let endpoint = OperatorEndpoint {
            pipe_name: r"\\.\pipe\eliot\operator\one-shot".to_owned(),
            broker_epoch: 4,
            interactive_session_id: "session-1".to_owned(),
            handoff_nonce: "nonce-1".to_owned(),
            role: "human_operator".to_owned(),
            capabilities: vec![
                "controlboard.read".to_owned(),
                "operator.command".to_owned(),
            ],
        };
        endpoint.validate().expect("valid endpoint");
        let wire = serde_json::to_string(&endpoint).expect("endpoint json");
        assert!(!wire.contains("token"));
        assert!(!wire.contains("auth_ref"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&wire)
                .expect("endpoint value")
                .get("role")
                .is_some()
        );
    }

    #[test]
    fn operator_endpoint_rejects_unfiltered_role() {
        let endpoint = OperatorEndpoint {
            pipe_name: r"\\.\pipe\eliot\operator\one-shot".to_owned(),
            broker_epoch: 1,
            interactive_session_id: "session-1".to_owned(),
            handoff_nonce: "nonce-1".to_owned(),
            role: "kernel".to_owned(),
            capabilities: vec!["controlboard.read".to_owned()],
        };
        assert_eq!(
            endpoint.validate(),
            Err(BrokerError::InvalidField("operator_endpoint_binding"))
        );
    }

    #[test]
    fn operator_handoff_is_exact_approved_and_one_shot() {
        let mut authority = OperatorHandoffAuthority::new(
            OperatorArtifact {
                image_id: "eliot.operator.v1".to_owned(),
                executable: r"C:\Program Files\Eliot\Eliot.Operator.exe".to_owned(),
                artifact_digest: "a".repeat(64),
            },
            OPERATOR_PIPE_NAME.to_owned(),
            4,
            "session-1".to_owned(),
        )
        .expect("artifact policy");
        let request = OperatorHandoffRequest {
            role: OPERATOR_ROLE.to_owned(),
            capabilities: OPERATOR_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        let endpoint = authority.issue(&request, 10).expect("issue handoff");
        authority.consume(&endpoint, 11).expect("consume once");
        assert_eq!(
            authority.consume(&endpoint, 11),
            Err(BrokerError::ReplayConflict)
        );
    }

    #[test]
    fn operator_handoff_expiry_and_capability_widening_fail_closed() {
        let mut authority = OperatorHandoffAuthority::new(
            OperatorArtifact {
                image_id: "eliot.operator.v1".to_owned(),
                executable: "C:/Eliot/Eliot.Operator.exe".to_owned(),
                artifact_digest: "a".repeat(64),
            },
            OPERATOR_PIPE_NAME.to_owned(),
            1,
            "session".to_owned(),
        )
        .expect("artifact policy");
        let request = OperatorHandoffRequest {
            role: OPERATOR_ROLE.to_owned(),
            capabilities: vec!["operator.command".to_owned()],
        };
        assert_eq!(authority.issue(&request, 10), Err(BrokerError::Denied));
        let valid = OperatorHandoffRequest {
            capabilities: OPERATOR_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            ..request
        };
        let endpoint = authority.issue(&valid, 10).expect("issue handoff");
        assert_eq!(
            authority.consume(&endpoint, 5_010),
            Err(BrokerError::StaleLease)
        );
    }

    #[test]
    fn operator_handoff_binds_session_epoch_nonce_and_policy_without_caller_time() {
        let artifact = OperatorArtifact {
            image_id: "eliot.operator.v1".to_owned(),
            executable: "C:/Eliot/Eliot.Operator.exe".to_owned(),
            artifact_digest: "a".repeat(64),
        };
        let mut authority = OperatorHandoffAuthority::new(
            artifact,
            OPERATOR_PIPE_NAME.to_owned(),
            7,
            "session-7".to_owned(),
        )
        .expect("artifact policy");
        let request = OperatorHandoffRequest {
            role: OPERATOR_ROLE.to_owned(),
            capabilities: OPERATOR_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        let endpoint = authority.issue(&request, 100).expect("issue handoff");
        assert_eq!(endpoint.broker_epoch, 7);
        assert_eq!(endpoint.interactive_session_id, "session-7");
        assert_eq!(endpoint.pipe_name, OPERATOR_PIPE_NAME);
        assert_ne!(endpoint.handoff_nonce, "caller-selected");
        assert!(
            serde_json::from_value::<OperatorHandoffRequest>(serde_json::json!({
                "role": OPERATOR_ROLE,
                "capabilities": OPERATOR_CAPABILITIES,
                "observed_at": 100,
                "expires_at": 105,
                "pipe_name": OPERATOR_PIPE_NAME,
                "handoff_nonce": "caller-selected"
            }))
            .is_err()
        );

        for tampered in [
            OperatorEndpoint {
                interactive_session_id: "other-session".to_owned(),
                ..endpoint.clone()
            },
            OperatorEndpoint {
                broker_epoch: 8,
                ..endpoint.clone()
            },
            OperatorEndpoint {
                handoff_nonce: "other-nonce".to_owned(),
                ..endpoint.clone()
            },
        ] {
            assert_eq!(
                authority.consume(&tampered, 101),
                Err(BrokerError::ReplayConflict)
            );
        }
    }

    #[derive(Clone, Copy)]
    enum Tamper {
        None,
        RegistrationSid,
        RegistrationSession,
        RegistrationNonce,
        LaunchRoute,
        LaunchArtifact,
        LaunchEffect,
        LaunchFence,
        LaunchLease,
        FenceReceipt,
    }

    struct FakeAuthority {
        epoch: u64,
        broker_epoch: u64,
        tamper: Tamper,
        last: Option<RegistrationRequest>,
    }

    impl FakeAuthority {
        fn new() -> Self {
            Self {
                epoch: 7,
                broker_epoch: 0,
                tamper: Tamper::None,
                last: None,
            }
        }

        fn registration_grant(&self, mut request: RegistrationRequest) -> RegistrationGrant {
            if matches!(self.tamper, Tamper::RegistrationSid) {
                request.windows_sid = "S-1-5-21-wrong".to_owned();
            }
            if matches!(self.tamper, Tamper::RegistrationSession) {
                request.interactive_session_id = "session-wrong".to_owned();
            }
            if matches!(self.tamper, Tamper::RegistrationNonce) {
                request.launch_nonce = "nonce-wrong".to_owned();
            }
            let fence_id = format!("broker-fence-{}", self.broker_epoch);
            let expires_at = request.lease_expires_at;
            let grant_digest = digest(&(
                request.clone(),
                self.epoch,
                self.broker_epoch,
                &fence_id,
                expires_at,
            ))
            .expect("digest");
            RegistrationGrant {
                registration: request,
                authority_epoch: self.epoch,
                user_broker_epoch: self.broker_epoch,
                fence_id,
                expires_at,
                grant_digest,
            }
        }
    }

    impl AuthorityPort for FakeAuthority {
        fn register(
            &mut self,
            request: &RegistrationRequest,
        ) -> Result<RegistrationGrant, PortError> {
            self.broker_epoch += 1;
            self.last = Some(request.clone());
            Ok(self.registration_grant(request.clone()))
        }

        fn heartbeat(
            &mut self,
            receipt: &RegistrationReceipt,
            _observed_at: u64,
        ) -> Result<RegistrationGrant, PortError> {
            let request = self
                .last
                .clone()
                .ok_or(PortError::Invalid("missing registration".to_owned()))?;
            if receipt.user_broker_epoch != self.broker_epoch {
                return Err(PortError::Denied);
            }
            Ok(self.registration_grant(request))
        }

        fn authorize_launch(
            &mut self,
            receipt: &RegistrationReceipt,
            request: &LaunchRequest,
        ) -> Result<LaunchGrant, PortError> {
            let mut approved = request.approved.clone();
            let mut expires_at = request.lease_expires_at;
            let mut fence_id = receipt.fence_id.clone();
            match self.tamper {
                Tamper::LaunchRoute => approved.route_fingerprint = "wrong-route".to_owned(),
                Tamper::LaunchArtifact => approved.artifact_digest = "f".repeat(64),
                Tamper::LaunchEffect => approved.effect_ceiling = EffectCeiling::ReadOnly,
                Tamper::LaunchFence => fence_id = "wrong-fence".to_owned(),
                Tamper::LaunchLease => expires_at += 10,
                Tamper::None
                | Tamper::RegistrationSid
                | Tamper::RegistrationSession
                | Tamper::RegistrationNonce
                | Tamper::FenceReceipt => {}
            }
            let proof_ceiling = ProofCeiling::Observation;
            let request_digest = digest(request).expect("request digest");
            let grant_digest = digest(&(
                receipt.registration_digest.clone(),
                &approved,
                proof_ceiling,
                request_digest.clone(),
                receipt.user_broker_epoch,
                receipt.authority_epoch,
                &fence_id,
                expires_at,
            ))
            .expect("digest");
            Ok(LaunchGrant {
                approved,
                proof_ceiling,
                request_digest,
                registration_digest: receipt.registration_digest.clone(),
                user_broker_epoch: receipt.user_broker_epoch,
                authority_epoch: receipt.authority_epoch,
                fence_id,
                expires_at,
                grant_digest,
            })
        }

        fn fence(
            &mut self,
            request: &RegistrationFenceRequest,
        ) -> Result<RegistrationFenceReceipt, PortError> {
            let registration_digest = if matches!(self.tamper, Tamper::FenceReceipt) {
                "wrong-registration-digest".to_owned()
            } else {
                request.registration.registration_digest.clone()
            };
            Ok(RegistrationFenceReceipt {
                registration_digest,
                windows_sid: request.registration.windows_sid.clone(),
                interactive_session_id: request.registration.interactive_session_id.clone(),
                user_broker_epoch: request.registration.user_broker_epoch,
                authority_epoch: request.registration.authority_epoch,
                fence_id: request.registration.fence_id.clone(),
                operation_id: request.operation_id.clone(),
                status: request.status,
            })
        }
    }

    struct FakeDurable {
        snapshot: Option<BrokerSnapshot>,
    }

    impl DurableRegistrationPort for FakeDurable {
        fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
            Ok(self.snapshot.clone())
        }
        fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
            self.snapshot = Some(snapshot.clone());
            Ok(())
        }
    }

    struct UncertainDurable {
        snapshot: Arc<Mutex<Option<BrokerSnapshot>>>,
        fail_next: Arc<AtomicBool>,
        publish_before_fail: bool,
    }

    impl DurableRegistrationPort for UncertainDurable {
        fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
            self.snapshot
                .lock()
                .map_err(|_| PortError::Unknown)
                .map(|snapshot| snapshot.clone())
        }

        fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                if self.publish_before_fail {
                    *self.snapshot.lock().map_err(|_| PortError::Unknown)? = Some(snapshot.clone());
                }
                return Err(PortError::Unknown);
            }
            *self.snapshot.lock().map_err(|_| PortError::Unknown)? = Some(snapshot.clone());
            Ok(())
        }
    }

    struct OrderingDurable {
        snapshot: Arc<Mutex<Option<BrokerSnapshot>>>,
    }

    impl DurableRegistrationPort for OrderingDurable {
        fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
            self.snapshot
                .lock()
                .map_err(|_| PortError::Unknown)
                .map(|snapshot| snapshot.clone())
        }

        fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
            self.snapshot
                .lock()
                .map_err(|_| PortError::Unknown)
                .map(|mut current| *current = Some(snapshot.clone()))
        }
    }

    struct FakeProcess {
        state: Option<ProcessState>,
        unknown: bool,
        wrong_receipt: bool,
    }

    impl ProcessPort for FakeProcess {
        fn prepare_start(
            &mut self,
            grant: &LaunchGrant,
            _registration: &RegistrationReceipt,
        ) -> Result<String, PortError> {
            let (request, _authority) = process_request_for_test(grant, false)?;
            Ok(request.invocation_digest().to_owned())
        }

        fn start(
            &mut self,
            grant: &LaunchGrant,
            _registration: &RegistrationReceipt,
            expected_request_digest: &str,
        ) -> Result<ProcessStartOutcome, PortError> {
            let (request, mut authority) = process_request_for_test(grant, self.wrong_receipt)?;
            let observed = SuspendedProcessIdentity::new(
                ProcessId::new("pid-1").expect("pid"),
                request.process_tree_id().clone(),
                request.job_id().clone(),
                request.image_id().clone(),
                request.session_id().clone(),
                request.generation(),
                42,
                100,
                request.executable_sha256(),
            )
            .map_err(|error| PortError::Invalid(error.to_string()))?;
            let current = test_context(grant, 200)?;
            let validated = authority
                .validate_and_consume(request, observed, &current)
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            let mut state = ProcessState::from_validated(&validated);
            state
                .mark_resumed(201, ProcessHealth::default())
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            self.state = Some(state);
            if self.unknown {
                return Ok(ProcessStartOutcome::Unknown {
                    request_digest: expected_request_digest.to_owned(),
                });
            }
            ProcessStartReceipt::new(self.state.as_ref().expect("state"))
                .map(|receipt| ProcessStartOutcome::Started {
                    request_digest: expected_request_digest.to_owned(),
                    receipt,
                })
                .map_err(|error| PortError::Invalid(error.to_string()))
        }

        fn inspect(
            &mut self,
            _operation_id: &OperationId,
        ) -> Result<ProcessExecutionView, PortError> {
            self.state
                .as_ref()
                .map(ProcessState::view)
                .ok_or(PortError::Unknown)
        }

        fn cancel(
            &mut self,
            _operation_id: &OperationId,
        ) -> Result<CancellationReceipt, PortError> {
            let state = self.state.as_mut().ok_or(PortError::Unknown)?;
            let request = eliot_process::CancellationRequest::new(state.binding().clone());
            state
                .cancel(&request)
                .map_err(|error| PortError::Invalid(error.to_string()))
        }
    }

    struct OrderingProcess {
        inner: FakeProcess,
        snapshot: Arc<Mutex<Option<BrokerSnapshot>>>,
        observed_unknown_before_start: Arc<AtomicBool>,
    }

    impl ProcessPort for OrderingProcess {
        fn prepare_start(
            &mut self,
            grant: &LaunchGrant,
            registration: &RegistrationReceipt,
        ) -> Result<String, PortError> {
            self.inner.prepare_start(grant, registration)
        }

        fn start(
            &mut self,
            grant: &LaunchGrant,
            registration: &RegistrationReceipt,
            expected_request_digest: &str,
        ) -> Result<ProcessStartOutcome, PortError> {
            let persisted = self
                .snapshot
                .lock()
                .map_err(|_| PortError::Unknown)?
                .as_ref()
                .and_then(|snapshot| {
                    snapshot.operation_cursors.iter().find(|cursor| {
                        cursor.operation_id == grant.approved.operation_id
                            && cursor.state == OperationState::Unknown
                            && cursor.process_request_digest == expected_request_digest
                    })
                })
                .is_some();
            self.observed_unknown_before_start
                .store(persisted, Ordering::SeqCst);
            self.inner
                .start(grant, registration, expected_request_digest)
        }

        fn inspect(
            &mut self,
            operation_id: &OperationId,
        ) -> Result<ProcessExecutionView, PortError> {
            self.inner.inspect(operation_id)
        }

        fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError> {
            self.inner.cancel(operation_id)
        }
    }

    struct InspectFailureProcess {
        inner: FakeProcess,
        fail_inspect: Arc<AtomicBool>,
    }

    impl ProcessPort for InspectFailureProcess {
        fn prepare_start(
            &mut self,
            grant: &LaunchGrant,
            registration: &RegistrationReceipt,
        ) -> Result<String, PortError> {
            self.inner.prepare_start(grant, registration)
        }

        fn start(
            &mut self,
            grant: &LaunchGrant,
            registration: &RegistrationReceipt,
            expected_request_digest: &str,
        ) -> Result<ProcessStartOutcome, PortError> {
            self.inner
                .start(grant, registration, expected_request_digest)
        }

        fn inspect(
            &mut self,
            operation_id: &OperationId,
        ) -> Result<ProcessExecutionView, PortError> {
            if self.fail_inspect.load(Ordering::SeqCst) {
                return Err(PortError::Unknown);
            }
            self.inner.inspect(operation_id)
        }

        fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError> {
            self.inner.cancel(operation_id)
        }
    }

    fn test_authority(_grant: &LaunchGrant) -> Result<DispatchPermitAuthority, PortError> {
        Ok(DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("broker-test-authority")
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])
                .map_err(|error| PortError::Invalid(error.to_string()))?,
        ))
    }

    fn test_context(grant: &LaunchGrant, now: i64) -> Result<DispatchValidationContext, PortError> {
        let fence = FencingToken::new(
            grant.authority_epoch,
            grant.approved.generation,
            grant.approved.process_fence_nonce.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(now),
                known_time_ms: Some(now),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch,
            BTreeMap::from([("broker".to_owned(), "a".repeat(64))]),
            1,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))
    }

    fn process_request_for_test(
        grant: &LaunchGrant,
        other_operation: bool,
    ) -> Result<(ProcessRequest, DispatchPermitAuthority), PortError> {
        let operation_id = if other_operation {
            OperationId::new("other-op")
        } else {
            Ok(grant.approved.operation_id.clone())
        }
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let intent = ProcessIntent::new(
            operation_id,
            grant.approved.process_tree_id.clone(),
            grant.approved.job_id.clone(),
            grant.approved.image_id.clone(),
            grant.approved.session_id.clone(),
            grant.approved.generation,
            grant.approved.executable.clone(),
            grant.approved.artifact_digest.clone(),
            grant.approved.argv.clone(),
            grant.approved.working_directory.clone(),
            grant.approved.environment.clone(),
            grant.approved.resource_limits,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let fence = FencingToken::new(
            grant.authority_epoch,
            grant.approved.generation,
            grant.approved.process_fence_nonce.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let mut authority = test_authority(grant)?;
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new("broker-test-lease")
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            fence,
            BTreeMap::from([("broker".to_owned(), "a".repeat(64))]),
            100,
            1_000,
            if other_operation {
                "other-nonce"
            } else {
                "launch-nonce"
            },
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let permit = authority
            .issue(&intent, issuance)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        let request = ProcessRequest::new(intent, permit)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        Ok((request, authority))
    }

    fn registration_request() -> RegistrationRequest {
        RegistrationRequest {
            installation_id: "install-1".to_owned(),
            windows_sid: "S-1-5-21-user".to_owned(),
            interactive_session_id: "session-1".to_owned(),
            boot_session_id: "boot-1".to_owned(),
            broker_process_id: "broker-pid".to_owned(),
            broker_artifact_digest: "a".repeat(64),
            protocol_generation: ProtocolVersion::CURRENT,
            launch_nonce: "nonce-1".to_owned(),
            observed_at: 10,
            lease_expires_at: 20,
        }
    }

    fn approved() -> ApprovedLaunch {
        ApprovedLaunch {
            operation_id: OperationId::new("op-1").expect("operation"),
            process_tree_id: ProcessTreeId::new("tree-1").expect("tree"),
            job_id: JobId::new("job-1").expect("job"),
            image_id: ImageId::new("image-1").expect("image"),
            session_id: SessionId::new("session-1").expect("session"),
            request_id: "request-1".to_owned(),
            route_fingerprint: "route-1".to_owned(),
            artifact_digest: "a".repeat(64),
            executable: "C:\\Eliot\\bin\\tool.exe".to_owned(),
            argv: vec!["--bounded".to_owned()],
            working_directory: "C:\\Eliot\\bin".to_owned(),
            root: "C:\\Eliot".to_owned(),
            effect_ceiling: EffectCeiling::CandidateOnly,
            tool: "tool-1".to_owned(),
            credential_handle: Some(
                SecretRef::new("credential-provider", "handle-1").expect("secret ref"),
            ),
            dependency_closure: vec!["dep-1".to_owned()],
            idempotency_key: "idem-1".to_owned(),
            generation: Generation::new(1).expect("generation"),
            process_fence_nonce: "process-fence".to_owned(),
            environment: EnvironmentProjection::default(),
            resource_limits: ResourceLimits::new(1000, None, None, 1024, 1024, 2).expect("limits"),
        }
    }

    fn launch_request() -> LaunchRequest {
        LaunchRequest {
            approved: approved(),
            observed_at: 11,
            lease_expires_at: 19,
        }
    }

    fn broker(authority: FakeAuthority, process: FakeProcess) -> UserBroker {
        UserBroker::new(
            Some(Box::new(authority)),
            Some(Box::new(process)),
            Some(Box::new(FakeDurable { snapshot: None })),
        )
    }

    #[test]
    fn registration_is_unique_and_epoch_fences_old_lineage() {
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let request = registration_request();
        let receipt = broker.register(request.clone()).expect("registration");
        assert_eq!(receipt.status, RegistrationStatus::Active);
        assert_eq!(
            broker.register(request.clone()),
            Err(BrokerError::DuplicateRegistration)
        );
        broker.logoff().expect("logoff");
        assert_eq!(
            broker.heartbeat(HeartbeatRequest {
                registration_digest: receipt.registration_digest,
                observed_at: 12
            }),
            Err(BrokerError::LeaseExpired)
        );
    }

    #[test]
    fn close_unknown_publication_reconciles_exact_state_or_restores_active() {
        for publish_before_fail in [false, true] {
            let snapshot = Arc::new(Mutex::new(None));
            let fail_next = Arc::new(AtomicBool::new(false));
            let mut broker = UserBroker::new(
                Some(Box::new(FakeAuthority::new())),
                Some(Box::new(FakeProcess {
                    state: None,
                    unknown: false,
                    wrong_receipt: false,
                })),
                Some(Box::new(UncertainDurable {
                    snapshot: Arc::clone(&snapshot),
                    fail_next: Arc::clone(&fail_next),
                    publish_before_fail,
                })),
            );
            let registered = broker
                .register(registration_request())
                .expect("registration");
            fail_next.store(true, Ordering::SeqCst);
            let closed = broker.logoff();
            if publish_before_fail {
                assert_eq!(closed, Ok(()));
            } else {
                assert_eq!(closed, Err(BrokerError::UnknownOutcome));
            }
            // The authoritative fence is known even when the local durable
            // publication is uncertain, so the fenced broker must not renew
            // or launch against the old ORS registration.
            assert_eq!(
                broker.heartbeat(HeartbeatRequest {
                    registration_digest: registered.registration_digest,
                    observed_at: 12,
                }),
                Err(BrokerError::LeaseExpired)
            );
        }
    }

    #[test]
    fn fence_receipt_mismatch_never_projects_local_close() {
        let mut authority = FakeAuthority::new();
        authority.tamper = Tamper::FenceReceipt;
        let mut broker = broker(
            authority,
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let registered = broker
            .register(registration_request())
            .expect("registration");
        assert_eq!(broker.logoff(), Err(BrokerError::GrantBindingMismatch));
        assert!(
            broker
                .heartbeat(HeartbeatRequest {
                    registration_digest: registered.registration_digest,
                    observed_at: 12,
                })
                .is_ok()
        );
    }

    #[test]
    fn recovered_registration_is_gated_until_authoritative_heartbeat() {
        let mut first = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        first
            .register(registration_request())
            .expect("registration");
        let snapshot = BrokerSnapshot {
            registration: first.registration.clone(),
            user_broker_epoch: first.broker_epoch,
            operation_cursors: Vec::new(),
        };
        let registration_digest = snapshot
            .registration
            .as_ref()
            .expect("registration")
            .registration_digest
            .clone();
        let mut authority = FakeAuthority::new();
        authority.broker_epoch = snapshot.user_broker_epoch;
        authority.last = Some(registration_request());
        let mut restarted = UserBroker::new(
            Some(Box::new(authority)),
            Some(Box::new(FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            })),
            Some(Box::new(FakeDurable {
                snapshot: Some(snapshot),
            })),
        );
        restarted.recover().expect("recover");
        assert_eq!(
            restarted.launch(launch_request()),
            Err(BrokerError::PlanGap(RequiredProvider::G01Authority))
        );
        assert!(
            restarted
                .heartbeat(HeartbeatRequest {
                    registration_digest,
                    observed_at: 11,
                })
                .is_ok()
        );
    }

    #[test]
    fn heartbeat_expiry_and_session_events_close_admission() {
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let mut request = registration_request();
        request.lease_expires_at = 12;
        let _ = broker.register(request).expect("registration");
        assert_eq!(
            broker.heartbeat(HeartbeatRequest {
                registration_digest: "wrong".to_owned(),
                observed_at: 11
            }),
            Err(BrokerError::GrantBindingMismatch)
        );
        assert_eq!(broker.boot_session_changed("boot-2"), Ok(()));
    }

    #[test]
    fn heartbeat_refreshes_the_exact_recovered_registration_lineage() {
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let mut request = registration_request();
        request.lease_expires_at = 100;
        let registered = broker.register(request).expect("registration");
        let refreshed = broker
            .heartbeat(HeartbeatRequest {
                registration_digest: registered.registration_digest.clone(),
                observed_at: 11,
            })
            .expect("heartbeat");
        assert_eq!(
            refreshed.registration_digest,
            registered.registration_digest
        );
        assert_eq!(refreshed.user_broker_epoch, registered.user_broker_epoch);
        assert_eq!(refreshed.fence_id, registered.fence_id);
        assert_eq!(refreshed.expires_at, registered.expires_at);
        assert_eq!(
            broker.registration_digest(),
            Some(registered.registration_digest.as_str())
        );
    }

    #[test]
    fn registration_grant_binding_rejects_wrong_sid_nonce_and_epoch() {
        for tamper in [
            Tamper::RegistrationSid,
            Tamper::RegistrationSession,
            Tamper::RegistrationNonce,
        ] {
            let mut first_broker = broker(
                FakeAuthority {
                    epoch: 7,
                    broker_epoch: 0,
                    tamper,
                    last: None,
                },
                FakeProcess {
                    state: None,
                    unknown: false,
                    wrong_receipt: false,
                },
            );
            assert_eq!(
                first_broker.register(registration_request()),
                Err(BrokerError::GrantBindingMismatch)
            );
        }
        let mut stale = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let mut request = registration_request();
        request.launch_nonce.clear();
        assert_eq!(
            stale.register(request),
            Err(BrokerError::InvalidField("launch_nonce"))
        );
    }

    #[test]
    fn launch_uses_exact_approval_and_rejects_artifact_route_effect_lease_fence() {
        for tamper in [
            Tamper::LaunchRoute,
            Tamper::LaunchArtifact,
            Tamper::LaunchEffect,
            Tamper::LaunchLease,
            Tamper::LaunchFence,
        ] {
            let mut authority = FakeAuthority::new();
            authority.tamper = tamper;
            let mut broker = broker(
                authority,
                FakeProcess {
                    state: None,
                    unknown: false,
                    wrong_receipt: false,
                },
            );
            broker
                .register(registration_request())
                .expect("registration");
            assert_eq!(
                broker.launch(launch_request()),
                Err(BrokerError::GrantBindingMismatch)
            );
        }
    }

    #[test]
    fn launch_is_single_use_lineage_checked_and_restart_is_unknown_until_reconciled() {
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        broker
            .register(registration_request())
            .expect("registration");
        let receipt = broker.launch(launch_request()).expect("launch");
        assert!(receipt.lineage_verified);
        assert_eq!(
            broker
                .launch(launch_request())
                .expect("idempotent")
                .operation_id,
            receipt.operation_id
        );

        let mut durable = FakeDurable { snapshot: None };
        durable
            .save(&BrokerSnapshot {
                registration: None,
                user_broker_epoch: 0,
                operation_cursors: Vec::new(),
            })
            .expect("seed");
        let mut restarted = UserBroker::new(
            Some(Box::new(FakeAuthority::new())),
            Some(Box::new(FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            })),
            Some(Box::new(durable)),
        );
        assert_eq!(restarted.recover(), Ok(()));
    }

    #[test]
    fn unknown_process_outcome_requires_reconcile_and_wrong_receipt_fails() {
        let mut unknown = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: true,
                wrong_receipt: false,
            },
        );
        unknown
            .register(registration_request())
            .expect("registration");
        assert_eq!(
            unknown.launch(launch_request()),
            Err(BrokerError::UnknownOutcome)
        );
        let permit = unknown
            .operations
            .get("idem-1")
            .expect("unknown cursor")
            .permit
            .clone();
        assert!(unknown.reconcile(&permit).is_ok());

        let mut wrong = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: true,
            },
        );
        wrong
            .register(registration_request())
            .expect("registration");
        assert_eq!(
            wrong.launch(launch_request()),
            Err(BrokerError::ProcessBindingMismatch)
        );
        let wrong_cursor = wrong
            .operations
            .get("idem-1")
            .expect("precommitted wrong-receipt cursor");
        assert_eq!(wrong_cursor.cursor.state, OperationState::Unknown);
        assert!(!wrong_cursor.cursor.process_request_digest.is_empty());
    }

    #[test]
    fn launch_persists_unknown_cursor_before_process_start_effect() {
        let snapshot = Arc::new(Mutex::new(None));
        let observed_unknown_before_start = Arc::new(AtomicBool::new(false));
        let mut broker = UserBroker::new(
            Some(Box::new(FakeAuthority::new())),
            Some(Box::new(OrderingProcess {
                inner: FakeProcess {
                    state: None,
                    unknown: false,
                    wrong_receipt: false,
                },
                snapshot: snapshot.clone(),
                observed_unknown_before_start: observed_unknown_before_start.clone(),
            })),
            Some(Box::new(OrderingDurable {
                snapshot: snapshot.clone(),
            })),
        );
        broker
            .register(registration_request())
            .expect("registration");
        broker.launch(launch_request()).expect("launch");
        assert!(observed_unknown_before_start.load(Ordering::SeqCst));
    }

    #[test]
    fn inspect_failure_keeps_unknown_cursor_for_later_reconcile() {
        let fail_inspect = Arc::new(AtomicBool::new(true));
        let mut broker = UserBroker::new(
            Some(Box::new(FakeAuthority::new())),
            Some(Box::new(InspectFailureProcess {
                inner: FakeProcess {
                    state: None,
                    unknown: false,
                    wrong_receipt: false,
                },
                fail_inspect: fail_inspect.clone(),
            })),
            Some(Box::new(FakeDurable { snapshot: None })),
        );
        broker
            .register(registration_request())
            .expect("registration");
        assert_eq!(
            broker.launch(launch_request()),
            Err(BrokerError::UnknownOutcome)
        );
        let permit = broker
            .operations
            .get("idem-1")
            .expect("unknown cursor after inspect failure")
            .permit
            .clone();
        assert_eq!(
            broker
                .operations
                .get("idem-1")
                .expect("cursor")
                .cursor
                .state,
            OperationState::Unknown
        );
        fail_inspect.store(false, Ordering::SeqCst);
        broker.reconcile(&permit).expect("reconcile");
        assert_eq!(
            broker
                .operations
                .get("idem-1")
                .expect("reconciled cursor")
                .cursor
                .state,
            OperationState::Active
        );
    }

    #[test]
    fn operation_permit_is_exact_and_restart_cursor_preserves_lineage_bindings() {
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        broker
            .register(registration_request())
            .expect("registration");
        let receipt = broker.launch(launch_request()).expect("launch");
        let snapshot = BrokerSnapshot {
            registration: broker.registration.clone(),
            user_broker_epoch: broker.broker_epoch,
            operation_cursors: broker
                .operations
                .values()
                .map(|record| record.cursor.clone())
                .collect(),
        };
        let expected_cursor = snapshot.operation_cursors.first().expect("cursor").clone();
        assert_eq!(expected_cursor.operation_id, receipt.operation_id);
        assert_eq!(
            expected_cursor.lease_expires_at,
            receipt.operation_permit.lease_expires_at
        );
        assert_eq!(expected_cursor.process_tree_id, approved().process_tree_id);
        assert_eq!(expected_cursor.generation, approved().generation);
        assert_eq!(
            expected_cursor.process_fence_nonce,
            approved().process_fence_nonce
        );

        let mut restarted = UserBroker::new(
            Some(Box::new(FakeAuthority::new())),
            Some(Box::new(FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            })),
            Some(Box::new(FakeDurable {
                snapshot: Some(snapshot),
            })),
        );
        restarted.recover().expect("recover");
        assert_eq!(
            restarted
                .operations
                .get("idem-1")
                .expect("recovered operation")
                .cursor,
            expected_cursor
        );

        let mut forged = receipt.operation_permit.clone();
        forged.fence_id = "forged-fence".to_owned();
        assert_eq!(
            restarted.cancel(&forged),
            Err(BrokerError::GrantBindingMismatch)
        );
        assert_eq!(
            restarted.reconcile(&forged),
            Err(BrokerError::GrantBindingMismatch)
        );
    }

    #[test]
    fn missing_authority_process_and_durable_ports_are_typed_gaps() {
        let request = registration_request();
        let mut no_authority =
            UserBroker::new(None, None, Some(Box::new(FakeDurable { snapshot: None })));
        assert_eq!(
            no_authority.register(request.clone()),
            Err(BrokerError::PlanGap(RequiredProvider::G01Authority))
        );
        let mut no_durable = UserBroker::new(Some(Box::new(FakeAuthority::new())), None, None);
        assert_eq!(
            no_durable.register(request),
            Err(BrokerError::PlanGap(RequiredProvider::DurableRegistration))
        );
    }

    #[test]
    fn unknown_fields_and_duplicate_dependency_closure_fail_closed() {
        assert!(serde_json::from_str::<RegistrationRequest>(r#"{"installation_id":"x","windows_sid":"s","interactive_session_id":"i","boot_session_id":"b","broker_process_id":"p","broker_artifact_digest":"a","protocol_generation":{"major":1,"minor":0,"extra":true},"launch_nonce":"n","observed_at":1,"lease_expires_at":2}"#).is_err());
        let mut request = launch_request();
        request.approved.dependency_closure.push("dep-1".to_owned());
        assert_eq!(
            request.validate(),
            Err(BrokerError::Duplicate("dependency_closure"))
        );
    }
}
