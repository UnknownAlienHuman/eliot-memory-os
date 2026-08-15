//! A-09 provider-neutral interactive user-broker core.
//!
//! This crate owns admission and lifecycle composition only.  G-01 supplies
//! authenticated grants, P-04 supplies the physical implementation behind the
//! P-03 process contract, and durable registration state is injected.  No
//! Windows API, SCM, process, credential, or storage implementation lives here.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_process::{
    CancellationReceipt, EnvironmentProjection, FencingToken, Generation, OperationId,
    ProcessExecutionView, ProcessLifecycle, ProcessRequest, ProcessStartReceipt, ProcessTreeId,
    ResourceLimits, SecretRef,
};
use eliot_protocol::ProtocolVersion;
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::EffectCeiling;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.surfaces.user-broker-core/v1";

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

/// The exact approved launch projection.  Credential material is never present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedLaunch {
    pub operation_id: OperationId,
    pub process_tree_id: ProcessTreeId,
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
}

pub trait DurableRegistrationPort: Send {
    fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError>;
    fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError>;
}

/// P-04 adapter boundary.  Every positive start uses exact P-03 types.
pub trait ProcessPort: Send {
    fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError>;
    fn inspect(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError>;
    fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError>;
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
        self.persist()?;
        Ok(sealed)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn heartbeat(
        &mut self,
        request: HeartbeatRequest,
    ) -> Result<HeartbeatReceipt, BrokerError> {
        text(&request.registration_digest, "registration_digest")?;
        let current = self.active_registration(request.observed_at)?.clone();
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
        self.persist()?;
        Ok(HeartbeatReceipt {
            registration_digest: refreshed.registration_digest,
            user_broker_epoch: refreshed.user_broker_epoch,
            fence_id: refreshed.fence_id,
            expires_at: refreshed.expires_at,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
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
        let process_request = process_request_from_grant(&grant)?;
        let permit = permit_from_grant(&grant, &current, &request_digest);
        let mut cursor = cursor_from_grant(
            &grant,
            &current,
            &request_digest,
            &process_request,
            OperationState::Unknown,
        );
        let receipt = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .start(process_request.clone())
            .map_err(|error| {
                if matches!(error, PortError::Unknown) {
                    self.operations.insert(
                        request.approved.idempotency_key.clone(),
                        OperationRecord {
                            cursor: cursor.clone(),
                            permit: permit.clone(),
                            receipt: None,
                        },
                    );
                    let _ = self.persist();
                    BrokerError::UnknownOutcome
                } else {
                    map_port(RequiredProvider::P03Process, error)
                }
            })?;
        if receipt.operation_id() != process_request.operation_id()
            || receipt.request_digest() != process_request.invocation_digest()
            || receipt.accepted_generation() != process_request.generation()
        {
            return Err(BrokerError::ProcessBindingMismatch);
        }
        let view = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .inspect(process_request.operation_id())
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        verify_lineage(&process_request, &view)?;
        cursor.state = OperationState::Active;
        let launch_receipt = LaunchReceipt {
            operation_id: process_request.operation_id().clone(),
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
                cursor,
                permit,
                receipt: Some(launch_receipt.clone()),
            },
        );
        self.persist()?;
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
            .inspect(&operation_id)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        verify_cursor_lineage(&cursor, &view)?;
        if let Some(record) = self
            .operations
            .values_mut()
            .find(|record| record.permit.operation_id == operation_id)
        {
            record.cursor.state = OperationState::Reconciled;
            record.receipt = None;
        }
        self.persist()?;
        Ok(view)
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
        if let Some(registration) = &mut self.registration {
            registration.status = status;
        }
        self.persist()
    }

    fn persist(&mut self) -> Result<(), BrokerError> {
        let snapshot = BrokerSnapshot {
            registration: self.registration.clone(),
            user_broker_epoch: self.broker_epoch,
            operation_cursors: self
                .operations
                .values()
                .map(|record| record.cursor.clone())
                .collect(),
        };
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

fn process_request_from_grant(grant: &LaunchGrant) -> Result<ProcessRequest, BrokerError> {
    let fence = FencingToken::new(
        grant.authority_epoch,
        grant.approved.generation,
        grant.approved.process_fence_nonce.clone(),
    )
    .map_err(|error| BrokerError::Provider(error.to_string()))?;
    ProcessRequest::new(
        grant.approved.operation_id.clone(),
        grant.approved.process_tree_id.clone(),
        grant.approved.generation,
        grant.approved.executable.clone(),
        grant.approved.artifact_digest.clone(),
        grant.approved.argv.clone(),
        grant.approved.working_directory.clone(),
        grant.approved.environment.clone(),
        grant.approved.resource_limits,
        fence,
    )
    .map_err(|error| BrokerError::Provider(error.to_string()))
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
    process_request: &ProcessRequest,
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
        process_request_digest: process_request.invocation_digest().to_owned(),
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

fn verify_lineage(
    request: &ProcessRequest,
    view: &ProcessExecutionView,
) -> Result<(), BrokerError> {
    if view.lifecycle() != ProcessLifecycle::Running {
        return Err(BrokerError::ProcessLineageMismatch);
    }
    let identity = view.identity().ok_or(BrokerError::ProcessLineageMismatch)?;
    if view.operation_id() != request.operation_id()
        || view.request_digest() != request.invocation_digest()
        || view.fence() != request.fence()
        || identity.process_tree_id() != request.process_tree_id()
        || identity.generation() != request.generation()
        || identity.executable_sha256() != request.executable_sha256()
    {
        return Err(BrokerError::ProcessLineageMismatch);
    }
    Ok(())
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
    use eliot_process::{
        ProcessHealth, ProcessId, ProcessIdentity, ProcessLifecycle, ProcessState,
    };

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
                | Tamper::RegistrationNonce => {}
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

    struct FakeProcess {
        state: Option<ProcessState>,
        unknown: bool,
        wrong_receipt: bool,
    }

    impl ProcessPort for FakeProcess {
        fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError> {
            let mut state = ProcessState::new(request.clone())
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            let identity = ProcessIdentity::new(
                ProcessId::new("pid-1").expect("pid"),
                request.process_tree_id().clone(),
                request.generation(),
                42,
                11,
                request.executable_sha256(),
            )
            .map_err(|error| PortError::Invalid(error.to_string()))?;
            state
                .start(identity)
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            state
                .mark_running(ProcessHealth::default())
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            self.state = Some(state);
            if self.unknown {
                return Err(PortError::Unknown);
            }
            if self.wrong_receipt {
                let other = ProcessRequest::new(
                    OperationId::new("other-op").expect("operation"),
                    request.process_tree_id().clone(),
                    request.generation(),
                    request.executable().to_owned(),
                    request.executable_sha256().to_owned(),
                    request.argv().to_vec(),
                    request.working_directory().to_owned(),
                    request.environment().clone(),
                    *request.resource_limits(),
                    request.fence().clone(),
                )
                .map_err(|error| PortError::Invalid(error.to_string()))?;
                return ProcessStartReceipt::new(&other, ProcessLifecycle::Running)
                    .map_err(|error| PortError::Invalid(error.to_string()));
            }
            ProcessStartReceipt::new(&request, ProcessLifecycle::Running)
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
            let fence = state.request().fence().clone();
            state
                .cancel(&fence)
                .map_err(|error| PortError::Invalid(error.to_string()))
        }
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
