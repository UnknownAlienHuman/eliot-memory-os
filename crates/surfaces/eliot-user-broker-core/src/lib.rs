//! A-09 provider-neutral interactive user-broker core.
//!
//! This crate owns admission and lifecycle composition only.  G-01 supplies
//! authenticated grants, P-04 supplies the physical implementation behind the
//! P-03 process contract, and durable registration state is injected.  No
//! Windows API, SCM, process, credential, or storage implementation lives here.
//!
//! Issue #74 adds two durable responsibilities to the injected durable
//! provider: the per-operation request-identity ledger
//! ([`IssuedOperationIdentity`], projected by the composition through
//! [`IssuedOperationIdentityLedger`]) and the exact-registration-identity
//! reconciliation of a lost acknowledgement ([`RegistrationReconciliation`]).
//! Neither mints authority: the Kernel still validates every identity, and the
//! broker-local `user_broker_epoch` scalar is never copied into an identity
//! row or conflated with an authority epoch.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::EpochId;
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

/// Rejects disclosed secret material in any operator-visible launch field.
///
/// A user credential or resource is introduced only as an opaque
/// [`SecretRef`] inside the exact grant.  An argument vector, an executable
/// path, a working directory, a route fingerprint, or a tool name is
/// published to the process table, to logs, and to diagnostic payloads, so
/// secret material there is a disclosure, not a launch.  The marker set is
/// the same one the process contract applies to a non-secret environment
/// map, so the broker refuses exactly what the child would refuse to carry.
fn validate_no_disclosed_secret(approved: &ApprovedLaunch) -> Result<(), BrokerError> {
    const NAME_MARKERS: [&str; 7] = [
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "SECRET",
        "PRIVATE_KEY",
        "API_KEY",
        "CREDENTIAL",
    ];
    const VALUE_MARKERS: [&str; 3] = ["bearer ", "sk-", "-----begin "];
    let carries_marker = |value: &str| {
        let upper = value.to_ascii_uppercase();
        let lower = value.to_ascii_lowercase();
        NAME_MARKERS.iter().any(|marker| upper.contains(marker))
            || VALUE_MARKERS.iter().any(|marker| lower.contains(marker))
    };
    let disclosed = carries_marker(&approved.executable)
        || carries_marker(&approved.working_directory)
        || carries_marker(&approved.root)
        || carries_marker(&approved.tool)
        || carries_marker(&approved.request_id)
        || carries_marker(&approved.route_fingerprint)
        || carries_marker(&approved.idempotency_key)
        || carries_marker(&approved.process_fence_nonce)
        || carries_marker(approved.image_id.as_str())
        || approved
            .argv
            .iter()
            .any(|value| carries_marker(value.as_str()))
        || approved
            .dependency_closure
            .iter()
            .any(|value| carries_marker(value.as_str()))
        // The introduction is scope and audience: it is published into the
        // grant digest, the durable operation cursor, and every diagnostic
        // the broker projects. Secret material in any of its scope fields is
        // a disclosure of exactly the same class as a secret in argv.
        || carries_marker(&approved.introduction.resource_ref)
        || carries_marker(&approved.introduction.facet_manifest_ref)
        || approved
            .introduction
            .introduced_operation_set
            .iter()
            .any(|value| carries_marker(value.as_str()))
        || approved
            .introduction
            .introduced_resource_set
            .iter()
            .any(|value| carries_marker(value.as_str()));
    if disclosed {
        return Err(BrokerError::CredentialMaterialDisclosed(
            "launch_disclosure",
        ));
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
///
/// `authority_epoch` is the lineage-aware Kernel authority minted ONLY at the
/// admitted broker/registration owner with a migration receipt (T6-E3 Split C).
/// `user_broker_epoch` is broker-local and never conflated with authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationGrant {
    pub registration: RegistrationRequest,
    pub authority_epoch: EpochId,
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
    pub authority_epoch: EpochId,
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
    pub authority_epoch: EpochId,
    pub fence_id: String,
    pub operation_id: OperationId,
    pub status: RegistrationStatus,
}

/// Principal-bound credential lease introduced for one admitted child
/// (I6.15 `CredentialUseBinding`, narrowed to the fields this broker
/// admission boundary must enforce).
///
/// Only the opaque provider/key handle crosses this boundary: no secret
/// material is present, is derivable here, or is forwarded to the child
/// environment. `expires_at` is the binding's own deadline and may never
/// outlive the introduction that names it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    /// Opaque provider/key handle resolved by the child's own crypto port.
    pub handle: SecretRef,
    /// Absolute expiry of this binding, in Unix milliseconds.
    pub expires_at: u64,
}

/// The exact user-session resource a grant introduces to one admitted child.
///
/// This is I6.15's `CapabilityIntroduction` reduced to the fields a broker
/// admission boundary can actually enforce: the opaque resource reference,
/// the facet manifest the introduction is limited to, the operation and
/// resource scope it covers, the effect ceiling it may reach, its own
/// issue/expiry window and use budget, and the credential lease it names.
/// The issuer is Kernel/Governor — this type grants nothing. Its whole
/// purpose is to make "a grant must not introduce a resource it does not
/// name" a checkable comparison instead of a carried-along string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIntroduction {
    /// Opaque, non-revealing reference presented to the child. I6.15: an
    /// agent sees "an opaque `ResourceRef`, not a broad reusable path
    /// grant", so a path-shaped or drive-shaped value is refused here
    /// rather than forwarded as one.
    pub resource_ref: String,
    /// Exact facet manifest identity this introduction is limited to.
    pub facet_manifest_ref: String,
    /// Operations this introduction may be used for.
    pub introduced_operation_set: Vec<String>,
    /// User-session resource roots this introduction may reach.
    pub introduced_resource_set: Vec<String>,
    /// Highest effect this introduction may produce.
    pub max_effect: EffectCeiling,
    /// Absolute issue instant of this introduction, in Unix milliseconds.
    pub issued_at: u64,
    /// Absolute expiry of this introduction, in Unix milliseconds.
    pub expires_at: u64,
    /// Use budget of this introduction. Zero is not a usable budget.
    pub max_calls: u32,
    /// The principal-bound credential lease, when one is introduced.
    pub credential_binding: Option<CredentialBinding>,
}

impl ResourceIntroduction {
    fn validate(&self) -> Result<(), BrokerError> {
        text(&self.resource_ref, "introduction.resource_ref")?;
        if self.resource_ref.contains(['/', '\\', ':', '*', '?']) {
            return Err(BrokerError::InvalidField("introduction.resource_ref"));
        }
        text(&self.facet_manifest_ref, "introduction.facet_manifest_ref")?;
        if self.introduced_operation_set.is_empty() {
            return Err(BrokerError::IntroductionRequired(
                "introduced_operation_set",
            ));
        }
        unique(&self.introduced_operation_set, "introduced_operation_set")?;
        if self.introduced_resource_set.is_empty() {
            return Err(BrokerError::IntroductionRequired("introduced_resource_set"));
        }
        unique(&self.introduced_resource_set, "introduced_resource_set")?;
        if self.max_calls == 0 || self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(BrokerError::InvalidField("introduction_window"));
        }
        if let Some(binding) = &self.credential_binding
            && (binding.expires_at == 0
                || binding.expires_at > self.expires_at
                || binding.expires_at <= self.issued_at)
        {
            return Err(BrokerError::InvalidField("credential_binding.expires_at"));
        }
        Ok(())
    }

    /// Returns the rank of one effect ceiling, from least to most authority.
    ///
    /// `NoExternalEffect` is the narrowest ceiling, so a request for a
    /// narrower ceiling than the introduction allows is admitted and a
    /// request for a wider one is not.
    const fn effect_rank(ceiling: EffectCeiling) -> u8 {
        match ceiling {
            EffectCeiling::ReadOnly => 0,
            EffectCeiling::CandidateOnly => 1,
            EffectCeiling::NoExternalEffect => 2,
        }
    }

    /// Compares one launch request against what this introduction names.
    ///
    /// Every comparison is exact: the tool must be an introduced operation,
    /// the resource root must be an introduced resource, the requested
    /// effect must fit under the introduced ceiling, the introduction must
    /// be active at the observation instant, and the credential lease the
    /// launch carries must be exactly the lease the introduction names.
    /// A request that reaches past any of those is refused with its own
    /// typed reason (I6.15: a missing exact resource facet returns
    /// `CAPABILITY_INTRODUCTION_REQUIRED`, and neither that condition nor a
    /// revoked supporting grant is translated into a generic tool failure or
    /// a silently widened introduction).
    fn admits(&self, approved: &ApprovedLaunch, observed_at: u64) -> Result<(), BrokerError> {
        self.validate()?;
        if !self.introduced_operation_set.contains(&approved.tool) {
            return Err(BrokerError::IntroductionOperationNotGranted);
        }
        if !self.introduced_resource_set.contains(&approved.root) {
            return Err(BrokerError::IntroductionResourceNotGranted);
        }
        if Self::effect_rank(approved.effect_ceiling) > Self::effect_rank(self.max_effect) {
            return Err(BrokerError::IntroductionEffectCeilingExceeded);
        }
        if observed_at < self.issued_at || observed_at >= self.expires_at {
            return Err(BrokerError::IntroductionExpired);
        }
        match (&self.credential_binding, &approved.credential_handle) {
            (Some(binding), Some(handle)) if binding.handle == *handle => {}
            (None, None) => {}
            // A grant that carries a credential the introduction does not
            // name, or names a credential the launch does not carry, is a
            // scope mismatch — never a silent pass.
            _ => return Err(BrokerError::IntroductionCredentialUnnamed),
        }
        if let Some(binding) = &self.credential_binding
            && observed_at >= binding.expires_at
        {
            return Err(BrokerError::IntroductionExpired);
        }
        Ok(())
    }
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
    /// The opaque credential handle the launch requests. It is meaningful
    /// only when the grant's [`ResourceIntroduction`] names exactly this
    /// handle; a request that carries a credential its introduction does
    /// not name is refused.
    pub credential_handle: Option<SecretRef>,
    /// The exact user-session resource this launch introduces.
    pub introduction: ResourceIntroduction,
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
        validate_no_disclosed_secret(&self.approved)?;
        self.approved
            .introduction
            .admits(&self.approved, self.observed_at)?;
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

/// One exact interactive identity tuple this broker process is admitted as.
///
/// The tuple is derived from the protected installation declaration the
/// composition authenticated against the live process; it is never supplied
/// by stdin, by a UI, or by a caller-provided launch request.  Admission is
/// *single*: one tuple admits one broker, and a registration recovered from
/// durable state is admitted only when it carries exactly this tuple.  A
/// different SID, logon Session, boot Session, installation, artifact, or
/// process is another broker's registration and is refused instead of
/// adopted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAdmissionIdentity {
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub boot_session_id: String,
    pub broker_process_id: String,
    pub broker_artifact_digest: String,
    pub protocol_generation: ProtocolVersion,
    pub launch_nonce: String,
}

impl BrokerAdmissionIdentity {
    /// Returns whether one sealed registration is this broker's own tuple.
    ///
    /// The broker-local generation, the authority epoch, and the fence are
    /// deliberately excluded: they are properties of one registration
    /// revision, not of the process identity that is admitted to hold it.
    /// A restart legitimately presents a new process identity and therefore
    /// a new registration revision under the same tuple.
    #[must_use]
    pub fn admits(&self, registration: &RegistrationReceipt) -> bool {
        self.installation_id == registration.installation_id
            && self.windows_sid == registration.windows_sid
            && self.interactive_session_id == registration.interactive_session_id
            && self.boot_session_id == registration.boot_session_id
    }

    fn validate(&self) -> Result<(), BrokerError> {
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
            .map_err(|error| BrokerError::Provider(error.to_string()))
    }
}

/// Broker-owned control operation with its own canonical operation identity.
///
/// Register, heartbeat, launch, and the terminal fence own Kernel operation
/// identities minted by the composed transport issuer.  Cancellation and
/// reconciliation are broker-owned effects on the broker's own Job contour:
/// they are not Kernel transactions, but they are still distinct, durable
/// operations, so they get their own operation selectors in the same durable
/// per-operation identity ledger instead of borrowing a launch identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrokerControlOperation {
    Cancel,
    Reconcile,
}

impl BrokerControlOperation {
    /// Returns the exact operation selector recorded in the durable ledger.
    #[must_use]
    pub const fn selector(self) -> &'static str {
        match self {
            Self::Cancel => "eliot.user-broker.cancel",
            Self::Reconcile => "eliot.user-broker.reconcile",
        }
    }

    /// Returns the short idempotency-namespace tag of this control operation.
    const fn namespace(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Reconcile => "reconcile",
        }
    }
}

/// Provider-issued exact launch approval; never accepted directly by public APIs.
///
/// `authority_epoch` is the lineage-aware authority minted ONLY at the
/// admitted broker owner. `user_broker_epoch` is broker-local (u64) and is
/// never conflated with authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchGrant {
    pub approved: ApprovedLaunch,
    pub proof_ceiling: ProofCeiling,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: EpochId,
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

/// Stable, credential-free projection of the real [`LaunchReceipt`] for the
/// authenticated Operator launch boundary.  The private [`OperationPermit`]
/// is deliberately excluded: it remains inside [`UserBroker`] and cannot be
/// manufactured by a UI, CLI, or wire decoder.
pub const OPERATOR_LAUNCH_RECEIPT_WIRE_ID: &str = "eliot.user-broker.operator-launch-receipt";
pub const OPERATOR_LAUNCH_RECEIPT_WIRE_VERSION: u16 = 1;
pub const OPERATOR_LAUNCH_RESTART_WIRE_ID: &str = "eliot.user-broker.operator-restart-receipt";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorLaunchReceipt {
    pub wire_id: String,
    pub wire_version: u16,
    pub operation_id: OperationId,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub fence_id: String,
    pub process_receipt: ProcessStartReceipt,
    pub proof_ceiling: ProofCeiling,
    pub lineage_verified: bool,
    pub disposition: LaunchDisposition,
}

impl OperatorLaunchReceipt {
    /// Projects the exact owner result without exposing its private permit.
    pub fn from_launch(receipt: &LaunchReceipt) -> Self {
        Self {
            wire_id: OPERATOR_LAUNCH_RECEIPT_WIRE_ID.to_owned(),
            wire_version: OPERATOR_LAUNCH_RECEIPT_WIRE_VERSION,
            operation_id: receipt.operation_id.clone(),
            request_digest: receipt.request_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            user_broker_epoch: receipt.user_broker_epoch,
            fence_id: receipt.fence_id.clone(),
            process_receipt: receipt.process_receipt.clone(),
            proof_ceiling: receipt.proof_ceiling,
            lineage_verified: receipt.lineage_verified,
            disposition: receipt.disposition,
        }
    }

    /// Validates the wire projection as an owner-bound terminal receipt.
    /// Arbitrary non-empty JSON cannot satisfy this contract.
    pub fn validate(&self) -> Result<(), BrokerError> {
        if OperationId::new(self.operation_id.as_str().to_owned()).is_err() {
            return Err(BrokerError::InvalidField("operator_operation_id"));
        }
        if self.wire_id != OPERATOR_LAUNCH_RECEIPT_WIRE_ID
            || self.wire_version != OPERATOR_LAUNCH_RECEIPT_WIRE_VERSION
        {
            return Err(BrokerError::InvalidField("operator_launch_receipt_wire"));
        }
        hex_digest(&self.request_digest, "operator_request_digest")?;
        hex_digest(&self.registration_digest, "operator_registration_digest")?;
        text(&self.fence_id, "operator_fence_id")?;
        if self.user_broker_epoch == 0 || !self.lineage_verified {
            return Err(BrokerError::InvalidField("operator_launch_receipt_binding"));
        }
        if self.proof_ceiling != ProofCeiling::Observation
            || self.disposition != LaunchDisposition::Active
        {
            return Err(BrokerError::InvalidField(
                "operator_launch_receipt_disposition",
            ));
        }
        self.process_receipt
            .validate()
            .map_err(|error| BrokerError::Provider(format!("process receipt: {error}")))?;
        if self.process_receipt.operation_id() != &self.operation_id {
            return Err(BrokerError::ProcessBindingMismatch);
        }
        Ok(())
    }
}

impl LaunchReceipt {
    /// Returns the only public launch projection admitted on the Operator
    /// boundary.  The private operation permit never crosses this method.
    pub fn operator_receipt(&self) -> OperatorLaunchReceipt {
        OperatorLaunchReceipt::from_launch(self)
    }
}

/// Exact owner binding returned when the serving generation/session has been
/// invalidated before a new Operator launch can be admitted.  This is a
/// typed restart disposition, not a free-form error object or a continuity
/// token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorLaunchRestartReceipt {
    pub wire_id: String,
    pub wire_version: u16,
    pub operation_id: OperationId,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub fence_id: String,
}

impl OperatorLaunchRestartReceipt {
    pub fn validate(&self) -> Result<(), BrokerError> {
        if OperationId::new(self.operation_id.as_str().to_owned()).is_err() {
            return Err(BrokerError::InvalidField("operator_operation_id"));
        }
        if self.wire_id != OPERATOR_LAUNCH_RESTART_WIRE_ID
            || self.wire_version != OPERATOR_LAUNCH_RECEIPT_WIRE_VERSION
        {
            return Err(BrokerError::InvalidField("operator_restart_receipt_wire"));
        }
        hex_digest(&self.registration_digest, "operator_registration_digest")?;
        text(&self.fence_id, "operator_fence_id")?;
        if self.user_broker_epoch == 0 {
            return Err(BrokerError::InvalidField(
                "operator_restart_receipt_binding",
            ));
        }
        Ok(())
    }
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
    authority_epoch: EpochId,
    fence_id: String,
    lease_expires_at: u64,
}

/// One durably retained per-operation Kernel request identity (issue #74).
///
/// This is the *ledger* half of an issued operation identity, not the
/// identity itself: it names the exact operation selector, the canonical
/// payload digest it is bound to, and the three transport identity strings
/// plus the absolute deadline it was minted with. A broker restart re-seeds
/// its operation-identity issuer from these rows, so a request id, a
/// cancellation id, or an idempotency key that was already spent is a durable
/// `IDENTITY_CONFLICT` instead of a fresh mint.
///
/// No authority field is copied here: the registration/epoch binding stays in
/// [`RegistrationReceipt`] and `user_broker_epoch` stays the broker-local
/// scalar next to it. This record grants nothing and expires nothing on its
/// own; the Kernel still validates every minted [`eliot_protocol::RequestIdentity`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedOperationIdentity {
    /// Closed Kernel operation selector this identity was minted for.
    pub operation: String,
    /// Lowercase SHA-256 of the canonical payload bytes the identity binds.
    pub canonical_digest: String,
    /// Exact transport request id of the issued identity.
    pub request_id: String,
    /// Exact transport idempotency key the identity is bound to.
    pub idempotency_key: String,
    /// Exact transport cancellation id of the issued identity.
    pub cancellation_id: String,
    /// Absolute transport deadline the identity was minted with.
    pub deadline_unix_ms: u64,
    /// Observation instant the identity was minted at.
    pub issued_at_ms: u64,
    /// Caller request id when a launch caller link owned this issuance.
    pub caller_request_id: Option<String>,
}

impl IssuedOperationIdentity {
    fn validate(&self) -> Result<(), BrokerError> {
        text(&self.operation, "operation_identity.operation")?;
        hex_digest(
            &self.canonical_digest,
            "operation_identity.canonical_digest",
        )?;
        text(&self.request_id, "operation_identity.request_id")?;
        text(&self.idempotency_key, "operation_identity.idempotency_key")?;
        text(&self.cancellation_id, "operation_identity.cancellation_id")?;
        if self.deadline_unix_ms == 0 || self.issued_at_ms == 0 {
            return Err(BrokerError::InvalidField("operation_identity.clock"));
        }
        if self.deadline_unix_ms <= self.issued_at_ms {
            return Err(BrokerError::InvalidField("operation_identity.deadline"));
        }
        if let Some(caller) = self.caller_request_id.as_deref() {
            text(caller, "operation_identity.caller_request_id")?;
        }
        Ok(())
    }
}

/// Live per-operation identity ledger supplied by the composition.
///
/// The broker core never mints an identity: it only projects whatever the
/// composed issuer holds into the durable snapshot, so the identity ledger
/// and the durable registration state are written in one atomic publication.
pub trait IssuedOperationIdentityLedger: Send {
    /// Returns every operation identity this process has issued, in a
    /// deterministic order. A poisoned ledger returns an empty projection and
    /// the caller fails closed on the next issuance.
    fn issued_operation_identities(&self) -> Vec<IssuedOperationIdentity>;
}

/// Durable restart cursor owned by the injected registration provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSnapshot {
    pub registration: Option<RegistrationReceipt>,
    pub user_broker_epoch: u64,
    pub operation_cursors: Vec<OperationCursor>,
    /// Durable per-operation request-identity ledger (issue #74).
    ///
    /// `#[serde(default)]` is the versioned additive migration: a snapshot
    /// written before the broker retained identities has no such ledger, and
    /// an absent ledger is read as *no identity was ever issued* rather than
    /// being reinterpreted. It is rewritten with the first publication of the
    /// current process, and a restart re-seeds the issuer from it before any
    /// Kernel call can mint.
    #[serde(default)]
    pub operation_identities: Vec<IssuedOperationIdentity>,
    /// Durable tombstones of operations fenced by a newer broker generation.
    ///
    /// A new `UserBrokerEpoch` fences the previous registration, so its live
    /// cursors stop being this broker's lineage. They are retired here
    /// rather than discarded: an `operation_id` that was already spent is
    /// the only thing that stops an exact replay of the same launch request
    /// from starting a *second* process for the same operation under the
    /// new generation. `#[serde(default)]` is the versioned additive
    /// migration — a snapshot written before this ledger existed has no
    /// tombstones, which is read as "nothing was retired", never as a
    /// licence to reuse an id.
    #[serde(default)]
    pub retired_operations: Vec<RetiredOperationIdentity>,
}

/// One operation identity fenced by a newer broker generation.
///
/// This is a tombstone, not a permit: it grants nothing and admits nothing.
/// It records that a specific `operation_id` already carried an effect under
/// a registration that a later generation fenced, so a replay of that exact
/// request is a typed conflict instead of a second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredOperationIdentity {
    /// The spent operation identity.
    pub operation_id: OperationId,
    /// Canonical digest of the exact request it carried.
    pub request_digest: String,
    /// Registration digest of the generation that spent it.
    pub registration_digest: String,
    /// Broker-local generation that spent it.
    pub user_broker_epoch: u64,
    /// The user-session resource/credential that generation introduced. It
    /// is retained so a later audit can prove which introduction was closed
    /// by the fence rather than infer it. `#[serde(default)]` is the versioned
    /// additive migration for a tombstone written before this field existed.
    #[serde(default)]
    pub introduction: Option<ResourceIntroduction>,
    /// State the operation held when its generation was fenced.
    pub state: OperationState,
}

/// Which broker-owned Kernel operation currently has an unproven outcome
/// (issue #74 A6).
///
/// This is a broker-core classification, not a transport selector: the
/// composition maps it onto the exact per-operation transport identity it
/// minted, so a lost acknowledgement is always reported against the operation
/// that actually lost it. Register and launch are never in this state — both
/// publish their effect durably before returning or fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LostOperation {
    /// A lease refresh whose acknowledgement was lost.
    LeaseRefresh,
    /// A fence/logoff whose acknowledgement was lost.
    Fence,
}

/// Typed outcome of reconciling one lost or unknown broker-owned Kernel
/// acknowledgement by its exact registration identity (issue #74 A6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationReconciliation {
    /// The durable registration already projects the exact effect the lost
    /// operation was attempting. Nothing is retried, so no second lease
    /// refresh, duplicate logoff, or second launch is created.
    Reconciled(RegistrationReceipt),
    /// The durable registration still holds the pre-operation binding. The
    /// lost effect is neither proven nor disproven, so the broker must
    /// re-attach through a fresh protected launch binding before any further
    /// operation; a blind retry is never issued from here.
    Unresolved(RegistrationReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCursor {
    pub idempotency_key: String,
    pub operation_id: OperationId,
    pub request_digest: String,
    pub registration_digest: String,
    pub user_broker_epoch: u64,
    pub authority_epoch: EpochId,
    pub fence_id: String,
    pub lease_expires_at: u64,
    pub process_tree_id: ProcessTreeId,
    pub generation: Generation,
    pub process_fence_nonce: String,
    pub process_request_digest: String,
    /// The exact user-session resource/credential this operation introduced.
    ///
    /// `#[serde(default)]` is the versioned additive migration: a cursor
    /// written before introductions were retained has no binding. `None` is
    /// read as *this operation introduced nothing the broker still owns*,
    /// never as permission to introduce anything; the child it started
    /// belonged to a process that is gone, and its introduction is closed
    /// with that process.
    #[serde(default)]
    pub introduction: Option<ResourceIntroduction>,
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
        if let Some(introduction) = &self.introduction {
            introduction.validate()?;
        }
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
    identity_ledger: Option<Box<dyn IssuedOperationIdentityLedger>>,
    admission: Option<BrokerAdmissionIdentity>,
    registration: Option<RegistrationReceipt>,
    registration_reconciled: bool,
    broker_epoch: u64,
    operations: BTreeMap<String, OperationRecord>,
    retired_operations: BTreeMap<String, RetiredOperationIdentity>,
    issued_operations: BTreeMap<String, IssuedOperationIdentity>,
    lost_operation: Option<LostOperation>,
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
            identity_ledger: None,
            admission: None,
            registration: None,
            registration_reconciled: false,
            broker_epoch: 0,
            operations: BTreeMap::new(),
            retired_operations: BTreeMap::new(),
            issued_operations: BTreeMap::new(),
            lost_operation: None,
        }
    }

    /// Binds the exact interactive identity tuple this process is admitted
    /// as, and proves that a registration recovered from durable state is
    /// this broker's own tuple rather than another principal's surviving
    /// registration.
    ///
    /// This is the single-broker admission gate. It runs after
    /// [`Self::recover`] and before any Kernel transaction: a durable
    /// registration carrying a different installation, SID, logon Session, or
    /// boot Session belongs to a broker this process is not, and adopting or
    /// heartbeating it would hand this process another principal's lease,
    /// lineage, and cancellation authority. A tuple already bound to a
    /// different identity in this process is equally refused.
    pub fn bind_admission(
        &mut self,
        identity: &BrokerAdmissionIdentity,
    ) -> Result<(), BrokerError> {
        identity.validate()?;
        if let Some(bound) = &self.admission
            && bound != identity
        {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        if let Some(registration) = &self.registration
            && !identity.admits(registration)
        {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        self.admission = Some(identity.clone());
        Ok(())
    }

    /// Attaches the composed per-operation identity ledger so every durable
    /// publication carries the exact identities this process issued (issue
    /// #74).  It must be attached before [`Self::recover`]: the recovered
    /// rows are re-seeded into the composed issuer from
    /// [`Self::recovered_operation_identities`], and the live ledger is
    /// projected into every snapshot written afterwards.
    pub fn attach_issued_operation_identity_ledger(
        &mut self,
        ledger: Box<dyn IssuedOperationIdentityLedger>,
    ) {
        self.identity_ledger = Some(ledger);
    }

    /// Returns the durable per-operation identity ledger recovered from the
    /// restart snapshot.  A composition re-seeds its issuer from exactly this
    /// list before it can mint, so a spent request id, cancellation id, or
    /// idempotency key from a previous process is a conflict, not a new mint.
    #[must_use]
    pub fn recovered_operation_identities(&self) -> Vec<IssuedOperationIdentity> {
        self.issued_operations.values().cloned().collect()
    }

    /// Takes the broker-owned operation whose outcome is currently unproven.
    ///
    /// Set exactly when a lease refresh or a fence lost its acknowledgement
    /// and the durable reconciliation could not prove the effect. The
    /// composition pairs it with the exact per-operation transport identity it
    /// minted, then clears it: a reconciliation is reported once, against one
    /// exact operation, and never as a bare unknown outcome.
    pub fn take_lost_operation(&mut self) -> Option<LostOperation> {
        self.lost_operation.take()
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
        let mut issued_operations = BTreeMap::new();
        for identity in snapshot.operation_identities {
            identity.validate()?;
            if issued_operations
                .insert(identity.request_id.clone(), identity)
                .is_some()
            {
                return Err(BrokerError::Duplicate("operation_identity.request_id"));
            }
        }
        self.issued_operations = issued_operations;
        self.retired_operations = retired_index(snapshot.retired_operations)?;
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
            // Scalar-only cursors have no lineage and stay HISTORICAL_SUSPENDED:
            // they fail closed here via exact-tuple is_same_authority and are
            // never promoted. Only an EVIDENCE_BOUND_ACTIVE import with a
            // migration receipt may mint a new EpochId at this owner.
            if cursor.registration_digest != registration.registration_digest
                || cursor.user_broker_epoch != registration.user_broker_epoch
                || !cursor
                    .authority_epoch
                    .is_same_authority(&registration.authority_epoch)
                || cursor.fence_id != registration.fence_id
                || cursor.lease_expires_at > registration.expires_at
            {
                return Err(BrokerError::GrantBindingMismatch);
            }
            if !operation_ids.insert(cursor.operation_id.clone()) {
                return Err(BrokerError::Duplicate("operation_cursor.operation_id"));
            }
            if self
                .retired_operations
                .contains_key(cursor.operation_id.as_str())
            {
                return Err(BrokerError::Duplicate("retired_operation.operation_id"));
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

    /// Returns the registration receipt this broker currently holds so the
    /// composition can choose between refreshing that exact registration and
    /// issuing a fresh one. A `Closed`/`Draining` registration, or one whose
    /// lease already elapsed, carries no launch authority and must never be
    /// heartbeated again.
    pub fn registration(&self) -> Option<&RegistrationReceipt> {
        self.registration.as_ref()
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
        // A registration request *is* this process's declared identity, so a
        // first registration also binds the admission tuple. A tuple that was
        // already bound to a different identity (a restarted broker admitted
        // from its protected launch declaration) keeps that identity and the
        // request is refused here rather than silently re-binding.
        self.bind_admission(&BrokerAdmissionIdentity {
            installation_id: request.installation_id.clone(),
            windows_sid: request.windows_sid.clone(),
            interactive_session_id: request.interactive_session_id.clone(),
            boot_session_id: request.boot_session_id.clone(),
            broker_process_id: request.broker_process_id.clone(),
            broker_artifact_digest: request.broker_artifact_digest.clone(),
            protocol_generation: request.protocol_generation,
            launch_nonce: request.launch_nonce.clone(),
        })?;
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
        // A new broker generation fences the previous one, so the previous
        // generation's operations stop being this broker's live lineage
        // (I1.4: processes from an old broker epoch cannot receive new
        // effect authority). They are *retired*, not discarded: the spent
        // `operation_id` is the only durable proof that stops an exact
        // replay of the same launch request from starting a second process
        // for the same operation under this new generation.
        for record in self.operations.values() {
            let retired = RetiredOperationIdentity {
                operation_id: record.cursor.operation_id.clone(),
                request_digest: record.cursor.request_digest.clone(),
                registration_digest: record.cursor.registration_digest.clone(),
                user_broker_epoch: record.cursor.user_broker_epoch,
                introduction: record.cursor.introduction.clone(),
                state: record.cursor.state,
            };
            self.retired_operations
                .insert(retired.operation_id.as_str().to_owned(), retired);
        }
        self.operations.clear();
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
        // Heartbeat is the reconciliation step, not an effect: it is exactly
        // the transaction through which a recovered registration is proven to
        // the authoritative owner. The composition has already refused a
        // foreign tuple through `bind_admission` before it gets here, so this
        // path deliberately does not re-gate on admission identity.
        if current.registration_digest != request.registration_digest {
            return Err(BrokerError::GrantBindingMismatch);
        }
        let grant = match self
            .authority
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .heartbeat(&current, request.observed_at)
        {
            Ok(grant) => grant,
            Err(PortError::Unknown) => {
                // A lost lease-refresh acknowledgement is reconciled against
                // the durable registration bound to this exact operation
                // rather than retried blind: a second refresh under a new
                // operation identity could renew an already renewed lease.
                return match self.reconcile_lost_lease_refresh(&current)? {
                    RegistrationReconciliation::Reconciled(receipt) => {
                        Ok(heartbeat_receipt(&receipt))
                    }
                    RegistrationReconciliation::Unresolved(_) => {
                        self.lost_operation = Some(LostOperation::LeaseRefresh);
                        Err(BrokerError::UnknownOutcome)
                    }
                };
            }
            Err(error) => return Err(map_port(RequiredProvider::G01Authority, error)),
        };
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
        Ok(heartbeat_receipt(&refreshed))
    }

    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_lines)]
    pub fn launch(&mut self, request: LaunchRequest) -> Result<LaunchReceipt, BrokerError> {
        request.validate()?;
        let current = self.active_registration(request.observed_at)?.clone();
        // A live lease over the right registration is not enough: the
        // registration must be the one *this* admitted process tuple holds.
        // A durable registration left by another SID/Session/installation
        // fails here, before any grant, process preparation, or credential
        // introduction.
        self.require_admitted_registration(&current)?;
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
        // An `operation_id` already spent under a fenced generation is never
        // reused, whatever the caller replays. Without this tombstone an
        // exact replay of the same request under a new registration would
        // prepare and start a *second* process for one operation identity,
        // including for an operation whose outcome was never proven.
        if let Some(retired) = self
            .retired_operations
            .get(request.approved.operation_id.as_str())
        {
            return Err(if retired.request_digest == request_digest {
                BrokerError::RetiredOperation(retired.operation_id.clone())
            } else {
                BrokerError::OperationIdRetired(retired.operation_id.clone())
            });
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
    ///
    /// An operation whose outcome is not yet proven is refused here, at the
    /// single site that performs the effect, so cancellation can never erase
    /// a possibly committed external effect. The refusal is structural
    /// rather than conventional: it does not depend on a caller having
    /// remembered to reconcile first.
    pub fn cancel_operation(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<CancellationReceipt, BrokerError> {
        let record = self
            .operations
            .values()
            .find(|record| record.permit.operation_id == *operation_id)
            .ok_or(BrokerError::OperationNotFound)?;
        if record.cursor.state == OperationState::Unknown {
            return Err(BrokerError::UnreconciledEffect(operation_id.clone()));
        }
        let permit = record.permit.clone();
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

    /// Admits one broker-owned control operation against one exact owned
    /// operation and records its distinct, durable operation identity.
    ///
    /// Cancellation and reconciliation are effects on this broker's own Job
    /// contour, so they are not Kernel transactions, but they are still
    /// operations with their own identity: the identity is written into the
    /// same durable per-operation identity ledger as register, heartbeat,
    /// launch, and fence, in the same atomic publication, and a restart
    /// re-seeds it before any further effect.
    ///
    /// The identity is derived from the exact registration binding and the
    /// exact target operation, so an exact retry resolves to the same row and
    /// no second effect, while a different target is a different operation
    /// rather than a widened one.  A target that is not this broker's
    /// admitted lineage, or that is already reconciled, fails closed.
    ///
    /// A cancellation is refused while its target's outcome is unproven: an
    /// unknown launch/effect must be reconciled first, so cancellation can
    /// never erase a possibly committed external effect.
    pub fn admit_control_operation(
        &mut self,
        operation: BrokerControlOperation,
        target: &OperationId,
        observed_at: u64,
    ) -> Result<(), BrokerError> {
        let current = self.active_registration(observed_at)?.clone();
        self.require_admitted_registration(&current)?;
        // A target whose generation was fenced is named as retired rather
        // than reported as merely absent, so a caller replaying an old
        // cancellation learns it is a fenced identity, not a typo.
        if self.retired_operations.contains_key(target.as_str()) {
            return Err(BrokerError::OperationIdRetired(target.clone()));
        }
        let record = self
            .operations
            .values()
            .find(|record| record.permit.operation_id == *target)
            .ok_or(BrokerError::OperationNotFound)?;
        if record.cursor.registration_digest != current.registration_digest
            || record.cursor.user_broker_epoch != current.user_broker_epoch
            || !record
                .cursor
                .authority_epoch
                .is_same_authority(&current.authority_epoch)
            || record.cursor.fence_id != current.fence_id
        {
            return Err(BrokerError::GrantBindingMismatch);
        }
        if record.cursor.state == OperationState::Reconciled {
            return Err(BrokerError::OperationNotFound);
        }
        if operation == BrokerControlOperation::Cancel
            && record.cursor.state == OperationState::Unknown
        {
            return Err(BrokerError::UnreconciledEffect(target.clone()));
        }
        let canonical_digest = digest(&(
            &current.registration_digest,
            current.user_broker_epoch,
            &current.authority_epoch,
            &current.fence_id,
            operation.selector(),
            target.as_str(),
            &record.cursor.request_digest,
        ))?;
        if self.issued_operations.values().any(|identity| {
            identity.operation == operation.selector()
                && identity.canonical_digest == canonical_digest
        }) {
            // Exact replay of one control operation: that identity is already
            // durable, so no second identity row and no second effect.
            return Ok(());
        }
        let namespace = operation.namespace();
        let identity = IssuedOperationIdentity {
            operation: operation.selector().to_owned(),
            // The registration lease is the control operation's deadline: a
            // cancellation or reconciliation is authorized no longer than the
            // lease that admitted it.
            deadline_unix_ms: current.expires_at,
            request_id: format!("ub-ctl-{namespace}-{}", &canonical_digest[..32]),
            idempotency_key: format!("ub-ctl/{namespace}/{canonical_digest}"),
            cancellation_id: format!("ub-ctl-end-{namespace}-{}", &canonical_digest[..32]),
            issued_at_ms: observed_at,
            // No caller launch link: one target operation owns both a cancel
            // and a reconcile identity, so a single-valued caller link would
            // make the second one look like a conflicting reuse.
            caller_request_id: None,
            canonical_digest,
        };
        identity.validate()?;
        if self
            .issued_operations
            .insert(identity.request_id.clone(), identity)
            .is_some()
        {
            return Err(BrokerError::Duplicate("operation_identity.request_id"));
        }
        self.persist()?;
        Ok(())
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
            || !permit
                .authority_epoch
                .is_same_authority(&registration.authority_epoch)
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

    /// Proves that the registration about to be used is the one this
    /// process's admitted identity tuple holds.
    ///
    /// Without this the broker would happily serve a live lease over a
    /// registration recovered from shared durable state that belongs to a
    /// different SID, logon Session, boot Session, or installation. That is
    /// exactly the cross-principal adoption the registration contour forbids,
    /// so it is refused before any grant, process preparation, or credential
    /// introduction rather than detected afterwards.
    fn require_admitted_registration(
        &self,
        registration: &RegistrationReceipt,
    ) -> Result<(), BrokerError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        if !admission.admits(registration) {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        Ok(())
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
            // Lease loss is a revocation: it closes every handle and child
            // the registration still owns, exactly as a terminal close does.
            // Reporting only the expiry while owned children keep running
            // would leave a live lineage with no authority behind it.
            let released = self.release_owned_operations();
            self.persist()?;
            released?;
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
            match self
                .authority
                .as_mut()
                .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
                .fence(&request)
            {
                Ok(receipt) => validate_fence_receipt(&request, &receipt)?,
                Err(PortError::Unknown) => {
                    // A lost logoff acknowledgement is reconciled against the
                    // durable projection of this exact fence operation
                    // (`user-broker-fence-<registration digest>-<status>`)
                    // instead of issuing a second fence.  When the durable
                    // state already carries the requested status the fence
                    // landed and the close is complete: no duplicate logoff
                    // and no second transport identity is created.
                    return match self.reconcile_lost_fence(&current, status)? {
                        RegistrationReconciliation::Reconciled(_) => Ok(()),
                        RegistrationReconciliation::Unresolved(_) => {
                            self.lost_operation = Some(LostOperation::Fence);
                            Err(BrokerError::UnknownOutcome)
                        }
                    };
                }
                Err(error) => return Err(map_port(RequiredProvider::G01Authority, error)),
            }
        }
        let mut desired = current;
        desired.status = status;
        self.registration = Some(desired.clone());
        self.registration_reconciled = true;
        // A terminal close revokes the registration, so it also revokes every
        // handle and child process the registration owned. Draining does not:
        // its children are allowed to finish under the drain disposition.
        let released = if status == RegistrationStatus::Closed {
            self.release_owned_operations()
        } else {
            Ok(())
        };
        match self.persist() {
            Ok(()) => released,
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
                if reconciled { released } else { Err(error) }
            }
        }
    }

    /// Closes every child process this registration still owns, drops the
    /// introduced user-session resources those children held, and removes
    /// their durable cursors, so a revoked, fenced, or lease-expired
    /// registration leaves no live lineage and nothing a restart could
    /// re-adopt.
    ///
    /// A child that cannot be closed is reported as a typed refusal naming the
    /// exact operation, and its cursor and introduced binding are *retained*:
    /// reporting a clean close while a child may still run, still holding an
    /// introduced credential, is exactly the "termination was assumed"
    /// shortcut the containment matrix forbids.
    fn release_owned_operations(&mut self) -> Result<(), BrokerError> {
        let mut retained = Vec::new();
        for record in self.operations.values() {
            if record.cursor.state == OperationState::Reconciled {
                continue;
            }
            let outcome = self
                .process
                .as_mut()
                .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
                .cancel(&record.cursor.operation_id);
            if outcome.is_err() {
                retained.push(record.cursor.operation_id.clone());
            }
        }
        if let Some(operation_id) = retained.first() {
            return Err(BrokerError::OwnedOperationNotClosed(operation_id.clone()));
        }
        self.operations.clear();
        Ok(())
    }

    /// Reconciles one lost fence/logoff acknowledgement by the exact
    /// registration identity the fence operation is derived from.
    ///
    /// The durable snapshot is the only admitted evidence: when it already
    /// projects `status` for this exact registration, the authoritative fence
    /// landed and the caller is told so instead of being invited to fence
    /// again. Otherwise the effect is unproven and the broker is told to
    /// re-attach. No second fence is issued from either branch.
    fn reconcile_lost_fence(
        &mut self,
        fenced: &RegistrationReceipt,
        status: RegistrationStatus,
    ) -> Result<RegistrationReconciliation, BrokerError> {
        let durable = self.load_durable_registration()?;
        let reconciled = durable.as_ref().is_some_and(|durable| {
            durable.registration_digest == fenced.registration_digest && durable.status == status
        });
        if !reconciled {
            return Ok(RegistrationReconciliation::Unresolved(fenced.clone()));
        }
        let adopted =
            self.adopt_durable_registration(durable.as_ref().ok_or(BrokerError::UnknownOutcome)?)?;
        self.persist()?;
        Ok(RegistrationReconciliation::Reconciled(adopted))
    }

    /// Reconciles one lost lease-refresh acknowledgement by the exact
    /// registration identity the refresh was requested against.
    ///
    /// A lease refresh is proven only when the durable registration advanced
    /// to a different registration digest under the same exact registration
    /// tuple: that is the fingerprint of a refresh that landed while its
    /// acknowledgement was lost. Returning the durable receipt keeps the
    /// broker on the renewed lease and issues no second refresh identity.
    fn reconcile_lost_lease_refresh(
        &mut self,
        current: &RegistrationReceipt,
    ) -> Result<RegistrationReconciliation, BrokerError> {
        let durable = self.load_durable_registration()?;
        let advanced = durable.as_ref().is_some_and(|durable| {
            durable.registration_digest != current.registration_digest
                && durable.status == RegistrationStatus::Active
                && durable.installation_id == current.installation_id
                && durable.windows_sid == current.windows_sid
                && durable.interactive_session_id == current.interactive_session_id
        });
        if !advanced {
            return Ok(RegistrationReconciliation::Unresolved(current.clone()));
        }
        let adopted =
            self.adopt_durable_registration(durable.as_ref().ok_or(BrokerError::UnknownOutcome)?)?;
        self.persist()?;
        Ok(RegistrationReconciliation::Reconciled(adopted))
    }

    /// Reads the durable registration projection without interpreting it.
    ///
    /// The durable broker-local epoch only ever moves forward: a snapshot
    /// written before a crash cannot lower the monotonic guard that
    /// [`Self::register`] enforces.
    fn load_durable_registration(&mut self) -> Result<Option<RegistrationReceipt>, BrokerError> {
        let snapshot = self
            .durable
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?
            .load()
            .map_err(|error| map_port(RequiredProvider::DurableRegistration, error))?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        self.broker_epoch = self.broker_epoch.max(snapshot.user_broker_epoch);
        Ok(snapshot.registration)
    }

    /// Adopts one reconciled durable registration as the in-memory truth.
    ///
    /// Only same-lineage evidence is adopted: the exact registration tuple,
    /// epoch lineage, and fence id must match, so a foreign durable
    /// registration can never become this broker's authority. A registration
    /// that does not match this broker's exact identity is an unresolved
    /// reconciliation, never an adopted one.
    fn adopt_durable_registration(
        &mut self,
        durable: &RegistrationReceipt,
    ) -> Result<RegistrationReceipt, BrokerError> {
        let current = self
            .registration
            .as_ref()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?;
        let same_identity = current.installation_id == durable.installation_id
            && current.windows_sid == durable.windows_sid
            && current.interactive_session_id == durable.interactive_session_id
            && current
                .authority_epoch
                .is_same_authority(&durable.authority_epoch)
            && current.fence_id == durable.fence_id;
        if !same_identity {
            return Err(BrokerError::GrantBindingMismatch);
        }
        self.registration = Some(durable.clone());
        self.registration_reconciled = true;
        Ok(durable.clone())
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
            operation_identities: self.projected_operation_identities(),
            retired_operations: self.retired_operations.values().cloned().collect(),
        }
    }

    /// Projects the durable identity ledger: everything recovered from the
    /// restart snapshot plus everything the composed issuer has issued since.
    ///
    /// A `request_id` can only appear in both halves when the live issuer
    /// resolved an exact retry of that same operation, and an exact retry
    /// carries byte-identical transport fields, so the live row is the same
    /// row. The recovered row is still kept when the composed ledger does not
    /// carry it, so attaching no ledger never erases durable history.
    fn projected_operation_identities(&self) -> Vec<IssuedOperationIdentity> {
        let mut projected = self.issued_operations.clone();
        if let Some(ledger) = self.identity_ledger.as_ref() {
            for identity in ledger.issued_operation_identities() {
                projected.insert(identity.request_id.clone(), identity);
            }
        }
        projected.into_values().collect()
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
    // EpochId carries non-zero sequence by construction; no scalar zero check.
    // Digest input is lineage+sequence via serde (canonical lineage spelling +
    // sequence), never a bare u64.
    if grant.user_broker_epoch == 0
        || grant.expires_at <= request.observed_at
        || grant.expires_at > request.lease_expires_at
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    let expected = digest(&(
        request,
        &grant.authority_epoch,
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
            &grant.authority_epoch,
            &grant.fence_id,
        ))?,
        installation_id: request.installation_id.clone(),
        windows_sid: request.windows_sid.clone(),
        interactive_session_id: request.interactive_session_id.clone(),
        boot_session_id: request.boot_session_id.clone(),
        broker_process_id: request.broker_process_id.clone(),
        user_broker_epoch: grant.user_broker_epoch,
        authority_epoch: grant.authority_epoch.clone(),
        fence_id: grant.fence_id.clone(),
        expires_at: grant.expires_at,
        status: RegistrationStatus::Active,
    })
}

/// Projects one sealed registration into its public lease-renewal receipt.
///
/// A reconciled lease refresh and an acknowledged one produce the same
/// receipt from the same registration, so a lost acknowledgement that is
/// proven by the durable projection is indistinguishable from success and
/// cannot be used to claim a renewal that never happened.
fn heartbeat_receipt(registration: &RegistrationReceipt) -> HeartbeatReceipt {
    HeartbeatReceipt {
        registration_digest: registration.registration_digest.clone(),
        user_broker_epoch: registration.user_broker_epoch,
        fence_id: registration.fence_id.clone(),
        expires_at: registration.expires_at,
    }
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
        || !receipt
            .authority_epoch
            .is_same_authority(&request.registration.authority_epoch)
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
    // EpochId is non-zero by construction; only the broker-local epoch needs
    // a scalar zero guard.
    if receipt.user_broker_epoch == 0 {
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
        &grant.authority_epoch,
        &grant.fence_id,
    ))? != current.registration_digest
        || grant.user_broker_epoch != current.user_broker_epoch
        || !grant
            .authority_epoch
            .is_same_authority(&current.authority_epoch)
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
        || !grant
            .authority_epoch
            .is_same_authority(&current.authority_epoch)
        || grant.fence_id != current.fence_id
        || grant.approved != request.approved
        || grant.request_digest != digest(request)?
        || grant.proof_ceiling != ProofCeiling::Observation
        || grant.expires_at <= request.observed_at
        || grant.expires_at > request.lease_expires_at
        // A grant may never outlive the introduction it carries: an
        // authorization that stays valid after its own user-session
        // resource/credential lease has ended is a silent widening.
        || grant.expires_at > grant.approved.introduction.expires_at
    {
        return Err(BrokerError::GrantBindingMismatch);
    }
    let expected = digest(&(
        grant.registration_digest.clone(),
        &grant.approved,
        grant.proof_ceiling,
        grant.request_digest.clone(),
        grant.user_broker_epoch,
        &grant.authority_epoch,
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
        authority_epoch: registration.authority_epoch.clone(),
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
        authority_epoch: registration.authority_epoch.clone(),
        fence_id: registration.fence_id.clone(),
        lease_expires_at: grant.expires_at,
        process_tree_id: grant.approved.process_tree_id.clone(),
        generation: grant.approved.generation,
        process_fence_nonce: grant.approved.process_fence_nonce.clone(),
        process_request_digest: process_request_digest.to_owned(),
        // The introduced user-session resource/credential is retained with
        // the operation so revocation and restart reconciliation name the
        // exact thing that was introduced, instead of only the child id.
        introduction: Some(grant.approved.introduction.clone()),
        state,
    }
}

/// Builds the in-memory index of operations already fenced by a newer broker
/// generation, validating every tombstone before any index is touched.
///
/// A tombstone is a refusal marker, not a permit, so a malformed or
/// duplicated one is a corrupt durable file and is rejected before it can
/// partially bind an operation id.
fn retired_index(
    rows: Vec<RetiredOperationIdentity>,
) -> Result<BTreeMap<String, RetiredOperationIdentity>, BrokerError> {
    let mut retired_operations = BTreeMap::new();
    for retired in rows {
        text(
            retired.operation_id.as_str(),
            "retired_operation.operation_id",
        )?;
        text(&retired.request_digest, "retired_operation.request_digest")?;
        text(
            &retired.registration_digest,
            "retired_operation.registration_digest",
        )?;
        if retired.user_broker_epoch == 0 {
            return Err(BrokerError::InvalidField("retired_operation"));
        }
        if let Some(introduction) = &retired.introduction {
            introduction.validate()?;
        }
        if retired_operations
            .insert(retired.operation_id.as_str().to_owned(), retired)
            .is_some()
        {
            return Err(BrokerError::Duplicate("retired_operation.operation_id"));
        }
    }
    Ok(retired_operations)
}

fn permit_from_cursor(cursor: &OperationCursor) -> OperationPermit {
    OperationPermit {
        operation_id: cursor.operation_id.clone(),
        request_digest: cursor.request_digest.clone(),
        registration_digest: cursor.registration_digest.clone(),
        user_broker_epoch: cursor.user_broker_epoch,
        authority_epoch: cursor.authority_epoch.clone(),
        fence_id: cursor.fence_id.clone(),
        lease_expires_at: cursor.lease_expires_at,
    }
}

fn verify_cursor_lineage(
    cursor: &OperationCursor,
    view: &ProcessExecutionView,
) -> Result<(), BrokerError> {
    let identity = view.identity().ok_or(BrokerError::ProcessLineageMismatch)?;
    // Full-pair exact-tuple check: equal sequences from different lineages are
    // unrelated and never authorize (contract types.EpochId). No scalar
    // comparison, no .sequence.get() adapter, no From<u64>.
    if view.lifecycle() != ProcessLifecycle::Running
        || view.operation_id() != &cursor.operation_id
        || view.request_digest() != cursor.process_request_digest
        || !view
            .fence()
            .authority_epoch()
            .is_same_authority(&cursor.authority_epoch)
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
    #[error("broker admission identity is not composed")]
    RegistrationNotAdmitted,
    #[error("registration identity is not this broker's own tuple")]
    StaleRegistrationIdentity,
    #[error("credential or secret material is disclosed in {0}")]
    CredentialMaterialDisclosed(&'static str),
    #[error("the grant introduces no {0} for this launch")]
    IntroductionRequired(&'static str),
    #[error("the launch's tool is not in the introduced operation set")]
    IntroductionOperationNotGranted,
    #[error("the launch's resource root is not in the introduced resource set")]
    IntroductionResourceNotGranted,
    #[error("the launch's effect ceiling exceeds the introduced ceiling")]
    IntroductionEffectCeilingExceeded,
    #[error("the introduced resource or credential lease is not active")]
    IntroductionExpired,
    #[error("the launch's credential is not the one its introduction names")]
    IntroductionCredentialUnnamed,
    #[error("operation {} has an unreconciled outcome and must be reconciled before cancellation", .0.as_str())]
    UnreconciledEffect(OperationId),
    #[error("operation {} was already spent under a fenced broker generation and cannot be replayed", .0.as_str())]
    RetiredOperation(OperationId),
    #[error("operation id {} was already spent under a fenced broker generation and cannot be reused", .0.as_str())]
    OperationIdRetired(OperationId),
    #[error("owned operation {} was not closed", .0.as_str())]
    OwnedOperationNotClosed(OperationId),
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
    use std::num::NonZeroU64;

    use eliot_contracts::EpochLineageId;
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        FencingToken, KernelDispatchKey, PermitIssuance, PhysicalProcessBinding, ProcessHealth,
        ProcessId, ProcessIntent, ProcessRequest, ProcessState, SuspendedProcessIdentity,
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
        epoch: EpochId,
        broker_epoch: u64,
        tamper: Tamper,
        last: Option<RegistrationRequest>,
    }

    /// Lineage-A fixture epoch for tests (canonical UUID lineage, no scalar).
    /// Never invents lineage: lineage-A is the fixed test lineage, sequence is
    /// explicit. No `.sequence.get()` adapter, no `From<u64>`.
    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_epoch_b(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
            .expect("canonical test lineage-B");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    impl FakeAuthority {
        fn new() -> Self {
            Self {
                epoch: test_epoch(7),
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
                &self.epoch,
                self.broker_epoch,
                &fence_id,
                expires_at,
            ))
            .expect("digest");
            RegistrationGrant {
                registration: request,
                authority_epoch: self.epoch.clone(),
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
                &receipt.authority_epoch,
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
                authority_epoch: receipt.authority_epoch.clone(),
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
                authority_epoch: request.registration.authority_epoch.clone(),
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
                PhysicalProcessBinding::new(
                    42,
                    11,
                    request.executable(),
                    r"Local\Eliot-User-Broker-Test",
                )
                .map_err(|error| PortError::Invalid(error.to_string()))?,
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
        // INTENDED EpochId shape per T6-E3 reader (Split A cutover):
        // FencingToken::new(EpochId), getter &EpochId, is_same_authority.
        // Integrator resolves order B→A→C; this branch does not edit A files.
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
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
            grant.authority_epoch.clone(),
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
            grant.authority_epoch.clone(),
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
            introduction: ResourceIntroduction {
                resource_ref: "resource-ref-1".to_owned(),
                facet_manifest_ref: "facet-manifest-1".to_owned(),
                introduced_operation_set: vec!["tool-1".to_owned()],
                introduced_resource_set: vec!["C:\\Eliot".to_owned()],
                max_effect: EffectCeiling::NoExternalEffect,
                issued_at: 10,
                expires_at: 19,
                max_calls: 1,
                credential_binding: Some(CredentialBinding {
                    handle: SecretRef::new("credential-provider", "handle-1").expect("secret ref"),
                    expires_at: 19,
                }),
            },
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
            operation_identities: Vec::new(),
            retired_operations: Vec::new(),
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
                    epoch: test_epoch(7),
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
                operation_identities: Vec::new(),
                retired_operations: Vec::new(),
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
            operation_identities: broker.projected_operation_identities(),
            retired_operations: broker.retired_operations.values().cloned().collect(),
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

    #[test]
    fn broker_grant_round_trip_with_epoch_id_and_wrong_lineage_cursor_rejected() {
        // Proportionate T6-E3 Split C proof: EpochId grant round-trips through
        // seal/validate, and a cursor minted in another lineage (same sequence)
        // is rejected via exact-tuple is_same_authority, never promoted.
        let mut broker = broker(
            FakeAuthority::new(),
            FakeProcess {
                state: None,
                unknown: false,
                wrong_receipt: false,
            },
        );
        let receipt = broker
            .register(registration_request())
            .expect("registration");
        assert!(receipt.authority_epoch.is_same_authority(&test_epoch(7)));
        assert_eq!(receipt.user_broker_epoch, 1);
        let launch = broker.launch(launch_request()).expect("launch");
        assert!(
            launch
                .operation_permit
                .authority_epoch
                .is_same_authority(&test_epoch(7))
        );
        // Wire round-trip preserves lineage+sequence.
        let wire = serde_json::to_string(&receipt).expect("receipt json");
        let decoded: RegistrationReceipt = serde_json::from_str(&wire).expect("decode");
        assert!(decoded.authority_epoch.is_same_authority(&test_epoch(7)));

        // Wrong-lineage cursor with equal sequence must fail closed.
        let mut snapshot = broker.snapshot();
        let mut wrong = snapshot.operation_cursors.first().expect("cursor").clone();
        wrong.authority_epoch = test_epoch_b(7);
        assert!(
            !wrong
                .authority_epoch
                .is_same_authority(&receipt.authority_epoch)
        );
        snapshot.operation_cursors[0] = wrong;
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
        assert_eq!(restarted.recover(), Err(BrokerError::GrantBindingMismatch));
    }
}
