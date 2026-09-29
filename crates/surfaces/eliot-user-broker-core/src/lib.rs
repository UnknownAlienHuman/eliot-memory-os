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
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_process::{
    CancellationReceipt, EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId,
    OperationId, ProcessExecutionView, ProcessLifecycle, ProcessStartReceipt, ProcessTreeId,
    ResourceLimits, SecretRef, SessionId,
};
use eliot_protocol::{ProtocolVersion, RequestIdentity};
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::{
    EffectCeiling, NativeResourceDevicePolicy, NativeResourceKind,
    NativeResourceLease, NativeResourceLeaseBinding, NativeResourceLeaseConsumptionReceipt,
    NativeResourceLeaseError, NativeResourceMeasurement, NativeResourceNetworkPolicy,
    NativeResourceReparsePolicy, NativeResourceSelection, NativeResourceSelectionCandidate,
    NativeResourceSelectionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const CONTRACT_NAME: &str = "eliot.surfaces.user-broker-core/v1";
pub const OPERATOR_ROLE: &str = "human_operator";
pub const OPERATOR_CAPABILITIES: [&str; 2] = ["controlboard.read", "operator.command"];
pub const OPERATOR_HANDOFF_TTL_MS: u64 = 5_000;
pub const OPERATOR_PIPE_NAME: &str = r"\\.\pipe\eliot\operator\one-shot";
/// Current durable identity-row shape. Version 1 rows remain spent-ID
/// tombstones because they did not retain the original `RequestIdentity`.
pub const ISSUED_OPERATION_IDENTITY_VERSION: u16 = 2;
const LEGACY_ISSUED_OPERATION_IDENTITY_VERSION: u16 = 1;
/// Spent operation identities are retained until the snapshot is fenced; new
/// issuances fail closed at this bound rather than evicting reuse evidence.
pub const MAX_ISSUED_OPERATION_IDENTITIES: usize = 4_096;
/// Serialized spent-identity evidence budget (the file store permits 16 MiB).
pub const MAX_ISSUED_OPERATION_IDENTITY_BYTES: usize = 4 * 1024 * 1024;
/// Capacity retained for fence/logoff and other control operation identities.
pub const ISSUED_OPERATION_CONTROL_ENTRY_RESERVE: usize = 2;
/// Byte budget retained for fence/logoff and other control operations.
pub const ISSUED_OPERATION_CONTROL_BYTE_RESERVE: usize = 16 * 1024;
/// Process lineage is observational, but its durable ledger is bounded too.
pub const MAX_PROCESS_EFFECT_LINEAGE_ENTRIES: usize = 4_096;
/// Serialized process-lineage budget, leaving room for cursors and receipts.
pub const MAX_PROCESS_EFFECT_LINEAGE_BYTES: usize = 2 * 1024 * 1024;
/// Native resource lease is deliberately short-lived and is measured against
/// the Broker-owned clock, never the caller's request timestamp.
pub const NATIVE_RESOURCE_LEASE_TTL_MS: u64 = 5_000;

fn legacy_issued_operation_identity_version() -> u16 {
    LEGACY_ISSUED_OPERATION_IDENTITY_VERSION
}

/// Upper bound for the one-shot standard-input bytes one admitted launch may
/// carry.
///
/// This is the same value the Windows suspended-launch primitive enforces
/// (`eliot_platform_windows::SUSPENDED_LAUNCH_STDIN_LIMIT`). It is duplicated
/// rather than imported because this crate is provider-neutral and owns no
/// Windows dependency; the platform primitive is still the enforcing gate, and
/// a request that exceeded it would be refused there after the child exists.
/// Validating it here refuses it before a grant is even asked for.
pub const MAX_LAUNCH_STDIN_PAYLOAD_BYTES: usize = 8 * 1024;

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

/// One issued handoff: the exact endpoint bytes it authenticates, its absolute
/// expiry, and whether it has already been redeemed.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HandoffState {
    endpoint: OperatorEndpoint,
    expires_at: u64,
    consumed: bool,
}

/// Owner binding an [`OperatorHandoffAuthority`] to the exact registration
/// revision and installation-approved artifact it was built for.
///
/// The binding is compared on every admission. When the broker's registration
/// epoch or interactive Session moves, or the protected installation
/// declaration names a different Operator image, the authority is rebuilt
/// rather than reused: the previous nonces are then not in the live ledger, so
/// an endpoint minted for the old revision cannot be redeemed at all.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OperatorHandoffBinding {
    broker_epoch: u64,
    interactive_session_id: String,
    artifact: OperatorArtifact,
}

/// One-shot broker handoff authority.  The nonce is an authenticator for one
/// inherited endpoint parse, not a reconnect token or durable credential.
#[derive(Clone, Debug)]
pub struct OperatorHandoffAuthority {
    artifact: OperatorArtifact,
    pipe_name: String,
    broker_epoch: u64,
    interactive_session_id: String,
    handoffs: BTreeMap<String, HandoffState>,
}

impl OperatorHandoffAuthority {
    pub fn new(
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

    /// Mints one owner-issued, generation-bound, expiring, single-use
    /// [`OperatorEndpoint`].
    ///
    /// The nonce is minted here, never taken from `request`: the request shape
    /// carries no nonce, pipe name, expiry or timestamp field, so a caller
    /// cannot choose the authenticator or pre-claim an expiry. Role and
    /// capability widening fails closed through [`BrokerError::Denied`].
    pub fn issue(
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

    /// Redeems one handoff exactly once and returns the installation-approved
    /// artifact it was issued for.
    ///
    /// A second presentation of a consumed nonce, an endpoint whose bound
    /// session/epoch/nonce does not match the issued row, and an endpoint past
    /// its expiry are three distinct refusals — [`BrokerError::ReplayConflict`]
    /// and [`BrokerError::StaleLease`] — so a reconnect can never be inferred
    /// from replaying the previous endpoint.
    pub fn consume(
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

fn lowercase_hex_digest(value: &str, field: &'static str) -> Result<(), BrokerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
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
    NativeResourceResolver,
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

impl RegistrationReceipt {
    /// Validates the shape of a sealed registration receipt on its own terms.
    ///
    /// This is a *shape* check, not an authority check: it proves the receipt
    /// names a real identity tuple, a real broker-local epoch, a real lineage
    /// authority and a non-empty fence.  It deliberately grants nothing and
    /// proves no grant signature — that remains the `seal_registration` job.
    /// It exists so a cutover candidate can be refused for being malformed
    /// before any comparison against the recorded registration is attempted.
    fn validate_shape(&self) -> Result<(), BrokerError> {
        text(&self.registration_digest, "registration_digest")?;
        hex_digest(&self.registration_digest, "registration_digest")?;
        text(&self.installation_id, "installation_id")?;
        text(&self.windows_sid, "windows_sid")?;
        text(&self.interactive_session_id, "interactive_session_id")?;
        text(&self.boot_session_id, "boot_session_id")?;
        text(&self.broker_process_id, "broker_process_id")?;
        text(&self.fence_id, "fence_id")?;
        if self.user_broker_epoch == 0 || self.expires_at == 0 {
            return Err(BrokerError::InvalidField("registration_receipt"));
        }
        Ok(())
    }
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
    /// Optional authenticated Operator-selected object candidate.
    ///
    /// This is input content only: it grants no resource authority and is
    /// never copied to `ApprovedLaunch` or projected into the child process.
    /// A boundary-crossing resource is usable only when the Kernel grant
    /// carries a matching [`NativeResourceSelection`] owner record.
    #[serde(default)]
    pub resource_selection_candidate: Option<NativeResourceSelectionCandidate>,
    /// Exact one-shot standard-input bytes this admitted launch hands the
    /// child, if any.
    ///
    /// This is the launch's only input channel and it is what a per-user
    /// one-shot adapter reads (I11.6:3, "Normal delivery is launched through
    /// the authorized User Broker"). It is `None` for every launch that needs
    /// no input, which is the previous behaviour exactly, and the field is
    /// `#[serde(default)]` so an older wire shape still decodes without
    /// inventing a second vocabulary.
    ///
    /// The bytes are NOT part of [`ApprovedLaunch`]: the approved launch is the
    /// Kernel grant and stays Kernel-minted. They are part of THIS request
    /// whole, so `digest(&request)` binds them into the permit, the durable
    /// operation cursor, and the replay check - a replayed request with
    /// different bytes is a `ReplayConflict`, not a second effect.
    ///
    /// What an admitted launch may put on its own standard input is decided by
    /// that launch's owner, not here: the broker composes the
    /// `eliot-notify.exe` acknowledgement line from typed fields and refuses
    /// every other request shape that carries a payload.
    #[serde(default)]
    pub stdin_payload: Option<String>,
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
        if let Some(candidate) = &self.resource_selection_candidate {
            candidate
                .validate()
                .map_err(BrokerError::NativeResourceSelection)?;
        }
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
        self.validate_stdin_payload()?;
        Ok(())
    }

    /// Fail-closed validation of the one-shot standard-input bytes.
    ///
    /// The payload is written to a suspended child before that child is
    /// resumed, so an empty or oversized payload would either be refused by the
    /// platform primitive after the process exists or block the spawning
    /// thread with no reader. It is refused here, before any grant is asked
    /// for. The bound is the same constant the platform primitive enforces, so
    /// an admitted payload is always writable whole.
    fn validate_stdin_payload(&self) -> Result<(), BrokerError> {
        let Some(payload) = self.stdin_payload.as_deref() else {
            return Ok(());
        };
        if payload.is_empty() || payload.len() > MAX_LAUNCH_STDIN_PAYLOAD_BYTES {
            return Err(BrokerError::InvalidField("stdin_payload"));
        }
        // A line protocol is what the child reads; embedded NUL would truncate
        // it at the child's end and an embedded control byte would let one
        // payload smuggle a second record past the child's own reader.
        if payload.contains('\0')
            || payload
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return Err(BrokerError::InvalidField("stdin_payload"));
        }
        if !payload.ends_with('\n') {
            return Err(BrokerError::InvalidField("stdin_payload"));
        }
        Ok(())
    }
}

/// Explicit Operator-selected root and object paths, accepted only at the
/// authenticated generic launch boundary.
///
/// This input is never added to [`LaunchRequest`] or sent to the Kernel. The
/// Broker passes it to its owner resolver, which retains private handle-backed
/// selection state and returns only path-free measurement evidence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorNativeResourceSelectionInput {
    /// Explicitly selected boundary root.
    pub selected_root_path: String,
    /// Explicitly selected file or directory object below that root.
    pub selected_object_path: String,
}

impl OperatorNativeResourceSelectionInput {
    fn validate(&self) -> Result<(), BrokerError> {
        for (path, field) in [
            (&self.selected_root_path, "resource_selection.selected_root_path"),
            (
                &self.selected_object_path,
                "resource_selection.selected_object_path",
            ),
        ] {
            if path.trim().is_empty()
                || path.len() > 32_767
                || path.chars().any(char::is_control)
                || path.contains(['*', '?'])
            {
                return Err(BrokerError::InvalidField(field));
            }
        }
        Ok(())
    }
}

/// Broker-owned observation of one explicitly selected native object.
///
/// The platform owner produces this from retained, no-follow root/object
/// handles. It contains no path and no StateFence: only the Kernel grant may
/// issue the latter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeResourceObjectMeasurement {
    /// Opaque Broker-owned selection reference for retained private state.
    pub candidate_ref: String,
    /// Digest of the selected root identity from retained owner handles.
    pub canonical_root_identity_digest: String,
    /// Digest of the selected object identity from retained owner handles.
    pub canonical_resource_identity_digest: String,
    /// Digest of stable object measurement facts from owner handles.
    pub measurement_digest: String,
    /// Measured object kind.
    pub resource_kind: NativeResourceKind,
    /// Reparse policy actually enforced by the owner resolver.
    pub reparse_policy: NativeResourceReparsePolicy,
    /// Network policy actually enforced by the owner resolver.
    pub network_policy: NativeResourceNetworkPolicy,
    /// Device policy actually enforced by the owner resolver.
    pub device_policy: NativeResourceDevicePolicy,
    /// Owner clock at measurement completion; absent means clock is unknown.
    pub measured_at_unix_ms: Option<u64>,
}

/// Native resource resolver owned by the authenticated User Broker.
///
/// `premeasure` retains the private selection and returns path-free evidence
/// before Kernel authorization. `remeasure_for_use` is available only after a
/// matching Kernel selection grant and must re-resolve the same private
/// selection immediately before the process boundary.
pub trait NativeResourceResolverPort: Send {
    /// Returns a Broker/owner clock observation, or refuses when unavailable.
    fn owner_now_unix_ms(&mut self) -> Result<u64, NativeResourceResolutionError>;

    /// Opens and measures the explicit Operator selection before authorization.
    fn premeasure(
        &mut self,
        input: &OperatorNativeResourceSelectionInput,
        not_before: u64,
    ) -> Result<NativeResourceObjectMeasurement, NativeResourceResolutionError>;

    /// Re-resolves the retained candidate after authorization, before use.
    fn remeasure_for_use(
        &mut self,
        candidate: &NativeResourceSelectionCandidate,
        not_before: u64,
    ) -> Result<NativeResourceObjectMeasurement, NativeResourceResolutionError>;

    /// Releases retained handles after the process boundary has returned.
    fn complete_use(&mut self, candidate_ref: &str);

    /// Burns and releases a candidate when authorization or preparation fails.
    fn discard_candidate(&mut self, candidate_ref: &str);
}

/// Typed owner-resolver failures. Unknown outcomes burn the current launch.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NativeResourceResolutionError {
    #[error("native resource selection is no longer available")]
    Unavailable,
    #[error("native resource selection was not found")]
    NotFound,
    #[error("native resource selection was substituted")]
    Substituted,
    #[error("native resource selection was revoked")]
    Revoked,
    #[error("native resource selection measurement is unknown")]
    Unknown,
    #[error("native resource selection owner rejected the request: {0}")]
    Invalid(String),
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
    /// Kernel/Governor-issued resource selection authority, present only for
    /// an exact boundary-crossing object admitted from an Operator candidate.
    #[serde(default)]
    pub resource_selection: Option<NativeResourceSelection>,
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
    /// Present only when the admitted launch crossed an explicitly selected
    /// native resource boundary.
    pub native_resource_lease_receipt: Option<NativeResourceLeaseConsumptionReceipt>,
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
    /// Explicit row schema version. Missing on pre-#74 snapshots and read as
    /// version 1, whose identity is reserved but cannot be replayed.
    #[serde(default = "legacy_issued_operation_identity_version")]
    pub schema_version: u16,
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
    /// Exact registration generation that admitted this request identity.
    /// Both values are absent only for a registration request issued before a
    /// registration exists, or on an explicit legacy row.
    #[serde(default)]
    pub registration_digest: Option<String>,
    #[serde(default)]
    pub user_broker_epoch: Option<u64>,
    /// Original typed Kernel identity. It is never reconstructed against a
    /// later fence; a missing value is a legacy/local-operation tombstone.
    #[serde(default)]
    pub request_identity: Option<RequestIdentity>,
    /// Observation instant the identity was minted at.
    pub issued_at_ms: u64,
    /// Caller request id when a launch caller link owned this issuance.
    pub caller_request_id: Option<String>,
    /// Caller launch idempotency key, distinct from the transport key above.
    #[serde(default)]
    pub caller_idempotency_key: Option<String>,
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
        if let Some(caller_key) = self.caller_idempotency_key.as_deref() {
            text(caller_key, "operation_identity.caller_idempotency_key")?;
        }
        match (self.registration_digest.as_deref(), self.user_broker_epoch) {
            (Some(digest), Some(epoch)) if epoch > 0 => {
                hex_digest(digest, "operation_identity.registration_digest")?;
            }
            (None, None) => {}
            _ => return Err(BrokerError::InvalidField("operation_identity.registration")),
        }
        let kernel_request = matches!(
            self.operation.as_str(),
            "eliot.user-broker.register"
                | "eliot.user-broker.heartbeat"
                | "eliot.user-broker.authorize-launch"
                | "eliot.user-broker.fence"
        );
        let broker_control = matches!(
            self.operation.as_str(),
            "eliot.user-broker.cancel" | "eliot.user-broker.reconcile"
        );
        let is_authorize_launch = self.operation == "eliot.user-broker.authorize-launch";
        match self.schema_version {
            LEGACY_ISSUED_OPERATION_IDENTITY_VERSION
                if (kernel_request || broker_control)
                    && self.request_identity.is_none()
                    && self.registration_digest.is_none()
                    && self.user_broker_epoch.is_none()
                    && self.caller_idempotency_key.is_none()
                    && self.caller_request_id.is_some() == is_authorize_launch => {}
            ISSUED_OPERATION_IDENTITY_VERSION if kernel_request => {
                self.validate_kernel_request_identity(is_authorize_launch)?;
            }
            ISSUED_OPERATION_IDENTITY_VERSION if broker_control => {
                if self.request_identity.is_some()
                    || self.registration_digest.is_none()
                    || self.user_broker_epoch.is_none()
                    || self.caller_request_id.is_some()
                    || self.caller_idempotency_key.is_some()
                {
                    return Err(BrokerError::InvalidField(
                        "operation_identity.control_binding",
                    ));
                }
            }
            _ => {
                return Err(BrokerError::InvalidField(
                    "operation_identity.schema_version",
                ));
            }
        }
        Ok(())
    }

    fn validate_kernel_request_identity(
        &self,
        is_authorize_launch: bool,
    ) -> Result<(), BrokerError> {
        if self.operation != "eliot.user-broker.register"
            && (self.registration_digest.is_none() || self.user_broker_epoch.is_none())
        {
            return Err(BrokerError::InvalidField("operation_identity.registration"));
        }
        let request_identity = self
            .request_identity
            .as_ref()
            .ok_or(BrokerError::InvalidField(
                "operation_identity.request_identity",
            ))?;
        request_identity
            .validate()
            .map_err(|_| BrokerError::InvalidField("operation_identity.request_identity"))?;
        let issued_at = i64::try_from(self.issued_at_ms)
            .map_err(|_| BrokerError::InvalidField("operation_identity.clock"))?;
        if request_identity.request.metadata.request_id.as_str() != self.request_id
            || request_identity.idempotency_key != self.idempotency_key
            || request_identity.cancellation_id != self.cancellation_id
            || request_identity.deadline_unix_ms != self.deadline_unix_ms
            || request_identity.request.metadata.state_fence != request_identity.request.state_fence
            || request_identity.request.metadata.product_id.as_str() != "eliot-user-broker"
            || request_identity.request.metadata.source_id.as_str() != "user-broker-transport"
            || request_identity.request.metadata.session_id.is_some()
            || request_identity.request.metadata.task_id.is_some()
            || request_identity.request.metadata.clock.valid_time_ms != Some(issued_at)
            || request_identity.request.metadata.clock.known_time_ms != Some(issued_at)
        {
            return Err(BrokerError::InvalidField(
                "operation_identity.request_identity_binding",
            ));
        }
        if self.caller_request_id.is_some() != self.caller_idempotency_key.is_some()
            || (is_authorize_launch && self.caller_request_id.is_none())
            || (!is_authorize_launch && self.caller_request_id.is_some())
        {
            return Err(BrokerError::InvalidField(
                "operation_identity.caller_binding",
            ));
        }
        Ok(())
    }
}

/// Live per-operation identity ledger supplied by the composition.
///
/// The broker core never mints a Kernel request identity: it only projects
/// whatever the composed issuer holds into the durable snapshot, so the
/// identity ledger and the durable registration state are written in one
/// atomic publication. A broken ledger is an error; it must not erase
/// recovered identities from the next snapshot.
pub trait IssuedOperationIdentityLedger: Send {
    /// Returns every operation identity this process has issued, in a
    /// deterministic order, or an error when the projection is unavailable.
    fn issued_operation_identities(&self) -> Result<Vec<IssuedOperationIdentity>, String>;

    /// Returns retained process/effect links in deterministic order. An empty
    /// result means this issuer has retained no confirmed start observations.
    fn process_effect_lineage(&self) -> Result<Vec<ProcessEffectLineage>, String>;
}

/// One durable, observation-only join from the caller request and Kernel grant
/// to the exact sealed process invocation. It grants no process authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEffectLineage {
    /// Caller request identity that admitted the operation.
    pub caller_request_id: String,
    /// Kernel authorize-launch transport request id, when linked by the issuer.
    pub authorize_request_id: Option<String>,
    /// Canonical grant request digest observed for this invocation.
    pub grant_request_digest: String,
    /// Exact sealed process invocation digest returned by the process adapter.
    pub process_request_digest: String,
}

impl ProcessEffectLineage {
    /// Validates the immutable relation before it is retained or restored.
    pub fn validate(&self) -> Result<(), BrokerError> {
        text(&self.caller_request_id, "process_lineage.caller_request_id")?;
        if let Some(authorize_request_id) = &self.authorize_request_id {
            text(authorize_request_id, "process_lineage.authorize_request_id")?;
        }
        lowercase_hex_digest(
            &self.grant_request_digest,
            "process_lineage.grant_request_digest",
        )?;
        lowercase_hex_digest(
            &self.process_request_digest,
            "process_lineage.process_request_digest",
        )?;
        Ok(())
    }
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
    /// Bounded observation-only joins from grants to process invocations.
    #[serde(default)]
    pub process_effect_lineage: Vec<ProcessEffectLineage>,
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
    /// The registration this broker's current generation superseded.
    ///
    /// I14.17 keeps every pre-cutover child runtime "pinned to the
    /// broker/epoch that launched it" and never silently adopts it, so the
    /// superseded generation's own identity has to outlive the transition that
    /// retired it. Without this row a restart could name the retired
    /// operation ids but not the generation they belonged to, and a
    /// registration/cutover receipt would have to take the old generation and
    /// epoch from caller-supplied text — which would let a receipt describe a
    /// transition this broker never performed.
    ///
    /// Only the immediately superseded registration is retained; a deeper
    /// predecessor is not chained, because the receipt of the earlier
    /// transition already recorded it. `#[serde(default)]` is the versioned
    /// additive migration — a snapshot written before generations were
    /// chained has no predecessor, which is read as "this file has recorded no
    /// superseded registration", never as a licence to invent one.
    #[serde(default)]
    pub predecessor_registration: Option<RegistrationReceipt>,
    /// The registration/cutover receipt this broker last published, or
    /// `None` when it has published none.
    ///
    /// The receipt is a durable record, not a completion signal: its
    /// [`OldJobObjectTermination`] field is the only state this owner can
    /// produce, so a reader can never conclude from its presence that a new
    /// generation took over. Persisting it is what makes the recorded Session
    /// binding transfer and the pre-cutover operation dispositions survive a
    /// restart instead of living only until the process died.
    /// `#[serde(default)]` is the versioned additive migration — absence is
    /// read as "no cutover was published into this file".
    #[serde(default)]
    pub cutover_receipt: Option<CutoverReceipt>,
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
    /// Path-free selection evidence retained for exact idempotent replay.
    #[serde(default)]
    pub native_resource_selection_candidate: Option<NativeResourceSelectionCandidate>,
    /// Digest of the original Operator path pair, retained without the paths.
    #[serde(default)]
    pub selection_input_digest: Option<String>,
    /// One-shot resource lease retained when this operation crossed a resource boundary.
    #[serde(default)]
    pub native_resource_lease: Option<NativeResourceLease>,
    /// Durable one-shot resolution state retained through broker cutover.
    #[serde(default)]
    pub native_resource_lease_use_state: Option<NativeResourceLeaseUseState>,
    /// Durable evidence of fresh re-resolution and lease consumption.
    #[serde(default)]
    pub native_resource_lease_receipt: Option<NativeResourceLeaseConsumptionReceipt>,
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
    /// Path-free selection candidate bound by the Kernel grant.
    #[serde(default)]
    pub native_resource_selection_candidate: Option<NativeResourceSelectionCandidate>,
    /// Digest of original Operator selection input; no path is retained.
    #[serde(default)]
    pub selection_input_digest: Option<String>,
    /// One-shot resource lease bound to the exact selection and operation.
    #[serde(default)]
    pub native_resource_lease: Option<NativeResourceLease>,
    /// Durable reservation/in-flight/consumed marker for one-shot use.
    #[serde(default)]
    pub native_resource_lease_use_state: Option<NativeResourceLeaseUseState>,
    /// Durable evidence of fresh measurement before process start.
    #[serde(default)]
    pub native_resource_lease_receipt: Option<NativeResourceLeaseConsumptionReceipt>,
    /// A durable recovery obligation when the process effect could not be
    /// joined to its caller/grant lineage. The operation ID and invocation
    /// digest above remain the exact handle for reconciliation.
    #[serde(default)]
    pub process_lineage_recovery_required: bool,
    pub state: OperationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Active,
    Unknown,
    Reconciled,
}

/// Durable phase of one-shot native resource lease consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeResourceLeaseUseState {
    /// Lease has been stored but the resolver has not been called.
    Reserved,
    /// Persisted before re-resolution; restart must treat the lease as spent.
    ResolutionInFlight,
    /// Current object and Kernel fence were checked and receipt persisted.
    Consumed,
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
        if let Some(candidate) = &self.native_resource_selection_candidate {
            candidate
                .validate()
                .map_err(BrokerError::NativeResourceSelection)?;
        }
        if let Some(selection_input_digest) = &self.selection_input_digest {
            hex_digest(selection_input_digest, "selection_input_digest")?;
        }
        if self.native_resource_selection_candidate.is_some()
            != self.selection_input_digest.is_some()
            || self.native_resource_selection_candidate.is_some()
                != self.native_resource_lease.is_some()
        {
            return Err(BrokerError::InvalidField(
                "operation_cursor.native_resource_selection_binding",
            ));
        }
        validate_retained_native_resource_lease(
            self.native_resource_lease.as_ref(),
            self.native_resource_lease_use_state,
            self.native_resource_lease_receipt.as_ref(),
            &NativeResourceLeaseOwner {
                operation_id: self.operation_id.as_str(),
                registration_digest: &self.registration_digest,
                user_broker_epoch: self.user_broker_epoch,
                consumer_generation: Some(self.generation.get()),
                authority_epoch: Some(&self.authority_epoch),
                introduction: self.introduction.as_ref(),
                candidate: self.native_resource_selection_candidate.as_ref(),
            },
            "operation_cursor.native_resource_lease",
        )?;
        Ok(())
    }
}

struct NativeResourceLeaseOwner<'a> {
    operation_id: &'a str,
    registration_digest: &'a str,
    user_broker_epoch: u64,
    consumer_generation: Option<u64>,
    authority_epoch: Option<&'a EpochId>,
    introduction: Option<&'a ResourceIntroduction>,
    candidate: Option<&'a NativeResourceSelectionCandidate>,
}

fn validate_retained_native_resource_lease(
    lease: Option<&NativeResourceLease>,
    use_state: Option<NativeResourceLeaseUseState>,
    receipt: Option<&NativeResourceLeaseConsumptionReceipt>,
    owner: &NativeResourceLeaseOwner<'_>,
    field: &'static str,
) -> Result<(), BrokerError> {
    let Some(lease) = lease else {
        return if use_state.is_none() && receipt.is_none() {
            Ok(())
        } else {
            Err(BrokerError::InvalidField(field))
        };
    };
    lease.validate().map_err(BrokerError::NativeResourceLease)?;
    match (use_state, receipt) {
        (
            Some(
                NativeResourceLeaseUseState::Reserved
                | NativeResourceLeaseUseState::ResolutionInFlight,
            ),
            None,
        ) => {}
        (Some(NativeResourceLeaseUseState::Consumed), Some(receipt)) => receipt
            .validate_for(lease)
            .map_err(BrokerError::NativeResourceLease)?,
        _ => return Err(BrokerError::InvalidField(field)),
    }
    let candidate = owner
        .candidate
        .ok_or(BrokerError::InvalidField(field))?;
    let introduction = owner
        .introduction
        .ok_or(BrokerError::InvalidField(field))?;
    if lease.operation_ref != owner.operation_id
        || lease.registration_ref != owner.registration_digest
        || lease.broker_epoch != owner.user_broker_epoch
        || owner
            .consumer_generation
            .is_some_and(|generation| lease.consumer_generation != generation)
        || owner.authority_epoch.is_some_and(|authority_epoch| {
            !lease
                .state_fence
                .authority_epoch
                .is_same_authority(authority_epoch)
        })
        || lease.resource_ref != introduction.resource_ref
        || lease.candidate_ref != candidate.candidate_ref
        || lease.principal_ref != candidate.principal_ref
        || lease.request_ref != candidate.request_ref
        || lease.operation_ref != candidate.operation_ref
        || lease.registration_ref != candidate.registration_ref
        || lease.broker_epoch != candidate.broker_epoch
        || lease.canonical_root_identity_digest != candidate.canonical_root_identity_digest
        || lease.resource_identity_digest != candidate.canonical_resource_identity_digest
        || lease.measurement_digest != candidate.measurement_digest
        || lease.resource_kind != candidate.resource_kind
        || lease.reparse_policy != candidate.reparse_policy
        || lease.network_policy != candidate.network_policy
        || lease.device_policy != candidate.device_policy
    {
        return Err(BrokerError::NativeResourceLease(
            NativeResourceLeaseError::ReceiptBindingMismatch,
        ));
    }
    Ok(())
}

/// The explicitly recorded broker-independent part of one broker Session
/// identity (I14.17:11).
///
/// A Session binding is recorded in two parts, and only this part is
/// broker-independent: the installation, Windows SID, interactive logon
/// Session and boot Session name the user's Session, not the broker process
/// that serves it. The broker-dependent part — the broker process id, its
/// immutable artifact digest and its launch nonce — is deliberately absent
/// from this type, so a cutover has no field to copy it into and
/// "leave broker-dependent bindings untransferred" is a property of the shape
/// rather than of a code path somebody has to remember to follow.
///
/// A transferred binding grants nothing. It records which user Session a
/// generation served, so a later generation can be shown to have continued the
/// same Session; it is never an admission, and every launch still runs against
/// the live registration's own binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIndependentSessionBinding {
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub boot_session_id: String,
}

impl BrokerIndependentSessionBinding {
    /// Projects the broker-independent part out of one registration.
    fn of(registration: &RegistrationReceipt) -> Self {
        Self {
            installation_id: registration.installation_id.clone(),
            windows_sid: registration.windows_sid.clone(),
            interactive_session_id: registration.interactive_session_id.clone(),
            boot_session_id: registration.boot_session_id.clone(),
        }
    }

    fn validate(&self) -> Result<(), BrokerError> {
        text(&self.installation_id, "session_binding.installation_id")?;
        text(&self.windows_sid, "session_binding.windows_sid")?;
        text(
            &self.interactive_session_id,
            "session_binding.interactive_session_id",
        )?;
        text(&self.boot_session_id, "session_binding.boot_session_id")
    }
}

/// The binding transfer one published cutover applied (I14.17:11).
///
/// The transfer moves the broker-independent content and nothing else: both
/// halves are the same Session identity, field for field. A cutover that
/// widened, narrowed or re-pointed the binding is refused rather than
/// published, so the receipt cannot describe a cutover that changed which
/// Session the broker serves.
///
/// The broker-dependent half of the transition — which broker process, which
/// immutable artifact and which nonce — is not represented here at all. It
/// lives in [`CutoverReceipt::old_registration`] and
/// [`CutoverReceipt::new_registration`], and the new generation's copy is
/// always its own: the candidate's process id, artifact digest and launch
/// nonce come from its own protected launch declaration, and no cutover copies
/// the superseded generation's.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBindingTransfer {
    /// The binding the superseded generation recorded.
    pub old_binding: BrokerIndependentSessionBinding,
    /// The binding this generation recorded.
    pub new_binding: BrokerIndependentSessionBinding,
}

impl SessionBindingTransfer {
    fn validate(&self) -> Result<(), BrokerError> {
        self.old_binding.validate()?;
        self.new_binding.validate()?;
        if self.old_binding != self.new_binding {
            return Err(BrokerError::SessionBindingNotTransferred);
        }
        Ok(())
    }
}

/// What this owner could prove about the superseded generation's Job Object
/// when the cutover stopped (I14.17:12, I14.17:16).
///
/// There is exactly one state to record here, and the type says so.
///
/// The broker cannot reach its own Job Object: [`ApprovedLaunch::job_id`] is a
/// Kernel/N4-supplied contour identity this broker never infers from a path,
/// process id or caller text, and the P-04 executor mints the per-attempt job
/// name internally and never returns it. No termination-proof producer exists
/// anywhere in this workspace.
///
/// A proved state is therefore deliberately *not* declared. Declaring one
/// without a producer would be a receipt able to *claim* a proof nothing can
/// produce — the "termination was assumed" shortcut that
/// [`UserBroker::release_owned_operations`] already refuses to make when a
/// child does not close. I14.17 requires the opposite: inability to prove old
/// Job Object termination stops the cutover and leaves it for reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OldJobObjectTermination {
    /// Termination of the superseded generation's Job Object is not proven by
    /// this owner, so the cutover stopped: the candidate is not marked active
    /// and the transition requires reconciliation. `reason` names the exact
    /// proof that is missing.
    Unproven { reason: String },
}

impl OldJobObjectTermination {
    /// The only state this owner can record, with the exact proof it lacks.
    fn unproven() -> Self {
        Self::Unproven {
            reason: "the superseded generation's Job Object identity is a Kernel/N4 contour the \
                     broker never infers and the P-04 executor never returns, so termination of \
                     that Job Object is not observable from this owner"
                .to_owned(),
        }
    }

    /// The exact proof this owner lacks, and why the cutover stopped.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Unproven { reason } => reason,
        }
    }
}

/// One pre-cutover operation and the state the cutover recorded for it
/// (I14.17:12, I14.17:16).
///
/// The pin tuple is the whole point of this row. An operation stays attributed
/// to the registration and broker generation that launched it, so a new broker
/// cannot silently adopt it and a reader of the receipt can tell which
/// generation each pre-cutover child runtime is still pinned to.
///
/// `state` is this broker's own [`OperationState`]. I14.14:45-63 fixes the
/// in-flight disposition vocabulary in one owner (Kernel/ORS,
/// `eliot_ors::InFlightDispositionKind`), and A-09 does not own that
/// vocabulary: this crate carries no ORS dependency, and re-spelling those five
/// dispositions here would be a second owner of them. Recording the state the
/// broker actually holds, and leaving the mapping onto I14.14's dispositions to
/// the ORS owner, is the honest split — which ORS vocabulary is authoritative
/// for a broker-generation cutover is an open decision (reported as
/// BLOCKED-BY decision on issue #1954).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverOperationDisposition {
    /// The operation identity. It stays the superseded generation's: a
    /// pre-cutover operation is never adopted by a new broker.
    pub operation_id: OperationId,
    /// Canonical digest of the exact request the superseded generation
    /// admitted, so a reader can tell which request this row is about.
    pub request_digest: String,
    /// Registration digest of the generation the operation is pinned to.
    pub registration_digest: String,
    /// Broker-local generation the operation is pinned to.
    pub user_broker_epoch: u64,
    /// The state the retired record held when its generation was fenced.
    pub state: OperationState,
}

/// The published registration/cutover receipt for one broker-generation
/// transition (I14.17:13).
///
/// Every field is a fact this broker holds. `old_job_object_termination` is
/// the field that decides what a reader may conclude: because
/// [`OldJobObjectTermination`] has exactly one inhabitant, this receipt can
/// never be read as a completed cutover, so treating publication as
/// completion is wrong by construction rather than by convention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverReceipt {
    /// The generation and epoch this transition superseded, exactly as this
    /// broker's own record held it.
    pub old_registration: RegistrationReceipt,
    /// The candidate generation and epoch. Publication grants it nothing: the
    /// candidate is not marked active, and the live launch path continues to
    /// admit only through this registration's own binding.
    pub new_registration: RegistrationReceipt,
    /// Exactly which broker-independent Session binding transferred.
    pub session_binding_transfer: SessionBindingTransfer,
    /// One row per pre-cutover operation of *this* transition, each still
    /// pinned to the superseded generation.
    pub operation_dispositions: Vec<CutoverOperationDisposition>,
    /// What this owner could prove about the superseded generation's Job
    /// Object.
    pub old_job_object_termination: OldJobObjectTermination,
}

impl CutoverReceipt {
    /// Checks a receipt read back from durable state.
    ///
    /// A receipt is only accepted if it is internally consistent with itself:
    /// the transfer really moved the same binding, the replacement really
    /// moved strictly forward inside one user Session, and every disposition
    /// really belongs to the generation the receipt claims to supersede. A
    /// corrupt file is rejected before it can report a binding as transferred
    /// or a foreign operation as pinned here.
    fn validate(&self) -> Result<(), BrokerError> {
        self.session_binding_transfer.validate()?;
        if self.old_registration.user_broker_epoch >= self.new_registration.user_broker_epoch
            || self.old_registration.windows_sid != self.new_registration.windows_sid
            || self.old_registration.interactive_session_id
                != self.new_registration.interactive_session_id
            || self.old_registration.boot_session_id != self.new_registration.boot_session_id
            || self.old_registration.installation_id != self.new_registration.installation_id
        {
            return Err(BrokerError::CutoverPrecondition("receipt_lineage"));
        }
        if self
            .operation_dispositions
            .iter()
            .any(|row| row.registration_digest != self.old_registration.registration_digest)
        {
            return Err(BrokerError::CutoverPrecondition(
                "receipt_operation_disposition_lineage",
            ));
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
    /// Reads the current Kernel-owned selection/fence immediately before use.
    ///
    /// The default refuses a selected resource. A production authority must
    /// implement a live currentness read; echoing the grant record is not
    /// sufficient evidence.
    fn validate_native_resource_selection_current(
        &mut self,
        _receipt: &RegistrationReceipt,
        _selection: &NativeResourceSelection,
        _observed_at: u64,
    ) -> Result<(), PortError> {
        Err(PortError::Unavailable)
    }
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
    ///
    /// `stdin_payload` is the exact one-shot standard-input bytes this admitted
    /// launch carries, or `None` when the child needs no input.  It is passed
    /// here, at the single point where the request is turned into a sealed
    /// provider request, and NOT to [`Self::start`]: an implementation that
    /// retains it from `prepare_start` cannot be handed different bytes at the
    /// start boundary, so the request digest committed durably before the
    /// effect and the bytes actually written to the child are the same bytes.
    fn prepare_start(
        &mut self,
        grant: &LaunchGrant,
        registration: &RegistrationReceipt,
        stdin_payload: Option<&str>,
    ) -> Result<String, PortError>;
    fn start(
        &mut self,
        grant: &LaunchGrant,
        registration: &RegistrationReceipt,
        expected_request_digest: &str,
    ) -> Result<ProcessStartOutcome, PortError>;
    /// Returns whether observation-only process lineage could not be retained
    /// for the just-returned start outcome. This result is attached to the
    /// durable cursor for the exact process operation and never changes the
    /// effect outcome or handle.
    fn take_process_lineage_recovery_obligation(&mut self) -> Result<bool, PortError>;
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
    native_resource_resolver: Option<Box<dyn NativeResourceResolverPort>>,
    durable: Option<Box<dyn DurableRegistrationPort>>,
    identity_ledger: Option<Box<dyn IssuedOperationIdentityLedger>>,
    admission: Option<BrokerAdmissionIdentity>,
    registration: Option<RegistrationReceipt>,
    registration_reconciled: bool,
    broker_epoch: u64,
    operations: BTreeMap<String, OperationRecord>,
    retired_operations: BTreeMap<String, RetiredOperationIdentity>,
    issued_operations: BTreeMap<String, IssuedOperationIdentity>,
    process_effect_lineage: BTreeMap<(String, String), ProcessEffectLineage>,
    lost_operation: Option<LostOperation>,
    /// The registration this broker's current generation superseded, retained
    /// so a pre-cutover child runtime's broker/epoch lineage outlives the
    /// transition that retired it (I14.17) and a receipt can name that
    /// generation from this broker's own record. `None` until this broker's
    /// lineage has actually superseded a registration.
    predecessor_registration: Option<RegistrationReceipt>,
    /// The last published registration/cutover receipt, restored from durable
    /// state on recovery and rewritten by the next publication.
    cutover_receipt: Option<CutoverReceipt>,
    /// The live one-shot Operator handoff authority, bound to the registration
    /// revision and installation-approved artifact it was built for. `None`
    /// until the first admission, and reset on every recovery so a restarted
    /// broker can never redeem an endpoint a previous process issued.
    operator_handoff: Option<(OperatorHandoffBinding, OperatorHandoffAuthority)>,
    /// The Kernel-coordinated registry and cutover machine (issue #1954).
    ///
    /// A fresh machine holds no candidate, so [`Self::admit_new_launch`] does
    /// not gate the ordinary single-registration path; only a completed
    /// cutover installs a candidate, and from that point the machine is the
    /// authority on which registration may admit a launch.  A restart drops the
    /// machine: the durable cutover receipt, not process memory, is what
    /// re-establishes it.
    cutover: BrokerCutover,
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
            native_resource_resolver: None,
            durable,
            identity_ledger: None,
            admission: None,
            registration: None,
            registration_reconciled: false,
            broker_epoch: 0,
            operations: BTreeMap::new(),
            retired_operations: BTreeMap::new(),
            issued_operations: BTreeMap::new(),
            process_effect_lineage: BTreeMap::new(),
            lost_operation: None,
            predecessor_registration: None,
            cutover_receipt: None,
            operator_handoff: None,
            cutover: BrokerCutover::new(),
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

    /// Attaches the authenticated Broker's retained native resource owner.
    ///
    /// Ordinary launches remain usable without this optional provider. A
    /// selected boundary crossing fails closed if the provider is absent.
    pub fn attach_native_resource_resolver(
        &mut self,
        resolver: Box<dyn NativeResourceResolverPort>,
    ) {
        self.native_resource_resolver = Some(resolver);
    }

    /// Returns the durable per-operation identity ledger recovered from the
    /// restart snapshot.  A composition re-seeds its issuer from exactly this
    /// list before it can mint, so a spent request id, cancellation id, or
    /// idempotency key from a previous process is a conflict, not a new mint.
    #[must_use]
    pub fn recovered_operation_identities(&self) -> Vec<IssuedOperationIdentity> {
        self.issued_operations.values().cloned().collect()
    }

    /// Returns process/effect relations recovered from the durable snapshot so
    /// the composition can re-seed its observation ledger before new effects.
    #[must_use]
    pub fn recovered_process_effect_lineage(&self) -> Vec<ProcessEffectLineage> {
        self.process_effect_lineage.values().cloned().collect()
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
        // A one-shot handoff is process-local and non-durable by construction:
        // a restarted broker holds no memory of the nonces its previous
        // incarnation issued, so continuity is never inferred from a cached
        // endpoint. Recovery therefore starts with no handoff authority, and
        // an endpoint from the previous process is refused as an unknown nonce.
        self.operator_handoff = None;
        // A cutover machine lives in process memory only, so a restart must
        // not inherit one: the previous process's in-flight transition is not
        // resumable evidence, and a surviving machine would gate launches
        // against a candidate this process never authenticated.  The durable
        // cutover receipt is what re-establishes a cutover, and that happens
        // through `stage_candidate` again after this recovery.
        self.cutover = BrokerCutover::new();
        let snapshot = self
            .durable
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?
            .load()
            .map_err(|error| map_port(RequiredProvider::DurableRegistration, error))?
            .ok_or(BrokerError::PlanGap(RequiredProvider::DurableRegistration))?;
        let registration = snapshot.registration;
        let broker_epoch = snapshot.user_broker_epoch;
        let RestoredIdentityEvidence {
            issued_operations,
            process_effect_lineage,
        } = restore_identity_evidence(
            snapshot.operation_identities,
            snapshot.process_effect_lineage,
        )?;
        let retired_operations = retired_index(snapshot.retired_operations)?;
        // A receipt is adopted only after it is checked against itself: a
        // corrupt file must not be able to report a binding as transferred, a
        // generation as replaced, or a foreign operation as pinned here.
        if let Some(receipt) = &snapshot.cutover_receipt {
            receipt.validate()?;
        }
        let Some(registration_ref) = registration.as_ref() else {
            if snapshot.operation_cursors.is_empty() {
                self.registration = registration;
                self.registration_reconciled = true;
                self.broker_epoch = broker_epoch;
                self.issued_operations = issued_operations;
                self.process_effect_lineage = process_effect_lineage;
                self.retired_operations = retired_operations;
                self.cutover_receipt = snapshot.cutover_receipt;
                self.predecessor_registration = snapshot.predecessor_registration;
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
            if cursor.registration_digest != registration_ref.registration_digest
                || cursor.user_broker_epoch != registration_ref.user_broker_epoch
                || !cursor
                    .authority_epoch
                    .is_same_authority(&registration_ref.authority_epoch)
                || cursor.fence_id != registration_ref.fence_id
                || cursor.lease_expires_at > registration_ref.expires_at
            {
                return Err(BrokerError::GrantBindingMismatch);
            }
            if !operation_ids.insert(cursor.operation_id.clone()) {
                return Err(BrokerError::Duplicate("operation_cursor.operation_id"));
            }
            if retired_operations.contains_key(cursor.operation_id.as_str()) {
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
        self.registration = registration;
        self.registration_reconciled = false;
        self.broker_epoch = broker_epoch;
        self.issued_operations = issued_operations;
        self.process_effect_lineage = process_effect_lineage;
        self.retired_operations = retired_operations;
        self.cutover_receipt = snapshot.cutover_receipt;
        self.predecessor_registration = snapshot.predecessor_registration;
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

    /// Admits one owner-issued, generation-bound, expiring, single-use Operator
    /// handoff and returns the endpoint the one-shot child parses.
    ///
    /// The binding is taken from this broker's own live registration, never
    /// from the request: `broker_epoch` is the registration epoch (the endpoint
    /// generation) and `interactive_session_id` is the logon Session the
    /// registration was admitted for. A broker that is not admitted, is not
    /// `Active`, or whose registration epoch disagrees with its own broker-local
    /// epoch is refused, so no handoff can exist without a live registration to
    /// bind it to. Reconnect is a *new* call here: nothing in this signature
    /// accepts a previous nonce, pipe name, endpoint, or expiry.
    pub fn issue_operator_handoff(
        &mut self,
        request: &OperatorHandoffRequest,
        artifact: &OperatorArtifact,
        observed_at: u64,
    ) -> Result<OperatorEndpoint, BrokerError> {
        self.operator_handoff_authority(artifact)?
            .issue(request, observed_at)
    }

    /// Redeems one previously issued Operator handoff exactly once and returns
    /// the installation-approved artifact it authenticates.
    ///
    /// A consumed nonce, an endpoint bound to another session/epoch, and an
    /// endpoint past its expiry are refused with their own distinct
    /// [`BrokerError`] rather than accepted as continuity.
    pub fn consume_operator_handoff(
        &mut self,
        endpoint: &OperatorEndpoint,
        artifact: &OperatorArtifact,
        now: u64,
    ) -> Result<OperatorArtifact, BrokerError> {
        self.operator_handoff_authority(artifact)?
            .consume(endpoint, now)
            .cloned()
    }

    /// Returns the live handoff authority, rebuilding it when the registration
    /// revision, the logon Session, or the installation-approved artifact moved.
    ///
    /// Rebuilding rather than carrying the old ledger forward is what makes a
    /// stale endpoint fail: a nonce minted under a previous registration epoch
    /// is simply absent from the new authority, so it is an unknown nonce
    /// ([`BrokerError::ReplayConflict`]) rather than a still-valid handoff.
    fn operator_handoff_authority(
        &mut self,
        artifact: &OperatorArtifact,
    ) -> Result<&mut OperatorHandoffAuthority, BrokerError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        if registration.status != RegistrationStatus::Active {
            return Err(BrokerError::LeaseExpired);
        }
        let broker_epoch = registration.user_broker_epoch;
        if broker_epoch == 0 || broker_epoch != self.broker_epoch {
            return Err(BrokerError::StaleEpoch);
        }
        let interactive_session_id = registration.interactive_session_id.clone();
        let retained = self.operator_handoff.as_ref().map(|(binding, _)| binding);
        if !retained.is_some_and(|binding| {
            binding.broker_epoch == broker_epoch
                && binding.interactive_session_id == interactive_session_id
                && binding.artifact == *artifact
        }) {
            let authority = OperatorHandoffAuthority::new(
                artifact.clone(),
                OPERATOR_PIPE_NAME.to_owned(),
                broker_epoch,
                interactive_session_id.clone(),
            )?;
            self.operator_handoff = Some((
                OperatorHandoffBinding {
                    broker_epoch,
                    interactive_session_id,
                    artifact: artifact.clone(),
                },
                authority,
            ));
        }
        Ok(&mut self
            .operator_handoff
            .as_mut()
            .ok_or(BrokerError::RegistrationNotAdmitted)?
            .1)
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
                native_resource_selection_candidate: record
                    .cursor
                    .native_resource_selection_candidate
                    .clone(),
                selection_input_digest: record.cursor.selection_input_digest.clone(),
                native_resource_lease: record.cursor.native_resource_lease.clone(),
                native_resource_lease_use_state: record.cursor.native_resource_lease_use_state,
                native_resource_lease_receipt: record
                    .cursor
                    .native_resource_lease_receipt
                    .clone(),
                state: record.cursor.state,
            };
            self.retired_operations
                .insert(retired.operation_id.as_str().to_owned(), retired);
        }
        self.operations.clear();
        // The superseded registration is retained, not dropped. It is the only
        // in-hand proof of which generation this one replaced, so a cutover
        // receipt can record the old generation and epoch from this broker's
        // own record instead of from anything a caller supplies, and the
        // retirements above can be shown to belong to that generation.
        self.predecessor_registration = self.registration.clone();
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

    /// Admits one new launch against the live cutover state.
    ///
    /// This is the production admission path named by the acceptance criterion:
    /// "After broker cutover, a new launch is accepted only through the
    /// candidate's broker registration and epoch."  When no cutover has
    /// installed a candidate, the ordinary live-registration gate in
    /// [`Self::launch`] decides, exactly as before.  Once a cutover *has*
    /// reached `Active`, this consults the machine instead and refuses any
    /// registration that is not the candidate's own, compared through
    /// [`BrokerAdmissionIdentity::admits`] and the exact registration digest,
    /// authority epoch, and fence — never a name match.
    fn admit_new_launch(
        &self,
        current: &RegistrationReceipt,
        observed_at: u64,
    ) -> Result<(), BrokerError> {
        if self.cutover.active_registration().is_none() {
            // No completed cutover: the live registration is the only route.
            return self.require_admitted_registration(current);
        }
        let admission = self
            .admission
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        let epoch = UserBrokerEpoch::new(
            current.authority_epoch.lineage_id.clone(),
            NonZeroU64::new(current.user_broker_epoch)
                .ok_or(BrokerError::InvalidField("user_broker_epoch"))?,
        )?;
        self.cutover.admits_new_launch(admission, current, &epoch)?;
        // A candidate that is active still owes a live lease: the cutover
        // proves *which* registration may launch, not that its lease covers
        // this instant.  Re-check the window so an expired candidate
        // registration is refused here rather than at the provider.
        if observed_at >= current.expires_at || current.status != RegistrationStatus::Active {
            return Err(BrokerError::LeaseExpired);
        }
        Ok(())
    }

    /// Runs one complete I14.17 cutover from a staged candidate to a
    /// published receipt.
    ///
    /// The steps are exactly the document's, in order, and each one can only
    /// be reached from the state before it.  The candidate is *not* active at
    /// any point in this call except the final `Active`, which requires a
    /// verified [`OldJobObjectTerminationProof`].  If that proof is refused or
    /// absent, the machine ends in `ReconciliationRequired` and this returns
    /// [`BrokerError::CutoverTerminationUnproven`] — the candidate is
    /// definitively not active and the cutover is left for reconciliation.
    ///
    /// `stage` supplies the pre-authentication evidence the machine cannot
    /// observe itself (old generation registration/artifact/contour, session
    /// bindings, and the per-operation dispositions); everything after that is
    /// decided here.
    pub fn cutover_to_candidate(
        &mut self,
        stage: BrokerCutoverStage,
        termination_proof: Option<&OldJobObjectTerminationProof>,
    ) -> Result<BrokerCutoverReceipt, BrokerError> {
        let BrokerCutoverStage {
            old,
            candidate,
            session_bindings,
            operation_dispositions,
        } = stage;
        // Only the registration this broker is actually serving can be fenced,
        // so a stage naming a different generation is refused before the
        // machine records anything.
        if let Some(old) = old.as_ref() {
            let live = self
                .registration
                .as_ref()
                .ok_or(BrokerError::RegistrationNotAdmitted)?;
            if old.registration.registration_digest != live.registration_digest {
                return Err(BrokerError::StaleRegistrationIdentity);
            }
        }
        let admission = self
            .admission
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?
            .clone();
        self.cutover.stage_candidate(old.as_ref(), &candidate)?;
        self.cutover.authenticate_candidate(&admission)?;
        self.cutover.fence_old_registration()?;
        self.cutover.transfer_session_bindings(&session_bindings)?;
        // The disposition set is validated against this broker's *own* live
        // operation ids, not against anything the caller asserts, so an
        // operation the broker never owned cannot be dispositioned and an owned
        // one cannot be silently dropped.
        let own_operation_ids: BTreeSet<OperationId> = self
            .operations
            .values()
            .map(|record| record.cursor.operation_id.clone())
            .collect();
        self.cutover
            .commit_operation_dispositions(&operation_dispositions, &own_operation_ids)?;
        self.cutover.request_old_termination()?;
        // The old registration is fenced from new launches at the generation
        // transition, so the authoritative fence is projected before activation
        // is even attempted.  Until termination is proven this leaves the old
        // registration draining, which still refuses every new launch.
        if old.is_some()
            && self
                .registration
                .as_ref()
                .is_some_and(|live| live.status == RegistrationStatus::Active)
        {
            self.close(RegistrationStatus::Draining)?;
        }
        // `complete` publishes a receipt whether or not termination was proven:
        // an unproven cutover publishes a `ReconciliationRequired` receipt with
        // no termination proof, and returns the typed error naming which
        // guarantee failed.  The receipt is captured before the error
        // propagates so the failed cutover stays inspectable through
        // [`Self::broker_cutover_receipt`] instead of being merely refused.
        // The returned receipt borrows `self.cutover`, so the verdict is
        // reduced to a plain `bool` here and the receipt is re-read below
        // once every borrow has ended.
        let cutover_complete = self
            .cutover
            .complete(termination_proof, &own_operation_ids)
            .is_ok();
        if cutover_complete {
            // Only a proven cutover installs the candidate as this broker's
            // live registration and epoch.  An unproven cutover never reaches
            // here, so the draining old registration keeps refusing launches.
            let candidate_registration = self.cutover.active_registration().cloned();
            if let Some(candidate_registration) = candidate_registration {
                self.registration = Some(candidate_registration);
                self.registration_reconciled = true;
                self.broker_epoch = candidate.user_broker_epoch.sequence.get();
                self.operations.clear();
                self.persist()?;
            }
        }
        let published = self
            .cutover
            .receipt()
            .cloned()
            .ok_or(BrokerError::CutoverTerminationUnproven)?;
        if !cutover_complete {
            // The failed cutover stays inspectable through
            // [`Self::broker_cutover_receipt`] instead of being merely refused.
            return Err(BrokerError::CutoverTerminationUnproven);
        }
        Ok(published)
    }

    /// Returns the published cutover receipt, if a cutover has completed.
    #[must_use]
    pub fn broker_cutover_receipt(&self) -> Option<&BrokerCutoverReceipt> {
        self.cutover.receipt()
    }

    /// Returns the current cutover state.
    #[must_use]
    pub fn broker_cutover_state(&self) -> BrokerCutoverState {
        self.cutover.state()
    }

    fn native_resource_owner_now(&mut self) -> Result<u64, BrokerError> {
        let now = self
            .native_resource_resolver
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::NativeResourceResolver))?
            .owner_now_unix_ms()
            .map_err(map_native_resource_resolution)?;
        if now == 0 {
            return Err(BrokerError::NativeResourceClockUnknown);
        }
        Ok(now)
    }

    fn issue_native_resource_lease(
        &mut self,
        registration: &RegistrationReceipt,
        request: &LaunchRequest,
        grant: &LaunchGrant,
        selection: &NativeResourceSelection,
        candidate: &NativeResourceSelectionCandidate,
    ) -> Result<(NativeResourceLeaseBinding, NativeResourceLease), BrokerError> {
        if !candidate.matches_selection(selection) {
            return Err(BrokerError::NativeResourceSelectionBindingMismatch);
        }
        let now = self.native_resource_owner_now()?;
        if now < selection.issued_at {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::NotYetValid,
            ));
        }
        if now >= selection.expires_at
            || now >= registration.expires_at
            || now >= grant.expires_at
            || now >= request.lease_expires_at
            || now >= request.approved.introduction.expires_at
        {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::Expired,
            ));
        }
        if candidate.measured_at > now {
            return Err(BrokerError::NativeResourceStaleMeasurement);
        }
        let binding = native_resource_lease_binding(registration, request, selection, candidate)?;
        let credential_expires_at = request
            .approved
            .introduction
            .credential_binding
            .as_ref()
            .map_or(u64::MAX, |credential| credential.expires_at);
        let expires_at = now
            .saturating_add(NATIVE_RESOURCE_LEASE_TTL_MS)
            .min(registration.expires_at)
            .min(grant.expires_at)
            .min(request.lease_expires_at)
            .min(request.approved.introduction.expires_at)
            .min(credential_expires_at)
            .min(selection.expires_at);
        if expires_at <= now {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::Expired,
            ));
        }
        let lease = NativeResourceLease {
            // UUID v4 is backed by the operating system CSPRNG. This nonce is
            // independent of caller request and operation IDs and becomes a
            // durable one-shot replay key before consumption starts.
            lease_id: Uuid::new_v4().simple().to_string(),
            principal_ref: binding.principal_ref.clone(),
            issuer_process_ref: binding.issuer_process_ref.clone(),
            attempt_ref: binding.attempt_ref.clone(),
            request_ref: binding.request_ref.clone(),
            operation_ref: binding.operation_ref.clone(),
            candidate_ref: binding.candidate_ref.clone(),
            resource_ref: binding.resource_ref.clone(),
            scope_digest: binding.scope_digest.clone(),
            canonical_root_identity_digest: binding.canonical_root_identity_digest.clone(),
            registration_ref: binding.registration_ref.clone(),
            broker_epoch: binding.broker_epoch,
            consumer_generation: binding.consumer_generation,
            state_fence: selection.state_fence.clone(),
            resource_identity_digest: binding.resource_identity_digest.clone(),
            measurement_digest: binding.measurement_digest.clone(),
            resource_kind: binding.resource_kind,
            reparse_policy: binding.reparse_policy,
            network_policy: binding.network_policy,
            device_policy: binding.device_policy,
            issued_at: now,
            expires_at,
        };
        lease.validate().map_err(BrokerError::NativeResourceLease)?;
        Ok((binding, lease))
    }

    fn validate_live_native_resource_selection(
        &mut self,
        selection: &NativeResourceSelection,
    ) -> Result<u64, BrokerError> {
        let now = self.native_resource_owner_now()?;
        let current = self
            .active_registration(now)
            .map_err(map_native_resource_currentness)?
            .clone();
        if current.registration_digest != selection.registration_ref
            || current.windows_sid != selection.principal_ref
            || current.interactive_session_id != selection.interactive_session_id
            || current.user_broker_epoch != selection.broker_epoch
            || current.fence_id != selection.fence_id
            || !current
                .authority_epoch
                .is_same_authority(&selection.authority_epoch)
        {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::Revoked,
            ));
        }
        self.admit_new_launch(&current, now)
            .map_err(map_native_resource_currentness)?;
        let result = self
            .authority
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::G01Authority))?
            .validate_native_resource_selection_current(&current, selection, now);
        result.map_err(map_native_resource_selection_currentness)?;
        Ok(now)
    }

    fn consume_native_resource_lease(
        &mut self,
        idempotency_key: &str,
        current: &RegistrationReceipt,
        selection: &NativeResourceSelection,
        candidate: &NativeResourceSelectionCandidate,
        lease: &NativeResourceLease,
        binding: &NativeResourceLeaseBinding,
    ) -> Result<NativeResourceLeaseConsumptionReceipt, BrokerError> {
        lease.validate().map_err(BrokerError::NativeResourceLease)?;
        binding
            .validate()
            .map_err(BrokerError::NativeResourceLease)?;
        if lease.binding() != *binding || !candidate.matches_selection(selection) {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::Revoked,
            ));
        }
        let reservation_key = self.begin_native_resource_lease_consumption(lease, binding)?;
        let measured = self
            .native_resource_resolver
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::NativeResourceResolver))?
            .remeasure_for_use(candidate, lease.issued_at)
            .map_err(map_native_resource_resolution)?;
        let measured_at = measured
            .measured_at_unix_ms
            .ok_or(BrokerError::NativeResourceClockUnknown)?;
        let consumed_at = self.native_resource_owner_now()?;
        if measured_at < lease.issued_at || measured_at > consumed_at {
            return Err(BrokerError::NativeResourceStaleMeasurement);
        }
        if measured.candidate_ref != candidate.candidate_ref
            || measured.canonical_root_identity_digest != candidate.canonical_root_identity_digest
            || measured.canonical_resource_identity_digest
                != candidate.canonical_resource_identity_digest
            || measured.measurement_digest != candidate.measurement_digest
            || measured.resource_kind != candidate.resource_kind
            || measured.reparse_policy != candidate.reparse_policy
            || measured.network_policy != candidate.network_policy
            || measured.device_policy != candidate.device_policy
            || measured.resource_kind != selection.resource_kind
            || measured.reparse_policy != selection.reparse_policy
            || measured.network_policy != selection.network_policy
            || measured.device_policy != selection.device_policy
        {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::ResourceSubstituted,
            ));
        }
        let measurement = NativeResourceMeasurement {
            candidate_ref: measured.candidate_ref,
            resource_ref: selection.resource_ref.clone(),
            scope_digest: selection.scope_digest.clone(),
            resource_identity_digest: measured.canonical_resource_identity_digest,
            canonical_root_identity_digest: measured.canonical_root_identity_digest,
            measurement_digest: measured.measurement_digest,
            resource_kind: measured.resource_kind,
            reparse_policy: measured.reparse_policy,
            network_policy: measured.network_policy,
            device_policy: measured.device_policy,
            measured_at,
        };
        measurement
            .validate()
            .map_err(BrokerError::NativeResourceLease)?;
        let live_at = self.validate_live_native_resource_selection(selection)?;
        lease
            .validate_use(binding, &measurement, live_at)
            .map_err(BrokerError::NativeResourceLease)?;
        if live_at < consumed_at {
            return Err(BrokerError::NativeResourceStaleMeasurement);
        }
        if current.registration_digest != lease.registration_ref
            || current.user_broker_epoch != lease.broker_epoch
            || idempotency_key.is_empty()
        {
            return Err(BrokerError::NativeResourceLease(
                NativeResourceLeaseError::Revoked,
            ));
        }
        let receipt = NativeResourceLeaseConsumptionReceipt {
            receipt_id: Uuid::new_v4().simple().to_string(),
            lease_id: lease.lease_id.clone(),
            lease_digest: lease
                .canonical_digest()
                .map_err(BrokerError::NativeResourceLease)?,
            principal_ref: lease.principal_ref.clone(),
            issuer_process_ref: lease.issuer_process_ref.clone(),
            attempt_ref: lease.attempt_ref.clone(),
            request_ref: lease.request_ref.clone(),
            operation_ref: lease.operation_ref.clone(),
            candidate_ref: lease.candidate_ref.clone(),
            resource_ref: lease.resource_ref.clone(),
            scope_digest: lease.scope_digest.clone(),
            canonical_root_identity_digest: lease.canonical_root_identity_digest.clone(),
            registration_ref: lease.registration_ref.clone(),
            broker_epoch: lease.broker_epoch,
            consumer_generation: lease.consumer_generation,
            // This is the exact grant fence whose live currentness the Kernel
            // just revalidated; it is not copied into physical measurement.
            state_fence: selection.state_fence.clone(),
            resource_identity_digest: measurement.resource_identity_digest.clone(),
            measurement_digest: measurement.measurement_digest.clone(),
            resource_kind: measurement.resource_kind,
            reparse_policy: measurement.reparse_policy,
            network_policy: measurement.network_policy,
            device_policy: measurement.device_policy,
            consumed_at: live_at,
        };
        receipt
            .validate_for(lease)
            .map_err(BrokerError::NativeResourceLease)?;
        let record = self
            .operations
            .get_mut(&reservation_key)
            .ok_or(BrokerError::NativeResourceLease(NativeResourceLeaseError::Replay))?;
        record.cursor.native_resource_lease_receipt = Some(receipt.clone());
        record.cursor.native_resource_lease_use_state = Some(NativeResourceLeaseUseState::Consumed);
        self.persist()?;
        Ok(receipt)
    }

    fn begin_native_resource_lease_consumption(
        &mut self,
        lease: &NativeResourceLease,
        expected: &NativeResourceLeaseBinding,
    ) -> Result<String, BrokerError> {
        let mut reservation_key = None;
        let mut replay = false;
        for (key, record) in &self.operations {
            if let Some(retained) = &record.cursor.native_resource_lease
                && retained.lease_id == lease.lease_id
            {
                let is_this_reservation = retained == lease
                    && record.cursor.operation_id.as_str() == expected.operation_ref
                    && record.cursor.native_resource_lease_use_state
                        == Some(NativeResourceLeaseUseState::Reserved)
                    && record.cursor.native_resource_lease_receipt.is_none();
                if !is_this_reservation || reservation_key.replace(key.clone()).is_some() {
                    replay = true;
                }
            }
        }
        if self.retired_operations.values().any(|retired| {
            retired
                .native_resource_lease
                .as_ref()
                .is_some_and(|retained| retained.lease_id == lease.lease_id)
        }) {
            replay = true;
        }
        let Some(reservation_key) = reservation_key.filter(|_| !replay) else {
            return Err(BrokerError::NativeResourceLease(NativeResourceLeaseError::Replay));
        };
        let record = self
            .operations
            .get_mut(&reservation_key)
            .ok_or(BrokerError::NativeResourceLease(NativeResourceLeaseError::Replay))?;
        record.cursor.native_resource_lease_use_state =
            Some(NativeResourceLeaseUseState::ResolutionInFlight);
        self.persist()?;
        Ok(reservation_key)
    }

    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_lines)]
    pub fn launch(&mut self, request: LaunchRequest) -> Result<LaunchReceipt, BrokerError> {
        if request.resource_selection_candidate.is_some() {
            return Err(BrokerError::NativeResourceSelectionCandidateUntrusted);
        }
        self.launch_admitted(request, None)
    }

    /// Admits an authenticated generic Operator launch with an explicit
    /// selected root/object pair. The raw paths stay inside this method and
    /// the resolver; only its path-free measurement candidate reaches Kernel.
    #[allow(clippy::needless_pass_by_value)]
    pub fn launch_with_native_resource_selection(
        &mut self,
        mut request: LaunchRequest,
        input: OperatorNativeResourceSelectionInput,
    ) -> Result<LaunchReceipt, BrokerError> {
        if request.resource_selection_candidate.is_some() {
            return Err(BrokerError::NativeResourceSelectionCandidateUntrusted);
        }
        input.validate()?;
        request.validate()?;
        let selection_input_digest = digest(&(
            "eliot.user-broker.operator-resource-selection-input.v1",
            &input.selected_root_path,
            &input.selected_object_path,
        ))?;

        // Exact retries reuse the path-free candidate already retained in the
        // operation cursor. No raw path is persisted, and a retry never opens
        // or consumes the resource a second time.
        if let Some(record) = self.operations.get(&request.approved.idempotency_key) {
            if record.cursor.selection_input_digest.as_deref()
                != Some(selection_input_digest.as_str())
            {
                return Err(BrokerError::ReplayConflict);
            }
            request.resource_selection_candidate = Some(
                record
                    .cursor
                    .native_resource_selection_candidate
                    .clone()
                    .ok_or(BrokerError::NativeResourceSelectionBindingMismatch)?,
            );
            return self.launch_admitted(request, Some(selection_input_digest));
        }
        if let Some(retired) = self
            .retired_operations
            .get(request.approved.operation_id.as_str())
        {
            return Err(if retired.selection_input_digest.as_deref()
                == Some(selection_input_digest.as_str())
            {
                BrokerError::RetiredOperation(retired.operation_id.clone())
            } else {
                BrokerError::OperationIdRetired(retired.operation_id.clone())
            });
        }

        let current = self.active_registration(request.observed_at)?.clone();
        self.admit_new_launch(&current, request.observed_at)?;
        let (owner_now, measurement) = {
            let resolver = self
                .native_resource_resolver
                .as_mut()
                .ok_or(BrokerError::PlanGap(RequiredProvider::NativeResourceResolver))?;
            let owner_now = resolver
                .owner_now_unix_ms()
                .map_err(map_native_resource_resolution)?;
            if owner_now == 0 {
                return Err(BrokerError::NativeResourceClockUnknown);
            }
            let measurement = resolver
                .premeasure(&input, owner_now)
                .map_err(map_native_resource_resolution)?;
            (owner_now, measurement)
        };
        let candidate_ref = measurement.candidate_ref.clone();
        let candidate = match candidate_from_measurement(&current, &request, measurement, owner_now)
        {
            Ok(candidate) => candidate,
            Err(error) => {
                if let Some(resolver) = self.native_resource_resolver.as_mut() {
                    resolver.discard_candidate(&candidate_ref);
                }
                return Err(error);
            }
        };
        request.resource_selection_candidate = Some(candidate);
        let result = self.launch_admitted(request, Some(selection_input_digest));
        if result.is_err()
            && let Some(resolver) = self.native_resource_resolver.as_mut()
        {
            resolver.discard_candidate(&candidate_ref);
        }
        result
    }

    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_lines)]
    fn launch_admitted(
        &mut self,
        request: LaunchRequest,
        selection_input_digest: Option<String>,
    ) -> Result<LaunchReceipt, BrokerError> {
        request.validate()?;
        let current = self.active_registration(request.observed_at)?.clone();
        // A live lease over the right registration is not enough: the
        // registration must be the one *this* admitted process tuple holds.
        // A durable registration left by another SID/Session/installation
        // fails here, before any grant, process preparation, or credential
        // introduction.  After a completed cutover this also proves the
        // registration is the candidate's own, carrying the candidate's epoch.
        self.admit_new_launch(&current, request.observed_at)?;
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
            // A missing owner-issued resource selection is a semantic refusal
            // for this selected launch, not evidence that the broker
            // registration itself was corrupted. Other malformed grant
            // bindings still fence this registration as before.
            if !matches!(error, BrokerError::NativeResourceSelectionNotGranted) {
                self.close(RegistrationStatus::Closed)?;
            }
            return Err(error);
        }
        let candidate = request.resource_selection_candidate.clone();
        let selection = grant.resource_selection.clone();
        let (resource_lease_binding, resource_lease) = match (&candidate, &selection) {
            (None, None) => (None, None),
            (Some(candidate), Some(selection)) => {
                let (binding, lease) = self.issue_native_resource_lease(
                    &current,
                    &request,
                    &grant,
                    selection,
                    candidate,
                )?;
                (Some(binding), Some(lease))
            }
            _ => return Err(BrokerError::NativeResourceSelectionBindingMismatch),
        };
        let process_operation_id = grant.approved.operation_id.clone();
        let process_generation = grant.approved.generation;
        let permit = permit_from_grant(&grant, &current, &request_digest);
        // The payload is handed over at the single preparation point and is
        // already inside `request_digest`, which `permit` and the durable cursor
        // both carry, so the bytes the provider retains here are the bytes the
        // idempotency key is bound to.
        let stdin_payload = request.stdin_payload.as_deref();
        let expected_process_request_digest = self
            .process
            .as_mut()
            .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?
            .prepare_start(&grant, &current, stdin_payload)
            .map_err(|error| map_port(RequiredProvider::P03Process, error))?;
        hex_digest(&expected_process_request_digest, "process_request_digest")?;
        let cursor = cursor_from_grant(
            &grant,
            &current,
            &request_digest,
            &expected_process_request_digest,
            &request,
            selection_input_digest.clone(),
            resource_lease.as_ref(),
            OperationState::Unknown,
        );
        let pending_record = OperationRecord {
            cursor: cursor.clone(),
            permit: permit.clone(),
            receipt: None,
        };
        self.operations.insert(
            request.approved.idempotency_key.clone(),
            pending_record.clone(),
        );
        // The Unknown cursor includes an optional lease. For a selected
        // boundary crossing its Reserved state is durable before the next
        // owner call; an ordinary launch retains no lease fields.
        self.persist()?;
        let resource_lease_receipt = match (
            resource_lease.as_ref(),
            resource_lease_binding.as_ref(),
            selection.as_ref(),
            candidate.as_ref(),
        ) {
            (Some(lease), Some(binding), Some(selection), Some(candidate)) => Some(
                self.consume_native_resource_lease(
                    &request.approved.idempotency_key,
                    &current,
                    selection,
                    candidate,
                    lease,
                    binding,
                )?,
            ),
            (None, None, None, None) => None,
            _ => return Err(BrokerError::NativeResourceSelectionBindingMismatch),
        };
        if let Some(selection) = selection.as_ref() {
            // Currentness is re-read again at the process-use boundary, after
            // the durable consumption receipt was published.
            let use_at = self.validate_live_native_resource_selection(selection)?;
            if resource_lease
                .as_ref()
                .is_some_and(|lease| use_at >= lease.expires_at)
            {
                return Err(BrokerError::NativeResourceLease(
                    NativeResourceLeaseError::Expired,
                ));
            }
        }
        let pending_record = self
            .operations
            .get(&request.approved.idempotency_key)
            .cloned()
            .ok_or(BrokerError::NativeResourceLease(NativeResourceLeaseError::Replay))?;
        let (start_result, lineage_status) = {
            let process = self
                .process
                .as_mut()
                .ok_or(BrokerError::PlanGap(RequiredProvider::P03Process))?;
            let start_result = process.start(&grant, &current, &expected_process_request_digest);
            let lineage_status = process.take_process_lineage_recovery_obligation();
            (start_result, lineage_status)
        };
        if let Some(candidate) = candidate.as_ref()
            && let Some(resolver) = self.native_resource_resolver.as_mut()
        {
            // Keep the retained no-follow handle chain until start has
            // returned. The resolver does not grant the child later pathname
            // access; this only closes the namespace race at the Broker's use
            // boundary.
            resolver.complete_use(&candidate.candidate_ref);
        }
        let lineage_recovery_required = lineage_status.unwrap_or(true);
        let mut observed_unknown_record = pending_record.clone();
        observed_unknown_record
            .cursor
            .process_lineage_recovery_required = lineage_recovery_required;
        let outcome = match start_result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.operations.insert(
                    request.approved.idempotency_key.clone(),
                    observed_unknown_record,
                );
                if self.persist().is_err() {
                    // Preserve the already-durable pre-effect Unknown cursor
                    // and its recovery obligation. The process result remains
                    // the result of the physical start call, never a second
                    // attempt caused by observation publication failure.
                    self.operations
                        .insert(request.approved.idempotency_key.clone(), pending_record);
                }
                return Err(if matches!(error, PortError::Unknown) {
                    BrokerError::UnknownOutcome
                } else {
                    map_port(RequiredProvider::P03Process, error)
                });
            }
        };
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
                self.operations.insert(
                    request.approved.idempotency_key.clone(),
                    observed_unknown_record.clone(),
                );
                if self.persist().is_err() {
                    self.operations
                        .insert(request.approved.idempotency_key.clone(), pending_record);
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
        verify_cursor_lineage(&observed_unknown_record.cursor, &view)?;
        let mut active_cursor = observed_unknown_record.cursor.clone();
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
            native_resource_lease_receipt: resource_lease_receipt,
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
                .insert(request.approved.idempotency_key, pending_record);
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
            schema_version: ISSUED_OPERATION_IDENTITY_VERSION,
            operation: operation.selector().to_owned(),
            // The registration lease is the control operation's deadline: a
            // cancellation or reconciliation is authorized no longer than the
            // lease that admitted it.
            deadline_unix_ms: current.expires_at,
            registration_digest: Some(current.registration_digest.clone()),
            user_broker_epoch: Some(current.user_broker_epoch),
            request_identity: None,
            request_id: format!("ub-ctl-{namespace}-{}", &canonical_digest[..32]),
            idempotency_key: format!("ub-ctl/{namespace}/{canonical_digest}"),
            cancellation_id: format!("ub-ctl-end-{namespace}-{}", &canonical_digest[..32]),
            issued_at_ms: observed_at,
            // No caller launch link: one target operation owns both a cancel
            // and a reconcile identity, so a single-valued caller link would
            // make the second one look like a conflicting reuse.
            caller_request_id: None,
            caller_idempotency_key: None,
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

    /// Returns the registration/cutover receipt this broker last published, or
    /// `None` when it has published none.
    ///
    /// The receipt is a durable record of a transition that did *not* complete.
    /// Its presence never means the candidate generation became active; see
    /// [`Self::publish_cutover_receipt`].
    #[must_use]
    pub fn cutover_receipt(&self) -> Option<&CutoverReceipt> {
        self.cutover_receipt.as_ref()
    }

    /// Publishes the durable registration/cutover receipt for the broker
    /// generation transition this lineage performed (I14.17:13).
    ///
    /// Both sides of the receipt are read from this broker's own record. The
    /// superseded side is the registration [`Self::register`] replaced and
    /// retired its operations against; the candidate side is the registration
    /// this process now holds. No caller input names a generation, an epoch, a
    /// fence or a job identity, so a receipt cannot be built around a
    /// transition this broker did not perform.
    ///
    /// **The cutover stops rather than completes.** Termination of the
    /// superseded generation's Job Object has no proof producer anywhere in
    /// this workspace, so the receipt records
    /// [`OldJobObjectTermination::Unproven`] and this call returns
    /// [`BrokerError::CutoverRequiresReconciliation`]: the candidate is not
    /// marked active, no new-generation effect authority follows from the
    /// publication, and the transition is left for reconciliation (I14.17:16).
    /// The `Ok` arm exists for the day a termination proof can actually be
    /// produced; until then it is unreachable by construction, because
    /// [`OldJobObjectTermination`] has exactly one inhabitant.
    ///
    /// The receipt is written durably *before* the refusal returns, so the
    /// refusal names a durable record a reader can inspect rather than an
    /// assertion they have to take on trust.
    ///
    /// Logout stops the publication outright. With no live lease over the
    /// admitted logon Session there is no Session to move a binding within, so
    /// [`Self::active_registration`] fails closed and no receipt is published.
    /// A replacement that did not move strictly forward inside one user
    /// Session is likewise refused, because a receipt about a lineage change
    /// this broker cannot prove it made would be a fiction.
    ///
    /// Pre-cutover operations are not adopted. Each one this transition
    /// retired is still named against the superseded registration, keeping the
    /// pin tuple that attributes it to the broker and epoch that launched it.
    pub fn publish_cutover_receipt(
        &mut self,
        observed_at: u64,
    ) -> Result<CutoverReceipt, BrokerError> {
        let current = self.active_registration(observed_at)?.clone();
        self.require_admitted_registration(&current)?;
        let old = self
            .predecessor_registration
            .as_ref()
            .ok_or(BrokerError::CutoverPrecondition(
                "no_superseded_registration",
            ))?
            .clone();
        if old.user_broker_epoch >= current.user_broker_epoch
            || old.installation_id != current.installation_id
            || old.windows_sid != current.windows_sid
            || old.interactive_session_id != current.interactive_session_id
            || old.boot_session_id != current.boot_session_id
        {
            return Err(BrokerError::CutoverPrecondition("predecessor_lineage"));
        }
        let session_binding_transfer = SessionBindingTransfer {
            old_binding: BrokerIndependentSessionBinding::of(&old),
            new_binding: BrokerIndependentSessionBinding::of(&current),
        };
        session_binding_transfer.validate()?;
        let receipt = CutoverReceipt {
            old_registration: old,
            new_registration: current,
            session_binding_transfer,
            operation_dispositions: self.cutover_operation_dispositions(),
            old_job_object_termination: OldJobObjectTermination::unproven(),
        };
        receipt.validate()?;
        // Durable before the refusal: a restart reconstructs the recorded
        // Session binding transfer and the pre-cutover dispositions from here
        // instead of losing them with the process.
        self.cutover_receipt = Some(receipt.clone());
        self.persist()?;
        Err(BrokerError::CutoverRequiresReconciliation(
            receipt.old_job_object_termination.reason().to_owned(),
        ))
    }

    /// The pre-cutover operations of the generation this one superseded, each
    /// with the pin tuple that keeps it attributed to the broker and epoch that
    /// launched it.
    ///
    /// Only operations whose tombstone still names the superseded
    /// registration are in flight for this transition. A tombstone left by an
    /// earlier transition already describes history this broker inherited, and
    /// an operation the superseded generation had already reconciled is
    /// reported with its final state rather than as in flight. The index is
    /// keyed by operation id, so the order is deterministic.
    fn cutover_operation_dispositions(&self) -> Vec<CutoverOperationDisposition> {
        let Some(old) = &self.predecessor_registration else {
            return Vec::new();
        };
        self.retired_operations
            .values()
            .filter(|row| row.registration_digest == old.registration_digest)
            .map(|row| CutoverOperationDisposition {
                operation_id: row.operation_id.clone(),
                request_digest: row.request_digest.clone(),
                registration_digest: row.registration_digest.clone(),
                user_broker_epoch: row.user_broker_epoch,
                state: row.state,
            })
            .collect()
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
                        Ok(Some(snapshot)) => {
                            matches!(self.snapshot(), Ok(expected) if expected == snapshot)
                        }
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

    fn snapshot(&self) -> Result<BrokerSnapshot, BrokerError> {
        Ok(BrokerSnapshot {
            registration: self.registration.clone(),
            user_broker_epoch: self.broker_epoch,
            operation_cursors: self
                .operations
                .values()
                .map(|record| record.cursor.clone())
                .collect(),
            operation_identities: self.projected_operation_identities()?,
            process_effect_lineage: self.projected_process_effect_lineage()?,
            retired_operations: self.retired_operations.values().cloned().collect(),
            predecessor_registration: self.predecessor_registration.clone(),
            cutover_receipt: self.cutover_receipt.clone(),
        })
    }

    /// Projects the durable identity ledger: everything recovered from the
    /// restart snapshot plus everything the composed issuer has issued since.
    ///
    /// A `request_id` can only appear in both halves when the live issuer
    /// resolved an exact retry of that same operation, and an exact retry
    /// carries byte-identical transport fields, so the live row is the same
    /// row. The recovered row is still kept when the composed ledger does not
    /// carry it, so attaching no ledger never erases durable history.
    fn projected_operation_identities(&self) -> Result<Vec<IssuedOperationIdentity>, BrokerError> {
        let mut projected = self.issued_operations.clone();
        let mut projected_bytes = 0_usize;
        for identity in projected.values() {
            let row_bytes = serde_json::to_vec(identity)
                .map_err(|error| BrokerError::Provider(error.to_string()))?
                .len();
            projected_bytes = projected_bytes
                .checked_add(row_bytes)
                .ok_or(BrokerError::InvalidField("operation_identity.capacity"))?;
        }
        if projected.len() > MAX_ISSUED_OPERATION_IDENTITIES
            || projected_bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES
        {
            return Err(BrokerError::InvalidField("operation_identity.capacity"));
        }
        if let Some(ledger) = self.identity_ledger.as_ref() {
            for identity in ledger.issued_operation_identities().map_err(|error| {
                BrokerError::Provider(format!("operation identity ledger unavailable: {error}"))
            })? {
                identity.validate()?;
                if let Some(retained) = projected.get(&identity.request_id) {
                    if retained != &identity {
                        return Err(BrokerError::InvalidField(
                            "operation_identity.duplicate_request_id_binding",
                        ));
                    }
                } else {
                    if projected.len() >= MAX_ISSUED_OPERATION_IDENTITIES {
                        return Err(BrokerError::InvalidField("operation_identity.capacity"));
                    }
                    let row_bytes = serde_json::to_vec(&identity)
                        .map_err(|error| BrokerError::Provider(error.to_string()))?
                        .len();
                    projected_bytes = projected_bytes
                        .checked_add(row_bytes)
                        .ok_or(BrokerError::InvalidField("operation_identity.capacity"))?;
                    if projected_bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES {
                        return Err(BrokerError::InvalidField("operation_identity.capacity"));
                    }
                    projected.insert(identity.request_id.clone(), identity);
                }
            }
        }
        Ok(projected.into_values().collect())
    }

    fn projected_process_effect_lineage(&self) -> Result<Vec<ProcessEffectLineage>, BrokerError> {
        let mut projected = self.process_effect_lineage.clone();
        let mut projected_bytes = 0_usize;
        for row in projected.values() {
            let row_bytes = serde_json::to_vec(row)
                .map_err(|error| BrokerError::Provider(error.to_string()))?
                .len();
            projected_bytes = projected_bytes
                .checked_add(row_bytes)
                .ok_or(BrokerError::InvalidField("process_effect_lineage.capacity"))?;
        }
        if projected.len() > MAX_PROCESS_EFFECT_LINEAGE_ENTRIES
            || projected_bytes > MAX_PROCESS_EFFECT_LINEAGE_BYTES
        {
            return Err(BrokerError::InvalidField("process_effect_lineage.capacity"));
        }
        if let Some(ledger) = self.identity_ledger.as_ref() {
            for relation in ledger.process_effect_lineage().map_err(|error| {
                BrokerError::Provider(format!("process effect lineage unavailable: {error}"))
            })? {
                relation.validate()?;
                let key = (
                    relation.caller_request_id.clone(),
                    relation.grant_request_digest.clone(),
                );
                if let Some(retained) = projected.get(&key) {
                    if retained != &relation {
                        return Err(BrokerError::InvalidField("process_effect_lineage.conflict"));
                    }
                    continue;
                }
                if projected.len() >= MAX_PROCESS_EFFECT_LINEAGE_ENTRIES {
                    return Err(BrokerError::InvalidField("process_effect_lineage.capacity"));
                }
                let row_bytes = serde_json::to_vec(&relation)
                    .map_err(|error| BrokerError::Provider(error.to_string()))?
                    .len();
                projected_bytes = projected_bytes
                    .checked_add(row_bytes)
                    .ok_or(BrokerError::InvalidField("process_effect_lineage.capacity"))?;
                if projected_bytes > MAX_PROCESS_EFFECT_LINEAGE_BYTES {
                    return Err(BrokerError::InvalidField("process_effect_lineage.capacity"));
                }
                projected.insert(key, relation);
            }
        }
        Ok(projected.into_values().collect())
    }

    fn persist(&mut self) -> Result<(), BrokerError> {
        let snapshot = self.snapshot()?;
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
    validate_resource_selection_binding(current, request, grant)?;
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
        &grant.resource_selection,
    ))?;
    if grant.grant_digest != expected {
        return Err(BrokerError::GrantBindingMismatch);
    }
    Ok(())
}

fn native_resource_lease_binding(
    registration: &RegistrationReceipt,
    request: &LaunchRequest,
    selection: &NativeResourceSelection,
    candidate: &NativeResourceSelectionCandidate,
) -> Result<NativeResourceLeaseBinding, BrokerError> {
    if !candidate.matches_selection(selection)
        || selection.resource_ref != request.approved.introduction.resource_ref
        || selection.principal_ref != registration.windows_sid
        || selection.interactive_session_id != registration.interactive_session_id
        || selection.request_ref != request.approved.request_id
        || selection.operation_ref != request.approved.operation_id.as_str()
        || selection.registration_ref != registration.registration_digest
        || selection.broker_epoch != registration.user_broker_epoch
        || selection.fence_id != registration.fence_id
        || !selection.authority_epoch.is_same_authority(&registration.authority_epoch)
    {
        return Err(BrokerError::NativeResourceSelectionBindingMismatch);
    }
    let binding = NativeResourceLeaseBinding {
        principal_ref: registration.windows_sid.clone(),
        issuer_process_ref: registration.broker_process_id.clone(),
        attempt_ref: selection.attempt_ref.clone(),
        request_ref: selection.request_ref.clone(),
        operation_ref: selection.operation_ref.clone(),
        candidate_ref: selection.candidate_ref.clone(),
        resource_ref: selection.resource_ref.clone(),
        scope_digest: selection.scope_digest.clone(),
        canonical_root_identity_digest: selection.canonical_root_identity_digest.clone(),
        resource_identity_digest: selection.canonical_resource_identity_digest.clone(),
        measurement_digest: selection.measurement_digest.clone(),
        resource_kind: selection.resource_kind,
        reparse_policy: selection.reparse_policy,
        network_policy: selection.network_policy,
        device_policy: selection.device_policy,
        state_fence: selection.state_fence.clone(),
        registration_ref: registration.registration_digest.clone(),
        broker_epoch: registration.user_broker_epoch,
        consumer_generation: selection.consumer_generation,
        authority_epoch: registration.authority_epoch.clone(),
    };
    binding
        .validate()
        .map_err(BrokerError::NativeResourceLease)?;
    Ok(binding)
}

fn validate_resource_selection_binding(
    current: &RegistrationReceipt,
    request: &LaunchRequest,
    grant: &LaunchGrant,
) -> Result<(), BrokerError> {
    match (
        request.resource_selection_candidate.as_ref(),
        grant.resource_selection.as_ref(),
    ) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(BrokerError::NativeResourceSelectionNotGranted),
        (None, Some(_)) => Err(BrokerError::NativeResourceSelectionNotRequested),
        (Some(candidate), Some(selection)) => {
            candidate
                .validate()
                .map_err(BrokerError::NativeResourceSelection)?;
            selection
                .validate()
                .map_err(BrokerError::NativeResourceSelection)?;
            if !candidate.matches_selection(selection)
                || selection.resource_ref != grant.approved.introduction.resource_ref
                || selection.principal_ref != current.windows_sid
                || selection.interactive_session_id != current.interactive_session_id
                || selection.request_ref != request.approved.request_id
                || selection.operation_ref != request.approved.operation_id.as_str()
                || selection.interactive_session_id != request.approved.session_id.as_str()
                || selection.registration_ref != current.registration_digest
                || selection.broker_epoch != current.user_broker_epoch
                || !selection.authority_epoch.is_same_authority(&current.authority_epoch)
                || selection.fence_id != current.fence_id
                || selection.consumer_generation != request.approved.generation.get()
                || selection.expires_at < grant.expires_at
                || selection.expires_at > current.expires_at
            {
                return Err(BrokerError::NativeResourceSelectionBindingMismatch);
            }
            Ok(())
        }
    }
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
    request: &LaunchRequest,
    selection_input_digest: Option<String>,
    native_resource_lease: Option<&NativeResourceLease>,
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
        native_resource_selection_candidate: request.resource_selection_candidate.clone(),
        selection_input_digest,
        native_resource_lease: native_resource_lease.cloned(),
        native_resource_lease_use_state: native_resource_lease
            .map(|_| NativeResourceLeaseUseState::Reserved),
        native_resource_lease_receipt: None,
        // Published with the Unknown cursor before physical start. It is
        // cleared only when the exact process lineage is retained durably.
        process_lineage_recovery_required: true,
        state,
    }
}

fn candidate_from_measurement(
    registration: &RegistrationReceipt,
    request: &LaunchRequest,
    measurement: NativeResourceObjectMeasurement,
    not_before: u64,
) -> Result<NativeResourceSelectionCandidate, BrokerError> {
    let measured_at = measurement
        .measured_at_unix_ms
        .ok_or(BrokerError::NativeResourceClockUnknown)?;
    if measured_at < not_before {
        return Err(BrokerError::NativeResourceStaleMeasurement);
    }
    if measurement.resource_kind == NativeResourceKind::Directory {
        return Err(BrokerError::NativeResourceDirectoryGenerationUnavailable);
    }
    if measurement.reparse_policy != NativeResourceReparsePolicy::Reject
        || measurement.network_policy != NativeResourceNetworkPolicy::LocalOnly
        || measurement.device_policy != NativeResourceDevicePolicy::Reject
    {
        return Err(BrokerError::NativeResourceResolution(
            NativeResourceResolutionError::Invalid(
                "selected object violates the admitted reparse, network, or device policy"
                    .to_owned(),
            ),
        ));
    }
    let candidate = NativeResourceSelectionCandidate {
        version: eliot_security_contracts::NATIVE_RESOURCE_SELECTION_CANDIDATE_VERSION,
        candidate_ref: measurement.candidate_ref,
        principal_ref: registration.windows_sid.clone(),
        interactive_session_id: registration.interactive_session_id.clone(),
        request_ref: request.approved.request_id.clone(),
        operation_ref: request.approved.operation_id.as_str().to_owned(),
        // The opaque ResourceRef comes from the request's admitted
        // introduction, but conveys no path or permission by itself. Kernel
        // must bind the exact candidate to that introduction before use.
        resource_ref: request.approved.introduction.resource_ref.clone(),
        canonical_root_identity_digest: measurement.canonical_root_identity_digest,
        canonical_resource_identity_digest: measurement.canonical_resource_identity_digest,
        measurement_digest: measurement.measurement_digest,
        resource_kind: measurement.resource_kind,
        reparse_policy: measurement.reparse_policy,
        network_policy: measurement.network_policy,
        device_policy: measurement.device_policy,
        registration_ref: registration.registration_digest.clone(),
        broker_epoch: registration.user_broker_epoch,
        fence_id: registration.fence_id.clone(),
        measured_at,
    };
    candidate
        .validate()
        .map_err(BrokerError::NativeResourceSelection)?;
    Ok(candidate)
}

fn map_native_resource_resolution(error: NativeResourceResolutionError) -> BrokerError {
    match error {
        NativeResourceResolutionError::Unavailable => {
            BrokerError::PlanGap(RequiredProvider::NativeResourceResolver)
        }
        NativeResourceResolutionError::Unknown => BrokerError::NativeResourceResolutionUnknown,
        NativeResourceResolutionError::Invalid(_) => BrokerError::NativeResourceResolution(
            NativeResourceResolutionError::Invalid("owner rejected the selected object".to_owned()),
        ),
        other => BrokerError::NativeResourceResolution(other),
    }
}

struct RestoredIdentityEvidence {
    issued_operations: BTreeMap<String, IssuedOperationIdentity>,
    process_effect_lineage: BTreeMap<(String, String), ProcessEffectLineage>,
}

fn restore_identity_evidence(
    operation_identities: Vec<IssuedOperationIdentity>,
    process_lineage_rows: Vec<ProcessEffectLineage>,
) -> Result<RestoredIdentityEvidence, BrokerError> {
    let mut issued_operations = BTreeMap::new();
    let mut issued_identity_bytes = 0_usize;
    for identity in operation_identities {
        identity.validate()?;
        if issued_operations.len() >= MAX_ISSUED_OPERATION_IDENTITIES {
            return Err(BrokerError::InvalidField("operation_identity.capacity"));
        }
        let row_bytes = serde_json::to_vec(&identity)
            .map_err(|error| BrokerError::Provider(error.to_string()))?
            .len();
        issued_identity_bytes = issued_identity_bytes
            .checked_add(row_bytes)
            .ok_or(BrokerError::InvalidField("operation_identity.capacity"))?;
        if issued_identity_bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES {
            return Err(BrokerError::InvalidField("operation_identity.capacity"));
        }
        if issued_operations
            .insert(identity.request_id.clone(), identity)
            .is_some()
        {
            return Err(BrokerError::Duplicate("operation_identity.request_id"));
        }
    }

    let mut process_effect_lineage = BTreeMap::new();
    let mut process_lineage_bytes = 0_usize;
    for relation in process_lineage_rows {
        relation.validate()?;
        let key = (
            relation.caller_request_id.clone(),
            relation.grant_request_digest.clone(),
        );
        if let Some(retained) = process_effect_lineage.get(&key) {
            if retained != &relation {
                return Err(BrokerError::InvalidField("process_effect_lineage.conflict"));
            }
            continue;
        }
        if process_effect_lineage.len() >= MAX_PROCESS_EFFECT_LINEAGE_ENTRIES {
            return Err(BrokerError::InvalidField("process_effect_lineage.capacity"));
        }
        let row_bytes = serde_json::to_vec(&relation)
            .map_err(|error| BrokerError::Provider(error.to_string()))?
            .len();
        process_lineage_bytes = process_lineage_bytes
            .checked_add(row_bytes)
            .ok_or(BrokerError::InvalidField("process_effect_lineage.capacity"))?;
        if process_lineage_bytes > MAX_PROCESS_EFFECT_LINEAGE_BYTES {
            return Err(BrokerError::InvalidField("process_effect_lineage.capacity"));
        }
        process_effect_lineage.insert(key, relation);
    }
    Ok(RestoredIdentityEvidence {
        issued_operations,
        process_effect_lineage,
    })
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
        if let Some(candidate) = &retired.native_resource_selection_candidate {
            candidate
                .validate()
                .map_err(BrokerError::NativeResourceSelection)?;
        }
        if let Some(selection_input_digest) = &retired.selection_input_digest {
            hex_digest(selection_input_digest, "retired_selection_input_digest")?;
        }
        if retired.native_resource_selection_candidate.is_some()
            != retired.selection_input_digest.is_some()
            || retired.native_resource_selection_candidate.is_some()
                != retired.native_resource_lease.is_some()
        {
            return Err(BrokerError::InvalidField(
                "retired_operation.native_resource_selection_binding",
            ));
        }
        validate_retained_native_resource_lease(
            retired.native_resource_lease.as_ref(),
            retired.native_resource_lease_use_state,
            retired.native_resource_lease_receipt.as_ref(),
            &NativeResourceLeaseOwner {
                operation_id: retired.operation_id.as_str(),
                registration_digest: &retired.registration_digest,
                user_broker_epoch: retired.user_broker_epoch,
                consumer_generation: None,
                authority_epoch: None,
                introduction: retired.introduction.as_ref(),
                candidate: retired.native_resource_selection_candidate.as_ref(),
            },
            "retired_operation.native_resource_lease",
        )?;
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

fn map_native_resource_currentness(error: BrokerError) -> BrokerError {
    match error {
        BrokerError::LeaseExpired
        | BrokerError::StaleEpoch
        | BrokerError::StaleRegistrationIdentity
        | BrokerError::RegistrationNotAdmitted
        | BrokerError::GrantBindingMismatch => {
            BrokerError::NativeResourceLease(NativeResourceLeaseError::Revoked)
        }
        other => other,
    }
}

fn map_native_resource_selection_currentness(error: PortError) -> BrokerError {
    match error {
        PortError::Denied => BrokerError::NativeResourceSelectionCurrentnessDenied,
        PortError::Unavailable => BrokerError::NativeResourceSelectionCurrentnessUnavailable,
        PortError::Unknown => BrokerError::NativeResourceSelectionCurrentnessUnknown,
        PortError::Invalid(_) => BrokerError::NativeResourceSelectionCurrentnessInvalid,
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
    #[error("Operator resource selection candidate has no owner-issued grant selection")]
    NativeResourceSelectionNotGranted,
    #[error("Kernel grant introduced a native resource selection the Operator did not request")]
    NativeResourceSelectionNotRequested,
    #[error("Kernel resource selection is not bound to the current candidate and registration")]
    NativeResourceSelectionBindingMismatch,
    #[error("invalid owner-issued native resource selection: {0}")]
    NativeResourceSelection(NativeResourceSelectionError),
    #[error("unauthenticated input supplied a Broker-owned selection candidate")]
    NativeResourceSelectionCandidateUntrusted,
    #[error("native resource selection owner is unavailable or rejected the request: {0}")]
    NativeResourceResolution(NativeResourceResolutionError),
    #[error("native resource resolver reported an unknown outcome")]
    NativeResourceResolutionUnknown,
    #[error("native resource owner clock is unavailable or invalid")]
    NativeResourceClockUnknown,
    #[error("native resource measurement is stale or temporally inconsistent")]
    NativeResourceStaleMeasurement,
    #[error("selected directory has no owner-issued generation measurement")]
    NativeResourceDirectoryGenerationUnavailable,
    #[error("Kernel could not confirm the current selected-resource fence")]
    NativeResourceSelectionCurrentnessUnavailable,
    #[error("Kernel denied current selected-resource authority")]
    NativeResourceSelectionCurrentnessDenied,
    #[error("Kernel current selected-resource outcome is unknown")]
    NativeResourceSelectionCurrentnessUnknown,
    #[error("Kernel current selected-resource response was invalid")]
    NativeResourceSelectionCurrentnessInvalid,
    #[error("invalid native resource lease: {0}")]
    NativeResourceLease(NativeResourceLeaseError),
    /// A cutover cannot be published because a precondition this broker holds
    /// no fact for is unmet. The reason names which one, so the refusal is
    /// never the generic recovery catch-all: a cutover with no live logon
    /// Session, no superseded registration of this lineage, or a predecessor
    /// that did not move strictly forward inside one user Session is a
    /// different condition from a malformed field and has to stay
    /// distinguishable.
    #[error("user broker cutover precondition unmet: {0}")]
    CutoverPrecondition(&'static str),
    /// The cutover stopped because termination of the superseded generation's
    /// Job Object is not proven, so the candidate is not marked active and the
    /// transition requires reconciliation (I14.17:16).
    #[error("user broker cutover requires reconciliation: {0}")]
    CutoverRequiresReconciliation(String),
    /// A cutover would have changed the recorded broker-independent Session
    /// binding instead of transferring it, so the transfer is refused rather
    /// than published as a cutover that changed which Session the broker serves.
    #[error("user broker cutover would have altered the recorded session binding")]
    SessionBindingNotTransferred,
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
    #[error("old Job Object termination is not proven; cutover requires reconciliation")]
    CutoverTerminationUnproven,
    #[error("logout stopped the broker cutover; it requires reconciliation")]
    CutoverStoppedByLogout,
    #[error("provider contract failure: {0}")]
    Provider(String),
}

/// Version of the User Broker-owned `OpenCode` bridge introduction (issue #2898).
pub const OPENCODE_BRIDGE_INTRODUCTION_VERSION: &str = "eliot.opencode.bridge-introduction.v1";
/// Closed capability: submit host-event observations through `/v1/host-events`.
pub const OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT: &str = "opencode.observation.submit";
/// Closed capability: request a pre-effect mutation-gate decision.
pub const OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE: &str = "opencode.mutation-gate.request";

/// Exact closed `OpenCode` bridge capabilities an introduction may grant.
pub const OPENCODE_BRIDGE_CAPABILITIES: [&str; 2] = [
    OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT,
    OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE,
];
/// Exact child environment name carrying the pinned bridge endpoint URL.
/// Read by the `OpenCode` plugin (`integrations/opencode/plugins/eliot.js`).
pub const OPENCODE_BRIDGE_ENV_URL: &str = "ELIOT_OPENCODE_BRIDGE_URL";
/// Exact child environment name carrying the protected bootstrap channel.
/// Consumed by the one-shot bootstrap transport; never a secret value.
pub const OPENCODE_BRIDGE_ENV_BOOTSTRAP: &str = "ELIOT_OPENCODE_BRIDGE_BOOTSTRAP";
/// Protected named-pipe channel served by the `OpenCode` one-shot bootstrap
/// authority (issue #2898, step 4). An introduction selects this transport by
/// carrying exactly this channel; `None` selects the exclusively pre-bound
/// listener path with bind-conflict refusal instead.
pub const OPENCODE_BOOTSTRAP_PIPE_NAME: &str = r"\\.\pipe\eliot\opencode\one-shot";
/// Time-to-live of one issued bootstrap ticket, in milliseconds. Mirrors the
/// Operator handoff TTL: a ticket is a single first-contact authenticator,
/// not a reconnect token or durable credential.
pub const OPENCODE_BOOTSTRAP_TTL_MS: u64 = 5_000;

/// Exact `OpenCode` process binding carried by one bridge introduction.
///
/// The introduction is materialized only to this process: the immutable
/// executable digest, the broker-minted launch nonce, and the User Broker
/// process that is its parent. A credential presented from any other process
/// is insufficient, even when the secret itself is valid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeProcessBinding {
    /// Lowercase SHA-256 hex of the exact approved `OpenCode` executable.
    pub executable_digest: String,
    /// Broker-minted launch nonce binding this introduction to one launch.
    pub launch_nonce: String,
    /// Process identity of the introducing User Broker (the exact parent).
    pub parent_broker_process_id: String,
}

impl OpenCodeProcessBinding {
    fn validate(&self) -> Result<(), BrokerError> {
        hex_digest(
            &self.executable_digest,
            "introduction.process_binding.executable_digest",
        )?;
        text(
            &self.launch_nonce,
            "introduction.process_binding.launch_nonce",
        )?;
        text(
            &self.parent_broker_process_id,
            "introduction.process_binding.parent_broker_process_id",
        )?;
        Ok(())
    }
}

/// Mint parameters for [`OpenCodeBridgeIntroduction`]. Every field is
/// broker-observed owner state; nothing is copied from `OpenCode` input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeIntroductionParams {
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub broker_generation: Generation,
    pub bridge_generation: Generation,
    /// Canonical pinned loopback endpoint (`http://127.0.0.1:<port>` or
    /// `http://[::1]:<port>`, explicit non-zero port, nothing else).
    pub endpoint: String,
    /// Opaque owner-minted server identity digest (lowercase SHA-256 hex)
    /// binding this introduction to one bridge incarnation.
    pub server_identity: String,
    /// Protected bootstrap channel (named-pipe name) when the installation
    /// uses pipe bootstrap; `None` selects the exclusively pre-bound
    /// listener path with bind-conflict refusal.
    pub bootstrap_channel: Option<String>,
    /// Opaque credential handle; raw secret material never appears here.
    pub credential: SecretRef,
    /// Absolute credential expiry in Unix milliseconds.
    pub credential_expires_at: u64,
    /// Exact closed capabilities granted (non-empty subset of
    /// [`OPENCODE_BRIDGE_CAPABILITIES`]).
    pub allowed_capabilities: Vec<String>,
    pub authority_epoch: EpochId,
    /// Live attach fence identity (the attach `FencingToken` nonce) as
    /// observed at mint. The ingress adapter requires an exact live match,
    /// so fence movement fails closed; the broker re-mints on rotation.
    pub fence_id: String,
    /// Absolute issue instant in Unix milliseconds.
    pub issued_at: u64,
    /// Absolute introduction expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Broker revocation-list key; rotation/revocation invalidates the
    /// introduction before any further request is admitted.
    pub revocation_id: String,
    pub process_binding: OpenCodeProcessBinding,
}

/// User Broker-owned introduction of one `OpenCode` bridge route (issue #2898,
/// step 2).
///
/// This is the only admitted client-identity path for `/v1/host-events`:
/// installation, Windows user/logon session, broker/bridge generations,
/// endpoint and server identity, credential [`SecretRef`], allowed
/// capabilities, issue/expiry/revocation facts, and the exact `OpenCode`
/// process binding. `ELIOT_*` environment entries may be a materialized
/// child projection of exactly this introduction; manually setting them is
/// not an admitted installation path and fails the server-side join.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeBridgeIntroduction {
    pub version: String,
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub broker_generation: Generation,
    pub bridge_generation: Generation,
    pub endpoint: String,
    pub server_identity: String,
    pub bootstrap_channel: Option<String>,
    pub credential: SecretRef,
    pub credential_expires_at: u64,
    pub allowed_capabilities: Vec<String>,
    pub authority_epoch: EpochId,
    /// Live attach fence identity (the attach `FencingToken` nonce) as
    /// observed at mint; the ingress adapter requires an exact live match.
    pub fence_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revocation_id: String,
    pub process_binding: OpenCodeProcessBinding,
    /// Lowercase SHA-256 hex over the canonical mint tuple, recomputed by
    /// [`OpenCodeBridgeIntroduction::validate`]; binds every field above.
    pub introduction_digest: String,
}

/// Broker-observed current-session facts for the introduction probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeSessionFacts {
    pub installation_id: String,
    pub windows_sid: String,
    pub interactive_session_id: String,
    pub broker_generation: Generation,
    pub bridge_generation: Generation,
    pub launch_nonce: String,
    pub executable_digest: String,
}

fn validate_opencode_endpoint(value: &str) -> Result<(), BrokerError> {
    const FIELD: &str = "introduction.endpoint";
    const PREFIX: &str = "http://";
    let authority = value
        .strip_prefix(PREFIX)
        .ok_or(BrokerError::InvalidField(FIELD))?;
    if authority.is_empty()
        || authority.contains(['@', '?', '#', '/', ' '])
        || authority.chars().any(char::is_control)
    {
        return Err(BrokerError::InvalidField(FIELD));
    }
    let port_text = if let Some(rest) = authority.strip_prefix("[::1]:") {
        if rest.is_empty() {
            return Err(BrokerError::InvalidField(FIELD));
        }
        rest
    } else if let Some(rest) = authority.strip_prefix("127.0.0.1:") {
        if rest.is_empty() {
            return Err(BrokerError::InvalidField(FIELD));
        }
        rest
    } else {
        return Err(BrokerError::InvalidField(FIELD));
    };
    if !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BrokerError::InvalidField(FIELD));
    }
    let port: u16 = port_text
        .parse()
        .map_err(|_| BrokerError::InvalidField(FIELD))?;
    if port == 0 {
        return Err(BrokerError::InvalidField(FIELD));
    }
    Ok(())
}

#[derive(Serialize)]
struct OpenCodeIntroductionDigest<'a> {
    version: &'a str,
    installation_id: &'a str,
    windows_sid: &'a str,
    interactive_session_id: &'a str,
    broker_generation: u64,
    bridge_generation: u64,
    endpoint: &'a str,
    server_identity: &'a str,
    bootstrap_channel: Option<&'a str>,
    credential_provider: &'a str,
    credential_key: &'a str,
    credential_expires_at: u64,
    allowed_capabilities: &'a [String],
    authority_epoch: &'a EpochId,
    fence_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    revocation_id: &'a str,
    executable_digest: &'a str,
    launch_nonce: &'a str,
    parent_broker_process_id: &'a str,
}

impl OpenCodeBridgeIntroduction {
    fn mint_digest(params: &OpenCodeIntroductionParams) -> Result<String, BrokerError> {
        digest(&OpenCodeIntroductionDigest {
            version: OPENCODE_BRIDGE_INTRODUCTION_VERSION,
            installation_id: params.installation_id.as_str(),
            windows_sid: params.windows_sid.as_str(),
            interactive_session_id: params.interactive_session_id.as_str(),
            broker_generation: params.broker_generation.get(),
            bridge_generation: params.bridge_generation.get(),
            endpoint: params.endpoint.as_str(),
            server_identity: params.server_identity.as_str(),
            bootstrap_channel: params.bootstrap_channel.as_deref(),
            credential_provider: params.credential.provider(),
            credential_key: params.credential.key(),
            credential_expires_at: params.credential_expires_at,
            allowed_capabilities: params.allowed_capabilities.as_slice(),
            authority_epoch: &params.authority_epoch,
            fence_id: params.fence_id.as_str(),
            issued_at: params.issued_at,
            expires_at: params.expires_at,
            revocation_id: params.revocation_id.as_str(),
            executable_digest: params.process_binding.executable_digest.as_str(),
            launch_nonce: params.process_binding.launch_nonce.as_str(),
            parent_broker_process_id: params.process_binding.parent_broker_process_id.as_str(),
        })
    }

    /// Mints one introduction from broker-observed owner state.
    ///
    /// Restart/rotation mints a new generation; the caller retires the old
    /// introduction (revocation list + generation switch) before the new one
    /// admits traffic, so a foreign or stale listener cannot inherit the
    /// route.
    pub fn mint(params: OpenCodeIntroductionParams) -> Result<Self, BrokerError> {
        if params.broker_generation.get() == 0 || params.bridge_generation.get() == 0 {
            return Err(BrokerError::InvalidField("introduction.generation"));
        }
        text(&params.installation_id, "introduction.installation_id")?;
        text(&params.windows_sid, "introduction.windows_sid")?;
        text(
            &params.interactive_session_id,
            "introduction.interactive_session_id",
        )?;
        validate_opencode_endpoint(&params.endpoint)?;
        hex_digest(&params.server_identity, "introduction.server_identity")?;
        if let Some(channel) = params.bootstrap_channel.as_deref() {
            text(channel, "introduction.bootstrap_channel")?;
        }
        if params.allowed_capabilities.is_empty()
            || params.allowed_capabilities.len() > OPENCODE_BRIDGE_CAPABILITIES.len()
        {
            return Err(BrokerError::InvalidField(
                "introduction.allowed_capabilities",
            ));
        }
        unique(
            &params.allowed_capabilities,
            "introduction.allowed_capabilities",
        )?;
        for capability in &params.allowed_capabilities {
            if !OPENCODE_BRIDGE_CAPABILITIES.contains(&capability.as_str()) {
                return Err(BrokerError::InvalidField(
                    "introduction.allowed_capabilities",
                ));
            }
        }
        text(&params.fence_id, "introduction.fence_id")?;
        text(&params.revocation_id, "introduction.revocation_id")?;
        if params.issued_at == 0 || params.expires_at <= params.issued_at {
            return Err(BrokerError::InvalidField("introduction.expires_at"));
        }
        if params.credential_expires_at <= params.issued_at
            || params.credential_expires_at > params.expires_at
        {
            return Err(BrokerError::InvalidField(
                "introduction.credential_expires_at",
            ));
        }
        params.process_binding.validate()?;
        let introduction_digest = Self::mint_digest(&params)?;
        Ok(Self {
            version: OPENCODE_BRIDGE_INTRODUCTION_VERSION.to_owned(),
            installation_id: params.installation_id,
            windows_sid: params.windows_sid,
            interactive_session_id: params.interactive_session_id,
            broker_generation: params.broker_generation,
            bridge_generation: params.bridge_generation,
            endpoint: params.endpoint,
            server_identity: params.server_identity,
            bootstrap_channel: params.bootstrap_channel,
            credential: params.credential,
            credential_expires_at: params.credential_expires_at,
            allowed_capabilities: params.allowed_capabilities,
            authority_epoch: params.authority_epoch,
            fence_id: params.fence_id,
            issued_at: params.issued_at,
            expires_at: params.expires_at,
            revocation_id: params.revocation_id,
            process_binding: params.process_binding,
            introduction_digest,
        })
    }

    /// Validates version, shape, issue/expiry window, and digest binding.
    ///
    /// Revocation is checked by the holder against the live revocation list,
    /// never from this value alone.
    pub fn validate(&self, now_ms: u64) -> Result<(), BrokerError> {
        if self.version != OPENCODE_BRIDGE_INTRODUCTION_VERSION {
            return Err(BrokerError::InvalidField("introduction.version"));
        }
        if self.broker_generation.get() == 0 || self.bridge_generation.get() == 0 {
            return Err(BrokerError::InvalidField("introduction.generation"));
        }
        text(&self.installation_id, "introduction.installation_id")?;
        text(&self.windows_sid, "introduction.windows_sid")?;
        text(
            &self.interactive_session_id,
            "introduction.interactive_session_id",
        )?;
        validate_opencode_endpoint(&self.endpoint)?;
        hex_digest(&self.server_identity, "introduction.server_identity")?;
        if let Some(channel) = self.bootstrap_channel.as_deref() {
            text(channel, "introduction.bootstrap_channel")?;
        }
        if self.allowed_capabilities.is_empty()
            || self.allowed_capabilities.len() > OPENCODE_BRIDGE_CAPABILITIES.len()
        {
            return Err(BrokerError::InvalidField(
                "introduction.allowed_capabilities",
            ));
        }
        unique(
            &self.allowed_capabilities,
            "introduction.allowed_capabilities",
        )?;
        for capability in &self.allowed_capabilities {
            if !OPENCODE_BRIDGE_CAPABILITIES.contains(&capability.as_str()) {
                return Err(BrokerError::InvalidField(
                    "introduction.allowed_capabilities",
                ));
            }
        }
        text(&self.fence_id, "introduction.fence_id")?;
        text(&self.revocation_id, "introduction.revocation_id")?;
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(BrokerError::InvalidField("introduction.expires_at"));
        }
        if self.credential_expires_at <= self.issued_at
            || self.credential_expires_at > self.expires_at
        {
            return Err(BrokerError::InvalidField(
                "introduction.credential_expires_at",
            ));
        }
        if now_ms < self.issued_at || now_ms >= self.expires_at {
            return Err(BrokerError::LeaseExpired);
        }
        if now_ms >= self.credential_expires_at {
            return Err(BrokerError::LeaseExpired);
        }
        self.process_binding.validate()?;
        hex_digest(
            &self.introduction_digest,
            "introduction.introduction_digest",
        )?;
        let params = OpenCodeIntroductionParams {
            installation_id: self.installation_id.clone(),
            windows_sid: self.windows_sid.clone(),
            interactive_session_id: self.interactive_session_id.clone(),
            broker_generation: self.broker_generation,
            bridge_generation: self.bridge_generation,
            endpoint: self.endpoint.clone(),
            server_identity: self.server_identity.clone(),
            bootstrap_channel: self.bootstrap_channel.clone(),
            credential: self.credential.clone(),
            credential_expires_at: self.credential_expires_at,
            allowed_capabilities: self.allowed_capabilities.clone(),
            authority_epoch: self.authority_epoch.clone(),
            fence_id: self.fence_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revocation_id: self.revocation_id.clone(),
            process_binding: self.process_binding.clone(),
        };
        let expected = Self::mint_digest(&params)?;
        if expected != self.introduction_digest {
            return Err(BrokerError::GrantBindingMismatch);
        }
        Ok(())
    }

    /// Returns whether the closed capability is granted by this introduction.
    #[must_use]
    pub fn allows(&self, capability: &str) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|granted| granted == capability)
    }

    /// Probes the introduction against live broker-observed session facts.
    ///
    /// Every field must match exactly: installation, SID, logon session,
    /// both generations, launch nonce, and executable digest. A valid
    /// secret from another process, session, or generation is insufficient.
    /// Rotation invalidates the old introduction before another request by
    /// retiring its generation/nonce from the observed facts.
    pub fn probe_current_session(
        &self,
        observed: &OpenCodeSessionFacts,
    ) -> Result<(), BrokerError> {
        if self.installation_id != observed.installation_id
            || self.windows_sid != observed.windows_sid
            || self.interactive_session_id != observed.interactive_session_id
            || self.broker_generation != observed.broker_generation
            || self.bridge_generation != observed.bridge_generation
            || self.process_binding.launch_nonce != observed.launch_nonce
            || self.process_binding.executable_digest != observed.executable_digest
        {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        Ok(())
    }

    /// Projects the exact child environment for the bound `OpenCode` process
    /// (issue #2898, step 3).
    ///
    /// The introduction is first revalidated at `now_ms` (version, shape,
    /// window, digest binding): an expired or tampered introduction never
    /// reaches a child map. The non-secret map carries only the pinned
    /// endpoint URL and, when the introduction selects pipe bootstrap, the
    /// protected channel name; the credential travels solely as the opaque
    /// [`SecretRef`] in `secret_refs`. [`EnvironmentProjection::new`]
    /// refuses secret-like names or values in the plain map, so the request
    /// credential (notably `ELIOT_OPENCODE_BRIDGE_TOKEN`) cannot be
    /// projected here: the admitted secret projection materializes it only
    /// into the exact approved child at spawn, and it stays out of durable
    /// registration, command lines, logs, route profiles, model context,
    /// and ordinary launch maps.
    pub fn child_environment_projection(
        &self,
        now_ms: u64,
    ) -> Result<EnvironmentProjection, BrokerError> {
        self.validate(now_ms)?;
        let mut non_secret = BTreeMap::new();
        non_secret.insert(OPENCODE_BRIDGE_ENV_URL.to_owned(), self.endpoint.clone());
        if let Some(channel) = self.bootstrap_channel.as_deref() {
            non_secret.insert(OPENCODE_BRIDGE_ENV_BOOTSTRAP.to_owned(), channel.to_owned());
        }
        EnvironmentProjection::new(
            non_secret,
            vec![self.credential.clone()],
            EnvironmentInheritance::None,
        )
        .map_err(|_| BrokerError::CredentialMaterialDisclosed("introduction.child_environment"))
    }
}

/// Single-use first-contact ticket redeemable on the protected
/// [`OPENCODE_BOOTSTRAP_PIPE_NAME`] channel (issue #2898, step 4).
///
/// The ticket names the exact bridge incarnation it introduces (endpoint,
/// generations, session, bound introduction digest) and carries one
/// broker-minted nonce. It contains no Bearer [REDACTED]: the pipe transport
/// authenticates the peer (SID/process/image/generation) against the bound
/// [`OpenCodeProcessBinding`] and yields the current HTTP endpoint plus the
/// one-use request credential through the owner's secret boundary only after
/// this ticket is consumed exactly once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeBootstrapTicket {
    pub pipe_name: String,
    pub broker_generation: u64,
    pub bridge_generation: u64,
    pub interactive_session_id: String,
    pub introduction_digest: String,
    pub endpoint: String,
    pub bootstrap_nonce: String,
}

impl OpenCodeBootstrapTicket {
    pub fn validate(&self) -> Result<(), BrokerError> {
        if self.pipe_name != OPENCODE_BOOTSTRAP_PIPE_NAME {
            return Err(BrokerError::InvalidField("bootstrap_ticket.pipe_name"));
        }
        if self.broker_generation == 0 || self.bridge_generation == 0 {
            return Err(BrokerError::InvalidField("bootstrap_ticket.generation"));
        }
        text(
            &self.interactive_session_id,
            "bootstrap_ticket.interactive_session_id",
        )?;
        hex_digest(
            &self.introduction_digest,
            "bootstrap_ticket.introduction_digest",
        )?;
        validate_opencode_endpoint(&self.endpoint)?;
        text(&self.bootstrap_nonce, "bootstrap_ticket.bootstrap_nonce")?;
        Ok(())
    }
}

/// Bootstrap request accepted by the authority. It deliberately names only
/// the bound introduction: endpoint, generations, session, channel, and
/// nonce are broker-selected, never caller-selected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeBootstrapRequest {
    pub introduction_digest: String,
}

/// Bound facts released to the pipe transport on exactly-once redemption.
///
/// The transport authenticates the peer against `process_binding`, then
/// yields `endpoint` plus the one-use request credential resolved through
/// the owner's secret boundary. The credential itself never appears here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeBootstrapGrant {
    pub introduction_digest: String,
    pub endpoint: String,
    pub server_identity: String,
    pub process_binding: OpenCodeProcessBinding,
}

/// One issued ticket: the exact ticket bytes it authenticates, its absolute
/// expiry, and whether it has already been redeemed.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BootstrapTicketState {
    ticket: OpenCodeBootstrapTicket,
    expires_at: u64,
    consumed: bool,
}

/// Physical User Broker secret boundary for one `OpenCode` route
/// (issue #2898, step 3).
///
/// The broker — and only the broker process that owns the physical launch —
/// implements this: it resolves the introduction's opaque [`SecretRef`] to its
/// short-lived bytes. The registry hands the resolved value to exactly one
/// approved consumer, the bound `OpenCode` process, and never places the raw
/// bytes in a durable registration, command line, log, route profile, model
/// context or ordinary non-secret launch map.
pub trait OpenCodeSecretBoundary {
    /// Resolution failure. Carries no secret material.
    type Error: std::error::Error + Send + 'static;

    /// Resolves one opaque handle to the current short-lived secret bytes.
    fn resolve_secret(&self, handle: &SecretRef) -> Result<Box<str>, Self::Error>;
}

/// The User Broker's current `OpenCode` bridge introductions and their
/// generation/revocation state (issue #2898, steps 3 and 14).
///
/// Installing a new introduction retires the previous one's revocation id
/// and its credential handle *together*, so restart/rotation mints a new
/// generation and the old material stops resolving the moment the new one is
/// installed. A revoked introduction is refused even while it is still
/// installed and inside its window; [`OpenCodeBridgeIntroductionRegistry::revoke`]
/// and [`OpenCodeBridgeIntroductionRegistry::clear`] cover logout, listener
/// death and bridge restart.
#[derive(Clone, Debug, Default)]
pub struct OpenCodeBridgeIntroductionRegistry {
    current: Option<OpenCodeBridgeIntroduction>,
    retired_revocation_ids: BTreeSet<String>,
    retired_credentials: BTreeSet<(String, String)>,
}

impl OpenCodeBridgeIntroductionRegistry {
    /// Creates an empty registry: no route is introduced until
    /// [`OpenCodeBridgeIntroductionRegistry::install`] runs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the current introduction, retiring the replaced entry.
    ///
    /// The replaced introduction's revocation id and its credential handle are
    /// retired in the same step, so the old generation can neither be admitted
    /// nor have its secret resolved after the rotation. Revoking by
    /// `revocation_id` is a *name* match, so it is performed only against the
    /// introduction this registry actually held — a caller-supplied id that
    /// was never installed is never "revoked" on the basis of its name.
    pub fn install(&mut self, introduction: OpenCodeBridgeIntroduction) {
        if let Some(previous) = self.current.replace(introduction) {
            self.retire(&previous);
        }
    }

    /// Retires the current introduction's material without installing a
    /// replacement (logout, listener death, bridge restart).
    pub fn clear(&mut self) {
        if let Some(previous) = self.current.take() {
            self.retire(&previous);
        }
    }

    /// Retires one named introduction. An id this registry never installed
    /// has no material to retire and is recorded as already retired, so a
    /// later install of that same generation still fails closed.
    pub fn revoke(&mut self, revocation_id: &str) {
        // The named introduction is taken only when it is the one this
        // registry actually holds, so a revocation never retires material by
        // name alone.
        if let Some(previous) = self.current.as_ref()
            && previous.revocation_id == revocation_id
        {
            if let Some(previous) = self.current.take() {
                self.retire(&previous);
            }
            return;
        }
        self.retired_revocation_ids.insert(revocation_id.to_owned());
    }

    /// Returns the current introduction, or `None` when the route is not
    /// presently introduced (fail closed).
    #[must_use]
    pub fn current(&self) -> Option<&OpenCodeBridgeIntroduction> {
        self.current.as_ref()
    }

    /// Returns whether one revocation id is retired.
    #[must_use]
    pub fn is_revoked(&self, revocation_id: &str) -> bool {
        self.retired_revocation_ids.contains(revocation_id)
            || self
                .current
                .as_ref()
                .is_some_and(|introduction| introduction.revocation_id == revocation_id)
    }

    /// Resolves the current introduction's credential handle through the
    /// broker's own secret boundary.
    ///
    /// Refuses when the route is unintroduced or the handle belongs to a
    /// retired generation, so a rotated credential never resolves even if a
    /// stale introduction is still in hand. The returned bytes go only to the
    /// exact approved `OpenCode` process.
    pub fn resolve_current_credential<S>(&self, boundary: &S) -> Result<Box<str>, BrokerError>
    where
        S: OpenCodeSecretBoundary<Error = BrokerError>,
    {
        let introduction = self
            .current
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        let key = (
            introduction.credential.provider().to_owned(),
            introduction.credential.key().to_owned(),
        );
        if self.retired_credentials.contains(&key) {
            return Err(BrokerError::StaleLease);
        }
        boundary.resolve_secret(&introduction.credential)
    }

    /// Retires the introduction's revocation id and its credential handle.
    fn retire(&mut self, introduction: &OpenCodeBridgeIntroduction) {
        self.retired_revocation_ids
            .insert(introduction.revocation_id.clone());
        self.retired_credentials.insert((
            introduction.credential.provider().to_owned(),
            introduction.credential.key().to_owned(),
        ));
    }
}

/// One-shot User Broker bootstrap authority for the `OpenCode` bridge route.
///
/// Mirrors [`OperatorHandoffAuthority`]: owner-issued, generation-bound,
/// expiring, single-use tickets. The authority is bound to exactly one
/// introduction (digest, endpoint, server identity, generations, session,
/// process binding); a request naming any other introduction is denied, and
/// a redeemed or expired ticket can never be reused. Peer authentication
/// and the one-use credential yield are the pipe transport's job behind this
/// redemption — this crate holds no Windows, process, or credential
/// implementation.
#[derive(Clone, Debug)]
pub struct OpenCodeBootstrapAuthority {
    introduction_digest: String,
    endpoint: String,
    server_identity: String,
    broker_generation: u64,
    bridge_generation: u64,
    interactive_session_id: String,
    process_binding: OpenCodeProcessBinding,
    credential: SecretRef,
    tickets: BTreeMap<String, BootstrapTicketState>,
}

impl OpenCodeBootstrapAuthority {
    /// Binds the authority to one pipe-bootstrap introduction.
    ///
    /// The introduction must select exactly [`OPENCODE_BOOTSTRAP_PIPE_NAME`]:
    /// an introduction without a bootstrap channel (or with any other
    /// channel) takes the exclusively pre-bound listener path instead and is
    /// refused here.
    pub fn new(introduction: &OpenCodeBridgeIntroduction) -> Result<Self, BrokerError> {
        if introduction.bootstrap_channel.as_deref() != Some(OPENCODE_BOOTSTRAP_PIPE_NAME) {
            return Err(BrokerError::InvalidField("introduction.bootstrap_channel"));
        }
        if introduction.broker_generation.get() == 0 || introduction.bridge_generation.get() == 0 {
            return Err(BrokerError::InvalidField("introduction.generation"));
        }
        text(
            &introduction.interactive_session_id,
            "introduction.interactive_session_id",
        )?;
        hex_digest(
            &introduction.introduction_digest,
            "introduction.introduction_digest",
        )?;
        validate_opencode_endpoint(&introduction.endpoint)?;
        hex_digest(
            &introduction.server_identity,
            "introduction.server_identity",
        )?;
        introduction.process_binding.validate()?;
        Ok(Self {
            introduction_digest: introduction.introduction_digest.clone(),
            endpoint: introduction.endpoint.clone(),
            server_identity: introduction.server_identity.clone(),
            broker_generation: introduction.broker_generation.get(),
            bridge_generation: introduction.bridge_generation.get(),
            interactive_session_id: introduction.interactive_session_id.clone(),
            process_binding: introduction.process_binding.clone(),
            credential: introduction.credential.clone(),
            tickets: BTreeMap::new(),
        })
    }

    /// Mints one owner-issued, generation-bound, expiring, single-use
    /// [`OpenCodeBootstrapTicket`].
    ///
    /// The nonce is minted here, never taken from `request`: the request
    /// shape carries no nonce, channel, endpoint, or timestamp field, so a
    /// caller cannot choose the authenticator or pre-claim an expiry. A
    /// request naming a foreign introduction digest fails closed through
    /// [`BrokerError::Denied`].
    pub fn issue(
        &mut self,
        request: &OpenCodeBootstrapRequest,
        observed_at: u64,
    ) -> Result<OpenCodeBootstrapTicket, BrokerError> {
        if request.introduction_digest != self.introduction_digest || observed_at == 0 {
            return Err(BrokerError::Denied);
        }
        let expires_at = observed_at
            .checked_add(OPENCODE_BOOTSTRAP_TTL_MS)
            .ok_or(BrokerError::Denied)?;
        let nonce = Uuid::new_v4().simple().to_string();
        text(&nonce, "bootstrap_nonce")?;
        let ticket = OpenCodeBootstrapTicket {
            pipe_name: OPENCODE_BOOTSTRAP_PIPE_NAME.to_owned(),
            broker_generation: self.broker_generation,
            bridge_generation: self.bridge_generation,
            interactive_session_id: self.interactive_session_id.clone(),
            introduction_digest: self.introduction_digest.clone(),
            endpoint: self.endpoint.clone(),
            bootstrap_nonce: nonce.clone(),
        };
        ticket.validate()?;
        if self.tickets.contains_key(&nonce) {
            return Err(BrokerError::ReplayConflict);
        }
        self.tickets.insert(
            nonce,
            BootstrapTicketState {
                ticket: ticket.clone(),
                expires_at,
                consumed: false,
            },
        );
        Ok(ticket)
    }

    /// Redeems one ticket exactly once and returns the bound grant.
    ///
    /// A second presentation of a consumed nonce, a ticket whose bound
    /// session/generations/nonce does not match the issued row, and a ticket
    /// past its expiry are distinct refusals — [`BrokerError::ReplayConflict`]
    /// and [`BrokerError::StaleLease`] — so first contact can never be
    /// inferred from replaying a previous ticket and a competing loopback
    /// listener gains no reusable secret from it.
    pub fn consume(
        &mut self,
        ticket: &OpenCodeBootstrapTicket,
        now: u64,
    ) -> Result<OpenCodeBootstrapGrant, BrokerError> {
        self.redeem_once(ticket, now)
    }

    /// Redeems one ticket exactly once and yields the current HTTP endpoint
    /// plus the one-use request credential (issue #2898, step 4).
    ///
    /// The credential is resolved through the broker's own secret boundary
    /// only *after* the ticket is consumed exactly once, so the protected
    /// named-pipe transport has already authenticated the peer SID, process,
    /// image and generation against the bound [`OpenCodeProcessBinding`]
    /// before any protected byte is disclosed. A replayed, mismatched or
    /// expired ticket never reaches the boundary. The yielded credential is
    /// the current generation's short-lived secret and travels on the
    /// protected channel only; it is never written to a durable registration,
    /// command line, log, route profile or non-secret launch map.
    pub fn consume_with_credential<S>(
        &mut self,
        ticket: &OpenCodeBootstrapTicket,
        now: u64,
        boundary: &S,
    ) -> Result<OpenCodeOneUseIntroduction, BrokerError>
    where
        S: OpenCodeSecretBoundary<Error = BrokerError>,
    {
        let grant = self.redeem_once(ticket, now)?;
        let credential = boundary.resolve_secret(&self.credential)?;
        Ok(OpenCodeOneUseIntroduction {
            introduction_digest: grant.introduction_digest,
            endpoint: grant.endpoint,
            server_identity: grant.server_identity,
            process_binding: grant.process_binding,
            credential,
        })
    }

    /// Performs the exactly-once redemption and returns the bound grant. The
    /// ticket is validated against the issued row, marked consumed, and only
    /// then are the bound facts released.
    fn redeem_once(
        &mut self,
        ticket: &OpenCodeBootstrapTicket,
        now: u64,
    ) -> Result<OpenCodeBootstrapGrant, BrokerError> {
        ticket.validate()?;
        {
            let state = self
                .tickets
                .get_mut(&ticket.bootstrap_nonce)
                .ok_or(BrokerError::ReplayConflict)?;
            if state.consumed || now >= state.expires_at || state.ticket != *ticket {
                return Err(if now >= state.expires_at {
                    BrokerError::StaleLease
                } else {
                    BrokerError::ReplayConflict
                });
            }
            state.consumed = true;
        }
        Ok(OpenCodeBootstrapGrant {
            introduction_digest: self.introduction_digest.clone(),
            endpoint: self.endpoint.clone(),
            server_identity: self.server_identity.clone(),
            process_binding: self.process_binding.clone(),
        })
    }
}

/// The one-use client introduction released by exactly-once bootstrap
/// redemption (issue #2898, step 4).
///
/// The first protected contact yields the current HTTP endpoint and the
/// current generation's request credential, released only after the pipe
/// transport authenticated the peer against the bound
/// [`OpenCodeProcessBinding`]. The credential is a short-lived generation
/// value: rotation replaces it, and the previous one is revoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenCodeOneUseIntroduction {
    /// Introduction digest this grant belongs to.
    pub introduction_digest: String,
    /// Current pinned loopback endpoint.
    pub endpoint: String,
    /// Owner-minted server identity digest of that bridge incarnation.
    pub server_identity: String,
    /// Exact approved `OpenCode` process the peer was authenticated as.
    pub process_binding: OpenCodeProcessBinding,
    /// The current short-lived request credential. Never logged or persisted.
    pub credential: Box<str>,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Issue #1954 — I14.17 immutable per-generation User Broker cutover.
//
// I14.17 requires a User Broker binary to be immutable per generation and
// never replaced in place in a logged-on session: a candidate starts with no
// launch/effect authority, authenticates its SID/session/artifact and EBP
// contract, receives a higher/new-lineage `UserBrokerEpoch`, fences the old
// registration from new launches, transfers only explicit broker-independent
// Session bindings, drains/reconciles the old exact operations, terminates the
// old Job Object, and only then publishes the registration/cutover receipt.
//
// Every guarantee below is a *comparison* against recorded state, never a
// recorded fact alone: activation requires a positive termination proof, and
// a new launch is admitted only through the candidate's own registration
// receipt, compared against the recorded one by the existing
// [`BrokerAdmissionIdentity::admits`].
// ---------------------------------------------------------------------------

/// The typed User Broker epoch identity (I14.17 "higher/new-lineage
/// `UserBrokerEpoch`").
///
/// The broker-local epoch used to be a bare `u64` scalar, which cannot express
/// "strictly higher" together with "or globally distinct when a shared maximum
/// cannot be demonstrated" (A13.7). This is the lineage-aware replacement: two
/// epochs are comparable only within one lineage, and a cutover epoch must be
/// a strictly higher sequence of the recorded epoch or a *different* lineage.
/// Equal sequences from different lineages are unrelated, never ordered, so a
/// new lineage is a genuinely new identity rather than a reset counter.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserBrokerEpoch {
    pub lineage_id: EpochLineageId,
    pub sequence: NonZeroU64,
}

impl UserBrokerEpoch {
    /// Constructs a typed epoch without exposing scalar coercion.
    pub fn new(lineage_id: EpochLineageId, sequence: NonZeroU64) -> Result<Self, BrokerError> {
        Ok(Self {
            lineage_id,
            sequence,
        })
    }

    /// Returns whether this epoch supersedes `prior` for a cutover.
    ///
    /// Two disjoint lineages are globally distinct, so any sequence in a new
    /// lineage is a valid successor (A13.7: "The new Authority Epoch lineage
    /// must be strictly newer than every observed value, or globally distinct
    /// when a shared maximum cannot be demonstrated"). Within one lineage the
    /// successor must be strictly higher, so the identical epoch, an older
    /// one, and a re-mint of the same sequence are all rejected.
    #[must_use]
    pub fn supersedes(&self, prior: &Self) -> bool {
        if self.lineage_id != prior.lineage_id {
            return true;
        }
        self.sequence > prior.sequence
    }

    fn validate(&self) -> Result<(), BrokerError> {
        text(self.lineage_id.as_str(), "user_broker_epoch.lineage_id")?;
        Ok(())
    }
}

/// One immutable candidate registration (I14.17 "immutable broker artifact
/// identity, generation, authenticated SID/session identity, EBP contract
/// version, Job Object identity, and `UserBrokerEpoch`").
///
/// Every field is a comparison target, not a label.  A candidate is
/// authenticated by comparing each of them against what the old registration
/// recorded, so a candidate claiming a different principal, a different
/// session, a replaced binary, or a different contract cannot be activated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCandidateRegistration {
    /// The candidate's own sealed registration receipt.  After cutover this is
    /// the only thing that may admit a new launch.
    pub registration: RegistrationReceipt,
    /// Immutable broker artifact identity of the candidate binary.  I14.17
    /// forbids replacing a broker in place, so this must differ from the
    /// artifact the old generation registered with.
    pub broker_artifact_digest: String,
    /// The candidate's broker generation: registry state over an immutable
    /// artifact (I14.14 "Running artifacts are immutable. Active generation is
    /// registry state.").  It must be strictly higher than the old generation.
    pub broker_generation: Generation,
    /// The typed epoch minted for the candidate at the generation transition.
    pub user_broker_epoch: UserBrokerEpoch,
    /// The EBP contract version the candidate was verified against.
    pub ebp_contract_version: ProtocolVersion,
    /// The Kernel/N4-owned Job contour identity the candidate's children run
    /// under.  It is the *new* contour; the old one is what must be proven
    /// terminated.
    pub job_id: JobId,
}

impl BrokerCandidateRegistration {
    fn validate(&self) -> Result<(), BrokerError> {
        self.registration.validate_shape()?;
        hex_digest(
            &self.broker_artifact_digest,
            "candidate.broker_artifact_digest",
        )?;
        if self.broker_generation.get() == 0 {
            return Err(BrokerError::InvalidField("candidate.broker_generation"));
        }
        self.user_broker_epoch.validate()?;
        self.ebp_contract_version
            .validate()
            .map_err(|error| BrokerError::Provider(error.to_string()))?;
        text(self.job_id.as_str(), "candidate.job_id")?;
        Ok(())
    }
}

/// One session binding, classified for cutover (I14.17 "transfer only explicit
/// broker-independent Session bindings").
///
/// The classification is explicit and recorded.  A broker-*dependent* binding —
/// one whose continued validity depends on the old broker's own authority,
/// its introduced resources, or its Job contour — is never transferred; it is
/// carried in [`BrokerCutoverReceipt::untransferred_bindings`] so a reader sees
/// it was deliberately left behind rather than silently dropped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBindingRecord {
    /// Stable identity of the session binding being classified.
    pub binding_id: String,
    /// The interactive logon Session this binding belongs to.
    pub interactive_session_id: String,
    /// Whether this binding survives the cutover on its own.
    pub broker_independent: bool,
}

/// The exact in-flight disposition an old-generation operation receives at
/// cutover (I14.14 "In-flight disposition").
///
/// Every accepted request records its generation, operation identity, effect
/// set and State Fence, and at cutover it receives *exactly one* disposition.
/// The variant names and meanings below are I14.14's, unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InFlightDisposition {
    /// read/stream may finish while its input fence remains valid.
    DrainRead,
    /// only the already admitted operation may finish under a committed
    /// `OperationContinuationPermit`; this is not general old-generation
    /// authority.
    FinishExactAuthorizedOperation,
    /// candidate resumes from a compatible checkpoint under a new
    /// attempt/generation receipt.
    CheckpointTransfer,
    /// cancellation is accepted only when no external/canonical effect is
    /// proven.
    CancelProvenNoEffect,
    /// outcome is unresolved; conflicting new effects in the affected scope
    /// remain blocked until receipt/probe/reconciliation resolves it.
    BlockScopeUnknownOutcome,
}

impl InFlightDisposition {
    /// Returns whether this disposition leaves the old operation *inside* the
    /// old Job contour, and therefore blocks activation.
    ///
    /// `drain_read` may still finish, and
    /// `block_scope_unknown_outcome` is unresolved by definition; both keep
    /// the old contour alive.  Only the three dispositions that resolve the
    /// operation's outcome release it.  This is a property of the disposition
    /// alone — a machine that records a resolving disposition for an operation
    /// that is actually still `Unknown` is refused by
    /// [`OldJobObjectTerminationProof::proves_termination`].
    #[must_use]
    pub const fn blocks_old_termination(self) -> bool {
        matches!(self, Self::DrainRead | Self::BlockScopeUnknownOutcome)
    }
}

/// One old-generation operation with its committed disposition and the state
/// observed for it at cutover commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightOperation {
    pub operation_id: OperationId,
    pub disposition: InFlightDisposition,
    /// Terminal state observed for this operation at the cutover commit.
    pub state: OperationState,
}

/// The proof that the old generation's Job Object is really gone.
///
/// This is deliberately not "a termination was requested".  It is the
/// conjunction of three independently checked facts: the old Job contour is the
/// exact one the old registration recorded (ownership, not a matching name),
/// the operation set it names is exactly the broker's own lineage for that
/// registration (coverage, not a subset), and every one of those operations
/// reached a state that cannot still produce an effect.  A refused, empty, or
/// mismatched proof leaves the candidate inactive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OldJobObjectTerminationProof {
    /// The old Job contour identity this proof claims to have terminated.  It
    /// must equal the `job_id` the old registration recorded.
    pub job_id: JobId,
    /// The old registration digest whose children were terminated.
    pub old_registration_digest: String,
    /// Every old-generation operation observed in the Job contour, with its
    /// committed disposition and observed state.
    pub operations: Vec<InFlightOperation>,
}

impl OldJobObjectTerminationProof {
    /// Verifies that this proof actually proves termination of the old Job
    /// Object.
    ///
    /// 1. **Ownership** — `job_id` and `old_registration_digest` must be the
    ///    exact contour and registration the recorded old registration owned.
    ///    A proof for any other contour is not a proof about this one, however
    ///    similar its name.
    /// 2. **Coverage** — the proof lists exactly the operation identities the
    ///    broker's own lineage holds for that registration: no omission (an
    ///    unlisted child may still be running) and no extra identity (an
    ///    operation the broker never owned proves nothing about this contour).
    /// 3. **Terminality** — every listed operation's disposition releases the
    ///    old contour *and* its observed state is not `Unknown`.  An
    ///    unproven outcome is exactly the case I14.17 says must stop cutover.
    fn proves_termination(
        &self,
        old_registration: &RegisteredGeneration,
        old_operation_ids: &BTreeSet<OperationId>,
    ) -> Result<(), BrokerError> {
        if self.old_registration_digest != old_registration.registration.registration_digest
            || self.job_id != old_registration.job_id
        {
            return Err(BrokerError::CutoverTerminationUnproven);
        }
        let mut claimed = BTreeSet::new();
        for operation in &self.operations {
            if operation.state == OperationState::Unknown
                || operation.disposition.blocks_old_termination()
            {
                return Err(BrokerError::CutoverTerminationUnproven);
            }
            if !claimed.insert(operation.operation_id.clone()) {
                return Err(BrokerError::Duplicate("cutover.operation_id"));
            }
        }
        let expected = old_operation_ids;
        if expected.len() != claimed.len() || !expected.iter().all(|id| claimed.contains(id)) {
            return Err(BrokerError::CutoverTerminationUnproven);
        }
        Ok(())
    }
}

/// The state of one candidate's cutover (I14.17 cutover states).
///
/// The order encodes the contract: a candidate reaches `Active` only by
/// passing through authentication, fencing, binding transfer, and a *proven*
/// old Job Object termination.  `ReconciliationRequired` is the rest state for
/// a cutover that cannot prove termination or that observed a logout, and the
/// candidate is never active there.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BrokerCutoverState {
    /// Candidate artifact and authorization policy are staged.  The candidate
    /// holds no launch/effect authority.
    CandidateStaged,
    /// SID/session/artifact and EBP contract are verified and a
    /// strictly higher/new-lineage epoch has been issued.  Still no launch
    /// authority.
    CandidateAuthenticated,
    /// The old registration is fenced from new launches.
    OldRegistrationFenced,
    /// Explicit broker-independent session bindings have been transferred.
    BindingsTransferred,
    /// A termination was requested for the old Job Object but has not been
    /// *proven*.  The candidate is still not active.
    TerminationRequested,
    /// Termination is proven and the candidate is marked active.
    Active,
    /// Logout, or an unprovable old Job Object termination, stopped the
    /// cutover.  Reconciliation is required and the candidate is not active.
    ReconciliationRequired,
}

/// The durable receipt a committed cutover publishes (I14.17 "publish
/// registration/cutover receipt"; I14.14 `GenerationCutoverReceipt`).
///
/// It records the old and new generation and epoch, which session bindings
/// transferred and which did not, the disposition of every old in-flight
/// operation, and the proof that the old Job Object was terminated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCutoverReceipt {
    /// Terminal state of the cutover this receipt closes.
    pub state: BrokerCutoverState,
    /// The fenced old registration digest.
    pub old_registration_digest: String,
    /// The old broker generation that stopped admitting new launches.
    pub old_broker_generation: Generation,
    /// The old broker-local epoch, kept as the exact value it had.
    pub old_user_broker_epoch: u64,
    /// The candidate registration digest that owns new launches.
    pub new_registration_digest: String,
    /// The candidate broker generation.
    pub new_broker_generation: Generation,
    /// The typed epoch issued to the candidate.
    pub new_user_broker_epoch: UserBrokerEpoch,
    /// Bindings deliberately moved to the candidate.
    pub transferred_bindings: Vec<SessionBindingRecord>,
    /// Broker-dependent bindings that stayed with the old generation.  They
    /// are recorded as untransferred rather than dropped.
    pub untransferred_bindings: Vec<SessionBindingRecord>,
    /// Every old-generation in-flight operation with its exact disposition.
    pub operation_dispositions: Vec<InFlightOperation>,
    /// Proof that the old Job Object was terminated.  `None` only when the
    /// state is `ReconciliationRequired`, and then the candidate is not active.
    pub old_job_object_termination: Option<OldJobObjectTerminationProof>,
}

/// One registered broker generation: its sealed registration plus the two
/// identities that a generation transition must compare against — the
/// immutable artifact it is running and the Job contour its children run in.
///
/// A [`RegistrationReceipt`] deliberately does not carry the Job contour, and
/// the admission tuple does not carry the broker generation, so the registry
/// holds this pair rather than inventing a second admission rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredGeneration {
    pub registration: RegistrationReceipt,
    pub broker_artifact_digest: String,
    pub broker_generation: Generation,
    /// The EBP contract version this generation registered with.  The
    /// registration receipt does not carry it, so the registry holds it
    /// explicitly as the value a candidate's contract is compared against.
    pub ebp_contract_version: ProtocolVersion,
    pub job_id: JobId,
}

impl RegisteredGeneration {
    fn validate(&self) -> Result<(), BrokerError> {
        self.registration.validate_shape()?;
        hex_digest(
            &self.broker_artifact_digest,
            "registered_generation.broker_artifact_digest",
        )?;
        if self.broker_generation.get() == 0 {
            return Err(BrokerError::InvalidField(
                "registered_generation.broker_generation",
            ));
        }
        self.ebp_contract_version
            .validate()
            .map_err(|error| BrokerError::Provider(error.to_string()))?;
        text(self.job_id.as_str(), "registered_generation.job_id")?;
        Ok(())
    }
}

/// The evidence a caller supplies to stage one cutover.
///
/// The old generation's registration/artifact/contour, the classified session
/// bindings, and the per-operation dispositions are observed facts about the
/// broker being replaced; the machine re-validates all of them against what it
/// recorded and against the broker's own operation lineage, so this struct is
/// input to a check, never a substitute for one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCutoverStage {
    /// The generation being replaced, or `None` for a first registration.
    pub old: Option<RegisteredGeneration>,
    /// The candidate to promote.
    pub candidate: BrokerCandidateRegistration,
    /// Session bindings, each explicitly classified broker-independent or not.
    pub session_bindings: Vec<SessionBindingRecord>,
    /// The exact I14.14 disposition of every old in-flight operation.
    pub operation_dispositions: Vec<InFlightOperation>,
}

/// The Kernel-coordinated User Broker registry and cutover machine
/// (I14.17, I14.14).
///
/// This type owns the cutover decision and its durable record.  The broker
/// core owns the live operation lineage; this machine is handed that lineage
/// for the proof, so it never has to guess what was still running.  The
/// production caller is [`UserBroker::admit_new_launch`], which is the
/// admission path every launch goes through.
pub struct BrokerCutover {
    state: BrokerCutoverState,
    old: Option<RegisteredGeneration>,
    candidate: Option<BrokerCandidateRegistration>,
    session_bindings: Vec<SessionBindingRecord>,
    operation_dispositions: Vec<InFlightOperation>,
    termination_proof: Option<OldJobObjectTerminationProof>,
    receipt: Option<BrokerCutoverReceipt>,
    logout_observed: bool,
}

impl Default for BrokerCutover {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerCutover {
    /// Creates a machine that has admitted no candidate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: BrokerCutoverState::CandidateStaged,
            old: None,
            candidate: None,
            session_bindings: Vec::new(),
            operation_dispositions: Vec::new(),
            termination_proof: None,
            receipt: None,
            logout_observed: false,
        }
    }

    /// Returns the current cutover state.
    #[must_use]
    pub fn state(&self) -> BrokerCutoverState {
        self.state
    }

    /// Returns the published cutover receipt, once one has been committed.
    #[must_use]
    pub fn receipt(&self) -> Option<&BrokerCutoverReceipt> {
        self.receipt.as_ref()
    }

    /// Returns the active candidate registration, once the cutover completed.
    #[must_use]
    pub fn active_registration(&self) -> Option<&RegistrationReceipt> {
        if self.state == BrokerCutoverState::Active {
            self.candidate.as_ref().map(|c| &c.registration)
        } else {
            None
        }
    }

    /// Stages the candidate that will replace the recorded generation.
    ///
    /// The candidate starts with no launch/effect authority by construction:
    /// this only records it, and [`Self::authenticate_candidate`] is what
    /// checks SID, session, artifact, and EBP contract.  Re-staging is refused
    /// until a new candidate is presented, so a cutover cannot be restarted
    /// from a half-completed state.
    pub fn stage_candidate(
        &mut self,
        old: Option<&RegisteredGeneration>,
        candidate: &BrokerCandidateRegistration,
    ) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::CandidateStaged || self.candidate.is_some() {
            return Err(BrokerError::StaleEpoch);
        }
        if let Some(old) = old {
            old.validate()?;
            if old.registration.status != RegistrationStatus::Active {
                // A registration that is already Closed/Draining admits no
                // successor transition: there is no live old generation to
                // fence, and admitting one would resurrect a fenced lease.
                return Err(BrokerError::LeaseExpired);
            }
        }
        candidate.validate()?;
        if old.is_some_and(|old| {
            candidate.registration.registration_digest == old.registration.registration_digest
        }) {
            return Err(BrokerError::DuplicateRegistration);
        }
        self.old = old.cloned();
        self.candidate = Some(candidate.clone());
        Ok(())
    }

    /// Authenticates the staged candidate against the recorded old generation.
    ///
    /// Every check is a comparison against what was recorded, never a
    /// self-assertion:
    ///
    /// * the candidate registration must be this process's own tuple, decided
    ///   by the existing [`BrokerAdmissionIdentity::admits`];
    /// * its artifact digest must differ from the old generation's, because
    ///   I14.17 forbids replacing a broker binary in place;
    /// * its broker generation must be strictly higher;
    /// * its epoch must be strictly higher *or* a new lineage
    ///   ([`UserBrokerEpoch::supersedes`]);
    /// * its EBP contract version must equal the one the old generation
    ///   registered with.
    ///
    /// A first registration has no predecessor, so there is nothing to fence
    /// or compare and the candidate is authenticated on shape alone.
    pub fn authenticate_candidate(
        &mut self,
        admission: &BrokerAdmissionIdentity,
    ) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::CandidateStaged {
            return Err(BrokerError::StaleEpoch);
        }
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        if !admission.admits(&candidate.registration) {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        let Some(old) = self.old.as_ref() else {
            self.state = BrokerCutoverState::CandidateAuthenticated;
            return Ok(());
        };
        if candidate.broker_artifact_digest == old.broker_artifact_digest {
            return Err(BrokerError::GrantBindingMismatch);
        }
        if candidate.broker_generation <= old.broker_generation {
            return Err(BrokerError::StaleEpoch);
        }
        let recorded_epoch = UserBrokerEpoch::new(
            candidate.registration.authority_epoch.lineage_id.clone(),
            NonZeroU64::new(old.registration.user_broker_epoch)
                .ok_or(BrokerError::InvalidField("cutover.old_user_broker_epoch"))?,
        )?;
        if !candidate.user_broker_epoch.supersedes(&recorded_epoch) {
            return Err(BrokerError::StaleEpoch);
        }
        if candidate.ebp_contract_version != old.ebp_contract_version {
            return Err(BrokerError::GrantBindingMismatch);
        }
        if candidate.job_id == old.job_id {
            // Two generations sharing one Job contour could never prove the
            // old one terminated, so the cutover would be unprovable by
            // construction.  Refuse it here rather than at completion.
            return Err(BrokerError::GrantBindingMismatch);
        }
        self.state = BrokerCutoverState::CandidateAuthenticated;
        Ok(())
    }

    /// Fences the old registration from new launches at the generation
    /// transition.
    ///
    /// Fencing is what makes the acceptance criterion hold: from here the only
    /// registration that can admit a launch is the candidate's own, compared
    /// against the recorded one in [`Self::admits_new_launch`].  Whether the
    /// candidate may *become* active is decided later by [`Self::complete`],
    /// and a cutover that never proves termination simply never leaves this
    /// state.
    pub fn fence_old_registration(&mut self) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::CandidateAuthenticated {
            return Err(BrokerError::StaleEpoch);
        }
        self.state = BrokerCutoverState::OldRegistrationFenced;
        Ok(())
    }

    /// Records the session bindings and transfers only the broker-independent
    /// ones.
    ///
    /// Each binding is classified explicitly by the caller and validated for
    /// shape and uniqueness.  A binding for any logon Session other than the
    /// one the old generation owned is refused outright rather than quietly
    /// carried across.  Broker-*dependent* bindings are accepted and retained
    /// here precisely so the receipt can record them as untransferred.
    pub fn transfer_session_bindings(
        &mut self,
        bindings: &[SessionBindingRecord],
    ) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::OldRegistrationFenced {
            return Err(BrokerError::StaleEpoch);
        }
        let mut seen = BTreeSet::new();
        for binding in bindings {
            text(&binding.binding_id, "session_binding.binding_id")?;
            text(
                &binding.interactive_session_id,
                "session_binding.interactive_session_id",
            )?;
            if !seen.insert(binding.binding_id.clone()) {
                return Err(BrokerError::Duplicate("session_binding.binding_id"));
            }
            if self.old.as_ref().is_some_and(|old| {
                binding.interactive_session_id != old.registration.interactive_session_id
            }) {
                return Err(BrokerError::StaleRegistrationIdentity);
            }
        }
        self.session_bindings = bindings.to_vec();
        self.state = BrokerCutoverState::BindingsTransferred;
        Ok(())
    }

    /// Commits the exact disposition of every old in-flight operation.
    ///
    /// Each operation receives exactly one I14.14 disposition, and `old_operations`
    /// is the broker's own live lineage for the old registration.  The
    /// disposition set must be exactly that lineage: an operation the broker
    /// does not own cannot be dispositioned here, and an owned operation that
    /// is omitted is a stale request, not a finished one.
    pub fn commit_operation_dispositions(
        &mut self,
        dispositions: &[InFlightOperation],
        old_operation_ids: &BTreeSet<OperationId>,
    ) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::BindingsTransferred {
            return Err(BrokerError::StaleEpoch);
        }
        if self.old.is_none() {
            // A first registration has no old generation to disposition.
            if !dispositions.is_empty() {
                return Err(BrokerError::OperationNotFound);
            }
            self.operation_dispositions.clear();
            return Ok(());
        }
        let expected = old_operation_ids;
        let mut seen = BTreeSet::new();
        for disposition in dispositions {
            if !seen.insert(disposition.operation_id.clone()) {
                return Err(BrokerError::Duplicate("cutover.operation_id"));
            }
            if !expected.contains(&disposition.operation_id) {
                return Err(BrokerError::OperationNotFound);
            }
        }
        if seen.len() != expected.len() {
            return Err(BrokerError::OperationNotFound);
        }
        self.operation_dispositions = dispositions.to_vec();
        Ok(())
    }

    /// Records that a termination was requested for the old Job Object.
    ///
    /// This moves the machine to `TerminationRequested`, which is explicitly
    /// *not* active: a request is not a proof.  Only [`Self::complete`] can
    /// promote the candidate, and only on a proof that passes
    /// [`OldJobObjectTerminationProof::proves_termination`].
    pub fn request_old_termination(&mut self) -> Result<(), BrokerError> {
        if self.state != BrokerCutoverState::BindingsTransferred {
            return Err(BrokerError::StaleEpoch);
        }
        self.state = BrokerCutoverState::TerminationRequested;
        Ok(())
    }

    /// Records that a logout was observed while the cutover was in flight.
    ///
    /// I14.17: "Logout or inability to prove old Job Object termination stops
    /// cutover and requires reconciliation."  A logout is terminal — the
    /// machine can no longer reach `Active`.
    pub fn observe_logout(&mut self) {
        self.logout_observed = true;
    }

    /// Attempts to promote the candidate to `Active`.
    ///
    /// This is the only transition that marks a candidate active.  When an old
    /// generation exists it happens only when a termination proof is supplied
    /// *and* verified against the recorded old registration and the broker's
    /// own operation lineage.  On refusal the machine moves to
    /// `ReconciliationRequired` and publishes a receipt with no termination
    /// proof, so the outcome is inspectable and the candidate is definitively
    /// not active.
    pub fn complete(
        &mut self,
        proof: Option<&OldJobObjectTerminationProof>,
        old_operation_ids: &BTreeSet<OperationId>,
    ) -> Result<&BrokerCutoverReceipt, BrokerError> {
        if self.state != BrokerCutoverState::TerminationRequested {
            return Err(BrokerError::StaleEpoch);
        }
        if self.logout_observed {
            self.state = BrokerCutoverState::ReconciliationRequired;
            self.publish();
            return Err(BrokerError::CutoverStoppedByLogout);
        }
        if let Some(old) = self.old.as_ref() {
            let Some(proof) = proof else {
                // A generation transition without a proof never activates.
                self.state = BrokerCutoverState::ReconciliationRequired;
                self.publish();
                return Err(BrokerError::CutoverTerminationUnproven);
            };
            if let Err(error) = proof.proves_termination(old, old_operation_ids) {
                self.state = BrokerCutoverState::ReconciliationRequired;
                self.publish();
                return Err(error);
            }
            self.termination_proof = Some(proof.clone());
        }
        self.state = BrokerCutoverState::Active;
        self.publish();
        self.receipt
            .as_ref()
            .ok_or(BrokerError::CutoverTerminationUnproven)
    }

    /// Returns the exact admission decision for a new launch.
    ///
    /// This is the production path the acceptance criterion names: after a
    /// broker cutover, a new launch is accepted only through the candidate's
    /// own registration and epoch, compared against the recorded one.  It
    /// never matches on a name: the presented registration must be the
    /// candidate's own sealed registration, admitted by this process's
    /// identity tuple, carrying the candidate's authority epoch and fence, and
    /// the presented epoch must be the candidate's strictly-higher/new-lineage
    /// epoch.
    pub fn admits_new_launch(
        &self,
        admission: &BrokerAdmissionIdentity,
        presented: &RegistrationReceipt,
        presented_epoch: &UserBrokerEpoch,
    ) -> Result<(), BrokerError> {
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(BrokerError::RegistrationNotAdmitted)?;
        if self.state != BrokerCutoverState::Active {
            return Err(BrokerError::RegistrationNotAdmitted);
        }
        if !admission.admits(presented)
            || !admission.admits(&candidate.registration)
            || presented.registration_digest != candidate.registration.registration_digest
            || !presented
                .authority_epoch
                .is_same_authority(&candidate.registration.authority_epoch)
            || presented.fence_id != candidate.registration.fence_id
        {
            return Err(BrokerError::StaleRegistrationIdentity);
        }
        if presented_epoch != &candidate.user_broker_epoch {
            return Err(BrokerError::StaleEpoch);
        }
        if let Some(old) = self.old.as_ref() {
            let recorded = UserBrokerEpoch::new(
                presented.authority_epoch.lineage_id.clone(),
                NonZeroU64::new(old.registration.user_broker_epoch)
                    .ok_or(BrokerError::InvalidField("cutover.old_user_broker_epoch"))?,
            )?;
            if !presented_epoch.supersedes(&recorded) {
                return Err(BrokerError::StaleEpoch);
            }
        }
        Ok(())
    }

    /// Projects the published receipt, splitting the session bindings into
    /// transferred and explicitly untransferred sets.
    fn publish(&mut self) {
        let Some(candidate) = self.candidate.as_ref() else {
            return;
        };
        let (transferred, untransferred): (Vec<_>, Vec<_>) = self
            .session_bindings
            .iter()
            .cloned()
            .partition(|binding| binding.broker_independent);
        self.receipt = Some(BrokerCutoverReceipt {
            state: self.state,
            old_registration_digest: self.old.as_ref().map_or_else(String::new, |old| {
                old.registration.registration_digest.clone()
            }),
            old_broker_generation: self
                .old
                .as_ref()
                .map_or_else(Generation::default, |old| old.broker_generation),
            old_user_broker_epoch: self
                .old
                .as_ref()
                .map_or(0, |old| old.registration.user_broker_epoch),
            new_registration_digest: candidate.registration.registration_digest.clone(),
            new_broker_generation: candidate.broker_generation,
            new_user_broker_epoch: candidate.user_broker_epoch.clone(),
            transferred_bindings: transferred,
            untransferred_bindings: untransferred,
            operation_dispositions: self.operation_dispositions.clone(),
            old_job_object_termination: self.termination_proof.clone(),
        });
    }
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
                &None::<NativeResourceSelection>,
            ))
            .expect("digest");
            Ok(LaunchGrant {
                approved,
                resource_selection: None,
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
            _stdin_payload: Option<&str>,
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

        fn take_process_lineage_recovery_obligation(&mut self) -> Result<bool, PortError> {
            Ok(false)
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
            stdin_payload: Option<&str>,
        ) -> Result<String, PortError> {
            self.inner.prepare_start(grant, registration, stdin_payload)
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

        fn take_process_lineage_recovery_obligation(&mut self) -> Result<bool, PortError> {
            self.inner.take_process_lineage_recovery_obligation()
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
            stdin_payload: Option<&str>,
        ) -> Result<String, PortError> {
            self.inner.prepare_start(grant, registration, stdin_payload)
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

        fn take_process_lineage_recovery_obligation(&mut self) -> Result<bool, PortError> {
            self.inner.take_process_lineage_recovery_obligation()
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
            resource_selection_candidate: None,
            stdin_payload: None,
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
            process_effect_lineage: Vec::new(),
            retired_operations: Vec::new(),
            predecessor_registration: None,
            cutover_receipt: None,
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
                process_effect_lineage: Vec::new(),
                retired_operations: Vec::new(),
                predecessor_registration: None,
                cutover_receipt: None,
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
            operation_identities: broker
                .projected_operation_identities()
                .expect("identity projection"),
            process_effect_lineage: broker
                .projected_process_effect_lineage()
                .expect("process-lineage projection"),
            retired_operations: broker.retired_operations.values().cloned().collect(),
            predecessor_registration: broker.predecessor_registration.clone(),
            cutover_receipt: broker.cutover_receipt.clone(),
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
        let mut snapshot = broker.snapshot().expect("snapshot");
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
