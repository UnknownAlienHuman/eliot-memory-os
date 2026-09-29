//! Exact, path-free authority record for one native resource selection.
//!
//! This record is emitted only by the Kernel/Governor owner after it admits an
//! exact Operator candidate. It does not contain a path and is not a broker
//! assertion of authority. The User Broker retains the candidate privately,
//! resolves it again immediately before use, and compares the measured object
//! and policy to this record.

use eliot_contracts::{EpochId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current serialized form of [`NativeResourceSelection`].
pub const NATIVE_RESOURCE_SELECTION_VERSION: u16 = 1;
/// Current serialized form of [`NativeResourceSelectionCandidate`].
pub const NATIVE_RESOURCE_SELECTION_CANDIDATE_VERSION: u16 = 1;

const MAX_SELECTION_REF_BYTES: usize = 512;
const MAX_PERMISSION_BYTES: usize = 256;
const MAX_PERMISSION_COUNT: usize = 64;

/// Semantic kind of the exact selected object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeResourceKind {
    File,
    Directory,
}

/// Reparse-point policy admitted for a selected native object.
///
/// The current contract supports only fail-closed reparse rejection. Adding a
/// more permissive policy requires an explicit contract revision and matching
/// resolver proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeResourceReparsePolicy {
    Reject,
}

/// Network resource policy admitted for a selected native object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeResourceNetworkPolicy {
    LocalOnly,
}

/// Device resource policy admitted for a selected native object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeResourceDevicePolicy {
    Reject,
}

/// Path-free evidence measured by the authenticated User Broker before it
/// asks the Kernel to authorize a launch.
///
/// This record is evidence only. It is not permission to use the object: the
/// Kernel/Governor must bind the exact candidate to an admitted introduction
/// and return a [`NativeResourceSelection`] before the Broker may issue a
/// one-shot lease. The opaque candidate reference lets the Broker recover its
/// private retained selection state for immediate remeasurement without
/// sending a path through the Kernel request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceSelectionCandidate {
    /// Candidate contract version.
    pub version: u16,
    /// Opaque Broker-owned reference to retained private selection state.
    pub candidate_ref: String,
    /// Authenticated principal that owns the user-session resource.
    pub principal_ref: String,
    /// Authenticated interactive session served by the registered Broker.
    pub interactive_session_id: String,
    /// Exact launch request identity bound to the Operator input.
    pub request_ref: String,
    /// Exact effect operation identity.
    pub operation_ref: String,
    /// Opaque `ResourceRef` from the request's introduction; it never selects a
    /// path and is checked against the Kernel-admitted introduction.
    pub resource_ref: String,
    /// Digest of the explicitly selected root object identity.
    pub canonical_root_identity_digest: String,
    /// Digest of the explicitly selected resource object identity.
    pub canonical_resource_identity_digest: String,
    /// Digest of the Broker's no-follow measurement of that exact selection.
    pub measurement_digest: String,
    /// Measured semantic kind of the exact selected object.
    pub resource_kind: NativeResourceKind,
    /// Reparse-point policy measured and enforced by the owner resolver.
    pub reparse_policy: NativeResourceReparsePolicy,
    /// Network policy measured and enforced by the owner resolver.
    pub network_policy: NativeResourceNetworkPolicy,
    /// Device policy measured and enforced by the owner resolver.
    pub device_policy: NativeResourceDevicePolicy,
    /// Digest of the authenticated Broker registration that measured it.
    pub registration_ref: String,
    /// Broker-local registration epoch at measurement time.
    pub broker_epoch: u64,
    /// Registration fence held by the measuring Broker.
    pub fence_id: String,
    /// Owner-clock measurement instant in Unix milliseconds.
    pub measured_at: u64,
}

impl NativeResourceSelectionCandidate {
    /// Rejects incomplete or malformed Broker evidence before authorization.
    pub fn validate(&self) -> Result<(), NativeResourceSelectionError> {
        if self.version != NATIVE_RESOURCE_SELECTION_CANDIDATE_VERSION {
            return Err(NativeResourceSelectionError::InvalidField(
                "candidate.version",
            ));
        }
        opaque_ref(&self.candidate_ref)
            .map_err(|_| NativeResourceSelectionError::InvalidField("candidate.candidate_ref"))?;
        bounded_text(
            &self.principal_ref,
            MAX_SELECTION_REF_BYTES,
            "candidate.principal_ref",
        )?;
        bounded_text(
            &self.interactive_session_id,
            MAX_SELECTION_REF_BYTES,
            "candidate.interactive_session_id",
        )?;
        bounded_text(
            &self.request_ref,
            MAX_SELECTION_REF_BYTES,
            "candidate.request_ref",
        )?;
        bounded_text(
            &self.operation_ref,
            MAX_SELECTION_REF_BYTES,
            "candidate.operation_ref",
        )?;
        opaque_ref(&self.resource_ref)
            .map_err(|_| NativeResourceSelectionError::InvalidField("candidate.resource_ref"))?;
        digest(
            &self.canonical_root_identity_digest,
            "candidate.canonical_root_identity_digest",
        )?;
        digest(
            &self.canonical_resource_identity_digest,
            "candidate.canonical_resource_identity_digest",
        )?;
        digest(&self.measurement_digest, "candidate.measurement_digest")?;
        bounded_text(
            &self.registration_ref,
            MAX_SELECTION_REF_BYTES,
            "candidate.registration_ref",
        )?;
        bounded_text(
            &self.fence_id,
            MAX_SELECTION_REF_BYTES,
            "candidate.fence_id",
        )?;
        if self.broker_epoch == 0 || self.measured_at == 0 {
            return Err(NativeResourceSelectionError::InvalidField(
                "candidate.owner_epoch_or_time",
            ));
        }
        Ok(())
    }

    /// Checks that the Kernel grant binds this exact Broker observation.
    #[must_use]
    pub fn matches_selection(&self, selection: &NativeResourceSelection) -> bool {
        self.candidate_ref == selection.candidate_ref
            && self.principal_ref == selection.principal_ref
            && self.interactive_session_id == selection.interactive_session_id
            && self.request_ref == selection.request_ref
            && self.operation_ref == selection.operation_ref
            && self.resource_ref == selection.resource_ref
            && self.canonical_root_identity_digest == selection.canonical_root_identity_digest
            && self.canonical_resource_identity_digest
                == selection.canonical_resource_identity_digest
            && self.measurement_digest == selection.measurement_digest
            && self.resource_kind == selection.resource_kind
            && self.reparse_policy == selection.reparse_policy
            && self.network_policy == selection.network_policy
            && self.device_policy == selection.device_policy
            && self.registration_ref == selection.registration_ref
            && self.broker_epoch == selection.broker_epoch
            && self.fence_id == selection.fence_id
            && self.measured_at <= selection.issued_at
    }
}

/// Kernel/Governor-issued authority for one exact selected resource object.
///
/// The User Broker's authenticated Operator request binds this record to the
/// original selection input through the launch request digest. The record
/// separately binds the measured object identity, resource scope and
/// reparse/network/device policy. No selected path is present here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceSelection {
    /// Record contract version.
    pub version: u16,
    /// Exact Broker candidate whose measured object was admitted.
    pub candidate_ref: String,
    /// Authenticated principal that owns the user-session resource.
    pub principal_ref: String,
    /// Authenticated interactive Session served by the registered broker.
    pub interactive_session_id: String,
    /// Owner-issued attempt identity, distinct from request and operation IDs.
    pub attempt_ref: String,
    /// Exact launch request identity bound to the Operator candidate.
    pub request_ref: String,
    /// Exact effect operation identity.
    pub operation_ref: String,
    /// Opaque resource reference introduced to the admitted child.
    pub resource_ref: String,
    /// Digest of the explicitly selected root object identity.
    pub canonical_root_identity_digest: String,
    /// Digest of the exact admitted resource scope and permissions.
    pub scope_digest: String,
    /// Exact facet permissions admitted for this resource object.
    pub permissions: Vec<String>,
    /// Digest of the measured canonical object identity.
    pub canonical_resource_identity_digest: String,
    /// Digest of the measurement that established the selected object.
    pub measurement_digest: String,
    /// Measured semantic kind of the exact selected object.
    pub resource_kind: NativeResourceKind,
    /// Reparse-point policy carried into the lease.
    pub reparse_policy: NativeResourceReparsePolicy,
    /// Network policy carried into the lease.
    pub network_policy: NativeResourceNetworkPolicy,
    /// Device policy carried into the lease.
    pub device_policy: NativeResourceDevicePolicy,
    /// Digest of the broker's current authenticated registration.
    pub registration_ref: String,
    /// Broker-local registration epoch.
    pub broker_epoch: u64,
    /// Exact consumer process generation approved for this operation.
    pub consumer_generation: u64,
    /// Lineage-aware authority epoch for the operation.
    pub authority_epoch: EpochId,
    /// Registration fence of the broker that may consume this selection.
    pub fence_id: String,
    /// State fence observed by the selection owner.
    pub state_fence: StateFence,
    /// Owner-issued selection time in Unix milliseconds.
    pub issued_at: u64,
    /// Selection expiry in Unix milliseconds.
    pub expires_at: u64,
}

impl NativeResourceSelection {
    /// Rejects incomplete or malformed owner records before grant use.
    pub fn validate(&self) -> Result<(), NativeResourceSelectionError> {
        if self.version != NATIVE_RESOURCE_SELECTION_VERSION {
            return Err(NativeResourceSelectionError::InvalidField("version"));
        }
        opaque_ref(&self.candidate_ref)
            .map_err(|_| NativeResourceSelectionError::InvalidField("candidate_ref"))?;
        bounded_text(
            &self.principal_ref,
            MAX_SELECTION_REF_BYTES,
            "principal_ref",
        )?;
        bounded_text(
            &self.interactive_session_id,
            MAX_SELECTION_REF_BYTES,
            "interactive_session_id",
        )?;
        bounded_text(&self.attempt_ref, MAX_SELECTION_REF_BYTES, "attempt_ref")?;
        bounded_text(&self.request_ref, MAX_SELECTION_REF_BYTES, "request_ref")?;
        bounded_text(
            &self.operation_ref,
            MAX_SELECTION_REF_BYTES,
            "operation_ref",
        )?;
        if self.attempt_ref == self.request_ref || self.attempt_ref == self.operation_ref {
            return Err(NativeResourceSelectionError::InvalidField(
                "attempt_ref_owner_identity",
            ));
        }
        opaque_ref(&self.resource_ref)?;
        digest(
            &self.canonical_root_identity_digest,
            "canonical_root_identity_digest",
        )?;
        digest(&self.scope_digest, "scope_digest")?;
        digest(
            &self.canonical_resource_identity_digest,
            "canonical_resource_identity_digest",
        )?;
        digest(&self.measurement_digest, "measurement_digest")?;
        bounded_text(
            &self.registration_ref,
            MAX_SELECTION_REF_BYTES,
            "registration_ref",
        )?;
        bounded_text(&self.fence_id, MAX_SELECTION_REF_BYTES, "fence_id")?;
        if self.permissions.is_empty() || self.permissions.len() > MAX_PERMISSION_COUNT {
            return Err(NativeResourceSelectionError::InvalidField("permissions"));
        }
        for permission in &self.permissions {
            bounded_text(permission, MAX_PERMISSION_BYTES, "permissions")?;
        }
        for (index, permission) in self.permissions.iter().enumerate() {
            if self.permissions[..index].contains(permission) {
                return Err(NativeResourceSelectionError::DuplicatePermission);
            }
        }
        if self.broker_epoch == 0 || self.consumer_generation == 0 {
            return Err(NativeResourceSelectionError::InvalidField(
                "broker_epoch_or_consumer_generation",
            ));
        }
        self.state_fence
            .validate()
            .map_err(|_| NativeResourceSelectionError::InvalidField("state_fence"))?;
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(NativeResourceSelectionError::InvalidField(
                "state_fence_authority_epoch",
            ));
        }
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(NativeResourceSelectionError::InvalidField(
                "selection_window",
            ));
        }
        Ok(())
    }
}

fn bounded_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), NativeResourceSelectionError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(NativeResourceSelectionError::InvalidField(field));
    }
    Ok(())
}

fn opaque_ref(value: &str) -> Result<(), NativeResourceSelectionError> {
    bounded_text(value, MAX_SELECTION_REF_BYTES, "resource_ref")?;
    if value.contains(['/', '\\', ':', '*', '?']) {
        return Err(NativeResourceSelectionError::InvalidField("resource_ref"));
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), NativeResourceSelectionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NativeResourceSelectionError::InvalidField(field));
    }
    Ok(())
}

/// Typed validation failure for an exact native resource selection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NativeResourceSelectionError {
    #[error("native resource selection has an invalid {0}")]
    InvalidField(&'static str),
    #[error("native resource selection repeats a permission")]
    DuplicatePermission,
}
