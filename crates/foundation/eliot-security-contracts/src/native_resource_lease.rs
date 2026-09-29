//! One-shot, operation-bound authority for a resource crossing.
//!
//! The lease carries only opaque identities and digests.  A consumer must
//! resolve and measure the current resource again at the point of use, then
//! retain the returned consumption receipt with the admitted operation.

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, fences_match_exact, sha256_hex};
use crate::{
    NativeResourceDevicePolicy, NativeResourceKind, NativeResourceNetworkPolicy,
    NativeResourceReparsePolicy,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current serialized form of [`NativeResourceLease`].
pub const NATIVE_RESOURCE_LEASE_VERSION: u16 = 1;

const MAX_PRINCIPAL_REF_BYTES: usize = 512;
const MAX_ISSUER_PROCESS_REF_BYTES: usize = 512;
const MAX_ATTEMPT_REF_BYTES: usize = 512;
const MAX_REQUEST_REF_BYTES: usize = 512;
const MAX_OPERATION_REF_BYTES: usize = 256;
const MAX_RESOURCE_REF_BYTES: usize = 256;

/// Exact operation and consumer identity a broker-issued lease is for.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceLeaseBinding {
    /// Authenticated principal that owns the user-session resource.
    pub principal_ref: String,
    /// Process identity of the broker issuing the lease, copied from its
    /// authenticated current registration rather than from the launch caller.
    pub issuer_process_ref: String,
    /// Owner-issued attempt identity; it is distinct from request and operation IDs.
    pub attempt_ref: String,
    /// Caller request identity carried separately from the attempt identity.
    pub request_ref: String,
    /// Exact effect operation identity.
    pub operation_ref: String,
    /// Exact Broker-owned selection candidate this lease uses.
    pub candidate_ref: String,
    /// Opaque resource reference; it must not be a path or drive-qualified value.
    pub resource_ref: String,
    /// Digest of the exact approved resource scope, so the scope path need not cross.
    pub scope_digest: String,
    /// Digest of the exact selected root identity.
    pub canonical_root_identity_digest: String,
    /// Digest of the exact selected object identity.
    pub resource_identity_digest: String,
    /// Digest of the measured object properties.
    pub measurement_digest: String,
    /// Exact object kind and policies admitted by the Kernel grant.
    pub resource_kind: NativeResourceKind,
    pub reparse_policy: NativeResourceReparsePolicy,
    pub network_policy: NativeResourceNetworkPolicy,
    pub device_policy: NativeResourceDevicePolicy,
    /// State fence issued by the Kernel grant for this exact selection.
    pub state_fence: StateFence,
    /// Digest of the broker registration that issued this lease.
    pub registration_ref: String,
    /// Broker-local registration epoch.
    pub broker_epoch: u64,
    /// Exact consumer process generation approved for this operation.
    pub consumer_generation: u64,
    /// Lineage-aware authority epoch for the operation.
    pub authority_epoch: EpochId,
}

impl NativeResourceLeaseBinding {
    /// Checks the identity shape before it is used as a lookup or authority key.
    pub fn validate(&self) -> Result<(), NativeResourceLeaseError> {
        bounded_text(
            &self.principal_ref,
            MAX_PRINCIPAL_REF_BYTES,
            NativeResourceLeaseField::PrincipalRef,
        )?;
        bounded_text(
            &self.issuer_process_ref,
            MAX_ISSUER_PROCESS_REF_BYTES,
            NativeResourceLeaseField::IssuerProcessRef,
        )?;
        bounded_text(
            &self.attempt_ref,
            MAX_ATTEMPT_REF_BYTES,
            NativeResourceLeaseField::AttemptRef,
        )?;
        bounded_text(
            &self.request_ref,
            MAX_REQUEST_REF_BYTES,
            NativeResourceLeaseField::RequestRef,
        )?;
        bounded_text(
            &self.operation_ref,
            MAX_OPERATION_REF_BYTES,
            NativeResourceLeaseField::OperationRef,
        )?;
        bounded_text(
            &self.candidate_ref,
            MAX_RESOURCE_REF_BYTES,
            NativeResourceLeaseField::CandidateRef,
        )?;
        validate_resource_ref(&self.resource_ref)?;
        validate_digest(&self.scope_digest, NativeResourceLeaseField::ScopeDigest)?;
        validate_digest(
            &self.canonical_root_identity_digest,
            NativeResourceLeaseField::CanonicalRootIdentityDigest,
        )?;
        validate_digest(
            &self.resource_identity_digest,
            NativeResourceLeaseField::ResourceIdentityDigest,
        )?;
        validate_digest(
            &self.measurement_digest,
            NativeResourceLeaseField::MeasurementDigest,
        )?;
        self.state_fence
            .validate()
            .map_err(|_| NativeResourceLeaseError::InvalidField(NativeResourceLeaseField::StateFence))?;
        if !self.state_fence.authority_epoch.is_same_authority(&self.authority_epoch) {
            return Err(NativeResourceLeaseError::Revoked);
        }
        validate_digest(
            &self.registration_ref,
            NativeResourceLeaseField::RegistrationRef,
        )?;
        if self.broker_epoch == 0 {
            return Err(NativeResourceLeaseError::InvalidField(
                NativeResourceLeaseField::BrokerEpoch,
            ));
        }
        if self.consumer_generation == 0 {
            return Err(NativeResourceLeaseError::InvalidField(
                NativeResourceLeaseField::ConsumerGeneration,
            ));
        }
        Ok(())
    }
}

/// Fresh, path-free observation returned by the resource owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceMeasurement {
    /// Exact Broker-owned selection candidate remeasured by the owner.
    pub candidate_ref: String,
    /// Opaque resource reference that was resolved.
    pub resource_ref: String,
    /// Digest of the approved resource scope observed by the resolver.
    pub scope_digest: String,
    /// Digest of the resolved resource identity (for example, file identity and reparse state).
    pub resource_identity_digest: String,
    /// Digest of the selected root identity.
    pub canonical_root_identity_digest: String,
    /// Digest of the resource measurement used by this operation.
    pub measurement_digest: String,
    /// Measured kind and enforced policies of the selected object.
    pub resource_kind: NativeResourceKind,
    pub reparse_policy: NativeResourceReparsePolicy,
    pub network_policy: NativeResourceNetworkPolicy,
    pub device_policy: NativeResourceDevicePolicy,
    /// Unix-millisecond observation time from the resolving owner.
    pub measured_at: u64,
}

impl NativeResourceMeasurement {
    /// Rejects incomplete or malformed observations before any lease decision.
    pub fn validate(&self) -> Result<(), NativeResourceLeaseError> {
        validate_resource_ref(&self.resource_ref)?;
        bounded_text(
            &self.candidate_ref,
            MAX_RESOURCE_REF_BYTES,
            NativeResourceLeaseField::CandidateRef,
        )?;
        validate_digest(&self.scope_digest, NativeResourceLeaseField::ScopeDigest)?;
        validate_digest(
            &self.resource_identity_digest,
            NativeResourceLeaseField::ResourceIdentityDigest,
        )?;
        validate_digest(
            &self.canonical_root_identity_digest,
            NativeResourceLeaseField::CanonicalRootIdentityDigest,
        )?;
        validate_digest(
            &self.measurement_digest,
            NativeResourceLeaseField::MeasurementDigest,
        )?;
        if self.measured_at == 0 {
            return Err(NativeResourceLeaseError::InvalidField(
                NativeResourceLeaseField::MeasuredAt,
            ));
        }
        Ok(())
    }
}

/// One-shot authority to use one measured resource for one admitted operation.
///
/// The lease issuer is the broker process named by `issuer_process_ref`, which
/// is copied from the broker's sealed `RegistrationReceipt`. The broker only
/// issues and consumes the lease while that exact registration is current;
/// its injected resource-owner port receives the issuer and registration
/// bindings on both resolution calls and must authenticate that caller before
/// returning a measurement. The registration digest and broker epoch therefore
/// bind this process identity to the owner-approved authority at use time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceLease {
    /// Lease identity minted by the broker.
    pub lease_id: String,
    /// Authenticated principal that owns the resource.
    pub principal_ref: String,
    /// Authenticated process identity of the broker issuing this lease.
    pub issuer_process_ref: String,
    /// Owner-issued attempt identity, distinct from request and operation IDs.
    pub attempt_ref: String,
    /// Caller request identity.
    pub request_ref: String,
    /// Exact effect operation identity.
    pub operation_ref: String,
    /// Exact Broker-owned selection candidate this lease uses.
    pub candidate_ref: String,
    /// Opaque resource reference.
    pub resource_ref: String,
    /// Digest of the exact approved resource scope.
    pub scope_digest: String,
    /// Digest of the exact selected root identity.
    pub canonical_root_identity_digest: String,
    /// Issuing broker registration digest.
    pub registration_ref: String,
    /// Issuing broker-local epoch.
    pub broker_epoch: u64,
    /// Exact approved consumer generation.
    pub consumer_generation: u64,
    /// State fence captured when the lease was issued.
    pub state_fence: StateFence,
    /// Digest of the resource identity captured at issue time.
    pub resource_identity_digest: String,
    /// Digest of the resource measurement captured at issue time.
    pub measurement_digest: String,
    /// Exact object kind and policies admitted by the Kernel grant.
    pub resource_kind: NativeResourceKind,
    pub reparse_policy: NativeResourceReparsePolicy,
    pub network_policy: NativeResourceNetworkPolicy,
    pub device_policy: NativeResourceDevicePolicy,
    /// Lease issue time in Unix milliseconds.
    pub issued_at: u64,
    /// Lease expiry in Unix milliseconds; it may not outlive its registration or grant.
    pub expires_at: u64,
}

impl NativeResourceLease {
    /// Validates the immutable lease shape.
    pub fn validate(&self) -> Result<(), NativeResourceLeaseError> {
        bounded_text(
            &self.lease_id,
            MAX_OPERATION_REF_BYTES,
            NativeResourceLeaseField::LeaseId,
        )?;
        let binding = self.binding();
        binding.validate()?;
        validate_digest(
            &self.resource_identity_digest,
            NativeResourceLeaseField::ResourceIdentityDigest,
        )?;
        validate_digest(
            &self.canonical_root_identity_digest,
            NativeResourceLeaseField::CanonicalRootIdentityDigest,
        )?;
        validate_digest(
            &self.measurement_digest,
            NativeResourceLeaseField::MeasurementDigest,
        )?;
        self.state_fence
            .validate()
            .map_err(|_| NativeResourceLeaseError::InvalidField(NativeResourceLeaseField::StateFence))?;
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&binding.authority_epoch)
        {
            return Err(NativeResourceLeaseError::Revoked);
        }
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(NativeResourceLeaseError::InvalidField(
                NativeResourceLeaseField::LeaseWindow,
            ));
        }
        Ok(())
    }

    /// Hashes the complete lease using the shared canonical JSON encoding.
    ///
    /// This digest is stored in the consumption receipt so durable replay
    /// checks bind to every immutable lease field, independent of serializer
    /// map ordering.
    pub fn canonical_digest(&self) -> Result<String, NativeResourceLeaseError> {
        let bytes = canonical_json_bytes(&(
            "eliot.security.native-resource-lease",
            NATIVE_RESOURCE_LEASE_VERSION,
            self,
        ))
        .map_err(|_| NativeResourceLeaseError::CanonicalDigestUnavailable)?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the exact identity tuple this lease authorizes.
    #[must_use]
    pub fn binding(&self) -> NativeResourceLeaseBinding {
        NativeResourceLeaseBinding {
            principal_ref: self.principal_ref.clone(),
            issuer_process_ref: self.issuer_process_ref.clone(),
            attempt_ref: self.attempt_ref.clone(),
            request_ref: self.request_ref.clone(),
            operation_ref: self.operation_ref.clone(),
            candidate_ref: self.candidate_ref.clone(),
            resource_ref: self.resource_ref.clone(),
            scope_digest: self.scope_digest.clone(),
            canonical_root_identity_digest: self.canonical_root_identity_digest.clone(),
            resource_identity_digest: self.resource_identity_digest.clone(),
            measurement_digest: self.measurement_digest.clone(),
            resource_kind: self.resource_kind,
            reparse_policy: self.reparse_policy,
            network_policy: self.network_policy,
            device_policy: self.device_policy,
            registration_ref: self.registration_ref.clone(),
            broker_epoch: self.broker_epoch,
            consumer_generation: self.consumer_generation,
            authority_epoch: self.state_fence.authority_epoch.clone(),
            state_fence: self.state_fence.clone(),
        }
    }

    /// Checks exact binding, expiry, fresh measurement, and current state fence.
    pub fn validate_use(
        &self,
        expected: &NativeResourceLeaseBinding,
        measurement: &NativeResourceMeasurement,
        now: u64,
    ) -> Result<(), NativeResourceLeaseError> {
        self.validate()?;
        expected.validate()?;
        measurement.validate()?;

        compare_binding(self, expected)?;
        if now < self.issued_at {
            return Err(NativeResourceLeaseError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(NativeResourceLeaseError::Expired);
        }
        if measurement.measured_at < self.issued_at || measurement.measured_at > now {
            return Err(NativeResourceLeaseError::StaleMeasurement);
        }
        if measurement.resource_ref != self.resource_ref
            || measurement.candidate_ref != self.candidate_ref
            || measurement.scope_digest != self.scope_digest
            || measurement.resource_identity_digest != self.resource_identity_digest
            || measurement.canonical_root_identity_digest != self.canonical_root_identity_digest
            || measurement.measurement_digest != self.measurement_digest
            || measurement.resource_kind != self.resource_kind
            || measurement.reparse_policy != self.reparse_policy
            || measurement.network_policy != self.network_policy
            || measurement.device_policy != self.device_policy
        {
            return Err(NativeResourceLeaseError::ResourceSubstituted);
        }
        Ok(())
    }
}

/// Durable evidence that one lease was consumed after a fresh resource check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeResourceLeaseConsumptionReceipt {
    /// Receipt identity minted by the broker.
    pub receipt_id: String,
    /// Consumed lease identity.
    pub lease_id: String,
    /// Canonical digest of the complete consumed lease.
    pub lease_digest: String,
    /// Principal that owned the resource at use time.
    pub principal_ref: String,
    /// Authenticated process identity of the broker that consumed the lease.
    pub issuer_process_ref: String,
    /// Owner-issued attempt identity.
    pub attempt_ref: String,
    /// Caller request identity.
    pub request_ref: String,
    /// Exact effect operation identity.
    pub operation_ref: String,
    /// Exact Broker-owned selection candidate that was consumed.
    pub candidate_ref: String,
    /// Opaque resource reference.
    pub resource_ref: String,
    /// Digest of the exact approved resource scope.
    pub scope_digest: String,
    /// Digest of the selected root identity.
    pub canonical_root_identity_digest: String,
    /// Broker registration digest.
    pub registration_ref: String,
    /// Broker-local epoch.
    pub broker_epoch: u64,
    /// Exact consumer generation.
    pub consumer_generation: u64,
    /// Fence re-observed at consumption.
    pub state_fence: StateFence,
    /// Resource identity digest re-observed at consumption.
    pub resource_identity_digest: String,
    /// Resource measurement digest re-observed at consumption.
    pub measurement_digest: String,
    /// Object kind and policies bound by the Kernel selection grant.
    pub resource_kind: NativeResourceKind,
    pub reparse_policy: NativeResourceReparsePolicy,
    pub network_policy: NativeResourceNetworkPolicy,
    pub device_policy: NativeResourceDevicePolicy,
    /// Fresh measurement time used for consumption.
    pub consumed_at: u64,
}

impl NativeResourceLeaseConsumptionReceipt {
    /// Checks that a durable receipt describes this exact lease consumption.
    pub fn validate_for(
        &self,
        lease: &NativeResourceLease,
    ) -> Result<(), NativeResourceLeaseError> {
        lease.validate()?;
        bounded_text(
            &self.receipt_id,
            MAX_OPERATION_REF_BYTES,
            NativeResourceLeaseField::ReceiptId,
        )?;
        validate_digest(&self.lease_digest, NativeResourceLeaseField::LeaseDigest)?;
        if self.lease_id != lease.lease_id
            || self.lease_digest != lease.canonical_digest()?
            || self.principal_ref != lease.principal_ref
            || self.issuer_process_ref != lease.issuer_process_ref
            || self.attempt_ref != lease.attempt_ref
            || self.request_ref != lease.request_ref
            || self.operation_ref != lease.operation_ref
            || self.candidate_ref != lease.candidate_ref
            || self.resource_ref != lease.resource_ref
            || self.scope_digest != lease.scope_digest
            || self.canonical_root_identity_digest != lease.canonical_root_identity_digest
            || self.registration_ref != lease.registration_ref
            || self.broker_epoch != lease.broker_epoch
            || self.consumer_generation != lease.consumer_generation
            || !fences_match_exact(&self.state_fence, &lease.state_fence)
            || self.resource_identity_digest != lease.resource_identity_digest
            || self.measurement_digest != lease.measurement_digest
            || self.resource_kind != lease.resource_kind
            || self.reparse_policy != lease.reparse_policy
            || self.network_policy != lease.network_policy
            || self.device_policy != lease.device_policy
        {
            return Err(NativeResourceLeaseError::ReceiptBindingMismatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| NativeResourceLeaseError::InvalidField(NativeResourceLeaseField::StateFence))?;
        if self.consumed_at < lease.issued_at || self.consumed_at >= lease.expires_at {
            return Err(NativeResourceLeaseError::Expired);
        }
        Ok(())
    }
}

fn compare_binding(
    lease: &NativeResourceLease,
    expected: &NativeResourceLeaseBinding,
) -> Result<(), NativeResourceLeaseError> {
    if lease.principal_ref != expected.principal_ref {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::Principal,
        ));
    }
    if lease.issuer_process_ref != expected.issuer_process_ref {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::Issuer,
        ));
    }
    if lease.attempt_ref != expected.attempt_ref {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::Attempt,
        ));
    }
    if lease.request_ref != expected.request_ref {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::Request,
        ));
    }
    if lease.operation_ref != expected.operation_ref {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::Operation,
        ));
    }
    if lease.candidate_ref != expected.candidate_ref
        || lease.resource_ref != expected.resource_ref
        || lease.scope_digest != expected.scope_digest
        || lease.canonical_root_identity_digest != expected.canonical_root_identity_digest
        || lease.resource_identity_digest != expected.resource_identity_digest
        || lease.measurement_digest != expected.measurement_digest
        || lease.resource_kind != expected.resource_kind
        || lease.reparse_policy != expected.reparse_policy
        || lease.network_policy != expected.network_policy
        || lease.device_policy != expected.device_policy
        || !fences_match_exact(&lease.state_fence, &expected.state_fence)
    {
        return Err(NativeResourceLeaseError::ResourceSubstituted);
    }
    if lease.registration_ref != expected.registration_ref
        || lease.broker_epoch != expected.broker_epoch
        || !lease
            .state_fence
            .authority_epoch
            .is_same_authority(&expected.authority_epoch)
    {
        return Err(NativeResourceLeaseError::Revoked);
    }
    if lease.consumer_generation != expected.consumer_generation {
        return Err(NativeResourceLeaseError::BindingMismatch(
            NativeResourceLeaseBindingField::ConsumerGeneration,
        ));
    }
    Ok(())
}

fn validate_resource_ref(value: &str) -> Result<(), NativeResourceLeaseError> {
    bounded_text(
        value,
        MAX_RESOURCE_REF_BYTES,
        NativeResourceLeaseField::ResourceRef,
    )?;
    if value.contains(['/', '\\', ':', '*', '?']) {
        return Err(NativeResourceLeaseError::InvalidField(
            NativeResourceLeaseField::ResourceRef,
        ));
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    max_bytes: usize,
    field: NativeResourceLeaseField,
) -> Result<(), NativeResourceLeaseError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(NativeResourceLeaseError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(
    value: &str,
    field: NativeResourceLeaseField,
) -> Result<(), NativeResourceLeaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NativeResourceLeaseError::InvalidField(field));
    }
    Ok(())
}

/// Field names used by the closed malformed-lease error surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeResourceLeaseField {
    LeaseId,
    ReceiptId,
    PrincipalRef,
    IssuerProcessRef,
    AttemptRef,
    RequestRef,
    OperationRef,
    CandidateRef,
    ResourceRef,
    ScopeDigest,
    CanonicalRootIdentityDigest,
    RegistrationRef,
    BrokerEpoch,
    ConsumerGeneration,
    StateFence,
    ResourceIdentityDigest,
    MeasurementDigest,
    LeaseDigest,
    MeasuredAt,
    LeaseWindow,
}

/// Binding mismatch labels used in a typed lease refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeResourceLeaseBindingField {
    Principal,
    Issuer,
    Attempt,
    Request,
    Operation,
    ConsumerGeneration,
}

/// Typed one-shot lease validation failures.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "detail")]
pub enum NativeResourceLeaseError {
    #[error("invalid native resource lease field: {0:?}")]
    InvalidField(NativeResourceLeaseField),
    #[error("native resource lease does not match {0:?}")]
    BindingMismatch(NativeResourceLeaseBindingField),
    #[error("native resource lease resource identity or scope was substituted")]
    ResourceSubstituted,
    #[error("native resource lease was revoked by registration or state-fence change")]
    Revoked,
    #[error("native resource lease has expired")]
    Expired,
    #[error("native resource lease has already been consumed")]
    Replay,
    #[error("native resource measurement is stale or temporally inconsistent")]
    StaleMeasurement,
    #[error("native resource lease has not become valid yet")]
    NotYetValid,
    #[error("native resource lease consumption receipt does not match the lease")]
    ReceiptBindingMismatch,
    #[error("native resource lease could not be canonically serialized for its receipt digest")]
    CanonicalDigestUnavailable,
}
