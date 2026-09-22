//! Host-issued restore destination authorization (issue #962, lane G).
//!
//! Architecture: A13.7 Backups, Restore, and Migration (restore executes in
//! an isolated area admitted by its owner; cutover needs separate
//! authority); A13.6 Operational Recovery State (only identities, opaque
//! envelopes, epochs, suspended leases, checkpoints, intents, manifests,
//! anchors); I1.2 Host process (owns the installation root, the approved
//! build registry, and the `HostStateJournal` boundary); I5.13 backup classes;
//! I5.16 common durable fields.
//! Implementation: I5.19 intent-before-effect ordering (the authorization is
//! issued before any destination effect and journaled by the Kernel before
//! later effects run); I14.21 unknown-commit recovery (a lost authorization
//! response retries with a fresh admitted request for the same descriptors
//! plus current owner evidence, never by replaying possibly stale bytes).
//!
//! What this file owns: the issuing owner half of restore destination
//! authorization. [`HostRestoreDestinationAuth::issue`] inspects the
//! committed installation registry through the existing read-only owner
//! query ([`RedbInstallationRegistry::inspect_existing_at`], A13.9
//! short-lived poll read — no writer is acquired and no registry mutation is
//! possible here) and binds exactly the fully validated chain below into one
//! [`DestinationAuthorization`]: lease-verified caller root equal to the
//! manifest root, validated registry, active approved generation, validated
//! manifest, topology-validated manifest-bound runtime roots, committed
//! fence, and fence↔manifest agreement. The bundle owns every record it
//! serves, so evidence cannot outlive its read and no caller input enters it
//! except the target/transaction/source descriptors the request binds.
//!
//! The authorization travels to the Kernel over the authenticated Host
//! runtime-control pipe as a digest-bound
//! [`HostRestoreDestinationReceipt`](eliot_host_service::runtime_control::HostRestoreDestinationReceipt):
//! the Kernel requests it for exact descriptors, the Host issues fresh
//! from live inspection per request, and the OS peer plus digest-bound
//! request/response correlation prove which service answered. No new pipe
//! family or transport is introduced, no Host lease is invented (the real
//! protected-root lease and installation registry owners issue every
//! fact), and no bare digest triple authorizes anything: digests ride
//! inside the owner-bound authorization the Kernel verifies in full.
//!
//! Capability cell: Host restore-destination ownership (destination
//! authorization issuance + authenticated queue dispatch).
//! Forbidden authority: no registry mutation, no epoch minting, no cutover,
//! no activation/retirement of any installation, no archive/phase rules, no
//! secret export, no live Host-state database copy.

use std::path::Path;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_host_service::runtime_control::{
    HostRestoreDestinationReceipt, HostRuntimeControlOperation, HostRuntimeControlRequest,
    HostRuntimeControlResponse, RESTORE_DESTINATION_ISSUER, RESTORE_DESTINATION_WIRE,
    runtime_control_refusal_ref,
};
use eliot_installation::{
    ActivationCommitFence, ApprovedGeneration, ApprovedGenerationRegistry, RedbInstallationRegistry,
    RuntimeStateRoots,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProtectedRootLease, windows_paths_equal};
use serde::{Deserialize, Serialize};

use super::HostComposition;

/// Wire identity of the Host-issued restore destination authorization. The
/// Kernel verifier requires this exact value.
pub const DESTINATION_AUTHORIZATION_WIRE: &str =
    "eliot.host.restore-destination-authorization.v1";
/// Issuer identity every authorization carries. The Kernel verifier requires
/// this exact value.
pub const DESTINATION_AUTHORIZATION_ISSUER: &str = "host-restore-destination-owner";
/// Maximum accepted serialized authorization bytes (bounded frame).
pub const MAX_AUTHORIZATION_BYTES: usize = 16_384;

/// Fail-closed issuance failure. Static reasons only: owner error internals
/// (registry bytes, lease details, digests) are never echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationAuthError {
    /// Presented request descriptor is malformed.
    InvalidRequest(&'static str),
    /// Protected-root lease or path proof failed.
    FilesystemEffect(&'static str),
    /// Owner evidence is absent, stale, or disagrees.
    OwnerEvidenceWithheld(&'static str),
}

impl std::fmt::Display for DestinationAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(field) => {
                write!(f, "restore destination request is invalid: {field}")
            }
            Self::FilesystemEffect(what) => {
                write!(f, "restore destination root proof failed: {what}")
            }
            Self::OwnerEvidenceWithheld(what) => {
                write!(f, "restore destination owner evidence withheld: {what}")
            }
        }
    }
}

/// Caller-presented descriptors one authorization binds. Every descriptor is
/// bounded text; authority facts always come from the inspected owner
/// evidence, never from these values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationAuthRequest {
    /// Presented source installation identity; must equal the owner-bound
    /// installation epoch.
    pub source_installation_id: String,
    /// Isolated restore target the authorization is issued for.
    pub target_id: String,
    /// Restore transaction the authorization is issued for.
    pub transaction_id: String,
}

impl DestinationAuthRequest {
    fn check_text(value: &str, field: &'static str) -> Result<(), DestinationAuthError> {
        if value.is_empty() || value.len() > 256 {
            return Err(DestinationAuthError::InvalidRequest(field));
        }
        Ok(())
    }

    /// Shape-checks the presented descriptors without granting authority.
    pub fn validate(&self) -> Result<(), DestinationAuthError> {
        Self::check_text(&self.source_installation_id, "source_installation_id")?;
        Self::check_text(&self.target_id, "target_id")?;
        Self::check_text(&self.transaction_id, "transaction_id")?;
        Ok(())
    }
}

/// Host-issued restore destination authorization: the owner-bound projection
/// every isolated destination must carry before restore effects run.
///
/// The issuing owner is this Host module; the Kernel verifier names this
/// issuer and cannot substitute its own bytes. Field names form the
/// cross-process contract the Kernel delivery codec rebuilds; both halves
/// pin the same [`DESTINATION_AUTHORIZATION_WIRE`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationAuthorization {
    /// Authorization wire discriminator.
    pub wire: String,
    /// Issuing owner identity.
    pub issuer: String,
    /// Owner-observed source installation identity.
    pub source_installation_id: String,
    /// Isolated restore target this authorization binds.
    pub target_id: String,
    /// Restore transaction this authorization binds.
    pub transaction_id: String,
    /// Owner config digest of the active manifest (hex64).
    pub manifest_digest: String,
    /// Digest of the manifest-bound runtime roots (hex64).
    pub roots_digest: String,
    /// Registry CAS revision observed at inspection time.
    pub registry_revision: u64,
    /// Kernel work root text bound by the active manifest roots.
    pub kernel_work_root: String,
    /// Active approved generation identity.
    pub approved_generation: String,
    /// Committed activation-fence generation bound to the manifest.
    pub fence_generation: String,
    /// Committed activation-fence config digest bound to the manifest.
    pub fence_config_digest: String,
    /// Committed activation-fence authority generation (live currency).
    pub fence_authority_generation: u64,
}

impl DestinationAuthorization {
    /// Validates shapes and the wire/issuer binding of issued bytes.
    pub fn validate(&self) -> Result<(), DestinationAuthError> {
        if self.wire.as_str() != DESTINATION_AUTHORIZATION_WIRE
            || self.issuer.as_str() != DESTINATION_AUTHORIZATION_ISSUER
        {
            return Err(DestinationAuthError::InvalidRequest("wire"));
        }
        for (value, field) in [
            (&self.source_installation_id, "source_installation_id"),
            (&self.target_id, "target_id"),
            (&self.transaction_id, "transaction_id"),
            (&self.kernel_work_root, "kernel_work_root"),
            (&self.approved_generation, "approved_generation"),
        ] {
            if value.is_empty() || value.len() > 1024 {
                return Err(DestinationAuthError::InvalidRequest(field));
            }
        }
        if !is_hex64(&self.manifest_digest) || !is_hex64(&self.roots_digest) {
            return Err(DestinationAuthError::InvalidRequest("manifest_digest"));
        }
        if !is_hex64(&self.fence_config_digest) {
            return Err(DestinationAuthError::InvalidRequest("fence_config_digest"));
        }
        for (value, field) in [
            (&self.fence_generation, "fence_generation"),
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(DestinationAuthError::InvalidRequest(field));
            }
        }
        Ok(())
    }

    /// Canonical bytes of this authorization for stable digesting.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DestinationAuthError> {
        self.validate()?;
        canonical_json_bytes(self).map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("encode"))
    }

    /// Stable digest binding this exact authorization for effect receipts.
    pub fn authorization_digest(&self) -> Result<String, DestinationAuthError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Fully bound owner evidence for one protected Host root: the inspected
/// registry, its active approved generation, and the committed activation
/// fence agreed with the manifest. Read-only; owns every record it serves.
struct InspectedOwnerEvidence {
    registry: ApprovedGenerationRegistry,
    approved: ApprovedGeneration,
    fence: ActivationCommitFence,
}

impl InspectedOwnerEvidence {
    /// Inspects and binds the committed owner evidence below one protected
    /// Host root.
    ///
    /// Order, mirroring the host open precedent
    /// (`open_installation_registry_with_transient_retry` plus manifest
    /// validation): absolute-path gate, protected-root lease, canonical
    /// path, stable-identity proof, caller-root equality, read-only registry
    /// inspection, registry validation, active generation, manifest
    /// validation, manifest-bound runtime-roots validation and profile
    /// agreement, manifest-root equality, committed fence, fence validation,
    /// and fence↔manifest agreement. Any step fails closed with a static
    /// [`DestinationAuthError`]; owner error internals are never echoed.
    /// Absence of proof is never treated as proof of absence.
    fn inspect(host_state_root: &Path) -> Result<Self, DestinationAuthError> {
        if !host_state_root.is_absolute() {
            return Err(DestinationAuthError::InvalidRequest("host_state_root"));
        }
        let lease = ProtectedRootLease::open_existing(host_state_root)
            .map_err(|_| DestinationAuthError::FilesystemEffect("protected source root"))?;
        let canonical = lease
            .canonical_path()
            .map_err(|_| DestinationAuthError::FilesystemEffect("resolve source root"))?;
        lease
            .verify_stable_identity()
            .map_err(|_| DestinationAuthError::FilesystemEffect("verify source identity"))?;
        if !windows_paths_equal(host_state_root, &canonical) {
            return Err(DestinationAuthError::InvalidRequest("host_state_root"));
        }
        let registry = RedbInstallationRegistry::inspect_existing_at(lease)
            .map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("source_registry"))?
            .ok_or(DestinationAuthError::OwnerEvidenceWithheld("source_registry"))?;
        registry
            .validate()
            .map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("source_registry"))?;
        let approved = registry
            .active()
            .cloned()
            .ok_or(DestinationAuthError::OwnerEvidenceWithheld(
                "approved_generation",
            ))?;
        approved
            .manifest
            .validate()
            .map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("approved_generation"))?;
        let roots: &RuntimeStateRoots = &approved.manifest.runtime_launch.runtime_state_roots;
        roots
            .validate()
            .map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("source_roots"))?;
        if approved.manifest.runtime_launch.profile != roots.profile {
            return Err(DestinationAuthError::OwnerEvidenceWithheld("source_roots"));
        }
        if !windows_paths_equal(Path::new(roots.host_state_root.as_str()), &canonical) {
            return Err(DestinationAuthError::OwnerEvidenceWithheld("host_state_root"));
        }
        let fence = registry
            .last_committed_activation_fence()
            .cloned()
            .ok_or(DestinationAuthError::OwnerEvidenceWithheld("commit_fence"))?;
        fence
            .validate()
            .map_err(|_| DestinationAuthError::OwnerEvidenceWithheld("commit_fence"))?;
        if fence.generation.as_str() != approved.manifest.generation.as_str()
            || fence.config_digest.as_str() != approved.manifest.config_digest.as_str()
            || fence.authority_generation != approved.manifest.runtime_launch.authority_generation
        {
            return Err(DestinationAuthError::OwnerEvidenceWithheld("commit_fence"));
        }
        Ok(Self {
            registry,
            approved,
            fence,
        })
    }

    /// Registry CAS revision observed at inspection time ("current": the
    /// preparation owner compares revisions to detect registry movement
    /// between inspection and preparation).
    fn revision(&self) -> u64 {
        self.registry.revision()
    }
}

/// Host restore-destination owner: issues and transports destination
/// authorizations from committed installation evidence.
pub struct HostRestoreDestinationAuth;

impl HostRestoreDestinationAuth {
    /// Issues one destination authorization from freshly inspected owner
    /// evidence below `host_state_root` plus the presented descriptors.
    ///
    /// The presented source installation must equal the owner-bound
    /// installation epoch; manifest, roots, fence, and revision facts come
    /// only from the inspected evidence. Re-issuance after response loss
    /// re-inspects first: a changed registry (new revision, rotated
    /// generation, drifted fence) yields a new authorization bound to the
    /// new facts or a fail-closed refusal — never a replay of stale bytes.
    pub fn issue(
        host_state_root: &Path,
        request: &DestinationAuthRequest,
    ) -> Result<DestinationAuthorization, DestinationAuthError> {
        request.validate()?;
        let evidence = InspectedOwnerEvidence::inspect(host_state_root)?;
        let installation_epoch = &evidence
            .approved
            .manifest
            .runtime_launch
            .installation_epoch;
        if installation_epoch.installation.as_str() != request.source_installation_id {
            return Err(DestinationAuthError::InvalidRequest("source_installation_id"));
        }
        let manifest_digest = evidence.approved.manifest.config_digest.as_str();
        let roots = &evidence
            .approved
            .manifest
            .runtime_launch
            .runtime_state_roots;
        let roots_digest = roots.roots_digest.as_str();
        if !is_hex64(manifest_digest) || !is_hex64(roots_digest) {
            return Err(DestinationAuthError::OwnerEvidenceWithheld("manifest_digest"));
        }
        let fence = &evidence.fence;
        let auth = DestinationAuthorization {
            wire: DESTINATION_AUTHORIZATION_WIRE.to_owned(),
            issuer: DESTINATION_AUTHORIZATION_ISSUER.to_owned(),
            source_installation_id: request.source_installation_id.clone(),
            target_id: request.target_id.clone(),
            transaction_id: request.transaction_id.clone(),
            manifest_digest: manifest_digest.to_owned(),
            roots_digest: roots_digest.to_owned(),
            registry_revision: evidence.revision(),
            kernel_work_root: roots.kernel_work_root.as_str().to_owned(),
            approved_generation: evidence.approved.manifest.generation.as_str().to_owned(),
            fence_generation: fence.generation.as_str().to_owned(),
            fence_config_digest: fence.config_digest.as_str().to_owned(),
            fence_authority_generation: fence.authority_generation.value(),
        };
        auth.validate()?;
        Ok(auth)
    }
}

impl HostComposition {
    /// Issues one restore destination authorization from the retained Host
    /// root's committed installation evidence.
    ///
    /// Thin owner delegation into [`HostRestoreDestinationAuth::issue`]:
    /// the retained `registry_host_root` (never caller text) plus the
    /// presented target/transaction/source descriptors. The issued
    /// authorization is returned to the authenticated queue dispatcher,
    /// which answers the digest-bound request with the Host-issued receipt.
    pub fn issue_restore_destination_authorization(
        &self,
        request: &DestinationAuthRequest,
    ) -> Result<DestinationAuthorization, DestinationAuthError> {
        HostRestoreDestinationAuth::issue(&self.registry_host_root, request)
    }

    /// Serves one restore-destination authorization request from the
    /// authenticated runtime-control queue: validates the digest-bound
    /// descriptors, requires the live owner lease, issues fresh from live
    /// inspection, and returns the Host-issued receipt.
    ///
    /// Deterministic failures (validation, lease fence, issuance) return
    /// typed `Refused` with the exact reason — final for these descriptors,
    /// never confused with the genuine uncertainty `Unknown` reserves for
    /// queue/transport loss. Issuance is effect-free read-only: a repeated
    /// request re-inspects and returns current owner facts rather than
    /// replaying possibly stale bytes.
    pub fn handle_restore_destination_request(
        &self,
        request: &HostRuntimeControlRequest,
    ) -> HostRuntimeControlResponse {
        let refused = |reason: &str| {
            super::host_lifecycle_observe_terminal("host-restore-destination-unknown");
            HostRuntimeControlResponse::refused_for(
                request,
                runtime_control_refusal_ref(reason, request),
            )
        };
        super::host_lifecycle_observe_scm("host.restore-destination requested");
        if request.operation != HostRuntimeControlOperation::DeliverRestoreDestinationAuth
            || request.validate().is_err()
        {
            return refused("restore-destination-validation");
        }
        if self
            .owner_lease
            .activation_capability()
            .live_guard()
            .is_err()
        {
            return refused("restore-destination-lease-fenced");
        }
        let Some(input) = request.restore_destination.as_ref() else {
            return refused("restore-destination-validation");
        };
        let issue_request = DestinationAuthRequest {
            source_installation_id: input.source_installation_id.as_str().to_owned(),
            target_id: input.target_id.as_str().to_owned(),
            transaction_id: input.transaction_id.as_str().to_owned(),
        };
        let Ok(auth) =
            HostRestoreDestinationAuth::issue(&self.registry_host_root, &issue_request)
        else {
            return refused("restore-destination-issuance");
        };
        let handle = |value: &str| PlatformHandle::new(value.to_owned());
        let mut receipt = HostRestoreDestinationReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            wire: match handle(RESTORE_DESTINATION_WIRE) {
                Ok(wire) => wire,
                Err(_) => return refused("restore-destination-issuance"),
            },
            issuer: match handle(RESTORE_DESTINATION_ISSUER) {
                Ok(issuer) => issuer,
                Err(_) => return refused("restore-destination-issuance"),
            },
            source_installation_id: match handle(&auth.source_installation_id) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            target_id: match handle(&auth.target_id) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            transaction_id: match handle(&auth.transaction_id) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            manifest_digest: match handle(&auth.manifest_digest) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            roots_digest: match handle(&auth.roots_digest) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            registry_revision: auth.registry_revision,
            kernel_work_root: match handle(&auth.kernel_work_root) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            approved_generation: match handle(&auth.approved_generation) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            fence_generation: match handle(&auth.fence_generation) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            fence_config_digest: match handle(&auth.fence_config_digest) {
                Ok(value) => value,
                Err(_) => return refused("restore-destination-issuance"),
            },
            fence_authority_generation: auth.fence_authority_generation,
            // Placeholder replaced by the computed digest below; the
            // request digest is a valid handle of the right shape.
            receipt_digest: request.request_digest.clone(),
        };
        receipt.receipt_digest = match receipt.computed_digest() {
            Ok(digest) => digest,
            Err(_) => return refused("restore-destination-issuance"),
        };
        if receipt.validate().is_err() {
            return refused("restore-destination-issuance");
        }
        super::host_lifecycle_observe_scm("host.restore-destination receipt completion");
        HostRuntimeControlResponse::destination_authorized_for(request, receipt)
    }
}
