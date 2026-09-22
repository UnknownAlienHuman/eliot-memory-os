//! Dedicated grant authorization (issue #1955, I14.19).
//!
//! Turns a wire-accepted [`AcceptedGrant`](crate::grant_client::AcceptedGrant)
//! into an [`AuthorizedGrant`] the child engine may consume. The wire accept
//! path proves the grant came from the authenticated Kernel channel intact;
//! this module proves the grant is *usable here*: the caller-asserted
//! component digests are re-hashed against the real artifact/interface bytes
//! staged for launch, and the grant's host binary binding is matched against
//! the live installation-approved records before anything is staged.
//!
//! Trust model: the installation records arrive only from the live
//! `RuntimeLaunchDescriptor` through `wasm_host_artifact_binding()`
//! (B2/installer lane, read-only — the descriptor self-validates before the
//! pair is released); [`authorize_grant_against_descriptor`] is the single
//! entry that couples a served grant to those records. Component bytes are
//! caller-staged evidence, re-hashed here — never trusted from the grant.
//! The output carries the [`WasmHostBinaryBinding`](crate::installed_binary::WasmHostBinaryBinding)
//! the resolver consumes plus the grant-proven component digests the
//! isolated-child engine enforces at invoke. Freshness (deadline) was
//! already enforced at wire accept; fence/epoch are threaded through
//! untouched — this module never re-decides Kernel authority.
//!
//! Failure discipline follows `grant_client`: stable `Denied` fields only,
//! no paths, bytes, or digests echoed.

use std::path::PathBuf;

use eliot_wasm_runtime::Sha256Digest;

use crate::grant_client::{AcceptedGrant, GrantClientError};
use crate::installed_binary::WasmHostBinaryBinding;

/// A grant proven usable at this host: component claims re-hashed against
/// real bytes, host binding matched against installation-approved records.
///
/// The isolated-child engine consumes exactly this: its admitted artifact
/// identity is the grant-proven digest below, and the resolver consumes the
/// host binding. Neither value is a caller claim anymore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedGrant {
    /// Admitted component identity, echoed from the served grant.
    component_id: String,
    /// Component artifact digest, re-proven against staged bytes.
    artifact_digest: Sha256Digest,
    /// WIT interface digest, re-proven against staged bytes.
    interface_digest: Sha256Digest,
    /// Kernel-observed fence at issuance, threaded through.
    fence: eliot_contracts::StateFence,
    /// Kernel-observed epoch at issuance, threaded through.
    epoch: eliot_contracts::EpochId,
    /// Caller nonce echoed from issuance.
    nonce: String,
    /// Deadline echoed from issuance (already enforced at wire accept).
    deadline_unix_ms: u64,
    /// Installation-approved host binary binding matched to the grant.
    host_binding: WasmHostBinaryBinding,
}

impl AuthorizedGrant {
    /// Returns the admitted component identity.
    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// Returns the grant-proven artifact digest the engine enforces.
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    /// Returns the grant-proven interface digest.
    #[must_use]
    pub const fn interface_digest(&self) -> &Sha256Digest {
        &self.interface_digest
    }

    /// Returns the Kernel-observed fence threaded from issuance.
    #[must_use]
    pub const fn fence(&self) -> &eliot_contracts::StateFence {
        &self.fence
    }

    /// Returns the Kernel-observed epoch threaded from issuance.
    #[must_use]
    pub const fn epoch(&self) -> &eliot_contracts::EpochId {
        &self.epoch
    }

    /// Returns the caller nonce echoed from issuance.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the deadline echoed from issuance.
    #[must_use]
    pub const fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    /// Returns the installation-approved host binding the resolver consumes.
    #[must_use]
    pub const fn host_binding(&self) -> &WasmHostBinaryBinding {
        &self.host_binding
    }
}

/// Authorizes one wire-accepted grant against live installation records.
///
/// Re-hashes `artifact_bytes`/`interface_bytes` against the grant's
/// caller-asserted digests, then requires the grant's host binary binding
/// to equal the installation-approved `(path, digest)` records exactly.
/// Every mismatch fails closed; the returned [`AuthorizedGrant`] is the
/// only value the child engine and resolver consume.
///
/// # Errors
///
/// Returns [`GrantClientError::Denied`] with the stable offending field
/// (`artifact_digest`, `interface_digest`, `host_executable_path`,
/// `host_artifact_digest`, or `binding`) when any check fails.
pub fn authorize_grant(
    accepted: &AcceptedGrant,
    installation_executable_path: &str,
    installation_artifact_digest: &Sha256Digest,
    artifact_bytes: &[u8],
    interface_bytes: &[u8],
) -> Result<AuthorizedGrant, GrantClientError> {
    let denied = |field: &'static str| GrantClientError::Denied { field };
    if Sha256Digest::of_bytes(artifact_bytes) != accepted.artifact_digest {
        return Err(denied("artifact_digest"));
    }
    if Sha256Digest::of_bytes(interface_bytes) != accepted.interface_digest {
        return Err(denied("interface_digest"));
    }
    if accepted.host_executable_path != installation_executable_path {
        return Err(denied("host_executable_path"));
    }
    if accepted.host_artifact_digest != *installation_artifact_digest {
        return Err(denied("host_artifact_digest"));
    }
    let host_binding = WasmHostBinaryBinding::new(
        PathBuf::from(installation_executable_path),
        installation_artifact_digest.clone(),
    )
    .map_err(|_| denied("binding"))?;
    Ok(AuthorizedGrant {
        component_id: accepted.component_id.clone(),
        artifact_digest: accepted.artifact_digest.clone(),
        interface_digest: accepted.interface_digest.clone(),
        fence: accepted.fence.clone(),
        epoch: accepted.epoch.clone(),
        nonce: accepted.nonce.clone(),
        deadline_unix_ms: accepted.deadline_unix_ms,
        host_binding,
    })
}

/// Authorizes one wire-accepted grant against the live installation
/// descriptor.
///
/// Read-only consumption of the B2/installer lane: the descriptor
/// self-validates through `wasm_host_artifact_binding()` before its records
/// are released, then [`authorize_grant`] proves the served grant against
/// those records and the staged bytes. Any descriptor rejection,
/// non-conforming record, or grant mismatch fails closed with
/// [`GrantClientError::Denied`] (`descriptor` for descriptor-side failure).
///
/// # Errors
///
/// Returns [`GrantClientError::Denied`] when the descriptor rejects or any
/// authorization check fails.
pub fn authorize_grant_against_descriptor(
    accepted: &AcceptedGrant,
    descriptor: &eliot_installation::RuntimeLaunchDescriptor,
    artifact_bytes: &[u8],
    interface_bytes: &[u8],
) -> Result<AuthorizedGrant, GrantClientError> {
    let denied = |field: &'static str| GrantClientError::Denied { field };
    let (path, digest) = descriptor
        .wasm_host_artifact_binding()
        .map_err(|_| denied("descriptor"))?;
    let installation_digest =
        Sha256Digest::new(digest.as_str()).map_err(|_| denied("descriptor"))?;
    authorize_grant(
        accepted,
        path.as_str(),
        &installation_digest,
        artifact_bytes,
        interface_bytes,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_fence_epoch() -> (eliot_contracts::StateFence, eliot_contracts::EpochId) {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
        let fence = StateFence::new(epoch.clone(), ResourceGeneration::genesis());
        (fence, epoch)
    }

    fn accepted_fixture(
        host_path: &str,
        host_digest: &Sha256Digest,
        artifact_bytes: &[u8],
        interface_bytes: &[u8],
    ) -> AcceptedGrant {
        let (fence, epoch) = test_fence_epoch();
        AcceptedGrant {
            component_id: "component-1955".to_owned(),
            artifact_digest: Sha256Digest::of_bytes(artifact_bytes),
            interface_digest: Sha256Digest::of_bytes(interface_bytes),
            fence,
            epoch,
            nonce: "nonce-1955".to_owned(),
            deadline_unix_ms: 9_999_999_999_999,
            host_executable_path: host_path.to_owned(),
            host_artifact_digest: host_digest.clone(),
        }
    }

    fn installation() -> (String, Sha256Digest) {
        (
            "C:\\Kernel\\eliot-wasm-host.exe".to_owned(),
            Sha256Digest::of_bytes(b"installed-wasm-host-image-bytes"),
        )
    }

    #[test]
    fn matching_grant_and_records_authorize() {
        let artifact = b"component-artifact-bytes";
        let interface = b"wit-world-bytes";
        let (path, digest) = installation();
        let accepted = accepted_fixture(&path, &digest, artifact, interface);
        let authorized = authorize_grant(&accepted, &path, &digest, artifact, interface)
            .expect("matching grant authorizes");
        assert_eq!(authorized.component_id(), "component-1955");
        assert_eq!(
            authorized.artifact_digest(),
            &Sha256Digest::of_bytes(artifact)
        );
        assert_eq!(
            authorized.interface_digest(),
            &Sha256Digest::of_bytes(interface)
        );
        assert_eq!(authorized.nonce(), "nonce-1955");
        assert_eq!(authorized.deadline_unix_ms(), 9_999_999_999_999);
        assert_eq!(authorized.host_binding().artifact_digest(), &digest);
        assert_eq!(
            authorized
                .host_binding()
                .executable_path()
                .as_os_str()
                .to_str(),
            Some(path.as_str())
        );
    }

    #[test]
    fn mismatched_claims_fail_closed_by_field() {
        let artifact = b"component-artifact-bytes";
        let interface = b"wit-world-bytes";
        let (path, digest) = installation();
        let accepted = accepted_fixture(&path, &digest, artifact, interface);
        assert_eq!(
            authorize_grant(&accepted, &path, &digest, b"other-artifact", interface),
            Err(GrantClientError::Denied {
                field: "artifact_digest"
            })
        );
        assert_eq!(
            authorize_grant(&accepted, &path, &digest, artifact, b"other-wit"),
            Err(GrantClientError::Denied {
                field: "interface_digest"
            })
        );
        assert_eq!(
            authorize_grant(
                &accepted,
                "C:\\Kernel\\other-host.exe",
                &digest,
                artifact,
                interface
            ),
            Err(GrantClientError::Denied {
                field: "host_executable_path"
            })
        );
        assert_eq!(
            authorize_grant(
                &accepted,
                &path,
                &Sha256Digest::of_bytes(b"other-image"),
                artifact,
                interface
            ),
            Err(GrantClientError::Denied {
                field: "host_artifact_digest"
            })
        );
    }

    #[test]
    fn descriptor_side_failure_is_descriptor_denial() {
        // An unvalidated descriptor rejects before any grant bytes are
        // compared: the failure is attributed to the descriptor, and no
        // descriptor content is echoed.
        use eliot_installation::PlatformHandle;
        let placeholder = || PlatformHandle::new("placeholder").expect("placeholder");
        let descriptor = eliot_installation::RuntimeLaunchDescriptor {
            profile: eliot_installation::InstallationProfile::PortableDev,
            portable_root: None,
            installation_epoch: eliot_installation::InstallationEpoch {
                installation: placeholder(),
                lineage_id: placeholder(),
                sequence: 1,
            },
            generation: placeholder(),
            authority_generation: eliot_contracts::ResourceGeneration::genesis(),
            authority_state_fence: test_fence_epoch().0,
            authority_descriptor_path: placeholder(),
            authority_descriptor_digest: placeholder(),
            supervision_authority: eliot_installation::SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: placeholder(),
            },
            runtime_state_roots: eliot_installation::RuntimeStateRoots {
                profile: eliot_installation::InstallationProfile::PortableDev,
                profile_anchor_root: placeholder(),
                installation_root: placeholder(),
                host_state_root: placeholder(),
                kernel_ors_root: placeholder(),
                kernel_work_root: placeholder(),
                store_data_root: placeholder(),
                store_work_root: placeholder(),
                store_temp_root: placeholder(),
                watchdog_state_root: placeholder(),
                roots_digest: placeholder(),
            },
            kernel_work_root: placeholder(),
            kernel_artifact_digest: placeholder(),
            eliotd_executable_path: placeholder(),
            eliotd_artifact_digest: placeholder(),
            eliotd_config_path: placeholder(),
            eliotd_config_digest: placeholder(),
            protected_snapshot_digest: placeholder(),
            eliotd_descriptor_path: placeholder(),
            eliotd_descriptor_digest: placeholder(),
            eliotd_launch_nonce: placeholder(),
            store_config_path: placeholder(),
            store_credential_target: placeholder(),
            store_bridge_executable_path: placeholder(),
            store_bridge_artifact_digest: placeholder(),
            store_bootstrap_descriptor_path: placeholder(),
            store_bootstrap_descriptor_digest: placeholder(),
            canonical_store_executable_path: placeholder(),
            canonical_store_artifact_digest: placeholder(),
            kernel_arguments: Vec::new(),
            store_bridge_arguments: Vec::new(),
            canonical_store_arguments: Vec::new(),
            host_executable_path: placeholder(),
            host_artifact_digest: placeholder(),
            watchdog_executable_path: placeholder(),
            watchdog_artifact_digest: placeholder(),
            doctor_artifact_digest: placeholder(),
            testd_artifact_digest: placeholder(),
            native_worker_artifact_digest: placeholder(),
            wasm_host_artifact_digest: placeholder(),
            doctor_executable_path: placeholder(),
            testd_executable_path: placeholder(),
            native_worker_executable_path: placeholder(),
            wasm_host_executable_path: placeholder(),
            descriptor_digest: placeholder(),
        };
        let artifact = b"component-artifact-bytes";
        let interface = b"wit-world-bytes";
        let (path, digest) = installation();
        let accepted = accepted_fixture(&path, &digest, artifact, interface);
        assert_eq!(
            authorize_grant_against_descriptor(&accepted, &descriptor, artifact, interface),
            Err(GrantClientError::Denied {
                field: "descriptor"
            })
        );
    }
}
