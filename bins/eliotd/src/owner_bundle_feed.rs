//! Governor P-07 owner feed for `eliotd`.
//!
//! Architecture traceability: I6.15 makes the Governor the owner of canonical
//! grant semantics, parent lineage, and introduction compilation; I1.8 keeps
//! Kernel enforcement behind the P-07 boundary; A13.2 keeps daemon/Kernel
//! failure domains explicit.
//!
//! This module owns the daemon side of the durable owner chain: it builds
//! the canonical [`OwnerClosureProvider`] from the live Governor
//! composition's restored authority state plus explicit CURRENT
//! revocation-history evidence, serves [`GovernorClosureRestore`] bundles
//! for the Kernel-side [`bind`](eliot_kernel_core::bind_canonical_owner),
//! persists the admitted registry across daemon restarts, and publishes
//! bundles toward the Kernel over the existing daemon→Kernel transport.
//!
//! Forbidden boundary: no ORS access (the Kernel owns ORS in its own
//! process), no Kernel state invention, no secret bytes (references only),
//! no silent empty bundles. The Kernel serves the published bundle through
//! its front-door owner route; until that route lands the publish call fails
//! closed through the typed transport mapping — honest diagnosed
//! degradation, never invented rights.

use std::sync::Arc;

use eliot_authority::RevocationHistoryEvidence;
use eliot_contracts::StateFence;
use eliot_governor::{
    AuthorityOwnerSnapshot, GrantAdmissionParams, IntroductionAdmissionParams,
    OwnerClosureProvider, PreservedAdmission,
};
use eliot_kernel_core::{
    GovernorClosureRestore, GrantClosureMember, IntroductionHydration, RootGrantHydration,
};

use super::{DaemonComposition, DaemonError};
use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_authority_client::KernelAuthorityClient;

/// Registry snapshot file retained under the daemon state root.
const OWNER_HYDRATIONS_FILE: &str = "owner-hydrations.snapshot";
/// Hard ceiling for persisted admitted-registry bytes.
const MAX_OWNER_HYDRATION_BYTES: u64 = 4 * 1024 * 1024;

/// Daemon-side canonical owner feed behind the P-07 durable boundary.
///
/// Constructed from the live Governor composition's restored authority
/// snapshot plus explicit CURRENT history (served by the daemon's
/// revocation-history read), with the previously persisted admitted
/// registry re-imported when present. The feed serves restore bundles at
/// the provider revision and persists registry changes for restart.
pub struct OwnerBundleFeed {
    provider: OwnerClosureProvider,
    served_revision: Option<u64>,
}

impl OwnerBundleFeed {
    /// Builds the feed from canonical Governor state.
    ///
    /// `persisted` carries previously exported registry bytes when the
    /// daemon state root holds them (`None` on first boot). Disagreeing
    /// bytes fail closed instead of silently starting from an empty
    /// registry.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for an invalid snapshot, absent or stale
    /// history, or disagreeing persisted registry bytes.
    pub fn build(
        snapshot: AuthorityOwnerSnapshot,
        history: Option<RevocationHistoryEvidence>,
        fence: &StateFence,
        persisted: Option<&[u8]>,
    ) -> Result<Self, DaemonError> {
        let mut provider = OwnerClosureProvider::restore(snapshot, history, fence)?;
        if let Some(bytes) = persisted {
            provider.import_registry(bytes)?;
        }
        Ok(Self {
            provider,
            served_revision: None,
        })
    }

    /// Returns the exact restored graph revision this feed serves.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.provider.revision()
    }

    /// Returns the distinct admitted lineage roots, sorted.
    #[must_use]
    pub fn authority_roots(&self) -> Vec<String> {
        self.provider.authority_roots()
    }

    /// Returns the bundle revision last served, if any bundle was served.
    #[must_use]
    pub const fn served_revision(&self) -> Option<u64> {
        self.served_revision
    }

    /// Serves the complete restore bundle the Kernel-side mirror binds at
    /// the provider revision, and records the served revision.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when no grant hydration is admitted.
    pub fn serve_bundle(&mut self) -> Result<GovernorClosureRestore, DaemonError> {
        let restore = self.provider.serve_restore()?;
        self.served_revision = Some(self.provider.revision());
        Ok(restore)
    }

    /// Rebinds the provider from newer durable Governor state, carrying
    /// admissions over only when they still resolve. Publishing must
    /// re-serve after a successful refresh: the recorded served revision
    /// clears so a stale bundle can never be republished.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for a fence change, a stale revision, or
    /// admitted material that disagrees with the new state.
    pub fn refresh(
        &mut self,
        snapshot: AuthorityOwnerSnapshot,
        history: Option<RevocationHistoryEvidence>,
        expected_revision: u64,
    ) -> Result<(), DaemonError> {
        self.provider.refresh(snapshot, history, expected_revision)?;
        self.served_revision = None;
        Ok(())
    }

    /// Admits one delegated member hydration into the registry.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for lineage, binding, or identity
    /// disagreement.
    pub fn admit_grant_member(
        &mut self,
        params: &GrantAdmissionParams,
        secret: &eliot_platform::SecretReference,
        observed_at_ms: i64,
    ) -> Result<GrantClosureMember, DaemonError> {
        Ok(self
            .provider
            .admit_grant_member(params, secret, observed_at_ms)?)
    }

    /// Admits one authority-root hydration into the registry.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for lineage, binding, or identity
    /// disagreement, or a non-root grant.
    pub fn admit_grant_root(
        &mut self,
        params: &GrantAdmissionParams,
        secret: &eliot_platform::SecretReference,
        observed_at_ms: i64,
    ) -> Result<RootGrantHydration, DaemonError> {
        Ok(self
            .provider
            .admit_grant_root(params, secret, observed_at_ms)?)
    }

    /// Admits one introduction hydration into the registry.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for unknown, non-active, or cross-root
    /// supporting lineage.
    pub fn admit_introduction(
        &mut self,
        params: &IntroductionAdmissionParams,
        secret: &eliot_platform::SecretReference,
        observed_at_ms: i64,
    ) -> Result<IntroductionHydration, DaemonError> {
        Ok(self
            .provider
            .admit_introduction(params, secret, observed_at_ms)?)
    }

    /// Admits one owner-declared alternate-path survivor.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for unknown target, survivor, or covering
    /// lineage.
    pub fn admit_preserved(&mut self, admission: PreservedAdmission) -> Result<(), DaemonError> {
        Ok(self.provider.admit_preserved(admission)?)
    }

    /// Exports the admitted registry as versioned canonical bytes for
    /// daemon state persistence.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the snapshot cannot be rendered.
    pub fn export_registry(&self) -> Result<Vec<u8>, DaemonError> {
        Ok(self.provider.export_registry()?)
    }
}

/// Builds the canonical owner feed from the live Governor composition.
///
/// The restored authority snapshot and fence come from the composition's
/// retained authority owner; `history` is the explicit CURRENT
/// revocation-history evidence served by the daemon's revocation-history
/// read; previously persisted registry bytes are re-imported from the
/// daemon state root when present (first boot proceeds without them).
///
/// # Errors
///
/// Returns [`DaemonError`] for an unrestorable snapshot, absent history,
/// disagreeing persisted bytes, or unreadable daemon state.
pub fn build_owner_feed(
    composition: &DaemonComposition,
    history: Option<RevocationHistoryEvidence>,
) -> Result<OwnerBundleFeed, DaemonError> {
    let owner = &composition.governor.owners().authority;
    let snapshot = owner.snapshot()?;
    let fence = owner.state_fence().clone();
    let persisted = read_persisted_registry(composition)?;
    OwnerBundleFeed::build(snapshot, history, &fence, persisted.as_deref())
}

/// Persists the feed's admitted registry to the daemon state root for
/// restart recovery. The bytes carry intents plus opaque records only.
///
/// # Errors
///
/// Returns [`DaemonError`] when the registry cannot be rendered or the
/// protected state file cannot be proven and written.
pub fn persist_owner_feed(
    composition: &DaemonComposition,
    feed: &OwnerBundleFeed,
) -> Result<(), DaemonError> {
    let bytes = feed.export_registry()?;
    if bytes.len() as u64 > MAX_OWNER_HYDRATION_BYTES {
        return Err(DaemonError::Lifecycle(
            "admitted registry exceeds the persistence bound".to_owned(),
        ));
    }
    let path = composition.state_root().join(OWNER_HYDRATIONS_FILE);
    let lease =
        eliot_platform_windows::ProtectedRuntimePathLease::open_or_create_absolute(&path)?;
    std::fs::write(lease.path(), &bytes).map_err(|_| {
        DaemonError::Lifecycle("admitted registry state file is not writable".to_owned())
    })?;
    Ok(())
}

/// Reads previously persisted registry bytes, if the state root holds
/// them. Absence is first boot, not an error; an unreadable file fails
/// closed instead of starting from a silently empty registry.
fn read_persisted_registry(
    composition: &DaemonComposition,
) -> Result<Option<Vec<u8>>, DaemonError> {
    let path = composition.state_root().join(OWNER_HYDRATIONS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let lease =
        eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    let bytes = lease.read_bounded(MAX_OWNER_HYDRATION_BYTES)?;
    Ok(Some(bytes))
}

/// Publishes one served bundle toward the Kernel owner route and returns
/// the Kernel-bound revision from the acknowledgement.
///
/// The bundle travels the existing daemon→Kernel transport as one JSON
/// operation; the Kernel binds it through its composition owner step.
/// Until the Kernel serves the route the call fails closed through the
/// typed transport mapping — honest diagnosed degradation.
///
/// # Errors
///
/// Returns the mapped transport refusal, or a binding failure for a
/// malformed acknowledgement.
pub fn publish_owner_bundle(
    kernel: &Arc<DaemonKernelClient>,
    bundle: &GovernorClosureRestore,
) -> Result<u64, eliot_authority::P07PortError> {
    KernelAuthorityClient::new(Arc::clone(kernel)).publish_owner_bundle(bundle)
}
