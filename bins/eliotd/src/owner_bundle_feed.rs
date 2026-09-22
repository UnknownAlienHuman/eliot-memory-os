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
    OwnerClosureProvider, PreservedAdmission, decode_revocation_history_evidence,
    revocation_history_read_request,
};
use eliot_kernel_core::{
    GovernorClosureRestore, GrantClosureMember, IntroductionHydration, RootGrantHydration,
    owner_bundle_digest,
};
use eliot_store_api::InfluenceDependencyClosure;

use super::{DaemonComposition, DaemonError};
use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_authority_client::KernelAuthorityClient;

/// Registry snapshot file retained under the daemon state root.
const OWNER_HYDRATIONS_FILE: &str = "owner-hydrations.snapshot";
/// Hard ceiling for persisted admitted-registry bytes.
const MAX_OWNER_HYDRATION_BYTES: u64 = 4 * 1024 * 1024;
/// Per-root history read bound: bounded evidence pages, never an open scan.
const HISTORY_READ_MAX_RECORDS: u32 = 64;

/// Exact publish disposition for one served owner bundle.
///
/// Every variant preserves what the caller needs next: `Bound` carries the
/// Kernel-acknowledged revision, `UnknownOutcome` preserves the exact
/// published identity (revision plus bundle digest) for reconcile
/// readback, and refusals name the re-serve discipline. Nothing collapses
/// an unproven outcome into ordinary unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerPublishDisposition {
    /// The Kernel bound the exact published bundle at this revision.
    Bound { revision: u64 },
    /// The Kernel holds conflicting owner state: re-serve fresh state,
    /// never retry the same bundle blindly.
    RefusedStale,
    /// The bundle or acknowledgement is malformed: fix the publisher.
    RefusedBinding,
    /// The Kernel generation is not admitted for this route.
    NotAdmitted,
    /// Transport down or pre-admission: retryable with no identity kept.
    Unavailable,
    /// Unproven delivery: reconcile the Kernel owner readback against the
    /// exact published identity before any reattempt or claim.
    UnknownOutcome {
        expected_revision: u64,
        bundle_digest: String,
    },
}

/// Kernel owner readback for publish reconcile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerReadback {
    /// Whether the Kernel holds a bound owner.
    pub bound: bool,
    /// The bound revision, when bound.
    pub revision: Option<u64>,
    /// The canonical digest of the bound bundle bytes, when bound.
    pub digest: Option<String>,
}

/// Reconcile verdict after comparing the Kernel readback against the exact
/// published identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishReconcile {
    /// The Kernel holds exactly the published bytes at the published
    /// revision: the bind is confirmed without republishing.
    Confirmed { revision: u64 },
    /// The Kernel holds different bytes or a different revision: report,
    /// never republish blindly over a foreign binding.
    DivergedStale,
    /// The Kernel holds no owner: a fresh publish flow may proceed.
    Unbound,
}

/// Owner-feed maintenance outcome for one loop pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerFeedMaintenance {
    /// No feed retained: attach was never completed.
    NoFeed,
    /// Provider revision and served digest agree with live Governor state
    /// and nothing is dirty: no IO performed.
    Unchanged,
    /// Refreshed, served, published, and persisted at this revision.
    Published { revision: u64 },
    /// Degraded outcome with a diagnostic reason; the daemon continues and
    /// retries on a later pass. No partial publish is claimed.
    Degraded { reason: String },
}

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
    /// Canonical digest of the provider snapshot last served or refreshed
    /// from. Maintenance compares it against live Governor state for exact
    /// change detection.
    served_snapshot_digest: Option<String>,
    /// Set by every registry mutation or refresh; cleared only by a
    /// Kernel-acknowledged publish. A dirty feed is republished on the next
    /// maintenance pass instead of re-serving silently served bytes.
    dirty: bool,
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
            served_snapshot_digest: None,
            dirty: true,
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

    /// Returns whether the feed holds unpublished changes.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Returns the canonical digest of the provider snapshot last served.
    #[must_use]
    pub fn served_snapshot_digest(&self) -> Option<&str> {
        self.served_snapshot_digest.as_deref()
    }

    /// Computes the canonical digest of the provider's current snapshot for
    /// exact change detection against live Governor state.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] when the snapshot cannot be rendered.
    pub fn snapshot_digest(&self) -> Result<String, DaemonError> {
        let snapshot = self.provider.owner_snapshot();
        let bytes = eliot_contracts::canonical_json_bytes(&snapshot.grant_graph)
            .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
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
        self.served_snapshot_digest = Some(self.snapshot_digest()?);
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
        self.served_snapshot_digest = None;
        self.dirty = true;
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
        let member = self
            .provider
            .admit_grant_member(params, secret, observed_at_ms)?;
        self.dirty = true;
        Ok(member)
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
        let hydration = self
            .provider
            .admit_grant_root(params, secret, observed_at_ms)?;
        self.dirty = true;
        Ok(hydration)
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
        let hydration = self
            .provider
            .admit_introduction(params, secret, observed_at_ms)?;
        self.dirty = true;
        Ok(hydration)
    }

    /// Admits one owner-declared alternate-path survivor.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError`] for unknown target, survivor, or covering
    /// lineage.
    pub fn admit_preserved(&mut self, admission: PreservedAdmission) -> Result<(), DaemonError> {
        self.provider.admit_preserved(admission)?;
        self.dirty = true;
        Ok(())
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
/// the exact publish disposition.
///
/// The feed serves the bundle at its revision, digests the exact bytes,
/// and publishes both; the disposition preserves the published identity
/// for reconcile readback on unproven delivery. A `Bound` disposition
/// clears the dirty flag and persists the registry: only acknowledged
/// bytes count as published.
pub fn publish_owner_bundle(
    kernel: &Arc<DaemonKernelClient>,
    feed: &mut OwnerBundleFeed,
    composition: &DaemonComposition,
) -> Result<OwnerPublishDisposition, DaemonError> {
    let bundle = feed.serve_bundle()?;
    let revision = feed.revision();
    let digest = owner_bundle_digest(&bundle)
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
    let disposition = KernelAuthorityClient::new(Arc::clone(kernel)).publish_owner_bundle(
        &bundle,
        revision,
        &digest,
    );
    if matches!(
        disposition,
        OwnerPublishDisposition::Bound { .. }
    ) {
        feed.dirty = false;
        persist_owner_feed(composition, feed)?;
    }
    Ok(disposition)
}

/// Reconciles an unproven publish against the Kernel owner readback and
/// the exact published identity.
///
/// The readback is compared field by field before any reattempt or claim:
/// an exact match confirms the bind without republishing; a different
/// binding reports stale instead of republishing blindly over foreign
/// state; no binding leaves the outcome unbound so a fresh publish flow
/// may proceed.
///
/// # Errors
///
/// Returns [`DaemonError`] when the readback itself cannot be obtained.
pub fn reconcile_owner_publish(
    kernel: &Arc<DaemonKernelClient>,
    expected_revision: u64,
    expected_digest: &str,
) -> Result<PublishReconcile, DaemonError> {
    let readback = KernelAuthorityClient::new(Arc::clone(kernel))
        .query_owner_readback()
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    if !readback.bound {
        return Ok(PublishReconcile::Unbound);
    }
    match (readback.revision, readback.digest.as_deref()) {
        (Some(revision), Some(digest))
            if revision == expected_revision && digest == expected_digest =>
        {
            Ok(PublishReconcile::Confirmed { revision })
        }
        _ => Ok(PublishReconcile::DivergedStale),
    }
}

/// Acquires CURRENT revocation-history evidence for every admitted root
/// through the canonical named-read path: one bounded read per root, each
/// decoded and fence-checked, merged into a single evidence value.
///
/// The merge preserves every part's claims exactly: closures union by
/// closure identity (a conflicting duplicate refuses), sorted by closure
/// identity, at the maximum observed source revision under the one shared
/// fence. An empty root set refuses: history for no lineage is not
/// evidence.
///
/// # Errors
///
/// Returns [`DaemonError`] for an unreadable store route, a malformed
/// reply, a fence disagreement, or a conflicting merge.
pub fn acquire_current_history(
    kernel: &Arc<DaemonKernelClient>,
    fence: &StateFence,
    roots: &[String],
) -> Result<RevocationHistoryEvidence, DaemonError> {
    if roots.is_empty() {
        return Err(DaemonError::Lifecycle(
            "history acquisition requires at least one admitted root".to_owned(),
        ));
    }
    let mut revision = 0u64;
    let mut closures: Vec<InfluenceDependencyClosure> = Vec::new();
    for root in roots {
        let request = revocation_history_read_request(
            fence,
            root,
            HISTORY_READ_MAX_RECORDS,
        )?;
        let response = kernel
            .store_named_blocking(request)
            .map_err(|error| DaemonError::Kernel(error.to_string()))?;
        let evidence = decode_revocation_history_evidence(&response, fence)?;
        revision = revision.max(evidence.source_revision);
        for closure in evidence.closures {
            match closures
                .iter()
                .find(|existing| existing.closure_id == closure.closure_id)
            {
                Some(existing) if *existing != closure => {
                    return Err(DaemonError::Lifecycle(
                        "history merge hit a conflicting closure identity".to_owned(),
                    ));
                }
                Some(_) => {}
                None => closures.push(closure),
            }
        }
    }
    closures.sort_by(|left, right| left.closure_id.cmp(&right.closure_id));
    Ok(RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: revision,
        closures,
    })
}

/// Runs one owner-feed maintenance pass: exact change detection against
/// live Governor state, then refresh, serve, publish, and persist when
/// anything is dirty or advanced.
///
/// Change detection compares the live snapshot digest against the last
/// served digest, so the common unchanged pass performs no IO at all. A
/// refresh re-acquires CURRENT history, carries admissions over only when
/// they still resolve, and republishes; an unproven publish reconciles
/// the readback before any claim. Every degraded outcome names its reason
/// and leaves the daemon running for a later pass.
pub fn maintain_owner_feed(
    feed: &mut OwnerBundleFeed,
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) -> OwnerFeedMaintenance {
    let owner = &composition.governor.owners().authority;
    let snapshot = match owner.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return OwnerFeedMaintenance::Degraded {
                reason: error.to_string(),
            };
        }
    };
    let live_bytes = match eliot_contracts::canonical_json_bytes(&snapshot.grant_graph) {
        Ok(bytes) => bytes,
        Err(error) => {
            return OwnerFeedMaintenance::Degraded {
                reason: error.to_string(),
            };
        }
    };
    let live_digest = eliot_contracts::sha256_hex(&live_bytes);
    let advanced = snapshot.grant_graph.revision != feed.revision();
    if !feed.is_dirty() && !advanced && Some(live_digest.as_str()) == feed.served_snapshot_digest()
    {
        return OwnerFeedMaintenance::Unchanged;
    }
    let fence = owner.state_fence().clone();
    let roots: Vec<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let history = match acquire_current_history(kernel, &fence, &roots) {
        Ok(history) => history,
        Err(error) => {
            return OwnerFeedMaintenance::Degraded {
                reason: error.to_string(),
            };
        }
    };
    let target_revision = feed.revision().max(snapshot.grant_graph.revision);
    if let Err(error) = feed.refresh(snapshot, Some(history), target_revision) {
        return OwnerFeedMaintenance::Degraded {
            reason: error.to_string(),
        };
    }
    match publish_owner_bundle(kernel, feed, composition) {
        Ok(OwnerPublishDisposition::Bound { revision }) => {
            OwnerFeedMaintenance::Published { revision }
        }
        Ok(OwnerPublishDisposition::UnknownOutcome {
            expected_revision,
            bundle_digest,
        }) => match reconcile_owner_publish(kernel, expected_revision, &bundle_digest) {
            Ok(PublishReconcile::Confirmed { revision }) => {
                OwnerFeedMaintenance::Published { revision }
            }
            Ok(PublishReconcile::DivergedStale) => OwnerFeedMaintenance::Degraded {
                reason: "publish reconciled against foreign owner state".to_owned(),
            },
            Ok(PublishReconcile::Unbound) => OwnerFeedMaintenance::Degraded {
                reason: "publish unproven and Kernel holds no owner".to_owned(),
            },
            Err(error) => OwnerFeedMaintenance::Degraded {
                reason: error.to_string(),
            },
        },
        Ok(other) => OwnerFeedMaintenance::Degraded {
            reason: format!("publish refused: {other:?}"),
        },
        Err(error) => OwnerFeedMaintenance::Degraded {
            reason: error.to_string(),
        },
    }
}

/// Attach outcome for the daemon startup site: either the feed bound and
/// published at this revision, or a named degradation reason. The daemon
/// continues without readiness impact on degradation: the owner feed is
/// not readiness-gating (pending grants stay pending, as with an absent
/// P-07 port).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerFeedAttach {
    /// The feed built, served, published, and persisted at this revision.
    Ready { revision: u64 },
    /// The feed is retained but unpublished, with the reason named.
    Unavailable { reason: String },
}

/// Attaches the canonical owner feed at daemon startup: acquires CURRENT
/// history, builds the feed from live Governor state (re-importing the
/// persisted registry when present), serves the bundle, publishes it
/// toward the Kernel owner route with reconcile on unproven delivery, and
/// persists the registry on an acknowledged bind.
///
/// The returned slot is retained by the runtime for loop maintenance; the
/// outcome names the attach disposition for diagnostics. An unproven
/// publish reconciles the Kernel readback against the exact published
/// identity before any claim — never collapsed to ordinary unavailable.
pub fn attach_owner_feed(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) -> (
    std::sync::Arc<std::sync::Mutex<Option<OwnerBundleFeed>>>,
    OwnerFeedAttach,
) {
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let owner = &composition.governor.owners().authority;
    let snapshot = match owner.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return (
                slot,
                OwnerFeedAttach::Unavailable {
                    reason: error.to_string(),
                },
            );
        }
    };
    let fence = owner.state_fence().clone();
    let roots: Vec<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if roots.is_empty() {
        return (
            slot,
            OwnerFeedAttach::Unavailable {
                reason: "no admitted lineage roots to serve".to_owned(),
            },
        );
    }
    let history = match acquire_current_history(kernel, &fence, &roots) {
        Ok(history) => history,
        Err(error) => {
            return (
                slot,
                OwnerFeedAttach::Unavailable {
                    reason: error.to_string(),
                },
            );
        }
    };
    let mut feed = match build_owner_feed(composition, Some(history)) {
        Ok(feed) => feed,
        Err(error) => {
            return (
                slot,
                OwnerFeedAttach::Unavailable {
                    reason: error.to_string(),
                },
            );
        }
    };
    let outcome = match publish_owner_bundle(kernel, &mut feed, composition) {
        Ok(OwnerPublishDisposition::Bound { revision }) => {
            OwnerFeedAttach::Ready { revision }
        }
        Ok(OwnerPublishDisposition::UnknownOutcome {
            expected_revision,
            bundle_digest,
        }) => match reconcile_owner_publish(kernel, expected_revision, &bundle_digest) {
            Ok(PublishReconcile::Confirmed { revision }) => {
                OwnerFeedAttach::Ready { revision }
            }
            Ok(PublishReconcile::DivergedStale) => OwnerFeedAttach::Unavailable {
                reason: "publish reconciled against foreign owner state".to_owned(),
            },
            Ok(PublishReconcile::Unbound) => OwnerFeedAttach::Unavailable {
                reason: "publish unproven and Kernel holds no owner".to_owned(),
            },
            Err(error) => OwnerFeedAttach::Unavailable {
                reason: error.to_string(),
            },
        },
        Ok(other) => OwnerFeedAttach::Unavailable {
            reason: format!("publish refused: {other:?}"),
        },
        Err(error) => OwnerFeedAttach::Unavailable {
            reason: error.to_string(),
        },
    };
    if let OwnerFeedAttach::Ready { .. } = outcome {
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(feed);
    }
    (slot, outcome)
}

/// Runs one retained-slot maintenance pass: recovers a missed attach when
/// the slot is empty, otherwise runs exact change detection with refresh,
/// serve, publish, and persist.
///
/// Lock poisoning degrades the pass instead of panicking: the daemon
/// continues and retries later.
pub fn maintain_owner_feed_slot(
    slot: &std::sync::Arc<std::sync::Mutex<Option<OwnerBundleFeed>>>,
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) -> OwnerFeedMaintenance {
    let Ok(mut guard) = slot.lock() else {
        return OwnerFeedMaintenance::Degraded {
            reason: "owner feed lock poisoned".to_owned(),
        };
    };
    if guard.is_none() {
        // Attach recovery: a missed or degraded startup attach is retried
        // here. The fresh attach owns its own slot; move a ready feed into
        // the retained slot so later passes maintain it.
        let (recovered, outcome) = attach_owner_feed(composition, kernel);
        if let OwnerFeedAttach::Ready { .. } = outcome {
            let moved = match recovered.lock() {
                Ok(mut slot) => slot.take(),
                Err(_) => None,
            };
            if moved.is_some() {
                *guard = moved;
                drop(guard);
                return match outcome {
                    OwnerFeedAttach::Ready { revision } => {
                        OwnerFeedMaintenance::Published { revision }
                    }
                    OwnerFeedAttach::Unavailable { reason } => {
                        OwnerFeedMaintenance::Degraded { reason }
                    }
                };
            }
        }
        return match outcome {
            OwnerFeedAttach::Ready { revision } => {
                OwnerFeedMaintenance::Published { revision }
            }
            OwnerFeedAttach::Unavailable { reason } => OwnerFeedMaintenance::Degraded { reason },
        };
    }
    let Some(feed) = guard.as_mut() else {
        return OwnerFeedMaintenance::Degraded {
            reason: "owner feed slot emptied during maintenance".to_owned(),
        };
    };
    maintain_owner_feed(feed, composition, kernel)
}
