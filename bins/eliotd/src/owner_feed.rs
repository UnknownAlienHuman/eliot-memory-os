//! O1 daemon owner-feed publisher for the Kernel P-07 owner (issue #2100).
//!
//! Architecture traceability: I6.15 keeps the Governor the owner of canonical
//! grant semantics, parent lineage, and introduction compilation; I1.8 keeps the
//! daemon/Kernel call path behind the authenticated transport; A13.2 keeps
//! daemon/Kernel failure domains explicit.
//!
//! This module owns the daemon (O1) side of the durable owner chain: the one
//! production [`OwnerPublishPort`] implementation against the Kernel front-door
//! `publish_owner_bundle` / `query_owner_bundle` operations, and the trigger
//! that drives [`synchronize_kernel_owner`](eliot_governor::GovernorComposition::synchronize_kernel_owner)
//! on provider-revision advance and on recovery. The feed exchange itself
//! (read, restore, serve, publish, readback verification) stays in
//! `eliot-governor`; this module only binds it to the live composition and
//! the authenticated transport.
//!
//! Forbidden boundary: no ORS access (the Kernel owns ORS in its own
//! process), no second grant graph, no epoch invention, no secret bytes, no
//! silent empty bundles, and no success claim without the Kernel readback
//! proving the exact published bytes. Until the Kernel binds an owner the
//! port stays unbound and grants stay pending; degradation never fails daemon
//! readiness.

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_governor::{
    AuthorityOwnerStateIngress, CompositionError, OwnerPublishPort,
    decode_revocation_history_with_root, revocation_history_read_request,
};
use eliot_kernel_core::GovernorClosureRestore;
use eliot_store_api::{
    CanonicalReadClient, REVOCATION_HISTORY_MAX_RECORDS, REVOCATION_HISTORY_ROOT_SELECTOR,
    RevocationHistoryRoot,
};

use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_context_read_client::KernelContextReadClient;
use super::{DaemonComposition, kind_value};

/// Daemon->Kernel front-door owner-bundle publish operation.
const PUBLISH_OWNER_BUNDLE_OPERATION: &str = "publish_owner_bundle";
/// Daemon->Kernel front-door owner-bundle readback operation.
const QUERY_OWNER_BUNDLE_OPERATION: &str = "query_owner_bundle";
/// Typed receipt kind answered by the publish arm.
const OWNER_BUNDLE_RECEIPT_KIND: &str = "owner_bundle_receipt";
/// Typed readback kind answered by the query arm.
const OWNER_BUNDLE_READBACK_KIND: &str = "owner_bundle_readback";
/// Only an acknowledged `bound` receipt counts as published.
const OWNER_BOUND_STATUS: &str = "bound";

/// Wire shape answered by the Kernel `publish_owner_bundle` arm: the bound
/// revision plus the acknowledged status. Anything but `bound` is a refusal,
/// never a partial publish.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerBundleReceiptWire {
    revision: u64,
    status: String,
}

/// Wire shape answered by the Kernel `query_owner_bundle` arm: whether the
/// Kernel holds a bound owner and, when bound, the exact revision and bundle
/// digest the publish path reconciles against.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerBundleReadbackWire {
    bound: bool,
    revision: Option<u64>,
    digest: Option<String>,
}

/// O1 Kernel publish endpoint for owner bundles: the one production
/// [`OwnerPublishPort`] implementation, over the already-connected
/// authenticated Kernel client.
///
/// Publish sends the canonical restore plus the exact expected revision and
/// returns the bound revision the Kernel acknowledged; readback returns the
/// retained triple for verification. No session management, no clock reads,
/// no retries: one presentation means one authenticated round trip, and any
/// ambiguity fails closed. A transport failure maps to
/// [`CompositionError::Recovery`] (degrade and reconcile the readback on a
/// later pass, never claim success); a malformed receipt maps to
/// [`CompositionError::Owner`] (deterministic publisher/contract breakage).
pub struct KernelOwnerPublishPort {
    kernel: Arc<DaemonKernelClient>,
}

impl KernelOwnerPublishPort {
    /// Retains the already-connected authenticated Kernel client.
    #[must_use]
    pub fn new(kernel: Arc<DaemonKernelClient>) -> Self {
        Self { kernel }
    }
}

impl OwnerPublishPort for KernelOwnerPublishPort {
    async fn publish_owner_bundle(
        &self,
        bundle: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, CompositionError> {
        if expected_revision == 0 {
            return Err(CompositionError::Owner(
                "owner publish expected revision must be nonzero".to_owned(),
            ));
        }
        let payload = serde_json::json!({
            "bundle": bundle,
            "expected_revision": expected_revision,
        });
        let value = self
            .kernel
            .transact_async(PUBLISH_OWNER_BUNDLE_OPERATION, payload)
            .await
            .map_err(|error| {
                CompositionError::Recovery(format!("owner publish transport: {error}"))
            })?;
        let value = kind_value(&value, OWNER_BUNDLE_RECEIPT_KIND).map_err(|error| {
            CompositionError::Owner(format!("owner publish receipt kind: {error}"))
        })?;
        let receipt: OwnerBundleReceiptWire = serde_json::from_value(value).map_err(|error| {
            CompositionError::Owner(format!("owner bundle receipt does not decode: {error}"))
        })?;
        if receipt.status != OWNER_BOUND_STATUS {
            return Err(CompositionError::Owner(format!(
                "owner bundle receipt status is not bound: {}",
                receipt.status
            )));
        }
        Ok(receipt.revision)
    }

    async fn query_owner_readback(
        &self,
    ) -> Result<(bool, Option<u64>, Option<String>), CompositionError> {
        let value = self
            .kernel
            .transact_async(QUERY_OWNER_BUNDLE_OPERATION, serde_json::json!({}))
            .await
            .map_err(|error| {
                CompositionError::Recovery(format!("owner readback transport: {error}"))
            })?;
        let value = kind_value(&value, OWNER_BUNDLE_READBACK_KIND)
            .map_err(|error| CompositionError::Owner(format!("owner readback kind: {error}")))?;
        let readback: OwnerBundleReadbackWire = serde_json::from_value(value).map_err(|error| {
            CompositionError::Owner(format!("owner readback does not decode: {error}"))
        })?;
        Ok((readback.bound, readback.revision, readback.digest))
    }
}

/// O1 owner-feed trigger state: the provider revision last proven published
/// to the Kernel. `None` until the first readback-proven publish; the daemon
/// runtime retains one trigger across passes so an unchanged provider
/// performs no IO while a revision advance or a recovery re-presentation
/// republishes exactly once per pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnerFeedTrigger {
    last_published: Option<(u64, RevocationHistoryRoot)>,
}

impl OwnerFeedTrigger {
    /// Starts unbound: the first maintenance pass always re-presents.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_published: None,
        }
    }

    /// Returns the provider revision last proven published, if any.
    #[must_use]
    pub fn last_published_revision(&self) -> Option<u64> {
        self.last_published.as_ref().map(|(revision, _)| *revision)
    }
}

/// Runs one O1 owner-feed maintenance pass (`#2100` production trigger).
///
/// Roots and the expected revision come from the live Governor authority
/// snapshot at call time - never caller-supplied - so a stale trigger fails
/// closed inside the feed exchange instead of publishing a partial closure.
/// An unchanged provider revision performs no transport. Otherwise every
/// admitted root is synchronized through the full
/// read->decode->restore->publish->readback exchange at the catalogue history
/// bound; the trigger records the revision only after every root binds with
/// its readback proven.
///
/// Returns `Ok(None)` when nothing needed publishing, `Ok(Some(revision))`
/// when the Kernel readback proved the publish at that revision, and `Err`
/// with the typed reason when the pass degraded: the daemon continues and
/// retries on a later pass, and no partial publish is ever claimed.
pub async fn maintain_owner_feed(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    trigger: &mut OwnerFeedTrigger,
) -> Result<Option<u64>, CompositionError> {
    let snapshot = composition.governor.owners().authority.snapshot()?;
    let revision = snapshot.grant_graph.revision;
    if revision == 0 {
        return Err(CompositionError::Owner(
            "owner feed live graph revision is zero".to_owned(),
        ));
    }
    let reads = KernelContextReadClient::new(Arc::clone(kernel));

    // The durable Store root index is the trigger source. Grant presence is
    // used only to enumerate the semantic graph after the index has been
    // observed; a graph with no current grant cannot silently suppress a
    // revocation already present in the independent history ledger.
    let root_request = revocation_history_read_request(
        &snapshot.state_fence,
        REVOCATION_HISTORY_ROOT_SELECTOR,
        REVOCATION_HISTORY_MAX_RECORDS,
    )?;
    let root_response = reads
        .execute_named(root_request)
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let (root_index, _) =
        decode_revocation_history_with_root(&root_response, &snapshot.state_fence)?;

    let mut root_set: BTreeSet<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect();
    root_set.extend(root_index.root_refs.iter().cloned());
    let roots: Vec<String> = root_set.into_iter().collect();
    if roots.is_empty() {
        return Ok(None);
    }
    let publish = KernelOwnerPublishPort::new(Arc::clone(kernel));
    let (bound_revision, history_root) = composition
        .governor
        .synchronize_kernel_owner_batch(
            &reads,
            &publish,
            &roots,
            REVOCATION_HISTORY_MAX_RECORDS,
            revision,
        )
        .await?;
    // The same production owner-feed pass hands the durable rebuild queue to
    // the one MaintenanceController.  The controller obtains and validates a
    // Kernel-issued active RuntimeLease before admitting each job; a missing
    // lease fails closed and leaves the order for a later pass.
    composition
        .consume_revocation_rebuilds(super::unix_ms_i64())
        .map_err(|error| match error {
            super::DaemonError::Composition(error) => error,
            other => CompositionError::Recovery(other.to_string()),
        })?;
    if trigger.last_published == Some((bound_revision, history_root.clone())) {
        return Ok(None);
    }
    trigger.last_published = Some((bound_revision, history_root));
    Ok(Some(bound_revision))
}

/// Runs the owner-feed arm for one authenticated product revocation event.
///
/// Unlike the periodic recovery/publication trigger, this arm requires the
/// caller-supplied owner-state ingress. It commits the post-fan-out Authority
/// image, proves the Store readback, and only then publishes the Kernel owner
/// bundle. No identity, operation id, or owner revision is derived here.
pub async fn maintain_owner_feed_with_product_event(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    trigger: &mut OwnerFeedTrigger,
    state_ingress: &AuthorityOwnerStateIngress,
) -> Result<(u64, RevocationHistoryRoot), CompositionError> {
    state_ingress
        .validate()
        .map_err(|error| CompositionError::Provider(error.to_string()))?;
    let snapshot = composition.governor.owners().authority.snapshot()?;
    let revision = snapshot.grant_graph.revision;
    if revision == 0 {
        return Err(CompositionError::Owner(
            "owner feed live graph revision is zero".to_owned(),
        ));
    }
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let root_request = revocation_history_read_request(
        &snapshot.state_fence,
        REVOCATION_HISTORY_ROOT_SELECTOR,
        REVOCATION_HISTORY_MAX_RECORDS,
    )?;
    let root_response = reads
        .execute_named(root_request)
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let (root_index, _) =
        decode_revocation_history_with_root(&root_response, &snapshot.state_fence)?;
    let mut root_set: BTreeSet<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect();
    root_set.extend(root_index.root_refs.iter().cloned());
    let roots: Vec<String> = root_set.into_iter().collect();
    if roots.is_empty() {
        return Err(CompositionError::Recovery(
            "authenticated revocation event has no live authority root to synchronize".to_owned(),
        ));
    }
    let publish = KernelOwnerPublishPort::new(Arc::clone(kernel));
    let (bound_revision, history_root) = composition
        .governor
        .synchronize_kernel_owner_batch_with_state(
            &reads,
            &publish,
            &roots,
            REVOCATION_HISTORY_MAX_RECORDS,
            revision,
            state_ingress,
        )
        .await?;
    composition
        .consume_revocation_rebuilds(super::unix_ms_i64())
        .map_err(|error| match error {
            super::DaemonError::Composition(error) => error,
            other => CompositionError::Recovery(other.to_string()),
        })?;
    trigger.last_published = Some((bound_revision, history_root.clone()));
    Ok((bound_revision, history_root))
}
