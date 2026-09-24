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

use eliot_governor::{CompositionError, OwnerPublishPort};
use eliot_kernel_core::GovernorClosureRestore;
use eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS;

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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerFeedTrigger {
    last_published_revision: Option<u64>,
}

impl OwnerFeedTrigger {
    /// Starts unbound: the first maintenance pass always re-presents.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_published_revision: None,
        }
    }

    /// Returns the provider revision last proven published, if any.
    #[must_use]
    pub const fn last_published_revision(&self) -> Option<u64> {
        self.last_published_revision
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
    if trigger.last_published_revision == Some(revision) {
        return Ok(None);
    }
    let roots: Vec<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if roots.is_empty() {
        return Ok(None);
    }
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let publish = KernelOwnerPublishPort::new(Arc::clone(kernel));
    for root in &roots {
        composition
            .governor
            .synchronize_kernel_owner(
                &reads,
                &publish,
                root,
                REVOCATION_HISTORY_MAX_RECORDS,
                revision,
            )
            .await?;
    }
    trigger.last_published_revision = Some(revision);
    Ok(Some(revision))
}
