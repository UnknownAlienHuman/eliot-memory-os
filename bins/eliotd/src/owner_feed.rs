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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use eliot_governor::{CompositionError, KernelGenerationSnapshotProvider, OwnerPublishPort};
use eliot_kernel_core::GovernorClosureRestore;
use eliot_receipts::ReceiptIdentity;
use eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS;

use super::daemon_kernel_client::DaemonKernelClient;
use super::kernel_context_read_client::KernelContextReadClient;
use super::{DaemonComposition, kind_value};

/// Daemon->Kernel front-door owner-bundle publish operation.
const PUBLISH_OWNER_BUNDLE_OPERATION: &str = "publish_owner_bundle";
/// Daemon->Kernel front-door owner-lineage revision initialization operation.
const INITIALIZE_OWNER_REVISION_OPERATION: &str = "initialize_owner_revision";
/// Typed receipt kind answered by the revision initialization arm.
const OWNER_REVISION_RECEIPT_KIND: &str = "owner_revision_receipt";
/// Daemon->Kernel front-door read of the completed canonical second phases of
/// one authority root (issue #2100, `R6`).
const QUERY_GRANT_CLOSURE_LINKS_OPERATION: &str = "query_grant_closure_canonical_receipts";
/// Typed receipt kind answered by the publish arm.
const OWNER_BUNDLE_RECEIPT_KIND: &str = "owner_bundle_receipt";
/// Typed receipt kind answered by the canonical second-phase read arm.
const GRANT_CLOSURE_LINKS_KIND: &str = "grant_closure_canonical_receipts";
/// Typed refusal kind answered by the same arm. A refusal is never read as an
/// empty link set: the durable reason is surfaced and the pass degrades.
const GRANT_CLOSURE_LINKS_REFUSAL_KIND: &str = "grant_closure_canonical_receipts_refused";
/// The only canonical second-phase payload shape this daemon build accepts.
const GRANT_CLOSURE_LINKS_VERSION: u32 = 1;
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

/// Wire shape answered by the owner-lineage revision initialization arm.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRevisionReceiptWire {
    revision: u64,
}

/// Wire shape answered by the canonical second-phase read arm: the completed
/// links of one root, read from the Kernel's durable ORS snapshot.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantClosureCanonicalLinksWire {
    version: u32,
    authority_root_ref: String,
    grant_graph_revision: u64,
    links: Vec<GrantClosureCanonicalLinkWire>,
}

/// One completed canonical second phase, named by its immutable first-phase
/// closure operation. The daemon never derives either value: both come from the
/// Kernel's durable read.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantClosureCanonicalLinkWire {
    closure_operation_id: String,
    canonical_receipt: ReceiptIdentity,
}

/// Reads the completed canonical second phases of the admitted roots from the
/// Kernel's durable ORS projection (issue #2100, `R6`).
///
/// The map is the only honest source of a canonical receipt identity on the
/// daemon path: the Kernel commits the first-phase closure row and the
/// canonical receipt into two separate ORS records, and the revocation-history
/// read cannot carry the second one because that payload is a frozen store
/// contract. An absent link is therefore read as what it is - a second phase
/// that has not completed yet - and never as a completed receipt. A refusal, a
/// transport failure, a disagreement between two roots, or an unusable
/// identity fails the pass closed; none of them degrades to an empty map.
async fn read_canonical_closure_receipts(
    kernel: &Arc<DaemonKernelClient>,
    origin_refs: &[String],
    bound: u32,
) -> Result<BTreeMap<String, ReceiptIdentity>, CompositionError> {
    let state_fence = kernel.snapshot().state_fence();
    let mut canonical_receipts: BTreeMap<String, ReceiptIdentity> = BTreeMap::new();
    for origin_ref in origin_refs {
        let value = kernel
            .transact_async(
                QUERY_GRANT_CLOSURE_LINKS_OPERATION,
                serde_json::json!({
                    "state_fence": state_fence,
                    "authority_root_ref": origin_ref,
                    "max_records": bound,
                }),
            )
            .await
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "canonical closure link read transport for {origin_ref}: {error}"
                ))
            })?;
        let object = value.as_object().ok_or_else(|| {
            CompositionError::Owner("canonical closure link read is not a typed object".to_owned())
        })?;
        match object.get("kind").and_then(serde_json::Value::as_str) {
            Some(GRANT_CLOSURE_LINKS_KIND) => {}
            Some(GRANT_CLOSURE_LINKS_REFUSAL_KIND) => {
                let reason = object
                    .get("value")
                    .and_then(|value| value.get("reason"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unspecified durable refusal");
                return Err(CompositionError::Recovery(format!(
                    "Kernel refused the durable canonical closure link read for {origin_ref}: {reason}"
                )));
            }
            other => {
                return Err(CompositionError::Owner(format!(
                    "canonical closure link read returned an unexpected kind: {other:?}"
                )));
            }
        }
        let value = object.get("value").cloned().ok_or_else(|| {
            CompositionError::Owner("canonical closure link read is missing its payload".to_owned())
        })?;
        let served: GrantClosureCanonicalLinksWire =
            serde_json::from_value(value).map_err(|error| {
                CompositionError::Owner(format!(
                    "canonical closure link read does not decode for {origin_ref}: {error}"
                ))
            })?;
        if served.version != GRANT_CLOSURE_LINKS_VERSION
            || served.authority_root_ref != *origin_ref
            || served.grant_graph_revision == 0
        {
            return Err(CompositionError::Recovery(format!(
                "canonical closure link read for {origin_ref} is bound to another root, version, or zero revision"
            )));
        }
        for link in served.links {
            if !canonical_receipt_identity_is_usable(&link.canonical_receipt) {
                return Err(CompositionError::Recovery(format!(
                    "canonical closure link for {} carries an incomplete receipt identity",
                    link.closure_operation_id
                )));
            }
            if let Some(previous) = canonical_receipts.get(&link.closure_operation_id)
                && previous != &link.canonical_receipt
            {
                return Err(CompositionError::Recovery(format!(
                    "durable canonical closure links disagree for {}",
                    link.closure_operation_id
                )));
            }
            canonical_receipts.insert(link.closure_operation_id, link.canonical_receipt);
        }
    }
    Ok(canonical_receipts)
}

/// Reports whether one canonical receipt identity is complete and bounded
/// enough to republish. `eliot_receipts` keeps its own `validate`
/// crate-private, so the daemon states the same rules instead of trusting a
/// decoded value; the authoritative check stays the Kernel's ORS link
/// read-back during the owner publish.
fn canonical_receipt_identity_is_usable(receipt: &ReceiptIdentity) -> bool {
    let receipt_id = receipt.receipt_id.as_str();
    !receipt_id.trim().is_empty()
        && !receipt_id.chars().any(char::is_control)
        && receipt.canonical_sha256.len() == 64
        && receipt
            .canonical_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    async fn initialize_owner_revision(
        &self,
        authority_root_ref: &str,
        expected_revision: u64,
        state_fence: &eliot_contracts::StateFence,
    ) -> Result<u64, CompositionError> {
        if expected_revision == 0 || authority_root_ref.trim().is_empty() {
            return Err(CompositionError::Owner(
                "owner revision initialization requires a root and nonzero revision".to_owned(),
            ));
        }
        let value = self
            .kernel
            .transact_async(
                INITIALIZE_OWNER_REVISION_OPERATION,
                serde_json::json!({
                    "authority_root_ref": authority_root_ref,
                    "expected_revision": expected_revision,
                    "state_fence": state_fence,
                }),
            )
            .await
            .map_err(|error| {
                CompositionError::Recovery(format!(
                    "owner revision initialization transport: {error}"
                ))
            })?;
        let value = kind_value(&value, OWNER_REVISION_RECEIPT_KIND).map_err(|error| {
            CompositionError::Owner(format!("owner revision receipt kind: {error}"))
        })?;
        let receipt: OwnerRevisionReceiptWire = serde_json::from_value(value).map_err(|error| {
            CompositionError::Owner(format!("owner revision receipt does not decode: {error}"))
        })?;
        if receipt.revision != expected_revision {
            return Err(CompositionError::Recovery(
                "owner revision initialization receipt disagrees".to_owned(),
            ));
        }
        Ok(receipt.revision)
    }

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
        let readback = self
            .kernel
            .query_owner_bundle_readback()
            .await
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(match readback {
            Some(readback) => (true, Some(readback.revision), Some(readback.bundle_sha256)),
            None => (false, None, None),
        })
    }
}

/// O1 owner-feed trigger state: the provider revision last proven published
/// to the Kernel. It is diagnostic only; every maintenance pass re-presents
/// the current bundle so a same-revision Kernel owner loss cannot be hidden
/// by process-local state.
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
/// Every admitted root is synchronized through the full
/// revision-initialize->read->decode->restore->publish->readback exchange at the
/// catalogue history bound; the trigger records the revision only after every
/// root binds with its readback proven.
///
/// The pass first reads the durable canonical second phases of those roots
/// (`R6`) and publishes them inside the owner bundle, so a second phase that
/// the Kernel already committed reaches the owner boundary instead of being
/// dropped on the way to `eliotd`. A lineage with no completed second phase
/// contributes no link and nothing is claimed reconciled; a refusal or an
/// unreadable identity fails the pass instead of degrading to no links.
///
/// Returns `Ok(None)` when nothing needed publishing, `Ok(Some(revision))`
/// when the Kernel readback proved the publish at that revision, and `Err`
/// with the typed reason when the pass degraded: the daemon continues and
/// retries on a later pass, and no partial publish is ever claimed.
pub async fn maintain_owner_feed(
    composition: &DaemonComposition,
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
    // The trigger is diagnostic only. Every pass re-presents the current
    // bundle so a same-revision owner loss or digest change cannot be hidden
    // by a process-local revision shortcut.
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
    let canonical_receipts =
        read_canonical_closure_receipts(kernel, &roots, REVOCATION_HISTORY_MAX_RECORDS).await?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let publish = KernelOwnerPublishPort::new(Arc::clone(kernel));
    composition
        .governor
        .synchronize_kernel_owner_with_canonical_receipts(
            &reads,
            &publish,
            &roots,
            REVOCATION_HISTORY_MAX_RECORDS,
            revision,
            canonical_receipts,
        )
        .await?;
    trigger.last_published_revision = Some(revision);
    Ok(Some(revision))
}
