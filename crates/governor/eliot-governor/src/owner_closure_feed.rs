//! Trigger-driven Governor owner-bundle feed for the Kernel P-07 owner
//! (issue #2100).
//!
//! The Kernel retains its P-07 owner behind `Mutex<Option<...>>`: `None`
//! from boot until the first published bundle binds it. No boot-time
//! bundle source exists (the Governor starts after the Kernel), so the
//! bind is driven at runtime by this feed, never by a default, a `None`
//! placeholder, or a fabricated owner.
//!
//! The feed is trigger-driven, not scheduled here: the owning daemon
//! runtime (O1 `daemon_runtime` / `reactive_feed` in `bins/eliotd`)
//! calls [`synchronize_owner_feed`] whenever the provider revision
//! advances (rotation) and during recovery (restart re-presentation).
//! This module owns the feed exchange — read, restore, serve, publish,
//! readback verification — while O1 owns when it runs. Registration
//! hunk for O1/root:
//!
//! ```text
//! use eliot_governor::owner_closure_feed::{OwnerPublishPort, synchronize_owner_feed};
//!
//! // On provider-revision advance and on recovery, with the canonical
//! // read client, the Kernel publish port, the owner snapshot, the live
//! // fence, the origin selector, the record bound, the exact expected
//! // graph revision, and the admitted revocation operation identity this
//! // restore runs under:
//! let bound = synchronize_owner_feed(
//!     &reads, &kernel_publish_port,
//!     snapshot, state_fence, origin_ref, max_records, expected_revision,
//!     operation,
//! ).await?;
//! ```
//!
//! `OwnerPublishPort` is implemented once by the daemon runtime against
//! the Kernel front-door `publish_owner_bundle` / `query_owner_bundle`
//! operations; the exchange below stays typed and never touches
//! transport bytes. [`publish_owner_feed`] remains available for a
//! caller that already holds a restored provider.

use std::collections::{BTreeMap, BTreeSet};

use eliot_authority::{
    CrossRootQuarantineEvidence, RevocationHistoryEvidence, RevocationOperationIdentity,
};
use eliot_contracts::{StateFence, canonical_json_bytes};
use eliot_kernel_core::{GovernorClosureRestore, owner_bundle_digest};
use eliot_receipts::ReceiptIdentity;
use eliot_store_api::CanonicalReadClient;

use crate::{
    AuthorityOwnerSnapshot, CompositionError, OwnerClosureProvider,
    decode_revocation_history_evidence, revocation_history_read_request,
};

/// Kernel publish endpoint for owner bundles, implemented by the daemon
/// runtime (O1) against the front-door operations.
///
/// `publish_owner_bundle` sends the canonical restore plus the exact
/// expected revision and returns the bound revision the Kernel
/// acknowledged. `query_owner_readback` returns the retained triple
/// `(bound, revision, bundle digest)` for verification.
#[allow(async_fn_in_trait)]
pub trait OwnerPublishPort: Send + Sync {
    /// Publishes one owner bundle and returns the bound revision.
    async fn publish_owner_bundle(
        &self,
        bundle: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, CompositionError>;
    /// Initializes or proves the current owner-lineage graph revision before
    /// the first history read. It carries no owner bundle or authority.
    async fn initialize_owner_revision(
        &self,
        authority_root_ref: &str,
        expected_revision: u64,
        state_fence: &StateFence,
    ) -> Result<u64, CompositionError>;

    /// Reads back the retained owner triple for verification.
    async fn query_owner_readback(
        &self,
    ) -> Result<(bool, Option<u64>, Option<String>), CompositionError>;
}

/// Publishes the provider's current owner bundle to the Kernel and
/// verifies the retained readback (`#2100` feed exchange).
///
/// The bundle is served from the live provider at the expected
/// revision, published once, and then proven: the readback must show a
/// bound owner at the acknowledged revision with the exact bundle
/// digest. Any disagreement refuses before the caller may claim the
/// publish committed — the caller re-serves fresh state, never retries
/// blindly. A zero expected revision refuses immediately: the Kernel
/// never binds revision zero.
pub async fn publish_owner_feed<P: OwnerPublishPort + ?Sized>(
    kernel: &P,
    provider: &OwnerClosureProvider,
    expected_revision: u64,
) -> Result<u64, CompositionError> {
    if expected_revision == 0 {
        return Err(CompositionError::Owner(
            "owner feed expected revision must be nonzero".to_owned(),
        ));
    }
    if provider.revision() != expected_revision {
        return Err(CompositionError::Owner(
            "owner feed provider revision disagrees with the expected revision".to_owned(),
        ));
    }
    let bundle = provider.serve_restore()?;
    let expected_digest = owner_bundle_digest(&bundle)
        .map_err(|error| CompositionError::Owner(format!("owner bundle digest failed: {error}")))?;
    let acknowledged = kernel
        .publish_owner_bundle(bundle, expected_revision)
        .await?;
    if acknowledged != expected_revision {
        return Err(CompositionError::Recovery(format!(
            "owner publish acknowledged revision {acknowledged} disagrees with expected {expected_revision}"
        )));
    }
    let (bound, revision, digest) = kernel.query_owner_readback().await?;
    if !bound
        || revision != Some(acknowledged)
        || digest.as_deref() != Some(expected_digest.as_str())
    {
        return Err(CompositionError::Recovery(
            "owner readback disagrees with the published bundle; publish did not commit".to_owned(),
        ));
    }
    Ok(acknowledged)
}

/// Runs one complete trigger-driven owner synchronization (`#2100`
/// admitted caller → publish → recover path).
///
/// One call performs the whole chain with no gaps for the trigger
/// owner to fill: it builds the closed history read for the exact
/// origin, executes it through the canonical read client, decodes the
/// reply against the expected fence, restores the provider with that
/// live evidence, and publishes through [`publish_owner_feed`]. The
/// observed evidence revision must equal the expected revision, or the
/// trigger is stale and the call refuses before any publish. Unavailable
/// history, fence disagreement, stale evidence, and readback mismatch
/// all refuse before any owner state is installed or claimed.
///
/// `operation` is the admitted revocation operation identity this
/// feed's restore runs under, supplied by the durable boundary and
/// forwarded verbatim. It is required, never defaulted: the snapshot,
/// the history evidence, and the receipt maps carry none of its five
/// coordinates, so deriving one here would fabricate the very identity
/// the closure recheck is meant to be audited against.
#[allow(
    clippy::too_many_arguments,
    reason = "the durable feed boundary keeps read, publish, fence, roots, history, revision, and the admitted operation identity explicit"
)]
pub async fn synchronize_owner_feed<
    R: CanonicalReadClient + ?Sized,
    P: OwnerPublishPort + ?Sized,
>(
    reads: &R,
    kernel: &P,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origin_refs: &[String],
    max_records: u32,
    expected_revision: u64,
    operation: RevocationOperationIdentity,
) -> Result<u64, CompositionError> {
    synchronize_owner_feed_with_canonical_receipts(
        reads,
        kernel,
        snapshot,
        state_fence,
        origin_refs,
        max_records,
        expected_revision,
        BTreeMap::new(),
        operation,
    )
    .await
}

/// Runs the owner feed with canonical second-phase links read from the
/// durable ORS boundary. The map is never reconstructed from process-local
/// state; an absent link remains explicitly pending.
///
/// `operation` carries the same admitted identity
/// [`synchronize_owner_feed`] requires, forwarded verbatim.
#[allow(
    clippy::too_many_arguments,
    reason = "the durable feed boundary keeps read, publish, fence, roots, history, revision, canonical receipt evidence, and the admitted operation identity explicit"
)]
pub async fn synchronize_owner_feed_with_canonical_receipts<
    R: CanonicalReadClient + ?Sized,
    P: OwnerPublishPort + ?Sized,
>(
    reads: &R,
    kernel: &P,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origin_refs: &[String],
    max_records: u32,
    expected_revision: u64,
    canonical_receipts: BTreeMap<String, ReceiptIdentity>,
    operation: RevocationOperationIdentity,
) -> Result<u64, CompositionError> {
    synchronize_owner_feed_with_quarantine_evidence(
        reads,
        kernel,
        snapshot,
        state_fence,
        origin_refs,
        max_records,
        expected_revision,
        canonical_receipts,
        BTreeMap::new(),
        operation,
    )
    .await
}

/// Runs the owner feed with canonical second-phase links plus owner
/// quarantine evidence records read from the durable boundary. Neither map
/// is reconstructed from process-local state; absent evidence leaves the
/// affected omissions explicitly unresolved.
///
/// `operation` is the admitted principal, task, work scope, observing
/// receipt, and causal transaction position the restored provider's
/// origin-bound recheck and every served closure verdict run under. It is
/// required, not defaulted, because nothing reachable from this boundary
/// holds it: the owner snapshot is a grant/effect payload, the decoded
/// history is a fence, a durable source revision, and per-closure owner
/// namespace/digest/bounds records, and the two evidence maps are
/// per-root link and quarantine records. The graph is a pure authority
/// evaluator with no plan, no scope binding, and no Store readback, so
/// no coordinate is derivable here. Reusing `origin_ref` as the principal
/// or work scope, or mapping `source_revision` into a transaction
/// sequence, would restate the operation's own subject as its identity
/// and break the audit the recheck exists to provide. The durable
/// boundary that admitted this operation supplies it, already refused by
/// `RevocationOperationIdentity::admit` if any coordinate is blank,
/// control-bearing, or carries no `transaction_sequence`.
#[allow(
    clippy::too_many_arguments,
    reason = "the durable feed boundary keeps read, publish, fence, roots, history, revision, canonical receipt evidence, quarantine evidence, and the admitted operation identity explicit"
)]
pub async fn synchronize_owner_feed_with_quarantine_evidence<
    R: CanonicalReadClient + ?Sized,
    P: OwnerPublishPort + ?Sized,
>(
    reads: &R,
    kernel: &P,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origin_refs: &[String],
    max_records: u32,
    expected_revision: u64,
    canonical_receipts: BTreeMap<String, ReceiptIdentity>,
    quarantine_evidence: BTreeMap<String, CrossRootQuarantineEvidence>,
    operation: RevocationOperationIdentity,
) -> Result<u64, CompositionError> {
    if expected_revision == 0 {
        return Err(CompositionError::Owner(
            "owner feed expected revision must be nonzero".to_owned(),
        ));
    }
    if snapshot.state_fence != *state_fence || snapshot.grant_graph.revision != expected_revision {
        return Err(CompositionError::Recovery(
            "owner feed snapshot is not bound to the expected fence and graph revision".to_owned(),
        ));
    }
    let expected_roots: BTreeSet<String> = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect();
    let requested_roots: BTreeSet<String> = origin_refs.iter().cloned().collect();
    if requested_roots.is_empty() || requested_roots != expected_roots {
        return Err(CompositionError::Recovery(
            "owner feed origin set does not match the durable graph roots".to_owned(),
        ));
    }
    let durable_registry = snapshot
        .owner_hydrations
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let mut merged_closures = BTreeMap::new();
    for origin_ref in origin_refs {
        let initialized = kernel
            .initialize_owner_revision(origin_ref, expected_revision, state_fence)
            .await?;
        if initialized != expected_revision {
            return Err(CompositionError::Recovery(format!(
                "owner feed initialized revision {initialized} disagrees with expected {expected_revision}"
            )));
        }
        let request = revocation_history_read_request(state_fence, origin_ref, max_records)?;
        let response = reads
            .execute_named(request)
            .await
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let evidence = decode_revocation_history_evidence(&response, state_fence)?;
        if evidence.source_revision != expected_revision {
            return Err(CompositionError::Recovery(format!(
                "owner feed observed revision {} disagrees with expected {expected_revision}; trigger is stale",
                evidence.source_revision
            )));
        }
        for closure in evidence.closures {
            if closure.root_ref != *origin_ref {
                return Err(CompositionError::Recovery(
                    "owner history returned a closure for a different authority root".to_owned(),
                ));
            }
            // #2966 step 2: the declared owner namespace is the partition key
            // this feed merges under, so a row served under another namespace
            // is never merged into this graph's history.
            if closure.owner_namespace != *origin_ref {
                return Err(CompositionError::Recovery(
                    "owner history returned a closure for a different owner namespace".to_owned(),
                ));
            }
            if let Some(previous) = merged_closures.get(&closure.closure_id) {
                if previous != &closure {
                    return Err(CompositionError::Recovery(
                        "owner histories disagree for the same closure identity".to_owned(),
                    ));
                }
            } else {
                merged_closures.insert(closure.closure_id.clone(), closure);
            }
        }
    }
    let evidence = RevocationHistoryEvidence {
        state_fence: state_fence.clone(),
        source_revision: expected_revision,
        closures: merged_closures.into_values().collect(),
    };
    let provider = OwnerClosureProvider::restore_with_quarantine_evidence(
        snapshot,
        Some(evidence),
        state_fence,
        canonical_receipts,
        quarantine_evidence,
        operation,
    )?;
    if let Some(expected_registry) = durable_registry {
        let actual_registry = provider.export_registry()?;
        if actual_registry != expected_registry {
            return Err(CompositionError::Recovery(
                "owner feed rebuilt a hydration registry different from durable owner payload"
                    .to_owned(),
            ));
        }
    }
    publish_owner_feed(kernel, &provider, expected_revision).await
}
