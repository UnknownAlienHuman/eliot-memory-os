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
//! // fence, the origin selector, the record bound, and the exact expected
//! // graph revision:
//! let bound = synchronize_owner_feed(
//!     &reads, &kernel_publish_port,
//!     snapshot, state_fence, origin_ref, max_records, expected_revision,
//! ).await?;
//! ```
//!
//! `OwnerPublishPort` is implemented once by the daemon runtime against
//! the Kernel front-door `publish_owner_bundle` / `query_owner_bundle`
//! operations; the exchange below stays typed and never touches
//! transport bytes. [`publish_owner_feed`] remains available for a
//! caller that already holds a restored provider.

use eliot_contracts::StateFence;
use eliot_kernel_core::{GovernorClosureRestore, owner_bundle_digest};
use eliot_store_api::{
    CanonicalReadClient, REVOCATION_HISTORY_ROOT_SELECTOR, RevocationHistoryRoot,
};

use crate::{
    AuthorityOwnerSnapshot, CompositionError, OwnerClosureProvider,
    decode_revocation_history_with_root, revocation_history_read_request,
};

/// Result of one owner-feed synchronization, including the exact live
/// revocation evidence consumed by the production fan-out.
#[derive(Clone, Debug)]
pub struct OwnerFeedSync {
    /// Revision proven by Kernel readback.
    pub revision: u64,
    /// CURRENT history decoded from the canonical read.
    pub history: eliot_authority::RevocationHistoryEvidence,
}

/// A read-and-restored owner feed that has not yet been published. The
/// production Governor applies its derivative invalidation fan-out to this
/// value before `publish_owner_feed` makes the restored owner observable.
pub struct PreparedOwnerFeed {
    /// Restored provider carrying the explicit current history.
    pub provider: OwnerClosureProvider,
    /// Exact history read from the canonical store.
    pub history: eliot_authority::RevocationHistoryEvidence,
}

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

/// Reads and restores one owner feed without publishing it yet.
///
/// Keeping this phase separate is causal: the production Governor can apply
/// revocation fan-out to the restored provider and its current effects,
/// context, cache, and rebuild owners before the Kernel can observe a newly
/// published owner bundle.
pub async fn prepare_owner_feed<R: CanonicalReadClient + ?Sized>(
    reads: &R,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origin_ref: &str,
    max_records: u32,
    expected_revision: u64,
) -> Result<PreparedOwnerFeed, CompositionError> {
    let root_request = revocation_history_read_request(
        state_fence,
        REVOCATION_HISTORY_ROOT_SELECTOR,
        max_records,
    )?;
    let root_response = reads
        .execute_named(root_request)
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let (root_index, _) = decode_revocation_history_with_root(&root_response, state_fence)?;
    let request = revocation_history_read_request(state_fence, origin_ref, max_records)?;
    let response = reads
        .execute_named(request)
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let (root, history) = decode_revocation_history_with_root(&response, state_fence)?;
    if root != root_index {
        return Err(CompositionError::Recovery(
            "owner feed origin and independent Store root-index reads disagree".to_owned(),
        ));
    }
    // `expected_revision` is the authority/graph revision. The Store history
    // root has its own independent revision; equating the two would reject a
    // valid history advance (or accept a stale graph) and is intentionally not
    // done here. The root watermark above is the history comparison.
    let _ = expected_revision;
    let provider = OwnerClosureProvider::restore(snapshot, Some(history.clone()), state_fence)?;
    Ok(PreparedOwnerFeed { provider, history })
}

/// Reads every origin named by the live owner snapshot and proves that every
/// read carries the same complete Store history root.  The provider is
/// restored once from the union, so the caller can fan out and publish one
/// coherent owner bundle rather than publishing per-origin projections.
pub async fn prepare_owner_feed_for_roots<R: CanonicalReadClient + ?Sized>(
    reads: &R,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origins: &[String],
    max_records: u32,
) -> Result<(PreparedOwnerFeed, RevocationHistoryRoot), CompositionError> {
    if origins.is_empty() {
        return Err(CompositionError::Recovery(
            "owner feed requires at least one live authority root".to_owned(),
        ));
    }
    if origins
        .iter()
        .any(|origin| origin == REVOCATION_HISTORY_ROOT_SELECTOR)
    {
        return Err(CompositionError::Recovery(
            "the Store history root selector cannot be used as a semantic authority origin"
                .to_owned(),
        ));
    }

    // The independent root-index read is the first observation and the
    // watermark against which every semantic origin read is compared.  A
    // caller-provided root list is only an additional live-graph enumeration;
    // it cannot replace or silently omit the Store-owned trigger.
    let root_request = revocation_history_read_request(
        state_fence,
        REVOCATION_HISTORY_ROOT_SELECTOR,
        max_records,
    )?;
    let root_response = reads
        .execute_named(root_request)
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let (root_index, _) = decode_revocation_history_with_root(&root_response, state_fence)?;
    let mut pending: Vec<String> = origins.to_vec();
    pending.extend(root_index.root_refs.iter().cloned());
    pending.sort();
    pending.dedup();

    let mut next = 0_usize;
    let mut closures = Vec::new();
    while next < pending.len() {
        let origin = pending[next].clone();
        next += 1;
        let request = revocation_history_read_request(state_fence, &origin, max_records)?;
        let response = reads
            .execute_named(request)
            .await
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let (root, history) = decode_revocation_history_with_root(&response, state_fence)?;
        if root != root_index {
            return Err(CompositionError::Recovery(
                "owner feed roots were not read at one shared Store history watermark".to_owned(),
            ));
        }
        closures.extend(history.closures);
    }
    let root = root_index;
    closures.sort_by(|left, right| left.closure_id.cmp(&right.closure_id));
    let history = eliot_authority::RevocationHistoryEvidence {
        state_fence: state_fence.clone(),
        source_revision: root.history_revision,
        closures,
    };
    history
        .require_current()
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    let provider = OwnerClosureProvider::restore(snapshot, Some(history.clone()), state_fence)?;
    Ok((PreparedOwnerFeed { provider, history }, root))
}

/// Runs one complete trigger-driven owner synchronization (`#2100`
/// admitted caller → publish → recover path).
///
/// One call performs the whole chain with no gaps for the trigger
/// owner to fill: it builds the closed history read for the exact
/// origin, executes it through the canonical read client, decodes the
/// reply against the expected fence, restores the provider with that
/// live evidence, and publishes through [`publish_owner_feed`]. The
/// independent Store history-root watermark, rather than the graph
/// revision, is compared across the root-index and origin reads. Unavailable
/// history, fence disagreement, stale evidence, and readback mismatch all
/// refuse before any owner state is installed or claimed.
pub async fn synchronize_owner_feed<
    R: CanonicalReadClient + ?Sized,
    P: OwnerPublishPort + ?Sized,
>(
    reads: &R,
    kernel: &P,
    snapshot: AuthorityOwnerSnapshot,
    state_fence: &StateFence,
    origin_ref: &str,
    max_records: u32,
    expected_revision: u64,
) -> Result<OwnerFeedSync, CompositionError> {
    let prepared = prepare_owner_feed(
        reads,
        snapshot,
        state_fence,
        origin_ref,
        max_records,
        expected_revision,
    )
    .await?;
    let revision = publish_owner_feed(kernel, &prepared.provider, expected_revision).await?;
    Ok(OwnerFeedSync {
        revision,
        history: prepared.history,
    })
}
