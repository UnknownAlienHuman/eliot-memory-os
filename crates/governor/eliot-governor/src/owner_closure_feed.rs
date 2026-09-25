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
) -> Result<u64, CompositionError> {
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
    let provider = OwnerClosureProvider::restore(snapshot, Some(evidence), state_fence)?;
    publish_owner_feed(kernel, &provider, expected_revision).await
}
