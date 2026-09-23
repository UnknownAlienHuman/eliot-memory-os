//! O1-owned owner-feed trigger: retained snapshot currency plus Kernel
//! readback state drive the synchronize call, once per evaluation (issue
//! #2100 owner-closure feed).
//!
//! Owner wiring: the Governor owner holds the canonical closure state
//! (`OwnerClosureProvider`: restore/refresh/serve, exact-revision
//! enumeration), the Kernel retains the bound P-07 owner behind its
//! front-door route, and the feed exchange
//! (`synchronize_owner_feed`: history read, decode, restore, publish,
//! readback verification) owns the admission mechanics. This drive owns
//! only the trigger sequencing between them: it reads the retained
//! snapshot, derives the origin selector plus expected revision from its
//! public fields, checks the Kernel readback, and invokes the exchange.
//! It mints no snapshot, revision, origin, receipt, or authority; every
//! load-bearing value is owner-read and every agreement is checked before
//! firing.
//!
//! Trigger policy with live checks before authoritative use (the feed
//! module names the two cases: provider-revision advance = rotation, and
//! recovery = restart re-presentation):
//!
//! 1. Read the retained authority snapshot through the composition (fails
//!    closed when the Governor is unready or the snapshot is invalid) and
//!    require a nonzero graph revision (the Kernel never binds zero).
//! 2. Require the snapshot fence to equal the live agreed fence exactly
//!    (a moved fence fails closed as stale; the Governor refresh path
//!    owns re-alignment, never this trigger).
//! 3. Derive the origin selector from the snapshot's distinct lineage
//!    roots: exactly one root proceeds; zero or several fail closed as
//!    missing/ambiguous rather than defaulting an origin.
//! 4. Read back the Kernel-retained triple. Unbound, or bound below the
//!    snapshot revision, proceeds to the full exchange at the snapshot
//!    revision; bound at the snapshot revision short-circuits as verified
//!    (no redundant publish, no lost-ack ambiguity); bound above it
//!    refuses as a snapshot-behind regression (never downgrades); bound
//!    without a revision, or at revision zero, refuses as anomalous.
//!    Digest skew under a matching revision is a Kernel-integrity matter
//!    outside daemon scope; the full digest proof runs inside the
//!    exchange on every publish path.
//! 5. The full exchange reads history (complete bound,
//!    [`REVOCATION_HISTORY_MAX_RECORDS`](eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS),
//!    because a partial history could miss a revocation), decodes,
//!    restores, publishes, and verifies readback itself; the observed
//!    evidence revision must equal the expected revision or the trigger
//!    is stale. Unknown-operation/unavailable store legs fail the
//!    evaluation (never silently skipped); the loop never fails.
//!
//! Unknown/replay/cancellation preservation: the drive mutates nothing
//! itself and retains nothing across calls — the Kernel readback is the
//! only currency record, so restarts re-present correctly with no stale
//! local state; a failed evaluation never advances anything, so retries
//! are always safe; cancellation paths are untouched; unknown outcomes
//! keep their identities in `Failed` without collapse. Execution-plane
//! failures must never fail the activation loop that hosts this drive.

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS;
use eliot_governor::OwnerPublishPort;
use crate::attempt_execution_chain::{
    ExecutionChainError, supply_governor_fence, supply_live_kernel_fence,
};
use crate::owner_publish::DaemonOwnerPublishPort;
use crate::{DaemonComposition, DaemonKernelClient};

/// Outcome of one owner-feed trigger evaluation: published with a verified
/// bound revision, verified already-bound without republishing, or failed
/// with identities preserved. Debug-only: the `Failed` payload carries
/// owner errors without clone/equality semantics.
#[derive(Debug)]
pub enum OwnerFeedDriveOutcome {
    /// The exchange published and verified the bound revision.
    Published {
        /// Kernel-acknowledged bound graph revision.
        revision: u64,
    },
    /// The Kernel readback already binds the snapshot revision: no
    /// publish ran, no lost-acknowledgement ambiguity remains.
    BoundVerified {
        /// Readback-confirmed bound graph revision.
        revision: u64,
    },
    /// A snapshot, fence, origin, readback, or exchange refusal with
    /// identities preserved, never collapsed. Never fails the activation
    /// loop that hosts this drive.
    Failed(ExecutionChainError),
}

/// Drive one owner-feed trigger evaluation over live owners.
///
/// Evaluated in the daemon binary flow (see the run-loop dispatch arm):
/// retained snapshot currency, origin derivation, Kernel readback state,
/// then at most one full exchange per evaluation. Deterministic except
/// for the live reads and the unbounded-leg exchange; mutates nothing
/// itself — the only mutation is the Kernel's retained owner binding
/// inside the verified exchange.
pub async fn drive_owner_feed_once(
    kernel: &Arc<DaemonKernelClient>,
    composition: &DaemonComposition,
) -> OwnerFeedDriveOutcome {
    let _span = tracing::info_span!("eliotd.owner_feed_poll").entered();
    let refused =
        |owner: &'static str, reason: String| OwnerFeedDriveOutcome::Failed(
            ExecutionChainError::SupplierReadRejected { owner, reason },
        );
    // 1. Retained snapshot plus nonzero revision.
    let snapshot = match composition.authority_owner_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return refused("authority owner snapshot", error.to_string());
        }
    };
    let snapshot_revision = snapshot.grant_graph.revision;
    if snapshot_revision == 0 {
        return refused(
            "authority owner snapshot",
            "snapshot graph revision is zero; the Kernel never binds revision zero".to_owned(),
        );
    }
    // 2. Fence currency: agreed live fence first (established O1 pattern),
    // then exact snapshot-fence equality mirroring the restore check.
    let live_fence = supply_live_kernel_fence(kernel.as_ref());
    let governor_fence = supply_governor_fence(composition);
    if !eliot_contracts::fences_match_exact(&live_fence, &governor_fence) {
        return OwnerFeedDriveOutcome::Failed(ExecutionChainError::StaleAdmissionFence);
    }
    if snapshot.state_fence != live_fence {
        return OwnerFeedDriveOutcome::Failed(ExecutionChainError::StaleAdmissionFence);
    }
    // 3. Origin selector: exactly one distinct lineage root or refuse.
    let mut roots = BTreeSet::new();
    for grant in &snapshot.grant_graph.grants {
        roots.insert(grant.authority_root_ref.clone());
    }
    let origin = match roots.len() {
        1 => roots.into_iter().next().unwrap_or_default(),
        0 => {
            return refused(
                "authority lineage roots",
                "authority snapshot carries no lineage root; no origin to read history under".to_owned(),
            );
        }
        _ => {
            return refused(
                "authority lineage roots",
                "authority snapshot carries several lineage roots; origin selection is ambiguous".to_owned(),
            );
        }
    };
    // 4. Kernel readback state drives publish-vs-verify-vs-refuse.
    let port = DaemonOwnerPublishPort::new(kernel.as_ref());
    let (bound, revision, _digest) = match port.query_owner_readback().await {
        Ok(triple) => triple,
        Err(error) => {
            return refused("owner readback", error.to_string());
        }
    };
    match (bound, revision) {
        (false, _) => {}
        (true, Some(current)) if current == snapshot_revision => {
            tracing::info!(
                revision = snapshot_revision,
                "owner feed already bound at the snapshot revision",
            );
            return OwnerFeedDriveOutcome::BoundVerified {
                revision: snapshot_revision,
            };
        }
        (true, Some(current)) if current > snapshot_revision => {
            return refused(
                "owner readback",
                "Kernel bound revision is newer than the snapshot revision; publishing would downgrade".to_owned(),
            );
        }
        (true, _) => {
            return refused(
                "owner readback",
                "Kernel bound state carries no usable revision; refusing without a bound identity".to_owned(),
            );
        }
    }
    // 5. Full exchange at the snapshot revision (complete history bound;
    // reads client built per call so a Governor refresh surfaces as an
    // exact mismatch instead of silent divergence).
    let reads = match composition.context_read_client(kernel) {
        Ok(reads) => reads,
        Err(error) => {
            return refused("bridge read client", error.to_string());
        }
    };
    match composition
        .synchronize_kernel_owner(
            &reads,
            &port,
            &origin,
            REVOCATION_HISTORY_MAX_RECORDS,
            snapshot_revision,
        )
        .await
    {
        Ok(revision) => {
            tracing::info!(
                revision = revision,
                "owner feed published and verified",
            );
            OwnerFeedDriveOutcome::Published { revision }
        }
        Err(error) => refused("owner feed synchronize", error.to_string()),
    }
}
