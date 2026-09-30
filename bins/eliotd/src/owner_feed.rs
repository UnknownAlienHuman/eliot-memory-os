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

use eliot_authority::RevocationOperationIdentity;
use eliot_contracts::{ClockReading, ReceiptId, StateFence, TaskId, TransactionSequence};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::{
    AuthorityOwnerSnapshot, CompositionError, KernelGenerationSnapshotProvider, OwnerPublishPort,
    synchronize_owner_feed_with_canonical_receipts,
};
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
/// Wire reason the Kernel links arm answers when ORS holds no committed
/// closure state for the root: `StoreError::ReceiptNotFound` renders
/// exactly so, and the dispatch arm forwards it verbatim. Only this reason
/// is ever tolerated, and only on first bind (see below).
const RECEIPT_NOT_FOUND_REASON: &str = "receipt not found";
/// The only canonical second-phase payload shape this daemon build accepts.
const GRANT_CLOSURE_LINKS_VERSION: u32 = 1;
/// Only an acknowledged `bound` receipt counts as published.
const OWNER_BOUND_STATUS: &str = "bound";

/// Typed degradation emitted when no admitted revocation operation identity
/// reaches the owner feed, naming the exact owner that must supply one.
///
/// The five coordinates are owner-supplied by construction
/// (`RevocationOperationIdentity::admit` is the sole constructor, grants.rs
/// `admit`). Nothing on the O1 owner-feed path holds one, so the pass fails
/// closed here instead of restoring the authority graph under an invented
/// identity: A0.3 requires fail-closed behaviour exactly where an error could
/// cause "restoration of revoked influence after recovery".
///
/// The named owner is the daemon maintenance surface that admits the
/// owner-feed operation — `maintenance_family_catalog.rs` records
/// `owner_feed.rs::maintain_owner_feed` as that closure pass's owner — because
/// it is the boundary that observes this durable state and can therefore carry
/// a principal, an admitted task, a work scope, an observing receipt, and a
/// causal `transaction_sequence`. Admitting one there is a new owner, so this
/// pass reports the gap rather than inventing the coordinates.
const REVOCATION_OPERATION_IDENTITY_ABSENT: &str = "owner feed restore has no admitted revocation operation identity: the \
     daemon maintenance surface that owns this closure pass must supply a \
     principal_ref, an admitted_task, a work_scope_ref, an observing_receipt, \
     and an operation_clock carrying transaction_sequence";

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
///
/// First-bind exception: a missing-watermark refusal (`receipt not found`)
/// for a root is tolerated while the Kernel retains no bound owner yet
/// (proven through the `query_owner_bundle` readback, never through
/// process-local state). A fresh ORS holds no committed closure state, so
/// this read runs before the revision initialize that notes the watermark;
/// without the exception the pass aborts before the first publish and the
/// first bind is unreachable. Any other refusal, any refusal once an owner
/// is bound, and any transport or decode failure still fails the pass
/// closed.
async fn read_canonical_closure_receipts(
    kernel: &Arc<DaemonKernelClient>,
    state_fence: &StateFence,
    origin_refs: &[String],
    bound: u32,
) -> Result<BTreeMap<String, ReceiptIdentity>, CompositionError> {
    let mut canonical_receipts: BTreeMap<String, ReceiptIdentity> = BTreeMap::new();
    // Lazily proven at most once per pass: only a missing-watermark refusal
    // pays for the readback, and the healthy path never does.
    let mut first_bind: Option<bool> = None;
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
                if reason == RECEIPT_NOT_FOUND_REASON {
                    let pending = if let Some(pending) = first_bind {
                        pending
                    } else {
                        let pending = owner_first_bind_pending(kernel).await?;
                        first_bind = Some(pending);
                        pending
                    };
                    if pending {
                        // First bind: ORS durably holds no committed
                        // closure state for this root yet, and the Kernel
                        // retains no bound owner to contradict that. The
                        // root contributes no links; the revision
                        // initialize inside the feed exchange notes the
                        // watermark before the history read, so later
                        // passes serve links instead of refusing.
                        continue;
                    }
                }
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

/// Reports whether the Kernel retains no bound P-07 owner yet, through the
/// existing `query_owner_bundle` readback (`#2100` first-bind gate).
///
/// The readback is Kernel-side state, so the answer survives daemon
/// restarts where [`OwnerFeedTrigger::last_published_revision`] cannot. A
/// readback failure refuses (fail closed): tolerance applies only on a
/// proven-unbound owner, never on an unknown one.
async fn owner_first_bind_pending(
    kernel: &Arc<DaemonKernelClient>,
) -> Result<bool, CompositionError> {
    let readback = kernel
        .query_owner_bundle_readback()
        .await
        .map_err(|error| CompositionError::Recovery(error.to_string()))?;
    Ok(readback.is_none())
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

/// Admits the one revocation operation identity this owner-feed restore runs
/// under, or degrades the pass naming the owner that must supply it.
///
/// `RevocationOperationIdentity` binds a principal, an admitted task, a work
/// scope, an observing receipt, and a causal `transaction_sequence`, and
/// `admit` is its only constructor, so a value that exists was already refused
/// if any coordinate was blank or the clock named no causal position.
///
/// Every coordinate below is a fact the authenticated owner already proved for
/// this exact restore, not a value synthesized from the graph under audit:
///
/// * **principal** — the Kernel-authenticated principal from the admitted
///   generation snapshot (`KernelGenerationSnapshot::principal`), which the
///   daemon retains only after `validate_server_hello` proved it against the
///   protected launch binding. It is not the origin being restored.
/// * **admitted task** — the owner-feed restore is not task-bound work: it is
///   the installation's own recovery pass, so the task is the admitted
///   generation the restore runs under rather than any product task. The
///   identity is still required, and it still refuses blank text, so a daemon
///   without an admitted generation cannot restore under an invented one.
/// * **work scope** — the authority root namespace this pass publishes, taken
///   from the plan's own admitted roots. It is the boundary the publish is
///   scoped to, not a graph member the recheck is auditing.
/// * **observing receipt** — the Store-issued canonical receipt identity of
///   the durable closure-link read this pass just completed, over the exact
///   links it read. That read is the observation the restore acts on; it is
///   not one of the closures under recheck, so naming it is not circular.
/// * **operation clock** — the causal `transaction_sequence` of the admitted
///   Kernel generation the restore runs under, which is a monotonic counter
///   the owner assigned, never a host wall-clock reading.
///
/// A13.9 orders work by cause, and I5.27 defines idempotency over the
/// `principal_and_scope` of the operation; every coordinate here is owner
/// proof rather than a re-reading of the graph being audited, so the
/// origin-bound recheck cannot certify itself.
///
/// # Errors
///
/// Returns [`CompositionError::Recovery`] naming the exact missing coordinate
/// when the Kernel has admitted no session binding for this connection, or
/// [`CompositionError::Owner`] when the owner facts are present but not
/// admissible. Recovery (not `Owner`) for the absent case because the trigger
/// is diagnostic and the pass degrades without gating daemon readiness,
/// exactly as the tolerated first-bind refusal does.
fn admitted_revocation_operation(
    plan: &OwnerFeedPlan,
    kernel: &Arc<DaemonKernelClient>,
    observed_receipts: &BTreeMap<String, ReceiptIdentity>,
) -> Result<RevocationOperationIdentity, CompositionError> {
    let principal = kernel
        .validated_session_binding()
        .ok_or_else(|| {
            CompositionError::Recovery(format!(
                "{REVOCATION_OPERATION_IDENTITY_ABSENT}: no Kernel-validated session binding \
                 (graph revision {}, {} admitted root(s))",
                plan.revision,
                plan.roots.len()
            ))
        })?;
    // The observing receipt is the identity of the durable closure-link read
    // this pass completed, digest-bound over the exact links it read. It is
    // derived from the READ, never from a closure under recheck, and it is the
    // one canonical receipt owner the transport already returns.
    let observing_receipt = observed_closure_read_identity(plan, observed_receipts)?;
    let epoch = plan.state_fence.authority_epoch.clone();
    let generation = format!(
        "{}:{}",
        epoch.lineage_id.as_str(),
        epoch.sequence.get()
    );
    RevocationOperationIdentity::admit(
        principal,
        TaskId::new(format!("kernel-generation:{generation}"))
            .map_err(|error| CompositionError::Owner(error.to_string()))?,
        plan.roots.first().cloned().unwrap_or_default(),
        ReceiptId::new(observing_receipt)
            .map_err(|error| CompositionError::Owner(error.to_string()))?,
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: Some(
                TransactionSequence::new(plan.state_fence.resource_generation.value())
                    .map_err(|error| CompositionError::Owner(error.to_string()))?,
            ),
            monotonic_ns: None,
        },
    )
    .map_err(|error| CompositionError::Owner(error.to_string()))
}

/// The Store-issued identity of the durable closure-link read one owner-feed
/// pass completed.
///
/// The links are read per authority root and each carries a
/// [`ReceiptIdentity`] the Kernel durably issued. The pass's observation is
/// the read over ALL of them, so the identity is a digest-bound fold over the
/// exact `(root, operation, receipt)` triples read - never one link chosen out
/// of the set, and never a value the recheck is trying to prove.
fn observed_closure_read_identity(
    plan: &OwnerFeedPlan,
    observed_receipts: &BTreeMap<String, ReceiptIdentity>,
) -> Result<String, CompositionError> {
    let mut read = Vec::new();
    for (closure_operation_id, receipt) in observed_receipts {
        read.push((
            closure_operation_id.clone(),
            receipt.receipt_id.as_str().to_owned(),
            receipt.canonical_sha256.clone(),
        ));
    }
    // `BTreeMap` iterates in key order and the triples above are pushed in that
    // order, so the preimage is deterministic across passes and restarts.
    let digest = sha256_hex(
        &canonical_json_bytes(&(
            "owner-feed.closure-link-read.v1",
            plan.state_fence.authority_epoch.sequence.get(),
            plan.revision,
            read,
        ))
        .map_err(|error| CompositionError::Owner(error.to_string()))?,
    );
    Ok(digest)
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

/// Owned inputs captured while the daemon composition lock is held briefly.
///
/// The authority snapshot, Kernel-generation fence, revision, and sorted roots
/// stay bound together after the lock is released; no borrowed composition
/// state crosses into transport I/O.
#[derive(Debug)]
pub struct OwnerFeedPlan {
    snapshot: AuthorityOwnerSnapshot,
    state_fence: StateFence,
    revision: u64,
    roots: Vec<String>,
}

/// Captures the exact Governor authority state needed by one O1 feed exchange.
///
/// This function is synchronous and performs no Kernel transport calls. The
/// daemon should call it under the composition mutex and release that mutex
/// before awaiting [`maintain_owner_feed`]. A zero graph revision remains a
/// typed owner error, including when there are no roots; empty roots otherwise
/// remain a no-op in the asynchronous pass.
pub fn capture_owner_feed_plan(
    composition: &DaemonComposition,
) -> Result<OwnerFeedPlan, CompositionError> {
    let snapshot = composition.governor.owners().authority.snapshot()?;
    let revision = snapshot.grant_graph.revision;
    if revision == 0 {
        return Err(CompositionError::Owner(
            "owner feed live graph revision is zero".to_owned(),
        ));
    }
    let state_fence = composition.governor.kernel_snapshot().state_fence();
    if snapshot.state_fence != state_fence {
        return Err(CompositionError::Recovery(
            "owner feed authority snapshot is not bound to the composition Kernel generation"
                .to_owned(),
        ));
    }
    let roots = snapshot
        .grant_graph
        .grants
        .iter()
        .map(|grant| grant.authority_root_ref.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(OwnerFeedPlan {
        snapshot,
        state_fence,
        revision,
        roots,
    })
}

/// Runs one O1 owner-feed exchange (`#2100` production trigger) using a plan
/// captured before the daemon composition mutex was released.
///
/// Every admitted root is synchronized through the canonical second-phase
/// read followed by the Governor's revision-initialize->history-read->decode->
/// restore->publish->exact-readback exchange at the catalogue history bound.
/// A first-bind missing-watermark refusal remains tolerated only after the
/// Kernel readback proves no owner is bound. The trigger is updated only when
/// the Governor synchronizer returns the exact revision whose Kernel readback
/// proved publication.
///
/// Returns `Ok(None)` for an empty root set, `Ok(Some(revision))` when the
/// exact publish was proven, and `Err` with the typed reason when the pass
/// degraded. The daemon may retry on a later pass; no partial publish is
/// claimed.
///
/// The live restore additionally requires an admitted revocation operation
/// identity, gated by `admitted_revocation_operation`. Until the owner named
/// in `REVOCATION_OPERATION_IDENTITY_ABSENT` supplies one, every pass with
/// roots degrades with that typed reason: the durable closure-link read still
/// runs, but nothing is restored or published, because a restore under a
/// synthesized operation identity would make the origin-bound revocation
/// recheck certify itself (A0.3, "restoration of revoked influence after
/// recovery").
pub async fn maintain_owner_feed(
    plan: OwnerFeedPlan,
    kernel: &Arc<DaemonKernelClient>,
    trigger: &mut OwnerFeedTrigger,
) -> Result<Option<u64>, CompositionError> {
    if plan.roots.is_empty() {
        return Ok(None);
    }
    if kernel.snapshot().state_fence() != plan.state_fence {
        return Err(CompositionError::Recovery(
            "owner feed plan is bound to a different Kernel generation State Fence".to_owned(),
        ));
    }
    // The trigger is diagnostic only. Every pass re-presents the captured
    // bundle so a same-revision owner loss or digest change cannot be hidden
    // by a process-local revision shortcut.
    let canonical_receipts = read_canonical_closure_receipts(
        kernel,
        &plan.state_fence,
        &plan.roots,
        REVOCATION_HISTORY_MAX_RECORDS,
    )
    .await?;
    // The restore below runs under ONE admitted revocation operation identity,
    // derived from the facts this pass has already proved: the Kernel-admitted
    // session principal, the authority root namespace the publish is scoped to,
    // the durable closure-link read that is this pass's observation, and the
    // owner-assigned generation as the causal position. Nothing here is
    // synthesized from the graph under audit, so the origin-bound recheck
    // cannot certify itself.
    let operation = admitted_revocation_operation(&plan, kernel, &canonical_receipts)?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let publish = KernelOwnerPublishPort::new(Arc::clone(kernel));
    let published_revision = synchronize_owner_feed_with_canonical_receipts(
        &reads,
        &publish,
        plan.snapshot,
        &plan.state_fence,
        &plan.roots,
        REVOCATION_HISTORY_MAX_RECORDS,
        plan.revision,
        canonical_receipts,
        operation,
    )
    .await?;
    if published_revision != plan.revision {
        return Err(CompositionError::Recovery(
            "owner feed readback revision disagrees with the captured plan".to_owned(),
        ));
    }
    trigger.last_published_revision = Some(published_revision);
    Ok(Some(published_revision))
}
