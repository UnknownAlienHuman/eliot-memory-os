//! Private Governor-backed Skill lifecycle port adapters.
//!
//! The forwarding adapter translates between the provider-neutral
//! [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi) and one Governor
//! [`GovernorSkillLifecycle`](eliot_governor::GovernorSkillLifecycle) borrowed
//! from the single [`DaemonComposition`](super::DaemonComposition) by its
//! `skill_lifecycle` accessor. It forwards authenticated input, translates
//! typed results, and enforces the catalogue usability gate on `promote`:
//!
//! - `promote` is blocked when the catalogue covers the candidate Skill and
//!   marks it stale or retired: drifted dependencies must be revalidated
//!   before Material promotion. Skills the catalogue does not cover forward
//!   untouched (open world: the registry stays authoritative until catalogue
//!   installation wiring lands).
//! - After a committed promotion, the candidate's observed dependency
//!   versions feed the catalogue, so the next promotion sees the drift. The
//!   feed runs after commit only: feeding before the usability gate would let
//!   an in-flight intentional update mark itself stale and deadlock every
//!   evolving Skill.
//! - `install_package` populates the shared catalogue from a canonical
//!   package source (production population caller): project, validate, and
//!   insert under the tool-owner existence check. It runs on whichever handle
//!   the adapter holds; the composition switches to the shared handle per the
//!   reported central hunk so installs are visible to the promote gate.
//! - `deliver_hotset` issues the Hotset delivery receipt the runtime injector
//!   carries, and `acknowledge_and_display` binds the runtime receiver's ack
//!   to that exact receipt before displaying. The ack is supplied by the real
//!   receiver (runtime Hotset injector caller), never minted here: the model
//!   validates the binding statelessly and keeps no second ledger.
//! - `view` and `propose` forward unchanged: reads and proposals neither
//!   consume the catalogue nor invent candidates.
//! - `activation_display` executes against the shared catalogue handle: entry
//!   usability, receipt self-consistency plus exact catalogue bind,
//!   applied-ack binding to that exact receipt, delivery coverage, and the
//!   tool-owner existence check all run inside the catalogue boundary. The
//!   display binds receipt, ack, and catalogue — not the state fence — so the
//!   guard is taken and dropped in a closed scope and never crosses an await.
//!   Tool-existence production wiring belongs to the tool owner: the caller
//!   supplies its `KnownTools` view, and this adapter never invents one.
//! - No other policy, admission, or semantic rules live here. Base digest/revision,
//!   exact evidence, fence, approval and reversibility stay with the Governor
//!   skill owner; this adapter never invents a candidate, gate, or promotion.
//! - `view` and `propose` are authenticated reads of the current owner at the
//!   admitted fence. A stale fence fails closed in the Governor owner, never
//!   as a local default.
//! - `promote` forwards the exact admitted identity, operation identity,
//!   candidate, gate and promoted view to the Governor canonical path. Only a
//!   `Committed` store receipt counts as promotion; rejected, cancelled and
//!   dead-letter outcomes stay pending as typed store failures, and a lost
//!   acknowledgement reconciles the same operation receipt.
//! - [`SkillPromotionReceipt`](eliot_skill::SkillPromotionReceipt) remains a
//!   domain payload/projection validated inside the Governor owner, never a
//!   second receipt ledger here.
//!
//! The adapter performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical commit. Catalogue locks are never held across an
//! await: the pre-commit gate and the post-commit feed each take and drop the
//! guard in a closed scope. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]
// The crate error carries the full store failure for typed recovery; every
// fallible function returns it by value like the Governor lifecycle API.
// Boxing it here would diverge from that contract, so the size lint is
// allowed for this module (same precedent as the Skill catalogue module).
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex, MutexGuard};

use eliot_skill::{
    ActivatedSkillDisplay, HotsetDeliveryAck, HotsetDeliveryReceipt, KnownTools, PromotionGate,
    SkillCandidate, SkillCatalogue, SkillError, SkillLifecycleApi, SkillLifecycleView,
    activation::detect_dependency_staleness,
};

/// Shared handle to the composition-owned Governor Skill catalogue.
///
/// The catalogue lives in [`DaemonComposition`](super::DaemonComposition);
/// every `skill_lifecycle` accessor hands out an adapter borrowing this
/// shared handle, so all promotions observe one catalogue state.
pub(crate) type CatalogueHandle = Arc<Mutex<SkillCatalogue>>;

/// Forwards one [`SkillLifecycleApi`] to the single Governor owner behind
/// the catalogue usability gate described above.
pub(crate) struct ForwardingSkillLifecycle<T> {
    inner: T,
    catalogue: CatalogueHandle,
}

impl<T> ForwardingSkillLifecycle<T> {
    /// Wraps the single Governor lifecycle owner for forwarding.
    ///
    /// The adapter carries a fresh empty catalogue handle, so promotion
    /// forwards exactly as before (open world: uncovered Skills forward).
    /// Composition switches to [`with_catalogue`](Self::with_catalogue) with
    /// the shared handle once catalogue installation wiring lands.
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            catalogue: Arc::new(Mutex::new(SkillCatalogue::default())),
        }
    }

    /// Wraps the single Governor lifecycle owner plus the shared catalogue
    /// handle for guarded forwarding (see the module contract).
    pub(crate) fn with_catalogue(inner: T, catalogue: CatalogueHandle) -> Self {
        Self { inner, catalogue }
    }

    fn lock_catalogue(&self) -> MutexGuard<'_, SkillCatalogue> {
        // The reactor is single-threaded and guards never cross an await, so
        // a poisoned mutex means a previous holder panicked: fail open to the
        // held state rather than bricking the skill path on a stale poison
        // flag. Locking itself cannot fail otherwise.
        self.catalogue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Installs one canonical package source into the shared catalogue and
    /// returns the installed Skill identity.
    ///
    /// This is the production population caller the runtime composition
    /// drives: the Governor owner hands over a validated package claim, its
    /// actual materialization inputs, and the explicit install context, and
    /// the shared handle records the projected entry under the tool-owner
    /// existence check. Synchronous: the guard is taken and dropped in a
    /// closed scope and never crosses an await.
    ///
    /// No in-tree production caller drives the runtime population path yet:
    /// the Governor owner wires it with the shared handle (reported central
    /// hunk). The allowance covers exactly that pending adoption; it expires
    /// when the hunk lands. Tests drive all three runtime callers.
    #[allow(dead_code)]
    pub(crate) fn install_package(
        &self,
        package: &eliot_skill::SkillPackage,
        inputs: &eliot_skill::MaterializationInputs,
        context: &eliot_skill::CatalogueInstallContext,
        tools: &dyn KnownTools,
    ) -> Result<String, SkillError> {
        let mut catalogue = self.lock_catalogue();
        eliot_skill::install_package(&mut catalogue, package, inputs, context, tools)
    }

    /// Issues the Hotset delivery receipt the runtime injector carries.
    ///
    /// Driven by the runtime Hotset injector caller with its own approval
    /// handle: a non-blank approval never comes from a Hotset identity alone.
    /// Synchronous: the guard is taken and dropped in a closed scope.
    #[allow(dead_code)]
    pub(crate) fn deliver_hotset(
        &self,
        hotset_id: String,
        skill_ids: Vec<String>,
        approval_ref: String,
        tools: &dyn KnownTools,
    ) -> Result<HotsetDeliveryReceipt, SkillError> {
        let catalogue = self.lock_catalogue();
        HotsetDeliveryReceipt::issue(hotset_id, &catalogue, skill_ids, tools, approval_ref)
    }

    /// Binds the runtime receiver's ack to its exact receipt, then displays.
    ///
    /// The ack arrives from the real receiver (runtime Hotset injector), which
    /// validated the receipt, applied or rejected the bodies, and returned the
    /// ack binding the exact receipt digest it acted on. Only an applied ack
    /// for this exact receipt reaches the catalogue boundary; anything else
    /// fails closed here without touching the catalogue. Synchronous: the
    /// guard never crosses an await.
    ///
    /// Receipt and ack travel by value, mirroring the `SkillLifecycleApi`
    /// display boundary: the injector caller relinquishes the pair it acted
    /// on instead of retaining an alias into the guarded display.
    #[allow(dead_code, clippy::needless_pass_by_value)]
    pub(crate) fn acknowledge_and_display(
        &self,
        skill_id: &str,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        tools: &dyn KnownTools,
    ) -> Result<ActivatedSkillDisplay, SkillError> {
        if !ack.confirms_applied(&receipt) {
            return Err(SkillError::IdentityMismatch);
        }
        ack.validate()?;
        let catalogue = self.lock_catalogue();
        catalogue.activation_display(skill_id, &receipt, &ack, tools)
    }
}

/// Records post-commit promotion observations in the catalogue: when the
/// catalogue covers the promoted Skill and the committed dependency versions
/// drift from the pinned set, the entry is marked stale for the next
/// promotion. Returns `true` when the entry became stale. Absent Skills are
/// uncovered (open world) and report `false`.
///
/// Called on the committed path only, with Governor-validated candidate
/// records, so the feed is infallible by construction once the pre-commit
/// usability gate has passed.
pub(crate) fn record_promotion_observation(
    catalogue: &mut SkillCatalogue,
    skill_id: &str,
    observed: Vec<eliot_skill::DependencyVersion>,
) -> Result<bool, SkillError> {
    if catalogue.get(skill_id).is_none() {
        return Ok(false);
    }
    let pinned = catalogue
        .get(skill_id)
        .map(|entry| entry.dependencies.clone())
        .unwrap_or_default();
    if let Some(reason) = detect_dependency_staleness(&pinned, &observed) {
        return catalogue.note_dependency_change(skill_id, observed, reason);
    }
    Ok(false)
}

impl<T: SkillLifecycleApi> SkillLifecycleApi for ForwardingSkillLifecycle<T> {
    async fn view(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
    ) -> Result<Option<SkillLifecycleView>, SkillError> {
        self.inner.view(ctx, skill_id).await
    }

    async fn propose(
        &self,
        ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
        candidate_package_digest: String,
        action: eliot_skill::LifecycleAction,
        evidence_refs: Vec<String>,
        dependencies: Vec<eliot_skill::DependencyVersion>,
        scope: eliot_skill::SkillScope,
    ) -> Result<SkillCandidate, SkillError> {
        self.inner
            .propose(
                ctx,
                skill_id,
                candidate_package_digest,
                action,
                evidence_refs,
                dependencies,
                scope,
            )
            .await
    }

    async fn promote(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: eliot_contracts::OperationId,
        candidate: SkillCandidate,
        gate: PromotionGate,
        promoted_view: SkillLifecycleView,
    ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
        let skill_id = candidate.base_skill_ref.skill_id().to_owned();
        let observed = candidate.dependency_versions.clone();
        {
            let catalogue = self.lock_catalogue();
            if let Some(entry) = catalogue.get(&skill_id)
                && !entry.is_usable()
            {
                return Err(SkillError::InvalidField {
                    field: "entry.status",
                    reason: "catalogue marks this Skill stale or retired; revalidate before Material promotion",
                });
            }
        }
        let receipt = self
            .inner
            .promote(identity, operation_id, candidate, gate, promoted_view)
            .await?;
        {
            let mut catalogue = self.lock_catalogue();
            if catalogue.get(&skill_id).is_some()
                && record_promotion_observation(&mut catalogue, &skill_id, observed).is_err()
            {
                debug_assert!(false, "promotion feed carries Governor-validated records");
            }
        }
        Ok(receipt)
    }

    async fn activation_display(
        &self,
        _ctx: &eliot_contracts::RequestMetadata,
        skill_id: String,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        tools: &dyn KnownTools,
    ) -> Result<ActivatedSkillDisplay, SkillError> {
        let catalogue = self.lock_catalogue();
        catalogue.activation_display(&skill_id, &receipt, &ack, tools)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use eliot_skill::{
        DependencyVersion, HotsetAckDisposition, HotsetDeliveryAck, HotsetDeliveryReceipt,
        KnownTools, LifecycleAction, LifecycleCounters, PromotionGate, SkillBody, SkillCandidate,
        SkillCatalogue, SkillCatalogueEntry, SkillIndexEntry, SkillInteractionView,
        SkillLifecycleView, SkillRef, SkillRuntimeMetadata, SkillScope, SkillStatus,
    };
    use eliot_store_api::{
        CommitId, OperationManifestDigest, Resubmission, TransitionClass, WriteReceipt,
        WriteReceiptStatus,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    struct ClosedInner {
        fence_mismatch: bool,
        succeed_promote: bool,
        calls: Arc<Mutex<u64>>,
    }

    fn success_receipt(fence: &StateFence, operation_id: OperationId) -> WriteReceipt {
        WriteReceipt {
            operation_id,
            idempotency_key: "idem-skill-1".to_owned(),
            canonical_request_hash: "d".repeat(64),
            transition_class: TransitionClass::LifecyclePolicy,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(CommitId::new("commit-1").expect("commit id")),
            state_fence: fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["cmd-1".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: OperationManifestDigest::new("manifest-test-1")
                .expect("manifest digest"),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some("commit-sequence-0000000000000001".to_owned()),
            envelope: None,
        }
    }

    impl SkillLifecycleApi for ClosedInner {
        async fn view(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
        ) -> Result<Option<SkillLifecycleView>, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            if self.fence_mismatch {
                return Err(SkillError::FenceMismatch);
            }
            Ok(None)
        }

        async fn propose(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
            _candidate_package_digest: String,
            _action: LifecycleAction,
            _evidence_refs: Vec<String>,
            _dependencies: Vec<DependencyVersion>,
            _scope: SkillScope,
        ) -> Result<SkillCandidate, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            Err(SkillError::NotFound)
        }

        async fn promote(
            &self,
            _identity: &eliot_protocol::RequestIdentity,
            operation_id: OperationId,
            _candidate: SkillCandidate,
            _gate: PromotionGate,
            _promoted_view: SkillLifecycleView,
        ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            if self.succeed_promote {
                // Test-only committed receipt: the adapter forwards receipts
                // without validating them, so only the Ok path matters here.
                let fence = StateFence::new(
                    test_epoch(1),
                    ResourceGeneration::new(1).expect("generation"),
                );
                return Ok(success_receipt(&fence, operation_id));
            }
            Err(SkillError::NotFound)
        }

        async fn activation_display(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
            _receipt: HotsetDeliveryReceipt,
            _ack: HotsetDeliveryAck,
            _tools: &dyn KnownTools,
        ) -> Result<ActivatedSkillDisplay, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            Err(SkillError::NotFound)
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn metadata(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-forward-1").expect("request"),
            session_id: Some(SessionId::new("session-forward-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn blocking_view<T>(future: impl std::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn forwarding_preserves_typed_read_results_without_policy() {
        let fence = fence();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let view = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()))
            .expect("forwarded view");
        assert!(view.is_none());
        assert_eq!(*calls.lock().expect("calls"), 1);
    }

    #[test]
    fn stale_catalogue_entry_blocks_promote_before_inner_call() {
        let fence = fence();
        let handle = installed_catalogue();
        {
            let mut catalogue = handle.lock().expect("catalogue lock");
            catalogue
                .note_dependency_change(
                    "skill-demo",
                    vec![DependencyVersion {
                        name: "tool-def-1".to_owned(),
                        version: "2.0.0".to_owned(),
                        contract_digest: "c".repeat(64),
                    }],
                    "tool-def-1 moved to 2.0.0".to_owned(),
                )
                .expect("mark stale");
        }
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: true,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let candidate = candidate_with_deps(&fence, vec![dependency("1.2.0")]);
        let gate = gate_for(&fence, &candidate);
        let blocked = blocking_view(forwarding.promote(
            &identity(&fence),
            OperationId::new("op-skill-1").expect("operation id"),
            candidate,
            gate,
            base_view(&fence),
        ));
        assert!(matches!(
            blocked,
            Err(SkillError::InvalidField { field, .. }) if field == "entry.status"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn committed_promote_feeds_observed_dependencies_into_catalogue() {
        let fence = fence();
        let handle = installed_catalogue();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: true,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, Arc::clone(&handle));
        let candidate = candidate_with_deps(&fence, vec![dependency("2.0.0")]);
        let gate = gate_for(&fence, &candidate);
        blocking_view(forwarding.promote(
            &identity(&fence),
            OperationId::new("op-skill-2").expect("operation id"),
            candidate,
            gate,
            base_view(&fence),
        ))
        .expect("committed promote forwards");
        assert_eq!(*calls.lock().expect("calls"), 1);
        let catalogue = handle.lock().expect("catalogue lock");
        let stored = catalogue.get("skill-demo").expect("stored entry");
        assert_eq!(stored.status, SkillStatus::Stale);
        assert_eq!(
            stored.dependencies,
            vec![DependencyVersion {
                name: "tool-def-1".to_owned(),
                version: "2.0.0".to_owned(),
                contract_digest: "c".repeat(64),
            }]
        );
    }

    #[test]
    fn promotion_observation_feed_covers_absent_steady_and_drift() {
        let mut catalogue = SkillCatalogue::default();
        assert!(
            !record_promotion_observation(
                &mut catalogue,
                "skill-missing",
                vec![dependency("1.2.0")]
            )
            .expect("absent skill reports no feed")
        );
        catalogue
            .insert(catalogue_entry(), &TestTools)
            .expect("install entry");
        assert!(
            !record_promotion_observation(&mut catalogue, "skill-demo", vec![dependency("1.2.0")])
                .expect("steady dependencies feed nothing")
        );
        assert!(
            record_promotion_observation(&mut catalogue, "skill-demo", vec![dependency("2.0.0")])
                .expect("drift feeds stale")
        );
        assert_eq!(
            catalogue.get("skill-demo").expect("entry").status,
            SkillStatus::Stale
        );
    }

    fn issued_display_inputs(
        handle: &CatalogueHandle,
    ) -> (HotsetDeliveryReceipt, HotsetDeliveryAck) {
        let catalogue = handle.lock().expect("catalogue lock");
        let receipt = HotsetDeliveryReceipt::issue(
            "hotset-display-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &TestTools,
            "approval-commit-1".to_owned(),
        )
        .expect("delivery receipt");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        (receipt, ack)
    }

    #[test]
    fn display_executes_real_boundary_without_touching_inner() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let display = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt.clone(),
            ack,
            &TestTools,
        ))
        .expect("applied display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn display_blocks_stale_entries_before_ack_checks() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        {
            let mut catalogue = handle.lock().expect("catalogue lock");
            catalogue
                .note_dependency_change(
                    "skill-demo",
                    vec![dependency("9.9.9")],
                    "tool-def-1 moved to 9.9.9".to_owned(),
                )
                .expect("mark stale");
        }
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let blocked = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt,
            ack,
            &TestTools,
        ));
        assert!(matches!(
            blocked,
            Err(SkillError::InvalidField { field, .. }) if field == "entry.status"
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn display_rejects_ack_bound_to_another_receipt() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, _) = issued_display_inputs(&handle);
        let foreign_ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let rejected = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt,
            foreign_ack,
            &TestTools,
        ));
        assert!(matches!(rejected, Err(SkillError::IdentityMismatch)));
    }

    #[test]
    fn display_rejects_unknown_skill_without_catalogue_entry() {
        let fence = fence();
        let handle = installed_catalogue();
        let (receipt, ack) = issued_display_inputs(&handle);
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::with_catalogue(inner, handle);
        let missing = blocking_view(forwarding.activation_display(
            &metadata(&fence),
            "skill-missing".to_owned(),
            receipt,
            ack,
            &TestTools,
        ));
        assert!(matches!(missing, Err(SkillError::NotFound)));
    }

    #[test]
    fn install_populates_the_shared_handle_for_the_promote_gate() {
        let (forwarding, _calls, handle) = installing_forwarder();
        let catalogue = handle.lock().expect("catalogue lock");
        let stored = catalogue.get("skill-demo").expect("installed entry");
        assert_eq!(stored.index.name, "demo skill");
        assert!(catalogue.is_usable("skill-demo"));
        drop(catalogue);
        drop(forwarding);
    }

    #[test]
    fn runtime_delivery_round_trip_installs_delivers_acks_and_displays() {
        let (forwarding, calls, _handle) = installing_forwarder();
        let receipt = forwarding
            .deliver_hotset(
                "hotset-runtime-1".to_owned(),
                vec!["skill-demo".to_owned()],
                "approval-commit-1".to_owned(),
                &InstallTools,
            )
            .expect("runtime delivery");
        assert!(receipt.confirms_delivery("skill-demo"));
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let display = forwarding
            .acknowledge_and_display("skill-demo", receipt.clone(), ack, &InstallTools)
            .expect("acked display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert!(
            display
                .render()
                .contains("when demo work arrives load this skill")
        );
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn acknowledge_rejects_unapplied_and_foreign_acks_before_display() {
        let (forwarding, calls, _handle) = installing_forwarder();
        let receipt = forwarding
            .deliver_hotset(
                "hotset-runtime-2".to_owned(),
                vec!["skill-demo".to_owned()],
                "approval-commit-1".to_owned(),
                &InstallTools,
            )
            .expect("runtime delivery");
        let rejected = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Rejected {
                reason: "receiver refused the bodies".to_owned(),
            },
        };
        assert!(matches!(
            forwarding.acknowledge_and_display(
                "skill-demo",
                receipt.clone(),
                rejected,
                &InstallTools
            ),
            Err(SkillError::IdentityMismatch)
        ));
        let foreign = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        assert!(matches!(
            forwarding.acknowledge_and_display("skill-demo", receipt, foreign, &InstallTools),
            Err(SkillError::IdentityMismatch)
        ));
        assert_eq!(*calls.lock().expect("calls"), 0);
    }

    #[test]
    fn delivery_requires_a_blank_rejected_approval_handle() {
        let (forwarding, _calls, _handle) = installing_forwarder();
        let refused = forwarding.deliver_hotset(
            "hotset-runtime-3".to_owned(),
            vec!["skill-demo".to_owned()],
            "   ".to_owned(),
            &InstallTools,
        );
        assert!(matches!(
            refused,
            Err(SkillError::InvalidField { field, .. }) if field == "delivery.approval_ref"
        ));
    }

    #[test]
    fn forwarding_preserves_typed_rejection_without_invention() {
        let fence = fence();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: true,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let rejected = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()));
        assert!(matches!(rejected, Err(SkillError::FenceMismatch)));
        assert_eq!(*calls.lock().expect("calls"), 1);
    }

    struct TestTools;

    impl KnownTools for TestTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn dependency(version: &str) -> DependencyVersion {
        DependencyVersion {
            name: "tool-def-1".to_owned(),
            version: version.to_owned(),
            contract_digest: "c".repeat(64),
        }
    }

    fn catalogue_entry() -> SkillCatalogueEntry {
        let mut body = SkillBody {
            skill_id: "skill-demo".to_owned(),
            body_version: "1.0.0".to_owned(),
            body_digest: String::new(),
            actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            stop_escalation: "Stop and escalate on conflicting instructions.".to_owned(),
            tool_refs: vec!["eliot.finish".to_owned()],
        };
        body.body_digest = body.expected_digest().expect("body digest");
        SkillCatalogueEntry {
            index: SkillIndexEntry {
                skill_id: "skill-demo".to_owned(),
                name: "demo skill".to_owned(),
                trigger: "when demo work arrives load this skill".to_owned(),
                eligible_routes: vec!["route-1".to_owned()],
                eligible_profiles: vec!["profile-1".to_owned()],
            },
            body,
            runtime: SkillRuntimeMetadata {
                skill_id: "skill-demo".to_owned(),
                body_version: "1.0.0".to_owned(),
                references: vec!["references/playbook.md".to_owned()],
                scripts: Vec::new(),
                assets: Vec::new(),
                index_budget_tokens: 200,
                body_budget_tokens: 800,
                runtime_budget_tokens: 2000,
                index_tokens: 60,
                body_tokens: 400,
                runtime_tokens: 0,
            },
            dependencies: vec![dependency("1.2.0")],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            status: SkillStatus::Provisional,
            stale_reason: None,
        }
    }

    fn installed_catalogue() -> CatalogueHandle {
        let mut catalogue = SkillCatalogue::default();
        catalogue
            .insert(catalogue_entry(), &TestTools)
            .expect("install entry");
        Arc::new(Mutex::new(catalogue))
    }

    struct InstallTools;

    impl KnownTools for InstallTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish" || name == "finish-cap"
        }
    }

    fn package_behavior() -> eliot_skill::SkillBehavior {
        eliot_skill::SkillBehavior {
            intent: "refresh the task view before a Material effect".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            action: "Refresh the task view before a Material effect.".to_owned(),
            applies_when: vec!["the task view is stale".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            required_outputs: vec!["refreshed view".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            stop: "Stop and escalate on conflicting instructions.".to_owned(),
            escalation: "escalate to the task owner".to_owned(),
            challenge: "show exact conflicting identities".to_owned(),
        }
    }

    fn package_inputs() -> eliot_skill::MaterializationInputs {
        eliot_skill::MaterializationInputs {
            canonical_source_bytes: b"canonical demo source\n".to_vec(),
            contract_materialization: package_behavior(),
            dependencies: vec![eliot_skill::DependencyMaterial {
                name: "tool-def-1".to_owned(),
                version: "1.2.0".to_owned(),
                contract_digest: "c".repeat(64),
            }],
            tool_definitions: vec![eliot_skill::ToolDefinitionMaterial {
                name: "eliot.finish".to_owned(),
                version: "1.0.0".to_owned(),
                description: "typed finish attempt".to_owned(),
                capabilities: vec![eliot_skill::CapabilityVersion {
                    name: "finish-cap".to_owned(),
                    version: "1".to_owned(),
                }],
                actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            }],
        }
    }

    fn package_source() -> (
        eliot_skill::SkillPackage,
        eliot_skill::MaterializationInputs,
    ) {
        let inputs = package_inputs();
        let rule: eliot_skill::AdvisoryRuleClaim = serde_json::from_value(serde_json::json!({
            "rule_ref": { "rule_id": "rule-demo-1", "revision": 1 }
        }))
        .expect("rule fixture");
        let package = eliot_skill::SkillPackage {
            registration: eliot_skill::RegistrationIdentity::new(
                "skill-demo",
                "1.0.0",
                "demo skill",
            )
            .expect("valid test registration"),
            digests: eliot_skill::PackageDigests::derive(&inputs).expect("valid test inputs"),
            host: eliot_skill::HostProfile {
                host: "codex".to_owned(),
                profile: "default".to_owned(),
                required_tools: vec![eliot_skill::VersionedRequirement {
                    name: "eliot.finish".to_owned(),
                    version: "1.0.0".to_owned(),
                }],
                required_capabilities: vec![eliot_skill::VersionedRequirement {
                    name: "finish-cap".to_owned(),
                    version: "1".to_owned(),
                }],
                limits: eliot_skill::HostLimits {
                    max_description_chars: 500,
                    max_actions: 1,
                    max_expansion_handles: 2,
                },
            },
            behavior: package_behavior(),
            counters: eliot_skill::SkillCounters::default(),
            state: eliot_skill::SkillState {
                freshness: eliot_skill::FreshnessState::Current,
                conflict: eliot_skill::ConflictState::None,
                distractor: eliot_skill::DistractorState::None,
                quarantine: eliot_skill::QuarantineState::Clear,
            },
            lifecycle_proposal: eliot_skill::LifecycleProposal::Keep,
            delivery: eliot_skill::DeliveryProjection::default(),
            interaction: eliot_skill::SkillInteractionProjection::default(),
            rule,
        };
        package
            .validate(&inputs)
            .expect("fixture package validates");
        (package, inputs)
    }

    fn install_context() -> eliot_skill::CatalogueInstallContext {
        eliot_skill::CatalogueInstallContext {
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            index_budget_tokens: 200,
            body_budget_tokens: 800,
            runtime_budget_tokens: 2000,
            index_tokens: 60,
            body_tokens: 400,
            runtime_tokens: 0,
            references: vec!["references/playbook.md".to_owned()],
            scripts: Vec::new(),
            assets: Vec::new(),
        }
    }

    fn installing_forwarder() -> (
        ForwardingSkillLifecycle<ClosedInner>,
        Arc<Mutex<u64>>,
        CatalogueHandle,
    ) {
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: false,
            succeed_promote: false,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let (package, inputs) = package_source();
        let installed =
            forwarding.install_package(&package, &inputs, &install_context(), &InstallTools);
        assert_eq!(installed.expect("package install"), "skill-demo");
        let handle = forwarding.catalogue.clone();
        (forwarding, calls, handle)
    }

    fn base_view(fence: &StateFence) -> SkillLifecycleView {
        SkillLifecycleView {
            skill_ref: SkillRef::new("skill-demo", "rev-1", "Demo Skill", "a".repeat(64))
                .expect("skill ref"),
            scope: SkillScope {
                task_scope: "task-scope".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "gov-1".to_owned(),
            },
            applies_when: vec!["when-a".to_owned()],
            does_not_apply_when: vec!["not-when-a".to_owned()],
            dependencies: Vec::new(),
            counters: LifecycleCounters::default(),
            execution_evidence: Vec::new(),
            observed_decision_or_verifier_delta: None,
            false_activation_refs: Vec::new(),
            interactions: SkillInteractionView::default(),
            status: SkillStatus::Current,
            stale_or_quarantine_reason: None,
            proposed_action: LifecycleAction::Keep,
            review: None,
            state_fence: fence.clone(),
            lifecycle_revision: 1,
        }
    }

    fn candidate_with_deps(
        fence: &StateFence,
        dependencies: Vec<DependencyVersion>,
    ) -> SkillCandidate {
        SkillCandidate::new(
            &base_view(fence),
            "b".repeat(64),
            LifecycleAction::Patch,
            vec!["evidence-1".to_owned()],
            dependencies,
            SkillScope {
                task_scope: "task-scope".to_owned(),
                host: "host-1".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "gov-1".to_owned(),
            },
            fence.clone(),
        )
        .expect("candidate")
    }

    fn gate_for(fence: &StateFence, candidate: &SkillCandidate) -> PromotionGate {
        PromotionGate {
            candidate_digest: candidate.candidate_digest.clone(),
            base_view_digest: candidate.base_view_digest.clone(),
            verifier_ref: "verifier-1".to_owned(),
            evidence_refs: vec!["evidence-1".to_owned()],
            independent_route_count: 1,
            human_approval_ref: None,
            reversible: true,
            state_fence: fence.clone(),
        }
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        RequestIdentity {
            request: RequestBinding {
                metadata: metadata(fence),
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-skill-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-skill-1".to_owned(),
        }
    }
}
