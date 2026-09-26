//! Private Governor-backed Skill surface port forwarder.
//!
//! [`GovernorSkillForwarder`] translates between the provider-neutral
//! [`SkillLifecyclePort`](eliot_controlboard::SkillLifecyclePort) surface
//! contract and one [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi)
//! owner. It forwards the exact admitted identity and typed fields and
//! returns only typed results:
//!
//! - No policy, admission, or semantic rules live here. Base digest/revision,
//!   exact evidence, fence, and typed validation stay with the Governor skill
//!   owner; this forwarder never invents a candidate, view, or digest.
//! - `skill_read` forwards to
//!   [`GovernorSkillLifecycle::view`](eliot_governor::GovernorSkillLifecycle)
//!   and `propose_skill` forwards to
//!   [`GovernorSkillLifecycle::propose`](eliot_governor::GovernorSkillLifecycle)
//!   through the [`DaemonComposition::skill_lifecycle`](super::DaemonComposition::skill_lifecycle)
//!   accessor (`skill_lifecycle` -> `ForwardingSkillLifecycle` -> Governor
//!   owner). A stale fence fails closed in the Governor owner, never as a
//!   local default.
//! - `skill_activation_display` forwards receipt, ack, and the caller-supplied
//!   tool view to the inner lifecycle API, which executes the catalogue
//!   boundary at the composition adapter. Port implementations without
//!   installed catalogue bodies keep the trait's fail-closed default; only
//!   this forwarder overrides it.
//! - The boxed-future shape mirrors the surface trait: it keeps the
//!   implementation object-safe without an async-trait dependency and imposes
//!   no `Send` bound the Governor borrows cannot guarantee.
//!
//! The forwarder performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical path. Callers take a fresh forwarder per
//! operation through
//! [`DaemonComposition::skill_controlboard_port`](super::DaemonComposition::skill_controlboard_port)
//! so a Governor refresh surfaces as an exact-view mismatch instead of silent
//! divergence.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use eliot_contracts::RequestMetadata;
use eliot_controlboard::{ProposeSkillRequest, SkillLifecyclePort};
use eliot_skill::{
    ActivatedSkillDisplay, HotsetDeliveryAck, HotsetDeliveryReceipt, KnownTools, SkillCandidate,
    SkillError, SkillLifecycleApi, SkillLifecycleView,
};

/// Forwards one [`SkillLifecyclePort`] to the single Governor skill owner.
///
/// The wrapper owns the inner lifecycle API (in production the
/// [`ForwardingSkillLifecycle`](super::skill_lifecycle_adapters::ForwardingSkillLifecycle)
/// over the borrowed [`GovernorSkillLifecycle`](eliot_governor::GovernorSkillLifecycle))
/// and forwards each call unchanged. It adds no validation, retry, or state
/// of its own; every typed success or fail-closed error comes from the
/// Governor owner.
pub(crate) struct GovernorSkillForwarder<T> {
    inner: T,
}

impl<T> GovernorSkillForwarder<T> {
    /// Wraps the single Governor lifecycle owner for forwarding.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: SkillLifecycleApi> SkillLifecyclePort for GovernorSkillForwarder<T> {
    fn skill_read<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        skill_id: String,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SkillLifecycleView>, SkillError>> + 'a>> {
        Box::pin(async move { self.inner.view(ctx, skill_id).await })
    }

    fn propose_skill<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        request: ProposeSkillRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SkillCandidate, SkillError>> + 'a>> {
        Box::pin(async move {
            self.inner
                .propose(
                    ctx,
                    request.skill_id,
                    request.candidate_package_digest,
                    request.action,
                    request.evidence_refs,
                    request.dependency_versions,
                    request.scope,
                )
                .await
        })
    }

    fn skill_activation_display<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        skill_id: String,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
        tools: &'a dyn KnownTools,
    ) -> Pin<Box<dyn Future<Output = Result<ActivatedSkillDisplay, SkillError>> + 'a>> {
        Box::pin(async move {
            self.inner
                .activation_display(ctx, skill_id, receipt, ack, tools)
                .await
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::task::{Context, Poll};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SessionId,
        SourceId, StateFence,
    };
    use eliot_skill::{
        DependencyVersion, HotsetAckDisposition, HotsetDeliveryAck, HotsetDeliveryReceipt,
        KnownTools, LifecycleAction, LifecycleCounters, SkillBody, SkillCatalogue,
        SkillCatalogueEntry, SkillIndexEntry, SkillInteractionView, SkillLifecycleView, SkillRef,
        SkillRuntimeMetadata, SkillScope, SkillStatus,
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

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn metadata(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-skill-surface-1").expect("request"),
            session_id: Some(SessionId::new("session-skill-surface-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn scope() -> SkillScope {
        SkillScope {
            task_scope: "task-scope".to_owned(),
            host: "host-1".to_owned(),
            route: "route-1".to_owned(),
            governance_scope: "gov-1".to_owned(),
        }
    }

    fn base_view(fence: &StateFence) -> SkillLifecycleView {
        SkillLifecycleView {
            skill_ref: SkillRef::new("skill-demo", "rev-1", "Demo Skill", "a".repeat(64))
                .expect("skill ref"),
            scope: scope(),
            applies_when: vec!["when-a".to_owned()],
            does_not_apply_when: vec!["not-when-a".to_owned()],
            dependencies: Vec::new(),
            counters: LifecycleCounters::default(),
            execution_evidence: Vec::new(),
            attempt_receipts: Vec::new(),
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

    /// Test owner that computes real candidates from the received fields, so
    /// the test proves exact field forwarding instead of replaying bytes.
    /// Display executes against a real installed catalogue for the same
    /// reason: the port-level test observes the catalogue boundary, not a
    /// canned display.
    struct ComputingInner {
        base: SkillLifecycleView,
        catalogue: SkillCatalogue,
    }

    struct ForwardTools;

    impl KnownTools for ForwardTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn installed_catalogue() -> SkillCatalogue {
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
        let index = SkillIndexEntry {
            skill_id: "skill-demo".to_owned(),
            name: "demo skill".to_owned(),
            trigger: "when demo work arrives load this skill".to_owned(),
            eligible_routes: vec!["route-1".to_owned()],
            eligible_profiles: vec!["profile-1".to_owned()],
            eligible_policies: vec!["policy-1".to_owned()],
        };
        let runtime = SkillRuntimeMetadata {
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
        };
        let dependencies = vec![DependencyVersion {
            name: "tool-def-1".to_owned(),
            version: "1.2.0".to_owned(),
            contract_digest: "c".repeat(64),
        }];
        let host_version = "host-4.1.0".to_owned();
        let profile_version = "profile-2.0.0".to_owned();
        let admitted_definition_version = "1.2.0".to_owned();
        let validation = eliot_skill::StructuralValidationReport::record(
            &index,
            &body,
            &runtime,
            &dependencies,
            &host_version,
            &profile_version,
            &admitted_definition_version,
        )
        .expect("validation report");
        let entry = SkillCatalogueEntry {
            index,
            body,
            runtime,
            dependencies,
            host_version,
            profile_version,
            admitted_definition_version,
            status: SkillStatus::Provisional,
            stale_reason: None,
            scope: scope(),
            validation,
            promotion_evidence: None,
        };
        SkillCatalogue::from_snapshot([entry], &ForwardTools).expect("installed catalogue")
    }

    impl SkillLifecycleApi for ComputingInner {
        async fn view(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
        ) -> Result<Option<SkillLifecycleView>, SkillError> {
            Ok(Some(self.base.clone()))
        }

        async fn propose(
            &self,
            ctx: &RequestMetadata,
            _skill_id: String,
            candidate_package_digest: String,
            action: LifecycleAction,
            evidence_refs: Vec<String>,
            dependencies: Vec<eliot_skill::DependencyVersion>,
            scope: SkillScope,
        ) -> Result<SkillCandidate, SkillError> {
            SkillCandidate::new(
                &self.base,
                candidate_package_digest,
                action,
                evidence_refs,
                dependencies,
                scope,
                ctx.state_fence.clone(),
            )
        }

        async fn promote(
            &self,
            _identity: &eliot_protocol::RequestIdentity,
            _operation_id: eliot_contracts::OperationId,
            _candidate: SkillCandidate,
            _gate: eliot_skill::PromotionGate,
            _promoted_view: SkillLifecycleView,
        ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
            Err(SkillError::NotFound)
        }

        async fn activation_display(
            &self,
            _ctx: &RequestMetadata,
            skill_id: String,
            receipt: HotsetDeliveryReceipt,
            ack: HotsetDeliveryAck,
            tools: &dyn KnownTools,
        ) -> Result<ActivatedSkillDisplay, SkillError> {
            self.catalogue
                .activation_display(&skill_id, &receipt, &ack, tools)
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn forwarder_passes_exact_fields_to_the_governor_owner() {
        let fence = fence();
        let base = base_view(&fence);
        let mut forwarder = GovernorSkillForwarder::new(ComputingInner {
            base: base.clone(),
            catalogue: installed_catalogue(),
        });
        let view = block_on(forwarder.skill_read(&metadata(&fence), "skill-demo".to_owned()))
            .expect("forwarded view");
        assert_eq!(view, Some(base.clone()));
        let proposal = ProposeSkillRequest::new(
            "skill-demo",
            "b".repeat(64),
            LifecycleAction::Patch,
            vec!["evidence-1".to_owned()],
            Vec::new(),
            scope(),
        )
        .expect("proposal");
        let candidate =
            block_on(forwarder.propose_skill(&metadata(&fence), proposal)).expect("candidate");
        let expected = SkillCandidate::new(
            &base,
            "b".repeat(64),
            LifecycleAction::Patch,
            vec!["evidence-1".to_owned()],
            Vec::new(),
            scope(),
            fence,
        )
        .expect("expected candidate");
        assert_eq!(candidate, expected);
        assert_eq!(candidate.candidate_digest, expected.candidate_digest);
    }

    #[test]
    fn forwarder_delegates_display_receipt_and_ack_to_the_owner() {
        let fence = fence();
        let base = base_view(&fence);
        let catalogue = installed_catalogue();
        let receipt = HotsetDeliveryReceipt::issue(
            "hotset-fwd-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &ForwardTools,
            "approval-commit-1".to_owned(),
        )
        .expect("delivery receipt");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let mut forwarder = GovernorSkillForwarder::new(ComputingInner { base, catalogue });
        let display = block_on(forwarder.skill_activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt.clone(),
            ack,
            &ForwardTools,
        ))
        .expect("forwarded display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
    }

    /// Port implementation without installed catalogue bodies keeps the
    /// trait's fail-closed default display instead of inventing one.
    struct DefaultPort;

    impl SkillLifecyclePort for DefaultPort {
        fn skill_read<'a>(
            &'a mut self,
            _ctx: &'a RequestMetadata,
            _skill_id: String,
        ) -> Pin<Box<dyn Future<Output = Result<Option<SkillLifecycleView>, SkillError>> + 'a>>
        {
            Box::pin(async move { Err(SkillError::NotFound) })
        }

        fn propose_skill<'a>(
            &'a mut self,
            _ctx: &'a RequestMetadata,
            _request: ProposeSkillRequest,
        ) -> Pin<Box<dyn Future<Output = Result<SkillCandidate, SkillError>> + 'a>> {
            Box::pin(async move { Err(SkillError::NotFound) })
        }
    }

    #[test]
    fn port_default_display_fails_closed_without_catalogue_bodies() {
        let fence = fence();
        let catalogue = installed_catalogue();
        let receipt = HotsetDeliveryReceipt::issue(
            "hotset-fwd-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &ForwardTools,
            "approval-commit-1".to_owned(),
        )
        .expect("delivery receipt");
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let mut port = DefaultPort;
        let refused = block_on(port.skill_activation_display(
            &metadata(&fence),
            "skill-demo".to_owned(),
            receipt,
            ack,
            &ForwardTools,
        ));
        assert!(matches!(refused, Err(SkillError::Surface(_))));
    }
}
