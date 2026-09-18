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
use eliot_skill::{SkillCandidate, SkillError, SkillLifecycleApi, SkillLifecycleView};

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
        LifecycleAction, LifecycleCounters, SkillInteractionView, SkillLifecycleView, SkillRef,
        SkillScope, SkillStatus,
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
    struct ComputingInner {
        base: SkillLifecycleView,
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
        let mut forwarder = GovernorSkillForwarder::new(ComputingInner { base: base.clone() });
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
}
