//! Private Governor-backed Skill lifecycle port adapters.
//!
//! The forwarding adapter translates between the provider-neutral
//! [`SkillLifecycleApi`](eliot_skill::SkillLifecycleApi) and one Governor
//! [`GovernorSkillLifecycle`](eliot_governor::GovernorSkillLifecycle) borrowed
//! from the single [`DaemonComposition`](super::DaemonComposition) by its
//! `skill_lifecycle` accessor. It forwards authenticated input and translates
//! typed results only:
//!
//! - No policy, admission, or semantic rules live here. Base digest/revision,
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
//! already-admitted canonical commit. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]

use eliot_skill::{PromotionGate, SkillCandidate, SkillError, SkillLifecycleApi, SkillLifecycleView};

/// Forwards one [`SkillLifecycleApi`] to the single Governor owner.
///
/// The wrapper owns the inner Governor adapter (which itself borrows the
/// single Governor owner triple) and forwards each call unchanged. It adds no
/// validation, retry, or state of its own; every typed success or fail-closed
/// error comes from the Governor owner.
pub(crate) struct ForwardingSkillLifecycle<T> {
    inner: T,
}

impl<T> ForwardingSkillLifecycle<T> {
    /// Wraps the single Governor lifecycle owner for forwarding.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
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
        self.inner
            .promote(identity, operation_id, candidate, gate, promoted_view)
            .await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        AuthorityEpoch, ClockReading, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_skill::{DependencyVersion, LifecycleAction, SkillScope};

    struct ClosedInner {
        fence_mismatch: bool,
        calls: Arc<Mutex<u64>>,
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
            _operation_id: OperationId,
            _candidate: SkillCandidate,
            _gate: PromotionGate,
            _promoted_view: SkillLifecycleView,
        ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
            *self.calls.lock().expect("calls") += 1;
            Err(SkillError::NotFound)
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
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

    fn blocking_view(
        future: impl std::future::Future<Output = Result<Option<SkillLifecycleView>, SkillError>>,
    ) -> Result<Option<SkillLifecycleView>, SkillError> {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = std::task::Waker::from(std::sync::Arc::new(NoopWaker));
        let mut context = std::task::Context::from_waker(&waker);
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
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let view = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()))
            .expect("forwarded view");
        assert!(view.is_none());
        assert_eq!(*calls.lock().expect("calls"), 1);
    }

    #[test]
    fn forwarding_preserves_typed_rejection_without_invention() {
        let fence = fence();
        let calls = Arc::new(Mutex::new(0));
        let inner = ClosedInner {
            fence_mismatch: true,
            calls: Arc::clone(&calls),
        };
        let forwarding = ForwardingSkillLifecycle::new(inner);
        let rejected = blocking_view(forwarding.view(&metadata(&fence), "skill-demo".to_owned()));
        assert!(matches!(rejected, Err(SkillError::FenceMismatch)));
        assert_eq!(*calls.lock().expect("calls"), 1);
    }
}
