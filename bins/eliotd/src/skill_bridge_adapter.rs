//! Agent-bridge Skill port forwarding adapter (issue #1882).
//!
//! [`BridgeSkillForwarder`] implements the thin agent-bridge
//! [`SkillLifecyclePort`](eliot_agent_bridge_core::SkillLifecyclePort) over
//! the single Governor skill owner behind the shared composition catalogue.
//! Reads and proposals forward through the [`SkillLifecycleApi`]; receiver-ack
//! display runs through the drift-gated composition path with the tool source
//! resolved live from the Governor hook on every display call — never a cached
//! source object. It adds no validation, retry, or state of its own; every
//! typed success or fail-closed error comes from the Governor and Skill
//! owners.
//!
//! In-process binding only: the forwarder borrows the composition-held
//! adapter, so it is valid exactly where the bridge core runs in the same
//! process as the composition (in-process embedding, tests). A remote bridge
//! process MUST NOT hold this forwarder: cross-process Skill traffic crosses
//! the authenticated EBP/IPC transport as messages (bridge/protocol owners),
//! and a borrowed local forwarder fabricated into remote authority would
//! invent a cross-process owner that does not exist.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use eliot_agent_bridge_core::{ProposeSkillRequest, SkillLifecyclePort};
use eliot_contracts::RequestMetadata;
use eliot_skill::{
    ActivatedSkillDisplay, HotsetDeliveryAck, HotsetDeliveryReceipt, SkillCandidate, SkillError,
    SkillLifecycleApi, SkillLifecycleView,
};

use super::skill_lifecycle_adapters::ForwardingSkillLifecycle;

/// Forwards one agent-bridge [`SkillLifecyclePort`] to the single Governor
/// skill owner.
///
/// The wrapper owns the composition-held forwarding adapter (in production
/// the [`ForwardingSkillLifecycle`] over the borrowed
/// [`GovernorSkillLifecycle`](eliot_governor::GovernorSkillLifecycle)) and
/// forwards each call. Reads and proposals travel unchanged; display resolves
/// the live canonical tool source plus admitted version through the Governor
/// hook per call, so the display-time drift gate always reads live tool-owner
/// state. It adds no validation, retry, or state of its own.
pub(crate) struct BridgeSkillForwarder<U> {
    adapter: ForwardingSkillLifecycle<U>,
}

impl<U> BridgeSkillForwarder<U> {
    /// Wraps the composition-held forwarding adapter.
    pub(crate) fn new(adapter: ForwardingSkillLifecycle<U>) -> Self {
        Self { adapter }
    }
}

impl<U: SkillLifecycleApi> SkillLifecyclePort for BridgeSkillForwarder<U> {
    fn skill_read<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        skill_id: String,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SkillLifecycleView>, SkillError>> + 'a>> {
        Box::pin(async move { self.adapter.view(ctx, skill_id).await })
    }

    fn propose_skill<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        request: ProposeSkillRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SkillCandidate, SkillError>> + 'a>> {
        Box::pin(async move {
            self.adapter
                .propose(
                    ctx,
                    request.skill_id().to_owned(),
                    request.candidate_package_digest().to_owned(),
                    request.action(),
                    request.evidence_refs().to_vec(),
                    request.dependency_versions().to_vec(),
                    request.scope().clone(),
                )
                .await
        })
    }

    fn display_skill<'a>(
        &'a mut self,
        _ctx: &'a RequestMetadata,
        skill_id: String,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
    ) -> Pin<Box<dyn Future<Output = Result<ActivatedSkillDisplay, SkillError>> + 'a>> {
        Box::pin(async move {
            let (source, admitted) = eliot_governor::canonical_skill_tool_source()?;
            let aliases = eliot_skill::ToolAliasTable::new();
            let display = self.adapter.acknowledge_and_display_versioned(
                &skill_id,
                receipt,
                ack,
                source.as_ref(),
                &aliases,
                &admitted,
            )?;
            Ok(display)
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_skill::{
        DependencyVersion, HotsetAckDisposition, KnownTools, LifecycleAction, PromotionGate,
        SkillBody, SkillCatalogue, SkillCatalogueEntry, SkillIndexEntry, SkillRuntimeMetadata,
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

    /// Minimal Governor-owner double: the forwarder only needs the
    /// [`SkillLifecycleApi`] contract for reads/proposals; delivery runs on
    /// the shared catalogue handle, never through this inner owner.
    struct ClosedInner;

    impl SkillLifecycleApi for ClosedInner {
        async fn view(
            &self,
            _ctx: &RequestMetadata,
            _skill_id: String,
        ) -> Result<Option<SkillLifecycleView>, SkillError> {
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
            Err(SkillError::NotFound)
        }

        async fn promote(
            &self,
            _identity: &RequestIdentity,
            _operation_id: OperationId,
            _candidate: SkillCandidate,
            _gate: PromotionGate,
            _promoted_view: SkillLifecycleView,
        ) -> Result<eliot_store_api::WriteReceipt, SkillError> {
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
            Err(SkillError::NotFound)
        }
    }

    struct InstallTools;

    impl KnownTools for InstallTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn installed_handle() -> Arc<Mutex<SkillCatalogue>> {
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
        let entry = SkillCatalogueEntry {
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
            dependencies: vec![DependencyVersion {
                name: "tool-def-1".to_owned(),
                version: "1.2.0".to_owned(),
                contract_digest: "c".repeat(64),
            }],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            status: SkillStatus::Provisional,
            stale_reason: None,
        };
        let mut catalogue = SkillCatalogue::default();
        catalogue
            .insert(entry, &InstallTools)
            .expect("install entry");
        Arc::new(Mutex::new(catalogue))
    }

    fn metadata(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("req-bridge-1").expect("request"),
            session_id: Some(SessionId::new("session-bridge-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("test product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
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
    fn bridge_display_drives_bound_receipt_ack_through_the_live_hook() {
        // The bridge forwarder resolves the REAL canonical tool source per
        // display call (no test double on the tool side): the installed
        // "eliot.finish" reference is known to the live registry at the
        // hook-pinned version, so the bound receipt displays provisional.
        let handle = installed_handle();
        let adapter = ForwardingSkillLifecycle::with_catalogue(ClosedInner, Arc::clone(&handle));
        let receipt = {
            let catalogue = handle.lock().expect("catalogue lock");
            HotsetDeliveryReceipt::issue(
                "hotset-bridge-1".to_owned(),
                &catalogue,
                vec!["skill-demo".to_owned()],
                &InstallTools,
                "approval-commit-1".to_owned(),
            )
            .expect("bridge delivery")
        };
        let ack = HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: HotsetAckDisposition::Applied,
        };
        let mut forwarder = BridgeSkillForwarder::new(adapter);
        let display = block_on(forwarder.display_skill(
            &metadata(&fence()),
            "skill-demo".to_owned(),
            receipt.clone(),
            ack,
        ))
        .expect("bridge display");
        assert_eq!(display.skill_id, "skill-demo");
        assert_eq!(display.delivery_receipt_digest, receipt.receipt_digest);
        assert_eq!(display.status, SkillStatus::Provisional);
    }

    #[test]
    fn bridge_read_proposes_nothing_and_reports_inner_truth() {
        // Reads and proposals forward the inner owner's typed answers
        // unchanged: no view exists behind the closed inner owner.
        let handle = installed_handle();
        let mut forwarder = BridgeSkillForwarder::new(ForwardingSkillLifecycle::with_catalogue(
            ClosedInner,
            handle,
        ));
        let view = block_on(forwarder.skill_read(&metadata(&fence()), "skill-demo".to_owned()))
            .expect("forwarded view");
        assert!(view.is_none());
    }
}
