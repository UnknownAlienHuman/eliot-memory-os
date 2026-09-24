//! W3/A1/A3/A8 registry-backed child launch (issue #1126).
//!
//! Resolves one admitted route class through the #874 `AdapterRegistry`
//! surface and the #22 generation permit, then delegates to the existing
//! [`dispatch_child`](super::durable_dispatch::dispatch_child) path. It feeds
//! the existing `DurableWorkStore`/`WorkExecutor` persist-before-launch path
//! only by returning the dispatch the caller persists and launches: this cell
//! is candidate-only and performs no store append, no executor call, no
//! `Finish`, and no authority/canonical write.
//!
//! Design notes (code over prose where they disagree):
//!
//! - `dispatch_child` takes `(attachment, item, work_id, grant, route_class,
//!   lease, term, epoch)` — it does not take `store`/`executor`. The store and
//!   executor owners are accepted here only to pin the feeding seam: the
//!   caller feeds the returned intent through the existing owner-side
//!   persist-before-launch path (`DurableWorkStore` append, then
//!   `WorkExecutor` launch). This helper never calls either owner.
//! - There is no single generation-permit type this cell can name. The only
//!   generation-permit authority is Kernel P-03 `DispatchPermit`
//!   (`crates/kernel/eliot-process/src/dispatch_permit.rs`): opaque,
//!   secret-key-authenticated, one-shot, non-`Clone`, with no public field
//!   constructor, consumed at the executor boundary by the Kernel-owned
//!   `DispatchPermitAuthority`. This crate (`eliot-swarm`) does not depend on
//!   the Kernel process crates and cannot mint, verify, or transport that
//!   permit, so generation travels here as an opaque `u64` plus opaque
//!   fingerprint bytes, sourced from the #694 catalogue [`RouteGrant`]
//!   (`generation`) and the #22 Kernel generation registry. Permit issuance
//!   and verification stay Kernel-owned; they are never constructed here.
//! - The #874 `AdapterRegistry` (`crates/eliot-engine/src/adapter/…`) is
//!   likewise outside this crate's dependency closure, so the registry lookup
//!   result is projected into [`RegistryRouteAdjudication`] by the caller that
//!   owns the registry. This module constructs no provider clients, no SDK
//!   handles, no credentials, and no shell paths.
//! - A replaced backing adapter under the same logical attempt identity is a
//!   fail-closed replay question, answered only through the existing
//!   [`verify_exact_replay`](super::durable_dispatch::verify_exact_replay):
//!   same identity with a changed payload is `PayloadConflict`; a different
//!   identity is `ForeignIdentity` (not a replay: the candidate proceeds);
//!   only an exact-digest replay is idempotent. Without a prior dispatch to
//!   prove exact replay, entry/grant drift is `RouteBlocked`.
//! - I09-09: every launch passes the admission gate; a revoked or stale route
//!   blocks with no local fallback. I10-15: no silent mid-attempt failover —
//!   a replaced route never relaunches silently under an old identity.

use eliot_agent_api::WorkLeaseId;
use eliot_agent_contracts::{RevisionId, WorkItem, WorkItemId};

use super::{
    SwarmError,
    durable_dispatch::{
        DispatchedLaunch, DurableJobAttachment, ReplayVerdict, dispatch_child, verify_exact_replay,
    },
    durable_work::{DurableWorkStore, RouteGrant, WorkExecutor, WorkUnitId},
    validate_text,
};

/// Registry verdict for one route class, projected from the #874
/// `AdapterRegistry` surface by the caller that owns the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRouteDecision {
    /// The route class is currently admitted.
    Admitted,
    /// The route class was revoked; launch is blocked with no fallback.
    Revoked,
    /// The route class entry is stale; launch is blocked with no fallback.
    Stale,
}

/// One registry lookup outcome for the requested route class.
///
/// The caller resolves the admitted route class through the #874
/// `AdapterRegistry` and projects the verdict here; this module never touches
/// the registry itself and constructs no adapter or provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryRouteAdjudication<'a> {
    /// Whether the route class is currently admitted.
    pub decision: RegistryRouteDecision,
    /// Admitted route class the registry resolved.
    pub route_class: &'a str,
    /// Current adapter-entry digest for the admitted route class.
    pub adapter_entry_digest: [u8; 32],
    /// Current generation admitted for the route class.
    pub generation: u64,
    /// Opaque generation fingerprint bound to `generation` by the #22
    /// generation-permit owner.
    pub generation_fingerprint: [u8; 32],
}

/// Registry-backed launch request: dispatch lineage plus the admitted route
/// class, adapter-entry digest, and opaque generation permit material.
///
/// `generation`/`generation_fingerprint` are the opaque projection of the #22
/// generation permit (see the module docs for why the Kernel `DispatchPermit`
/// itself cannot travel here). `grant` is the #694 catalogue grant the
/// dispatch envelope is sealed against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryLaunchRequest<'a> {
    /// Durable-job handle the child must derive from.
    pub job_id: &'a str,
    /// Admitted plan revision the child must derive from.
    pub plan_revision: &'a RevisionId,
    /// Child slot to dispatch.
    pub slot: &'a WorkItemId,
    /// Durable work-unit identity for the launch intent.
    pub work_id: &'a WorkUnitId,
    /// Catalogue route grant sealing the dispatch envelope.
    pub grant: &'a RouteGrant,
    /// Work lease bound into the launch intent.
    pub lease: &'a WorkLeaseId,
    /// Lease term bound into the launch intent.
    pub term: u64,
    /// Authority epoch bound into the launch intent.
    pub epoch: u64,
    /// Requested route class; must equal the registry-admitted class.
    pub route_class: &'a str,
    /// Adapter-entry digest the request was sealed against.
    pub adapter_entry_digest: [u8; 32],
    /// Generation the request was sealed against.
    pub generation: u64,
    /// Opaque generation fingerprint the request was sealed against.
    pub generation_fingerprint: [u8; 32],
}

/// One admitted child launch: the existing dispatch plus the post-launch
/// receipt material. The adapter entry digest and generation travel outside
/// [`DispatchedLaunch`] so `durable_dispatch.rs` stays unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedChildLaunch {
    /// Dispatch built by the existing `dispatch_child` path.
    pub launch: DispatchedLaunch,
    /// Registry adapter-entry digest pinned to this launch.
    pub adapter_digest: [u8; 32],
    /// Generation pinned to this launch.
    pub generation: u64,
}

/// Lowercase hex of a 32-byte digest, compared against the lineage route
/// fingerprint carried by the #694 catalogue grant.
fn hex_digest(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Resolves one admitted route class through the registry adjudication and
/// the generation permit, then delegates to the existing `dispatch_child`
/// path.
///
/// `store` and `executor` pin the feeding seam only: this candidate-only
/// helper performs no store append and no executor call (a fake owner that
/// panics on either call proves it). The caller feeds
/// `AdmittedChildLaunch.launch.intent` through the existing owner-side
/// persist-before-launch path (`DurableWorkStore` append, then
/// `WorkExecutor` launch).
///
/// Fail-closed order: a revoked or stale registry decision is
/// [`SwarmError::RouteBlocked`] with no fallback and no direct provider
/// construction; any request/adjudication/grant disagreement on route class,
/// generation, generation fingerprint, or adapter-entry digest is
/// `RouteBlocked`; request lineage that disagrees with the attachment or item
/// is `StaleLineage`; the remaining dispatch rules are `dispatch_child`'s
/// own. When the registry entry digest differs from the lineage route
/// fingerprint the backing adapter was replaced: with a prior dispatch the
/// exact-replay verdict decides (`PayloadConflict` propagates, `Idempotent`
/// re-observes, `ForeignIdentity` is not a replay and proceeds); without a
/// prior dispatch the drift is `RouteBlocked` rather than a silent relaunch.
pub fn launch_admitted_child(
    _store: &dyn DurableWorkStore,
    _executor: &dyn WorkExecutor,
    attachment: &DurableJobAttachment,
    item: &WorkItem,
    request: &RegistryLaunchRequest<'_>,
    registry: &RegistryRouteAdjudication<'_>,
    prior: Option<&DispatchedLaunch>,
) -> Result<AdmittedChildLaunch, SwarmError> {
    if registry.decision != RegistryRouteDecision::Admitted {
        return Err(SwarmError::RouteBlocked);
    }
    validate_text(registry.route_class, "route_class")?;
    if registry.route_class != request.route_class {
        return Err(SwarmError::RouteBlocked);
    }
    if registry.generation != request.generation
        || registry.generation_fingerprint != request.generation_fingerprint
    {
        return Err(SwarmError::RouteBlocked);
    }
    if request.grant.generation != request.generation {
        return Err(SwarmError::RouteBlocked);
    }
    if registry.adapter_entry_digest != request.adapter_entry_digest {
        return Err(SwarmError::RouteBlocked);
    }
    if request.job_id != attachment.job_handle()
        || request.plan_revision != attachment.plan_revision()
        || request.slot != &item.work_item_id
    {
        return Err(SwarmError::StaleLineage);
    }
    let launch = dispatch_child(
        attachment,
        item,
        request.work_id,
        request.grant,
        registry.route_class,
        request.lease.clone(),
        request.term,
        request.epoch,
    )?;
    if hex_digest(&registry.adapter_entry_digest) != launch.lineage.route_fingerprint {
        match prior {
            None => return Err(SwarmError::RouteBlocked),
            Some(prior) => match verify_exact_replay(prior, &launch.intent)? {
                ReplayVerdict::Idempotent | ReplayVerdict::ForeignIdentity => {}
            },
        }
    }
    Ok(AdmittedChildLaunch {
        launch,
        adapter_digest: registry.adapter_entry_digest,
        generation: registry.generation,
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use eliot_agent_contracts::WorkItemState;
    use eliot_coordination::SwarmPlanAttachmentLedger;
    use serde_json::{Value, json};

    use super::super::{
        AdmittedSwarmPlan, AgentRouteProvider, BranchId, IndependentMapSubmission, LaneId,
        ProviderAttestation, ProviderBinding, ProviderError, ProviderOutcome, ReceiptEnvelope,
        RevisionId, RootContextRevision, SealedIndependentMaps, SwarmError, SwarmPlanProposal,
        WorkItemId, admit_plan, collect_independent_maps, digest,
        durable_dispatch::{DurableJobAttachment, attach_plan_job},
        durable_work::{
            CancelOutcome, ChildHandle, DurableWorkRecord, DurableWorkStore, LaunchIntent,
            LaunchOutcome, ObserveOutcome, RouteGrant, StoreReceipt, WorkExecutor, WorkUnitId,
        },
        plan_admission_request,
    };
    use super::*;
    use eliot_agent_contracts::AgentAttemptId;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Candidate-only proof: any store touch fails the test.
    struct TestStore;

    impl DurableWorkStore for TestStore {
        fn append(&self, _record: &DurableWorkRecord) -> Result<StoreReceipt, ProviderError> {
            panic!("adapter_launch must not append to the durable store")
        }

        fn load(&self, _work_id: &WorkUnitId) -> Result<Vec<DurableWorkRecord>, ProviderError> {
            panic!("adapter_launch must not read the durable store")
        }
    }

    /// Candidate-only proof: any executor touch fails the test.
    struct TestExecutor;

    impl WorkExecutor for TestExecutor {
        fn launch(&self, _intent: &LaunchIntent) -> Result<LaunchOutcome, ProviderError> {
            panic!("adapter_launch must not call the executor")
        }

        fn observe(&self, _child: &ChildHandle) -> Result<ObserveOutcome, ProviderError> {
            panic!("adapter_launch must not call the executor")
        }

        fn observe_attempt(
            &self,
            _attempt_id: &AgentAttemptId,
        ) -> Result<ObserveOutcome, ProviderError> {
            panic!("adapter_launch must not call the executor")
        }

        fn cancel(&self, _child: &ChildHandle) -> Result<CancelOutcome, ProviderError> {
            panic!("adapter_launch must not call the executor")
        }
    }

    fn fence() -> Value {
        json!({
            "authority_epoch": epoch(),
            "resource_generation": 1,
            "task_revision": 1,
            "policy_revision": null,
            "integration_revision": null
        })
    }

    fn epoch() -> Value {
        json!({"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1})
    }

    fn lease() -> Result<WorkLeaseId, serde_json::Error> {
        serde_json::from_value(json!({
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-launch-1"
        }))
    }

    fn binding_for(task_id: &str) -> Result<ProviderBinding, Box<dyn Error>> {
        let scope: eliot_receipts::WorkScopeBinding = serde_json::from_value(json!({
            "scope_id": "scope-1",
            "product_id": "product-1",
            "resource_generation": 1,
            "state_fence": fence()
        }))?;
        Ok(ProviderBinding {
            task_id: task_id.to_owned(),
            session_id: "session-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            work_scope_digest: digest(&scope)?,
            state_fence_digest: digest(&scope.state_fence)?,
            authority_fence_digest: digest(&scope.state_fence)?,
            root_context_revision: RootContextRevision::new("root-1")?,
            task_revision: "1".to_owned(),
            plan_revision: RevisionId::new("plan-1")?,
            receipt_contract_revision: eliot_receipts::contract_identity()?.version.to_string(),
            work_contract_revision: "contract-1".to_owned(),
            work_item_id: WorkItemId::new("item-1")?,
            role_id: super::super::RoleId::new("role-1")?,
            route_id: "route-1".to_owned(),
            lease_id: lease()?,
            reviewer_attempt_id: None,
            affected_branch: None,
        })
    }

    fn receipt_for(
        owner: &str,
        request: &super::super::ProviderRequest,
        attestation: Option<&ProviderAttestation>,
    ) -> Result<ReceiptEnvelope, ProviderError> {
        let contract = eliot_receipts::contract_identity().map_err(|_| ProviderError::Failed)?;
        let request_binding_digest = digest(request).map_err(|_| ProviderError::Invalid)?;
        let task_revision = request
            .binding
            .task_revision
            .parse::<u64>()
            .map_err(|_| ProviderError::Invalid)?;
        let mut artifacts = vec![json!({
            "artifact_id": format!("artifact-{}", request.artifact_digest),
            "sha256": request.artifact_digest,
            "role": "ARTIFACT",
            "source_revision": request_binding_digest
        })];
        let mut artifact_ids = vec![format!("artifact-{}", request.artifact_digest)];
        if let Some(attestation) = attestation {
            let attestation_digest = digest(attestation).map_err(|_| ProviderError::Invalid)?;
            artifact_ids.push(format!("attestation-{attestation_digest}"));
            artifacts.push(json!({
                "artifact_id": format!("attestation-{attestation_digest}"),
                "sha256": attestation_digest,
                "role": "ARTIFACT",
                "source_revision": request_binding_digest
            }));
        }
        let value = json!({
            "contract": contract,
            "kind": "VERIFICATION",
            "work_scope": {
                "scope_id": request.binding.work_scope_id,
                "product_id": "product-1",
                "resource_generation": 1,
                "state_fence": fence()
            },
            "task": {
                "task_id": request.binding.task_id,
                "task_revision": task_revision,
                "state_fence": fence()
            },
            "session": {
                "session_id": request.binding.session_id,
                "authority_epoch": epoch(),
                "state_fence": fence()
            },
            "causal": {
                "state_fence": fence(),
                "transaction_sequence": 1,
                "parent_receipt_id": null,
                "predecessor_receipt_ids": []
            },
            "request": {
                "metadata": {
                    "request_id": format!("request-{}", request.artifact_digest),
                    "session_id": request.binding.session_id,
                    "task_id": request.binding.task_id,
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": fence(),
                    "clock": {
                        "valid_time_ms": 10,
                        "known_time_ms": 11,
                        "transaction_sequence": 1,
                        "monotonic_ns": 12
                    }
                },
                "state_fence": fence()
            },
            "operation": {
                "operation_id": format!("operation-{}", request.artifact_digest),
                "request_id": format!("request-{}", request.artifact_digest),
                "idempotency_key": format!("idem-{}", request.artifact_digest),
                "operation_kind": request.operation_kind,
                "effect": "READ",
                "state_fence": fence()
            },
            "authority": {
                "authority_id": format!("authority-{owner}"),
                "authority_owner": owner,
                "authority_epoch": epoch(),
                "state_fence": fence(),
                "allowed_effect": "READ",
                "proof_ceiling": "SCOPED_VERIFICATION"
            },
            "artifacts": artifacts,
            "verifier": {
                "verifier_id": "verifier-1",
                "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
                "artifact_ids": artifact_ids,
                "proof_ceiling": "SCOPED_VERIFICATION",
                "state_fence": fence()
            },
            "problem": null,
            "coordination": null,
            "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
        });
        let core: eliot_receipts::ReceiptCore =
            serde_json::from_value(value).map_err(|_| ProviderError::Invalid)?;
        ReceiptEnvelope::issue(core).map_err(|_| ProviderError::Invalid)
    }

    struct Trusted;

    impl super::super::ReceiptVerificationPort for Trusted {
        fn verify(&self, _receipt: &ReceiptEnvelope) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct A02;

    impl AgentRouteProvider for A02 {
        fn current_cursor(&self, _stream_id: &str) -> Result<u64, ProviderError> {
            Ok(0)
        }

        fn seal(
            &self,
            request: &super::super::ProviderRequest,
        ) -> Result<ProviderOutcome, ProviderError> {
            if request.operation_kind.as_str() != "swarm.map.seal" {
                return Err(ProviderError::Invalid);
            }
            let evidence: eliot_evidence::EvidenceEnvelope = serde_json::from_value(json!({
                "authority": "DETERMINISTIC_RUNTIME_TEST",
                "freshness": "EXACT_CANDIDATE",
                "coverage": "COMPLETE_FOR_SCOPE",
                "status": "SUPPORTED",
                "assertability": "ASSERTABLE",
                "provenance": {
                    "source_id": "source-1",
                    "capture_route": "route-1",
                    "scope": "scope-1",
                    "raw_handle": "raw-1",
                    "revision": "rev-1"
                },
                "verification": null,
                "state_fence": fence()
            }))
            .map_err(|_| ProviderError::Invalid)?;
            let assurance: eliot_security_contracts::SourceAssurance =
                serde_json::from_value(json!({
                    "source_ref": "source-1",
                    "provenance_ref": "provenance-1",
                    "integrity": "VERIFIED",
                    "freshness": "CURRENT",
                    "competence": "DOMAIN_VERIFIED",
                    "independence": "INDEPENDENT",
                    "privacy_class": "INTERNAL",
                    "instruction_taint": "CLEARED",
                    "allowed_epistemic_use": ["CANDIDATE_EVIDENCE"],
                    "allowed_effects": ["NO_EXTERNAL_EFFECT"],
                    "required_verifier": "verifier-1",
                    "quarantine": "NONE",
                    "state_fence": fence()
                }))
                .map_err(|_| ProviderError::Invalid)?;
            let attestation = ProviderAttestation::Independent {
                source_assurance: Box::new(assurance),
                evidence: Box::new(evidence),
                sealed_before_peer_disclosure: true,
                all_disclosures_predate_candidate: true,
                no_sibling_finding_disclosed: true,
            };
            let receipt = receipt_for("A-02", request, Some(&attestation))?;
            Ok(ProviderOutcome {
                receipt,
                attestation,
                committed_cursor: None,
            })
        }
    }

    fn admitted_plan() -> Result<AdmittedSwarmPlan, Box<dyn Error>> {
        use std::collections::BTreeMap;

        let lane = LaneId::new("item-1")?;
        let submission = IndependentMapSubmission {
            lane_id: lane.clone(),
            root_context_revision: RootContextRevision::new("root-1")?,
            dependency_sketch: Vec::new(),
            unknowns: vec!["unknown".to_owned()],
            candidate_subquestions: vec!["bounded subquestion".to_owned()],
            likely_overlaps: Vec::new(),
            provider_binding: binding_for("task-1")?,
        };
        let provider = A02;
        let verifier = Trusted;
        let maps: SealedIndependentMaps = collect_independent_maps(
            vec![lane],
            vec![submission],
            Some(&provider),
            Some(&verifier),
        )?;
        let proposal = SwarmPlanProposal {
            plan_revision: RevisionId::new("plan-1")?,
            root_context_revision: RootContextRevision::new("root-1")?,
            work_items: vec![eliot_agent_contracts::WorkItem {
                work_item_id: WorkItemId::new("item-1")?,
                responsibility: "investigate item-1".to_owned(),
                plan_revision: RevisionId::new("plan-1")?,
                wave_revision: RevisionId::new("wave-1")?,
                dependency_ids: Vec::new(),
                overlap_ids: Vec::new(),
                assigned_attempt_id: None,
                assigned_role: None,
                mailbox_route_handle: None,
                state: WorkItemState::Planned,
            }],
            branch_roots: BTreeMap::from([(BranchId::new("item-1")?, WorkItemId::new("item-1")?)]),
            global_wip: 1,
            per_route_wip: 1,
            reduction_fan_in: 1,
            preserved_partition_dissent: Vec::new(),
        };
        let request = plan_admission_request(&proposal, &maps)?;
        let receipt = receipt_for("Governor", &request, None)?;
        Ok(admit_plan(proposal, &maps, receipt, Some(&verifier))?)
    }

    fn attached(
        plan: &AdmittedSwarmPlan,
        owner: &SwarmPlanAttachmentLedger,
        job_handle: &str,
    ) -> Result<DurableJobAttachment, Box<dyn Error>> {
        let binding = plan.provider_binding();
        let request = super::super::ProviderRequest {
            operation_kind: crate::durable_dispatch::JOB_ATTACH_OPERATION.to_owned(),
            artifact_digest: digest(&(
                job_handle,
                binding.plan_revision.as_str(),
                binding.state_fence_digest.as_str(),
            ))?,
            binding: binding.clone(),
            replay: None,
        };
        let receipt = receipt_for(crate::durable_dispatch::JOB_OWNER, &request, None)?;
        Ok(attach_plan_job(
            plan,
            owner,
            job_handle,
            receipt,
            Some(&Trusted),
        )?)
    }

    fn grant_for(fingerprint: &str, stale: bool) -> RouteGrant {
        RouteGrant {
            route_id: "route-1".to_owned(),
            fingerprint: fingerprint.to_owned(),
            evidence_digest: "evidence-1".to_owned(),
            generation: 7,
            stale,
        }
    }

    fn digest_bytes(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn hex_of(seed: u8) -> String {
        hex_digest(&digest_bytes(seed))
    }

    #[test]
    fn revoked_route_blocks_without_fallback() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let item = plan
            .work_items()
            .iter()
            .find(|item| item.work_item_id.as_str() == "item-1")
            .ok_or("missing work item")?
            .clone();
        let work_id = WorkUnitId::new("unit-1")?;
        let lease_value = lease()?;
        let grant = grant_for(&hex_of(3), false);
        let entry = digest_bytes(3);
        let request = RegistryLaunchRequest {
            job_id: attachment.job_handle(),
            plan_revision: attachment.plan_revision(),
            slot: &item.work_item_id,
            work_id: &work_id,
            grant: &grant,
            lease: &lease_value,
            term: 3,
            epoch: 5,
            route_class: "provider-class",
            adapter_entry_digest: entry,
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        let store = TestStore;
        let executor = TestExecutor;
        for decision in [RegistryRouteDecision::Revoked, RegistryRouteDecision::Stale] {
            let registry = RegistryRouteAdjudication {
                decision,
                route_class: "provider-class",
                adapter_entry_digest: entry,
                generation: 7,
                generation_fingerprint: digest_bytes(9),
            };
            assert_eq!(
                launch_admitted_child(
                    &store, &executor, &attachment, &item, &request, &registry, None,
                ),
                Err(SwarmError::RouteBlocked)
            );
        }
        // A stale catalogue grant is equally blocked: dispatch_child's own
        // stale-grant gate fires before any launch material exists.
        let stale_grant = grant_for(&hex_of(3), true);
        let stale_request = RegistryLaunchRequest {
            grant: &stale_grant,
            ..request.clone()
        };
        let registry = RegistryRouteAdjudication {
            decision: RegistryRouteDecision::Admitted,
            route_class: "provider-class",
            adapter_entry_digest: entry,
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        assert_eq!(
            launch_admitted_child(
                &store, &executor, &attachment, &item, &stale_request, &registry, None,
            ),
            Err(SwarmError::RouteBlocked)
        );
        Ok(())
    }

    #[test]
    fn admitted_route_delegates_to_dispatch_child() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let item = plan
            .work_items()
            .iter()
            .find(|item| item.work_item_id.as_str() == "item-1")
            .ok_or("missing work item")?
            .clone();
        let work_id = WorkUnitId::new("unit-1")?;
        let lease_value = lease()?;
        let grant = grant_for(&hex_of(3), false);
        let entry = digest_bytes(3);
        let request = RegistryLaunchRequest {
            job_id: attachment.job_handle(),
            plan_revision: attachment.plan_revision(),
            slot: &item.work_item_id,
            work_id: &work_id,
            grant: &grant,
            lease: &lease_value,
            term: 3,
            epoch: 5,
            route_class: "provider-class",
            adapter_entry_digest: entry,
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        let registry = RegistryRouteAdjudication {
            decision: RegistryRouteDecision::Admitted,
            route_class: "provider-class",
            adapter_entry_digest: entry,
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        let admitted = launch_admitted_child(
            &TestStore,
            &TestExecutor,
            &attachment,
            &item,
            &request,
            &registry,
            None,
        )?;
        // Delegation proof: byte-identical to the existing dispatch path.
        let direct = dispatch_child(
            &attachment,
            &item,
            &work_id,
            &grant,
            "provider-class",
            lease_value.clone(),
            3,
            5,
        )?;
        assert_eq!(admitted.launch, direct);
        assert_eq!(admitted.launch.lineage.route_class, "provider-class");
        assert_eq!(admitted.launch.lineage.route_generation, 7);
        assert_eq!(admitted.adapter_digest, entry);
        assert_eq!(admitted.generation, 7);
        Ok(())
    }

    #[test]
    fn digest_drift_on_same_identity_conflicts() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let item = plan
            .work_items()
            .iter()
            .find(|item| item.work_item_id.as_str() == "item-1")
            .ok_or("missing work item")?
            .clone();
        let work_id = WorkUnitId::new("unit-1")?;
        let lease_value = lease()?;
        // Prior dispatch sealed against the old backing adapter: same logical
        // attempt identity (job/plan/slot), different payload.
        let old_grant = grant_for(&hex_of(5), false);
        let prior = dispatch_child(
            &attachment,
            &item,
            &work_id,
            &old_grant,
            "provider-class",
            lease_value.clone(),
            3,
            5,
        )?;
        // Registry replaced the entry (digest 3) while the catalogue grant
        // still pins the old fingerprint: drift fires the replay gate.
        let grant = grant_for(&hex_of(4), false);
        let request = RegistryLaunchRequest {
            job_id: attachment.job_handle(),
            plan_revision: attachment.plan_revision(),
            slot: &item.work_item_id,
            work_id: &work_id,
            grant: &grant,
            lease: &lease_value,
            term: 3,
            epoch: 5,
            route_class: "provider-class",
            adapter_entry_digest: digest_bytes(3),
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        let registry = RegistryRouteAdjudication {
            decision: RegistryRouteDecision::Admitted,
            route_class: "provider-class",
            adapter_entry_digest: digest_bytes(3),
            generation: 7,
            generation_fingerprint: digest_bytes(9),
        };
        // Same identity, changed payload: never a silent relaunch.
        assert_eq!(
            launch_admitted_child(
                &TestStore,
                &TestExecutor,
                &attachment,
                &item,
                &request,
                &registry,
                Some(&prior),
            ),
            Err(SwarmError::PayloadConflict)
        );
        // A prior for a different slot is a foreign identity, not a replay:
        // the candidate proceeds with its own lineage.
        let other_item = eliot_agent_contracts::WorkItem {
            work_item_id: WorkItemId::new("item-9")?,
            responsibility: "investigate item-9".to_owned(),
            plan_revision: RevisionId::new("plan-1")?,
            wave_revision: RevisionId::new("wave-1")?,
            dependency_ids: Vec::new(),
            overlap_ids: Vec::new(),
            assigned_attempt_id: None,
            assigned_role: None,
            mailbox_route_handle: None,
            state: WorkItemState::Planned,
        };
        let foreign_prior = dispatch_child(
            &attachment,
            &other_item,
            &work_id,
            &old_grant,
            "provider-class",
            lease_value.clone(),
            3,
            5,
        )?;
        let admitted = launch_admitted_child(
            &TestStore,
            &TestExecutor,
            &attachment,
            &item,
            &request,
            &registry,
            Some(&foreign_prior),
        )?;
        assert_eq!(admitted.launch.lineage.child_slot.as_str(), "item-1");
        assert_eq!(admitted.adapter_digest, digest_bytes(3));
        Ok(())
    }
}
