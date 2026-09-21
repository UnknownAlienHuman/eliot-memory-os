//! Settled-plan to [`BridgeRunner`] admission transport (I7.19 admit step).
//!
//! This module is the transport complement to the Smart producer
//! ([`plan_bridge_admissions`](eliot_reactive_context_plan::plan_bridge_admissions)):
//! it carries one settled [`PendingContextInjectionPlan`](eliot_reactive_context_plan::PendingContextInjectionPlan)
//! (or one already-produced [`BridgeAdmissionBatch`]) into live
//! [`BridgeRunner::admit_reactive_injection`] calls, in the exact join order:
//!
//! ```text
//! produce batch → session-equality gate → Governor assessment per item →
//! invalidations first → admit each item in order (replay-deduped,
//! withholds never admitted)
//! ```
//!
//! Authority boundaries (the transport invents nothing):
//!
//! ```text
//! plan owns:    item selection, cue binding, firing reference, relations,
//!               scope/status/governance strings, fence, severity, delivery,
//!               dedup keys, skip accounting.
//! bridge owns:  session binding (live attach), ledger mutation, receipts,
//!               stickiness, normal dedup, representation checks.
//! governor owns (supplied by the caller, never defaulted here): per-item
//!               risk assessment over the same critical bit, with the
//!               attested fence echo; withholds on missing evidence.
//! ```
//!
//! The risk assessor is a caller-supplied function because no plan source
//! carries Governor risk: the transport never defaults, infers, or carries
//! it. Session text from the batch is never authority either: the batch
//! session must equal the bridge's live attach session or nothing is called.
//! Afterwards the existing bridge machinery owns delivery (host-hook and
//! next-response drains issue [`InjectionReceipt`](super::InjectionReceipt)s).

use std::collections::VecDeque;

use eliot_agent_bridge_core::BridgeError;
use eliot_contracts::StateFence;
use eliot_reactive_context_plan::{
    BridgeAdmissionBatch, BridgeAdmissionError, BridgeAdmissionInstruction,
    BridgeAdmissionSeverity, PendingContextInjectionPlan, plan_bridge_admissions,
};

use super::{
    AdmissionBasis, BridgeRunner, CueKind, FiringEvidence, NormalizedCue,
    ReactiveInjectionError, RiskTier, Severity,
};

/// Bound on transport-side replay keys retained across batches.
///
/// Matches the bridge ledger item bound so the transport window can never
/// outgrow the ledger it protects; oldest keys rotate out first.
pub const MAX_TRANSPORT_REPLAY_KEYS: usize = 512;

/// One admitted plan item, in batch order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedPlanItem {
    /// Stable replay key (`<plan result digest>:<item id>`).
    pub dedup_key: String,
    /// Ledger identity minted by the bridge (`reactive-item-{seq}`).
    pub item_id: String,
}

/// What the transport needs from the risk owner for one item.
///
/// Transport-owned minimal vocabulary (bridge-lane): the assessed tier, and
/// the ATTESTED fence echo the assessment was evaluated under. The post-freeze
/// Governor adapter fills this from `ReactiveRiskAssessment` (`tier` rendered
/// 1:1, `fence_epoch_text()` / `fence_generation_value()`); the transport
/// never renders fences from raw plan text on the governed path, so an
/// assessment cannot be mixed across fence rotations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorAssessmentView {
    /// Governor-assessed tier for this item.
    pub risk: RiskTier,
    /// Attested fence-epoch spelling (`<lineage-uuid>:<sequence>`).
    pub fence_epoch: String,
    /// Attested fence generation (non-zero).
    pub fence_generation: u64,
}

/// One item withheld for missing Governor evidence.
///
/// Withhold is an honest outcome, not a failure: the item is never admitted,
/// never defaulted, and its reason travels with the report so the owner can
/// buffer bounded owner-side or drop WITH a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithheldPlanItem {
    /// Stable replay key (`<plan result digest>:<item id>`).
    pub dedup_key: String,
    /// Owner-readable withhold reason (Governor evidence gap).
    pub reason: String,
}

/// Outcome of driving one batch into the live bridge ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAdmissionReport {
    /// Live attach session every item was admitted under.
    pub session_id: String,
    /// Delivered items reopened for re-admission by invalidation-first ordering.
    pub invalidations_applied: usize,
    /// Items admitted by the bridge, in batch order.
    pub admitted: Vec<AdmittedPlanItem>,
    /// Items suppressed by the transport replay window before any bridge call.
    pub replay_suppressed: u64,
    /// Normal items the bridge refused as already-delivered duplicates.
    pub duplicate_suppressed: u64,
    /// Items withheld for missing Governor evidence, in batch order.
    pub withheld: Vec<WithheldPlanItem>,
    /// Producer skip counts, passed through so no drop is silent.
    pub skipped_sticky: u64,
    /// Producer skip counts, passed through so no drop is silent.
    pub skipped_ineligible: u64,
}

/// Fail-closed transport errors. No bridge call happens after the error point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanAdmissionError {
    /// A sourceless, over-bound, or otherwise malformed planned item aborted
    /// the batch: a plan defect, surfaced, never downgraded.
    Producer(BridgeAdmissionError),
    /// No live attach: the owner buffers (bounded, owner-side) or drops with
    /// a receipt — never re-mints a session.
    NotAttached,
    /// Batch session differs from the live attach session: buffered or
    /// dropped owner-side, never passed as authority.
    SessionMismatch {
        /// Session text carried by the batch.
        plan_session: String,
        /// Session bound to the live attach.
        live_session: String,
    },
    /// The bridge rejected one item for a reason other than duplicate
    /// suppression (a defect, since the producer pre-validates): earlier
    /// items in the batch stay admitted; nothing after is called.
    BridgeRejected {
        /// Replay key of the rejected item.
        dedup_key: String,
        /// Bridge-side reason text.
        reason: String,
        /// Ledger identities admitted before the rejection, in order.
        admitted: Vec<String>,
    },
}

impl std::fmt::Display for PlanAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Producer(error) => write!(formatter, "plan producer defect: {error}"),
            Self::NotAttached => write!(formatter, "bridge is not attached"),
            Self::SessionMismatch {
                plan_session,
                live_session,
            } => write!(
                formatter,
                "plan session {plan_session} does not equal live attach session {live_session}"
            ),
            Self::BridgeRejected {
                dedup_key, reason, ..
            } => write!(
                formatter,
                "bridge rejected plan item {dedup_key}: {reason}"
            ),
        }
    }
}

impl std::error::Error for PlanAdmissionError {}

/// Renders one native fence into the bridge admission text pair.
///
/// The epoch carries the full lineage-aware identity
/// (`<lineage-uuid>:<sequence>` — never a bare scalar, so equal sequences
/// from different lineages stay unrelated) and the generation carries the
/// native resource-generation value (non-zero by construction). The bridge
/// records both as bounded text without semantic interpretation.
#[must_use]
pub fn render_admission_fence(fence: &StateFence) -> (String, u64) {
    let epoch = format!(
        "{}:{}",
        fence.authority_epoch.lineage_id.as_str(),
        fence.authority_epoch.sequence
    );
    (epoch, fence.resource_generation.value())
}

/// Whether a bridge rejection is the expected normal-item duplicate
/// suppression (already delivered in this session, not invalidated).
///
/// Compared against the canonical [`ReactiveInjectionError`] rendering, not a
/// copied string, so the classification tracks the ledger's own vocabulary.
fn is_duplicate_suppressed(error: &BridgeError) -> bool {
    matches!(error, BridgeError::ProviderContract(reason)
        if reason == &ReactiveInjectionError::DuplicateSuppressed.to_string())
}

/// Settled-plan admission driver with a bounded transport-side replay window.
///
/// One driver instance serves one runtime integrator: it remembers the replay
/// keys it already presented so a replanned or redelivered batch cannot
/// re-admit the same plan item. The window is bounded
/// ([`MAX_TRANSPORT_REPLAY_KEYS`]); oldest keys rotate out first. The bridge
/// ALSO deduplicates delivered normals — defense in depth, not reliance.
pub struct SettledPlanAdmission {
    seen: VecDeque<String>,
}

impl SettledPlanAdmission {
    /// Creates a driver with an empty replay window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: VecDeque::new(),
        }
    }

    /// Number of replay keys currently retained.
    #[must_use]
    pub fn replay_len(&self) -> usize {
        self.seen.len()
    }

    /// Whether a replay key is currently retained in the window.
    #[must_use]
    pub fn replay_contains(&self, dedup_key: &str) -> bool {
        self.seen.contains(&dedup_key.to_string())
    }

    /// Records one presented key, rotating the oldest out at the bound.
    fn note_presented(&mut self, dedup_key: &str) {
        if self.seen.len() >= MAX_TRANSPORT_REPLAY_KEYS {
            self.seen.pop_front();
        }
        self.seen.push_back(dedup_key.to_owned());
    }

    /// Drives one settled plan through production and admission.
    ///
    /// Produces the batch with
    /// [`plan_bridge_admissions`](eliot_reactive_context_plan::plan_bridge_admissions)
    /// (aborting the batch on producer error), then admits it with
    /// [`Self::admit_batch`]. `assess` is the Governor risk owner: one
    /// assessment per instruction over the SAME critical bit the transport
    /// derives from owner stickiness, never defaulted by the transport.
    /// Withheld items are skipped with their reason, never admitted.
    pub fn admit_settled_plan(
        &mut self,
        runner: &mut BridgeRunner,
        plan: &PendingContextInjectionPlan,
        assess: impl Fn(&BridgeAdmissionInstruction, bool) -> Result<GovernorAssessmentView, String>,
    ) -> Result<PlanAdmissionReport, PlanAdmissionError> {
        let batch = plan_bridge_admissions(plan).map_err(PlanAdmissionError::Producer)?;
        self.admit_batch(runner, &batch, assess)
    }

    /// Drives one already-produced batch into the live bridge ledger.
    ///
    /// In order: verifies the batch session equals the live attach session;
    /// applies invalidations first (invalidation-aware dedup); assesses each
    /// item in order with the Governor-supplied assessment over the same
    /// critical bit used for severity, collapsing transport-side replays of
    /// the same plan before calling. A withhold (`Err`) records the item
    /// with its reason and never admits it.
    pub fn admit_batch(
        &mut self,
        runner: &mut BridgeRunner,
        batch: &BridgeAdmissionBatch,
        assess: impl Fn(&BridgeAdmissionInstruction, bool) -> Result<GovernorAssessmentView, String>,
    ) -> Result<PlanAdmissionReport, PlanAdmissionError> {
        let live_session = runner
            .attach_view()
            .map(|view| view.binding().session_id().as_str().to_owned())
            .ok_or(PlanAdmissionError::NotAttached)?;
        if batch.session_id.as_str() != live_session {
            return Err(PlanAdmissionError::SessionMismatch {
                plan_session: batch.session_id.as_str().to_owned(),
                live_session: live_session.clone(),
            });
        }
        let mut invalidations_applied = 0;
        for source in &batch.invalidations {
            invalidations_applied += runner.invalidate_reactive_source(source);
        }
        let mut report = PlanAdmissionReport {
            session_id: live_session,
            invalidations_applied,
            admitted: Vec::with_capacity(batch.items.len()),
            replay_suppressed: 0,
            duplicate_suppressed: 0,
            withheld: Vec::new(),
            skipped_sticky: batch.skipped_sticky,
            skipped_ineligible: batch.skipped_ineligible,
        };
        for item in &batch.items {
            if self.replay_contains(&item.dedup_key) {
                report.replay_suppressed += 1;
                continue;
            }
            // The SAME owner-stickiness bit feeds assessment and severity:
            // the tier and the stickiness can never disagree about an item.
            let critical = item.severity == BridgeAdmissionSeverity::Critical;
            let view = match assess(item, critical) {
                Ok(view) => view,
                Err(reason) => {
                    report.withheld.push(WithheldPlanItem {
                        dedup_key: item.dedup_key.clone(),
                        reason,
                    });
                    continue;
                }
            };
            let admitted_severity = if critical {
                Severity::Critical
            } else {
                Severity::Normal
            };
            let outcome = runner.admit_reactive_injection(
                NormalizedCue {
                    cue_id: item.cue_id.clone(),
                    kind: CueKind::ToolObservation,
                    source: item.cue_source.clone(),
                    source_revision: item.cue_source_revision.clone(),
                    cue_digest: item.cue_digest.clone(),
                },
                Some(FiringEvidence {
                    rule_id: item.rule_id.clone(),
                    cue_id: item.cue_id.clone(),
                    cue_digest: item.cue_digest.clone(),
                }),
                item.relations.clone(),
                AdmissionBasis {
                    scope_id: item.scope_id.clone(),
                    status: item.status.clone(),
                    risk: view.risk,
                    governance_profile_rev: item.governance_profile_rev.clone(),
                    fence_epoch: view.fence_epoch,
                    fence_generation: view.fence_generation,
                    admitted_severity,
                },
            );
            match outcome {
                Ok(item_id) => {
                    self.note_presented(&item.dedup_key);
                    report.admitted.push(AdmittedPlanItem {
                        dedup_key: item.dedup_key.clone(),
                        item_id,
                    });
                }
                Err(error) if is_duplicate_suppressed(&error) => {
                    self.note_presented(&item.dedup_key);
                    report.duplicate_suppressed += 1;
                }
                Err(error) => {
                    return Err(PlanAdmissionError::BridgeRejected {
                        dedup_key: item.dedup_key.clone(),
                        reason: error.to_string(),
                        admitted: report
                            .admitted
                            .iter()
                            .map(|admitted| admitted.item_id.clone())
                            .collect(),
                    });
                }
            }
        }
        Ok(report)
    }
}

impl Default for SettledPlanAdmission {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use eliot_agent_bridge_core::{
        ActivationPortOutcome, ActivationPortResult, AttachRequest, DemandId, FencingToken,
        Generation, HostActivationPort, PrincipalId, ProviderFailure, ProviderReadiness,
        SessionId, TaskId, WorkUnitId,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_reactive_context_plan::{
        BridgeAdmissionDelivery, MAX_BRIDGE_RELATIONS,
    };
    use eliot_receipts::WorkScopeId;
    use std::num::NonZeroU64;

    use super::super::{ConnectionId, Profile};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_SESSION: &str = "session-transport-1";
    const TEST_DIGEST: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct StaticActivation {
        result: ActivationPortResult,
    }

    impl HostActivationPort for StaticActivation {
        fn activate(
            &mut self,
            _request: &AttachRequest,
        ) -> Result<ActivationPortOutcome, ProviderFailure> {
            Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
        }
    }

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(3),
            ResourceGeneration::new(7).expect("non-zero test generation"),
        )
    }

    fn attached_runner(session: &str) -> BridgeRunner {
        let generation = Generation::new(7).expect("non-zero test generation");
        let fence = FencingToken::new(test_epoch(3), generation, "fence-transport-7")
            .expect("valid test fence");
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-transport-1").expect("valid principal"),
            SessionId::new(session).expect("valid session"),
            generation,
            fence,
            TaskId::new("task-transport-1").expect("valid task"),
            WorkUnitId::new("work-unit-transport-1").expect("valid work unit"),
            "scope-transport-1",
            "task-revision-1",
            "plan-transport-1",
            "plan-revision-1",
        )
        .expect("valid activation result");
        let mut runner = BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticActivation { result })),
            None,
        )
        .expect("runner composes");
        runner
            .attach(AttachRequest::managed(
                DemandId::new("demand-transport-1").expect("valid demand"),
                ConnectionId::new("conn-transport-1").expect("valid connection"),
            ))
            .expect("managed attach admits");
        runner
    }

    fn detached_runner() -> BridgeRunner {
        let generation = Generation::new(7).expect("non-zero test generation");
        let fence = FencingToken::new(test_epoch(3), generation, "fence-transport-7")
            .expect("valid test fence");
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-transport-1").expect("valid principal"),
            SessionId::new(TEST_SESSION).expect("valid session"),
            generation,
            fence,
            TaskId::new("task-transport-1").expect("valid task"),
            WorkUnitId::new("work-unit-transport-1").expect("valid work unit"),
            "scope-transport-1",
            "task-revision-1",
            "plan-transport-1",
            "plan-revision-1",
        )
        .expect("valid activation result");
        BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticActivation { result })),
            None,
        )
        .expect("runner composes")
    }

    fn instruction(
        item_id: &str,
        source: &str,
        revision: &str,
        severity: BridgeAdmissionSeverity,
    ) -> BridgeAdmissionInstruction {
        BridgeAdmissionInstruction {
            cue_id: item_id.to_owned(),
            cue_source: source.to_owned(),
            cue_source_revision: revision.to_owned(),
            cue_digest: TEST_DIGEST.to_owned(),
            rule_id: "reactive-activation:plan-digest-1".to_owned(),
            relations: vec!["rel-a".to_owned()],
            scope_id: "scope-transport-1".to_owned(),
            status: "TOOL_ONLY_ADVISORY".to_owned(),
            governance_profile_rev: "policy-digest-1".to_owned(),
            fence: test_fence(),
            severity,
            delivery: BridgeAdmissionDelivery::NextBridgeResponse,
            dedup_key: format!("plan-digest-1:{item_id}"),
            plan_item_id: item_id.to_owned(),
            plan_result_digest: "plan-digest-1".to_owned(),
            item_reason: "fixture reason".to_owned(),
            attention: None,
        }
    }

    fn batch(session: &str, items: Vec<BridgeAdmissionInstruction>) -> BridgeAdmissionBatch {
        BridgeAdmissionBatch {
            session_id: eliot_contracts::SessionId::new(session).expect("valid session"),
            scope_id: WorkScopeId::new("scope-transport-1").expect("valid scope"),
            invalidations: Vec::new(),
            items,
            skipped_sticky: 1,
            skipped_ineligible: 2,
        }
    }

    /// Stand-in for the post-freeze Governor adapter: tiers by the SAME
    /// critical bit the transport passes in and echoes the item fence
    /// through the canonical rendering (mirroring the attested-echo
    /// contract, where the assessment echoes its input fence). Pins the
    /// transport contract — echo use, same-bit severity, withhold
    /// semantics — never Governor tier logic, which the Governor lane owns.
    fn stub_assess(
        item: &BridgeAdmissionInstruction,
        critical: bool,
        risk: RiskTier,
    ) -> Result<GovernorAssessmentView, String> {
        assert_eq!(
            critical,
            item.severity == BridgeAdmissionSeverity::Critical,
            "assessor must see the owner-stickiness bit"
        );
        let (fence_epoch, fence_generation) = render_admission_fence(&item.fence);
        Ok(GovernorAssessmentView {
            risk,
            fence_epoch,
            fence_generation,
        })
    }

    #[test]
    fn fence_rendering_carries_lineage_and_generation() {
        let (epoch, generation) = render_admission_fence(&test_fence());
        assert_eq!(epoch, format!("{TEST_LINEAGE}:3"));
        assert_eq!(generation, 7);
    }

    #[test]
    fn settled_items_admit_with_canonical_session_risk_status_fence() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let batch = batch(
            TEST_SESSION,
            vec![
                instruction(
                    "item-critical-1",
                    "tool-surface-1",
                    "rev-1",
                    BridgeAdmissionSeverity::Critical,
                ),
                instruction(
                    "item-normal-1",
                    "tool-surface-2",
                    "rev-1",
                    BridgeAdmissionSeverity::Normal,
                ),
            ],
        );
        // Governor risk owner assesses per item over the same critical bit:
        // no plan source, no default.
        let report = driver
            .admit_batch(&mut runner, &batch, |item, critical| {
                let risk = if critical {
                    RiskTier::Severe
                } else {
                    RiskTier::Low
                };
                stub_assess(item, critical, risk)
            })
            .expect("matching session admits");
        assert_eq!(report.session_id, TEST_SESSION);
        assert_eq!(report.invalidations_applied, 0);
        assert_eq!(report.admitted.len(), 2);
        assert_eq!(report.replay_suppressed, 0);
        assert_eq!(report.duplicate_suppressed, 0);
        assert!(report.withheld.is_empty());
        assert_eq!(report.skipped_sticky, 1);
        assert_eq!(report.skipped_ineligible, 2);
        assert_eq!(runner.reactive_pending_count(), 2);
        // Every admitted item carries the canonical session, risk, status,
        // and fence through the real bridge ledger into its receipt.
        let receipts = runner
            .deliver_reactive_pending_via_response("resp-transport-1")
            .expect("pending drains through the real response path");
        assert_eq!(receipts.len(), 2);
        for receipt in &receipts {
            assert_eq!(receipt.session_id, TEST_SESSION);
            assert_eq!(receipt.admission.status, "TOOL_ONLY_ADVISORY");
            assert_eq!(
                receipt.admission.governance_profile_rev,
                "policy-digest-1"
            );
            assert_eq!(
                receipt.admission.fence_epoch,
                format!("{TEST_LINEAGE}:3")
            );
            assert_eq!(receipt.admission.fence_generation, 7);
        }
        let risks: Vec<RiskTier> =
            receipts.iter().map(|receipt| receipt.admission.risk).collect();
        assert!(risks.contains(&RiskTier::Severe));
        assert!(risks.contains(&RiskTier::Low));
        let severities: Vec<Severity> = receipts
            .iter()
            .map(|receipt| receipt.admission.admitted_severity)
            .collect();
        assert!(severities.contains(&Severity::Critical));
        assert!(severities.contains(&Severity::Normal));
        // Critical items stay sticky in later attention output.
        let attention = runner.reactive_attention();
        assert!(
            attention
                .iter()
                .any(|item| item.severity == Severity::Critical),
            "critical admission must stay sticky until resolved"
        );
    }

    #[test]
    fn session_mismatch_calls_nothing() {
        use std::cell::Cell;

        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let batch = batch(
            "session-other-9",
            vec![instruction(
                "item-1",
                "tool-surface-1",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        let calls = Cell::new(0);
        let error = driver
            .admit_batch(&mut runner, &batch, |item, critical| {
                calls.set(calls.get() + 1);
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect_err("mismatched session must fail closed");
        assert!(
            matches!(error, PlanAdmissionError::SessionMismatch { .. }),
            "unexpected error {error:?}"
        );
        assert_eq!(calls.get(), 0, "session gate precedes any assessment");
        assert_eq!(runner.reactive_pending_count(), 0);
        assert_eq!(driver.replay_len(), 0);
    }

    #[test]
    fn detached_bridge_admits_nothing() {
        use std::cell::Cell;

        let mut runner = detached_runner();
        let mut driver = SettledPlanAdmission::new();
        let batch = batch(
            TEST_SESSION,
            vec![instruction(
                "item-1",
                "tool-surface-1",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        let calls = Cell::new(0);
        let error = driver
            .admit_batch(&mut runner, &batch, |item, critical| {
                calls.set(calls.get() + 1);
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect_err("detached bridge must fail closed");
        assert_eq!(error, PlanAdmissionError::NotAttached);
        assert_eq!(calls.get(), 0, "attach gate precedes any assessment");
    }

    #[test]
    fn invalidations_apply_before_items_and_reopen_dedup() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        // First delivery of a normal item arms the bridge session dedup.
        let first = batch(
            TEST_SESSION,
            vec![instruction(
                "item-normal-1",
                "tool-surface-9",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        driver
            .admit_batch(&mut runner, &first, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect("first admission");
        runner
            .deliver_reactive_pending_via_response("resp-transport-1")
            .expect("first delivery");
        // Same source/revision/risk without invalidation is bridge-duplicate.
        let replay_same_source = batch(
            TEST_SESSION,
            vec![instruction(
                "item-normal-2",
                "tool-surface-9",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        let suppressed = driver
            .admit_batch(&mut runner, &replay_same_source, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect("duplicate suppression is an honest outcome, not a failure");
        assert_eq!(suppressed.admitted.len(), 0);
        assert_eq!(suppressed.duplicate_suppressed, 1);
        // With the invalidation listed, the transport reopens dedup FIRST and
        // the same source admits again.
        let mut reopened = batch(
            TEST_SESSION,
            vec![instruction(
                "item-normal-3",
                "tool-surface-9",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        reopened.invalidations.push("tool-surface-9".to_owned());
        let report = driver
            .admit_batch(&mut runner, &reopened, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect("invalidation must reopen the source");
        assert_eq!(report.invalidations_applied, 1);
        assert_eq!(report.admitted.len(), 1);
        assert_eq!(report.duplicate_suppressed, 0);
    }

    #[test]
    fn same_plan_replay_collapses_before_bridge_calls() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let batch_value = batch(
            TEST_SESSION,
            vec![instruction(
                "item-1",
                "tool-surface-1",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        let first = driver
            .admit_batch(&mut runner, &batch_value, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect("first presentation admits");
        assert_eq!(first.admitted.len(), 1);
        assert_eq!(driver.replay_len(), 1);
        let second = driver
            .admit_batch(&mut runner, &batch_value, |item, critical| {
                stub_assess(item, critical, RiskTier::Elevated)
            })
            .expect("replay collapses without calling");
        assert_eq!(second.admitted.len(), 0);
        assert_eq!(second.replay_suppressed, 1);
        // No second ledger item: the replay never reached the bridge.
        assert_eq!(runner.reactive_pending_count(), 1);
    }

    #[test]
    fn withhold_never_admits_and_records_reason() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let batch_value = batch(
            TEST_SESSION,
            vec![
                instruction(
                    "item-withheld-1",
                    "tool-surface-1",
                    "rev-1",
                    BridgeAdmissionSeverity::Normal,
                ),
                instruction(
                    "item-admitted-1",
                    "tool-surface-2",
                    "rev-1",
                    BridgeAdmissionSeverity::Critical,
                ),
            ],
        );
        // Missing Governor evidence withholds the normal item; the critical
        // item under live evidence still admits in the same batch.
        let report = driver
            .admit_batch(&mut runner, &batch_value, |item, critical| {
                if item.cue_id == "item-withheld-1" {
                    Err("no current GovernanceProfile derived: risk cannot be assessed".to_owned())
                } else {
                    stub_assess(item, critical, RiskTier::Severe)
                }
            })
            .expect("withhold is an honest outcome, not a failure");
        assert_eq!(report.admitted.len(), 1);
        assert_eq!(
            report.admitted[0].dedup_key,
            "plan-digest-1:item-admitted-1"
        );
        assert_eq!(report.withheld.len(), 1);
        assert_eq!(
            report.withheld[0].dedup_key,
            "plan-digest-1:item-withheld-1"
        );
        assert!(
            report.withheld[0].reason.contains("GovernanceProfile"),
            "withhold reason must name the evidence gap"
        );
        assert_eq!(runner.reactive_pending_count(), 1);
        // A withheld key is NOT marked presented: once evidence arrives the
        // same item admits instead of collapsing as a replay.
        assert!(!driver.replay_contains("plan-digest-1:item-withheld-1"));
        let retry = batch(
            TEST_SESSION,
            vec![instruction(
                "item-withheld-1",
                "tool-surface-1",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        let second = driver
            .admit_batch(&mut runner, &retry, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect("evidence arrival admits the withheld item");
        assert_eq!(second.admitted.len(), 1);
        assert_eq!(second.replay_suppressed, 0);
        assert!(second.withheld.is_empty());
    }

    #[test]
    fn assessor_echo_fence_is_used_verbatim() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let batch_value = batch(
            TEST_SESSION,
            vec![instruction(
                "item-1",
                "tool-surface-1",
                "rev-1",
                BridgeAdmissionSeverity::Normal,
            )],
        );
        // The echo deliberately differs from the plan-fence rendering: the
        // receipt must carry the attested echo, never raw plan text.
        driver
            .admit_batch(&mut runner, &batch_value, |_, _| {
                Ok(GovernorAssessmentView {
                    risk: RiskTier::Elevated,
                    fence_epoch: "echo-lineage-9:9".to_owned(),
                    fence_generation: 9,
                })
            })
            .expect("echo assessment admits");
        let receipts = runner
            .deliver_reactive_pending_via_response("resp-echo-1")
            .expect("pending drains");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].admission.risk, RiskTier::Elevated);
        assert_eq!(receipts[0].admission.fence_epoch, "echo-lineage-9:9");
        assert_eq!(receipts[0].admission.fence_generation, 9);
    }

    #[test]
    fn replay_window_stays_bounded_across_sessions() {
        let mut first_runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        for index in 0..300 {
            let item = format!("fill-a-{index}");
            let made = batch(
                TEST_SESSION,
                vec![instruction(
                    &item,
                    &format!("source-a-{index}"),
                    "rev-1",
                    BridgeAdmissionSeverity::Critical,
                )],
            );
            driver
                .admit_batch(&mut first_runner, &made, |item, critical| {
                    stub_assess(item, critical, RiskTier::Low)
                })
                .expect("distinct critical items admit");
            // Drain through the real delivery path so the ledger pending
            // bound never interferes with the transport window proof.
            first_runner
                .deliver_reactive_pending_via_response(&format!("resp-a-{index}"))
                .expect("pending drains");
            // Drain through the real delivery path so the ledger pending
            // bound never interferes with the transport window proof.
            first_runner
                .deliver_reactive_pending_via_response(&format!("resp-a-{index}"))
                .expect("pending drains");
        }
        assert_eq!(driver.replay_len(), 300);
        // A fresh ledger on a second session keeps presenting: the window
        // rotates instead of growing without bound.
        let mut second_runner = attached_runner("session-transport-2");
        for index in 0..300 {
            let item = format!("fill-b-{index}");
            let made = batch(
                "session-transport-2",
                vec![instruction(
                    &item,
                    &format!("source-b-{index}"),
                    "rev-1",
                    BridgeAdmissionSeverity::Critical,
                )],
            );
            driver
                .admit_batch(&mut second_runner, &made, |item, critical| {
                    stub_assess(item, critical, RiskTier::Low)
                })
                .expect("distinct critical items admit");
            second_runner
                .deliver_reactive_pending_via_response(&format!("resp-b-{index}"))
                .expect("pending drains");
            second_runner
                .deliver_reactive_pending_via_response(&format!("resp-b-{index}"))
                .expect("pending drains");
        }
        assert_eq!(driver.replay_len(), MAX_TRANSPORT_REPLAY_KEYS);
        assert!(
            !driver.replay_contains("plan-digest-1:fill-a-0"),
            "oldest keys must rotate out at the bound"
        );
        assert!(
            driver.replay_contains("plan-digest-1:fill-b-299"),
            "newest keys must stay retained"
        );
    }

    #[test]
    fn bridge_rejection_aborts_with_partial_progress() {
        let mut runner = attached_runner(TEST_SESSION);
        let mut driver = SettledPlanAdmission::new();
        let mut over_bound = instruction(
            "item-over-1",
            "tool-surface-1",
            "rev-1",
            BridgeAdmissionSeverity::Normal,
        );
        over_bound.relations = (0..MAX_BRIDGE_RELATIONS + 1)
            .map(|index| format!("rel-{index}"))
            .collect();
        let made = batch(
            TEST_SESSION,
            vec![
                instruction(
                    "item-ok-1",
                    "tool-surface-1",
                    "rev-1",
                    BridgeAdmissionSeverity::Normal,
                ),
                over_bound,
            ],
        );
        let error = driver
            .admit_batch(&mut runner, &made, |item, critical| {
                stub_assess(item, critical, RiskTier::Low)
            })
            .expect_err("over-bound relations must fail closed");
        match error {
            PlanAdmissionError::BridgeRejected {
                dedup_key,
                admitted,
                ..
            } => {
                assert_eq!(dedup_key, "plan-digest-1:item-over-1");
                assert_eq!(admitted.len(), 1);
            }
            other => panic!("unexpected error {other:?}"),
        }
        assert_eq!(runner.reactive_pending_count(), 1);
    }

    #[test]
    fn producer_defects_stay_classified_as_plan_defects() {
        // The settled-plan entry maps producer failures without downgrade;
        // the producer itself is proven against the real planner in the plan
        // crate, so here the classification contract is pinned: a producer
        // defect never becomes a session, rejection, or attach error.
        let error = PlanAdmissionError::Producer(BridgeAdmissionError::MissingSource {
            item_id: "item-sourceless-1".to_owned(),
        });
        assert!(error.to_string().contains("plan producer defect"));
        assert!(!matches!(error, PlanAdmissionError::BridgeRejected { .. }));
        assert!(!matches!(error, PlanAdmissionError::SessionMismatch { .. }));
        assert!(!matches!(error, PlanAdmissionError::NotAttached));
    }
}
