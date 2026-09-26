//! Daemon swarm composition proof for issue #1126 (W1/W4/W5, A1/A4/A5/A7,
//! A10-negative, A11-locality).
//!
//! Non-test composition proof: the test drives the real non-test
//! composition in `bins/eliotd/src/swarm_composition.rs` (included below by
//! path because the `lib.rs` one-line activation,
//! `pub mod swarm_composition;`, is the integrator's follow-up outside this
//! work unit's file grant) against the REAL Governor owner
//! ([`SwarmAttachmentComposition`] over [`SwarmPlanAttachmentService`] and
//! the canonical [`CanonicalSwarmPlanAttachmentStore`]) plus deterministic
//! fake ledger/runner owners behind the composition's port traits.
//!
//! Covered, in order: attach one admitted plan through the vended port;
//! launch two children with persist-before-launch order (one success, one
//! slot-local budget-exhausted failure); revoked route blocked with no
//! ledger effect; daemon restart (drop everything but the owners, rehydrate
//! from the sealed attachment, reconcile-before-relaunch enforced, unknown
//! stays unknown, no launched child lost); cancel drain to `terminal_ready`;
//! unknown blocking the false terminal; second-job conflict naming the
//! canonical winner; blank identities rejected before any owner contact.
//!
//! [`SwarmAttachmentComposition`]: eliot_governor::SwarmAttachmentComposition
//! [`SwarmPlanAttachmentService`]: eliot_governor::SwarmPlanAttachmentService
//! [`CanonicalSwarmPlanAttachmentStore`]: eliot_governor::CanonicalSwarmPlanAttachmentStore

#[path = "../src/swarm_composition.rs"]
mod swarm_composition;

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_governor::{SwarmAttachmentComposition, SwarmPlanAttachmentService};

use swarm_composition::{
    AttachedPlan, ChildExit, ChildLaunchIntent, ChildRunner, ChildState, LaunchIntentLedger,
    RegistryRouteStatus, SwarmComposition, SwarmCompositionError, plan_drain,
};

const ADMISSION: &str = "admission-digest-1126";
const PLAN: &str = "plan-rev-7";
const FENCE: &str = "fence-digest-1126";
const JOB: &str = "job-1126-1";
/// Registry adapter-entry digest sealing every fixture launch (pinned per
/// route class on first launch; identical across fixtures so pins agree).
const ADAPTER_DIGEST: [u8; 32] = [0xA1; 32];
/// Opaque generation fingerprint sealing every fixture launch.
const GENERATION_FINGERPRINT: [u8; 32] = [0xF1; 32];

/// Shared ordered event log proving persist-before-launch across the two
/// owners: the ledger logs `persist:<operation_id>`, the runner logs
/// `launch:<operation_id>`.
#[derive(Debug, Default)]
struct EventLog {
    events: Mutex<Vec<String>>,
}

impl EventLog {
    fn push(&self, event: String) {
        self.events
            .lock()
            .expect("event log lock holds")
            .push(event);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("event log lock holds").clone()
    }
}

/// Deterministic fake persistence owner: appends intents in order and echoes
/// a 1-based durable sequence. Restart safety belongs to the real owner;
/// this fake proves the order protocol, not disk behavior.
struct FakeLedger<'a> {
    intents: Mutex<Vec<ChildLaunchIntent>>,
    log: &'a EventLog,
}

impl<'a> FakeLedger<'a> {
    fn new(log: &'a EventLog) -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            log,
        }
    }
}

impl LaunchIntentLedger for FakeLedger<'_> {
    fn append_intent(&self, intent: &ChildLaunchIntent) -> Result<u64, SwarmCompositionError> {
        let mut intents = self
            .intents
            .lock()
            .map_err(|_| SwarmCompositionError::OwnerFailure {
                detail: "fake ledger lock is poisoned".to_owned(),
            })?;
        intents.push(intent.clone());
        self.log.push(format!("persist:{}", intent.operation_id));
        Ok(intents.len() as u64)
    }

    fn intents(&self) -> Vec<ChildLaunchIntent> {
        self.intents.lock().expect("fake ledger lock holds").clone()
    }
}

/// Deterministic fake native-worker dispatch surface: launches exactly the
/// persisted intents it is shown, observes per-slot scripted states, and
/// flips `Running` to terminal on cancel.
struct FakeRunner<'a> {
    states: Mutex<BTreeMap<String, ChildState>>,
    launched: Mutex<Vec<String>>,
    log: &'a EventLog,
}

impl<'a> FakeRunner<'a> {
    fn new(log: &'a EventLog) -> Self {
        Self {
            states: Mutex::new(BTreeMap::new()),
            launched: Mutex::new(Vec::new()),
            log,
        }
    }

    fn set_state(&self, slot: &str, state: ChildState) {
        self.states
            .lock()
            .expect("fake runner lock holds")
            .insert(slot.to_owned(), state);
    }

    fn lock_states(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, ChildState>>, SwarmCompositionError>
    {
        self.states
            .lock()
            .map_err(|_| SwarmCompositionError::OwnerFailure {
                detail: "fake runner lock is poisoned".to_owned(),
            })
    }
}

impl ChildRunner for FakeRunner<'_> {
    fn launch(&self, intent: &ChildLaunchIntent) -> Result<(), SwarmCompositionError> {
        self.log.push(format!("launch:{}", intent.operation_id));
        self.launched
            .lock()
            .map_err(|_| SwarmCompositionError::OwnerFailure {
                detail: "fake runner lock is poisoned".to_owned(),
            })?
            .push(intent.operation_id.clone());
        let mut states = self.lock_states()?;
        states
            .entry(intent.slot.clone())
            .or_insert(ChildState::Running);
        Ok(())
    }

    fn observe(&self, slot: &str) -> Result<ChildState, SwarmCompositionError> {
        let states = self.lock_states()?;
        Ok(states.get(slot).copied().unwrap_or(ChildState::Stale))
    }

    fn cancel(&self, slot: &str) -> Result<(), SwarmCompositionError> {
        let mut states = self.lock_states()?;
        let state = states.get(slot).copied().unwrap_or(ChildState::Stale);
        let next = match state {
            ChildState::Running => ChildState::Terminal(ChildExit::CancelledAfterEffect),
            other => other,
        };
        states.insert(slot.to_owned(), next);
        Ok(())
    }
}

fn composition<'a>(
    attachment: &'a SwarmAttachmentComposition,
    ledger: &'a FakeLedger<'a>,
    runner: &'a FakeRunner<'a>,
) -> SwarmComposition<'a, FakeLedger<'a>, FakeRunner<'a>> {
    SwarmComposition::new(attachment, ledger, runner)
}

fn attach(composition: &mut SwarmComposition<'_, FakeLedger<'_>, FakeRunner<'_>>) -> AttachedPlan {
    composition
        .attach_admitted_plan(ADMISSION, PLAN, FENCE, JOB)
        .expect("plan attaches through the Governor owner")
}

fn assert_persist_before_launch(log: &EventLog, operation_id: &str) {
    let events = log.events();
    let persist = events
        .iter()
        .position(|event| event == &format!("persist:{operation_id}"))
        .expect("persist event is logged");
    let launch = events
        .iter()
        .position(|event| event == &format!("launch:{operation_id}"))
        .expect("launch event is logged");
    assert!(
        persist < launch,
        "intent must persist before the runner call: {events:?}"
    );
}

#[test]
fn attach_launches_two_children_with_persist_before_launch_order() {
    let log = EventLog::default();
    let attachment = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
    let ledger = FakeLedger::new(&log);
    let runner = FakeRunner::new(&log);
    let mut composition = composition(&attachment, &ledger, &runner);

    // Governor durable-job owner binds the admitted plan to exactly one job.
    let sealed = attach(&mut composition);
    assert_eq!(sealed.admission_digest, ADMISSION);
    assert_eq!(sealed.plan_revision, PLAN);
    assert_eq!(sealed.job_handle, JOB);
    assert_eq!(sealed.fence_digest, FENCE);
    assert!(!sealed.binding_digest.trim().is_empty());
    assert!(composition.launch_allowed());
    assert_eq!(
        composition.plan().expect("plan is attached").job_handle,
        JOB
    );

    // Identical replay is idempotent and returns the identical binding.
    let replay = composition
        .attach_admitted_plan(ADMISSION, PLAN, FENCE, JOB)
        .expect("identical replay binds");
    assert_eq!(replay, sealed);

    // Two children launch over the admitted route surface.
    let first = composition
        .launch_child(
            "slot-a",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT,
        )
        .expect("first child launches");
    assert_eq!(first.operation_id, format!("{JOB}:{PLAN}:slot-a"));
    assert_eq!(first.attempt_id, format!("{JOB}:{PLAN}:slot-a-attempt"));
    assert_persist_before_launch(&log, &first.operation_id);

    let second = composition
        .launch_child(
            "slot-b",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT,
        )
        .expect("second child launches");
    assert_persist_before_launch(&log, &second.operation_id);
    assert_eq!(composition.launched().len(), 2);

    // One success, one slot-local budget-exhausted failure: exhaustion is
    // observed at the slot through the runner, never inferred here.
    runner.set_state("slot-a", ChildState::Terminal(ChildExit::Completed));
    runner.set_state("slot-b", ChildState::Terminal(ChildExit::FailedExhausted));
    assert_eq!(
        runner.observe("slot-a").expect("slot-a observes"),
        ChildState::Terminal(ChildExit::Completed)
    );
    assert_eq!(
        runner.observe("slot-b").expect("slot-b observes"),
        ChildState::Terminal(ChildExit::FailedExhausted)
    );

    // A revoked registry verdict blocks launch with no fallback and, above
    // all, no ledger append: the intent never persists.
    let intents_before = ledger.intents().len();
    assert!(matches!(
        composition.launch_child(
            "slot-c",
            RegistryRouteStatus::Revoked,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::RouteBlocked { .. })
    ));
    assert!(matches!(
        composition.launch_child(
            "slot-c",
            RegistryRouteStatus::Stale,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::RouteBlocked { .. })
    ));
    assert_eq!(ledger.intents().len(), intents_before);

    // Reusing a slot that already carries a persisted intent is refused:
    // changed input needs a new identity, never a silent relaunch.
    assert!(matches!(
        composition.launch_child(
            "slot-a",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::DuplicateSlot { .. })
    ));
}

#[test]
fn restart_rehydrates_and_reconciles_before_any_relaunch() {
    let log = EventLog::default();
    let attachment = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
    let ledger = FakeLedger::new(&log);
    let runner = FakeRunner::new(&log);
    let sealed = attach(&mut composition(&attachment, &ledger, &runner));

    // Launch before the simulated restart: one child still running, one
    // unreachable with possible effect.
    {
        let mut before = composition(&attachment, &ledger, &runner);
        before
            .attach_admitted_plan(ADMISSION, PLAN, FENCE, JOB)
            .expect("replay binds before restart");
        before
            .launch_child(
                "slot-a",
                RegistryRouteStatus::Admitted,
                "native-worker",
                3,
                ADAPTER_DIGEST,
                GENERATION_FINGERPRINT,
            )
            .expect("slot-a launches");
        before
            .launch_child(
                "slot-b",
                RegistryRouteStatus::Admitted,
                "native-worker",
                3,
                ADAPTER_DIGEST,
                GENERATION_FINGERPRINT,
            )
            .expect("slot-b launches");
    }
    runner.set_state("slot-a", ChildState::Running);
    runner.set_state("slot-b", ChildState::UnknownBlocked);

    // Simulate the daemon restart: drop every composition (all in-memory
    // attachments are gone); the owners (service, ledger, runner) survive.
    // A fresh composition has no plan, so launches are refused until the
    // sealed attachment is rehydrated through the canonical owner.
    let mut restarted = composition(&attachment, &ledger, &runner);
    assert!(!restarted.launch_allowed());
    assert!(matches!(
        restarted.launch_child(
            "slot-c",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::PlanNotAttached)
    ));

    // Rehydrate from the sealed attachment: the canonical decision (not
    // process memory) is the source of truth, every persisted intent is
    // re-observed, and unknown stays unknown. No launch happens here.
    let launches_before = runner
        .launched
        .lock()
        .expect("fake runner lock holds")
        .len();
    let report = restarted
        .rehydrate_after_restart(&sealed)
        .expect("rehydration reconciles");
    assert_eq!(report.plan, sealed);
    assert_eq!(
        runner
            .launched
            .lock()
            .expect("fake runner lock holds")
            .len(),
        launches_before,
        "rehydration must not relaunch"
    );

    // No-lost-child: every ledger intent rehydrated with its reconciled
    // state, including the unknown one.
    let mut rehydrated_slots: Vec<(&str, ChildState)> = report
        .children
        .iter()
        .map(|(intent, state)| (intent.slot.as_str(), *state))
        .collect();
    rehydrated_slots.sort();
    assert_eq!(
        rehydrated_slots,
        vec![
            ("slot-a", ChildState::Running),
            ("slot-b", ChildState::UnknownBlocked),
        ]
    );
    let persisted = ledger.intents();
    let ledger_slots: Vec<&str> = persisted
        .iter()
        .map(|intent| intent.slot.as_str())
        .collect();
    assert_eq!(ledger_slots, vec!["slot-a", "slot-b"]);
    assert!(restarted.launch_allowed());

    // A drifted sealed revision is stale lineage, not a silent rebind.
    // The failed rehydration leaves the composition unreconciled, so the
    // next launch is refused until reconciliation runs again — and a fresh
    // rehydrate with the true sealed attachment recovers.
    let mut drifted = sealed.clone();
    drifted.plan_revision = "plan-rev-8".to_owned();
    assert!(matches!(
        restarted.rehydrate_after_restart(&drifted),
        Err(SwarmCompositionError::StaleLineage { .. })
    ));
    assert!(matches!(
        restarted.launch_child(
            "slot-c",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::ReconcileRequired)
    ));
    let recovered = restarted
        .rehydrate_after_restart(&sealed)
        .expect("true sealed attachment recovers");
    assert_eq!(recovered.plan, sealed);
    // slot-c is a new identity, so it may launch; reusing slot-a is refused.
    restarted
        .launch_child(
            "slot-c",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT,
        )
        .expect("new slot launches after reconcile");
    assert!(matches!(
        restarted.launch_child(
            "slot-a",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT
        ),
        Err(SwarmCompositionError::DuplicateSlot { .. })
    ));
}

#[test]
fn cancel_drain_reaches_terminal_ready_then_unknown_blocks_false_terminal() {
    let log = EventLog::default();
    let attachment = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
    let ledger = FakeLedger::new(&log);
    let runner = FakeRunner::new(&log);
    let mut composition = composition(&attachment, &ledger, &runner);
    attach(&mut composition);
    composition
        .launch_child(
            "slot-a",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT,
        )
        .expect("slot-a launches");
    composition
        .launch_child(
            "slot-b",
            RegistryRouteStatus::Admitted,
            "native-worker",
            3,
            ADAPTER_DIGEST,
            GENERATION_FINGERPRINT,
        )
        .expect("slot-b launches");
    runner.set_state("slot-a", ChildState::Running);
    runner.set_state("slot-b", ChildState::Running);

    // Bounded cancel drain: both running children cancel through the
    // owner-side path and the terminal aggregate publishes with exact kinds.
    let outcome = composition
        .drain_bounded(16)
        .expect("drain reaches terminal_ready");
    let mut terminal = outcome.terminal.clone();
    terminal.sort();
    assert_eq!(
        terminal,
        vec![
            ("slot-a".to_owned(), ChildExit::CancelledAfterEffect),
            ("slot-b".to_owned(), ChildExit::CancelledAfterEffect),
        ]
    );
    assert_eq!(outcome.cancel_requested.len(), 2);
    assert!(outcome.passes >= 1);

    // One child goes unreachable with possible effect: the same drain now
    // blocks the terminal aggregate instead of publishing a false terminal.
    runner.set_state("slot-b", ChildState::UnknownBlocked);
    match composition.drain_bounded(16).expect_err("unknown blocks") {
        SwarmCompositionError::TerminalBlocked { unknown, progress } => {
            assert_eq!(unknown, vec!["slot-b".to_owned()]);
            // Progress already made stays reported with the block: slot-a was
            // observed terminal in the same call.
            assert!(
                progress
                    .terminal
                    .contains(&("slot-a".to_owned(), ChildExit::CancelledAfterEffect))
            );
        }
        other => panic!("unknown must block the terminal, got {other:?}"),
    }
}

#[test]
fn plan_drain_decision_is_pure_bounded_and_exact() {
    // Every terminal kind passes through exactly; an all-terminal
    // denominator is immediately terminal-ready with no cancels.
    let children: Vec<(String, ChildState)> = [
        ChildExit::Completed,
        ChildExit::FailedProvedNoEffect,
        ChildExit::FailedExhausted,
        ChildExit::CancelledBeforeLaunch,
        ChildExit::CancelledAfterEffect,
        ChildExit::Partial,
    ]
    .iter()
    .enumerate()
    .map(|(index, kind)| (format!("slot-{index}"), ChildState::Terminal(*kind)))
    .collect();
    let view = plan_drain(&children, 16).expect("all-terminal denominator drains");
    assert!(view.terminal_ready);
    assert!(view.cancel.is_empty());
    assert!(view.pending.is_empty());
    assert!(view.unknown.is_empty());
    for (slot, kind) in &view.terminal {
        let index: usize = slot
            .strip_prefix("slot-")
            .expect("slot shape")
            .parse()
            .expect("slot index parses");
        assert_eq!(Some(*kind), children[index].1.terminal_kind());
    }

    // Empty denominator and duplicate slots fail closed.
    assert!(matches!(
        plan_drain(&[], 16),
        Err(SwarmCompositionError::EmptyDenominator)
    ));
    let duplicate = vec![
        ("slot-a".to_owned(), ChildState::Running),
        ("slot-a".to_owned(), ChildState::Running),
    ];
    assert!(matches!(
        plan_drain(&duplicate, 16),
        Err(SwarmCompositionError::DuplicateSlot { .. })
    ));

    // Twenty running children with the pass bound: sixteen cancel, four wait
    // pending, and the terminal is not ready.
    let wide: Vec<(String, ChildState)> = (0..20)
        .map(|index| (format!("slot-{index}"), ChildState::Running))
        .collect();
    let view = plan_drain(&wide, usize::MAX).expect("wide denominator drains bounded");
    assert_eq!(view.cancel.len(), 16);
    assert_eq!(view.pending.len(), 4);
    assert!(!view.terminal_ready);
}

#[test]
fn second_job_conflicts_with_canonical_winner_and_blank_input_fails_closed() {
    let log = EventLog::default();
    let attachment = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
    let ledger = FakeLedger::new(&log);
    let runner = FakeRunner::new(&log);
    let mut composition = composition(&attachment, &ledger, &runner);
    attach(&mut composition);

    // A second job for the same plan key conflicts and names the canonical
    // winner; no second commit escapes.
    match composition
        .attach_admitted_plan(ADMISSION, PLAN, FENCE, "job-1126-2")
        .expect_err("second job must conflict")
    {
        SwarmCompositionError::AttachConflict { winner_job, detail } => {
            assert_eq!(winner_job.as_deref(), Some(JOB));
            assert!(!detail.trim().is_empty());
        }
        other => panic!("second job must conflict with the winner, got {other:?}"),
    }

    // Blank identities fail closed before any owner contact: the committed
    // image still holds exactly the one winner binding.
    for (admission, revision, fence, job) in [
        ("   ", PLAN, FENCE, JOB),
        (ADMISSION, "", FENCE, JOB),
        (ADMISSION, PLAN, "   ", JOB),
        (ADMISSION, PLAN, FENCE, "  "),
    ] {
        assert!(
            matches!(
                composition.attach_admitted_plan(admission, revision, fence, job),
                Err(SwarmCompositionError::InvalidInput { .. })
            ),
            "blank identity must fail closed"
        );
    }
    assert_eq!(ledger.intents().len(), 0);
}
