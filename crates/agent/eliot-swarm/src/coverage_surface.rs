//! W6-projection/W7/A9/A11 visibility: pure read projection over
//! [`DurableWorkMachine`] and [`PlanDrain`] state.
//!
//! Candidate only: every value emitted here is visibility, never a task
//! finish, authority decision, or verified artifact. The projection performs
//! no store writes, mints no dispatch, launches nothing, and resolves
//! nothing: unknown stays unknown, and each coverage dimension (missing,
//! terminal-by-kind, unknown) is reported separately with no confidence
//! scalar and no majority vote. It never touches the store, Finish,
//! authority, Session, canonical, or credential paths.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::durable_dispatch::PlanDrain;
use crate::durable_work::{
    BudgetAccount, BudgetDimension, DurableWorkMachine, TerminalKind, WorkUnitPhase,
};

/// Opaque child slot label echoed from one denominator namespace.
///
/// A coverage projection merges two denominators keyed by different identity
/// types (durable [`WorkUnitId`](crate::durable_work::WorkUnitId) records
/// versus [`WorkItemId`](eliot_agent_contracts::WorkItemId) drain slots), so
/// a slot carries only the echoed text label for visibility. Labels never
/// join identities across namespaces: same text in both lists is coincidence
/// until the owner-side lineage proves otherwise. Candidate only.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct ChildSlot(String);

impl ChildSlot {
    /// Echoes one slot label from a denominator view.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Returns the echoed slot label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Projection vocabulary for one exact terminal kind.
///
/// Mirrors [`TerminalKind`] without depending on its lifecycle semantics:
/// proved-no-effect, exhaustion, pre-launch versus post-effect cancellation,
/// and partial coverage stay separate here exactly as they do at the owner.
/// Candidate only.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalKindName {
    Completed,
    FailedProvedNoEffect,
    FailedExhausted,
    CancelledBeforeLaunch,
    CancelledAfterEffect,
    Partial,
}

impl TerminalKindName {
    /// Names one exact terminal kind without merging or ranking kinds.
    #[must_use]
    pub const fn from_terminal(kind: TerminalKind) -> Self {
        match kind {
            TerminalKind::Completed => Self::Completed,
            TerminalKind::FailedProvedNoEffect => Self::FailedProvedNoEffect,
            TerminalKind::FailedExhausted => Self::FailedExhausted,
            TerminalKind::CancelledBeforeLaunch => Self::CancelledBeforeLaunch,
            TerminalKind::CancelledAfterEffect => Self::CancelledAfterEffect,
            TerminalKind::Partial => Self::Partial,
        }
    }
}

/// The next safe local action read off the projected coverage.
///
/// Candidate only: a suggestion for the caller, never an admission, launch
/// authorization, or finish.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NextSafeAction {
    /// Every child is terminally accounted, nothing is unknown, and local
    /// budget remains: a relaunch candidate may be built.
    RelaunchReady,
    /// The machine holds records blocked for reconcile or safe restart while
    /// the drain names no unknown slot: reconcile those records before any
    /// relaunch candidate.
    ReconcileBeforeRelaunch,
    /// Active children are still draining through the owner-side cancellation
    /// path: keep draining, build nothing.
    DrainRemaining,
    /// An expected child has no durable record, so the denominator is still
    /// open and no relaunch candidate may be built.
    BlockedOnMissingChild,
    /// The drain is not terminal-ready or accounts no terminal children, but
    /// it names no higher-priority blocker that explains the incomplete state.
    BlockedOnIncompleteDrain,
    /// The drain names unknown or stale children that block the terminal
    /// aggregate: nothing may be inferred until they reconcile.
    BlockedOnUnknown,
    /// No local budget dimensions were supplied, so launch eligibility cannot
    /// be determined.
    BudgetUnavailable,
    /// One or more supplied local budget dimensions are exhausted. This never
    /// touches Control Reserve or authorizes spend elsewhere.
    ExhaustedLocal,
}

/// Pure read projection of swarm coverage for one plan revision.
///
/// Candidate only: visibility over already-owned state, never a finish or an
/// authority decision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmCoverage {
    /// Echoed plan revision this projection was read for.
    pub plan_revision: u64,
    /// Exact accounted terminal children named by the drain. Candidate count
    /// only, never a denominator proof.
    pub accounted: usize,
    /// Expected children with no durable record: parent records reference
    /// these child identities but the machine holds no record for them, so
    /// the denominator stays open rather than guessed.
    pub missing: Vec<ChildSlot>,
    /// Unknown or stale children blocking the terminal aggregate: drain-named
    /// unknown slots plus machine records in blocked phases. Unknown stays
    /// unknown here.
    pub unknown: Vec<ChildSlot>,
    /// Per-kind terminal counts in [`TerminalKind`] declaration order, only
    /// for kinds present. Partial, failed, and cancelled kinds stay separate;
    /// no confidence scalar, no majority vote.
    pub terminal_by_kind: Vec<(TerminalKindName, usize)>,
    /// Supplied local budget accounts, kept separate by their independent
    /// dimensions. An empty list means the caller supplied no budget evidence.
    /// Deadline and non-budget resource evidence are not available here.
    pub budgets: Vec<BudgetDimensionCoverage>,
    /// The next safe local action. Candidate only.
    pub next_safe_action: NextSafeAction,
}

/// One local budget account with its dimension label and admitted limit.
///
/// Keeping accounts separate prevents compute, cost, and evidence limits from
/// being collapsed into an unlabeled scalar. Local only; never Control Reserve.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDimensionCoverage {
    /// Independent budget dimension represented by this account.
    pub dimension: BudgetDimension,
    /// Admitted local limit for this dimension.
    pub limit: u64,
    /// Amount currently reserved in this dimension.
    pub reserved: u64,
    /// Amount already spent in this dimension.
    pub spent: u64,
    /// Local headroom after reservations and spend, saturating at zero.
    pub remaining: u64,
}

/// Projects coverage over the machine and drain views without writing anything.
///
/// Reads only: the machine's held records, the drain decision, and the passed
/// per-dimension budget accounts. No store access, no dispatch, no launch, no
/// finish.
///
/// Action priority, in order: drain-named unknown slots block everything
/// ([`NextSafeAction::BlockedOnUnknown`]); machine records stuck in blocked
/// phases require reconcile first
/// ([`NextSafeAction::ReconcileBeforeRelaunch`]); outstanding cancels or
/// deferred active children keep draining
/// ([`NextSafeAction::DrainRemaining`]); a missing expected child record blocks
/// relaunch ([`NextSafeAction::BlockedOnMissingChild`]); a drain that is not
/// terminal-ready or has no terminal children blocks as
/// [`NextSafeAction::BlockedOnIncompleteDrain`]; no supplied budget evidence
/// reports [`NextSafeAction::BudgetUnavailable`], and any exhausted local
/// dimension reports [`NextSafeAction::ExhaustedLocal`]. Only a nonempty,
/// terminal-ready drain and nonempty budget view with remaining budget reports
/// [`NextSafeAction::RelaunchReady`].
#[must_use]
pub fn project_coverage(
    machine: &DurableWorkMachine<'_>,
    drain: &PlanDrain,
    budgets: &BTreeMap<BudgetDimension, BudgetAccount>,
    plan_revision: u64,
) -> SwarmCoverage {
    let records = machine.all_records();
    let held = records
        .iter()
        .map(|record| record.work_id.as_str())
        .collect::<BTreeSet<_>>();

    // Missing: child identities a held parent record references but the
    // machine holds no record for. The denominator stays open; a missing
    // child is never guessed terminal, failed, or safe-to-repeat.
    let mut missing = BTreeSet::new();
    for record in &records {
        for child in &record.children {
            if !held.contains(child.as_str()) {
                missing.insert(child.as_str().to_owned());
            }
        }
    }

    // Unknown: drain-named unknown slots plus machine records in blocked
    // phases (unknown outcome or quarantined). Both namespaces surface as
    // labels only; no cross-namespace identity is claimed.
    let mut unknown = BTreeSet::new();
    for slot in &drain.unknown {
        unknown.insert(slot.as_str().to_owned());
    }
    let mut needs_reconcile = false;
    for record in &records {
        if matches!(
            record.phase,
            WorkUnitPhase::UnknownOutcome | WorkUnitPhase::Quarantined
        ) {
            needs_reconcile = true;
            unknown.insert(record.work_id.as_str().to_owned());
        }
    }

    // Terminal kinds pass through exactly: counted per kind, never merged
    // into a scalar, never voted.
    let mut counts = BTreeMap::<TerminalKind, usize>::new();
    for (_, kind) in &drain.terminal {
        *counts.entry(*kind).or_default() += 1;
    }
    let terminal_by_kind = counts
        .into_iter()
        .map(|(kind, count)| (TerminalKindName::from_terminal(kind), count))
        .collect::<Vec<_>>();

    let budgets = budgets
        .iter()
        .map(|(dimension, account)| BudgetDimensionCoverage {
            dimension: *dimension,
            limit: account.limit,
            reserved: account.reserved,
            spent: account.spent,
            remaining: account
                .limit
                .saturating_sub(account.reserved)
                .saturating_sub(account.spent),
        })
        .collect::<Vec<_>>();

    let next_safe_action = if !drain.unknown.is_empty() {
        NextSafeAction::BlockedOnUnknown
    } else if needs_reconcile {
        NextSafeAction::ReconcileBeforeRelaunch
    } else if !drain.cancel.is_empty() || !drain.pending.is_empty() {
        NextSafeAction::DrainRemaining
    } else if !missing.is_empty() {
        NextSafeAction::BlockedOnMissingChild
    } else if !drain.terminal_ready || drain.terminal.is_empty() {
        NextSafeAction::BlockedOnIncompleteDrain
    } else if budgets.is_empty() {
        NextSafeAction::BudgetUnavailable
    } else if budgets.iter().any(|budget| budget.remaining == 0) {
        NextSafeAction::ExhaustedLocal
    } else {
        NextSafeAction::RelaunchReady
    };

    SwarmCoverage {
        plan_revision,
        accounted: drain.terminal.len(),
        missing: missing.into_iter().map(ChildSlot::new).collect::<Vec<_>>(),
        unknown: unknown.into_iter().map(ChildSlot::new).collect::<Vec<_>>(),
        terminal_by_kind,
        budgets,
        next_safe_action,
    }
}

#[cfg(test)]
mod tests {
    use eliot_agent_contracts::WorkItemId;

    use super::*;
    use crate::durable_work::DurablePorts;

    fn empty_machine() -> DurableWorkMachine<'static> {
        DurableWorkMachine::new(DurablePorts {
            store: None,
            executor: None,
            catalogue: None,
            peer: None,
            verifier: None,
        })
    }

    fn slot(text: &str) -> WorkItemId {
        WorkItemId::new(text).expect("test slot identity")
    }

    #[test]
    fn ready_projection_keeps_terminal_kinds_separate() {
        let machine = empty_machine();
        let drain = PlanDrain {
            cancel: Vec::new(),
            pending: Vec::new(),
            unknown: Vec::new(),
            terminal: vec![
                (slot("child-a"), TerminalKind::Completed),
                (slot("child-b"), TerminalKind::Partial),
                (slot("child-c"), TerminalKind::FailedExhausted),
            ],
            terminal_ready: true,
        };
        let budgets = BTreeMap::from([(
            BudgetDimension::ComputeSteps,
            BudgetAccount {
                limit: 100,
                reserved: 10,
                spent: 30,
            },
        )]);

        let coverage = project_coverage(&machine, &drain, &budgets, 7);

        assert_eq!(coverage.plan_revision, 7);
        assert_eq!(coverage.accounted, 3);
        assert!(coverage.missing.is_empty());
        assert!(coverage.unknown.is_empty());
        // Separate dimensions in TerminalKind declaration order: no scalar,
        // no vote.
        assert_eq!(
            coverage.terminal_by_kind,
            vec![
                (TerminalKindName::Completed, 1),
                (TerminalKindName::FailedExhausted, 1),
                (TerminalKindName::Partial, 1),
            ]
        );
        assert_eq!(
            coverage.budgets,
            vec![BudgetDimensionCoverage {
                dimension: BudgetDimension::ComputeSteps,
                limit: 100,
                reserved: 10,
                spent: 30,
                remaining: 60,
            }]
        );
        assert_eq!(coverage.next_safe_action, NextSafeAction::RelaunchReady);
    }

    #[test]
    fn unknown_drain_blocks_terminal_aggregate() {
        let machine = empty_machine();
        let drain = PlanDrain {
            cancel: Vec::new(),
            pending: Vec::new(),
            unknown: vec![slot("child-u")],
            terminal: vec![(slot("child-a"), TerminalKind::Completed)],
            terminal_ready: false,
        };
        let budgets = BTreeMap::from([(
            BudgetDimension::ComputeSteps,
            BudgetAccount {
                limit: 100,
                reserved: 0,
                spent: 0,
            },
        )]);

        let coverage = project_coverage(&machine, &drain, &budgets, 3);

        // Unknown blocks even with funded budget and accounted terminals.
        assert_eq!(coverage.next_safe_action, NextSafeAction::BlockedOnUnknown);
        assert_eq!(coverage.unknown, vec![ChildSlot::new("child-u")]);
        assert_eq!(coverage.accounted, 1);
    }

    #[test]
    fn pending_drain_precedes_budget_exhaustion() {
        let machine = empty_machine();
        let funded = BTreeMap::from([(
            BudgetDimension::ComputeSteps,
            BudgetAccount {
                limit: 100,
                reserved: 0,
                spent: 0,
            },
        )]);
        let draining = PlanDrain {
            cancel: vec![slot("child-a")],
            pending: vec![slot("child-b")],
            unknown: Vec::new(),
            terminal: Vec::new(),
            terminal_ready: false,
        };
        assert_eq!(
            project_coverage(&machine, &draining, &funded, 5).next_safe_action,
            NextSafeAction::DrainRemaining
        );

        let exhausted = BTreeMap::from([(
            BudgetDimension::CostMicrounits,
            BudgetAccount {
                limit: 50,
                reserved: 20,
                spent: 30,
            },
        )]);
        let drained = PlanDrain {
            cancel: Vec::new(),
            pending: Vec::new(),
            unknown: Vec::new(),
            terminal: vec![(slot("child-a"), TerminalKind::Completed)],
            terminal_ready: true,
        };
        let coverage = project_coverage(&machine, &drained, &exhausted, 5);
        // Local exhaustion only: remaining hits zero without touching
        // Control Reserve.
        assert_eq!(coverage.budgets[0].remaining, 0);
        assert_eq!(coverage.next_safe_action, NextSafeAction::ExhaustedLocal);
    }
}
