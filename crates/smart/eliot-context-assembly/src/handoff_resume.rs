//! Runtime resume owner for the recovery handoff (#1730 W7).
//!
//! This module is the runtime caller that drives `recover_handoff` and
//! completes the W6 STITCH: it runs the required checkpoint, content, and
//! authority checks, calls [`rebuild_handoff_view`] with the derived rebuild
//! request once an `Executable` admission with `rebuild_required` exists, and
//! binds the observed outcome (`Executable` vs `DiagnosticOnly`) to the
//! existing causal link and attempt record.
//!
//! Owner routing, step by step:
//!
//! - Canonical reads stay with their owners. The #1729 coherent reads run
//!   through the Governor read owner (fence-bound revision heads observed
//!   before and after a stable read); the task, scope, world, module, policy,
//!   route, and lease observations come from their owning readers. This
//!   caller only presents that caller-observed evidence via
//!   [`HandoffRecoveryInputs`] and [`HandoffRebuildCurrent`]; it retrieves
//!   nothing, mints no authority, and performs no IO.
//! - `recover_handoff` consumes the complete retained payload, admits the
//!   resume under fresh authority, dispatches the continuity branch,
//!   reconciles every in-flight operation without duplicating launch or
//!   tools, derives the rebuild request when a changed generation fences the
//!   retained authority, and binds the admitted outcome to the causal link
//!   and intent. A stale request naming another target is refused before any
//!   dispatch or launch, so it can never launch another worker; a repeated
//!   request for the same target intent reconciles to the recorded stage.
//! - the run additionally requires the payload to be bound to the
//!   controlled-boundary capture named by `inputs.ledger` /`inputs.boundary`.
//!   A commit permit alone is not a capture: the boundary ledger is what
//!   proves a real boundary captured this exact payload and read it back.
//! - Only an admitted executable outcome is bound: the bound link is cited
//!   on the target attempt record through the finisher, and the launch owner
//!   may launch the worker. A `DiagnosticOnly` outcome — from the gate or
//!   from the rebuild — carries its explicit dispositions for inspection and
//!   authorizes no launch and no attempt citation.
//! - A fresh transfer binds no link and cites nothing: it inherits no
//!   conversational state.
//! - Retained data and resources are never released here. Every value is
//!   borrowed; release stays with the existing owners under their
//!   terminal-retention rules.
//! - Status is the intent's own five-state path, surfaced on the carried
//!   recovery output: checkpoint stored, compaction observed, revalidation
//!   pending, resume admitted, and actual resumed execution. The last step
//!   belongs to the launch owner, which reports actual execution through the
//!   finisher's `mark_executed`; this caller never marks execution itself.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    AgentAttempt, HandoffRecoveryFinish, HandoffRecoveryInputs, HandoffRecoveryOutput,
    HandoffResumeAdmission, HandoffResumeIntent, recover_handoff,
};

use crate::{
    HandoffRebuildCurrent, HandoffRebuildDiagnostic, HandoffRebuildError, HandoffRebuildOutcome,
    HandoffRebuiltView, rebuild_handoff_view,
};

/// Observed outcome of one runtime resume run (I12.17, I7.15).
///
/// An executable outcome authorizes the launch owner to launch the bound
/// worker; a diagnostic outcome keeps the explicit dispositions available
/// for inspection while the dependent action stays blocked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffResumeOutcome {
    /// The resume is admitted and the observed rebuild outcome is bound to
    /// the causal link and the target attempt record. The rebuilt View is
    /// present when a changed generation required a rebuild; it is absent
    /// when the retained fence still covers the resume.
    Executable {
        /// Recovery output with admission, dispatch, effect instructions,
        /// bound link, and intent status.
        recovery: HandoffRecoveryOutput,
        /// Rebuilt current delta View, absent when no rebuild was required.
        rebuilt: Option<Box<HandoffRebuiltView>>,
    },
    /// The dependent action stays blocked; diagnostic inspection remains
    /// available. The diagnostic value is present when the rebuild ran and
    /// blocked, absent when the gate blocked before any rebuild.
    DiagnosticOnly {
        /// Recovery output with the blocking admission and intent status.
        recovery: HandoffRecoveryOutput,
        /// Blocked rebuild with its explicit dispositions, when the rebuild ran.
        diagnostic: Option<Box<HandoffRebuildDiagnostic>>,
    },
}

/// Runs one recovery handoff through the runtime resume owner (I12.17, I7.15).
///
/// The caller holds one `intent` per target attempt across requests: repeats
/// reconcile the same target intent, and a stale request is refused before
/// any dispatch, binding, or launch. `attempt` must be the link's own target;
/// a crossed attempt is refused before launch. Only shared references cross
/// this boundary, so retained data stays with its owners and is released
/// only under their terminal-retention rules.
pub fn resume_handoff(
    inputs: &HandoffRecoveryInputs<'_>,
    intent: &mut HandoffResumeIntent,
    attempt: &mut AgentAttempt,
    current: &HandoffRebuildCurrent<'_>,
) -> Result<HandoffResumeOutcome, HandoffRebuildError> {
    let recovery = recover_handoff(inputs, intent)?;
    match &recovery.admission {
        HandoffResumeAdmission::DiagnosticOnly { .. } => Ok(HandoffResumeOutcome::DiagnosticOnly {
            recovery,
            diagnostic: None,
        }),
        HandoffResumeAdmission::Executable { .. } => match recovery.rebuild.as_ref() {
            None => {
                cite_bound_link(&recovery, attempt)?;
                Ok(HandoffResumeOutcome::Executable {
                    recovery,
                    rebuilt: None,
                })
            }
            Some(request) => {
                let retained = inputs.evidence.retained()?;
                match rebuild_handoff_view(retained, request, current)? {
                    HandoffRebuildOutcome::Executable { rebuilt } => {
                        cite_bound_link(&recovery, attempt)?;
                        Ok(HandoffResumeOutcome::Executable {
                            recovery,
                            rebuilt: Some(rebuilt),
                        })
                    }
                    HandoffRebuildOutcome::DiagnosticOnly { diagnostic } => {
                        Ok(HandoffResumeOutcome::DiagnosticOnly {
                            recovery,
                            diagnostic: Some(diagnostic),
                        })
                    }
                }
            }
        },
    }
}

/// Cites the bound link on the target attempt record when the recovery bound
/// one. A fresh transfer binds no link, so there is nothing to cite.
fn cite_bound_link(
    recovery: &HandoffRecoveryOutput,
    attempt: &mut AgentAttempt,
) -> Result<(), HandoffRebuildError> {
    if let Some(link) = recovery.bound_link.as_ref() {
        HandoffRecoveryFinish::bind_attempt_record(attempt, link)?;
    }
    Ok(())
}
