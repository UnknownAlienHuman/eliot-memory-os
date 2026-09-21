//! Issue #1924: Dreamer advice change-control gate (MAINT-4 / I18.40).
//!
//! Dreamer stays proposal-only. Topology and mechanism advice are Meta
//! candidates that change the system only through the
//! candidate -> owner decision -> verifier -> rollback/retain loop.
//! Repeatedly failed advice becomes negative procedural memory keyed to the
//! failed hypothesis and cannot be re-proposed without new discriminating
//! evidence. Evaluation improvements never alter policy automatically.
//!
//! This module is a pure boundary: it holds no filesystem, store, runtime,
//! promotion, or execution handles. It only builds inspectable candidate
//! records, owner decisions, verifier bindings, terminal dispositions, and
//! negative-memory entries. There is deliberately no method that mutates
//! runtime configuration, code, policy, or release state; the only
//! mutation-shaped entry point ([`AdviceGate::direct_apply`]) always fails
//! with [`AdviceRejected::DirectMutationForbidden`] so the prohibition is
//! executable and testable.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Class of Dreamer advice. Topology and mechanism advice are Meta
/// candidates; evaluation improvements are candidates that must never alter
/// policy automatically.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdviceClass {
    MechanismChange,
    TopologyChange,
    EvaluationImprovement,
}

impl AdviceClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MechanismChange => "mechanism_change",
            Self::TopologyChange => "topology_change",
            Self::EvaluationImprovement => "evaluation_improvement",
        }
    }
}

/// Terminal lifecycle state of an advice candidate.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdviceState {
    Proposed,
    OwnerApproved,
    OwnerRejected,
    VerifierRetained,
    VerifierRolledBack,
    Failed,
}

/// Durable candidate record for one Dreamer advice hypothesis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceCandidate {
    pub hypothesis_key: String,
    pub statement: String,
    pub advice_class: AdviceClass,
    pub discriminating_evidence: Vec<String>,
    pub expected_benefit: String,
    pub cost_counter_metrics: String,
    pub owner: String,
    pub verifier: Option<String>,
    pub rollback_plan: Option<String>,
    pub state: AdviceState,
}

/// Owner decision on a proposed candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum OwnerDecision {
    Approve { verifier: String, rollback: String },
    Reject { reason: String },
}

/// Durable negative procedural memory entry for a failed hypothesis family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryEntry {
    pub hypothesis_key: String,
    pub advice_class: AdviceClass,
    pub failure_reason: String,
    pub failures: u32,
    pub known_discriminators: BTreeSet<String>,
}

/// Inbound proposal shape. The gate normalises the statement into a stable
/// [`AdviceCandidate::hypothesis_key`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceProposal {
    pub statement: String,
    pub advice_class: AdviceClass,
    pub discriminating_evidence: Vec<String>,
    pub expected_benefit: String,
    pub cost_counter_metrics: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AdviceRejected {
    #[error("proposal is blank or unbounded: {0}")]
    BlankField(&'static str),
    #[error("proposal carries no discriminating evidence")]
    MissingEvidence,
    #[error(
        "rejected: hypothesis '{hypothesis_key}' is in negative procedural memory ({failures} prior failure(s): {reason}); attach new discriminating evidence beyond {known:?}"
    )]
    NegativeMemoryBlock {
        hypothesis_key: String,
        failures: u32,
        reason: String,
        known: Vec<String>,
    },
    #[error("owner approval requires a named verifier")]
    MissingVerifier,
    #[error("owner approval requires a rollback condition")]
    MissingRollback,
    #[error("candidate '{0}' is not in a decidable state")]
    NotDecidable(String),
    #[error("candidate '{0}' is not awaiting verification")]
    NotAwaitingVerification(String),
    #[error(
        "direct mutation forbidden: Dreamer proposals are candidate-only and cannot modify runtime configuration, code, policy, or release state"
    )]
    DirectMutationForbidden,
}

/// Pure change-control gate. Holds negative procedural memory; all other
/// methods are pure transitions over owned records.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceGate {
    negative_memory: BTreeMap<String, NegativeMemoryEntry>,
}

impl AdviceGate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            negative_memory: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn negative_memory(&self) -> &BTreeMap<String, NegativeMemoryEntry> {
        &self.negative_memory
    }

    /// Stable hypothesis key: `<class>:<normalised statement>`.
    #[must_use]
    pub fn hypothesis_key_for(advice_class: AdviceClass, statement: &str) -> String {
        format!(
            "{}:{}",
            advice_class.as_str(),
            normalise_statement(statement)
        )
    }

    fn check_negative_block(
        &self,
        hypothesis_key: &str,
        evidence: &[String],
    ) -> Result<(), AdviceRejected> {
        if let Some(entry) = self.negative_memory.get(hypothesis_key) {
            let fresh = evidence
                .iter()
                .any(|item| !entry.known_discriminators.contains(item));
            if !fresh {
                return Err(AdviceRejected::NegativeMemoryBlock {
                    hypothesis_key: hypothesis_key.to_owned(),
                    failures: entry.failures,
                    reason: entry.failure_reason.clone(),
                    known: entry
                        .known_discriminators
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                });
            }
        }
        Ok(())
    }

    /// Admit a proposal as a `Proposed` candidate record.
    ///
    /// Rejects blank fields, missing discriminating evidence, and any
    /// re-submission of a negatively-remembered hypothesis that carries no
    /// new discriminator.
    pub fn propose(&self, proposal: &AdviceProposal) -> Result<AdviceCandidate, AdviceRejected> {
        if proposal.statement.trim().is_empty() {
            return Err(AdviceRejected::BlankField("statement"));
        }
        if proposal.expected_benefit.trim().is_empty() {
            return Err(AdviceRejected::BlankField("expected_benefit"));
        }
        if proposal.cost_counter_metrics.trim().is_empty() {
            return Err(AdviceRejected::BlankField("cost_counter_metrics"));
        }
        if proposal.owner.trim().is_empty() {
            return Err(AdviceRejected::BlankField("owner"));
        }
        let evidence: Vec<String> = proposal
            .discriminating_evidence
            .iter()
            .map(|item| item.trim().to_owned())
            .filter(|item| !item.is_empty())
            .collect();
        if evidence.is_empty() {
            return Err(AdviceRejected::MissingEvidence);
        }
        let hypothesis_key = Self::hypothesis_key_for(proposal.advice_class, &proposal.statement);
        self.check_negative_block(&hypothesis_key, &evidence)?;
        Ok(AdviceCandidate {
            hypothesis_key,
            statement: proposal.statement.trim().to_owned(),
            advice_class: proposal.advice_class,
            discriminating_evidence: evidence,
            expected_benefit: proposal.expected_benefit.trim().to_owned(),
            cost_counter_metrics: proposal.cost_counter_metrics.trim().to_owned(),
            owner: proposal.owner.trim().to_owned(),
            verifier: None,
            rollback_plan: None,
            state: AdviceState::Proposed,
        })
    }

    /// Apply the owner decision. Approval binds a named verifier and a
    /// rollback condition; rejection parks the candidate as `OwnerRejected`
    /// (the caller then records negative memory via [`Self::record_failure`]).
    pub fn record_owner_decision(
        &self,
        mut candidate: AdviceCandidate,
        decision: &OwnerDecision,
    ) -> Result<AdviceCandidate, AdviceRejected> {
        if candidate.state != AdviceState::Proposed {
            return Err(AdviceRejected::NotDecidable(candidate.hypothesis_key));
        }
        match decision {
            OwnerDecision::Approve { verifier, rollback } => {
                if verifier.trim().is_empty() {
                    return Err(AdviceRejected::MissingVerifier);
                }
                if rollback.trim().is_empty() {
                    return Err(AdviceRejected::MissingRollback);
                }
                candidate.verifier = Some(verifier.trim().to_owned());
                candidate.rollback_plan = Some(rollback.trim().to_owned());
                candidate.state = AdviceState::OwnerApproved;
                Ok(candidate)
            }
            OwnerDecision::Reject { .. } => {
                candidate.state = AdviceState::OwnerRejected;
                Ok(candidate)
            }
        }
    }

    /// Record a rejected or failed candidate family as negative procedural
    /// memory keyed to the failed hypothesis.
    pub fn record_failure(
        &mut self,
        candidate: &AdviceCandidate,
        reason: &str,
    ) -> NegativeMemoryEntry {
        let reason = if reason.trim().is_empty() {
            "unspecified failure"
        } else {
            reason.trim()
        };
        let entry = self
            .negative_memory
            .entry(candidate.hypothesis_key.clone())
            .or_insert(NegativeMemoryEntry {
                hypothesis_key: candidate.hypothesis_key.clone(),
                advice_class: candidate.advice_class,
                failure_reason: reason.to_owned(),
                failures: 0,
                known_discriminators: BTreeSet::new(),
            });
        entry.failures = entry.failures.saturating_add(1);
        entry.failure_reason = reason.to_string();
        entry
            .known_discriminators
            .extend(candidate.discriminating_evidence.iter().cloned());
        entry.clone()
    }

    /// Record the named verifier outcome. A pass retains the candidate; a
    /// failure rolls it back and writes negative procedural memory.
    pub fn record_verifier_outcome(
        &mut self,
        mut candidate: AdviceCandidate,
        passed: bool,
        detail: &str,
    ) -> Result<AdviceCandidate, AdviceRejected> {
        if candidate.state != AdviceState::OwnerApproved {
            return Err(AdviceRejected::NotAwaitingVerification(
                candidate.hypothesis_key,
            ));
        }
        if passed {
            candidate.state = AdviceState::VerifierRetained;
            Ok(candidate)
        } else {
            candidate.state = AdviceState::VerifierRolledBack;
            self.record_failure(&candidate, detail);
            Ok(candidate)
        }
    }

    /// Proposal-only ceiling proof: no Dreamer output can directly invoke
    /// write, promotion, or execution capabilities. This always fails.
    pub fn direct_apply(&self, _candidate: &AdviceCandidate) -> Result<(), AdviceRejected> {
        Err(AdviceRejected::DirectMutationForbidden)
    }
}

fn normalise_statement(statement: &str) -> String {
    statement
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod advice_gate_1924 {
    //! Issue #1924 acceptance proof (minimal by owner order): one test that a
    //! Dreamer proposal routes through candidate -> owner decision ->
    //! verifier -> rollback/retain with negative memory.

    use super::{
        AdviceClass, AdviceGate, AdviceProposal, AdviceRejected, AdviceState, OwnerDecision,
    };

    fn proposal(statement: &str, evidence: &[&str]) -> AdviceProposal {
        AdviceProposal {
            statement: statement.to_owned(),
            advice_class: AdviceClass::TopologyChange,
            discriminating_evidence: evidence.iter().map(ToString::to_string).collect(),
            expected_benefit: "faster edge proof".to_owned(),
            cost_counter_metrics: "compile minutes + rollback cost".to_owned(),
            owner: "dreamer-maintenance-owner".to_owned(),
        }
    }

    #[test]
    fn dreamer_advice_routes_through_candidate_owner_verifier_and_negative_memory() {
        let mut gate = AdviceGate::new();

        // Proposal-only ceiling: a proposal can never directly mutate runtime.
        let candidate = gate
            .propose(&proposal(
                "merge dreamer probe crates",
                &["edge-time before/after"],
            ))
            .expect("first proposal is admitted");
        assert_eq!(candidate.state, AdviceState::Proposed);
        assert_eq!(
            gate.direct_apply(&candidate),
            Err(AdviceRejected::DirectMutationForbidden)
        );

        // Owner-approved proposal produces a candidate record with a named
        // verifier and rollback condition.
        let approved = gate
            .record_owner_decision(
                candidate,
                &OwnerDecision::Approve {
                    verifier: "instrument-plane".to_owned(),
                    rollback: "revert merge on edge-time regression".to_owned(),
                },
            )
            .expect("owner approval binds verifier and rollback");
        assert_eq!(approved.state, AdviceState::OwnerApproved);
        assert_eq!(approved.verifier.as_deref(), Some("instrument-plane"));
        assert!(approved.rollback_plan.is_some());

        // Verifier failure rolls back and writes negative procedural memory.
        let rolled_back = gate
            .record_verifier_outcome(approved, false, "edge-time regressed")
            .expect("verifier outcome is recorded");
        assert_eq!(rolled_back.state, AdviceState::VerifierRolledBack);
        assert!(
            gate.negative_memory()
                .contains_key(&rolled_back.hypothesis_key)
        );

        // Re-submitting the same failed proposal without new discriminating
        // evidence is rejected with a visible reason.
        let blocked = gate.propose(&proposal(
            "merge dreamer probe crates",
            &["edge-time before/after"],
        ));
        match blocked {
            Err(AdviceRejected::NegativeMemoryBlock { reason, .. }) => {
                assert!(
                    reason.contains("edge-time regressed"),
                    "visible reason carries failure: {reason}"
                );
            }
            other => panic!("expected negative-memory block, got {other:?}"),
        }

        // The same hypothesis with a new discriminator is re-admitted.
        let readmitted = gate
            .propose(&proposal(
                "merge dreamer probe crates",
                &["edge-time before/after", "link-artifact size discriminator"],
            ))
            .expect("new discriminator re-admits the hypothesis");
        assert_eq!(readmitted.state, AdviceState::Proposed);

        // A rejected proposal also creates a negative-memory entry.
        let rejected = gate
            .record_owner_decision(
                readmitted,
                &OwnerDecision::Reject {
                    reason: "insufficient benefit".to_owned(),
                },
            )
            .expect("owner rejection is recorded");
        assert_eq!(rejected.state, AdviceState::OwnerRejected);
        gate.record_failure(&rejected, "owner rejected: insufficient benefit");
        assert!(
            gate.negative_memory()
                .contains_key(&rejected.hypothesis_key)
        );
    }
}
