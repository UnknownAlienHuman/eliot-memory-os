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
//!
//! # D-DRM-NEG-1 — an OPEN, deliberate divergence from the admitted owner
//!
//! [`NegativeMemoryEntry`] is a second negative-memory state shape. The
//! ADMITTED owner of the durable negative-memory rule is cell
//! `smart.dreamer.failure` (`crates/smart/eliot-dreamer-failure`, whose
//! `NegativeMemoryFingerprint` is the only current durable record), and it is
//! strictly stronger on every dimension this type names: a typed exact
//! trigger predicate, an owner-issued affected scope with a non-empty resource
//! set, a recomputed record digest, a mandatory reopen condition with a named
//! verifier, a mandatory discriminating check, and an
//! owner-admitted `NegativeMemoryActionPolicy`.
//!
//! This shape keys negative memory on a free-text hypothesis key —
//! `<class>:<whitespace-folded lowercased statement>` — with no failed action,
//! no trigger predicate, no affected scope and no policy. It is KEPT, not
//! closed, and the divergence is recorded here rather than hidden, because
//! closing it is not a deletion: the admitted owner admits an exact typed
//! predicate or refuses, and has no path that accepts a model-authored prose
//! key, so deleting this type would drop a capability rather than migrate one.
//! The exact precondition is recorded in
//! `crates/smart/eliot-dreamer-core/disposition.module.toml`
//! (`[[work_item_4_negative_memory_owner_reevaluation]]`). It must not be read
//! as the canonical failure memory of I12.19, and it acquires no
//! admission, blocking power, authority or Finish role of its own.

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
/// A14.3 roles carried here: the exact deterministic trigger is
/// [`AdviceCandidate::hypothesis_key`], the failed action is the candidate
/// statement plus class, the outcome is `failure_reason`, and the reopen
/// condition is "a new discriminator beyond `known_discriminators`".
/// Violated invariant, scope, and extinction condition have no producer:
/// neither owner decisions nor verifier outcomes supply them.
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

/// Change-control gate. Holds the committed candidate ledger and negative
/// procedural memory. Records stay durable through the gate's serde snapshot;
/// the snapshot store owner is external, since this module holds no
/// filesystem, store, or runtime handles.
///
/// Every committed record is returned by the mutator that committed it
/// ([`AdviceGate::propose`], [`AdviceGate::record_owner_decision`],
/// [`AdviceGate::record_verifier_outcome`]). The two extra read accessors
/// `candidates` and `candidate` were removed in #1143 work item 4: they had an
/// empty caller set across the whole workspace, so they were a second way to
/// observe the same private ledger with no reader, not an owner of it.
///
/// Every text value this gate admits or commits is trimmed by the single
/// private owner `trim_to_owned`, and every discriminator and hypothesis
/// statement is folded by the single private owner `fold_whitespace`. The two
/// are deliberately different rules: a committed record keeps its internal
/// spacing, a hypothesis key folds it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdviceGate {
    negative_memory: BTreeMap<String, NegativeMemoryEntry>,
    #[serde(default)]
    candidates: BTreeMap<String, AdviceCandidate>,
}

impl AdviceGate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            negative_memory: BTreeMap::new(),
            candidates: BTreeMap::new(),
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

    /// Admit a proposal as a `Proposed` candidate record and commit it to
    /// the durable ledger.
    ///
    /// Rejects blank fields, missing discriminating evidence, and any
    /// re-submission of a negatively-remembered hypothesis that carries no
    /// new discriminator.
    pub fn propose(
        &mut self,
        proposal: &AdviceProposal,
    ) -> Result<AdviceCandidate, AdviceRejected> {
        for (field, value) in [
            ("statement", proposal.statement.as_str()),
            ("expected_benefit", proposal.expected_benefit.as_str()),
            (
                "cost_counter_metrics",
                proposal.cost_counter_metrics.as_str(),
            ),
            ("owner", proposal.owner.as_str()),
        ] {
            if trim_to_owned(value).is_empty() {
                return Err(AdviceRejected::BlankField(field));
            }
        }
        let evidence: Vec<String> = proposal
            .discriminating_evidence
            .iter()
            .map(|item| fold_whitespace(item.as_str()))
            .filter(|item| !item.is_empty())
            .collect();
        if evidence.is_empty() {
            return Err(AdviceRejected::MissingEvidence);
        }
        let hypothesis_key = Self::hypothesis_key_for(proposal.advice_class, &proposal.statement);
        self.check_negative_block(&hypothesis_key, &evidence)?;
        let candidate = AdviceCandidate {
            hypothesis_key,
            statement: trim_to_owned(&proposal.statement),
            advice_class: proposal.advice_class,
            discriminating_evidence: evidence,
            expected_benefit: trim_to_owned(&proposal.expected_benefit),
            cost_counter_metrics: trim_to_owned(&proposal.cost_counter_metrics),
            owner: trim_to_owned(&proposal.owner),
            verifier: None,
            rollback_plan: None,
            state: AdviceState::Proposed,
        };
        self.commit(&candidate);
        Ok(candidate)
    }

    /// Commit a candidate record to the durable ledger, keyed by hypothesis.
    fn commit(&mut self, candidate: &AdviceCandidate) {
        self.candidates
            .insert(candidate.hypothesis_key.clone(), candidate.clone());
    }

    /// Apply the owner decision and commit the resulting record. Approval
    /// binds a named verifier and a rollback condition; rejection parks the
    /// candidate as `OwnerRejected` and records its reason in negative memory.
    pub fn record_owner_decision(
        &mut self,
        mut candidate: AdviceCandidate,
        decision: &OwnerDecision,
    ) -> Result<AdviceCandidate, AdviceRejected> {
        if candidate.state != AdviceState::Proposed {
            return Err(AdviceRejected::NotDecidable(candidate.hypothesis_key));
        }
        match decision {
            OwnerDecision::Approve { verifier, rollback } => {
                if trim_to_owned(verifier).is_empty() {
                    return Err(AdviceRejected::MissingVerifier);
                }
                if trim_to_owned(rollback).is_empty() {
                    return Err(AdviceRejected::MissingRollback);
                }
                candidate.verifier = Some(trim_to_owned(verifier));
                candidate.rollback_plan = Some(trim_to_owned(rollback));
                candidate.state = AdviceState::OwnerApproved;
                self.commit(&candidate);
                Ok(candidate)
            }
            OwnerDecision::Reject { reason } => {
                candidate.state = AdviceState::OwnerRejected;
                self.record_failure(&candidate, reason);
                self.commit(&candidate);
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
        let trimmed = trim_to_owned(reason);
        let reason = if trimmed.is_empty() {
            "unspecified failure"
        } else {
            trimmed.as_str()
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

    /// Record the named verifier outcome and commit the terminal record. A
    /// pass retains the candidate; a failure rolls it back and writes
    /// negative procedural memory.
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
            self.commit(&candidate);
            Ok(candidate)
        } else {
            candidate.state = AdviceState::VerifierRolledBack;
            self.record_failure(&candidate, detail);
            self.commit(&candidate);
            Ok(candidate)
        }
    }

    /// Proposal-only ceiling proof: no Dreamer output can directly invoke
    /// write, promotion, or execution capabilities. This always fails.
    pub fn direct_apply(&self, _candidate: &AdviceCandidate) -> Result<(), AdviceRejected> {
        Err(AdviceRejected::DirectMutationForbidden)
    }
}

/// The single owner of the advice-text whitespace fold.
///
/// `AdviceGate::propose` folded every discriminator and
/// `AdviceGate::hypothesis_key_for` folded the statement through two separate
/// copies of this rule. #1143 work item 4 collapsed them into this one owner
/// so the fold cannot drift into two disagreeing normalization paths. Case
/// folding is deliberately NOT here: it belongs to the hypothesis key alone,
/// because discriminator identity is case-significant and
/// [`AdviceGate::record_failure`] accumulates it verbatim.
fn fold_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The single owner of the committed-text edge trim.
///
/// The value a record commits — the proposal's four admitted fields, the
/// owner's named verifier and rollback condition, and the recorded failure
/// reason — was trimmed with `value.trim().to_owned()` written out at seven
/// sites across `AdviceGate::propose`, `AdviceGate::record_owner_decision` and
/// `AdviceGate::record_failure`, and blank-checked with
/// `value.trim().is_empty()` at two more. Seven copies of one commit rule can
/// drift into committing differently-shaped values for the same input, which
/// is the duplication work item 4 removes. All of them now read this one
/// private owner.
///
/// `trim_to_owned` deliberately stays separate from `fold_whitespace`: a
/// committed record keeps its internal spacing and only loses its edges, while
/// the hypothesis key folds internal whitespace and lowercases. Merging them
/// would silently rewrite committed values, so the two rules stay distinct
/// owners with distinct jobs.
fn trim_to_owned(value: &str) -> String {
    value.trim().to_owned()
}

fn normalise_statement(statement: &str) -> String {
    fold_whitespace(statement).to_lowercase()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
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
