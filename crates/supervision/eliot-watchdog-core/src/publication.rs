//! Bounded, deterministic Problem/attention publication intents.
//!
//! I8.1 / I13.7 boundary: the Watchdog publishes a *publication intent* about
//! one evidence-backed Signal; canonical Problem, attention and Incident policy
//! is owned by #1759 and the Governor performs the canonical transition. This
//! module therefore has no Incident-declaring variant to construct: the only
//! classes it can name are a Problem attention intent and an Incident
//! *candidate* attention intent, and an `incident_candidate` severity produces
//! the latter.
//!
//! Determinism: the decision is a pure function of one immutable signal
//! revision, one owner-issued [`AttentionPolicy`], and the distinct
//! evidence identities already counted for that signal under that policy
//! revision. It reads no clock, opens no file, and mutates nothing.
//!
//! Repeated delivery cannot cross a threshold by itself. A signal revision
//! whose evidence identities are all already counted returns
//! [`PublicationDecision::RepeatedDelivery`], which advances nothing and
//! mints nothing; only evidence that is not already counted contributes to the
//! distinct count, so a retransmitted observation can never push a signal over
//! its threshold.
//!
//! Unsupported history is not a success default: a signal whose evidence
//! references are unavailable returns
//! [`PublicationDecision::EvidenceUnavailable`] with the recorded limitation
//! instead of crossing on a count it cannot substantiate.

use crate::rules::encode_identity;
use crate::signals::{
    ObservedTime, RecordedValue, RuleRevision, Signal, SignalId, SignalReferences, SignalSeverity,
    SignalTarget, SignalValidationError, positive, text,
};

/// Owner-issued attention policy: its identity, its immutable revision, and the
/// distinct-evidence thresholds each severity class must reach.
///
/// The thresholds are a Config-owned value rather than an invariant: the policy
/// revision is carried into every decision so a later policy revision states
/// which thresholds a publication intent was actually decided under, and a
/// signal already published under one revision is not re-decided under another
/// without being re-offered with its evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionPolicy {
    policy_id: String,
    revision: u64,
    problem_evidence_threshold: usize,
    incident_candidate_evidence_threshold: usize,
}

impl AttentionPolicy {
    /// Binds one owner-issued attention policy; fails closed on any bound
    /// violation.
    ///
    /// # Errors
    ///
    /// Returns [`SignalValidationError`] when the policy identity is blank or
    /// carries control characters, when the revision is uninitialized, or when
    /// either threshold is zero.
    pub fn new(
        policy_id: String,
        revision: u64,
        problem_evidence_threshold: usize,
        incident_candidate_evidence_threshold: usize,
    ) -> Result<Self, SignalValidationError> {
        text(&policy_id, "policy_id")?;
        positive(revision, "policy_revision")?;
        if problem_evidence_threshold == 0 {
            return Err(SignalValidationError::ZeroValue(
                "problem_evidence_threshold",
            ));
        }
        if incident_candidate_evidence_threshold == 0 {
            return Err(SignalValidationError::ZeroValue(
                "incident_candidate_evidence_threshold",
            ));
        }
        Ok(Self {
            policy_id,
            revision,
            problem_evidence_threshold,
            incident_candidate_evidence_threshold,
        })
    }
}

/// Observation label of one publication intent.
///
/// There is deliberately no Incident-declaring variant: this type cannot
/// express a canonical Incident decision, so an `incident_candidate` severity
/// reaches #1759 as a candidate intent and nothing more.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationClass {
    /// A Problem attention intent: evidence-backed, not a canonical Problem.
    ProblemAttention,
    /// An Incident-candidate attention intent: evidence-backed severity, not a
    /// canonical Incident declaration.
    IncidentCandidateAttention,
}

impl PublicationClass {
    /// Returns the exact intent class name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProblemAttention => "problem_attention_intent",
            Self::IncidentCandidateAttention => "incident_candidate_attention_intent",
        }
    }
}

/// One linked publication intent over a single immutable signal revision.
///
/// It is evidence about the Watchdog's own observation. It declares no
/// canonical Problem, attention closure, or Incident, it authorizes no
/// containment, and its presence is not a resolution of anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationIntent {
    /// Stable identity derived from the signal, the policy, and the class, so
    /// the same crossing decided twice names the same intent.
    pub intent_id: String,
    /// Identity of the signal this intent is linked to.
    pub signal_id: SignalId,
    /// Exact immutable signal revision this intent was decided from.
    pub signal_revision: u64,
    /// Rule identity and revision that produced the signal.
    pub rule: RuleRevision,
    /// Owner-issued policy identity and revision the threshold was decided
    /// under.
    pub policy_id: String,
    /// The immutable policy revision the crossing is bound to.
    pub policy_revision: u64,
    /// Observation label of this intent.
    pub class: PublicationClass,
    /// Exact subject, scope and generation observed.
    pub target: SignalTarget,
    /// Observed time and clock domain of the crossing observation.
    pub observed_at: RecordedValue<ObservedTime>,
    /// The exact distinct evidence identities this revision contributes to the
    /// crossing. An already-counted identity never appears here, so a
    /// retransmission contributes nothing to this list.
    pub crossing_evidence: Vec<String>,
    /// Total distinct evidence counted for this signal under this policy
    /// revision at the crossing, which is the count the threshold was compared
    /// against.
    pub distinct_evidence_count: usize,
    /// The signal's own deduplication key, carried so a later revision of the
    /// same failure episode is correlated rather than republished.
    pub dedup_key: RecordedValue<String>,
}

/// Deterministic result of evaluating one signal revision against one policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationDecision {
    /// The revision contributes no evidence that is not already counted, so it
    /// is a repeated delivery. It advances nothing and mints nothing, which is
    /// what keeps a retransmitted observation from crossing a threshold by
    /// itself.
    RepeatedDelivery {
        /// Distinct evidence already counted for this signal and policy.
        distinct_evidence_count: usize,
    },
    /// The signal records no usable evidence references, so no threshold can be
    /// substantiated. The recorded limitation travels with the decision.
    EvidenceUnavailable {
        /// The historical limitation the signal itself recorded.
        limitation: String,
    },
    /// The signal's severity does not request attention, so no publication
    /// intent is derivable from it regardless of the evidence count.
    NotAttention {
        /// The severity that excluded publication.
        severity: SignalSeverity,
    },
    /// Distinct evidence is accumulating but has not reached the threshold this
    /// severity requires.
    BelowThreshold {
        /// Distinct evidence counted for this signal and policy so far.
        distinct_evidence_count: usize,
        /// The threshold this severity requires.
        required: usize,
    },
    /// The threshold is crossed: exactly one publication intent is linked to
    /// this signal revision and this policy revision.
    Publish(Box<PublicationIntent>),
}

/// Decides whether one evidence-backed signal revision crosses the attention
/// threshold its severity requires under `policy`.
///
/// `counted_evidence` is the exact set of distinct evidence identities already
/// counted for this signal under this policy revision, as the durable owner
/// holds it. This function never extends that set itself; the owner persists
/// [`PublicationDecision::Publish`]'s `crossing_evidence` beside its
/// threshold state, and a replay of the same identities therefore returns
/// [`PublicationDecision::RepeatedDelivery`] rather than a second intent.
///
/// # Errors
///
/// Returns [`SignalValidationError`] when an already-counted evidence identity
/// is blank or carries control characters. A blank or control-charactered
/// identity is refused rather than counted, so a malformed durable row cannot
/// be laundered into distinct evidence that crosses a threshold.
pub fn evaluate_publication_intent(
    signal: &Signal,
    policy: &AttentionPolicy,
    counted_evidence: &[String],
) -> Result<PublicationDecision, SignalValidationError> {
    let revision = signal.revision();
    for identity in counted_evidence {
        text(identity, "counted_evidence")?;
    }
    let references = match &revision.evidence {
        SignalReferences::Known(references) => references,
        SignalReferences::Unknown { limitation } => {
            return Ok(PublicationDecision::EvidenceUnavailable {
                limitation: limitation.clone(),
            });
        }
    };
    // Only evidence this revision adds counts. Identities the owner already
    // counted are skipped, and identities repeated inside one revision are
    // collapsed, so neither a retransmitted observation nor a duplicated
    // reference can raise the distinct count.
    let mut crossing_evidence: Vec<String> = Vec::new();
    for reference in references {
        if !crossing_evidence.contains(&reference.evidence_id)
            && !counted_evidence.contains(&reference.evidence_id)
        {
            crossing_evidence.push(reference.evidence_id.clone());
        }
    }
    let distinct_evidence_count = counted_evidence.len() + crossing_evidence.len();
    if crossing_evidence.is_empty() {
        return Ok(PublicationDecision::RepeatedDelivery {
            distinct_evidence_count,
        });
    }
    let (class, required) = match revision.severity {
        SignalSeverity::Info => {
            return Ok(PublicationDecision::NotAttention {
                severity: SignalSeverity::Info,
            });
        }
        SignalSeverity::Warning | SignalSeverity::Blocking => (
            PublicationClass::ProblemAttention,
            policy.problem_evidence_threshold,
        ),
        SignalSeverity::IncidentCandidate => (
            PublicationClass::IncidentCandidateAttention,
            policy.incident_candidate_evidence_threshold,
        ),
    };
    if distinct_evidence_count < required {
        return Ok(PublicationDecision::BelowThreshold {
            distinct_evidence_count,
            required,
        });
    }
    let intent_id = encode_identity(&[
        revision.signal_id.0.clone(),
        revision.revision.to_string(),
        policy.policy_id.clone(),
        policy.revision.to_string(),
        class.as_str().to_owned(),
    ]);
    Ok(PublicationDecision::Publish(Box::new(PublicationIntent {
        intent_id,
        signal_id: revision.signal_id.clone(),
        signal_revision: revision.revision,
        rule: revision.rule.clone(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.revision,
        class,
        target: revision.target.clone(),
        observed_at: revision.observed_at.clone(),
        crossing_evidence,
        distinct_evidence_count,
        dedup_key: revision.dedup_key.clone(),
    })))
}
