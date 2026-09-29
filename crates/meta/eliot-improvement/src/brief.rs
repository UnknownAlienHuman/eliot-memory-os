//! Owner-facing improvement brief at a safe boundary (I12.24:74).
//!
//! `ImprovementBrief` shows problem, evidence, likely benefit, risk, proposed
//! owner, cost, next reversible step and what remains unknown. The named
//! decision owner does not search raw metrics: [`record_owner_decision`]
//! only records the owner's disposition over an already-validated brief and
//! mutates nothing. Briefs are constructed only via
//! [`brief_at_safe_boundary`], which requires an active Main Agent or Human
//! reference at a safe boundary.
//!
//! # The boundary is OBSERVED, never NAMED
//!
//! I12.24:64 puts the brief "to active Main Agent or Human at a safe boundary".
//! [`SafeBoundary`] therefore has NO public fields and NO literal constructor:
//! with public fields, any caller satisfied the gate by formatting two strings,
//! which proves nothing about the operation it claims to gate. Its only
//! constructor is [`SafeBoundary::from_observed_closure`], which reads the
//! Governor's OWN committed learning-closure image
//! ([`eliot_governor::CanonicalLearningDeltaStore`]) and takes both values from
//! a record an owner actually closed:
//!
//! - `boundary_ref` is the `consequential_boundary` value
//!   `eliot_learning_delta::derive_boundaries` DERIVED from the lifecycle
//!   activities the same owner recorded
//!   (`crates/governor/eliot-governor/src/learning_closure.rs:483`), which
//!   refuses an ordinary read (`read_file`/`read`/`grep`) and an empty activity
//!   set outright (`crates/smart/eliot-learning-delta/src/boundary.rs:214-228`)
//!   before anything is committed. A record in that image IS therefore an
//!   owner-observed consequential boundary, and I12.24:181 makes that derivation
//!   the definition of one. The boundary type itself is never named here: the
//!   reading of the record's own public field is the whole observation.
//! - `active_main_agent_or_human_ref` is the `actor_id` the closure owner
//!   recorded for that attempt
//!   (`crates/governor/eliot-governor/src/learning_closure.rs:844`) — the
//!   identity that EXECUTED the consequential work, a principal rather than a
//!   label. `ASSUMPTION:` that actor is the "active Main Agent or Human" of
//!   I12.24:64, because it is the only principal the closure owner records and
//!   the closure seam records no Human identity; naming the maintenance owner
//!   constant instead would restate the literal this constructor exists to
//!   remove.
//!
//! An empty image, an unreadable image, or a record naming no principal is
//! [`ImprovementError::UnsafeBoundary`]. That is a deliberate behaviour change:
//! before this, the daemon's improvement pass always succeeded because the gate
//! read a literal; now it commits nothing until a consequential attempt has
//! actually been closed. Failing closed is the direction I12.24:64 requires — a
//! brief must not reach an owner as though a boundary had been observed when
//! none was.
//!
//! # The brief's `proposed_owner` and its boundary are ONE principal
//!
//! I12.24:64 sends the brief "to active Main Agent or Human at a safe
//! boundary" and I12.24:74 requires the brief to state a "proposed owner".
//! Those are two clauses of one decision, so a brief over an observed boundary
//! takes `proposed_owner` from
//! [`SafeBoundary::observed_principal_ref`] — the same `actor_id` the boundary
//! gate was built from — rather than from a second, unrelated name. A brief that
//! says "produced at a boundary actor X observed" while proposing owner Y reads
//! as though two principals were involved in producing it, and a reader cannot
//! tell from the artifact which of them decides.
//!
//! [`SafeBoundary::observed_boundary_ref`] is the matching read-only handle for
//! the derived boundary itself, so a caller can name the same two values in the
//! brief's own text that the gate enforced.
//!
//! The roles that ARE genuinely different live on different artifacts, not in
//! adjacent fields of this one, and this module does not merge them:
//!
//! - the boundary's principal EXECUTED the observed consequential attempt, and
//!   is the principal this brief proposes should decide;
//! - a candidate's ADMISSION authority is a separate owner decision, recorded
//!   on [`ImprovementCandidate::owner_and_decision_authority`], and is what
//!   admits the candidate to the backlog.
//!
//! `brief_at_safe_boundary` takes `proposed_owner` as a parameter rather than
//! deriving it, because `intake_from_evidence` supplies both the boundary and
//! the owner from its own request; it therefore cannot be checked here without
//! constraining that caller. The relationship above is the contract, and the
//! production caller is held to it.

use eliot_governor::CanonicalLearningDeltaStore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ImprovementCandidate, ImprovementError};

/// Advisory owner-facing brief over one candidate revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementBrief {
    pub brief_id: String,
    pub candidate_id: String,
    pub candidate_revision: u64,
    pub problem: String,
    pub evidence_refs: Vec<String>,
    pub likely_benefit: String,
    pub risk: String,
    pub proposed_owner: String,
    pub cost: String,
    pub next_reversible_step: String,
    pub unknowns: Vec<String>,
    pub created_at: OffsetDateTime,
}

impl ImprovementBrief {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        non_empty(&self.brief_id, "brief_id")?;
        non_empty(&self.candidate_id, "candidate_id")?;
        non_empty(&self.problem, "problem")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        non_empty(&self.likely_benefit, "likely_benefit")?;
        non_empty(&self.risk, "risk")?;
        non_empty(&self.proposed_owner, "proposed_owner")?;
        non_empty(&self.cost, "cost")?;
        non_empty(&self.next_reversible_step, "next_reversible_step")?;
        require_refs(&self.unknowns, "unknowns")?;
        Ok(())
    }
}

/// Owner disposition over a brief; recording mutates nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerDecisionKind {
    Reject,
    Investigate,
    WorkItem,
    Experiment,
}

/// Pure record of the named owner's decision on a brief.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OwnerDecision {
    pub brief_id: String,
    pub candidate_id: String,
    pub owner: String,
    pub kind: OwnerDecisionKind,
    pub note: String,
    pub decided_at: OffsetDateTime,
}

impl OwnerDecision {
    pub fn is_non_mutating(&self) -> bool {
        matches!(
            self.kind,
            OwnerDecisionKind::Reject | OwnerDecisionKind::Investigate
        )
    }
}

/// Safe-boundary gate: an active Main Agent or Human plus a boundary ref.
///
/// # The fields are private, and that is the gate
///
/// Both fields were public `String`s checked only for non-emptiness, so
/// `format!("owner:{OWNER}")` satisfied the gate on its own — a check reading a
/// literal. They are private now and [`Self::from_observed_closure`] is the
/// only constructor, so both values must come from a record the Governor's
/// learning-closure owner actually committed. `Serialize`/`Deserialize` are
/// retained so the two observed values still round-trip into the durable
/// learning record next to the brief.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafeBoundary {
    /// Identity that executed the observed consequential attempt
    /// (`StoredLearningDelta::actor_id`).
    active_main_agent_or_human_ref: String,
    /// Derived consequential boundary the closure recorded
    /// (`StoredLearningDelta::consequential_boundary`).
    boundary_ref: String,
}

impl SafeBoundary {
    /// Read the boundary from the owner-observed closure image.
    ///
    /// `store` is the single Governor-owned
    /// [`eliot_governor::CanonicalLearningDeltaStore`] this process already
    /// holds (`DaemonComposition::learning_closure().store()`). This is a read
    /// of already-committed in-process state: it opens no transport, no store
    /// client and no new durability path. The store's own mutex is taken by
    /// [`CanonicalLearningDeltaStore::load`], so the caller must invoke this
    /// under whatever guard already serializes composition access.
    ///
    /// The MOST RECENT committed record is the observed boundary:
    /// [`eliot_governor::LearningClosureService::close_attempt`] appends one
    /// record per consequential closure
    /// (`crates/governor/eliot-governor/src/learning_closure.rs:293-303`), so
    /// the last element is the newest owner-observed consequential boundary
    /// this process holds. Both values on the result are that record's own
    /// fields; neither is formatted, defaulted or synthesized here.
    ///
    /// # Errors
    ///
    /// [`ImprovementError::UnsafeBoundary`] when the image cannot be read, when
    /// it is empty (no consequential closure has been observed at all), or when
    /// the newest record names no principal. An absent observation is a
    /// refusal, never a substituted constant.
    pub fn from_observed_closure(
        store: &CanonicalLearningDeltaStore,
    ) -> Result<Self, ImprovementError> {
        let (records, _version) = store.load().map_err(|_| ImprovementError::UnsafeBoundary)?;
        let record = records.last().ok_or(ImprovementError::UnsafeBoundary)?;
        // `consequential_boundary` is not named as a type here: this crate has
        // no `eliot-learning-delta` edge, and reading the record's own public
        // field is the entire observation. `as_str` is the boundary's own
        // canonical spelling, so the recorded name is the owner's closed
        // vocabulary rather than a string spelled at this call site.
        let boundary = Self {
            active_main_agent_or_human_ref: record.actor_id.clone(),
            boundary_ref: record.consequential_boundary.as_str().to_owned(),
        };
        boundary.validate()?;
        Ok(boundary)
    }

    /// The observed principal this boundary was read from.
    ///
    /// Read-only: it hands back the `actor_id` [`Self::from_observed_closure`]
    /// read from the committed record and cannot be used to change the
    /// boundary. An owner-facing brief takes this value as its `proposed_owner`
    /// so the name it proposes and the name its gate observed are one principal
    /// (see the module documentation).
    pub fn observed_principal_ref(&self) -> &str {
        &self.active_main_agent_or_human_ref
    }

    /// The derived consequential boundary the owner observed.
    ///
    /// Read-only counterpart of [`Self::observed_principal_ref`]: the
    /// `consequential_boundary` spelling the closure record itself committed.
    /// A brief that describes the operation it is gated on names this value, so
    /// the described boundary and the enforced one cannot differ.
    pub fn observed_boundary_ref(&self) -> &str {
        &self.boundary_ref
    }

    /// Rejects a boundary that names no principal or no derived boundary.
    ///
    /// This is a shape check over values [`Self::from_observed_closure`] read
    /// from a committed record. It cannot be satisfied by a formatted constant
    /// because the struct has no public constructor; it is kept because a
    /// deserialized boundary reaches the same gate through
    /// [`brief_at_safe_boundary`].
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.active_main_agent_or_human_ref.trim().is_empty()
            || self.boundary_ref.trim().is_empty()
        {
            return Err(ImprovementError::UnsafeBoundary);
        }
        Ok(())
    }
}

/// Build a brief for `candidate` at `boundary`.
///
/// Validates the boundary first, then the candidate, then the brief fields.
/// The brief carries the candidate's evidence refs and revision by value.
///
/// `proposed_owner` is a parameter, not a value read from `boundary`, because
/// `intake_from_evidence` supplies the boundary and the owner from its own
/// request. Over an OBSERVED boundary the two are one principal, so pass
/// `boundary.observed_principal_ref()` here; see the module documentation for
/// why an admission authority is the wrong name for this field.
#[allow(
    clippy::too_many_arguments,
    reason = "brief assembly takes one concise field per I12.24:74 decision slot"
)]
pub fn brief_at_safe_boundary(
    candidate: &ImprovementCandidate,
    problem: &str,
    likely_benefit: &str,
    risk: &str,
    proposed_owner: &str,
    cost: &str,
    next_reversible_step: &str,
    unknowns: Vec<String>,
    boundary: &SafeBoundary,
) -> Result<ImprovementBrief, ImprovementError> {
    boundary.validate()?;
    candidate.validate()?;
    non_empty(problem, "problem")?;
    non_empty(likely_benefit, "likely_benefit")?;
    non_empty(risk, "risk")?;
    non_empty(proposed_owner, "proposed_owner")?;
    non_empty(cost, "cost")?;
    non_empty(next_reversible_step, "next_reversible_step")?;
    require_refs(&unknowns, "unknowns")?;
    Ok(ImprovementBrief {
        brief_id: Uuid::now_v7().to_string(),
        candidate_id: candidate.candidate_id.clone(),
        candidate_revision: candidate.revision,
        problem: problem.to_string(),
        evidence_refs: candidate.evidence_refs.clone(),
        likely_benefit: likely_benefit.to_string(),
        risk: risk.to_string(),
        proposed_owner: proposed_owner.to_string(),
        cost: cost.to_string(),
        next_reversible_step: next_reversible_step.to_string(),
        unknowns,
        created_at: OffsetDateTime::now_utc(),
    })
}

/// Record the named owner's decision over an already-validated brief.
///
/// Pure record construction: validates the brief, owner, and note, then
/// returns the decision. Records mutate nothing.
pub fn record_owner_decision(
    brief: &ImprovementBrief,
    owner: &str,
    kind: OwnerDecisionKind,
    note: &str,
) -> Result<OwnerDecision, ImprovementError> {
    brief.validate()?;
    non_empty(owner, "owner")?;
    non_empty(note, "note")?;
    Ok(OwnerDecision {
        brief_id: brief.brief_id.clone(),
        candidate_id: brief.candidate_id.clone(),
        owner: owner.to_string(),
        kind,
        note: note.to_string(),
        decided_at: OffsetDateTime::now_utc(),
    })
}

fn non_empty(value: &str, field: &'static str) -> Result<(), ImprovementError> {
    if value.trim().is_empty() {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_refs(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}
