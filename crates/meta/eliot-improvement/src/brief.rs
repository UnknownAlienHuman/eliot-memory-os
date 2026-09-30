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
//! constructor is [`SafeBoundary::from_observed_closure_record`], which takes both
//! values from a closure record an owner actually closed and that this crate
//! cannot name — `eliot-improvement` has no `eliot-learning-delta` edge, and the
//! record type is never spelled here:
//!
//! - `boundary_ref` is the `consequential_boundary` value
//!   `eliot_learning_delta::derive_boundaries` DERIVED from the lifecycle
//!   activities the same owner recorded
//!   (`crates/governor/eliot-governor/src/learning_closure.rs:498`), which
//!   refuses an ordinary read (`read_file`/`read`/`grep`) and an empty activity
//!   set outright (`crates/smart/eliot-learning-delta/src/boundary.rs:214-228`)
//!   before anything is committed. A committed record therefore IS an
//!   owner-observed consequential boundary, and I12.24:181 makes that derivation
//!   the definition of one.
//! - `active_main_agent_or_human_ref` is the `actor_id` the closure owner
//!   recorded for that attempt
//!   (`crates/governor/eliot-governor/src/learning_closure.rs:940`) — the
//!   identity that EXECUTED the consequential work, a principal rather than a
//!   label. `ASSUMPTION:` that actor is the "active Main Agent or Human" of
//!   I12.24:64, because it is the only principal the closure owner records and
//!   the closure seam records no Human identity; naming the maintenance owner
//!   constant instead would restate the literal this constructor exists to
//!   remove.
//!
//! # The caller is the DURABLE owner of that record, and this says so
//!
//! The values are read by the Governor, which owns the closure record and the
//! `eliot-learning-delta` decode
//! ([`eliot_governor::observed_closure_from_durable_rows`]), and handed here as
//! two owned strings. That indirection is deliberate and it is the reason the
//! provenance marker still means something: this crate cannot re-derive the
//! record, and it does not pretend to. A caller that reads the record from
//! anywhere but the durable owner can pass any two strings it likes — the
//! guarantee this constructor offers is that the boundary VALUES are the ones the
//! owner's committed record carries, and that guarantee is discharged by the
//! caller, exactly as `A12.02:3` ("Identity is not a model's self-declared
//! string") requires.
//!
//! An absent record, a record naming no principal, or a record naming no derived
//! boundary is [`ImprovementError::UnsafeBoundary`]. That is a deliberate
//! behaviour change: before this, the daemon's improvement pass always succeeded
//! because the gate read a literal; now it commits nothing until a consequential
//! attempt has actually been closed AND durably published. Failing closed is the
//! direction I12.24:64 requires — a brief must not reach an owner as though a
//! boundary had been observed when none was.
//!
//! # BYTES ARE NOT AN OBSERVATION
//!
//! Private fields are not a seal. `Deserialize` is a public trait impl and does
//! not go through them, so a caller could write two arbitrary non-empty strings
//! into any wire format and rebuild a `SafeBoundary` that
//! [`brief_at_safe_boundary`] accepts — the same gate the public fields used to
//! pass, reached by a different route. `SafeBoundary` therefore
//! carries a provenance marker that only
//! [`SafeBoundary::from_observed_closure_record`] sets and `Deserialize` skips,
//! so a boundary rebuilt from bytes cannot satisfy [`SafeBoundary::validate`]:
//! I12.24:64 asks for a brief at a boundary an owner actually closed, and a
//! re-serialized pair of strings is not one. `Serialize` is retained, so the two
//! observed values still round-trip into the durable learning record next to the
//! brief. What does not round-trip is the fact of the observation, which is a
//! fact about this process rather than about bytes.
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
//!
//! # The brief's IDENTITY is the candidate revision it describes
//!
//! I12.24:65 puts "decision owner selects reject / investigate / work item /
//! experiment" AFTER the brief reaches one, so an owner has to be able to NAME
//! the brief they are ruling on. That was impossible while `brief_id` was a
//! fresh `Uuid::now_v7()` minted on every call: the same brief over the same
//! candidate revision carried a different name on every pass, so no handle an
//! owner could hold, repeat, or hand to another principal existed, and a
//! disposition recorded against one pass's name named nothing on the next.
//!
//! `brief_id` is now derived from the candidate the brief is about — the
//! candidate's own content-derived `candidate_id` (which
//! `ImprovementCandidate::derive_candidate_id` hashes over project, target
//! surface, proposed change, both scope-rule sets, the source trace and the
//! canonical evidence lineage, and which deliberately excludes every per-pass
//! value) together with the `candidate_revision` this brief carries. No new
//! digest, nonce, MAC, or clock reading is introduced: the candidate id already
//! IS the deduplication handle, and a brief is about ONE candidate revision, so
//! one candidate revision has exactly one brief name — this pass, the next one,
//! and after a restart.
//!
//! The guarantee is deliberately ONE-DIRECTIONAL, and only that direction is
//! claimed. The same candidate at the same revision always yields the same
//! name, so a name identifies one brief revision. The converse is NOT claimed
//! and is not true: the brief's `problem`, `likely_benefit`, `risk`, `cost`,
//! `next_reversible_step` and `unknowns` are the CALLER's prose, and two
//! callers may word them differently over one candidate revision. The name
//! therefore names the decision subject — this improvement at this revision —
//! which is what a disposition selects over, and each committed brief still
//! carries its own full wording verbatim beside the name.
//!
//! `created_at` still reads the clock, and nothing here claims row
//! convergence. The store keys a learning row by `(record_kind, handle,
//! record_digest)`, so a re-commit whose `created_at` moved is a new digest and
//! therefore a new row under the same handle; that is the improvement owner's
//! own recorded expectation, unchanged by this derivation. What IS stable is
//! the NAME, and the name is what an owner's disposition is recorded against.
//!
//! A blank `candidate_id` is refused rather than formatted into a handle: the
//! handle's content component has to be real for the handle to name one brief
//! revision rather than every brief built over an unnamed candidate.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ImprovementCandidate, ImprovementError};

/// Advisory owner-facing brief over one candidate revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementBrief {
    /// Stable, owner-nameable identity of the brief over THIS candidate
    /// revision.
    ///
    /// Assigned by `brief_at_safe_boundary` from the candidate's own
    /// content-derived identity and revision, so one candidate revision has one
    /// name on every pass and across a restart, and an owner's disposition
    /// recorded against it names one brief revision rather than one pass over
    /// it. See the module section "The brief's IDENTITY is the candidate
    /// revision it describes" for the exact direction of that guarantee.
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
/// # The fields are private, and that is not by itself the gate
///
/// Both fields were public `String`s checked only for non-emptiness, so
/// `format!("owner:{OWNER}")` satisfied the gate on its own — a check reading a
/// literal. They are private now and
/// [`Self::from_observed_closure_record`] is the only constructor. Private alone
/// still left a second route, because
/// `Deserialize` is a public trait impl that ignores privacy: the provenance
/// marker below closes it. `Serialize`/`Deserialize` are retained so the two
/// observed values still round-trip into the durable learning record next to the
/// brief.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafeBoundary {
    /// Identity that executed the observed consequential attempt
    /// (`StoredLearningDelta::actor_id`).
    active_main_agent_or_human_ref: String,
    /// Derived consequential boundary the closure recorded
    /// (`StoredLearningDelta::consequential_boundary`).
    boundary_ref: String,
    /// Provenance of the observation itself, not a boundary attribute.
    ///
    /// `true` only on a value [`Self::from_observed_closure_record`] built from a
    /// committed closure record. `#[serde(skip)]` means the field is neither
    /// written nor read by `Serialize`/`Deserialize`, so a boundary rebuilt from
    /// bytes always arrives unmarked and is refused by [`Self::validate`] — the
    /// observation is a fact about this process and cannot be re-established
    /// from the two strings it produced.
    #[serde(skip)]
    observed: bool,
}

impl SafeBoundary {
    /// Builds the boundary from one owner-observed closure record's own values.
    ///
    /// `actor_id` and `consequential_boundary` are the two fields a committed
    /// [`eliot_learning_delta::StoredLearningDelta`] carries; neither is
    /// formatted, defaulted or synthesized here. The record TYPE is not named —
    /// this crate has no `eliot-learning-delta` edge and does not take one for a
    /// value it only quotes — and neither is the image it came from. The
    /// production caller is the durable owner of the record: it reads the
    /// committed rows and re-proves each one through
    /// [`eliot_governor::observed_closure_from_durable_rows`], so the values
    /// handed here are the ones an owner's committed record carries. This
    /// constructor performs no read, opens no transport and takes no store
    /// client, which is why it can be called from a phase that holds no
    /// composition guard.
    ///
    /// The provenance marker records that THIS constructor ran, not a third
    /// observed value: it is the one thing about a boundary that cannot arrive
    /// from outside this module, which is what makes [`Self::validate`] a gate
    /// rather than a shape check.
    ///
    /// # Errors
    ///
    /// [`ImprovementError::UnsafeBoundary`] when a value is blank or
    /// whitespace-only, i.e. when the record it came from names no principal or
    /// no derived boundary. An absent observation is a refusal at the caller,
    /// never a substituted constant.
    pub fn from_observed_closure_record(
        actor_id: &str,
        consequential_boundary: &str,
    ) -> Result<Self, ImprovementError> {
        let boundary = Self {
            active_main_agent_or_human_ref: actor_id.to_owned(),
            boundary_ref: consequential_boundary.to_owned(),
            observed: true,
        };
        boundary.validate()?;
        Ok(boundary)
    }

    /// The observed principal this boundary was read from.
    ///
    /// Read-only: it hands back the `actor_id`
    /// [`Self::from_observed_closure_record`] was given from the committed record
    /// and cannot be used to change the boundary. An owner-facing brief takes this
    /// value as its `proposed_owner` so the name it proposes and the name its gate
    /// observed are one principal (see the module documentation).
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

    /// Rejects a boundary that was not observed, or names no principal and no
    /// derived boundary.
    ///
    /// The provenance requirement is what seals the gate. Private fields stop a
    /// Rust caller from spelling the struct, but `Deserialize` is a public trait
    /// impl that never reads them, so two arbitrary non-empty strings rebuilt
    /// from any wire format would otherwise pass this check and reach
    /// [`brief_at_safe_boundary`] as though a closure had been observed — the
    /// literal-shaped gate this module exists to remove, one serde route away.
    /// The empty-shape check remains because the observed record's own fields
    /// are what the other half reads.
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if !self.observed
            || self.active_main_agent_or_human_ref.trim().is_empty()
            || self.boundary_ref.trim().is_empty()
        {
            return Err(ImprovementError::UnsafeBoundary);
        }
        Ok(())
    }
}

/// The brief's stable identity over one candidate revision.
///
/// I12.24:65 places "decision owner selects reject / investigate / work item /
/// experiment" after the brief reaches an owner, and I12.24:74 says the named
/// decision owner does not search raw metrics. Both require the owner to be
/// able to NAME the brief they rule on, so the name has to survive a
/// re-observation.
///
/// The two components are the candidate's OWN recorded identity, read
/// verbatim:
///
/// - `candidate.candidate_id` is the content-derived digest
///   `ImprovementCandidate::new` computes over project, target surface,
///   proposed change, both scope-rule sets, the source trace and the canonical
///   evidence lineage, excluding `created_at`, `updated_at`, `revision` and
///   `lifecycle` precisely so a re-observation yields the same value. It is
///   therefore already the deduplication handle; nothing is re-hashed here and
///   no second identity scheme is introduced.
/// - `candidate.revision` is the revision this brief states, so a brief over a
///   NEWER candidate revision is a DIFFERENT brief and cannot be confused with
///   the one an owner already ruled on. `transition`, `transition_lifecycle`
///   and `promotion_lifecycle` advance it monotonically, so the two components
///   together name one brief revision.
///
/// The spelling mirrors the one the store's own record keys already use for a
/// revisioned improvement record — `improvement-merge:<candidate_id>@<revision>`
/// (`improvement_intake_dispatch::lineage_merge_record_key`) — so a brief id
/// and a merge-record key over the same entry read the same way.
///
/// # A blank `candidate_id` is refused, not formatted
///
/// [`brief_at_safe_boundary`] validates the candidate before calling this, but
/// `ImprovementCandidate::validate` does not itself require `candidate_id` to
/// be non-empty, so a value rebuilt from bytes could otherwise produce the
/// degenerate handle `brief-@<revision>`, which names no brief revision and
/// collides across every candidate. This is the same refusal
/// `canonical_evidence_lineage` and the deduplication registry already apply to
/// a nameless candidate, and it is a check on the ORIGINAL recorded value.
fn brief_identity(candidate: &ImprovementCandidate) -> Result<String, ImprovementError> {
    let candidate_id = candidate.candidate_id.trim();
    non_empty(candidate_id, "candidate_id")?;
    Ok(format!("brief-{candidate_id}@{}", candidate.revision))
}

/// Build a brief for `candidate` at `boundary`.
///
/// Validates the boundary first, then the candidate, then the brief fields.
/// The brief carries the candidate's evidence refs and revision by value, and
/// its `brief_id` is derived by `brief_identity` from that same candidate
/// revision rather than minted per call — see the module section "The brief's
/// IDENTITY is the candidate revision it describes".
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
        brief_id: brief_identity(candidate)?,
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
