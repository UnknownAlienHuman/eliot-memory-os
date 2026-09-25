//! Governor-owned canonical bank/feedback admission and projection supply (B223).
//!
//! This module is the Governor enumeration/admission lane for the admitted
//! record schemas in `eliot-observation-contracts::experience_records`. It
//! owns:
//!
//! - [`admit_bank_record`] / [`admit_feedback_record`]: pure semantic
//!   admission. Journal-derived provenance is checked (non-empty unique
//!   source refs for bank; explicit consent for feedback), scope/fence are
//!   validated through the foundation contract, and the owner digest is
//!   computed at admission. No database write occurs here: the admitted
//!   record enters the canonical path as a `capture_candidate`
//!   `CommitExperienceBank` / `CommitAgentFeedback` payload
//!   through the existing Governor → `PreparedTransition` → store-bridge
//!   contour (#18/#19 lanes own that execution).
//! - [`ExperienceRevisionLedger`]: rebuildable per-handle revision
//!   monotonicity (review F2 join). The ledger is Governor admission
//!   state, reconstructible from admitted records exactly like the
//!   observation journal projection: it proves sequencing within the
//!   snapshot the owner holds, never durable authority.
//! - [`produce_feedback_from_journal`]: the actual feedback producer.
//!   Closed mechanical mapping from journal event kinds (`AgentFeedback`,
//!   `ProductOutcome`, `UserCorrection`) to [`FeedbackClass`]; journal
//!   control events never become feedback (self-observation
//!   non-recursion); event-less records are counted skips, not invented
//!   feedback. Origin, consent, and subject refs are preserved per record.
//! - [`assemble_experience_for_consumer`]: the actual caller-to-consumer
//!   edge driver. Assembles both envelopes from admitted snapshots and
//!   re-resolves them at the consumer scope/fence before return, so the
//!   Smart consumer receives pre-validated owner envelopes.
//! - [`parse_bank_record`] / [`parse_feedback_record`]: the readback
//!   join. Decode verbatim store documents and re-prove each record
//!   (digest recomputed from fields) before refs resolve: the bridge
//!   persists bytes, this owner re-establishes their authority on read.
//! - [`supply_bank_refs`] / [`supply_feedback_refs`]: the owner projection
//!   supplier. Builds opaque [`ExperienceRecordRef`]s with owner-issued
//!   revision cursors for admitted records only, enforcing envelope
//!   scope/fence agreement up front.
//! - [`assemble_bank_projection`] / [`assemble_feedback_projection`]: the
//!   first real production callers of the frozen `BankProjection::assemble`
//!   / `FeedbackProjection::assemble` (previously reachable only from Smart
//!   test fixtures). The journal leg assembles from durable-audit reads
//!   (`GetAuditRange` via the read facade); the in-memory journal alone is
//!   never claimed as full owner records.
//! - [`revalidate_bank_projection_for_consumer`] and siblings: consumer-edge
//!   re-resolution mirroring the Smart acceptance rule (validate, consumer
//!   scope equality, fence compatibility, frozen digest). This runs without
//!   importing any Smart crate: Smart depends on Governor contracts, never
//!   the reverse.
//! - [`consume_bank_range_payload`] / [`consume_feedback_range_payload`]:
//!   the payload-to-projection callers. Decode a bridge range payload and
//!   run the full snapshot join, so every helper below gains a real
//!   in-copy caller. Owner coverage/omissions/revision stay
//!   caller-supplied owner evidence.
//!
//! Cross-copy seams (no in-copy caller by design; exact consumers named):
//!
//! ```text
//! produce_feedback_from_journal
//!   → terminal daemon/observation edge, B-lane O1 trigger wiring;
//! assemble_experience_for_consumer, consume_*_range_payload,
//!   supply_*_projection_from_store
//!   → B terminal bank/feedback invocation: bridge range read → parse →
//!     supply → assess/recheck (owner coverage built B-side from heads);
//! produce_bank_commit, produce_feedback_commit
//!   → #18 PreparedTransition contour (reserved 325/C lane) as the typed
//!     named-operation inputs;
//! parse_bank_record, parse_feedback_record
//!   → B terminal loop per document, plus the consume drivers above;
//! RetentionSchedule::issue
//!   → Governor configuration owner;
//! BANK/FEEDBACK_COMMIT_OPERATION strings
//!   → store-api operation_parameters name maps (byte-identical spelling).
//! ```
//!
//! Never: store/vendor I/O, credential handling, lifecycle/support/
//! influence mutation, epistemic promotion, score/verdict emission, or
//! retention-policy invention (see `resolve_retention_read`).
//!
//! F2 resolution (implemented rule, not a challenge): audit-range reads
//! are scope-free at the store catalogue (`SCOPE_KIND_NONE`,
//! `requires_scope_id: false`) while the Governor facade requires a
//! caller scope (`requires_scope` arm, pre-existing) — matching the
//! established in-catalogue scope-free reads (`GetNotificationState`,
//! `GetReactiveInjectionState`, `GetResourceSnapshot`): catalogue rows
//! stay scope-free while caller context is enforced at the facade and
//! decided at the retrieval layer. I12-26 evaluates scope and fence at
//! the retrieval decision layer, and the coordinated consumer filters
//! by event scope itself while carrying scope-free records regardless;
//! store-level scope filtering would diverge the memory/surreal
//! contours (command rows carry scope, evidence rows do not) and drop
//! records the consumer must see. Facade, catalogue, daemon plan (which
//! always sends a scope), and provider shaping are mutually compatible
//! as they stand — no layer changes. Bank/feedback reads stay genuinely
//! scope-addressed and unchanged.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_store_api::StoreError;
pub use eliot_store_api::{ExperiencePageBoundary, ExperienceRangePage, PageBoundary};

use eliot_contracts::{ArtifactId, StateFence};
use eliot_observation_contracts::{
    AgentFeedbackRecord, BankProjection, ExperienceBankRecord, ExperienceCommitParameters,
    ExperienceRecordRef, ExperienceRetentionReadPosture, FeedbackClass, FeedbackProjection,
    JournalProjection, ObservationKind, ObservationScope, PrivacyRetentionDisclosure,
    ProducerTrace, ProjectionCoverage, ProjectionOmission, ProjectionOmissionClass, RetentionHold,
    RetentionSchedule, SystemObservationJournalRecord, bank_record_ref, feedback_record_ref,
    resolve_bank_ref, resolve_feedback_ref, resolve_retention_read,
};

use serde_json::Value;

use crate::GovernorObservationError;

/// Owner source identity minted bank cursors under.
pub const BANK_SOURCE_ID: &str = "governor.experience-bank";
/// Owner source identity minted feedback cursors under.
pub const FEEDBACK_SOURCE_ID: &str = "governor.agent-feedback";

static DRIVER_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_driver_instance() -> u64 {
    DRIVER_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Exact owner binding for one current paged experience read.
///
/// A paged projection is not authorized by a cursor or a record revision
/// alone.  The consumer carries the exact fence and the owner revision marker
/// for each family together with that family's generation.  The revision
/// ledger and the canonical commit caller compare this token before producing
/// a commit payload.  The fields are private so a caller can only obtain a
/// token from the owner-side page driver; arbitrary JSON cannot manufacture a
/// generation/fence binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperienceReadBinding {
    driver_instance: u64,
    fence: StateFence,
    bank_generation: u64,
    bank_source_revision: String,
    feedback_generation: u64,
    feedback_source_revision: String,
}

impl ExperienceReadBinding {
    /// Builds an owner binding for the current two-family page.
    fn new(
        driver_instance: u64,
        fence: StateFence,
        bank_generation: u64,
        bank_source_revision: impl Into<String>,
        feedback_generation: u64,
        feedback_source_revision: impl Into<String>,
    ) -> Result<Self, GovernorObservationError> {
        fence
            .validate()
            .map_err(GovernorObservationError::Foundation)?;
        let bank_source_revision = bounded_binding_text(
            bank_source_revision.into(),
            "experience_read.bank_source_revision",
        )?;
        let feedback_source_revision = bounded_binding_text(
            feedback_source_revision.into(),
            "experience_read.feedback_source_revision",
        )?;
        Ok(Self {
            driver_instance,
            fence,
            bank_generation,
            bank_source_revision,
            feedback_generation,
            feedback_source_revision,
        })
    }

    /// Returns the owner-driver instance that issued this binding.
    #[must_use]
    pub const fn driver_instance(&self) -> u64 {
        self.driver_instance
    }

    /// Returns the exact fence under which both owner reads were assembled.
    #[must_use]
    pub const fn fence(&self) -> &StateFence {
        &self.fence
    }

    /// Returns the current bank enumeration generation.
    #[must_use]
    pub const fn bank_generation(&self) -> u64 {
        self.bank_generation
    }

    /// Returns the current feedback enumeration generation.
    #[must_use]
    pub const fn feedback_generation(&self) -> u64 {
        self.feedback_generation
    }

    /// Returns the owner revision marker for the bank projection.
    #[must_use]
    pub fn bank_source_revision(&self) -> &str {
        &self.bank_source_revision
    }

    /// Returns the owner revision marker for the feedback projection.
    #[must_use]
    pub fn feedback_source_revision(&self) -> &str {
        &self.feedback_source_revision
    }
}

fn bounded_binding_text(
    value: String,
    field: &'static str,
) -> Result<String, GovernorObservationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.chars().count() > 256
    {
        return Err(GovernorObservationError::InvalidField {
            field,
            reason: "must be non-blank, bounded, and free of control characters",
        });
    }
    Ok(value)
}

#[derive(Clone, Debug, Default)]
struct ExperienceFamilyRevisionState {
    revisions: BTreeMap<String, u64>,
    binding: Option<ExperienceReadBinding>,
}

/// Rebuildable per-handle revision monotonicity for bank/feedback admission.
///
/// The ledger tracks the greatest admitted revision per record handle for
/// both families. It is Governor admission state with the same standing
/// as the observation journal projection: reconstructible from admitted
/// records via [`rebuild_bank`](Self::rebuild_bank) /
/// [`rebuild_feedback`](Self::rebuild_feedback), carrying no durable
/// authority of its own. Durable sequencing stays with the #19 commit
/// path (idempotency + revision conflict); this ledger fails closed on
/// non-monotonic admission attempts before they reach it.
#[derive(Clone, Debug, Default)]
pub struct ExperienceRevisionLedger {
    bank: ExperienceFamilyRevisionState,
    feedback: ExperienceFamilyRevisionState,
}

impl ExperienceRevisionLedger {
    /// Create an empty ledger. Prefer the generation-bound rebuild methods
    /// when the records came from a paged owner read.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild bank sequencing from an owner snapshot.
    ///
    /// The snapshot replaces this family's revision map. The operation remains
    /// useful for single-page admission owners that do not yet carry a paged
    /// binding, but a commit caller must use
    /// [`Self::rebuild_bank_for_binding`] before producing a payload.
    pub fn rebuild_bank(&mut self, records: &[ExperienceBankRecord]) {
        self.bank.revisions = greatest_bank_revisions(records);
        self.bank.binding = None;
    }

    /// Rebuild feedback sequencing from an owner snapshot, replacing only the
    /// feedback family.
    pub fn rebuild_feedback(&mut self, records: &[AgentFeedbackRecord]) {
        self.feedback.revisions = greatest_feedback_revisions(records);
        self.feedback.binding = None;
    }

    fn replace_bank_revisions(&mut self, records: &[ExperienceBankRecord]) {
        self.bank.revisions = greatest_bank_revisions(records);
    }

    fn replace_feedback_revisions(&mut self, records: &[AgentFeedbackRecord]) {
        self.feedback.revisions = greatest_feedback_revisions(records);
    }

    /// Rebuilds and binds the bank family to one exact owner page.
    pub fn rebuild_bank_for_binding(
        &mut self,
        records: &[ExperienceBankRecord],
        source_revision: &str,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        validate_bank_binding(records, source_revision, binding)?;
        self.bank.revisions = greatest_bank_revisions(records);
        self.bank.binding = Some(binding.clone());
        Ok(())
    }

    /// Rebuilds and binds the feedback family to one exact owner page.
    pub fn rebuild_feedback_for_binding(
        &mut self,
        records: &[AgentFeedbackRecord],
        source_revision: &str,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        validate_feedback_binding(records, source_revision, binding)?;
        self.feedback.revisions = greatest_feedback_revisions(records);
        self.feedback.binding = Some(binding.clone());
        Ok(())
    }

    /// Drops all bank-family revisions and its generation binding. The
    /// feedback family is deliberately untouched, which is the family-local
    /// restart rule for the paged consumer.
    pub fn invalidate_bank(&mut self) {
        self.bank = ExperienceFamilyRevisionState::default();
    }

    /// Drops all feedback-family revisions and its generation binding while
    /// preserving the unrelated bank family.
    pub fn invalidate_feedback(&mut self) {
        self.feedback = ExperienceFamilyRevisionState::default();
    }

    /// Binds an already complete family without replacing its retained
    /// revisions. This is used when the other family is the only one making
    /// progress on a page.
    pub fn retain_bank_binding(
        &mut self,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        if self.bank.binding.as_ref() != Some(binding) {
            return Err(GovernorObservationError::InvalidField {
                field: "consumer_page.bank_binding",
                reason: "completed family binding changed; restart that family explicitly",
            });
        }
        Ok(())
    }

    /// Binds an already complete feedback family without replacing its
    /// retained revisions.
    pub fn retain_feedback_binding(
        &mut self,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        if self.feedback.binding.as_ref() != Some(binding) {
            return Err(GovernorObservationError::InvalidField {
                field: "consumer_page.feedback_binding",
                reason: "completed family binding changed; restart that family explicitly",
            });
        }
        Ok(())
    }

    /// Check a bank revision against the tracked greatest and track it.
    /// Genesis (untracked handle) accepts any revision; afterwards only a
    /// strictly greater revision passes.
    pub fn track_bank(
        &mut self,
        handle: &ArtifactId,
        revision: u64,
    ) -> Result<(), GovernorObservationError> {
        match self.bank.revisions.get(handle.as_str()) {
            Some(last) if revision <= *last => Err(GovernorObservationError::InvalidField {
                field: "bank_record.bank_revision",
                reason: "revision is not strictly greater than the tracked revision",
            }),
            _ => {
                self.bank
                    .revisions
                    .insert(handle.as_str().to_owned(), revision);
                self.bank.binding = None;
                Ok(())
            }
        }
    }

    /// Check a feedback revision against the tracked greatest and track it.
    pub fn track_feedback(
        &mut self,
        handle: &ArtifactId,
        revision: u64,
    ) -> Result<(), GovernorObservationError> {
        match self.feedback.revisions.get(handle.as_str()) {
            Some(last) if revision <= *last => Err(GovernorObservationError::InvalidField {
                field: "feedback_record.feedback_revision",
                reason: "revision is not strictly greater than the tracked revision",
            }),
            _ => {
                self.feedback
                    .revisions
                    .insert(handle.as_str().to_owned(), revision);
                self.feedback.binding = None;
                Ok(())
            }
        }
    }

    /// Greatest tracked bank revision for one handle, when admitted through
    /// this owner. This legacy view is intentionally not sufficient for a
    /// commit; [`Self::tracked_bank_revision_for_binding`] is the commit gate.
    pub fn tracked_bank_revision(&self, handle: &ArtifactId) -> Option<u64> {
        self.bank.revisions.get(handle.as_str()).copied()
    }

    /// Greatest tracked feedback revision for one handle, without generation
    /// authority.
    pub fn tracked_feedback_revision(&self, handle: &ArtifactId) -> Option<u64> {
        self.feedback.revisions.get(handle.as_str()).copied()
    }

    /// Validates that a commit record slice is the current owner page for the
    /// already-bound bank family without replacing unrelated family state.
    pub fn validate_bank_records_for_binding(
        &self,
        records: &[ExperienceBankRecord],
        source_revision: &str,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        validate_bank_binding(records, source_revision, binding)?;
        for record in records {
            if self.tracked_bank_revision_for_binding(&record.handle, binding)
                != Some(record.bank_revision)
            {
                return Err(GovernorObservationError::InvalidField {
                    field: "bank_record.bank_revision",
                    reason: "record is not the current owner-page revision for this binding",
                });
            }
        }
        Ok(())
    }

    /// Validates the current feedback page without replacing the bank family.
    pub fn validate_feedback_records_for_binding(
        &self,
        records: &[AgentFeedbackRecord],
        source_revision: &str,
        binding: &ExperienceReadBinding,
    ) -> Result<(), GovernorObservationError> {
        validate_feedback_binding(records, source_revision, binding)?;
        for record in records {
            if self.tracked_feedback_revision_for_binding(&record.handle, binding)
                != Some(record.feedback_revision)
            {
                return Err(GovernorObservationError::InvalidField {
                    field: "feedback_record.feedback_revision",
                    reason: "record is not the current owner-page revision for this binding",
                });
            }
        }
        Ok(())
    }

    /// Returns a bank revision only when the complete family binding matches
    /// the page token and the revision is the current snapshot revision.
    pub fn tracked_bank_revision_for_binding(
        &self,
        handle: &ArtifactId,
        binding: &ExperienceReadBinding,
    ) -> Option<u64> {
        if self.bank.binding.as_ref() != Some(binding) {
            return None;
        }
        self.bank.revisions.get(handle.as_str()).copied()
    }

    /// Returns a feedback revision only for the exact current family binding.
    pub fn tracked_feedback_revision_for_binding(
        &self,
        handle: &ArtifactId,
        binding: &ExperienceReadBinding,
    ) -> Option<u64> {
        if self.feedback.binding.as_ref() != Some(binding) {
            return None;
        }
        self.feedback.revisions.get(handle.as_str()).copied()
    }
}

fn greatest_bank_revisions(records: &[ExperienceBankRecord]) -> BTreeMap<String, u64> {
    let mut revisions = BTreeMap::new();
    for record in records {
        let entry = revisions
            .entry(record.handle.as_str().to_owned())
            .or_insert(0);
        *entry = (*entry).max(record.bank_revision);
    }
    revisions
}

fn greatest_feedback_revisions(records: &[AgentFeedbackRecord]) -> BTreeMap<String, u64> {
    let mut revisions = BTreeMap::new();
    for record in records {
        let entry = revisions
            .entry(record.handle.as_str().to_owned())
            .or_insert(0);
        *entry = (*entry).max(record.feedback_revision);
    }
    revisions
}

fn validate_bank_binding(
    records: &[ExperienceBankRecord],
    source_revision: &str,
    binding: &ExperienceReadBinding,
) -> Result<(), GovernorObservationError> {
    if source_revision != binding.bank_source_revision() {
        return Err(GovernorObservationError::InvalidField {
            field: "experience_read.bank_source_revision",
            reason: "owner source revision does not equal the exact paged binding",
        });
    }
    for record in records {
        record
            .validate()
            .map_err(GovernorObservationError::Observation)?;
        if record.fence != *binding.fence() {
            return Err(GovernorObservationError::InvalidField {
                field: "bank_record.fence",
                reason: "record fence does not equal the exact paged owner binding",
            });
        }
    }
    Ok(())
}

fn validate_feedback_binding(
    records: &[AgentFeedbackRecord],
    source_revision: &str,
    binding: &ExperienceReadBinding,
) -> Result<(), GovernorObservationError> {
    if source_revision != binding.feedback_source_revision() {
        return Err(GovernorObservationError::InvalidField {
            field: "experience_read.feedback_source_revision",
            reason: "owner source revision does not equal the exact paged binding",
        });
    }
    for record in records {
        record
            .validate()
            .map_err(GovernorObservationError::Observation)?;
        if record.fence != *binding.fence() {
            return Err(GovernorObservationError::InvalidField {
                field: "feedback_record.fence",
                reason: "record fence does not equal the exact paged owner binding",
            });
        }
    }
    Ok(())
}

/// Admit one experience-bank record.
///
/// Requires at least one source journal ref (empty) and unique refs
/// (duplicate); enforces strictly increasing `bank_revision` per handle
/// through `ledger` (review F2 join); delegates shape/digest authority to
/// [`ExperienceBankRecord::admit`]. The ledger is tracked only after the
/// shape admits, so failed admissions never pollute sequencing. Durable
/// commit flows through the `capture_candidate` named operation, never
/// from this pure function.
pub fn admit_bank_record(
    ledger: &mut ExperienceRevisionLedger,
    handle: ArtifactId,
    bank_revision: u64,
    source_journal_refs: Vec<ArtifactId>,
    scope: ObservationScope,
    fence: StateFence,
    coverage: ProjectionCoverage,
    retention: PrivacyRetentionDisclosure,
    predecessor: Option<ArtifactId>,
    summary: String,
) -> Result<ExperienceBankRecord, GovernorObservationError> {
    if source_journal_refs.is_empty() {
        return Err(GovernorObservationError::Empty {
            field: "bank_record.source_journal_refs",
        });
    }
    let mut seen: Vec<&str> = Vec::with_capacity(source_journal_refs.len());
    for reference in &source_journal_refs {
        let id = reference.as_str();
        if seen.contains(&id) {
            return Err(GovernorObservationError::Duplicate {
                field: "bank_record.source_journal_refs",
            });
        }
        seen.push(id);
    }
    let record = ExperienceBankRecord::admit(
        handle,
        bank_revision,
        source_journal_refs,
        scope,
        fence,
        coverage,
        retention,
        predecessor,
        summary,
    )
    .map_err(GovernorObservationError::Observation)?;
    ledger.track_bank(&record.handle, record.bank_revision)?;
    Ok(record)
}

/// Admit one agent-feedback record.
///
/// Consent is required and explicit: an empty consent ref fails closed
/// (absence is not consent). Revision monotonicity runs through `ledger`
/// as for bank records. Input origin travels in `origin`; the record
/// stays candidate-only (no verdict/score field exists to promote).
pub fn admit_feedback_record(
    ledger: &mut ExperienceRevisionLedger,
    handle: ArtifactId,
    feedback_revision: u64,
    origin: ProducerTrace,
    consent_ref: String,
    class: FeedbackClass,
    subject_event_ref: Option<ArtifactId>,
    scope: ObservationScope,
    fence: StateFence,
    retention: PrivacyRetentionDisclosure,
    note: String,
) -> Result<AgentFeedbackRecord, GovernorObservationError> {
    if consent_ref.trim().is_empty() {
        return Err(GovernorObservationError::Empty {
            field: "feedback_record.consent_ref",
        });
    }
    let record = AgentFeedbackRecord::admit(
        handle,
        feedback_revision,
        origin,
        consent_ref,
        class,
        subject_event_ref,
        scope,
        fence,
        retention,
        note,
    )
    .map_err(GovernorObservationError::Observation)?;
    ledger.track_feedback(&record.handle, record.feedback_revision)?;
    Ok(record)
}

/// Supply owner-issued opaque refs for admitted bank records.
///
/// Every ref carries the owner revision cursor with the record's own
/// scope/fence echoes. Records whose scope differs from the envelope
/// scope, or whose fence is incompatible with the envelope fence, fail
/// closed here rather than inside the frozen assembler. Supply order is
/// the caller's deterministic order.
pub fn supply_bank_refs(
    records: &[ExperienceBankRecord],
    scope: &ObservationScope,
    fence: &StateFence,
) -> Result<Vec<ExperienceRecordRef>, GovernorObservationError> {
    let mut refs = Vec::with_capacity(records.len());
    for record in records {
        if record.scope != *scope {
            return Err(GovernorObservationError::InvalidField {
                field: "bank_record.scope",
                reason: "record scope does not match projection scope",
            });
        }
        if !record.fence.is_compatible_with(fence) {
            return Err(GovernorObservationError::InvalidField {
                field: "bank_record.fence",
                reason: "record fence is not compatible with projection fence",
            });
        }
        refs.push(
            bank_record_ref(record, BANK_SOURCE_ID)
                .map_err(GovernorObservationError::Observation)?,
        );
    }
    Ok(refs)
}

/// Supply owner-issued opaque refs for admitted feedback records.
/// Same scope/fence agreement rule as [`supply_bank_refs`].
pub fn supply_feedback_refs(
    records: &[AgentFeedbackRecord],
    scope: &ObservationScope,
    fence: &StateFence,
) -> Result<Vec<ExperienceRecordRef>, GovernorObservationError> {
    let mut refs = Vec::with_capacity(records.len());
    for record in records {
        if record.scope != *scope {
            return Err(GovernorObservationError::InvalidField {
                field: "feedback_record.scope",
                reason: "record scope does not match projection scope",
            });
        }
        if !record.fence.is_compatible_with(fence) {
            return Err(GovernorObservationError::InvalidField {
                field: "feedback_record.fence",
                reason: "record fence is not compatible with projection fence",
            });
        }
        refs.push(
            feedback_record_ref(record, FEEDBACK_SOURCE_ID)
                .map_err(GovernorObservationError::Observation)?,
        );
    }
    Ok(refs)
}

/// Assemble a validated bank projection over admitted bank records.
///
/// First real production caller of the frozen `BankProjection::assemble`:
/// refs resolve to actual admitted records/bytes with owner-issued
/// revision/digest cursors. An empty record set is honest intermediate
/// state (partial coverage, never `Complete` posture from this function
/// alone): completeness is declared by the owner's coverage evidence.
pub fn assemble_bank_projection(
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    source_revision: String,
    records: &[ExperienceBankRecord],
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<BankProjection, GovernorObservationError> {
    let refs = supply_bank_refs(records, &scope, &fence)?;
    BankProjection::assemble(
        projection_id,
        scope,
        fence,
        source_revision,
        refs,
        coverage,
        omissions,
    )
    .map_err(GovernorObservationError::Observation)
}

/// Assemble a validated feedback projection over admitted feedback
/// records. Same owner-issued cursor rule as [`assemble_bank_projection`].
pub fn assemble_feedback_projection(
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    source_revision: String,
    records: &[AgentFeedbackRecord],
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<FeedbackProjection, GovernorObservationError> {
    let refs = supply_feedback_refs(records, &scope, &fence)?;
    FeedbackProjection::assemble(
        projection_id,
        scope,
        fence,
        source_revision,
        refs,
        coverage,
        omissions,
    )
    .map_err(GovernorObservationError::Observation)
}

/// Re-resolve one bank projection against the consumer edge.
///
/// Mirrors the Smart acceptance rule without importing any Smart crate:
/// frozen validation (shape, per-ref echoes, coverage rule, digest),
/// consumer scope equality, and fence compatibility. Anything drifted,
/// uncited, or unattested fails closed at the edge.
pub fn revalidate_bank_projection_for_consumer(
    projection: &BankProjection,
    consumer_scope: &ObservationScope,
    consumer_fence: &StateFence,
) -> Result<(), GovernorObservationError> {
    projection
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    if projection.scope != *consumer_scope {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.scope",
            reason: "projection scope does not match consumer scope",
        });
    }
    if !projection.fence.is_compatible_with(consumer_fence) {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.fence",
            reason: "projection fence is not compatible with consumer fence",
        });
    }
    Ok(())
}

/// Re-resolve one feedback projection against the consumer edge.
/// Same rule as [`revalidate_bank_projection_for_consumer`].
pub fn revalidate_feedback_projection_for_consumer(
    projection: &FeedbackProjection,
    consumer_scope: &ObservationScope,
    consumer_fence: &StateFence,
) -> Result<(), GovernorObservationError> {
    projection
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    if projection.scope != *consumer_scope {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.scope",
            reason: "projection scope does not match consumer scope",
        });
    }
    if !projection.fence.is_compatible_with(consumer_fence) {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.fence",
            reason: "projection fence is not compatible with consumer fence",
        });
    }
    Ok(())
}

/// Decode and re-prove one bank record from a durable readback document.
///
/// The readback join: deserializes the verbatim `record_json` the store
/// persisted, then runs full [`ExperienceBankRecord::validate`] — which
/// recomputes the owner digest from fields and compares it to the stored
/// digest. A forged or drifted stored digest fails closed here, before
/// any ref resolves or any projection assembles. Single-document
/// granularity preserves exact failure identity: the caller (terminal
/// invocation loop) knows which document failed from its own position.
/// Decode failures map to [`GovernorObservationError::Serialization`];
/// content failures map to their exact contract error.
pub fn parse_bank_record(document: &str) -> Result<ExperienceBankRecord, GovernorObservationError> {
    let record: ExperienceBankRecord =
        serde_json::from_str(document).map_err(|_| GovernorObservationError::Serialization)?;
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    Ok(record)
}

/// Decode and re-prove one feedback record from a durable readback
/// document. Same digest re-proof rule as [`parse_bank_record`].
pub fn parse_feedback_record(
    document: &str,
) -> Result<AgentFeedbackRecord, GovernorObservationError> {
    let record: AgentFeedbackRecord =
        serde_json::from_str(document).map_err(|_| GovernorObservationError::Serialization)?;
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    Ok(record)
}

/// Re-resolve one journal projection against the consumer edge.
///
/// Journal records travel full-bodied from the durable audit (read via
/// the `GetAuditRange` named-read contour); this edge check binds the
/// envelope the Smart consumer cites to the consumer scope/fence. Same
/// rule as [`revalidate_bank_projection_for_consumer`].
pub fn revalidate_journal_projection_for_consumer(
    projection: &JournalProjection,
    consumer_scope: &ObservationScope,
    consumer_fence: &StateFence,
) -> Result<(), GovernorObservationError> {
    projection
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    if projection.scope != *consumer_scope {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.scope",
            reason: "projection scope does not match consumer scope",
        });
    }
    if !projection.fence.is_compatible_with(consumer_fence) {
        return Err(GovernorObservationError::InvalidField {
            field: "projection.fence",
            reason: "projection fence is not compatible with consumer fence",
        });
    }
    Ok(())
}

/// Closed journal→feedback class mapping.
///
/// Mechanical only: `AgentFeedback` journal events carry usefulness
/// signals, `ProductOutcome` events carry outcome deltas, and
/// `UserCorrection` events carry corrections. Every other event kind has
/// no feedback interpretation in this owner and maps to `None`; the
/// caller counts the skip rather than inferring one. This is not an
/// `ObservationKind -> ObservationRecordKind` family matrix (#217): it
/// names the subject of a newly admitted feedback record defined by the
/// foundation feedback contract, never re-labels an observation family.
fn feedback_class_for_kind(kind: ObservationKind) -> Option<FeedbackClass> {
    match kind {
        ObservationKind::AgentFeedback => Some(FeedbackClass::UsefulnessSignal),
        ObservationKind::ProductOutcome => Some(FeedbackClass::OutcomeDelta),
        ObservationKind::UserCorrection => Some(FeedbackClass::UserCorrection),
        ObservationKind::ContextPacket
        | ObservationKind::MemoryDelivery
        | ObservationKind::ToolOrRoute
        | ObservationKind::TaskProgress
        | ObservationKind::LoopOrNoProgress
        | ObservationKind::FailureOrRepair
        | ObservationKind::QueueResource
        | ObservationKind::Configuration
        | ObservationKind::Maintenance
        | ObservationKind::Security => None,
    }
}

/// Result of one journal→feedback production pass.
///
/// `admitted` carries ledger-sequenced feedback records; both skip
/// counters account every input exactly (admitted + skips = inputs), so
/// silence is never mistaken for absence and nothing is dropped silently.
pub struct FeedbackProduction {
    /// Ledger-sequenced feedback records, in journal supply order.
    pub admitted: Vec<AgentFeedbackRecord>,
    /// Inputs with no event (coverage gaps, control shapes): no feedback
    /// exists to produce, counted rather than invented.
    pub skipped_no_event: u64,
    /// Journal control events (self-observation non-recursion) and
    /// event-carrying inputs whose kind has no feedback mapping.
    pub skipped_non_feedback_kind: u64,
}

/// Produce admitted feedback records from journal records.
///
/// The actual feedback producer (root decision 5): for each journal
/// record carrying a feedback-mapped event kind, admits one
/// [`AgentFeedbackRecord`] through `ledger`, preserving input origin
/// (`producer_generation_and_trace`), the caller-attested `consent_ref`,
/// the subject journal handle, the event scope, and the read `fence`.
/// Handles derive deterministically as `{record_id}/feedback/{revision}`
/// from `feedback_revision_start`, incrementing per produced record.
///
/// Journal control events never become feedback: admission, coalescing,
/// import, and read of a journal event do not emit journal events about
/// themselves. Records without events and unmapped kinds are counted in
/// the skip classes, never promoted. An overlong event delta fails closed
/// at admission rather than truncating evidence.
pub fn produce_feedback_from_journal(
    ledger: &mut ExperienceRevisionLedger,
    journal: &[SystemObservationJournalRecord],
    consent_ref: String,
    feedback_revision_start: u64,
    fence: StateFence,
    retention: PrivacyRetentionDisclosure,
) -> Result<FeedbackProduction, GovernorObservationError> {
    if consent_ref.trim().is_empty() {
        return Err(GovernorObservationError::Empty {
            field: "feedback_record.consent_ref",
        });
    }
    fence
        .validate()
        .map_err(GovernorObservationError::Foundation)?;
    retention
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    let mut admitted = Vec::new();
    let mut skipped_no_event: u64 = 0;
    let mut skipped_non_feedback_kind: u64 = 0;
    let mut revision = feedback_revision_start;
    for record in journal {
        record
            .validate()
            .map_err(GovernorObservationError::Observation)?;
        let Some(event) = &record.event else {
            skipped_no_event = skipped_no_event.saturating_add(1);
            continue;
        };
        if record.journal_control_event {
            skipped_non_feedback_kind = skipped_non_feedback_kind.saturating_add(1);
            continue;
        }
        let Some(class) = feedback_class_for_kind(event.kind) else {
            skipped_non_feedback_kind = skipped_non_feedback_kind.saturating_add(1);
            continue;
        };
        let handle = ArtifactId::new(format!("{}/feedback/{revision}", record.record_id))
            .map_err(GovernorObservationError::Foundation)?;
        let subject = ArtifactId::new(record.record_id.clone())
            .map_err(GovernorObservationError::Foundation)?;
        let feedback = admit_feedback_record(
            ledger,
            handle,
            revision,
            event.producer_generation_and_trace.clone(),
            consent_ref.clone(),
            class,
            Some(subject),
            event.affected_scope.clone(),
            fence.clone(),
            retention.clone(),
            event.observed_delta.clone(),
        )?;
        revision = revision.saturating_add(1);
        admitted.push(feedback);
    }
    Ok(FeedbackProduction {
        admitted,
        skipped_no_event,
        skipped_non_feedback_kind,
    })
}

/// Store-issued snapshot of bank records for one read.
///
/// The records arrive as function arguments from the durable read owner
/// (store bridge `#19` read contour once the bank named reads register;
/// owner-issued fixtures until then) together with the exact revision
/// marker read at, the owner coverage binding, and owner omissions. This
/// type carries read evidence; it performs no I/O and owns no table.
#[derive(Clone)]
pub struct BankStoreSnapshot<'a> {
    /// Records the durable read returned, in read order.
    pub records: &'a [ExperienceBankRecord],
    /// Owner revision marker read at.
    pub source_revision: String,
    /// Owner coverage binding for the read.
    pub coverage: ProjectionCoverage,
    /// Owner omissions for the read.
    pub omissions: Vec<ProjectionOmission>,
}

/// Store-issued snapshot of feedback records for one read. Same
/// read-evidence rule as [`BankStoreSnapshot`].
#[derive(Clone)]
pub struct FeedbackStoreSnapshot<'a> {
    /// Records the durable read returned, in read order.
    pub records: &'a [AgentFeedbackRecord],
    /// Owner revision marker read at.
    pub source_revision: String,
    /// Owner coverage binding for the read.
    pub coverage: ProjectionCoverage,
    /// Owner omissions for the read.
    pub omissions: Vec<ProjectionOmission>,
}

/// Withhold one record under retention gating as a closed omission.
///
/// Retention-withheld material maps to [`ProjectionOmissionClass::ProtectedWithheld`]:
/// the record exists in the owner read but this projection may not carry
/// it. The detail names only the posture, never record content.
fn retention_omission(
    handle: &ArtifactId,
    blocked: bool,
) -> Result<ProjectionOmission, GovernorObservationError> {
    let omission = ProjectionOmission {
        handle: handle.clone(),
        class: ProjectionOmissionClass::ProtectedWithheld,
        detail: if blocked {
            "retention:blocked".to_owned()
        } else {
            "retention:unknown-policy".to_owned()
        },
    };
    omission
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    Ok(omission)
}

/// Supply a validated bank projection from a durable store snapshot.
///
/// The durable-read join (reviews F1/F5): rebuilds ledger sequencing
/// from the snapshot, gates every record through the owner-issued
/// retention schedule (withheld records become `ProtectedWithheld`
/// omissions, never carried and never dropped silently), assembles the
/// envelope over readable records only, resolves every carried ref
/// against the snapshot with [`resolve_bank_ref`], and re-resolves the
/// envelope at the consumer scope/fence. Withheld volume keeps the
/// envelope at partial posture: completeness still requires the owner
/// `Complete` disposition with empty omissions.
///
/// Single-page entry: it deliberately exposes only the projection and does
/// not manufacture a page boundary. Multi-page callers use
/// [`supply_bank_projection_from_store_paged`], which carries the typed owner
/// boundary alongside the identical projection join.
pub fn supply_bank_projection_from_store(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: BankStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
) -> Result<BankProjection, GovernorObservationError> {
    ledger.replace_bank_revisions(snapshot.records);
    let mut readable: Vec<ExperienceBankRecord> = Vec::with_capacity(snapshot.records.len());
    let mut omissions = snapshot.omissions;
    for record in snapshot.records {
        record
            .validate()
            .map_err(GovernorObservationError::Observation)?;
        let hold = holds.get(record.handle.as_str());
        match resolve_retention_read(&record.retention, schedule, &record.fence, hold)
            .map_err(GovernorObservationError::Observation)?
        {
            ExperienceRetentionReadPosture::Readable { .. } => readable.push(record.clone()),
            ExperienceRetentionReadPosture::RetentionBlocked { .. } => {
                omissions.push(retention_omission(&record.handle, true)?);
            }
            ExperienceRetentionReadPosture::UnknownPolicy { .. } => {
                omissions.push(retention_omission(&record.handle, false)?);
            }
        }
    }
    let projection = assemble_bank_projection(
        projection_id,
        scope,
        fence,
        snapshot.source_revision,
        &readable,
        snapshot.coverage,
        omissions,
    )?;
    for reference in &projection.refs {
        resolve_bank_ref(snapshot.records, reference)
            .map_err(GovernorObservationError::Observation)?;
    }
    Ok(projection)
}

/// Supply a validated feedback projection from a durable store snapshot.
/// Same durable-read join as [`supply_bank_projection_from_store`].
/// Single-page entry (boundary not threaded); multi-page callers use
/// [`supply_feedback_projection_from_store_paged`] with the typed owner
/// boundary.
pub fn supply_feedback_projection_from_store(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: FeedbackStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
) -> Result<FeedbackProjection, GovernorObservationError> {
    ledger.replace_feedback_revisions(snapshot.records);
    let mut readable: Vec<AgentFeedbackRecord> = Vec::with_capacity(snapshot.records.len());
    let mut omissions = snapshot.omissions;
    for record in snapshot.records {
        record
            .validate()
            .map_err(GovernorObservationError::Observation)?;
        let hold = holds.get(record.handle.as_str());
        match resolve_retention_read(&record.retention, schedule, &record.fence, hold)
            .map_err(GovernorObservationError::Observation)?
        {
            ExperienceRetentionReadPosture::Readable { .. } => readable.push(record.clone()),
            ExperienceRetentionReadPosture::RetentionBlocked { .. } => {
                omissions.push(retention_omission(&record.handle, true)?);
            }
            ExperienceRetentionReadPosture::UnknownPolicy { .. } => {
                omissions.push(retention_omission(&record.handle, false)?);
            }
        }
    }
    let projection = assemble_feedback_projection(
        projection_id,
        scope,
        fence,
        snapshot.source_revision,
        &readable,
        snapshot.coverage,
        omissions,
    )?;
    for reference in &projection.refs {
        resolve_feedback_ref(snapshot.records, reference)
            .map_err(GovernorObservationError::Observation)?;
    }
    Ok(projection)
}

/// Fail-closed gate for a parsed owner-page boundary.
///
/// The owner wire distinguishes an omitted member, an explicit `null`, and a
/// continuation cursor. This lane accepts only the latter two; an omitted
/// member is never converted into an end marker.
fn check_owner_page_boundary(
    boundary: PageBoundary,
    field: &'static str,
) -> Result<PageBoundary, GovernorObservationError> {
    boundary
        .validate_field(field)
        .map_err(map_owner_page_error)?;
    Ok(boundary)
}

fn map_owner_page_error(error: StoreError) -> GovernorObservationError {
    match error {
        StoreError::InvalidField { field, reason } => {
            GovernorObservationError::InvalidField { field, reason }
        }
        StoreError::Foundation(error) => GovernorObservationError::Foundation(error),
        _ => GovernorObservationError::InvalidField {
            field: "experience.page",
            reason: "owner page envelope failed typed boundary validation",
        },
    }
}

/// Parse one owner range envelope before any record or cursor is consumed.
///
/// The returned page retains the typed boundary, including the distinct
/// [`PageBoundary::MissingCursor`] state. Callers must validate/consume that
/// proof; deserialization alone never grants completion.
pub fn parse_experience_range_page(
    payload: &Value,
) -> Result<ExperienceRangePage, GovernorObservationError> {
    ExperienceRangePage::from_value(payload).map_err(map_owner_page_error)
}

/// One bank page: the validated projection plus the typed owner proof of
/// continuation or explicit end-of-stream.
pub struct PagedBankProjection {
    /// Validated bank envelope for this page, same join as
    /// [`supply_bank_projection_from_store`].
    pub projection: BankProjection,
    /// Owner-issued page boundary proof; `MissingCursor` is rejected before
    /// this value can reach a consumer.
    pub next_cursor: PageBoundary,
}

/// One feedback page: same typed-boundary rule as [`PagedBankProjection`].
pub struct PagedFeedbackProjection {
    /// Validated feedback envelope for this page.
    pub projection: FeedbackProjection,
    /// Owner-issued page boundary proof; `MissingCursor` is rejected before
    /// this value can reach a consumer.
    pub next_cursor: PageBoundary,
}

/// Supply one validated bank page from a durable store snapshot.
///
/// Identical projection join to [`supply_bank_projection_from_store`];
/// the extra `next_cursor` is the opaque owner-minted continuation
/// cursor for the page the snapshot was read from. It is echoed into
/// [`PagedBankProjection::next_cursor`] with only the fail-closed
/// malformed gate ([`check_owner_page_boundary`]): no parsing, no authority
/// invention. The pre-existing single-page supplier remains boundary-free;
/// paged callers must supply and validate the typed owner proof explicitly.
#[allow(clippy::too_many_arguments)]
pub fn supply_bank_projection_from_store_paged(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: BankStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    next_cursor: PageBoundary,
) -> Result<PagedBankProjection, GovernorObservationError> {
    let next_cursor = check_owner_page_boundary(next_cursor, "bank_page.next_cursor")?;
    let projection = supply_bank_projection_from_store(
        ledger,
        snapshot,
        projection_id,
        scope,
        fence,
        schedule,
        holds,
    )?;
    Ok(PagedBankProjection {
        projection,
        next_cursor,
    })
}

/// Supply one validated feedback page from a durable store snapshot.
/// Same opaque-cursor echo rule as
/// [`supply_bank_projection_from_store_paged`].
#[allow(clippy::too_many_arguments)]
pub fn supply_feedback_projection_from_store_paged(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: FeedbackStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    next_cursor: PageBoundary,
) -> Result<PagedFeedbackProjection, GovernorObservationError> {
    let next_cursor = check_owner_page_boundary(next_cursor, "feedback_page.next_cursor")?;
    let projection = supply_feedback_projection_from_store(
        ledger,
        snapshot,
        projection_id,
        scope,
        fence,
        schedule,
        holds,
    )?;
    Ok(PagedFeedbackProjection {
        projection,
        next_cursor,
    })
}

/// Both owner envelopes assembled and edge-re-resolved for one consumer.
pub struct ExperienceConsumerBundle {
    /// Assembled bank envelope over readable admitted bank records.
    pub bank: BankProjection,
    /// Assembled feedback envelope over readable admitted feedback records.
    pub feedback: FeedbackProjection,
}

/// Assemble and edge-consume both experience envelopes.
///
/// The actual caller-to-consumer edge driver: supplies both envelopes
/// from durable store snapshots (owner-issued cursors, retention gating,
/// per-ref snapshot resolution via
/// [`supply_bank_projection_from_store`] /
/// [`supply_feedback_projection_from_store`]) and re-resolves both at the
/// consumer scope/fence before return, so the Smart consumer receives
/// pre-validated owner envelopes. Anything drifted, withheld, or
/// unattested fails closed or names an explicit omission here, never
/// downstream. Per-family `source_revision` markers name each read
/// (review F3: the marker never overrides individually bound refs).
#[allow(clippy::too_many_arguments)]
pub fn assemble_experience_for_consumer(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    bank: BankStoreSnapshot<'_>,
    feedback: FeedbackStoreSnapshot<'_>,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
) -> Result<ExperienceConsumerBundle, GovernorObservationError> {
    let bank = supply_bank_projection_from_store(
        ledger,
        bank,
        projection_id.clone(),
        scope.clone(),
        fence.clone(),
        schedule,
        holds,
    )?;
    let feedback = supply_feedback_projection_from_store(
        ledger,
        feedback,
        projection_id,
        scope.clone(),
        fence.clone(),
        schedule,
        holds,
    )?;
    revalidate_bank_projection_for_consumer(&bank, &scope, &fence)?;
    revalidate_feedback_projection_for_consumer(&feedback, &scope, &fence)?;
    Ok(ExperienceConsumerBundle { bank, feedback })
}

/// Both owner envelopes for one page, edge-re-resolved, plus the typed
/// owner boundary proof for the next page.
///
/// Multi-page contract (owner five-part fence+heads cursors):
/// the consumer iterates a family by echoing that family's continuation
/// cursor back to the owner store as the next read's cursor selector until
/// the owner returns `PageBoundary::ExplicitEnd`. Bank and feedback
/// paginate independently: each family's cursor resumes only its own
/// enumeration. A fence/heads mismatch on the next page (the owner store
/// fails the cursor closed because a commit advanced a revision head or the
/// fence moved) means restart that family's enumeration from the headless
/// first page — never skip ahead, never replay rows into a duplicate, never
/// treat a rejected cursor as truncation. `ExplicitEnd` on both families
/// ends the read; anything else is a partial read, never a complete one.
/// `MissingCursor` is always a refusal, never an end marker.
pub struct PagedExperienceConsumerBundle {
    /// Assembled bank envelope for this page.
    pub bank: BankProjection,
    /// Assembled feedback envelope for this page.
    pub feedback: FeedbackProjection,
    /// Typed owner proof for the next bank page.
    pub bank_next_cursor: PageBoundary,
    /// Typed owner proof for the next feedback page.
    pub feedback_next_cursor: PageBoundary,
    generation: ConsumerPagedReadGeneration,
    binding: ExperienceReadBinding,
}

impl PagedExperienceConsumerBundle {
    /// Returns the owner token that authorizes a commit for this exact page.
    /// The token cannot be assembled outside this module.
    #[must_use]
    pub const fn binding(&self) -> &ExperienceReadBinding {
        &self.binding
    }
}

/// Assemble and edge-consume one page of both experience envelopes.
///
/// Paged entry of [`assemble_experience_for_consumer`]: runs the same
/// per-family supply join plus consumer-edge re-resolution, then echoes
/// the typed owner boundary proofs (fail-closed on missing or malformed
/// values, no cursor parsing or minting in this lane) into
/// [`PagedExperienceConsumerBundle`]. See its multi-page contract for
/// iteration, per-family independence, and the restart-instead-of-skip/dup rule.
#[allow(clippy::too_many_arguments)]
pub fn assemble_experience_for_consumer_paged(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: &ObservationScope,
    fence: &StateFence,
    bank: BankStoreSnapshot<'_>,
    feedback: FeedbackStoreSnapshot<'_>,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    bank_next_cursor: PageBoundary,
    feedback_next_cursor: PageBoundary,
) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
    let binding = ExperienceReadBinding::new(
        0,
        fence.clone(),
        0,
        bank.source_revision.clone(),
        0,
        feedback.source_revision.clone(),
    )?;
    ledger.rebuild_bank_for_binding(bank.records, &bank.source_revision, &binding)?;
    ledger.rebuild_feedback_for_binding(feedback.records, &feedback.source_revision, &binding)?;
    let bank = supply_bank_projection_from_store_paged(
        ledger,
        bank,
        projection_id.clone(),
        scope.clone(),
        fence.clone(),
        schedule,
        holds,
        bank_next_cursor,
    )?;
    let feedback = supply_feedback_projection_from_store_paged(
        ledger,
        feedback,
        projection_id,
        scope.clone(),
        fence.clone(),
        schedule,
        holds,
        feedback_next_cursor,
    )?;
    revalidate_bank_projection_for_consumer(&bank.projection, scope, fence)?;
    revalidate_feedback_projection_for_consumer(&feedback.projection, scope, fence)?;
    Ok(PagedExperienceConsumerBundle {
        bank: bank.projection,
        feedback: feedback.projection,
        bank_next_cursor: bank.next_cursor,
        feedback_next_cursor: feedback.next_cursor,
        generation: ConsumerPagedReadGeneration::initial(),
        binding,
    })
}

/// Per-family state for one current paged enumeration.
///
/// `None` is never overloaded: `NeedsFirstPage` is the only state that
/// selects the headless page, `Continuing` carries the exact owner cursor,
/// and `Complete` is reached only after a validated page reports no next
/// cursor. A restart returns the family to `NeedsFirstPage` and advances
/// its generation, invalidating every page from the prior enumeration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumerPagedFamilyState {
    /// The next owner read must use the headless first-page selector.
    NeedsFirstPage,
    /// The next owner read must use this exact opaque owner cursor.
    Continuing(String),
    /// The current enumeration ended on a validated page.
    Complete,
}

/// Generation token carried by a page bundle so a restart can invalidate
/// one family's partial result without invalidating the other family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerPagedReadGeneration {
    /// Bank enumeration generation.
    pub bank: u64,
    /// Feedback enumeration generation.
    pub feedback: u64,
}

impl ConsumerPagedReadGeneration {
    const fn initial() -> Self {
        Self {
            bank: 0,
            feedback: 0,
        }
    }
}

/// Echo-next-boundary driver for the multi-page consumer read.
///
/// Production loop driver over the owner page suppliers. The caller performs
/// each owner-store read with the selectors exposed by this driver, then
/// hands fresh snapshots and the owner-issued typed boundaries to
/// [`ConsumerPagedReadDriver::assemble_next_page`]. Each family has an
/// explicit first-page/continuation/completed state, so a missing boundary
/// cannot make a restart look complete. The loop ends only when both families
/// have reached a validated `PageBoundary::ExplicitEnd` in the same current
/// enumeration generation.
///
/// Boundary: this lane never performs the store read and never parses or
/// mints cursors. A fence/heads mismatch is reported by the owner store
/// failing the echoed cursor closed. The caller must then use the matching
/// restart method; that method invalidates only that family's retained page
/// and generation while leaving the other family untouched.
pub struct ConsumerPagedReadDriver {
    driver_instance: u64,
    bank_state: ConsumerPagedFamilyState,
    feedback_state: ConsumerPagedFamilyState,
    bank_projection: Option<BankProjection>,
    feedback_projection: Option<FeedbackProjection>,
    bank_generation: u64,
    feedback_generation: u64,
}

impl ConsumerPagedReadDriver {
    /// Start a headless read: both families explicitly need their first page.
    pub fn headless() -> Self {
        Self {
            driver_instance: next_driver_instance(),
            bank_state: ConsumerPagedFamilyState::NeedsFirstPage,
            feedback_state: ConsumerPagedFamilyState::NeedsFirstPage,
            bank_projection: None,
            feedback_projection: None,
            bank_generation: 0,
            feedback_generation: 0,
        }
    }

    /// Opaque bank cursor for the next owner-store read.
    ///
    /// `None` is returned for both `NeedsFirstPage` and `Complete`; callers
    /// that need to distinguish those cases must inspect [`Self::bank_state`].
    pub fn bank_cursor(&self) -> Option<&str> {
        match &self.bank_state {
            ConsumerPagedFamilyState::Continuing(cursor) => Some(cursor.as_str()),
            ConsumerPagedFamilyState::NeedsFirstPage | ConsumerPagedFamilyState::Complete => None,
        }
    }

    /// Opaque feedback cursor for the next owner-store read. The selector
    /// follows the same explicit-state rule as [`Self::bank_cursor`].
    pub fn feedback_cursor(&self) -> Option<&str> {
        match &self.feedback_state {
            ConsumerPagedFamilyState::Continuing(cursor) => Some(cursor.as_str()),
            ConsumerPagedFamilyState::NeedsFirstPage | ConsumerPagedFamilyState::Complete => None,
        }
    }

    /// Current explicit bank state.
    pub fn bank_state(&self) -> &ConsumerPagedFamilyState {
        &self.bank_state
    }

    /// Current explicit feedback state.
    pub fn feedback_state(&self) -> &ConsumerPagedFamilyState {
        &self.feedback_state
    }

    /// Generation token for the current per-family enumerations.
    pub fn generation(&self) -> ConsumerPagedReadGeneration {
        ConsumerPagedReadGeneration {
            bank: self.bank_generation,
            feedback: self.feedback_generation,
        }
    }

    /// `true` only after both families have reached `Complete` in their
    /// current generations. A headless driver is therefore never complete.
    pub fn is_complete(&self) -> bool {
        matches!(self.bank_state, ConsumerPagedFamilyState::Complete)
            && matches!(self.feedback_state, ConsumerPagedFamilyState::Complete)
    }

    /// Return whether a returned page still belongs to both current family
    /// generations. Use the family-specific methods when preserving the
    /// unrelated family after a restart.
    pub fn bundle_is_current(&self, bundle: &PagedExperienceConsumerBundle) -> bool {
        self.bank_page_is_current(bundle) && self.feedback_page_is_current(bundle)
    }

    /// Checks both the opaque generation token and its exact owner binding.
    /// A caller must also compare the event fence before committing; this
    /// method is the generation side of that fail-closed join.
    pub fn binding_is_current(&self, bundle: &PagedExperienceConsumerBundle) -> bool {
        bundle.binding.driver_instance == self.driver_instance
            && bundle.binding.bank_generation == self.bank_generation
            && bundle.binding.feedback_generation == self.feedback_generation
    }

    /// Returns the binding only when the page belongs to this exact retained
    /// driver instance and both current family generations.
    pub fn current_binding<'bundle>(
        &self,
        bundle: &'bundle PagedExperienceConsumerBundle,
    ) -> Result<&'bundle ExperienceReadBinding, GovernorObservationError> {
        if !self.bundle_is_current(bundle) || !self.binding_is_current(bundle) {
            return Err(GovernorObservationError::InvalidField {
                field: "experience_page.binding",
                reason: "page binding is not current for the retained owner driver",
            });
        }
        Ok(&bundle.binding)
    }

    /// Return whether the bank projection in `bundle` belongs to the
    /// current bank enumeration.
    pub fn bank_page_is_current(&self, bundle: &PagedExperienceConsumerBundle) -> bool {
        bundle.generation.bank == self.bank_generation
    }

    /// Return whether the feedback projection in `bundle` belongs to the
    /// current feedback enumeration.
    pub fn feedback_page_is_current(&self, bundle: &PagedExperienceConsumerBundle) -> bool {
        bundle.generation.feedback == self.feedback_generation
    }

    /// Restart bank enumeration from the headless first page after the
    /// owner store rejects the echoed bank cursor. The bank projection and
    /// all of its old-generation pages are invalidated; feedback state,
    /// projection, and generation are untouched. The revision ledger is a
    /// required argument so a restart cannot leave old-generation revisions
    /// authorized by a separate additive map.
    pub fn restart_bank_from_head(&mut self, ledger: &mut ExperienceRevisionLedger) {
        self.bank_state = ConsumerPagedFamilyState::NeedsFirstPage;
        self.bank_projection = None;
        self.bank_generation = self.bank_generation.wrapping_add(1);
        ledger.invalidate_bank();
    }

    /// Restart feedback enumeration from the headless first page. The
    /// independence and invalidation rules mirror [`Self::restart_bank_from_head`].
    pub fn restart_feedback_from_head(&mut self, ledger: &mut ExperienceRevisionLedger) {
        self.feedback_state = ConsumerPagedFamilyState::NeedsFirstPage;
        self.feedback_projection = None;
        self.feedback_generation = self.feedback_generation.wrapping_add(1);
        ledger.invalidate_feedback();
    }

    /// Assemble the next consumer page from fresh caller-supplied snapshots
    /// and owner-issued next cursors.
    ///
    /// This compatibility entry cannot observe which selector the caller used
    /// for the store read, so it refuses a continuation state rather than
    /// accepting an unproven selector. New production paths use
    /// [`Self::assemble_next_page_with_selectors`], which validates both the
    /// selector and the owner-issued next cursor before state advances. A
    /// completed family is retained while the other family continues from its
    /// headless first page.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_next_page(
        &mut self,
        ledger: &mut ExperienceRevisionLedger,
        projection_id: ArtifactId,
        scope: &ObservationScope,
        fence: &StateFence,
        bank: BankStoreSnapshot<'_>,
        feedback: FeedbackStoreSnapshot<'_>,
        schedule: &RetentionSchedule,
        holds: &BTreeMap<String, RetentionHold>,
        bank_next_cursor: PageBoundary,
        feedback_next_cursor: PageBoundary,
    ) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
        if matches!(self.bank_state, ConsumerPagedFamilyState::Continuing(_))
            || matches!(self.feedback_state, ConsumerPagedFamilyState::Continuing(_))
        {
            return Err(GovernorObservationError::InvalidField {
                field: "consumer_page.selector",
                reason: "compatibility page entry cannot prove a continuation selector; use the selector-aware entry",
            });
        }
        self.assemble_next_page_inner(
            ledger,
            projection_id,
            scope,
            fence,
            bank,
            feedback,
            schedule,
            holds,
            false,
            None,
            None,
            bank_next_cursor,
            feedback_next_cursor,
        )
    }

    /// Assemble one page while proving the exact selector used for each
    /// current family read.
    ///
    /// `bank_selector` and `feedback_selector` are the selectors echoed to
    /// the owner store: `None` for `NeedsFirstPage`/`Complete`, or exactly the
    /// current `Continuing` cursor. `bank_next_cursor` and
    /// `feedback_next_cursor` are the explicit owner results of this read and
    /// become the next family state. A completed family must remain selector-
    /// free and next-cursor-free; the other family can continue independently.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_next_page_with_selectors(
        &mut self,
        ledger: &mut ExperienceRevisionLedger,
        projection_id: ArtifactId,
        scope: &ObservationScope,
        fence: &StateFence,
        bank: BankStoreSnapshot<'_>,
        feedback: FeedbackStoreSnapshot<'_>,
        schedule: &RetentionSchedule,
        holds: &BTreeMap<String, RetentionHold>,
        bank_selector: Option<&str>,
        feedback_selector: Option<&str>,
        bank_next_cursor: PageBoundary,
        feedback_next_cursor: PageBoundary,
    ) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
        self.assemble_next_page_inner(
            ledger,
            projection_id,
            scope,
            fence,
            bank,
            feedback,
            schedule,
            holds,
            true,
            bank_selector,
            feedback_selector,
            bank_next_cursor,
            feedback_next_cursor,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn assemble_next_page_inner(
        &mut self,
        ledger: &mut ExperienceRevisionLedger,
        projection_id: ArtifactId,
        scope: &ObservationScope,
        fence: &StateFence,
        bank: BankStoreSnapshot<'_>,
        feedback: FeedbackStoreSnapshot<'_>,
        schedule: &RetentionSchedule,
        holds: &BTreeMap<String, RetentionHold>,
        validate_selectors: bool,
        bank_selector: Option<&str>,
        feedback_selector: Option<&str>,
        bank_next_cursor: PageBoundary,
        feedback_next_cursor: PageBoundary,
    ) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
        if self.is_complete() {
            return Err(GovernorObservationError::InvalidField {
                field: "consumer_page.read",
                reason: "paged consumer read already ended; both families must be restarted explicitly",
            });
        }
        if validate_selectors {
            validate_family_selector(
                &self.bank_state,
                bank_selector,
                "consumer_page.bank_selector",
            )?;
            validate_family_selector(
                &self.feedback_state,
                feedback_selector,
                "consumer_page.feedback_selector",
            )?;
        }
        validate_completed_family_cursor(
            &self.bank_state,
            &bank_next_cursor,
            "consumer_page.bank_next_cursor",
        )?;
        validate_completed_family_cursor(
            &self.feedback_state,
            &feedback_next_cursor,
            "consumer_page.feedback_next_cursor",
        )?;

        let bank_source_revision = if matches!(self.bank_state, ConsumerPagedFamilyState::Complete)
        {
            self.bank_projection
                .as_ref()
                .ok_or(GovernorObservationError::InvalidField {
                    field: "consumer_page.bank_projection",
                    reason: "completed bank enumeration has no retained page",
                })?
                .source_revision
                .clone()
        } else {
            bank.source_revision.clone()
        };
        let feedback_source_revision =
            if matches!(self.feedback_state, ConsumerPagedFamilyState::Complete) {
                self.feedback_projection
                    .as_ref()
                    .ok_or(GovernorObservationError::InvalidField {
                        field: "consumer_page.feedback_projection",
                        reason: "completed feedback enumeration has no retained page",
                    })?
                    .source_revision
                    .clone()
            } else {
                feedback.source_revision.clone()
            };
        let binding = ExperienceReadBinding::new(
            self.driver_instance,
            fence.clone(),
            self.bank_generation,
            bank_source_revision,
            self.feedback_generation,
            feedback_source_revision,
        )?;
        if matches!(self.bank_state, ConsumerPagedFamilyState::Complete) {
            ledger.retain_bank_binding(&binding)?;
        } else {
            ledger.rebuild_bank_for_binding(bank.records, &bank.source_revision, &binding)?;
        }
        if matches!(self.feedback_state, ConsumerPagedFamilyState::Complete) {
            ledger.retain_feedback_binding(&binding)?;
        } else {
            ledger.rebuild_feedback_for_binding(
                feedback.records,
                &feedback.source_revision,
                &binding,
            )?;
        }

        let bank_page = if matches!(self.bank_state, ConsumerPagedFamilyState::Complete) {
            None
        } else {
            Some(supply_bank_projection_from_store_paged(
                ledger,
                bank,
                projection_id.clone(),
                scope.clone(),
                fence.clone(),
                schedule,
                holds,
                bank_next_cursor,
            )?)
        };
        let feedback_page = if matches!(self.feedback_state, ConsumerPagedFamilyState::Complete) {
            None
        } else {
            Some(supply_feedback_projection_from_store_paged(
                ledger,
                feedback,
                projection_id,
                scope.clone(),
                fence.clone(),
                schedule,
                holds,
                feedback_next_cursor,
            )?)
        };

        let bank_result = match bank_page {
            Some(page) => {
                let next = page.next_cursor;
                let projection = page.projection;
                Some((projection, next))
            }
            None => None,
        };
        let feedback_result = match feedback_page {
            Some(page) => {
                let next = page.next_cursor;
                let projection = page.projection;
                Some((projection, next))
            }
            None => None,
        };

        let (bank_projection, bank_next, bank_next_state) = match bank_result {
            Some((projection, next)) => {
                revalidate_bank_projection_for_consumer(&projection, scope, fence)?;
                let next_state = state_after_page(next.clone())?;
                (projection, next, Some(next_state))
            }
            None => (
                self.bank_projection
                    .clone()
                    .ok_or(GovernorObservationError::InvalidField {
                        field: "consumer_page.bank_projection",
                        reason: "completed bank enumeration has no retained page",
                    })?,
                PageBoundary::ExplicitEnd,
                None,
            ),
        };
        let (feedback_projection, feedback_next, feedback_next_state) = match feedback_result {
            Some((projection, next)) => {
                revalidate_feedback_projection_for_consumer(&projection, scope, fence)?;
                let next_state = state_after_page(next.clone())?;
                (projection, next, Some(next_state))
            }
            None => (
                self.feedback_projection
                    .clone()
                    .ok_or(GovernorObservationError::InvalidField {
                        field: "consumer_page.feedback_projection",
                        reason: "completed feedback enumeration has no retained page",
                    })?,
                PageBoundary::ExplicitEnd,
                None,
            ),
        };

        // Commit both family transitions only after both pages and both
        // boundary proofs have validated. A malformed feedback page must not
        // leave the bank family advanced in the driver.
        if let Some(next_state) = bank_next_state {
            self.bank_state = next_state;
            self.bank_projection = Some(bank_projection.clone());
        }
        if let Some(next_state) = feedback_next_state {
            self.feedback_state = next_state;
            self.feedback_projection = Some(feedback_projection.clone());
        }

        Ok(PagedExperienceConsumerBundle {
            bank: bank_projection,
            feedback: feedback_projection,
            bank_next_cursor: bank_next,
            feedback_next_cursor: feedback_next,
            generation: self.generation(),
            binding,
        })
    }
}

fn state_after_page(
    next_cursor: PageBoundary,
) -> Result<ConsumerPagedFamilyState, GovernorObservationError> {
    match next_cursor {
        PageBoundary::MissingCursor => Err(GovernorObservationError::InvalidField {
            field: "consumer_page.next_cursor",
            reason: "owner page omitted next_cursor; missing is not an end proof",
        }),
        PageBoundary::ExplicitEnd => Ok(ConsumerPagedFamilyState::Complete),
        PageBoundary::Continuation(cursor) => Ok(ConsumerPagedFamilyState::Continuing(cursor)),
    }
}

fn validate_family_selector(
    state: &ConsumerPagedFamilyState,
    supplied: Option<&str>,
    field: &'static str,
) -> Result<(), GovernorObservationError> {
    let valid = match state {
        ConsumerPagedFamilyState::NeedsFirstPage | ConsumerPagedFamilyState::Complete => {
            supplied.is_none()
        }
        ConsumerPagedFamilyState::Continuing(expected) => supplied == Some(expected.as_str()),
    };
    if valid {
        Ok(())
    } else {
        Err(GovernorObservationError::InvalidField {
            field,
            reason: "supplied selector does not match the family's explicit first-page/continuation/completed state",
        })
    }
}

fn validate_completed_family_cursor(
    state: &ConsumerPagedFamilyState,
    next_cursor: &PageBoundary,
    field: &'static str,
) -> Result<(), GovernorObservationError> {
    if matches!(state, ConsumerPagedFamilyState::Complete)
        && !matches!(next_cursor, PageBoundary::ExplicitEnd)
    {
        return Err(GovernorObservationError::InvalidField {
            field,
            reason: "completed family requires an explicit owner end proof and cannot reopen",
        });
    }
    Ok(())
}

/// Produce the durable commit payload for one admitted bank record.
///
/// The durable-write join: the record must validate and its exact
/// revision must be tracked by `ledger` as admitted through this owner —
/// superseded revisions and never-admitted records fail closed here, so
/// the `capture_candidate` commit path can never be entered for material
/// this owner did not sequence. Returns the closed
/// [`ExperienceCommitParameters`] the `CommitExperienceBank` named
/// operation carries; execution stays with the store bridge (#19 lane),
/// which registers the name and enforces idempotency + revision conflict
/// durably.
pub fn produce_bank_commit(
    ledger: &ExperienceRevisionLedger,
    record: &ExperienceBankRecord,
    binding: &ExperienceReadBinding,
) -> Result<ExperienceCommitParameters, GovernorObservationError> {
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    match ledger.tracked_bank_revision_for_binding(&record.handle, binding) {
        Some(tracked) if tracked == record.bank_revision => {}
        _ => {
            return Err(GovernorObservationError::InvalidField {
                field: "bank_record.bank_revision",
                reason: "record revision was not admitted through this owner",
            });
        }
    }
    ExperienceCommitParameters::for_bank(record).map_err(GovernorObservationError::Observation)
}

/// Produce the durable commit payload for one admitted feedback record.
/// Same owner-sequencing gate as [`produce_bank_commit`].
pub fn produce_feedback_commit(
    ledger: &ExperienceRevisionLedger,
    record: &AgentFeedbackRecord,
    binding: &ExperienceReadBinding,
) -> Result<ExperienceCommitParameters, GovernorObservationError> {
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    match ledger.tracked_feedback_revision_for_binding(&record.handle, binding) {
        Some(tracked) if tracked == record.feedback_revision => {}
        _ => {
            return Err(GovernorObservationError::InvalidField {
                field: "feedback_record.feedback_revision",
                reason: "record revision was not admitted through this owner",
            });
        }
    }
    ExperienceCommitParameters::for_feedback(record).map_err(GovernorObservationError::Observation)
}

/// Decode bridge range-payload records into admitted bank records.
///
/// Each element is either a wrapper row as projected by the store range
/// backends (`{handle, revision, record_json, record_digest}`) or — for
/// owner-held fixtures only — a bare record document. Wrappers unwrap to
/// `record_json` after three fail-closed bindings: the wrapper `handle`
/// and `revision` must echo the document's own fields, and the wrapper
/// `record_digest` must equal the document's embedded digest; the
/// document then passes through [`parse_bank_record`] (deserialize plus
/// full digest re-proof from fields). A missing or non-array `records`
/// member fails closed: a malformed bridge payload is corruption
/// evidence, never an empty read. A single undecodable element fails the
/// whole read for the same reason — malformed material has no omission
/// class in the frozen contract, so it cannot travel as a gap. The
/// caller (terminal invocation loop) preserves element position for
/// diagnostics from its own iteration.
///
/// Producer contract (store side, both contours): range rows MUST carry
/// the four wrapper fields with `record_json` holding the verbatim
/// admitted document and `record_digest` repeating its digest. Bare
/// documents are accepted only as owner-held fixture input, never as a
/// substitute for the wrapper shape on the bridge path.
pub fn bank_records_from_range_payload(
    payload: &Value,
) -> Result<Vec<ExperienceBankRecord>, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    bank_records_from_page(&page)
}

/// Decode records from an already parsed owner range page.
///
/// The page boundary is deliberately not re-read here: callers that need a
/// paged result consume the same parsed envelope and carry its typed proof
/// into [`supply_bank_projection_from_store_paged`].
pub fn bank_records_from_page(
    page: &ExperienceRangePage,
) -> Result<Vec<ExperienceBankRecord>, GovernorObservationError> {
    let mut records = Vec::with_capacity(page.records.len());
    for member in &page.records {
        let document = unwrap_range_member(member, "bank_revision")?;
        records.push(parse_bank_record(&document)?);
    }
    Ok(records)
}

/// Decode bridge range-payload records into admitted feedback records.
/// Same wrapper-or-bare rule as [`bank_records_from_range_payload`],
/// binding the `feedback_revision` document field.
pub fn feedback_records_from_range_payload(
    payload: &Value,
) -> Result<Vec<AgentFeedbackRecord>, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    feedback_records_from_page(&page)
}

/// Decode feedback records from an already parsed owner range page.
pub fn feedback_records_from_page(
    page: &ExperienceRangePage,
) -> Result<Vec<AgentFeedbackRecord>, GovernorObservationError> {
    let mut records = Vec::with_capacity(page.records.len());
    for member in &page.records {
        let document = unwrap_range_member(member, "feedback_revision")?;
        records.push(parse_feedback_record(&document)?);
    }
    Ok(records)
}

/// Unwrap one range-payload element to its verbatim record document.
///
/// Wrapper rows (`record_json` string present) bind handle, revision,
/// and digest echoes against the embedded document before release; bare
/// record documents (no `record_json` member) pass through for
/// owner-held fixture input. Every mismatch is a typed envelope-mismatch
/// refusal, never a silent default.
#[cfg(test)]
#[allow(dead_code)]
mod generation_binding_compile_fixtures {
    use super::{
        ConsumerPagedReadDriver, ExperienceBankRecord, ExperienceReadBinding,
        ExperienceRevisionLedger,
    };

    /// Compile fixture: a page from another retained driver is never current.
    fn stale_page_binding_is_rejected(
        current: &ConsumerPagedReadDriver,
        stale: &super::PagedExperienceConsumerBundle,
    ) -> bool {
        !current.binding_is_current(stale)
    }

    /// Compile fixture: a commit ledger rebuild cannot omit the exact owner
    /// source-revision check before a generation token is accepted.
    fn source_revision_gate_compiles(
        ledger: &mut ExperienceRevisionLedger,
        records: &[ExperienceBankRecord],
        source_revision: &str,
        binding: &ExperienceReadBinding,
    ) -> bool {
        ledger
            .rebuild_bank_for_binding(records, source_revision, binding)
            .is_ok()
    }
}

fn unwrap_range_member(
    member: &Value,
    revision_field: &'static str,
) -> Result<String, GovernorObservationError> {
    let object = member
        .as_object()
        .ok_or(GovernorObservationError::InvalidField {
            field: "audit_range.records",
            reason: "range record must be an object",
        })?;
    let Some(document) = object.get("record_json").and_then(Value::as_str) else {
        return serde_json::to_string(member).map_err(|_| GovernorObservationError::InvalidField {
            field: "audit_range.records",
            reason: "range record must re-encode canonically",
        });
    };
    let parsed: Value =
        serde_json::from_str(document).map_err(|_| GovernorObservationError::InvalidField {
            field: "audit_range.record_json",
            reason: "wrapped record document must decode",
        })?;
    let body = parsed
        .as_object()
        .ok_or(GovernorObservationError::InvalidField {
            field: "audit_range.record_json",
            reason: "wrapped record document must be an object",
        })?;
    let handle = object.get("handle").and_then(Value::as_str).ok_or(
        GovernorObservationError::InvalidField {
            field: "audit_range.handle",
            reason: "wrapper handle must be present text",
        },
    )?;
    let revision = object.get("revision").and_then(Value::as_u64).ok_or(
        GovernorObservationError::InvalidField {
            field: "audit_range.revision",
            reason: "wrapper revision must be a count",
        },
    )?;
    let digest = object.get("record_digest").and_then(Value::as_str).ok_or(
        GovernorObservationError::InvalidField {
            field: "audit_range.record_digest",
            reason: "wrapper digest must be present text",
        },
    )?;
    if body.get("handle").and_then(Value::as_str) != Some(handle) {
        return Err(GovernorObservationError::InvalidField {
            field: "audit_range.handle",
            reason: "wrapper handle must echo the document handle",
        });
    }
    if body.get(revision_field).and_then(Value::as_u64) != Some(revision) {
        return Err(GovernorObservationError::InvalidField {
            field: "audit_range.revision",
            reason: "wrapper revision must echo the document revision",
        });
    }
    if body.get("digest").and_then(Value::as_str) != Some(digest) {
        return Err(GovernorObservationError::InvalidField {
            field: "audit_range.record_digest",
            reason: "wrapper digest must echo the document digest",
        });
    }
    Ok(document.to_owned())
}

/// Require an owner page's exact state fence to equal the consumer fence.
///
/// A syntactically valid page from another fence is not a usable page: it must
/// be rejected before records or continuation state can advance.
pub fn validate_experience_range_page_fence(
    page: &ExperienceRangePage,
    fence: &StateFence,
) -> Result<(), GovernorObservationError> {
    if page.state_fence != *fence {
        return Err(GovernorObservationError::InvalidField {
            field: "experience.page.state_fence",
            reason: "owner page fence does not equal the consumer fence",
        });
    }
    Ok(())
}

/// Consume one bank range payload into a validated bank projection.
///
/// The payload-to-projection caller: decodes the bridge payload, then
/// runs the full store-snapshot join
/// ([`supply_bank_projection_from_store`]: ledger rebuild, retention
/// gating, snapshot ref resolution, consumer revalidation). Owner
/// coverage, omissions, and the source-revision marker stay
/// caller-supplied owner evidence — this driver never invents them.
/// Cross-copy seam: the B terminal bank invocation calls this with the
/// bridge payload plus owner coverage for one scope and fence.
#[allow(clippy::too_many_arguments)]
pub fn consume_bank_range_payload(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    payload: &Value,
    source_revision: String,
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<BankProjection, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    validate_experience_range_page_fence(&page, &fence)?;
    let records = bank_records_from_page(&page)?;
    supply_bank_projection_from_store(
        ledger,
        BankStoreSnapshot {
            records: &records,
            source_revision,
            coverage,
            omissions,
        },
        projection_id,
        scope,
        fence,
        schedule,
        holds,
    )
}

/// Consume one feedback range payload into a validated feedback
/// projection. Same payload-to-projection rule as
/// [`consume_bank_range_payload`]; cross-copy seam for the B terminal
/// feedback invocation.
#[allow(clippy::too_many_arguments)]
pub fn consume_feedback_range_payload(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    payload: &Value,
    source_revision: String,
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<FeedbackProjection, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    validate_experience_range_page_fence(&page, &fence)?;
    let records = feedback_records_from_page(&page)?;
    supply_feedback_projection_from_store(
        ledger,
        FeedbackStoreSnapshot {
            records: &records,
            source_revision,
            coverage,
            omissions,
        },
        projection_id,
        scope,
        fence,
        schedule,
        holds,
    )
}

/// Consume one bank range payload into one validated bank page.
///
/// The owner envelope is parsed exactly once. Its records and typed
/// `next_cursor` boundary are then consumed from the same parsed page, so a
/// missing member can never be re-read as an end-of-stream `None`. Single-page
/// callers stay on [`consume_bank_range_payload`]; multi-page callers iterate
/// per the contract on [`PagedExperienceConsumerBundle`].
#[allow(clippy::too_many_arguments)]
pub fn consume_bank_range_payload_paged(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    payload: &Value,
    source_revision: String,
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<PagedBankProjection, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    validate_experience_range_page_fence(&page, &fence)?;
    let records = bank_records_from_page(&page)?;
    supply_bank_projection_from_store_paged(
        ledger,
        BankStoreSnapshot {
            records: &records,
            source_revision,
            coverage,
            omissions,
        },
        projection_id,
        scope,
        fence,
        schedule,
        holds,
        page.next_cursor,
    )
}

/// Consume one feedback range payload into one validated feedback page.
///
/// The same parsed-envelope rule as [`consume_bank_range_payload_paged`]
/// applies: records and the typed boundary come from one owner page parse.
#[allow(clippy::too_many_arguments)]
pub fn consume_feedback_range_payload_paged(
    ledger: &mut ExperienceRevisionLedger,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    payload: &Value,
    source_revision: String,
    coverage: ProjectionCoverage,
    omissions: Vec<ProjectionOmission>,
) -> Result<PagedFeedbackProjection, GovernorObservationError> {
    let page = parse_experience_range_page(payload)?;
    validate_experience_range_page_fence(&page, &fence)?;
    let records = feedback_records_from_page(&page)?;
    supply_feedback_projection_from_store_paged(
        ledger,
        FeedbackStoreSnapshot {
            records: &records,
            source_revision,
            coverage,
            omissions,
        },
        projection_id,
        scope,
        fence,
        schedule,
        holds,
        page.next_cursor,
    )
}
