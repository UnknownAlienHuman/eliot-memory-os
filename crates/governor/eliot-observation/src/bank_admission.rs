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
    bank: BTreeMap<String, u64>,
    feedback: BTreeMap<String, u64>,
}

impl ExperienceRevisionLedger {
    /// Create an empty ledger. Prefer [`rebuild_bank`](Self::rebuild_bank)
    /// + [`rebuild_feedback`](Self::rebuild_feedback) after restarts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild bank sequencing from admitted records (greatest revision
    /// wins per handle). Idempotent: rebuilding twice changes nothing.
    pub fn rebuild_bank(&mut self, records: &[ExperienceBankRecord]) {
        for record in records {
            let entry = self
                .bank
                .entry(record.handle.as_str().to_owned())
                .or_insert(0);
            if record.bank_revision > *entry {
                *entry = record.bank_revision;
            }
        }
    }

    /// Rebuild feedback sequencing from admitted records.
    pub fn rebuild_feedback(&mut self, records: &[AgentFeedbackRecord]) {
        for record in records {
            let entry = self
                .feedback
                .entry(record.handle.as_str().to_owned())
                .or_insert(0);
            if record.feedback_revision > *entry {
                *entry = record.feedback_revision;
            }
        }
    }

    /// Check a bank revision against the tracked greatest and track it.
    /// Genesis (untracked handle) accepts any revision; afterwards only a
    /// strictly greater revision passes.
    pub fn track_bank(
        &mut self,
        handle: &ArtifactId,
        revision: u64,
    ) -> Result<(), GovernorObservationError> {
        match self.bank.get(handle.as_str()) {
            Some(last) if revision <= *last => Err(GovernorObservationError::InvalidField {
                field: "bank_record.bank_revision",
                reason: "revision is not strictly greater than the tracked revision",
            }),
            _ => {
                self.bank.insert(handle.as_str().to_owned(), revision);
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
        match self.feedback.get(handle.as_str()) {
            Some(last) if revision <= *last => Err(GovernorObservationError::InvalidField {
                field: "feedback_record.feedback_revision",
                reason: "revision is not strictly greater than the tracked revision",
            }),
            _ => {
                self.feedback.insert(handle.as_str().to_owned(), revision);
                Ok(())
            }
        }
    }

    /// Greatest tracked bank revision for one handle, when admitted
    /// through this owner. The commit producer requires an exact match:
    /// only the current revision of each handle may enter the durable
    /// path, never a superseded or never-admitted one.
    pub fn tracked_bank_revision(&self, handle: &ArtifactId) -> Option<u64> {
        self.bank.get(handle.as_str()).copied()
    }

    /// Greatest tracked feedback revision for one handle.
    pub fn tracked_feedback_revision(&self, handle: &ArtifactId) -> Option<u64> {
        self.feedback.get(handle.as_str()).copied()
    }
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
/// Single-page entry: the owner continuation cursor is not threaded
/// here (this predates the five-part fence+heads `next_cursor` the
/// owner store mints). Multi-page callers use
/// [`supply_bank_projection_from_store_paged`], which echoes the opaque
/// owner cursor alongside the identical projection join.
pub fn supply_bank_projection_from_store(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: BankStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
) -> Result<BankProjection, GovernorObservationError> {
    ledger.rebuild_bank(snapshot.records);
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
/// Single-page entry (cursor dropped); multi-page callers use
/// [`supply_feedback_projection_from_store_paged`].
pub fn supply_feedback_projection_from_store(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: FeedbackStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
) -> Result<FeedbackProjection, GovernorObservationError> {
    ledger.rebuild_feedback(snapshot.records);
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

/// Fail-closed gate for an owner-minted continuation cursor.
///
/// The cursor is opaque here: the store owner mints the five-part
/// fence+heads shape (`audit:{fence_digest}:{heads_digest}:{ordinal}:{bound}`)
/// and the store owner alone parses it (`audit_cursor_issue` /
/// `audit_cursor_parse` in the store-api owner). This lane never parses,
/// rebuilds, or re-mints a cursor; it only echoes what the owner issued.
/// A present-but-blank or control-bearing cursor is malformed owner
/// evidence and fails closed rather than silently starting, skipping,
/// or duplicating a page.
fn check_owner_cursor(
    cursor: Option<String>,
    field: &'static str,
) -> Result<Option<String>, GovernorObservationError> {
    match cursor {
        None => Ok(None),
        Some(cursor) if cursor.trim().is_empty() || cursor.chars().any(char::is_control) => {
            Err(GovernorObservationError::InvalidField {
                field,
                reason: "owner continuation cursor is malformed; fail closed, never skip or duplicate a page",
            })
        }
        Some(cursor) => Ok(Some(cursor)),
    }
}

/// One bank page: the validated projection plus the opaque owner
/// continuation cursor for the next page (`None` ends enumeration).
///
/// `BankProjection` itself stays frozen in its owner crate (digest-bound,
/// `deny_unknown_fields`): the cursor travels alongside the projection,
/// never inside it.
pub struct PagedBankProjection {
    /// Validated bank envelope for this page, same join as
    /// [`supply_bank_projection_from_store`].
    pub projection: BankProjection,
    /// Opaque owner-minted cursor for the next page, or `None` when this
    /// page ends the enumeration. Echoed verbatim from the owner store;
    /// never constructed or parsed in this lane.
    pub next_cursor: Option<String>,
}

/// One feedback page: same alongside-cursor rule as
/// [`PagedBankProjection`].
pub struct PagedFeedbackProjection {
    /// Validated feedback envelope for this page.
    pub projection: FeedbackProjection,
    /// Opaque owner-minted cursor for the next page, or `None` when this
    /// page ends the enumeration.
    pub next_cursor: Option<String>,
}

/// Supply one validated bank page from a durable store snapshot.
///
/// Identical projection join to [`supply_bank_projection_from_store`];
/// the extra `next_cursor` is the opaque owner-minted continuation
/// cursor for the page the snapshot was read from. It is echoed into
/// [`PagedBankProjection::next_cursor`] with only the fail-closed
/// malformed gate ([`check_owner_cursor`]): no parsing, no authority
/// invention. The pre-existing single-page supplier delegates here with
/// `None`, so external single-page callers keep compiling unchanged.
#[allow(clippy::too_many_arguments)]
pub fn supply_bank_projection_from_store_paged(
    ledger: &mut ExperienceRevisionLedger,
    snapshot: BankStoreSnapshot<'_>,
    projection_id: ArtifactId,
    scope: ObservationScope,
    fence: StateFence,
    schedule: &RetentionSchedule,
    holds: &BTreeMap<String, RetentionHold>,
    next_cursor: Option<String>,
) -> Result<PagedBankProjection, GovernorObservationError> {
    let next_cursor = check_owner_cursor(next_cursor, "bank_page.next_cursor")?;
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
    next_cursor: Option<String>,
) -> Result<PagedFeedbackProjection, GovernorObservationError> {
    let next_cursor = check_owner_cursor(next_cursor, "feedback_page.next_cursor")?;
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

/// Both owner envelopes for one page, edge-re-resolved, plus the opaque
/// owner continuation cursors for the next page.
///
/// Multi-page contract (owner five-part fence+heads cursors):
/// the consumer iterates a family by echoing that family's cursor back
/// to the owner store as the next read's cursor selector until the
/// cursor is `None`. Bank and feedback paginate independently: each
/// family's cursor resumes only its own enumeration. A fence/heads
/// mismatch on the next page (the owner store fails the cursor closed
/// because a commit advanced a revision head or the fence moved) means
/// restart that family's enumeration from the headless first page —
/// never skip ahead, never replay rows into a duplicate, never treat a
/// rejected cursor as truncation. Each family records its own progress in
/// [`ConsumerFamilyState`], and a family is complete only when the owner
/// issued no next cursor for it; any family short of that, including one
/// restarted from the head, is a partial read, never a complete one.
pub struct PagedExperienceConsumerBundle {
    /// Assembled bank envelope for this page.
    pub bank: BankProjection,
    /// Assembled feedback envelope for this page.
    pub feedback: FeedbackProjection,
    /// Opaque owner cursor for the next bank page (`None` ends it).
    pub bank_next_cursor: Option<String>,
    /// Opaque owner cursor for the next feedback page (`None` ends it).
    pub feedback_next_cursor: Option<String>,
}

/// Assemble and edge-consume one page of both experience envelopes.
///
/// Paged entry of [`assemble_experience_for_consumer`]: runs the same
/// per-family supply join plus consumer-edge re-resolution, then echoes
/// the opaque owner continuation cursors (fail-closed on malformed, no
/// parsing in this lane) into [`PagedExperienceConsumerBundle`]. See its
/// multi-page contract for iteration, per-family independence, and the
/// restart-instead-of-skip/dup rule.
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
    bank_next_cursor: Option<String>,
    feedback_next_cursor: Option<String>,
) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
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
    })
}

/// Explicit per-family progress of one paged consumer read.
///
/// Each source family carries its own state, so bank and feedback
/// progress are never conflated by a shared cursor pair or a shared page
/// counter. This is the local form of the I5.20 stable-scope rule ("if
/// every dependency revision matches, publish; / else retry once or
/// return stale/churn directive"): a family advances only on the cursor
/// the owner issued for that same read, and a restart is the bounded
/// retry, never a completion claim.
///
/// Variant contract:
///
/// - [`ConsumerFamilyState::Complete`]: an owner-observed fact, never an
///   inference. It is recorded only from a page whose owner-issued next
///   cursor for this family was `None`; no counter, elapsed iteration or
///   sibling family's state can produce it.
/// - [`ConsumerFamilyState::NeedsFirstPage`]: no page of this family has
///   been assembled since that family's last restart, so the next
///   selector is the headless first page.
/// - [`ConsumerFamilyState::Continuing`]: carries the owner-issued cursor
///   that produced this family's most recent page, and is the only state
///   that supplies a next-read selector.
///
/// No `Default` is derived: the headless start state is `NeedsFirstPage`
/// per family, which is a decision about an unfinished read rather than a
/// neutral value, so a defaulted state would let a family that has never
/// started read as already decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumerFamilyState {
    /// No page of this family has been assembled since that family's last
    /// restart; the next read selects the headless first page.
    NeedsFirstPage,
    /// The owner-issued cursor that produced this family's most recent
    /// page; supplying it selects this family's next page.
    Continuing(String),
    /// The owner returned no next cursor for this family, so this
    /// family's enumeration is complete. An owner-observed fact recorded
    /// only from a page whose owner-issued next cursor for this family
    /// was `None`, never an inference from a counter, an elapsed
    /// iteration or a sibling family's state.
    Complete,
}

/// Echo-next-cursor driver for the multi-page consumer read.
///
/// Production loop driver over [`assemble_experience_for_consumer_paged`]:
/// the caller performs each owner-store read with the cursors this driver
/// exposes ([`ConsumerPagedReadDriver::bank_cursor`] /
/// [`ConsumerPagedReadDriver::feedback_cursor`]), then hands the fresh
/// caller-supplied snapshots plus the owner-issued next cursors from that
/// read to [`ConsumerPagedReadDriver::assemble_next_page`], which runs the
/// same per-family supply join plus consumer-edge re-resolution and stores
/// the echoed cursors as the next iteration's selectors. The loop ends when
/// the owner returned no next cursor for both families, which
/// [`ConsumerPagedReadDriver::is_complete`] reports; anything else is a
/// partial read, never a complete one. Per-family progress is carried by
/// [`ConsumerFamilyState`], so a restart marks only the restarted family
/// incomplete and never completes or rewinds the other family.
///
/// Boundary: this lane never performs the store read and never parses or
/// mints cursors. Snapshots stay caller-supplied inputs on every iteration;
/// the driver only echoes the opaque owner cursors and revalidates through
/// [`assemble_experience_for_consumer_paged`]. A fence/heads mismatch is
/// reported by the owner store failing the echoed cursor closed (a commit
/// advanced a revision head or the fence moved): the caller restarts that
/// family's enumeration from the headless first page with
/// [`ConsumerPagedReadDriver::restart_bank_from_head`] /
/// [`ConsumerPagedReadDriver::restart_feedback_from_head`] — never skip
/// ahead, never replay rows into a duplicate, never treat a rejected
/// cursor as truncation. Families paginate independently: restarting one
/// never touches the other's progress, and never completes it.
pub struct ConsumerPagedReadDriver {
    /// Bank family's own progress; the only mutable state the driver
    /// owns for bank enumeration.
    bank: ConsumerFamilyState,
    /// Feedback family's own progress, paginated independently of `bank`.
    feedback: ConsumerFamilyState,
}

impl ConsumerPagedReadDriver {
    /// Start a headless read: both families enumerate from their first
    /// page, each family explicitly incomplete.
    pub fn headless() -> Self {
        Self {
            bank: ConsumerFamilyState::NeedsFirstPage,
            feedback: ConsumerFamilyState::NeedsFirstPage,
        }
    }

    /// Opaque bank cursor for the next owner-store read: a selector
    /// exactly when bank is [`ConsumerFamilyState::Continuing`].
    ///
    /// `None` covers both remaining states and is therefore not a
    /// completion signal: it selects bank's headless first page when bank
    /// is `NeedsFirstPage`, and is never a valid next selector once bank
    /// is `Complete`. Termination is
    /// [`ConsumerPagedReadDriver::is_complete`], never this `None`.
    pub fn bank_cursor(&self) -> Option<&str> {
        match &self.bank {
            ConsumerFamilyState::Continuing(cursor) => Some(cursor.as_str()),
            ConsumerFamilyState::NeedsFirstPage | ConsumerFamilyState::Complete => None,
        }
    }

    /// Opaque feedback cursor for the next owner-store read. Same
    /// continuation-only rule as [`ConsumerPagedReadDriver::bank_cursor`].
    pub fn feedback_cursor(&self) -> Option<&str> {
        match &self.feedback {
            ConsumerFamilyState::Continuing(cursor) => Some(cursor.as_str()),
            ConsumerFamilyState::NeedsFirstPage | ConsumerFamilyState::Complete => None,
        }
    }

    /// `true` only when both families are [`ConsumerFamilyState::Complete`],
    /// that is when the owner returned no next cursor for both families.
    ///
    /// Two `None` selectors are not completion: a family restarted from
    /// the head is `NeedsFirstPage` while its sibling may already be
    /// `Complete`, and that read is still unfinished.
    pub fn is_complete(&self) -> bool {
        self.bank == ConsumerFamilyState::Complete && self.feedback == ConsumerFamilyState::Complete
    }

    /// Restart bank enumeration from the headless first page after the
    /// owner store rejects the echoed bank cursor (fence/heads mismatch).
    ///
    /// Bank becomes explicitly incomplete again, never `Complete`: a
    /// restart is the bounded retry of the I5.20 stable-scope rule ("else
    /// retry once or return stale/churn directive"), so it must not read
    /// as a completion claim even when the other family has finished.
    /// Feedback enumeration is untouched: families paginate independently.
    pub fn restart_bank_from_head(&mut self) {
        self.bank = ConsumerFamilyState::NeedsFirstPage;
    }

    /// Restart feedback enumeration from the headless first page. Same
    /// independence rule as
    /// [`ConsumerPagedReadDriver::restart_bank_from_head`]: feedback
    /// becomes explicitly incomplete again, never `Complete`, and bank
    /// enumeration is untouched.
    pub fn restart_feedback_from_head(&mut self) {
        self.feedback = ConsumerFamilyState::NeedsFirstPage;
    }

    /// Assemble the next consumer page from fresh caller-supplied
    /// snapshots and the owner-issued next cursors of this read, then
    /// record each family's owner-observed progress as the next
    /// iteration's selector.
    ///
    /// One call advances both families, so it fails closed only when the
    /// read has already ended ([`ConsumerPagedReadDriver::is_complete`]):
    /// a family that is already `Complete` while its sibling still has a
    /// page left is a normal restartable state, not an ended read, and
    /// re-calling past the end would replay the last page into a
    /// duplicate, so that errors instead of assembling.
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
        bank_next_cursor: Option<String>,
        feedback_next_cursor: Option<String>,
    ) -> Result<PagedExperienceConsumerBundle, GovernorObservationError> {
        if self.is_complete() {
            return Err(GovernorObservationError::InvalidField {
                field: "consumer_page.read",
                reason: "paged consumer read already ended; the owner returned no next cursor for both families, never replay the last page",
            });
        }
        let page = assemble_experience_for_consumer_paged(
            ledger,
            projection_id,
            scope,
            fence,
            bank,
            feedback,
            schedule,
            holds,
            bank_next_cursor,
            feedback_next_cursor,
        )?;
        self.bank = family_state_after_page(page.bank_next_cursor.as_deref());
        self.feedback = family_state_after_page(page.feedback_next_cursor.as_deref());
        Ok(page)
    }
}

/// Map one family after an assembled page: the owner's next cursor is
/// the only evidence of that family's progress.
///
/// `None` is the owner reporting no next cursor, which is the sole way a
/// family becomes [`ConsumerFamilyState::Complete`]; any other cursor
/// means the family continues from exactly the cursor that produced this
/// page.
fn family_state_after_page(next_cursor: Option<&str>) -> ConsumerFamilyState {
    match next_cursor {
        Some(cursor) => ConsumerFamilyState::Continuing(cursor.to_owned()),
        None => ConsumerFamilyState::Complete,
    }
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
) -> Result<ExperienceCommitParameters, GovernorObservationError> {
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    match ledger.tracked_bank_revision(&record.handle) {
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
) -> Result<ExperienceCommitParameters, GovernorObservationError> {
    record
        .validate()
        .map_err(GovernorObservationError::Observation)?;
    match ledger.tracked_feedback_revision(&record.handle) {
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
    let members = payload.get("records").and_then(Value::as_array).ok_or(
        GovernorObservationError::InvalidField {
            field: "audit_range.records",
            reason: "range payload must carry a records array",
        },
    )?;
    let mut records = Vec::with_capacity(members.len());
    for member in members {
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
    let members = payload.get("records").and_then(Value::as_array).ok_or(
        GovernorObservationError::InvalidField {
            field: "audit_range.records",
            reason: "range payload must carry a records array",
        },
    )?;
    let mut records = Vec::with_capacity(members.len());
    for member in members {
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
    let records = bank_records_from_range_payload(payload)?;
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
    let records = feedback_records_from_range_payload(payload)?;
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

/// Extract the opaque owner continuation cursor from a bridge
/// range-payload envelope.
///
/// The store backends bind `next_cursor` into the payload (`None`
/// serializes as `null` when the page ends enumeration). A present
/// non-text member is a malformed bridge envelope and fails closed;
/// text passes through the same blank/control gate as
/// [`check_owner_cursor`]. No cursor is ever parsed or minted here.
fn owner_cursor_from_range_payload(
    payload: &Value,
) -> Result<Option<String>, GovernorObservationError> {
    match payload.get("next_cursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(cursor)) => {
            check_owner_cursor(Some(cursor.clone()), "audit_range.next_cursor")
        }
        Some(_) => Err(GovernorObservationError::InvalidField {
            field: "audit_range.next_cursor",
            reason: "owner continuation cursor must be text or null",
        }),
    }
}

/// Consume one bank range payload into one validated bank page.
///
/// Same payload-to-projection rule as [`consume_bank_range_payload`],
/// plus the opaque owner `next_cursor` echoed from the payload envelope
/// into [`PagedBankProjection::next_cursor`]. Single-page callers stay
/// on [`consume_bank_range_payload`]; multi-page callers iterate per
/// the contract on [`PagedExperienceConsumerBundle`].
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
    let records = bank_records_from_range_payload(payload)?;
    let next_cursor = owner_cursor_from_range_payload(payload)?;
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
        next_cursor,
    )
}

/// Consume one feedback range payload into one validated feedback page.
/// Same opaque-cursor echo rule as [`consume_bank_range_payload_paged`].
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
    let records = feedback_records_from_range_payload(payload)?;
    let next_cursor = owner_cursor_from_range_payload(payload)?;
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
        next_cursor,
    )
}
