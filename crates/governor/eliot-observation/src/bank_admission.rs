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
//!   `ExperienceBankCommit` / `AgentFeedbackCommit` payload
//!   through the existing Governor → `PreparedTransition` → store-bridge
//!   contour (#18/#19 lanes own that execution).
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
//!
//! Never: store/vendor I/O, credential handling, lifecycle/support/
//! influence mutation, epistemic promotion, score/verdict emission, or
//! retention-policy invention (see `resolve_retention_read`).

use eliot_contracts::{ArtifactId, StateFence};
use eliot_observation_contracts::{
    AgentFeedbackRecord, BankProjection, ExperienceBankRecord, ExperienceRecordRef, FeedbackClass,
    FeedbackProjection, JournalProjection, ObservationScope, PrivacyRetentionDisclosure,
    ProducerTrace, ProjectionCoverage, ProjectionOmission, bank_record_ref, feedback_record_ref,
};

use crate::GovernorObservationError;

/// Owner source identity minted bank cursors under.
pub const BANK_SOURCE_ID: &str = "governor.experience-bank";
/// Owner source identity minted feedback cursors under.
pub const FEEDBACK_SOURCE_ID: &str = "governor.agent-feedback";

/// Admit one experience-bank record.
///
/// Requires at least one source journal ref (empty) and unique refs
/// (duplicate); delegates shape/digest authority to
/// [`ExperienceBankRecord::admit`]. Returns the admitted record; durable
/// commit flows through the `capture_candidate` named operation, never
/// from this pure function.
pub fn admit_bank_record(
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
    ExperienceBankRecord::admit(
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
    .map_err(GovernorObservationError::Observation)
}

/// Admit one agent-feedback record.
///
/// Consent is required and explicit: an empty consent ref fails closed
/// (absence is not consent). Input origin travels in `origin`; the record
/// stays candidate-only (no verdict/score field exists to promote).
pub fn admit_feedback_record(
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
    AgentFeedbackRecord::admit(
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
    .map_err(GovernorObservationError::Observation)
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
