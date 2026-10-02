//! Execution-unit ingest driver for durable host-event ingest (issue #2645
//! W1/W3, external audit 5848315622).
//!
//! [`produce_execution_unit_allowed`](crate::produce_execution_unit_allowed) and
//! [`produce_execution_unit_redacted`](crate::produce_execution_unit_redacted)
//! own the execution-unit producer: they normalize through the exact recorded #361
//! binding and the governing #369 admission, derive the requested/actual route
//! digests from those owners, and commit. They were reachable from no
//! production caller, which left the `physical_observation: Some(...)` staging
//! branch and the whole route-evidence relation structurally unreachable for the
//! execution-unit events they exist to protect.
//!
//! This module is that production caller.
//! [`run_ingest_for_fingerprint`](crate::run_ingest_for_fingerprint) — the
//! per-fingerprint ingest run flow the run owner invokes — drives
//! [`produce_execution_unit_events`] once per declared execution-unit event
//! before the ordinary reconnect/intake/coverage path, so a produced event is
//! never staged and dropped: it is committed, then delivered and projected by
//! [`drive_reconnect_observed`](crate::drive_reconnect_observed), and its
//! retained route evidence reaches the coverage denominator resolved from
//! committed records.
//!
//! OWNER MATERIAL IS NEVER SYNTHESIZED HERE. Each
//! [`ExecutionUnitDriverEvent`] carries an [`ExecutionUnitFrame`] whose
//! `binding`, `admission` and optional `physical_observation` are references to
//! receipts the run owner already holds; the driver passes them through
//! unchanged and never defaults, synthesizes or reconstructs a value. A
//! pre-observation event declares `None` explicitly, which is the owner's own
//! statement that no observation applies yet — not a driver-invented absence.
//!
//! READBACK IS BOUND TO THE OPERATION. After each produce, the driver reads the
//! ORIGINAL retained relation back from the committed journal record
//! ([`DurableHostEventJournal::committed_route_evidence`]) and re-validates it
//! with that value's own existing validator
//! ([`CommittedRouteEvidenceRelation::verify_against`], which runs the
//! relation's `validate()` and compares it against a fresh resolve from the
//! same owners). Existence and shape prove nothing here: the retained relation
//! must equal what these owners resolve to, or the run fails typed.
//!
//! COMPLETENESS IS CHECKED AGAINST THE DECLARED ROSTER. The driver compares the
//! set of produced keys with the set of keys the caller declared, so a dropped,
//! duplicated or mis-sequenced event fails the run instead of quietly shrinking
//! the run. The journal's own record list is never used as its own expectation.

use std::collections::BTreeSet;

use eliot_agent_api::route_receipts::CommittedRouteEvidenceRelation;
use thiserror::Error;

use crate::{
    DurableHostEventJournal, EventKey, ExecutionUnitFrame, IngestError, ProduceOutcome,
    ProducerError, produce_execution_unit_allowed, produce_execution_unit_redacted,
};

/// Disclosure decision the run owner declares for one execution-unit event.
///
/// This is not a flag that labels a value redacted: the two arms select the two
/// existing producer entry points, and the withheld arm really runs
/// [`produce_execution_unit_redacted`], which stores the deterministic redacted
/// projection plus its redaction receipt and never the original bytes. The
/// redacted field classes are owner-declared, exactly as the session-only
/// [`produce_redacted`](crate::produce_redacted) path requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionUnitDisclosure {
    /// The transport bytes are admissible raw; denied content still fails closed
    /// inside the producer with
    /// [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation).
    Admissible,
    /// The original bytes cannot be retained: the declared field classes are
    /// hashed and scanned but never stored.
    Withheld(Vec<String>),
}

/// One execution-unit event handed to the driver by the run owner.
///
/// The owner material lives in the frame and is passed through unchanged:
/// `frame.binding` is the recorded #361 provider-execution binding,
/// `frame.admission` the governing #369 admitted-route receipt, and
/// `frame.physical_observation` the applicable #369 physical-route observation
/// or the owner's explicit statement that none applies yet.
#[derive(Clone, Debug)]
pub struct ExecutionUnitDriverEvent<'a> {
    /// The exact ACP frame plus its owner-issued execution-unit material.
    pub frame: ExecutionUnitFrame<'a>,
    /// The run owner's disclosure decision for these bytes.
    pub disclosure: ExecutionUnitDisclosure,
}

/// One produced execution-unit event: the producer outcome plus the retained
/// route evidence read back from the committed record and re-verified against
/// this event's own owner material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducedExecutionUnitEvent {
    /// Producer outcome: journal key, freshness, resulting durable cursor, and
    /// whether the stored bytes are the deterministic redacted projection.
    pub outcome: ProduceOutcome,
    /// The versioned relation retained on the committed record, re-validated
    /// against the binding, admission and applicable observation of this event.
    pub route_evidence: CommittedRouteEvidenceRelation,
}

/// Typed failure of the execution-unit ingest run.
///
/// Both producer failures and journal failures stay typed across the layer
/// boundary: nothing is flattened into a string or a catch-all, and an
/// [`IngestError`] from the ordinary run flow below this driver is never
/// re-wrapped as a producer error.
#[derive(Debug, Error)]
pub enum ExecutionUnitRunError {
    /// The execution-unit producer refused the event (framing, normalization,
    /// privacy, or an owner/route validation failure at staging).
    #[error(transparent)]
    Event(#[from] ProducerError),
    /// The ordinary reconnect/coverage run flow refused the run.
    #[error(transparent)]
    Ingest(#[from] IngestError),
}

/// Produces every declared execution-unit event through the existing execution-unit
/// producer entry points and proves each one's retained route evidence against
/// its own owner material.
///
/// For each event in `events` the driver calls
/// [`produce_execution_unit_allowed`] or
/// [`produce_execution_unit_redacted`] according to the declared
/// [`ExecutionUnitDisclosure`], so the `physical_observation: Some(...)` staging
/// branch is reached by a real event: a matched observation stages its observed
/// actual digest, a valid divergent observation stages Diverged evidence, an
/// `Unobserved` observation or a pre-observation `None` stages with no actual
/// digest, and a receipt from another observation boundary (or substituted
/// caller digests, which this path never accepts) rejects before any mutation.
///
/// Each produced key is then read back from the committed record and its
/// retained relation re-validated with
/// [`CommittedRouteEvidenceRelation::verify_against`] against the very binding,
/// admission and observation that event carried. Finally the produced key set
/// is compared with the declared roster; a missing, extra or duplicated key
/// fails the run typed. Failures propagate unchanged; no partial outcome is
/// returned.
pub fn produce_execution_unit_events(
    owner: &mut DurableHostEventJournal,
    events: &[ExecutionUnitDriverEvent<'_>],
    delivered_streams: &[&str],
) -> Result<Vec<ProducedExecutionUnitEvent>, ExecutionUnitRunError> {
    // Fail before any mutation when a declared event rides a stream the run flow
    // never drives: such an event would be committed and then never delivered or
    // projected, which is exactly the produced-and-dropped shape this driver
    // exists to remove.
    for event in events {
        if !delivered_streams.contains(&event.frame.stream_id) {
            return Err(IngestError::InvalidInput("execution_unit.stream_id").into());
        }
    }

    let declared: BTreeSet<EventKey> = events
        .iter()
        .map(|event| EventKey {
            stream_id: event.frame.stream_id.to_owned(),
            sequence: event.frame.stream_sequence,
        })
        .collect();
    if declared.len() != events.len() {
        return Err(IngestError::InvalidInput("execution_unit.roster").into());
    }

    let mut produced = Vec::with_capacity(events.len());
    for event in events {
        let outcome = match &event.disclosure {
            ExecutionUnitDisclosure::Admissible => {
                produce_execution_unit_allowed(owner, &event.frame)?
            }
            ExecutionUnitDisclosure::Withheld(redacted_classes) => {
                produce_execution_unit_redacted(owner, &event.frame, redacted_classes.clone())?
            }
        };
        // Readback of the ORIGINAL retained value, compared with this event's own
        // owner material through the relation's existing validator.
        let route_evidence = owner
            .committed_route_evidence(&outcome.key)?
            .ok_or(IngestError::InvalidInput("execution_unit.route_evidence"))?;
        route_evidence
            .verify_against(
                event.frame.binding,
                event.frame.admission,
                event.frame.physical_observation,
            )
            .map_err(IngestError::Contract)?;
        produced.push(ProducedExecutionUnitEvent {
            outcome,
            route_evidence,
        });
    }

    let observed: BTreeSet<EventKey> = produced
        .iter()
        .map(|event| event.outcome.key.clone())
        .collect();
    if observed != declared {
        return Err(IngestError::InvalidInput("execution_unit.roster").into());
    }
    Ok(produced)
}
