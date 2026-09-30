//! Bridge producer path for durable host-event ingest (issue #1934, I7.23).
//!
//! This module is the one bridge producer the consume lane flagged missing:
//! ACP transport bytes enter, and a durably committed journal record leaves.
//! For one complete ACP content-length frame the producer
//!
//! ```text
//! ACP frame bytes
//! → AcpFrameCodec framing + AcpJsonRpcMessage shape validation
//! → normalize_acp_event (session-observation small-event shape)
//! → stage_allowed | stage_redacted on the persistence owner
//! → commit (the only step that advances the per-stream durable cursor).
//! ```
//!
//! The producer hashes the exact frame bytes as transported, so the immutable
//! transport hash is a pure function of the bridge input. The small-event
//! shape is a session-lifecycle observation; richer ACP payload mappings stay
//! with the normalization owner and never enter this path implicitly.
//!
//! Fail-closed ordering: [`produce_allowed`] never stores denied content (the
//! owner rejects it with [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation)
//! before any commit), and the cursor is unadvanced until [`commit`](crate::HostEventPersistenceOwner::commit)
//! succeeds. Redacted events require the explicit [`produce_redacted`] entry
//! with declared redacted classes; the original bytes are never stored.

use eliot_agent_api::{
    AdmittedRouteReceipt, ClockReading, ContractError, EventCursor, EventId,
    ExecutionUnitObservation, HostEventDeliveryDisposition, HostEventPrivacyClass, NativeSession,
    NativeSessionLocator, NormalizationCoverage, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    ProviderObservationLineage, RestrictedRawSourceHandle, SessionLifecycleObservation,
    SessionLifecycleTransition, SessionObservation,
};
use eliot_contracts::sha256_hex;
use thiserror::Error;

use crate::{
    AcpAdapterError, AcpFrameCodec, AcpHostEventInput, AcpJsonRpcMessage, AcpProtocolError,
    DURABLE_INGEST_TRANSFORMATION_VERSION, EventKey, HostEventPersistenceOwner, IngestError,
    StageAllowed, StageOutcome, StageRedacted, StreamCursorState, contains_forbidden_content,
    deterministic_redacted_bytes, normalize_acp_event,
};

/// Error returned by the bridge producer path.
#[derive(Debug, Error)]
pub enum ProducerError {
    /// ACP framing or JSON-RPC shape validation failed. The bytes never reach
    /// staging: unparseable transport cannot become a durable record.
    #[error(transparent)]
    Protocol(#[from] AcpProtocolError),
    /// Typed ACP normalization rejected the observation.
    #[error(transparent)]
    Adapter(#[from] AcpAdapterError),
    /// The persistence owner rejected staging or commit, including the
    /// fail-closed [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation)
    /// for denied content on the allowed path.
    #[error(transparent)]
    Ingest(#[from] IngestError),
    /// A producer-side identity or locator failed contract validation before
    /// normalization.
    #[error(transparent)]
    Contract(#[from] ContractError),
}

/// One ACP transport frame plus the stream binding for the small-event shape.
#[derive(Clone, Debug)]
pub struct ProducerFrame<'a> {
    /// Owning stream identifier (one stream per producer call).
    pub stream_id: &'a str,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub stream_sequence: u64,
    /// Event identity minted by the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor minted by the post-R1 owner.
    pub cursor: EventCursor,
    /// Native session locator for the session-observation lineage.
    pub native_session: &'a str,
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Exactly one complete ACP content-length frame: the immutable transport
    /// bytes that are hashed, staged, and committed.
    pub frame_bytes: &'a [u8],
    /// Session-lifecycle transition for the small-event payload shape.
    pub transition: SessionLifecycleTransition,
    /// Typed observation time.
    pub observed_at: ClockReading,
}

/// Execution-unit frame for durable host-event ingest (issue #2645 W1/W3).
///
/// Unlike [`ProducerFrame`], this carries the exact owner material for one
/// execution-unit observation: the recorded #361 binding (cloned into the
/// execution-unit lineage), the governing #369 admission, and the applicable
/// #369 physical observation — or its explicit absence for a valid
/// pre-observation event. Requested/actual route digests are never supplied
/// here: [`StageAllowed::execution_unit`](crate::StageAllowed::execution_unit)
/// and [`StageRedacted::execution_unit`](crate::StageRedacted::execution_unit)
/// derive them from these owners, and the staging guard re-verifies every
/// digest before any mutation. A supplied observation must belong to this
/// event's observation boundary (`unit_cursor`/`unit_sequence`); a receipt
/// from another boundary rejects fail-closed at staging. The typed `payload`
/// must be a non-session-lifecycle observation: session-lifecycle payloads
/// cannot ride execution-unit lineage and the normalizer rejects them.
#[derive(Clone, Debug)]
pub struct ExecutionUnitFrame<'a> {
    /// Owning stream identifier (one stream per producer call).
    pub stream_id: &'a str,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub stream_sequence: u64,
    /// Event identity minted by the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor minted by the post-R1 owner.
    pub cursor: EventCursor,
    /// Position of this event inside the bound execution unit. The staging
    /// gate binds a supplied observation's causal applicability to exactly
    /// this position.
    pub unit_cursor: EventCursor,
    /// Sequence of this event inside the bound execution unit. Must be
    /// nonzero.
    pub unit_sequence: u64,
    /// Recorded #361 provider-execution binding for this execution unit.
    pub binding: &'a ProviderExecutionBinding,
    /// Governing #369 admitted-route receipt for this execution unit.
    pub admission: &'a AdmittedRouteReceipt,
    /// Applicable #369 physical-route observation for this event's
    /// observation boundary. `None` exactly when no observation applies yet
    /// (a valid pre-observation event records the applicable absence with no
    /// actual digest).
    pub physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Exactly one complete ACP content-length frame: the immutable transport
    /// bytes that are hashed, staged, and committed.
    pub frame_bytes: &'a [u8],
    /// Closed typed payload: a bounded summary, never raw provider content.
    pub payload: NormalizedHostEventPayload,
    /// Causal predecessor event identities.
    pub predecessors: Vec<EventId>,
    /// Normalization warnings. Bounded; never raw provider content.
    pub warnings: Vec<String>,
    /// Typed observation time.
    pub observed_at: ClockReading,
}

/// Outcome of one produced event: its journal key, freshness, resulting
/// durable cursor, and whether the stored bytes are the redacted projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProduceOutcome {
    /// Key of the staged-then-committed record (or its idempotent replay).
    pub key: EventKey,
    /// False when the delivery was an idempotent duplicate of an identical
    /// prior delivery.
    pub fresh: bool,
    /// Per-stream cursor after commit. The durable sequence reaches
    /// `stream_sequence` exactly when this call persisted the relation first;
    /// for idempotent replays it reports the already-advanced cursor.
    pub cursor: StreamCursorState,
    /// True when the stored bytes are the deterministic redacted projection.
    pub redacted: bool,
}

/// Decodes exactly one ACP frame and validates its JSON-RPC shape, returning
/// the exact body bytes as transported inside the frame.
fn decode_single_frame(frame_bytes: &[u8]) -> Result<Vec<u8>, ProducerError> {
    let mut codec = AcpFrameCodec::default();
    let mut bodies = codec.feed(frame_bytes)?;
    codec.finish()?;
    if bodies.len() != 1 {
        return Err(ProducerError::Protocol(AcpProtocolError::InvalidEnvelope(
            "producer accepts exactly one ACP frame per event".into(),
        )));
    }
    let body = bodies.pop().unwrap_or_default();
    AcpJsonRpcMessage::from_frame(&body)?;
    Ok(frame_bytes.to_vec())
}

fn session_lineage(native_session: &str) -> Result<ProviderObservationLineage, ProducerError> {
    Ok(ProviderObservationLineage::SessionObservation(
        SessionObservation {
            session_id: None,
            native: NativeSession::Native(NativeSessionLocator::new(native_session)?),
        },
    ))
}

fn normalize_small_event(
    frame: &ProducerFrame<'_>,
    source_bytes: &[u8],
    privacy_class: HostEventPrivacyClass,
) -> Result<NormalizedHostEventEnvelope, ProducerError> {
    let (envelope, receipt) = normalize_acp_event(AcpHostEventInput {
        event_id: frame.event_id.clone(),
        cursor: frame.cursor.clone(),
        sequence: frame.stream_sequence,
        predecessors: Vec::new(),
        lineage: session_lineage(frame.native_session)?,
        raw_source_bytes: source_bytes,
        raw_source_handle: frame.raw_source_handle.clone(),
        payload: NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
            transition: frame.transition,
            detail_ref: None,
        }),
        omitted_source_fields: Vec::new(),
        warnings: Vec::new(),
        privacy_class,
        coverage: NormalizationCoverage::Complete,
        observed_at: frame.observed_at,
        delivery: HostEventDeliveryDisposition::DurableOrdered,
        admission: None,
    })?;
    debug_assert_eq!(envelope.normalization, receipt);
    Ok(envelope)
}

/// Normalizes one execution-unit observation through the exact owner
/// material (issue #2645 W1/W3): the binding is cloned into the
/// execution-unit lineage and the governing admission is referenced by
/// digest, so [`normalize_acp_event`] runs its execution-unit validation
/// (`validate_for_lineage`) before any staging. The typed `payload` travels
/// unchanged; a session-lifecycle payload fails closed here, never sealed.
fn normalize_execution_unit_event(
    frame: &ExecutionUnitFrame<'_>,
    source_bytes: &[u8],
    privacy_class: HostEventPrivacyClass,
) -> Result<NormalizedHostEventEnvelope, ProducerError> {
    if frame.unit_sequence == 0 {
        return Err(ProducerError::Ingest(IngestError::InvalidInput(
            "unit_sequence",
        )));
    }
    let (envelope, receipt) = normalize_acp_event(AcpHostEventInput {
        event_id: frame.event_id.clone(),
        cursor: frame.cursor.clone(),
        sequence: frame.stream_sequence,
        predecessors: frame.predecessors.clone(),
        lineage: ProviderObservationLineage::ExecutionUnitObservation(Box::new(
            ExecutionUnitObservation {
                binding: (*frame.binding).clone(),
                cursor: frame.unit_cursor.clone(),
                sequence: frame.unit_sequence,
            },
        )),
        raw_source_bytes: source_bytes,
        raw_source_handle: frame.raw_source_handle.clone(),
        payload: frame.payload.clone(),
        omitted_source_fields: Vec::new(),
        warnings: frame.warnings.clone(),
        privacy_class,
        coverage: NormalizationCoverage::Complete,
        observed_at: frame.observed_at,
        delivery: HostEventDeliveryDisposition::DurableOrdered,
        admission: Some(frame.admission),
    })?;
    debug_assert_eq!(envelope.normalization, receipt);
    Ok(envelope)
}

/// Produces one event from admissible ACP transport bytes: decode, normalize,
/// [`stage_allowed`](crate::HostEventPersistenceOwner::stage_allowed), then
/// [`commit`](crate::HostEventPersistenceOwner::commit).
///
/// Fails closed with [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation)
/// when the frame carries denied content; the cursor is left unadvanced and
/// the caller must use [`produce_redacted`] explicitly. The durable cursor
/// advances only inside `commit`, so a pre-commit interruption leaves the
/// stream cursor unadvanced by construction.
pub fn produce_allowed<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ProducerFrame<'_>,
) -> Result<ProduceOutcome, ProducerError> {
    let transport_bytes = decode_single_frame(frame.frame_bytes)?;
    if contains_forbidden_content(&transport_bytes) {
        return Err(ProducerError::Ingest(IngestError::PrivacyViolation));
    }
    let envelope = normalize_small_event(
        frame,
        &transport_bytes,
        HostEventPrivacyClass::PublicSummary,
    )?;
    let outcome: StageOutcome = owner.stage_allowed(StageAllowed {
        stream_id: frame.stream_id,
        stream_sequence: frame.stream_sequence,
        transport_bytes: &transport_bytes,
        envelope,
        binding: None,
        admission: None,
        physical_observation: None,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: false,
    })
}

/// Produces one event whose original bytes cannot be retained: decode,
/// normalize over the deterministic redacted projection,
/// [`stage_redacted`](crate::HostEventPersistenceOwner::stage_redacted), then
/// [`commit`](crate::HostEventPersistenceOwner::commit).
///
/// The original frame bytes are hashed and scanned but never stored; the
/// record exposes the deterministic projection plus its redaction receipt.
/// The durable cursor advances only inside `commit`.
pub fn produce_redacted<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ProducerFrame<'_>,
    redacted_classes: Vec<String>,
) -> Result<ProduceOutcome, ProducerError> {
    let transport_bytes = decode_single_frame(frame.frame_bytes)?;
    let transport_hash = sha256_hex(&transport_bytes);
    let mut sorted = redacted_classes.clone();
    sorted.sort();
    sorted.dedup();
    let class_refs: Vec<&str> = sorted.iter().map(String::as_str).collect();
    let projection = deterministic_redacted_bytes(&transport_hash, &class_refs);
    let envelope =
        normalize_small_event(frame, &projection, HostEventPrivacyClass::RedactedSummary)?;
    let outcome: StageOutcome = owner.stage_redacted(StageRedacted {
        stream_id: frame.stream_id,
        stream_sequence: frame.stream_sequence,
        transport_bytes: &transport_bytes,
        redacted_classes,
        envelope,
        binding: None,
        admission: None,
        physical_observation: None,
        requested_route_digest: None,
        actual_route_digest: None,
        predecessors: Vec::new(),
        warnings: Vec::new(),
        transformation_version: DURABLE_INGEST_TRANSFORMATION_VERSION,
    })?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: true,
    })
}

/// Produces one execution-unit event from admissible ACP transport bytes
/// (issue #2645 W1/W3): decode, normalize through the exact binding and
/// governing admission, stage through
/// [`StageAllowed::execution_unit`](crate::StageAllowed::execution_unit) —
/// which derives the requested/actual route digests from those owners and
/// the applicable physical observation — then commit.
///
/// This is the production caller that makes the `physical_observation:
/// Some(...)` staging branch reachable: a valid matched observation stages
/// its observed actual digest, a valid divergent observation stages Diverged
/// evidence, an `Unobserved` observation or a pre-observation `None` stages
/// with no actual digest, and a receipt from another observation boundary
/// (or substituted caller digests, which this path never accepts) rejects
/// before any mutation. Fails closed with
/// [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation)
/// when the frame carries denied content; the caller must use
/// [`produce_execution_unit_redacted`] explicitly. The durable cursor
/// advances only inside `commit`.
pub fn produce_execution_unit_allowed<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ExecutionUnitFrame<'_>,
) -> Result<ProduceOutcome, ProducerError> {
    let transport_bytes = decode_single_frame(frame.frame_bytes)?;
    if contains_forbidden_content(&transport_bytes) {
        return Err(ProducerError::Ingest(IngestError::PrivacyViolation));
    }
    let envelope = normalize_execution_unit_event(
        frame,
        &transport_bytes,
        HostEventPrivacyClass::PublicSummary,
    )?;
    let request = StageAllowed::execution_unit(
        frame.stream_id,
        frame.stream_sequence,
        &transport_bytes,
        envelope,
        frame.binding,
        frame.admission,
        frame.physical_observation,
        frame.predecessors.clone(),
        frame.warnings.clone(),
        DURABLE_INGEST_TRANSFORMATION_VERSION,
    )?;
    let outcome: StageOutcome = owner.stage_allowed(request)?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: false,
    })
}

/// Produces one execution-unit event whose original bytes cannot be retained
/// (issue #2645 W1/W3): decode, normalize over the deterministic redacted
/// projection through the exact binding and governing admission, stage
/// through
/// [`StageRedacted::execution_unit`](crate::StageRedacted::execution_unit)
/// under identical route rules to [`produce_execution_unit_allowed`], then
/// commit.
///
/// The original frame bytes are hashed and scanned but never stored; the
/// record exposes the deterministic projection plus its redaction receipt.
/// The durable cursor advances only inside `commit`.
pub fn produce_execution_unit_redacted<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ExecutionUnitFrame<'_>,
    redacted_classes: Vec<String>,
) -> Result<ProduceOutcome, ProducerError> {
    let transport_bytes = decode_single_frame(frame.frame_bytes)?;
    let transport_hash = sha256_hex(&transport_bytes);
    let mut sorted = redacted_classes.clone();
    sorted.sort();
    sorted.dedup();
    let class_refs: Vec<&str> = sorted.iter().map(String::as_str).collect();
    let projection = deterministic_redacted_bytes(&transport_hash, &class_refs);
    let envelope = normalize_execution_unit_event(
        frame,
        &projection,
        HostEventPrivacyClass::RedactedSummary,
    )?;
    let request = StageRedacted::execution_unit(
        frame.stream_id,
        frame.stream_sequence,
        &transport_bytes,
        redacted_classes,
        envelope,
        frame.binding,
        frame.admission,
        frame.physical_observation,
        frame.predecessors.clone(),
        frame.warnings.clone(),
        DURABLE_INGEST_TRANSFORMATION_VERSION,
    )?;
    let outcome: StageOutcome = owner.stage_redacted(request)?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: true,
    })
}
