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
///
/// Session-only observations carry no attempt authority: they stage with the
/// struct-literal `None` binding/admission/observation shape. Execution-unit
/// events use [`ExecutionUnitProducerFrame`] instead, which stages through
/// [`StageAllowed::execution_unit`] / [`StageRedacted::execution_unit`] with
/// the validated owner material.
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

/// Transport plus validated owner material for one ACP execution-unit event
/// (issue #2645 W1/W3).
///
/// This is the production execution-unit caller into durable staging: the
/// producer normalizes the exact frame bytes under ACP identity with
/// execution-unit lineage bound to `binding`/`admission`, then stages through
/// [`StageAllowed::execution_unit`] / [`StageRedacted::execution_unit`] so the
/// requested/actual route digests derive from validated owner material, never
/// from caller hashes. `physical_observation` is `Some` exactly when a
/// validated observation applies to this event's boundary (its
/// cursor/sequence must equal `lineage_cursor`/`lineage_sequence`; the
/// constructor and the staging guard reject a foreign boundary before any
/// mutation); `None` is the honest pre-observation event with no actual
/// digest, whose later immutable observation evidence links as a new record.
/// The session-only [`ProducerFrame`] path is untouched.
#[derive(Clone, Debug)]
pub struct ExecutionUnitProducerFrame<'a> {
    /// Owning stream identifier (one stream per producer call).
    pub stream_id: &'a str,
    /// Monotonic sequence within the stream. Must be nonzero.
    pub stream_sequence: u64,
    /// Event identity minted by the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor minted by the post-R1 owner.
    pub cursor: EventCursor,
    /// Exactly one complete ACP content-length frame: the immutable transport
    /// bytes that are hashed, staged, and committed.
    pub frame_bytes: &'a [u8],
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Closed typed payload for the execution observation. Session-lifecycle
    /// payloads fail closed in normalization and lineage validation: they
    /// observe the session, not the unit, and can never ride this lineage.
    pub payload: NormalizedHostEventPayload,
    /// Observation position declared by the lineage. Must equal the supplied
    /// observation's own cursor/sequence when one applies.
    pub lineage_cursor: EventCursor,
    /// Observation sequence declared by the lineage. Must be nonzero, and
    /// must equal the supplied observation's own sequence when one applies.
    pub lineage_sequence: u64,
    /// Recorded #361 provider-execution binding this unit executes under.
    pub binding: &'a ProviderExecutionBinding,
    /// Governing #369 admitted-route receipt.
    pub admission: &'a AdmittedRouteReceipt,
    /// Validated #369 physical-route observation for this event's observation
    /// boundary, or its explicit absence for a valid pre-observation event.
    pub physical_observation: Option<&'a PhysicalRouteObservationReceipt>,
    /// Causal predecessor event identities, sealed into the envelope and the
    /// staging request together.
    pub predecessors: Vec<EventId>,
    /// Typed observation time.
    pub observed_at: ClockReading,
}

fn normalize_execution_unit_event(
    frame: &ExecutionUnitProducerFrame<'_>,
    source_bytes: &[u8],
    privacy_class: HostEventPrivacyClass,
) -> Result<NormalizedHostEventEnvelope, ProducerError> {
    let (envelope, receipt) = normalize_acp_event(AcpHostEventInput {
        event_id: frame.event_id.clone(),
        cursor: frame.cursor.clone(),
        sequence: frame.stream_sequence,
        predecessors: frame.predecessors.clone(),
        lineage: ProviderObservationLineage::ExecutionUnitObservation(Box::new(
            ExecutionUnitObservation {
                binding: frame.binding.clone(),
                cursor: frame.lineage_cursor.clone(),
                sequence: frame.lineage_sequence,
            },
        )),
        raw_source_bytes: source_bytes,
        raw_source_handle: frame.raw_source_handle.clone(),
        payload: frame.payload.clone(),
        omitted_source_fields: Vec::new(),
        warnings: Vec::new(),
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

/// Produces one execution-unit event from admissible ACP transport bytes:
/// decode, normalize under execution-unit lineage, stage through
/// [`StageAllowed::execution_unit`] with the validated owner material, then
/// [`commit`](crate::HostEventPersistenceOwner::commit).
///
/// `frame.physical_observation` carries the exact validated physical
/// observation for this event's boundary (`Some`), or the explicit absence
/// for a valid pre-observation event (`None`, staged with no actual digest).
/// Requested/actual digests derive from the binding/admission/observation
/// owners inside the constructor and are re-verified by the staging guard
/// before any mutation; no caller hash is trusted. An observation from
/// another attempt, binding, fence, generation, admission, or
/// cursor/sequence boundary rejects before any mutation. Denied content fails
/// closed with [`IngestError::PrivacyViolation`](crate::IngestError::PrivacyViolation)
/// and leaves the cursor unadvanced; the caller must use
/// [`produce_execution_unit_redacted`] explicitly.
pub fn produce_execution_unit_allowed<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ExecutionUnitProducerFrame<'_>,
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
    let outcome: StageOutcome = owner.stage_allowed(StageAllowed::execution_unit(
        frame.stream_id,
        frame.stream_sequence,
        &transport_bytes,
        envelope,
        frame.binding,
        frame.admission,
        frame.physical_observation,
        frame.predecessors.clone(),
        Vec::new(),
        DURABLE_INGEST_TRANSFORMATION_VERSION,
    )?)?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: false,
    })
}

/// Produces one execution-unit event whose original bytes cannot be retained:
/// decode, normalize over the deterministic redacted projection under
/// execution-unit lineage, stage through [`StageRedacted::execution_unit`]
/// with the validated owner material, then
/// [`commit`](crate::HostEventPersistenceOwner::commit).
///
/// The original frame bytes are hashed and scanned but never stored; the
/// record exposes the deterministic projection plus its redaction receipt.
/// Route rules are identical to [`produce_execution_unit_allowed`]: the same
/// binding/admission/observation owners supply the requested/actual digests.
/// The durable cursor advances only inside `commit`.
pub fn produce_execution_unit_redacted<O: HostEventPersistenceOwner>(
    owner: &mut O,
    frame: &ExecutionUnitProducerFrame<'_>,
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
        normalize_execution_unit_event(frame, &projection, HostEventPrivacyClass::RedactedSummary)?;
    let outcome: StageOutcome = owner.stage_redacted(StageRedacted::execution_unit(
        frame.stream_id,
        frame.stream_sequence,
        &transport_bytes,
        redacted_classes,
        envelope,
        frame.binding,
        frame.admission,
        frame.physical_observation,
        frame.predecessors.clone(),
        Vec::new(),
        DURABLE_INGEST_TRANSFORMATION_VERSION,
    )?)?;
    let cursor = owner.commit(&outcome.key)?;
    Ok(ProduceOutcome {
        key: outcome.key,
        fresh: outcome.fresh,
        cursor,
        redacted: true,
    })
}
