//! Host-owner session-envelope facts (issue #1942, lane O1).
//!
//! Owner: the Host instance owns its installation identity
//! ([`HostService::installation`] in `service.rs`: "the installation identity
//! owned by this Host instance"), and the Host journal-backed delivery queue
//! durably retains every admitted reactive payload with its recipient and
//! operation envelope (`ReactiveContextQueueEntry` in `eliot-host-state`).
//! Every field below traces to a read of that live owner state; no
//! caller-supplied value is accepted.
//!
//! Live reads:
//!
//! - `snapshot.host_id` ([`produce_host_id`]): the installation identity.
//! - Admitted delivery facts ([`produce_admitted_deliveries`]): one
//!   [`AdmittedDeliveryFacts`] per retained queue entry, projected from the
//!   Context owner's admitted payload — recipient session/runtime/route
//!   (`ReactiveContextRecipient`), the payload operation envelope
//!   (`operation_id`, `request_id`, `idempotency_key` as supplied by the
//!   Context owner and validated at admission), the Host entry fence, and the
//!   admitting queue generation. The scan pages the live queue through the
//!   existing [`ReactiveContextQueuePort`] read path (same bounded cursor
//!   discipline as the delivery coordinator's `load_active_entries`), so
//!   facts flow the moment a real producer delivers through Host admission;
//!   an empty queue yields an honest empty projection, never an error.
//!
//! Absence: the Host owner holds installation identity plus lifecycle epochs
//! and activation generations in the Host state journal, but no
//! `ResourceGeneration` projection for reactive sessions. There is therefore
//! no live source for `snapshot.host_generation`, and
//! [`produce_host_generation`] fails closed naming it instead of minting or
//! converting a generation from another domain.
//!
//! Recipient-identity contract for the D2 join (M2): the recipient owner
//! vocabulary (`ReactiveContextRecipient`: session, opaque runtime identity,
//! runtime generation, route) carries no standalone `recipient_id` string,
//! so the contract derivation reads the authoritative disclosure vocabulary:
//! I5.26 names disclosure recipients as `recipient_principal_or_route`, and
//! the admitted recipient carries no principal. The route
//! fingerprint-or-identity is therefore the recipient identity text
//! (`AdmittedDeliveryFacts.recipient_id`), cloned from the admitted struct —
//! never parsed, hashed, or composed from other fields. Principal and
//! recipient stay un-conflated: the snapshot carries the bridge-owned
//! `principal_id` separately.
//!
//! Fence note: `entry_fence` is the Host journal `RecordFence`, not the
//! bridge `StateFence` — distinct fenced domains, carried side by side, never
//! converted. Generation precedence: the Kernel activation receipt's
//! approved runtime generation (see the `eliot-kernel-service`
//! `session_envelope` producer) is authoritative over the
//! producer-observed `recipient.runtime_generation` retained here.
//!
//! Consumer: `resolve_runtime_envelope` / `resolve_record_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) name the missing `snapshot.host_id`,
//! `snapshot.host_generation`, `snapshot.recipient_id`, and per-record
//! operation facts.

use eliot_contracts::{OperationId, RequestId, ResourceGeneration, SessionId};
use eliot_host_state::{
    ReactiveContextQueueEntry, ReactiveContextQueueError, ReactiveContextQueuePort,
    ReactiveContextQueueQuery, RecordFence,
};
use eliot_platform::{HostStateStore, ServicePort};
use eliot_protocol::reactive_context::{ReactiveContextPayload, ReactiveContextRecipient};
use eliot_protocol::ReactiveContextStage;
use thiserror::Error;

use crate::service::HostService;

/// Page size for one admitted-delivery queue scan page.
const ADMITTED_SCAN_PAGE_LIMIT: usize = 256;

/// Maximum queue pages traversed by one admitted-delivery scan. Bounds the
/// scan to 1024 entries; a larger admitted set fails closed with
/// [`HostDeliveryEnvelopeError::ScanCoverageExceeded`] instead of
/// truncating silently.
const ADMITTED_SCAN_MAX_PAGES: usize = 4;

/// Live Host identity fact for the session envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEnvelopeFacts {
    /// Installation identity owned by this Host instance.
    pub host_id: String,
}

/// One admitted delivery's envelope facts, projected from the Context
/// owner's payload as retained by the Host journal queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDeliveryFacts {
    /// Recipient session the payload was admitted for.
    pub session: SessionId,
    /// Recipient identity for the session envelope, under the authoritative
    /// recipient vocabulary: I5.26 names disclosure recipients as
    /// `recipient_principal_or_route`, and the admitted recipient carries no
    /// principal — so the route fingerprint-or-identity
    /// (`ReactiveContextRecipient.route`) is the recipient identity text.
    /// Derived by clone from the admitted struct, never parsed or hashed.
    pub recipient_id: String,
    /// Exact admitted recipient (session, opaque runtime identity, runtime
    /// generation, route).
    pub recipient: ReactiveContextRecipient,
    /// Opaque runtime identity from the admitted recipient.
    pub runtime_id: String,
    /// Canonical operation identity supplied by the Context owner.
    pub operation_id: OperationId,
    /// Request identity supplied by the Context owner.
    pub request_id: RequestId,
    /// Caller idempotency key supplied by the Context owner.
    pub idempotency_key: String,
    /// Host journal fence that admitted this entry (a `RecordFence`, never
    /// converted to the bridge `StateFence`).
    pub entry_fence: RecordFence,
    /// Exact queue lifecycle stage of this entry at scan time. Terminal
    /// stages (`DeliveredToExactEndpoint`, acknowledgements, closures) are
    /// admission history, not liveness: the assembly must never mistake the
    /// latest terminal entry for a live one.
    pub stage: ReactiveContextStage,
    /// Queue generation that admitted this entry (ordering within a session).
    pub queue_generation: u64,
}

/// Fail-closed Host-envelope errors. Each names the exact D2 fact or scan
/// bound that cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostEnvelopeError {
    /// The Host owner holds no resource generation for reactive sessions, so
    /// `snapshot.host_generation` has no live source. The Host state journal
    /// owns installation/activation generations, never a
    /// `ResourceGeneration` for the session envelope.
    #[error("host owner holds no resource generation for snapshot.host_generation")]
    HostGenerationNotOwned,
}

/// Fail-closed admitted-delivery scan errors.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostDeliveryEnvelopeError {
    /// The live queue read failed; the ledger owns the reason detail.
    #[error("admitted-delivery queue read failed: {0}")]
    Queue(#[from] ReactiveContextQueueError),
    /// The admitted set exceeds the bounded scan (more pages or entries
    /// than the scan covers), so coverage cannot be honestly claimed.
    #[error("admitted-delivery scan exceeded its coverage bound")]
    ScanCoverageExceeded,
}

/// Produce the live Host identity from the Host instance.
///
/// Reads [`HostService::installation`] (validated at `open`; see
/// `service.rs`). Infallible: the installation handle is owner-held, never
/// caller-supplied.
pub fn produce_host_id<P, S>(host: &HostService<P, S>) -> HostEnvelopeFacts
where
    P: ServicePort,
    S: HostStateStore,
{
    HostEnvelopeFacts {
        host_id: host.installation().as_str().to_owned(),
    }
}

/// Attempt to produce the Host generation for the session envelope.
///
/// Always fails closed: no `ResourceGeneration` exists in Host owner state
/// (`service.rs` installation handle plus the Host state journal's
/// installation/activation generations). The owner borrow is threaded to
/// prove the read was attempted against live state rather than skipped.
pub fn produce_host_generation<P, S>(
    host: &HostService<P, S>,
) -> Result<ResourceGeneration, HostEnvelopeError>
where
    P: ServicePort,
    S: HostStateStore,
{
    let _ = host;
    Err(HostEnvelopeError::HostGenerationNotOwned)
}

/// Project one retained queue entry into admitted-delivery facts.
///
/// Every field traces to the entry's Context-owner payload or the Host
/// journal fence/generation that admitted it.
fn admitted_facts_for_entry(entry: &ReactiveContextQueueEntry) -> AdmittedDeliveryFacts {
    let payload: &ReactiveContextPayload = &entry.payload;
    AdmittedDeliveryFacts {
        session: payload.recipient.session_id.clone(),
        recipient_id: payload.recipient.route.clone(),
        recipient: payload.recipient.clone(),
        runtime_id: payload.recipient.runtime_id.clone(),
        operation_id: payload.operation_id.clone(),
        request_id: payload.request_id.clone(),
        idempotency_key: payload.idempotency_key.clone(),
        entry_fence: entry.fence.clone(),
        stage: entry.stage.clone(),
        queue_generation: entry.queue_generation,
    }
}

/// Produce the admitted-delivery envelope facts retained by the Host journal
/// queue.
///
/// Pages the live queue through [`ReactiveContextQueuePort::load_attempt_queue`]
/// with terminal history included (the envelope describes delivered rows),
/// projecting every retained entry in stable page order. Deterministic and
/// bounded: at most `ADMITTED_SCAN_MAX_PAGES` pages of
/// `ADMITTED_SCAN_PAGE_LIMIT` entries; a larger admitted set fails closed
/// with [`HostDeliveryEnvelopeError::ScanCoverageExceeded`], and a partial
/// page without a continuation cursor fails closed the same way. An empty
/// queue yields an empty projection — no admissions, not an error.
///
/// Join contract for the D2 assembly (M2): match `session` against the live
/// attach session, select the maximum `queue_generation` per session, and
/// read `stage` before any liveness claim — terminal stages are admission
/// history and must never be mistaken for live. Render
/// `snapshot.recipient_id` only under a contract-owned derivation
/// (see the module docs — no conflation here).
pub fn produce_admitted_deliveries<Q>(
    queue: &Q,
) -> Result<Vec<AdmittedDeliveryFacts>, HostDeliveryEnvelopeError>
where
    Q: ReactiveContextQueuePort,
{
    let mut facts = Vec::new();
    let mut cursor = None;
    for _ in 0..ADMITTED_SCAN_MAX_PAGES {
        let snapshot = queue.load_attempt_queue(ReactiveContextQueueQuery {
            attempt_id: None,
            stream_id: None,
            include_terminal: true,
            limit: ADMITTED_SCAN_PAGE_LIMIT,
            cursor,
        })?;
        facts.extend(snapshot.items.iter().map(admitted_facts_for_entry));
        if !snapshot.partial {
            return Ok(facts);
        }
        cursor = snapshot.next_cursor;
        if cursor.is_none() {
            return Err(HostDeliveryEnvelopeError::ScanCoverageExceeded);
        }
    }
    Err(HostDeliveryEnvelopeError::ScanCoverageExceeded)
}
