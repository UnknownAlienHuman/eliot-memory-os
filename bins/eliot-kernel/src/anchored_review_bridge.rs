//! Kernel-side Store-bridge dispatch for durable anchored review (issue #1823;
//! I10.18/I10.21).
//!
//! Architecture: I10.18 durable anchored review under the existing
//! mailbox/attention/coordination authority. The Kernel-mechanical surface
//! itself lives in [`super::anchored_review`] (slice A); this module is the
//! Store-bridge slice that registers its stable operation names on the
//! authenticated daemon transport and routes each admitted operation to
//! exactly one slice-A entry point. Implementation anchor: I1.8 (Kernel
//! verifies identity, authority, State Fence and idempotency; the store
//! bridge persists only named, already prepared state).
//!
//! # Registration
//!
//! Each `ANCHORED_REVIEW_*_OPERATION` constant below is bound to the matching
//! slice-A `ANCHORED_REVIEW_*_NAME` constant, so the transport operation
//! string and the Kernel surface name cannot drift into two spellings of one
//! canonical operation. The daemon dispatch (`daemon_request_dispatch.rs`)
//! admits these strings in `trusted_daemon_operation` and routes them in its
//! operation match; the frame gateway (`frame_dispatch.rs`) mirrors them in
//! `is_daemon_operation` so frames reach the arms. No other vocabulary
//! exists and no generic JSON command routing is added.
//!
//! # Production chain
//!
//! Each arm proves the live session fence (the envelope `state_fence` must
//! equal the presenting session fence) and decodes one closed envelope
//! (`deny_unknown_fields`, exact operation check), then calls exactly one
//! slice-A entry point against the caller-read-back records the envelope
//! carries: [`submit_review_item`](super::anchored_review::submit_review_item),
//! [`submit_review_batch`](super::anchored_review::submit_review_batch),
//! [`observe_review_batch`](super::anchored_review::observe_review_batch),
//! [`advance_review_item`](super::anchored_review::advance_review_item),
//! [`route_requested_change`](super::anchored_review::route_requested_change),
//! [`accept_requested_change_effect`](super::anchored_review::accept_requested_change_effect),
//! or [`escalate_review_blocker`](super::anchored_review::escalate_review_blocker).
//! The computed record or row returns in the typed response for the existing
//! coordination Store owner to persist through the canonical Store; this
//! slice creates no journal and no store, performs no Store write, mints no
//! identity, and grants no write, effect, goal, or acceptance authority. A
//! slice-A refusal stays a typed `anchored_review_refused` application
//! answer carrying its durable reason, never an empty result and never a
//! fenced session. Unknown operation names fall through to the existing
//! typed transport refusal unchanged.
//!
//! # What this deliberately does not do
//!
//! No verifier close: `VerifyRequestedChangeEffect` stays declared in slice
//! A for the later verifier slice, so that name remains unregistered and an
//! unknown operation here. No second approval system: there is no
//! approve/admit/finish transition on this path. Escalation names only the
//! existing Problem/Critical-Attention control classes through slice A; the
//! Governor peer-conflict owner stays separate and the owning slice delivers
//! the returned row to that control path.

use super::TransportError;
use super::anchored_review::{
    ANCHORED_REVIEW_ACCEPT_NAME, ANCHORED_REVIEW_ADVANCE_NAME,
    ANCHORED_REVIEW_BATCH_SUBMIT_NAME, ANCHORED_REVIEW_ESCALATE_NAME,
    ANCHORED_REVIEW_OBSERVE_NAME, ANCHORED_REVIEW_ROUTE_NAME, ANCHORED_REVIEW_SUBMIT_NAME,
    AnchoredReviewDraft, AnchoredReviewRecord, BatchReviewEntry, RequestedChangeRoute,
    ReviewAdvance, ReviewBatch, ReviewBlockerKind, ReviewCandidate, accept_requested_change_effect,
    advance_review_item, escalate_review_blocker, observe_review_batch, route_requested_change,
    submit_review_batch, submit_review_item,
};
use eliot_contracts::StateFence;
use serde::Deserialize;

/// Stable named submission, registered for anchored-review admission. The
/// marker is slice A's own closed name, never a second Kernel spelling.
pub(crate) const ANCHORED_REVIEW_SUBMIT_OPERATION: &str = ANCHORED_REVIEW_SUBMIT_NAME;
/// Stable named batch submission, registered for derived-envelope batch
/// admission. The marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_BATCH_SUBMIT_OPERATION: &str = ANCHORED_REVIEW_BATCH_SUBMIT_NAME;
/// Stable named observation, registered for per-item batch readback. The
/// marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_OBSERVE_OPERATION: &str = ANCHORED_REVIEW_OBSERVE_NAME;
/// Stable named lifecycle advance, registered for the delivery slice. The
/// marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_ADVANCE_OPERATION: &str = ANCHORED_REVIEW_ADVANCE_NAME;
/// Stable named requested-change routing, registered for the owner slice.
/// The marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_ROUTE_OPERATION: &str = ANCHORED_REVIEW_ROUTE_NAME;
/// Stable named effect-owner acceptance, registered for the effect slice.
/// The marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_ACCEPT_OPERATION: &str = ANCHORED_REVIEW_ACCEPT_NAME;
/// Stable named blocker escalation, registered for the owning slice. The
/// marker is slice A's own closed name.
pub(crate) const ANCHORED_REVIEW_ESCALATE_OPERATION: &str = ANCHORED_REVIEW_ESCALATE_NAME;

/// Typed receipt kind answered by the submit arm.
const ANCHORED_REVIEW_SUBMISSION_KIND: &str = "anchored_review_submission";
/// Typed receipt kind answered by the batch-submit arm.
const ANCHORED_REVIEW_BATCH_SUBMISSION_KIND: &str = "anchored_review_batch_submission";
/// Typed receipt kind answered by the observe arm.
const ANCHORED_REVIEW_BATCH_OBSERVATION_KIND: &str = "anchored_review_batch_observation";
/// Typed receipt kind answered by the advance arm.
const ANCHORED_REVIEW_ITEM_KIND: &str = "anchored_review_item";
/// Typed receipt kind answered by the route arm.
const ANCHORED_REVIEW_ROUTE_KIND: &str = "anchored_review_route";
/// Typed receipt kind answered by the accept arm.
const ANCHORED_REVIEW_EFFECT_KIND: &str = "anchored_review_effect";
/// Typed receipt kind answered by the escalate arm.
const ANCHORED_REVIEW_ESCALATION_KIND: &str = "anchored_review_escalation";
/// Typed refusal kind answered by every arm when slice A refuses. A refusal
/// keeps its durable reason and stays a refusal, never an empty result.
const ANCHORED_REVIEW_REFUSAL_KIND: &str = "anchored_review_refused";

/// Projects one computed anchored-review answer into the closed daemon
/// response envelope. The value is slice A's own typed output, serialized
/// verbatim; this projection never re-derives or reshapes it.
fn anchored_review_answer<T: serde::Serialize>(
    kind: &'static str,
    value: &T,
) -> Result<serde_json::Value, TransportError> {
    let projected = serde_json::to_value(value).map_err(|_| TransportError::SessionFenced)?;
    Ok(serde_json::json!({
        "status": "known",
        "value": { "kind": kind, "value": projected },
        "recovery": null,
    }))
}

/// Projects one slice-A refusal into the closed daemon response envelope.
/// The reason is slice A's own typed Display text (field and reason names
/// plus routing identities, never secret values); the operation names which
/// arm refused so a refused sending is never read as admitted.
fn anchored_review_refusal(operation: &'static str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "error",
        "value": {
            "kind": ANCHORED_REVIEW_REFUSAL_KIND,
            "value": { "operation": operation, "reason": reason },
        },
        "recovery": null,
    })
}

/// Requires the envelope to name exactly the arm's registered operation and
/// to ride the live session fence. A mismatched operation or a foreign
/// fence fences the session before any slice-A entry point is reached.
fn admit_review_envelope(
    operation: &str,
    expected: &'static str,
    state_fence: &StateFence,
    session_fence: &StateFence,
) -> Result<(), TransportError> {
    if operation != expected {
        return Err(TransportError::SessionFenced);
    }
    if state_fence != session_fence {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

/// Closed submit envelope (`SubmitAnchoredReviewItem`). Carries the draft,
/// the producing lane's resolution inputs, and the already-known records the
/// Store bridge read back, so a retried identity replays instead of
/// recording a second effect.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewSubmitEnvelope {
    operation: String,
    state_fence: StateFence,
    draft: AnchoredReviewDraft,
    candidates: Vec<ReviewCandidate>,
    target_deleted: bool,
    existing: Vec<AnchoredReviewRecord>,
}

/// Closed batch-submit envelope (`SubmitAnchoredReviewBatch`). Carries the
/// derived envelope, its entries in send order, and the already-known
/// records, so members admit independently with fully separate lifecycles.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewBatchSubmitEnvelope {
    operation: String,
    state_fence: StateFence,
    batch: ReviewBatch,
    entries: Vec<BatchReviewEntry>,
    existing: Vec<AnchoredReviewRecord>,
}

/// Closed observe envelope (`ObserveAnchoredReviewBatch`). Carries the
/// derived envelope and the retained records; every member is reported with
/// its own lifecycle, never merged.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewObserveEnvelope {
    operation: String,
    state_fence: StateFence,
    batch: ReviewBatch,
    records: Vec<AnchoredReviewRecord>,
}

/// Closed advance envelope (`AdvanceAnchoredReviewItem`). Carries the
/// retained record, the single advance, and the rejection reason, which is
/// present exactly for rejection and refused anywhere else by slice A.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewAdvanceEnvelope {
    operation: String,
    state_fence: StateFence,
    record: AnchoredReviewRecord,
    advance: ReviewAdvance,
    reason: Option<String>,
}

/// Closed route envelope (`RouteRequestedChange`). Carries the retained
/// requested-change record and the normal owner, effect, and verifier
/// entries the change routes to as a candidate only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewRouteEnvelope {
    operation: String,
    state_fence: StateFence,
    record: AnchoredReviewRecord,
    owner_id: String,
    effect_entry: String,
    verifier_entry: String,
    routed_at_unix_ms: u64,
}

/// Closed accept envelope (`AcceptRequestedChangeEffect`). Carries the route,
/// the retained record it must name, and the accepting owner identity bound
/// by the accepting caller. Records the acceptance; it is not the effect.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewAcceptEnvelope {
    operation: String,
    state_fence: StateFence,
    route: RequestedChangeRoute,
    record: AnchoredReviewRecord,
    accepted_by: String,
    effect_name: String,
    accepted_at_unix_ms: u64,
}

/// Closed escalate envelope (`EscalateReviewBlocker`). Carries the retained
/// record, the classifier-presented blocker class, and the observation
/// time. Only the classifier's current outcome escalates.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredReviewEscalateEnvelope {
    operation: String,
    state_fence: StateFence,
    record: AnchoredReviewRecord,
    blocker: ReviewBlockerKind,
    observed_at_unix_ms: u64,
}

/// Serves one `SubmitAnchoredReviewItem` frame: admits the envelope, then
/// routes to [`submit_review_item`]. The admitted record returns for the
/// existing coordination Store owner to persist; nothing is stored here.
pub(crate) fn anchored_review_submit_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewSubmitEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_SUBMIT_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match submit_review_item(
        envelope.draft,
        &envelope.candidates,
        envelope.target_deleted,
        &envelope.existing,
    ) {
        Ok(submission) => anchored_review_answer(ANCHORED_REVIEW_SUBMISSION_KIND, &submission),
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_SUBMIT_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `SubmitAnchoredReviewBatch` frame: admits the envelope, then
/// routes to [`submit_review_batch`]. Members admit independently; the first
/// invalid entry refuses the whole sending and names its identity.
pub(crate) fn anchored_review_batch_submit_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewBatchSubmitEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_BATCH_SUBMIT_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match submit_review_batch(&envelope.batch, &envelope.entries, &envelope.existing) {
        Ok(submission) => {
            anchored_review_answer(ANCHORED_REVIEW_BATCH_SUBMISSION_KIND, &submission)
        }
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_BATCH_SUBMIT_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `ObserveAnchoredReviewBatch` frame: admits the envelope, then
/// routes to [`observe_review_batch`]. Read-only: answering one item never
/// resolves or hides another.
pub(crate) fn anchored_review_observe_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewObserveEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_OBSERVE_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match observe_review_batch(&envelope.batch, &envelope.records) {
        Ok(observations) => {
            anchored_review_answer(ANCHORED_REVIEW_BATCH_OBSERVATION_KIND, &observations)
        }
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_OBSERVE_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `AdvanceAnchoredReviewItem` frame: admits the envelope, then
/// routes to [`advance_review_item`]. The advanced record value returns for
/// the existing coordination Store owner to persist.
pub(crate) fn anchored_review_advance_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewAdvanceEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_ADVANCE_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match advance_review_item(&envelope.record, envelope.advance, envelope.reason) {
        Ok(advanced) => anchored_review_answer(ANCHORED_REVIEW_ITEM_KIND, &advanced),
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_ADVANCE_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `RouteRequestedChange` frame: admits the envelope, then routes
/// to [`route_requested_change`]. The returned row is a candidate only; it
/// grants no write and performs none.
pub(crate) fn anchored_review_route_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewRouteEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_ROUTE_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match route_requested_change(
        &envelope.record,
        &envelope.owner_id,
        &envelope.effect_entry,
        &envelope.verifier_entry,
        envelope.routed_at_unix_ms,
    ) {
        Ok(route) => anchored_review_answer(ANCHORED_REVIEW_ROUTE_KIND, &route),
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_ROUTE_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `AcceptRequestedChangeEffect` frame: admits the envelope, then
/// routes to [`accept_requested_change_effect`]. Records the normal effect
/// owner's acceptance; the change stays unverified until the verifier
/// closes it, and no direct write is produced.
pub(crate) fn anchored_review_accept_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewAcceptEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_ACCEPT_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match accept_requested_change_effect(
        &envelope.route,
        &envelope.record,
        &envelope.accepted_by,
        &envelope.effect_name,
        envelope.accepted_at_unix_ms,
    ) {
        Ok(effect) => anchored_review_answer(ANCHORED_REVIEW_EFFECT_KIND, &effect),
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_ACCEPT_OPERATION,
            &error.to_string(),
        )),
    }
}

/// Serves one `EscalateReviewBlocker` frame: admits the envelope, then routes
/// to [`escalate_review_blocker`]. Only the classifier's current blocker
/// outcome escalates, to the existing Problem or Critical-Attention control
/// owner the row names; the owning slice delivers it to that control path.
pub(crate) fn anchored_review_escalate_operation(
    session_fence: &StateFence,
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    let envelope: AnchoredReviewEscalateEnvelope =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    admit_review_envelope(
        &envelope.operation,
        ANCHORED_REVIEW_ESCALATE_OPERATION,
        &envelope.state_fence,
        session_fence,
    )?;
    match escalate_review_blocker(
        &envelope.record,
        envelope.blocker,
        envelope.observed_at_unix_ms,
    ) {
        Ok(escalation) => anchored_review_answer(ANCHORED_REVIEW_ESCALATION_KIND, &escalation),
        Err(error) => Ok(anchored_review_refusal(
            ANCHORED_REVIEW_ESCALATE_OPERATION,
            &error.to_string(),
        )),
    }
}
