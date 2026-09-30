//! Governor-owned issuance of the coordination work-item and lease identity.
//!
//! # Why this module exists
//!
//! The coordination owner is the only authority over a coordination
//! `work_item_id` and `lease_id`: nothing in the workspace names them, and every
//! owner method that would create them
//! (`CoordinationOwner::register_work`, `acquire_work`, and
//! `acquire_work_with_issuance`) takes the identity as an input. Until
//! something issued that input the persisted `owner/coordination` image held no
//! session, no work item, and no lease, and every production consumer of that
//! image — including `GovernorComposition::read_unique_agent_activation`, which
//! is what projects `work_unit_id` — could never observe a live lease.
//!
//! This module is that issuer. It lives in `eliot-governor` because the Governor
//! owns coordination intent (`crates/governor/AGENTS.md`) and because
//! `eliot-coordination` deliberately has no `eliot-protocol` edge, so the
//! coordination owner cannot itself read the Kernel-issued attempt.
//!
//! # What is derived and what is not
//!
//! Every handle this module emits is a pure function of the Kernel-issued
//! [`TaskControllerAttempt`] — its `attempt_id`, `operation_id`,
//! `fencing_generation`, `session_id`, `scope_id`, `task_id`, `state_fence`,
//! `authority_epoch`, `expires_at_unix_ms`, and `use_budget` — through the
//! repository's single canonicalization and digest owner
//! (`eliot_contracts::canonical_json_bytes` + `eliot_contracts::sha256_hex`),
//! exactly the construction `CoordinationOwner` already uses for its own event
//! identities (`format!("claim:{}", lease_id)`) and that
//! `work_lease_issuance::issue_provenance` uses for the canonical
//! `WorkLeaseId`.
//!
//! There is no literal, counter, ambient clock, or random input in any emitted
//! handle. Consequences that matter:
//!
//! - a changed attempt produces a different handle, so a coordination work item
//!   can never be reused for, or outlive, another attempt;
//! - an exact replay of one admitted claim reproduces byte-identical handles,
//!   so the coordination owner's own idempotent and conflict paths are the ones
//!   that decide a replay, not a fresh identity;
//! - `session_id` is not derived at all: it is the Kernel's own authenticated
//!   session for the attempt, carried verbatim.
//!
//! # The two references that are not owner-issued anywhere
//!
//! `RegisterSession` requires a `principal_id` and a `route_ref`. No owner in
//! the workspace issues either for a Task Controller attempt, so they are
//! derived here as namespaced, content-bound references to the exact admitted
//! attempt and are documented as what they are: **recorded references, not
//! validated external authority.** They change whenever the attempt changes, and
//! the session-owner admission inside `read_unique_agent_activation` remains the
//! place where a real session-owner principal is bound. This limitation is
//! recorded rather than papered over with an invented constant.
//!
//! # Time and window
//!
//! The coordination lease window is exactly the remaining Kernel attempt window:
//! `lease_duration = attempt.expires_at_unix_ms - now`, and an attempt that has
//! already expired is refused. There is no configured lease constant, so the
//! coordination lease can never outlive the Kernel capability that authorized
//! it, and the session heartbeat deadline is the attempt's own Kernel-issued
//! expiry.
//!
//! # Authority
//!
//! This module issues identity only. It admits nothing: the coordination owner
//! still re-checks the session, the lease holder, the lease window, the
//! authority epoch, the fence, the work-item state, and the event idempotency
//! on the way in, and it still stamps every admitted result at
//! `CandidateArtifact`. No handle emitted here is a Task finish decision, a
//! completion proof, or a closure authority.

#![forbid(unsafe_code)]

use eliot_contracts::{
    ClockReading, OperationId, RequestId, RequestMetadata, canonical_json_bytes, sha256_hex,
};
use eliot_coordination::{RegisterSession, WorkItem, WorkLeaseRequest, WorkState};
use eliot_protocol::{ProtocolError, RequestIdentity, TaskControllerAttempt};
use eliot_receipts::RequestBinding;
use serde::Serialize;
use thiserror::Error;

/// Revision of the complete owner-issued coordination work-identity encoding.
///
/// Bound into every derived handle, so a future encoding change cannot silently
/// re-key a coordination record already admitted under this one.
pub const COORDINATION_WORK_IDENTITY_REVISION: &str =
    "eliot.governor.coordination-work-identity.v1";

/// Domain separator that keeps these digests disjoint from every other digest
/// in the system, so a coordination work identity can never be reproduced from
/// unrelated material.
const IDENTITY_DOMAIN: &str = "eliot.governor.coordination-work-identity";

/// Namespace of the derived coordination work-item identity.
pub const COORDINATION_WORK_ITEM_NAMESPACE: &str = "coordwork-item";
/// Namespace of the derived coordination lease identity.
pub const COORDINATION_WORK_LEASE_NAMESPACE: &str = "coordwork-lease";
/// Namespace of the derived coordination result identity.
pub const COORDINATION_RESULT_NAMESPACE: &str = "coordwork-result";
/// Namespace of the derived coordination session principal reference.
const COORDINATION_PRINCIPAL_NAMESPACE: &str = "coordwork-principal";
/// Namespace of the derived coordination session route reference.
const COORDINATION_ROUTE_NAMESPACE: &str = "coordwork-route";
/// Namespace prefix of a coordination candidate artifact reference.
pub const COORDINATION_RESULT_ARTIFACT_NAMESPACE: &str = "coordwork-artifact";

const SESSION_COMPONENT: &str = "session";
const WORK_COMPONENT: &str = "work";
const LEASE_COMPONENT: &str = "lease";
const RESULT_COMPONENT: &str = "result";

/// Typed failure at the coordination work-identity issuance boundary.
#[derive(Debug, Error)]
pub enum CoordinationIdentityError {
    /// The Kernel-issued attempt or the admitted request identity did not pass
    /// its own closed-shape validation, so nothing was derived from it.
    #[error("coordination work identity input is not valid: {0}")]
    Input(#[from] ProtocolError),
    /// The admitted request identity and the Kernel-issued attempt disagree
    /// about the fence this lifecycle is admitted under.
    #[error("admitted request identity and Kernel attempt do not bind one state fence")]
    FenceMismatch,
    /// The admitted request identity does not name the attempt's task.
    #[error("admitted request identity does not name the Kernel attempt's task")]
    TaskMismatch,
    /// The observation instant is unusable as a coordination lease issue time.
    #[error("coordination work identity observation instant must be greater than zero")]
    ObservationInstant,
    /// The Kernel attempt has no remaining window, so no coordination lease can
    /// be issued under it. Refused rather than issued with a zero duration.
    #[error("Kernel attempt has no remaining window for a coordination lease")]
    AttemptExpired,
    /// A derived identifier was not constructible as a contract identifier.
    #[error("coordination work identity could not be constructed: {0}")]
    Contract(String),
    /// The identity digest input could not be canonicalized.
    #[error("coordination work identity input could not be canonicalized: {0}")]
    Encoding(String),
}

/// One issued coordination lifecycle leg's transport identity.
///
/// The three legs commit three different `owner/coordination` images, so they
/// cannot share one idempotency key: the store would read the second leg as a
/// conflicting replay of the first. Each leg therefore carries its own derived
/// key, and each is a pure function of the same attempt, so an exact replay of
/// one claim reproduces all three and the store's own arbitration decides it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationLegIdentity {
    /// Owner-side request identity for this leg, used verbatim as the
    /// coordination owner's event idempotency key.
    pub request_id: RequestId,
    /// Canonical envelope operation identity for this leg.
    pub operation_id: OperationId,
    /// Store idempotency key for this leg.
    pub idempotency_key: String,
    /// The complete admitted request identity handed to the commit entry.
    pub identity: RequestIdentity,
}

/// One complete coordination lifecycle identity for one Kernel-issued attempt.
///
/// The three owner request values are the coordination owner's own types, so
/// every field is re-validated by the owner on the way in; this struct is the
/// issuer, not a second validator. It carries no `AgentResultDraft`: the
/// candidate result reference has its own closed ingress shape, because a result
/// is the one leg a weaker check would matter on.
#[derive(Clone, Debug)]
pub struct IssuedCoordinationWork {
    /// Leg identity for the session registration commit.
    pub session_leg: CoordinationLegIdentity,
    /// Leg identity for the work registration commit.
    pub work_leg: CoordinationLegIdentity,
    /// Leg identity for the lease acquisition commit.
    pub lease_leg: CoordinationLegIdentity,
    /// Leg identity for the candidate result admission commit.
    pub result_leg: CoordinationLegIdentity,
    /// The registered coordination session for the attempt.
    pub session: RegisterSession,
    /// The ready coordination work item for the attempt.
    pub work_item: WorkItem,
    /// The fenced coordination lease claim for the ready work item.
    pub lease: WorkLeaseRequest,
    /// Owner-issued candidate result identity for this attempt's one result.
    pub result_id: String,
    /// Clock reading the owner records for the work registration event. This is
    /// the admitted request's own observation, not a fresh reading.
    pub observed_clock: ClockReading,
}

/// Canonical digest input for one derived coordination handle.
///
/// Every field is owner-issued: the attempt is Kernel-issued, and the component
/// and the two constants are this owner's own. Nothing ambient enters here.
#[derive(Serialize)]
struct IdentityDigestInput<'a> {
    domain_separator: &'a str,
    revision: &'a str,
    component: &'a str,
    attempt: &'a TaskControllerAttempt,
}

fn derived_handle(
    component: &str,
    attempt: &TaskControllerAttempt,
) -> Result<String, CoordinationIdentityError> {
    let bytes = canonical_json_bytes(&IdentityDigestInput {
        domain_separator: IDENTITY_DOMAIN,
        revision: COORDINATION_WORK_IDENTITY_REVISION,
        component,
        attempt,
    })
    .map_err(|error| CoordinationIdentityError::Encoding(error.to_string()))?;
    Ok(format!("{component}:{}", sha256_hex(&bytes)))
}

fn leg_identity(
    component: &str,
    attempt: &TaskControllerAttempt,
    admitted: &RequestIdentity,
) -> Result<CoordinationLegIdentity, CoordinationIdentityError> {
    let handle = derived_handle(component, attempt)?;
    let request_id = RequestId::new(format!("{handle}:request"))
        .map_err(|error| CoordinationIdentityError::Contract(error.to_string()))?;
    let operation_id = OperationId::new(format!("{handle}:operation"))
        .map_err(|error| CoordinationIdentityError::Contract(error.to_string()))?;
    let idempotency_key = format!("{handle}:idempotency");
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: request_id.clone(),
                session_id: admitted.request.metadata.session_id.clone(),
                task_id: Some(attempt.task_id.clone()),
                product_id: admitted.request.metadata.product_id.clone(),
                source_id: admitted.request.metadata.source_id.clone(),
                state_fence: attempt.state_fence.clone(),
                clock: admitted.request.metadata.clock,
            },
            state_fence: attempt.state_fence.clone(),
        },
        idempotency_key: idempotency_key.clone(),
        deadline_unix_ms: attempt.expires_at_unix_ms,
        cancellation_id: admitted.cancellation_id.clone(),
    };
    identity.validate()?;
    Ok(CoordinationLegIdentity {
        request_id,
        operation_id,
        idempotency_key,
        identity,
    })
}

/// Issues the complete coordination lifecycle identity for one Kernel-issued
/// Task Controller attempt.
///
/// `admitted` is the request identity the Kernel admitted for the same claim.
/// It is required, not optional, and it is checked against the attempt: a fence
/// or task disagreement is refused here rather than producing a lifecycle leg
/// bound to a foreign admission.
///
/// `now` is the observation instant in the same millisecond time base as
/// `attempt.expires_at_unix_ms`; the coordination lease window is exactly the
/// remaining attempt window, so an expired attempt is refused instead of being
/// issued a zero-duration lease.
///
/// This issues identity only. Nothing here is admitted, published, or
/// persisted: the caller commits the three owner requests through the durable
/// `owner/coordination` route, and the coordination owner re-validates all of
/// it.
pub fn issue_coordination_work(
    attempt: &TaskControllerAttempt,
    admitted: &RequestIdentity,
    now: u64,
) -> Result<IssuedCoordinationWork, CoordinationIdentityError> {
    attempt.validate()?;
    admitted.validate()?;
    if admitted.request.state_fence != attempt.state_fence
        || admitted.request.metadata.state_fence != attempt.state_fence
    {
        return Err(CoordinationIdentityError::FenceMismatch);
    }
    if admitted.request.metadata.task_id.as_ref() != Some(&attempt.task_id) {
        return Err(CoordinationIdentityError::TaskMismatch);
    }
    if now == 0 {
        return Err(CoordinationIdentityError::ObservationInstant);
    }
    let lease_duration = attempt
        .expires_at_unix_ms
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(CoordinationIdentityError::AttemptExpired)?;

    let work_item_id = derived_handle(COORDINATION_WORK_ITEM_NAMESPACE, attempt)?;
    let lease_id = derived_handle(COORDINATION_WORK_LEASE_NAMESPACE, attempt)?;
    let result_id = derived_handle(COORDINATION_RESULT_NAMESPACE, attempt)?;
    let principal_id = derived_handle(COORDINATION_PRINCIPAL_NAMESPACE, attempt)?;
    let route_ref = derived_handle(COORDINATION_ROUTE_NAMESPACE, attempt)?;

    let session_leg = leg_identity(SESSION_COMPONENT, attempt, admitted)?;
    let work_leg = leg_identity(WORK_COMPONENT, attempt, admitted)?;
    let lease_leg = leg_identity(LEASE_COMPONENT, attempt, admitted)?;
    let result_leg = leg_identity(RESULT_COMPONENT, attempt, admitted)?;
    // The owner-side event idempotency key is the same text as the leg's
    // request identity, so the coordination event, the store envelope, and the
    // transport all name one request per leg.
    let session_request_id = session_leg.request_id.as_str().to_owned();
    let lease_request_id = lease_leg.request_id.as_str().to_owned();

    Ok(IssuedCoordinationWork {
        session_leg,
        work_leg,
        lease_leg,
        result_leg,
        session: RegisterSession {
            request_id: session_request_id,
            // The Kernel's own authenticated session for this attempt, carried
            // verbatim. It is never re-derived: a different session for the
            // same attempt would be a different admission.
            session_id: attempt.session_id.clone(),
            principal_id,
            route_ref,
            authority_epoch: attempt.authority_epoch.clone(),
            state_fence: attempt.state_fence.clone(),
            now,
            heartbeat_deadline: attempt.expires_at_unix_ms,
        },
        work_item: WorkItem {
            work_item_id: work_item_id.clone(),
            task_id: attempt.task_id.to_string(),
            state: WorkState::Ready,
            state_fence: attempt.state_fence.clone(),
            owner_session_id: None,
            lease_id: None,
            // Zero-based coordination attempt counter; the owner increments it on
            // the claim. The Kernel fencing generation is not projected here
            // because it is a different counter over a different domain, and
            // narrowing it into this one would conflate them.
            attempt: 0,
            checkpoint_ref: None,
            result_ref: None,
        },
        lease: WorkLeaseRequest {
            request_id: lease_request_id,
            lease_id,
            work_item_id: work_item_id.clone(),
            session_id: attempt.session_id.clone(),
            authority_epoch: attempt.authority_epoch.clone(),
            state_fence: attempt.state_fence.clone(),
            now,
            lease_duration,
        },
        result_id,
        observed_clock: admitted.request.metadata.clock,
    })
}
