//! Capability-bound Host runtime-control named-pipe endpoint.
//!
//! The canonical wire contract remains owned by `eliot-host-service`; this
//! cell owns only the bounded authenticated endpoint and its in-process queue.
//!
//! A backup control request on this pipe is admitted only against
//! [`BackupAuthenticatedPeer`], an authenticated context minted from the
//! transport's own observation of the connected handle. The closed accepted
//! method table decides which owner operations exist; it never authenticates
//! the requester, and no caller can build the context.
//!
//! Transport exclusion (I7.5): this admin surface — Kernel restart, store
//! recovery, and authenticated UserAutomation execution — is named-pipe-only
//! and is excluded from the agent-facing loopback HTTP transport profile by
//! routing policy; the loopback HTTP bridge never routes to this endpoint,
//! and this endpoint never exposes itself over HTTP.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    missing_docs,
    reason = "Host runtime-control endpoint keeps explicit production plumbing"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use eliot_host_service::runtime_control::{
    BackupOperationBody, BackupOwnerOutcome, BackupRetainedOperation, BackupRuntimeControlRequest,
    BackupRuntimeControlResponse, HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR,
    HostKernelRestartReceipt, HostReactiveContextRuntimeRequest, HostRuntimeControlOperation,
    HostRuntimeControlRequest, HostRuntimeControlResponse, HostStoreRecoveryReceipt,
    backup_response_frame, backup_response_matches_request, decode_backup_request_frame,
    decode_runtime_control_request_frame, runtime_control_response_frame,
    runtime_control_unknown_ref,
};
use eliot_host_service::runtime_control::{operation_unknown_ref, response_matches_request};
pub use eliot_host_service::{
    UserAutomationHostChannelBinding, UserAutomationHostExecutionEndpoint,
    UserAutomationHostExecutionRequest, UserAutomationHostExecutionResponse,
    UserAutomationRuntimeError, decode_user_automation_host_execution_open_frame,
    decode_user_automation_host_execution_request_frame,
    user_automation_host_execution_open_response_frame,
    user_automation_host_execution_response_frame,
};
use eliot_host_service::{UserAutomationHostExecutionSession, UserAutomationHostOwnerBinding};
use eliot_ipc::{NamedPipeServer, PeerIdentity, TransportLimits};
use tokio::sync::oneshot;

pub mod backup;
pub mod responsiveness_challenge;
pub use backup::{
    AcceptedOwnerMethod, BackupDispatchRefusal, BackupOperationKind, BackupRole,
    BACKUP_REPLAY_IDENTITY_REFUSAL, CUTOVER_AUTHORITY_DIVERGENCE_REFUSAL, HostBackupOwner,
    HostBackupOwnerRegistration, accepted_host_backup_methods, authority_matches,
    backup_replay_refusal, is_supported, register_backup_methods, rehearsal_resolves_cutover,
    requires_cutover_admission, resolves_cutover_authority,
};

use eliot_protocol::backup::BackupReplayLedger;

pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";
const MAX_QUEUE_DEPTH: usize = 32;
const QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AUTOMATION_QUEUE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct ResponseCorrelation(Arc<()>);

struct HostRuntimeControlReply {
    response: HostRuntimeControlResponse,
    correlation: ResponseCorrelation,
}

pub struct HostRuntimeControlEnvelope {
    request: HostRuntimeControlRequest,
    reply: oneshot::Sender<HostRuntimeControlReply>,
    correlation: ResponseCorrelation,
}

impl HostRuntimeControlEnvelope {
    pub fn request(&self) -> &HostRuntimeControlRequest {
        &self.request
    }

    pub fn respond(
        self,
        response: HostRuntimeControlResponse,
    ) -> Result<(), HostRuntimeControlResponse> {
        self.reply
            .send(HostRuntimeControlReply {
                response,
                correlation: self.correlation,
            })
            .map_err(|reply| reply.response)
    }
}

pub type HostRuntimeControlQueue = Arc<Mutex<VecDeque<HostRuntimeControlEnvelope>>>;

struct HostUserAutomationExecutionReply {
    response: UserAutomationHostExecutionResponse,
    correlation: ResponseCorrelation,
}

/// One authenticated UserAutomation request waiting for the explicit Host
/// owner endpoint.  The request is retained until the owner returns a
/// correlated response; no queue consumer may replace its carrier.
pub struct HostUserAutomationExecutionEnvelope {
    request: UserAutomationHostExecutionRequest,
    session: UserAutomationHostExecutionSession,
    reply: oneshot::Sender<HostUserAutomationExecutionReply>,
    correlation: ResponseCorrelation,
}

impl HostUserAutomationExecutionEnvelope {
    /// Returns the exact authenticated carrier admitted by the transport.
    #[must_use]
    pub const fn request(&self) -> &UserAutomationHostExecutionRequest {
        &self.request
    }

    /// Returns the opaque server-authored session retained for this carrier.
    #[must_use]
    pub const fn session(&self) -> &UserAutomationHostExecutionSession {
        &self.session
    }

    /// Completes this request with a response bound to the same carrier.
    ///
    /// The transport performs a second validation before serializing the
    /// response, so a queue consumer cannot substitute another request's
    /// response without producing a fail-closed transport result.
    pub fn respond(
        self,
        response: UserAutomationHostExecutionResponse,
    ) -> Result<(), UserAutomationHostExecutionResponse> {
        self.reply
            .send(HostUserAutomationExecutionReply {
                response,
                correlation: self.correlation,
            })
            .map_err(|reply| reply.response)
    }
}

/// Bounded queue shared by the authenticated endpoint and the Host owner
/// contour.  It carries no fallback owner and never manufactures a Durable
/// Job or WakeIntent result.
pub type HostUserAutomationExecutionQueue =
    Arc<Mutex<VecDeque<HostUserAutomationExecutionEnvelope>>>;

/// Removes one queued UserAutomation carrier for an owner contour.
pub fn pop_user_automation_execution(
    queue: &HostUserAutomationExecutionQueue,
) -> Option<HostUserAutomationExecutionEnvelope> {
    queue.lock().ok()?.pop_front()
}

/// Returns an explicit unavailable response for every request while the
/// root-owned Durable Job gateway has not been composed.
///
/// This is a fail-closed boundary only.  It is deliberately separate from
/// [`process_user_automation_execution_queue`], which requires an explicit
/// typed Host endpoint and is the production owner integration point.
pub fn reject_unbound_user_automation_execution(queue: &HostUserAutomationExecutionQueue) -> usize {
    let mut rejected = 0;
    while let Some(envelope) = pop_user_automation_execution(queue) {
        let response = UserAutomationHostExecutionResponse::failed_for(
            envelope.request(),
            UserAutomationRuntimeError::Unavailable(
                "Host UserAutomation owner is not composed".to_owned(),
            ),
        );
        let _ = envelope.respond(response);
        rejected += 1;
    }
    rejected
}

/// Processes all currently queued UserAutomation carriers through the
/// explicit owner endpoint.  Callers must supply a concrete
/// [`UserAutomationHostExecutionEndpoint`] whose Durable Job and Wake ports
/// are already bound to their canonical owners.
pub async fn process_user_automation_execution_queue<D, W>(
    queue: &HostUserAutomationExecutionQueue,
    endpoint: &UserAutomationHostExecutionEndpoint<D, W>,
) -> usize
where
    D: eliot_host_service::UserAutomationDurableJobPort,
    W: eliot_host_service::UserAutomationWakePort,
{
    let mut processed = 0;
    while let Some(envelope) = pop_user_automation_execution(queue) {
        let response = endpoint
            .execute_authenticated_response(envelope.request.clone(), envelope.session.clone())
            .await;
        let _ = envelope.respond(response);
        processed += 1;
    }
    processed
}

fn response_matches_private_correlation(
    expected: &ResponseCorrelation,
    reply: &HostRuntimeControlReply,
    request: &HostRuntimeControlRequest,
) -> bool {
    Arc::ptr_eq(&expected.0, &reply.correlation.0)
        && response_matches_request(request, &reply.response)
}

/// The authenticated context of one received backup control request.
///
/// The context exists because a closed method table cannot authenticate
/// itself. [`HostRuntimeControl::handle_backup_operation`] decides which owner
/// operations exist; it cannot decide who is asking, and a decoded `role`,
/// `source` or `destination` string is a claim about the request, never a
/// proof of who sent it. This value carries the one fact the transport
/// observed and the payload cannot supply: the peer the pipe itself sealed
/// for the connected handle.
///
/// It is minted only by [`HostRuntimeControl::serve_one`], from
/// [`NamedPipeServer::peer_identity`] on the server the transport has already
/// run [`NamedPipeServer::wait_for_authenticated_client`] against. Every field
/// is private, the sole constructor takes that connected server and is itself
/// private, and the value is neither deserializable, defaulted nor built from a
/// payload field, so no requester on the wire and no caller of this endpoint
/// can construct one or substitute a peer of its own. A context that cannot
/// be minted is an absent observation, and an absent observation is unknown,
/// not zero: the request is refused, never admitted on trust.
///
/// The context grants no authority beyond the observation it was minted from.
/// It is not a cutover receipt, it is not a backup capability, and a permitted
/// administrator connection is therefore not by itself approval for one exact
/// cutover: the separate cutover admission stays with the registered owner
/// operation and its own admission, and every payload `role`, `capability`,
/// `source` and `destination` string stays a claim that authorizes nothing on
/// its own here.
pub struct BackupAuthenticatedPeer {
    /// The provider proof the transport sealed for the connected handle.
    ///
    /// The handle-bound process binding, SID and session inside it are private
    /// to the IPC crate, so this field holds an observation of the live peer
    /// and never a caller-supplied identity.
    peer: PeerIdentity,
}

impl BackupAuthenticatedPeer {
    /// Mints the authenticated context from the transport's own peer
    /// observation of the connected server.
    ///
    /// This is the only constructor, and it takes the connected
    /// [`NamedPipeServer`] itself rather than an identity, so the peer can
    /// only ever come from the transport's own platform proof for a live
    /// connection.
    fn observe_transport_peer(server: &NamedPipeServer) -> Self {
        Self {
            peer: server.peer_identity().clone(),
        }
    }

    /// Admits one decoded backup control request against this authenticated
    /// context, before any owner effect.
    ///
    /// Two facts are required and neither is a payload claim: the transport
    /// sealed a live peer proof for this connection — an unauthenticated or
    /// unproven transport is `PeerIdentity::Unavailable`, which is refused
    /// rather than read as an administrator — and the request still carries
    /// the complete canonical commitment its own carrier defines. The second
    /// check is the existing envelope validator used as it stands, and this is
    /// the admission boundary where the wire identity, operation, principal,
    /// role/capability, nonce, generation, fence and body commitment of this
    /// request must all hold together before any owner is reached. No digest
    /// is recomputed here and no evidence is inferred from the existence or
    /// the shape of a value.
    ///
    /// # Errors
    ///
    /// Returns this operation's typed pre-effect [`BackupDispatchRefusal`]
    /// when the connection carried no transport-proved peer, when that peer's
    /// own proof does not validate, or when the request does not carry its own
    /// canonical identity.
    pub fn admit_request(
        &self,
        request: &BackupRuntimeControlRequest,
    ) -> Result<(), BackupDispatchRefusal> {
        let operation = request.operation;
        let refusal = BackupDispatchRefusal::new;
        if matches!(self.peer, PeerIdentity::Unavailable { .. }) {
            return Err(refusal(
                operation,
                "backup control request carries no transport-proved peer",
            ));
        }
        if self.peer.validate().is_err() {
            return Err(refusal(
                operation,
                "backup control transport peer proof does not validate",
            ));
        }
        if request.validate().is_err() {
            return Err(refusal(
                operation,
                "backup control request lacks its own canonical identity",
            ));
        }
        Ok(())
    }
}

pub struct HostRuntimeControl {
    queue: HostRuntimeControlQueue,
    user_automation_queue: HostUserAutomationExecutionQueue,
    user_automation_owner: Option<UserAutomationHostOwnerBinding>,
    backup_owner: Option<HostBackupOwnerRegistration>,
    /// The canonical `#954` replay ledger for admitted backup control requests.
    ///
    /// It lives on the endpoint rather than inside one request because the
    /// endpoint is the long-lived owner of the canonical pipe: `serve_one` is
    /// driven in a loop by the Host composition for the life of the process, so
    /// this ledger observes every admitted backup request across frames and a
    /// replayed envelope is refused against the ORIGINAL accepted content.
    ///
    /// It is the protocol owner's ledger used as it stands
    /// ([`BackupReplayLedger::observe_typed`]); this endpoint introduces no
    /// second replay scheme and never recomputes a digest to decide one. It is
    /// not durable storage: cross-restart reconciliation and durability stay
    /// with the owner's journal, and this ledger refuses a replay inside one
    /// endpoint lifetime.
    backup_replay: Mutex<BackupReplayLedger>,
}

impl HostRuntimeControl {
    pub fn new_with_capability(
        queue: HostRuntimeControlQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<Self, String> {
        Self::new_with_capability_and_user_automation(
            queue,
            Arc::new(Mutex::new(VecDeque::new())),
            capability,
        )
    }

    /// Creates the endpoint with both the existing runtime-control queue and
    /// the typed UserAutomation owner queue.
    pub fn new_with_capability_and_user_automation(
        queue: HostRuntimeControlQueue,
        user_automation_queue: HostUserAutomationExecutionQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<Self, String> {
        let _guard = capability
            .live_guard()
            .map_err(|_| "Host owner capability is not live".to_owned())?;
        Ok(Self {
            queue,
            user_automation_queue,
            user_automation_owner: None,
            backup_owner: None,
            backup_replay: Mutex::new(BackupReplayLedger::new()),
        })
    }

    /// Creates the runtime-control endpoint with the retained Kernel owner
    /// anchor used to authenticate UserAutomation carriers before enqueue.
    pub fn new_with_capability_and_user_automation_bound(
        queue: HostRuntimeControlQueue,
        user_automation_queue: HostUserAutomationExecutionQueue,
        capability: &eliot_platform_windows::HostOwnerEpochCapability,
        owner: UserAutomationHostOwnerBinding,
    ) -> Result<Self, String> {
        let _guard = capability
            .live_guard()
            .map_err(|_| "Host owner capability is not live".to_owned())?;
        owner.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            queue,
            user_automation_queue,
            user_automation_owner: Some(owner),
            backup_owner: None,
            backup_replay: Mutex::new(BackupReplayLedger::new()),
        })
    }

    /// Registers the Host backup owner and its exact closed dispatch table on
    /// the endpoint that already serves the canonical Host runtime-control
    /// pipe.
    ///
    /// This is registration only: it opens no pipe, starts no task, and can
    /// therefore never delay endpoint readiness. An endpoint without this
    /// registration refuses every backup control request before effects
    /// ([`Self::handle_backup_operation`]), exactly as an endpoint without
    /// the UserAutomation owner refuses UserAutomation carriers.
    #[must_use]
    pub fn with_backup_owner(mut self, owner: HostBackupOwnerRegistration) -> Self {
        self.backup_owner = Some(owner);
        self
    }

    pub fn queue(&self) -> HostRuntimeControlQueue {
        Arc::clone(&self.queue)
    }

    /// Returns the bounded typed UserAutomation owner queue.
    pub fn user_automation_queue(&self) -> HostUserAutomationExecutionQueue {
        Arc::clone(&self.user_automation_queue)
    }

    async fn handle(&self, request: &HostRuntimeControlRequest) -> HostRuntimeControlResponse {
        if request.validate().is_err() {
            return HostRuntimeControlResponse::unknown_for(
                request,
                operation_unknown_ref(&request.operation, "validation", request),
            );
        }
        let (reply, response) = oneshot::channel();
        let correlation = ResponseCorrelation(Arc::new(()));
        {
            let Ok(mut queue) = self.queue.lock() else {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    operation_unknown_ref(&request.operation, "queue-lock", request),
                );
            };
            if queue.len() >= MAX_QUEUE_DEPTH {
                return HostRuntimeControlResponse::unknown_for(
                    request,
                    operation_unknown_ref(&request.operation, "queue-full", request),
                );
            }
            queue.push_back(HostRuntimeControlEnvelope {
                request: request.clone(),
                reply,
                correlation: correlation.clone(),
            });
        }
        match tokio::time::timeout(QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(reply))
                if Arc::ptr_eq(&correlation.0, &reply.correlation.0)
                    && response_matches_request(request, &reply.response) =>
            {
                // Bounded-interval identity recheck (#1757 W7): a queued reply
                // that correlates is not yet proof the Host control loop made
                // progress — a listener-thread echo cannot show that. Re-run
                // the wire-owner validators on both peers after the wait, so
                // a substituted or malformed answer stays an explicit
                // challenge/identity uncertainty instead of health.
                //
                // PARTIAL: the loop-progress proof lives outside this file.
                // STITCH: the Host composition owner contour must answer the
                // owner queue with its current owner/epoch plus the defined
                // control-progress observation, and the challenger must bind
                // the expected owner digest per challenge identity (see
                // `eliot-host-state::host_owner_epoch_digest`); only then can
                // `responsiveness_challenge::validate_owner_challenge_response`
                // gain its production caller on this path.
                if request.validate().is_ok() && reply.response.validate().is_ok() {
                    reply.response
                } else {
                    HostRuntimeControlResponse::unknown_for(
                        request,
                        operation_unknown_ref(
                            &request.operation,
                            "queue-response-identity",
                            request,
                        ),
                    )
                }
            }
            Ok(Ok(_)) => HostRuntimeControlResponse::unknown_for(
                request,
                operation_unknown_ref(&request.operation, "queue-response", request),
            ),
            Ok(Err(_)) | Err(_) => HostRuntimeControlResponse::unknown_for(
                request,
                operation_unknown_ref(&request.operation, "queue-response", request),
            ),
        }
    }

    async fn handle_user_automation(
        &self,
        request: UserAutomationHostExecutionRequest,
        server: &NamedPipeServer,
        channel: UserAutomationHostChannelBinding,
    ) -> UserAutomationHostExecutionResponse {
        let Some(owner) = self.user_automation_owner.as_ref() else {
            return UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::Unavailable(
                    "Host UserAutomation owner is not composed".to_owned(),
                ),
            );
        };
        let session = match UserAutomationHostExecutionSession::issue(
            channel,
            request.request_sha256.clone(),
            server.peer_identity().clone(),
            owner.clone(),
        ) {
            Ok(session) => session,
            Err(error) => {
                return UserAutomationHostExecutionResponse::failed_for(&request, error);
            }
        };
        if session.authorize_request(&request).is_err() {
            return UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::IdentityConflict,
            );
        }
        let (reply, response) = oneshot::channel();
        let correlation = ResponseCorrelation(Arc::new(()));
        {
            let Ok(mut queue) = self.user_automation_queue.lock() else {
                return UserAutomationHostExecutionResponse::failed_for(
                    &request,
                    UserAutomationRuntimeError::Unavailable(
                        "UserAutomation owner queue lock is poisoned".to_owned(),
                    ),
                );
            };
            if queue.len() >= MAX_QUEUE_DEPTH {
                return UserAutomationHostExecutionResponse::failed_for(
                    &request,
                    UserAutomationRuntimeError::Rejected(
                        "UserAutomation owner queue is full".to_owned(),
                    ),
                );
            }
            // This endpoint is only the authenticated queue boundary. It is
            // neither a durable mutation owner nor a replay ledger: an exact
            // retry after an UnknownOutcome must reach the canonical Store or
            // Host journal owner, including after this process restarts.
            queue.push_back(HostUserAutomationExecutionEnvelope {
                request: request.clone(),
                session,
                reply,
                correlation: correlation.clone(),
            });
        }
        match tokio::time::timeout(USER_AUTOMATION_QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(reply))
                if Arc::ptr_eq(&correlation.0, &reply.correlation.0)
                    && reply.response.validate_for(&request).is_ok() =>
            {
                reply.response
            }
            Ok(Ok(_)) => UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::IdentityConflict,
            ),
            Ok(Err(_)) | Err(_) => UserAutomationHostExecutionResponse::failed_for(
                &request,
                UserAutomationRuntimeError::UnknownOutcome(
                    "UserAutomation owner response crossed an unknown boundary".to_owned(),
                ),
            ),
        }
    }

    /// Admits one decoded backup control request and routes it to the
    /// registered owner operation (#962).
    ///
    /// The order is fail-closed and every gate runs before any owner effect:
    /// the authenticated context the transport derived for this connection,
    /// the closed Host-accepted method table, the payload-to-authenticated
    /// operation binding, the separate cutover admission, the registered
    /// dispatch row, the owner itself, and finally the exact request/response
    /// identity. An unsupported or absent method, a payload that does not
    /// carry the authenticated operation's own wire identity, and a cutover
    /// without its separate installation-authority admission are all refused
    /// here, so none of them can be reported as a no-op/zero/default success.
    ///
    /// The authenticated context ([`BackupAuthenticatedPeer`]) and the closed
    /// table are separate invariants and neither replaces the other: a
    /// consistent table row never authenticates a requester, and an
    /// authenticated connection never admits an operation the table does not
    /// carry. The context also grants no cutover authority, so a permitted
    /// administrator peer is not by itself approval for one exact cutover.
    ///
    /// The answer is the owner's own typed outcome, bound to the exact
    /// admitted request by [`BackupRuntimeControlResponse::backup_response_for`]
    /// and validated with the existing [`backup_response_matches_request`]
    /// before it is serialized. That constructor supplies the correlation
    /// portion only: the pending/completed/possible-effect disposition, the
    /// retained operation, the owner's phase attestation, and any prepared
    /// destination handle all come from the owner, never from the request. A
    /// response therefore cannot exist without an owner outcome, and
    /// correlation alone is never reported as backup semantic success.
    ///
    /// A pre-effect [`BackupDispatchRefusal`] stays typed all the way to the
    /// caller; it is rendered to text exactly once, at the endpoint's own
    /// pre-existing `Result<(), String>` boundary. A refusal is only ever
    /// produced by a gate that ran before the owner was called, so no
    /// response is fabricated for a request that may already have effected.
    ///
    /// # Errors
    ///
    /// Returns [`BackupDispatchRefusal`] when any gate above refuses. The
    /// refusal is always produced before any owner effect.
    fn handle_backup_operation(
        &self,
        request: &BackupRuntimeControlRequest,
        peer: &BackupAuthenticatedPeer,
    ) -> Result<BackupRuntimeControlResponse, BackupDispatchRefusal> {
        let operation = request.operation;
        let refusal = BackupDispatchRefusal::new;
        // 0. The authenticated context. This request is admitted only against
        //    the peer the transport itself proved for this connection and
        //    against the complete canonical commitment the carrier already
        //    defines for it. The context is derived from the transport's own
        //    observation, so a payload `role`, `source` or `destination`
        //    string cannot become authority here however self-consistent it
        //    is, and a connection the transport could not prove refuses
        //    before the closed table below is even consulted.
        peer.admit_request(request)?;
        // 0a. Cutover authority is ONE operation. The canonical disposition
        //     must agree with the operation itself that only the separately
        //     admitted cutover request reaches cutover authority; a rehearsal
        //     completion, or any other canonical operation, that ever resolved
        //     there refuses here, in a normal build, before the closed table is
        //     consulted and long before any owner effect. This is the release
        //     caller for the rehearsal/cutover guarantee: the only previous
        //     caller of that predicate was a `debug_assert!`, which a release
        //     build removes, so nothing carried the guarantee there.
        if backup::resolves_cutover_authority(operation)
            != (operation == BackupOperationKind::AdmitCutover)
        {
            return Err(refusal(
                operation,
                backup::CUTOVER_AUTHORITY_DIVERGENCE_REFUSAL,
            ));
        }
        // 1. Closed Host-accepted method table. Unsupported and absent
        //    methods fail before effects, never as a default success.
        if !backup::is_supported(operation) {
            return Err(refusal(
                operation,
                "backup method is not accepted by the Host",
            ));
        }
        let method = accepted_host_backup_methods()
            .iter()
            .find(|method| method.op == operation)
            .ok_or_else(|| {
                refusal(
                    operation,
                    "backup method has no accepted Host registration row",
                )
            })?;
        // 2. The payload's claimed operation must carry the authenticated
        //    operation's own canonical wire identity. Only exact byte
        //    equality passes, so a payload can never substitute another
        //    operation's wire identity and select an owner operation.
        if !authority_matches(operation, method.wire_id) {
            return Err(refusal(
                operation,
                "backup payload does not carry the authenticated operation wire identity",
            ));
        }
        // 3. Resolve the operation's separate cutover admission from the
        //    closed accepted table. `None` means the method carries no
        //    accepted registration at all and fails before effects.
        let Some(needs_cutover_admission) = backup::requires_cutover_admission(operation) else {
            return Err(refusal(
                operation,
                "backup method has no accepted Host cutover admission",
            ));
        };
        // A cutover requires the authenticated role that carries cutover
        // authority. A prepare-domain role cannot present a cutover
        // admission, and a rehearsal completion is not an accepted method at
        // all, so rehearsal can never select cutover.
        //
        // This decoded role claim is still not this admission by itself, and
        // the authenticated context above is deliberately not a substitute for
        // it: a proved administrator peer never approves one exact cutover,
        // and the registered owner operation below performs its own separate
        // cutover admission before it can effect anything.
        if needs_cutover_admission && !request.role.permits(BackupOperationKind::AdmitCutover) {
            return Err(refusal(
                operation,
                "backup cutover lacks its separate installation-authority admission",
            ));
        }
        // 4. The registered closed dispatch table is the owner registration:
        //    an accepted method the composition did not register has no owner
        //    operation and fails before effects.
        let Some(registration) = self.backup_owner.as_ref() else {
            return Err(refusal(operation, "Host backup owner is not composed"));
        };
        let Some(registered) = registration.registered_method(operation) else {
            return Err(refusal(
                operation,
                "no Host backup owner operation is registered for this method",
            ));
        };
        if registered.needs_cutover_admission != needs_cutover_admission {
            return Err(refusal(
                operation,
                "registered cutover admission diverges from the accepted Host backup table",
            ));
        }
        // 4a. Replayed envelope, refused by the canonical `#954` replay ledger
        //     against the ORIGINAL content this endpoint already accepted.
        //     Duplicate, unknown, stale and changed replay are four distinct
        //     closed classes and each is refused with its own typed reason; the
        //     class text is read from the owner, so this endpoint does not
        //     become a second source for the reason vocabulary. The observation
        //     happens after every gate above has passed and before the owner is
        //     called, so this refusal is exact and pre-effect: nothing has
        //     transitioned, and the caller reconciles the original operation
        //     instead of starting a second one.
        let mut ledger = match self.backup_replay.lock() {
            Ok(ledger) => ledger,
            Err(_) => {
                return Err(refusal(operation, "backup replay ledger is unavailable"));
            }
        };
        // The observation is taken under the lock and the guard is released
        // before the owner is called, so no ledger guard is ever held across
        // an owner call.
        let observed = ledger.observe_typed(request.body.identity());
        drop(ledger);
        // `backup::backup_replay_refusal` is the ONE place this endpoint turns
        // a replay observation into an answer. It reads the owner's typed
        // result and never recomputes a digest or re-decides which case
        // occurred, so the endpoint cannot become a second source for the replay
        // vocabulary; `None` is the only path that reaches the owner below.
        if let Some(refused) = backup::backup_replay_refusal(operation, observed) {
            return Err(refused);
        }
        // 5. Route to the one registered owner operation. Its typed outcome
        //    is the only source of the answer's disposition: pending,
        //    completed with the owner's receipt, or possible-effect. A
        //    pre-effect refusal of the owner stays a refusal.
        let outcome = registration.dispatch(request)?;
        // 6. Exact-identity answer. Correlation comes from the request and
        //    the disposition from the owner; the two are re-validated
        //    together, so a transport acknowledgement, a foreign retained
        //    operation, or a phase this operation cannot establish is never
        //    reported as backup semantic success.
        let response = BackupRuntimeControlResponse::backup_response_for(request, outcome);
        if !backup_response_matches_request(request, &response) {
            return Err(refusal(
                operation,
                "backup response does not match the admitted request identity",
            ));
        }
        Ok(response)
    }

    pub async fn serve_one(&self, timeout: Duration) -> Result<(), String> {
        let installer =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|error| error.to_string())?;
        let mut server = NamedPipeServer::create(HOST_RUNTIME_CONTROL_PIPE, &installer)
            .map_err(|error| error.to_string())?;
        server
            .wait_for_authenticated_client(timeout, &installer)
            .await
            .map_err(|error| error.to_string())?;
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .map_err(|error| error.to_string())?;
        if let Ok(open_id) = decode_user_automation_host_execution_open_frame(&frame) {
            let owner = self
                .user_automation_owner
                .as_ref()
                .ok_or_else(|| "Host UserAutomation owner is not composed".to_owned())?;
            let channel = UserAutomationHostChannelBinding::issue_server_authored(
                server.peer_identity(),
                owner,
            )
            .map_err(|error| error.to_string())?;
            let open_response =
                user_automation_host_execution_open_response_frame(&open_id, &channel)
                    .map_err(|error| error.to_string())?;
            server
                .send_frame(&open_response, limits)
                .await
                .map_err(|error| error.to_string())?;
            let request_frame = server
                .receive_frame(limits)
                .await
                .map_err(|error| error.to_string())?;
            let request = decode_user_automation_host_execution_request_frame(&request_frame)
                .map_err(|error| error.to_string())?;
            let response = self
                .handle_user_automation(request.clone(), &server, channel)
                .await;
            let response_frame = user_automation_host_execution_response_frame(&request, &response)
                .map_err(|error| error.to_string())?;
            server
                .send_frame(&response_frame, limits)
                .await
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        let connection_id = frame.connection_id.clone();
        let response_frame = match decode_runtime_control_request_frame(&frame) {
            Ok(request) => {
                let response = self.handle(&request).await;
                runtime_control_response_frame(connection_id, &response)?
            }
            Err(_) => {
                // The canonical Host runtime-control pipe also carries the
                // `#954` backup envelope. Its decoder is the existing bridge
                // owner; a frame that is neither shape still falls through to
                // the unchanged UserAutomation refusal below. A backup request
                // that is not admitted fails with its typed refusal here, so
                // no unsupported method can reach an owner effect.
                if let Ok(backup_request) = decode_backup_request_frame(&frame) {
                    // The authenticated context is minted here, from the
                    // transport's own observation of the connected peer, and
                    // travels into the backup handler. It cannot be supplied
                    // by the requester: the constructor takes the connected
                    // server the transport just authenticated and has private
                    // fields, so no frame can carry or name one.
                    //
                    // The typed refusal is rendered to text exactly once,
                    // here, at the endpoint's pre-existing `Result<(), String>`
                    // boundary. No backup request is answered with a frame
                    // unless every gate admitted it and the registered owner
                    // returned its own outcome; the frame states that outcome,
                    // so a pending or possibly-effected operation stays
                    // visible as such instead of collapsing into a refusal.
                    let peer = BackupAuthenticatedPeer::observe_transport_peer(&server);
                    let backup_response = self
                        .handle_backup_operation(&backup_request, &peer)
                        .map_err(|refused| refused.to_string())?;
                    backup_response_frame(connection_id, &backup_response)?
                } else {
                    let request = decode_user_automation_host_execution_request_frame(&frame)
                        .map_err(|error| error.to_string())?;
                    let response = UserAutomationHostExecutionResponse::failed_for(
                        &request,
                        UserAutomationRuntimeError::IdentityConflict,
                    );
                    user_automation_host_execution_response_frame(&request, &response)
                        .map_err(|error| error.to_string())?
                }
            }
        };
        server
            .send_frame(&response_frame, limits)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_host_service::runtime_control::runtime_control_request_frame;
    use eliot_platform::PlatformHandle;

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn endpoint_uses_builtin_administrator_policy() {
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .unwrap_or_else(|_| unreachable!());
        assert!(expectation.requires_builtin_administrators());
        assert_eq!(expectation.expected_sid(), "S-1-5-32-544");
        assert_eq!(
            HOST_RUNTIME_CONTROL_PIPE,
            r"\\.\pipe\eliot\host\runtime-control-v1"
        );
    }

    #[test]
    fn shared_wire_roundtrip_has_no_in_process_capability_field() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("host-wire-test"),
        )
        .unwrap_or_else(|_| unreachable!());
        let frame = runtime_control_request_frame("host-test-connection", &request)
            .unwrap_or_else(|_| unreachable!());
        let value = serde_json::to_value(&request).unwrap_or_else(|_| unreachable!());
        assert!(value.get("response_capability").is_none());
        assert!(decode_runtime_control_request_frame(&frame).is_ok());
    }

    #[test]
    fn same_digest_forged_response_requires_the_private_queue_correlation() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("same-digest-response"),
        )
        .unwrap_or_else(|_| unreachable!());
        let response = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("kernel-restart", &request),
        };
        assert!(response_matches_request(&request, &response));

        let expected = ResponseCorrelation(Arc::new(()));
        let forged = HostRuntimeControlReply {
            response: response.clone(),
            correlation: ResponseCorrelation(Arc::new(())),
        };
        assert!(!response_matches_private_correlation(
            &expected, &forged, &request
        ));

        let trusted = HostRuntimeControlReply {
            response,
            correlation: expected.clone(),
        };
        assert!(response_matches_private_correlation(
            &expected, &trusted, &request
        ));
    }
}
