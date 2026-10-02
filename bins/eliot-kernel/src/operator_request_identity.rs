//! Kernel-owned per-operation request identity for the public operator CLI
//! entries (issue #4600).
//!
//! I7.2/I7.3 and I11.8: one authenticated local session needs a *fresh, exact,
//! operation-bound* EBP [`RequestIdentity`] before it may cross the front door
//! for an application operation. The public `eliot ui` and
//! `eliot controlboard status` entries are served by this Kernel composition,
//! so the Kernel is the admission owner that mints the identity. The CLI never
//! mints one: it asks this owner, over the same authenticated session it
//! already holds, and it re-validates the answer against the live
//! [`ServerHello`](eliot_protocol::ServerHello) before use.
//!
//! Every field is taken from the same admitted front-door state the closed
//! dispatch matrix already trusts, and from nothing else:
//!
//! * **principal** — the OS-observed pipe peer of the admitted session
//!   (`Session::peer`: SID, logon session, handle-bound process binding). It is
//!   echoed as proof of which principal the identity was issued to; it is never
//!   accepted from the wire.
//! * **session** — `Session::connection_id` with `Session::session_epoch`, the
//!   transport binding this composition itself established. It is bound into
//!   [`RequestMetadata::session_id`] and into the request id, so an identity is
//!   useless on any other connection.
//! * **generation / Authority Epoch / StateFence** — the *current* front-door
//!   policy generation (`front_door_policy.module_generation.state_fence`),
//!   re-read live under the same lock the closed gateway uses. The presented
//!   session must be compatible with it, so a replaced or expired generation
//!   fences before any identity exists.
//! * **role / capability** — the session's already-admitted capability set,
//!   filtered against the live policy's allowed set. A capability the session
//!   does not hold is never placed in a grant.
//! * **clock / deadline** — the crate-wide `unix_ms()` clock this composition
//!   already reads for every other admission, plus one bounded lease. Nothing
//!   here is a static deadline and nothing is read from ambient environment.
//!
//! One-use handoff: the retained [`OperatorIdentityLedger`] records every
//! `(session, operation)` pair it has issued for, together with the exact
//! [`RequestIdentity`]. A repeated request for the same pair replays the
//! retained identity (exact retry / unknown-outcome reconciliation, and never a
//! second launch); a request for a *different* operation always mints a fresh
//! identity, and replaying one operation's identity for another is refused.
//! The ledger is process-local and bounded: at the bound this owner fails
//! closed rather than evicting reuse evidence.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use eliot_contracts::{
    ClockReading, EpochId, ProductId, RequestId, ResourceGeneration, SessionId, SourceId,
    StateFence,
};
use eliot_receipts::RequestBinding;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload, RequestIdentity};

use super::{KernelComposition, KernelFrameAction, Session, TransportError, unix_ms};

/// The one closed wire identity of this issuance request/grant pair.
///
/// Declared identically on both ends of the authenticated boundary: the CLI
/// crate re-declares this exact wire id and version as its closed decode shape
/// (`crates/surfaces/eliot-cli/src/lib.rs`), because the Kernel is the
/// semantic owner and the CLI is its consumer.
pub const OPERATOR_REQUEST_IDENTITY_WIRE_ID: &str = "eliot.operator.request-identity";
/// Wire version of [`OPERATOR_REQUEST_IDENTITY_WIRE_ID`].
pub const OPERATOR_REQUEST_IDENTITY_WIRE_VERSION: u16 = 1;

/// Prefix of the Kernel-minted request id of every issued operator identity.
///
/// I5.27 canonical operation identity: the value is minted here, is unique per
/// `(session, operation, issuance ordinal)`, and is never caller-supplied.
const OPERATOR_REQUEST_ID_PREFIX: &str = "operator-request-identity";

/// Stable product identity this composition issues under.
///
/// The value is the Kernel front-door service name, the same string the CLI
/// already proves against `ServerHello` in `validate_server_snapshot`.
const OPERATOR_IDENTITY_PRODUCT_ID: &str = "eliot-kernel";

/// Stable source identity of this issuance route.
const OPERATOR_IDENTITY_SOURCE_ID: &str = "operator-request-identity";

/// Bounded lease of one issued operator request identity, in milliseconds.
///
/// It is a lease, not a deadline: the absolute `deadline_unix_ms` of every
/// identity is `issued_at + this`, read from the composition's own clock at
/// issuance. No caller can extend it, and no static absolute deadline exists.
const OPERATOR_REQUEST_IDENTITY_TTL_MS: u64 = 30_000;

/// Bounded retained issuances per composition process lifetime.
///
/// Reaching it fails closed. Evicting a retained row would let a spent
/// operation identity be reissued under a new request id, which is exactly the
/// reuse this owner exists to prevent.
const MAX_RETAINED_OPERATOR_IDENTITIES: usize = 4_096;

/// Closed vocabulary of operations this owner issues an identity for.
///
/// The set is closed on purpose: an issuer that would mint for any caller-named
/// operation would be a general authority factory, not an admission owner. Both
/// entries are the exact wire selectors the public CLI entries send.
const ISSUABLE_OPERATIONS: [&str; 2] = ["operator.launch", "controlboard.status"];

/// Request for one fresh, operation-bound operator identity.
///
/// Closed: `deny_unknown_fields`, so a caller cannot smuggle a principal, a
/// fence, a clock, a deadline, or a role/capability claim through it. The only
/// caller-supplied field is *which* operation the identity is for.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorRequestIdentityRequest {
    /// Wire identity; must equal [`OPERATOR_REQUEST_IDENTITY_WIRE_ID`].
    pub wire_id: String,
    /// Wire version; must equal [`OPERATOR_REQUEST_IDENTITY_WIRE_VERSION`].
    pub wire_version: u16,
    /// Exact operation selector the identity is minted for.
    pub operation: String,
}

impl OperatorRequestIdentityRequest {
    fn validate(&self) -> Result<(), TransportError> {
        if self.wire_id != OPERATOR_REQUEST_IDENTITY_WIRE_ID
            || self.wire_version != OPERATOR_REQUEST_IDENTITY_WIRE_VERSION
            || !ISSUABLE_OPERATIONS.contains(&self.operation.as_str())
            || self.operation.trim().is_empty()
            || self.operation.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }
}

/// Owner-issued grant of one operation-bound [`RequestIdentity`].
///
/// The observed principal, session, generation, role and capability set, the
/// current State Fence, the lease, and the identity itself are all carried so
/// the consumer can *compare* them against what it independently observed on
/// the same connection instead of trusting a bare identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperatorRequestIdentityGrant {
    /// Wire identity; echoes [`OPERATOR_REQUEST_IDENTITY_WIRE_ID`].
    pub wire_id: String,
    /// Wire version; echoes [`OPERATOR_REQUEST_IDENTITY_WIRE_VERSION`].
    pub wire_version: u16,
    /// Operation selector this grant is bound to.
    pub operation: String,
    /// The issued identity.
    pub request_identity: RequestIdentity,
    /// Kernel-observed instant the identity was issued, in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Absolute expiry of this identity, in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Live Authority Epoch the identity is bound to.
    pub authority_epoch: EpochId,
    /// Live resource generation the identity is bound to.
    pub resource_generation: ResourceGeneration,
    /// Live State Fence the identity is bound to.
    pub state_fence: StateFence,
    /// Operator role this issuer bound, from the broker-owned closed contract.
    pub role: String,
    /// Exact admitted capability set of the issuing session, filtered against
    /// the live policy's allowed set.
    pub capabilities: Vec<String>,
    /// OS-observed SID of the issuing peer, as this owner saw it.
    pub principal_sid: String,
    /// OS-observed logon session of the issuing peer, as this owner saw it.
    pub principal_session: String,
    /// Transport connection this identity is bound to.
    pub connection_id: String,
    /// Transport session epoch this identity is bound to.
    pub session_epoch: u64,
    /// The server-owned session principal binding of the issuing session.
    ///
    /// It is the same value this composition put in the `ServerHello` for this
    /// session, so the consumer compares it against the one it independently
    /// validated instead of trusting a bare peer claim.
    pub session_principal_binding: String,
}

/// One retained issuance, keyed by `(connection_id, operation)`.
#[derive(Clone, Debug)]
struct RetainedOperatorIdentity {
    identity: RequestIdentity,
    expires_at_unix_ms: u64,
}

/// Bounded process-local retained-issuance ledger.
///
/// Process-local by construction: it is reuse evidence for the lifetime of one
/// Kernel process and is never a durable authority record. A Kernel restart
/// cannot revive a historical request id, cancellation id, or idempotency key
/// through it, because every value is minted from a monotonic issuance ordinal.
#[derive(Debug, Default)]
pub struct OperatorIdentityLedger {
    retained: Mutex<BTreeMap<(String, String), RetainedOperatorIdentity>>,
    next_ordinal: std::sync::atomic::AtomicU64,
}

impl OperatorIdentityLedger {
    fn next_ordinal(&self) -> Result<u64, TransportError> {
        let ordinal = self
            .next_ordinal
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Zero is never a valid ordinal for a minted request id, and a wrapped
        // counter would reuse request ids, so both refuse instead of minting.
        if ordinal == 0 || ordinal == u64::MAX {
            return Err(TransportError::SessionFenced);
        }
        Ok(ordinal)
    }
}

/// Collapses every owner-local refusal — a poisoned lock, a malformed peer, a
/// closed-contract violation — into the one typed failure this route reports.
///
/// The cause is deliberately not forwarded: the wire carries no diagnostic
/// channel here, and a reason string would become an oracle on the admission
/// state of a session the caller may not own.
fn fenced<T, E>(result: Result<T, E>) -> Result<T, TransportError> {
    result.map_err(|_error| TransportError::SessionFenced)
}

impl KernelComposition {
    /// Mints one fresh, exact, operation-bound operator request identity for an
    /// already-admitted front-door session.
    ///
    /// This is the missing owner for the public CLI entries: the session is
    /// already authenticated and bound, so the identity can be issued from the
    /// live admission instead of being asserted by the caller. Every gate
    /// fails closed with [`TransportError::SessionFenced`], and no failure
    /// produces an identity.
    pub(crate) fn issue_operator_request_identity(
        &self,
        session: &Session,
        request: &OperatorRequestIdentityRequest,
    ) -> Result<OperatorRequestIdentityGrant, TransportError> {
        request.validate()?;

        // Principal: the OS-observed pipe peer of this admitted session. A
        // session whose peer cannot be proven never receives an identity.
        let PeerObservation {
            sid: principal_sid,
            session: principal_session,
        } = observed_peer(session)?;

        // Session: the transport binding this composition established itself.
        if session.connection_id.trim().is_empty()
            || session.connection_id.chars().any(char::is_control)
            || session.session_epoch == 0
            || !session.accepts(&session.authority_epoch, session.session_epoch)
        {
            return Err(TransportError::SessionFenced);
        }

        // Generation / Authority Epoch / State Fence: re-read live, under the
        // same policy lock the closed gateway reads. A replaced or expired
        // generation fences here, before any identity exists.
        let (state_fence, allowed_capabilities, session_principal_binding) = {
            let policy = fenced(self.front_door_policy.lock())?;
            if !policy
                .module_generation
                .state_fence
                .is_compatible_with(&session.module_generation.state_fence)
            {
                return Err(TransportError::SessionFenced);
            }
            (
                policy.module_generation.state_fence.clone(),
                policy.allowed_capabilities.clone(),
                policy.session_principal_binding.clone(),
            )
        };
        if session_principal_binding.trim().is_empty()
            || session_principal_binding.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }

        // Admission: an identity exists only while this generation is serving.
        if self
            .generation_poison
            .lock()
            .map_err(|_poisoned| TransportError::SessionFenced)?
            .is_some()
            || !matches!(self.service_state(), Ok(super::KernelServiceState::Ready))
        {
            return Err(TransportError::SessionFenced);
        }

        // Role / capability: the session's own admitted set, intersected with
        // the live policy. An empty result grants no capability, and the role
        // is the broker-owned closed operator role, never a caller claim.
        let capabilities = session
            .capabilities
            .iter()
            .filter(|capability| allowed_capabilities.contains(capability))
            .cloned()
            .collect::<Vec<String>>();
        if capabilities.is_empty() {
            return Err(TransportError::SessionFenced);
        }
        let role = eliot_user_broker_core::OPERATOR_ROLE.to_owned();

        let issued_at_unix_ms = unix_ms();
        if issued_at_unix_ms == 0 {
            return Err(TransportError::SessionFenced);
        }
        let expires_at_unix_ms = issued_at_unix_ms
            .checked_add(OPERATOR_REQUEST_IDENTITY_TTL_MS)
            .filter(|expires| *expires > issued_at_unix_ms)
            .ok_or(TransportError::SessionFenced)?;

        // Exact retry of one operation replays its retained identity, so an
        // unknown launch outcome reconciles by operation identity and never
        // becomes a second launch. A different operation always mints fresh.
        let key = (session.connection_id.clone(), request.operation.clone());
        let now_replay = unix_ms();
        let replayed = fenced(self.operator_request_identities.retained.lock())?
            .get(&key)
            .filter(|existing| existing.expires_at_unix_ms > now_replay)
            .map(|existing| existing.identity.clone());
        let request_identity = if let Some(replayed) = replayed {
            replayed
        } else {
            let ordinal = fenced(self.operator_request_identities.next_ordinal())?;
            let minted = fenced(mint_operator_request_identity(
                &role,
                &capabilities,
                &key.0,
                session.session_epoch,
                &request.operation,
                ordinal,
                &state_fence,
                issued_at_unix_ms,
                expires_at_unix_ms,
            ))?;
            let mut retained = fenced(self.operator_request_identities.retained.lock())?;
            if retained.len() >= MAX_RETAINED_OPERATOR_IDENTITIES {
                return Err(TransportError::SessionFenced);
            }
            retained.insert(
                key.clone(),
                RetainedOperatorIdentity {
                    identity: minted.clone(),
                    expires_at_unix_ms,
                },
            );
            minted
        };

        Ok(OperatorRequestIdentityGrant {
            wire_id: OPERATOR_REQUEST_IDENTITY_WIRE_ID.to_owned(),
            wire_version: OPERATOR_REQUEST_IDENTITY_WIRE_VERSION,
            operation: request.operation.clone(),
            request_identity,
            issued_at_unix_ms,
            expires_at_unix_ms,
            authority_epoch: state_fence.authority_epoch.clone(),
            resource_generation: state_fence.resource_generation.clone(),
            state_fence,
            role,
            capabilities,
            principal_sid,
            principal_session,
            connection_id: session.connection_id.clone(),
            session_epoch: session.session_epoch,
            session_principal_binding,
        })
    }

    /// Routes one control-lane operator request-identity request and returns the
    /// owner-issued grant frame.
    ///
    /// The control lane is the only request form that carries no
    /// `request_identity` of its own, which is what makes it the correct
    /// carrier for the request *for* an identity: a `Request`/`Execute` frame
    /// cannot ask for one because it would have to present one.
    pub(crate) fn dispatch_operator_request_identity(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if frame.kind != FrameKind::Control || frame.message_type != MessageType::Challenge {
            return Err(TransportError::SessionFenced);
        }
        // The issuance request carries no correlation identity and no authority
        // of its own. Anything else on this lane is a different contract.
        if frame.request_id.is_some() || frame.request_identity.is_some() {
            return Err(TransportError::SessionFenced);
        }
        if frame.connection_id != session.connection_id
            || frame.protocol_version != session.protocol_version
        {
            return Err(TransportError::SessionFenced);
        }
        let ProtocolPayload::Json(payload) = &frame.payload else {
            return Err(TransportError::SessionFenced);
        };
        let request: OperatorRequestIdentityRequest = serde_json::from_value(payload.clone())
            .map_err(|_error| TransportError::SessionFenced)?;
        let grant = self.issue_operator_request_identity(session, &request)?;
        let reply = super::status_frame(
            session,
            FrameKind::Control,
            MessageType::Ready,
            serde_json::to_value(grant).map_err(|_error| TransportError::SessionFenced)?,
        )?;
        Ok(KernelFrameAction::Reply(reply))
    }
}

/// The OS-observed peer evidence of one admitted session.
struct PeerObservation {
    sid: String,
    session: String,
}

fn observed_peer(session: &Session) -> Result<PeerObservation, TransportError> {
    session.peer.validate()?;
    match &session.peer {
        eliot_ipc::PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } => Ok(PeerObservation {
            sid: user_identity.clone(),
            session: session_identity.clone(),
        }),
        eliot_ipc::PeerIdentity::Unavailable { .. } => Err(TransportError::PeerIdentityUnavailable),
    }
}

/// Builds one operation-bound identity from the values the owner observed.
///
/// Every argument is owner-derived; nothing here reads a caller value except
/// the closed operation selector, and the id/key/cancellation strings are
/// derived here rather than supplied.
fn mint_operator_request_identity(
    role: &str,
    capabilities: &[String],
    connection_id: &str,
    session_epoch: u64,
    operation: &str,
    ordinal: u64,
    state_fence: &StateFence,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<RequestIdentity, TransportError> {
    let request_id = RequestId::new(format!(
        "{OPERATOR_REQUEST_ID_PREFIX}:{connection_id}:{operation}:{ordinal}"
    ))
    .map_err(|_error| TransportError::SessionFenced)?;
    let idempotency_key = format!("{operation}:{connection_id}:{ordinal}");
    let cancellation_id = format!("{idempotency_key}:cancel");
    // The role and the admitted capability set are named in the idempotency
    // key preimage through the request id, so a grant for one role/capability
    // set can never be replayed as a grant for another. They are additionally
    // checked here so a caller-side change to either is a refusal, not a
    // silent re-binding.
    if role.trim().is_empty()
        || role.chars().any(char::is_control)
        || capabilities.is_empty()
        || capabilities.iter().any(|capability| {
            capability.trim().is_empty() || capability.chars().any(char::is_control)
        })
    {
        return Err(TransportError::SessionFenced);
    }
    let observed_at =
        i64::try_from(issued_at_unix_ms).map_err(|_error| TransportError::SessionFenced)?;
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: eliot_contracts::RequestMetadata {
                request_id,
                session_id: Some(
                    SessionId::new(format!("{connection_id}:{session_epoch}"))
                        .map_err(|_error| TransportError::SessionFenced)?,
                ),
                // These two operations are operator-contour reads/admissions,
                // not semantic task work. No task binding is invented for them.
                task_id: None,
                product_id: ProductId::new(OPERATOR_IDENTITY_PRODUCT_ID)
                    .map_err(|_error| TransportError::SessionFenced)?,
                source_id: SourceId::new(OPERATOR_IDENTITY_SOURCE_ID)
                    .map_err(|_error| TransportError::SessionFenced)?,
                state_fence: state_fence.clone(),
                clock: ClockReading {
                    valid_time_ms: Some(observed_at),
                    known_time_ms: Some(observed_at),
                    transaction_sequence: None,
                    monotonic_ns: None,
                },
            },
            state_fence: state_fence.clone(),
        },
        idempotency_key,
        deadline_unix_ms: expires_at_unix_ms,
        cancellation_id,
    };
    identity
        .validate()
        .map_err(|_error| TransportError::SessionFenced)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_ipc::{PeerIdentity, ProcessBinding, SessionState};
    use eliot_kernel_service::{
        HostKernelCandidateBinding, KernelActivationPermit, KernelControlCommand,
        KernelReadyReceipt, KernelService, KernelServiceState,
    };
    use eliot_platform::PlatformHandle;
    use eliot_protocol::{EncodingProfile, ProtocolVersion};
    use eliot_runtime_contracts::{
        HealthVector, RegisteredActivityWakePolicy, ServiceProcessState, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };

    use super::*;
    use crate::{KernelComposition, KernelConfig};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero sequence"),
        )
        .expect("test epoch")
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("test handle")
    }

    fn candidate_binding() -> HostKernelCandidateBinding {
        use eliot_kernel_service::{
            HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostProcessBinding,
            RestartBudget,
        };
        HostKernelCandidateBinding {
            installation_id: handle("installation-4600"),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: test_epoch(1),
            activation_id: handle("activation-4600"),
            artifact_hash: handle("artifact-4600"),
            config_hash: handle("config-4600"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-4600"),
            pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: r"C:\eliot\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-4600".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: r"C:\eliot\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: test_supervision_incarnation(),
            restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    /// The one sealed supervision incarnation this crate's activation contour
    /// requires, built through the real `with_derived_ids` derivation.
    fn test_supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
        SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:operator-identity".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-4600".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-4600".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-4600".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-4600".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-4600".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-4600".to_owned(),
                sequence: 1,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        }
        .with_derived_ids()
        .expect("sealed supervision incarnation")
    }

    /// Brings one `KernelService` through the real activation contour to
    /// `Ready`, the state the issuer admits under.
    fn ready_service() -> KernelService {
        let mut service = KernelService::new([7; 32], 4, 8).expect("kernel service");
        let candidate = candidate_binding();
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("prepare handoff");
        let permit = KernelActivationPermit {
            operation_id: handle("op-4600-activate"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("txn-4600"),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
                .expect("activation nonce"),
        };
        service
            .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .expect("activate");
        let ready = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: service
                .activation_receipt()
                .expect("activation receipt")
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ev-4600")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-4600")],
        };
        service.publish_ready(ready).expect("publish ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        service
    }

    /// One composition with a `Ready` service, ready to admit identities.
    fn ready_composition(tag: &str) -> (KernelComposition, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-operator-identity-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let service = ready_service();
        *kernel.service.lock().expect("service lock") = service;
        assert_eq!(
            kernel.service_state().expect("service state"),
            KernelServiceState::Ready
        );
        (kernel, root)
    }

    /// One admitted front-door session carrying a proven OS peer and the live
    /// policy generation, exactly as `bind_session` establishes it.
    fn admitted_session(kernel: &KernelComposition, connection_id: &str) -> Session {
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        Session {
            connection_id: connection_id.to_owned(),
            protocol_version: ProtocolVersion::CURRENT,
            peer: PeerIdentity::authenticated_for_test(
                ProcessBinding::from_observation(4242, 55, r"C:\eliot\eliot.exe")
                    .expect("process binding"),
                "S-1-5-18".to_owned(),
                "0".to_owned(),
            )
            .expect("authenticated peer"),
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
            module_generation: policy.module_generation.clone(),
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: policy.allowed_effects.clone(),
            session_epoch: 1,
            state: SessionState::Open,
        }
    }

    fn request_for(operation: &str) -> OperatorRequestIdentityRequest {
        OperatorRequestIdentityRequest {
            wire_id: OPERATOR_REQUEST_IDENTITY_WIRE_ID.to_owned(),
            wire_version: OPERATOR_REQUEST_IDENTITY_WIRE_VERSION,
            operation: operation.to_owned(),
        }
    }

    /// Builds the exact control-lane issuance frame the CLI client sends.
    fn issuance_request_frame(connection_id: &str, operation: &str) -> Frame {
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.to_owned(),
            request_id: None,
            kind: FrameKind::Control,
            message_type: MessageType::Challenge,
            request_identity: None,
            payload: ProtocolPayload::Json(
                serde_json::to_value(request_for(operation)).expect("request encodes"),
            ),
            trace_context: std::collections::BTreeMap::new(),
        }
    }

    /// The positive case for each public entry: `eliot ui` and
    /// `eliot controlboard status` each reach a real owner-issued identity
    /// through the closed front-door dispatch, and that identity reaches the
    /// wire it is then sent on.
    #[test]
    fn public_operator_entries_receive_owner_issued_operation_identities() {
        for (operation, code) in [
            ("operator.launch", "eliot ui"),
            ("controlboard.status", "eliot controlboard status"),
        ] {
            let (kernel, root) = ready_composition(operation);
            let session = admitted_session(&kernel, &format!("cli-{operation}"));
            let action = kernel
                .dispatch_frame(
                    &session,
                    &issuance_request_frame(&session.connection_id, operation),
                )
                .expect("issuance request is admitted");
            let KernelFrameAction::Reply(reply) = action else {
                panic!("{code}: issuance must answer with the owner grant frame");
            };
            let ProtocolPayload::Json(payload) = &reply.payload else {
                panic!("{code}: grant payload is typed JSON");
            };
            let grant: OperatorRequestIdentityGrant =
                serde_json::from_value(payload.clone()).expect("closed grant decodes");
            assert_eq!(grant.operation, operation, "{code}: bound operation");
            assert_eq!(grant.role, eliot_user_broker_core::OPERATOR_ROLE);
            assert_eq!(grant.principal_sid, "S-1-5-18");
            assert_eq!(grant.connection_id, session.connection_id);
            assert_eq!(grant.session_epoch, session.session_epoch);
            // The identity is bound to the live generation, epoch and fence the
            // owner holds, not to anything the caller supplied.
            let policy_fence = kernel
                .front_door_policy
                .lock()
                .expect("front-door policy")
                .module_generation
                .state_fence
                .clone();
            assert_eq!(grant.state_fence, policy_fence, "{code}: live fence");
            assert!(
                grant
                    .authority_epoch
                    .is_same_authority(&policy_fence.authority_epoch)
            );
            // And the identity is a real EBP frame value the client can carry.
            grant
                .request_identity
                .validate()
                .expect("identity validates");
            let wire = Frame {
                protocol_version: ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: session.connection_id.clone(),
                request_id: Some(grant.request_identity.request.metadata.request_id.clone()),
                kind: FrameKind::Request,
                message_type: MessageType::Execute,
                request_identity: Some(grant.request_identity.clone()),
                payload: ProtocolPayload::Json(serde_json::json!({"operation": operation})),
                trace_context: std::collections::BTreeMap::new(),
            };
            wire.validate().expect("identity reaches the wire frame");
            let _ = std::fs::remove_dir_all(root);
        }
    }

    /// No-admission: an identity exists only while this generation is serving
    /// and the session is admitted. A non-`Ready` composition and an
    /// unproven peer are both refusals, and neither yields an identity.
    #[test]
    fn operator_identity_is_refused_without_admission() {
        let (kernel, root) = ready_composition("no-admission");
        let session = admitted_session(&kernel, "cli-no-admission");
        *kernel.service.lock().expect("service lock") =
            KernelService::new([7; 32], 4, 8).expect("kernel service");
        assert_ne!(
            kernel.service_state().expect("service state"),
            KernelServiceState::Ready
        );
        assert!(matches!(
            kernel.issue_operator_request_identity(&session, &request_for("operator.launch")),
            Err(TransportError::SessionFenced)
        ));

        *kernel.service.lock().expect("service lock") = ready_service();
        let mut unproven = session.clone();
        unproven.peer = PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        };
        assert!(matches!(
            kernel.issue_operator_request_identity(&unproven, &request_for("operator.launch")),
            Err(TransportError::PeerIdentityUnavailable)
        ));
        assert!(
            kernel
                .operator_request_identities
                .retained
                .lock()
                .expect("retained ledger")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Wrong session and wrong generation: a session that is not this
    /// composition's, or one bound to a replaced generation, never receives an
    /// identity.
    #[test]
    fn operator_identity_is_refused_for_a_foreign_or_replaced_session() {
        let (kernel, root) = ready_composition("wrong-session");
        let session = admitted_session(&kernel, "cli-wrong-session");

        let mut replaced = session.clone();
        replaced.module_generation.state_fence.resource_generation = ResourceGeneration::new(
            session
                .module_generation
                .state_fence
                .resource_generation
                .value()
                + 1,
        )
        .expect("next generation");
        assert!(matches!(
            kernel.issue_operator_request_identity(&replaced, &request_for("operator.launch")),
            Err(TransportError::SessionFenced)
        ));

        let mut foreign = session.clone();
        foreign.connection_id = "some-other-connection".to_owned();
        let frame = issuance_request_frame("some-other-connection", "operator.launch");
        assert!(matches!(
            kernel.dispatch_operator_request_identity(&foreign, &frame),
            Err(TransportError::SessionFenced)
        ));
        assert!(
            kernel
                .operator_request_identities
                .retained
                .lock()
                .expect("retained ledger")
                .is_empty()
        );

        // A request frame on this lane would have to present an identity, so it
        // can never be the issuance request and is refused as a contract error.
        let mut execute = issuance_request_frame(&session.connection_id, "operator.launch");
        execute.kind = FrameKind::Request;
        execute.message_type = MessageType::Execute;
        assert!(matches!(
            kernel.dispatch_operator_request_identity(&session, &execute),
            Err(TransportError::SessionFenced)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    /// Reuse and consecutive distinct identities: an exact retry replays the
    /// retained identity, so a lost launch response reconciles without a second
    /// launch, while a different operation always mints a distinct one that can
    /// never be replayed for the first.
    #[test]
    fn operator_identities_are_distinct_per_operation_and_replayed_only_on_exact_retry() {
        let (kernel, root) = ready_composition("distinct");
        let session = admitted_session(&kernel, "cli-distinct");

        let launch = kernel
            .issue_operator_request_identity(&session, &request_for("operator.launch"))
            .expect("launch identity admitted");
        let launch_retry = kernel
            .issue_operator_request_identity(&session, &request_for("operator.launch"))
            .expect("exact retry replays the retained identity");
        assert_eq!(
            launch_retry.request_identity, launch.request_identity,
            "an exact retry of one operation must not mint a second identity"
        );

        let status = kernel
            .issue_operator_request_identity(&session, &request_for("controlboard.status"))
            .expect("status identity admitted");
        assert_ne!(
            status.request_identity.request.metadata.request_id,
            launch.request_identity.request.metadata.request_id,
            "two operations never share a request id"
        );
        assert_ne!(
            status.request_identity.idempotency_key, launch.request_identity.idempotency_key,
            "two operations never share an idempotency key"
        );
        assert_ne!(
            status.request_identity.cancellation_id, launch.request_identity.cancellation_id,
            "two operations never share a cancellation id"
        );
        // The one-use handoff is the ledger itself: it retains one identity per
        // (session, operation), so neither operation can ever be answered with
        // the other's identity.
        let retained = kernel
            .operator_request_identities
            .retained
            .lock()
            .expect("retained ledger");
        assert_eq!(retained.len(), 2, "one retained identity per operation");
        assert_eq!(
            retained[&(session.connection_id.clone(), "operator.launch".to_owned())].identity,
            launch.request_identity
        );
        assert_eq!(
            retained[&(
                session.connection_id.clone(),
                "controlboard.status".to_owned()
            )]
                .identity,
            status.request_identity
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
