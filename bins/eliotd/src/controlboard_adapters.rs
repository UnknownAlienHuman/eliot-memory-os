//! Private Governor-backed `ControlBoard` port adapters.
//!
//! The four adapters translate between the provider-neutral
//! [`ControlBoard`](eliot_controlboard::ControlBoard) ports and one immutable
//! [`ControlBoardGovernorSnapshot`](eliot_governor::ControlBoardGovernorSnapshot)
//! taken from the single [`GovernorComposition`](eliot_governor::GovernorComposition)
//! by [`DaemonComposition::controlboard`](super::DaemonComposition::controlboard).
//! They forward authenticated input and translate typed results only:
//!
//! - No policy, admission, or semantic rules live here. Role, privacy, and
//!   capability resolution stays with the session/authority owner, so
//!   [`resolve`](eliot_controlboard::AccessResolverPort::resolve) validates
//!   the request shape and snapshot pins, then fails closed with a typed
//!   provider gap instead of inventing rights.
//! - The Swarm projection providers (catalogue, preferences) are not admitted
//!   to the Governor composition, so the Swarm read fails closed with a typed
//!   gap after the same currency checks. The zero-model gate stays intact in
//!   `eliot-controlboard`; nothing here populates live execution.
//! - Operator submission admits one exact-view intent against the live
//!   snapshot fence and returns a candidate-only receipt. Acceptance is
//!   transport acknowledgement, never task completion or a canonical write:
//!   there is no commit path in this module.
//! - Action digests, ceilings, capabilities, and targets are enforced by
//!   `ControlBoard` before and after the port call; the adapters enforce the
//!   bindings only the live snapshot can check (revision/fence currency and
//!   the owner-issued identity binding) and echo the board-validated ceilings
//!   without widening them.
//!
//! The adapters perform only in-memory reads over the immutable snapshot and
//! never touch I/O, so they cannot block the single-thread async reactor. The
//! current Kernel binding is observed through the composition snapshot, never
//! through a second client.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_contracts::SessionId;
use eliot_controlboard::{
    AccessBinding, AccessResolverPort, CanonicalState, CanonicalStatePort, CommandDisposition,
    CommandReceipt, CommandRequest, ControlBoard, OperatorCommandPort, PortError,
    ProjectionBinding, ProjectionProvider, ProviderCompleteness, ReadRequest,
    SwarmProjectionEnvelope, SwarmProjectionPort, ViewRevision,
};
use eliot_governor::ControlBoardGovernorSnapshot;

/// Builds one [`ControlBoard`] over a fresh Governor projection snapshot.
///
/// The snapshot is immutable: every port call in the returned board observes
/// the same fence and revision, so a mid-read Governor refresh surfaces as an
/// exact-view mismatch at the next call rather than silent divergence.
pub(crate) fn controlboard_over_snapshot(snapshot: ControlBoardGovernorSnapshot) -> ControlBoard {
    let snapshot = Arc::new(snapshot);
    ControlBoard::new(
        Some(Box::new(GovernorAccessResolver::new(Arc::clone(&snapshot)))),
        Some(Box::new(GovernorCanonicalState::new(Arc::clone(&snapshot)))),
        Some(Box::new(GovernorOperatorCommand::new(Arc::clone(
            &snapshot,
        )))),
    )
    .with_swarm_projection(Box::new(GovernorSwarmProjection::new(snapshot)))
}

/// Rejects bindings that are not current at the snapshot fence and revision.
///
/// A refresh between the access resolution and this call fails closed here
/// instead of serving a cross-fence view.
fn access_currency(
    snapshot: &ControlBoardGovernorSnapshot,
    access: &AccessBinding,
) -> Result<(), PortError> {
    if access.access_revision.get() != snapshot.read_revision
        || access.access_fence != snapshot.fence
    {
        return Err(PortError::Denied);
    }
    Ok(())
}

/// Governor-backed access resolver.
///
/// Performs the real request-shape and snapshot-pin checks, then reports the
/// genuinely missing session-to-access semantic mapping as a typed gap. The
/// Governor session owner carries no `ControlBoard` role, privacy, or
/// capability facts, and this adapter never invents them.
struct GovernorAccessResolver {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
}

impl GovernorAccessResolver {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl AccessResolverPort for GovernorAccessResolver {
    fn resolve(&mut self, request: &ReadRequest) -> Result<AccessBinding, PortError> {
        SessionId::new(&request.session_id)
            .map_err(|error| PortError::Invalid(format!("controlboard session: {error}")))?;
        if request
            .expected_revision
            .is_some_and(|revision| revision.get() != self.snapshot.read_revision)
            || request
                .expected_fence
                .as_ref()
                .is_some_and(|fence| fence != &self.snapshot.fence)
        {
            return Err(PortError::Denied);
        }
        Err(PortError::Unavailable)
    }
}

/// Governor-backed canonical state reader.
///
/// Serves the refresh-consistent snapshot as a valid empty-items view over
/// real G-11/I-12 bindings. Empty data and a missing provider stay distinct:
/// this path succeeds with zero items while genuinely absent providers fail
/// as typed gaps elsewhere.
struct GovernorCanonicalState {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
}

impl GovernorCanonicalState {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl CanonicalStatePort for GovernorCanonicalState {
    fn read(
        &mut self,
        _request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<CanonicalState, PortError> {
        access_currency(&self.snapshot, access)?;
        let revision = ViewRevision::new(self.snapshot.read_revision).map_err(|_| {
            PortError::Invalid("controlboard read revision must be non-zero".to_owned())
        })?;
        let state = CanonicalState {
            revision,
            fence: self.snapshot.fence.clone(),
            completeness: ProviderCompleteness {
                g11_coordination: ProjectionBinding {
                    provider: ProjectionProvider::G11,
                    work_id: "G-11".to_owned(),
                    binding_id: self.snapshot.g11_coordination.binding_id.clone(),
                    binding_revision: revision,
                    binding_fence: self.snapshot.fence.clone(),
                    binding_digest: self.snapshot.g11_coordination.binding_digest.clone(),
                    receipt_ref: self.snapshot.g11_coordination.receipt_ref.clone(),
                },
                i12_report_projection: ProjectionBinding {
                    provider: ProjectionProvider::I12,
                    work_id: "I-12".to_owned(),
                    binding_id: self.snapshot.i12_report.binding_id.clone(),
                    binding_revision: revision,
                    binding_fence: self.snapshot.fence.clone(),
                    binding_digest: self.snapshot.i12_report.binding_digest.clone(),
                    receipt_ref: self.snapshot.i12_report.receipt_ref.clone(),
                },
            },
            items: Vec::new(),
            reviews: Vec::new(),
            provenance: Vec::new(),
        };
        state
            .validate()
            .map_err(|error| PortError::Invalid(format!("governor controlboard state: {error}")))?;
        Ok(state)
    }
}

/// Governor-backed operator command admission.
///
/// Admits one exact-view intent after verifying the owner-issued identity
/// binding against the live snapshot fence. The receipt is candidate-only:
/// it acknowledges admission, never execution, completion, or a canonical
/// write.
struct GovernorOperatorCommand {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
}

impl GovernorOperatorCommand {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl OperatorCommandPort for GovernorOperatorCommand {
    fn submit(&mut self, command: &CommandRequest) -> Result<CommandReceipt, PortError> {
        if command.expected_revision.get() != self.snapshot.read_revision
            || command.expected_fence != self.snapshot.fence
        {
            return Err(PortError::Denied);
        }
        command.identity.validate().map_err(|error| {
            PortError::Invalid(format!("controlboard command identity: {error}"))
        })?;
        if command.identity.request.state_fence != self.snapshot.fence {
            return Err(PortError::Denied);
        }
        let identity_session = command
            .identity
            .request
            .metadata
            .session_id
            .clone()
            .map(SessionId::into_string)
            .unwrap_or_default();
        if identity_session != command.session_id {
            return Err(PortError::Denied);
        }
        Ok(CommandReceipt {
            receipt_ref: format!(
                "controlboard-candidate:{}:{}",
                command.operation_id.as_str(),
                command.action_digest
            ),
            session_id: command.session_id.clone(),
            access_digest: command.access_digest.clone(),
            action_digest: command.action_digest.clone(),
            proof_ceiling: command.proof_ceiling,
            effect_ceiling: command.effect_ceiling,
            disposition: CommandDisposition::Accepted,
            observed_revision: command.expected_revision,
            observed_fence: command.expected_fence.clone(),
        })
    }
}

/// Governor-backed Swarm projection reader.
///
/// Applies the same currency check as the canonical reader, then reports the
/// genuinely absent Swarm projection providers as a typed gap. The zero-model
/// profile is preserved by refusing to populate it, not by synthesizing one.
struct GovernorSwarmProjection {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
}

impl GovernorSwarmProjection {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl SwarmProjectionPort for GovernorSwarmProjection {
    fn read(
        &mut self,
        _request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<SwarmProjectionEnvelope, PortError> {
        access_currency(&self.snapshot, access)?;
        Err(PortError::Unavailable)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use eliot_contracts::{
        AuthorityEpoch, ClockReading, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_controlboard::{
        ActionCapability, ControlBoardError, OperatorAction, PrivacyClass, RequiredProvider, Role,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;

    fn fence() -> StateFence {
        StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn snapshot() -> ControlBoardGovernorSnapshot {
        ControlBoardGovernorSnapshot {
            fence: fence(),
            read_revision: 7,
            coordination_sequence: 3,
            g11_coordination: eliot_governor::ControlBoardOwnerBinding {
                binding_id: "governor-owner:coordination".to_owned(),
                binding_digest: "c".repeat(64),
                receipt_ref: "a".repeat(64),
            },
            i12_report: eliot_governor::ControlBoardOwnerBinding {
                binding_id: "governor-owner:observation".to_owned(),
                binding_digest: "d".repeat(64),
                receipt_ref: "b".repeat(64),
            },
        }
    }

    fn identity_for(session: &str, fence: &StateFence) -> RequestIdentity {
        RequestIdentity {
            request: RequestBinding {
                metadata: RequestMetadata {
                    request_id: RequestId::new("request-1").expect("request id"),
                    session_id: Some(eliot_contracts::SessionId::new(session).expect("session id")),
                    task_id: None,
                    product_id: ProductId::new("product").expect("product id"),
                    source_id: SourceId::new("source").expect("source id"),
                    state_fence: fence.clone(),
                    clock: ClockReading::default(),
                },
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-1".to_owned(),
            deadline_unix_ms: 1_000,
            cancellation_id: "cancel-1".to_owned(),
        }
    }

    fn request_for(session: &str) -> ReadRequest {
        ReadRequest::new(
            session,
            format!("{session}-connection"),
            format!("{session}-credential"),
            format!("{session}-challenge"),
            format!("{session}-request"),
            1,
        )
        .expect("request")
    }

    fn access_for(session: &str, capabilities: &[ActionCapability]) -> AccessBinding {
        access_at(
            session,
            capabilities,
            ViewRevision::new(7).expect("revision"),
            fence(),
        )
    }

    fn access_at(
        session: &str,
        capabilities: &[ActionCapability],
        revision: ViewRevision,
        fence: StateFence,
    ) -> AccessBinding {
        AccessBinding {
            principal_id: format!("{session}-principal"),
            work_scope: "scope".to_owned(),
            role: Role::HumanRequester,
            admitted_privacy: vec![PrivacyClass::Public],
            capabilities: capabilities.to_vec(),
            session_id: session.to_owned(),
            connection_id: format!("{session}-connection"),
            credential_binding: format!("{session}-credential"),
            challenge: format!("{session}-challenge"),
            request_id: format!("{session}-request"),
            generation: 1,
            issued_at_unix_ms: 1_000,
            observed_at_unix_ms: 1_100,
            expires_at_unix_ms: 2_000,
            access_revision: revision,
            access_fence: fence,
        }
    }

    fn command_for(session: &str, action: OperatorAction) -> CommandRequest {
        let fence = fence();
        CommandRequest::new(
            identity_for(session, &fence),
            OperationId::new("operation-1").expect("operation id"),
            ViewRevision::new(7).expect("revision"),
            fence,
            action,
        )
        .expect("command")
    }

    /// Session-keyed test access resolver. It returns exact bindings per
    /// known session and denies unknown ones; it mints no authority of its
    /// own and exists only to let the adapter tests reach the board logic.
    #[derive(Clone)]
    struct SessionKeyedAccess {
        bindings: BTreeMap<String, AccessBinding>,
    }

    impl AccessResolverPort for SessionKeyedAccess {
        fn resolve(&mut self, request: &ReadRequest) -> Result<AccessBinding, PortError> {
            self.bindings
                .get(&request.session_id)
                .cloned()
                .ok_or(PortError::Denied)
        }
    }

    /// Counting test command port. It records invocations and always
    /// accepts with the board-validated ceilings; assertions on the call
    /// count prove rejected commands never reach an effecting port.
    #[derive(Clone)]
    struct CountingCommand {
        calls: Arc<Mutex<usize>>,
    }

    impl OperatorCommandPort for CountingCommand {
        fn submit(&mut self, command: &CommandRequest) -> Result<CommandReceipt, PortError> {
            *self.calls.lock().expect("call count") += 1;
            Ok(CommandReceipt {
                receipt_ref: "receipt-1".to_owned(),
                session_id: command.session_id.clone(),
                access_digest: command.access_digest.clone(),
                action_digest: command.action_digest.clone(),
                proof_ceiling: command.proof_ceiling,
                effect_ceiling: command.effect_ceiling,
                disposition: CommandDisposition::Accepted,
                observed_revision: command.expected_revision,
                observed_fence: command.expected_fence.clone(),
            })
        }
    }

    fn board_with_counting_command(
        sessions: &[&str],
        capabilities: &[ActionCapability],
        calls: Arc<Mutex<usize>>,
    ) -> ControlBoard {
        let bindings = sessions
            .iter()
            .map(|session| ((*session).to_owned(), access_for(session, capabilities)))
            .collect();
        ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::new(snapshot())))),
            Some(Box::new(CountingCommand { calls })),
        )
    }

    #[test]
    fn governor_read_adapter_serves_a_coherent_empty_view() {
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_counting_command(&["session-a"], &[], Arc::clone(&calls));
        let view = board.view(&request_for("session-a")).expect("view");
        assert_eq!(view.revision.get(), 7);
        assert_eq!(view.fence, fence());
        assert!(view.items.is_empty());
        assert!(view.reviews.is_empty());
        assert!(view.provenance.is_empty());
        assert_eq!(*calls.lock().expect("call count"), 0);
    }

    #[test]
    fn admitted_start_query_returns_candidate_only_acceptance() {
        let snapshot = Arc::new(snapshot());
        let bindings = BTreeMap::from([(
            "session-a".to_owned(),
            access_for("session-a", &[ActionCapability::StartQuery]),
        )]);
        let mut board = ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::clone(&snapshot)))),
            Some(Box::new(GovernorOperatorCommand::new(snapshot))),
        );
        let view = board.view(&request_for("session-a")).expect("view");
        assert!(view.items.is_empty());
        let submitted = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        let receipt = board
            .submit(&request_for("session-a"), submitted.clone())
            .expect("receipt");
        assert_eq!(receipt.disposition, CommandDisposition::Accepted);
        assert_eq!(
            receipt.proof_ceiling,
            eliot_receipts::ProofCeiling::Observation
        );
        assert_eq!(receipt.proof_ceiling, submitted.proof_ceiling);
        assert_eq!(
            receipt.effect_ceiling,
            eliot_controlboard::EffectCeiling::CandidateOnly
        );
        assert_eq!(receipt.effect_ceiling, submitted.effect_ceiling);
        assert_eq!(receipt.observed_revision.get(), 7);
        assert_eq!(receipt.observed_fence, fence());
        let view = board.view(&request_for("session-a")).expect("view");
        assert!(view.items.is_empty());
    }

    #[test]
    fn cross_principal_and_stale_commands_invoke_no_effecting_port() {
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_counting_command(
            &["session-a", "session-b"],
            &[ActionCapability::PauseTask, ActionCapability::StartQuery],
            Arc::clone(&calls),
        );
        let foreign = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        assert_eq!(
            board.submit(&request_for("session-b"), foreign),
            Err(ControlBoardError::StaleView)
        );

        let mut replay = request_for("session-a");
        replay.connection_id = "stolen-connection".to_owned();
        assert_eq!(
            board.submit(
                &replay,
                command_for(
                    "session-a",
                    OperatorAction::StartQuery {
                        query_kind: "semantic-search".to_owned(),
                    },
                ),
            ),
            Err(ControlBoardError::Unauthorized)
        );

        let stale_fence = StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
            ResourceGeneration::new(6).expect("generation"),
        );
        let stale = CommandRequest::new(
            identity_for("session-a", &stale_fence),
            OperationId::new("operation-1").expect("operation id"),
            ViewRevision::new(6).expect("revision"),
            stale_fence,
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&request_for("session-a"), stale),
            Err(ControlBoardError::StaleView)
        );

        let mut tampered = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        tampered.action_digest = "0".repeat(64);
        assert_eq!(
            board.submit(&request_for("session-a"), tampered),
            Err(ControlBoardError::ActionBindingMismatch)
        );
        assert_eq!(*calls.lock().expect("call count"), 0);
    }

    #[test]
    fn missing_providers_are_typed_gaps_not_empty_views() {
        let mut board = controlboard_over_snapshot(snapshot());
        assert_eq!(
            board.view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))
        );

        let bindings = BTreeMap::from([("session-a".to_owned(), access_for("session-a", &[]))]);
        let mut board =
            ControlBoard::new(Some(Box::new(SessionKeyedAccess { bindings })), None, None)
                .with_swarm_projection(Box::new(GovernorSwarmProjection::new(
                    Arc::new(snapshot()),
                )));
        assert_eq!(
            board.swarm_view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::SwarmProjection
            ))
        );
    }

    #[test]
    fn stale_live_snapshot_denies_commands_before_effects() {
        let mut churned = snapshot();
        churned.read_revision = 8;
        churned.fence = StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
            ResourceGeneration::new(8).expect("generation"),
        );
        let churned = Arc::new(churned);
        let bindings = BTreeMap::from([(
            "session-a".to_owned(),
            access_at(
                "session-a",
                &[ActionCapability::StartQuery],
                ViewRevision::new(8).expect("revision"),
                churned.fence.clone(),
            ),
        )]);
        let mut board = ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::clone(&churned)))),
            Some(Box::new(GovernorOperatorCommand::new(Arc::new(snapshot())))),
        );
        let churned_command = {
            let fence = churned.fence.clone();
            CommandRequest::new(
                identity_for("session-a", &fence),
                OperationId::new("operation-1").expect("operation id"),
                ViewRevision::new(8).expect("revision"),
                fence,
                OperatorAction::StartQuery {
                    query_kind: "semantic-search".to_owned(),
                },
            )
            .expect("command")
        };
        assert_eq!(
            board.submit(&request_for("session-a"), churned_command),
            Err(ControlBoardError::Unauthorized)
        );
    }
}
