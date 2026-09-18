//! Authenticated A-08 command-candidate edge for the zero-model Swarm projection.
//!
//! This module compiles the four operator swarm intents
//! ([`OperatorAction::RefreshSwarmCatalogue`],
//! [`OperatorAction::ReplaceSwarmPolicy`],
//! [`OperatorAction::RequestSwarmLaunch`],
//! [`OperatorAction::CancelSwarmAttempt`]) into candidate-only
//! [`SwarmCommandCandidate`] values following
//! [`ControlBoard::swarm_view`](super::ControlBoard::swarm_view). It performs
//! no provider or model call, persists nothing, refreshes no provider, admits
//! no route, issues no [`StateFence`](super::StateFence), launches or cancels
//! no process, redispatches no work, and completes no task.
//!
//! Authentication order mirrors the read edge: the inert request is validated,
//! access is resolved into provider-owned facts, the caller role is gated to
//! human operators, the caller capability is enforced with
//! [`ResolvedAccess::can`](super::ResolvedAccess::can) before the projection
//! is read, and the envelope is re-validated at the exact
//! `(revision, fence)` pin. Only then is the matching coordinator compiler
//! invoked with plain-data binding (`capability_present` plus scope text; the
//! pure compilers never see [`AccessBinding`](super::AccessBinding)).
//!
//! Every refusal path returns before any compiler call, so a refusal compiles
//! no candidate and performs zero effecting calls: there is no effecting port
//! on this edge at all. Successful output stays candidate-only
//! (`candidate_only` with no dispatch authority and zero execution counters)
//! and carries the immutable canonical digest plus the replay identity owned
//! by [`SwarmCommandCandidate::replay_disposition`]. This edge stores no
//! replay itself.
//!
//! Error mapping (decided once, documented here):
//!
//! - `MissingCapability` maps to [`ControlBoardError::Unauthorized`];
//! - `StaleView` maps to [`ControlBoardError::StaleView`];
//! - `StalePolicy` maps to [`ControlBoardError::StaleView`: a stale pinned
//!   policy revision or digest means the caller must re-read the view and
//!   retry with fresh identities, exactly like a stale view pin;
//! - `UnknownAttempt` maps to [`ControlBoardError::HiddenOrMissingTarget`],
//!   matching the canonical target check for absent targets;
//! - `IdentityConflict` maps to [`ControlBoardError::IdentityConflict`];
//! - `InvalidField` preserves its static field path;
//! - `DuplicateIdentity` and `ModelControl` failures are preserved verbatim as
//!   [`ControlBoardError::Provider`] contract failures.
//!
//! Expected policy revision/digest equality is enforced by the owning
//! coordinator compiler against the exact replacement policy (the single
//! owner of that check); this edge enforces capability, exact view pinning,
//! and visible-attempt existence, then forwards and maps. The command identity
//! is derived deterministically from the exact view revision plus the action
//! bytes, so an identical submission replays to the identical candidate while
//! changed bytes always produce a different identity and digest.
//!
//! Proof ceiling:
//! `AUTHENTICATED_SWARM_COMMAND_CANDIDATE_PACKAGE_PROOF_ONLY`.

use eliot_agent_coordinator::{
    CancelAttemptRequest, LaunchSwarmRequest, RefreshCatalogueRequest,
    ReplacePreferencePolicyRequest, SWARM_CONTROLBOARD_PROJECTION_VERSION,
    SwarmCommandCallerBinding, SwarmCommandCandidate, SwarmCommandCandidateError,
    SwarmProjectionAuthorityCeiling, ZeroModelExecutionCounters, compile_cancel_attempt_candidate,
    compile_launch_swarm_candidate, compile_refresh_catalogue_candidate,
    compile_replace_policy_candidate,
};

use super::{
    ControlBoard, ControlBoardError, OperatorAction, ReadRequest, RequiredProvider, Role,
    SwarmProjectionEnvelope,
};

/// Proof ceiling for the authenticated swarm command-candidate package.
pub const AUTHENTICATED_SWARM_COMMAND_CANDIDATE_PACKAGE_PROOF_ONLY: &str =
    "AUTHENTICATED_SWARM_COMMAND_CANDIDATE_PACKAGE_PROOF_ONLY";

fn human_command_role(role: Role) -> bool {
    matches!(
        role,
        Role::HumanRequester
            | Role::HumanArchitectureOwner
            | Role::HumanSystemOwner
            | Role::HumanWorkScopeOwner
            | Role::HumanApprover
            | Role::HumanRecoveryPrincipal
            | Role::HumanReadOnlyObserver
    )
}

fn validates_as_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn projection_contract_is_closed(
    projection: &eliot_agent_coordinator::SwarmControlBoardProjection,
) -> bool {
    projection.schema_version == SWARM_CONTROLBOARD_PROJECTION_VERSION
        && projection.observed_at_unix_ms != 0
        && projection.execution == ZeroModelExecutionCounters::zero()
        && projection
            .catalogue
            .as_ref()
            .is_none_or(|catalogue| catalogue.query.execution == ZeroModelExecutionCounters::zero())
        && projection.authority_ceiling == SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly
}

/// Re-validates the swarm envelope for command use. This is the
/// `validate_envelope`-equivalent for the command edge: identical checks
/// (owner text, digest shape, fence validity, exact `(revision, fence)`
/// pinning against both the access binding and the caller pin, scope,
/// visibility, privacy, closed contract, source-digest closure) without
/// sharing the read edge's private function.
fn validate_command_envelope(
    envelope: &SwarmProjectionEnvelope,
    request: &ReadRequest,
    access: &super::ResolvedAccess,
) -> Result<(), ControlBoardError> {
    super::text(&envelope.work_scope, "swarm_projection.work_scope")?;
    if !validates_as_lower_sha256(&envelope.source_digest) {
        return Err(ControlBoardError::InvalidField(
            "swarm_projection.source_digest",
        ));
    }
    envelope
        .fence
        .validate()
        .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
    if envelope.revision != access.binding.access_revision
        || envelope.fence != access.binding.access_fence
        || request
            .expected_revision
            .is_some_and(|revision| revision != envelope.revision)
        || request
            .expected_fence
            .as_ref()
            .is_some_and(|fence| fence != &envelope.fence)
    {
        return Err(ControlBoardError::StaleView);
    }
    if envelope.work_scope != access.binding.work_scope
        || !envelope.visibility.permits(access.binding.role)
        || !access.binding.admitted_privacy.contains(&envelope.privacy)
    {
        return Err(ControlBoardError::Unauthorized);
    }
    if !projection_contract_is_closed(&envelope.projection) {
        return Err(ControlBoardError::InvalidField("swarm_projection.contract"));
    }
    if super::swarm_projection_source_digest(envelope)? != envelope.source_digest {
        return Err(ControlBoardError::SwarmSourceDigestMismatch);
    }
    Ok(())
}

fn map_swarm_command_error(error: SwarmCommandCandidateError) -> ControlBoardError {
    match error {
        SwarmCommandCandidateError::MissingCapability => ControlBoardError::Unauthorized,
        SwarmCommandCandidateError::StaleView | SwarmCommandCandidateError::StalePolicy => {
            ControlBoardError::StaleView
        }
        SwarmCommandCandidateError::UnknownAttempt => ControlBoardError::HiddenOrMissingTarget,
        SwarmCommandCandidateError::IdentityConflict => ControlBoardError::IdentityConflict,
        SwarmCommandCandidateError::InvalidField(field) => ControlBoardError::InvalidField(field),
        SwarmCommandCandidateError::DuplicateIdentity(field) => {
            ControlBoardError::Provider(format!("swarm_command_candidate duplicate: {field}"))
        }
        SwarmCommandCandidateError::ModelControl(error) => {
            ControlBoardError::Provider(error.to_string())
        }
    }
}

/// Re-checks the candidate-only posture after compilation: immutable digest
/// closure, no dispatch authority, and zero execution. The compiler already
/// enforces these; this seal keeps the edge's guarantee explicit at the
/// authenticated boundary.
fn seal_candidate(
    candidate: SwarmCommandCandidate,
) -> Result<SwarmCommandCandidate, ControlBoardError> {
    candidate.validate().map_err(map_swarm_command_error)?;
    if !candidate.candidate_only || candidate.dispatch_authority {
        return Err(ControlBoardError::InvalidField("swarm_command.authority"));
    }
    if candidate.execution != ZeroModelExecutionCounters::zero() {
        return Err(ControlBoardError::InvalidField("swarm_command.execution"));
    }
    Ok(candidate)
}

impl ControlBoard {
    /// Compiles one authenticated swarm command candidate against the exact
    /// current projection view.
    ///
    /// Only the four swarm [`OperatorAction`] variants are accepted; any other
    /// action fails closed as [`ControlBoardError::InvalidField`]. The caller
    /// capability is enforced with `ResolvedAccess::can` before the projection
    /// is read, the envelope is pinned at the exact `(revision, fence)` pair,
    /// cancel targets must exist in the visible attempt rows, and expected
    /// policy revision/digest equality is enforced by the owning compiler.
    /// Every refusal returns before any compiler call with zero effecting
    /// calls; success returns a candidate-only value with no effect authority.
    pub fn swarm_command_candidate(
        &mut self,
        request: &ReadRequest,
        action: &OperatorAction,
    ) -> Result<SwarmCommandCandidate, ControlBoardError> {
        request.validate()?;
        action.validate()?;
        let access = self.resolve_access(request)?;
        if !human_command_role(access.binding.role) {
            return Err(ControlBoardError::Unauthorized);
        }
        let capability = match action {
            OperatorAction::RefreshSwarmCatalogue { .. }
            | OperatorAction::ReplaceSwarmPolicy { .. }
            | OperatorAction::RequestSwarmLaunch { .. }
            | OperatorAction::CancelSwarmAttempt { .. } => action.required_capability(),
            _ => return Err(ControlBoardError::InvalidField("action.kind")),
        };
        if !access.can(capability) {
            return Err(ControlBoardError::Unauthorized);
        }
        let envelope = self
            .swarm_projection
            .as_mut()
            .ok_or(ControlBoardError::PlanGap(
                RequiredProvider::SwarmProjection,
            ))?
            .read(request, &access.binding)
            .map_err(|error| {
                ControlBoardError::from_port(RequiredProvider::SwarmProjection, error)
            })?;
        validate_command_envelope(&envelope, request, &access)?;
        // Deterministic command identity bound to the exact view revision plus
        // the action bytes: identical submissions replay identically, changed
        // bytes always change the identity and therefore the digest. This
        // derives a content-bound label; it mints no fence, principal,
        // session, epoch, operation, or ceiling authority.
        let action_hex = super::action_digest(action)?;
        let command_id = format!("swarm-command-{}-{action_hex}", envelope.revision.get());
        let revision_text = envelope.revision.get().to_string();
        let binding = SwarmCommandCallerBinding {
            command_id,
            capability_present: true,
            capability_scope: access.binding.work_scope.clone(),
            view_revision: revision_text.clone(),
            expected_view_revision: revision_text,
            view_fence: envelope.fence.clone(),
            expected_view_fence: envelope.fence.clone(),
            now_unix_ms: envelope.projection.observed_at_unix_ms,
        };
        Self::compile_candidate(&binding, &access.binding.work_scope, &envelope, action)
    }

    /// Dispatches one validated swarm action to its owning coordinator
    /// compiler. Split from [`ControlBoard::swarm_command_candidate`] so each
    /// authentication stage stays independently reviewable.
    fn compile_candidate(
        binding: &SwarmCommandCallerBinding,
        account_scope: &str,
        envelope: &SwarmProjectionEnvelope,
        action: &OperatorAction,
    ) -> Result<SwarmCommandCandidate, ControlBoardError> {
        let account_scope = account_scope.to_owned();
        match action {
            OperatorAction::RefreshSwarmCatalogue { catalogue, reason } => {
                let candidate = compile_refresh_catalogue_candidate(&RefreshCatalogueRequest {
                    binding: binding.clone(),
                    account_scope,
                    catalogue: catalogue.clone(),
                    reason: reason.clone(),
                })
                .map_err(map_swarm_command_error)?;
                seal_candidate(candidate)
            }
            OperatorAction::ReplaceSwarmPolicy {
                policy,
                expected_policy_revision,
                expected_policy_digest,
            } => {
                let candidate = compile_replace_policy_candidate(&ReplacePreferencePolicyRequest {
                    binding: binding.clone(),
                    account_scope,
                    policy: policy.clone(),
                    expected_policy_revision: expected_policy_revision.clone(),
                    expected_policy_digest: expected_policy_digest.clone(),
                })
                .map_err(map_swarm_command_error)?;
                seal_candidate(candidate)
            }
            OperatorAction::RequestSwarmLaunch {
                catalogue,
                policy,
                task_id,
                plan_revision,
                demand,
            } => {
                let candidate = compile_launch_swarm_candidate(&LaunchSwarmRequest {
                    binding: binding.clone(),
                    account_scope,
                    catalogue: catalogue.clone(),
                    policy: policy.clone(),
                    task_id: task_id.clone(),
                    plan_revision: plan_revision.clone(),
                    demand: demand.clone(),
                })
                .map_err(map_swarm_command_error)?;
                seal_candidate(candidate)
            }
            OperatorAction::CancelSwarmAttempt { attempt_id, reason } => {
                let visible_attempts = envelope.projection.attempts.clone();
                let target_id = visible_attempts
                    .iter()
                    .find(|row| row.health.attempt_id.as_str() == attempt_id)
                    .map(|row| row.health.attempt_id.clone());
                let Some(target_id) = target_id else {
                    return Err(ControlBoardError::HiddenOrMissingTarget);
                };
                let candidate = compile_cancel_attempt_candidate(&CancelAttemptRequest {
                    binding: binding.clone(),
                    account_scope,
                    visible_attempts,
                    attempt_id: target_id,
                    reason: reason.clone(),
                })
                .map_err(map_swarm_command_error)?;
                seal_candidate(candidate)
            }
            _ => Err(ControlBoardError::InvalidField("action.kind")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use eliot_agent_coordinator::{
        BillingClass, HumanModelPreferencePolicy, MODEL_CATALOGUE_SCHEMA_VERSION,
        MODEL_PREFERENCE_SCHEMA_VERSION, ModelCatalogueSnapshot, ModelRole, ModelSelector,
        RoleModelPreference, SwarmCommandReplayDisposition, SwarmControlBoardProjection,
        SwarmProjectionGap, SwarmProjectionProvider,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

    use super::*;
    use crate::{AccessBinding, AccessResolverPort, ActionCapability, PortError};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    #[derive(Clone)]
    struct FakeAccess {
        binding: AccessBinding,
    }

    impl AccessResolverPort for FakeAccess {
        fn resolve(&mut self, _request: &ReadRequest) -> Result<AccessBinding, PortError> {
            Ok(self.binding.clone())
        }
    }

    #[derive(Clone)]
    struct CountingSwarm {
        envelope: SwarmProjectionEnvelope,
        reads: Arc<Mutex<usize>>,
    }

    impl super::super::SwarmProjectionPort for CountingSwarm {
        fn read(
            &mut self,
            _request: &ReadRequest,
            _access: &AccessBinding,
        ) -> Result<SwarmProjectionEnvelope, PortError> {
            *self.reads.lock().expect("read count") += 1;
            Ok(self.envelope.clone())
        }
    }

    #[derive(Clone)]
    struct FakeSwarm {
        envelope: SwarmProjectionEnvelope,
    }

    impl super::super::SwarmProjectionPort for FakeSwarm {
        fn read(
            &mut self,
            _request: &ReadRequest,
            _access: &AccessBinding,
        ) -> Result<SwarmProjectionEnvelope, PortError> {
            Ok(self.envelope.clone())
        }
    }

    fn revision() -> super::super::ViewRevision {
        super::super::ViewRevision::new(7).expect("revision")
    }

    fn fence() -> super::super::StateFence {
        super::super::StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn request() -> ReadRequest {
        ReadRequest::new(
            "session",
            "connection",
            "credential",
            "challenge",
            "request",
            4,
        )
        .expect("request")
        .pinned(revision(), fence())
    }

    fn access(role: Role, capabilities: Vec<ActionCapability>) -> FakeAccess {
        FakeAccess {
            binding: AccessBinding {
                principal_id: "principal".to_owned(),
                work_scope: "scope".to_owned(),
                role,
                admitted_privacy: vec![eliot_security_contracts::PrivacyClass::Public],
                capabilities,
                session_id: "session".to_owned(),
                connection_id: "connection".to_owned(),
                credential_binding: "credential".to_owned(),
                challenge: "challenge".to_owned(),
                request_id: "request".to_owned(),
                generation: 4,
                issued_at_unix_ms: 1_000,
                observed_at_unix_ms: 1_100,
                expires_at_unix_ms: 2_000,
                access_revision: revision(),
                access_fence: fence(),
            },
        }
    }

    fn projection() -> SwarmControlBoardProjection {
        SwarmControlBoardProjection {
            schema_version: SWARM_CONTROLBOARD_PROJECTION_VERSION.to_owned(),
            observed_at_unix_ms: 1_050,
            catalogue: None,
            preferences: None,
            attempts: Vec::new(),
            gaps: vec![SwarmProjectionGap::ProviderUnavailable {
                provider: SwarmProjectionProvider::ModelCatalogue,
            }],
            execution: ZeroModelExecutionCounters::zero(),
            authority_ceiling:
                eliot_agent_coordinator::SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly,
        }
    }

    fn envelope() -> SwarmProjectionEnvelope {
        let mut envelope = SwarmProjectionEnvelope {
            revision: revision(),
            fence: fence(),
            work_scope: "scope".to_owned(),
            visibility: super::super::Visibility::Public,
            privacy: eliot_security_contracts::PrivacyClass::Public,
            source_digest: String::new(),
            projection: projection(),
        };
        envelope.source_digest =
            super::super::swarm_projection_source_digest(&envelope).expect("source digest");
        envelope
    }

    fn catalogue() -> ModelCatalogueSnapshot {
        ModelCatalogueSnapshot {
            schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
            snapshot_id: "catalogue-1".to_owned(),
            account_scope: "scope".to_owned(),
            collector_identity: "collector-1".to_owned(),
            observed_at_unix_ms: 900,
            expires_at_unix_ms: 1_100,
            entries: Vec::new(),
        }
    }

    fn policy(revision_text: &str) -> HumanModelPreferencePolicy {
        HumanModelPreferencePolicy {
            schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
            policy_id: "human-model-policy-1".to_owned(),
            revision: revision_text.to_owned(),
            account_scope: "scope".to_owned(),
            roles: vec![RoleModelPreference {
                role: ModelRole::Worker,
                preferred: vec![ModelSelector {
                    host_family: None,
                    provider_id: None,
                    model_id: Some("model-1".to_owned()),
                    model_family: None,
                }],
                denied: Vec::new(),
                allowed_billing: BTreeSet::from([BillingClass::Free]),
                allow_paid_fallback: false,
                allow_degraded_routes: false,
                minimum_context_window: 100_000,
                maximum_cost_class: 10,
                maximum_latency_class: 10,
                required_capabilities: BTreeSet::from(["coding".to_owned()]),
            }],
        }
    }

    fn refresh_action() -> OperatorAction {
        OperatorAction::RefreshSwarmCatalogue {
            catalogue: catalogue(),
            reason: "refresh reason".to_owned(),
        }
    }

    #[test]
    fn missing_capability_and_stale_pin_fail_closed_without_effect() {
        // Missing capability fails before the projection is read: zero reads,
        // zero compiler calls, zero effects.
        let reads = Arc::new(Mutex::new(0));
        let mut denied = ControlBoard::new(
            Some(Box::new(access(Role::HumanRequester, Vec::new()))),
            None,
            None,
        )
        .with_swarm_projection(Box::new(CountingSwarm {
            envelope: envelope(),
            reads: Arc::clone(&reads),
        }));
        assert_eq!(
            denied.swarm_command_candidate(&request(), &refresh_action()),
            Err(ControlBoardError::Unauthorized)
        );
        assert_eq!(*reads.lock().expect("read count"), 0);

        // A stale envelope pin fails closed as StaleView with no candidate and
        // no effecting call; the single projection read is a read, not an effect.
        let stale_reads = Arc::new(Mutex::new(0));
        let mut stale = envelope();
        stale.revision = super::super::ViewRevision::new(8).expect("revision");
        stale.fence = super::super::StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(8).expect("generation"),
        );
        stale.source_digest =
            super::super::swarm_projection_source_digest(&stale).expect("source digest");
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                vec![ActionCapability::RefreshSwarmCatalogue],
            ))),
            None,
            None,
        )
        .with_swarm_projection(Box::new(CountingSwarm {
            envelope: stale,
            reads: Arc::clone(&stale_reads),
        }));
        assert_eq!(
            board.swarm_command_candidate(&request(), &refresh_action()),
            Err(ControlBoardError::StaleView)
        );
        assert_eq!(*stale_reads.lock().expect("read count"), 1);
    }

    #[test]
    fn unknown_attempt_and_stale_policy_fail_closed_candidate_only_and_digest_stable() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                vec![
                    ActionCapability::RefreshSwarmCatalogue,
                    ActionCapability::ReplaceSwarmPolicy,
                    ActionCapability::CancelSwarmAttempt,
                ],
            ))),
            None,
            None,
        )
        .with_swarm_projection(Box::new(FakeSwarm {
            envelope: envelope(),
        }));

        // Unknown attempt: absent from the visible rows, mapped from the
        // compiler's UnknownAttempt to the board's hidden-target refusal.
        let unknown = OperatorAction::CancelSwarmAttempt {
            attempt_id: "missing-attempt".to_owned(),
            reason: "stop it".to_owned(),
        };
        assert_eq!(
            board.swarm_command_candidate(&request(), &unknown),
            Err(ControlBoardError::HiddenOrMissingTarget)
        );

        // Stale expected policy revision: copied from a superseded revision,
        // so it no longer equals the replacement identity.
        let stale_revision = OperatorAction::ReplaceSwarmPolicy {
            policy: policy("policy-rev-7"),
            expected_policy_revision: "policy-rev-6".to_owned(),
            expected_policy_digest: format!("sha256:{}", "0".repeat(64)),
        };
        assert_eq!(
            board.swarm_command_candidate(&request(), &stale_revision),
            Err(ControlBoardError::StaleView)
        );

        // Stale expected policy digest: revision matches but the digest no
        // longer equals the recomputed replacement digest.
        let stale_digest = OperatorAction::ReplaceSwarmPolicy {
            policy: policy("policy-rev-7"),
            expected_policy_revision: "policy-rev-7".to_owned(),
            expected_policy_digest: format!("sha256:{}", "0".repeat(64)),
        };
        assert_eq!(
            board.swarm_command_candidate(&request(), &stale_digest),
            Err(ControlBoardError::StaleView)
        );

        // Candidate-only posture and digest stability on the refresh path:
        // exact inputs replay to the exact digest, changed bytes change it,
        // and no candidate ever carries effect authority.
        let candidate = board
            .swarm_command_candidate(&request(), &refresh_action())
            .expect("refresh candidate");
        assert!(candidate.candidate_only);
        assert!(!candidate.dispatch_authority);
        assert_eq!(candidate.execution, ZeroModelExecutionCounters::zero());
        candidate.validate().expect("candidate validates");
        let replay = board
            .swarm_command_candidate(&request(), &refresh_action())
            .expect("replayed candidate");
        assert_eq!(candidate, replay);
        assert_eq!(candidate.command_digest, replay.command_digest);
        assert_eq!(
            candidate
                .replay_disposition(&replay)
                .expect("replay disposition"),
            SwarmCommandReplayDisposition::ExactReplay
        );
        let changed = OperatorAction::RefreshSwarmCatalogue {
            catalogue: catalogue(),
            reason: "a different reason".to_owned(),
        };
        let other = board
            .swarm_command_candidate(&request(), &changed)
            .expect("changed candidate");
        assert_ne!(candidate.command_digest, other.command_digest);
        assert_eq!(
            other
                .replay_disposition(&candidate)
                .expect("new command disposition"),
            SwarmCommandReplayDisposition::NewCommand
        );
    }
}
