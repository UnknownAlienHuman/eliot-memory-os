//! Authenticated A-08 read edge for the zero-model Swarm projection.
//!
//! This module authenticates and fences one immutable A-02 projection. It does
//! not refresh providers, persist preferences, admit routes, launch or cancel
//! processes, redispatch work, mutate task state, or decide finish.

use eliot_agent_coordinator::{
    SWARM_CONTROLBOARD_PROJECTION_VERSION, SwarmControlBoardProjection,
    SwarmProjectionAuthorityCeiling, ZeroModelExecutionCounters,
};
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::{EffectCeiling, PrivacyClass};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    AccessBinding, ControlBoard, ControlBoardError, PortError, ReadRequest, RequiredProvider, Role,
    StateFence, ViewRevision, Visibility,
};

/// Stable schema identity for the authenticated A-08 Swarm view.
pub const AUTHENTICATED_SWARM_VIEW_VERSION: &str = "eliot.controlboard-authenticated-swarm-view/v1";

const MAX_SWARM_PROJECTION_BYTES: usize = 8 * 1024 * 1024;

/// One owner-issued projection envelope. The digest binds every field except
/// the digest itself, including the exact projection bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwarmProjectionEnvelope {
    pub revision: ViewRevision,
    pub fence: StateFence,
    pub work_scope: String,
    pub visibility: Visibility,
    pub privacy: PrivacyClass,
    pub source_digest: String,
    pub projection: SwarmControlBoardProjection,
}

/// Read-only provider boundary for the existing A-02 projection.
pub trait SwarmProjectionPort: Send {
    /// Reads one immutable projection for the already authenticated access.
    fn read(
        &mut self,
        request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<SwarmProjectionEnvelope, PortError>;
}

/// Immutable A-08 view. It contains no command, lease, process, route-admission,
/// task-completion, or finish authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedSwarmView {
    pub schema_version: String,
    pub revision: ViewRevision,
    pub fence: StateFence,
    pub work_scope: String,
    pub access_digest: String,
    pub source_digest: String,
    pub visibility: Visibility,
    pub privacy: PrivacyClass,
    pub projection: SwarmControlBoardProjection,
    pub proof_ceiling: ProofCeiling,
    pub effect_ceiling: EffectCeiling,
}

fn validates_as_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn human_read_role(role: Role) -> bool {
    matches!(
        role,
        Role::HumanRequester
            | Role::HumanArchitectureOwner
            | Role::HumanSystemOwner
            | Role::HumanWorkScopeOwner
            | Role::HumanApprover
            | Role::HumanRecoveryPrincipal
            | Role::HumanReadOnlyObserver
            | Role::ReadOnlyApi
    )
}

fn projection_contract_is_closed(projection: &SwarmControlBoardProjection) -> bool {
    projection.schema_version == SWARM_CONTROLBOARD_PROJECTION_VERSION
        && projection.observed_at_unix_ms != 0
        && projection.execution == ZeroModelExecutionCounters::zero()
        && projection
            .catalogue
            .as_ref()
            .is_none_or(|catalogue| catalogue.query.execution == ZeroModelExecutionCounters::zero())
        && projection.authority_ceiling == SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly
}

/// Computes the canonical source digest used by the projection owner and A-08.
/// Computing this digest grants no authority and performs no external effect.
pub fn swarm_projection_source_digest(
    envelope: &SwarmProjectionEnvelope,
) -> Result<String, ControlBoardError> {
    let bytes = serde_json::to_vec(&(
        AUTHENTICATED_SWARM_VIEW_VERSION,
        envelope.revision,
        &envelope.fence,
        envelope.work_scope.as_str(),
        &envelope.visibility,
        envelope.privacy,
        &envelope.projection,
    ))
    .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
    if bytes.len() > MAX_SWARM_PROJECTION_BYTES {
        return Err(ControlBoardError::InvalidField(
            "swarm_projection.serialized_size",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_envelope(
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
    envelope.fence.validate()?;
    if envelope.fence.revision != envelope.revision
        || envelope.revision != access.binding.access_revision
        || envelope.fence.authority_epoch != access.binding.authority_epoch
        || envelope.fence.fence_id != access.binding.access_fence_id
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
    if swarm_projection_source_digest(envelope)? != envelope.source_digest {
        return Err(ControlBoardError::SwarmSourceDigestMismatch);
    }
    Ok(())
}

impl ControlBoard {
    /// Injects the composition-selected Swarm projection owner.
    #[must_use]
    pub fn with_swarm_projection(mut self, port: Box<dyn SwarmProjectionPort>) -> Self {
        self.swarm_projection = Some(port);
        self
    }

    /// Returns one authenticated, privacy-filtered, exact-fence Swarm read view.
    pub fn swarm_view(
        &mut self,
        request: &ReadRequest,
    ) -> Result<AuthenticatedSwarmView, ControlBoardError> {
        request.validate()?;
        let access = self.resolve_access(request)?;
        if !human_read_role(access.binding.role) {
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
        validate_envelope(&envelope, request, &access)?;
        Ok(AuthenticatedSwarmView {
            schema_version: AUTHENTICATED_SWARM_VIEW_VERSION.to_owned(),
            revision: envelope.revision,
            fence: envelope.fence,
            work_scope: envelope.work_scope,
            access_digest: access.digest,
            source_digest: envelope.source_digest,
            visibility: envelope.visibility,
            privacy: envelope.privacy,
            projection: envelope.projection,
            proof_ceiling: ProofCeiling::Observation,
            effect_ceiling: EffectCeiling::ReadOnly,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use eliot_agent_coordinator::{
        ModelQueryReceipt, SwarmCatalogueProjection, SwarmProjectionGap, SwarmProjectionProvider,
    };

    use super::*;

    use crate::{AccessResolverPort, PLAN_GAP};

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
    struct FakeSwarm {
        envelope: SwarmProjectionEnvelope,
    }

    impl SwarmProjectionPort for FakeSwarm {
        fn read(
            &mut self,
            _request: &ReadRequest,
            _access: &AccessBinding,
        ) -> Result<SwarmProjectionEnvelope, PortError> {
            Ok(self.envelope.clone())
        }
    }

    fn revision() -> ViewRevision {
        ViewRevision::new(7).expect("revision")
    }

    fn fence() -> StateFence {
        StateFence::new(3, revision(), "swarm-fence-7").expect("fence")
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

    fn access(role: Role, privacy: Vec<PrivacyClass>) -> FakeAccess {
        FakeAccess {
            binding: AccessBinding {
                principal_id: "principal".to_owned(),
                work_scope: "scope".to_owned(),
                role,
                admitted_privacy: privacy,
                capabilities: Vec::new(),
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
                authority_epoch: 3,
                access_fence_id: "swarm-fence-7".to_owned(),
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
            authority_ceiling: SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly,
        }
    }

    fn envelope(visibility: Visibility, privacy: PrivacyClass) -> SwarmProjectionEnvelope {
        let mut envelope = SwarmProjectionEnvelope {
            revision: revision(),
            fence: fence(),
            work_scope: "scope".to_owned(),
            visibility,
            privacy,
            source_digest: String::new(),
            projection: projection(),
        };
        envelope.source_digest = swarm_projection_source_digest(&envelope).expect("source digest");
        envelope
    }

    fn board(
        role: Role,
        privacy: Vec<PrivacyClass>,
        envelope: SwarmProjectionEnvelope,
    ) -> ControlBoard {
        ControlBoard::new(Some(Box::new(access(role, privacy))), None, None)
            .with_swarm_projection(Box::new(FakeSwarm { envelope }))
    }

    #[test]
    fn exact_projection_is_exposed_without_semantic_rewrite() {
        let envelope = envelope(Visibility::Public, PrivacyClass::Public);
        let expected = envelope.projection.clone();
        let expected_digest = envelope.source_digest.clone();
        let mut board = board(Role::HumanRequester, vec![PrivacyClass::Public], envelope);
        let view = board.swarm_view(&request()).expect("authenticated view");
        assert_eq!(view.projection, expected);
        assert_eq!(view.source_digest, expected_digest);
        assert_eq!(view.proof_ceiling, ProofCeiling::Observation);
        assert_eq!(view.effect_ceiling, EffectCeiling::ReadOnly);
        assert_eq!(view.schema_version, AUTHENTICATED_SWARM_VIEW_VERSION);
    }

    #[test]
    fn missing_projection_owner_is_a_typed_plan_gap() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanReadOnlyObserver,
                vec![PrivacyClass::Public],
            ))),
            None,
            None,
        );
        assert_eq!(
            board.swarm_view(&request()),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::SwarmProjection,
            ))
        );
        assert_eq!(PLAN_GAP, "PLAN_GAP");
    }

    #[test]
    fn agent_roles_cannot_open_the_human_swarm_view() {
        let mut board = board(
            Role::MainAgent,
            vec![PrivacyClass::Public],
            envelope(Visibility::Public, PrivacyClass::Public),
        );
        assert_eq!(
            board.swarm_view(&request()),
            Err(ControlBoardError::Unauthorized)
        );
    }

    #[test]
    fn visibility_and_privacy_are_both_required() {
        let mut hidden = board(
            Role::HumanRequester,
            vec![PrivacyClass::Public],
            envelope(
                Visibility::RoleScoped(Role::HumanApprover),
                PrivacyClass::Public,
            ),
        );
        assert_eq!(
            hidden.swarm_view(&request()),
            Err(ControlBoardError::Unauthorized)
        );

        let mut private = board(
            Role::HumanRequester,
            vec![PrivacyClass::Public],
            envelope(Visibility::Public, PrivacyClass::Private),
        );
        assert_eq!(
            private.swarm_view(&request()),
            Err(ControlBoardError::Unauthorized)
        );
    }

    #[test]
    fn changed_projection_bytes_fail_the_source_digest() {
        let mut changed = envelope(Visibility::Public, PrivacyClass::Public);
        changed.projection.observed_at_unix_ms += 1;
        let mut board = board(Role::ReadOnlyApi, vec![PrivacyClass::Public], changed);
        assert_eq!(
            board.swarm_view(&request()),
            Err(ControlBoardError::SwarmSourceDigestMismatch)
        );
    }

    #[test]
    fn stale_fence_and_cross_scope_envelopes_fail_closed() {
        let mut stale = envelope(Visibility::Public, PrivacyClass::Public);
        stale.revision = ViewRevision::new(8).expect("revision");
        stale.fence = StateFence::new(3, stale.revision, "swarm-fence-8").expect("fence");
        stale.source_digest = swarm_projection_source_digest(&stale).expect("digest");
        let mut stale_board = board(Role::HumanRequester, vec![PrivacyClass::Public], stale);
        assert_eq!(
            stale_board.swarm_view(&request()),
            Err(ControlBoardError::StaleView)
        );

        let mut other_scope = envelope(Visibility::Public, PrivacyClass::Public);
        other_scope.work_scope = "other-scope".to_owned();
        other_scope.source_digest = swarm_projection_source_digest(&other_scope).expect("digest");
        let mut scope_board = board(
            Role::HumanRequester,
            vec![PrivacyClass::Public],
            other_scope,
        );
        assert_eq!(
            scope_board.swarm_view(&request()),
            Err(ControlBoardError::Unauthorized)
        );
    }

    #[test]
    fn projection_cannot_widen_its_zero_model_authority_ceiling() {
        let mut widened = envelope(Visibility::Public, PrivacyClass::Public);
        widened.projection.execution.model_calls = 1;
        widened.source_digest = swarm_projection_source_digest(&widened).expect("digest");
        let mut board = board(Role::HumanRequester, vec![PrivacyClass::Public], widened);
        assert_eq!(
            board.swarm_view(&request()),
            Err(ControlBoardError::InvalidField("swarm_projection.contract",))
        );
    }

    #[test]
    fn nested_catalogue_query_cannot_widen_zero_model_authority_ceiling() {
        let mut widened = envelope(Visibility::Public, PrivacyClass::Public);
        widened.projection.catalogue = Some(SwarmCatalogueProjection {
            snapshot_id: "snapshot".to_owned(),
            account_scope: "scope".to_owned(),
            collector_identity: "collector".to_owned(),
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            current: true,
            query: ModelQueryReceipt {
                schema_version: eliot_agent_coordinator::MODEL_QUERY_RECEIPT_VERSION.to_owned(),
                query_id: "query".to_owned(),
                catalogue_snapshot_id: "snapshot".to_owned(),
                catalogue_digest: "digest".to_owned(),
                hits: Vec::new(),
                execution: ZeroModelExecutionCounters::zero(),
            },
        });
        widened
            .projection
            .catalogue
            .as_mut()
            .expect("catalogue")
            .query
            .execution
            .model_calls = 1;
        widened.source_digest = swarm_projection_source_digest(&widened).expect("digest");
        let mut board = board(Role::HumanRequester, vec![PrivacyClass::Public], widened);
        assert_eq!(
            board.swarm_view(&request()),
            Err(ControlBoardError::InvalidField("swarm_projection.contract",))
        );
    }
}
