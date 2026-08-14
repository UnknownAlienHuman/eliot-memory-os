use std::collections::BTreeSet;
use std::error::Error;

use eliot_authority::{
    ActionContract, ActionLease, AuthorityError, AuthoritySet, BreakGlassAuthorization,
    BreakGlassAuthorizationId, BreakGlassState, CapabilityGrant, CapabilityIntroduction,
    EffectAuthorizer, EffectOutcome, EffectReceipt, GrantGraph, GrantId, GrantStatus,
    IntroductionActivationRequest, IntroductionId, IntroductionRevocationRequest,
    IntroductionStatus, LeaseId, LogicalTime, P07AuthorityPort, PrincipalRef, ProposedEffect,
    ReceiptObligation, SnapshotId, UnavailableP07AuthorityPort,
};
use eliot_contracts::{
    AuthorityEpoch, ContractId, OperationId, ProductId, RequestId, ResourceGeneration, SessionId,
    StateFence,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, SessionBinding,
    WorkScopeBinding, WorkScopeId,
};
use eliot_security_contracts::EffectCeiling;

type TestResult = Result<(), Box<dyn Error>>;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn bindings(
    epoch: u64,
    generation: u64,
) -> Result<(WorkScopeBinding, SessionBinding, AuthorityBinding), Box<dyn Error>> {
    let authority_epoch = AuthorityEpoch::new(epoch)?;
    let state_fence = StateFence::new(authority_epoch, ResourceGeneration::new(generation)?);
    Ok((
        WorkScopeBinding {
            scope_id: WorkScopeId::new("scope:test")?,
            product_id: ProductId::new("product:test")?,
            resource_generation: ResourceGeneration::new(generation)?,
            state_fence: state_fence.clone(),
        },
        SessionBinding {
            session_id: SessionId::new("session:test")?,
            authority_epoch,
            state_fence: state_fence.clone(),
        },
        AuthorityBinding {
            authority_id: ContractId::new("authority:test")?,
            authority_owner: "G-01".to_owned(),
            authority_epoch,
            state_fence,
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        },
    ))
}

fn authority(
    operations: &[&str],
    resources: &[&str],
    effect: EffectClass,
) -> Result<AuthoritySet, AuthorityError> {
    AuthoritySet::new(
        operations.iter().map(|value| (*value).to_owned()),
        resources.iter().map(|value| (*value).to_owned()),
        effect,
    )
}

#[allow(clippy::too_many_arguments)]
fn grant(
    id: &str,
    parent: Option<&str>,
    issuer: &str,
    holder: &str,
    authority: AuthoritySet,
    binding: AuthorityBinding,
    expiry: u64,
    max_uses: u32,
) -> Result<CapabilityGrant, AuthorityError> {
    Ok(CapabilityGrant {
        grant_id: GrantId::new(id)?,
        parent_grant_id: parent.map(GrantId::new).transpose()?,
        authority_root_ref: "root:test".to_owned(),
        issuer: PrincipalRef::new(issuer)?,
        holder: PrincipalRef::new(holder)?,
        authority,
        inherited_source_ceiling: None,
        binding,
        issued_at: LogicalTime::new(1),
        expires_at: LogicalTime::new(expiry),
        max_uses,
        status: GrantStatus::Active,
    })
}

fn operation(
    id: &str,
    key: &str,
    effect: EffectClass,
    fence: StateFence,
) -> Result<OperationBinding, Box<dyn Error>> {
    Ok(OperationBinding {
        operation_id: OperationId::new(id)?,
        request_id: RequestId::new(format!("request:{id}"))?,
        idempotency_key: key.to_owned(),
        operation_kind: "test.effect".to_owned(),
        effect,
        state_fence: fence,
    })
}

#[test]
fn cycles_are_rejected_before_any_path_can_be_effective() -> TestResult {
    let (_, _, binding) = bindings(1, 1)?;
    let grants = [
        grant(
            "grant:a",
            Some("grant:b"),
            "principal:b",
            "principal:a",
            authority(&["read"], &["a"], EffectClass::Read)?,
            binding.clone(),
            10,
            1,
        )?,
        grant(
            "grant:b",
            Some("grant:a"),
            "principal:a",
            "principal:b",
            authority(&["read"], &["b"], EffectClass::Read)?,
            binding,
            10,
            1,
        )?,
    ];
    let result = GrantGraph::from_grants(grants, 1);
    assert!(matches!(result, Err(AuthorityError::GrantCycle(_))));
    Ok(())
}

#[test]
fn narrowing_is_strict_and_source_ceiling_is_fail_closed() -> TestResult {
    let (_, _, binding) = bindings(1, 1)?;
    let root = grant(
        "grant:root",
        None,
        "principal:root",
        "principal:holder",
        authority(
            &["read", "write"],
            &["repo", "network"],
            EffectClass::ExternalEffect,
        )?,
        binding.clone(),
        20,
        4,
    )?;
    let widened = grant(
        "grant:widened",
        Some("grant:root"),
        "principal:holder",
        "principal:child",
        authority(
            &["read", "write", "admin"],
            &["repo"],
            EffectClass::ExternalEffect,
        )?,
        binding.clone(),
        20,
        4,
    )?;
    assert!(matches!(
        GrantGraph::from_grants([root.clone(), widened], 1),
        Err(AuthorityError::GrantNotNarrower(_))
    ));

    let mut source_limited = root;
    source_limited.inherited_source_ceiling = Some(EffectCeiling::NoExternalEffect);
    assert_eq!(
        source_limited.validate_local(),
        Err(AuthorityError::EffectCeilingExceeded)
    );
    Ok(())
}

#[test]
fn revocation_preserves_only_a_real_alternate_path() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let holder = PrincipalRef::new("principal:holder")?;
    let first = grant(
        "grant:first",
        None,
        "principal:root-a",
        holder.as_str(),
        authority(&["read"], &["repo"], EffectClass::Read)?,
        binding.clone(),
        20,
        4,
    )?;
    let second = grant(
        "grant:second",
        None,
        "principal:root-b",
        holder.as_str(),
        authority(&["read"], &["repo"], EffectClass::Read)?,
        binding,
        20,
        4,
    )?;
    let mut graph = GrantGraph::from_grants([first, second], 1)?;
    let before = graph.snapshot(
        SnapshotId::new("snapshot:before")?,
        &holder,
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    assert_eq!(before.paths.len(), 2);
    graph.revoke(&GrantId::new("grant:first")?)?;
    let after = graph.snapshot(
        SnapshotId::new("snapshot:after")?,
        &holder,
        &scope,
        &session,
        LogicalTime::new(3),
    )?;
    assert_eq!(after.paths.len(), 1);
    assert!(after.allows("read", "repo", EffectClass::Read));
    Ok(())
}

#[test]
fn introduction_becomes_stale_after_supporting_revocation() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let holder = PrincipalRef::new("principal:holder")?;
    let root = grant(
        "grant:intro",
        None,
        "principal:root",
        holder.as_str(),
        authority(&["read"], &["repo"], EffectClass::Read)?,
        binding,
        20,
        2,
    )?;
    let alternate = grant(
        "grant:intro-alternate",
        None,
        "principal:root-2",
        holder.as_str(),
        authority(&["read"], &["repo"], EffectClass::Read)?,
        root.binding.clone(),
        20,
        2,
    )?;
    let mut graph = GrantGraph::from_grants([root, alternate], 1)?;
    let snapshot = graph.snapshot(
        SnapshotId::new("snapshot:intro")?,
        &holder,
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    let mut introduction = CapabilityIntroduction::compile(
        IntroductionId::new("introduction:1")?,
        holder.clone(),
        [GrantId::new("grant:intro")?],
        "repo",
        "facet:read",
        authority(&["read"], &["repo"], EffectClass::Read)?,
        &snapshot,
        LogicalTime::new(10),
        2,
    )?;
    graph.revoke(&GrantId::new("grant:intro")?)?;
    let alternate_snapshot = graph.snapshot(
        SnapshotId::new("snapshot:revoked")?,
        &holder,
        &scope,
        &session,
        LogicalTime::new(3),
    )?;
    assert!(matches!(
        introduction.authorize_call(
            "read",
            "repo",
            EffectClass::Read,
            &alternate_snapshot,
            LogicalTime::new(3),
        ),
        Err(AuthorityError::GrantRevoked(_))
    ));
    assert_eq!(introduction.status, IntroductionStatus::Stale);
    Ok(())
}

#[test]
fn stale_fence_epoch_expiry_and_use_budget_deny() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let (stale_scope, stale_session, _) = bindings(2, 2)?;
    let mut lease = ActionLease::new(
        LeaseId::new("lease:1")?,
        PrincipalRef::new("principal:holder")?,
        "idem:1",
        authority(&["write"], &["repo"], EffectClass::ReversibleMutation)?,
        binding,
        scope.clone(),
        session.clone(),
        LogicalTime::new(5),
        1,
        vec![ReceiptObligation::CanonicalEffectReceipt],
    )?;
    let proposed = ProposedEffect::new(
        "action:1",
        operation(
            "operation:1",
            "idem:1",
            EffectClass::ReversibleMutation,
            scope.state_fence.clone(),
        )?,
        "write",
        "repo",
        digest('a'),
    )?;
    let mut authorizer = EffectAuthorizer::default();
    assert_eq!(
        authorizer.authorize(
            &mut lease,
            proposed.clone(),
            "executor:test",
            &stale_scope,
            &stale_session,
            LogicalTime::new(2),
        ),
        Err(AuthorityError::FenceMismatch)
    );
    assert_eq!(
        authorizer.authorize(
            &mut lease,
            proposed.clone(),
            "executor:test",
            &scope,
            &session,
            LogicalTime::new(5),
        ),
        Err(AuthorityError::Expired)
    );
    let admitted_effect = authorizer.authorize(
        &mut lease,
        proposed,
        "executor:test",
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    assert_eq!(lease.remaining_uses, 0);
    let repeated = authorizer.authorize(
        &mut lease,
        admitted_effect.proposal.clone(),
        "executor:test",
        &scope,
        &session,
        LogicalTime::new(3),
    )?;
    assert_eq!(repeated, admitted_effect);
    Ok(())
}

#[test]
fn duplicate_identity_changed_payload_is_conflict_and_unauthorized_effect_denies() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let mut lease = ActionLease::new(
        LeaseId::new("lease:identity")?,
        PrincipalRef::new("principal:holder")?,
        "idem:same",
        authority(&["write"], &["repo"], EffectClass::ReversibleMutation)?,
        binding,
        scope.clone(),
        session.clone(),
        LogicalTime::new(10),
        2,
        vec![ReceiptObligation::CanonicalEffectReceipt],
    )?;
    let first = ProposedEffect::new(
        "action:identity",
        operation(
            "operation:first",
            "idem:same",
            EffectClass::ReversibleMutation,
            scope.state_fence.clone(),
        )?,
        "write",
        "repo",
        digest('a'),
    )?;
    let changed = ProposedEffect::new(
        "action:identity",
        operation(
            "operation:changed",
            "idem:same",
            EffectClass::ReversibleMutation,
            scope.state_fence.clone(),
        )?,
        "write",
        "repo",
        digest('b'),
    )?;
    let unauthorized = ProposedEffect::new(
        "action:identity",
        operation(
            "operation:unauthorized",
            "idem:same",
            EffectClass::ExternalEffect,
            scope.state_fence.clone(),
        )?,
        "delete",
        "network",
        digest('c'),
    )?;
    let mut authorizer = EffectAuthorizer::default();
    let _authorized = authorizer.authorize(
        &mut lease,
        first,
        "executor:test",
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    assert_eq!(
        authorizer.authorize(
            &mut lease,
            changed,
            "executor:test",
            &scope,
            &session,
            LogicalTime::new(3),
        ),
        Err(AuthorityError::IdentityConflict)
    );

    let mut other_lease = ActionLease::new(
        LeaseId::new("lease:unauthorized")?,
        PrincipalRef::new("principal:holder")?,
        "idem:same",
        authority(&["write"], &["repo"], EffectClass::ReversibleMutation)?,
        lease.authority_binding.clone(),
        scope.clone(),
        session.clone(),
        LogicalTime::new(10),
        1,
        vec![ReceiptObligation::CanonicalEffectReceipt],
    )?;
    let mut isolated_authorizer = EffectAuthorizer::default();
    assert!(matches!(
        isolated_authorizer.authorize(
            &mut other_lease,
            unauthorized,
            "executor:test",
            &scope,
            &session,
            LogicalTime::new(2),
        ),
        Err(AuthorityError::UnauthorizedOperation)
    ));
    Ok(())
}

#[test]
fn unknown_outcome_has_no_fabricated_final_receipt() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let action = ActionContract::new(
        "action:unknown",
        "write an exact reversible test value",
        scope.clone(),
        "authority:test",
        ["repo:before".to_owned()],
        ["repo:write".to_owned()],
        "repo contains the test value",
        "verifier:test",
        "restore repo:before",
        ["unknown outcome".to_owned()],
    )?;
    let mut lease = ActionLease::new(
        LeaseId::new("lease:unknown")?,
        PrincipalRef::new("principal:holder")?,
        "idem:unknown",
        authority(&["write"], &["repo"], EffectClass::ReversibleMutation)?,
        binding,
        scope.clone(),
        session.clone(),
        LogicalTime::new(10),
        1,
        vec![ReceiptObligation::ExternalReadback],
    )?;
    let proposed = ProposedEffect::new(
        action.action_id,
        operation(
            "operation:unknown",
            "idem:unknown",
            EffectClass::ReversibleMutation,
            scope.state_fence.clone(),
        )?,
        "write",
        "repo",
        digest('d'),
    )?;
    let authorized = EffectAuthorizer::default().authorize(
        &mut lease,
        proposed,
        "executor:test",
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    let receipt = EffectReceipt::unknown(authorized, "executor acknowledgement missing")?;
    assert!(matches!(
        receipt.outcome,
        EffectOutcome::UnknownOutcome { .. }
    ));
    assert!(receipt.canonical_receipt.is_none());
    Ok(())
}

#[test]
fn break_glass_is_one_use_and_p07_stays_unavailable() -> TestResult {
    let (scope, session, binding) = bindings(1, 1)?;
    let principal = PrincipalRef::new("principal:recovery")?;
    let exact_operation = operation(
        "operation:recovery",
        "idem:recovery",
        EffectClass::ExternalEffect,
        scope.state_fence.clone(),
    )?;
    let mut authorization = BreakGlassAuthorization::new(
        BreakGlassAuthorizationId::new("break-glass:1")?,
        principal.clone(),
        exact_operation.clone(),
        binding,
        scope.clone(),
        session.clone(),
        LogicalTime::new(10),
        vec![ReceiptObligation::IndependentVerification],
    )?;
    let _permit = authorization.authorize_once(
        &principal,
        &exact_operation,
        &scope,
        &session,
        LogicalTime::new(2),
    )?;
    assert_eq!(authorization.state, BreakGlassState::Consumed);
    assert_eq!(
        authorization.authorize_once(
            &principal,
            &exact_operation,
            &scope,
            &session,
            LogicalTime::new(3),
        ),
        Err(AuthorityError::Consumed)
    );

    let port = UnavailableP07AuthorityPort;
    let activation = eliot_authority::GrantActivationRequest {
        grant_id: GrantId::new("grant:port")?,
        snapshot_id: SnapshotId::new("snapshot:port")?,
        binding: authorization.authority_binding.clone(),
    };
    assert!(port.activate_grant(&activation).is_err());
    let introduction_activation = IntroductionActivationRequest {
        introduction_id: IntroductionId::new("introduction:port")?,
        snapshot_id: SnapshotId::new("snapshot:introduction-port")?,
        binding: authorization.authority_binding.clone(),
    };
    let introduction_revocation = IntroductionRevocationRequest {
        introduction_id: IntroductionId::new("introduction:port")?,
        snapshot_id: SnapshotId::new("snapshot:introduction-port")?,
        binding: authorization.authority_binding.clone(),
    };
    assert!(
        port.activate_introduction(&introduction_activation)
            .is_err()
    );
    assert!(port.revoke_introduction(&introduction_revocation).is_err());
    Ok(())
}

#[test]
fn deterministic_subset_property_never_allows_widening() -> TestResult {
    let universe = ["read", "write", "delete"];
    let parent = authority(&universe, &["repo"], EffectClass::ExternalEffect)?;
    for mask in 1_u8..8 {
        let selected = universe
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, value)| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        let candidate =
            AuthoritySet::new(selected, ["repo".to_owned()], EffectClass::ExternalEffect)?;
        assert!(candidate.is_subset_of(&parent));
        assert_eq!(candidate.is_strict_subset_of(&parent), mask != 7);
    }
    let widened = authority(
        &["read", "write", "delete", "admin"],
        &["repo"],
        EffectClass::ExternalEffect,
    )?;
    assert!(!widened.is_subset_of(&parent));
    Ok(())
}
