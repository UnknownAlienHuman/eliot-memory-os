//! Original Governor admission for one finite Git child process in a
//! selected-source capture. This uses the live GrantGraph and EffectAuthorizer
//! and requires the exact active ORS reservation already read back by its
//! original store owner.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_authority::{
    ActionContract, ActionLease, AuthorizedEffect, ImpactClass, LeaseId, LogicalTime, PrincipalRef,
    ReceiptObligation, SnapshotId,
};
use eliot_contracts::{OperationId, RequestId, canonical_json_bytes, fences_match_exact};
use eliot_instrument_runner::git_source_snapshot_profile::GitSourceSnapshotProcessProfile;
use eliot_instrument_runner::registry::GIT_SOURCE_SNAPSHOT_PROFILE;
use eliot_ors::{ActiveAdmissionReservation, AdmissionReservationState, StateFenceSnapshot};
use eliot_process::ActionLeaseRef;
use eliot_protocol::{RequestIdentity, SelectedSourceCaptureInvocation};
use eliot_receipts::{
    EffectClass, OperationBinding, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding,
};
use serde_json::json;

use super::{
    CompositionReadiness, GovernorComposition, KernelGenerationPort, ensure_snapshot_fresh,
};

const GIT_PROCESS_EXECUTOR_BOUNDARY: &str = "eliot.git-source-snapshot.p03";

/// One original Governor action authorization bound to a current selected
/// source request and its already-active ORS admission.
///
/// This value is non-Serde and carries the exact ActionContract, ActionLease,
/// AuthorizedEffect, child RequestIdentity and verified active reservation
/// produced or consumed in this original owner stack. It is not a Kernel P-03
/// permit and cannot start a process by itself.
#[derive(Clone, Debug)]
pub struct CurrentSourceGitProcessAdmission {
    identity: RequestIdentity,
    action_contract: ActionContract,
    action_lease: ActionLease,
    authorized_effect: AuthorizedEffect,
    active_reservation: ActiveAdmissionReservation,
    resource_ref: String,
    graph_revision: u64,
    intent_effect_digest: String,
}

impl CurrentSourceGitProcessAdmission {
    pub fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    pub fn action_contract(&self) -> &ActionContract {
        &self.action_contract
    }

    pub fn action_lease(&self) -> &ActionLease {
        &self.action_lease
    }

    pub fn authorized_effect(&self) -> &AuthorizedEffect {
        &self.authorized_effect
    }

    pub fn active_reservation(&self) -> &ActiveAdmissionReservation {
        &self.active_reservation
    }

    pub fn resource_ref(&self) -> &str {
        &self.resource_ref
    }

    pub const fn graph_revision(&self) -> u64 {
        self.graph_revision
    }

    pub fn intent_effect_digest(&self) -> &str {
        &self.intent_effect_digest
    }

    pub fn action_lease_ref(&self) -> Result<ActionLeaseRef, String> {
        ActionLeaseRef::new(self.action_lease.lease_id.as_str().to_owned())
            .map_err(|error| error.to_string())
    }
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Admits one exact typed Git source-snapshot process through the current
    /// owner graph. The profile must be the result of the existing runner
    /// `prepare_current_git_source_snapshot_profile`; all of its values are
    /// rechecked against the closed command and original ProcessIntent here.
    ///
    /// Every Git command keeps its original `ExternalEffect` classification.
    /// A `Read` grant or caller-selected ActionContract cannot be substituted.
    pub fn admit_current_source_git_process(
        &mut self,
        parent_identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        selected_invocation: &SelectedSourceCaptureInvocation,
        active_reservation: &ActiveAdmissionReservation,
        profile: &GitSourceSnapshotProcessProfile<'_>,
    ) -> Result<CurrentSourceGitProcessAdmission, String> {
        parent_identity
            .validate()
            .map_err(|error| error.to_string())?;
        selected_invocation
            .validate()
            .map_err(|error| error.to_string())?;
        profile
            .intent
            .validate()
            .map_err(|error| error.to_string())?;
        if self.readiness != CompositionReadiness::Ready {
            return Err("Governor composition is not ready".to_owned());
        }

        validate_git_profile(profile)?;
        let fence = self.snapshot.state_fence();
        validate_active_reservation(active_reservation, selected, fence)?;

        let metadata = &parent_identity.request.metadata;
        let task_id = metadata
            .task_id
            .as_ref()
            .ok_or_else(|| "selected-source parent has no original Task".to_owned())?;
        let session_id = metadata
            .session_id
            .as_ref()
            .ok_or_else(|| "selected-source parent has no original Session".to_owned())?;
        if !fences_match_exact(&parent_identity.request.state_fence, fence)
            || !fences_match_exact(&metadata.state_fence, fence)
            || !fences_match_exact(selected.state_fence(), fence)
            || metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(selected.task_ref())
            || metadata
                .session_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                != Some(selected.session_ref())
            || profile.intent.operation_id().as_str() == metadata.request_id.as_str()
        {
            return Err(
                "Git child request differs from the exact current selected-source identity"
                    .to_owned(),
            );
        }

        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?
            .as_millis()
            .try_into()
            .map_err(|_| "system clock exceeds the source admission time range".to_owned())?;
        let now = LogicalTime::new(now_ms);
        let now_ms_i64 = i64::try_from(now_ms)
            .map_err(|_| "system clock exceeds the ORS time range".to_owned())?;
        if active_reservation.record().expires_at_ms <= now_ms_i64
            || parent_identity.deadline_unix_ms <= now_ms
        {
            return Err("active source admission or request deadline has expired".to_owned());
        }

        let current_scope = self
            .owners
            .work_scope
            .as_ref()
            .ok_or_else(|| "current WorkScope owner is unbound".to_owned())?
            .read_current(fence)
            .map_err(|error| error.to_string())?;
        ensure_snapshot_fresh(&current_scope, "Git process WorkScope is stale")
            .map_err(|error| error.to_string())?;
        if !fences_match_exact(&current_scope.state_fence, fence)
            || current_scope.binding.scope.scope_ref
                != selected.work_scope().binding.scope.scope_ref
            || current_scope.binding.scope.generation
                != selected.work_scope().binding.scope.generation
        {
            return Err("current WorkScope changed since the selected-source admission".to_owned());
        }

        let current_task = self
            .owners
            .task
            .task(task_id)
            .ok_or_else(|| "current Task owner lacks the selected Task".to_owned())?;
        if !current_task.state.is_active()
            || !fences_match_exact(&current_task.state_fence, fence)
            || current_task.revision != selected.task_revision()
        {
            return Err("selected Task is stale or no longer active".to_owned());
        }
        let current_session = self
            .owners
            .session
            .session(session_id)
            .ok_or_else(|| "current Session owner lacks the selected Session".to_owned())?;
        if current_session.status != eliot_session::SessionState::Active
            || !fences_match_exact(&current_session.state_fence, fence)
            || current_session.authority_epoch != fence.authority_epoch
            || current_session.expires_at <= now.value()
            || current_session.expires_at <= parent_identity.deadline_unix_ms
        {
            return Err("selected Session is stale, expired, or not active".to_owned());
        }
        if self.owners.authority.state_fence() != fence {
            return Err("current AuthorityOwner is stale against the Governor fence".to_owned());
        }

        let current_work = self
            .read_unique_agent_activation_with_selection(now.value())
            .map_err(|error| error.to_string())?;
        let current_projection = &current_work.1;
        if !fences_match_exact(&current_work.0.state_fence, fence)
            || current_projection.work_item.task_id != selected.task_ref()
            || current_projection.work_item.owner_session_id.as_deref()
                != Some(selected.session_ref())
            || current_projection.work_item.lease_id.as_deref()
                != Some(current_projection.lease.lease_id.as_str())
            || current_projection.lease.work_item_id != current_projection.work_item.work_item_id
            || current_projection.lease.holder_session_id != selected.session_ref()
            || !fences_match_exact(&current_projection.lease.state_fence, fence)
            || current_projection.lease.authority_epoch != fence.authority_epoch
            || current_projection.lease.expires_at <= now.value()
            || current_projection.work_item.work_item_id
                != active_reservation.record().work_item_id.as_str()
            || current_projection.session.principal_id != selected.principal_ref()
            || selected.evidence().task_ref != current_projection.work_item.task_id
            || selected.evidence().task_revision != selected.task_revision()
            || selected.evidence().acceptance_digest != selected.acceptance_digest()
            || selected.evidence().work_scope_ref != current_scope.binding.scope.scope_ref
        {
            return Err(
                "current WorkItem/WorkLease no longer matches the active source reservation"
                    .to_owned(),
            );
        }

        let child_request_id = RequestId::new(profile.intent.operation_id().as_str().to_owned())
            .map_err(|error| error.to_string())?;
        let mut child_metadata = metadata.clone();
        child_metadata.request_id = child_request_id.clone();
        let child_idempotency = format!("{}:git-process-effect", child_request_id.as_str());
        let child_identity = RequestIdentity {
            request: RequestBinding {
                metadata: child_metadata.clone(),
                state_fence: fence.clone(),
            },
            idempotency_key: child_idempotency.clone(),
            deadline_unix_ms: parent_identity.deadline_unix_ms,
            cancellation_id: format!("{}:git-process-cancel", child_request_id.as_str()),
        };
        child_identity
            .validate()
            .map_err(|error| error.to_string())?;

        let authority_snapshot = self
            .owners
            .authority
            .snapshot()
            .map_err(|error| error.to_string())?;
        if authority_snapshot.state_fence != *fence || authority_snapshot.grant_graph.revision == 0
        {
            return Err(
                "current GrantGraph snapshot has a stale fence or zero revision".to_owned(),
            );
        }
        let work_scope = WorkScopeBinding {
            scope_id: eliot_contracts::WorkScopeId::new(
                current_scope.binding.scope.scope_ref.clone(),
            )
            .map_err(|error| error.to_string())?,
            product_id: child_metadata.product_id.clone(),
            resource_generation: eliot_contracts::ResourceGeneration::new(
                current_scope.binding.scope.generation,
            )
            .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id: task_id.clone(),
            task_revision: eliot_contracts::TaskRevision::new(current_task.revision)
                .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id: session_id.clone(),
            authority_epoch: current_session.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned())
            .map_err(|error| error.to_string())?;
        let operation_name = profile.command.instrument_id();
        let effect = profile.command.effect();
        if effect != EffectClass::ExternalEffect {
            return Err(
                "Git source snapshot command lost its original ExternalEffect classification"
                    .to_owned(),
            );
        }
        let snapshot_id = SnapshotId::new(format!(
            "git-source-snapshot:{}:{}",
            operation_name,
            child_request_id.as_str()
        ))
        .map_err(|error| error.to_string())?;
        let capability = self
            .owners
            .authority
            .grants
            .snapshot(snapshot_id, &holder, &work_scope, &session, now)
            .map_err(|error| error.to_string())?;
        capability
            .validate_context(&work_scope, &session)
            .map_err(|error| error.to_string())?;
        let resources = capability.supporting_resources(operation_name, effect);
        let resource_ref = resources.into_iter().next().ok_or_else(|| {
            "current GrantGraph has no exact Git ExternalEffect resource".to_owned()
        })?;
        let supporting_path = capability
            .supporting_path(operation_name, &resource_ref, effect)
            .map_err(|error| error.to_string())?;

        let active_record = active_reservation.record();
        let selected_operation = selected_invocation
            .operation
            .canonical_serialization()
            .map_err(|error| error.to_string())?;
        let payload = json!({
            "schema": "eliot.git-source-snapshot-process-action.v2",
            "profile": GIT_SOURCE_SNAPSHOT_PROFILE,
            "operation": operation_name,
            "argv": profile.argv,
            "selected_source_operation": selected_operation,
            "selected_relative_path": selected_invocation.selected_relative_path,
            "selector": selected_invocation.selector,
            "resource_ref": resource_ref,
            "canonical_source_root": profile.resource_targets.source_root,
            "resolved_executable_path": profile.resource_targets.executable_path,
            "resolved_executable_sha256": profile.resolved_executable.content_digest,
            "isolated_index_file": profile.resource_targets.isolated_index_file,
            "provider_instrument": profile.provider.instrument_key(),
            "provider_adapter": profile.provider.adapter,
            "provider_generation": profile.provider.generation,
            "instrument_revision": profile.spec.revision,
            "parent_request_identity": parent_identity,
            "child_request_identity": child_identity,
            "process_intent": profile.intent,
            "active_reservation": active_record,
            "active_reservation_store_receipt": active_reservation.receipt(),
            "canonical_admission_receipt": active_record.canonical_admission_receipt,
            "activation_receipt": active_record.activation_receipt,
            "work_item_id": current_projection.work_item.work_item_id,
            "work_lease_id": current_projection.lease.lease_id,
            "work_scope_id": current_scope.binding.scope.scope_ref,
            "work_scope_binding": work_scope,
            "task_binding": task,
            "session_binding": session,
            "task_revision": current_task.revision,
            "session_id": current_session.session_id,
            "authority_fence": fence,
            "grant_graph_revision": authority_snapshot.grant_graph.revision,
            "supporting_grant_path": supporting_path
                .grant_path
                .iter()
                .map(|grant| grant.as_str())
                .collect::<Vec<_>>(),
        });
        let payload =
            String::from_utf8(canonical_json_bytes(&payload).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let action_contract = ActionContract::new(
            format!(
                "git-source-snapshot:{operation_name}:{}",
                child_request_id.as_str()
            ),
            task_id.to_string(),
            "Run one finite Git source-snapshot command under the current selected WorkScope",
            work_scope.clone(),
            operation_name,
            [payload],
            [resource_ref.clone()],
            ImpactClass::Material,
            ["original P-03 process evidence and exact source owner readback".to_owned()],
            "exact current selected-source snapshot under the admitted Git profile",
            GIT_PROCESS_EXECUTOR_BOUNDARY,
            "one finite Git source-snapshot operation through the shared process owner",
            [
                "owner_binding_stale".to_owned(),
                "source_tree_changed".to_owned(),
            ],
        )
        .map_err(|error| error.to_string())?;
        let operation = OperationBinding {
            operation_id: OperationId::new(child_request_id.as_str().to_owned())
                .map_err(|error| error.to_string())?,
            request_id: child_request_id.clone(),
            idempotency_key: child_idempotency.clone(),
            operation_kind: operation_name.to_owned(),
            effect,
            state_fence: fence.clone(),
        };
        let mut action_lease = capability
            .issue_action_lease(
                LeaseId::new(format!("git-source-snapshot:{}", child_request_id.as_str()))
                    .map_err(|error| error.to_string())?,
                child_idempotency,
                operation_name,
                resource_ref.clone(),
                effect,
                vec![ReceiptObligation::ExternalReadback],
            )
            .map_err(|error| error.to_string())?;
        let authorized_effect = self
            .owners
            .authority
            .effects
            .compile_effectful_action(
                &action_contract,
                operation,
                operation_name,
                resource_ref.clone(),
                GIT_PROCESS_EXECUTOR_BOUNDARY,
                &mut action_lease,
                &work_scope,
                &session,
                now,
            )
            .map_err(|error| error.to_string())?
            .authorized()
            .clone();
        let authority_after = self
            .owners
            .authority
            .snapshot()
            .map_err(|error| error.to_string())?;
        if authority_after.state_fence != *fence
            || authority_after.grant_graph.revision != authority_snapshot.grant_graph.revision
        {
            return Err(
                "GrantGraph or AuthorityOwner changed during Git process admission".to_owned(),
            );
        }

        Ok(CurrentSourceGitProcessAdmission {
            identity: child_identity,
            action_contract,
            action_lease,
            authorized_effect,
            active_reservation: active_reservation.clone(),
            resource_ref,
            graph_revision: authority_snapshot.grant_graph.revision,
            intent_effect_digest: profile.intent.effect_digest().to_owned(),
        })
    }
}

fn validate_active_reservation(
    active: &ActiveAdmissionReservation,
    selected: &crate::TaskSelectionAdmissionBinding,
    current_fence: &eliot_contracts::StateFence,
) -> Result<(), String> {
    let record = active.record();
    let expected_fence =
        StateFenceSnapshot::capture(current_fence, current_fence.authority_epoch.sequence.get())
            .map_err(|error| error.to_string())?;
    record.validate().map_err(|error| error.to_string())?;
    if record.state != AdmissionReservationState::Active
        || record.canonical_admission_receipt.is_none()
        || record.activation_receipt.is_none()
        || record.canonical_admission_receipt == record.activation_receipt
        || record.state_fence != expected_fence
        || record.authority_epoch.current != current_fence.authority_epoch
        || record.work_item_id.as_str().trim().is_empty()
        || active.receipt().record_id().as_str().trim().is_empty()
        || active.receipt().subject_id() != &record.operation_id
        || active.receipt().operation_order() == 0
    {
        return Err("active ORS reservation does not match the current selected-source fence and distinct owner receipts".to_owned());
    }
    if !fences_match_exact(selected.state_fence(), current_fence)
        || selected.evidence().task_ref != selected.task_ref()
        || selected.evidence().work_scope_ref != selected.work_scope().binding.scope.scope_ref
    {
        return Err(
            "TaskSelection evidence is not the current owner-bound source task and WorkScope"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_git_profile(profile: &GitSourceSnapshotProcessProfile<'_>) -> Result<(), String> {
    let command_argv = profile.command.argv().map_err(|error| error.to_string())?;
    let intent = profile.intent;
    let executable = profile.resolved_executable;
    let command = profile.command.instrument_id();
    if profile.effect != EffectClass::ExternalEffect
        || profile.command.effect() != EffectClass::ExternalEffect
        || profile.argv != command_argv
        || intent.argv() != command_argv
        || profile.spec.kind.as_str() != command
        || profile.spec.executable != "git"
        || profile.provider.instrument_key() != command
        || profile.provider.adapter != GIT_SOURCE_SNAPSHOT_PROFILE
        || profile.provider.generation == 0
        || profile
            .provider
            .check_resolved_executable(Some(executable))
            .is_err()
        || intent.executable() != executable.canonical_path
        || intent.executable_sha256() != executable.content_digest
        || intent.working_directory() != profile.canonical_working_directory
        || profile.resource_targets.executable_path != executable.canonical_path
        || profile.resource_targets.source_root != profile.canonical_working_directory
        || profile
            .resource_targets
            .isolated_index_file
            .trim()
            .is_empty()
        || profile
            .resource_targets
            .isolated_index_file
            .chars()
            .any(char::is_control)
        || profile
            .environment
            .non_secret()
            .get("GIT_INDEX_FILE")
            .map(String::as_str)
            != Some(profile.resource_targets.isolated_index_file)
        || intent.environment() != profile.environment
        || profile.instrument_limits != profile.spec.limits
        || profile.stdout_ceiling_bytes == 0
        || profile.stdout_ceiling_bytes > intent.resource_limits().stdout_bytes()
    {
        return Err(
            "current Git process profile is not the exact original closed operation".to_owned(),
        );
    }
    let expected_stdout = profile
        .spec
        .limits
        .max_output_bytes
        .map_or(intent.resource_limits().stdout_bytes(), |instrument| {
            instrument.min(intent.resource_limits().stdout_bytes())
        });
    if profile.stdout_ceiling_bytes != expected_stdout {
        return Err(
            "Git process stdout ceiling differs from the original admitted bounds".to_owned(),
        );
    }
    Ok(())
}
