//! Original AuthorityOwner admission for one closed Git source-snapshot P-03
//! command. This reuses the current GrantGraph and EffectAuthorizer; it never
//! widens a grant and it never borrows source-READ authority for process use.

use eliot_authority::{
    ActionContract, ActionLease, AuthorizedEffect, ImpactClass, LeaseId, LogicalTime,
    PrincipalRef, ReceiptObligation, SnapshotId,
};
use eliot_contracts::{OperationId, RequestId};
use eliot_process::{ActionLeaseRef, ProcessIntent};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    EffectClass, OperationBinding, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding,
};

use super::{CompositionReadiness, GovernorComposition, KernelGenerationPort, ensure_snapshot_fresh};

const GIT_SOURCE_SNAPSHOT_PROFILE: &str = "git-source-snapshot";

const GIT_SOURCE_SNAPSHOT_OPERATIONS: [&str; 7] = [
    "eliot.instrument.git.source-snapshot.resolve-root",
    "eliot.instrument.git.source-snapshot.initialize-index",
    "eliot.instrument.git.source-snapshot.capture-overlay",
    "eliot.instrument.git.source-snapshot.write-tree",
    "eliot.instrument.git.source-snapshot.enumerate-tree",
    "eliot.instrument.git.source-snapshot.read-blob",
    "eliot.instrument.git.source-snapshot.archive-tree",
];

/// Original current-owner ActionContract/ActionLease/AuthorizedEffect and the
/// child identity tied to the exact P-03 intent. This is process data, not a
/// serializable capability; Kernel still validates its own current P-03 owner.
#[derive(Clone, Debug)]
pub struct CurrentSourceGitProcessAdmission {
    identity: RequestIdentity,
    action_contract: ActionContract,
    action_lease: ActionLease,
    authorized_effect: AuthorizedEffect,
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
    /// Issues one original Graph/EffectAuthorizer process action for one
    /// operation from the closed `git-source-snapshot` instrument catalogue.
    /// The caller passes the exact resource target produced by that admitted
    /// profile (source root or isolated index); Graph remains the authority
    /// and rejects any ungranted operation/resource/effect tuple.
    pub fn admit_current_source_git_process(
        &mut self,
        parent_identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        canonical_source_root: &str,
        resolved_executable_path: &str,
        isolated_index_file: &str,
        operation_name: &str,
        resource_ref: &str,
        intent: &ProcessIntent,
    ) -> Result<CurrentSourceGitProcessAdmission, String> {
        parent_identity
            .validate()
            .map_err(|error| error.to_string())?;
        intent.validate().map_err(|error| error.to_string())?;
        if self.readiness != CompositionReadiness::Ready {
            return Err("Governor composition is not ready".to_owned());
        }
        if !GIT_SOURCE_SNAPSHOT_OPERATIONS.contains(&operation_name)
            || canonical_source_root.trim().is_empty()
            || canonical_source_root.chars().any(char::is_control)
            || intent.working_directory() != canonical_source_root
            || resolved_executable_path.trim().is_empty()
            || intent.executable() != resolved_executable_path
            || isolated_index_file.trim().is_empty()
            || intent
                .environment()
                .non_secret()
                .get("GIT_INDEX_FILE")
                .map(String::as_str)
                != Some(isolated_index_file)
            || resource_ref.trim().is_empty()
            || resource_ref.chars().any(char::is_control)
        {
            return Err("Git source process is outside the closed operation/resource profile".to_owned());
        }

        let fence = self.snapshot.state_fence();
        let metadata = &parent_identity.request.metadata;
        let task_id = metadata
            .task_id
            .as_ref()
            .ok_or_else(|| "Git source process parent has no original Task".to_owned())?;
        let session_id = metadata
            .session_id
            .as_ref()
            .ok_or_else(|| "Git source process parent has no original Session".to_owned())?;
        let work_scope_id = selected.work_scope().binding.scope.scope_ref.as_str();
        if parent_identity.request.state_fence != *fence
            || metadata.state_fence != *fence
            || selected.state_fence() != fence
            || metadata.task_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.task_ref())
            || metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.session_ref())
            || intent.operation_id().as_str() == metadata.request_id.as_str()
        {
            return Err("Git source process parent or child identity differs from the exact current selection".to_owned());
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
        let scope = &current_scope.binding.scope;
        if scope.scope_ref != work_scope_id
            || scope.generation != selected.work_scope().binding.scope.generation
            || current_scope.state_fence != *fence
        {
            return Err("current WorkScope changed since the original source selection".to_owned());
        }
        let task_record = self
            .owners
            .task
            .task(task_id)
            .ok_or_else(|| "current Task owner lacks the selected Task".to_owned())?;
        if !task_record.state.is_active()
            || task_record.state_fence != *fence
            || task_record.revision != selected.task_revision()
        {
            return Err("selected Task is stale or no longer active".to_owned());
        }
        let session_record = self
            .owners
            .session
            .session(session_id)
            .ok_or_else(|| "current Session owner lacks the selected Session".to_owned())?;
        if session_record.status != eliot_session::SessionState::Active
            || session_record.state_fence != *fence
            || session_record.authority_epoch != fence.authority_epoch
            || session_record.expires_at <= parent_identity.deadline_unix_ms
        {
            return Err("selected Session is stale, expired, or not active".to_owned());
        }
        if self.owners.authority.state_fence() != fence {
            return Err("current AuthorityOwner is stale against the Governor fence".to_owned());
        }
        let authority_before = self
            .owners
            .authority
            .snapshot()
            .map_err(|error| error.to_string())?;
        if authority_before.state_fence != *fence || authority_before.grant_graph.revision == 0 {
            return Err("current AuthorityOwner snapshot has a stale fence or zero GrantGraph revision".to_owned());
        }

        let child_request_id = RequestId::new(intent.operation_id().as_str().to_owned())
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

        let work_scope = WorkScopeBinding {
            scope_id: eliot_contracts::WorkScopeId::new(scope.scope_ref.clone())
                .map_err(|error| error.to_string())?,
            product_id: child_metadata.product_id.clone(),
            resource_generation: eliot_contracts::ResourceGeneration::new(scope.generation)
                .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id: task_id.clone(),
            task_revision: eliot_contracts::TaskRevision::new(task_record.revision)
                .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id: session_id.clone(),
            authority_epoch: session_record.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned())
            .map_err(|error| error.to_string())?;
        let now = LogicalTime::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before Unix epoch".to_owned())?
                .as_millis()
                .try_into()
                .map_err(|_| "system clock exceeds the authority time range".to_owned())?,
        );
        let operation_id = OperationId::new(child_request_id.as_str().to_owned())
            .map_err(|error| error.to_string())?;
        let operation = OperationBinding {
            operation_id,
            request_id: child_request_id,
            idempotency_key: child_idempotency.clone(),
            operation_kind: operation_name.to_owned(),
            effect: EffectClass::ExternalEffect,
            state_fence: fence.clone(),
        };
        let payload = serde_json::json!({
            "schema": "eliot.git-source-snapshot-process-action.v1",
            "profile": GIT_SOURCE_SNAPSHOT_PROFILE,
            "operation": operation_name,
            "resource": resource_ref,
            "canonical_source_root": canonical_source_root,
            "resolved_executable_path": resolved_executable_path,
            "isolated_index_file": isolated_index_file,
            "parent_request_identity": parent_identity,
            "child_request_identity": child_identity,
            "process_intent": intent,
            "work_scope_id": scope.scope_ref,
            "task_revision": task_record.revision,
            "authority_fence": fence,
        });
        let payload = String::from_utf8(
            eliot_contracts::canonical_json_bytes(&payload)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let action_contract = ActionContract::new(
            format!("git-source-snapshot:{operation_name}:{}", child_request_id.as_str()),
            task_id.to_string(),
            "Run one closed Git source snapshot command under the current selected WorkScope".to_owned(),
            work_scope.clone(),
            operation_name.to_owned(),
            [payload],
            [resource_ref.to_owned()],
            ImpactClass::Material,
            ["original P-03 process evidence and exact source owner readback".to_owned()],
            "exact selected-source snapshot under current WorkScope and admitted Git profile",
            "eliot.instrument.git.source-snapshot",
            "one finite P-03 Git source snapshot operation through the shared process owner",
            ["owner_binding_stale".to_owned(), "source_tree_changed".to_owned()],
        )
        .map_err(|error| error.to_string())?;
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
        let mut action_lease = capability
            .issue_action_lease(
                LeaseId::new(format!("git-source-snapshot:{}", child_request_id.as_str()))
                    .map_err(|error| error.to_string())?,
                child_idempotency,
                operation_name.clone(),
                resource_ref.to_owned(),
                EffectClass::ExternalEffect,
                vec![ReceiptObligation::ExternalReadback],
            )
            .map_err(|error| error.to_string())?;
        let graph_revision = authority_before.grant_graph.revision;
        let authorized = self
            .owners
            .authority
            .effects
            .compile_effectful_action(
                &action_contract,
                operation,
                operation_name,
                resource_ref.to_owned(),
                "eliot.git-source-snapshot.p03",
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
            || authority_after.grant_graph.revision != graph_revision
        {
            return Err("GrantGraph or AuthorityOwner changed during Git process admission".to_owned());
        }

        Ok(CurrentSourceGitProcessAdmission {
            identity: child_identity,
            action_contract,
            action_lease,
            authorized_effect: authorized,
            graph_revision,
            intent_effect_digest: intent.effect_digest().to_owned(),
        })
    }
}
