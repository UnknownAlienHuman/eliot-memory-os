//! Original Governor admission for one separate Instrument Registry
//! registration HostRequest. The request payload is closed and digest-bound;
//! current Task, Session, WorkScope and AuthorityOwner state are independently
//! reread before the original GrantGraph and EffectAuthorizer decide.

use eliot_authority::{ActionContract, ImpactClass, LeaseId, LogicalTime, PrincipalRef, ReceiptObligation, SnapshotId};
use eliot_contracts::{OperationId, ResourceGeneration, TaskRevision, WorkScopeId};
use eliot_protocol::{HostRequestEnvelope, HostRequestKind, RequestIdentity, host_request_operation_id};
use eliot_receipts::{EffectClass, OperationBinding, SessionBinding, TaskBinding, WorkScopeBinding};

use super::{CompositionReadiness, GovernorComposition, KernelGenerationPort};
use crate::InstrumentRegistryRegistrationAdmission;

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Issues the sealed original mutation admission used by the registration
    /// owner. This method does not commit or retain the registry itself.
    pub fn admit_instrument_registry_registration(
        &mut self,
        envelope: &HostRequestEnvelope,
        identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        snapshot_json: &str,
    ) -> Result<InstrumentRegistryRegistrationAdmission, String> {
        identity.validate().map_err(|error| error.to_string())?;
        envelope
            .validate_for_admission()
            .map_err(|error| error.to_string())?;
        if self.readiness != CompositionReadiness::Ready {
            return Err("Governor composition is not ready".to_owned());
        }
        let fence = self.snapshot.state_fence();
        let host = &envelope.identity;
        let metadata = &identity.request.metadata;
        if envelope.kind != HostRequestKind::InstrumentRegistryRegistration
            || envelope.state_fence != *fence
            || identity.request.state_fence != *fence
            || metadata.state_fence != *fence
            || host.capability != "instrument_registry.register"
            || host.payload_schema_id
                != eliot_protocol::InstrumentRegistryRegistrationInvocation::PAYLOAD_SCHEMA_ID
            || host.request_id != metadata.request_id
            || host.idempotency_key != identity.idempotency_key
            || host.cancellation_id != identity.cancellation_id
            || host.deadline_unix_ms != identity.deadline_unix_ms
            || host.work_scope_id.as_deref()
                != Some(selected.work_scope().binding.scope.scope_ref.as_str())
            || envelope
                .identity
                .request_id
                .as_str()
                != identity.request.metadata.request_id.as_str()
            || metadata.task_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.task_ref())
            || metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.session_ref())
            || selected.state_fence() != fence
            || snapshot_json.is_empty()
            || snapshot_json.chars().any(char::is_control)
        {
            return Err(
                "Instrument Registry registration does not bind the exact HostRequest, original RequestIdentity, selected owners, and snapshot".to_owned(),
            );
        }

        let current_scope = self
            .owners
            .work_scope
            .as_ref()
            .ok_or_else(|| "current WorkScope owner is unbound".to_owned())?
            .read_current(fence)
            .map_err(|error| error.to_string())?;
        super::ensure_snapshot_fresh(&current_scope, "registration WorkScope is stale")
            .map_err(|error| error.to_string())?;
        if current_scope.state_fence != *fence
            || current_scope.binding.scope.scope_ref
                != selected.work_scope().binding.scope.scope_ref
            || current_scope.binding.scope.generation
                != selected.work_scope().binding.scope.generation
        {
            return Err("registration WorkScope changed since owner selection".to_owned());
        }
        let task_id = metadata
            .task_id
            .clone()
            .ok_or_else(|| "registration RequestIdentity omits Task".to_owned())?;
        let task_record = self
            .owners
            .task
            .task(&task_id)
            .ok_or_else(|| "current Task owner lacks the registration Task".to_owned())?;
        if !task_record.state.is_active()
            || task_record.state_fence != *fence
            || task_record.revision != selected.task_revision()
        {
            return Err("registration Task owner is stale or inactive".to_owned());
        }
        let session_id = metadata
            .session_id
            .clone()
            .ok_or_else(|| "registration RequestIdentity omits Session".to_owned())?;
        let session_record = self
            .owners
            .session
            .session(&session_id)
            .ok_or_else(|| "current Session owner lacks the registration Session".to_owned())?;
        if session_record.status != eliot_session::SessionState::Active
            || session_record.state_fence != *fence
            || session_record.authority_epoch != fence.authority_epoch
            || session_record.expires_at <= identity.deadline_unix_ms
        {
            return Err("registration Session owner is stale, expired, or inactive".to_owned());
        }
        if self.owners.authority.state_fence() != fence {
            return Err("registration AuthorityOwner is stale against the live fence".to_owned());
        }

        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new(current_scope.binding.scope.scope_ref.clone())
                .map_err(|error| error.to_string())?,
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(current_scope.binding.scope.generation)
                .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id,
            task_revision: TaskRevision::new(task_record.revision)
                .map_err(|error| error.to_string())?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id,
            authority_epoch: session_record.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned())
            .map_err(|error| error.to_string())?;
        let operation_id = host_request_operation_id(envelope);
        let operation_name = eliot_governor::INSTRUMENT_REGISTRY_REGISTER_OPERATION;
        let resource_ref = format!("instrument-registry:{}:head", work_scope.scope_id.as_str());
        let now = LogicalTime::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before Unix epoch".to_owned())?
                .as_millis()
                .try_into()
                .map_err(|_| "system clock exceeds authority time range".to_owned())?,
        );
        let operation = OperationBinding {
            operation_id: OperationId::new(operation_id.clone())
                .map_err(|error| error.to_string())?,
            request_id: metadata.request_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            operation_kind: operation_name.to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        };
        let action_payload = eliot_governor::instrument_registry_registration_action_payload(
            identity,
            snapshot_json,
        );
        let action_payload = String::from_utf8(
            eliot_contracts::canonical_json_bytes(&action_payload)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let action_contract = ActionContract::new(
            format!("instrument-registry-register:{operation_id}"),
            task.task_id.to_string(),
            "Register the exact Instrument Registry snapshot under the current owner scope".to_owned(),
            work_scope.clone(),
            operation_name.to_owned(),
            [action_payload],
            [resource_ref.clone()],
            ImpactClass::Material,
            ["canonical_instrument_registry_snapshot_read_back".to_owned()],
            "Instrument Registry snapshot bytes are the exact admitted profile and supply contract".to_owned(),
            "eliot.instrument-registry-registration",
            "commit one canonical Instrument Registry head and verify exact named readback",
            ["owner_binding_stale".to_owned(), "snapshot_payload_changed".to_owned()],
        )
        .map_err(|error| error.to_string())?;
        let snapshot_id = SnapshotId::new(format!("instrument-registry-register:{operation_id}"))
            .map_err(|error| error.to_string())?;
        let capability = self
            .owners
            .authority
            .grants
            .snapshot(
                snapshot_id,
                &holder,
                &work_scope,
                &session,
                now,
            )
            .map_err(|error| error.to_string())?;
        capability
            .validate_context(&work_scope, &session)
            .map_err(|error| error.to_string())?;
        let mut action_lease = capability
            .issue_action_lease(
                LeaseId::new(format!("instrument-registry-register:{operation_id}"))
                    .map_err(|error| error.to_string())?,
                identity.idempotency_key.clone(),
                operation_name,
                resource_ref.clone(),
                EffectClass::ReversibleMutation,
                vec![ReceiptObligation::ExternalReadback],
            )
            .map_err(|error| error.to_string())?;
        let compiled = self
            .owners
            .authority
            .effects
            .compile_effectful_action(
                &action_contract,
                operation,
                operation_name,
                resource_ref,
                "eliot.instrument-registry-registration",
                &mut action_lease,
                &work_scope,
                &session,
                now,
            )
            .map_err(|error| error.to_string())?;
        eliot_governor::admit_instrument_registry_registration(
            &self.owners.authority,
            identity.clone(),
            action_contract,
            compiled.authorized().clone(),
            &action_lease,
            &work_scope,
            &session,
            now,
            snapshot_json.to_owned(),
        )
        .map_err(|error| error.to_string())
    }
}
