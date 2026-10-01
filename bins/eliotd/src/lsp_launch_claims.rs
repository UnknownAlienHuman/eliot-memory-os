//! Current-owner data used to stage and revalidate one LSP launch reservation.
//!
//! The carrier keeps the exact role payloads in memory alongside the ORS
//! references. It is deliberately not serializable: a later stage/use must
//! rebuild it from the current registry, WorkScope, Coordination, environment,
//! and Authority owners and compare the payloads and references by value.

use eliot_authority::{ActionContract, ActionLease, AuthorizedEffect};
use eliot_contracts::StateFence;
use eliot_instrument_api::InstrumentInvocation;
use eliot_instrument_runner::ResolvedExecutableIdentity;
use eliot_process::{EnvironmentProjection, ProcessIntent, ResourceLimits};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{NamedReadResponse, WriteReceipt};
use eliot_ors::{AdmissionReservationClaimRef, AdmissionReservationClaims, OpaqueLabel};
use serde_json::{Value, json};

use crate::SelectedSourceInstrumentRegistryReadback;
use crate::daemon_kernel_client::CurrentSourceExecutableObservation;
use eliot_governor::PreparedSelectedSourceSnapshotMutation;

/// A non-Serde snapshot of the five role payloads and the exact ORS references
/// derived from their original owners. No reference is accepted without its
/// owner payload, and no role can be refilled from a caller label.
pub(crate) struct LspLaunchClaimSet {
    claims: AdmissionReservationClaims,
    role_payloads: [Value; 5],
    state_fence: StateFence,
    task_id: String,
    work_scope_id: String,
    session_id: String,
    parent_request_id: String,
    registry_revision: u64,
    invocation: InstrumentInvocation,
}

impl LspLaunchClaimSet {
    /// Builds role data only from the current original owners. `actions` is the
    /// complete currently admitted selected-source/launch action set; later
    /// archive publication and W1 observation mutations have separate
    /// original admissions and must not be folded into this set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_current_owners(
        identity: &RequestIdentity,
        selected: &eliot_governor::TaskSelectionAdmissionBinding,
        registry: &SelectedSourceInstrumentRegistryReadback,
        registration_receipt: &WriteReceipt,
        registry_readback: &NamedReadResponse,
        invocation: &InstrumentInvocation,
        executable: &ResolvedExecutableIdentity,
        executable_observation: &CurrentSourceExecutableObservation,
        environment: &EnvironmentProjection,
        process_intent: &ProcessIntent,
        actions: &[ActionContract],
        leases: &[ActionLease],
        authorized_effects: &[AuthorizedEffect],
        process_limits: &ResourceLimits,
    ) -> Result<Self, String> {
        identity.validate().map_err(|error| error.to_string())?;
        if actions.is_empty() || leases.is_empty() || authorized_effects.is_empty() {
            return Err(
                "LSP claims require original currently admitted ActionContracts, ActionLeases, and AuthorizedEffects"
                    .to_owned(),
            );
        }
        if registration_receipt.validate().is_err()
            || registry_readback.validate().is_err()
            || registration_receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || registration_receipt.commit_id.is_none()
            || registration_receipt.state_fence != *selected.state_fence()
            || registry_readback.operation
                != eliot_store_api::NamedReadOperation::GetInstrumentRegistryState
            || registry_readback.state_fence != *selected.state_fence()
            || identity.request.state_fence != *selected.state_fence()
            || identity.request.metadata.state_fence != *selected.state_fence()
            || registry_readback
                .payload
                .get("snapshot_json")
                .and_then(Value::as_str)
                != Some(registry.snapshot_json.as_str())
            || registry_readback
                .payload
                .get("revision")
                .and_then(Value::as_u64)
                != Some(registry.revision)
            || registry_readback
                .payload
                .get("state_fence")
                .and_then(|value| serde_json::from_value::<StateFence>(value.clone()).ok())
                .as_ref()
                != Some(selected.state_fence())
        {
            return Err(
                "LSP resource claim is not joined to the original current Instrument Registry receipt and exact readback"
                    .to_owned(),
            );
        }

        let state_fence = selected.state_fence().clone();
        let task_id = selected.task_ref().to_owned();
        let work_scope_id = selected.work_scope().binding.scope.scope_ref.clone();
        let scope_generation = selected.work_scope().binding.scope.generation;
        let session_id = selected.session_ref().to_owned();
        let registry_revision = registry.revision;
        let active_work = selected.active_work();
        if active_work.session.session_id != session_id
            || active_work.work_item.task_id != task_id
            || active_work.work_item.work_item_id != selected.evidence_ref()
            || active_work.lease.lease_id != selected.selection_source_ref()
            || active_work.session.state_fence != state_fence
            || active_work.work_item.state_fence != state_fence
            || active_work.lease.state_fence != state_fence
            || identity.request.metadata.task_id.as_ref().map(ToString::to_string).as_deref()
                != Some(task_id.as_str())
            || identity.request.metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(session_id.as_str())
            || registry_revision == 0
            || invocation.profile.trim().is_empty()
            || executable.canonical_path.trim().is_empty()
            || executable.content_digest.len() != 64
            || process_intent.executable() != executable.canonical_path
            || process_intent.executable_sha256() != executable.content_digest
            || process_intent.argv() != executable.arguments
            || process_intent.environment() != environment
            || process_intent.resource_limits() != process_limits
            || executable_observation.instrument != invocation.instrument.as_str()
            || executable_observation.canonical_path != executable.canonical_path
            || executable_observation.content_digest != executable.content_digest
            || executable_observation.environment_digest != executable.environment_digest
            || executable_observation.arguments != executable.arguments
            || !executable_observation.native_file_identity.is_object()
            || executable_observation.request_identity.request.metadata.task_id
                != identity.request.metadata.task_id
            || executable_observation.request_identity.request.metadata.session_id
                != identity.request.metadata.session_id
            || executable_observation.request_identity.request.metadata.product_id
                != identity.request.metadata.product_id
            || executable_observation.request_identity.request.metadata.source_id
                != identity.request.metadata.source_id
            || executable_observation.request_identity.request.state_fence != state_fence
            || executable_observation.request_identity.request.metadata.state_fence
                != state_fence
            || executable_observation.request_identity.deadline_unix_ms
                != identity.deadline_unix_ms
            || executable_observation.request_identity.request.metadata.request_id
                == identity.request.metadata.request_id
            || actions.iter().any(|action| {
                action.task_id != task_id
                    || action.work_scope.scope_id.as_str() != work_scope_id
                    || action.work_scope.product_id != identity.request.metadata.product_id
                    || action.work_scope.resource_generation.value() != scope_generation
                    || action.work_scope.state_fence != state_fence
            })
            || leases.iter().any(|lease| {
                lease.work_scope.scope_id.as_str() != work_scope_id
                    || lease.work_scope.product_id != identity.request.metadata.product_id
                    || lease.work_scope.resource_generation.value() != scope_generation
                    || lease.work_scope.state_fence != state_fence
                    || lease.session.session_id.as_str() != session_id
                    || lease.session.state_fence != state_fence
                    || lease.authority_binding.state_fence != state_fence
                    || lease.remaining_uses == 0
                    || lease.expires_at <= eliot_authority::LogicalTime::new(identity.deadline_unix_ms)
            })
            || authorized_effects.iter().any(|effect| {
                effect.proposal.operation.state_fence != state_fence
                    || effect.proposal.operation.request_id != identity.request.metadata.request_id
                    || effect.proposal.operation.idempotency_key != identity.idempotency_key
                    || !leases.iter().any(|lease| {
                        lease.lease_id == effect.lease_id
                            && lease.exact_idempotency_key
                                == effect.proposal.operation.idempotency_key
                            && lease.authority_set.allows(
                                &effect.proposal.operation_name,
                                &effect.proposal.resource_ref,
                                effect.proposal.operation.effect,
                            )
                    })
                    || !actions.iter().any(|action| {
                        action.action_id == effect.proposal.action_id
                            && action.effect_set.contains(&effect.proposal.operation_name)
                            && action.read_set.contains(&effect.proposal.resource_ref)
                            && action.work_scope.state_fence == effect.proposal.operation.state_fence
                    })
            })
        {
            return Err(
                "LSP claims do not share the exact active owner selection, registry revision, profile, executable, and State Fence"
                    .to_owned(),
            );
        }

        let executable_data = json!({
            "canonical_path": executable.canonical_path,
            "content_digest": executable.content_digest,
            "tool_version": executable.tool_version,
            "environment_digest": executable.environment_digest,
            "arguments": executable.arguments,
            "native_file_identity": executable_observation.native_file_identity,
            "observed_request_identity": executable_observation.request_identity,
        });
        let action_data = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("original Authority action records cannot be encoded: {error}"))?;
        let action_owner_ids = actions
            .iter()
            .map(|action| action.action_id.as_str())
            .collect::<Vec<_>>();
        if action_owner_ids
            .iter()
            .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err("LSP effect claim is missing an original Authority action identity".to_owned());
        }
        let lease_owner_data = leases
            .iter()
            .map(|lease| {
                Ok(json!({
                    "lease_id": lease.lease_id.as_str(),
                    "holder": lease.holder.as_str(),
                    "exact_idempotency_key": lease.exact_idempotency_key,
                    "operations": lease.authority_set.operations(),
                    "resources": lease.authority_set.resources(),
                    "max_effect": lease.authority_set.max_effect(),
                    "authority_binding": lease.authority_binding,
                    "work_scope": lease.work_scope,
                    "session": lease.session,
                    "expires_at": lease.expires_at.value(),
                    "remaining_uses": lease.remaining_uses,
                    "receipt_obligations": lease.receipt_obligations,
                }))
            })
            .collect::<Result<Vec<Value>, String>>()?;
        let authorized_effect_data = authorized_effects
            .iter()
            .map(|effect| {
                json!({
                    "proposal": {
                        "action_id": effect.proposal.action_id,
                        "operation": effect.proposal.operation,
                        "operation_name": effect.proposal.operation_name,
                        "resource_ref": effect.proposal.resource_ref,
                        "canonical_payload_sha256": effect.proposal.canonical_payload_sha256,
                    },
                    "lease_id": effect.lease_id.as_str(),
                    "executor_boundary": effect.executor_boundary,
                    "receipt_obligations": effect.receipt_obligations,
                })
            })
            .collect::<Vec<_>>();
        let role_payloads = [
            json!({
                "owner": "instrument_registry",
                "owner_reference": registration_receipt.operation_id.as_str(),
                "registration_receipt": registration_receipt,
                "named_readback": registry_readback,
                "registry_snapshot": registry.snapshot_json,
                "registry_revision": registry.revision,
                "invocation": invocation,
                "executable_observation": executable_data,
            }),
            json!({
                "owner": "coordination",
                "owner_reference": active_work.work_item.work_item_id.as_str(),
                "selection": active_work,
                "operation": invocation,
                "task_id": task_id,
                "work_scope_id": work_scope_id,
            }),
            json!({
                "owner": "work_scope_and_environment",
                "owner_reference": work_scope_id.as_str(),
                "work_scope": selected.work_scope().binding,
                "session": active_work.session,
                "environment_projection": environment,
                "state_fence": state_fence,
            }),
            json!({
                "owner": "authority",
                "owner_reference": leases[0].lease_id.as_str(),
                "scope": "currently admitted selected-source and launch actions only",
                "actions": action_data,
                "leases": lease_owner_data,
                "authorized_effects": authorized_effect_data,
                "state_fence": state_fence,
            }),
            json!({
                "owner": "work_lease_and_process_profile",
                "owner_reference": active_work.lease.lease_id.as_str(),
                "work_lease": active_work.lease,
                "work_item": active_work.work_item,
                "action_lease_budgets": lease_owner_data,
                "process_resource_limits": process_limits,
                "state_fence": state_fence,
            }),
        ];
        let refs = [
            claim_ref(
                registration_receipt.operation_id.as_str().to_owned(),
                &role_payloads[0],
            )?,
            claim_ref(
                active_work.work_item.work_item_id.as_str().to_owned(),
                &role_payloads[1],
            )?,
            claim_ref(
                work_scope_id.clone(),
                &role_payloads[2],
            )?,
            claim_ref(
                leases[0].lease_id.as_str().to_owned(),
                &role_payloads[3],
            )?,
            claim_ref(
                active_work.lease.lease_id.as_str().to_owned(),
                &role_payloads[4],
            )?,
        ];
        let claims = AdmissionReservationClaims {
            resources: refs[0].clone(),
            lane: refs[1].clone(),
            environment: refs[2].clone(),
            effects: refs[3].clone(),
            quota_view: refs[4].clone(),
        };
        claims.validate().map_err(|error| error.to_string())?;

        Ok(Self {
            claims,
            role_payloads,
            state_fence,
            task_id,
            work_scope_id,
            session_id,
            parent_request_id: identity.request.metadata.request_id.as_str().to_owned(),
            registry_revision,
            invocation: invocation.clone(),
        })
    }

    pub(crate) fn claims(&self) -> &AdmissionReservationClaims {
        &self.claims
    }

    /// Exact original-owner payload values included in the SourceSnapshotStage
    /// canonical record. The caller persists these alongside the ORS claims;
    /// their digests are checked by the storage contract on every decode.
    pub(crate) fn owner_claim_payloads(&self) -> Vec<Value> {
        self.role_payloads.to_vec()
    }

    /// Rebuilds from newly read original owners and compares all five exact
    /// payloads and ORS refs, plus task/scope/session/profile/revision/fence.
    pub(crate) fn require_same_current_owners(
        &self,
        current: &Self,
    ) -> Result<(), String> {
        if self.claims != current.claims
            || self.role_payloads != current.role_payloads
            || self.state_fence != current.state_fence
            || self.task_id != current.task_id
            || self.work_scope_id != current.work_scope_id
            || self.session_id != current.session_id
            || self.parent_request_id != current.parent_request_id
            || self.registry_revision != current.registry_revision
            || self.invocation != current.invocation
        {
            return Err(
                "LSP reservation owner payload, reference, or full request binding changed since staging"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Separate five-role ORS claims for the byte-bound source-snapshot E action.
/// The first three roles are rebuilt from the same current registry,
/// coordination, WorkScope and environment owners as the selected-source S
/// claims. The last two roles bind the original E ActionContract/ActionLease
/// and its exact per-action budget; this never promotes S's Read effect set.
pub(crate) struct LspSourcePublicationClaimSet {
    claims: AdmissionReservationClaims,
    role_payloads: [Value; 5],
    state_fence: StateFence,
    task_id: String,
    work_scope_id: String,
    session_id: String,
    child_request_id: String,
    action_contract_sha256: String,
    blob_root_id: String,
    artifact_resource_ref: String,
    archive_sha256: String,
}

impl LspSourcePublicationClaimSet {
    pub(crate) fn from_current_owners(
        selected_source: &LspLaunchClaimSet,
        prepared: &PreparedSelectedSourceSnapshotMutation,
        blob_root_id: &str,
        artifact_resource_ref: &str,
        archive_sha256: &str,
    ) -> Result<Self, String> {
        let identity = prepared.child_identity();
        let action = prepared.action_contract();
        let lease = prepared.action_lease();
        let operation = prepared.operation();
        let action_contract_sha256 = prepared.action_contract_sha256().to_owned();
        let child_request_id = identity.request.metadata.request_id.as_str().to_owned();
        if prepared.state_fence() != &selected_source.state_fence
            || prepared.task_id() != selected_source.task_id
            || prepared.work_scope_id() != selected_source.work_scope_id
            || identity.request.metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected_source.session_id.as_str())
            || child_request_id == selected_source.parent_request_id
            || action.work_scope.state_fence != selected_source.state_fence
            || action.work_scope.scope_id.as_str() != selected_source.work_scope_id
            || action.task_id != selected_source.task_id
            || action.authority_ref != operation.operation_kind
            || action.effect_set.len() != 1
            || !action.effect_set.contains(artifact_resource_ref)
            || prepared.resource_ref() != artifact_resource_ref
            || operation.effect != eliot_receipts::EffectClass::ReversibleMutation
            || operation.state_fence != selected_source.state_fence
            || operation.request_id.as_str() != child_request_id
            || operation.request_id.as_str() == selected_source.parent_request_id
            || blob_root_id.trim().is_empty()
            || blob_root_id.chars().any(char::is_control)
            || artifact_resource_ref.trim().is_empty()
            || artifact_resource_ref.chars().any(char::is_control)
            || !valid_sha256(archive_sha256)
            || lease.work_scope != action.work_scope
            || lease.session.session_id.as_str() != selected_source.session_id
            || lease.session.state_fence != selected_source.state_fence
            || lease.exact_idempotency_key != identity.idempotency_key
            || lease.remaining_uses == 0
            || !lease.authority_set.allows(
                &action.authority_ref,
                artifact_resource_ref,
                eliot_receipts::EffectClass::ReversibleMutation,
            )
        {
            return Err(
                "source-snapshot E claims do not match the selected owner state, exact Blob target, action, and lease"
                    .to_owned(),
            );
        }

        // Preserve the exact original registry/resource-owner payload. The
        // independently owner-derived target and archive digest are retained
        // in SourceSnapshotAdmissionBinding and the E ActionContract instead
        // of being grafted into the earlier resource owner's payload.
        let mut role_payloads = selected_source.role_payloads.clone();
        let action_lease_data = json!({
            "lease_id": lease.lease_id.as_str(),
            "holder": lease.holder.as_str(),
            "exact_idempotency_key": lease.exact_idempotency_key,
            "operations": lease.authority_set.operations(),
            "resources": lease.authority_set.resources(),
            "max_effect": lease.authority_set.max_effect(),
            "authority_binding": lease.authority_binding,
            "work_scope": lease.work_scope,
            "session": lease.session,
            "expires_at": lease.expires_at.value(),
            "remaining_uses": lease.remaining_uses,
            "receipt_obligations": lease.receipt_obligations,
        });
        role_payloads[3] = json!({
            "owner": "authority",
            "owner_reference": lease.lease_id.as_str(),
            "scope": "one byte-bound source snapshot E mutation only",
            "action_contract": action,
            "action_contract_sha256": action_contract_sha256,
            "action_lease": action_lease_data,
            "effect_authority": {
                "operations": lease.authority_set.operations(),
                "resources": lease.authority_set.resources(),
                "max_effect": lease.authority_set.max_effect(),
            },
            "state_fence": selected_source.state_fence,
        });
        role_payloads[4] = json!({
            "owner": "work_lease_and_source_snapshot_quota",
            "owner_reference": selected_source.claims.quota_view.reference.as_str(),
            "work_lease_role": selected_source.role_payloads[4],
            "source_snapshot_action_lease": action_lease_data,
            "operation_budget": {
                "remaining_uses": lease.remaining_uses,
                "expires_at": lease.expires_at.value(),
                "resource_ref": artifact_resource_ref,
                "archive_sha256": archive_sha256,
            },
            "state_fence": selected_source.state_fence,
        });

        let old = &selected_source.claims;
        let claims = AdmissionReservationClaims {
            resources: claim_ref(old.resources.reference.as_str().to_owned(), &role_payloads[0])?,
            lane: claim_ref(old.lane.reference.as_str().to_owned(), &role_payloads[1])?,
            environment: claim_ref(
                old.environment.reference.as_str().to_owned(),
                &role_payloads[2],
            )?,
            effects: claim_ref(
                lease.lease_id.as_str().to_owned(),
                &role_payloads[3],
            )?,
            quota_view: claim_ref(
                old.quota_view.reference.as_str().to_owned(),
                &role_payloads[4],
            )?,
        };
        claims.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            claims,
            role_payloads,
            state_fence: selected_source.state_fence.clone(),
            task_id: selected_source.task_id.clone(),
            work_scope_id: selected_source.work_scope_id.clone(),
            session_id: selected_source.session_id.clone(),
            child_request_id,
            action_contract_sha256,
            blob_root_id: blob_root_id.to_owned(),
            artifact_resource_ref: artifact_resource_ref.to_owned(),
            archive_sha256: archive_sha256.to_owned(),
        })
    }

    pub(crate) fn claims(&self) -> &AdmissionReservationClaims {
        &self.claims
    }

    /// Exact five role payloads retained beside this distinct E claim set.
    /// The canonical SourceSnapshotStage record persists these exact values
    /// and the storage validator checks them against the claim digests.
    pub(crate) fn owner_claim_payloads(&self) -> Vec<Value> {
        self.role_payloads.to_vec()
    }

    pub(crate) fn archive_sha256_for_admission(&self) -> &str {
        &self.archive_sha256
    }

    pub(crate) fn blob_root_id_for_admission(&self) -> &str {
        &self.blob_root_id
    }

    pub(crate) fn artifact_resource_ref_for_admission(&self) -> &str {
        &self.artifact_resource_ref
    }

    pub(crate) fn require_same_current_owners(&self, current: &Self) -> Result<(), String> {
        if self.claims != current.claims
            || self.role_payloads != current.role_payloads
            || self.state_fence != current.state_fence
            || self.task_id != current.task_id
            || self.work_scope_id != current.work_scope_id
            || self.session_id != current.session_id
            || self.child_request_id != current.child_request_id
            || self.action_contract_sha256 != current.action_contract_sha256
            || self.blob_root_id != current.blob_root_id
            || self.artifact_resource_ref != current.artifact_resource_ref
            || self.archive_sha256 != current.archive_sha256
        {
            return Err(
                "source-snapshot E role payloads, references, target, or full owner binding changed since reservation stage"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn claim_ref(owner_record: String, payload: &Value) -> Result<AdmissionReservationClaimRef, String> {
    if owner_record.trim().is_empty() || owner_record.chars().any(char::is_control) {
        return Err("LSP claim does not identify an original owner record".to_owned());
    }
    let bytes = eliot_contracts::canonical_json_bytes(payload)
        .map_err(|error| format!("LSP owner claim canonicalization failed: {error}"))?;
    let reference = OpaqueLabel::new(owner_record).map_err(|error| error.to_string())?;
    let claim = AdmissionReservationClaimRef {
        reference,
        sha256: eliot_contracts::sha256_hex(&bytes),
    };
    claim.validate().map_err(|error| error.to_string())?;
    Ok(claim)
}
