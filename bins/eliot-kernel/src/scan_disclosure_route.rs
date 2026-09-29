//! Authenticated Kernel owner route for installation-bound scan disclosure.
//!
//! The daemon reaches this route only through the authenticated daemon gateway.
//! Every request is joined to the live application session, retained accepted
//! activation, exact durable activation rows, and the current P-07 owner
//! projection before the durable ORS port can be touched. Owner inputs that
//! have no current producer remain typed plan gaps; the route never turns a
//! request field into authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(windows)]
use eliot_contracts::StateFence;
#[cfg(windows)]
use eliot_ipc::ApplicationSessionState;
use eliot_ipc::{Session, TransportError};
use eliot_ors::{
    ScanDisclosureOrsRecord, ScanDisclosureRecordOwner, ScanDisclosureStageOutcome,
};

use super::{
    ACTIVE_DAEMON_CALLER, KernelComposition,
};
#[cfg(windows)]
use super::{AgentActivationResultPhase, sha256_json};

/// The one authenticated daemon operation owned by this module.
pub(crate) const OPERATION: &str = "scan_disclosure_owner";

const WIRE_VERSION: u16 = 1;

/// Closed typed request envelope for contour/binding issuance and the five
/// durable ORS scan-disclosure operations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanDisclosureOwnerRequest {
    pub wire_version: u16,
    pub application_connection_id: String,
    pub activation_ticket_id: String,
    #[serde(flatten)]
    pub action: ScanDisclosureOwnerAction,
}

/// The route's closed operation vocabulary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ScanDisclosureOwnerAction {
    /// Return the Kernel-owned installation/ORS contour.
    IssueContour,
    /// Admit one scanner binding against the currently retained activation.
    IssueBinding { binding: ScanDisclosureOwnerBinding },
    /// Stage one canonical receipt row.
    Stage { binding: ScanDisclosureOwnerBinding, record: ScanDisclosureOrsRecord },
    /// Commit one staged receipt row.
    Commit {
        binding: ScanDisclosureOwnerBinding,
        operation_key: String,
        request_hash: String,
        writer_receipt: String,
    },
    /// Load one exact receipt row.
    Load {
        binding: ScanDisclosureOwnerBinding,
        operation_key: String,
    },
    /// Retire one committed receipt row.
    Retire {
        binding: ScanDisclosureOwnerBinding,
        operation_key: String,
        request_hash: String,
        policy_revision: u64,
        successor_ref: Option<String>,
    },
    /// List a bounded page for the admitted installation and application.
    List {
        binding: ScanDisclosureOwnerBinding,
        limit: u16,
    },
}

/// Kernel-neutral wire projection of `ScanDisclosureOwnerBinding`.
///
/// The Kernel crate does not depend on Governor/WorkScope. This wire type
/// carries the exact existing fields and adds no semantics of its own.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanDisclosureOwnerBinding {
    pub installation_id: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub host_generation_ref: String,
    pub lease_ref: String,
    pub candidate_root_ref: String,
    pub privacy_boundary_ref: String,
    pub state_fence_ref: Option<String>,
    pub authority_epoch_ref: Option<String>,
    pub operation_id: String,
    pub idempotency_key: String,
    pub lease_consumed: u64,
    pub policy_revision: u64,
    pub deadline: u64,
}

/// Kernel-issued installation storage contour.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallationScanContour {
    pub installation_id: String,
    pub ors_object_ref: String,
    pub ors_generation: u64,
}

/// Typed response for the closed owner route.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanDisclosureOwnerResponse {
    pub wire_version: u16,
    #[serde(flatten)]
    pub value: ScanDisclosureOwnerValue,
}

/// Response vocabulary; the stage outcome is projected because its ORS type
/// intentionally has no serde implementation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ScanDisclosureOwnerValue {
    Contour { contour: InstallationScanContour },
    Binding { binding: ScanDisclosureOwnerBinding },
    Staged { stored: bool, record: Option<ScanDisclosureOrsRecord> },
    Record { record: Option<ScanDisclosureOrsRecord> },
    Records { records: Vec<ScanDisclosureOrsRecord> },
}

#[cfg(windows)]
#[derive(Clone)]
struct CurrentApplicationBinding {
    retained: super::ActivatedApplicationBinding,
    ticket: eliot_protocol::AgentActivationResolutionTicket,
    installation_id: String,
}

impl KernelComposition {
    /// Executes one authenticated scan-disclosure owner request.
    ///
    /// `execute_daemon_request_inner` is the only production caller; it has
    /// already checked `ACTIVE_DAEMON_CALLER` and the current daemon session.
    /// This method repeats those checks at the owner boundary so a future
    /// dispatcher arm cannot accidentally widen the route.
    #[cfg(windows)]
    pub(crate) fn scan_disclosure_owner_operation(
        &self,
        session: &Session,
        payload: &Value,
    ) -> Result<Value, TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        self.require_current_daemon_session(session)?;
        let request: ScanDisclosureOwnerRequest =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        if request.wire_version != WIRE_VERSION
            || request.application_connection_id.trim().is_empty()
            || request.activation_ticket_id.trim().is_empty()
        {
            return Err(TransportError::SessionFenced);
        }
        let current = self.current_application_binding(
            &request.application_connection_id,
            &request.activation_ticket_id,
        )?;
        let value = match request.action {
            ScanDisclosureOwnerAction::IssueContour => {
                let contour = self.issue_scan_disclosure_contour(&current)?;
                ScanDisclosureOwnerValue::Contour { contour }
            }
            ScanDisclosureOwnerAction::IssueBinding { binding } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                ScanDisclosureOwnerValue::Binding { binding }
            }
            ScanDisclosureOwnerAction::Stage { binding, record } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                self.validate_record_binding(&current, &binding, &record)?;
                match self.p07_ors.stage_scan_disclosure(&record) {
                    Ok(ScanDisclosureStageOutcome::Stored) => ScanDisclosureOwnerValue::Staged {
                        stored: true,
                        record: None,
                    },
                    Ok(ScanDisclosureStageOutcome::AlreadyBound(record)) => {
                        ScanDisclosureOwnerValue::Staged {
                            stored: false,
                            record: Some(*record),
                        }
                    }
                    Err(_) => return Err(TransportError::SessionFenced),
                }
            }
            ScanDisclosureOwnerAction::Commit {
                binding,
                operation_key,
                request_hash,
                writer_receipt,
            } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                if operation_key != binding.operation_key()
                    || request_hash.trim().is_empty()
                    || writer_receipt.trim().is_empty()
                {
                    return Err(TransportError::IdentityConflict);
                }
                let record = self
                    .p07_ors
                    .commit_scan_disclosure(&operation_key, &request_hash, &writer_receipt)
                    .map_err(|_| TransportError::SessionFenced)?;
                if let Some(record) = record.as_ref() {
                    self.validate_record_binding(&current, &binding, record)?;
                }
                ScanDisclosureOwnerValue::Record { record }
            }
            ScanDisclosureOwnerAction::Load {
                binding,
                operation_key,
            } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                if operation_key != binding.operation_key() {
                    return Err(TransportError::IdentityConflict);
                }
                let record = self
                    .p07_ors
                    .load_scan_disclosure(&operation_key)
                    .map_err(|_| TransportError::SessionFenced)?;
                if let Some(record) = record.as_ref() {
                    self.validate_record_binding(&current, &binding, record)?;
                }
                ScanDisclosureOwnerValue::Record { record }
            }
            ScanDisclosureOwnerAction::Retire {
                binding,
                operation_key,
                request_hash,
                policy_revision,
                successor_ref,
            } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                if operation_key != binding.operation_key()
                    || policy_revision != binding.policy_revision
                    || request_hash.trim().is_empty()
                {
                    return Err(TransportError::IdentityConflict);
                }
                let record = self
                    .p07_ors
                    .retire_scan_disclosure(
                        &operation_key,
                        &request_hash,
                        policy_revision,
                        successor_ref.as_deref(),
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                if let Some(record) = record.as_ref() {
                    self.validate_record_binding(&current, &binding, record)?;
                }
                ScanDisclosureOwnerValue::Record { record }
            }
            ScanDisclosureOwnerAction::List { binding, limit } => {
                self.validate_scan_disclosure_binding(&current, &binding)?;
                if limit == 0 || limit > eliot_ors::MAX_SCAN_DISCLOSURE_PAGE {
                    return Err(TransportError::SessionFenced);
                }
                let records = self
                    .p07_ors
                    .list_scan_disclosures(&current.installation_id, limit)
                    .map_err(|_| TransportError::SessionFenced)?
                    .into_iter()
                    .filter(|record| {
                        record.principal_ref == binding.principal_ref
                            && record.session_ref == binding.session_ref
                    })
                    .collect();
                ScanDisclosureOwnerValue::Records { records }
            }
        };
        serde_json::to_value(ScanDisclosureOwnerResponse {
            wire_version: WIRE_VERSION,
            value,
        })
        .map_err(|_| TransportError::SessionFenced)
    }

    #[cfg(not(windows))]
    pub(crate) fn scan_disclosure_owner_operation(
        &self,
        _session: &Session,
        _payload: &Value,
    ) -> Result<Value, TransportError> {
        Err(TransportError::PlanGap {
            dependency: "windows.daemon_scan_disclosure_owner",
            reason: "the authenticated daemon scan-disclosure owner route is Windows-only",
        })
    }

    #[cfg(windows)]
    fn current_application_binding(
        &self,
        connection_id: &str,
        ticket_id: &str,
    ) -> Result<CurrentApplicationBinding, TransportError> {
        let (retained, application_session_epoch) = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let connection = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if !connection.activation_completed || connection.session.is_none() {
                return Err(TransportError::SessionFenced);
            }
            let retained = connection
                .activated_binding
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            if retained.activation_ticket_id != ticket_id {
                return Err(TransportError::IdentityConflict);
            }
            let session_epoch = connection
                .session
                .as_ref()
                .map(|session| session.session_epoch)
                .ok_or(TransportError::SessionFenced)?;
            (retained.clone(), session_epoch)
        };

        {
            let sessions = self
                .agent_application_sessions
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let application = sessions
                .get(&retained.session_id)
                .ok_or(TransportError::SessionFenced)?;
            if application.session_id() != retained.session_id
                || application.state() != ApplicationSessionState::Active
                || !application
                    .authority_epoch()
                    .is_same_authority(&retained.authority_epoch)
                || !application.transport_bindings().last().is_some_and(|binding| {
                    binding.binding_id == connection_id
                        && binding.session_epoch == application_session_epoch
                })
            {
                return Err(TransportError::SessionFenced);
            }
        }

        let (owner_bound, owner_revision, owner_digest) = self.p07_owner_readback();
        if !owner_bound
            || owner_revision != Some(retained.kernel_owner_revision)
            || owner_digest.as_deref() != Some(retained.kernel_owner_bundle_sha256.as_str())
        {
            return Err(TransportError::SessionFenced);
        }

        let pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let local = pending
            .results
            .get(ticket_id)
            .ok_or(TransportError::SessionFenced)?;
        if local.phase != AgentActivationResultPhase::AcceptedTerminal
            || local.result.validate().is_err()
            || local.result.ticket_id != retained.activation_ticket_id
            || local.result.ticket_sha256 != retained.activation_ticket_sha256
            || local.result.result_sha256 != retained.resolution_result_sha256
            || local.result.resolved_binding() != Some(&retained.resolved_binding)
            || retained.resolved_binding.principal_id != retained.principal_id
            || retained.resolved_binding.session_id != retained.session_id
            || retained.resolved_binding.task_id != retained.task_id
            || retained.resolved_binding.work_scope_id != retained.work_scope_id
            || retained.resolved_binding.task_revision != retained.task_revision.value().to_string()
        {
            return Err(TransportError::SessionFenced);
        }
        drop(pending);

        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let retained_result = self
            .generation_gateway
            .ors
            .load_activation_result(ticket_id, &retained.resolution_result_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        if lifecycle.state != eliot_ors::ActivationLifecycleState::ResultAccepted
            || lifecycle.ticket_id != retained.activation_ticket_id
            || lifecycle.ticket_sha256 != retained.activation_ticket_sha256
            || lifecycle.connection_id != connection_id
            || lifecycle.result_sha256.as_deref()
                != Some(retained.resolution_result_sha256.as_str())
            || retained_result.phase != eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal
            || retained_result.ticket_id != lifecycle.ticket_id
            || retained_result.ticket_sha256 != lifecycle.ticket_sha256
            || retained_result.ticket_payload != lifecycle.ticket_payload
            || retained_result.result_sha256 != retained.resolution_result_sha256
            || retained_result.connection_id != connection_id
            || retained_result.state_fence != lifecycle.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let ticket = serde_json::from_str::<eliot_protocol::AgentActivationResolutionTicket>(
            &lifecycle.ticket_payload,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let result = serde_json::from_str::<eliot_protocol::AgentActivationResolutionResult>(
            &retained_result.result_payload,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let state_fence_digest = sha256_json(&ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if ticket.validate().is_err()
            || result.validate().is_err()
            || ticket.ticket_id != retained.activation_ticket_id
            || ticket.ticket_sha256 != retained.activation_ticket_sha256
            || ticket.connection_id != connection_id
            || ticket.workspace_selector.is_none()
            || ticket.state_fence.authority_epoch != retained.authority_epoch
            || ticket.state_fence.resource_generation != retained.activation_generation
            || lifecycle.state_fence != state_fence_digest
            || result.ticket_id != retained.activation_ticket_id
            || result.ticket_sha256 != retained.activation_ticket_sha256
            || result.result_sha256 != retained.resolution_result_sha256
            || result.resolved_binding() != Some(&retained.resolved_binding)
        {
            return Err(TransportError::SessionFenced);
        }

        let installation_id = super::dispatch_contour()
            .map(|contour| contour.installation_id().to_owned())
            .filter(|identity| !identity.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        Ok(CurrentApplicationBinding {
            retained,
            ticket,
            installation_id,
        })
    }

    #[cfg(windows)]
    fn issue_scan_disclosure_contour(
        &self,
        current: &CurrentApplicationBinding,
    ) -> Result<InstallationScanContour, TransportError> {
        let object_path = self.work_root.join(".eliot").join("kernel-ors.redb");
        let object_path = std::fs::canonicalize(&object_path).map_err(|_| {
            TransportError::PlanGap {
                dependency: "kernel.ors_object_path_readback",
                reason: "the live Kernel ORS object path could not be read back",
            }
        })?;
        let _object_ref = object_path
            .to_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?
            .to_owned();
        let _ = current;
        // ORS exposes no durable store-wide generation counter on this base.
        // P-07 revision and daemon resource generation identify different
        // owners and must not be substituted for the missing ORS generation.
        Err(TransportError::PlanGap {
            dependency: "kernel.ors_object_generation_owner",
            reason: "the live ORS object path is known but ORS has no durable store-wide object generation readback",
        })
    }

    #[cfg(windows)]
    fn validate_scan_disclosure_binding(
        &self,
        current: &CurrentApplicationBinding,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<(), TransportError> {
        let state_fence_ref = sha256_json(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        let authority_epoch_ref = StateFence::canonical_epoch_digest(
            &current.ticket.state_fence.authority_epoch,
        )
        .map_err(|_| TransportError::SessionFenced)?
        .as_str()
        .to_owned();
        if binding.installation_id != current.installation_id
            || binding.principal_ref != current.retained.principal_id
            || binding.session_ref != current.retained.session_id
            || binding.host_generation_ref != current.retained.activation_generation.value().to_string()
            || binding.candidate_root_ref
                != current.ticket.workspace_selector.as_deref().unwrap_or_default()
            || binding.state_fence_ref.as_deref() != Some(state_fence_ref.as_str())
            || binding.authority_epoch_ref.as_deref() != Some(authority_epoch_ref.as_str())
            || binding.lease_ref.trim().is_empty()
            || binding.privacy_boundary_ref.trim().is_empty()
            || binding.operation_id.trim().is_empty()
            || binding.idempotency_key.trim().is_empty()
            || binding.lease_consumed == 0
            || binding.policy_revision == 0
            || binding.deadline == 0
            || binding.deadline > current.ticket.kernel_deadline_unix_ms
        {
            return Err(TransportError::IdentityConflict);
        }
        // The current Kernel/application state has no admitted privacy-policy
        // boundary or retained discovery-lease owner to compare these fields
        // against. Shape and activation equality alone are not authority.
        Err(TransportError::PlanGap {
            dependency: "governor.current_scan_privacy_policy_and_lease_owner",
            reason: "no admitted live privacy-boundary/policy and DiscoveryReadLease owner is available for this activation",
        })
    }

    #[cfg(windows)]
    fn validate_record_binding(
        &self,
        current: &CurrentApplicationBinding,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<(), TransportError> {
        record.validate().map_err(|_| TransportError::SessionFenced)?;
        if record.installation_id != current.installation_id
            || record.principal_ref != binding.principal_ref
            || record.session_ref != binding.session_ref
            || record.host_generation_ref != binding.host_generation_ref
            || record.lease_ref != binding.lease_ref
            || record.lease_consumed != binding.lease_consumed
            || record.candidate_root_ref != binding.candidate_root_ref
            || record.privacy_boundary_ref != binding.privacy_boundary_ref
            || record.state_fence_ref != binding.state_fence_ref
            || record.authority_epoch_ref != binding.authority_epoch_ref
            || record.idempotency_key != binding.idempotency_key
            || record.policy_revision != binding.policy_revision
            || record.deadline != binding.deadline
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
    }
}
