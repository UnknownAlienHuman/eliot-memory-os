//! Authenticated Kernel owner route for installation-bound scan disclosure.
//!
//! The daemon reaches this route only through the authenticated daemon gateway.
//! Every request is joined to the retained accepted activation, exact durable
//! activation rows, and current P-07 owner projection. The initial contour and
//! binding requests can run after `AcceptedTerminal` and before application
//! session projection; record operations require the later active session
//! before the durable ORS port can be touched. Owner inputs without current
//! producers remain typed plan gaps; request fields never become authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(windows)]
use eliot_contracts::StateFence;
#[cfg(windows)]
use eliot_ipc::ApplicationSessionState;
use eliot_ipc::{Session, TransportError};
use eliot_ors::{ScanDisclosureOrsRecord, ScanDisclosureStageOutcome};

use super::{ACTIVE_DAEMON_CALLER, KernelComposition};
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
    /// Issue one scanner binding from the current retained activation owners.
    IssueBinding,
    /// Stage one canonical receipt row.
    Stage {
        binding: ScanDisclosureOwnerBinding,
        record: Box<ScanDisclosureOrsRecord>,
    },
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

impl ScanDisclosureOwnerBinding {
    /// Exact operation identity projected by `eliot_workscope` on the daemon
    /// side; Kernel derives it from the retained, validated binding fields.
    fn operation_key(&self) -> String {
        format!(
            "scan-disclosure:{}:{}",
            self.installation_id, self.operation_id
        )
    }
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
    Contour {
        contour: InstallationScanContour,
    },
    Binding {
        binding: ScanDisclosureOwnerBinding,
    },
    Staged {
        stored: bool,
        record: Option<ScanDisclosureOrsRecord>,
    },
    Record {
        record: Option<ScanDisclosureOrsRecord>,
    },
    Records {
        records: Vec<ScanDisclosureOrsRecord>,
    },
}

#[cfg(windows)]
#[derive(Clone)]
struct CurrentScanDisclosureActivation {
    binding: eliot_protocol::AgentActivationResolvedBinding,
    ticket: eliot_protocol::AgentActivationResolutionTicket,
    result: eliot_protocol::AgentActivationResolutionResult,
    installation_id: String,
    kernel_owner_revision: u64,
    kernel_owner_bundle_sha256: String,
    active_session_epoch: Option<u64>,
    activated_binding: Option<super::ActivatedApplicationBinding>,
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
        let request = self.authenticated_scan_disclosure_owner_request(session, payload)?;
        let current = self.current_scan_disclosure_activation(
            &request.application_connection_id,
            &request.activation_ticket_id,
        )?;
        self.require_scan_disclosure_action_session(
            &request.action,
            &current,
            &request.application_connection_id,
        )?;
        let value = self.apply_scan_disclosure_owner_action(&current, request.action)?;
        serde_json::to_value(ScanDisclosureOwnerResponse {
            wire_version: WIRE_VERSION,
            value,
        })
        .map_err(|_| TransportError::SessionFenced)
    }

    #[cfg(windows)]
    fn authenticated_scan_disclosure_owner_request(
        &self,
        session: &Session,
        payload: &Value,
    ) -> Result<ScanDisclosureOwnerRequest, TransportError> {
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
        Ok(request)
    }

    #[cfg(windows)]
    fn require_scan_disclosure_action_session(
        &self,
        action: &ScanDisclosureOwnerAction,
        current: &CurrentScanDisclosureActivation,
        connection_id: &str,
    ) -> Result<(), TransportError> {
        if matches!(
            action,
            ScanDisclosureOwnerAction::IssueContour | ScanDisclosureOwnerAction::IssueBinding
        ) {
            if super::unix_ms() > current.ticket.kernel_deadline_unix_ms {
                return Err(TransportError::Timeout);
            }
            return Ok(());
        }
        self.require_active_scan_disclosure_session(current, connection_id)
    }

    #[cfg(windows)]
    fn apply_scan_disclosure_owner_action(
        &self,
        current: &CurrentScanDisclosureActivation,
        action: ScanDisclosureOwnerAction,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        match action {
            ScanDisclosureOwnerAction::IssueContour => {
                let contour = Self::issue_scan_disclosure_contour(&self.work_root)?;
                Ok(ScanDisclosureOwnerValue::Contour { contour })
            }
            ScanDisclosureOwnerAction::IssueBinding => {
                let binding = Self::issue_scan_disclosure_binding()?;
                Ok(ScanDisclosureOwnerValue::Binding { binding })
            }
            ScanDisclosureOwnerAction::Stage { binding, record } => {
                self.stage_scan_disclosure_owner(current, &binding, record.as_ref())
            }
            ScanDisclosureOwnerAction::Commit {
                binding,
                operation_key,
                request_hash,
                writer_receipt,
            } => self.commit_scan_disclosure_owner(
                current,
                &binding,
                &operation_key,
                &request_hash,
                &writer_receipt,
            ),
            ScanDisclosureOwnerAction::Load {
                binding,
                operation_key,
            } => self.load_scan_disclosure_owner(current, &binding, &operation_key),
            ScanDisclosureOwnerAction::Retire {
                binding,
                operation_key,
                request_hash,
                policy_revision,
                successor_ref,
            } => self.retire_scan_disclosure_owner(
                current,
                &binding,
                &operation_key,
                &request_hash,
                policy_revision,
                successor_ref.as_deref(),
            ),
            ScanDisclosureOwnerAction::List { binding, limit } => {
                self.list_scan_disclosure_owner(current, &binding, limit)
            }
        }
    }

    #[cfg(windows)]
    fn stage_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        Self::validate_scan_disclosure_binding(current, binding)?;
        Self::validate_record_binding(current, binding, record)?;
        match self.p07_ors.stage_scan_disclosure(record) {
            Ok(ScanDisclosureStageOutcome::Stored) => Ok(ScanDisclosureOwnerValue::Staged {
                stored: true,
                record: None,
            }),
            Ok(ScanDisclosureStageOutcome::AlreadyBound(record)) => {
                Ok(ScanDisclosureOwnerValue::Staged {
                    stored: false,
                    record: Some(*record),
                })
            }
            Err(_) => Err(TransportError::SessionFenced),
        }
    }

    #[cfg(windows)]
    fn commit_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        Self::validate_scan_disclosure_binding(current, binding)?;
        if operation_key != binding.operation_key().as_str()
            || request_hash.trim().is_empty()
            || writer_receipt.trim().is_empty()
        {
            return Err(TransportError::IdentityConflict);
        }
        let record = self
            .p07_ors
            .commit_scan_disclosure(operation_key, request_hash, writer_receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(record) = record.as_ref() {
            Self::validate_record_binding(current, binding, record)?;
        }
        Ok(ScanDisclosureOwnerValue::Record { record })
    }

    #[cfg(windows)]
    fn load_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        Self::validate_scan_disclosure_binding(current, binding)?;
        if operation_key != binding.operation_key().as_str() {
            return Err(TransportError::IdentityConflict);
        }
        let record = self
            .p07_ors
            .load_scan_disclosure(operation_key)
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(record) = record.as_ref() {
            Self::validate_record_binding(current, binding, record)?;
        }
        Ok(ScanDisclosureOwnerValue::Record { record })
    }

    #[cfg(windows)]
    fn retire_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        Self::validate_scan_disclosure_binding(current, binding)?;
        if operation_key != binding.operation_key().as_str()
            || policy_revision != binding.policy_revision
            || request_hash.trim().is_empty()
        {
            return Err(TransportError::IdentityConflict);
        }
        let record = self
            .p07_ors
            .retire_scan_disclosure(operation_key, request_hash, policy_revision, successor_ref)
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(record) = record.as_ref() {
            Self::validate_record_binding(current, binding, record)?;
        }
        Ok(ScanDisclosureOwnerValue::Record { record })
    }

    #[cfg(windows)]
    fn list_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        limit: u16,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        Self::validate_scan_disclosure_binding(current, binding)?;
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
        Ok(ScanDisclosureOwnerValue::Records { records })
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
    fn current_scan_disclosure_activation(
        &self,
        connection_id: &str,
        ticket_id: &str,
    ) -> Result<CurrentScanDisclosureActivation, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        let (local_result, pending_entry) =
            self.retained_scan_disclosure_activation_result(ticket_id)?;
        let (ticket, result) =
            self.load_scan_disclosure_activation_payloads(connection_id, ticket_id, &local_result)?;
        let binding = (*result
            .resolved_binding()
            .ok_or(TransportError::SessionFenced)?)
        .clone();
        let (session_epoch, activated_binding) = self
            .validate_scan_disclosure_accepted_connection(
                connection_id,
                &ticket,
                pending_entry.as_ref(),
            )?;
        let (kernel_owner_revision, kernel_owner_bundle_sha256) = self
            .current_scan_disclosure_owner_revision(
                &ticket,
                &result,
                &binding,
                pending_entry.as_ref(),
                activated_binding.as_ref(),
            )?;
        let installation_id = super::dispatch_contour()
            .map(|contour| contour.installation_id().to_owned())
            .filter(|identity| !identity.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        Ok(CurrentScanDisclosureActivation {
            binding,
            ticket,
            result,
            installation_id,
            kernel_owner_revision,
            kernel_owner_bundle_sha256,
            active_session_epoch: session_epoch,
            activated_binding,
        })
    }

    #[cfg(windows)]
    fn retained_scan_disclosure_activation_result(
        &self,
        ticket_id: &str,
    ) -> Result<
        (
            eliot_protocol::AgentActivationResolutionResult,
            Option<super::AgentActivationPending>,
        ),
        TransportError,
    > {
        // The accepted-result owner comes first; the lock is released before
        // durable ORS readback, preserving the activation lock order.
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
            || local.result.ticket_id != ticket_id
            || local.result.resolved_binding().is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        let local_result = local.result.clone();
        let pending_entry = pending.entries.get(ticket_id).cloned();
        drop(pending);
        Ok((local_result, pending_entry))
    }

    #[cfg(windows)]
    fn load_scan_disclosure_activation_payloads(
        &self,
        connection_id: &str,
        ticket_id: &str,
        local_result: &eliot_protocol::AgentActivationResolutionResult,
    ) -> Result<
        (
            eliot_protocol::AgentActivationResolutionTicket,
            eliot_protocol::AgentActivationResolutionResult,
        ),
        TransportError,
    > {
        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let retained_result = self
            .generation_gateway
            .ors
            .load_activation_result(ticket_id, &local_result.result_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        if lifecycle.state != eliot_ors::ActivationLifecycleState::ResultAccepted
            || lifecycle.ticket_id != ticket_id
            || lifecycle.connection_id != connection_id
            || lifecycle.result_sha256.as_deref() != Some(local_result.result_sha256.as_str())
            || lifecycle.kernel_deadline_unix_ms == 0
            || retained_result.phase != eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal
            || retained_result.ticket_id != lifecycle.ticket_id
            || retained_result.ticket_sha256 != lifecycle.ticket_sha256
            || retained_result.ticket_payload != lifecycle.ticket_payload
            || retained_result.result_sha256 != local_result.result_sha256
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
        if result != *local_result || result.validate_against(&ticket).is_err() {
            return Err(TransportError::IdentityConflict);
        }
        let state_fence_digest =
            sha256_json(&ticket.state_fence).map_err(|_| TransportError::SessionFenced)?;
        if ticket.validate().is_err()
            || ticket.ticket_id != ticket_id
            || ticket.connection_id != connection_id
            || lifecycle.ticket_sha256 != ticket.ticket_sha256
            || retained_result.ticket_sha256 != ticket.ticket_sha256
            || ticket.workspace_selector.is_none()
            || lifecycle.activation_request_id != ticket.activation_request_id.as_str()
            || lifecycle.activation_request_sha256 != ticket.activation_request_sha256
            || lifecycle.kernel_deadline_unix_ms != ticket.kernel_deadline_unix_ms
            || lifecycle.state_fence != state_fence_digest
            || result.ticket_id != ticket.ticket_id
            || result.ticket_sha256 != ticket.ticket_sha256
            || result.ticket_state_fence != ticket.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        Ok((ticket, result))
    }

    #[cfg(windows)]
    fn validate_scan_disclosure_accepted_connection(
        &self,
        connection_id: &str,
        ticket: &eliot_protocol::AgentActivationResolutionTicket,
        pending_entry: Option<&super::AgentActivationPending>,
    ) -> Result<(Option<u64>, Option<super::ActivatedApplicationBinding>), TransportError> {
        let (accepted, session_epoch, activated_binding) = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let connection = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            let accepted = connection
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .clone();
            if accepted.connection_id() != connection_id
                || accepted.peer() != &connection.peer
                || accepted.declaration() != &connection.declaration
                || (connection.activation_completed && connection.session.is_none())
                || (connection.session.is_some() && !connection.activation_completed)
                || (connection.activation_completed && connection.activated_binding.is_none())
            {
                return Err(TransportError::SessionFenced);
            }
            (
                accepted,
                connection
                    .session
                    .as_ref()
                    .map(|session| session.session_epoch),
                connection.activated_binding.clone(),
            )
        };
        let receipt = accepted.admission_receipt();
        receipt
            .validate_challenge(accepted.challenge())
            .map_err(|_| TransportError::SessionFenced)?;
        receipt
            .validate_client_hello(accepted.declaration(), accepted.client_hello())
            .map_err(|_| TransportError::SessionFenced)?;
        if receipt.connection_id != connection_id
            || receipt.receipt_sha256 != ticket.peer_admission_receipt_sha256
            || receipt.state_fence != ticket.state_fence
            || receipt.activation_deadline_unix_ms != ticket.kernel_deadline_unix_ms
            || ticket.connection_id != connection_id
        {
            return Err(TransportError::SessionFenced);
        }
        if let Some(entry) = pending_entry
            && (entry.ticket != *ticket
                || entry
                    .ticket
                    .validate_against(&entry.request, receipt)
                    .is_err())
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok((session_epoch, activated_binding))
    }

    #[cfg(windows)]
    fn current_scan_disclosure_owner_revision(
        &self,
        ticket: &eliot_protocol::AgentActivationResolutionTicket,
        result: &eliot_protocol::AgentActivationResolutionResult,
        binding: &eliot_protocol::AgentActivationResolvedBinding,
        pending_entry: Option<&super::AgentActivationPending>,
        activated_binding: Option<&super::ActivatedApplicationBinding>,
    ) -> Result<(u64, String), TransportError> {
        let owner_readback = pending_entry.and_then(|entry| entry.owner_readback.as_ref());
        if let Some(readback) = owner_readback {
            let evidence = result
                .owner_evidence
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            readback
                .validate_against_binding(binding, &ticket.state_fence)
                .map_err(|_| TransportError::SessionFenced)?;
            if readback.evidence.owner_id != evidence.owner_id
                || readback.evidence.owner_revision < evidence.owner_revision
                || readback.evidence.state_fence != evidence.state_fence
                || readback.evidence.binding != evidence.binding
            {
                return Err(TransportError::IdentityConflict);
            }
        }
        let (kernel_owner_revision, kernel_owner_bundle_sha256) = if let Some(readback) =
            owner_readback
        {
            let kernel_owner = readback
                .kernel_owner
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            kernel_owner
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            (kernel_owner.revision, kernel_owner.bundle_sha256.clone())
        } else if let Some(active) = activated_binding {
            if active.activation_ticket_id != ticket.ticket_id
                || active.activation_ticket_sha256 != ticket.ticket_sha256
                || active.resolution_result_sha256 != result.result_sha256
                || active.resolved_binding != *binding
            {
                return Err(TransportError::IdentityConflict);
            }
            (
                active.kernel_owner_revision,
                active.kernel_owner_bundle_sha256.clone(),
            )
        } else {
            return Err(TransportError::PlanGap {
                dependency: "kernel.activation_owner_readback_retention",
                reason: "the accepted connection no longer retains the exact P-07 revision and digest",
            });
        };
        if let Some(active) = activated_binding
            && (active.kernel_owner_revision != kernel_owner_revision
                || active.kernel_owner_bundle_sha256 != kernel_owner_bundle_sha256)
        {
            return Err(TransportError::IdentityConflict);
        }
        let (owner_bound, current_owner_revision, current_owner_digest) = self.p07_owner_readback();
        if !owner_bound
            || current_owner_revision != Some(kernel_owner_revision)
            || current_owner_digest.as_deref() != Some(kernel_owner_bundle_sha256.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        Ok((kernel_owner_revision, kernel_owner_bundle_sha256))
    }

    #[cfg(windows)]
    fn require_active_scan_disclosure_session(
        &self,
        current: &CurrentScanDisclosureActivation,
        connection_id: &str,
    ) -> Result<(), TransportError> {
        let retained = current
            .activated_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let application_session_epoch = current
            .active_session_epoch
            .ok_or(TransportError::SessionFenced)?;
        if retained.activation_ticket_id != current.ticket.ticket_id
            || retained.activation_ticket_sha256 != current.ticket.ticket_sha256
            || retained.activation_request_id != current.ticket.activation_request_id.as_str()
            || retained.activation_request_sha256 != current.ticket.activation_request_sha256
            || retained.peer_admission_receipt_sha256
                != current.ticket.peer_admission_receipt_sha256
            || retained.resolution_result_sha256 != current.result.result_sha256
            || retained.resolved_binding != current.binding
            || retained.principal_id != current.binding.principal_id
            || retained.session_id != current.binding.session_id
            || retained.task_id != current.binding.task_id
            || retained.work_scope_id != current.binding.work_scope_id
            || retained.task_revision.value().to_string() != current.binding.task_revision
            || retained.authority_epoch != current.ticket.state_fence.authority_epoch
            || retained.activation_generation != current.ticket.state_fence.resource_generation
            || retained.kernel_owner_revision != current.kernel_owner_revision
            || retained.kernel_owner_bundle_sha256 != current.kernel_owner_bundle_sha256
        {
            return Err(TransportError::IdentityConflict);
        }
        let sessions = self
            .agent_application_sessions
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let application = sessions
            .get(&current.binding.session_id)
            .ok_or(TransportError::SessionFenced)?;
        if application.session_id() != current.binding.session_id
            || application.state() != ApplicationSessionState::Active
            || !application
                .authority_epoch()
                .is_same_authority(&current.ticket.state_fence.authority_epoch)
            || !application
                .transport_bindings()
                .last()
                .is_some_and(|binding| {
                    binding.binding_id == connection_id
                        && binding.session_epoch == application_session_epoch
                })
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn issue_scan_disclosure_contour(
        work_root: &std::path::Path,
    ) -> Result<InstallationScanContour, TransportError> {
        let object_path = work_root.join(".eliot").join("kernel-ors.redb");
        let object_path =
            std::fs::canonicalize(&object_path).map_err(|_| TransportError::PlanGap {
                dependency: "kernel.ors_object_path_readback",
                reason: "the live Kernel ORS object path could not be read back",
            })?;
        let _object_ref = object_path
            .to_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?
            .to_owned();
        // ORS exposes no durable store-wide generation counter on this base.
        // P-07 revision and daemon resource generation identify different
        // owners and must not be substituted for the missing ORS generation.
        Err(TransportError::PlanGap {
            dependency: "kernel.ors_object_generation_owner",
            reason: "the live ORS object path is known but ORS has no durable store-wide object generation readback",
        })
    }

    #[cfg(windows)]
    fn issue_scan_disclosure_binding() -> Result<ScanDisclosureOwnerBinding, TransportError> {
        // The accepted activation and Host observation do not carry an
        // admitted privacy boundary, policy revision, or durable
        // DiscoveryReadLease owner, and the accepted result carries no
        // TaskSelectionEvidence. Kernel cannot turn request data or the
        // activation ticket into those missing authorities.
        Err(TransportError::PlanGap {
            dependency: "governor.current_scan_privacy_policy_and_lease_owner",
            reason: "no admitted privacy-boundary/policy, DiscoveryReadLease owner, or TaskSelectionEvidence is available for this activation",
        })
    }

    #[cfg(windows)]
    fn validate_scan_disclosure_binding(
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<(), TransportError> {
        let state_fence_ref =
            sha256_json(&current.ticket.state_fence).map_err(|_| TransportError::SessionFenced)?;
        let authority_epoch_ref =
            StateFence::canonical_epoch_digest(&current.ticket.state_fence.authority_epoch)
                .map_err(|_| TransportError::SessionFenced)?
                .as_str()
                .to_owned();
        if binding.installation_id != current.installation_id
            || binding.principal_ref != current.binding.principal_id
            || binding.session_ref != current.binding.session_id
            || binding.host_generation_ref
                != current
                    .ticket
                    .state_fence
                    .resource_generation
                    .value()
                    .to_string()
            || binding.candidate_root_ref
                != current
                    .ticket
                    .workspace_selector
                    .as_deref()
                    .unwrap_or_default()
            || binding.state_fence_ref.as_deref() != Some(state_fence_ref.as_str())
            || binding.authority_epoch_ref.as_deref() != Some(authority_epoch_ref.as_str())
            || binding.lease_ref.trim().is_empty()
            || binding.privacy_boundary_ref.trim().is_empty()
            || binding.operation_id.trim().is_empty()
            || binding.idempotency_key.trim().is_empty()
            || binding.policy_revision == 0
            || binding.deadline == 0
            || binding.deadline > current.ticket.kernel_deadline_unix_ms
        {
            return Err(TransportError::IdentityConflict);
        }
        // The current Kernel/application state has no admitted privacy-policy
        // boundary, retained discovery-lease owner, or TaskSelectionEvidence
        // to compare these fields against. Shape and activation equality alone
        // are not authority.
        Err(TransportError::PlanGap {
            dependency: "governor.current_scan_privacy_policy_and_lease_owner",
            reason: "no admitted live privacy-boundary/policy, DiscoveryReadLease owner, or TaskSelectionEvidence is available for this activation",
        })
    }

    #[cfg(windows)]
    fn validate_record_binding(
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<(), TransportError> {
        record
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
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
