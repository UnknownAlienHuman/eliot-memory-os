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
use eliot_ors::{
    ColdStartReadinessOrsRecord, ColdStartReadinessOwnerKey, ColdStartReadinessStageOutcome,
    ColdStartReadinessTerminalDisposition, ScanDisclosureOrsRecord,
    ScanDisclosureQuarantineRecord, ScanDisclosureReadFailure, ScanDisclosureStageOutcome,
};
#[cfg(windows)]
use eliot_store_api::{
    RecoveryRecord, RecoveryRecordKey, StoreRecoveryRequest, StoreWorkScopeOwnerRequest,
};
use eliot_workscope::{
    BootstrapScanEvidence, DiscoveryLeaseRequest, DiscoveryRead, DiscoveryReadLease,
    ScanReceiptHandle, WorkScopeBindingSnapshot, issue_discovery_lease,
};
#[cfg(windows)]
use eliot_workscope::{ColdStartOwnerInputs, WorkScopeBindingOwner};

use super::{ACTIVE_DAEMON_CALLER, KernelComposition};
#[cfg(windows)]
use super::{AgentActivationResultPhase, sha256_json};

/// The one authenticated daemon operation owned by this module.
pub(crate) const OPERATION: &str = "scan_disclosure_owner";

const WIRE_VERSION: u16 = 1;
#[cfg(windows)]
const WORK_SCOPE_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.owner.snapshot.v1";

/// Closed typed request envelope for contour/binding issuance, durable
/// scan-disclosure operations, and durable cold-start readiness operations.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanDisclosureOwnerRequest {
    pub wire_version: u16,
    pub application_connection_id: String,
    pub activation_ticket_id: String,
    #[serde(default)]
    pub initial_bind_scope_proof: Option<InitialBindScopeOwnerProof>,
    #[serde(flatten)]
    pub action: ScanDisclosureOwnerAction,
}

/// Original accepted BIND_SCOPE proof carried by eliotd on the unresolved
/// initial discovery lane. Its fields are independently checked against the
/// retained ticket/result and current canonical owners on every operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialBindScopeOwnerProof {
    pub evidence: eliot_protocol::AgentActivationBindScopeEvidence,
    pub envelope: eliot_protocol::HostRequestEnvelope,
}

/// The route's closed operation vocabulary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ScanDisclosureOwnerAction {
    /// Authenticate the original explicit BIND_SCOPE continuation, issue its
    /// first discovery lease, and return only the immutable lifecycle row
    /// readback. This path deliberately has no application Session.
    InitialBindScopeDiscovery {
        evidence: Box<eliot_protocol::AgentActivationBindScopeEvidence>,
        envelope: Box<eliot_protocol::HostRequestEnvelope>,
        explicit_root: String,
        root_identity_ref: String,
        allowed_reads: Vec<DiscoveryRead>,
    },
    /// Return the Kernel-owned installation/ORS contour.
    IssueContour,
    /// Issue one scanner binding from the current retained activation owners.
    IssueBinding,
    /// Persist the exact initial Kernel discovery lease on the next immutable
    /// WorkScope owner revision before issuing the scan binding.
    RetainDiscoveryLease {
        expected_owner_revision: u64,
        lease: Box<DiscoveryReadLease>,
        snapshot: Box<WorkScopeBindingSnapshot>,
    },
    /// Persist the post-scan consumed lease, original evidence, exact binding
    /// and owner-issued receipt handle on the next WorkScope owner revision.
    RetainScanEvidence {
        expected_owner_revision: u64,
        discovery_lease: Box<DiscoveryReadLease>,
        evidence: Box<BootstrapScanEvidence>,
        binding: ScanDisclosureOwnerBinding,
        receipt_handle: Box<ScanReceiptHandle>,
        snapshot: Box<WorkScopeBindingSnapshot>,
    },
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
    /// Retain an exact legacy capture in the separate quarantine row family.
    QuarantineRetain {
        binding: ScanDisclosureOwnerBinding,
        record: Box<ScanDisclosureQuarantineRecord>,
    },
    /// Read one exact quarantine row without exposing it as a scan receipt.
    QuarantineLoad {
        binding: ScanDisclosureOwnerBinding,
        quarantine_key: String,
    },
    /// Atomically claim or join one exact durable cold-start lease key.
    ReadinessClaim {
        key: Box<ColdStartReadinessOwnerKey>,
    },
    /// Publish one immutable terminal readiness receipt revision.
    ReadinessPublish {
        record_key: String,
        binding_digest: String,
        lease_ref: String,
        disposition: ColdStartReadinessTerminalDisposition,
        receipt_ref: String,
        receipt_bytes: String,
    },
    /// Read one exact durable readiness lease revision.
    ReadinessLoad { record_key: String },
    /// Read the latest revision for one complete readiness binding digest.
    ReadinessLoadForBinding { binding_digest: String },
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
    #[serde(default)]
    pub cancellation_ref: String,
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
    InitialBindScopeDiscovery {
        ticket: eliot_protocol::AgentActivationResolutionTicket,
        lease: DiscoveryReadLease,
    },
    InitialBindScopeRootRequired {
        ticket: eliot_protocol::AgentActivationResolutionTicket,
    },
    Contour {
        contour: InstallationScanContour,
    },
    Binding {
        binding: ScanDisclosureOwnerBinding,
    },
    #[cfg(windows)]
    WorkScopeOwnerRevision {
        owner_revision: u64,
        state_fence: StateFence,
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
    QuarantineRecord {
        record: Option<ScanDisclosureQuarantineRecord>,
    },
    ReadinessClaimed {
        outcome: ColdStartReadinessStageOutcome,
    },
    ReadinessRecord {
        record: Option<ColdStartReadinessOrsRecord>,
    },
    /// A retained scan handle did not resolve to a valid durable receipt.
    /// This is a typed negative owner result; callers must not interpret it
    /// as readiness or as an absent optional receipt.
    ReceiptReadFailure {
        failure: ScanDisclosureReadFailure,
    },
}

enum ScanDisclosureOwnerActionError {
    Transport(TransportError),
    ReceiptRead(ScanDisclosureReadFailure),
}

#[cfg(windows)]
fn scan_disclosure_owner_action_may_mutate(action: &ScanDisclosureOwnerAction) -> bool {
    matches!(
        action,
        ScanDisclosureOwnerAction::RetainDiscoveryLease { .. }
            | ScanDisclosureOwnerAction::RetainScanEvidence { .. }
            | ScanDisclosureOwnerAction::Stage { .. }
            | ScanDisclosureOwnerAction::Commit { .. }
            | ScanDisclosureOwnerAction::Retire { .. }
            | ScanDisclosureOwnerAction::QuarantineRetain { .. }
            | ScanDisclosureOwnerAction::ReadinessClaim { .. }
            | ScanDisclosureOwnerAction::ReadinessPublish { .. }
    )
}

impl From<TransportError> for ScanDisclosureOwnerActionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<ScanDisclosureReadFailure> for ScanDisclosureOwnerActionError {
    fn from(failure: ScanDisclosureReadFailure) -> Self {
        Self::ReceiptRead(failure)
    }
}

#[cfg(windows)]
#[derive(Clone)]
struct CurrentScanDisclosureActivation {
    binding: Option<eliot_protocol::AgentActivationResolvedBinding>,
    initial_bind_scope_proof: Option<InitialBindScopeOwnerProof>,
    principal_id: String,
    session_id: String,
    task_id: String,
    task_revision: u64,
    work_scope_id: String,
    ticket: eliot_protocol::AgentActivationResolutionTicket,
    result: eliot_protocol::AgentActivationResolutionResult,
    /// Original authenticated bridge request identity. Scan child operations
    /// are namespaced from this retained identity, never from ticket or scan
    /// caller fields.
    activation_request_identity: Option<eliot_protocol::RequestIdentity>,
    installation_id: String,
    kernel_owner_revision: u64,
    kernel_owner_bundle_sha256: String,
    active_session_epoch: Option<u64>,
    activated_binding: Option<super::ActivatedApplicationBinding>,
}

#[cfg(windows)]
impl CurrentScanDisclosureActivation {
    fn principal_id(&self) -> &str {
        &self.principal_id
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn task_id(&self) -> &str {
        &self.task_id
    }

    fn task_revision(&self) -> u64 {
        self.task_revision
    }

    fn work_scope_id(&self) -> &str {
        &self.work_scope_id
    }
}

impl KernelComposition {
    /// Executes one authenticated scan-disclosure owner request.
    ///
    /// `execute_daemon_request_inner` is the only production caller; it has
    /// already checked `ACTIVE_DAEMON_CALLER` and the current daemon session.
    /// This method repeats those checks at the owner boundary so a future
    /// dispatcher arm cannot accidentally widen the route.
    #[cfg(windows)]
    pub(crate) async fn scan_disclosure_owner_operation(
        &self,
        session: &Session,
        payload: &Value,
    ) -> Result<Value, TransportError> {
        let request = self.authenticated_scan_disclosure_owner_request(session, payload)?;
        if let Err(failure) = self.verify_scan_disclosure_storage() {
            return serde_json::to_value(ScanDisclosureOwnerResponse {
                wire_version: WIRE_VERSION,
                value: ScanDisclosureOwnerValue::ReceiptReadFailure { failure },
            })
            .map_err(|_| TransportError::SessionFenced);
        }
        if matches!(
            &request.action,
            ScanDisclosureOwnerAction::InitialBindScopeDiscovery { .. }
        ) {
            if request.initial_bind_scope_proof.is_some() {
                return Err(TransportError::SessionFenced);
            }
            let result = self.initial_bind_scope_discovery(&request);
            if self.verify_scan_disclosure_storage().is_err() {
                return serde_json::to_value(ScanDisclosureOwnerResponse {
                    wire_version: WIRE_VERSION,
                    value: ScanDisclosureOwnerValue::ReceiptReadFailure {
                        failure: ScanDisclosureReadFailure::UnknownCommit,
                    },
                })
                .map_err(|_| TransportError::SessionFenced);
            }
            let value = result?;
            return serde_json::to_value(ScanDisclosureOwnerResponse {
                wire_version: WIRE_VERSION,
                value,
            })
            .map_err(|_| TransportError::SessionFenced);
        }
        let current = self.current_scan_disclosure_activation(
            &request.application_connection_id,
            &request.activation_ticket_id,
            request.initial_bind_scope_proof.as_ref(),
        )?;
        self.require_scan_disclosure_action_session(
            &request.action,
            &current,
            &request.application_connection_id,
        )?;
        let may_mutate = scan_disclosure_owner_action_may_mutate(&request.action);
        let result = self
            .apply_scan_disclosure_owner_action(&current, request.action)
            .await;
        let post_context = if super::unix_ms() > current.ticket.kernel_deadline_unix_ms {
            Err(TransportError::Timeout)
        } else {
            self.recheck_scan_disclosure_activation(&current)
        };
        if post_context.is_err() {
            return serde_json::to_value(ScanDisclosureOwnerResponse {
                wire_version: WIRE_VERSION,
                value: ScanDisclosureOwnerValue::ReceiptReadFailure {
                    failure: if may_mutate {
                        ScanDisclosureReadFailure::UnknownCommit
                    } else {
                        ScanDisclosureReadFailure::Stale
                    },
                },
            })
            .map_err(|_| TransportError::SessionFenced);
        }
        let storage_result = self.verify_scan_disclosure_storage();
        if let Err(failure) = storage_result {
            return serde_json::to_value(ScanDisclosureOwnerResponse {
                wire_version: WIRE_VERSION,
                value: ScanDisclosureOwnerValue::ReceiptReadFailure {
                    failure: if may_mutate {
                        ScanDisclosureReadFailure::UnknownCommit
                    } else {
                        failure
                    },
                },
            })
            .map_err(|_| TransportError::SessionFenced);
        }
        let value = match result {
            Ok(value) => value,
            Err(ScanDisclosureOwnerActionError::ReceiptRead(failure)) => {
                ScanDisclosureOwnerValue::ReceiptReadFailure { failure }
            }
            Err(ScanDisclosureOwnerActionError::Transport(error)) => return Err(error),
        };
        serde_json::to_value(ScanDisclosureOwnerResponse {
            wire_version: WIRE_VERSION,
            value,
        })
        .map_err(|_| TransportError::SessionFenced)
    }

    #[cfg(windows)]
    fn verify_scan_disclosure_storage(
        &self,
    ) -> Result<(), ScanDisclosureReadFailure> {
        let binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(ScanDisclosureReadFailure::Inaccessible)?;
        let expected_generation = self
            .scan_disclosure_ors_generation
            .ok_or(ScanDisclosureReadFailure::Inaccessible)?;
        let identity = self
            .p07_ors
            .installed_store_identity()
            .map_err(|_| ScanDisclosureReadFailure::Inaccessible)?;
        if identity.installation_id() != binding.installation_id()
            || identity.ors_generation() != expected_generation
        {
            return Err(ScanDisclosureReadFailure::Replaced);
        }
        let storage = self
            .scan_disclosure_storage
            .as_ref()
            .ok_or(ScanDisclosureReadFailure::Inaccessible)?;
        storage
            .verify(&self.ors_object_path)
            .map_err(|error| match error {
                eliot_platform_windows::ProtectedPathError::IdentityMismatch
                | eliot_platform_windows::ProtectedPathError::ReparsePoint
                | eliot_platform_windows::ProtectedPathError::InvalidPath
                | eliot_platform_windows::ProtectedPathError::InvalidRoot => {
                    ScanDisclosureReadFailure::Replaced
                }
                _ => ScanDisclosureReadFailure::Inaccessible,
            })
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
    fn initial_bind_scope_discovery(
        &self,
        request: &ScanDisclosureOwnerRequest,
    ) -> Result<ScanDisclosureOwnerValue, TransportError> {
        let ScanDisclosureOwnerAction::InitialBindScopeDiscovery {
            evidence,
            envelope,
            explicit_root,
            root_identity_ref,
            allowed_reads,
        } = &request.action
        else {
            return Err(TransportError::SessionFenced);
        };
        if request.application_connection_id != envelope.connection_id
            || request.activation_ticket_id != evidence.ticket_id
            || envelope.validate().is_err()
            || evidence.validate().is_err()
            || explicit_root.trim().is_empty()
            || explicit_root.chars().any(char::is_control)
            || root_identity_ref.trim().is_empty()
            || root_identity_ref.chars().any(char::is_control)
            || !matches!(
                allowed_reads.as_slice(),
                [DiscoveryRead::FilesystemIdentity, DiscoveryRead::GoverningSourceCandidates]
                    | [
                        DiscoveryRead::FilesystemIdentity,
                        DiscoveryRead::GoverningSourceCandidates,
                        DiscoveryRead::VcsIdentity
                    ]
                    | [
                        DiscoveryRead::FilesystemIdentity,
                        DiscoveryRead::GoverningSourceCandidates,
                        DiscoveryRead::ManifestNamesAndHashes
                    ]
                    | [
                        DiscoveryRead::FilesystemIdentity,
                        DiscoveryRead::GoverningSourceCandidates,
                        DiscoveryRead::VcsIdentity,
                        DiscoveryRead::ManifestNamesAndHashes
                    ]
            )
        {
            return Err(TransportError::SessionFenced);
        }

        // Hold the activation transition read through the immutable lifecycle
        // first-issue CAS/readback so the accepted result and P-07 projection
        // cannot move between proof validation and lease retention.
        let _transition = self.agent_bridge_transition_read()?;
        let pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if !self.pre_scope_bind_scope_evidence_still_retained_in(
            &pending,
            evidence.as_ref(),
            envelope.as_ref(),
        ) {
            return Err(TransportError::SessionFenced);
        }
        let local = pending
            .results
            .get(&evidence.ticket_id)
            .ok_or(TransportError::SessionFenced)?;
        if local.phase != AgentActivationResultPhase::AcceptedTerminal
            || local.result.bind_scope_evidence.as_ref() != Some(evidence.as_ref())
        {
            return Err(TransportError::SessionFenced);
        }
        let local_result = local.result.clone();
        let pending_entry = pending.entries.get(&evidence.ticket_id).cloned();
        drop(pending);

        let (ticket, result) = self.load_scan_disclosure_activation_payloads(
            &request.application_connection_id,
            &request.activation_ticket_id,
            &local_result,
        )?;
        evidence
            .validate_against(&ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        if result != local_result
            || !matches!(
                &result.disposition,
                eliot_protocol::AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
            )
            || super::unix_ms() > ticket.kernel_deadline_unix_ms
        {
            return Err(TransportError::IdentityConflict);
        }
        let (session_epoch, activated_binding) = self.validate_scan_disclosure_accepted_connection(
            &request.application_connection_id,
            &ticket,
            pending_entry.as_ref(),
        )?;
        if session_epoch.is_some() || activated_binding.is_some() {
            return Err(TransportError::SessionFenced);
        }
        let Some(ticket_root) = ticket.workspace_selector.as_deref() else {
            return Ok(ScanDisclosureOwnerValue::InitialBindScopeRootRequired { ticket });
        };
        if ticket_root != explicit_root {
            return Err(TransportError::IdentityConflict);
        }

        let consumption_limit = u32::try_from(allowed_reads.len())
            .map_err(|_| TransportError::SessionFenced)?;
        let lease_request = DiscoveryLeaseRequest {
            proposer_ref: evidence.principal_id.clone(),
            session_ref: evidence.session_id.clone(),
            host_ref: ticket.peer_admission_receipt_sha256.clone(),
            candidate_root_ref: root_identity_ref.clone(),
            root_filesystem_identity_ref: root_identity_ref.clone(),
            allowed_reads: allowed_reads.clone(),
            consumption_limit,
            deadline: ticket.kernel_deadline_unix_ms,
        };
        let issued = issue_discovery_lease(&lease_request)
            .map_err(|_| TransportError::SessionFenced)?;
        issued
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if issued.deadline != evidence.ticket_deadline_unix_ms
            || issued.proposer_ref != evidence.principal_id
            || issued.session_ref != evidence.session_id
            || issued.host_ref != ticket.peer_admission_receipt_sha256
            || issued.root_filesystem_identity_ref != *root_identity_ref
            || issued.candidate_root_ref != *root_identity_ref
            || issued.allowed_reads != *allowed_reads
        {
            return Err(TransportError::IdentityConflict);
        }

        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(&ticket.ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let result_sha256 = lifecycle
            .result_sha256
            .as_deref()
            .ok_or(TransportError::SessionFenced)?;
        if lifecycle.state != eliot_ors::ActivationLifecycleState::ResultAccepted
            || lifecycle.ticket_id != ticket.ticket_id
            || lifecycle.ticket_sha256 != ticket.ticket_sha256
            || lifecycle.connection_id != ticket.connection_id
            || lifecycle.kernel_deadline_unix_ms != ticket.kernel_deadline_unix_ms
        {
            return Err(TransportError::IdentityConflict);
        }
        let lease_bytes = eliot_contracts::canonical_json_bytes(&issued)
            .map_err(|_| TransportError::SessionFenced)?;
        let lease_json = String::from_utf8(lease_bytes).map_err(|_| TransportError::SessionFenced)?;
        let retained = self
            .generation_gateway
            .ors
            .retain_initial_discovery_lease(&ticket.ticket_id, &ticket.ticket_sha256, &lease_json)
            .map_err(|error| match error {
                eliot_ors::OrsError::DuplicateConflict => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?;
        let mut expected_lifecycle = lifecycle.clone();
        expected_lifecycle.initial_discovery_lease = Some(lease_json.clone());
        if retained != expected_lifecycle || retained.result_sha256.as_deref() != Some(result_sha256) {
            return Err(TransportError::IdentityConflict);
        }
        let retained_ticket = serde_json::from_str::<
            eliot_protocol::AgentActivationResolutionTicket,
        >(&retained.ticket_payload)
        .map_err(|_| TransportError::SessionFenced)?;
        let retained_lease = serde_json::from_str::<DiscoveryReadLease>(
            retained
                .initial_discovery_lease
                .as_deref()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if retained_ticket != ticket || retained_lease != issued {
            return Err(TransportError::IdentityConflict);
        }
        if super::unix_ms() > ticket.kernel_deadline_unix_ms {
            return Err(TransportError::Timeout);
        }
        Ok(ScanDisclosureOwnerValue::InitialBindScopeDiscovery {
            ticket: retained_ticket,
            lease: retained_lease,
        })
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
            ScanDisclosureOwnerAction::IssueContour
                | ScanDisclosureOwnerAction::IssueBinding
                | ScanDisclosureOwnerAction::RetainDiscoveryLease { .. }
                | ScanDisclosureOwnerAction::RetainScanEvidence { .. }
                | ScanDisclosureOwnerAction::ReadinessClaim { .. }
                | ScanDisclosureOwnerAction::ReadinessPublish { .. }
                | ScanDisclosureOwnerAction::ReadinessLoad { .. }
                | ScanDisclosureOwnerAction::ReadinessLoadForBinding { .. }
        ) {
            if super::unix_ms() > current.ticket.kernel_deadline_unix_ms {
                return Err(TransportError::Timeout);
            }
            return Ok(());
        }
        self.require_active_scan_disclosure_session(current, connection_id)
    }

    #[cfg(windows)]
    async fn apply_scan_disclosure_owner_action(
        &self,
        current: &CurrentScanDisclosureActivation,
        action: ScanDisclosureOwnerAction,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        match action {
            ScanDisclosureOwnerAction::InitialBindScopeDiscovery { .. } => {
                Err(TransportError::SessionFenced.into())
            }
            ScanDisclosureOwnerAction::IssueContour => {
                let contour = self.issue_scan_disclosure_contour(current)?;
                Ok(ScanDisclosureOwnerValue::Contour { contour })
            }
            ScanDisclosureOwnerAction::IssueBinding => {
                let binding = self.issue_scan_disclosure_binding(current).await?;
                Ok(ScanDisclosureOwnerValue::Binding { binding })
            }
            ScanDisclosureOwnerAction::RetainDiscoveryLease {
                expected_owner_revision,
                lease,
                snapshot,
            } => {
                self.retain_discovery_lease(
                    current,
                    expected_owner_revision,
                    lease.as_ref(),
                    snapshot.as_ref(),
                )
                .await
            }
            ScanDisclosureOwnerAction::RetainScanEvidence {
                expected_owner_revision,
                discovery_lease,
                evidence,
                binding,
                receipt_handle,
                snapshot,
            } => {
                self.retain_scan_evidence(
                    current,
                    expected_owner_revision,
                    discovery_lease.as_ref(),
                    evidence.as_ref(),
                    &binding,
                    receipt_handle.as_ref(),
                    snapshot.as_ref(),
                )
                .await
            }
            ScanDisclosureOwnerAction::Stage { binding, record } => {
                self.stage_scan_disclosure_owner(current, &binding, record.as_ref())
                    .await
            }
            ScanDisclosureOwnerAction::Commit {
                binding,
                operation_key,
                request_hash,
                writer_receipt,
            } => {
                self.commit_scan_disclosure_owner(
                    current,
                    &binding,
                    &operation_key,
                    &request_hash,
                    &writer_receipt,
                )
                .await
            }
            ScanDisclosureOwnerAction::Load {
                binding,
                operation_key,
            } => {
                self.load_scan_disclosure_owner(current, &binding, &operation_key)
                    .await
            }
            ScanDisclosureOwnerAction::Retire {
                binding,
                operation_key,
                request_hash,
                policy_revision,
                successor_ref,
            } => {
                self.retire_scan_disclosure_owner(
                    current,
                    &binding,
                    &operation_key,
                    &request_hash,
                    policy_revision,
                    successor_ref.as_deref(),
                )
                .await
            }
            ScanDisclosureOwnerAction::List { binding, limit } => {
                self.list_scan_disclosure_owner(current, &binding, limit)
                    .await
            }
            ScanDisclosureOwnerAction::QuarantineRetain { binding, record } => {
                self.retain_scan_disclosure_quarantine_owner(current, &binding, record.as_ref())
                    .await
            }
            ScanDisclosureOwnerAction::QuarantineLoad {
                binding,
                quarantine_key,
            } => {
                self.load_scan_disclosure_quarantine_owner(
                    current,
                    &binding,
                    &quarantine_key,
                )
                .await
            }
            ScanDisclosureOwnerAction::ReadinessClaim { key } => {
                self.claim_cold_start_readiness_owner(current, key.as_ref())
                    .await
            }
            ScanDisclosureOwnerAction::ReadinessPublish {
                record_key,
                binding_digest,
                lease_ref,
                disposition,
                receipt_ref,
                receipt_bytes,
            } => {
                self.publish_cold_start_readiness_owner(
                    current,
                    &record_key,
                    &binding_digest,
                    &lease_ref,
                    disposition,
                    &receipt_ref,
                    &receipt_bytes,
                )
                .await
            }
            ScanDisclosureOwnerAction::ReadinessLoad { record_key } => {
                self.load_cold_start_readiness_owner(current, &record_key)
                    .await
            }
            ScanDisclosureOwnerAction::ReadinessLoadForBinding { binding_digest } => {
                self.load_cold_start_readiness_owner_for_binding(current, &binding_digest)
                    .await
            }
        }
    }

    #[cfg(windows)]
    async fn claim_cold_start_readiness_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        key: &ColdStartReadinessOwnerKey,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let (record, owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, true).await?;
        self.recheck_scan_disclosure_activation(current)?;
        if record.revision != snapshot.owner_revision {
            return Err(TransportError::IdentityConflict.into());
        }
        let (sources, privacy) = owner
            .read_current_source_closure(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if sources != inputs.governing_sources || privacy != inputs.privacy {
            return Err(TransportError::IdentityConflict.into());
        }
        let binding = inputs
            .scan_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let evidence = inputs
            .scan_evidence
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let receipt_handle = inputs.scan_receipt_handle.as_ref().ok_or(
            ScanDisclosureOwnerActionError::ReceiptRead(ScanDisclosureReadFailure::Missing),
        )?;
        let discovery = inputs
            .bootstrap_discovery_inputs
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let wire_binding = Self::wire_binding(binding);
        self.validate_scan_disclosure_binding(current, &wire_binding)
            .await?;
        self.validate_scan_receipt_handle(
            current,
            &wire_binding,
            &discovery.scan_ref,
            evidence,
            receipt_handle,
        )?;
        let expected_key = Self::expected_cold_start_readiness_key(
            current, &snapshot, &inputs, &sources, &binding, evidence,
        )?;
        if &expected_key != key {
            return Err(TransportError::IdentityConflict.into());
        }
        let lease_deadline = inputs
            .discovery_lease
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .deadline;
        let outcome = self
            .p07_ors
            .claim_cold_start_readiness(key, lease_deadline, super::unix_ms())
            .map_err(|_| TransportError::SessionFenced)?;
        match &outcome {
            ColdStartReadinessStageOutcome::Stored { record }
            | ColdStartReadinessStageOutcome::AlreadyBound { record } => {
                Self::validate_cold_start_readiness_record(current, record)?;
                if !record.claim.key.eq(key) {
                    return Err(TransportError::IdentityConflict.into());
                }
            }
        }
        Ok(ScanDisclosureOwnerValue::ReadinessClaimed { outcome })
    }

    #[cfg(windows)]
    async fn validated_current_cold_start_owner_key(
        &self,
        current: &CurrentScanDisclosureActivation,
    ) -> Result<(ColdStartReadinessOwnerKey, u64), ScanDisclosureOwnerActionError> {
        let (record, owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, true).await?;
        self.recheck_scan_disclosure_activation(current)?;
        if record.revision != snapshot.owner_revision {
            return Err(TransportError::IdentityConflict.into());
        }
        let (sources, privacy) = owner
            .read_current_source_closure(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if sources != inputs.governing_sources || privacy != inputs.privacy {
            return Err(TransportError::IdentityConflict.into());
        }
        let binding = inputs
            .scan_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let evidence = inputs
            .scan_evidence
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let receipt_handle = inputs.scan_receipt_handle.as_ref().ok_or(
            ScanDisclosureOwnerActionError::ReceiptRead(ScanDisclosureReadFailure::Missing),
        )?;
        let discovery = inputs
            .bootstrap_discovery_inputs
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let wire_binding = Self::wire_binding(binding);
        self.validate_scan_disclosure_binding(current, &wire_binding)
            .await?;
        self.validate_scan_receipt_handle(
            current,
            &wire_binding,
            &discovery.scan_ref,
            evidence,
            receipt_handle,
        )?;
        let key = Self::expected_cold_start_readiness_key(
            current, &snapshot, &inputs, &sources, binding, evidence,
        )?;
        let deadline = inputs
            .discovery_lease
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .deadline;
        self.recheck_scan_disclosure_activation(current)?;
        Ok((key, deadline))
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    async fn publish_cold_start_readiness_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        record_key: &str,
        binding_digest: &str,
        lease_ref: &str,
        disposition: ColdStartReadinessTerminalDisposition,
        receipt_ref: &str,
        receipt_bytes: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let existing = self
            .p07_ors
            .load_cold_start_readiness(record_key)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::IdentityConflict)?;
        Self::validate_cold_start_readiness_record(current, &existing)?;
        let (expected_key, _) = self.validated_current_cold_start_owner_key(current).await?;
        if existing.claim.binding_digest != binding_digest
            || existing.claim.lease_ref != lease_ref
            || existing.claim.key != expected_key
        {
            return Err(TransportError::IdentityConflict.into());
        }
        let record = self
            .p07_ors
            .publish_cold_start_readiness(
                record_key,
                binding_digest,
                lease_ref,
                disposition,
                receipt_ref,
                receipt_bytes,
            )
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::IdentityConflict)?;
        Self::validate_cold_start_readiness_record(current, &record)?;
        Ok(ScanDisclosureOwnerValue::ReadinessRecord {
            record: Some(record),
        })
    }

    #[cfg(windows)]
    async fn load_cold_start_readiness_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        record_key: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let record = self
            .p07_ors
            .load_cold_start_readiness(record_key)
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(record) = record.as_ref() {
            Self::validate_cold_start_readiness_record(current, record)?;
            if record.record_key != record_key {
                return Err(TransportError::IdentityConflict.into());
            }
            let (expected_key, _) = self.validated_current_cold_start_owner_key(current).await?;
            if record.claim.key != expected_key {
                return Err(TransportError::IdentityConflict.into());
            }
        }
        Ok(ScanDisclosureOwnerValue::ReadinessRecord { record })
    }

    #[cfg(windows)]
    async fn load_cold_start_readiness_owner_for_binding(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding_digest: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let (expected_key, _) = self.validated_current_cold_start_owner_key(current).await?;
        if expected_key
            .binding_digest()
            .map_err(|_| TransportError::SessionFenced)?
            != binding_digest
        {
            return Err(TransportError::IdentityConflict.into());
        }
        let record = self
            .p07_ors
            .load_cold_start_readiness_for_binding(binding_digest)
            .map_err(|_| TransportError::SessionFenced)?;
        if let Some(record) = record.as_ref() {
            Self::validate_cold_start_readiness_record(current, record)?;
            if record.claim.binding_digest != binding_digest {
                return Err(TransportError::IdentityConflict.into());
            }
            if record.claim.key != expected_key {
                return Err(TransportError::IdentityConflict.into());
            }
        }
        Ok(ScanDisclosureOwnerValue::ReadinessRecord { record })
    }

    #[cfg(windows)]
    fn validate_cold_start_readiness_key(
        current: &CurrentScanDisclosureActivation,
        key: &eliot_ors::ColdStartReadinessOwnerKey,
    ) -> Result<(), TransportError> {
        key.validate().map_err(|_| TransportError::SessionFenced)?;
        if key.installation_id != current.installation_id
            || key.state_fence != current.ticket.state_fence
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn validate_cold_start_readiness_record(
        current: &CurrentScanDisclosureActivation,
        record: &ColdStartReadinessOrsRecord,
    ) -> Result<(), TransportError> {
        record
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_cold_start_readiness_key(current, &record.claim.key)?;
        if super::unix_ms() > record.claim.lease_deadline {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    #[cfg(windows)]
    async fn stage_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
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
            Err(_) => Err(TransportError::SessionFenced.into()),
        }
    }

    #[cfg(windows)]
    async fn commit_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        if operation_key != binding.operation_key().as_str()
            || request_hash.trim().is_empty()
            || writer_receipt.trim().is_empty()
        {
            return Err(TransportError::IdentityConflict.into());
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
    async fn load_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        if operation_key != binding.operation_key().as_str() {
            return Err(TransportError::IdentityConflict.into());
        }
        let record = self
            .p07_ors
            .load_scan_disclosure(operation_key)
            .map_err(|error| {
                ScanDisclosureOwnerActionError::ReceiptRead(
                    Self::scan_disclosure_read_failure(error),
                )
            })?;
        if let Some(record) = record.as_ref() {
            if Self::validate_record_binding(current, binding, record).is_err() {
                return Err(ScanDisclosureOwnerActionError::ReceiptRead(
                    ScanDisclosureReadFailure::Replaced,
                ));
            }
        }
        Ok(ScanDisclosureOwnerValue::Record { record })
    }

    #[cfg(windows)]
    fn scan_disclosure_read_failure(error: eliot_ors::OrsError) -> ScanDisclosureReadFailure {
        match error {
            eliot_ors::OrsError::ScanDisclosureReadFailure(failure) => failure,
            eliot_ors::OrsError::IntegrityProblem { record_type, .. }
                if record_type == eliot_ors::SCAN_DISCLOSURE_RECORD_TYPE =>
            {
                ScanDisclosureReadFailure::Corrupt
            }
            eliot_ors::OrsError::MigrationRequired { .. } => ScanDisclosureReadFailure::Stale,
            eliot_ors::OrsError::InvalidField {
                field: "scan_disclosure_cancellation_ref",
                ..
            } => ScanDisclosureReadFailure::Stale,
            eliot_ors::OrsError::StagingCommitOutcomeUnknown { .. } => {
                ScanDisclosureReadFailure::UnknownCommit
            }
            eliot_ors::OrsError::StoreContract(error) => match *error {
                eliot_store_api::StoreError::Unavailable => ScanDisclosureReadFailure::Inaccessible,
                eliot_store_api::StoreError::UnknownOutcome { .. }
                | eliot_store_api::StoreError::MissingReceiptEnvelope => {
                    ScanDisclosureReadFailure::UnknownCommit
                }
                _ => ScanDisclosureReadFailure::Corrupt,
            },
            eliot_ors::OrsError::Storage(_) => ScanDisclosureReadFailure::Inaccessible,
            eliot_ors::OrsError::PayloadIntegrityMismatch
            | eliot_ors::OrsError::UnsupportedContractVersion(_)
            | eliot_ors::OrsError::InvalidField { .. }
            | eliot_ors::OrsError::Encoding(_) => ScanDisclosureReadFailure::Corrupt,
            _ => ScanDisclosureReadFailure::Inaccessible,
        }
    }

    #[cfg(windows)]
    async fn retire_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        if operation_key != binding.operation_key().as_str()
            || policy_revision != binding.policy_revision
            || request_hash.trim().is_empty()
        {
            return Err(TransportError::IdentityConflict.into());
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
    async fn list_scan_disclosure_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        limit: u16,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        if limit == 0 || limit > eliot_ors::MAX_SCAN_DISCLOSURE_PAGE {
            return Err(TransportError::SessionFenced.into());
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

    #[cfg(windows)]
    async fn retain_scan_disclosure_quarantine_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        record: &ScanDisclosureQuarantineRecord,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        let contour = self.issue_scan_disclosure_contour(current)?;
        Self::validate_scan_disclosure_quarantine_record(&contour, record)?;
        let retained = self
            .p07_ors
            .retain_scan_disclosure_quarantine(record)
            .map_err(|error| match error {
                eliot_ors::OrsError::DuplicateConflict
                | eliot_ors::OrsError::PayloadIntegrityMismatch
                | eliot_ors::OrsError::IntegrityProblem {
                    record_type: eliot_ors::SCAN_DISCLOSURE_QUARANTINE_RECORD_TYPE,
                    ..
                } => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?;
        Self::validate_scan_disclosure_quarantine_record(&contour, &retained)?;
        if !retained.same_binding(record) {
            return Err(TransportError::IdentityConflict.into());
        }
        Ok(ScanDisclosureOwnerValue::QuarantineRecord {
            record: Some(retained),
        })
    }

    #[cfg(windows)]
    async fn load_scan_disclosure_quarantine_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        quarantine_key: &str,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        self.validate_scan_disclosure_binding(current, binding)
            .await?;
        let contour = self.issue_scan_disclosure_contour(current)?;
        let key_prefix = format!("scan-disclosure-quarantine:{}:", contour.installation_id);
        if !quarantine_key.starts_with(&key_prefix) {
            return Err(TransportError::IdentityConflict.into());
        }
        let record = self
            .p07_ors
            .load_scan_disclosure_quarantine(quarantine_key)
            .map_err(|error| match error {
                eliot_ors::OrsError::IntegrityProblem { .. }
                | eliot_ors::OrsError::PayloadIntegrityMismatch => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?;
        if let Some(record) = record.as_ref() {
            Self::validate_scan_disclosure_quarantine_record(&contour, record)?;
            if record.quarantine_key != quarantine_key {
                return Err(TransportError::IdentityConflict.into());
            }
        }
        Ok(ScanDisclosureOwnerValue::QuarantineRecord { record })
    }

    #[cfg(windows)]
    fn validate_scan_disclosure_quarantine_record(
        contour: &InstallationScanContour,
        record: &ScanDisclosureQuarantineRecord,
    ) -> Result<(), TransportError> {
        record.validate().map_err(|error| match error {
            eliot_ors::OrsError::IntegrityProblem { .. }
            | eliot_ors::OrsError::PayloadIntegrityMismatch
            | eliot_ors::OrsError::DuplicateConflict => TransportError::IdentityConflict,
            _ => TransportError::SessionFenced,
        })?;
        let basename_stem = record
            .file_name
            .strip_prefix(eliot_workscope::LOOSE_SCAN_DISCLOSURE_PREFIX)
            .and_then(|name| name.strip_suffix(eliot_workscope::LOOSE_SCAN_DISCLOSURE_SUFFIX));
        if record.installation_id != contour.installation_id
            || record.ors_generation != contour.ors_generation
            || record.file_name.contains('/')
            || record.file_name.contains('\\')
            || !basename_stem.is_some_and(|value| {
                !value.is_empty() && value.len() <= 200 && !value.chars().any(char::is_control)
            })
            || eliot_workscope::quarantine_loose_scan_disclosure(&record.file_name).is_err()
        {
            return Err(TransportError::IdentityConflict);
        }
        let expected_writer_receipt = format!(
            "ors:{}:{}:{}:{}",
            contour.ors_object_ref,
            contour.ors_generation,
            record.quarantine_key,
            record.request_hash
        );
        if record.writer_receipt != expected_writer_receipt {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
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
        initial_proof: Option<&InitialBindScopeOwnerProof>,
    ) -> Result<CurrentScanDisclosureActivation, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        let (local_result, pending_entry) =
            self.retained_scan_disclosure_activation_result(ticket_id, initial_proof.is_some())?;
        let (ticket, result) =
            self.load_scan_disclosure_activation_payloads(connection_id, ticket_id, &local_result)?;
        let binding = result.resolved_binding().map(|value| (*value).clone());
        let initial_bind_scope_proof = if let Some(proof) = initial_proof {
            if binding.is_some()
                || proof.evidence.ticket_id != ticket.ticket_id
                || proof.evidence.ticket_sha256 != ticket.ticket_sha256
                || proof.envelope.connection_id != connection_id
            {
                return Err(TransportError::SessionFenced);
            }
            let pending = self
                .agent_activation_pending
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if !self.pre_scope_bind_scope_evidence_still_retained_in(
                &pending,
                &proof.evidence,
                &proof.envelope,
            ) || local_result.bind_scope_evidence.as_ref() != Some(&proof.evidence)
                || !matches!(
                    &result.disposition,
                    eliot_protocol::AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
                )
            {
                return Err(TransportError::SessionFenced);
            }
            Some(proof.clone())
        } else {
            if binding.is_none() {
                return Err(TransportError::SessionFenced);
            }
            None
        };
        let (session_epoch, activated_binding) = self
            .validate_scan_disclosure_accepted_connection(
                connection_id,
                &ticket,
                pending_entry.as_ref(),
            )?;
        if initial_bind_scope_proof.is_some()
            && (session_epoch.is_some() || activated_binding.is_some())
        {
            return Err(TransportError::SessionFenced);
        }
        let (kernel_owner_revision, kernel_owner_bundle_sha256) = self
            .current_scan_disclosure_owner_revision(
                &ticket,
                &result,
                binding.as_ref(),
                pending_entry.as_ref(),
                activated_binding.as_ref(),
                initial_bind_scope_proof.as_ref(),
            )?;
        let installation_id = super::dispatch_contour()
            .map(|contour| contour.installation_id().to_owned())
            .filter(|identity| !identity.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        let activation_request_identity = pending_entry
            .as_ref()
            .map(|entry| entry.request.request_identity.clone());
        if let Some(identity) = &activation_request_identity {
            identity
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            if identity.request.state_fence != ticket.state_fence {
                return Err(TransportError::IdentityConflict);
            }
        }
        let (principal_id, session_id, task_id, task_revision, work_scope_id) =
            if let Some(binding) = &binding {
                (
                    binding.principal_id.clone(),
                    binding.session_id.clone(),
                    binding.task_id.clone(),
                    binding.task_revision.value(),
                    binding.work_scope_id.clone(),
                )
            } else {
                let evidence = &initial_bind_scope_proof
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?
                    .evidence;
                (
                    evidence.principal_id.clone(),
                    evidence.session_id.clone(),
                    evidence.task_id.clone(),
                    evidence.task_revision,
                    evidence.work_scope_id.clone(),
                )
            };
        Ok(CurrentScanDisclosureActivation {
            binding,
            initial_bind_scope_proof,
            principal_id,
            session_id,
            task_id,
            task_revision,
            work_scope_id,
            ticket,
            result,
            activation_request_identity,
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
        allow_initial: bool,
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
            || (!allow_initial && local.result.resolved_binding().is_none())
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
        binding: Option<&eliot_protocol::AgentActivationResolvedBinding>,
        pending_entry: Option<&super::AgentActivationPending>,
        activated_binding: Option<&super::ActivatedApplicationBinding>,
        initial_proof: Option<&InitialBindScopeOwnerProof>,
    ) -> Result<(u64, String), TransportError> {
        let owner_readback = pending_entry.and_then(|entry| entry.owner_readback.as_ref());
        if let (Some(readback), Some(binding)) = (owner_readback, binding) {
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
        let (kernel_owner_revision, kernel_owner_bundle_sha256) = if let Some(proof) = initial_proof {
            (
                proof.evidence.kernel_owner.revision,
                proof.evidence.kernel_owner.bundle_sha256.clone(),
            )
        } else if let Some(readback) = owner_readback {
            let kernel_owner = readback
                .kernel_owner
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            kernel_owner
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            (kernel_owner.revision, kernel_owner.bundle_sha256.clone())
        } else if let (Some(active), Some(binding)) = (activated_binding, binding) {
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
            || initial_proof.is_some_and(|proof| {
                proof.evidence.kernel_owner.revision != kernel_owner_revision
                    || proof.evidence.kernel_owner.bundle_sha256 != kernel_owner_bundle_sha256
            })
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
        let binding = current.binding.as_ref().ok_or(TransportError::SessionFenced)?;
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
            || retained.resolved_binding != *binding
            || retained.principal_id != binding.principal_id
            || retained.session_id != binding.session_id
            || retained.task_id != binding.task_id
            || retained.work_scope_id != binding.work_scope_id
            || retained.task_revision.value() != binding.task_revision.value()
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
            .get(&binding.session_id)
            .ok_or(TransportError::SessionFenced)?;
        if application.session_id() != binding.session_id
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
        &self,
        current: &CurrentScanDisclosureActivation,
    ) -> Result<InstallationScanContour, TransportError> {
        let host_binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(TransportError::PlanGap {
                dependency: "kernel.host_installation_ors_binding",
                reason: "this ORS composition has no Host installation binding",
            })?;
        if host_binding.installation_id() != current.installation_id {
            return Err(TransportError::SessionFenced);
        }

        let identity = self
            .p07_ors
            .installed_store_identity()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.installation_id() != current.installation_id {
            return Err(TransportError::SessionFenced);
        }

        let ors_object_ref = self
            .ors_object_path
            .to_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?
            .to_owned();
        Ok(InstallationScanContour {
            installation_id: current.installation_id.clone(),
            ors_object_ref,
            ors_generation: identity.ors_generation(),
        })
    }

    #[cfg(windows)]
    async fn load_retained_work_scope_owner(
        &self,
        current: &CurrentScanDisclosureActivation,
        require_discovery_lease: bool,
    ) -> Result<
        (
            RecoveryRecord,
            WorkScopeBindingOwner,
            WorkScopeBindingSnapshot,
            ColdStartOwnerInputs,
        ),
        TransportError,
    > {
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .as_ref()
            .cloned()
            .ok_or(TransportError::PlanGap {
                dependency: "kernel.canonical_store_recovery_gateway",
                reason: "the retained canonical Store recovery owner is unavailable",
            })?;
        let work_scope_key = RecoveryRecordKey::new("owner", "work_scope")
            .map_err(|_| TransportError::SessionFenced)?;
        let policy_key =
            RecoveryRecordKey::new("owner", "policy").map_err(|_| TransportError::SessionFenced)?;
        let recovery = gateway
            .recovery(StoreRecoveryRequest {
                contract_version: eliot_store_api::CONTRACT_VERSION,
                state_fence: current.ticket.state_fence.clone(),
                records: vec![work_scope_key.clone(), policy_key.clone()],
                include_receipts: false,
                include_jobs: false,
            })
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        recovery
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if recovery.state_fence != current.ticket.state_fence
            || recovery.canonical_scope.state_fence != current.ticket.state_fence
            || recovery.owner_records.len() != 2
            || !recovery.job_records.is_empty()
            || !recovery.receipts.is_empty()
        {
            return Err(TransportError::IdentityConflict);
        }
        // Recovery enumeration order is not an identity contract. Resolve
        // each requested owner row independently before consuming the vector.
        let record = recovery
            .owner_records
            .iter()
            .find(|record| record.record_key() == work_scope_key)
            .cloned()
            .ok_or(TransportError::SessionFenced)?;
        let policy_record = recovery
            .owner_records
            .iter()
            .find(|record| record.record_key() == policy_key)
            .cloned()
            .ok_or(TransportError::SessionFenced)?;
        if record.record_key() != work_scope_key
            || record.state_fence != current.ticket.state_fence
            || record.schema != WORK_SCOPE_OWNER_SNAPSHOT_SCHEMA
            || policy_record.record_key() != policy_key
            || policy_record.state_fence != current.ticket.state_fence
            || policy_record.schema != WORK_SCOPE_OWNER_SNAPSHOT_SCHEMA
        {
            return Err(TransportError::IdentityConflict);
        }
        let snapshot: WorkScopeBindingSnapshot =
            serde_json::from_slice(&record.payload).map_err(|_| TransportError::SessionFenced)?;
        let canonical = eliot_contracts::canonical_json_bytes(&snapshot)
            .map_err(|_| TransportError::SessionFenced)?;
        if canonical != record.payload
            || snapshot.state_fence != current.ticket.state_fence
            || snapshot.owner_revision != record.revision
            || snapshot.binding.scope.scope_ref != current.work_scope_id()
        {
            return Err(TransportError::IdentityConflict);
        }
        let owner = WorkScopeBindingOwner::from_snapshot(snapshot.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        owner
            .read_current(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        owner
            .read_current_source_closure(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        let cold_start_inputs = if require_discovery_lease {
            owner.read_current_cold_start_inputs_from_owner(
                &current.ticket.state_fence,
                current.principal_id(),
                current.session_id(),
                &snapshot.binding.scope.root_identity,
                super::unix_ms(),
            )
        } else {
            owner.read_current_cold_start_admission(
                &current.ticket.state_fence,
                current.principal_id(),
                current.session_id(),
                &snapshot.binding.scope.root_identity,
                super::unix_ms(),
            )
        }
        .map_err(|_| TransportError::SessionFenced)?;
        if let Some(proof) = &current.initial_bind_scope_proof {
            let evidence = &proof.evidence;
            let lifecycle = self
                .generation_gateway
                .ors
                .load_activation_lifecycle(&current.ticket.ticket_id)
                .map_err(|_| TransportError::SessionFenced)?
                .ok_or(TransportError::SessionFenced)?;
            let retained_initial_lease = lifecycle
                .initial_discovery_lease
                .as_deref()
                .ok_or(TransportError::SessionFenced)?;
            let original_lease = serde_json::from_str::<DiscoveryReadLease>(retained_initial_lease)
                .map_err(|_| TransportError::SessionFenced)?;
            original_lease
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            let current_lease = cold_start_inputs.discovery_lease.as_ref();
            let original_bootstrap = cold_start_inputs
                .bootstrap_discovery_inputs
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            let current_lease_conflicts = current_lease.is_some_and(|lease| {
                lease.lease_ref != original_lease.lease_ref
                    || lease.proposer_ref != original_lease.proposer_ref
                    || lease.session_ref != original_lease.session_ref
                    || lease.host_ref != original_lease.host_ref
                    || lease.root_filesystem_identity_ref
                        != original_lease.root_filesystem_identity_ref
                    || lease.candidate_root_ref != original_lease.candidate_root_ref
                    || lease.allowed_reads != original_lease.allowed_reads
                    || lease.deadline != original_lease.deadline
                    || lease.consumption_limit != original_lease.consumption_limit
                    || lease.consumed > original_lease.consumption_limit
            });
            let scan_lease_consumption_conflicts = cold_start_inputs
                .scan_binding
                .as_ref()
                .is_some_and(|binding| {
                    current_lease.is_none_or(|lease| {
                        binding.lease_consumed != u64::from(lease.consumed)
                    })
                });
            if lifecycle.state != eliot_ors::ActivationLifecycleState::ResultAccepted
                || lifecycle.ticket_id != current.ticket.ticket_id
                || lifecycle.ticket_sha256 != current.ticket.ticket_sha256
                || lifecycle.connection_id != current.ticket.connection_id
                || lifecycle.result_sha256.as_deref()
                    != Some(current.result.result_sha256.as_str())
                || lifecycle.kernel_deadline_unix_ms != evidence.ticket_deadline_unix_ms
                || lifecycle.initial_discovery_lease.as_deref() != Some(retained_initial_lease)
                || original_lease.proposer_ref != evidence.principal_id
                || original_lease.session_ref != evidence.session_id
                || original_lease.host_ref != current.ticket.peer_admission_receipt_sha256
                || original_lease.root_filesystem_identity_ref
                    != original_bootstrap.evidence.filesystem_identity_ref
                || original_bootstrap.evidence.canonical_root_ref
                    != original_lease.candidate_root_ref
                || original_lease.candidate_root_ref != cold_start_inputs.explicit_root_identity
                || original_lease.deadline != evidence.ticket_deadline_unix_ms
                || original_lease.allowed_reads
                    != original_bootstrap.evidence.attested_reads
                || original_lease.consumed != 0
                || (require_discovery_lease && current_lease.is_none())
                || current_lease_conflicts
                || scan_lease_consumption_conflicts
                || (current_lease.is_none()
                    && (cold_start_inputs.scan_evidence.is_some()
                        || cold_start_inputs.scan_receipt_handle.is_some()))
                || cold_start_inputs.task_selection.acceptance_digest != evidence.acceptance_digest
                || cold_start_inputs.task_selection.task_revision != evidence.task_revision
                || cold_start_inputs.task_selection.task_ref != evidence.task_id
                || cold_start_inputs.task_selection.work_scope_ref != evidence.work_scope_id
                || cold_start_inputs.owner_revision != snapshot.owner_revision
                || cold_start_inputs.state_fence != evidence.state_fence
                || cold_start_inputs.principal_ref != evidence.principal_id
                || cold_start_inputs.session_ref != evidence.session_id
                || cold_start_inputs.explicit_root_identity
                    != original_lease.candidate_root_ref
            {
                return Err(TransportError::IdentityConflict);
            }
        }
        let policy_snapshot: serde_json::Value = serde_json::from_slice(&policy_record.payload)
            .map_err(|_| TransportError::SessionFenced)?;
        let policy_canonical = eliot_contracts::canonical_json_bytes(&policy_snapshot)
            .map_err(|_| TransportError::SessionFenced)?;
        let policy_state_fence = policy_snapshot
            .get("state_fence")
            .cloned()
            .ok_or(TransportError::SessionFenced)?;
        let expected_policy_state_fence = serde_json::to_value(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        let policy_revision = policy_snapshot
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or(TransportError::SessionFenced)?;
        let policy_digest = policy_snapshot
            .get("policy_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        let policy_content = policy_snapshot
            .get("snapshot")
            .ok_or(TransportError::SessionFenced)?;
        let policy_owner_ref = policy_content
            .get("policy_owner")
            .and_then(|owner| owner.get("owner_ref"))
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        let policy_content_digest =
            sha256_json(policy_content).map_err(|_| TransportError::SessionFenced)?;
        if policy_canonical != policy_record.payload
            || policy_record.revision != policy_revision
            || policy_state_fence != expected_policy_state_fence
            || policy_revision != cold_start_inputs.policy_revision
            || policy_digest != cold_start_inputs.policy_digest
            || policy_content_digest != cold_start_inputs.policy_digest
            || policy_owner_ref != cold_start_inputs.policy_owner_ref
        {
            return Err(TransportError::IdentityConflict);
        }
        if cold_start_inputs.owner_revision != snapshot.owner_revision
            || cold_start_inputs.state_fence != current.ticket.state_fence
            || cold_start_inputs.principal_ref != current.principal_id()
            || cold_start_inputs.session_ref != current.session_id()
            || cold_start_inputs.task_selection.task_ref != current.task_id()
            || cold_start_inputs.task_selection.work_scope_ref != current.work_scope_id()
            || cold_start_inputs.task_selection.task_revision.to_string()
                != current.task_revision().to_string()
        {
            return Err(TransportError::IdentityConflict);
        }
        if super::unix_ms() > current.ticket.kernel_deadline_unix_ms {
            return Err(TransportError::Timeout);
        }
        Ok((record, owner, snapshot, cold_start_inputs))
    }

    #[cfg(windows)]
    fn child_scan_operation_identity(
        current: &CurrentScanDisclosureActivation,
        namespace: &str,
        owner_revision: u64,
    ) -> Result<(String, String), TransportError> {
        let identity =
            current
                .activation_request_identity
                .as_ref()
                .ok_or(TransportError::PlanGap {
                    dependency: "kernel.retained_original_activation_request_identity",
                    reason: "the accepted activation no longer has its original request identity",
                })?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.state_fence != current.ticket.state_fence || owner_revision == 0 {
            return Err(TransportError::IdentityConflict);
        }
        let request_id = identity.request.metadata.request_id.as_str();
        let source_idempotency_key = identity.idempotency_key.as_str();
        let operation_id = format!(
            "eliot.scan-disclosure.v1/{namespace}/request/{request_id}/idempotency/{source_idempotency_key}/owner-revision/{owner_revision}"
        );
        let idempotency_key = format!(
            "eliot.scan-disclosure.v1/{namespace}/{source_idempotency_key}/owner-revision/{owner_revision}"
        );
        Ok((operation_id, idempotency_key))
    }

    #[cfg(windows)]
    async fn persist_work_scope_owner_revision(
        &self,
        current: &CurrentScanDisclosureActivation,
        expected_owner_revision: u64,
        stage: &str,
        snapshot: WorkScopeBindingSnapshot,
    ) -> Result<u64, TransportError> {
        let next_owner_revision = expected_owner_revision
            .checked_add(1)
            .ok_or(TransportError::SessionFenced)?;
        if snapshot.owner_revision != next_owner_revision
            || snapshot.state_fence != current.ticket.state_fence
        {
            return Err(TransportError::IdentityConflict);
        }
        self.recheck_scan_disclosure_activation(current)?;
        let identity =
            current
                .activation_request_identity
                .as_ref()
                .ok_or(TransportError::PlanGap {
                    dependency: "kernel.retained_original_activation_request_identity",
                    reason: "the accepted activation no longer has its original request identity",
                })?;
        let context = identity.request.metadata.clone();
        if context.state_fence != current.ticket.state_fence {
            return Err(TransportError::IdentityConflict);
        }
        let (operation_id, idempotency_key) =
            Self::child_scan_operation_identity(current, stage, expected_owner_revision)?;
        let payload = eliot_contracts::canonical_json_bytes(&snapshot)
            .map_err(|_| TransportError::SessionFenced)?;
        let owner_record = RecoveryRecord {
            namespace: "owner".to_owned(),
            key: "work_scope".to_owned(),
            state_fence: current.ticket.state_fence.clone(),
            revision: next_owner_revision,
            schema: WORK_SCOPE_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: eliot_contracts::sha256_hex(&payload),
            payload,
        };
        owner_record
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let request = StoreWorkScopeOwnerRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            operation_id: eliot_contracts::OperationId::new(operation_id)
                .map_err(|_| TransportError::SessionFenced)?,
            idempotency_key,
            state_fence: current.ticket.state_fence.clone(),
            protected_snapshot_digest: current.kernel_owner_bundle_sha256.clone(),
            expected_owner_revision,
            owner_record: owner_record.clone(),
            canonical_request_hash: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        request
            .validate_for_context(&context)
            .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .as_ref()
            .cloned()
            .ok_or(TransportError::PlanGap {
                dependency: "kernel.canonical_store_work_scope_owner_gateway",
                reason: "the retained canonical Store WorkScope owner is unavailable",
            })?;
        let response = gateway
            .write_work_scope_owner(&context, request)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if response.record != owner_record {
            return Err(TransportError::IdentityConflict);
        }
        self.recheck_scan_disclosure_activation(current)?;
        let work_scope_key = RecoveryRecordKey::new("owner", "work_scope")
            .map_err(|_| TransportError::SessionFenced)?;
        let recovery = gateway
            .recovery(StoreRecoveryRequest {
                contract_version: eliot_store_api::CONTRACT_VERSION,
                state_fence: current.ticket.state_fence.clone(),
                records: vec![work_scope_key.clone()],
                include_receipts: false,
                include_jobs: false,
            })
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        recovery
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if recovery.state_fence != current.ticket.state_fence
            || recovery.canonical_scope.state_fence != current.ticket.state_fence
            || recovery.owner_records.len() != 1
            || !recovery.job_records.is_empty()
            || !recovery.receipts.is_empty()
        {
            return Err(TransportError::IdentityConflict);
        }
        let readback = recovery
            .owner_records
            .first()
            .ok_or(TransportError::SessionFenced)?;
        if readback != &owner_record {
            return Err(TransportError::IdentityConflict);
        }
        let readback_snapshot: WorkScopeBindingSnapshot =
            serde_json::from_slice(&readback.payload).map_err(|_| TransportError::SessionFenced)?;
        if eliot_contracts::canonical_json_bytes(&readback_snapshot)
            .map_err(|_| TransportError::SessionFenced)?
            != readback.payload
            || readback_snapshot.owner_revision != next_owner_revision
            || readback_snapshot.state_fence != current.ticket.state_fence
            || readback_snapshot.binding.scope.scope_ref != current.work_scope_id()
        {
            return Err(TransportError::IdentityConflict);
        }
        WorkScopeBindingOwner::from_snapshot(readback_snapshot)
            .map_err(|_| TransportError::SessionFenced)?
            .read_current_source_closure(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        self.recheck_scan_disclosure_activation(current)?;
        Ok(next_owner_revision)
    }

    #[cfg(windows)]
    async fn retain_discovery_lease(
        &self,
        current: &CurrentScanDisclosureActivation,
        expected_owner_revision: u64,
        lease: &DiscoveryReadLease,
        proposed_snapshot: &WorkScopeBindingSnapshot,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let (record, owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, false).await?;
        self.recheck_scan_disclosure_activation(current)?;
        if record.revision > expected_owner_revision
            && record.revision - expected_owner_revision == 1
            && snapshot.owner_revision == record.revision
            && inputs.discovery_lease.as_ref() == Some(lease)
            && &snapshot == proposed_snapshot
        {
            return Ok(ScanDisclosureOwnerValue::WorkScopeOwnerRevision {
                owner_revision: record.revision,
                state_fence: record.state_fence,
            });
        }
        if record.revision != expected_owner_revision
            || snapshot.owner_revision != expected_owner_revision
            || inputs.state_fence != current.ticket.state_fence
        {
            return Err(TransportError::IdentityConflict.into());
        }
        if inputs.discovery_lease.as_ref() == Some(lease) && &snapshot == proposed_snapshot {
            return Ok(ScanDisclosureOwnerValue::WorkScopeOwnerRevision {
                owner_revision: record.revision,
                state_fence: record.state_fence,
            });
        }
        if inputs.discovery_lease.is_some() {
            return Err(TransportError::IdentityConflict.into());
        }
        let next_owner_revision = expected_owner_revision
            .checked_add(1)
            .ok_or(TransportError::SessionFenced)?;
        let next_owner = owner
            .attach_discovery_lease_and_privacy_boundary(
                lease.clone(),
                next_owner_revision,
                super::unix_ms(),
            )
            .map_err(|_| TransportError::SessionFenced)?;
        let next_snapshot = next_owner
            .read_current(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if &next_snapshot != proposed_snapshot {
            return Err(TransportError::IdentityConflict.into());
        }
        self.persist_work_scope_owner_revision(
            current,
            expected_owner_revision,
            "discovery-lease",
            proposed_snapshot.clone(),
        )
        .await?;
        Ok(ScanDisclosureOwnerValue::WorkScopeOwnerRevision {
            owner_revision: next_owner_revision,
            state_fence: current.ticket.state_fence.clone(),
        })
    }

    #[cfg(windows)]
    async fn retain_scan_evidence(
        &self,
        current: &CurrentScanDisclosureActivation,
        expected_owner_revision: u64,
        discovery_lease: &DiscoveryReadLease,
        evidence: &BootstrapScanEvidence,
        binding: &ScanDisclosureOwnerBinding,
        receipt_handle: &ScanReceiptHandle,
        proposed_snapshot: &WorkScopeBindingSnapshot,
    ) -> Result<ScanDisclosureOwnerValue, ScanDisclosureOwnerActionError> {
        let (record, owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, true).await?;
        self.recheck_scan_disclosure_activation(current)?;
        if record.revision != expected_owner_revision
            || snapshot.owner_revision != expected_owner_revision
            || inputs.state_fence != current.ticket.state_fence
        {
            if record.revision > expected_owner_revision
                && record.revision - expected_owner_revision == 1
                && inputs.scan_evidence.as_ref() == Some(evidence)
                && inputs
                    .scan_binding
                    .as_ref()
                    .is_some_and(|retained| Self::workscope_binding(binding) == *retained)
                && inputs.scan_receipt_handle.as_ref() == Some(receipt_handle)
                && inputs.discovery_lease.as_ref() == Some(discovery_lease)
                && &snapshot == proposed_snapshot
            {
                let discovery = inputs
                    .bootstrap_discovery_inputs
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?;
                if discovery.evidence != *evidence {
                    return Err(TransportError::IdentityConflict.into());
                }
                self.validate_scan_receipt_handle(
                    current,
                    binding,
                    &discovery.scan_ref,
                    evidence,
                    receipt_handle,
                )?;
                return Ok(ScanDisclosureOwnerValue::WorkScopeOwnerRevision {
                    owner_revision: record.revision,
                    state_fence: record.state_fence,
                });
            }
            return Err(TransportError::IdentityConflict.into());
        }
        let original_lease = inputs
            .discovery_lease
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !Self::same_discovery_lease_identity(original_lease, discovery_lease)
            || discovery_lease.consumed < original_lease.consumed
            || discovery_lease.consumed > discovery_lease.consumption_limit
        {
            return Err(TransportError::IdentityConflict.into());
        }
        let expected_binding = Self::expected_scan_disclosure_binding(current, &snapshot, &inputs)?;
        if binding != &expected_binding {
            return Err(TransportError::IdentityConflict.into());
        }
        self.validate_scan_receipt_handle(
            current,
            &expected_binding,
            &inputs
                .bootstrap_discovery_inputs
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .scan_ref,
            evidence,
            receipt_handle,
        )?;
        let next_owner_revision = expected_owner_revision
            .checked_add(1)
            .ok_or(TransportError::SessionFenced)?;
        let next_owner = owner
            .attach_scan_evidence(
                discovery_lease.clone(),
                evidence.clone(),
                Self::workscope_binding(binding),
                receipt_handle.clone(),
                next_owner_revision,
                super::unix_ms(),
            )
            .map_err(|_| TransportError::SessionFenced)?;
        let next_snapshot = next_owner
            .read_current(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if &next_snapshot != proposed_snapshot {
            return Err(TransportError::IdentityConflict.into());
        }
        self.persist_work_scope_owner_revision(
            current,
            expected_owner_revision,
            "scan-evidence",
            proposed_snapshot.clone(),
        )
        .await?;
        Ok(ScanDisclosureOwnerValue::WorkScopeOwnerRevision {
            owner_revision: next_owner_revision,
            state_fence: current.ticket.state_fence.clone(),
        })
    }

    #[cfg(windows)]
    fn workscope_binding(
        binding: &ScanDisclosureOwnerBinding,
    ) -> eliot_workscope::ScanDisclosureOwnerBinding {
        eliot_workscope::ScanDisclosureOwnerBinding {
            installation_id: binding.installation_id.clone(),
            principal_ref: binding.principal_ref.clone(),
            session_ref: binding.session_ref.clone(),
            host_generation_ref: binding.host_generation_ref.clone(),
            lease_ref: binding.lease_ref.clone(),
            candidate_root_ref: binding.candidate_root_ref.clone(),
            privacy_boundary_ref: binding.privacy_boundary_ref.clone(),
            state_fence_ref: binding.state_fence_ref.clone(),
            authority_epoch_ref: binding.authority_epoch_ref.clone(),
            operation_id: binding.operation_id.clone(),
            idempotency_key: binding.idempotency_key.clone(),
            cancellation_ref: binding.cancellation_ref.clone(),
            lease_consumed: binding.lease_consumed,
            policy_revision: binding.policy_revision,
            deadline: binding.deadline,
        }
    }

    #[cfg(windows)]
    fn wire_binding(
        binding: &eliot_workscope::ScanDisclosureOwnerBinding,
    ) -> ScanDisclosureOwnerBinding {
        ScanDisclosureOwnerBinding {
            installation_id: binding.installation_id.clone(),
            principal_ref: binding.principal_ref.clone(),
            session_ref: binding.session_ref.clone(),
            host_generation_ref: binding.host_generation_ref.clone(),
            lease_ref: binding.lease_ref.clone(),
            candidate_root_ref: binding.candidate_root_ref.clone(),
            privacy_boundary_ref: binding.privacy_boundary_ref.clone(),
            state_fence_ref: binding.state_fence_ref.clone(),
            authority_epoch_ref: binding.authority_epoch_ref.clone(),
            operation_id: binding.operation_id.clone(),
            idempotency_key: binding.idempotency_key.clone(),
            cancellation_ref: binding.cancellation_ref.clone(),
            lease_consumed: binding.lease_consumed,
            policy_revision: binding.policy_revision,
            deadline: binding.deadline,
        }
    }

    #[cfg(windows)]
    fn same_discovery_lease_identity(
        original: &DiscoveryReadLease,
        observed: &DiscoveryReadLease,
    ) -> bool {
        original.lease_ref == observed.lease_ref
            && original.proposer_ref == observed.proposer_ref
            && original.session_ref == observed.session_ref
            && original.host_ref == observed.host_ref
            && original.root_filesystem_identity_ref == observed.root_filesystem_identity_ref
            && original.candidate_root_ref == observed.candidate_root_ref
            && original.allowed_reads == observed.allowed_reads
            && original.deadline == observed.deadline
            && original.consumption_limit == observed.consumption_limit
    }

    #[cfg(windows)]
    fn expected_scan_disclosure_binding(
        current: &CurrentScanDisclosureActivation,
        snapshot: &WorkScopeBindingSnapshot,
        inputs: &ColdStartOwnerInputs,
    ) -> Result<ScanDisclosureOwnerBinding, TransportError> {
        let lease = inputs
            .discovery_lease
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let boundary = inputs
            .privacy_boundary
            .as_ref()
            .ok_or(TransportError::PlanGap {
                dependency: "governor.admitted_bootstrap_privacy_boundary",
                reason: "the retained admission has no original PrivacyBoundary",
            })?;
        boundary
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let discovery = inputs
            .bootstrap_discovery_inputs
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if discovery.privacy_boundary.as_ref() != Some(boundary)
            || discovery.evidence.canonical_root_ref != inputs.explicit_root_identity
            || discovery.evidence.filesystem_identity_ref != lease.root_filesystem_identity_ref
            || lease.proposer_ref != inputs.principal_ref
            || lease.session_ref != inputs.session_ref
            || lease.candidate_root_ref != inputs.explicit_root_identity
            || lease.deadline > current.ticket.kernel_deadline_unix_ms
            || snapshot.owner_revision != inputs.owner_revision
            || snapshot.state_fence != current.ticket.state_fence
            || inputs.state_fence != current.ticket.state_fence
            || inputs.principal_ref != current.principal_id()
            || inputs.session_ref != current.session_id()
            || inputs.task_selection.task_ref != current.task_id()
            || inputs.task_selection.work_scope_ref != current.work_scope_id()
        {
            return Err(TransportError::IdentityConflict);
        }
        let (operation_id, idempotency_key) =
            Self::child_scan_operation_identity(current, "scan", snapshot.owner_revision)?;
        let state_fence_ref =
            sha256_json(&current.ticket.state_fence).map_err(|_| TransportError::SessionFenced)?;
        let authority_epoch_ref =
            StateFence::canonical_epoch_digest(&current.ticket.state_fence.authority_epoch)
                .map_err(|_| TransportError::SessionFenced)?
                .as_str()
                .to_owned();
        let binding = ScanDisclosureOwnerBinding {
            installation_id: current.installation_id.clone(),
            principal_ref: inputs.principal_ref.clone(),
            session_ref: inputs.session_ref.clone(),
            host_generation_ref: current
                .ticket
                .state_fence
                .resource_generation
                .value()
                .to_string(),
            lease_ref: lease.lease_ref.clone(),
            candidate_root_ref: inputs.explicit_root_identity.clone(),
            privacy_boundary_ref: boundary.boundary_ref.clone(),
            state_fence_ref: Some(state_fence_ref),
            authority_epoch_ref: Some(authority_epoch_ref),
            operation_id,
            idempotency_key,
            cancellation_ref: current.ticket.cancellation_id.clone(),
            lease_consumed: u64::from(lease.consumed),
            policy_revision: inputs.policy_revision,
            deadline: lease.deadline,
        };
        Self::validate_scan_disclosure_binding_shape(current, &binding)?;
        Self::workscope_binding(&binding)
            .admit()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(binding)
    }

    #[cfg(windows)]
    fn expected_cold_start_readiness_key(
        current: &CurrentScanDisclosureActivation,
        snapshot: &WorkScopeBindingSnapshot,
        inputs: &ColdStartOwnerInputs,
        sources: &eliot_workscope::GoverningSourceSet,
        binding: &eliot_workscope::ScanDisclosureOwnerBinding,
        evidence: &BootstrapScanEvidence,
    ) -> Result<ColdStartReadinessOwnerKey, TransportError> {
        let lineage = inputs
            .descriptor
            .lineage
            .as_ref()
            .ok_or(TransportError::PlanGap {
                dependency: "governor.retained_workspace_lineage",
                reason: "the current admitted WorkScope descriptor has no repository lineage",
            })?;
        let mut instances = inputs
            .descriptor
            .instances
            .iter()
            .filter(|instance| instance.root_identity == inputs.explicit_root_identity);
        let instance = instances.next().ok_or(TransportError::SessionFenced)?;
        if instances.next().is_some()
            || instance.instance_ref != snapshot.binding.scope.instance_ref
            || instance.root_identity != snapshot.binding.scope.root_identity
            || instance.root_identity != evidence.filesystem_identity_ref
        {
            return Err(TransportError::IdentityConflict);
        }
        let boundary = inputs
            .privacy_boundary
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let privacy_class = inputs.privacy_class;
        if !boundary.admits(privacy_class)
            || !inputs.privacy.admits(privacy_class)
            || binding.privacy_boundary_ref != boundary.boundary_ref
            || binding.candidate_root_ref != inputs.explicit_root_identity
            || binding.lease_ref
                != inputs
                    .discovery_lease
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?
                    .lease_ref
            || binding.policy_revision != inputs.policy_revision
            || evidence.canonical_root_ref != inputs.explicit_root_identity
        {
            return Err(TransportError::IdentityConflict);
        }
        let mut governing_source_digests = sources
            .sources
            .iter()
            .map(|source| source.digest.clone())
            .collect::<Vec<_>>();
        governing_source_digests.sort();
        governing_source_digests.dedup();
        let key = ColdStartReadinessOwnerKey {
            installation_id: current.installation_id.clone(),
            lineage_candidate_ref: lineage.lineage_ref.clone(),
            workspace_instance_candidate_ref: instance.instance_ref.clone(),
            filesystem_identity_ref: instance.root_identity.clone(),
            vcs_identity_ref: instance.vcs_identity_ref.clone(),
            privacy_boundary_ref: boundary.boundary_ref.clone(),
            privacy_class,
            governing_source_set_ref: format!(
                "governing-source-set:{}:{}",
                sources.scope_ref, sources.generation
            ),
            governing_source_generation: sources.generation,
            governing_source_digests,
            dirty_summary_ref: evidence.vcs_dirty_summary_ref.clone(),
            state_fence: snapshot.state_fence.clone(),
        };
        key.validate().map_err(|_| TransportError::SessionFenced)?;
        Ok(key)
    }

    #[cfg(windows)]
    fn validate_scan_disclosure_binding_shape(
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
            || binding.principal_ref != current.principal_id()
            || binding.session_ref != current.session_id()
            || binding.host_generation_ref
                != current
                    .ticket
                    .state_fence
                    .resource_generation
                    .value()
                    .to_string()
            || binding.state_fence_ref.as_deref() != Some(state_fence_ref.as_str())
            || binding.authority_epoch_ref.as_deref() != Some(authority_epoch_ref.as_str())
            || binding.cancellation_ref != current.ticket.cancellation_id
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
        Ok(())
    }

    #[cfg(windows)]
    fn validate_scan_receipt_handle(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
        expected_scan_ref: &str,
        evidence: &BootstrapScanEvidence,
        handle: &ScanReceiptHandle,
    ) -> Result<(), ScanDisclosureReadFailure> {
        handle.validate().map_err(|error| match error {
            eliot_workscope::WorkScopeError::ScanReceiptMissing => {
                ScanDisclosureReadFailure::Missing
            }
            eliot_workscope::WorkScopeError::ScanReceiptInaccessible => {
                ScanDisclosureReadFailure::Inaccessible
            }
            eliot_workscope::WorkScopeError::ScanReceiptCorrupt => {
                ScanDisclosureReadFailure::Corrupt
            }
            eliot_workscope::WorkScopeError::ScanReceiptReplaced => {
                ScanDisclosureReadFailure::Replaced
            }
            eliot_workscope::WorkScopeError::ScanReceiptStale => ScanDisclosureReadFailure::Stale,
            eliot_workscope::WorkScopeError::ScanReceiptInvalidated => {
                ScanDisclosureReadFailure::Invalidated
            }
            eliot_workscope::WorkScopeError::ScanReceiptUnknownCommit => {
                ScanDisclosureReadFailure::UnknownCommit
            }
            _ => ScanDisclosureReadFailure::Corrupt,
        })?;
        let record = match self.p07_ors.load_scan_disclosure(&binding.operation_key()) {
            Ok(Some(record)) => record,
            Ok(None) => return Err(ScanDisclosureReadFailure::Missing),
            Err(eliot_ors::OrsError::Storage(_)) => {
                return Err(ScanDisclosureReadFailure::Inaccessible);
            }
            Err(eliot_ors::OrsError::StoreContract(error)) => {
                return Err(match *error {
                    eliot_store_api::StoreError::Unavailable => {
                        ScanDisclosureReadFailure::Inaccessible
                    }
                    eliot_store_api::StoreError::UnknownOutcome { .. }
                    | eliot_store_api::StoreError::MissingReceiptEnvelope => {
                        ScanDisclosureReadFailure::UnknownCommit
                    }
                    _ => ScanDisclosureReadFailure::Corrupt,
                });
            }
            Err(eliot_ors::OrsError::IntegrityProblem { .. }) => {
                return Err(ScanDisclosureReadFailure::Corrupt);
            }
            Err(eliot_ors::OrsError::InvalidField {
                field: "scan_disclosure_cancellation_ref",
                ..
            }) => {
                return Err(ScanDisclosureReadFailure::Stale);
            }
            Err(eliot_ors::OrsError::MigrationRequired { .. }) => {
                return Err(ScanDisclosureReadFailure::Stale);
            }
            Err(eliot_ors::OrsError::StagingCommitOutcomeUnknown { .. }) => {
                return Err(ScanDisclosureReadFailure::UnknownCommit);
            }
            Err(_) => return Err(ScanDisclosureReadFailure::Corrupt),
        };
        if handle.retention != eliot_workscope::ScanReceiptRetention::Active {
            return Err(ScanDisclosureReadFailure::Invalidated);
        }
        record
            .validate()
            .map_err(|_| ScanDisclosureReadFailure::Corrupt)?;
        if record.operation_key != binding.operation_key()
            || Self::validate_record_binding(current, binding, &record).is_err()
        {
            return Err(ScanDisclosureReadFailure::Replaced);
        }
        match record.state {
            eliot_ors::ScanDisclosureRecordState::Prepared => {
                return Err(ScanDisclosureReadFailure::UnknownCommit);
            }
            eliot_ors::ScanDisclosureRecordState::Retired
            | eliot_ors::ScanDisclosureRecordState::Superseded => {
                return Err(ScanDisclosureReadFailure::Invalidated);
            }
            eliot_ors::ScanDisclosureRecordState::Committed => {}
        }
        if record.writer_receipt.trim().is_empty() {
            return Err(ScanDisclosureReadFailure::Corrupt);
        }
        let receipt: eliot_workscope::ScanDisclosureReceipt =
            serde_json::from_str(&record.receipt_bytes)
                .map_err(|_| ScanDisclosureReadFailure::Corrupt)?;
        receipt
            .validate()
            .map_err(|_| ScanDisclosureReadFailure::Corrupt)?;
        let expected_commitment = format!("{}:{}", record.operation_key, record.request_hash);
        let expected_owner = format!("installation:{}:scan-disclosure", current.installation_id);
        if record.operation_key != binding.operation_key()
            || receipt.scan_ref != expected_scan_ref
            || receipt.lease_ref != binding.lease_ref
            || receipt.candidate_root_ref != binding.candidate_root_ref
            || receipt.privacy_boundary_ref.as_deref()
                != Some(binding.privacy_boundary_ref.as_str())
            || receipt.allowed != evidence.attested_reads
            || receipt.unresolved != evidence.unresolved_fields
            || receipt.redacted != evidence.redacted_literal_identities
            || handle.receipt_ref != receipt.scan_ref
            || handle.store_ref != record.operation_key
            || handle.owner_ref != expected_owner
            || handle.record_commitment != expected_commitment
            || handle.receipt_digest != record.receipt_digest
            || handle.schema_version != record.schema_version
            || handle.writer_receipt_ref != record.writer_receipt
            || evidence.canonical_root_ref != receipt.candidate_root_ref
        {
            return Err(ScanDisclosureReadFailure::Replaced);
        }
        Ok(())
    }

    #[cfg(windows)]
    async fn issue_scan_disclosure_binding(
        &self,
        current: &CurrentScanDisclosureActivation,
    ) -> Result<ScanDisclosureOwnerBinding, TransportError> {
        let (record, owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, true).await?;
        self.recheck_scan_disclosure_activation(current)?;
        let (sources, privacy) = owner
            .read_current_source_closure(&current.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if record.revision != snapshot.owner_revision
            || inputs.descriptor.state_fence != current.ticket.state_fence
            || inputs.governing_sources != sources
            || inputs.privacy != privacy
            || !inputs
                .descriptor
                .root_identities
                .contains(&inputs.explicit_root_identity)
            || inputs.discovery_lease.as_ref().map_or(true, |lease| {
                lease.candidate_root_ref != inputs.explicit_root_identity
            })
            || snapshot.binding.scope.root_identity != inputs.explicit_root_identity
        {
            return Err(TransportError::IdentityConflict);
        }
        let binding = Self::expected_scan_disclosure_binding(current, &snapshot, &inputs)?;
        self.recheck_scan_disclosure_activation(current)?;
        Ok(binding)
    }

    #[cfg(windows)]
    fn recheck_scan_disclosure_activation(
        &self,
        current: &CurrentScanDisclosureActivation,
    ) -> Result<(), TransportError> {
        let latest = self.current_scan_disclosure_activation(
            &current.ticket.connection_id,
            &current.ticket.ticket_id,
            current.initial_bind_scope_proof.as_ref(),
        )?;
        if latest.binding != current.binding
            || latest.initial_bind_scope_proof != current.initial_bind_scope_proof
            || latest.ticket != current.ticket
            || latest.result != current.result
            || latest.activation_request_identity != current.activation_request_identity
            || latest.installation_id != current.installation_id
            || latest.kernel_owner_revision != current.kernel_owner_revision
            || latest.kernel_owner_bundle_sha256 != current.kernel_owner_bundle_sha256
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
    }

    #[cfg(windows)]
    async fn validate_scan_disclosure_binding(
        &self,
        current: &CurrentScanDisclosureActivation,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<(), ScanDisclosureOwnerActionError> {
        let (_record, _owner, snapshot, inputs) =
            self.load_retained_work_scope_owner(current, true).await?;
        self.recheck_scan_disclosure_activation(current)?;
        let expected = inputs
            .scan_binding
            .as_ref()
            .map(|retained| ScanDisclosureOwnerBinding {
                installation_id: retained.installation_id.clone(),
                principal_ref: retained.principal_ref.clone(),
                session_ref: retained.session_ref.clone(),
                host_generation_ref: retained.host_generation_ref.clone(),
                lease_ref: retained.lease_ref.clone(),
                candidate_root_ref: retained.candidate_root_ref.clone(),
                privacy_boundary_ref: retained.privacy_boundary_ref.clone(),
                state_fence_ref: retained.state_fence_ref.clone(),
                authority_epoch_ref: retained.authority_epoch_ref.clone(),
                operation_id: retained.operation_id.clone(),
                idempotency_key: retained.idempotency_key.clone(),
                cancellation_ref: retained.cancellation_ref.clone(),
                lease_consumed: retained.lease_consumed,
                policy_revision: retained.policy_revision,
                deadline: retained.deadline,
            })
            .map(Ok)
            .unwrap_or_else(|| {
                Self::expected_scan_disclosure_binding(current, &snapshot, &inputs)
            })?;
        if binding != &expected {
            return Err(TransportError::IdentityConflict.into());
        }
        Self::validate_scan_disclosure_binding_shape(current, binding)?;
        let retained_scan_fields = [
            inputs.scan_evidence.is_some(),
            inputs.scan_binding.is_some(),
            inputs.scan_receipt_handle.is_some(),
        ];
        if inputs.scan_evidence.is_some()
            && inputs.scan_binding.is_some()
            && inputs.scan_receipt_handle.is_none()
        {
            return Err(ScanDisclosureOwnerActionError::ReceiptRead(
                ScanDisclosureReadFailure::Missing,
            ));
        }
        if retained_scan_fields.iter().any(|present| *present)
            && !retained_scan_fields.iter().all(|present| *present)
        {
            return Err(TransportError::IdentityConflict.into());
        }
        if let (Some(evidence), Some(handle), Some(discovery)) = (
            inputs.scan_evidence.as_ref(),
            inputs.scan_receipt_handle.as_ref(),
            inputs.bootstrap_discovery_inputs.as_ref(),
        ) {
            if discovery.evidence != *evidence {
                return Err(TransportError::IdentityConflict.into());
            }
            if Self::workscope_binding(binding)
                != inputs
                    .scan_binding
                    .clone()
                    .ok_or(TransportError::IdentityConflict)?
            {
                return Err(TransportError::IdentityConflict.into());
            }
            self.validate_scan_receipt_handle(
                current,
                binding,
                &discovery.scan_ref,
                evidence,
                handle,
            )?;
        }
        self.recheck_scan_disclosure_activation(current)?;
        Ok(())
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
            || record.cancellation_ref != binding.cancellation_ref
            || record.idempotency_key != binding.idempotency_key
            || record.policy_revision != binding.policy_revision
            || record.deadline != binding.deadline
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
    }
}
