//! Task-binding admission for the daemon ingress boundary (issue #1929).
//!
//! Implements I5.5 capture/promotion split at the `eliotd` admission edge:
//! `eliot.observe` may retain a safe raw cold [`ObservationCandidate`] when
//! task selection is absent or ambiguous, while reusable task memory,
//! Claim/Failure/Procedure promotion, and task-control writes require the
//! canonical Governor [`TaskSelectionEvidence`] plus a valid current fence
//! and a `Compatible` disposition.
//!
//! The selection evidence is the canonical Governor-owned contract
//! (`eliot-observation`); this module defines no parallel shape and parses
//! no invented marker syntax. Field names, types, and validation rules come
//! from that contract: exact task handle, non-zero `TaskContract` revision,
//! lowercase acceptance digest, `WorkScope` identity, selection source and
//! evidence handles. The fence is bound by the authenticated caller context
//! (the `state_fence`/`expected_fence` parameters), matching the canonical
//! consumer where the submission envelope carries the single fence.
//!
//! This module is a pure validator. It owns no journal, store, task lifecycle,
//! or promotion state machine; it only classifies one admission attempt so the
//! Governor/store owners keep semantic ownership. It never selects the most
//! recent or open task and never guesses from resolver output: ambiguous input
//! stays cold. A contaminated selection (canonical crossover marker) never
//! promotes: captures stay cold and task-bound promotion rejects.
//!
//! # Live daemon ingress (issue #1929 and #2900)
//!
//! The composition-root `admit_canonical_write` runs on the live Task
//! Controller material path after `commit_task_controller_transition` reads
//! current task selection and durable readiness. Its input is the original
//! `CanonicalWriteEnvelope` and identity from the Governor-prepared transition;
//! readiness, original WorkScope binding observation, and source/privacy
//! closure come from the guarded owner readback. `admit_named_mutation_capture`
//! remains the transport edge: task-free captures may remain cold and
//! task-relative writes still require the composition-root gate and downstream
//! proof-handle enforcement.
//!
//! `observe_explicit_workspace` remains the mechanical Host observation used
//! by the authenticated BIND_SCOPE owner admission. It creates no WorkScope
//! receipt or semantic selection. Governor validates the original bootstrap,
//! source, privacy, Policy, task, and fence inputs before the daemon persists
//! the exact snapshot through Kernel's WorkScope owner CAS/readback route.
//!
//! # Measured reachability (issue #1929 and #2900)
//!
//! The production path is now live. `daemon_runtime::trigger_accepted_cold_start`
//! asks Governor to attach the accepted discovery lease, persists that exact
//! owner snapshot through Kernel CAS and readback, and only then requests the
//! installation scan binding. `GovernorComposition::run_cold_start_trigger_scan`
//! scans through its bound installation owner; the caller then retains the
//! consumed lease, original evidence, binding and receipt handle as another
//! WorkScope revision before `compile_cold_start_from_owner_inputs` publishes
//! the durable terminal readiness owner.
//!
//! Task Controller material writes use one guarded path:
//! `campaign_task_controller::commit_task_controller_transition` resolves the
//! current owner task selection, requires exact `Selected` evidence, reads the
//! guarded durable readiness and original WorkScope observation, then invokes
//! `DaemonComposition::commit_canonical_and_refresh` once with the prepared
//! transition's unchanged request identity and original envelope. That envelope
//! retains the expected revision and ordering heads; there is no direct
//! `PreparedTaskTransition::exchange` bypass on this path. Unknown Store outcomes
//! retain the original operation identity for canonical reconciliation, and a
//! committed receipt remains reportable if dependent-view refresh degrades.
//!
//! The Kernel-issued RequestIdentity is retained at the authenticated Task
//! Controller enqueue owner and returned unchanged on each claim. The BIND_SCOPE
//! caller persists its original admitted WorkScope binding through the same
//! typed owner CAS/readback path; subsequent activation stages use separate
//! owner-issued child operations keyed to the original activation identity and
//! exact expected WorkScope revision. No task selector or claimed transport
//! field supplies a readiness receipt, task revision, or scan receipt.
//!
//! # Where a cold unbound candidate is retained (issue #1929)
//!
//! Retention is not this module's work and is not the `tracing` line its
//! callers emit — a log record is neither durable nor listable.
//! `eliot_store_surreal::task_binding_gate::gate_apply` classifies the unbound
//! capture `GateDisposition::ColdUnbound` so the write *proceeds* instead of
//! being rejected, and the durable owner is the store adapter:
//! `eliot_store_surreal_adapter`'s `plan::evidence_records` builds one
//! `EvidenceRecord` per `CaptureObservation` regardless of task binding, and
//! `apply::atomic_write` binds those records into the `write_receipt` row in
//! the same transaction that creates the receipt. The read-back symbol is the
//! `GetEvidencePack` named read served by
//! `eliot_store_surreal_adapter`'s `apply::read_boundary::read_evidence_records`.
//! A later governed binding transition therefore has a durable, listable
//! candidate to read, and the daemon's own contribution is the admission
//! decision plus its log projection.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_bootstrap::capture::{
    WorkspaceInstanceFacts, WorkspaceSourceDocumentKind, observe_workspace_instance,
    observe_workspace_source_candidates,
};
use eliot_contracts::sha256_hex;
use eliot_contracts::{RequestMetadata, StateFence, TaskId};
use eliot_governor::{
    CanonicalWriteEnvelope, ColdStartSurfaceView, GoverningSourceSet, PrivacyProfile, ScopeBinding,
    WorkScopeDescriptor, derive_observed_resources,
};
use eliot_integration_coverage::{GovernanceProfile, IntegrationCoverageProfile};
use eliot_observation::TaskSelectionEvidence;
use eliot_ors::{
    ColdStartReadinessClaim, ColdStartReadinessOrsRecord, ColdStartReadinessOwnerKey,
    ColdStartReadinessRecordOwner, ColdStartReadinessStageOutcome,
    ColdStartReadinessTerminalDisposition, OrsError, ScanDisclosureOrsRecord,
    ScanDisclosureQuarantineRecord, ScanDisclosureReadFailure, ScanDisclosureRecordOwner,
    ScanDisclosureStageOutcome,
};
use eliot_protocol::{
    AgentActivationBindScopeEvidence, AgentActivationCandidateCoverage,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, HostRequestEnvelope,
};
use eliot_security_contracts::PrivacyClass;
use eliot_store_api::{NamedMutationOperation, PreparedTransition};
use eliot_workscope::{
    BootstrapDiscoveryInputs, BootstrapScanEvidence, DiscoveryLeaseKey, DiscoveryLeaseRequest,
    DiscoveryRead, DiscoveryReadLease, GoverningSourceCandidate, GoverningSourceCandidateEvidence,
    GoverningSourceRole, ManifestEvidence, ObservedScopeResources, OnboardingLease,
    OnboardingReadinessReceipt, PrecedenceDeclaration, ReadinessLifecycle, ScopeBindingDisposition,
    ScopeResolutionState, TaskBindingState, WorkScopeBindingSnapshot, issue_discovery_lease,
    task_selection_required,
};

/// Authenticated activation's bounded filesystem/VCS observation and its
/// scanner inputs. The ticket binds the explicit selector to the admitted
/// Bridge request and peer receipt; all identity/evidence fields below are
/// derived from the Host observer, never accepted from the caller.
#[derive(Clone, Debug)]
pub struct ColdStartDiscoveryInput {
    pub lease: DiscoveryReadLease,
    pub key: DiscoveryLeaseKey,
    pub discovery: BootstrapDiscoveryInputs,
}

/// Caller-declared WorkScope data carried by the authenticated `BIND_SCOPE`
/// Task Controller action. These values are validated against Governor-owned
/// sources and privacy before they can become retained owner state.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialWorkScopeBindingRequest {
    pub explicit_root: PathBuf,
    /// Original bounded Host discovery payload. The full typed payload is
    /// retained by Governor so the original privacy boundary and scan
    /// evidence can be independently joined after restart.
    pub bootstrap_discovery: BootstrapDiscoveryInputs,
    pub descriptor: WorkScopeDescriptor,
    pub binding: ScopeBinding,
    pub sources: GoverningSourceSet,
    pub privacy: PrivacyProfile,
    pub source_candidates: Vec<GoverningSourceCandidate>,
    pub declared_precedences: Vec<PrecedenceDeclaration>,
    pub absence_reason_ref: Option<String>,
    pub admission_deadline: u64,
    /// Kernel-issued discovery lease when the accepted activation has reached
    /// the post-admission scan stage. Initial BIND_SCOPE may happen first.
    #[serde(default)]
    pub discovery_lease: Option<DiscoveryReadLease>,
}

impl InitialWorkScopeBindingRequest {
    pub fn validate_for_task_scope(&self, work_scope_id: &str) -> Result<(), String> {
        if !self.explicit_root.is_absolute() {
            return Err("explicit_root must be an absolute Host observation selector".to_owned());
        }
        self.descriptor
            .validate()
            .map_err(|error| format!("WorkScope descriptor is invalid: {error}"))?;
        self.binding
            .validate()
            .map_err(|error| format!("WorkScope binding is invalid: {error}"))?;
        self.privacy
            .validate()
            .map_err(|error| format!("WorkScope privacy profile is invalid: {error}"))?;
        if let Some(discovery_lease) = &self.discovery_lease {
            discovery_lease
                .validate()
                .map_err(|error| format!("discovery lease is invalid: {error}"))?;
        }
        self.bootstrap_discovery
            .evidence
            .validate()
            .map_err(|error| format!("bootstrap discovery evidence is invalid: {error}"))?;
        if let Some(boundary) = &self.bootstrap_discovery.privacy_boundary {
            boundary
                .validate()
                .map_err(|error| format!("bootstrap privacy boundary is invalid: {error}"))?;
            if self
                .bootstrap_discovery
                .candidate_privacy
                .is_some_and(|class| !boundary.admits(class))
            {
                return Err("bootstrap privacy boundary excludes the admitted class".to_owned());
            }
        }
        if let Some(policy) = &self.bootstrap_discovery.policy {
            policy
                .validate()
                .map_err(|error| format!("bootstrap descriptor policy is invalid: {error}"))?;
        }
        if self.descriptor.scope_ref != work_scope_id
            || self.binding.scope.scope_ref != work_scope_id
            || self.sources.scope_ref != work_scope_id
            || self
                .discovery_lease
                .as_ref()
                .is_some_and(|lease| lease.candidate_root_ref != self.binding.scope.root_identity)
            || self
                .bootstrap_discovery
                .evidence
                .attested_reads
                .iter()
                .any(|read| {
                    self.discovery_lease
                        .as_ref()
                        .is_some_and(|lease| !lease.allowed_reads.contains(read))
                })
        {
            return Err("WorkScope request does not match the admitted task scope/root".to_owned());
        }
        if self.descriptor.scope_ref != self.binding.scope.scope_ref {
            return Err("WorkScope descriptor and resolved binding disagree".to_owned());
        }
        if self.admission_deadline == 0
            || self.source_candidates.iter().any(|candidate| {
                candidate.validate().is_err()
                    || candidate.applicable_scope_ref != work_scope_id
                    || candidate.applicable_generation != self.binding.scope.generation
            })
            || self.declared_precedences.iter().any(|precedence| {
                precedence.validate().is_err() || precedence.scope_ref != work_scope_id
            })
        {
            return Err("WorkScope source admission inputs are invalid".to_owned());
        }
        self.sources
            .validate_for(&self.binding.scope, &self.privacy)
            .map_err(|error| format!("WorkScope source/privacy closure is invalid: {error}"))
    }
}

/// The exact installation-owned scan result retained across the accepted
/// attach trigger. The receipt handle and full scan evidence stay paired with
/// the original lease/binding so readiness compilation can validate the same
/// durable operation instead of reconstructing it from a disclosure summary.
pub struct ColdStartScanOwnerReceipt {
    pub trigger: eliot_workscope::ColdStartTrigger,
    pub discovery: ColdStartDiscoveryInput,
    pub contour: eliot_governor::InstallationScanContour,
    pub binding: eliot_workscope::ScanDisclosureOwnerBinding,
    pub scan_evidence: BootstrapScanEvidence,
    pub disclosure_receipt: eliot_workscope::ScanDisclosureReceipt,
    pub receipt_handle: eliot_workscope::ScanReceiptHandle,
    pub store: eliot_governor::InstallationScanDisclosureStore,
}

pub enum ColdStartTriggerResult {
    Question(eliot_workscope::BootstrapScanOutcome),
    Persisted { scan: ColdStartScanOwnerReceipt },
}

const SCAN_DISCLOSURE_OWNER_OPERATION: &str = "scan_disclosure_owner";
const SCAN_DISCLOSURE_OWNER_WIRE_VERSION: u16 = 1;

/// Exact original accepted BIND_SCOPE proof carried through every initial
/// scan/readiness owner call. It contains only the caller-retained envelope
/// and evidence; Kernel revalidates both against the original accepted ticket.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitialBindScopeOwnerProof {
    evidence: AgentActivationBindScopeEvidence,
    envelope: HostRequestEnvelope,
}

impl InitialBindScopeOwnerProof {
    pub fn new(evidence: AgentActivationBindScopeEvidence, envelope: HostRequestEnvelope) -> Self {
        Self { evidence, envelope }
    }
}

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ScanDisclosureOwnerRpcRequest<'a> {
    wire_version: u16,
    application_connection_id: &'a str,
    activation_ticket_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_bind_scope_proof: Option<&'a InitialBindScopeOwnerProof>,
    #[serde(flatten)]
    action: ScanDisclosureOwnerRpcAction<'a>,
}

#[derive(serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ScanDisclosureOwnerRpcAction<'a> {
    InitialBindScopeDiscovery {
        evidence: &'a AgentActivationBindScopeEvidence,
        envelope: &'a HostRequestEnvelope,
        explicit_root: &'a str,
        root_identity_ref: &'a str,
        allowed_reads: &'a [DiscoveryRead],
    },
    IssueContour,
    IssueBinding,
    RetainDiscoveryLease {
        expected_owner_revision: u64,
        lease: &'a DiscoveryReadLease,
        snapshot: &'a WorkScopeBindingSnapshot,
    },
    RetainScanEvidence {
        expected_owner_revision: u64,
        discovery_lease: &'a DiscoveryReadLease,
        evidence: &'a BootstrapScanEvidence,
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        receipt_handle: &'a eliot_workscope::ScanReceiptHandle,
        snapshot: &'a WorkScopeBindingSnapshot,
    },
    Stage {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        record: &'a ScanDisclosureOrsRecord,
    },
    Commit {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        operation_key: &'a str,
        request_hash: &'a str,
        writer_receipt: &'a str,
    },
    Load {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        operation_key: &'a str,
    },
    Retire {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        operation_key: &'a str,
        request_hash: &'a str,
        policy_revision: u64,
        successor_ref: Option<&'a str>,
    },
    List {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        limit: u16,
    },
    QuarantineRetain {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        record: &'a ScanDisclosureQuarantineRecord,
    },
    QuarantineLoad {
        binding: &'a eliot_workscope::ScanDisclosureOwnerBinding,
        quarantine_key: &'a str,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanDisclosureOwnerRpcResponse {
    wire_version: u16,
    #[serde(flatten)]
    result: ScanDisclosureOwnerRpcResult,
}

#[derive(serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum ScanDisclosureOwnerRpcResult {
    InitialBindScopeDiscovery {
        ticket: AgentActivationResolutionTicket,
        lease: DiscoveryReadLease,
    },
    InitialBindScopeRootRequired {
        ticket: AgentActivationResolutionTicket,
    },
    Contour {
        contour: KernelScanDisclosureContour,
    },
    Binding {
        binding: eliot_workscope::ScanDisclosureOwnerBinding,
    },
    WorkScopeOwnerRevision {
        owner_revision: u64,
        state_fence: eliot_contracts::StateFence,
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
    ReceiptReadFailure {
        failure: ScanDisclosureReadFailure,
    },
}

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ColdStartReadinessOwnerRpcRequest<'a> {
    wire_version: u16,
    application_connection_id: &'a str,
    activation_ticket_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_bind_scope_proof: Option<&'a InitialBindScopeOwnerProof>,
    #[serde(flatten)]
    action: ColdStartReadinessOwnerRpcAction<'a>,
}

#[derive(serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
#[allow(
    clippy::enum_variant_names,
    reason = "wire action names must match the authenticated Kernel readiness route"
)]
enum ColdStartReadinessOwnerRpcAction<'a> {
    ReadinessClaim {
        key: &'a ColdStartReadinessOwnerKey,
    },
    ReadinessPublish {
        record_key: &'a str,
        binding_digest: &'a str,
        lease_ref: &'a str,
        disposition: ColdStartReadinessTerminalDisposition,
        receipt_ref: &'a str,
        receipt_bytes: &'a str,
    },
    ReadinessLoad {
        record_key: &'a str,
    },
    ReadinessLoadForBinding {
        binding_digest: &'a str,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdStartReadinessOwnerRpcResponse {
    wire_version: u16,
    #[serde(flatten)]
    result: ColdStartReadinessOwnerRpcResult,
}

#[derive(serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum ColdStartReadinessOwnerRpcResult {
    ReadinessClaimed {
        outcome: ColdStartReadinessStageOutcome,
    },
    ReadinessRecord {
        record: Option<Box<ColdStartReadinessOrsRecord>>,
    },
    ReceiptReadFailure {
        failure: ScanDisclosureReadFailure,
    },
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelScanDisclosureContour {
    installation_id: String,
    ors_object_ref: String,
    ors_generation: u64,
}

/// Daemon-side `ScanDisclosureRecordOwner` adapter. Every method crosses the
/// existing authenticated Kernel client; no ORS object or in-process trait
/// handle is passed into eliotd.
pub struct KernelScanDisclosureRecordOwner {
    kernel: Arc<super::DaemonKernelClient>,
    application_connection_id: String,
    activation_ticket_id: String,
    binding: eliot_workscope::ScanDisclosureOwnerBinding,
    initial_bind_scope_proof: Option<InitialBindScopeOwnerProof>,
}

impl KernelScanDisclosureRecordOwner {
    pub fn new(
        kernel: Arc<super::DaemonKernelClient>,
        application_connection_id: String,
        activation_ticket_id: String,
        binding: eliot_workscope::ScanDisclosureOwnerBinding,
    ) -> Self {
        Self {
            kernel,
            application_connection_id,
            activation_ticket_id,
            binding,
            initial_bind_scope_proof: None,
        }
    }

    pub fn new_initial(
        kernel: Arc<super::DaemonKernelClient>,
        application_connection_id: String,
        activation_ticket_id: String,
        binding: eliot_workscope::ScanDisclosureOwnerBinding,
        proof: InitialBindScopeOwnerProof,
    ) -> Self {
        Self {
            kernel,
            application_connection_id,
            activation_ticket_id,
            binding,
            initial_bind_scope_proof: Some(proof),
        }
    }

    fn request(
        &self,
        action: ScanDisclosureOwnerRpcAction<'_>,
    ) -> Result<ScanDisclosureOwnerRpcResult, OrsError> {
        let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id: &self.application_connection_id,
            activation_ticket_id: &self.activation_ticket_id,
            initial_bind_scope_proof: self.initial_bind_scope_proof.as_ref(),
            action,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = self
            .kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ScanDisclosureOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported scan-disclosure owner response version".to_owned(),
            ));
        }
        Ok(response.result)
    }

    /// Obtains the installation contour through the authenticated Kernel
    /// route. ORS generation is never supplied by this daemon call.
    pub(crate) fn issue_contour(
        kernel: &super::DaemonKernelClient,
        application_connection_id: &str,
        activation_ticket_id: &str,
    ) -> Result<eliot_governor::InstallationScanContour, OrsError> {
        let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: None,
            action: ScanDisclosureOwnerRpcAction::IssueContour,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ScanDisclosureOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported scan-disclosure owner response version".to_owned(),
            ));
        }
        match response.result {
            ScanDisclosureOwnerRpcResult::Contour { contour } => {
                eliot_governor::InstallationScanContour::bind(
                    contour.installation_id,
                    contour.ors_object_ref,
                    contour.ors_generation,
                )
                .map_err(|error| OrsError::Contract(error.to_string()))
            }
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned the wrong scan-disclosure owner result".to_owned(),
            )),
        }
    }

    /// Requests a Kernel-issued scan binding. The caller supplies no binding
    /// fields; the authenticated Kernel route must derive them from current
    /// retained owners or return its typed missing-owner refusal.
    pub(crate) fn issue_binding(
        kernel: &super::DaemonKernelClient,
        application_connection_id: &str,
        activation_ticket_id: &str,
    ) -> Result<eliot_workscope::ScanDisclosureOwnerBinding, OrsError> {
        let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: None,
            action: ScanDisclosureOwnerRpcAction::IssueBinding,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ScanDisclosureOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported scan-disclosure owner response version".to_owned(),
            ));
        }
        match response.result {
            ScanDisclosureOwnerRpcResult::Binding { binding } => Ok(binding),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned the wrong scan-disclosure owner result".to_owned(),
            )),
        }
    }

    /// Obtains an installation contour while carrying the original unresolved
    /// BIND_SCOPE proof through the authenticated Kernel owner boundary.
    pub(crate) fn issue_initial_contour(
        kernel: &super::DaemonKernelClient,
        application_connection_id: &str,
        activation_ticket_id: &str,
        proof: &InitialBindScopeOwnerProof,
    ) -> Result<eliot_governor::InstallationScanContour, OrsError> {
        let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: Some(proof),
            action: ScanDisclosureOwnerRpcAction::IssueContour,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ScanDisclosureOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported scan-disclosure owner response version".to_owned(),
            ));
        }
        match response.result {
            ScanDisclosureOwnerRpcResult::Contour { contour } => {
                eliot_governor::InstallationScanContour::bind(
                    contour.installation_id,
                    contour.ors_object_ref,
                    contour.ors_generation,
                )
                .map_err(|error| OrsError::Contract(error.to_string()))
            }
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned the wrong scan-disclosure owner result".to_owned(),
            )),
        }
    }

    /// Requests a Kernel-issued scan binding for the unresolved initial lane.
    pub(crate) fn issue_initial_binding(
        kernel: &super::DaemonKernelClient,
        application_connection_id: &str,
        activation_ticket_id: &str,
        proof: &InitialBindScopeOwnerProof,
    ) -> Result<eliot_workscope::ScanDisclosureOwnerBinding, OrsError> {
        let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: Some(proof),
            action: ScanDisclosureOwnerRpcAction::IssueBinding,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ScanDisclosureOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported scan-disclosure owner response version".to_owned(),
            ));
        }
        match response.result {
            ScanDisclosureOwnerRpcResult::Binding { binding } => Ok(binding),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned the wrong scan-disclosure owner result".to_owned(),
            )),
        }
    }
}

impl ScanDisclosureRecordOwner for KernelScanDisclosureRecordOwner {
    fn stage_scan_disclosure(
        &self,
        record: &ScanDisclosureOrsRecord,
    ) -> Result<ScanDisclosureStageOutcome, OrsError> {
        match self.request(ScanDisclosureOwnerRpcAction::Stage {
            binding: &self.binding,
            record,
        })? {
            ScanDisclosureOwnerRpcResult::Staged {
                stored: true,
                record: None,
            } => Ok(ScanDisclosureStageOutcome::Stored),
            ScanDisclosureOwnerRpcResult::Staged {
                stored: false,
                record: Some(record),
            } => Ok(ScanDisclosureStageOutcome::AlreadyBound(Box::new(record))),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid scan-disclosure stage result".to_owned(),
            )),
        }
    }

    fn commit_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        writer_receipt: &str,
    ) -> Result<Option<ScanDisclosureOrsRecord>, OrsError> {
        match self.request(ScanDisclosureOwnerRpcAction::Commit {
            binding: &self.binding,
            operation_key,
            request_hash,
            writer_receipt,
        })? {
            ScanDisclosureOwnerRpcResult::Record { record } => Ok(record),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid scan-disclosure commit result".to_owned(),
            )),
        }
    }

    fn load_scan_disclosure(
        &self,
        operation_key: &str,
    ) -> Result<Option<ScanDisclosureOrsRecord>, OrsError> {
        match self.request(ScanDisclosureOwnerRpcAction::Load {
            binding: &self.binding,
            operation_key,
        })? {
            ScanDisclosureOwnerRpcResult::Record { record } => Ok(record),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid scan-disclosure load result".to_owned(),
            )),
        }
    }

    fn retire_scan_disclosure(
        &self,
        operation_key: &str,
        request_hash: &str,
        policy_revision: u64,
        successor_ref: Option<&str>,
    ) -> Result<Option<ScanDisclosureOrsRecord>, OrsError> {
        match self.request(ScanDisclosureOwnerRpcAction::Retire {
            binding: &self.binding,
            operation_key,
            request_hash,
            policy_revision,
            successor_ref,
        })? {
            ScanDisclosureOwnerRpcResult::Record { record } => Ok(record),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid scan-disclosure retire result".to_owned(),
            )),
        }
    }

    fn list_scan_disclosures(
        &self,
        installation_id: &str,
        limit: u16,
    ) -> Result<Vec<ScanDisclosureOrsRecord>, OrsError> {
        if installation_id != self.binding.installation_id {
            return Err(OrsError::Contract(
                "scan-disclosure list installation conflicts with its owner binding".to_owned(),
            ));
        }
        match self.request(ScanDisclosureOwnerRpcAction::List {
            binding: &self.binding,
            limit,
        })? {
            ScanDisclosureOwnerRpcResult::Records { records } => Ok(records),
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid scan-disclosure list result".to_owned(),
            )),
        }
    }

    fn retain_scan_disclosure_quarantine(
        &self,
        record: &ScanDisclosureQuarantineRecord,
    ) -> Result<ScanDisclosureQuarantineRecord, OrsError> {
        if record.installation_id != self.binding.installation_id {
            return Err(OrsError::Contract(
                "quarantine installation conflicts with its owner binding".to_owned(),
            ));
        }
        match self.request(ScanDisclosureOwnerRpcAction::QuarantineRetain {
            binding: &self.binding,
            record,
        })? {
            ScanDisclosureOwnerRpcResult::QuarantineRecord {
                record: Some(retained),
            } if retained == *record => Ok(retained),
            ScanDisclosureOwnerRpcResult::QuarantineRecord { record: Some(_) } => {
                Err(OrsError::DuplicateConflict)
            }
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid quarantine retain result".to_owned(),
            )),
        }
    }

    fn load_scan_disclosure_quarantine(
        &self,
        quarantine_key: &str,
    ) -> Result<Option<ScanDisclosureQuarantineRecord>, OrsError> {
        if quarantine_key.trim().is_empty() {
            return Err(OrsError::Contract("quarantine key is empty".to_owned()));
        }
        match self.request(ScanDisclosureOwnerRpcAction::QuarantineLoad {
            binding: &self.binding,
            quarantine_key,
        })? {
            ScanDisclosureOwnerRpcResult::QuarantineRecord { record } => {
                if record
                    .as_ref()
                    .is_some_and(|retained| retained.quarantine_key != quarantine_key)
                {
                    return Err(OrsError::DuplicateConflict);
                }
                Ok(record)
            }
            ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            _ => Err(OrsError::Contract(
                "Kernel returned an invalid quarantine load result".to_owned(),
            )),
        }
    }
}

/// Daemon-side adapter for the authenticated Kernel route that owns durable
/// cold-start readiness leases and terminal receipts. This deliberately has
/// no scan-disclosure binding: readiness rows have a separate ORS lifecycle,
/// while the route authenticates the application connection and activation
/// ticket and checks the full claim against its retained activation.
pub struct KernelColdStartReadinessRecordOwner {
    kernel: Arc<super::DaemonKernelClient>,
    application_connection_id: String,
    activation_ticket_id: String,
    initial_bind_scope_proof: Option<InitialBindScopeOwnerProof>,
}

impl KernelColdStartReadinessRecordOwner {
    pub fn new(
        kernel: Arc<super::DaemonKernelClient>,
        application_connection_id: String,
        activation_ticket_id: String,
    ) -> Self {
        Self {
            kernel,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: None,
        }
    }

    pub fn new_initial(
        kernel: Arc<super::DaemonKernelClient>,
        application_connection_id: String,
        activation_ticket_id: String,
        proof: InitialBindScopeOwnerProof,
    ) -> Self {
        Self {
            kernel,
            application_connection_id,
            activation_ticket_id,
            initial_bind_scope_proof: Some(proof),
        }
    }

    fn request(
        &self,
        action: ColdStartReadinessOwnerRpcAction<'_>,
    ) -> Result<ColdStartReadinessOwnerRpcResult, OrsError> {
        let payload = serde_json::to_value(ColdStartReadinessOwnerRpcRequest {
            wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
            application_connection_id: &self.application_connection_id,
            activation_ticket_id: &self.activation_ticket_id,
            initial_bind_scope_proof: self.initial_bind_scope_proof.as_ref(),
            action,
        })
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        let value = self
            .kernel
            .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let response: ColdStartReadinessOwnerRpcResponse =
            serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
        if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
            return Err(OrsError::Contract(
                "unsupported cold-start readiness owner response version".to_owned(),
            ));
        }
        Ok(response.result)
    }
}

impl ColdStartReadinessRecordOwner for KernelColdStartReadinessRecordOwner {
    fn claim_cold_start_readiness(
        &self,
        key: &ColdStartReadinessOwnerKey,
        lease_deadline: u64,
        _now: u64,
    ) -> Result<ColdStartReadinessStageOutcome, OrsError> {
        match self.request(ColdStartReadinessOwnerRpcAction::ReadinessClaim { key })? {
            ColdStartReadinessOwnerRpcResult::ReadinessClaimed { outcome } => {
                let (ColdStartReadinessStageOutcome::Stored { record }
                | ColdStartReadinessStageOutcome::AlreadyBound { record }) = &outcome;
                record.validate()?;
                if &record.claim.key != key || record.claim.lease_deadline > lease_deadline {
                    return Err(OrsError::FenceMismatch);
                }
                Ok(outcome)
            }
            ColdStartReadinessOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            ColdStartReadinessOwnerRpcResult::ReadinessRecord { .. } => Err(OrsError::Contract(
                "Kernel returned an invalid cold-start readiness claim result".to_owned(),
            )),
        }
    }

    fn publish_cold_start_readiness(
        &self,
        record_key: &str,
        binding_digest: &str,
        lease_ref: &str,
        disposition: ColdStartReadinessTerminalDisposition,
        receipt_ref: &str,
        receipt_bytes: &str,
    ) -> Result<Option<ColdStartReadinessOrsRecord>, OrsError> {
        match self.request(ColdStartReadinessOwnerRpcAction::ReadinessPublish {
            record_key,
            binding_digest,
            lease_ref,
            disposition,
            receipt_ref,
            receipt_bytes,
        })? {
            ColdStartReadinessOwnerRpcResult::ReadinessRecord { record } => {
                Ok(record.map(|value| *value))
            }
            ColdStartReadinessOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            ColdStartReadinessOwnerRpcResult::ReadinessClaimed { .. } => Err(OrsError::Contract(
                "Kernel returned an invalid cold-start readiness publish result".to_owned(),
            )),
        }
    }

    fn load_cold_start_readiness(
        &self,
        record_key: &str,
    ) -> Result<Option<ColdStartReadinessOrsRecord>, OrsError> {
        match self.request(ColdStartReadinessOwnerRpcAction::ReadinessLoad { record_key })? {
            ColdStartReadinessOwnerRpcResult::ReadinessRecord { record } => {
                Ok(record.map(|value| *value))
            }
            ColdStartReadinessOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            ColdStartReadinessOwnerRpcResult::ReadinessClaimed { .. } => Err(OrsError::Contract(
                "Kernel returned an invalid cold-start readiness load result".to_owned(),
            )),
        }
    }

    fn load_cold_start_readiness_for_binding(
        &self,
        binding_digest: &str,
    ) -> Result<Option<ColdStartReadinessOrsRecord>, OrsError> {
        match self
            .request(ColdStartReadinessOwnerRpcAction::ReadinessLoadForBinding { binding_digest })?
        {
            ColdStartReadinessOwnerRpcResult::ReadinessRecord { record } => {
                Ok(record.map(|value| *value))
            }
            ColdStartReadinessOwnerRpcResult::ReceiptReadFailure { failure } => {
                Err(OrsError::ScanDisclosureReadFailure(failure))
            }
            ColdStartReadinessOwnerRpcResult::ReadinessClaimed { .. } => Err(OrsError::Contract(
                "Kernel returned an invalid cold-start readiness binding read result".to_owned(),
            )),
        }
    }
}

/// Requests a current contour through the same authenticated Kernel owner
/// route used by the durable record adapter.
pub fn request_scan_disclosure_contour(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
) -> Result<eliot_governor::InstallationScanContour, OrsError> {
    KernelScanDisclosureRecordOwner::issue_contour(
        kernel,
        application_connection_id,
        activation_ticket_id,
    )
}

/// Requests the authenticated Kernel owner to derive the scan binding from
/// retained session, workspace, privacy, lease and task-selection evidence.
pub fn request_scan_disclosure_binding(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
) -> Result<eliot_workscope::ScanDisclosureOwnerBinding, OrsError> {
    KernelScanDisclosureRecordOwner::issue_binding(
        kernel,
        application_connection_id,
        activation_ticket_id,
    )
}

/// Initial-lane contour request carrying the exact original accepted proof.
pub fn request_initial_scan_disclosure_contour(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    proof: &InitialBindScopeOwnerProof,
) -> Result<eliot_governor::InstallationScanContour, OrsError> {
    KernelScanDisclosureRecordOwner::issue_initial_contour(
        kernel,
        application_connection_id,
        activation_ticket_id,
        proof,
    )
}

/// Initial-lane binding request carrying the exact original accepted proof.
pub fn request_initial_scan_disclosure_binding(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    proof: &InitialBindScopeOwnerProof,
) -> Result<eliot_workscope::ScanDisclosureOwnerBinding, OrsError> {
    KernelScanDisclosureRecordOwner::issue_initial_binding(
        kernel,
        application_connection_id,
        activation_ticket_id,
        proof,
    )
}

/// Authenticates the first explicit BIND_SCOPE discovery against the original
/// Kernel ticket and lifecycle-retained lease before the first WorkScope owner
/// CAS. `envelope` and `evidence` are the exact values returned by the original
/// Task Controller claim; this function neither rebuilds them nor rewrites the
/// caller's proposal.
pub fn prepare_initial_bind_scope_discovery(
    kernel: &super::DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    evidence: &AgentActivationBindScopeEvidence,
    proposal: &InitialWorkScopeBindingRequest,
    now: u64,
) -> Result<(AgentActivationResolutionTicket, ColdStartDiscoveryInput), TaskBindingError> {
    let fail = |detail: &str| TaskBindingError::scope_incompatible(detail.to_owned());
    if envelope.validate().is_err()
        || evidence.validate().is_err()
        || envelope.kind != eliot_protocol::HostRequestKind::Invocation
        || envelope.identity.capability != "eliot.task-controller"
        || envelope.connection_id.trim().is_empty()
        || envelope.identity.session_id.as_deref() != Some(evidence.session_id.as_str())
        || envelope.identity.task_id.as_deref() != Some(evidence.task_id.as_str())
        || envelope.identity.work_scope_id.as_deref() != Some(evidence.work_scope_id.as_str())
        || envelope.identity.deadline_unix_ms != evidence.ticket_deadline_unix_ms
        || envelope.state_fence != evidence.state_fence
        || proposal
            .validate_for_task_scope(&evidence.work_scope_id)
            .is_err()
        || proposal.binding.scope.scope_ref != evidence.work_scope_id
        || proposal.descriptor.scope_ref != evidence.work_scope_id
        || proposal.sources.scope_ref != evidence.work_scope_id
        || proposal.descriptor.state_fence != evidence.state_fence
        || proposal.admission_deadline == 0
        || proposal.admission_deadline > evidence.ticket_deadline_unix_ms
        || now == 0
        || now > evidence.ticket_deadline_unix_ms
    {
        return Err(fail(
            "BIND_SCOPE proposal or original claim/evidence is not exact and current",
        ));
    }
    let explicit_root = proposal
        .explicit_root
        .to_str()
        .filter(|path| Path::new(path).is_absolute())
        .ok_or_else(|| fail("BIND_SCOPE requires one explicit absolute UTF-8 root"))?;
    let (facts, observed) =
        observe_explicit_workspace_facts(proposal.explicit_root.as_path(), &evidence.state_fence)?;
    let Some(instance) = observed.instances.first() else {
        return Err(fail(
            "Host observation returned no explicit workspace instance",
        ));
    };
    if observed.instances.len() != 1
        || proposal.binding.scope.root_identity != instance.root_identity
        || proposal.binding.scope.instance_ref != instance.instance_ref
        || proposal.descriptor.instances != observed.instances
        || proposal.descriptor.root_identities != observed.root_identities
        || proposal.descriptor.canonical_resource_refs != observed.canonical_resource_refs
        || proposal.descriptor.external_resource_refs != observed.external_resource_refs
        || proposal.descriptor.generation != observed.generation
        || proposal.descriptor.kind != observed.kind
        || proposal.descriptor.lineage != observed.lineage
    {
        return Err(fail(
            "BIND_SCOPE owner proposal disagrees with independent Host root facts",
        ));
    }
    let allowed_reads = initial_discovery_allowed_reads(&facts);
    let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
        wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
        application_connection_id: &envelope.connection_id,
        activation_ticket_id: &evidence.ticket_id,
        initial_bind_scope_proof: None,
        action: ScanDisclosureOwnerRpcAction::InitialBindScopeDiscovery {
            evidence,
            envelope,
            explicit_root,
            root_identity_ref: &instance.root_identity,
            allowed_reads: &allowed_reads,
        },
    })
    .map_err(|error| {
        fail(&format!(
            "BIND_SCOPE owner request encoding failed: {error}"
        ))
    })?;
    let value = kernel
        .request_blocking(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
        .map_err(|error| fail(&format!("BIND_SCOPE owner request failed: {error}")))?;
    let response: ScanDisclosureOwnerRpcResponse = serde_json::from_value(value)
        .map_err(|error| fail(&format!("BIND_SCOPE owner response is invalid: {error}")))?;
    if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
        return Err(fail("BIND_SCOPE owner returned another wire version"));
    }
    let observed_at = super::unix_ms();
    if observed_at == 0 || observed_at > evidence.ticket_deadline_unix_ms {
        return Err(TaskBindingError::selection_required(
            "original activation ticket expired while its discovery lease was being retained",
        ));
    }
    let (ticket, lease) = match response.result {
        ScanDisclosureOwnerRpcResult::InitialBindScopeDiscovery { ticket, lease } => {
            (ticket, lease)
        }
        ScanDisclosureOwnerRpcResult::InitialBindScopeRootRequired { ticket } => {
            if ticket.ticket_id != evidence.ticket_id
                || ticket.ticket_sha256 != evidence.ticket_sha256
                || ticket.connection_id != envelope.connection_id
                || ticket.state_fence != envelope.state_fence
                || ticket.kernel_deadline_unix_ms != evidence.ticket_deadline_unix_ms
                || ticket.workspace_selector.is_some()
            {
                return Err(fail(
                    "Kernel explicit-root prerequisite returned another ticket",
                ));
            }
            return Err(TaskBindingError::selection_required(
                "original activation ticket has no explicit workspace selector; submit a new explicit-root Attach",
            ));
        }
        _ => return Err(fail("Kernel returned the wrong first-scope owner result")),
    };
    ticket
        .validate()
        .and_then(|()| evidence.validate_against(&ticket))
        .map_err(|error| fail(&format!("original BIND_SCOPE ticket proof failed: {error}")))?;
    if ticket.ticket_id != evidence.ticket_id
        || ticket.ticket_sha256 != evidence.ticket_sha256
        || ticket.connection_id != envelope.connection_id
        || ticket.state_fence != envelope.state_fence
        || ticket.kernel_deadline_unix_ms != evidence.ticket_deadline_unix_ms
        || ticket.workspace_selector.as_deref() != Some(explicit_root)
        || lease.validate().is_err()
        || lease.proposer_ref != evidence.principal_id
        || lease.session_ref != evidence.session_id
        || lease.host_ref != ticket.peer_admission_receipt_sha256
        || lease.deadline != ticket.kernel_deadline_unix_ms
        || lease.candidate_root_ref != instance.root_identity
        || lease.root_filesystem_identity_ref != instance.root_identity
        || lease.allowed_reads != allowed_reads
        || proposal
            .discovery_lease
            .as_ref()
            .is_some_and(|proposed| proposed != &lease)
    {
        return Err(fail(
            "Kernel-retained discovery lease or BIND_SCOPE proposal identity conflicts",
        ));
    }
    let discovery = observe_cold_start_discovery(
        &ticket,
        &evidence.principal_id,
        &evidence.session_id,
        &evidence.state_fence,
        observed_at,
    )?;
    if discovery.lease != lease
        || discovery.discovery.evidence != proposal.bootstrap_discovery.evidence
        || discovery.discovery.observed != proposal.bootstrap_discovery.observed
        || discovery.discovery.scan_ref != proposal.bootstrap_discovery.scan_ref
        || discovery.discovery.proposed_kind != proposal.bootstrap_discovery.proposed_kind
        || discovery.discovery.identity_fingerprint
            != proposal.bootstrap_discovery.identity_fingerprint
        || discovery.discovery.governing_source_refs
            != proposal.bootstrap_discovery.governing_source_refs
    {
        return Err(fail(
            "BIND_SCOPE bootstrap proposal differs from fresh Host discovery or retained lease",
        ));
    }
    Ok((ticket, discovery))
}

fn initial_discovery_allowed_reads(facts: &WorkspaceInstanceFacts) -> Vec<DiscoveryRead> {
    let mut allowed_reads = vec![
        DiscoveryRead::FilesystemIdentity,
        DiscoveryRead::GoverningSourceCandidates,
    ];
    if facts.has_git {
        allowed_reads.push(DiscoveryRead::VcsIdentity);
    }
    if !facts.manifest_names.is_empty() {
        allowed_reads.push(DiscoveryRead::ManifestNamesAndHashes);
    }
    allowed_reads
}

async fn request_scan_work_scope_revision(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    initial_bind_scope_proof: Option<&InitialBindScopeOwnerProof>,
    action: ScanDisclosureOwnerRpcAction<'_>,
    expected_snapshot: &WorkScopeBindingSnapshot,
) -> Result<(), OrsError> {
    let payload = serde_json::to_value(ScanDisclosureOwnerRpcRequest {
        wire_version: SCAN_DISCLOSURE_OWNER_WIRE_VERSION,
        application_connection_id,
        activation_ticket_id,
        initial_bind_scope_proof,
        action,
    })
    .map_err(|error| OrsError::Contract(error.to_string()))?;
    let value = kernel
        .transact_async(SCAN_DISCLOSURE_OWNER_OPERATION, payload)
        .await
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    let response: ScanDisclosureOwnerRpcResponse =
        serde_json::from_value(value).map_err(|error| OrsError::Contract(error.to_string()))?;
    if response.wire_version != SCAN_DISCLOSURE_OWNER_WIRE_VERSION {
        return Err(OrsError::Contract(
            "Kernel scan disclosure owner returned another wire version".to_owned(),
        ));
    }
    match response.result {
        ScanDisclosureOwnerRpcResult::WorkScopeOwnerRevision {
            owner_revision,
            state_fence,
        } if owner_revision == expected_snapshot.owner_revision
            && state_fence == expected_snapshot.state_fence =>
        {
            Ok(())
        }
        ScanDisclosureOwnerRpcResult::WorkScopeOwnerRevision { .. } => Err(OrsError::Contract(
            "Kernel WorkScope owner CAS acknowledged another revision or fence".to_owned(),
        )),
        ScanDisclosureOwnerRpcResult::ReceiptReadFailure { failure } => {
            Err(OrsError::ScanDisclosureReadFailure(failure))
        }
        _ => Err(OrsError::Contract(
            "Kernel scan disclosure owner returned an unexpected result".to_owned(),
        )),
    }
}

/// Persists the Governor's exact lease-stage WorkScope snapshot through the
/// authenticated scan owner route and accepts only the matching durable
/// revision acknowledgement.
pub async fn retain_scan_discovery_lease_owner_revision(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    expected_owner_revision: u64,
    lease: &DiscoveryReadLease,
    snapshot: &WorkScopeBindingSnapshot,
) -> Result<(), OrsError> {
    request_scan_work_scope_revision(
        kernel,
        application_connection_id,
        activation_ticket_id,
        None,
        ScanDisclosureOwnerRpcAction::RetainDiscoveryLease {
            expected_owner_revision,
            lease,
            snapshot,
        },
        snapshot,
    )
    .await
}

/// Persists the Governor's exact post-scan WorkScope revision, including the
/// consumed discovery lease and its exact durable receipt binding.
pub async fn retain_scan_evidence_owner_revision(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    expected_owner_revision: u64,
    discovery_lease: &DiscoveryReadLease,
    evidence: &BootstrapScanEvidence,
    binding: &eliot_workscope::ScanDisclosureOwnerBinding,
    receipt_handle: &eliot_workscope::ScanReceiptHandle,
    snapshot: &WorkScopeBindingSnapshot,
) -> Result<(), OrsError> {
    request_scan_work_scope_revision(
        kernel,
        application_connection_id,
        activation_ticket_id,
        None,
        ScanDisclosureOwnerRpcAction::RetainScanEvidence {
            expected_owner_revision,
            discovery_lease,
            evidence,
            binding,
            receipt_handle,
            snapshot,
        },
        snapshot,
    )
    .await
}

/// Initial-lane counterpart that carries the original accepted proof through
/// the canonical owner CAS/readback.
pub async fn retain_initial_scan_discovery_lease_owner_revision(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    proof: &InitialBindScopeOwnerProof,
    expected_owner_revision: u64,
    lease: &DiscoveryReadLease,
    snapshot: &WorkScopeBindingSnapshot,
) -> Result<(), OrsError> {
    request_scan_work_scope_revision(
        kernel,
        application_connection_id,
        activation_ticket_id,
        Some(proof),
        ScanDisclosureOwnerRpcAction::RetainDiscoveryLease {
            expected_owner_revision,
            lease,
            snapshot,
        },
        snapshot,
    )
    .await
}

/// Initial-lane post-scan CAS/readback with the same original proof.
pub async fn retain_initial_scan_evidence_owner_revision(
    kernel: &super::DaemonKernelClient,
    application_connection_id: &str,
    activation_ticket_id: &str,
    proof: &InitialBindScopeOwnerProof,
    expected_owner_revision: u64,
    discovery_lease: &DiscoveryReadLease,
    evidence: &BootstrapScanEvidence,
    binding: &eliot_workscope::ScanDisclosureOwnerBinding,
    receipt_handle: &eliot_workscope::ScanReceiptHandle,
    snapshot: &WorkScopeBindingSnapshot,
) -> Result<(), OrsError> {
    request_scan_work_scope_revision(
        kernel,
        application_connection_id,
        activation_ticket_id,
        Some(proof),
        ScanDisclosureOwnerRpcAction::RetainScanEvidence {
            expected_owner_revision,
            discovery_lease,
            evidence,
            binding,
            receipt_handle,
            snapshot,
        },
        snapshot,
    )
    .await
}

/// Stable rejection code when task-bound promotion lacks current evidence.
pub const TASK_SELECTION_REQUIRED: &str = "TASK_SELECTION_REQUIRED";
/// Stable rejection code when evidence names another/incompatible `WorkScope`.
pub const TASK_SCOPE_INCOMPATIBLE: &str = "TASK_SCOPE_INCOMPATIBLE";

/// Compatibility disposition computed by the owning selector.
///
/// `Compatible` is the only disposition that admits reusable/task-bound
/// promotion. Any other disposition keeps the observation cold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityDisposition {
    /// Selection, contract revision, digest, scope, and fence all agree.
    Compatible,
    /// Selection names another scope or an incompatible contract revision.
    Incompatible,
}

/// Requirement class of one canonical operation before any gating
/// (issue #1746, W1; frozen against I7.6 and I5.5, not renegotiated per
/// request).
///
/// - `DiscoveryReadOnly` — authenticated discovery/read-only preview. Reachable
///   without a selected task (`state`/task-selection/bootstrap must stay
///   reachable or the user cannot select one). Never grants a task effect.
/// - `SafeRawCapture` — `observe` raw capture. May retain an explicitly
///   unbound/provisional cold candidate under its valid identity, privacy, and
///   staging policy ([`admit_capture`]); grants no task effect.
/// - `TaskRelativeEffectful` — task-bound promotion, control, action,
///   verification, and Finish. Requires the exact applicable task evidence
///   ([`admit_task_bound`]). Unauthenticated requests never gain exceptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalOperationRequirement {
    DiscoveryReadOnly,
    SafeRawCapture,
    TaskRelativeEffectful,
}

/// Maps the eight canonical MCP operations (I7.6) to their requirement class.
///
/// `state`/`query`/`packet` are authenticated read-only previews;
/// `observe` is the single safe raw capture surface; `act`/`verify`/
/// `coordinate`/`finish` are task-relative/effectful. A `None` return means
/// the name is not a canonical operation and is refused upstream, never
/// defaulted to a weaker class.
///
/// Frozen against the shared MCP contract (`crates/surfaces/eliot-mcp`
/// `ADMITTED_TOOL_NAMES` / `ToolRequest::canonical_name` carry exactly these
/// eight hot tools; the `eliot_user_automation`, `skill.inject`, and
/// `skill.display` non-hot carriers are not canonical operations and stay
/// `None`). Re-verify against that contract before changing this table; a
/// renamed tool never smuggles a weaker class past the gate.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher
/// maps tool names through this table before submitting; the daemon write path
/// re-derives its own requirement from the typed [`NamedMutationOperation`]
/// via [`requirement_for_named_mutation`], so a renamed tool cannot smuggle a
/// weaker class past the gate.
#[must_use]
pub fn classify_canonical_operation(operation: &str) -> Option<CanonicalOperationRequirement> {
    match operation {
        "eliot.state" | "eliot.query" | "eliot.packet" => {
            Some(CanonicalOperationRequirement::DiscoveryReadOnly)
        }
        "eliot.observe" => Some(CanonicalOperationRequirement::SafeRawCapture),
        "eliot.act" | "eliot.verify" | "eliot.coordinate" | "eliot.finish" => {
            Some(CanonicalOperationRequirement::TaskRelativeEffectful)
        }
        _ => None,
    }
}

/// Maps one `eliot.observe` typed suboperation (I7.6) to its requirement.
///
/// Every capture suboperation — `observation`, `decision`, `failure`,
/// `outcome`, `influence_ack` — is safe raw capture at admission: whether one
/// capture becomes task-bound is decided by the exact selection evidence in
/// [`admit_capture`], never by the suboperation name.
///
/// Frozen against the exact five `ObserveInput` kinds in the shared MCP
/// contract (`tag = "kind"`, `snake_case`); an unknown suboperation stays
/// `None` and is refused upstream, never defaulted.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher,
///
/// together with [`classify_canonical_operation`].
#[must_use]
pub fn classify_observe_suboperation(suboperation: &str) -> Option<CanonicalOperationRequirement> {
    match suboperation {
        "observation" | "decision" | "failure" | "outcome" | "influence_ack" => {
            Some(CanonicalOperationRequirement::SafeRawCapture)
        }
        _ => None,
    }
}

/// Maps one `eliot.coordinate` operation discriminator (I7.6) to its
/// requirement.
///
/// `inspect`/`wait` are read-only orientation over run lineage and durable
/// state; `delegate`/`audit`/`compare`/`cancel`/`send` create or reconcile
/// execution effects and are task-relative.
///
/// Frozen against the exact `CoordinateInput` discriminators in the shared
/// MCP contract (`snake_case` `operation` tag); an unknown discriminator stays
/// `None` and is refused upstream, never defaulted.
///
/// Designated caller (STITCH, surfaces lane): the agent-bridge MCP dispatcher,
/// together with [`classify_canonical_operation`].
#[must_use]
pub fn classify_coordinate_suboperation(
    suboperation: &str,
) -> Option<CanonicalOperationRequirement> {
    match suboperation {
        "inspect" | "wait" => Some(CanonicalOperationRequirement::DiscoveryReadOnly),
        "delegate" | "audit" | "compare" | "cancel" | "send" => {
            Some(CanonicalOperationRequirement::TaskRelativeEffectful)
        }
        _ => None,
    }
}

/// Maps one typed store mutation to its requirement class (issue #1746, W1).
///
/// This is the write-path side of the frozen table: `CaptureObservation` is
/// the safe raw capture leg, `UpdateTaskState`/`RecordFinishDecision`/
/// `RecordFinishEvidence` are the task-relative/effectful legs, and every
/// other named operation needs no task binding. Called by
/// [`admit_canonical_write`] to derive its capture/task-relative split, so the
/// split cannot drift from the table.
#[must_use]
pub fn requirement_for_named_mutation(
    operation: NamedMutationOperation,
) -> CanonicalOperationRequirement {
    match operation {
        NamedMutationOperation::CaptureObservation => CanonicalOperationRequirement::SafeRawCapture,
        NamedMutationOperation::UpdateTaskState
        | NamedMutationOperation::RecordFinishDecision
        | NamedMutationOperation::RecordFinishEvidence => {
            CanonicalOperationRequirement::TaskRelativeEffectful
        }
        _ => CanonicalOperationRequirement::DiscoveryReadOnly,
    }
}

/// Whether one canonical write envelope is task-relative (issue #1746, W4).
///
/// Single definition of the capture/task-relative split predicate behind
/// [`admit_canonical_write`]: a write that names a task, or that carries a
/// task-relative/effectful named mutation
/// ([`requirement_for_named_mutation`]), needs the live activation recheck
/// ([`admit_canonical_write_with_activation`]); anything else stays on the
/// receipt-only cold/non-task-relative legs, so permitted raw capture remains
/// cold without a retained terminal. Consulted by [`admit_canonical_write`]
/// and by the dispatch effect gate in
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition).
#[must_use]
pub fn envelope_is_task_relative(envelope: &CanonicalWriteEnvelope) -> bool {
    envelope.task_id.is_some()
        || envelope.semantic_commands.iter().any(|command| {
            requirement_for_named_mutation(command.operation)
                == CanonicalOperationRequirement::TaskRelativeEffectful
        })
}

/// Daemon dispatch entrypoint presenting one admission attempt
/// (issue #1746, A6).
///
/// Both entrypoints enforce the same binding through the same rule table
/// ([`entrypoint_requires_binding`]): the bridge transport edge
/// (`DaemonKernelClient::apply_prepared` via [`admit_named_mutation_capture`])
/// and the direct internal composition-root intake
/// ([`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition)
/// via [`admit_canonical_write`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEntrypoint {
    /// Bridge transport edge (`DaemonKernelClient::apply_prepared`).
    BridgeTransport,
    /// Direct internal composition-root intake
    /// (`DaemonComposition::commit_canonical_and_refresh`).
    DirectInternal,
}

/// Whether one dispatch entrypoint requires owner task evidence for one
/// requirement class (issue #1746, A6).
///
/// The table is deliberately entrypoint-independent: task-relative/effectful
/// work requires exact evidence at every entrypoint, while discovery/read-only
/// and safe raw capture (cold quarantined route) never do. The `entrypoint`
/// parameter forces every dispatch edge to declare itself and consult this one
/// shared rule instead of carrying a local copy. Consulted by
/// [`admit_canonical_write`] (`DirectInternal`) and
/// [`admit_named_mutation_capture`] (`BridgeTransport`).
#[must_use]
pub fn entrypoint_requires_binding(
    entrypoint: DispatchEntrypoint,
    requirement: CanonicalOperationRequirement,
) -> bool {
    match (entrypoint, requirement) {
        (
            DispatchEntrypoint::BridgeTransport | DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) => true,
        (
            DispatchEntrypoint::BridgeTransport | DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::DiscoveryReadOnly
            | CanonicalOperationRequirement::SafeRawCapture,
        ) => false,
    }
}

/// Safe raw cold candidate retained when selection is absent or ambiguous.
///
/// Carries no task activation, no support/influence promotion, and no finish
/// relevance: durable capture-first bytes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCandidate {
    /// Stable candidate identity derived by the caller.
    pub candidate_id: String,
    /// Fence under which the bytes were captured.
    pub state_fence: StateFence,
    /// Bounded reason; always the unbound-capture marker here.
    pub reason_ref: String,
}

impl ObservationCandidate {
    /// Builds the single cold unbound shape this module ever emits.
    pub fn cold_unbound(candidate_id: String, state_fence: StateFence) -> Self {
        Self {
            candidate_id,
            state_fence,
            reason_ref: "unbound-capture".to_owned(),
        }
    }

    /// Whether this candidate can affect task memory/support/finish (never).
    #[must_use]
    pub const fn affects_task(&self) -> bool {
        false
    }
}

/// Typed admission failure carrying exactly one stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskBindingError {
    code: &'static str,
    detail: String,
}

impl TaskBindingError {
    fn selection_required(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SELECTION_REQUIRED,
            detail: detail.into(),
        }
    }

    fn scope_incompatible(detail: impl Into<String>) -> Self {
        Self {
            code: TASK_SCOPE_INCOMPATIBLE,
            detail: detail.into(),
        }
    }

    /// Stable wire code (`TASK_SELECTION_REQUIRED` / `TASK_SCOPE_INCOMPATIBLE`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Bounded human detail (never a task guess).
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for TaskBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for TaskBindingError {}

/// Result of splitting capture admission from task-bound promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureAdmission {
    /// Durably retainable cold bytes with no task effects.
    ColdUnbound(ObservationCandidate),
    /// Exact selection admitted for a later governed binding transition.
    TaskBound(TaskSelectionEvidence),
}

/// Disposition of one daemon ingress attempt (issue #1929).
///
/// The variant, not the transport, decides what the write means: a cold
/// candidate carries no task activation, support/influence promotion, or
/// finish relevance, while `TaskBound` is only ever returned after the exact
/// selection evidence passed [`admit_task_bound`].
#[expect(
    clippy::large_enum_variant,
    reason = "TaskBound carries the sealed dispatch identity by value so the effect gate revalidates the exact admitted bytes"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskBindingAdmission {
    /// Cold unbound capture: durable bytes with no task effect.
    ColdUnbound(ObservationCandidate),
    /// Exact task-bound transition admitted toward the governed owner commit.
    ///
    /// Carries the sealed [`DispatchedBinding`] (issue #1746, W6): the admitted
    /// operation identity is the evidence plus its task, scope, principal,
    /// session, presented fence, and bootstrap/profile revision — never a
    /// mutable ambient selection. The dispatch edge must revalidate it against
    /// the live fence at the effect gate (see [`revalidate_dispatched_binding`]
    /// and [`revalidate_task_bound_for_effect`]) instead of reusing the
    /// caller-presented fence; a moved fence, task, revision, digest, scope,
    /// principal, session, or profile revision conflicts for rebind, it is
    /// never rewritten under the old operation identity.
    TaskBound(DispatchedBinding),
    /// Task-relative transition whose selection decision belongs to the
    /// caller that owns the exact selection evidence, never to a capture
    /// edge. Reported, never admitted and never silently downgraded.
    TaskRelative,
    /// Not a capture-first or task-relative write; no binding is required.
    NotTaskRelative,
}

/// Task-selection disposition a caller-presented readiness receipt carries.
///
/// This is the I5.6 step-4 resolution result. A current task binding is
/// admitted only when its owner-proven selection source/evidence is available;
/// task/revision/digest shape by itself does not become selection evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSelectionDisposition {
    /// The caller selected no task.
    Absent,
    /// One exploratory task is available for read-only orientation only.
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    /// More than one candidate task handle survived selection; none is chosen.
    /// The owner-issued handles are carried verbatim so the caller can answer
    /// with the bounded eligible set instead of inventing a choice.
    Ambiguous(Vec<String>),
    /// A task selection names an older revision; preserve the exact identity
    /// for the owner's refresh/rebind response instead of treating it as absent.
    Stale {
        task_ref: String,
        task_revision: u64,
    },
    /// One current `TaskContract` revision with owner-proven selection evidence.
    Current(TaskSelectionEvidence),
}

/// Agent-facing result of resolving the current task selection.
///
/// Absence carries the existing bounded task-intake shape for the retained
/// scope; task-candidate ambiguity preserves the exact owner-issued handles
/// and remains distinct from active-work scope ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskSelectionResponse {
    /// No current selection; caller can answer with this scope's intake shape.
    Absent(Box<eliot_workscope::TaskSelectionRequired>),
    /// Exploratory binding stays explicitly read-only, not material task work.
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    /// Multiple task candidates survived; none is selected.
    Ambiguous(Vec<String>),
    /// Stale task identity preserved for an explicit refresh/rebind response.
    Stale {
        task_ref: String,
        task_revision: u64,
    },
    /// One exact current `TaskContract` revision with its owner evidence.
    Current(TaskSelectionEvidence),
}

/// Typed identity correlation of one activation result to its exact ticket
/// (issue #1746, W2).
///
/// Every arm carries only owner-resolved values: the `Resolved` arm repeats
/// the principal/session/task/scope/revision the Governor's typed resolution
/// bound to the exact ticket, never a caller-supplied principal/task string
/// and never the bridge-process identity. Selection/retry/denial arms preserve
/// the exact owner-issued candidate handles and retry terms instead of
/// selecting the latest or most similar task. Stored Resolved/READY values are
/// projections, not authority: this correlation is valid only for the exact
/// ticket it was computed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationCorrelation {
    /// Exact ticket-bound application identity with its owner revision fence.
    Resolved {
        principal_id: String,
        session_id: String,
        task_id: String,
        work_scope_id: String,
        task_revision: u64,
        owner_revision: u64,
        state_fence: StateFence,
    },
    /// No task is selected; the bounded eligible task handles survive verbatim.
    TaskSelectionRequired {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// No scope is selected; the bounded eligible scope handles survive verbatim.
    ScopeSelectionRequired {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// Several scopes survived; none is chosen.
    ScopeAmbiguous {
        candidate_handles: Vec<String>,
        candidate_coverage: AgentActivationCandidateCoverage,
        recovery_handle: String,
    },
    /// Transient hold: retry only under the exact owner-issued retry terms.
    Retry {
        recovery_handle: String,
        dependency_ref: String,
        observed_dependency_revision: String,
        not_before_unix_ms: u64,
    },
    /// The ticket fence moved; re-resolve at the observed fence, never reuse.
    Stale {
        recovery_handle: String,
        observed_state_fence: Option<StateFence>,
    },
    /// Terminal owner denial; carries no identity and selects nothing.
    Denied { failure_handle: String },
}

/// Correlates one typed activation result to its exact ticket through the
/// existing activation route (issue #1746, W2).
///
/// Runs the existing owner join
/// (`AgentActivationResolutionResult::validate_against`, owned by
/// `eliot-protocol`): exact ticket identity/digest/fence/cancellation match,
/// deadline and successor-observation terms. A result for another ticket, a
/// mismatching digest/fence, or an expired/cancelled identity fails closed
/// with `TASK_SCOPE_INCOMPATIBLE`. The typed disposition is then projected
/// without invention: `Resolved` repeats the owner binding plus the
/// authenticated owner revision; every selection arm preserves the exact
/// owner-issued candidate handles; `NotReady` preserves the exact retry terms;
/// `StaleFence` preserves the observed fence; `FailedInternal` stays a denial.
/// No caller principal/task string enters on any arm, and the bridge-process
/// identity is never copied as the end user.
///
/// Designated caller (STITCH, activation lane): the activation resolution
/// projection (`bins/eliotd/src/activation_projection.rs`,
/// `map_governor_outcome_to_protocol`, behind
/// `GovernorComposition::resolve_activation_outcome`) correlates each produced
/// ticket/result pair here before the daemon derives the
/// `GovernorActivationSnapshot` that [`bind_current_task_selection`] consumes.
/// Until that wiring lands, this entry selects nothing and stores nothing.
pub fn correlate_activation_result(
    ticket: &AgentActivationResolutionTicket,
    result: &AgentActivationResolutionResult,
) -> Result<ActivationCorrelation, TaskBindingError> {
    result.validate_against(ticket).map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "activation result does not correlate to the exact ticket/request: {error}"
        ))
    })?;
    match &result.disposition {
        AgentActivationResolutionDisposition::Resolved { binding } => {
            let task_revision = binding.task_revision.parse::<u64>().map_err(|_| {
                TaskBindingError::scope_incompatible(
                    "activation binding carries no current task revision",
                )
            })?;
            if task_revision == 0 {
                return Err(TaskBindingError::scope_incompatible(
                    "activation binding carries no current task revision",
                ));
            }
            let evidence = result.owner_evidence.as_ref().ok_or_else(|| {
                TaskBindingError::scope_incompatible(
                    "resolved activation carries no authenticated owner evidence",
                )
            })?;
            Ok(ActivationCorrelation::Resolved {
                principal_id: binding.principal_id.clone(),
                session_id: binding.session_id.clone(),
                task_id: binding.task_id.clone(),
                work_scope_id: binding.work_scope_id.clone(),
                task_revision,
                owner_revision: evidence.owner_revision,
                state_fence: evidence.state_fence.clone(),
            })
        }
        AgentActivationResolutionDisposition::TaskSelectionRequired { selection } => {
            Ok(ActivationCorrelation::TaskSelectionRequired {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::ScopeSelectionRequired { selection } => {
            Ok(ActivationCorrelation::ScopeSelectionRequired {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
            Ok(ActivationCorrelation::ScopeAmbiguous {
                candidate_handles: selection.candidate_handles.clone(),
                candidate_coverage: selection.candidate_coverage,
                recovery_handle: selection.recovery_handle.clone(),
            })
        }
        AgentActivationResolutionDisposition::NotReady {
            recovery_handle,
            retry,
        } => Ok(ActivationCorrelation::Retry {
            recovery_handle: recovery_handle.clone(),
            dependency_ref: retry.dependency_ref.clone(),
            observed_dependency_revision: retry.observed_dependency_revision.clone(),
            not_before_unix_ms: retry.not_before_unix_ms,
        }),
        AgentActivationResolutionDisposition::StaleFence {
            recovery_handle,
            observed_state_fence,
        } => Ok(ActivationCorrelation::Stale {
            recovery_handle: recovery_handle.clone(),
            observed_state_fence: observed_state_fence.clone(),
        }),
        AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
            Ok(ActivationCorrelation::Denied {
                failure_handle: failure_handle.clone(),
            })
        }
    }
}

/// Builds the agent-facing task-selection response for one caller-presented
/// readiness receipt (issue #1746, W4).
///
/// This is the typed Absent/Ambiguous-bounded answer constructor behind
/// [`resolve_task_selection`]: `Absent` carries this scope's bounded intake
/// shape from the existing task-intake owner
/// (`eliot_workscope::task_selection_required`); `Ambiguous` preserves the
/// exact owner-issued candidate handles verbatim, and the receipt validation
/// in [`resolve_task_selection`] enforces the owner bound (2..=16) on this
/// exact receipt before they are returned, so the caller answers with the
/// eligible set instead of choosing; `Exploratory` stays explicitly read-only; `Stale` preserves the
/// exact revision for a refresh/rebind answer; `Current` without
/// owner-proven selection source/evidence is refused with
/// `TASK_SELECTION_REQUIRED` (structural validation of request-supplied
/// evidence is never sufficient). No task is ever auto-created to remove an
/// absence, and no cold capture is retroactively attached here.
///
/// Called by [`admit_canonical_write`] to derive its selection legs.
///
/// # Not yet reached (issue #1929)
///
/// That named caller is not live either. Measured on this tree by symbol,
/// this constructor has **two** code references, both of them inside entries
/// with no live caller: [`admit_bootstrap_context`] (zero call sites, disclosed
/// on its own entry) and [`admit_canonical_write`], whose only two callers are
/// [`admit_canonical_write_with_activation`] and
/// `DaemonComposition::commit_canonical_and_refresh`, and that composition entry
/// has zero production call sites. So this answer constructor is transitively
/// dead at depth three and no typed selection leg is derived on any live daemon
/// path. The blocking symbol is the compiled readiness receipt named in this
/// module's "Measured reachability" section; a production caller needs that owner
/// to exist first, and none was invented to close the gap.
pub fn selection_response_for_receipt(
    receipt: &OnboardingReadinessReceipt,
) -> Result<TaskSelectionResponse, TaskBindingError> {
    match resolve_task_selection(receipt)? {
        TaskSelectionDisposition::Absent => {
            let intake = task_selection_required(&receipt.scope.scope_ref).map_err(|_| {
                TaskBindingError::selection_required(
                    "task selection is absent and no intake shape is available",
                )
            })?;
            Ok(TaskSelectionResponse::Absent(Box::new(intake)))
        }
        TaskSelectionDisposition::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => Ok(TaskSelectionResponse::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        }),
        TaskSelectionDisposition::Ambiguous(candidate_handles) => {
            Ok(TaskSelectionResponse::Ambiguous(candidate_handles))
        }
        TaskSelectionDisposition::Stale {
            task_ref,
            task_revision,
        } => Ok(TaskSelectionResponse::Stale {
            task_ref,
            task_revision,
        }),
        TaskSelectionDisposition::Current(evidence) => Ok(TaskSelectionResponse::Current(evidence)),
    }
}

/// Admits one `eliot.observe` capture without ever guessing a task.
///
/// - `selection = None` or `candidate_count != 1` (absent/ambiguous) admits
///   only [`CaptureAdmission::ColdUnbound`]: no activation, promotion, or
///   finish relevance.
/// - Exactly one canonical, valid, compatible, uncontaminated selection admits
///   [`CaptureAdmission::TaskBound`] for a later governed binding transition;
///   this function still performs no promotion itself. A contaminated
///   selection (canonical crossover marker) stays cold, mirroring the
///   Governor `Quarantined` disposition.
/// - There is deliberately no `latest_task`, `open_task`, or resolver-guess
///   input: ambiguity stays cold.
pub fn admit_capture(
    candidate_id: String,
    state_fence: StateFence,
    selection: Option<&TaskSelectionEvidence>,
    candidate_count: usize,
    compatibility: CompatibilityDisposition,
) -> Result<CaptureAdmission, TaskBindingError> {
    if state_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "capture.state_fence is invalid",
        ));
    }
    if candidate_id.trim().is_empty() || candidate_id.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "capture.candidate_id is blank",
        ));
    }
    match selection {
        None => Ok(CaptureAdmission::ColdUnbound(
            ObservationCandidate::cold_unbound(candidate_id, state_fence),
        )),
        Some(evidence) => {
            if candidate_count != 1 {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            evidence.validate().map_err(|error| {
                TaskBindingError::selection_required(format!(
                    "task selection evidence invalid: {error}"
                ))
            })?;
            if evidence.is_contaminated() {
                return Ok(CaptureAdmission::ColdUnbound(
                    ObservationCandidate::cold_unbound(candidate_id, state_fence),
                ));
            }
            match compatibility {
                CompatibilityDisposition::Compatible => {
                    Ok(CaptureAdmission::TaskBound(evidence.clone()))
                }
                CompatibilityDisposition::Incompatible => {
                    Err(TaskBindingError::scope_incompatible(
                        "task selection is incompatible with observation scope",
                    ))
                }
            }
        }
    }
}

/// Admits one task-relative reusable/control transition.
///
/// Requires the canonical selection evidence, the expected task and
/// `WorkScope` handles, a valid current fence that scopes this admission,
/// and a `Compatible` disposition. Missing evidence rejects with
/// `TASK_SELECTION_REQUIRED`; a `WorkScope`/task mismatch or an incompatible
/// disposition rejects with `TASK_SCOPE_INCOMPATIBLE` without changing either
/// task (this function mutates nothing). A contaminated selection never
/// promotes: it rejects as non-current evidence.
pub fn admit_task_bound(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected_work_scope_ref: &str,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
) -> Result<(), TaskBindingError> {
    let Some(evidence) = selection else {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires current TaskSelectionEvidence",
        ));
    };
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != expected_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different task",
        ));
    }
    if evidence.work_scope_ref != expected_work_scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task selection names a different WorkScope",
        ));
    }
    if expected_fence.validate().is_err() {
        return Err(TaskBindingError::selection_required(
            "task-bound promotion requires a valid current fence",
        ));
    }
    match compatibility {
        CompatibilityDisposition::Compatible => Ok(()),
        CompatibilityDisposition::Incompatible => Err(TaskBindingError::scope_incompatible(
            "task selection is incompatible with the target WorkScope",
        )),
    }
}

/// Refuses a task-identity conflict between the admitted request context and
/// the write envelope (issue #1746, A2).
///
/// A task-relative write whose envelope names a different task than the
/// admitted context — or names no task at all — can never receive a task-bound
/// write: the former fails closed with `TASK_SCOPE_INCOMPATIBLE`, the latter
/// with `TASK_SELECTION_REQUIRED`. Neither arm changes a task. Called by
/// [`admit_canonical_write`] for its task-relative leg, so the wrong
/// workspace/task case rejects before any selection evidence is consulted.
///
/// # Not yet reached (issue #1929)
///
/// That named caller is itself unreachable. Measured on this tree by symbol,
/// this refusal has exactly **one** code reference: the task-relative leg
/// inside [`admit_canonical_write`], whose only callers are
/// [`admit_canonical_write_with_activation`] and
/// `DaemonComposition::commit_canonical_and_refresh`, and that composition entry
/// has zero production call sites. So the wrong-workspace/wrong-task case is
/// not rejected by this entry on any live daemon path — the ordering sentence
/// above describes the code as written, not a behaviour production enforces
/// today. The two stable codes stay enforced on the real write path by
/// `eliot_store_surreal::task_binding_gate::gate_apply`, which re-derives them
/// from the opaque proof handles the transition actually carries. No caller was
/// invented to close the gap.
pub fn refuse_task_identity_conflict(
    context_task_ref: Option<&str>,
    envelope_task_ref: Option<&str>,
) -> Result<String, TaskBindingError> {
    let Some(envelope_task_ref) = envelope_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-relative write names no task binding",
        ));
    };
    if envelope_task_ref.trim().is_empty() || envelope_task_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-relative write names no task binding",
        ));
    }
    if let Some(context_task_ref) = context_task_ref
        && context_task_ref != envelope_task_ref
    {
        return Err(TaskBindingError::scope_incompatible(
            "task-relative write names a different task than the admitted context",
        ));
    }
    Ok(envelope_task_ref.to_owned())
}

/// Refuses a material effect without owner-proven selection evidence
/// (issue #1746, A7).
///
/// A READY lifecycle token, a successful handshake, or a pure DTO shape grants
/// nothing by itself: without owner evidence this entry fails closed with
/// `TASK_SELECTION_REQUIRED` however material the receipt claims to be, and
/// the READY token is never even read. With owner evidence the bootstrap must
/// additionally rest on an authenticated scope at material readiness, or the
/// effect is withheld with `TASK_SCOPE_INCOMPATIBLE`. Called by
/// [`admit_canonical_write`] for its task-relative leg before
/// [`admit_task_bound`].
///
/// # Not yet reached (issue #1929)
///
/// That named caller is itself unreachable, exactly as for
/// [`refuse_task_identity_conflict`] on the preceding leg. Measured on this
/// tree by symbol, this refusal has exactly **one** code reference: the
/// task-relative leg inside [`admit_canonical_write`], whose only callers are
/// [`admit_canonical_write_with_activation`] and
/// `DaemonComposition::commit_canonical_and_refresh`, and that composition entry
/// has zero production call sites. So this entry is transitively dead and the
/// "never even read the READY token" property above is a property of the code as
/// written, not a behaviour a live daemon path currently applies. The module's
/// "Measured reachability" section records the same fact from the caller side;
/// no caller was invented to close the gap.
pub fn refuse_ready_string_without_evidence(
    receipt: &OnboardingReadinessReceipt,
    has_owner_evidence: bool,
) -> Result<(), TaskBindingError> {
    if !has_owner_evidence {
        return Err(TaskBindingError::selection_required(
            "task-relative effect has no owner-proven selection evidence; readiness tokens grant nothing",
        ));
    }
    if receipt.scope_resolution != ScopeResolutionState::Authenticated
        || receipt.readiness != ReadinessLifecycle::ReadyMaterial
    {
        return Err(TaskBindingError::scope_incompatible(
            "task-relative effect rests on a bootstrap that is not authenticated material readiness",
        ));
    }
    Ok(())
}

/// Runs the existing `WorkScope` guard at one use boundary and returns the
/// typed disposition (issue #1746, W3; I4.2.1).
///
/// The observed binding is derived from the actual live workspace/resource
/// observation through the existing owner (`eliot_workscope::observed_scope_binding`:
/// exact instance/root, lineage, and resource generation — never a caller cwd
/// or a normalized path string), then checked with the existing owner guard
/// (`eliot_workscope::check_at_trigger`) at the caller-named trigger
/// (`SessionAttachResume`, `FirstToolEvent`, `AgentLaunch`, `RootChange`,
/// `CanonicalWrite`, `MaterialEffect`, or `GenerationChange`) with the
/// gate-supplied governing-source closure. `Allow` returns `MATCHED`;
/// anything else returns the exact disposition — stale, different-instance,
/// ambiguous, provisional, or conflicted — and the retained binding, task
/// state, and project memory stay untouched. An identity-clear observation
/// without a `MATCHED` owner receipt (no source closure supplied, or a
/// disagreeing receipt) returns `PROVISIONAL_REBIND` — or the receipt's own
/// `CONFLICTED` — instead of admitting: scope uncertainty permits only the
/// quarantined capture route ([`admit_capture`] `ColdUnbound`, conflicting
/// lineage preserved). A relocation is not a silent move: the legs compare
/// the exact instance/root, lineage, and generation, so a moved observation
/// reports `DIFFERENT_INSTANCE` (or `STALE_BINDING` for a moved revision);
/// only an explicit owner receipt (`produce_attach_receipt` /
/// `rebind_with_receipt`, owned by `eliot-workscope` and admitted by
/// `GovernorComposition::admit_observed_scope_attach`) can establish a new
/// binding.
///
/// Reference (read-only, Governor-owned; issue #1746, W3): the retained-data
/// leg is `GovernorComposition::require_scope_guard_for_observed` /
/// `require_fresh_matched_binding`, and the canonical-write trigger is
/// `GovernorComposition::check_canonical_write_work_scope` (already joined in
/// `DaemonComposition::commit_canonical_and_refresh` after
/// [`admit_canonical_write`]). This entry is the daemon's observation-derived
/// legs over the same owner primitives — it mints no receipt and installs no
/// binding.
///
/// Called by [`admit_task_bound_with_observed_scope`].
///
/// # Not yet reached (issue #1929)
///
/// That is the whole caller set, so this entry is dead transitively: its only
/// caller has one caller of its own, [`observe_and_admit_task`], which has zero
/// call sites (see this module's "Measured reachability" section). The next
/// live `check_at_trigger` owner leg is
/// `GovernorComposition::check_canonical_write_work_scope`, joined in
/// `DaemonComposition::commit_canonical_and_refresh`; this composition-level
/// disposition mapper is the unwired observation-derived duplicate of it.
pub fn scope_guard_disposition(
    expected: &ScopeBinding,
    observed: &ObservedScopeResources,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    trigger: eliot_workscope::GuardTrigger,
) -> Result<ScopeBindingDisposition, TaskBindingError> {
    let observed_binding = eliot_workscope::observed_scope_binding(
        expected,
        observed,
        expected.privacy_class,
        expected.governing_source_generation,
    )
    .map_err(|error| match error {
        eliot_workscope::WorkScopeError::AmbiguousObservation { observed_instances } => {
            TaskBindingError::scope_incompatible(format!(
                "task observation scope identity check AMBIGUOUS: {observed_instances} workspace instances observed"
            ))
        }
        other => TaskBindingError::scope_incompatible(format!(
            "task observation scope identity could not be established: {other}"
        )),
    })?;
    // The full owner guard, not the sources-independent identity legs alone:
    // `Allow` requires identity-clear `MATCHED`, so the provisional and
    // conflicted dispositions below are reachable, never dead arms.
    let report =
        eliot_workscope::check_at_trigger(expected, &observed_binding, source_closure, trigger);
    if report.verdict == eliot_workscope::GuardVerdict::Allow {
        return Ok(ScopeBindingDisposition::Matched);
    }
    match report.identity {
        eliot_workscope::IdentityLegOutcome::DifferentInstance => {
            Ok(ScopeBindingDisposition::DifferentInstance)
        }
        eliot_workscope::IdentityLegOutcome::Ambiguous => Ok(ScopeBindingDisposition::Ambiguous),
        eliot_workscope::IdentityLegOutcome::StaleBinding => {
            Ok(ScopeBindingDisposition::StaleBinding)
        }
        eliot_workscope::IdentityLegOutcome::IdentityClear => Ok(match report.receipt {
            Some(receipt) if receipt.disposition != ScopeBindingDisposition::Matched => {
                receipt.disposition
            }
            _ => ScopeBindingDisposition::ProvisionalRebind,
        }),
    }
}

/// Admits one task-relative transition with observed workspace identity.
///
/// Extends [`admit_task_bound`] with the full owner scope guard at the
/// caller-named I4.2.1 trigger. It derives the observed binding from the
/// complete live workspace observation, including lineage, exact
/// instance/root, and resource generation, and runs
/// [`scope_guard_disposition`] — the existing `check_at_trigger` owner legs
/// with the gate-supplied governing-source closure — so only a `MATCHED`
/// (`Allow`) observation proceeds. A mismatching checkout fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` naming the exact disposition
/// (`DIFFERENT_INSTANCE`, `AMBIGUOUS`, `STALE_BINDING`, `PROVISIONAL_REBIND`,
/// or `CONFLICTED`); the retained binding, task state, and project memory
/// are untouched. A provisional observation withholds pending source closure:
/// scope uncertainty permits only the quarantined capture route
/// ([`admit_capture`] `ColdUnbound`), never a task-bound effect here.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[allow(
    clippy::too_many_arguments,
    reason = "admission joins the retained binding, live observation, fence, compatibility, source closure, and trigger in one edge"
)]
pub fn admit_task_bound_with_observed_scope(
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    observed: &ObservedScopeResources,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    trigger: eliot_workscope::GuardTrigger,
) -> Result<(), TaskBindingError> {
    if selection.is_none() {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    }
    let observed_binding = scope_guard_disposition(expected, observed, source_closure, trigger)?;
    match observed_binding {
        ScopeBindingDisposition::Matched => {}
        ScopeBindingDisposition::DifferentInstance => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check DIFFERENT_INSTANCE",
            ));
        }
        ScopeBindingDisposition::Ambiguous => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check AMBIGUOUS",
            ));
        }
        ScopeBindingDisposition::StaleBinding => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check STALE_BINDING",
            ));
        }
        ScopeBindingDisposition::ProvisionalRebind => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check PROVISIONAL_REBIND: withheld pending source closure; scope uncertainty permits only the quarantined capture route",
            ));
        }
        ScopeBindingDisposition::Conflicted => {
            return Err(TaskBindingError::scope_incompatible(
                "task observation scope identity check CONFLICTED: rebind with an explicit owner receipt",
            ));
        }
    }
    admit_task_bound(
        selection,
        expected_task_ref,
        &expected.scope.scope_ref,
        expected_fence,
        compatibility,
    )
}

/// Resolves the exact task-selection disposition of one caller-presented
/// readiness receipt (I5.6 step 4, issue #1929).
///
/// The caller-presented receipt is an owner artifact, so its bound references
/// are validated first: Absent/Ambiguous answers always carry the owner's
/// bounded intake/handles (ambiguous handles 2..=16, enforced by the receipt
/// owner on this exact receipt), never an unbounded caller set. An invalid
/// receipt fails closed with `TASK_SCOPE_INCOMPATIBLE` and resolves nothing.
///
/// A current binding resolves only from the owner-proven selection
/// source/evidence refs the promoting owner admitted into the receipt
/// (`TaskIntakeCandidate::promote`): the evidence is structurally validated
/// here, never fabricated, and admission additionally requires the live
/// applicability recheck in [`bind_current_task_selection`] — a `Current`
/// receipt with no owner-validated activation snapshot never admits
/// task-bound work. The governance profile and receipt
/// handle are unrelated to task selection and are not used as provenance.
/// Every non-current binding state keeps its typed meaning:
///
/// - [`TaskBindingState::None_`] — the caller selected no task;
/// - `Exploratory` — a task is named but the binding is explicitly
///   non-material, so it remains a read-only disposition;
/// - `Stale` — the exact named revision is no longer current and is preserved
///   for an owner refresh/rebind response;
/// - `Ambiguous` — several candidate handles survived selection and the receipt
///   is forbidden to prefer one, so the candidate count is preserved and the
///   disposition stays non-material.
///
/// There is deliberately no latest-task, open-task, or resolver-guess leg here:
/// ambiguity is reported, never resolved. The task-intake owner shape is
/// produced by `eliot_workscope::task_selection_required` and consumed by
/// [`selection_response_for_receipt`]; the owner-proven selection
/// source/evidence refs arrive through the promoting owner above, never
/// through a request.
pub fn resolve_task_selection(
    receipt: &OnboardingReadinessReceipt,
) -> Result<TaskSelectionDisposition, TaskBindingError> {
    receipt.validate().map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "compiled readiness receipt is invalid: {error}"
        ))
    })?;
    match &receipt.task_binding {
        TaskBindingState::CurrentTaskContract {
            task_ref,
            task_revision,
            acceptance_digest,
            selection_source_ref,
            evidence_ref,
        } => {
            let evidence = TaskSelectionEvidence {
                task_ref: task_ref.clone(),
                task_revision: *task_revision,
                acceptance_digest: acceptance_digest.clone(),
                work_scope_ref: receipt.scope.scope_ref.clone(),
                selection_source_ref: selection_source_ref.clone(),
                evidence_ref: evidence_ref.clone(),
                contamination_flags: Vec::new(),
            };
            evidence.validate().map_err(|error| {
                TaskBindingError::selection_required(format!(
                    "current task selection evidence is invalid: {error}"
                ))
            })?;
            Ok(TaskSelectionDisposition::Current(evidence))
        }
        TaskBindingState::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => Ok(TaskSelectionDisposition::Exploratory {
            task_ref: task_ref.clone(),
            task_revision: *task_revision,
            acceptance_digest: acceptance_digest.clone(),
        }),
        TaskBindingState::Ambiguous { candidate_handles } => Ok(
            TaskSelectionDisposition::Ambiguous(candidate_handles.clone()),
        ),
        TaskBindingState::Stale {
            task_ref,
            task_revision,
        } => Ok(TaskSelectionDisposition::Stale {
            task_ref: task_ref.clone(),
            task_revision: *task_revision,
        }),
        TaskBindingState::None_ => Ok(TaskSelectionDisposition::Absent),
    }
}

/// Rechecks one Governor-resolved task selection against the current
/// applicability and fence before any admission (I5.6 step 4, issue #1746 W4).
///
/// [`resolve_task_selection`] resolves `CurrentTaskContract` from the
/// receipt's owner-proven selection source/evidence refs; this entry is the
/// applicability leg required by the issue: the ORIGINAL owner evidence is
/// validated as compiled
/// (non-zero `TaskContract` revision, acceptance-digest shape, `WorkScope`,
/// selection source and evidence handles), then every selection field is
/// rechecked at this exact fence — revision and `WorkScope` against what the
/// activation route proved (principal, session, task, non-zero revision,
/// `WorkScope`), and the acceptance digest against the owner-compiled receipt
/// original, which the activation snapshot does not carry. A selection naming
/// another task, moved revision, moved digest, or other scope rejects with
/// `TASK_SCOPE_INCOMPATIBLE` and admits nothing. Until then,
/// no current selection evidence escapes this entry.
///
/// Structure preserved, never resolved:
///
/// - [`TaskSelectionDisposition::Absent`] stays absent. No task is created to
///   remove a missing selection;
/// - [`TaskSelectionDisposition::Ambiguous`] keeps the owner-issued candidate
///   handles verbatim (bounded by the owner that produced them) so the caller
///   can return the typed selection/intake response. None is chosen;
/// - exploratory bindings remain explicitly read-only, and stale bindings
///   preserve the exact task and revision for an owner refresh/rebind response;
/// - a receipt compiled for a different `WorkScope` or a different fence is
///   refused before the binding state is even inspected.
///
/// It reads no caller-supplied `TaskSelectionEvidence`: structural validation
/// of evidence a request carried is never sufficient here.
///
/// Owner seam, stated exactly: the `TaskContract` revision, `WorkScope`,
/// principal/session, and fence are rechecked against the live
/// [`eliot_governor::GovernorActivationSnapshot`]; the acceptance digest is
/// rechecked against the owner-compiled receipt original
/// (`TaskBindingState::CurrentTaskContract`), which the activation snapshot
/// does not carry. The owner-proven selection source/evidence refs rest on the
/// Governor-compiled receipt (`ColdStartController::compile` through the
/// retained cold-start terminal) plus structural validation here — never
/// synthesized, never read from the request.
pub fn bind_current_task_selection(
    activation: Option<&eliot_governor::GovernorActivationSnapshot>,
    receipt: &OnboardingReadinessReceipt,
    live_fence: &StateFence,
) -> Result<TaskSelectionDisposition, TaskBindingError> {
    receipt.validate().map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "compiled readiness receipt is invalid: {error}"
        ))
    })?;
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt was compiled at another fence",
        ));
    }
    let disposition = resolve_task_selection(receipt)?;
    let TaskSelectionDisposition::Current(evidence) = &disposition else {
        // The Governor's current-task owner returns no activation for these
        // receipt states. A contradictory activation must fail closed rather
        // than being discarded or reported as an ordinary task choice.
        if activation.is_some() {
            return Err(TaskBindingError::scope_incompatible(
                "activation route returned a task for a non-current TaskContract receipt",
            ));
        }
        return Ok(disposition);
    };
    let activation = activation.ok_or_else(|| {
        TaskBindingError::scope_incompatible(
            "current TaskContract receipt has no owner-validated activation snapshot",
        )
    })?;
    if !eliot_contracts::fences_match_exact(&activation.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "activation snapshot is not applicable at the current fence",
        ));
    }
    if receipt.principal_ref != activation.principal_id
        || receipt.session_ref != activation.session_id
        || receipt.scope.scope_ref != activation.work_scope_id
    {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt is bound to another principal, session, or WorkScope",
        ));
    }
    // Issue #1746, W4: validate the ORIGINAL owner evidence as compiled
    // before rechecking its fields. Structural validation of a
    // request-supplied copy is never sufficient; this validates the
    // Governor-compiled original (revision, digest shape, scope, selection
    // source/evidence handles) and then compares every field at this fence.
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != activation.task_id.as_str()
        || evidence.task_revision != activation.task_revision
        || evidence.work_scope_ref != activation.work_scope_id
    {
        return Err(TaskBindingError::scope_incompatible(
            "task selection is no longer the applicable TaskContract revision",
        ));
    }
    // The activation snapshot carries no acceptance digest, so the digest is
    // rechecked against the owner-compiled receipt original: a selection whose
    // digest is not the currently applicable one rejects here, never admitted.
    let TaskBindingState::CurrentTaskContract {
        acceptance_digest: receipt_digest,
        ..
    } = &receipt.task_binding
    else {
        return Err(TaskBindingError::scope_incompatible(
            "task selection acceptance digest has no current TaskContract original",
        ));
    };
    if evidence.acceptance_digest != *receipt_digest {
        return Err(TaskBindingError::scope_incompatible(
            "task selection acceptance digest is not the currently applicable digest",
        ));
    }
    if receipt.scope_resolution != eliot_workscope::ScopeResolutionState::Authenticated {
        return Err(TaskBindingError::scope_incompatible(
            "task selection rests on a scope that is not authenticated",
        ));
    }
    if receipt.readiness != eliot_workscope::ReadinessLifecycle::ReadyMaterial {
        return Err(TaskBindingError::scope_incompatible(
            "task selection rests on a readiness that is not material-ready",
        ));
    }
    Ok(disposition)
}

/// Agent-facing bootstrap admission assembled from real owners
/// (issue #1746, W5; I7.8 step 4, I7.11).
#[expect(
    clippy::large_enum_variant,
    reason = "Material carries the owner-evidenced bootstrap identity by value so the dispatch gate sees the exact admitted fields"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapAdmission {
    /// Complete owner-evidenced bootstrap: may proceed to Material work only
    /// through the #1742 owner gate
    /// (`GovernorComposition::commit_canonical_with_readiness`, which runs
    /// `check_material_readiness_for_write`). This value is not Material
    /// authority by itself.
    Material(MaterialBootstrap),
    /// Diagnostic bootstrap: selection/intake data, never Material-ready.
    /// A bootstrap without a task always lands here. It carries the exact
    /// non-material task-or-selection-state (bounded eligible handles,
    /// exploratory/stale identity, or the current evidence withheld on
    /// readiness/profiles) so the caller answers from owner evidence instead
    /// of inventing a choice.
    Diagnostic {
        reason: &'static str,
        next_safe_action: String,
        selection: TaskSelectionResponse,
    },
    /// No task is selected: answer with this scope's bounded intake shape.
    IntakeRequired(Box<eliot_workscope::TaskSelectionRequired>),
}

/// Owner-evidenced bootstrap identity carried toward the #1746 dispatch gate.
///
/// Every field repeats an owner-issued value bound to the same
/// session/scope/selection-state and source revisions: the receipt revision
/// and fence from the compiled [`OnboardingReadinessReceipt`], the governance
/// profile revision from the Governor-derived [`GovernanceProfile`], the
/// coverage fingerprint from the verified [`IntegrationCoverageProfile`], and
/// the projection source/generation from #8's `ColdStartSurfaceView`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterialBootstrap {
    pub receipt_ref: String,
    pub lease_ref: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub scope_ref: String,
    pub task: TaskSelectionEvidence,
    pub state_fence: StateFence,
    pub receipt_revision: u64,
    pub governance_profile_ref: String,
    pub governance_revision: u64,
    pub coverage_fingerprint: String,
    pub projection_source_ref: String,
    pub projection_generation: u64,
}

/// Assembles one bootstrap from its real owners and admits it for dispatch
/// (issue #1746, W5; I7.8 step 4, I7.11).
///
/// Joins #8's response surface (`ColdStartSurfaceView` with boot delta) to the
/// compiled [`OnboardingReadinessReceipt`], the [`IntegrationCoverageProfile`],
/// and the derived [`GovernanceProfile`], all bound to the same
/// session/scope/task-or-selection-state and source revisions: receipt/lease,
/// principal/session, scope/descriptor-revision/instance/lineage,
/// scope-resolution state, task binding, state fence,
/// governing-source set/generation, governance/route profile refs, receipt
/// revision, and projection source/generation must name the same values on
/// both sides, or the join fails closed with `TASK_SCOPE_INCOMPATIBLE`.
///
/// Unknown/unavailable/partial profile evidence is preserved, never defaulted:
/// absent coverage/governance profiles, or present-but-unverified ones, yield
/// `Diagnostic`, never `Material`. A governance profile at revision zero fails
/// closed instead: the owner derivation never issues it (see below), so zero
/// was defaulted, never derived. Empty sensor lists or a caller READY flag
/// cannot imply full readiness — and the surface's string readiness token is
/// never even read here (issue #1746, A7): only the receipt's typed
/// [`ReadinessLifecycle`] and the surface's typed [`ScopeResolutionState`]
/// decide. `Material` additionally requires an authenticated scope, material
/// readiness, exact current selection evidence, and fingerprint-matched
/// verified profiles; anything else is `Diagnostic` (without a task, always,
/// carrying the exact non-material task-or-selection-state) or
/// `IntakeRequired` (no task selected). Budget previews and expansion
/// handles travel on the owners' surfaces; required selection, authority, and
/// recovery information is never dropped by this join.
///
/// Designated caller (STITCH, daemon composition lane):
/// `DaemonComposition::read_cold_start_surface_for_attach` supplies the exact
/// retained surface for the lease, and
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition)
/// carries the admitted bootstrap toward the #1742 Material gate. `now` is the
/// caller's unix-millisecond observation clock (the same clock
/// [`observe_cold_start_discovery`] takes): the join honors #8's bounded
/// freshness instead of re-deriving it, so an expired receipt or lease fails
/// closed here before any owner field is compared. This entry
/// mints no profile, receipt, or lease of its own.
///
/// # Not yet reached (issue #1929)
///
/// Measured on this tree, this entry has **zero call sites**: no code in any
/// crate names it other than its defining line; every other mention in the tree
/// is a [`admit_bootstrap_context`] prose back-link. Both designated callers
/// above are themselves uncalled —
/// `DaemonComposition::read_cold_start_surface_for_attach` has zero call sites
/// (`caller: STITCH`), and
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition)
/// has zero production call sites (see this module's "Measured reachability"
/// section) — so the #1742 Material gate has no live bootstrap to carry even
/// once that composition entry is wired. Nothing reads
/// [`BootstrapAdmission::Material`] from here, and the retention route this
/// admission feeds is already held behind the same blocking symbol (the
/// compiled readiness receipt). A production caller therefore needs the
/// receipt owner named in that section to exist first; none was invented to
/// close the gap.
#[allow(
    clippy::too_many_arguments,
    reason = "bootstrap joins the receipt, surface, both profiles, the live fence, and the freshness clock in one edge"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one owner join over receipt, surface, coverage, governance, and fence; splitting would scatter the fail-closed ordering"
)]
pub fn admit_bootstrap_context(
    receipt: &OnboardingReadinessReceipt,
    surface: &ColdStartSurfaceView,
    coverage: Option<&IntegrationCoverageProfile>,
    governance: Option<&GovernanceProfile>,
    live_fence: &StateFence,
    now: u64,
) -> Result<BootstrapAdmission, TaskBindingError> {
    receipt.validate().map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "compiled readiness receipt is invalid: {error}"
        ))
    })?;
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt was compiled at another fence",
        ));
    }
    // #8 bounds every bootstrap by receipt expiry and lease deadline. The join
    // reuses that bound as stated: an expired receipt or lease re-resolves
    // through the owner route instead of admitting a stale bootstrap.
    if now == 0 {
        return Err(TaskBindingError::selection_required(
            "bootstrap freshness clock is not available",
        ));
    }
    if receipt.expiry_tick < now {
        return Err(TaskBindingError::scope_incompatible(
            "compiled readiness receipt expired before bootstrap; re-resolve through the owner route",
        ));
    }
    if surface.lease_deadline < now {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap lease expired before dispatch; re-resolve through the owner route",
        ));
    }
    // Same session/scope/selection-state and source revisions on both sides.
    // Each comparison names its field so a drifted join diagnoses exactly.
    let bound = |field: &'static str, left: &str, right: &str| -> Result<(), TaskBindingError> {
        if left != right {
            return Err(TaskBindingError::scope_incompatible(format!(
                "bootstrap surface is bound to another {field}"
            )));
        }
        Ok(())
    };
    bound("receipt", &receipt.receipt_ref, &surface.receipt_ref)?;
    bound("lease", &receipt.lease_ref, &surface.lease_ref)?;
    bound("principal", &receipt.principal_ref, &surface.principal_ref)?;
    bound("session", &receipt.session_ref, &surface.session_ref)?;
    bound("scope", &receipt.scope.scope_ref, &surface.scope.scope_ref)?;
    // Issue #1746, W3: the scope descriptor revision is part of the bound
    // scope identity (I4.2.1 `session_task_and_expected_scope_revision`). A
    // surface projected for another descriptor revision is another scope
    // binding, never silently adopted under this receipt.
    if receipt.scope_descriptor_revision != surface.scope_descriptor_revision {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another scope descriptor revision",
        ));
    }
    bound(
        "instance",
        &receipt.instance.instance_ref,
        &surface.instance.instance_ref,
    )?;
    bound(
        "lineage",
        receipt
            .lineage
            .as_ref()
            .map_or("", |lineage| lineage.lineage_ref.as_str()),
        surface
            .lineage
            .as_ref()
            .map_or("", |lineage| lineage.lineage_ref.as_str()),
    )?;
    if receipt.task_binding != surface.task_binding {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another task-or-selection-state",
        ));
    }
    if !eliot_contracts::fences_match_exact(&receipt.state_fence, &surface.state_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface was projected at another fence",
        ));
    }
    // Issue #1746, W5: the scope resolution state is owner-issued on both
    // sides for this same receipt/projection. A surface disagreeing on whether
    // the scope is authenticated withholds instead of admitting.
    if receipt.scope_resolution != surface.scope_resolution {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another scope resolution state",
        ));
    }
    bound(
        "governing-source set",
        &receipt.governing_source_set_ref,
        &surface.governing_source_set_ref,
    )?;
    if receipt.governing_source_generation != surface.governing_source_generation {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another governing-source generation",
        ));
    }
    bound(
        "governance profile",
        &receipt.governance_profile_ref,
        &surface.governance_profile_ref,
    )?;
    bound(
        "route profile",
        &receipt.route_profile_ref,
        &surface.route_profile_ref,
    )?;
    if receipt.receipt_revision != surface.receipt_revision {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another receipt revision",
        ));
    }
    if receipt.projection_source_ref != surface.projection_source_ref {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another projection source",
        ));
    }
    if receipt.projection_generation != surface.projection_generation {
        return Err(TaskBindingError::scope_incompatible(
            "bootstrap surface names another projection generation",
        ));
    }
    // Profiles are owner evidence, never caller claims. Absent or unverified
    // profiles stay unknown: they cap the bootstrap at Diagnostic.
    let verified_profiles = match (coverage, governance) {
        (Some(coverage), Some(governance)) => {
            coverage.validate().map_err(|error| {
                TaskBindingError::scope_incompatible(format!(
                    "integration coverage profile is invalid: {error}"
                ))
            })?;
            if coverage.fingerprint != governance.fingerprint {
                return Err(TaskBindingError::scope_incompatible(
                    "coverage and governance profiles name different fingerprints",
                ));
            }
            // Issue #1746, W5: the owner derivation never issues revision zero
            // (`GovernorCoverageDerivation` floors issued revisions at one and
            // reports zero only when nothing was derived). A zero revision was
            // defaulted, never derived, so it fails closed here instead of
            // sealing into a Material bootstrap.
            if governance.revision == 0 {
                return Err(TaskBindingError::scope_incompatible(
                    "governance profile revision is not owner-issued",
                ));
            }
            coverage.verified && governance.verified
        }
        _ => false,
    };
    match selection_response_for_receipt(receipt)? {
        TaskSelectionResponse::Absent(intake) => Ok(BootstrapAdmission::IntakeRequired(intake)),
        TaskSelectionResponse::Ambiguous(candidate_handles) => Ok(BootstrapAdmission::Diagnostic {
            reason: "task selection is ambiguous; answer with the bounded eligible handles",
            next_safe_action: receipt.next_safe_action.clone(),
            selection: TaskSelectionResponse::Ambiguous(candidate_handles),
        }),
        TaskSelectionResponse::Exploratory {
            task_ref,
            task_revision,
            acceptance_digest,
        } => Ok(BootstrapAdmission::Diagnostic {
            reason: "exploratory binding is read-only orientation, not material work",
            next_safe_action: receipt.next_safe_action.clone(),
            selection: TaskSelectionResponse::Exploratory {
                task_ref,
                task_revision,
                acceptance_digest,
            },
        }),
        TaskSelectionResponse::Stale {
            task_ref,
            task_revision,
        } => Ok(BootstrapAdmission::Diagnostic {
            reason: "task selection is stale; refresh or rebind before material work",
            next_safe_action: receipt.next_safe_action.clone(),
            selection: TaskSelectionResponse::Stale {
                task_ref,
                task_revision,
            },
        }),
        TaskSelectionResponse::Current(task) => {
            // `resolve_task_selection` admits `CurrentTaskContract` only from
            // the owner-proven selection source/evidence the receipt carries —
            // never through a caller READY flag.
            if receipt.scope_resolution != ScopeResolutionState::Authenticated
                || receipt.readiness != ReadinessLifecycle::ReadyMaterial
            {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "bootstrap is not authenticated material readiness",
                    next_safe_action: receipt.next_safe_action.clone(),
                    selection: TaskSelectionResponse::Current(task),
                });
            }
            if !verified_profiles {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "coverage or governance profile evidence is unknown or unverified",
                    next_safe_action: receipt.next_safe_action.clone(),
                    selection: TaskSelectionResponse::Current(task),
                });
            }
            let (Some(coverage), Some(governance)) = (coverage, governance) else {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "coverage or governance profile evidence is unknown or unverified",
                    next_safe_action: receipt.next_safe_action.clone(),
                    selection: TaskSelectionResponse::Current(task),
                });
            };
            let (Some(projection_source_ref), Some(projection_generation)) = (
                receipt
                    .projection_source_ref
                    .as_ref()
                    .filter(|source| !source.trim().is_empty()),
                receipt
                    .projection_generation
                    .filter(|generation| *generation > 0),
            ) else {
                return Ok(BootstrapAdmission::Diagnostic {
                    reason: "bootstrap projection owner evidence is absent",
                    next_safe_action: receipt.next_safe_action.clone(),
                    selection: TaskSelectionResponse::Current(task),
                });
            };
            Ok(BootstrapAdmission::Material(MaterialBootstrap {
                receipt_ref: receipt.receipt_ref.clone(),
                lease_ref: receipt.lease_ref.clone(),
                principal_ref: receipt.principal_ref.clone(),
                session_ref: receipt.session_ref.clone(),
                scope_ref: receipt.scope.scope_ref.clone(),
                task,
                state_fence: receipt.state_fence.clone(),
                receipt_revision: receipt.receipt_revision,
                governance_profile_ref: receipt.governance_profile_ref.clone(),
                governance_revision: governance.revision,
                coverage_fingerprint: coverage.fingerprint.clone(),
                projection_source_ref: projection_source_ref.clone(),
                projection_generation,
            }))
        }
    }
}

/// Requires one sealed task-bound dispatch identity to rest on its
/// owner-evidenced Material bootstrap (issue #1746, W5/A4; I7.8 step 4).
///
/// Joins the [`TaskBindingAdmission::TaskBound`] identity
/// ([`admit_canonical_write`]) to the [`BootstrapAdmission`] assembled from
/// the real owners ([`admit_bootstrap_context`]): a task-bound effect proceeds
/// toward the #1742 Material gate
/// (`GovernorComposition::commit_canonical_with_readiness`) only when the
/// bootstrap is `Material` and names the same admitted task, `WorkScope`,
/// presented fence, receipt revision, governance profile reference, and
/// projection generation as the sealed binding. Anything else fails closed
/// with a typed error and admits nothing: `Diagnostic` (including a bootstrap
/// without a task, which always lands there) withholds with
/// `TASK_SCOPE_INCOMPATIBLE` — a diagnostic bootstrap is never Material
/// authority — and `IntakeRequired` withholds with `TASK_SELECTION_REQUIRED`.
/// A moved task, scope, fence, bootstrap/profile revision, or re-projected
/// bootstrap conflicts for rebind; it is never rewritten
/// under the old operation identity.
///
/// Cold/unbound and non-task-relative admissions carry no sealed identity and
/// pass through untouched. This entry mints nothing and selects nothing.
///
/// Designated caller (STITCH, daemon composition lane):
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition),
/// between the admission projection and the #1742 material gate, passing the
/// admitted binding and the bootstrap admitted for the same lease at the write
/// fence.
pub fn require_material_bootstrap_for_task_bound(
    binding: &DispatchedBinding,
    bootstrap: &BootstrapAdmission,
) -> Result<(), TaskBindingError> {
    let material = match bootstrap {
        BootstrapAdmission::Material(material) => material,
        BootstrapAdmission::Diagnostic { reason, .. } => {
            return Err(TaskBindingError::scope_incompatible(format!(
                "task-bound dispatch rests on a diagnostic bootstrap, never Material authority: {reason}"
            )));
        }
        BootstrapAdmission::IntakeRequired(_) => {
            return Err(TaskBindingError::selection_required(
                "task-bound dispatch has no selected task; answer with the bounded intake shape",
            ));
        }
    };
    if material.task.task_ref != binding.admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch bootstrap names another task than the admitted binding; rebind, no rewrite",
        ));
    }
    if material.scope_ref != binding.scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch bootstrap names another WorkScope than the admitted binding; rebind, no rewrite",
        ));
    }
    if !eliot_contracts::fences_match_exact(&material.state_fence, &binding.presented_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch bootstrap was assembled at another fence; rebind at the live fence, no silent rebind",
        ));
    }
    if material.receipt_revision != binding.receipt_revision
        || material.governance_profile_ref != binding.governance_profile_ref
    {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch bootstrap/profile revision moved before effect; rebind at the live revision, no silent rebind",
        ));
    }
    // A re-projected bootstrap under the same receipt revision still conflicts
    // for rebind: the admitted projection is never silently adopted under the
    // old operation identity.
    if material.projection_generation != binding.projection_generation {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch bootstrap was re-projected before effect; rebind at the live projection, no silent adoption",
        ));
    }
    Ok(())
}

/// Computes the `TaskContract` compatibility disposition for one write from
/// the caller's receipt: the selection is compatible only when the receipt was
/// compiled at the exact write fence and resolved the exact `WorkScope` the
/// write addresses.
///
/// Anything else is `Incompatible` and therefore rejects the task-relative
/// transition with `TASK_SCOPE_INCOMPATIBLE` instead of admitting it. This
/// reads only caller-presented terms; it resolves no authority of its own.
fn compatibility_for(
    receipt: &OnboardingReadinessReceipt,
    envelope: &CanonicalWriteEnvelope,
    write_fence: &StateFence,
) -> CompatibilityDisposition {
    if eliot_contracts::fences_match_exact(&receipt.state_fence, write_fence)
        && receipt.scope.scope_ref == envelope.scope_id.as_str()
    {
        CompatibilityDisposition::Compatible
    } else {
        CompatibilityDisposition::Incompatible
    }
}

/// Admits one daemon named-mutation write at the composition-root ingress
/// (issue #1929, I5.5 capture/promotion split, I5.6 step 4).
///
/// This is the composition-root named-mutation intake, and the only entry that
/// consumes a caller-presented [`OnboardingReadinessReceipt`]. Its one
/// production call site is
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition);
/// that caller itself has zero production call sites, so the entry is not yet
/// reached in production. See the module's "Measured reachability" section for
/// the exact measurement. The write is split by what it actually is:
///
/// - a capture naming no task — the capture-first case — goes through
///   [`admit_capture`] and is returned as
///   [`TaskBindingAdmission::ColdUnbound`] unless the caller resolved one exact
///   compatible selection **and** the authenticated request names the task that
///   selection names. A selection naming a different task rejects with
///   `TASK_SCOPE_INCOMPATIBLE`; a selection whose admitted request names no task
///   at all stays cold, because that capture has no exact task selection for
///   this transition. It never affects task memory, support, influence, or
///   finish while cold;
/// - any task-relative write — one that names a task, or a task-control,
///   finish, or other task-bearing transition — requires the exact selection
///   and is admitted only through [`admit_task_bound`]. Absent, exploratory,
///   or stale evidence rejects with `TASK_SELECTION_REQUIRED`; a selection
///   naming a different task, `WorkScope`, or moved fence rejects with
///   `TASK_SCOPE_INCOMPATIBLE`, mutating nothing;
/// - anything else is [`TaskBindingAdmission::NotTaskRelative`].
///
/// This entry never selects a task the caller did not name and never consults
/// recency, proximity, or the newest/open task. Its typed evidence is exactly
/// what the store bridge cannot see: the store gate re-derives presence and
/// agreement from the opaque proof handles, this gate verifies the
/// `TaskSelectionEvidence` values against the caller's own receipt. A
/// `TaskBound` admission carries the sealed [`DispatchedBinding`] forward; the
/// dispatch effect gate revalidates it against the live owners through
/// [`revalidate_dispatched_binding`] (and [`revalidate_task_bound_for_effect`]
/// for the fence leg) (issue #1746, W6/A5).
#[expect(
    clippy::too_many_lines,
    reason = "single dispatch edge sealing identity, scope, fence, and bootstrap revisions; splitting would scatter the conflict/rebind ordering"
)]
pub fn admit_canonical_write(
    candidate_id: String,
    context: &RequestMetadata,
    envelope: &CanonicalWriteEnvelope,
    receipt: &OnboardingReadinessReceipt,
    write_fence: &StateFence,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    let compatibility = compatibility_for(receipt, envelope, write_fence);
    // Issue #1746, W1: the capture/task-relative split is derived from the
    // frozen requirement table, so gating cannot drift from the mapped
    // operation classes.
    let carries_requirement = |requirement: CanonicalOperationRequirement| {
        envelope
            .semantic_commands
            .iter()
            .any(|command| requirement_for_named_mutation(command.operation) == requirement)
    };
    let captures = carries_requirement(CanonicalOperationRequirement::SafeRawCapture);
    // Issue #1746, W4: the same frozen split the dispatch effect gate consults
    // through `envelope_is_task_relative`, so gating cannot drift from it.
    let task_relative = envelope_is_task_relative(envelope);
    // Issue #1746, W4: Absent stays absent and Ambiguous keeps its bounded
    // eligible handles through the single typed response constructor.
    // A task-free capture remains cold and unrelated non-task writes need
    // no task selection. Task-relative effects return the typed error.
    let (selection, candidate_count) = match selection_response_for_receipt(receipt) {
        Ok(
            TaskSelectionResponse::Absent(_)
            | TaskSelectionResponse::Exploratory { .. }
            | TaskSelectionResponse::Stale { .. },
        ) => (None, 0_usize),
        Ok(TaskSelectionResponse::Ambiguous(candidate_handles)) => (None, candidate_handles.len()),
        Ok(TaskSelectionResponse::Current(evidence)) => (Some(evidence), 1_usize),
        Err(_) if !task_relative => (None, 0_usize),
        Err(error) => return Err(error),
    };

    if captures && !task_relative {
        // `admit_capture` consumes the candidate identity on each of its cold
        // arms, so the caller's own value is kept here: a capture that cannot
        // be shown to be task-bound is still retained cold, and this edge
        // mints no second candidate identity.
        let cold_candidate_id = candidate_id.clone();
        return match admit_capture(
            candidate_id,
            context.state_fence.clone(),
            selection.as_ref(),
            candidate_count,
            compatibility,
        )? {
            CaptureAdmission::ColdUnbound(candidate) => {
                Ok(TaskBindingAdmission::ColdUnbound(candidate))
            }
            CaptureAdmission::TaskBound(evidence) => {
                // The expected task is the one the authenticated admitted
                // request names, never the evidence's own value. Passing
                // `evidence.task_ref` as the expectation made this leg a
                // tautology: every check `admit_task_bound` performs here was
                // either already made by `admit_capture` (validate, not
                // contaminated) or structurally guaranteed by
                // `compatibility_for` (same fence, same `WorkScope`), so the
                // call could not reject and a `CurrentTaskContract` naming a
                // task other than the admitted one was still reported
                // task-bound. I5.5 requires the wrong-task case to reject.
                let Some(admitted_task_ref) = context.task_id.as_ref().map(TaskId::as_str) else {
                    // A capture whose admitted request names no task has no
                    // exact task selection for this transition. I5.5 keeps the
                    // capture-first observation cold instead of rejecting it,
                    // so the original observation is never discarded.
                    return Ok(TaskBindingAdmission::ColdUnbound(
                        ObservationCandidate::cold_unbound(
                            cold_candidate_id,
                            context.state_fence.clone(),
                        ),
                    ));
                };
                if evidence.task_ref != admitted_task_ref {
                    return Err(TaskBindingError::scope_incompatible(
                        "task-bound capture names a different task than the admitted context",
                    ));
                }
                admit_task_bound(
                    Some(&evidence),
                    admitted_task_ref,
                    envelope.scope_id.as_str(),
                    write_fence,
                    compatibility,
                )?;
                let Ok(projection_generation) = required_task_projection_generation(receipt) else {
                    return Ok(TaskBindingAdmission::ColdUnbound(
                        ObservationCandidate::cold_unbound(
                            cold_candidate_id,
                            context.state_fence.clone(),
                        ),
                    ));
                };
                // Issue #1746, W6: seal the admitted identity (task, scope,
                // principal, session, presented fence, bootstrap/profile
                // revision) so the effect gate revalidates it instead of
                // reusing the caller fence.
                Ok(TaskBindingAdmission::TaskBound(seal_dispatched_binding(
                    evidence,
                    admitted_task_ref,
                    envelope.scope_id.as_str(),
                    &receipt.principal_ref,
                    &receipt.session_ref,
                    write_fence,
                    receipt.receipt_revision,
                    &receipt.governance_profile_ref,
                    projection_generation,
                    cold_candidate_id,
                )?))
            }
        };
    }

    if task_relative {
        // Issue #1746, A6: the direct internal entrypoint enforces the same
        // binding rule as the bridge transport edge. Unreachable fail-closed:
        // the frozen table requires owner evidence for task-relative work at
        // every entrypoint.
        if !entrypoint_requires_binding(
            DispatchEntrypoint::DirectInternal,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) {
            return Err(TaskBindingError::selection_required(
                "direct internal entrypoint cannot admit a task-relative effect without owner evidence",
            ));
        }
        // Issue #1746, A2: a wrong workspace/task identity cannot receive a
        // task-bound write. Issue #1746, A7: READY tokens grant nothing.
        let expected_task_ref = refuse_task_identity_conflict(
            context.task_id.as_ref().map(TaskId::as_str),
            envelope.task_id.as_deref(),
        )?;
        refuse_ready_string_without_evidence(receipt, selection.is_some())?;
        admit_task_bound(
            selection.as_ref(),
            &expected_task_ref,
            envelope.scope_id.as_str(),
            write_fence,
            compatibility,
        )?;
        let Some(evidence) = selection else {
            return Err(TaskBindingError::selection_required(
                "task-relative write admitted without selection evidence",
            ));
        };
        // Issue #1746, W6: seal the admitted identity for the effect gate.
        return Ok(TaskBindingAdmission::TaskBound(seal_dispatched_binding(
            evidence,
            &expected_task_ref,
            envelope.scope_id.as_str(),
            &receipt.principal_ref,
            &receipt.session_ref,
            write_fence,
            receipt.receipt_revision,
            &receipt.governance_profile_ref,
            required_task_projection_generation(receipt)?,
            candidate_id,
        )?));
    }

    Ok(TaskBindingAdmission::NotTaskRelative)
}

fn required_task_projection_generation(
    receipt: &OnboardingReadinessReceipt,
) -> Result<u64, TaskBindingError> {
    receipt
        .projection_generation
        .filter(|generation| *generation > 0)
        .ok_or_else(|| {
            TaskBindingError::scope_incompatible(
                "task-bound dispatch has no original projection generation",
            )
        })
}

/// Admits one daemon named-mutation write with the live activation
/// applicability recheck joined in (issue #1746, W4/A2).
///
/// This is [`admit_canonical_write`] preceded by
/// [`bind_current_task_selection`]: the owner-compiled receipt's `TaskContract`
/// revision, `WorkScope`, and owner-proven selection source/evidence must name
/// exactly what the activation route proved at the write fence — principal,
/// session, task, non-zero revision, and `WorkScope` — while the acceptance
/// digest is rechecked against the owner-compiled receipt original, which the
/// activation snapshot does not carry. A receipt that structurally validates
/// but names another task, a moved revision, a moved digest, another scope, or
/// another fence than the live activation fails closed here with
/// `TASK_SCOPE_INCOMPATIBLE` before any admission runs, so a wrong
/// workspace/task or stale selection can never receive a task-bound
/// write. Absent/ambiguous/exploratory/stale dispositions fall through to
/// [`admit_canonical_write`], which maps them to the cold candidate, the
/// bounded intake answer, or the typed error without ever promoting.
///
/// Structural validation of request-supplied `TaskSelectionEvidence` is never
/// sufficient: a `Current` receipt with no owner-validated activation snapshot
/// (`activation = None`) fails closed rather than admitting on the receipt
/// alone. No task is created to remove an absence, none is chosen from
/// ambiguity, and no cold capture is retroactively attached.
///
/// Live caller (daemon composition lane):
/// [`DaemonComposition::commit_canonical_and_refresh`](super::DaemonComposition),
/// for task-relative envelopes (see [`envelope_is_task_relative`]): it
/// resolves the snapshot from the presented readiness lease through
/// `GovernorComposition::current_task_selection` and passes it here with the
/// presented write fence for admission and the live Governor kernel-snapshot
/// fence for the applicability recheck — the recheck never compares the
/// presentation to itself (I4.2.1: `MATCHED` is required again after any
/// generation change). Captures and non-task-relative writes stay on the
/// receipt-only [`admit_canonical_write`] leg, so the cold path never needs a
/// retained terminal. That routing is enforced in-function as well as by the
/// caller: a task-free non-task-relative envelope takes the receipt-only leg
/// below even when invoked directly, so a permitted raw capture still stays
/// cold (issue #1746, A3) instead of failing on a missing activation.
pub fn admit_canonical_write_with_activation(
    candidate_id: String,
    context: &RequestMetadata,
    envelope: &CanonicalWriteEnvelope,
    receipt: &OnboardingReadinessReceipt,
    write_fence: &StateFence,
    live_fence: &StateFence,
    activation: Option<&eliot_governor::GovernorActivationSnapshot>,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    // A task-free non-task-relative envelope can only ever admit `ColdUnbound`
    // or `NotTaskRelative` (no admitted task, so no `TaskBound` arm is
    // reachable in `admit_canonical_write`); the live activation recheck could
    // only add refusals here, including refusing a permitted raw capture that
    // must stay cold. Keep it on the receipt-only leg, never weaker: anything
    // naming a task, or carrying a task-relative/effectful mutation, still
    // binds first below.
    if !envelope_is_task_relative(envelope) && context.task_id.is_none() {
        return admit_canonical_write(candidate_id, context, envelope, receipt, write_fence);
    }
    // Issue #1746, W4/A5: the applicability recheck runs against the live
    // owner fence, never the caller-presented write fence — `write_fence`
    // stays the admission-time comparison inside `admit_canonical_write`, so
    // a generation move between bootstrap and dispatch still fails closed
    // here (I4.2.1) instead of comparing the presentation to itself.
    bind_current_task_selection(activation, receipt, live_fence)?;
    admit_canonical_write(candidate_id, context, envelope, receipt, write_fence)
}

/// Admitted operation/payload identity carried through dispatch
/// (issue #1746, W6).
///
/// The admitted binding is the exact [`TaskSelectionEvidence`] plus the task,
/// scope, principal, session, presented fence, and bootstrap/profile revision
/// it was admitted under — never a mutable ambient selection. The effect gate
/// revalidates it with [`revalidate_dispatched_binding`]: a mismatch conflicts
/// for rebind, it is never rewritten to a new task under the old operation
/// identity, never duplicated, and already-possible effects keep this original
/// identity for reconciliation. Sealed only by [`seal_dispatched_binding`];
/// minted nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchedBinding {
    /// Exact admitted selection evidence.
    pub evidence: TaskSelectionEvidence,
    /// Task the admitted request named (request-context task, or the envelope
    /// task when the context names none) — never the evidence's own value.
    pub admitted_task_ref: String,
    /// Write scope the binding was admitted for.
    pub scope_ref: String,
    /// Principal the binding was admitted for: an intervening logout or
    /// rebind to another principal conflicts at the effect gate.
    pub principal_ref: String,
    /// Session the binding was admitted for: an intervening logout or
    /// rebind to another session conflicts at the effect gate.
    pub session_ref: String,
    /// Caller-presented fence admission ran against.
    pub presented_fence: StateFence,
    /// Bootstrap receipt revision admission ran against.
    pub receipt_revision: u64,
    /// Governance profile reference admission ran against.
    pub governance_profile_ref: String,
    /// Projection generation admission ran against.
    pub projection_generation: u64,
    /// Stable operation identity; preserved across revalidation, never mutated.
    pub operation_id: String,
}

/// Seals one admitted task-bound transition into its dispatch identity
/// (issue #1746, W6).
///
/// Checks the ORIGINAL evidence shape and then the evidence against the exact
/// admitted request task and write scope before sealing: invalid or
/// contaminated evidence, a selection naming another task or scope, or a blank
/// principal, session, or operation identity fails closed with the typed code
/// and seals nothing. Called by [`admit_canonical_write`] for both task-bound
/// arms, so every [`TaskBindingAdmission::TaskBound`] carries its principal,
/// session, fence, and bootstrap/profile revision from birth.
#[allow(
    clippy::too_many_arguments,
    reason = "seal joins the evidence, admitted identities, presented fence, bootstrap revisions, and operation identity in one edge"
)]
pub fn seal_dispatched_binding(
    evidence: TaskSelectionEvidence,
    admitted_task_ref: &str,
    scope_ref: &str,
    principal_ref: &str,
    session_ref: &str,
    presented_fence: &StateFence,
    receipt_revision: u64,
    governance_profile_ref: &str,
    projection_generation: u64,
    operation_id: String,
) -> Result<DispatchedBinding, TaskBindingError> {
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch names a different task than the admitted context",
        ));
    }
    if evidence.work_scope_ref != scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "task-bound dispatch names a different WorkScope than the admitted write",
        ));
    }
    if principal_ref.trim().is_empty() || principal_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no admitted principal",
        ));
    }
    if session_ref.trim().is_empty() || session_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no admitted session",
        ));
    }
    if operation_id.trim().is_empty() || operation_id.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no operation identity",
        ));
    }
    Ok(DispatchedBinding {
        evidence,
        admitted_task_ref: admitted_task_ref.to_owned(),
        scope_ref: scope_ref.to_owned(),
        principal_ref: principal_ref.to_owned(),
        session_ref: session_ref.to_owned(),
        presented_fence: presented_fence.clone(),
        receipt_revision,
        governance_profile_ref: governance_profile_ref.to_owned(),
        projection_generation,
        operation_id,
    })
}

/// Renders one non-matched `MaterialEffect` guard report as a stable typed
/// detail (issue #1746, W3).
///
/// Preserves the exact owner disposition — stale, different-instance,
/// ambiguous, provisional, or conflicted — instead of reducing every refusal
/// to one prose reason, so the effect gate answers conflict/rebind with the
/// discriminating identity instead of a guess. Called only by
/// [`revalidate_dispatched_binding`].
fn material_effect_guard_detail(report: &eliot_workscope::TriggerReport) -> String {
    let identity = match report.identity {
        eliot_workscope::IdentityLegOutcome::DifferentInstance => "DIFFERENT_INSTANCE",
        eliot_workscope::IdentityLegOutcome::Ambiguous => "AMBIGUOUS",
        eliot_workscope::IdentityLegOutcome::StaleBinding => "STALE_BINDING",
        eliot_workscope::IdentityLegOutcome::IdentityClear => "IDENTITY_CLEAR",
    };
    let verdict = match report.verdict {
        eliot_workscope::GuardVerdict::Allow => "ALLOW",
        eliot_workscope::GuardVerdict::Withhold => "WITHHOLD",
        eliot_workscope::GuardVerdict::Quarantine => "QUARANTINE",
    };
    let receipt = report
        .receipt
        .as_ref()
        .map_or("", |receipt| match receipt.disposition {
            ScopeBindingDisposition::Matched => ", receipt MATCHED",
            ScopeBindingDisposition::DifferentInstance => ", receipt DIFFERENT_INSTANCE",
            ScopeBindingDisposition::Ambiguous => ", receipt AMBIGUOUS",
            ScopeBindingDisposition::StaleBinding => ", receipt STALE_BINDING",
            ScopeBindingDisposition::ProvisionalRebind => ", receipt PROVISIONAL_REBIND",
            ScopeBindingDisposition::Conflicted => ", receipt CONFLICTED",
        });
    format!(
        "scope guard at material effect is not MATCHED: identity {identity}, verdict {verdict}{receipt}; rebind under a new operation, no rewrite"
    )
}

/// Revalidates one sealed dispatch identity at the effect gate against the
/// live owners (issue #1746, W6/A5).
///
/// The live task/scope, principal/session, task revision, acceptance digest,
/// bootstrap receipt revision, governance profile reference, projection
/// generation, and fence come from the live owners at the existing
/// queued-claim/launch/effect gate —
/// never from the request. An intervening rebind, task revision, acceptance
/// change, logout, or generation change fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` for conflict/rebind: the old operation is not
/// rewritten to the new task under its identity, never duplicated, and
/// already-possible effects keep their original identity for reconciliation.
/// Shared safe status/recovery remains available under its own authority and
/// never passes through this entry.
///
/// The scope-identity legs run here as well (issue #1746, W3; I4.2.1): the
/// retained binding the gate read at the live fence, the live observation,
/// and the governing-source closure run through the existing owner
/// (`eliot_workscope::check_at_trigger`) at the `MaterialEffect` trigger.
/// `Allow` requires identity-clear `MATCHED`; stale, different-instance,
/// ambiguous, provisional, or conflicted observations conflict for rebind with
/// the exact disposition (see [`material_effect_guard_detail`]). Scope
/// uncertainty never admits a task-bound effect here — only the quarantined
/// capture route ([`admit_capture`] `ColdUnbound`) may retain bytes. This entry
/// runs only the pure owner legs over gate-supplied bindings; the Governor's
/// retained-data legs (`require_scope_guard_for_observed`,
/// `check_canonical_write_work_scope`) remain the authority for the
/// retained binding itself. This entry mints no receipt and installs no
/// binding.
///
/// Designated caller (STITCH, daemon composition lane): the pre-commit effect
/// gate in `DaemonComposition::commit_canonical_and_refresh`
/// (`bins/eliotd/src/lib.rs`), between the `ColdUnbound` admission projection
/// and the scope-sensitive trigger, passing the live Governor task/scope, the
/// retained binding read at the live fence, the live observed binding, the
/// governing-source closure, principal/session, task revision, acceptance digest,
/// receipt revision, governance profile reference, projection generation (the
/// live receipt's own `projection_generation`, alongside its revision), and
/// kernel-snapshot fence.
///
/// # Not yet reached (issue #1929)
///
/// Measured on this tree, this entry has **zero call sites**: no code in any
/// crate names it other than its defining line; every other mention in the tree
/// is a [`revalidate_dispatched_binding`] prose back-link. The designated
/// caller above is itself uncalled (zero production call sites — see this
/// module's "Measured reachability" section).
/// The daemon holds no retained `ScopeBinding` — that requires the uncalled,
/// circular `DaemonComposition::admit_scope_attach` — so no live gate can pass
/// this entry's `retained`/`observed` pair even if it were called. One
/// second-order consequence is named here because a name-level scan cannot see
/// it: the private [`material_effect_guard_detail`] is called only from this
/// entry and is therefore dead with it. This entry is also *not* the route by
/// which the
/// fence leg [`revalidate_task_bound_for_effect`] runs: that function's only
/// other caller is `DaemonComposition::commit_canonical_and_refresh`, which
/// itself has zero production call sites (see this module's "Measured
/// reachability" section), so nothing here substitutes for it. No caller was
/// invented to close the gap.
#[allow(
    clippy::too_many_arguments,
    reason = "revalidation joins the sealed identity against every live owner value that can invalidate it in one fail-closed edge"
)]
pub fn revalidate_dispatched_binding(
    binding: &DispatchedBinding,
    live_task_ref: Option<&str>,
    live_scope_ref: &str,
    retained: &ScopeBinding,
    observed: &ScopeBinding,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    live_principal_ref: &str,
    live_session_ref: &str,
    live_task_revision: u64,
    live_acceptance_digest: &str,
    live_receipt_revision: u64,
    live_governance_profile_ref: &str,
    live_projection_generation: u64,
    live_fence: &StateFence,
) -> Result<(), TaskBindingError> {
    let Some(live_task_ref) = live_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch revalidation names no live task",
        ));
    };
    if live_task_ref != binding.admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched task is not the admitted task; rebind under a new operation, no rewrite",
        ));
    }
    if live_scope_ref != binding.scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched WorkScope is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    // Issue #1746, W3: the MaterialEffect scope-identity legs run at this
    // effect gate, not only at the canonical-write trigger. The gate passes
    // the retained binding it read at the live fence, the live observation,
    // and the governing-source closure; the existing owner legs decide.
    // `Allow` requires identity-clear `MATCHED`. Anything else conflicts for
    // rebind with the exact disposition — never a silent move, never a task
    // or memory transfer.
    if retained.scope.scope_ref != binding.scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "effect gate retained binding is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    let guard = eliot_workscope::check_at_trigger(
        retained,
        observed,
        source_closure,
        eliot_workscope::GuardTrigger::MaterialEffect,
    );
    if !guard.is_matched() {
        return Err(TaskBindingError::scope_incompatible(
            material_effect_guard_detail(&guard),
        ));
    }
    // An intervening logout or rebind moved the live principal/session. The
    // old operation conflicts for rebind under a new operation identity; it is
    // never rewritten to the new principal/session.
    if live_principal_ref != binding.principal_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched principal is not the admitted principal; logout or rebind under a new operation, no rewrite",
        ));
    }
    if live_session_ref != binding.session_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched session is not the admitted session; logout or rebind under a new operation, no rewrite",
        ));
    }
    // An intervening task revision or acceptance change moved the contract the
    // operation was admitted under. The evidence revision/digest sealed at
    // admission is compared with the live owner values here, never refreshed
    // in place.
    if live_task_revision != binding.evidence.task_revision {
        return Err(TaskBindingError::scope_incompatible(
            "admitted task revision moved before effect; rebind at the live revision, no silent rebind",
        ));
    }
    if live_acceptance_digest != binding.evidence.acceptance_digest {
        return Err(TaskBindingError::scope_incompatible(
            "admitted acceptance digest moved before effect; rebind at the live digest, no silent rebind",
        ));
    }
    if live_receipt_revision != binding.receipt_revision
        || live_governance_profile_ref != binding.governance_profile_ref
    {
        return Err(TaskBindingError::scope_incompatible(
            "admitted bootstrap/profile revision moved before effect; rebind at the live revision, no silent rebind",
        ));
    }
    // The admitted projection generation is sealed alongside the receipt
    // revision at admission (`seal_dispatched_binding`) and rechecked here
    // against the live receipt's own generation: a re-projected bootstrap
    // under the same receipt revision still conflicts for rebind, it is never
    // silently adopted under the old operation identity.
    if live_projection_generation != binding.projection_generation {
        return Err(TaskBindingError::scope_incompatible(
            "admitted projection generation moved before effect; rebind at the live projection, no silent rebind",
        ));
    }
    revalidate_task_bound_for_effect(
        &binding.evidence,
        Some(binding.admitted_task_ref.as_str()),
        &binding.scope_ref,
        &binding.presented_fence,
        live_fence,
    )
}

/// Revalidates one admitted task-bound transition at the effect gate against
/// the live fence (issue #1746, W6/A5).
///
/// [`admit_canonical_write`] admits against the caller-presented write fence;
/// between that admission (bootstrap) and the commit (dispatch) the task,
/// scope, or generation may have moved. This entry carries the exact admitted
/// [`TaskSelectionEvidence`] forward and rejoins it here: the ORIGINAL
/// evidence is validated with the existing [`TaskSelectionEvidence::validate`],
/// contamination still refuses, the evidence task/scope must name exactly the
/// admitted request task and the write scope, and the presented fence must
/// still match the live owner fence exactly. A mismatch fails closed with
/// `TASK_SCOPE_INCOMPATIBLE` for conflict/rebind: the old operation is never
/// rewritten to the new task under its identity, never duplicated, and already
/// possible effects keep their original identity for reconciliation. This entry
/// mints no evidence and selects no task; `admitted_task_ref` is the exact
/// task the admitted request names (the request-context task, or the envelope
/// task when the context names none — the same value admission compared),
/// never the evidence's own value.
///
/// Designated caller (live, daemon composition lane): the pre-commit effect
/// gate in `DaemonComposition::commit_canonical_and_refresh`
/// (`bins/eliotd/src/lib.rs`), between the `ColdUnbound` admission projection
/// and the scope-sensitive trigger, passing the admitted request task, the
/// envelope scope, the readiness fence as presented, and the live Governor
/// kernel-snapshot fence as live. Callers holding a sealed [`DispatchedBinding`]
/// prefer [`revalidate_dispatched_binding`], which checks the carried
/// task/scope/bootstrap/profile/projection revision first, runs the `MaterialEffect`
/// scope-identity legs over the gate-supplied retained/observed bindings,
/// and delegates here for the fence leg; that fuller entry stays STITCH
/// until the effect gate passes the retained/observed pair with source
/// closure and the live projection generation without invention.
pub fn revalidate_task_bound_for_effect(
    evidence: &TaskSelectionEvidence,
    admitted_task_ref: Option<&str>,
    expected_scope_ref: &str,
    presented_fence: &StateFence,
    live_fence: &StateFence,
) -> Result<(), TaskBindingError> {
    let Some(admitted_task_ref) = admitted_task_ref else {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch names no admitted task",
        ));
    };
    if admitted_task_ref.trim().is_empty() || admitted_task_ref.chars().any(char::is_control) {
        return Err(TaskBindingError::selection_required(
            "task-bound dispatch admitted task is blank",
        ));
    }
    evidence.validate().map_err(|error| {
        TaskBindingError::selection_required(format!("task selection evidence invalid: {error}"))
    })?;
    if evidence.is_contaminated() {
        return Err(TaskBindingError::selection_required(
            "task selection is contaminated",
        ));
    }
    if evidence.task_ref != admitted_task_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched task is not the admitted task; rebind under a new operation, no rewrite",
        ));
    }
    if evidence.work_scope_ref != expected_scope_ref {
        return Err(TaskBindingError::scope_incompatible(
            "dispatched WorkScope is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    if !eliot_contracts::fences_match_exact(presented_fence, live_fence) {
        return Err(TaskBindingError::scope_incompatible(
            "admitted fence moved before effect; rebind at the live fence, no silent rebind",
        ));
    }
    Ok(())
}

/// Admits the capture leg of one prepared transition at the daemon transport
/// edge (issue #1929, I5.5).
///
/// This is the production entry for `DaemonKernelClient::apply_prepared`'s
/// pre-transport admission: the last point inside the daemon where a
/// `CaptureObservation` can still be classified before it reaches Kernel and
/// the store. It decides the capture leg and reports task-relative work it
/// cannot admit:
///
/// - a `CaptureObservation` naming no task on either the admitted context or
///   the transition, and with no task-relative/effectful operation in the
///   typed catalogue, has no unique task selection, so it is admitted through
///   [`admit_capture`] as [`TaskBindingAdmission::ColdUnbound`] with no task
///   activation, support/influence promotion, or finish relevance;
/// - a `CaptureObservation` that names a task is task-relative, and this edge
///   reports [`TaskBindingAdmission::TaskRelative`] rather than guessing: the
///   binding decision belongs to the ingress that owns the exact selection
///   ([`admit_canonical_write`]) and is re-derived at the store gate from the
///   proof handles the transition actually carries. A typed selection is never
///   manufactured here, and an absent one is never treated as compatible;
/// - a transition with no capture that still names a task on either the
///   admitted context or the transition — or whose typed operation is
///   task-relative/effectful under the frozen requirement table
///   ([`requirement_for_named_mutation`]) even when no task handle is named —
///   is equally task-relative work passing a capture-only edge (issue #1746,
///   A6): it is reported as [`TaskBindingAdmission::TaskRelative`] — never
///   admitted here and never labelled [`TaskBindingAdmission::NotTaskRelative`],
///   which would claim no binding is required. Its binding belongs to the same
///   selection-owning ingress and store gate as the capture-naming-task arm;
/// - a transition with no capture and no task on either side is
///   [`TaskBindingAdmission::NotTaskRelative`].
///
/// It never selects the most recent or open task and never falls back to
/// resolver output.
///
/// # Why this entry has no `selection` parameter (issue #1929)
///
/// This edge is reached from `DaemonKernelClient::apply_prepared`, which
/// receives only a `PreparedTransition` and an `eliot_protocol::RequestIdentity`.
/// Neither carries a compiled readiness receipt or a `TaskSelectionEvidence`,
/// and neither does `DaemonKernelClient` or the retained Governor
/// `WorkScopeBindingOwner`; a `TaskSelectionEvidence` additionally requires a
/// non-zero `task_revision` and an `acceptance_digest` that this edge has no
/// legitimate source for. Adding the parameter anyway and passing `None` would
/// reproduce the present state under a new name, and synthesizing those two
/// fields would turn every typed rejection on this path into a rejection of
/// fabricated evidence — strictly worse than the `ColdUnbound` this edge
/// reports. The signature therefore has no selection parameter, which makes the
/// missing evidence owner structural rather than an assertion. The ingress that
/// would carry it, [`admit_canonical_write`], does have a production call site,
/// but that caller has none; see the module's "Measured reachability" section.
pub fn admit_named_mutation_capture(
    context: &RequestMetadata,
    transition: &PreparedTransition,
) -> Result<TaskBindingAdmission, TaskBindingError> {
    // Issue #1746, W1: the capture/task-relative split is derived from the
    // frozen requirement table, never from an operation-name comparison on
    // this edge, so a renamed or newly catalogued effectful operation cannot
    // slip through as needing no binding. This is the same table
    // [`admit_canonical_write`] derives its split from.
    let carries_requirement = |requirement: CanonicalOperationRequirement| {
        transition
            .named_operations
            .iter()
            .any(|named| requirement_for_named_mutation(named.operation) == requirement)
    };
    let names_a_task = transition.task_id.is_some() || context.task_id.is_some();
    if names_a_task || carries_requirement(CanonicalOperationRequirement::TaskRelativeEffectful) {
        // Issue #1746, A6: the bridge transport edge enforces the same binding
        // rule as the direct internal intake — task-relative work needs owner
        // evidence, so its binding decision belongs to the ingress that owns
        // the exact selection, whether or not this transition carries a
        // capture. A task-bearing non-capture transition is reported here,
        // never admitted and never labelled as needing no binding. The
        // terminal arm is unreachable fail-closed if the frozen table ever
        // stops requiring it.
        if entrypoint_requires_binding(
            DispatchEntrypoint::BridgeTransport,
            CanonicalOperationRequirement::TaskRelativeEffectful,
        ) {
            return Ok(TaskBindingAdmission::TaskRelative);
        }
        return Err(TaskBindingError::selection_required(
            "bridge transport edge cannot admit a task-relative effect without owner evidence",
        ));
    }
    if !carries_requirement(CanonicalOperationRequirement::SafeRawCapture) {
        return Ok(TaskBindingAdmission::NotTaskRelative);
    }
    match admit_capture(
        transition.identity.operation_id.as_str().to_owned(),
        context.state_fence.clone(),
        None,
        0,
        CompatibilityDisposition::Compatible,
    )? {
        CaptureAdmission::ColdUnbound(candidate) => {
            Ok(TaskBindingAdmission::ColdUnbound(candidate))
        }
        CaptureAdmission::TaskBound(evidence) => {
            Err(TaskBindingError::selection_required(format!(
                "task-free capture must not carry a task selection: {}",
                evidence.evidence_ref
            )))
        }
    }
}

/// Observes one explicit workspace root and admits one task-relative
/// transition against the live observation.
///
/// This is the daemon trigger ingress for scope identity: absent selection
/// stays on the cold path with no observation performed, while a present
/// selection observes the explicit root mechanically (filesystem/VCS/project
/// facts, never invented), derives the observed instance and generation, and
/// admits only through [`admit_task_bound_with_observed_scope`] at the
/// caller-named I4.2.1 trigger with the gate-supplied governing-source
/// closure. Only a `MATCHED` (`Allow`) observation admits: a root that cannot
/// be observed, or an observation that disagrees with the retained binding,
/// fails closed with `TASK_SCOPE_INCOMPATIBLE`; an identity-clear observation
/// without a `MATCHED` owner receipt withholds `PROVISIONAL_REBIND` pending
/// source closure. The retained binding, task state, and project memory are
/// untouched. The root is always explicit — the daemon never infers a
/// workspace from cwd, proximity, or recency. Live status: no live caller
/// threads an explicit root yet; awaiting the attach-transport owner
/// (BLOCKED-BY attach-transport).
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
///
/// # Not yet reached (issue #1929)
///
/// This entry takes a caller-presented selection rather than owning one, and it
/// currently has zero call sites, which also makes
/// [`admit_task_bound_with_observed_scope`] transitively dead. Its two
/// remaining inputs are the reason: the daemon holds no retained
/// `ScopeBinding` (that requires `DaemonComposition::admit_scope_attach`, which
/// is itself uncalled and circular) and no explicit user workspace root — only
/// its own config and state directories, which are not a user `WorkScope` and
/// must never be attached as one. A production caller therefore needs the
/// attach-transport ingress named in the module's "Measured reachability"
/// section.
#[allow(
    clippy::too_many_arguments,
    reason = "trigger ingress joins the explicit root, selection, retained binding, fence, compatibility, source closure, and trigger in one edge"
)]
pub fn observe_and_admit_task(
    workspace_root: &Path,
    selection: Option<&TaskSelectionEvidence>,
    expected_task_ref: &str,
    expected: &ScopeBinding,
    expected_fence: &StateFence,
    compatibility: CompatibilityDisposition,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    trigger: eliot_workscope::GuardTrigger,
) -> Result<(), TaskBindingError> {
    if selection.is_none() {
        return admit_task_bound(
            None,
            expected_task_ref,
            &expected.scope.scope_ref,
            expected_fence,
            compatibility,
        );
    }
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed = derive_observed_resources(&facts, expected_fence.resource_generation, None)
        .map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    admit_task_bound_with_observed_scope(
        selection,
        expected_task_ref,
        expected,
        &observed,
        expected_fence,
        compatibility,
        source_closure,
        trigger,
    )
}

/// Exact retained cold-start tuple presented to the daemon attach boundary.
///
/// This carries an existing Governor lease and its previously returned
/// `ColdStartSurfaceView`; it is not an authority or a receipt constructor.
/// `DaemonComposition::read_cold_start_surface_for_attach` re-reads the
/// retained terminal for this exact lease key and returns it only when the
/// complete surface, lease reference/deadline, and supplied `StateFence` still
/// match. In particular the equality covers principal/session, scope and
/// descriptor revision, instance/lineage, task binding, source set/generation,
/// governance/route profiles, serializer/tokenizer identities, and projection
/// source/revision. No field is derived from an activation ticket or a display
/// label.
///
/// The producer remains the authenticated attach/onboarding owner. The type
/// itself does not authenticate these values; a caller must pass the exact
/// owner-issued lease/surface/claim tuple and the fence it observed at the
/// same boundary. Without that producer, there is deliberately no live daemon
/// caller.
#[derive(Clone, Debug)]
pub struct ColdStartAttachInput {
    /// The exact single-flight lease whose terminal is being attached.
    pub lease: OnboardingLease,
    /// Full Governor-built ORS claim for the exact lease identity and fence.
    /// Partial lease fields are never sufficient for a durable readiness
    /// readback.
    pub readiness_claim: ColdStartReadinessClaim,
    /// Exact original scan receipt handle, re-read from the installation owner.
    pub scan_receipt_handle: eliot_workscope::ScanReceiptHandle,
    /// Full admitted scan binding used by the protected owner readback.
    pub scan_binding: eliot_workscope::ScanDisclosureOwnerBinding,
    /// The complete prior projection returned by the Governor for this lease.
    pub expected_surface: ColdStartSurfaceView,
    /// Fence observed by the authenticated attach boundary.
    pub state_fence: StateFence,
}

impl ColdStartAttachInput {
    /// Checks the key fields projected into the surface before the adapter
    /// performs the full retained-lease comparison.
    #[must_use]
    pub fn matches_lease(&self) -> bool {
        self.expected_surface.lease_ref == self.lease.lease_ref
            && self.expected_surface.lease_deadline == self.lease.deadline
            && self.expected_surface.scope.lineage_ref.as_deref()
                == Some(self.lease.lineage_candidate_ref.as_str())
            && self.expected_surface.scope.instance_ref
                == self.lease.workspace_instance_candidate_ref
            && self.expected_surface.instance.instance_ref
                == self.lease.workspace_instance_candidate_ref
            && self.expected_surface.governing_source_generation
                == self.lease.governing_source_generation
            && self.readiness_claim.lease_ref == self.lease.lease_ref
            && self.readiness_claim.lease_deadline == self.lease.deadline
            && self.readiness_claim.key.lineage_candidate_ref == self.lease.lineage_candidate_ref
            && self.readiness_claim.key.workspace_instance_candidate_ref
                == self.lease.workspace_instance_candidate_ref
            && self.readiness_claim.key.privacy_class == self.lease.privacy_class
            && self.readiness_claim.key.governing_source_generation
                == self.lease.governing_source_generation
            && self.expected_surface.governing_source_set_ref
                == self.readiness_claim.key.governing_source_set_ref
            && self.expected_surface.governing_source_generation
                == self.readiness_claim.key.governing_source_generation
            && self.readiness_claim.key.state_fence == self.state_fence
    }
}

/// Authenticated scope-attach ingress payload assembled from owned evidence.
///
/// The attach trigger builds exactly one of these per attach attempt from
/// evidence it already owns — never inferred from the activation ticket
/// (correlation-only by contract), the current directory, proximity, or
/// recency:
///
/// - `explicit_root`: the explicit host/session workspace path the trigger
///   was asked to attach (absolute; observed live, never a display name);
/// - `receipt_ref`: fresh bounded receipt identity minted per attempt;
/// - `descriptor`: the retained scope description the trigger resolves from
///   the onboarding path (the producer requires it to describe the live
///   owner binding on every identity field);
/// - `authorizing_ref`: the authenticated session/host authorization evidence
///   reference (the explicit Human/host binding token or session attach
///   record the trigger authenticated through owned IPC/session state) — a
///   reference only; the producer enforces non-blank, the trigger owns the
///   authentication;
/// - `privacy_class`, `governing_source_generation`, `sources`, `privacy`:
///   the scope's admitted privacy class and the onboarding-retained source
///   closure that authenticates the observed instance;
/// - `owner_revision`: caller-sequenced durable revision for the admitted
///   owner (same convention as the sibling admission entries).
///
/// [`ScopeAttachIngress::validate`] checks shape only: it never authenticates
/// the scope, the lineage, or the authorization — the live owner read at the
/// fence, the `MATCHED` guard, and the source closure inside
/// `GovernorComposition::admit_observed_scope_attach` do. Call sequence:
/// `validate`, then [`observe_explicit_workspace`] on `explicit_root`, then
/// `GovernorComposition::admit_observed_scope_attach` with every field below.
/// That call order is the production one in
/// `DaemonComposition::admit_scope_attach`.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
#[derive(Clone, Debug)]
pub struct ScopeAttachIngress {
    /// Explicit absolute workspace root to observe live and attach.
    pub explicit_root: PathBuf,
    /// Fresh bounded receipt identity minted per attempt.
    pub receipt_ref: String,
    /// Retained scope description the observed instance attaches to.
    pub descriptor: WorkScopeDescriptor,
    /// Trigger-authenticated session/host authorization evidence reference.
    pub authorizing_ref: String,
    /// Admitted privacy class for the new binding.
    pub privacy_class: PrivacyClass,
    /// Source generation the onboarding closure authenticates.
    pub governing_source_generation: u64,
    /// Onboarding-retained governing sources for the observed instance.
    pub sources: GoverningSourceSet,
    /// Privacy boundary the new binding must satisfy.
    pub privacy: PrivacyProfile,
    /// Caller-sequenced durable revision for the admitted owner.
    pub owner_revision: u64,
}

impl ScopeAttachIngress {
    /// Validates the payload shape without authenticating anything.
    ///
    /// Malformed caller fields (blank references, zero counters) fail as
    /// `TASK_SELECTION_REQUIRED`; scope-identity disagreements (a descriptor
    /// that does not validate, a privacy class outside the admitted
    /// boundary) fail as `TASK_SCOPE_INCOMPATIBLE`. A non-absolute root
    /// fails as incompatible: only an explicit absolute path may be
    /// observed. The governing source set itself is checked at admission
    /// against the observed scope, never here.
    pub fn validate(&self) -> Result<(), TaskBindingError> {
        if !self.explicit_root.is_absolute() {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress explicit_root must be absolute",
            ));
        }
        if self.receipt_ref.trim().is_empty() || self.receipt_ref.chars().any(char::is_control) {
            return Err(TaskBindingError::selection_required(
                "attach ingress receipt_ref is blank",
            ));
        }
        if self.authorizing_ref.trim().is_empty()
            || self.authorizing_ref.chars().any(char::is_control)
        {
            return Err(TaskBindingError::selection_required(
                "attach ingress authorizing_ref is blank",
            ));
        }
        if self.governing_source_generation == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress governing_source_generation is zero",
            ));
        }
        if self.owner_revision == 0 {
            return Err(TaskBindingError::selection_required(
                "attach ingress owner_revision is zero",
            ));
        }
        self.descriptor.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress descriptor invalid: {error}"
            ))
        })?;
        self.privacy.validate().map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "attach ingress privacy boundary invalid: {error}"
            ))
        })?;
        if !self.privacy.admits(self.privacy_class) {
            return Err(TaskBindingError::scope_incompatible(
                "attach ingress privacy class is outside the admitted boundary",
            ));
        }
        Ok(())
    }
}

/// Observes one explicit workspace root and derives the observed scope
/// resources the `WorkScope` attach trigger admits against.
///
/// This is the daemon half of the attach ingress and the only mechanical step
/// it owns: the explicit absolute root is observed from filesystem/VCS/project
/// facts (never invented, never inferred from cwd, proximity, or recency) and
/// the observation is derived at the admission fence generation through the
/// same `derive_observed_resources` the CLI scope-observe ingress runs. A root
/// that cannot be observed, or one whose derived resources are invalid, fails
/// closed with `TASK_SCOPE_INCOMPATIBLE` carrying the exact detail; the
/// retained binding, task state, and project memory are untouched.
///
/// Receipt production and admission stay with the Governor owner
/// (`GovernorComposition::admit_observed_scope_attach`): this function mints no
/// receipt and installs no binding, so the daemon cannot become a second
/// `WorkScope` writer. The caller's admitted owner read, the fresh `MATCHED`
/// source-closure check, and the explicit authorization reference are the
/// Governor's terms, not this crate's.
pub fn observe_explicit_workspace(
    workspace_root: &Path,
    fence: &StateFence,
) -> Result<ObservedScopeResources, TaskBindingError> {
    observe_explicit_workspace_facts(workspace_root, fence).map(|(_, observed)| observed)
}

fn observe_explicit_workspace_facts(
    workspace_root: &Path,
    fence: &StateFence,
) -> Result<(WorkspaceInstanceFacts, ObservedScopeResources), TaskBindingError> {
    let facts = observe_workspace_instance(workspace_root).map_err(|error| {
        TaskBindingError::scope_incompatible(format!("workspace observation failed: {error}"))
    })?;
    let observed =
        derive_observed_resources(&facts, fence.resource_generation, None).map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "observed workspace resources invalid: {error}"
            ))
        })?;
    Ok((facts, observed))
}

/// Observes one authenticated activation selector and creates the exact
/// discovery lease/evidence inputs admitted by the privacy-bounded scanner.
///
/// Host observes filesystem/VCS/manifests and a fixed set of root-relative
/// governing-source filenames only; no document contents are opened. The
/// authenticated ticket and observed root bind a short discovery lease that
/// explicitly admits the source-candidate read. Known-format inspection stays
/// unresolved. No privacy class, boundary, source closure, or task is inferred
/// here; the scanner returns its smallest privacy question until the
/// applicable owner supplies those inputs. `principal_ref` and `session_ref`
/// are exact semantic owner identities; transport connection and activation-
/// request identities are distinct and are never substituted into the lease.
#[allow(
    clippy::too_many_lines,
    reason = "bounded Host observations and the matching discovery lease are assembled in one auditable path"
)]
pub fn observe_cold_start_discovery(
    ticket: &eliot_protocol::AgentActivationResolutionTicket,
    principal_ref: &str,
    session_ref: &str,
    fence: &StateFence,
    now: u64,
) -> Result<ColdStartDiscoveryInput, TaskBindingError> {
    let selector = ticket.workspace_selector.as_deref().ok_or_else(|| {
        TaskBindingError::selection_required(
            "activation has no explicit workspace selector for bounded discovery",
        )
    })?;
    let workspace_root = Path::new(selector);
    if !workspace_root.is_absolute() {
        return Err(TaskBindingError::scope_incompatible(
            "activation workspace selector must be an explicit absolute path",
        ));
    }
    if now == 0 {
        return Err(TaskBindingError::selection_required(
            "activation discovery clock is not available",
        ));
    }
    let (facts, observed) = observe_explicit_workspace_facts(workspace_root, fence)?;
    let instance = observed.instances.first().ok_or_else(|| {
        TaskBindingError::scope_incompatible("Host observer returned no workspace instance")
    })?;
    let instance_ref = instance.instance_ref.clone();
    let root_identity = instance.root_identity.clone();
    let proposed_kind = observed.kind;
    let allowed_reads = initial_discovery_allowed_reads(&facts);
    let consumption_limit = u32::try_from(allowed_reads.len()).map_err(|_| {
        TaskBindingError::scope_incompatible(
            "Host discovery read count exceeds the lease consumption limit",
        )
    })?;
    let request = DiscoveryLeaseRequest {
        proposer_ref: principal_ref.to_owned(),
        session_ref: session_ref.to_owned(),
        host_ref: ticket.peer_admission_receipt_sha256.clone(),
        candidate_root_ref: root_identity.clone(),
        root_filesystem_identity_ref: root_identity.clone(),
        allowed_reads: allowed_reads.clone(),
        consumption_limit,
        deadline: ticket.kernel_deadline_unix_ms,
    };
    let key = DiscoveryLeaseKey {
        proposer_ref: request.proposer_ref.clone(),
        session_ref: request.session_ref.clone(),
        host_ref: request.host_ref.clone(),
        root_filesystem_identity_ref: request.root_filesystem_identity_ref.clone(),
    };
    let lease = issue_discovery_lease(&request).map_err(|error| {
        TaskBindingError::scope_incompatible(format!(
            "Host-observed discovery lease refused: {error}"
        ))
    })?;
    lease
        .authorize(DiscoveryRead::GoverningSourceCandidates, now)
        .map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "Host source-candidate read is outside its discovery lease: {error:?}"
            ))
        })?;
    let source_candidates = observe_workspace_source_candidates(Path::new(&facts.canonical_root))
        .map_err(|error| {
            TaskBindingError::scope_incompatible(format!(
                "Host source-candidate observation failed: {error}"
            ))
        })?
        .into_iter()
        .map(|candidate| GoverningSourceCandidateEvidence {
            source_ref: candidate.relative_path,
            role: match candidate.kind {
                WorkspaceSourceDocumentKind::UserTask => GoverningSourceRole::UserTask,
                WorkspaceSourceDocumentKind::Architecture => GoverningSourceRole::Architecture,
                WorkspaceSourceDocumentKind::Implementation => GoverningSourceRole::Implementation,
                WorkspaceSourceDocumentKind::AgentInstruction => {
                    GoverningSourceRole::AgentInstruction
                }
                WorkspaceSourceDocumentKind::BuildTestContract => {
                    GoverningSourceRole::BuildTestContract
                }
                WorkspaceSourceDocumentKind::DomainPolicy => GoverningSourceRole::DomainPolicy,
                WorkspaceSourceDocumentKind::SupportingReference => {
                    GoverningSourceRole::SupportingReference
                }
            },
        })
        .collect::<Vec<_>>();
    let mut attested_reads = vec![DiscoveryRead::FilesystemIdentity];
    attested_reads.push(DiscoveryRead::GoverningSourceCandidates);
    if facts.has_git {
        attested_reads.push(DiscoveryRead::VcsIdentity);
    }
    let mut manifests = facts
        .manifest_names
        .iter()
        .map(|name| {
            let name_hash = sha256_hex(name.as_bytes());
            ManifestEvidence {
                manifest_ref: format!("manifest:{name_hash}"),
                name_hash,
            }
        })
        .collect::<Vec<_>>();
    manifests.sort_by(|left, right| left.manifest_ref.cmp(&right.manifest_ref));
    if !manifests.is_empty() {
        attested_reads.push(DiscoveryRead::ManifestNamesAndHashes);
    }
    let evidence = BootstrapScanEvidence {
        canonical_root_ref: root_identity.clone(),
        filesystem_identity_ref: root_identity,
        vcs_branch_ref: observed.generation.branch_ref.clone(),
        vcs_commit_ref: observed.generation.commit_ref.clone(),
        vcs_dirty_summary_ref: observed.generation.dirty_summary_ref.clone(),
        file_distribution: Vec::new(),
        manifests,
        build_profiles: Vec::new(),
        root_services: Vec::new(),
        editor_workspaces: Vec::new(),
        existing_records: Vec::new(),
        adapters: Vec::new(),
        governing_source_candidates: Some(source_candidates),
        recent_changes: Vec::new(),
        artifact_dirs: Vec::new(),
        execution_identity: None,
        broker_attached: None,
        redacted_literal_identities: Vec::new(),
        unresolved_fields: vec![DiscoveryRead::KnownFormatHeaders],
        attested_reads,
    };
    let governing_source_refs = evidence
        .governing_source_candidates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|candidate| candidate.source_ref.clone())
        .collect();
    let discovery = BootstrapDiscoveryInputs {
        scan_ref: format!("scan:{}", ticket.ticket_id),
        candidate_privacy: None,
        privacy_boundary: None,
        observed,
        policy: None,
        proposed_kind,
        identity_fingerprint: instance_ref,
        evidence,
        governing_source_refs,
        now,
    };
    Ok(ColdStartDiscoveryInput {
        lease,
        key,
        discovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    #[test]
    fn missing_selection_is_cold_without_task_effects() {
        let admission = admit_capture(
            "candidate-1".to_owned(),
            fence(),
            None,
            0,
            CompatibilityDisposition::Compatible,
        )
        .expect("absent selection stays cold");
        match admission {
            CaptureAdmission::ColdUnbound(candidate) => {
                assert_eq!(candidate.reason_ref, "unbound-capture");
                assert!(!candidate.affects_task());
            }
            CaptureAdmission::TaskBound(_) => panic!("absent selection must not bind a task"),
        }
    }
}
