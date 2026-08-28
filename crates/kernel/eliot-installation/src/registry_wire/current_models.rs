//! Current-version registry wire DTOs and pure deserialization conversion.
//!
//! Architecture A2.3 (`docs/architecture/ELIOT_ARCHITECTURE.md`): this is a
//! bounded source contract island; the module/package does not own runtime
//! lifecycle or authority.
//! Implementation I3.14 keeps declared capability separate from observed
//! capability, with runtime observation winning current availability. I3.15
//! keeps durable installation/update transaction ownership with installer/Host
//! (`docs/architecture/ELIOT_IMPLEMENTATION.md`).
//!
//! Ownership: this child owns only current-version wire DTOs, serde
//! required-field/default decoding, and pure conversion. The parent
//! `registry_wire` owns shape selection, legacy migration, and decode dispatch;
//! the installation registry/Host owns durable mutation and authority.

use serde::Deserialize;

use super::super::{
    ActivationCommitFence, ActivePhaseBRebind, ActivePhaseBRebindIntent, ActivePhaseBRebindReceipt,
    ActivePhaseBRebindRecovery, AgentBridgeStagePrepared, ApprovedGeneration,
    ApprovedGenerationRegistry, CandidateManifest, ContractVersion,
    HostPhaseBMaterializationIntent, HostPhaseBMaterializationReceipt,
    HostPhaseBPreparedMaterialization, HostPhaseBPreparedReceipt, InstallationActivationApproval,
    InstallerServiceRegistrationApproval, PendingActivation, PendingActivationState,
    PlatformHandle, ResourceGeneration, StateFence,
};

use super::{PendingActivationTerminal, PendingActivationTerminalDisposition};

/// Private deserialization mirror for an authority-issued approval.  The
/// public approval type intentionally has no `Deserialize` implementation;
/// only this registry boundary may reconstruct a previously sealed value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationActivationApprovalWire {
    approval_ref: PlatformHandle,
    transaction_id: PlatformHandle,
    installer_plan_digest: PlatformHandle,
    generation: PlatformHandle,
    candidate_manifest_digest: PlatformHandle,
    runtime_descriptor_digest: PlatformHandle,
    required_owner: PlatformHandle,
    signature_ref: PlatformHandle,
    authority_descriptor_path: PlatformHandle,
    authority_descriptor_digest: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_state_fence: StateFence,
}

impl InstallationActivationApprovalWire {
    fn into_approval(self) -> InstallationActivationApproval {
        InstallationActivationApproval {
            approval_ref: self.approval_ref,
            transaction_id: self.transaction_id,
            installer_plan_digest: self.installer_plan_digest,
            generation: self.generation,
            candidate_manifest_digest: self.candidate_manifest_digest,
            runtime_descriptor_digest: self.runtime_descriptor_digest,
            required_owner: self.required_owner,
            signature_ref: self.signature_ref,
            authority_descriptor_path: self.authority_descriptor_path,
            authority_descriptor_digest: self.authority_descriptor_digest,
            authority_generation: self.authority_generation,
            authority_state_fence: self.authority_state_fence,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedGenerationWire {
    manifest: CandidateManifest,
    approval: InstallationActivationApprovalWire,
    active: bool,
    last_known_good: bool,
}

impl ApprovedGenerationWire {
    fn into_generation(self) -> ApprovedGeneration {
        ApprovedGeneration {
            manifest: self.manifest,
            approval: self.approval.into_approval(),
            active: self.active,
            last_known_good: self.last_known_good,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    manifest: CandidateManifest,
    config_digest: PlatformHandle,
    kernel_artifact_digest: PlatformHandle,
    store_bridge_artifact_digest: PlatformHandle,
    canonical_store_artifact_digest: PlatformHandle,
    host_executable_path: PlatformHandle,
    host_artifact_digest: PlatformHandle,
    runtime_state_roots_digest: PlatformHandle,
    manifest_digest: PlatformHandle,
    prior_active_generation: Option<PlatformHandle>,
    approval: InstallationActivationApprovalWire,
    phase_b_intent: RequiredOption<HostPhaseBMaterializationIntent>,
    phase_b_prepared: RequiredOption<HostPhaseBPreparedMaterialization>,
    #[serde(default)]
    phase_b_prepared_receipt: Option<HostPhaseBPreparedReceipt>,
    phase_b_agent_bridge_stage_prepared: RequiredOption<AgentBridgeStagePrepared>,
    phase_b_receipt: RequiredOption<HostPhaseBMaterializationReceipt>,
    state: PendingActivationState,
}

impl PendingActivationWire {
    fn into_pending(self) -> PendingActivation {
        PendingActivation {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            manifest: self.manifest,
            config_digest: self.config_digest,
            kernel_artifact_digest: self.kernel_artifact_digest,
            store_bridge_artifact_digest: self.store_bridge_artifact_digest,
            canonical_store_artifact_digest: self.canonical_store_artifact_digest,
            host_executable_path: self.host_executable_path,
            host_artifact_digest: self.host_artifact_digest,
            runtime_state_roots_digest: self.runtime_state_roots_digest,
            manifest_digest: self.manifest_digest,
            prior_active_generation: self.prior_active_generation,
            approval: self.approval.into_approval(),
            phase_b_intent: self.phase_b_intent.0,
            phase_b_prepared: self.phase_b_prepared.0,
            phase_b_prepared_receipt: self.phase_b_prepared_receipt,
            phase_b_agent_bridge_stage_prepared: self.phase_b_agent_bridge_stage_prepared.0,
            phase_b_receipt: self.phase_b_receipt.0,
            state: self.state,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingActivationTerminalWire {
    transaction_id: PlatformHandle,
    plan_digest: PlatformHandle,
    generation: PlatformHandle,
    disposition: PendingActivationTerminalDisposition,
    /// The member is mandatory on the current wire, while explicit `null`
    /// remains the only valid value for an aborted terminal.
    commit_fence: RequiredOption<ActivationCommitFence>,
}

impl PendingActivationTerminalWire {
    fn into_terminal(self) -> PendingActivationTerminal {
        PendingActivationTerminal {
            transaction_id: self.transaction_id,
            plan_digest: self.plan_digest,
            generation: self.generation,
            disposition: self.disposition,
            commit_fence: self.commit_fence.0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivePhaseBRebindWireV11 {
    intent: ActivePhaseBRebindIntent,
    prepared: RequiredOption<HostPhaseBPreparedMaterialization>,
    receipt: RequiredOption<ActivePhaseBRebindReceipt>,
    recovery_history: Vec<ActivePhaseBRebindRecovery>,
}

impl ActivePhaseBRebindWireV11 {
    fn into_rebind(self) -> ActivePhaseBRebind {
        ActivePhaseBRebind {
            intent: self.intent,
            prepared: self.prepared.0,
            receipt: self.receipt.0,
            recovery_history: self.recovery_history,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistryWireV11 {
    pub(super) registry_wire_version: ContractVersion,
    pub(super) revision: u64,
    generations: Vec<ApprovedGenerationWire>,
    service_registration_approvals: Vec<InstallerServiceRegistrationApproval>,
    active_generation: RequiredOption<PlatformHandle>,
    last_known_good_generation: RequiredOption<PlatformHandle>,
    pending_activation: RequiredOption<PendingActivationWire>,
    last_terminal_activation: RequiredOption<PendingActivationTerminalWire>,
    active_phase_b_rebind: RequiredOption<ActivePhaseBRebindWireV11>,
}

/// An optional wire member whose presence is mandatory.  Explicit `null` is
/// the only valid empty value; an omitted member is a schema migration rather
/// than an implicit serde default.
struct RequiredOption<T>(Option<T>);

impl<'de, T> Deserialize<'de> for RequiredOption<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

impl RegistryWireV11 {
    pub(super) fn into_registry(self) -> ApprovedGenerationRegistry {
        ApprovedGenerationRegistry {
            registry_wire_version: self.registry_wire_version,
            revision: self.revision,
            generations: self
                .generations
                .into_iter()
                .map(ApprovedGenerationWire::into_generation)
                .collect(),
            service_registration_approvals: self.service_registration_approvals,
            active_generation: self.active_generation.0,
            last_known_good_generation: self.last_known_good_generation.0,
            pending_activation: self
                .pending_activation
                .0
                .map(PendingActivationWire::into_pending),
            last_terminal_activation: self
                .last_terminal_activation
                .0
                .map(PendingActivationTerminalWire::into_terminal),
            active_phase_b_rebind: self
                .active_phase_b_rebind
                .0
                .map(ActivePhaseBRebindWireV11::into_rebind),
        }
    }
}
