//! The frozen, finite artifact-to-contract map for the admitted hot path.
//!
//! `I6.4` obliges every hot reachable module to ship a contract, but a crate
//! name in an old inventory is not an artifact. This module records the finite
//! set the product actually loads, keeps the three kinds apart, and refuses a
//! record with no real loader or consumer.
//!
//! Kind matters because the three cases have different boundaries:
//!
//! * [`HotArtifactKind::LinkedLibrary`] is ordinary linked Rust code. It is
//!   covered through the bundle that actually hosts it and never receives a
//!   process, generation or manifest of its own.
//! * [`HotArtifactKind::ProcessService`] is a supervised process with its own
//!   generation but no side-by-side hot replacement.
//! * [`HotArtifactKind::HotReplaceableModule`] is an independently admitted
//!   artifact replaced under a new artifact/manifest revision.
//!
//! The map is a declaration, exactly like the contract it points at. It confers
//! no readiness, health, test success or activation authority, and a required
//! artifact with no record stays visible as a refusal rather than shrinking the
//! admitted set.

use eliot_contracts::{ArtifactId, ContractId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::RuntimeContractError;

/// How one in-scope artifact is actually executed and replaced.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HotArtifactKind {
    /// Ordinary linked Rust library, covered through its owning bundle.
    LinkedLibrary,
    /// A supervised process service with its own generation.
    ProcessService,
    /// An independently admitted artifact replaced by a new revision.
    HotReplaceableModule,
}

/// One record of the frozen artifact-to-contract map.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotArtifactRecord {
    /// Module whose contract the artifact carries.
    pub module_id: ContractId,
    /// Exact immutable artifact identity.
    pub artifact_id: ArtifactId,
    /// Execution/replacement class of the artifact.
    pub kind: HotArtifactKind,
    /// Runtime bundle that actually hosts the artifact.
    pub runtime_bundle: String,
    /// Source owner of the artifact.
    pub source_owner: String,
    /// Real registration/loader path that admits the artifact.
    pub registration_loader: String,
    /// Real consumer that invokes the admitted module.
    pub consumer: String,
}

/// The finite map from admitted hot artifact to module contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotArtifactMap {
    /// One record per in-scope hot artifact.
    pub records: Vec<HotArtifactRecord>,
}

impl HotArtifactMap {
    /// Returns the record for one module, or `None` when the module is not in
    /// the admitted set. A missing record is a visible gap, never a default.
    pub fn record(&self, module_id: &ContractId) -> Option<&HotArtifactRecord> {
        self.records
            .iter()
            .find(|record| &record.module_id == module_id)
    }

    /// Validates the frozen map.
    ///
    /// Every record must name a non-blank runtime bundle, source owner,
    /// registration/loader and consumer, and each module and artifact identity
    /// may be claimed once. A linked library must name the bundle that hosts it
    /// and must not claim a manifest location of its own, so a crate name in the
    /// old inventory cannot mint a separate process or generation.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        let mut modules: Vec<ContractId> = Vec::with_capacity(self.records.len());
        let mut artifacts: Vec<ArtifactId> = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let module = record.module_id.to_string();
            for field in [
                (&record.runtime_bundle, "runtime_bundle"),
                (&record.source_owner, "source_owner"),
                (&record.registration_loader, "registration_loader"),
                (&record.consumer, "consumer"),
            ] {
                if field.0.trim().is_empty() || field.0.chars().any(char::is_control) {
                    return Err(RuntimeContractError::HotArtifactLoaderMissing {
                        module: module.clone(),
                        field: field.1,
                    });
                }
            }
            if modules.contains(&record.module_id) {
                return Err(RuntimeContractError::DuplicateHotArtifact { identity: module });
            }
            if artifacts.contains(&record.artifact_id) {
                return Err(RuntimeContractError::DuplicateHotArtifact {
                    identity: record.artifact_id.to_string(),
                });
            }
            modules.push(record.module_id.clone());
            artifacts.push(record.artifact_id.clone());
        }
        Ok(())
    }
}

/// Returns the frozen artifact-to-contract map for the admitted
/// captured-query → bridge/Kernel → eliotd path.
///
/// The set is the artifacts that path actually loads and invokes, plus the
/// User Broker and the canonical store it depends on. Each entry names the
/// artifact, the runtime bundle that hosts it, the source owner, the real
/// registration/loader, and the real consumer. The `eliot-runtime-contracts`
/// and `eliot-protocol` libraries are recorded as linked libraries covered
/// through the bundles that host them, so no process or generation is minted
/// for them.
pub fn admitted_hot_artifact_map() -> Result<HotArtifactMap, RuntimeContractError> {
    let records = vec![
        HotArtifactRecord {
            module_id: ContractId::new("eliot-agent-bridge")?,
            artifact_id: ArtifactId::new("eliot-agent-bridge")?,
            kind: HotArtifactKind::ProcessService,
            runtime_bundle: "eliot-agent-bridge.exe".to_owned(),
            source_owner: "bins/eliot-agent-bridge".to_owned(),
            registration_loader: "bins/eliot-agent-bridge/src/lib.rs::kernel_ports_with_declaration"
                .to_owned(),
            consumer: "crates/kernel/eliot-installation/src/agent_bridge_profile.rs::agent_bridge_source_plan_from_observed_kernel".to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliot-kernel")?,
            artifact_id: ArtifactId::new("eliot-kernel")?,
            kind: HotArtifactKind::ProcessService,
            runtime_bundle: "eliot-kernel.exe".to_owned(),
            source_owner: "bins/eliot-kernel".to_owned(),
            registration_loader: "bins/eliot-kernel/src/lib.rs::SERVICE_NAME".to_owned(),
            consumer: "bins/eliotd/src/daemon_kernel_client/handshake.rs::client_hello".to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliot-store")?,
            artifact_id: ArtifactId::new("eliot-store")?,
            kind: HotArtifactKind::ProcessService,
            runtime_bundle: "eliot-store-surreal.exe".to_owned(),
            source_owner: "bins/eliot-store-surreal".to_owned(),
            registration_loader: "bins/eliot-store-surreal/src/lib.rs::SERVICE_NAME".to_owned(),
            consumer: "crates/kernel/eliot-kernel-service/src/store_client.rs::client_hello"
                .to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliot-user-broker")?,
            artifact_id: ArtifactId::new("eliot-user-broker")?,
            kind: HotArtifactKind::ProcessService,
            runtime_bundle: "eliot-user-broker.exe".to_owned(),
            source_owner: "bins/eliot-user-broker".to_owned(),
            registration_loader: "bins/eliot-user-broker/src/lib.rs::SERVICE_NAME".to_owned(),
            consumer: "bins/eliot-user-broker/src/kernel_authority_port.rs::KernelAuthorityPort"
                .to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliotd")?,
            artifact_id: ArtifactId::new("eliotd")?,
            kind: HotArtifactKind::HotReplaceableModule,
            runtime_bundle: "eliotd.exe".to_owned(),
            source_owner: "bins/eliotd".to_owned(),
            registration_loader: "bins/eliotd/src/daemon_config.rs::DaemonConfig::load_protected_bound"
                .to_owned(),
            consumer: "bins/eliotd/src/daemon_kernel_client/handshake.rs::client_hello".to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliot-protocol")?,
            artifact_id: ArtifactId::new("eliot-protocol")?,
            kind: HotArtifactKind::LinkedLibrary,
            runtime_bundle: "linked into eliot-agent-bridge and eliotd".to_owned(),
            source_owner: "crates/foundation/eliot-protocol".to_owned(),
            registration_loader: "crates/foundation/eliot-protocol/src/lib.rs::AGENT_BRIDGE_MODULE_ID"
                .to_owned(),
            consumer: "bins/eliotd/src/daemon_kernel_client/handshake.rs::client_hello".to_owned(),
        },
        HotArtifactRecord {
            module_id: ContractId::new("eliot-runtime-contracts")?,
            artifact_id: ArtifactId::new("eliot-runtime-contracts")?,
            kind: HotArtifactKind::LinkedLibrary,
            runtime_bundle: "linked into eliotd and eliot-kernel-core".to_owned(),
            source_owner: "crates/foundation/eliot-runtime-contracts".to_owned(),
            registration_loader:
                "crates/foundation/eliot-runtime-contracts/src/module_manifest.rs::admit_module_manifest"
                    .to_owned(),
            consumer: "crates/kernel/eliot-kernel-core/src/module/generation_readiness.rs::evaluate_module_set_readiness"
                .to_owned(),
        },
    ];
    let map = HotArtifactMap { records };
    map.validate()?;
    Ok(map)
}
