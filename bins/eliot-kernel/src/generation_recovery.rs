#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_contracts::{AuthorityEpoch, StateFence};
use eliot_ipc::ServerHandshakePolicy;
use eliot_kernel_core::{CutoverDecision, GenerationRoute, GenerationRouter, RouteScope};
use eliot_kernel_service::KernelService;
use eliot_ors::RedbRecoveryStore;
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
};

use crate::{PROTOCOL_VERSION, SERVICE_NAME};

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

pub(crate) struct OrsGenerationCoordinator {
    pub(crate) ors: Arc<RedbRecoveryStore>,
}

impl OrsGenerationCoordinator {
    pub(crate) fn new(ors: Arc<RedbRecoveryStore>) -> Self {
        Self { ors }
    }

    pub(crate) fn recover(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        let _ = self
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        let snapshots = self
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        if snapshots.is_empty() {
            return Ok(());
        }
        let epoch_value = snapshots
            .iter()
            .map(|snapshot| snapshot.record().new_epoch.value())
            .max()
            .ok_or_else(|| "committed cutover projection was empty".to_owned())?;
        let epoch = AuthorityEpoch::new(epoch_value).map_err(|error| error.to_string())?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            if record.state != GenerationCutoverState::Committed
                || record.new_epoch.value() > epoch_value
            {
                return Err("ORS route projection has invalid committed epochs".to_owned());
            }
        }
        service
            .synchronize_authority_epoch(epoch)
            .map_err(|error| error.to_string())?;
        let mut recovered = GenerationRouter::at_epoch(epoch).map_err(|error| error.to_string())?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            let scope =
                RouteScope::new(record.route_scope.clone()).map_err(|error| error.to_string())?;
            let route = GenerationRoute::new(scope, record.new_generation, epoch)
                .map_err(|error| error.to_string())?;
            recovered
                .register(route)
                .map_err(|error| error.to_string())?;
        }
        update_handshake_policy(policy, &recovered)?;
        *generations = recovered;
        Ok(())
    }

    pub(crate) fn persist_and_publish(
        &self,
        decision: &CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        let mut candidate = generations.clone();
        candidate
            .cutover(decision)
            .map_err(|error| error.to_string())?;
        let staged = RuntimeGenerationCutoverRecord {
            cutover_id: decision.cutover_id().to_owned(),
            route_scope: decision.route_scope().as_str().to_owned(),
            old_generation: decision.old_generation(),
            new_generation: decision.new_generation(),
            old_epoch: decision.old_epoch(),
            new_epoch: decision.new_epoch(),
            state: GenerationCutoverState::Armed,
        };
        self.ors
            .stage_generation_cutover(staged.clone())
            .map_err(|error| error.to_string())?;
        let committed = self
            .ors
            .commit_generation_cutover_state(staged)
            .map_err(|error| error.to_string())?;
        if committed.record().state != GenerationCutoverState::Committed {
            return Err("ORS did not return a committed cutover".to_owned());
        }
        service
            .synchronize_authority_epoch(decision.new_epoch())
            .map_err(|error| error.to_string())?;
        update_handshake_policy(policy, &candidate)?;
        *generations = candidate;
        Ok(())
    }
}

pub(crate) fn update_handshake_policy(
    policy: &mut ServerHandshakePolicy,
    generations: &GenerationRouter,
) -> Result<(), String> {
    let daemon = RouteScope::new("daemon").map_err(|error| error.to_string())?;
    if let Ok(route) = generations.route(&daemon) {
        let artifact_digest = policy.config_snapshot.get("artifact_digest").cloned();
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .cloned();
        if let Some(protected_snapshot_digest) = protected_snapshot_digest.as_ref() {
            let Some(value) = protected_snapshot_digest.as_str() else {
                return Err("Kernel protected snapshot digest must be a JSON string".to_owned());
            };
            if !is_lower_sha256(value) {
                return Err("Kernel protected snapshot digest must be lowercase SHA-256".to_owned());
            }
        }
        policy.module_generation.generation = route.active_generation();
        policy.module_generation.state_fence =
            StateFence::new(route.authority_epoch(), route.active_generation());
        policy.config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": route.active_generation().value(),
            "authority_epoch": route.authority_epoch().value(),
        });
        if let Some(artifact_digest) = artifact_digest {
            policy.config_snapshot["artifact_digest"] = artifact_digest;
        }
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            policy.config_snapshot["protected_snapshot_digest"] = protected_snapshot_digest;
        }
    }
    Ok(())
}
