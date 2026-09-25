//! Kernel ORS generation recovery and cutover persistence.
//!
//! Owns bounded reconstruction of the generation router from committed ORS
//! cutovers and the persist-then-publish closure that synchronizes the Kernel
//! service epoch and daemon handshake generation/state fence.
//!
//! Architecture: A13.2 Kernel и failure domains; A13.3 Module supervision и Doctor; A13.6 Operational Recovery State; ARCH-RES-01 Fail locally, recover globally; ARCH-RES-03 Restore/migration cannot resurrect invalid state; ARCH-RES-04 Degradation is visible and local
//! Implementation: I4.5 Generation vector and State Fence; I14.14 Module hot replacement; I14.21 Unknown commit recovery; P.4 Operational Recovery State boundary; I2.23 Capability-family topology and crate extraction decisions
//! Forbidden authority: must not interpret semantic content, become a second generation authority, publish an uncommitted route, or bypass the ORS cutover record, authority epoch, and handshake fence.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_contracts::{AuthorityEpoch, StateFence};
use eliot_ipc::ServerHandshakePolicy;
use eliot_kernel_core::{CutoverDecision, GenerationRoute, GenerationRouter, RouteScope};
use eliot_kernel_service::KernelService;
use eliot_ors::{CutoverRouteSnapshot, CutoverRouteTable, OrsError, RedbRecoveryStore};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
};

use crate::{PROTOCOL_VERSION, SERVICE_NAME};

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// F-LOG-KERNEL-4 (#903 slice B): recovery and cutover-persistence boundary
/// observations.
///
/// Observation only, via #895's facade: fixed `kernel.recovery.*` event names
/// plus a bounded stable outcome. Never carries cutover identities, digests,
/// epochs, scopes, generations, or owner error strings (I15.4, I07.20).
/// Terminal ownership stays with the calling gateways: a failed `recover`
/// replay is terminal-mapped by the composition build owner, and a failed
/// `persist_and_publish` is fenced and terminal-mapped by the cutover gateway
/// owner in `generation_control.rs`. Subordinate phases correlate here
/// without duplicate failure claims, and no observation mutates the router,
/// the service epoch, the handshake policy, or the ORS record.
fn observe_recovery(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "generation recovery observation"
    );
}

pub(crate) struct OrsGenerationCoordinator {
    pub(crate) ors: Arc<RedbRecoveryStore>,
    /// Committed I14.14 route ownership rebuilt during startup recovery.
    /// Admission consumers must supply the canonical route-scope hash; this
    /// table never derives one from a request's partial route fields.
    pub(crate) cutover_routes: CutoverRouteTable,
}

impl OrsGenerationCoordinator {
    pub(crate) fn new(ors: Arc<RedbRecoveryStore>) -> Self {
        Self {
            ors,
            cutover_routes: CutoverRouteTable::new(),
        }
    }

    /// Restores the committed I14.14 ownership projection before the Kernel
    /// can accept work. Staged candidates are fenced first, and only the
    /// durable committed rows are allowed into the immutable route snapshot.
    /// No route identity is inferred here: the snapshot retains each
    /// record's canonical ORS route-scope hash for a later typed admission
    /// boundary.
    pub(crate) fn recover_cutover_ownership(&self) -> Result<(), String> {
        observe_recovery("kernel.recovery.cutover_ownership_requested", "attempt");
        let outcome = (|| {
            if let Err(error) = self
                .ors
                .reconcile_staged_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
            {
                if is_absent_cutover_ownership_table(&error) {
                    observe_recovery("kernel.recovery.cutover_ownership_absent", "empty");
                    return Ok(());
                }
                return Err(error.to_string());
            }
            observe_recovery("kernel.recovery.cutover_ownership_reconciled", "success");
            let committed = self
                .ors
                .latest_committed_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
                .map_err(|error| error.to_string())?;
            let snapshot =
                CutoverRouteSnapshot::rebuild(&committed).map_err(|error| error.to_string())?;
            self.cutover_routes.swap_committed(snapshot);
            observe_recovery("kernel.recovery.cutover_ownership_restored", "success");
            Ok(())
        })();
        if outcome.is_err() {
            observe_recovery("kernel.recovery.cutover_ownership_failed", "rejected");
        }
        outcome
    }

    pub(crate) fn recover(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        observe_recovery("kernel.recovery.recover_requested", "attempt");
        let outcome = self.recover_inner(generations, service, policy);
        if outcome.is_ok() {
            observe_recovery("kernel.recovery.recover_completed", "success");
        } else {
            observe_recovery("kernel.recovery.recover_failed", "rejected");
        }
        outcome
    }

    fn recover_inner(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        let _ = self
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        observe_recovery("kernel.recovery.cutovers_reconciled", "success");
        let snapshots = self
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        observe_recovery("kernel.recovery.cutovers_loaded", "success");
        if snapshots.is_empty() {
            observe_recovery("kernel.recovery.load_empty", "empty");
            return Ok(());
        }
        let epoch_value = snapshots
            .iter()
            .map(|snapshot| snapshot.record().new_epoch.value())
            .max()
            .ok_or_else(|| "committed cutover projection was empty".to_owned())?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            if record.state != GenerationCutoverState::Committed
                || record.new_epoch.value() > epoch_value
            {
                return Err("ORS route projection has invalid committed epochs".to_owned());
            }
        }
        observe_recovery("kernel.recovery.cutovers_validated", "success");
        // Lineage-aware bridge (Implements #64): the durable ORS cutover record
        // carries only the sequence, so it can never prove a lineage. The
        // canonical service epoch keeps its own lineage and advances to the
        // maximal committed sequence; `synchronize` fails closed on a lineage
        // mismatch or a regression, and the rebuilt route table is then bound
        // to that exact tuple rather than to a bare counter.
        let current_lineage = service.authority_epoch().lineage_id.clone();
        let canonical = eliot_contracts::EpochId::new(
            current_lineage,
            std::num::NonZeroU64::new(epoch_value)
                .ok_or_else(|| "committed cutover epoch must be non-zero".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        service
            .synchronize_authority_epoch(canonical)
            .map_err(|error| error.to_string())?;
        let active_epoch = service.authority_epoch();
        let mut recovered = GenerationRouter::at_epoch(active_epoch.clone());
        for snapshot in &snapshots {
            let record = snapshot.record();
            // A committed record at any other sequence belongs to a superseded
            // position in the epoch history. Adopting it here would replay a
            // bare scalar into the current lineage, so it stays historical and
            // never becomes the active route.
            if record.state != GenerationCutoverState::Committed
                || record.new_epoch.value() != active_epoch.sequence.get()
            {
                continue;
            }
            let scope =
                RouteScope::new(record.route_scope.clone()).map_err(|error| error.to_string())?;
            let route =
                GenerationRoute::new(scope, record.new_generation, active_epoch.clone())
                    .map_err(|error| error.to_string())?;
            recovered
                .register(route)
                .map_err(|error| error.to_string())?;
        }
        update_handshake_policy(policy, &recovered)?;
        *generations = recovered;
        observe_recovery("kernel.recovery.routes_applied", "success");
        Ok(())
    }

    pub(crate) fn persist_and_publish(
        &self,
        decision: &CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        observe_recovery("kernel.recovery.persist_requested", "attempt");
        let outcome = self.persist_and_publish_inner(decision, generations, service, policy);
        if outcome.is_ok() {
            observe_recovery("kernel.recovery.persist_completed", "success");
        } else {
            observe_recovery("kernel.recovery.persist_failed", "rejected");
        }
        outcome
    }

    fn persist_and_publish_inner(
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
            // The durable ORS record is still a scalar contour (W3 residual,
            // #64): only the sequence is projected into it, and no
            // authorization decision reads it back. The lineage-bearing
            // decision stays in `decision` and in the live route table.
            old_epoch: durable_epoch_projection(decision.old_epoch())?,
            new_epoch: durable_epoch_projection(decision.new_epoch())?,
            state: GenerationCutoverState::Armed,
        };
        self.ors
            .stage_generation_cutover(staged.clone())
            .map_err(|error| error.to_string())?;
        observe_recovery("kernel.recovery.cutover_staged", "success");
        let committed = self
            .ors
            .commit_generation_cutover_state(staged)
            .map_err(|error| error.to_string())?;
        if committed.record().state != GenerationCutoverState::Committed {
            return Err("ORS did not return a committed cutover".to_owned());
        }
        observe_recovery("kernel.recovery.cutover_committed", "success");
        // Same exact-tuple bridge as `recover`: the durable record projected the
        // canonical decision sequence; the service is then synchronized on the
        // complete tuple, which fails closed on a cross-lineage target or a
        // regression. The decision itself is never widened by its sequence.
        let decision_canonical = decision.new_epoch().clone();
        service
            .synchronize_authority_epoch(decision_canonical)
            .map_err(|error| error.to_string())?;
        update_handshake_policy(policy, &candidate)?;
        *generations = candidate;
        observe_recovery("kernel.recovery.cutover_applied", "success");
        Ok(())
    }
}

/// Projects one lineage-aware epoch into the still-scalar durable ORS cutover
/// record.
///
/// This is the only place a canonical epoch is narrowed to a bare counter, and
/// it exists because [`RuntimeGenerationCutoverRecord`] is a durable contract
/// that a versioned compatibility decoder (issue #64 W3) has not migrated yet.
/// The projection is write-only: every read and every authorization decision
/// in this file uses the complete [`eliot_contracts::EpochId`] tuple, so a
/// sequence-only record can never decide lineage.
fn durable_epoch_projection(epoch: &eliot_contracts::EpochId) -> Result<AuthorityEpoch, String> {
    AuthorityEpoch::new(epoch.sequence.get())
        .map_err(|error| format!("epoch projection is not representable: {error}"))
}

/// Older ORS databases predate the optional I14.14 ownership table. An absent
/// table means there are no committed cutover rows to restore; it is distinct
/// from a present table whose contents fail validation and must remain
/// terminal. The ORS crate currently exposes the redb absence only through
/// its typed storage message, so keep this compatibility test local to the
/// Kernel recovery boundary.
fn is_absent_cutover_ownership_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_cutover_ownership_v1' does not exist")
    )
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
        // Exact tuple equality (Implements #64): the policy fence adopts the
        // route's complete `EpochId`. Re-deriving a sequence on the policy's
        // own lineage is what previously let a route from another lineage be
        // rewritten into the current one, so a lineage disagreement is now a
        // terminal policy error instead of a silent rewrite.
        if policy.module_generation.state_fence.authority_epoch.lineage_id
            != route.authority_epoch().lineage_id
        {
            return Err("Kernel handshake policy epoch lineage disagrees with the route".to_owned());
        }
        policy.module_generation.state_fence =
            StateFence::new(route.authority_epoch().clone(), route.active_generation());
        policy.config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": route.active_generation().value(),
            "authority_epoch": route.authority_epoch(),
        });
        if let Some(artifact_digest) = artifact_digest {
            policy.config_snapshot["artifact_digest"] = artifact_digest;
        }
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            policy.config_snapshot["protected_snapshot_digest"] = protected_snapshot_digest;
        }
        observe_recovery("kernel.recovery.handshake_projected", "success");
    } else {
        observe_recovery("kernel.recovery.handshake_absent", "absent");
    }
    Ok(())
}

#[cfg(test)]
mod generation_recovery_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903 slice B) focused diagnostics proof: the
    //! handshake-projection boundary keeps its exact owner behavior while
    //! recording only fixed, secret-free observation names.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::{KernelComposition, KernelConfig, unix_ms};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    #[test]
    fn startup_restores_committed_cutover_routes_only() {
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-cutover-recovery-{}-{}.redb",
            std::process::id(),
            unix_ms()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let scope =
            eliot_ors::CapabilityRouteScope::declare("mod-startup", "serve", "work", "effects")
                .expect("route scope");
        let route_scope_hash = scope.route_scope_hash.clone();
        let record = eliot_ors::GenerationCutoverOwnership {
            cutover_id: "cutover-startup-recovery".to_owned(),
            candidate_artifact: eliot_ors::ModuleArtifactIdentity {
                module_id: "mod-startup".to_owned(),
                semver: "1.0.0".to_owned(),
                artifact_hash: "a".repeat(64),
                manifest_digest: "b".repeat(64),
                layout_root: format!("modules/mod-startup/1.0.0/{}", "a".repeat(64)),
            },
            incumbent_artifact: None,
            scope,
            old_generation: None,
            new_generation: eliot_contracts::ResourceGeneration::new(2).expect("generation"),
            old_epoch: AuthorityEpoch::new(1).expect("epoch"),
            new_epoch: AuthorityEpoch::new(2).expect("epoch"),
            in_flight: Vec::new(),
            migration: eliot_ors::StateMigrationDecision::RetainCompatible,
            health_proof_ref: "health-proof-startup".to_owned(),
            rollback_boundary: "forward-only".to_owned(),
            unresolved_scopes: Vec::new(),
            linearization_record_id: None,
            state: GenerationCutoverState::Armed,
        };
        store
            .stage_cutover_ownership(record)
            .expect("stage cutover ownership");
        store
            .commit_cutover_ownership("cutover-startup-recovery")
            .expect("commit cutover ownership");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .recover_cutover_ownership()
            .expect("restore committed cutover ownership");
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                eliot_contracts::ResourceGeneration::new(2).expect("generation"),
                AuthorityEpoch::new(2).expect("epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::AdmitCandidate
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                "unrecorded-route-scope",
                eliot_contracts::ResourceGeneration::new(2).expect("generation"),
                AuthorityEpoch::new(2).expect("epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale
        );

        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn recovery_handshake_observation_preserves_policy_projection() {
        // A real composition supplies the policy contour and a real router
        // supplies the daemon route. Both legs run through the existing
        // `update_handshake_policy` caller — never a copied projection.
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-diagnostics-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let baseline = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock")
            .clone();

        // Projected leg: the daemon route drives generation, fence epoch,
        // and snapshot exactly as before; only fixed names reach the sink.
        let epoch = test_epoch(7);
        let mut router = GenerationRouter::at_epoch(epoch.clone());
        let scope = RouteScope::new("daemon").expect("daemon scope");
        let generation = eliot_contracts::ResourceGeneration::new(3).expect("generation");
        router
            .register(GenerationRoute::new(scope, generation, epoch.clone()).expect("route"))
            .expect("register");
        let mut policy = baseline.clone();
        policy.config_snapshot["artifact_digest"] =
            serde_json::Value::String("artifact-canary-string".to_owned());
        policy.config_snapshot["protected_snapshot_digest"] =
            serde_json::Value::String("e".repeat(64));
        let text = capture(|| {
            update_handshake_policy(&mut policy, &router).expect("policy update");
        });
        assert!(
            text.contains("kernel.recovery.handshake_projected"),
            "missing diagnostics marker kernel.recovery.handshake_projected"
        );
        assert!(
            !text.contains("artifact-canary-string"),
            "policy material leaked into diagnostics"
        );
        assert_eq!(policy.module_generation.generation.value(), 3);
        let fence = &policy.module_generation.state_fence;
        assert_eq!(fence.authority_epoch.sequence.get(), 7);
        assert_eq!(fence.resource_generation.value(), 3);
        assert_eq!(
            policy.config_snapshot["generation"],
            serde_json::json!(3u64)
        );
        assert_eq!(
            policy.config_snapshot["authority_epoch"],
            serde_json::to_value(&epoch).expect("epoch json")
        );
        assert_eq!(
            policy.config_snapshot["service"],
            serde_json::json!(SERVICE_NAME)
        );
        assert_eq!(
            policy.config_snapshot["protocol"],
            serde_json::json!(PROTOCOL_VERSION)
        );
        assert_eq!(
            policy.config_snapshot["artifact_digest"],
            serde_json::json!("artifact-canary-string")
        );
        assert_eq!(
            policy.config_snapshot["protected_snapshot_digest"],
            serde_json::json!("e".repeat(64))
        );

        // Absent leg: without a daemon route the policy is byte-identical
        // and the omission — not a projection — is recorded.
        let empty = GenerationRouter::at_epoch(epoch);
        let mut policy = baseline.clone();
        let before = policy.clone();
        let text = capture(|| {
            update_handshake_policy(&mut policy, &empty).expect("absent policy update");
        });
        assert!(
            text.contains("kernel.recovery.handshake_absent"),
            "missing diagnostics marker kernel.recovery.handshake_absent"
        );
        assert_eq!(policy, before);

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }
}
