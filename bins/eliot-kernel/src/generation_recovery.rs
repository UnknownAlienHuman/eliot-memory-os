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

use eliot_contracts::StateFence;
use eliot_ipc::ServerHandshakePolicy;
use eliot_kernel_core::{
    CompatibilityMismatch, CutoverDecision, DurableCompatibilityState, GenerationRoute,
    GenerationRouter, RouteScope, StateMigrationClass, VersionRange, admit_rollback,
    restore_recorded_evidence,
};
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

/// F-LOG-KERNEL-4 (#903 W7): cutover-scoped persistence observations.
///
/// Same #895-only shape as [`observe_recovery`] plus the cutover call's own
/// validated operation identity (already echoed on the authenticated
/// `GenerationCutoverOutcome` reply; I15.4, I07.20, W6), policy-screened and
/// bounded by `bound_field` before formatting. Deferred phase records of
/// concurrent cutovers correlate by identity with no dedup cache, no new
/// probe, and no lock-held emission.
fn observe_recovery_cutover(event: &'static str, outcome: &'static str, cutover_id: &str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    let cutover_bound = bound_field(cutover_id);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        cutover_id = cutover_bound.text(),
        "generation recovery observation"
    );
}

#[derive(Clone, Copy)]
enum HandshakePolicyObservation {
    Projected,
    Absent,
}

impl HandshakePolicyObservation {
    fn emit(self) {
        match self {
            Self::Projected => {
                observe_recovery("kernel.recovery.handshake_projected", "success");
            }
            Self::Absent => observe_recovery("kernel.recovery.handshake_absent", "absent"),
        }
    }

    /// Cutover-scoped handshake observation: the same subordinate record,
    /// correlated to its cutover call by the validated operation identity (W7).
    fn emit_for_cutover(self, cutover_id: &str) {
        match self {
            Self::Projected => {
                observe_recovery_cutover(
                    "kernel.recovery.handshake_projected",
                    "success",
                    cutover_id,
                );
            }
            Self::Absent => {
                observe_recovery_cutover("kernel.recovery.handshake_absent", "absent", cutover_id);
            }
        }
    }
}

/// Fixed-size record of the persistence phases reached by one cutover.
///
/// The owner performs each phase synchronously while it holds the generation,
/// service, policy, and poison guards. The caller emits this record only after
/// those guards have been released, preserving the phase order without adding
/// a queue or another state owner. Every emitted record carries the cutover's
/// own validated operation identity, so concurrent cutovers correlate by
/// identity as well as by order (W7).
#[derive(Clone, Copy, Default)]
pub(crate) struct PersistAndPublishObservations {
    cutover_staged: bool,
    cutover_committed: bool,
    handshake_policy: Option<HandshakePolicyObservation>,
    cutover_applied: bool,
}

pub(crate) struct PersistAndPublishResult {
    pub(crate) result: Result<(), String>,
    pub(crate) observations: PersistAndPublishObservations,
}

impl PersistAndPublishObservations {
    pub(crate) fn emit(self, succeeded: bool, cutover_id: &str) {
        observe_recovery_cutover("kernel.recovery.persist_requested", "attempt", cutover_id);
        if self.cutover_staged {
            observe_recovery_cutover("kernel.recovery.cutover_staged", "success", cutover_id);
        }
        if self.cutover_committed {
            observe_recovery_cutover("kernel.recovery.cutover_committed", "success", cutover_id);
        }
        if let Some(observation) = self.handshake_policy {
            observation.emit_for_cutover(cutover_id);
        }
        if self.cutover_applied {
            observe_recovery_cutover("kernel.recovery.cutover_applied", "success", cutover_id);
        }
        if succeeded {
            observe_recovery_cutover("kernel.recovery.persist_completed", "success", cutover_id);
        } else {
            observe_recovery_cutover("kernel.recovery.persist_failed", "rejected", cutover_id);
        }
    }
}

pub(crate) struct OrsGenerationCoordinator {
    pub(crate) ors: Arc<RedbRecoveryStore>,
    /// Committed I14.14 route ownership rebuilt during startup recovery.
    /// Admission consumers must supply the canonical route-scope hash; this
    /// table never derives one from a request's partial route fields.
    pub(crate) cutover_routes: CutoverRouteTable,
}

/// The current durable compatibility state the Kernel is running under, used
/// to gate every restored route as a rollback (I1.12, issue #1890 W4).
///
/// Built from the SAME live values the runtime handshake binds
/// (`frame_dispatch::runtime_compatibility_evidence`), so the rollback gate and
/// the activation handshake are compared against one durable state rather than
/// two independently derived projections. It is derived from the running
/// binary's own protocol/format/contract/architecture identity and the service's
/// current authority epoch; nothing is invented and no evidence is carried over
/// from a previous process.
fn current_durable_compatibility_state(
    service: &KernelService,
) -> Result<DurableCompatibilityState, String> {
    let protocol_range = VersionRange::new(1, 1).map_err(|error| error.to_string())?;
    let canonical_format_range = VersionRange::new(1, 1).map_err(|error| error.to_string())?;
    let contract_set_digest =
        super::frame_dispatch::runtime_contract_set_digest().map_err(|error| error.to_string())?;
    DurableCompatibilityState::new(
        protocol_range,
        contract_set_digest,
        canonical_format_range,
        eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
        service.authority_epoch(),
        vec![super::frame_dispatch::RUNTIME_HEALTH_CAPABILITY.to_owned()],
        StateMigrationClass::NoMigration,
    )
    .map_err(|error| error.to_string())
}

impl OrsGenerationCoordinator {
    pub(crate) fn new(ors: Arc<RedbRecoveryStore>) -> Self {
        Self {
            ors,
            cutover_routes: CutoverRouteTable::new(),
        }
    }

    /// Re-verifies one retained generation's recorded I1.12 evidence against the
    /// CURRENT durable compatibility state before that generation may be used as
    /// a rollback target (I1.12, issue #1890 W4/A2).
    ///
    /// This is the production caller of [`admit_rollback`]. "Last known good"
    /// means verified compatible with current durable formats and Authority
    /// Epoch lineage, not "it launched once": the verdict persisted with the
    /// candidate generation is re-read from ORS, projected back into the
    /// handshake evidence shape, and compared against the durable state the
    /// Kernel is running under right now.
    ///
    /// A previously launched artifact is therefore refused as a rollback target
    /// after a format, contract, architecture, seal, migration-class or
    /// epoch-lineage change, even though its own recorded verdict was admitted
    /// when it first ran.
    ///
    /// # Errors
    ///
    /// Returns the exact [`CompatibilityMismatch`] produced by
    /// [`admit_rollback`], or one naming an absent/unreadable record, so the
    /// caller retains the field label and reason as the structured cause.
    pub(crate) fn admit_generation_rollback(
        &self,
        module_id: &str,
        generation: u64,
        durable: &DurableCompatibilityState,
    ) -> Result<(), CompatibilityMismatch> {
        let recorded = self
            .ors
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                CompatibilityMismatch::new(
                    eliot_kernel_core::MismatchField::EnvelopeVersion,
                    format!("generation registry is unreadable: {error}"),
                )
            })?
            .compatibility(module_id, generation)
            .cloned()
            .ok_or_else(|| {
                CompatibilityMismatch::new(
                    eliot_kernel_core::MismatchField::EnvelopeVersion,
                    "no recorded compatibility verdict exists for this generation",
                )
            })?;
        let evidence = restore_recorded_evidence(&recorded)?;
        admit_rollback(&evidence, durable)
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
        // Current bindings are rebuilt from verified records, and the current
        // tuple is the complete `(lineage_id, sequence)` of the most recently
        // committed cutover in durable ORS order. A bare `max()` over sequences
        // is undefined as soon as more than one lineage exists, and re-deriving
        // that number on the service's own lineage would silently attach
        // today's lineage to a record that never carried one. A row written
        // before the typed migration no longer decodes, so it cannot reach here
        // at all: a historical valid tuple never reactivates current authority.
        let current = snapshots
            .iter()
            .max_by_key(|snapshot| snapshot.operation_order())
            .map(|snapshot| snapshot.record().new_epoch.clone())
            .ok_or_else(|| "committed cutover projection was empty".to_owned())?;
        for snapshot in &snapshots {
            if snapshot.record().state != GenerationCutoverState::Committed {
                return Err("ORS route projection has invalid committed epochs".to_owned());
            }
        }
        observe_recovery("kernel.recovery.cutovers_validated", "success");
        // The service keeps its own Host-approved lineage and refuses a
        // cross-lineage or regressing target, so a record from a superseded
        // lineage fails closed here instead of being adopted.
        service
            .synchronize_authority_epoch(current)
            .map_err(|error| error.to_string())?;
        let active_epoch = service.authority_epoch();
        let mut recovered = GenerationRouter::at_epoch(active_epoch.clone());
        // I1.12 (issue #1890 W4/A2): a restart rebuilds the route table from the
        // committed cutover records, which is the one place a retained
        // generation is re-selected as a live route after it previously ran.
        // That re-selection is a rollback, so it is gated here: each restored
        // route's recorded I1.12 evidence must still validate against the
        // durable compatibility state the Kernel is running under NOW. A
        // generation that was admitted once is not thereby a valid rollback
        // target after a format, contract, architecture, seal, migration-class
        // or epoch-lineage change.
        let durable = current_durable_compatibility_state(service)?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            // A committed record for any other tuple — a pre-restore tuple, a
            // superseded sequence, or a tuple from a lineage that is no longer
            // active — belongs to epoch history only. Adopting it would replay
            // history into the current binding, so it stays historical and
            // never becomes the active route.
            if record.state != GenerationCutoverState::Committed
                || !record.new_epoch.is_same_authority(&active_epoch)
            {
                continue;
            }
            // The cutover record names its generation as the typed
            // `ResourceGeneration`; the ORS versioned-artifact registry keys
            // the recorded verdict by the same generation value, so the
            // rollback lookup uses that value rather than a re-derived one.
            let generation = record.new_generation.value();
            self.admit_generation_rollback(&record.route_scope, generation, &durable)
                .map_err(|mismatch| {
                    format!(
                        "restored route {} generation {} is not a valid rollback target: {} ({})",
                        record.route_scope,
                        generation,
                        mismatch.field(),
                        mismatch.reason()
                    )
                })?;
            let scope =
                RouteScope::new(record.route_scope.clone()).map_err(|error| error.to_string())?;
            let route = GenerationRoute::new(scope, record.new_generation, active_epoch.clone())
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
    ) -> PersistAndPublishResult {
        let mut observations = PersistAndPublishObservations::default();
        let result = self.persist_and_publish_inner(
            decision,
            generations,
            service,
            policy,
            &mut observations,
        );
        PersistAndPublishResult {
            result,
            observations,
        }
    }

    fn persist_and_publish_inner(
        &self,
        decision: &CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
        observations: &mut PersistAndPublishObservations,
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
            // The durable ORS record carries the complete typed tuples, so a
            // reader can no longer lose the lineage. Nothing here narrows an
            // `EpochId` to a sequence: the record written here is the same
            // tuple the router advanced on, and every authorization decision
            // still reads the live route table.
            old_epoch: decision.old_epoch().clone(),
            new_epoch: decision.new_epoch().clone(),
            state: GenerationCutoverState::Armed,
        };
        self.ors
            .stage_generation_cutover(staged.clone())
            .map_err(|error| error.to_string())?;
        observations.cutover_staged = true;
        let committed = self
            .ors
            .commit_generation_cutover_state(staged)
            .map_err(|error| error.to_string())?;
        if committed.record().state != GenerationCutoverState::Committed {
            return Err("ORS did not return a committed cutover".to_owned());
        }
        observations.cutover_committed = true;
        // Same exact-tuple bridge as `recover`: the durable record projected the
        // canonical decision sequence; the service is then synchronized on the
        // complete tuple, which fails closed on a cross-lineage target or a
        // regression. The decision itself is never widened by its sequence.
        let decision_canonical = decision.new_epoch().clone();
        service
            .synchronize_authority_epoch(decision_canonical)
            .map_err(|error| error.to_string())?;
        observations.handshake_policy = Some(update_handshake_policy_without_observation(
            policy, &candidate,
        )?);
        *generations = candidate;
        observations.cutover_applied = true;
        Ok(())
    }
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
    let observation = update_handshake_policy_without_observation(policy, generations)?;
    observation.emit();
    Ok(())
}

fn update_handshake_policy_without_observation(
    policy: &mut ServerHandshakePolicy,
    generations: &GenerationRouter,
) -> Result<HandshakePolicyObservation, String> {
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
        if policy
            .module_generation
            .state_fence
            .authority_epoch
            .lineage_id
            != route.authority_epoch().lineage_id
        {
            return Err(
                "Kernel handshake policy epoch lineage disagrees with the route".to_owned(),
            );
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
        Ok(HandshakePolicyObservation::Projected)
    } else {
        Ok(HandshakePolicyObservation::Absent)
    }
}

#[cfg(test)]
mod generation_recovery_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903 slice B) focused diagnostics proof: the
    //! handshake-projection boundary keeps its exact owner behavior while
    //! recording only fixed, secret-free observation names.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::{KernelComposition, KernelConfig, unix_ms};
    use eliot_contracts::AuthorityEpoch;
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
        // Owner disclosure: this coordinator is a FRESH owner of the store
        // opened below, not the composition's own coordinator. See the shared
        // fixture header further down in this module.
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

    // ------------------------------------------------------------------
    // Shared fixtures for the recovery / cutover-persistence proofs below.
    //
    // Every premise in these tests is read back through the SAME store handle
    // production writes through, or out of the live `KernelComposition`'s own
    // `service` and `front_door_policy` guards — the same values the
    // composition mutates. No helper builds a look-alike store, router, policy
    // or service.
    //
    // The ORS owner is the ONE thing that is not shared, and it is disclosed
    // here rather than claimed away: `OrsGenerationCoordinator` is constructed
    // FRESH inside each test from `Arc::clone` of that shared store, while
    // production constructs its own coordinator at
    // `composition_bootstrap.rs:1893` and calls `recover_cutover_ownership` on
    // that one at `composition_bootstrap.rs:1932`. Each coordinator holds its
    // OWN in-memory `cutover_routes` snapshot, so these tests observe a fresh
    // owner's snapshot rebuilt from the shared DURABLE rows. The composition's
    // own coordinator wiring — that production constructs a coordinator and
    // recovers through it — is therefore NOT covered by this file, and cannot
    // be without a production change, which is out of scope for this slice.
    // ------------------------------------------------------------------

    /// One durable `ors_cutover_ownership_v1` candidate in its staged (`Armed`)
    /// shape, plus the stable route-scope hash its own coordinates produce.
    fn ownership_row(
        module: &str,
        cutover_id: &str,
        old_generation: Option<u64>,
        new_generation: u64,
        old_epoch: u64,
        new_epoch: u64,
        unresolved_scopes: Vec<String>,
    ) -> (eliot_ors::GenerationCutoverOwnership, String) {
        let scope = eliot_ors::CapabilityRouteScope::declare(module, "serve", "work", "effects")
            .expect("declare route scope");
        let route_scope_hash = scope.route_scope_hash.clone();
        let artifact_hash = "a".repeat(64);
        let row = eliot_ors::GenerationCutoverOwnership {
            cutover_id: cutover_id.to_owned(),
            candidate_artifact: eliot_ors::ModuleArtifactIdentity {
                module_id: module.to_owned(),
                semver: "1.0.0".to_owned(),
                artifact_hash: artifact_hash.clone(),
                manifest_digest: "b".repeat(64),
                layout_root: format!("modules/{module}/1.0.0/{artifact_hash}"),
            },
            incumbent_artifact: None,
            scope,
            old_generation: old_generation
                .map(|value| eliot_contracts::ResourceGeneration::new(value).expect("generation")),
            new_generation: eliot_contracts::ResourceGeneration::new(new_generation)
                .expect("candidate generation"),
            old_epoch: AuthorityEpoch::new(old_epoch).expect("old epoch"),
            new_epoch: AuthorityEpoch::new(new_epoch).expect("new epoch"),
            in_flight: Vec::new(),
            migration: eliot_ors::StateMigrationDecision::RetainCompatible,
            health_proof_ref: format!("health-proof-{cutover_id}"),
            rollback_boundary: "forward-only".to_owned(),
            unresolved_scopes,
            linearization_record_id: None,
            state: GenerationCutoverState::Armed,
        };
        (row, route_scope_hash)
    }

    /// The exact one-step child of a live epoch, built from the live tuple so a
    /// test never invents a lineage the production owner does not hold.
    fn direct_child_epoch(parent: &eliot_contracts::EpochId) -> eliot_contracts::EpochId {
        let sequence = parent.sequence.get().checked_add(1).expect("epoch step");
        eliot_contracts::EpochId::new(
            parent.lineage_id.clone(),
            std::num::NonZeroU64::new(sequence).expect("epoch sequence"),
        )
        .expect("direct child epoch")
    }

    /// Byte offset of one observation name inside the WHOLE captured sink
    /// surface, so phase order is asserted against the real emitted sequence.
    fn observed_at(text: &str, marker: &str) -> usize {
        text.find(marker)
            .unwrap_or_else(|| panic!("missing diagnostics marker {marker}"))
    }

    fn recovery_store_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-903-{tag}-{}-{}.redb",
            std::process::id(),
            unix_ms()
        ))
    }

    /// Scratch work root for one live `KernelComposition`, in the same
    /// temporary directory and identity shape as [`recovery_store_path`].
    fn recovery_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-903-{tag}-{}-{}",
            std::process::id(),
            unix_ms()
        ))
    }

    /// Stages a generation transition that OCCUPIES the operational subject a
    /// cutover for `scope` needs to stage under.
    ///
    /// `RedbRecoveryStore::stage_generation_cutover` derives the transition's
    /// subject from the record's route scope alone
    /// (`eliot-ors/src/store.rs:32767`), so this record — staged under its own
    /// `cutover_id`, hence a different immutable input — makes the owner's own
    /// stage write for the same scope collide with
    /// `OrsError::DuplicateConflict` (`store.rs:32965`) instead of landing. The
    /// refusal is reached through the store's own public seam; no failpoint,
    /// test hook or production flag is involved.
    fn stage_conflicting_transition(
        store: &RedbRecoveryStore,
        scope: &RouteScope,
        incumbent: eliot_contracts::ResourceGeneration,
        old_epoch: &eliot_contracts::EpochId,
        new_epoch: &eliot_contracts::EpochId,
    ) {
        store
            .stage_generation_cutover(RuntimeGenerationCutoverRecord {
                cutover_id: "cutover-903-stage-conflict".to_owned(),
                route_scope: scope.as_str().to_owned(),
                old_generation: None,
                new_generation: incumbent,
                old_epoch: old_epoch.clone(),
                new_epoch: new_epoch.clone(),
                state: GenerationCutoverState::Armed,
            })
            .expect("stage the conflicting transition");
    }

    /// A refused publish reports NO phase: not one flag is set, and the ladder
    /// emits only `persist_failed`. Both halves are asserted together so the
    /// flag surface and the emitted surface cannot drift apart.
    fn assert_no_persist_phase_reported(published: &PersistAndPublishResult, text: &str) {
        let observations = &published.observations;
        assert!(
            !observations.cutover_staged,
            "a refused publish reported a staged phase"
        );
        assert!(
            !observations.cutover_committed,
            "a refused publish reported a committed phase"
        );
        assert!(
            !observations.cutover_applied,
            "a refused publish reported an applied phase"
        );
        assert!(
            observations.handshake_policy.is_none(),
            "a refused publish reported a handshake projection"
        );
        assert!(text.contains("kernel.recovery.persist_failed"));
        assert!(!text.contains("kernel.recovery.cutover_staged"));
        assert!(!text.contains("kernel.recovery.cutover_committed"));
        assert!(!text.contains("kernel.recovery.cutover_applied"));
        assert!(!text.contains("kernel.recovery.persist_completed"));
    }

    /// The live service epoch and handshake policy as a REFUSED publish must
    /// leave them.
    ///
    /// `persist_and_publish_inner` runs the durable stage write FIRST and only
    /// then synchronizes the service epoch and projects the handshake policy.
    /// Those two steps are exactly what this compares, which is what makes the
    /// stage write's position observable: moving the service synchronization
    /// or the policy projection ahead of it leaves the process advanced past a
    /// cutover that was never recorded, and the service and fence comparisons
    /// both redden on precisely that reordering.
    ///
    /// The fence generation is compared against the policy's OWN generation
    /// field rather than against itself: `state_fence.resource_generation` and
    /// `module_generation.generation` are two distinct fields the projection
    /// writes together (`generation_recovery.rs`'s
    /// `update_handshake_policy_without_observation`), so this asserts a
    /// relation between them, not a value against its own copy.
    fn assert_live_fence_untouched(
        service: &KernelService,
        policy: &ServerHandshakePolicy,
        fence_epoch_before: &eliot_contracts::EpochId,
        policy_generation_before: eliot_contracts::ResourceGeneration,
    ) {
        let fence = &policy.module_generation.state_fence;
        assert_eq!(
            service.authority_epoch(),
            *fence_epoch_before,
            "a refused stage write advanced the authority epoch"
        );
        assert_eq!(
            fence.authority_epoch, *fence_epoch_before,
            "a refused stage write rewrote the handshake fence epoch"
        );
        assert_eq!(
            fence.resource_generation, policy_generation_before,
            "a refused stage write rewrote the handshake fence generation"
        );
    }

    /// The live router as a REFUSED publish must leave it: still at the
    /// pre-cutover epoch, still serving the incumbent generation on the very
    /// scope the refused decision named.
    fn assert_router_untouched(
        generations: &GenerationRouter,
        daemon: &RouteScope,
        incumbent: eliot_contracts::ResourceGeneration,
        from_epoch: &eliot_contracts::EpochId,
    ) {
        assert_eq!(
            generations.epoch(),
            from_epoch,
            "a refused stage write advanced the live router"
        );
        assert_eq!(
            generations
                .route(daemon)
                .expect("daemon route")
                .active_generation(),
            incumbent,
            "a refused stage write switched the live route"
        );
    }

    /// CHECKLIST T4 ("candidate versus staged generation"), T10 ("observed
    /// old/new authority epochs preserved") and the fence half of T11 ("old/new
    /// fences preserved").
    ///
    /// Doc anchor — I14.20 canonical runtime lifecycle vocabulary, Generation
    /// cutover: `PREPARING → ARMED → COMMITTED → RECONCILING → COMPLETED` and
    /// "`COMMITTED` is the ORS linearization point; unresolved scopes remain
    /// explicit during reconciliation." CHECKLIST W3: "Candidate, staged,
    /// active and current are different" and "Cutover/current-state events
    /// require the actual owner's receipt."
    ///
    /// Premises compared here are the owner's own values: the `PersistAndPublishObservations`
    /// phase record, the committed ORS row re-read through
    /// `RedbRecoveryStore::latest_generation_cutovers`, the live
    /// `GenerationRouter` admission guard and the live `ServerHandshakePolicy`
    /// fence the coordinator rewrote.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one cutover's staged/committed/applied phases are asserted as a single ordered contour"
    )]
    fn persist_and_publish_stages_commits_then_applies_one_cutover() {
        let path = recovery_store_path("persist");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));

        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-903-persist-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let mut service = kernel.service.lock().expect("service lock");
        let mut policy = kernel.front_door_policy.lock().expect("policy lock");

        // Live production values, not literals: the composition's own canonical
        // epoch is the genesis of its Host-approved lineage.
        let base = service.authority_epoch();
        let staged_epoch = direct_child_epoch(&base);
        let applied_epoch = direct_child_epoch(&staged_epoch);
        let first_generation = eliot_contracts::ResourceGeneration::new(1).expect("generation");
        let second_generation = eliot_contracts::ResourceGeneration::new(2).expect("generation");
        let work = RouteScope::new("work-903").expect("work scope");
        let refused_scope = RouteScope::new("work-refused-903").expect("refused scope");
        let daemon = RouteScope::new("daemon").expect("daemon scope");

        // A cutover that names a prior generation needs a prior committed route
        // for the same scope. It is written through the very store this
        // coordinator reads from, so the readback below compares two production
        // values rather than a fixture against itself.
        let base_record = RuntimeGenerationCutoverRecord {
            cutover_id: "cutover-903-persist-base".to_owned(),
            route_scope: work.as_str().to_owned(),
            old_generation: None,
            new_generation: first_generation,
            old_epoch: base.clone(),
            new_epoch: staged_epoch.clone(),
            state: GenerationCutoverState::Armed,
        };
        store
            .stage_generation_cutover(base_record.clone())
            .expect("stage base cutover");
        store
            .commit_generation_cutover_state(base_record)
            .expect("commit base cutover");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        let mut generations = GenerationRouter::at_epoch(staged_epoch.clone());
        generations
            .register(
                GenerationRoute::new(work.clone(), first_generation, staged_epoch.clone())
                    .expect("work generation route"),
            )
            .expect("register work route");
        generations
            .register(
                GenerationRoute::new(daemon.clone(), first_generation, staged_epoch.clone())
                    .expect("daemon generation route"),
            )
            .expect("register daemon route");

        let pre_fence_epoch = policy.module_generation.state_fence.authority_epoch.clone();
        let pre_fence_generation = policy.module_generation.state_fence.resource_generation;
        assert_eq!(
            pre_fence_epoch, base,
            "the composition fence epoch precondition changed"
        );
        assert_eq!(
            pre_fence_generation, first_generation,
            "the composition fence generation precondition changed"
        );

        let decision = CutoverDecision::new(
            "cutover-903-persist",
            work.clone(),
            Some(first_generation),
            second_generation,
            staged_epoch.clone(),
            applied_epoch.clone(),
            GenerationCutoverState::Committed,
        )
        .expect("cutover decision");

        let mut published = None;
        let text = capture(|| {
            let outcome = coordinator.persist_and_publish(
                &decision,
                &mut generations,
                &mut service,
                &mut policy,
            );
            // Exactly the emission the cutover gateway owner performs after it
            // releases the generation/service/policy guards.
            outcome
                .observations
                .emit(outcome.result.is_ok(), decision.cutover_id());
            published = Some(outcome);
        });
        let published = published.expect("persist_and_publish outcome");

        assert!(
            published.result.is_ok(),
            "a committed cutover over a committed route was refused"
        );
        // Phase record: STAGED, COMMITTED and APPLIED are three separate
        // production observations, not one blanket success. Each flag is
        // PRODUCTION-set: `PersistAndPublishObservations` exposes no setter,
        // its `Default` is all-false, and the only assignments are the four
        // lines inside `persist_and_publish_inner`, so no test-side value can
        // reach this record. That is falsifiable, not decorative: the
        // `stage_failure_...` test below makes the durable stage write fail
        // and proves the staged observation is then never emitted.
        assert!(
            published.observations.cutover_staged,
            "the staged phase was not reached"
        );
        assert!(
            published.observations.cutover_committed,
            "the committed phase was not reached"
        );
        assert!(
            published.observations.cutover_applied,
            "the applied phase was not reached"
        );
        assert!(
            matches!(
                published.observations.handshake_policy,
                Some(HandshakePolicyObservation::Projected)
            ),
            "the handshake projection phase was not reached"
        );
        // What these four comparisons establish, exactly: `emit` is a flat `if`
        // ladder whose sequence is a compile-time constant of
        // `PersistAndPublishObservations::emit`, so the offsets read the ladder's
        // own vocabulary order. They prove every one of those phases was ENABLED
        // and rendered in that fixed order.
        //
        // What they do NOT establish: any order of the real work inside
        // `persist_and_publish_inner`. Production emits no marker at the work
        // site, so no byte offset in this surface can observe whether
        // `stage_generation_cutover` ran before
        // `service.synchronize_authority_epoch`. The order-sensitive half of
        // that claim is proven elsewhere, by
        // `stage_failure_never_reports_a_staged_phase_or_moves_the_live_fence`,
        // which observes the same ordering through the durable store and the
        // live service epoch and policy fence.
        assert!(
            observed_at(&text, "kernel.recovery.persist_requested")
                < observed_at(&text, "kernel.recovery.cutover_staged")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutover_staged")
                < observed_at(&text, "kernel.recovery.cutover_committed")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutover_committed")
                < observed_at(&text, "kernel.recovery.cutover_applied")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutover_applied")
                < observed_at(&text, "kernel.recovery.persist_completed")
        );

        // T10: the durable ORS row, read back through the store's own public
        // seam, carries the COMPLETE old/new `EpochId` tuples (lineage AND
        // sequence) and the old/new generation pair the owner decided. A
        // mutation that narrowed either tuple to a scalar at
        // `persist_and_publish_inner`'s `RuntimeGenerationCutoverRecord`
        // construction reds here and nowhere else.
        let rows = store
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed cutovers");
        let newest = rows
            .iter()
            .max_by_key(|snapshot| snapshot.operation_order())
            .expect("committed cutover row");
        let recorded = newest.record();
        assert_eq!(recorded.state, GenerationCutoverState::Committed);
        assert_eq!(recorded.cutover_id, decision.cutover_id());
        assert_eq!(recorded.old_generation, decision.old_generation());
        assert_eq!(recorded.new_generation, decision.new_generation());
        assert_eq!(&recorded.old_epoch, decision.old_epoch());
        assert_eq!(&recorded.new_epoch, decision.new_epoch());

        // T9/T11: the live router publishes the committed tuple and the
        // pre-cutover pair is no longer current for the switched scope.
        assert_eq!(generations.epoch(), &applied_epoch);
        assert_eq!(
            generations
                .route(&work)
                .expect("work route")
                .active_generation(),
            second_generation
        );
        assert!(
            generations
                .route_for_supervised_generation(&work, first_generation, &staged_epoch)
                .is_err(),
            "the pre-cutover generation and epoch are still current"
        );
        assert!(
            generations
                .route_for_supervised_generation(&work, second_generation, &applied_epoch)
                .is_ok(),
            "the committed cutover tuple was never published"
        );

        // T11: the authority epoch is global, so every still-active scope is
        // re-fenced to the new tuple and the handshake fence adopts it whole.
        // Its GENERATION half is compared against the sibling field the same
        // projection writes (`update_handshake_policy_without_observation`
        // assigns `module_generation.generation` and `state_fence` from the live
        // daemon route), never against a copy of the fence read before that run.
        assert_eq!(
            generations
                .route(&daemon)
                .expect("daemon route")
                .authority_epoch(),
            &applied_epoch
        );
        assert_eq!(
            policy.module_generation.state_fence.authority_epoch,
            applied_epoch
        );
        assert_eq!(
            policy.module_generation.state_fence.resource_generation,
            policy.module_generation.generation
        );
        assert_ne!(
            pre_fence_epoch, applied_epoch,
            "the handshake fence epoch never advanced"
        );
        assert_eq!(policy.module_generation.generation, first_generation);

        // ---- negative leg: the candidate is never current before commit ----
        // A decision for a scope the router does not carry fails closed in
        // `GenerationRouter::cutover`, before any ORS write. Nothing about that
        // refusal may be presented as a staged, committed or applied cutover.
        let refused = CutoverDecision::new(
            "cutover-903-refused",
            refused_scope.clone(),
            Some(second_generation),
            eliot_contracts::ResourceGeneration::new(3).expect("generation"),
            applied_epoch.clone(),
            direct_child_epoch(&applied_epoch),
            GenerationCutoverState::Committed,
        )
        .expect("refused cutover decision");
        let rows_before_refusal = rows.len();
        let mut rejection = None;
        let refused_text = capture(|| {
            let outcome = coordinator.persist_and_publish(
                &refused,
                &mut generations,
                &mut service,
                &mut policy,
            );
            outcome
                .observations
                .emit(outcome.result.is_ok(), refused.cutover_id());
            rejection = Some(outcome);
        });
        let rejection = rejection.expect("refused publish outcome");
        assert!(
            rejection.result.is_err(),
            "a cutover for an unowned route scope was published"
        );
        assert_no_persist_phase_reported(&rejection, &refused_text);

        let rows_after_refusal = store
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed cutovers");
        assert_eq!(
            rows_after_refusal.len(),
            rows_before_refusal,
            "a refused cutover wrote a durable row"
        );
        assert!(
            rows_after_refusal
                .iter()
                .all(|snapshot| snapshot.record().cutover_id != refused.cutover_id()),
            "a refused cutover left durable evidence behind"
        );
        assert!(generations.route(&refused_scope).is_err());
        assert_eq!(generations.epoch(), &applied_epoch);
        assert_eq!(
            policy.module_generation.state_fence.authority_epoch,
            applied_epoch
        );

        // Absence claims over the WHOLE captured surface of both cuts, not a
        // hand-listed pair of markers. Each names the production line whose
        // mutation would break it: a route scope or an owner error reaching the
        // sink would have to be emitted by `observe_recovery`/
        // `observe_recovery_cutover` (which format only `event`, `outcome` and
        // the bounded `cutover_id`), or by the `format!` refusal text
        // `recover_inner` builds and `persist_and_publish` propagates.
        for surface in [&text, &refused_text] {
            assert!(
                !surface.contains("work-903"),
                "route scope leaked into the recovery diagnostics surface"
            );
            assert!(
                !surface.contains("work-refused-903"),
                "refused route scope leaked into the recovery diagnostics surface"
            );
            assert!(
                !surface.contains("lineage_id"),
                "an authority epoch lineage leaked into the recovery diagnostics surface"
            );
            assert!(
                !surface.contains("authority_epoch"),
                "an authority epoch leaked into the recovery diagnostics surface"
            );
            assert!(
                !surface.contains("resource_generation"),
                "a resource generation leaked into the recovery diagnostics surface"
            );
            assert!(
                !surface.contains("route_scope"),
                "a route scope label leaked into the recovery diagnostics surface"
            );
        }

        drop(policy);
        drop(service);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    /// F-LOG-KERNEL-4 (#903 slice B): the phase record is production-set, and
    /// the durable stage write is the FIRST thing the owner does.
    ///
    /// The persist test above compares byte offsets in a surface whose order is
    /// fixed by `PersistAndPublishObservations::emit` itself, so it cannot
    /// observe the order of the real work. This leg can: it makes the durable
    /// stage write fail and then reads the consequences.
    ///
    /// The failure is genuine and reached through the owner's own public seam.
    /// `RedbRecoveryStore::stage_generation_cutover` keys its `Applying`
    /// transition on the record's route scope alone
    /// (`eliot-ors/src/store.rs:32767`), so a DIFFERENT transition already
    /// staged for the same scope makes the owner's own stage write collide with
    /// `OrsError::DuplicateConflict` (`store.rs:32965`) instead of landing.
    ///
    /// Two claims are proven here and neither is a tautology:
    ///
    /// 1. The phase flags are production-driven. `PersistAndPublishObservations`
    ///    has no setter and its `Default` is all-false, so a failed stage write
    ///    leaving every flag false can only come from
    ///    `persist_and_publish_inner`, and the ladder then emits no staged,
    ///    committed, applied or completed observation at all.
    /// 2. Nothing after the stage write ran. Moving
    ///    `service.synchronize_authority_epoch` and the handshake-policy
    ///    projection ahead of the stage write is a real reordering of real work
    ///    that would leave the service advanced past an unrecorded cutover; the
    ///    live epoch, policy fence and router assertions below all redden on it.
    #[test]
    fn stage_failure_never_reports_a_staged_phase_or_moves_the_live_fence() {
        let path = recovery_store_path("stage-failure");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));

        let root = recovery_root("stage-failure");
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let mut service = kernel.service.lock().expect("service lock");
        let mut policy = kernel.front_door_policy.lock().expect("policy lock");

        let base = service.authority_epoch();
        let from_epoch = direct_child_epoch(&base);
        let to_epoch = direct_child_epoch(&from_epoch);
        let daemon = RouteScope::new("daemon").expect("daemon scope");
        let incumbent = eliot_contracts::ResourceGeneration::new(1).expect("generation");
        let candidate = eliot_contracts::ResourceGeneration::new(2).expect("generation");
        stage_conflicting_transition(&store, &daemon, incumbent, &base, &from_epoch);

        let mut generations = GenerationRouter::at_epoch(from_epoch.clone());
        generations
            .register(
                GenerationRoute::new(daemon.clone(), incumbent, from_epoch.clone())
                    .expect("daemon generation route"),
            )
            .expect("register daemon route");
        let fence_epoch_before = policy.module_generation.state_fence.authority_epoch.clone();
        let policy_generation_before = policy.module_generation.generation;
        let decision = CutoverDecision::new(
            "cutover-903-stage-failure",
            daemon.clone(),
            Some(incumbent),
            candidate,
            from_epoch.clone(),
            to_epoch.clone(),
            GenerationCutoverState::Committed,
        )
        .expect("cutover decision");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        let mut published = None;
        let text = capture(|| {
            let outcome = coordinator.persist_and_publish(
                &decision,
                &mut generations,
                &mut service,
                &mut policy,
            );
            outcome
                .observations
                .emit(outcome.result.is_ok(), decision.cutover_id());
            published = Some(outcome);
        });
        let published = published.expect("persist_and_publish outcome");

        assert!(
            published.result.is_err(),
            "a colliding durable stage write was accepted"
        );
        assert_no_persist_phase_reported(&published, &text);

        // The refused stage write left no COMMITTED evidence under its own
        // identity.
        //
        // NON-VACUITY DISCLOSURE, and it is the store's own contract rather than a
        // guess: `latest_generation_cutovers` is documented as returning "the
        // bounded latest committed route set from canonical current operational
        // records" and skips every row whose phase is not `Active`
        // (crates/kernel/eliot-ors/src/store.rs:33154-33156 and :33170-33172). The
        // only row this test stages is `Armed` (:1397) and the refused write never
        // commits, so this read CANNOT carry the refused id whether or not the
        // stage write succeeded. It is therefore NOT the evidence that the refusal
        // happened, and it is asserted as an explicit id-set membership rather
        // than as a scan, so that it cannot be read as one. The refusal itself is
        // proved by the typed error above, by `assert_no_persist_phase_reported`,
        // and by the untouched live fence asserted below.
        let committed_rows = store
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed cutovers");
        let committed_ids: Vec<&str> = committed_rows
            .iter()
            .map(|snapshot| snapshot.record().cutover_id.as_str())
            .collect();
        assert!(
            !committed_ids.contains(&decision.cutover_id()),
            "a refused stage write left a COMMITTED row behind: {committed_ids:?}"
        );

        // Order-sensitive: every live value compared here is written AFTER the
        // durable stage write in `persist_and_publish_inner`.
        assert_live_fence_untouched(
            &service,
            &policy,
            &fence_epoch_before,
            policy_generation_before,
        );
        assert_router_untouched(&generations, &daemon, incumbent, &from_epoch);

        drop(policy);
        drop(service);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    /// CHECKLIST T9 ("old generation cannot appear current after cutover") and
    /// the staged-versus-committed half of T5.
    ///
    /// Doc anchor — I14.20, Generation cutover: "Rollback is never a backward
    /// state transition. It is a new cutover with a newer Authority Epoch."
    /// `CutoverRouteSnapshot::rebuild` states the same rule for the ownership
    /// contour: "When several committed records share one scope hash, the
    /// strictly newest epoch wins: rollback is another cutover with a newer
    /// epoch, and an old epoch is never reactivated."
    ///
    /// The premise is the ORS committed-row set re-read through
    /// `latest_committed_cutover_ownership` and `load_cutover_ownership`, and
    /// the verdict is read from the production `CutoverRouteTable` that
    /// `recover_cutover_ownership` fills through `swap_committed`.
    ///
    /// Disclosure — the coordinator under test is a FRESH owner of the shared
    /// store, not the `KernelComposition`'s own coordinator; see the shared
    /// fixture header in this module. What is covered is the recovery owner's
    /// rebuild of a snapshot from shared DURABLE rows; the composition's
    /// coordinator wiring is not.
    ///
    /// Disclosure — this test previously carried a second probe that asked for
    /// the staged candidate's own coordinates under `ownership_row`'s
    /// `mod-903-staged` scope hash. That hash was never a committed scope, so
    /// the probe hit the same `entries.get` miss as the `unrecorded-route-scope`
    /// leg and proved nothing about staged-ness; it has been REPLACED, not
    /// quietly dropped, by the in-scope fenced-candidate leg below, which
    /// probes a scope that IS in the snapshot.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "two committed cutovers plus one fenced candidate are asserted against one restored route table"
    )]
    fn committed_cutover_restore_never_reactivates_an_old_generation() {
        let path = recovery_store_path("ownership");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));

        let (first, route_scope_hash) = ownership_row(
            "mod-903-owner",
            "cutover-903-owner-a",
            None,
            1,
            1,
            2,
            Vec::new(),
        );
        store
            .stage_cutover_ownership(first)
            .expect("stage first ownership");
        store
            .commit_cutover_ownership("cutover-903-owner-a")
            .expect("commit first ownership");

        let (second, second_hash) = ownership_row(
            "mod-903-owner",
            "cutover-903-owner-b",
            Some(1),
            2,
            2,
            3,
            Vec::new(),
        );
        assert_eq!(
            second_hash, route_scope_hash,
            "both committed cutovers must name the same route scope"
        );
        store
            .stage_cutover_ownership(second)
            .expect("stage second ownership");
        store
            .commit_cutover_ownership("cutover-903-owner-b")
            .expect("commit second ownership");

        // A third candidate is staged and never committed: the durable process
        // died before the linearization point answered.
        let (staged, staged_hash) = ownership_row(
            "mod-903-staged",
            "cutover-903-owner-staged",
            None,
            1,
            1,
            2,
            Vec::new(),
        );
        store
            .stage_cutover_ownership(staged)
            .expect("stage uncommitted candidate");

        // A second candidate is fenced INSIDE the live committed scope, on
        // coordinates strictly newer than the committed entry (generation 3 at
        // epoch 4). Publishing it would supersede the committed route, so its
        // refusal is read against the very scope that IS admitted below and not
        // against a scope hash nothing was ever declared under.
        let (fenced, fenced_hash) = ownership_row(
            "mod-903-owner",
            "cutover-903-owner-fenced",
            Some(2),
            3,
            3,
            4,
            Vec::new(),
        );
        assert_eq!(
            fenced_hash, route_scope_hash,
            "the fenced candidate must be declared in the committed scope"
        );
        store
            .stage_cutover_ownership(fenced)
            .expect("stage the fenced in-scope candidate");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        let text = capture(|| {
            coordinator
                .recover_cutover_ownership()
                .expect("restore committed cutover ownership");
        });
        assert!(
            observed_at(&text, "kernel.recovery.cutover_ownership_requested")
                < observed_at(&text, "kernel.recovery.cutover_ownership_reconciled")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutover_ownership_reconciled")
                < observed_at(&text, "kernel.recovery.cutover_ownership_restored")
        );
        assert!(!text.contains("kernel.recovery.cutover_ownership_absent"));
        assert!(!text.contains("kernel.recovery.cutover_ownership_failed"));

        // Durable readback through the same store handle, before any verdict.
        let committed = store
            .latest_committed_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed ownership");
        assert_eq!(
            committed.len(),
            2,
            "recovery admitted a non-committed ownership row"
        );
        let durable = store
            .load_cutover_ownership("cutover-903-owner-b")
            .expect("load ownership by cutover identity")
            .expect("committed ownership row");
        assert_eq!(durable.state, GenerationCutoverState::Committed);
        assert_eq!(
            durable.old_generation,
            Some(eliot_contracts::ResourceGeneration::new(1).expect("generation"))
        );
        assert_eq!(
            durable.new_generation,
            eliot_contracts::ResourceGeneration::new(2).expect("generation")
        );
        assert_eq!(
            durable.old_epoch,
            AuthorityEpoch::new(2).expect("old epoch")
        );
        assert_eq!(
            durable.new_epoch,
            AuthorityEpoch::new(3).expect("new epoch")
        );
        assert!(
            durable.linearization_record_id.is_some(),
            "a committed ownership row carries no linearization identity"
        );

        // The staged candidate survives as fenced evidence and never gains a
        // linearization identity.
        let staged_durable = store
            .load_cutover_ownership("cutover-903-owner-staged")
            .expect("load staged ownership")
            .expect("staged ownership row does not survive recovery");
        assert_eq!(
            staged_durable.state,
            GenerationCutoverState::FailedRequiresForwardCutover
        );
        assert!(
            staged_durable.linearization_record_id.is_none(),
            "a never-committed candidate was linearized"
        );

        // The in-scope fenced candidate survives as fenced evidence too, on its
        // own identity.
        let fenced_durable = store
            .load_cutover_ownership("cutover-903-owner-fenced")
            .expect("load fenced ownership")
            .expect("fenced in-scope ownership row does not survive recovery");
        assert_eq!(
            fenced_durable.state,
            GenerationCutoverState::FailedRequiresForwardCutover
        );
        assert!(
            fenced_durable.linearization_record_id.is_none(),
            "a fenced in-scope candidate was linearized"
        );

        let first_generation = eliot_contracts::ResourceGeneration::new(1).expect("generation");
        let second_generation = eliot_contracts::ResourceGeneration::new(2).expect("generation");
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                second_generation,
                AuthorityEpoch::new(3).expect("new epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::AdmitCandidate,
            "the newest committed cutover is not current for its own scope"
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                first_generation,
                AuthorityEpoch::new(2).expect("old epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale,
            "the superseded generation and epoch pair is still admitted"
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                first_generation,
                AuthorityEpoch::new(3).expect("new epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale,
            "the superseded generation is admitted under the new epoch"
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                second_generation,
                AuthorityEpoch::new(2).expect("old epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale,
            "the current generation is admitted under the superseded epoch"
        );
        // Staged-versus-committed discrimination, read INSIDE the live
        // committed scope. The fenced candidate's OWN coordinates
        // (`ownership_row`'s generation 3 at epoch 4, asserted equal to the
        // committed scope hash above) are refused while the committed
        // coordinates are admitted in the first assertion. That is the
        // entry-PRESENT path of `CutoverRouteSnapshot::admit`: an entry is
        // found, generation and epoch both disagree with it, and no
        // pre-cutover operation is allowlisted — the final fallthrough at
        // `crates/kernel/eliot-ors/src/cutover_ownership.rs:850`.
        //
        // It is deliberately NOT a re-run of the unknown-scope leg: that leg
        // answers at the `entries.get` miss on
        // `cutover_ownership.rs:835-837` before any coordinate is read, so it
        // cannot tell a fenced candidate from a scope that was never declared.
        // This leg can, because the entry it probes is the committed row's.
        // Under a mutation that let a fenced candidate reach the snapshot
        // (`latest_committed_cutover_ownership` dropping its committed-state
        // filter, or `recover_cutover_ownership` handing every row to
        // `CutoverRouteSnapshot::rebuild`) this scope's entry would become
        // generation 3 at epoch 4 and the verdict would flip to
        // `AdmitCandidate`.
        let fenced_generation = eliot_contracts::ResourceGeneration::new(3).expect("generation");
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                fenced_generation,
                AuthorityEpoch::new(4).expect("fenced candidate epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale,
            "a fenced candidate superseded a committed route scope"
        );
        // The other branch, for contrast: this hash was never declared at all,
        // so the snapshot holds no entry for it.
        assert_eq!(
            coordinator.cutover_routes.admit(
                "unrecorded-route-scope",
                second_generation,
                AuthorityEpoch::new(3).expect("new epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale
        );

        // Replay is a readback: re-offering the same commit returns the
        // ALREADY-recorded outcome the owner stored, at the same linearization
        // identity, and writes no second row. The premise is the durable row
        // read back above, not a second application agreeing with the first.
        let (replayed, replayed_receipt) = store
            .commit_cutover_ownership("cutover-903-owner-b")
            .expect("replay the committed ownership");
        assert_eq!(replayed.cutover_id, durable.cutover_id);
        assert_eq!(replayed.state, GenerationCutoverState::Committed);
        assert_eq!(replayed.new_generation, durable.new_generation);
        assert_eq!(replayed.new_epoch, durable.new_epoch);
        // The two fields are different types, so they are reconciled as types,
        // not by casting: the receipt's `linearization_record_id` is a `String`
        // (eliot-ors/src/cutover_ownership.rs:559) because `from_committed` only
        // derives it from a committed record (cutover_ownership.rs:573), while
        // the durable row's is `Option<String>` (cutover_ownership.rs:435)
        // because `None` is its staged value (store.rs:33294). Only the commit
        // path assigns one (store.rs:33411), and the replay early return at
        // store.rs:33357 hands that same stored record back, so a committed row
        // always has one. Wrapping the receipt side in `Some` therefore keeps
        // the comparison `Option<&str> == Option<&str>` while refusing to pass
        // on an absent durable identity.
        assert_eq!(
            Some(replayed_receipt.linearization_record_id.as_str()),
            durable.linearization_record_id.as_deref(),
            "a replayed commit was linearized a second time"
        );
        let durable_after_replay = store
            .latest_committed_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed ownership after replay");
        assert_eq!(
            durable_after_replay.len(),
            committed.len(),
            "a replayed commit applied a second time"
        );

        // Absence over the WHOLE captured surface. A mutation that emitted the
        // record identity, the module identity, the scope hash or the retained
        // unresolved set from `observe_recovery` (which formats only `event` and
        // `outcome`) would break one of these.
        assert!(
            !text.contains("mod-903-owner"),
            "module identity leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("mod-903-staged"),
            "module identity leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains(&route_scope_hash),
            "route scope hash leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains(&staged_hash),
            "route scope hash leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("FailedRequiresForwardCutover"),
            "the fenced candidate state leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("lineage_id"),
            "an authority epoch lineage leaked into the recovery diagnostics surface"
        );

        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    /// CHECKLIST T20 ("recovery requested/load/validated/reconciled/applied
    /// distinct") and the staged-candidate half of T5.
    ///
    /// Doc anchor — I14.21 unknown commit recovery: "if unknown → pause
    /// Ordering Scope, preserve operation and open Problem State; Human/Doctor
    /// chooses evidence-backed reconciliation; no blind duplicate effect."
    /// I14.20 ORS Operation: "APPLYING → `UNKNOWN_OUTCOME` → RECONCILING", and
    /// "`DEAD_LETTER` requires proven no-effect; ambiguous effect remains
    /// `UNKNOWN_OUTCOME` until reconciliation produces a final
    /// receipt/disposition."
    ///
    /// The five phases are read from the whole captured sink surface in
    /// emission order; the candidate-versus-committed premise is the durable
    /// ORS row re-read through `latest_generation_cutovers` and
    /// `reconcile_staged_generation_cutovers` on the same store handle.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "four recovery legs assert one ordered phase contour each"
    )]
    fn recovery_phases_stay_distinct_and_never_resolve_a_staged_cutover() {
        let path = recovery_store_path("phases");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));

        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-903-phases-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let mut service = kernel.service.lock().expect("service lock");
        let mut policy = kernel.front_door_policy.lock().expect("policy lock");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        let base = service.authority_epoch();
        let advanced = direct_child_epoch(&base);
        let first_generation = eliot_contracts::ResourceGeneration::new(1).expect("generation");
        let daemon = RouteScope::new("daemon").expect("daemon scope");
        let staged_scope_name = "mod-903-staged";
        let committed_scope_name = "mod-903-committed";
        let staged_scope = RouteScope::new(staged_scope_name).expect("staged scope");
        let committed_scope = RouteScope::new(committed_scope_name).expect("committed scope");

        let mut generations = GenerationRouter::at_epoch(base.clone());
        generations
            .register(
                GenerationRoute::new(daemon, first_generation, base.clone())
                    .expect("daemon generation route"),
            )
            .expect("register daemon route");

        // Leg 1 — REQUESTED, RECONCILED and LOADED are reached and reported
        // separately on an empty durable store; nothing was validated or
        // applied because there was nothing to validate.
        let text = capture(|| {
            coordinator
                .recover(&mut generations, &mut service, &mut policy)
                .expect("empty recovery");
        });
        assert!(
            observed_at(&text, "kernel.recovery.recover_requested")
                < observed_at(&text, "kernel.recovery.cutovers_reconciled")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_reconciled")
                < observed_at(&text, "kernel.recovery.cutovers_loaded")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_loaded")
                < observed_at(&text, "kernel.recovery.load_empty")
        );
        assert!(
            observed_at(&text, "kernel.recovery.load_empty")
                < observed_at(&text, "kernel.recovery.recover_completed")
        );
        assert!(
            !text.contains("kernel.recovery.cutovers_validated"),
            "an empty projection reported a validated phase"
        );
        assert!(
            !text.contains("kernel.recovery.routes_applied"),
            "an empty projection reported an applied phase"
        );
        assert!(!text.contains("kernel.recovery.recover_failed"));
        assert_eq!(generations.epoch(), &base);
        assert_eq!(service.authority_epoch(), base);

        // Leg 2 — a candidate staged before the commit response is reconciled
        // first and stays unresolved: never committed, never an active route.
        store
            .stage_generation_cutover(RuntimeGenerationCutoverRecord {
                cutover_id: "cutover-903-phases-staged".to_owned(),
                route_scope: staged_scope_name.to_owned(),
                old_generation: None,
                new_generation: first_generation,
                old_epoch: base.clone(),
                new_epoch: advanced.clone(),
                state: GenerationCutoverState::Armed,
            })
            .expect("stage cutover before commit");
        let text = capture(|| {
            coordinator
                .recover(&mut generations, &mut service, &mut policy)
                .expect("staged-only recovery");
        });
        assert!(
            observed_at(&text, "kernel.recovery.recover_requested")
                < observed_at(&text, "kernel.recovery.cutovers_reconciled")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_reconciled")
                < observed_at(&text, "kernel.recovery.cutovers_loaded")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_loaded")
                < observed_at(&text, "kernel.recovery.load_empty")
        );
        assert!(
            !text.contains("kernel.recovery.cutovers_validated"),
            "a staged candidate was validated"
        );
        assert!(
            !text.contains("kernel.recovery.routes_applied"),
            "a staged candidate was applied"
        );
        assert!(!text.contains("kernel.recovery.recover_failed"));

        let fenced = store
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back the reconciled staged candidate");
        assert_eq!(fenced.len(), 1, "the staged candidate is no longer durable");
        assert_eq!(
            fenced[0].record().state,
            GenerationCutoverState::FailedRequiresForwardCutover
        );
        assert!(
            store
                .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
                .expect("read back committed cutovers")
                .is_empty(),
            "a staged candidate became an active route"
        );
        assert_eq!(
            service.authority_epoch(),
            base,
            "a staged candidate moved the authority epoch"
        );
        assert_eq!(generations.epoch(), &base);
        assert!(generations.route(&staged_scope).is_err());

        // Leg 3 — a committed cutover whose recorded I1.12 verdict does not
        // still validate is VALIDATED and then refused. A validated phase is
        // never reported as an applied one, and the refusal is never dressed as
        // a success.
        let committed_record = RuntimeGenerationCutoverRecord {
            cutover_id: "cutover-903-phases-committed".to_owned(),
            route_scope: committed_scope_name.to_owned(),
            old_generation: None,
            new_generation: first_generation,
            old_epoch: base.clone(),
            new_epoch: advanced.clone(),
            state: GenerationCutoverState::Armed,
        };
        store
            .stage_generation_cutover(committed_record.clone())
            .expect("stage committed cutover");
        store
            .commit_generation_cutover_state(committed_record.clone())
            .expect("commit cutover");
        let text = capture(|| {
            let outcome = coordinator.recover(&mut generations, &mut service, &mut policy);
            assert!(
                outcome.is_err(),
                "a route with no recorded rollback verdict was restored"
            );
        });
        assert!(
            observed_at(&text, "kernel.recovery.recover_requested")
                < observed_at(&text, "kernel.recovery.cutovers_reconciled")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_reconciled")
                < observed_at(&text, "kernel.recovery.cutovers_loaded")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_loaded")
                < observed_at(&text, "kernel.recovery.cutovers_validated")
        );
        assert!(
            observed_at(&text, "kernel.recovery.cutovers_validated")
                < observed_at(&text, "kernel.recovery.recover_failed")
        );
        assert!(
            !text.contains("kernel.recovery.routes_applied"),
            "a refused restore reported an applied phase"
        );
        assert!(!text.contains("kernel.recovery.recover_completed"));
        assert!(generations.route(&committed_scope).is_err());
        assert_eq!(generations.epoch(), &base);

        let rows = store
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed cutovers");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record().cutover_id, "cutover-903-phases-committed");
        assert_eq!(rows[0].record().state, GenerationCutoverState::Committed);

        // Leg 4 — replay is a readback. A second recovery pass and a second
        // commit offer both return the ALREADY-recorded durable outcome; the
        // owner neither re-applies nor advances its operation order.
        let durable_before_replay: Vec<(String, u64)> = rows
            .iter()
            .map(|snapshot| {
                (
                    snapshot.record().cutover_id.clone(),
                    snapshot.operation_order(),
                )
            })
            .collect();
        let _ = capture(|| {
            let outcome = coordinator.recover(&mut generations, &mut service, &mut policy);
            assert!(outcome.is_err(), "a replayed recovery changed the verdict");
        });
        let replayed_commit = store
            .commit_generation_cutover_state(committed_record)
            .expect("replay the committed cutover");
        assert_eq!(
            replayed_commit.record().cutover_id,
            "cutover-903-phases-committed"
        );
        assert_eq!(
            replayed_commit.record().state,
            GenerationCutoverState::Committed
        );
        assert_eq!(
            replayed_commit.operation_order(),
            durable_before_replay[0].1,
            "a replayed commit advanced the durable operation order"
        );
        let durable_after_replay = store
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("read back committed cutovers after replay");
        assert_eq!(
            durable_after_replay.len(),
            durable_before_replay.len(),
            "a replayed recovery applied durable state a second time"
        );
        let durable_durable_after_replay_keys: Vec<(String, u64)> = durable_after_replay
            .iter()
            .map(|snapshot| {
                (
                    snapshot.record().cutover_id.clone(),
                    snapshot.operation_order(),
                )
            })
            .collect();
        assert_eq!(durable_durable_after_replay_keys, durable_before_replay);

        // Absence over the WHOLE captured surface of the refused leg. The owner
        // refusal text is built by `recover_inner`'s `format!` and returned as a
        // `String`; the only way any of it reaches the sink is if
        // `observe_recovery` grew a detail field, so these break on that
        // mutation alone. `observe_recovery` formats exactly `event` and
        // `outcome`, so no authority-epoch spelling can appear either.
        assert!(
            !text.contains(committed_scope_name),
            "route scope leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("is not a valid rollback target"),
            "owner refusal text leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("no recorded compatibility verdict"),
            "owner refusal reason leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("lineage_id"),
            "an authority epoch lineage leaked into the recovery diagnostics surface"
        );
        assert!(
            !text.contains("authority_epoch"),
            "an authority epoch leaked into the recovery diagnostics surface"
        );

        drop(policy);
        drop(service);
        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    /// A committed cutover whose exact route scope still carries an unresolved
    /// external-effect outcome blocks candidate admission with the typed
    /// unknown verdict — neither `AdmitCandidate` (a synthesised success) nor
    /// `RejectStale` (a synthesised failure) — and the unresolved set survives
    /// durably for reconciliation.
    ///
    /// Doc anchor — I14.20: "`UNKNOWN_OUTCOME` ... remains `UNKNOWN_OUTCOME`
    /// until reconciliation produces a final receipt/disposition." I14.21:
    /// "if unknown → pause Ordering Scope, preserve operation and open Problem
    /// State; Human/Doctor chooses evidence-backed reconciliation; no blind
    /// duplicate effect." I14.24 local failure containment matrix, ORS row:
    /// "close durable mutation and effect admission; never return
    /// `ACCEPTED_PENDING`" and "unresolved state becomes Problem/Incident".
    ///
    /// The premise is the committed ORS ownership row re-read through
    /// `load_cutover_ownership`; the verdict is read from the production
    /// `CutoverRouteTable` filled by `recover_cutover_ownership`.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one unresolved scope and one resolved sibling are asserted against one restored route table"
    )]
    fn unresolved_route_scope_stays_unknown_instead_of_being_resolved() {
        let path = recovery_store_path("unknown");
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));

        let declared =
            eliot_ors::CapabilityRouteScope::declare("mod-903-unknown", "serve", "work", "effects")
                .expect("declare route scope");
        let unknown_hash = declared.route_scope_hash.clone();
        let (unknown_row, row_hash) = ownership_row(
            "mod-903-unknown",
            "cutover-903-unknown",
            None,
            1,
            1,
            2,
            vec![unknown_hash.clone()],
        );
        assert_eq!(
            row_hash, unknown_hash,
            "the unresolved scope must be the record's own route scope hash"
        );
        store
            .stage_cutover_ownership(unknown_row)
            .expect("stage ownership with an unresolved scope");
        store
            .commit_cutover_ownership("cutover-903-unknown")
            .expect("commit ownership with an unresolved scope");

        // A sibling scope with no unresolved outcome on the same store, so the
        // unknown verdict is provably scoped and not a blanket refusal.
        let (clean_row, clean_hash) = ownership_row(
            "mod-903-clean",
            "cutover-903-clean",
            None,
            1,
            1,
            4,
            Vec::new(),
        );
        store
            .stage_cutover_ownership(clean_row)
            .expect("stage clean ownership");
        store
            .commit_cutover_ownership("cutover-903-clean")
            .expect("commit clean ownership");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .recover_cutover_ownership()
            .expect("restore committed cutover ownership");

        let first_generation = eliot_contracts::ResourceGeneration::new(1).expect("generation");
        assert_eq!(
            coordinator.cutover_routes.admit(
                &unknown_hash,
                first_generation,
                AuthorityEpoch::new(2).expect("new epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::BlockUnknownOutcome,
            "an unresolved route scope was resolved into candidate admission"
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                &clean_hash,
                first_generation,
                AuthorityEpoch::new(4).expect("new epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::AdmitCandidate,
            "a resolved sibling scope was refused"
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                &unknown_hash,
                first_generation,
                AuthorityEpoch::new(4).expect("foreign epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale,
            "an unresolved scope admitted a tuple it never recorded"
        );

        let durable = store
            .load_cutover_ownership("cutover-903-unknown")
            .expect("load ownership by cutover identity")
            .expect("committed ownership row");
        assert_eq!(durable.state, GenerationCutoverState::Committed);
        assert_eq!(
            durable.unresolved_scopes,
            vec![unknown_hash.clone()],
            "the unresolved scope set was resolved away in durable state"
        );
        assert!(
            durable.linearization_record_id.is_some(),
            "a committed ownership row carries no linearization identity"
        );

        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
