//! Kernel generation control gateway.
//!
//! Closed generation-route snapshot and single cutover publish path owned by
//! [`crate::KernelComposition`]. Snapshot returns a cloned router; cutover
//! fences the composition on any persist/publish failure and never retries
//! with a stale route.
//!
//! The `I5.11` `canonical_store` route cutover is the one cutover whose ORS
//! `CUTOVER_OWNERSHIP` row this file produces: `I5.11` stage 8 is "commit the
//! `canonical_store` `CapabilityRouteScope` cutover through Kernel Generation
//! Registry", and this ingress is that registry. It writes the row only for a
//! completed `I5.11` replacement the `eliot_kernel_service::StorageReplacement`
//! coordinator re-derives through its own stage machine, and it derives the
//! replacement's receipt back from the committed row rather than asserting one —
//! see [`KernelComposition::apply_authenticated_generation_cutover`].
//!
//! Architecture: A5.4 Time и State Fence; A13.2 Kernel и failure domains; A13.3 Module supervision и Doctor; ARCH-AUTH-01; ARCH-RES-03; ARCH-RES-04
//! Implementation: I4.5 Generation vector and State Fence; I5.6 Admission and staging; I14.14 Module hot replacement; I14.15 Daemon hot replacement; I14.16 Kernel and Host update; I14.21 Unknown commit recovery
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition::generation_route_snapshot` and `KernelComposition::apply_generation_cutover` plus inseparable fencing with zero external users; no new crate.
//! Forbidden authority: must not perform semantic planning, must not allow an alternate epoch owner, must not resurrect stale routes; publishes only the ORS-committed candidate via `OrsGenerationCoordinator` and fences on failure; and it commits the `canonical_store` cutover-ownership row only for a replacement the `I5.11` coordinator itself re-derives.

use super::KernelComposition;
use super::kernel_audit::AuditEventDraft;
use eliot_contracts::{
    AuthorityEpoch, EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_kernel_core::{CutoverDecision, GenerationRoute, GenerationRouter, RouteScope};
use eliot_kernel_service::{
    IrreversibleStorageEffect, KernelServiceError, StorageReplacement,
    StorageReplacementCutoverReceipt, StorageReplacementStage, StorageReplacementTransfer,
};
use eliot_ors::{
    GenerationCutoverOwnership, InFlightDisposition, ModuleArtifactIdentity, RedbRecoveryStore,
    StateMigrationDecision,
};
use eliot_runtime_contracts::GenerationCutoverState;
use serde::{Deserialize, Serialize};

/// Authenticated daemon operation used by Governor to obtain the mechanical
/// active-generation projection for one startup window.
///
/// The operation is served by the existing authenticated daemon dispatch
/// channel. This is a selector, not a second transport or an authority.
pub const ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION: &str = "daemon_generation_projection";

/// Authenticated daemon operation that drives one generation cutover through
/// the sole Kernel semantic gateway.
///
/// The operation is served by the same existing authenticated daemon dispatch
/// channel as [`ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION`]; the projection
/// read and the cutover write are the two halves of one generation control
/// plane, and neither mints a second transport or a second authority. The
/// selector only picks this entry: the durable cutover-ownership record and the
/// authenticated session fence below remain the sole evidence.
pub const GENERATION_CUTOVER_OPERATION: &str = "daemon_generation_cutover";

/// Exact request payload for [`GENERATION_CUTOVER_OPERATION`].
///
/// The caller names ONE cutover identity and presents the State Fence it is
/// operating under. It never supplies a generation, an epoch, a route scope, a
/// migration decision, or a cutover state: every one of those is read from the
/// owner's durable cutover-ownership record, so a request cannot assert an
/// authority field the ORS linearization point never recorded.
///
/// `replacement` is the one addition, and it is the `I5.11` completion this
/// ingress needs in order to *produce* that record when the cutover has never
/// been committed. The `canonical_store` route cutover is the one `I5.11` cutover
/// whose ORS row this ingress owns end to end, and it can own it only for a
/// replacement the coordinator actually completed — so the request may present
/// that completion, and every field of the row is then taken from the
/// coordinator's own reconstructed state rather than from this payload. It is
/// optional because a cutover that is already committed is reconciled against
/// that committed row and needs nothing presented; see
/// [`KernelComposition::apply_authenticated_generation_cutover`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverRequest {
    /// Version of the authenticated cutover request.
    pub version: u8,
    /// Exact cutover identity of one owner-recorded cutover-ownership row.
    pub cutover_id: String,
    /// Exact State Fence carried by the admitted daemon session.
    pub state_fence: StateFence,
    /// The completed `I5.11` replacement whose `canonical_store` route cutover
    /// this request commits, when no committed row exists for `cutover_id` yet.
    /// `None` for a cutover that is already committed.
    #[serde(default)]
    pub replacement: Option<GenerationCutoverReplacement>,
}

/// One `I5.11` stage exactly as the owner that performed it recorded it.
///
/// It is the wire form of the coordinator's own per-stage record. The stage name
/// is resolved through the coordinator's own
/// [`StorageReplacementStage::from_name`] and the transfer is required for
/// exactly the two stages that move `I5.10` data into the candidate. The Kernel
/// interprets nothing here: `evidence` is the same bounded opaque text
/// [`StorageReplacement::record_stage`] records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverReplacementStage {
    /// Exact `I5.11` stage name ([`StorageReplacementStage::name`]).
    pub stage: String,
    /// Bounded opaque evidence the performing owner recorded.
    pub evidence: String,
    /// The `I5.10` transfer, for the two transferring stages only.
    #[serde(default)]
    pub transfer: Option<StorageReplacementTransfer>,
}

/// The `I14.14` step-7 cutover-ownership content committed for this cutover.
///
/// `I14.14` step 7 is "classify every in-flight request and persist a
/// `GenerationCutoverRecord` in ORS" and step 8 is the one commit; this is that
/// step-7 content and nothing else. Every field is the module owner's own
/// `I14.14` content and is validated by `GenerationCutoverOwnership::validate`
/// on the ORIGINAL recorded values inside the existing
/// `RedbRecoveryStore::stage_cutover_ownership` — no digest, identity, epoch or
/// decision is recomputed here to stand in for an owner proof.
///
/// What this claim deliberately does NOT carry is the two store generations, the
/// route scope and the cutover state. Those are the coordinator's own, read back
/// from the replacement it reconstructed, so a claim cannot assert a generation
/// pair the coordinator never reached or a scope other than the pinned
/// `canonical_store` one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverOwnershipClaim {
    /// Immutable artifact identity of the candidate store bridge.
    pub candidate_artifact: ModuleArtifactIdentity,
    /// Immutable artifact identity of the incumbent store bridge, if any.
    pub incumbent_artifact: Option<ModuleArtifactIdentity>,
    /// Authority epoch before the switch. It must be the admitted session
    /// fence's own epoch, which this ingress checks before it writes anything.
    pub old_epoch: AuthorityEpoch,
    /// Authority epoch issued by the switch.
    pub new_epoch: AuthorityEpoch,
    /// The exact `I14.14` in-flight disposition allowlist fixed at commit.
    pub in_flight: Vec<InFlightDisposition>,
    /// The `I14.14` state-migration decision. It must name forward repair
    /// exactly when the coordinator's irreversible-effect ledger is non-empty,
    /// which the coordinator re-checks against the committed row.
    pub migration: StateMigrationDecision,
    /// Health/readiness proof reference for the candidate store bridge.
    pub health_proof_ref: String,
    /// Rollback boundary: the retained incumbent artifact or its forward-repair
    /// reference.
    pub rollback_boundary: String,
    /// Scopes left unresolved at commit.
    pub unresolved_scopes: Vec<String>,
}

/// The coordinator's own completed `I5.11` replacement, in the exact form the
/// Kernel Generation Registry receives it.
///
/// It is the two things this ingress cannot invent: the ordered stages 1-7 the
/// coordinator reached with their own evidence, and the `I14.14` step-7 claim to
/// commit. It is re-derived here through the coordinator's OWN stage machine
/// ([`StorageReplacement::replay_recorded_stages`]), not through a summary of it,
/// so a skipped, repeated or out-of-order stage, a stage that moves data without
/// its `I5.10` transfer record, a presented stage 8, or a completion that stops
/// before stage 8 is all refused by the coordinator rather than by a local rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCutoverReplacement {
    /// Exact replacement identity this completion belongs to.
    pub replacement_id: String,
    /// The store generation that owned the route before the cutover.
    pub incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    pub candidate_generation: ResourceGeneration,
    /// Irreversible migrations/effects the coordinator observed. The
    /// coordinator's ledger only grows, and the committed row's `migration`
    /// decision must agree with it exactly.
    pub irreversible_effects: Vec<IrreversibleStorageEffect>,
    /// The `I5.11` stages in the order their performing owners reached them.
    pub stages: Vec<GenerationCutoverReplacementStage>,
    /// The `I14.14` step-7 content committed at the cutover.
    pub cutover: GenerationCutoverOwnershipClaim,
    /// Bounded opaque evidence recorded for the `I5.11` stage-8 route cutover.
    pub cutover_evidence: String,
}

impl GenerationCutoverRequest {
    /// Validates the closed request shape before it reaches the ORS owner.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.version != 1 {
            return Err(KernelServiceError::InvalidField {
                field: "generation_cutover.request.version",
                reason: "unsupported cutover request version",
            });
        }
        if self.cutover_id.trim().is_empty() || self.cutover_id.chars().any(char::is_control) {
            return Err(KernelServiceError::InvalidField {
                field: "generation_cutover.request.cutover_id",
                reason: "cutover identity is invalid",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "generation_cutover.request.state_fence",
                reason: "state fence is invalid",
            })
    }
}

/// Closed outcome of one authenticated generation cutover request.
///
/// `terminal_code` is the ONE stable diagnostic code for the failed cutover,
/// read from the same mapper the cutover gateway uses. It is `None` only when
/// the owner's durable receipt actually committed the cutover, so "requested",
/// "refused", and "committed" never collapse into one answer: an unknown or
/// refused outcome is never projected as a committed cutover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GenerationCutoverOutcome {
    /// Version of the authenticated cutover outcome.
    pub version: u8,
    /// Exact cutover identity this outcome answers.
    pub cutover_id: String,
    /// Terminal diagnostic code of the refused cutover, `None` when committed.
    pub terminal_code: Option<&'static str>,
    /// State Fence the cutover was admitted and attempted under.
    pub state_fence: StateFence,
    /// The `I5.11` cutover receipt the coordinator re-derived from the committed
    /// ORS row this request committed.
    ///
    /// It is present only when this request presented the completed replacement
    /// AND the coordinator constructed the receipt from that durable row, so it
    /// can never precede the durable linearization point. A request reconciled
    /// against an already-committed cutover presents no completion and therefore
    /// carries no receipt. It rides on a refused live swap too, because it
    /// evidences the durable ORS cutover and says nothing about the in-memory
    /// route swap, which `terminal_code` alone answers. The post-cutover `I5.11`
    /// stages and the `I5.14` rollback answer are both reached by presenting this
    /// value back to the coordinator, which re-derives it from ORS rather than
    /// accepting it.
    pub cutover_receipt: Option<StorageReplacementCutoverReceipt>,
}

/// Exact request payload for [`ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION`].
///
/// Governor must present the fence it is using for the startup evidence
/// observation. The authenticated session boundary supplies the peer and
/// process binding; this payload only narrows the requested route and fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActiveGenerationRegistryQuery {
    /// Version of the authenticated projection request.
    pub version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    pub state_fence: StateFence,
}

impl ActiveGenerationRegistryQuery {
    /// Validates the closed query shape before it reaches the route table.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.version != 1 {
            return Err(KernelServiceError::InvalidField {
                field: "generation_registry.query.version",
                reason: "unsupported projection request version",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "generation_registry.query.state_fence",
                reason: "state fence is invalid",
            })?;
        Ok(())
    }
}

/// Kernel-owned read projection of one active generation route.
///
/// This is a mechanical query result, not a new authority. The route comes
/// from the canonical [`GenerationRouter`], while the fence comes from the
/// live Kernel service epoch. The fingerprint therefore changes whenever the
/// route, lineage-aware epoch, or exact fence changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveGenerationRegistryProjection {
    route_scope: String,
    active_generation: ResourceGeneration,
    authority_epoch: EpochId,
    state_fence: StateFence,
    generation_fingerprint: String,
}

/// Closed response value returned by the authenticated Governor projection
/// query. Generation and epoch remain inside the exact `StateFence`; the
/// fingerprint is the only derived scalar crossing this wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveGenerationRegistryResponse {
    /// Version of the authenticated projection response.
    pub version: u8,
    /// Kernel-owned canonical projection fingerprint.
    pub fingerprint: String,
    /// Exact `StateFence` used to compute the fingerprint.
    pub state_fence: StateFence,
}

#[derive(Serialize)]
struct ActiveGenerationFingerprintPreimage<'a> {
    route_scope: &'a str,
    active_generation: ResourceGeneration,
    authority_epoch: &'a EpochId,
    state_fence: &'a StateFence,
}

impl ActiveGenerationRegistryProjection {
    fn from_route(
        route: &GenerationRoute,
        state_fence: StateFence,
    ) -> Result<Self, KernelServiceError> {
        // Exact tuple equality is the authorization rule (Implements #64):
        // the route carries the canonical `EpochId`, so a restore that minted
        // a different lineage at the same sequence is unrelated and is refused
        // here instead of matching on the number.
        if state_fence.resource_generation != route.active_generation()
            || !state_fence
                .authority_epoch
                .is_same_authority(route.authority_epoch())
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.state_fence",
            });
        }

        let route_scope = route.route_scope().as_str().to_owned();
        let preimage = ActiveGenerationFingerprintPreimage {
            route_scope: &route_scope,
            active_generation: route.active_generation(),
            authority_epoch: &state_fence.authority_epoch,
            state_fence: &state_fence,
        };
        let bytes = canonical_json_bytes(&preimage).map_err(|_| {
            KernelServiceError::Platform(
                "generation registry fingerprint encoding failed".to_owned(),
            )
        })?;
        let generation_fingerprint = sha256_hex(&bytes);

        Ok(Self {
            route_scope,
            active_generation: route.active_generation(),
            authority_epoch: state_fence.authority_epoch.clone(),
            state_fence,
            generation_fingerprint,
        })
    }

    /// Returns the canonical route scope represented by this projection.
    #[must_use]
    pub fn route_scope(&self) -> &str {
        &self.route_scope
    }

    /// Returns the active resource generation from the Kernel route table.
    #[must_use]
    pub const fn active_generation(&self) -> ResourceGeneration {
        self.active_generation
    }

    /// Returns the lineage-aware epoch bound to the projection.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the exact fence that was used to build the projection.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the lowercase SHA-256 fingerprint for the exact projection.
    #[must_use]
    pub fn generation_fingerprint(&self) -> &str {
        &self.generation_fingerprint
    }

    /// Projects the internal route calculation onto the closed Governor wire.
    #[must_use]
    pub fn response(&self) -> ActiveGenerationRegistryResponse {
        ActiveGenerationRegistryResponse {
            version: 1,
            fingerprint: self.generation_fingerprint.clone(),
            state_fence: self.state_fence.clone(),
        }
    }
}

fn validate_active_generation_query(
    query: &ActiveGenerationRegistryQuery,
    authenticated_session_fence: &StateFence,
) -> Result<(), KernelServiceError> {
    query.validate()?;
    if &query.state_fence != authenticated_session_fence {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "generation_registry.query.session_fence",
        });
    }
    Ok(())
}

/// F-LOG-KERNEL-4 (#903): generation-gateway boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.generation.*` event
/// names plus a bounded stable outcome. Never carries route contents,
/// generation values, epoch/fence material, digests, or owner error strings
/// (I15.4, I07.20). Candidate, staged, active, and current stay distinct:
/// a snapshot read is never logged as a cutover, and a cutover request is
/// never logged as observed activation.
fn observe_generation(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "generation gateway observation"
    );
}

/// F-LOG-KERNEL-4 (#903 W7): cutover-scoped gateway observations.
///
/// Same #895-only shape as [`observe_generation`] plus the cutover call's own
/// validated operation identity (`CutoverDecision::cutover_id`, already echoed
/// on the authenticated `GenerationCutoverOutcome` reply; I15.4, I07.20, W6),
/// policy-screened and bounded by `bound_field` before formatting. Concurrent
/// cutovers correlate by identity with no dedup cache, no new probe, and no
/// lock-held emission.
fn observe_generation_cutover(event: &'static str, outcome: &'static str, cutover_id: &str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    let cutover_bound = bound_field(cutover_id);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        cutover_id = cutover_bound.text(),
        "generation gateway observation"
    );
}

/// Maps one generation-route snapshot failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged.
fn generation_snapshot_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "SNAPSHOT_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "SNAPSHOT_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "SNAPSHOT_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "SNAPSHOT_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "SNAPSHOT_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "SNAPSHOT_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "SNAPSHOT_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "SNAPSHOT_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "SNAPSHOT_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "SNAPSHOT_PLATFORM",
        KernelServiceError::Core(_) => "SNAPSHOT_CORE",
    }
}

/// Maps one generation-cutover failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload (including the fence
/// reason retained by the gateway) is never logged.
fn generation_cutover_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "CUTOVER_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "CUTOVER_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "CUTOVER_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "CUTOVER_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "CUTOVER_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "CUTOVER_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "CUTOVER_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "CUTOVER_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "CUTOVER_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "CUTOVER_PLATFORM",
        KernelServiceError::Core(_) => "CUTOVER_CORE",
    }
}

#[derive(Clone, Copy)]
struct ServiceFenceObservation {
    succeeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationCutoverApplyDisposition {
    /// This invocation published the committed route transition.
    Applied,
    /// The exact committed destination is already the live route state.
    Readback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationCutoverLiveEndpoint {
    Apply,
    Readback,
    Mismatch,
}

fn classify_generation_cutover_live_endpoint(
    router: &GenerationRouter,
    service: &eliot_kernel_service::KernelService,
    decision: &CutoverDecision,
) -> GenerationCutoverLiveEndpoint {
    if decision.state() != GenerationCutoverState::Committed {
        return GenerationCutoverLiveEndpoint::Apply;
    }
    let Some(old_generation) = decision.old_generation() else {
        return GenerationCutoverLiveEndpoint::Apply;
    };

    let service_epoch = service.authority_epoch();
    let route = router.route(decision.route_scope()).ok();
    let route_matches = |generation, epoch: &EpochId| {
        route.is_some_and(|route| {
            route.active_generation() == generation
                && route.authority_epoch().is_same_authority(epoch)
        })
    };

    if router.epoch().is_same_authority(decision.new_epoch())
        && service_epoch.is_same_authority(decision.new_epoch())
        && route_matches(decision.new_generation(), decision.new_epoch())
        && decision
            .new_epoch()
            .is_direct_child_of(decision.old_epoch())
    {
        return GenerationCutoverLiveEndpoint::Readback;
    }
    if router.epoch().is_same_authority(decision.old_epoch())
        && service_epoch.is_same_authority(decision.old_epoch())
        && route_matches(old_generation, decision.old_epoch())
    {
        return GenerationCutoverLiveEndpoint::Apply;
    }
    GenerationCutoverLiveEndpoint::Mismatch
}

enum GenerationCutoverInnerFailure {
    Gateway(String),
    Refused(KernelServiceError),
}

impl ServiceFenceObservation {
    /// Cutover-scoped fence observation: the same subordinate pair, correlated
    /// to its cutover call by the validated operation identity (W7).
    fn emit_for_cutover(self, cutover_id: &str) {
        observe_generation_cutover(
            "kernel.generation.service_fence_requested",
            "attempt",
            cutover_id,
        );
        if self.succeeded {
            observe_generation_cutover("kernel.generation.service_fenced", "success", cutover_id);
        } else {
            observe_generation_cutover(
                "kernel.generation.service_fence_rejected",
                "rejected",
                cutover_id,
            );
        }
    }
}

#[cfg(test)]
fn fence_service_after_generation_failure(
    service: &std::sync::Arc<std::sync::Mutex<eliot_kernel_service::KernelService>>,
    reason: impl Into<String>,
) -> Result<(), KernelServiceError> {
    // F-LOG-KERNEL-4 (#903): subordinate fence observation; the cutover
    // gateway owns the single terminal for the failed cutover. Only the
    // fence outcome is logged, never the reason body.
    let result = fence_service_after_generation_failure_without_observation(service, reason);
    ServiceFenceObservation {
        succeeded: result.is_ok(),
    }
    .emit_for_cutover("cutover-op-903");
    result
}

fn fence_service_after_generation_failure_without_observation(
    service: &std::sync::Arc<std::sync::Mutex<eliot_kernel_service::KernelService>>,
    reason: impl Into<String>,
) -> Result<(), KernelServiceError> {
    {
        let mut service = service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        service.fence_generation(reason)
    }
}

impl KernelComposition {
    /// Executes the authenticated R4 query against the live Kernel fence and
    /// canonical `GenerationRouter`. The caller's session fence must match the
    /// query fence exactly; a compatible-but-different fence is still stale
    /// for this startup observation.
    pub fn active_generation_registry_query(
        &self,
        query: &ActiveGenerationRegistryQuery,
        authenticated_session_fence: &StateFence,
    ) -> Result<ActiveGenerationRegistryProjection, KernelServiceError> {
        validate_active_generation_query(query, authenticated_session_fence)?;
        let projection = self.active_generation_registry_projection("daemon")?;
        if projection.state_fence() != authenticated_session_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.query.live_fence",
            });
        }
        Ok(projection)
    }

    /// Reads the active generation projection from the canonical Kernel route.
    ///
    /// The route's lineage-aware epoch must be the exact same tuple as the live
    /// service epoch before a fence or fingerprint is returned. A missing
    /// route, cross-lineage epoch, poisoned boundary, or non-exact tuple fails
    /// closed.
    pub fn active_generation_registry_projection(
        &self,
        route_scope: &str,
    ) -> Result<ActiveGenerationRegistryProjection, KernelServiceError> {
        let router = self.generation_route_snapshot()?;
        let route_scope = RouteScope::new(route_scope.to_owned()).map_err(|_| {
            KernelServiceError::InvalidField {
                field: "generation_registry.route_scope",
                reason: "route scope is invalid",
            }
        })?;
        let route =
            router
                .route(&route_scope)
                .map_err(|_| KernelServiceError::HandshakeMismatch {
                    field: "generation_registry.route",
                })?;
        let live_epoch = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .authority_epoch();
        if !route.authority_epoch().is_same_authority(&live_epoch) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.authority_epoch",
            });
        }
        let state_fence = StateFence::new(live_epoch, route.active_generation());
        ActiveGenerationRegistryProjection::from_route(route, state_fence)
    }

    /// Checks one authenticated Governor fingerprint against the live Kernel
    /// generation projection and its exact admitted fence.
    ///
    /// This comparison is mechanical. It does not mark startup readiness or
    /// interpret Governor capability semantics.
    pub fn verify_active_generation_registry_fingerprint(
        &self,
        route_scope: &str,
        admitted_fence: &StateFence,
        presented_fingerprint: &str,
    ) -> Result<(), KernelServiceError> {
        let projection = self.active_generation_registry_projection(route_scope)?;
        if projection.state_fence() != admitted_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.admitted_fence",
            });
        }
        if projection.generation_fingerprint() != presented_fingerprint {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.fingerprint",
            });
        }
        Ok(())
    }

    /// Returns a cloned, read-only route projection.  Callers cannot obtain a
    /// mutable router guard or bypass the ORS transition gateway.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed read; the cloned projection versus a fenced
    /// gateway stay distinct, and no route, generation, or fence material
    /// is logged.
    pub fn generation_route_snapshot(&self) -> Result<GenerationRouter, KernelServiceError> {
        observe_generation("kernel.generation.snapshot_requested", "attempt");
        match self.generation_route_snapshot_inner() {
            Ok(router) => {
                observe_generation("kernel.generation.snapshot_committed", "success");
                Ok(router)
            }
            Err(error) => {
                observe_generation("kernel.generation.snapshot_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(
                    generation_snapshot_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Read-only clone sequence; the fence check precedes the router clone.
    /// See [`KernelComposition::generation_route_snapshot`].
    fn generation_route_snapshot_inner(&self) -> Result<GenerationRouter, KernelServiceError> {
        if let Some(reason) = self
            .generation_poison
            .lock()
            .map_err(|_| {
                KernelServiceError::Platform("generation poison lock poisoned".to_owned())
            })?
            .clone()
        {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        self.generations
            .lock()
            .map(|router| router.clone())
            .map_err(|_| KernelServiceError::Platform("generation lock poisoned".to_owned()))
    }

    /// Persists and publishes one epoch-raising generation cutover through the
    /// sole semantic gateway.  A failed publish permanently fences this
    /// composition instance until restart/recovery proves a durable route.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): exactly one terminal is
    /// emitted per failed cutover; the cutover request versus the owner's
    /// durable receipt stay distinct. Subordinate phase records of one call
    /// carry only that call's validated operation identity (already echoed on
    /// the authenticated outcome reply), so concurrent cutovers correlate
    /// without a dedup cache, a new probe, or a lock-held emission; no route,
    /// epoch, generation, or fence material is logged.
    pub fn apply_generation_cutover(
        &self,
        decision: &CutoverDecision,
    ) -> Result<(), KernelServiceError> {
        observe_generation_cutover(
            "kernel.generation.cutover_requested",
            "attempt",
            decision.cutover_id(),
        );
        match self.apply_generation_cutover_inner(decision) {
            Ok(GenerationCutoverApplyDisposition::Applied) => {
                observe_generation_cutover(
                    "kernel.generation.cutover_committed",
                    "success",
                    decision.cutover_id(),
                );
                // Issue #1837: durable audit evidence for epoch transition.
                self.audit_observe(AuditEventDraft::epoch_cutover_applied(decision));
                Ok(())
            }
            Ok(GenerationCutoverApplyDisposition::Readback) => Ok(()),
            Err(error) => {
                observe_generation_cutover(
                    "kernel.generation.cutover_failed",
                    "rejected",
                    decision.cutover_id(),
                );
                super::kernel_diagnostics::observe_terminal_error(
                    generation_cutover_terminal_code(&error),
                );
                Err(error)
            }
        }
    }

    /// Fenced persist-and-publish sequence; any publish failure fences this
    /// composition before returning. See
    /// [`KernelComposition::apply_generation_cutover`].
    fn apply_generation_cutover_inner(
        &self,
        decision: &CutoverDecision,
    ) -> Result<GenerationCutoverApplyDisposition, KernelServiceError> {
        let mut poison = self.generation_poison.lock().map_err(|_| {
            KernelServiceError::Platform("generation poison lock poisoned".to_owned())
        })?;
        if let Some(reason) = poison.clone() {
            return Err(KernelServiceError::Platform(format!(
                "generation gateway fenced: {reason}"
            )));
        }
        let mut persistence_observations = None;
        let result =
            (|| -> Result<GenerationCutoverApplyDisposition, GenerationCutoverInnerFailure> {
                let mut generations = self.generations.lock().map_err(|_| {
                    GenerationCutoverInnerFailure::Gateway("generation lock poisoned".to_owned())
                })?;
                let mut service = self.service.lock().map_err(|_| {
                    GenerationCutoverInnerFailure::Gateway("service lock poisoned".to_owned())
                })?;

                // I14.14: the authenticated production path reaches this point
                // after loading the committed ORS decision. The read-only
                // classification distinguishes exact replay from stale state.
                match classify_generation_cutover_live_endpoint(&generations, &service, decision) {
                    GenerationCutoverLiveEndpoint::Apply => {}
                    GenerationCutoverLiveEndpoint::Readback => {
                        return Ok(GenerationCutoverApplyDisposition::Readback);
                    }
                    GenerationCutoverLiveEndpoint::Mismatch => {
                        return Err(GenerationCutoverInnerFailure::Refused(
                            KernelServiceError::HandshakeMismatch {
                                field: "generation_cutover.live_state",
                            },
                        ));
                    }
                }

                let mut policy = self.front_door_policy.lock().map_err(|_| {
                    GenerationCutoverInnerFailure::Gateway(
                        "front-door policy lock poisoned".to_owned(),
                    )
                })?;
                let persisted = self.generation_gateway.persist_and_publish(
                    decision,
                    &mut generations,
                    &mut service,
                    &mut policy,
                );
                persistence_observations = Some(persisted.observations);
                persisted
                    .result
                    .map(|()| GenerationCutoverApplyDisposition::Applied)
                    .map_err(GenerationCutoverInnerFailure::Gateway)
            })();

        let mut fence_observation = None;
        let result = match result {
            Ok(GenerationCutoverApplyDisposition::Readback) => {
                drop(poison);
                return Ok(GenerationCutoverApplyDisposition::Readback);
            }
            Ok(GenerationCutoverApplyDisposition::Applied) => {
                Ok(GenerationCutoverApplyDisposition::Applied)
            }
            Err(GenerationCutoverInnerFailure::Refused(error)) => {
                drop(poison);
                return Err(error);
            }
            Err(GenerationCutoverInnerFailure::Gateway(reason)) => {
                *poison = Some(reason.clone());
                let fence_result = fence_service_after_generation_failure_without_observation(
                    &self.service,
                    reason.clone(),
                );
                fence_observation = Some(ServiceFenceObservation {
                    succeeded: fence_result.is_ok(),
                });
                if let Err(fence_error) = fence_result {
                    Err(KernelServiceError::Platform(format!(
                        "generation cutover failed and service fencing failed: {fence_error}"
                    )))
                } else {
                    Err(KernelServiceError::Platform(format!(
                        "generation cutover fenced: {reason}"
                    )))
                }
            }
        };
        drop(poison);
        if let Some(observations) = persistence_observations {
            observations.emit(result.is_ok(), decision.cutover_id());
        }
        if let Some(observation) = fence_observation {
            observation.emit_for_cutover(decision.cutover_id());
        }
        result
    }

    /// Applies one authenticated generation cutover from the owner's durable
    /// cutover-ownership record through the sole Kernel semantic gateway.
    ///
    /// This is the production control-plane entry that drives
    /// [`KernelComposition::apply_generation_cutover`]. It is a selector and a
    /// binding, never a second authority:
    ///
    /// - the request carries only a cutover identity, the admitted session
    ///   `StateFence` and — when the cutover has never been committed — the
    ///   completed `I5.11` replacement it commits; every generation, epoch, route
    ///   scope, and cutover state below is READ from the owner's committed ORS
    ///   record, so a request can never assert an authority field the
    ///   linearization point never recorded;
    /// - the request fence must be the exact admitted session fence, and the
    ///   record's `old_epoch` must be the same authority tuple that fence
    ///   carries, so a stale, foreign, or replayed epoch stays typed instead of
    ///   advancing the live fence;
    /// - only a `Committed` record reaches the gateway. A staged (`Armed`)
    ///   candidate or a `FailedRequiresForwardCutover` row is evidence, never
    ///   authority, and is refused before any ORS staging happens.
    ///
    /// ## The one cutover this ingress commits
    ///
    /// A cutover identity that already carries a row is reconciled against that
    /// row and nothing is written: no second ORS commit, no second linearization
    /// identity, and the same durable evidence the first request read.
    ///
    /// The `I5.11` `canonical_store` route cutover is the one cutover whose ORS
    /// row this ingress owns end to end, so when no row exists at all it may
    /// produce one — through [`commit_canonical_store_cutover_ownership`], and
    /// only for a completed replacement the `I5.11` coordinator itself
    /// re-derives. A request that presents no completion is refused exactly as
    /// before, and the missing-row refusal is never relaxed: the row is made to
    /// exist honestly, by its owner, for a cutover that was actually completed.
    ///
    /// The gateway owns the one terminal for the underlying cutover operation.
    /// This boundary reports that same terminal code back on the authenticated
    /// reply through [`GenerationCutoverOutcome::terminal_code`] so a refused or
    /// unknown cutover is observable on the real control-plane path and is never
    /// projected as a committed cutover. No route, epoch, generation, digest, or
    /// owner error string crosses the reply (I15.4, I07.20).
    pub fn apply_authenticated_generation_cutover(
        &self,
        request: &GenerationCutoverRequest,
        authenticated_session_fence: &StateFence,
    ) -> Result<GenerationCutoverOutcome, KernelServiceError> {
        request.validate()?;
        if &request.state_fence != authenticated_session_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_cutover.request.session_fence",
            });
        }
        let ors = &self.generation_gateway.ors;
        let existing = ors
            .load_cutover_ownership(request.cutover_id.as_str())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let (record, cutover_receipt) = if let Some(record) = existing {
            (record, None)
        } else {
            // No row at all. This ingress owns the `canonical_store` route
            // cutover's row, so it may produce it - but only from a completed
            // replacement the coordinator re-derives through its own stage
            // machine, and only once the claim's epoch is shown to be the
            // admitted session's own. A request that presents no completion
            // reaches the same typed refusal as before.
            let replacement =
                request
                    .replacement
                    .as_ref()
                    .ok_or(KernelServiceError::InvalidField {
                        field: "generation_cutover.request.cutover_id",
                        reason: "no cutover ownership record is recorded for this cutover",
                    })?;
            let (record, receipt) =
                commit_canonical_store_cutover_ownership(ors, request, replacement)?;
            (record, Some(receipt))
        };
        // I14.14: the ORS commit is the durable linearization point. A staged or
        // fenced row is evidence of an interrupted attempt, never authority, so
        // only a `Committed` record can reach the semantic gateway. The refusal
        // is a typed handshake mismatch on the record's state — the presented
        // record does not match the required committed state — and never
        // fabricates a service-lifecycle transition. A row this ingress has just
        // committed satisfies that requirement by construction and is still read
        // back here rather than assumed, so the gateway is only ever reached
        // through a durable record.
        if record.state != GenerationCutoverState::Committed {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_cutover.request.record_state",
            });
        }
        // The durable record projects only scalar epoch sequences (issue #64),
        // so the lineage-bearing epoch is the admitted session's own. The
        // record's `old_epoch` must be that same authority's current sequence,
        // which refuses a stale, foreign, or already-superseded epoch before
        // the router is ever asked to cut over.
        let old_epoch = authenticated_session_fence.authority_epoch.clone();
        if old_epoch.sequence.get() != record.old_epoch.value() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "generation_cutover.request.old_epoch",
            });
        }
        let new_epoch = EpochId::new(
            old_epoch.lineage_id.clone(),
            std::num::NonZeroU64::new(record.new_epoch.value()).ok_or(
                KernelServiceError::Platform(
                    "recorded cutover epoch is not representable".to_owned(),
                ),
            )?,
        )
        .map_err(|_| {
            KernelServiceError::Platform("recorded cutover epoch is not representable".to_owned())
        })?;
        let decision = CutoverDecision::new(
            record.cutover_id.as_str(),
            RouteScope::new(record.scope.module_id.as_str().to_owned()).map_err(|_| {
                KernelServiceError::Platform("recorded cutover route scope is invalid".to_owned())
            })?,
            record.old_generation,
            record.new_generation,
            old_epoch,
            new_epoch,
            GenerationCutoverState::Committed,
        )
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let state_fence = request.state_fence.clone();
        let cutover_id = record.cutover_id;
        match self.apply_generation_cutover(&decision) {
            Ok(()) => Ok(GenerationCutoverOutcome {
                version: 1,
                cutover_id,
                terminal_code: None,
                state_fence,
                cutover_receipt,
            }),
            Err(error) => {
                // The gateway already emitted the one terminal diagnostic for
                // this failed cutover. The stable code is projected back on the
                // authenticated reply so the refusal is observable on the real
                // control-plane path; it is the SAME code and never a second
                // failure claim, and no error payload crosses the reply.
                //
                // `cutover_receipt` still rides along when the coordinator built
                // one: it is the durable ORS cutover's own evidence and says
                // nothing about the live in-memory swap, which `terminal_code`
                // alone answers.
                Ok(GenerationCutoverOutcome {
                    version: 1,
                    cutover_id,
                    terminal_code: Some(generation_cutover_terminal_code(&error)),
                    state_fence,
                    cutover_receipt,
                })
            }
        }
    }
}

/// Commits the one ORS `CUTOVER_OWNERSHIP` row for the pinned `canonical_store`
/// route cutover of a completed `I5.11` replacement, and returns that committed
/// record together with the coordinator's own receipt for it.
///
/// This is the production caller of
/// [`StorageReplacement::replay_recorded_stages`],
/// [`StorageReplacement::commit_canonical_store_route_cutover`] and the two
/// existing ORS ownership writers, and it is reachable only from the admitted,
/// fence-checked ingress above — there is no other route to it, no fixture arm
/// and no unconditional commit. The order is fixed and each step can refuse:
///
/// 1. the claim's `old_epoch` must be the admitted session fence's own authority
///    sequence, so a stale, foreign or already-superseded epoch is refused
///    before any row exists;
/// 2. [`StorageReplacement::begin`] re-reads the durable committed rows for the
///    pinned route scope and refuses a candidate generation that already owns it,
///    so a restart cannot reopen a replacement from the top and cannot obtain a
///    second identity for a switch that is already committed;
/// 3. the presented stages are re-recorded through the coordinator's own stage
///    machine, so a skipped, repeated or out-of-order stage, a data-moving stage
///    without its `I5.10` transfer record, or a presented `I5.11` stage 8 is
///    refused by the coordinator rather than by a rule here;
/// 4. only a coordinator positioned exactly at `I5.11` stage 8 reaches the write,
///    and the row it writes takes its route scope and its two store generations
///    from that coordinator — never from this payload — while the remaining
///    `I14.14` step-7 content is the claim's own and is validated by ORS on the
///    original recorded values. The claim's `migration` is the one field of that
///    content this ingress does not take on trust: it is required to agree with
///    the coordinator's irreversible-effect ledger before the row is staged, so
///    the durable record a later rollback refusal reads cannot be a claim's own
///    account of whether an irreversible effect occurred;
/// 5. the coordinator then re-derives the receipt from the committed row itself,
///    which reloads the row, refuses anything that is not `Committed`, and
///    cross-checks the route scope, the two store generations and the state
///    migration against the coordinator's own irreversible-effect ledger.
///
/// The cutover identity is the request's own label for the row, and it is bound
/// by the ORS owner rather than trusted: `stage_cutover_ownership` refuses a
/// different record already stored under it and is idempotent for the identical
/// one, and `commit_cutover_ownership` mints the linearization identity from it
/// while refusing any epoch that does not continue this route's committed
/// lineage. With the restart guard above, a second identity for one route switch
/// therefore cannot be obtained, and the row's own content never comes from the
/// label.
///
/// Every refusal before the write is one of the coordinator's own typed
/// refusals, so it reaches the caller as `InvalidField { field: … }` or
/// `HandshakeMismatch { field: … }` on this crate's existing vocabulary. The ORS
/// write refusal itself is projected exactly as this file already projects every
/// ORS refusal at this boundary (the record load in the ingress above): as the
/// owner's own text, with no second classifier invented beside it.
fn commit_canonical_store_cutover_ownership(
    ors: &RedbRecoveryStore,
    request: &GenerationCutoverRequest,
    replacement: &GenerationCutoverReplacement,
) -> Result<(GenerationCutoverOwnership, StorageReplacementCutoverReceipt), KernelServiceError> {
    let claimed_old_epoch = replacement.cutover.old_epoch.value();
    if claimed_old_epoch != request.state_fence.authority_epoch.sequence.get() {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "generation_cutover.request.old_epoch",
        });
    }
    let mut coordinator = StorageReplacement::begin(
        ors,
        replacement.replacement_id.clone(),
        replacement.incumbent_generation,
        replacement.candidate_generation,
    )?;
    for effect in &replacement.irreversible_effects {
        coordinator.record_irreversible_effect(*effect);
    }
    let stages = replacement
        .stages
        .iter()
        .map(|stage| {
            StorageReplacementStage::from_name(&stage.stage)
                .map(|resolved| (resolved, stage.evidence.clone(), stage.transfer.clone()))
                .ok_or(KernelServiceError::InvalidField {
                    field: "generation_cutover.replacement.stage",
                    reason: "the presented stage is not one of the I5.11 ordered replacement stages",
                })
        })
        .collect::<Result<Vec<_>, KernelServiceError>>()?;
    coordinator.replay_recorded_stages(&stages)?;
    if coordinator.next_stage() != Some(StorageReplacementStage::CommitCanonicalStoreRouteCutover) {
        return Err(KernelServiceError::InvalidField {
            field: "generation_cutover.replacement.stages",
            reason: "the canonical_store route cutover is committed only after every preceding I5.11 stage is recorded",
        });
    }
    // The claim's `migration` is the value the row below is written from, so it
    // is bound to the coordinator's own irreversible-effect ledger here, BEFORE
    // ORS persists it. The coordinator re-checks the committed row's decision
    // after the write, but that is already the durable linearization point: a
    // mismatch caught only there leaves a row that says no irreversible effect
    // occurred while this replacement recorded one, and that row is what the
    // rollback refusal reads. The same rule, not a second one, is asked twice.
    coordinator.require_declared_state_migration(replacement.cutover.migration)?;
    commit_canonical_store_cutover_ownership_row(
        ors,
        &coordinator,
        request.cutover_id.as_str(),
        &replacement.cutover,
    )?;
    let receipt = coordinator.commit_canonical_store_route_cutover(
        ors,
        request.cutover_id.as_str(),
        replacement.cutover_evidence.as_str(),
    )?;
    let committed = coordinator
        .cutover()
        .cloned()
        .ok_or(KernelServiceError::InvalidField {
            field: "generation_cutover.request.cutover_id",
            reason: "the coordinator derived a cutover receipt without holding its committed ORS record",
        })?;
    Ok((committed, receipt))
}

/// Stages and commits the one ORS `CUTOVER_OWNERSHIP` row for the pinned
/// `canonical_store` route cutover, and returns the committed record.
///
/// The row is written in the `I14.14` two-step order the ORS owner already
/// implements: [`RedbRecoveryStore::stage_cutover_ownership`] persists the
/// `Armed` candidate — validating it on the original recorded values, and
/// refusing a different record already stored under the same cutover identity —
/// and [`RedbRecoveryStore::commit_cutover_ownership`] performs the single
/// write transaction that is the durable linearization point, mints the
/// linearization identity, and refuses a cutover whose epoch lineage does not
/// continue this route's committed one. Neither writer invents anything here:
/// the scope and the two store generations are the coordinator's own, and the
/// rest is the claim's own `I14.14` step-7 content.
fn commit_canonical_store_cutover_ownership_row(
    ors: &RedbRecoveryStore,
    replacement: &StorageReplacement,
    cutover_id: &str,
    claim: &GenerationCutoverOwnershipClaim,
) -> Result<GenerationCutoverOwnership, KernelServiceError> {
    let staged = GenerationCutoverOwnership {
        cutover_id: cutover_id.to_owned(),
        candidate_artifact: claim.candidate_artifact.clone(),
        incumbent_artifact: claim.incumbent_artifact.clone(),
        scope: replacement.route_scope().clone(),
        old_generation: replacement.incumbent_generation(),
        new_generation: replacement.candidate_generation(),
        old_epoch: claim.old_epoch,
        new_epoch: claim.new_epoch,
        in_flight: claim.in_flight.clone(),
        migration: claim.migration,
        health_proof_ref: claim.health_proof_ref.clone(),
        rollback_boundary: claim.rollback_boundary.clone(),
        unresolved_scopes: claim.unresolved_scopes.clone(),
        linearization_record_id: None,
        state: GenerationCutoverState::Armed,
    };
    ors.stage_cutover_ownership(staged)
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    Ok(ors
        .commit_cutover_ownership(cutover_id)
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?
        .0)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[allow(clippy::expect_used, clippy::unwrap_used)]
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
    fn poisoned_service_lock_is_recovered_and_fenced() {
        let service = std::sync::Arc::new(std::sync::Mutex::new(
            eliot_kernel_service::KernelService::new([37; 32], 2, 4)
                .unwrap_or_else(|_| unreachable!()),
        ));
        let poisoned = std::sync::Arc::clone(&service);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap_or_else(|_| unreachable!());
            panic!("force service lock poisoning");
        })
        .join();

        let result = fence_service_after_generation_failure(&service, String::new());
        assert!(result.is_ok(), "unexpected fencing failure: {result:?}");

        let service = service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(service.generation_fenced());
        assert!(matches!(
            service.failure(),
            Some(eliot_kernel_service::ServiceFailure::Contract(reason))
                if reason == "generation fence reason was invalid; canonical reason substituted"
        ));
    }

    #[test]
    fn generation_diagnostics_codes_are_stable_and_fence_observation_is_canary_free() {
        // F-LOG-KERNEL-4 (#903): snapshot and cutover failures keep distinct
        // stable codes per variant; only the code may be logged, never the
        // fence reason or any route/epoch material.
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::GenerationFenced),
            "SNAPSHOT_GENERATION_FENCED"
        );
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "SNAPSHOT_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            generation_snapshot_terminal_code(&KernelServiceError::Platform(
                "fence-canary-snapshot".to_owned()
            )),
            "SNAPSHOT_PLATFORM"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::GenerationFenced),
            "CUTOVER_GENERATION_FENCED"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::ControlReserveExhausted),
            "CUTOVER_RESERVE_EXHAUSTED"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::ReadinessNotProven),
            "CUTOVER_READINESS_NOT_PROVEN"
        );
        assert_eq!(
            generation_cutover_terminal_code(&KernelServiceError::Platform(
                "fence-canary-cutover".to_owned()
            )),
            "CUTOVER_PLATFORM"
        );

        // The fence observation carries fixed vocabulary only: the canary
        // reason retained by the service never reaches the sink, and the
        // fencing behavior itself is unchanged.
        let service = std::sync::Arc::new(std::sync::Mutex::new(
            eliot_kernel_service::KernelService::new([41; 32], 2, 4)
                .unwrap_or_else(|_| unreachable!()),
        ));
        let text = capture(|| {
            observe_generation("kernel.generation.cutover_requested", "attempt");
            let fenced =
                fence_service_after_generation_failure(&service, "fence-canary-service-reason-903");
            assert!(fenced.is_ok());
            crate::kernel_diagnostics::observe_terminal_error(generation_cutover_terminal_code(
                &KernelServiceError::GenerationFenced,
            ));
        });
        for marker in [
            "kernel.generation.cutover_requested",
            "kernel.generation.service_fence_requested",
            "kernel.generation.service_fenced",
            "CUTOVER_GENERATION_FENCED",
        ] {
            assert!(text.contains(marker), "missing diagnostics marker {marker}");
        }
        for canary in [
            "fence-canary-service-reason-903",
            "fence-canary-snapshot",
            "fence-canary-cutover",
        ] {
            assert!(
                !text.contains(canary),
                "diagnostics leaked fenced material {canary}"
            );
        }
        assert!(
            service
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .generation_fenced()
        );
    }

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn test_route(generation: u64) -> GenerationRoute {
        GenerationRoute::new(
            RouteScope::new("daemon").expect("test route scope"),
            ResourceGeneration::new(generation).expect("test generation"),
            test_epoch(4),
        )
        .expect("test route")
    }

    #[test]
    fn active_generation_projection_is_fenced_and_fingerprint_is_stable() {
        let epoch = test_epoch(4);
        let route = test_route(7);
        let fence = StateFence::new(epoch.clone(), route.active_generation());
        let projection = ActiveGenerationRegistryProjection::from_route(&route, fence.clone())
            .expect("matching route and fence");

        assert_eq!(projection.route_scope(), "daemon");
        assert_eq!(projection.active_generation().value(), 7);
        assert_eq!(projection.authority_epoch(), &epoch);
        assert_eq!(projection.state_fence(), &fence);
        assert_eq!(projection.generation_fingerprint().len(), 64);
        assert!(
            projection
                .generation_fingerprint()
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
        let response = serde_json::to_value(projection.response()).expect("wire response");
        let response_object = response.as_object().expect("closed response object");
        assert_eq!(response_object.len(), 3);
        assert!(response_object.contains_key("version"));
        assert!(response_object.contains_key("fingerprint"));
        assert!(response_object.contains_key("state_fence"));

        let repeat = ActiveGenerationRegistryProjection::from_route(&route, fence)
            .expect("same canonical state");
        assert_eq!(projection, repeat);

        let changed_route = test_route(8);
        let changed_fence = StateFence::new(test_epoch(4), changed_route.active_generation());
        let changed = ActiveGenerationRegistryProjection::from_route(&changed_route, changed_fence)
            .expect("changed active generation");
        assert_ne!(
            projection.generation_fingerprint(),
            changed.generation_fingerprint()
        );
    }

    #[test]
    fn active_generation_projection_rejects_cross_generation_fence() {
        let route = test_route(7);
        let foreign_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(8).expect("foreign generation"),
        );

        assert!(matches!(
            ActiveGenerationRegistryProjection::from_route(&route, foreign_fence),
            Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.state_fence"
            })
        ));
    }

    #[test]
    fn active_generation_query_accepts_exact_authenticated_fence() {
        let fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 1,
            state_fence: fence.clone(),
        };

        validate_active_generation_query(&query, &fence)
            .expect("exact authenticated fence is accepted");
    }

    #[test]
    fn active_generation_query_rejects_foreign_fence() {
        let query_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("query generation"),
        );
        let session_fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(8).expect("session generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 1,
            state_fence: query_fence,
        };

        assert!(matches!(
            validate_active_generation_query(&query, &session_fence),
            Err(KernelServiceError::HandshakeMismatch {
                field: "generation_registry.query.session_fence"
            })
        ));
    }

    #[test]
    fn active_generation_query_rejects_unsupported_version() {
        let fence = StateFence::new(
            test_epoch(4),
            ResourceGeneration::new(7).expect("generation"),
        );
        let query = ActiveGenerationRegistryQuery {
            version: 2,
            state_fence: fence.clone(),
        };

        assert!(matches!(
            validate_active_generation_query(&query, &fence),
            Err(KernelServiceError::InvalidField {
                field: "generation_registry.query.version",
                ..
            })
        ));
    }
}
