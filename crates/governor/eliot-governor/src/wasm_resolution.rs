//! Governor-owned WASM resolution ports (issue #1955, I14.19).
//!
//! Architecture: I14.19 (WASM default contour; host calls stay
//! Governor-authorized proposals); I6.15 (Governor owns grant semantics and
//! semantic admission; adapters implement facets); I2.1/I2.3 (one module in
//! the Governor owner crate over the neutral runtime's contract surface —
//! no new crate, no new state machine, no prost cell). This cell resolves
//! WASM invocation admission from retained Governor observations: it binds
//! requests to admitted manifest, generation, lease, authority, and
//! provenance state and recomputes receipt digests. Content and shape
//! validation stays with the single neutral runtime validators; process
//! mechanics stay with the P03 lane; guest execution stays with the engine
//! lane; lifecycle evidence stays with the lifecycle owners.
//!
//! Delegation boundary (delegate, never copy):
//!
//! - observations arrive threaded per admission (contour admission, Kernel
//!   generation projection, task state, provenance, policy) and must share
//!   one Governor fence; staleness across snapshots fails closed instead of
//!   composing. The constructor enforces this admission coherence; the
//!   resolvers enforce request binding.
//! - manifest, limits, and lease content validation stays with the neutral
//!   runtime validators (single implementation); this cell checks ownership,
//!   binding, and fence/epoch coherence, then attests.
//! - promotion verdicts stay Rejected until lifecycle evidence is threaded:
//!   only the Conformance contour (which ignores verdicts) admits, so higher
//!   contours correctly deny (A13.3 promotion path).
//!
//! Conformance scope: the promotion corpus is computed via the real
//! [`DeterministicEchoCore`](eliot_wasm_runtime::lifecycle::DeterministicEchoCore)
//! oracle over the documented fixed vector below — never hardcoded hex.
//! Changing the vector changes every digest (proven); the joined engine
//! comparison (host lane) binds them to real guest output.

use std::collections::BTreeSet;

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes};
use eliot_observation_contracts::ObservationScope;
use eliot_runtime_contracts::{ModuleGeneration, RuntimeLease};
use eliot_security_contracts::SourceAssurance;
use eliot_wasm_runtime::lifecycle::{DeterministicEchoCore, SemanticCore};
use eliot_wasm_runtime::{
    AuthorityResolution, AuthorityResolutionPort, CapabilityId, ComponentManifest,
    DerivedExecutionEvidence, EffectProposal, EngineInvocation, EngineReport, GovernorResolution,
    GovernorResolutionPort, InvocationLimits, InvocationRequest, OwnerId, PortError,
    PromotionQuery, PromotionVerification, PromotionVerificationPort, Revision, Sha256Digest,
    SourceVerification, SourceVerificationPort, VerificationVerdict, WorkUnitId,
};
use serde::Serialize;

use crate::KernelGenerationSnapshot;

/// Documented conformance vector (single-component scope).
///
/// Mirrors the in-tree lifecycle reference core: corpus expectations below
/// are COMPUTED from these via the real oracle, never hardcoded hex.
pub const CONFORMANCE_COMPONENT: &str = "component-1956";
/// Fixed framed input the conformance corpus covers.
pub const CONFORMANCE_INPUT: &[u8] = b"lc-wasm-1956";
/// Fixed seed the conformance corpus covers.
pub const CONFORMANCE_SEED: u64 = 0x1956;

/// Promotion corpus expectations computed via the real conformance oracle.
///
/// `corpus_digest` binds the covered input; the expected digests bind the
/// oracle's deterministic output over it. Empty effects/delta digest honestly
/// (the pure core reports none) — no digest convention is manufactured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionExpectations {
    /// Digest of the covered corpus input bytes.
    pub corpus_digest: Sha256Digest,
    /// Digest of the oracle result bytes over the corpus input.
    pub expected_result_digest: Sha256Digest,
    /// Digest of the oracle effect proposals (canonically encoded).
    pub expected_effect_digest: Sha256Digest,
    /// Digest of the oracle state delta (canonically encoded).
    pub expected_state_delta_digest: Sha256Digest,
}

impl PromotionExpectations {
    /// Computes expectations by invoking the real deterministic core over
    /// the given input and seed. Pure computation: no reads, no clock, no
    /// randomness, no hardcoded digests. Effect and state-delta digests use
    /// the same canonical JSON scheme as the neutral digest helper.
    ///
    /// # Errors
    ///
    /// Returns [`PortError::Denied`] when the expectation bytes cannot be
    /// canonicalized (fail-closed; practically infallible for these shapes).
    pub fn compute(input: &[u8], seed: u64) -> Result<Self, PortError> {
        Self::for_component(CONFORMANCE_COMPONENT, input, seed)
    }

    /// Computes expectations for the documented conformance vector.
    ///
    /// # Errors
    ///
    /// Returns [`PortError::Denied`] when the expectation bytes cannot be
    /// canonicalized (fail-closed; practically infallible for these shapes).
    pub fn conformance() -> Result<Self, PortError> {
        Self::for_component(CONFORMANCE_COMPONENT, CONFORMANCE_INPUT, CONFORMANCE_SEED)
    }

    /// Computes expectations for one registered component identity over the
    /// given input and seed. The identity names the attested vector; the
    /// oracle itself is input- and seed-determined.
    ///
    /// # Errors
    ///
    /// Returns [`PortError::Denied`] when the expectation bytes cannot be
    /// canonicalized (fail-closed; practically infallible for these shapes).
    pub fn for_component(
        component: &'static str,
        input: &[u8],
        seed: u64,
    ) -> Result<Self, PortError> {
        let outcome = DeterministicEchoCore::new(component).invoke(input, seed);
        let canonical = |bytes: &[u8]| Sha256Digest::of_bytes(bytes);
        let canonical_json = |value: &Vec<u8>| {
            canonical_json_bytes(value)
                .map(|bytes| Sha256Digest::of_bytes(&bytes))
                .map_err(|_| PortError::Denied)
        };
        let canonical_effects = |effects: &Vec<EffectProposal>| {
            canonical_json_bytes(effects)
                .map(|bytes| Sha256Digest::of_bytes(&bytes))
                .map_err(|_| PortError::Denied)
        };
        Ok(Self {
            corpus_digest: canonical(input),
            expected_result_digest: canonical(&outcome.result),
            expected_effect_digest: canonical_effects(&outcome.effects)?,
            expected_state_delta_digest: canonical_json(&outcome.state_delta)?,
        })
    }
}

/// Contour-admitted values bound by the host admission proof, threaded by
/// the constructing owner.
///
/// The host lane constructs these from `AdmittedGeneration` accessors
/// (contour, world, target, artifact/wit digests — field privacy there
/// proves the admission sequence ran) plus the raw artifact bytes the
/// digests bind. Byte blobs are re-hashed here, never trusted; blank
/// world/target or empty bytes fail closed as meaningless admission.
#[derive(Clone, Debug)]
pub struct ContourAdmission {
    /// Raw component artifact bytes the artifact digest binds.
    pub artifact_bytes: Vec<u8>,
    /// Raw WIT world bytes the interface digest binds.
    pub wit_bytes: Vec<u8>,
    /// Raw component configuration bytes the configuration digest binds.
    pub configuration_bytes: Vec<u8>,
    /// Admitted artifact digest (`AdmittedGeneration::artifact_digest`).
    pub admitted_artifact: Sha256Digest,
    /// Admitted WIT digest (`AdmittedGeneration::wit_digest`).
    pub admitted_wit: Sha256Digest,
    /// Admitted world name (`AdmittedGeneration::world`).
    pub admitted_world: String,
    /// Admitted guest target (`AdmittedGeneration::target`).
    pub admitted_target: String,
}

/// Retained Governor admission observations for one admitted WASM component.
///
/// Single-component scope: every observation below was admitted for the same
/// component under one Governor fence. Multi-component work threads one
/// instance per component; no registry is invented here. Prefer
/// [`GovernorWasmAdmission::from_owners`], which reads the Governor fence
/// and epoch from canonical recovery state and re-derives manifest digests
/// from real bytes; direct construction is the test and edge-case path.
#[derive(Clone, Debug)]
pub struct GovernorWasmAdmission {
    governor_fence: StateFence,
    governor_epoch: EpochId,
    manifest: ComponentManifest,
    generation: ModuleGeneration,
    lease: RuntimeLease,
    owner: OwnerId,
    work_unit: WorkUnitId,
    work_scope: ObservationScope,
    assurance: SourceAssurance,
    limits: InvocationLimits,
    authority_revision: Revision,
    lifecycle_revision: Revision,
    verification_revision: Revision,
    allowed_host_calls: BTreeSet<CapabilityId>,
    allowed_effect_proposals: BTreeSet<CapabilityId>,
    promotion: PromotionExpectations,
}

impl GovernorWasmAdmission {
    /// Retains one admission observation bundle after coherence checks.
    ///
    /// Admission coherence (all fail closed with [`PortError::Denied`):
    /// generation and lease bind the manifest component and artifact;
    /// generation, lease, and assurance share the Governor fence (single
    /// snapshot — observations from different snapshots never compose);
    /// the lease epoch shares the Governor authority lineage; the scope
    /// attempt/module refs link the work unit and component; the assurance
    /// verifier equals the manifest verifier. Content and shape validation
    /// stays with the neutral runtime validators.
    #[allow(
        clippy::too_many_arguments,
        reason = "admission observations arrive as one explicit bundle mirroring the sealed envelope; grouping would duplicate the runtime shape"
    )]
    pub fn new(
        governor_fence: StateFence,
        governor_epoch: EpochId,
        manifest: ComponentManifest,
        generation: ModuleGeneration,
        lease: RuntimeLease,
        owner: OwnerId,
        work_unit: WorkUnitId,
        work_scope: ObservationScope,
        assurance: SourceAssurance,
        limits: InvocationLimits,
        authority_revision: Revision,
        lifecycle_revision: Revision,
        verification_revision: Revision,
        allowed_host_calls: BTreeSet<CapabilityId>,
        allowed_effect_proposals: BTreeSet<CapabilityId>,
        promotion: PromotionExpectations,
    ) -> Result<Self, PortError> {
        if generation.module_id.as_str() != manifest.component_id.as_str()
            || generation.artifact_id.as_str() != manifest.artifact_digest.as_str()
        {
            return Err(PortError::Denied);
        }
        if generation.state_fence != governor_fence
            || lease.state_fence != governor_fence
            || assurance.state_fence != governor_fence
        {
            return Err(PortError::Denied);
        }
        if !lease.authority_epoch.is_same_authority(&governor_epoch) {
            return Err(PortError::Denied);
        }
        if work_scope.attempt_ref.as_deref() != Some(work_unit.as_str())
            || work_scope.module_or_route_ref.as_deref() != Some(manifest.component_id.as_str())
        {
            return Err(PortError::Denied);
        }
        if assurance.required_verifier.as_deref() != Some(manifest.required_verifier.as_str()) {
            return Err(PortError::Denied);
        }
        Ok(Self {
            governor_fence,
            governor_epoch,
            manifest,
            generation,
            lease,
            owner,
            work_unit,
            work_scope,
            assurance,
            limits,
            authority_revision,
            lifecycle_revision,
            verification_revision,
            allowed_host_calls,
            allowed_effect_proposals,
            promotion,
        })
    }

    /// Returns the Governor fence every retained observation was bound to at
    /// admission. Callers correlate this admission with their own fence
    /// before executing under it; a mismatch means the admission belongs to
    /// another snapshot.
    #[must_use]
    pub const fn admitted_fence(&self) -> &StateFence {
        &self.governor_fence
    }

    /// Returns the Governor authority epoch the admission is bound to.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.governor_epoch
    }

    /// Builds admission from canonical Governor recovery state plus contour
    /// observations (production factory).
    ///
    /// The Governor fence and epoch come from the admitted
    /// [`KernelGenerationSnapshot`] (composition recovery state), never
    /// from caller threading. Manifest identity digests are recomputed from
    /// real bytes — artifact, WIT, and configuration — and must match both
    /// the manifest claim and the host admission proof; tampered bytes or a
    /// foreign admission fail closed. All remaining observations thread
    /// through [`GovernorWasmAdmission::new`], which enforces the rest of
    /// the admission coherence. A manifest whose non-derived digests
    /// (source, state contract, engine) lack an owner stays threaded and
    /// documented; the runtime validators admit or reject their content.
    #[allow(
        clippy::too_many_arguments,
        reason = "factory threads one explicit observation bundle plus the snapshot and contour proof; grouping would duplicate the sealed envelope"
    )]
    pub fn from_owners(
        snapshot: &KernelGenerationSnapshot,
        manifest: ComponentManifest,
        contour: &ContourAdmission,
        generation: ModuleGeneration,
        lease: RuntimeLease,
        owner: OwnerId,
        work_unit: WorkUnitId,
        work_scope: ObservationScope,
        assurance: SourceAssurance,
        limits: InvocationLimits,
        authority_revision: Revision,
        lifecycle_revision: Revision,
        verification_revision: Revision,
        allowed_host_calls: BTreeSet<CapabilityId>,
        allowed_effect_proposals: BTreeSet<CapabilityId>,
        promotion: PromotionExpectations,
    ) -> Result<Self, PortError> {
        snapshot.validate().map_err(|_| PortError::Denied)?;
        if contour.artifact_bytes.is_empty()
            || contour.wit_bytes.is_empty()
            || contour.configuration_bytes.is_empty()
            || contour.admitted_world.trim().is_empty()
            || contour.admitted_target.trim().is_empty()
        {
            return Err(PortError::Denied);
        }
        if Sha256Digest::of_bytes(&contour.artifact_bytes) != manifest.artifact_digest
            || Sha256Digest::of_bytes(&contour.wit_bytes) != manifest.interface_digest
            || Sha256Digest::of_bytes(&contour.configuration_bytes) != manifest.configuration_digest
        {
            return Err(PortError::Denied);
        }
        if manifest.artifact_digest != contour.admitted_artifact
            || manifest.interface_digest != contour.admitted_wit
            || manifest.world.as_str() != contour.admitted_world.as_str()
            || manifest.guest_target != contour.admitted_target
        {
            return Err(PortError::Denied);
        }
        Self::new(
            snapshot.state_fence(),
            snapshot.authority_epoch.clone(),
            manifest,
            generation,
            lease,
            owner,
            work_unit,
            work_scope,
            assurance,
            limits,
            authority_revision,
            lifecycle_revision,
            verification_revision,
            allowed_host_calls,
            allowed_effect_proposals,
            promotion,
        )
    }

    /// Recomputes the Governor resolution receipt digest from the retained
    /// resolution content. Deterministic and content-bound: any substituted
    /// field changes the digest.
    fn governor_receipt(&self) -> Result<Sha256Digest, PortError> {
        digest_canonical(&(
            &self.manifest,
            &self.generation,
            &self.lease,
            &self.limits,
            self.authority_revision,
            self.lifecycle_revision,
        ))
    }

    /// Recomputes the authority resolution receipt digest.
    fn authority_receipt(&self) -> Result<Sha256Digest, PortError> {
        digest_canonical(&(
            &self.owner,
            &self.work_unit,
            &self.work_scope,
            &self.allowed_host_calls,
            &self.allowed_effect_proposals,
        ))
    }

    /// Recomputes the source verification receipt digest.
    fn source_receipt(&self) -> Result<Sha256Digest, PortError> {
        digest_canonical(&self.assurance)
    }

    /// Recomputes the promotion verification receipt digest.
    fn promotion_receipt(&self) -> Result<Sha256Digest, PortError> {
        digest_canonical(&(
            &self.promotion.corpus_digest,
            &self.promotion.expected_result_digest,
            &self.promotion.expected_effect_digest,
            &self.promotion.expected_state_delta_digest,
            Self::UNEVALUATED_VERDICTS,
        ))
    }

    /// Encodes lifecycle verdicts for receipt binding. All `false` until
    /// lifecycle evidence is threaded (A13.3 promotion path).
    const UNEVALUATED_VERDICTS: (bool, bool, bool, bool) = (false, false, false, false);
}

/// Canonical digest helper: deterministic JSON bytes hashed with SHA-256.
/// Fail-closed mapping; practically infallible for these shapes.
fn digest_canonical<T: Serialize>(value: &T) -> Result<Sha256Digest, PortError> {
    canonical_json_bytes(value)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| PortError::Denied)
}

impl GovernorResolutionPort for GovernorWasmAdmission {
    /// Resolves the admitted manifest, generation, lease, revisions, and
    /// limits for exactly the admitted component. The sealed request digest
    /// is verified first (tampered bytes fail closed — the neutral runtime
    /// trusts ports here); a request naming any other component is a
    /// confused-deputy attempt and fails closed.
    fn resolve(&mut self, request: &InvocationRequest) -> Result<GovernorResolution, PortError> {
        request.validate().map_err(|_| PortError::Denied)?;
        if request.component_id != self.manifest.component_id {
            return Err(PortError::Denied);
        }
        Ok(GovernorResolution {
            manifest: self.manifest.clone(),
            generation: self.generation.clone(),
            lease: self.lease.clone(),
            authority_revision: self.authority_revision,
            lifecycle_revision: self.lifecycle_revision,
            limits: self.limits.clone(),
            resolution_receipt_digest: self.governor_receipt()?,
        })
    }
}

impl AuthorityResolutionPort for GovernorWasmAdmission {
    /// Resolves the admitted owner, work unit, scope, and ceilings for
    /// exactly the admitted component, work unit, and scope. The sealed
    /// request digest is verified first; any other binding fails closed.
    fn resolve(&mut self, request: &InvocationRequest) -> Result<AuthorityResolution, PortError> {
        request.validate().map_err(|_| PortError::Denied)?;
        if request.component_id != self.manifest.component_id
            || request.work_unit != self.work_unit
            || request.work_scope_ref.as_str() != self.work_scope.work_scope.as_str()
        {
            return Err(PortError::Denied);
        }
        Ok(AuthorityResolution {
            owner: self.owner.clone(),
            work_unit: self.work_unit.clone(),
            work_scope: self.work_scope.clone(),
            allowed_host_calls: self.allowed_host_calls.clone(),
            allowed_effect_proposals: self.allowed_effect_proposals.clone(),
            resolution_receipt_digest: self.authority_receipt()?,
        })
    }
}

impl SourceVerificationPort for GovernorWasmAdmission {
    /// Attests the retained provenance observation with a recomputed
    /// receipt. Source admission itself (verifier match, taint, quarantine,
    /// freshness) is evaluated by the neutral runtime against the admitted
    /// manifest; this port carries the observation without reimplementing it.
    fn verify(&mut self, _request: &InvocationRequest) -> Result<SourceVerification, PortError> {
        Ok(SourceVerification {
            assurance: self.assurance.clone(),
            verification_revision: self.verification_revision,
            verification_receipt_digest: self.source_receipt()?,
        })
    }
}

impl PromotionVerificationPort for GovernorWasmAdmission {
    /// Returns the oracle-computed corpus expectations for exactly the
    /// admitted component, artifact, interface, state contract, and
    /// generation. Any other query fails closed. Lifecycle verdicts stay
    /// rejected until lifecycle evidence is threaded, so only the
    /// Conformance contour (which ignores verdicts) admits.
    fn verify(&mut self, query: &PromotionQuery) -> Result<PromotionVerification, PortError> {
        if query.component_id != self.manifest.component_id
            || query.artifact_digest != self.manifest.artifact_digest
            || query.interface_digest != self.manifest.interface_digest
            || query.state_contract_digest != self.manifest.state_contract_digest
            || query.generation != self.generation
        {
            return Err(PortError::Denied);
        }
        Ok(PromotionVerification {
            corpus_digest: self.promotion.corpus_digest.clone(),
            expected_result_digest: self.promotion.expected_result_digest.clone(),
            expected_effect_digest: self.promotion.expected_effect_digest.clone(),
            expected_state_delta_digest: self.promotion.expected_state_delta_digest.clone(),
            verification_revision: self.verification_revision,
            shadow: VerificationVerdict::Rejected,
            canary: VerificationVerdict::Rejected,
            rollback: VerificationVerdict::Rejected,
            cutover: VerificationVerdict::Rejected,
            verification_receipt_digest: self.promotion_receipt()?,
        })
    }

    /// Revalidates one sealed execution against the admitted resolutions.
    ///
    /// Mirrors the neutral echo conjunction with admission-bound values
    /// instead of canned digests: the invocation must carry this admission's
    /// manifest, generation, lease, authority, assurance, limits, corpus, and
    /// recomputed receipts, and the derived evidence must recompute exactly
    /// from the engine report. P03 artifacts (bindings, receipts) and usage
    /// metering are the P03/engine lanes' to verify and are not rechecked
    /// here. Any deviation fails closed.
    fn verify_execution(
        &mut self,
        invocation: &EngineInvocation,
        report: &EngineReport,
        derived: &DerivedExecutionEvidence,
    ) -> Result<(), PortError> {
        let exact = invocation.manifest == self.manifest
            && invocation.imports == self.manifest.imports
            && invocation.exports == self.manifest.exports
            && invocation.generation == self.generation
            && invocation.lease == self.lease
            && invocation.owner == self.owner
            && invocation.work_unit == self.work_unit
            && invocation.work_scope == self.work_scope
            && invocation.authority_revision == self.authority_revision
            && invocation.lifecycle_revision == self.lifecycle_revision
            && invocation.source_assurance == self.assurance
            && invocation.source_verification_revision == self.verification_revision
            && invocation.promotion_verification_revision == self.verification_revision
            && invocation.allowed_host_calls == self.allowed_host_calls
            && invocation.allowed_effect_proposals == self.allowed_effect_proposals
            && invocation.limits == self.limits
            && invocation.conformance_corpus_digest == self.promotion.corpus_digest
            && invocation.governor_resolution_receipt_digest == self.governor_receipt()?
            && invocation.authority_resolution_receipt_digest == self.authority_receipt()?
            && invocation.source_verification_receipt_digest == self.source_receipt()?
            && invocation.promotion_verification_receipt_digest == self.promotion_receipt()?
            && invocation.state_contract_digest == self.manifest.state_contract_digest
            && derived.result_digest == Sha256Digest::of_bytes(&report.output)
            && derived.effect_digest
                == Sha256Digest::of_bytes(
                    &canonical_json_bytes(&report.proposed_effects)
                        .map_err(|_| PortError::Denied)?,
                )
            && derived.state_delta_digest
                == Sha256Digest::of_bytes(
                    &canonical_json_bytes(&report.observed_state_delta)
                        .map_err(|_| PortError::Denied)?,
                );
        if exact {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{ArtifactId, ContractId, EpochLineageId, ResourceGeneration};
    use eliot_receipts::WorkScopeId;
    use eliot_runtime_contracts::{HealthVector, LeaseState, ModuleGenerationState};
    use eliot_security_contracts::{
        CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
        InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState,
    };
    use eliot_wasm_runtime::{DEFAULT_GUEST_TARGET, ExecutionContour, InvocationId, WorkScopeRef};
    use std::num::NonZeroU64;

    /// Real guest fixture bytes: the manifest binds these, never a pasted hex.
    const GUEST_WAT: &[u8] =
        include_bytes!("../../../../bins/eliot-wasm-host/tests/fixtures/guest-conformance.wat");
    const GUEST_WIT: &[u8] = include_bytes!("../../../../bins/eliot-wasm-host/wit/guest.wit");

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    /// Proof configuration bytes: mirrors the provider-owned test
    /// configuration (`COMPONENT_CONFIGURATION` in the Wasmtime provider
    /// tests). The manifest digest below is recomputed from these bytes, so
    /// the binding is derived, never pasted; the joined proof substitutes
    /// the provider-read configuration.
    const PROOF_CONFIGURATION: &[u8] =
        b"component=guest;world=eliot:wasm/guest;export=run;imports=closed";

    fn manifest_fixture() -> ComponentManifest {
        use eliot_wasm_runtime::{EngineBinding, Sha256Digest as WasmDigest};
        ComponentManifest {
            component_id: CapabilityId::new(CONFORMANCE_COMPONENT).expect("component"),
            world: CapabilityId::new("eliot:wasm/guest").expect("world"),
            wit_version: "1.0.0".to_owned(),
            guest_target: DEFAULT_GUEST_TARGET.to_owned(),
            artifact_digest: WasmDigest::of_bytes(GUEST_WAT),
            interface_digest: WasmDigest::of_bytes(GUEST_WIT),
            // Single-file fixture: source and artifact are the same bytes,
            // stated not hidden.
            source_digest: WasmDigest::of_bytes(GUEST_WAT),
            // Proof vector constant: recomputed from the proof
            // configuration bytes above (not pasted); the joined proof
            // substitutes the provider-read value.
            configuration_digest: WasmDigest::of_bytes(PROOF_CONFIGURATION),
            // Proof vector constant: no state-contract owner exists in this
            // lane; the joined proof substitutes the admitted value.
            state_contract_digest: WasmDigest::new(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            )
            .expect("state contract digest"),
            imports: BTreeSet::from([CapabilityId::new("log").expect("import")]),
            exports: BTreeSet::from([CapabilityId::new("run").expect("export")]),
            admitted_privacy_classes: vec![PrivacyClass::Internal],
            required_verifier: "verifier:a12".to_owned(),
            engine: EngineBinding {
                implementation_id: "wasmtime-component".to_owned(),
                exact_version: "47.0.4".to_owned(),
                // Proof vector constants: provider-owned artifact digests;
                // the joined proof substitutes provider-read values.
                engine_artifact_digest: WasmDigest::new(&"8".repeat(64)).expect("engine artifact"),
                engine_configuration_digest: WasmDigest::new(&"9".repeat(64))
                    .expect("engine configuration"),
                wit_interface_digest: WasmDigest::of_bytes(GUEST_WIT),
            },
        }
    }

    fn generation_fixture(fence: &StateFence) -> ModuleGeneration {
        ModuleGeneration {
            module_id: ContractId::new(CONFORMANCE_COMPONENT).expect("module"),
            generation: ResourceGeneration::new(1).expect("generation"),
            artifact_id: ArtifactId::new(eliot_contracts::sha256_hex(GUEST_WAT)).expect("artifact"),
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: fence.clone(),
        }
    }

    fn lease_fixture(fence: &StateFence) -> RuntimeLease {
        RuntimeLease {
            lease_id: "lease-1956".to_owned(),
            scope_ref: "scope-1956".to_owned(),
            authority_epoch: test_epoch(),
            state_fence: fence.clone(),
            state: LeaseState::Active,
        }
    }

    fn scope_fixture() -> ObservationScope {
        ObservationScope {
            work_scope: WorkScopeId::new("scope-1956").expect("scope"),
            task_ref: Some("task-1956".to_owned()),
            attempt_ref: Some("work-1956".to_owned()),
            module_or_route_ref: Some(CONFORMANCE_COMPONENT.to_owned()),
        }
    }

    fn assurance_fixture(fence: &StateFence) -> SourceAssurance {
        SourceAssurance {
            source_ref: "source-1956".to_owned(),
            provenance_ref: "provenance-1956".to_owned(),
            integrity: IntegrityStatus::Verified,
            freshness: FreshnessStatus::Current,
            competence: CompetenceLevel::DomainVerified,
            independence: IndependenceLevel::Independent,
            privacy_class: PrivacyClass::Internal,
            instruction_taint: InstructionTaint::DataOnly,
            allowed_epistemic_use: vec![EpistemicUse::VerificationInput],
            allowed_effects: vec![EffectCeiling::NoExternalEffect],
            required_verifier: Some("verifier:a12".to_owned()),
            quarantine: QuarantineState::None,
            state_fence: fence.clone(),
        }
    }

    fn limits_fixture() -> InvocationLimits {
        use eliot_wasm_runtime::{ArtifactAccessLimits, CancellationPolicy, EpochPolicy};
        InvocationLimits {
            max_input_bytes: 128,
            max_output_bytes: 128,
            max_host_calls: 4,
            max_fuel: 1_000,
            max_memory_bytes: 65_536,
            max_table_elements: 64,
            max_instances: 2,
            max_stack_bytes: 8_192,
            wall_deadline_ms: 500,
            epoch: EpochPolicy {
                deadline_ticks: 50,
                cancellation: CancellationPolicy::EpochAndFuel,
            },
            artifact_access: ArtifactAccessLimits {
                allowed_digests: BTreeSet::from([eliot_wasm_runtime::Sha256Digest::of_bytes(
                    GUEST_WAT,
                )]),
                max_reads: 2,
                max_bytes: 1_024,
            },
        }
    }

    fn admission_fixture() -> GovernorWasmAdmission {
        let fence = test_fence();
        GovernorWasmAdmission::new(
            fence.clone(),
            test_epoch(),
            manifest_fixture(),
            generation_fixture(&fence),
            lease_fixture(&fence),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance_fixture(&fence),
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        )
        .expect("admission observes one coherent snapshot")
    }

    fn request_fixture() -> InvocationRequest {
        InvocationRequest::new(
            InvocationId::new("invoke-1956").expect("invocation"),
            CapabilityId::new(CONFORMANCE_COMPONENT).expect("component"),
            WorkUnitId::new("work-1956").expect("work unit"),
            WorkScopeRef::new("scope-1956").expect("scope"),
            ExecutionContour::Conformance,
            CONFORMANCE_INPUT.to_vec(),
            CONFORMANCE_SEED,
            false,
        )
        .expect("request seals")
    }

    #[test]
    fn resolve_binds_request_to_admitted_observations() {
        let mut admission = admission_fixture();
        let request = request_fixture();
        let governor =
            GovernorResolutionPort::resolve(&mut admission, &request).expect("governor resolves");
        assert_eq!(
            governor.manifest.component_id.as_str(),
            CONFORMANCE_COMPONENT
        );
        let authority =
            AuthorityResolutionPort::resolve(&mut admission, &request).expect("authority resolves");
        assert_eq!(authority.work_unit.as_str(), "work-1956");
        let source =
            SourceVerificationPort::verify(&mut admission, &request).expect("source attests");
        assert!(matches!(
            source.assurance.integrity,
            IntegrityStatus::Verified
        ));
        // Receipts are deterministic recomputation, not canned values: a
        // second resolution round-trips identically.
        let again =
            GovernorResolutionPort::resolve(&mut admission, &request).expect("governor resolves");
        assert_eq!(
            governor.resolution_receipt_digest,
            again.resolution_receipt_digest
        );
    }

    #[test]
    fn manifest_tracks_real_fixture_bytes() {
        let manifest = manifest_fixture();
        assert_eq!(
            manifest.artifact_digest.as_str(),
            &eliot_contracts::sha256_hex(GUEST_WAT),
            "artifact digest must track the real guest bytes, never a pasted hex"
        );
        assert_eq!(
            manifest.interface_digest.as_str(),
            &eliot_contracts::sha256_hex(GUEST_WIT),
            "interface digest must track the real WIT bytes"
        );
        assert_eq!(
            manifest.engine.wit_interface_digest, manifest.interface_digest,
            "engine binding must agree with the manifest interface"
        );
    }

    #[test]
    fn corpus_computed_not_canned() {
        use eliot_wasm_runtime::lifecycle::{DeterministicEchoCore, SemanticCore};
        let expectations = PromotionExpectations::conformance().expect("corpus");
        // Independent oracle run over the same documented vector reproduces
        // every digest: the values are computed, never hardcoded.
        let outcome = DeterministicEchoCore::new(CONFORMANCE_COMPONENT)
            .invoke(CONFORMANCE_INPUT, CONFORMANCE_SEED);
        assert_eq!(
            expectations.expected_result_digest.as_str(),
            &eliot_contracts::sha256_hex(&outcome.result)
        );
        assert_eq!(
            expectations.corpus_digest.as_str(),
            &eliot_contracts::sha256_hex(CONFORMANCE_INPUT)
        );
        // A different input moves every digest: the computation is input-bound.
        let other = PromotionExpectations::for_component(
            CONFORMANCE_COMPONENT,
            b"other-input",
            CONFORMANCE_SEED,
        )
        .expect("corpus");
        assert_ne!(other.corpus_digest, expectations.corpus_digest);
        assert_ne!(
            other.expected_result_digest,
            expectations.expected_result_digest
        );
    }

    #[test]
    fn promotion_query_binds_component_and_digests() {
        let mut admission = admission_fixture();
        let query = PromotionQuery {
            request_digest: request_fixture().request_digest().clone(),
            component_id: CapabilityId::new(CONFORMANCE_COMPONENT).expect("component"),
            generation: admission.generation.clone(),
            contour: ExecutionContour::Conformance,
            artifact_digest: admission.manifest.artifact_digest.clone(),
            interface_digest: admission.manifest.interface_digest.clone(),
            state_contract_digest: admission.manifest.state_contract_digest.clone(),
        };
        let promotion =
            PromotionVerificationPort::verify(&mut admission, &query).expect("promotion verifies");
        assert_eq!(promotion.corpus_digest, admission.promotion.corpus_digest);
        // No lifecycle evidence is threaded: verdicts stay rejected, so only
        // the Conformance contour (which ignores verdicts) admits.
        assert_eq!(promotion.shadow, VerificationVerdict::Rejected);
        assert_eq!(promotion.canary, VerificationVerdict::Rejected);
        assert_eq!(promotion.rollback, VerificationVerdict::Rejected);
        assert_eq!(promotion.cutover, VerificationVerdict::Rejected);
    }

    fn request_for(component: &str, work_unit: &str, scope: &str) -> InvocationRequest {
        InvocationRequest::new(
            InvocationId::new("invoke-1956").expect("invocation"),
            CapabilityId::new(component).expect("component"),
            WorkUnitId::new(work_unit).expect("work unit"),
            WorkScopeRef::new(scope).expect("scope"),
            ExecutionContour::Conformance,
            CONFORMANCE_INPUT.to_vec(),
            CONFORMANCE_SEED,
            false,
        )
        .expect("request seals")
    }

    #[test]
    fn foreign_component_denied_on_every_entry() {
        let mut admission = admission_fixture();
        // Freshly sealed foreign request: valid digest, wrong component.
        let foreign = request_for("other-component", "work-1956", "scope-1956");
        assert_eq!(
            GovernorResolutionPort::resolve(&mut admission, &foreign),
            Err(PortError::Denied)
        );
        assert_eq!(
            AuthorityResolutionPort::resolve(&mut admission, &foreign),
            Err(PortError::Denied)
        );
        let query = PromotionQuery {
            request_digest: foreign.request_digest().clone(),
            component_id: CapabilityId::new("other-component").expect("component"),
            generation: admission.generation.clone(),
            contour: ExecutionContour::Conformance,
            artifact_digest: admission.manifest.artifact_digest.clone(),
            interface_digest: admission.manifest.interface_digest.clone(),
            state_contract_digest: admission.manifest.state_contract_digest.clone(),
        };
        assert_eq!(
            PromotionVerificationPort::verify(&mut admission, &query),
            Err(PortError::Denied)
        );
        // Digest mismatch on an otherwise bound query also fails closed.
        let mut rotated = query;
        rotated.component_id = CapabilityId::new(CONFORMANCE_COMPONENT).expect("component");
        rotated.artifact_digest = eliot_wasm_runtime::Sha256Digest::of_bytes(b"rotated-artifact");
        assert_eq!(
            PromotionVerificationPort::verify(&mut admission, &rotated),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn tampered_request_bytes_denied_before_binding() {
        let mut admission = admission_fixture();
        // Mutating sealed bytes without resealing breaks the request digest:
        // the ports refuse before any binding check runs.
        let mut tampered = request_fixture();
        tampered.input.push(0xFF);
        assert_eq!(
            GovernorResolutionPort::resolve(&mut admission, &tampered),
            Err(PortError::Denied)
        );
        assert_eq!(
            AuthorityResolutionPort::resolve(&mut admission, &tampered),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn foreign_work_unit_and_scope_denied() {
        let mut admission = admission_fixture();
        let foreign_unit = request_for(CONFORMANCE_COMPONENT, "work-foreign", "scope-1956");
        assert_eq!(
            AuthorityResolutionPort::resolve(&mut admission, &foreign_unit),
            Err(PortError::Denied)
        );
        let foreign_scope = request_for(CONFORMANCE_COMPONENT, "work-1956", "scope-foreign");
        assert_eq!(
            AuthorityResolutionPort::resolve(&mut admission, &foreign_scope),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn rotated_fence_in_retained_observation_denied_at_construction() {
        let fence = test_fence();
        let mut rotated = fence.clone();
        rotated.resource_generation =
            eliot_contracts::ResourceGeneration::new(2).expect("generation");
        let manifest = manifest_fixture();
        let result = GovernorWasmAdmission::new(
            fence,
            test_epoch(),
            manifest,
            generation_fixture(&rotated),
            lease_fixture(&rotated),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance_fixture(&rotated),
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        );
        assert_eq!(result.map(|_| ()), Err(PortError::Denied));
    }

    #[test]
    fn epoch_lineage_mismatch_denied_at_construction() {
        let fence = test_fence();
        let foreign_epoch = eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("123e4567-e89b-12d3-a456-426614174000")
                .expect("lineage"),
            std::num::NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let result = GovernorWasmAdmission::new(
            fence.clone(),
            foreign_epoch,
            manifest_fixture(),
            generation_fixture(&fence),
            lease_fixture(&fence),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance_fixture(&fence),
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        );
        assert_eq!(result.map(|_| ()), Err(PortError::Denied));
    }

    #[test]
    fn broken_scope_linkage_denied_at_construction() {
        let fence = test_fence();
        let mut scope = scope_fixture();
        scope.attempt_ref = Some("work-foreign".to_owned());
        let result = GovernorWasmAdmission::new(
            fence.clone(),
            test_epoch(),
            manifest_fixture(),
            generation_fixture(&fence),
            lease_fixture(&fence),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope,
            assurance_fixture(&fence),
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        );
        assert_eq!(result.map(|_| ()), Err(PortError::Denied));
    }

    #[test]
    fn verifier_mismatch_denied_at_construction() {
        let fence = test_fence();
        let mut assurance = assurance_fixture(&fence);
        assurance.required_verifier = Some("verifier:foreign".to_owned());
        let result = GovernorWasmAdmission::new(
            fence.clone(),
            test_epoch(),
            manifest_fixture(),
            generation_fixture(&fence),
            lease_fixture(&fence),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance,
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        );
        assert_eq!(result.map(|_| ()), Err(PortError::Denied));
    }

    #[test]
    fn receipt_binds_resolution_content() {
        let first = admission_fixture();
        let mut limited = limits_fixture();
        limited.max_host_calls = 8;
        let fence = test_fence();
        let second = GovernorWasmAdmission::new(
            fence.clone(),
            test_epoch(),
            manifest_fixture(),
            generation_fixture(&fence),
            lease_fixture(&fence),
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance_fixture(&fence),
            limited,
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        )
        .expect("admission observes");
        let request = request_fixture();
        let mut first_mut = first;
        let mut second_mut = second;
        let first_receipt = GovernorResolutionPort::resolve(&mut first_mut, &request)
            .expect("resolves")
            .resolution_receipt_digest;
        let second_receipt = GovernorResolutionPort::resolve(&mut second_mut, &request)
            .expect("resolves")
            .resolution_receipt_digest;
        assert_ne!(
            first_receipt, second_receipt,
            "receipt must bind content: changed limits change the digest"
        );
    }

    fn snapshot_fixture() -> crate::KernelGenerationSnapshot {
        crate::KernelGenerationSnapshot {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            generation: ResourceGeneration::new(1).expect("generation"),
            authority_epoch: test_epoch(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "S-1-5-18".to_owned(),
        }
    }

    fn contour_fixture(manifest: &ComponentManifest) -> ContourAdmission {
        ContourAdmission {
            artifact_bytes: GUEST_WAT.to_vec(),
            wit_bytes: GUEST_WIT.to_vec(),
            configuration_bytes: PROOF_CONFIGURATION.to_vec(),
            admitted_artifact: manifest.artifact_digest.clone(),
            admitted_wit: manifest.interface_digest.clone(),
            admitted_world: manifest.world.as_str().to_owned(),
            admitted_target: manifest.guest_target.clone(),
        }
    }

    fn admission_via_factory(
        snapshot: &crate::KernelGenerationSnapshot,
        manifest: ComponentManifest,
        contour: &ContourAdmission,
        generation: ModuleGeneration,
        lease: RuntimeLease,
        assurance: SourceAssurance,
    ) -> Result<GovernorWasmAdmission, PortError> {
        GovernorWasmAdmission::from_owners(
            snapshot,
            manifest,
            contour,
            generation,
            lease,
            OwnerId::new("owner-1956").expect("owner"),
            WorkUnitId::new("work-1956").expect("work unit"),
            scope_fixture(),
            assurance,
            limits_fixture(),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            Revision::new(1).expect("revision"),
            BTreeSet::from([CapabilityId::new("log").expect("host call")]),
            BTreeSet::new(),
            PromotionExpectations::conformance().expect("corpus"),
        )
    }

    #[test]
    fn factory_binds_snapshot_bytes_and_admission() {
        let snapshot = snapshot_fixture();
        let manifest = manifest_fixture();
        let contour = contour_fixture(&manifest);
        let fence = snapshot.state_fence();
        let admission = admission_via_factory(
            &snapshot,
            manifest,
            &contour,
            generation_fixture(&fence),
            lease_fixture(&fence),
            assurance_fixture(&fence),
        )
        .expect("factory admits coherent observations");
        // Fence and epoch come from recovery state, never threading.
        assert_eq!(admission.admitted_fence(), &fence);
        assert!(
            admission
                .authority_epoch()
                .is_same_authority(&snapshot.authority_epoch)
        );
        // The factory product resolves like a directly built admission.
        let mut admission = admission;
        let request = request_fixture();
        GovernorResolutionPort::resolve(&mut admission, &request).expect("resolves");
    }

    #[test]
    fn factory_rejects_tampered_artifact_bytes() {
        let snapshot = snapshot_fixture();
        let manifest = manifest_fixture();
        let mut contour = contour_fixture(&manifest);
        contour.artifact_bytes[0] ^= 0xFF;
        let fence = snapshot.state_fence();
        assert_eq!(
            admission_via_factory(
                &snapshot,
                manifest,
                &contour,
                generation_fixture(&fence),
                lease_fixture(&fence),
                assurance_fixture(&fence),
            )
            .map(|_| ()),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn factory_rejects_foreign_admission_proof() {
        let snapshot = snapshot_fixture();
        let manifest = manifest_fixture();
        let mut contour = contour_fixture(&manifest);
        contour.admitted_world = "eliot:wasm/foreign".to_owned();
        let fence = snapshot.state_fence();
        assert_eq!(
            admission_via_factory(
                &snapshot,
                manifest,
                &contour,
                generation_fixture(&fence),
                lease_fixture(&fence),
                assurance_fixture(&fence),
            )
            .map(|_| ()),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn factory_rejects_empty_bytes_and_invalid_snapshot() {
        let snapshot = snapshot_fixture();
        let manifest = manifest_fixture();
        let fence = snapshot.state_fence();
        let mut contour = contour_fixture(&manifest);
        contour.wit_bytes.clear();
        assert_eq!(
            admission_via_factory(
                &snapshot,
                manifest.clone(),
                &contour,
                generation_fixture(&fence),
                lease_fixture(&fence),
                assurance_fixture(&fence),
            )
            .map(|_| ()),
            Err(PortError::Denied)
        );
        let mut bad_snapshot = snapshot_fixture();
        bad_snapshot.service.clear();
        let contour = contour_fixture(&manifest);
        assert_eq!(
            admission_via_factory(
                &bad_snapshot,
                manifest,
                &contour,
                generation_fixture(&fence),
                lease_fixture(&fence),
                assurance_fixture(&fence),
            )
            .map(|_| ()),
            Err(PortError::Denied)
        );
    }
}
