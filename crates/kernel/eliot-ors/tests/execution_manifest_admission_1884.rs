//! Issue #1884 — immutable `KernelExecutionManifest` admission and enforcement.
//!
//! One `#[test]` per mandatory check of the owner audit (issue #1884 comment
//! 5946154380) plus the audit's three admission negative discriminators:
//! SIXTEEN `#[test]` functions in all, and NONE of them is `#[ignore]`d. Check 5
//! is split across seven tests: three because it names seven independent
//! coordinates whose request-side inputs live in three different sets of request
//! fields, two more because its durable half is about the escalation table
//! and the lifecycle owner rather than about a launch decision, and two
//! further ones because check 5's refusal is recorded per FIELD, so it is only
//! falsifiable one field at a time. Every value is built through the crate's
//! own canonical constructors
//! (`GovernorGenerationAdmissionSeal::canonical_sha256`,
//! `GovernorGenerationAdmissionSeal::seal`, `GovernorAdmissionReceipt::issue`,
//! `StateFenceSnapshot::capture`, `CapabilityRouteScope::declare`,
//! `CompatibilityEvidence::new`, `CompatibilityRefusal::new`,
//! `KernelExecutionManifest::admit`, `EffectOperationLease::issue`,
//! `ObservedGenerationLifecycle::compose`), never hand-rolled, and every
//! refusal is proved by matching the crate's typed `OrsError` /
//! `KernelReconciliationKind` rather than by "it did not succeed".
//! No test name claims more than its body asserts.
//!
//! ## Why check 5 needs a case per field
//!
//! `manifest_blocking_defect`
//! (`crates/kernel/eliot-ors/src/execution_manifest.rs`) compares the observed
//! Job Object/resource limits to the recorded ones as ONE whole-struct equality,
//! so `job_object_policy` is covered exactly as the three numeric ceilings are.
//! That field is the declared policy TOKEN: it has no OS representation of its
//! own, so nothing at the process edge would notice a comparison that dropped
//! it, and a comparison rewritten field by field without it would pass every
//! other case in this file. So
//! `a_substituted_job_object_policy_token_alone_blocks_the_launch` substitutes
//! that token and nothing else, and its refusal is the only evidence in this
//! file that ORS compares it. The unobserved counterparts are pinned separately
//! by `an_unobserved_job_limits_or_readiness_coordinate_is_refused_as_unobserved`,
//! because `ManifestResourceLimitsUnobserved` and
//! `ManifestReadinessContractUnobserved` are kinds of their own, distinct from
//! the two mismatch kinds: an omission can never be recorded as a substitution.
//!
//! Both read through the production store entry point
//! `RedbRecoveryStore::load_and_verify_kernel_execution_restart`, which is the
//! only path in this crate that decides against a manifest row the store itself
//! admitted: `persist_admitted_kernel_execution_manifest` verifies the canonical
//! Governor owner receipt field by field, so the recorded row cannot be
//! substituted here by an in-memory manifest.
//!
//! ## The vocabulary this file uses for the two owner-evidence types
//!
//! A **seal** is a seal: `GovernorGenerationAdmissionSeal` is the typed,
//! sealed, versioned projection the Generation Registry admits against, its
//! `owner_canonical_sha256` is inside its own canonical digest, and forging one
//! of its fields is refused by `defect()` on every readback.
//!
//! A **receipt** is the canonical owner RECORD:
//! `GovernorAdmissionReceipt` is the durable, versioned, integrity-bound
//! statement the Governor accept path persists, and
//! `RedbRecoveryStore::persist_admitted_kernel_execution_manifest` REFUSES to
//! write a Generation Registry manifest unless one exists for the seal's own
//! canonical operation identity and `verify_seal` agrees with the seal field by
//! field. The two digests are never confused here:
//! `owner_canonical_sha256` is the owner's canonical digest over the admission
//! facts, and `receipt_sha256()` is the receipt record's own integrity digest
//! over its own field set.
//!
//! ## Which half of audit check 3 is proved HERE
//!
//! The audit's check 3 is a chain: a Governor-issued accepted generation must
//! automatically create the exact Generation Registry copy. The Governor half
//! of that chain — reading the canonical Module Catalog receipt back, applying
//! the accept mutation and producing the one seal — lives OUTSIDE this crate
//! in `eliot_governor::admit_accepted_generation_into_generation_registry`
//! (`crates/governor/eliot-governor/src/module_registry_admission.rs`, re-exported
//! from that crate's root), which takes the `eliot_ors::RedbRecoveryStore` as an
//! explicit argument. This file proves the ORS half and only the ORS half:
//! `GovernorAdmissionReceipt::issue` from exactly the
//! `GovernorGenerationAdmissionSealParts` the seal was sealed from, then
//! `persist_governor_admission_receipt`, then the manifest persisting as the
//! exact recorded copy — and a MISSING canonical receipt refusing that same
//! manifest before any row exists. The Governor half is not exercised here
//! because `eliot-ors` declares no dependency on `eliot-governor` and this test
//! file is not the owner of `Cargo.toml`.
//!
//! ## What check 7's lifecycle ceiling used to say
//!
//! An earlier delivery of this file carried an `#[ignore]`d test named
//! `missing_manifest_puts_the_affected_generation_into_a_visible_degraded_state`
//! whose ceiling paragraph said there was no Generation Registry lifecycle owner
//! and nothing could move a real generation into a degraded or quarantined
//! state. That paragraph is no longer true and the test is gone:
//! `crates/kernel/eliot-ors/src/generation_lifecycle.rs` now owns
//! `GenerationLifecycleRecord`, `GenerationDisposition` and the single
//! composition point `ObservedGenerationLifecycle::compose`, and
//! `RedbRecoveryStore::persist_kernel_restart_reconciliation` moves the affected
//! generation in that owner inside the very transaction that appends its
//! escalation row. Check 7 is therefore decidable today and is proved by
//! `a_missing_manifest_degrades_the_generation_and_refuses_every_restart_of_it`:
//! no lifecycle row, then a manifest refusal, then
//! `load_observed_generation_lifecycle` reading `Degraded`, then
//! `admits_launch()` and `admits_new_effect_leases()` both false, and then a
//! restart request for that same generation refused. The old test's
//! `is_degraded()` call only restated "this decision admitted nothing", which is
//! a property of the decision rather than of the generation, and it is replaced
//! rather than kept.
//!
//! ## What check 8 can and cannot observe, stated exactly
//!
//! The restart-refusal family appends under
//! `{module_id}::{generation:020}::{attempt:020}` and
//! `RedbRecoveryStore::load_kernel_restart_reconciliation` resolves ONLY the
//! newest attempt. Check 8 does NOT use the public row counter
//! `RedbRecoveryStore::count_kernel_restart_reconciliations`, which reports that
//! family's row count over exactly the keys this reader can read; the two cases
//! that prove the append/idempotence half of audit check 5 use that counter
//! instead, because "nothing was appended" is what they assert. Check 8 itself
//! observes the row COUNT through this reader as the NEWEST recorded row, which
//! is a function of the count, and never by comparing two decoded rows with each
//! other:
//!
//! * the same cause observed twice at two different clocks keeps the FIRST
//!   recorded clock on the newest row, because a second row would be the newest
//!   one and would carry the second clock — so exactly one row exists;
//! * a differently-caused second refusal becomes the newest row with its own
//!   clock, so a second row exists beside the first;
//! * the FIRST cause survives, which is read through the lifecycle owner
//!   (`GenerationLifecycleRecord::first_refusal_cause`) rather than through the
//!   newest-only reader, and re-observing it leaves the second cause newest.

use std::error::Error;
use std::num::NonZeroU64;

use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ors::test_support::KernelRouteStoreFixture;
use eliot_ors::{
    AdmittedModuleGeneration, CapabilityRouteScope, CatalogPolicyView, CompatibilityEvidence,
    CompatibilityRefusal, EffectDeliveryAcknowledgement, EffectOperationLease,
    EffectOperationLeaseAdmission, GenerationDisposition, GenerationLifecycleRecord,
    GovernorAdmissionReceipt, GovernorGenerationAdmissionSeal,
    GovernorGenerationAdmissionSealParts, KernelExactEffectReplayRequest, KernelExecutionManifest,
    KernelExecutionProjection, KernelExecutionRestartRequest, KernelLaunchBinding,
    KernelReconciliationItem, KernelReconciliationKind, KernelServiceAdmission,
    LifecycleAdmissionDisposition, ManifestDependencyEntry, ManifestEffectCeiling,
    ManifestResourceLimits, ManifestRestartBudget, ObservedGenerationLifecycle, OperationIdentity,
    OrsError, RedbRecoveryStore, RestartAuthorizationClass, RevocationAcknowledgement,
    StateFenceSnapshot, StateMigrationDecision, verify_exact_effect_replay,
    verify_kernel_execution_restart,
};

const MODULE_ID: &str = "module-ors-1884";
const OTHER_MODULE_ID: &str = "module-ors-1884-other";
const GENERATION: u64 = 1;
const EPOCH_SEQUENCE: u64 = 1;
const CATALOG_REVISION: u64 = 7;
const POLICY_REVISION: u64 = 11;
const LINEAGE_ID: &str = "550e8400-e29b-41d4-a716-446655440188";
const OBSERVED_AT_MS: i64 = 1_700_000_000_000;
const ADMISSION_OPERATION_ID: &str = "operation-ors-1884-admission";
const ADMISSION_IDEMPOTENCY_KEY: &str = "idempotency-ors-1884-admission";

/// A non-blank invented RECEIPT text, i.e. an issuer-evidence value that is
/// well-formed prose rather than a digest. It is refused on its own shape, which
/// is the first half of check 1.
const INVENTED_RECEIPT_TEXT: &str = "receipt-oracle-1884-invented-non-blank";

/// A different Job Object policy TOKEN from the one the receipted read/rebuild
/// fixture records (`read_rebuild_projection` records `job-object-1884`). It is
/// non-blank, so `ManifestResourceLimits::validate` accepts the limits carrying
/// it and the refusal it provokes is a substitution rather than a bad shape.
const SUBSTITUTED_JOB_OBJECT_POLICY: &str = "job-object-1884-substituted";

/// Durable record types the typed refusals below are matched against.
const SEAL_RECORD_TYPE: &str = "kernel_execution_manifest_governor_admission_seal";
const RECEIPT_RECORD_TYPE: &str = "governor_admission_receipt";
const MANIFEST_RECORD_TYPE: &str = "kernel_execution_manifest";

/// The exact recorded refusal reasons this file asserts. Each is a `&'static
/// str` the crate itself records, so a changed reason fails the test instead of
/// being silently accepted.
const REASON_SEAL_IDENTITY: &str = "the sealed admission names a different module or generation";
const REASON_RECEIPT_NOT_BINDING: &str =
    "the recorded owner canonical digest does not bind the receipt's own fields";
const REASON_RECEIPT_ABSENT_PREFIX: &str = "GovernorAdmissionSealAbsent:";
const REASON_IDENTITY_CONFLICT_PREFIX: &str = "IDENTITY_CONFLICT:";
const REASON_NOT_A_DIGEST: &str = "must be a lowercase SHA-256 digest";
const FIELD_ACCEPTED_DIGEST: &str = "governor_admission_receipt_accepted_manifest_sha256";
const REASON_ACCEPTED_DIGEST_MISMATCH: &str =
    "must equal the sealed admission's accepted-manifest digest";
const FIELD_OWNER_DIGEST: &str = "governor_admission_receipt_owner_canonical_sha256";
const FIELD_EFFECT_CEILING: &str = "kernel_execution_manifest_effect_ceiling";
const REASON_CEILING_EXCEEDED: &str = "must not exceed the admitted effect ceiling";
const FIELD_ALLOWED_SCOPES: &str = "kernel_execution_manifest_allowed_scopes";
const REASON_SCOPES_NOT_ADMITTED: &str = "must be a subset of the admitted route scopes";

/// A 64-lowercase-hex placeholder of a recorded digest. These are fixture
/// coordinates, never computed digests: the only digests that carry meaning in
/// this file are the ones the crate itself computes.
fn hex_digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

/// Captures the real provider State Fence through the crate's own capture.
fn fence_snapshot() -> Result<StateFenceSnapshot, Box<dyn Error>> {
    let lineage = EpochLineageId::new(LINEAGE_ID)?;
    let epoch = EpochId::new(
        lineage,
        NonZeroU64::new(EPOCH_SEQUENCE).ok_or("1884: the epoch sequence must be non-zero")?,
    )?;
    let fence = StateFence::new(epoch, ResourceGeneration::new(GENERATION)?);
    Ok(StateFenceSnapshot::capture(&fence, EPOCH_SEQUENCE)?)
}

/// Builds the owner parts and computes the owner digest with the canonical
/// function the seal verifies against, so no fixture is self-consistent in the
/// wrong way. The three bounds are stated here because they are sealed fields
/// as well as record fields, and the record derived from these parts below can
/// therefore never disagree with the seal about them.
fn admission_seal_parts(
    module_id: &str,
    generation: u64,
    accepted_manifest_sha256: String,
    restart_authorization_class: RestartAuthorizationClass,
    admitted_effect_ceiling: ManifestEffectCeiling,
    admitted_allowed_scopes: Vec<CapabilityRouteScope>,
) -> Result<GovernorGenerationAdmissionSealParts, Box<dyn Error>> {
    let mut parts = GovernorGenerationAdmissionSealParts {
        operation_id: OperationIdentity::new(ADMISSION_OPERATION_ID)?,
        idempotency_key: ADMISSION_IDEMPOTENCY_KEY.to_owned(),
        module_id: module_id.to_owned(),
        generation: ResourceGeneration::new(generation)?,
        catalog_revision: CATALOG_REVISION,
        policy_revision: POLICY_REVISION,
        accepted_manifest_sha256,
        state_fence: fence_snapshot()?,
        lifecycle_disposition: LifecycleAdmissionDisposition::Admitted,
        restart_authorization_class,
        admitted_effect_ceiling,
        admitted_allowed_scopes,
        owner_canonical_sha256: String::new(),
    };
    parts.owner_canonical_sha256 = GovernorGenerationAdmissionSeal::canonical_sha256(&parts)?;
    Ok(parts)
}

fn read_rebuild_parts(
    module_id: &str,
    generation: u64,
    accepted_manifest_sha256: String,
) -> Result<GovernorGenerationAdmissionSealParts, Box<dyn Error>> {
    admission_seal_parts(
        module_id,
        generation,
        accepted_manifest_sha256,
        RestartAuthorizationClass::ReadRebuild,
        ManifestEffectCeiling::ReadRebuild,
        Vec::new(),
    )
}

fn effect_exact_lease_parts(
    scope: &CapabilityRouteScope,
) -> Result<GovernorGenerationAdmissionSealParts, Box<dyn Error>> {
    admission_seal_parts(
        MODULE_ID,
        GENERATION,
        hex_digest('a'),
        RestartAuthorizationClass::EffectExactLease,
        ManifestEffectCeiling::EffectExactLease,
        vec![scope.clone()],
    )
}

/// The one canonical seal constructor, applied to already-digested parts.
fn seal_of(
    parts: &GovernorGenerationAdmissionSealParts,
) -> Result<GovernorGenerationAdmissionSeal, Box<dyn Error>> {
    Ok(GovernorGenerationAdmissionSeal::seal(parts.clone())?)
}

/// The one canonical owner receipt constructor, over exactly the parts the seal
/// was sealed from.
fn receipt_of(
    parts: &GovernorGenerationAdmissionSealParts,
) -> Result<GovernorAdmissionReceipt, Box<dyn Error>> {
    Ok(GovernorAdmissionReceipt::issue(parts, OBSERVED_AT_MS)?)
}

/// Derives the admitted record from the sealed parts, so the record's own class,
/// ceiling and scope set are the sealed ones by construction.
fn admission_from_parts(
    parts: &GovernorGenerationAdmissionSealParts,
) -> Result<AdmittedModuleGeneration, Box<dyn Error>> {
    Ok(AdmittedModuleGeneration {
        module_id: parts.module_id.clone(),
        generation: parts.generation,
        authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        catalog_revision: parts.catalog_revision,
        policy_revision: parts.policy_revision,
        governor_admission_seal: seal_of(parts)?,
        restart_authorization_class: parts.restart_authorization_class,
        admitted_effect_ceiling: parts.admitted_effect_ceiling,
        admitted_allowed_scopes: parts.admitted_allowed_scopes.clone(),
    })
}

/// The same record carrying a seal that is NOT its own, which is how a receipt
/// issued for another generation reaches this generation's ingress.
fn admission_with_seal(
    parts: &GovernorGenerationAdmissionSealParts,
    seal: GovernorGenerationAdmissionSeal,
) -> Result<AdmittedModuleGeneration, Box<dyn Error>> {
    let mut admission = admission_from_parts(parts)?;
    admission.governor_admission_seal = seal;
    Ok(admission)
}

/// The technical execution projection every fixture starts from. Every recorded
/// field is filled from its real constructor; none is defaulted.
fn read_rebuild_projection() -> KernelExecutionProjection {
    KernelExecutionProjection {
        artifact_sha256: hex_digest('a'),
        config_sha256: hex_digest('b'),
        protocol_sha256: hex_digest('c'),
        start_command: "eliot-module-1884 --serve".to_owned(),
        dependency_order: vec![ManifestDependencyEntry {
            module_id: "module-ors-1884-dependency".to_owned(),
            startup_order: 0,
        }],
        resource_limits: ManifestResourceLimits {
            job_object_policy: "job-object-1884".to_owned(),
            max_processes: 4,
            max_working_set_bytes: 1_073_741_824,
            cpu_rate_control_percent: 80,
        },
        health_readiness_contract_ref: "readiness-contract-1884".to_owned(),
        restart_budget: ManifestRestartBudget {
            max_restarts: 3,
            quarantine_rule: "quarantine-1884".to_owned(),
        },
        effect_ceiling: ManifestEffectCeiling::ReadRebuild,
        allowed_scopes: Vec::new(),
        state_class_behavior: StateMigrationDecision::RebuildFromSnapshot,
    }
}

fn declared_scope() -> Result<CapabilityRouteScope, Box<dyn Error>> {
    Ok(CapabilityRouteScope::declare(
        MODULE_ID,
        "restart",
        "work-scope-1884",
        "effect-domain-1884",
    )?)
}

fn foreign_scope() -> Result<CapabilityRouteScope, Box<dyn Error>> {
    Ok(CapabilityRouteScope::declare(
        MODULE_ID,
        "not-admitted-capability",
        "work-scope-1884",
        "effect-domain-1884",
    )?)
}

fn effect_exact_lease_projection(scope: &CapabilityRouteScope) -> KernelExecutionProjection {
    let base = read_rebuild_projection();
    KernelExecutionProjection {
        effect_ceiling: ManifestEffectCeiling::EffectExactLease,
        allowed_scopes: vec![scope.clone()],
        ..base
    }
}

fn effect_exact_lease_manifest(
    scope: &CapabilityRouteScope,
) -> Result<KernelExecutionManifest, Box<dyn Error>> {
    let parts = effect_exact_lease_parts(scope)?;
    Ok(KernelExecutionManifest::admit(
        admission_from_parts(&parts)?,
        effect_exact_lease_projection(scope),
    )?)
}

/// An in-memory read/rebuild manifest, used only to source the request's own
/// observed launch coordinates where no row is recorded at all.
fn read_rebuild_manifest() -> Result<KernelExecutionManifest, Box<dyn Error>> {
    let parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    Ok(KernelExecutionManifest::admit(
        admission_from_parts(&parts)?,
        read_rebuild_projection(),
    )?)
}

/// Records the canonical owner receipt and then the manifest, exactly in the
/// order the Governor accept path uses, and returns the recorded row.
fn persist_receipted_read_rebuild_manifest(
    store: &RedbRecoveryStore,
) -> Result<KernelExecutionManifest, Box<dyn Error>> {
    let parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    let receipt = receipt_of(&parts)?;
    receipt.verify_seal(&seal_of(&parts)?)?;
    store.persist_governor_admission_receipt(&receipt)?;
    let recorded = store.persist_admitted_kernel_execution_manifest(
        &admission_from_parts(&parts)?,
        &read_rebuild_projection(),
    )?;
    let manifest = recorded_manifest(store, MODULE_ID, GENERATION)?;
    manifest.validate()?;
    if manifest.manifest_sha256 != recorded {
        return Err("1884: the persisted digest must be the recorded row's own identity".into());
    }
    Ok(manifest)
}

fn persist_receipted_effect_exact_lease_manifest(
    store: &RedbRecoveryStore,
    scope: &CapabilityRouteScope,
) -> Result<KernelExecutionManifest, Box<dyn Error>> {
    let parts = effect_exact_lease_parts(scope)?;
    store.persist_governor_admission_receipt(&receipt_of(&parts)?)?;
    let recorded = store.persist_admitted_kernel_execution_manifest(
        &admission_from_parts(&parts)?,
        &effect_exact_lease_projection(scope),
    )?;
    let manifest = recorded_manifest(store, MODULE_ID, GENERATION)?;
    manifest.validate()?;
    if manifest.manifest_sha256 != recorded {
        return Err("1884: the persisted digest must be the recorded row's own identity".into());
    }
    Ok(manifest)
}

/// Reads the recorded row and requires one, so a test never reads a manifest it
/// believes was persisted without the store confirming it.
fn recorded_manifest(
    store: &RedbRecoveryStore,
    module_id: &str,
    generation: u64,
) -> Result<KernelExecutionManifest, Box<dyn Error>> {
    store
        .load_kernel_execution_manifest(module_id, generation)?
        .ok_or_else(|| -> Box<dyn Error> {
            "1884: the recorded execution manifest must be readable".into()
        })
}

/// Reads the recorded lifecycle row and requires one. `None` from the store is
/// the honest absence of any recorded observation and is never a disposition.
fn recorded_lifecycle(
    store: &RedbRecoveryStore,
    module_id: &str,
    generation: u64,
) -> Result<GenerationLifecycleRecord, Box<dyn Error>> {
    store
        .load_generation_lifecycle(module_id, generation)?
        .ok_or_else(|| -> Box<dyn Error> {
            "1884: the recorded generation lifecycle row must be readable".into()
        })
}

/// Composes the one lifecycle observation a gate is allowed to read, from the
/// store's own durable readback and the manifest it is offered against. There is
/// no other construction path, so no fixture can invent an observation.
fn observed_lifecycle(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
) -> Result<ObservedGenerationLifecycle, Box<dyn Error>> {
    let record = store.load_generation_lifecycle(
        manifest.admission.module_id.as_str(),
        manifest.admission.generation.value(),
    )?;
    Ok(ObservedGenerationLifecycle::compose(record, manifest)?)
}

/// The one exact, unexpired operation lease an effect-capable manifest may hold.
fn effect_lease_admission(
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
    generation_lifecycle: ObservedGenerationLifecycle,
) -> Result<EffectOperationLeaseAdmission, Box<dyn Error>> {
    Ok(EffectOperationLeaseAdmission {
        lease_id: OperationIdentity::new("lease-ors-1884-exact-effect")?,
        operation_id: OperationIdentity::new("operation-ors-1884-exact-effect")?,
        effect_receipt_sha256: hex_digest('7'),
        allowed_scope: scope.clone(),
        authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        catalog_revision: manifest.admission.catalog_revision,
        policy_revision: manifest.admission.policy_revision,
        revocation: RevocationAcknowledgement::None,
        delivery: EffectDeliveryAcknowledgement::Acknowledged,
        generation_lifecycle,
        issued_at_ms: OBSERVED_AT_MS,
        expires_at_ms: OBSERVED_AT_MS + 60_000,
    })
}

fn issue_exact_effect_lease(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
) -> Result<EffectOperationLease, Box<dyn Error>> {
    Ok(EffectOperationLease::issue(
        manifest,
        effect_lease_admission(manifest, scope, observed_lifecycle(store, manifest)?)?,
    )?)
}

fn exact_effect_replay_request(
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
    lease: &EffectOperationLease,
    operation_id: OperationIdentity,
    observed_at_ms: i64,
    generation_lifecycle: ObservedGenerationLifecycle,
) -> Result<KernelExactEffectReplayRequest, Box<dyn Error>> {
    Ok(KernelExactEffectReplayRequest {
        operation_id,
        lease_id: lease.lease_id.clone(),
        module_id: manifest.admission.module_id.clone(),
        generation: manifest.admission.generation,
        bound_manifest_sha256: manifest.manifest_sha256.clone(),
        effect_receipt_sha256: lease.effect_receipt_sha256.clone(),
        allowed_scope: scope.clone(),
        authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        current_catalog_revision: CATALOG_REVISION,
        current_policy_revision: POLICY_REVISION,
        catalog_view: CatalogPolicyView::Current,
        revocation: RevocationAcknowledgement::None,
        delivery: EffectDeliveryAcknowledgement::Acknowledged,
        generation_lifecycle,
        observed_at_ms,
    })
}

/// The I1.12 verdict the request validator requires, bound to the manifest's own
/// generation.
fn compatibility_evidence(generation: u64) -> Result<CompatibilityEvidence, Box<dyn Error>> {
    Ok(CompatibilityEvidence::new(
        1,
        1,
        1,
        hex_digest('d'),
        1,
        1,
        hex_digest('9'),
        hex_digest('8'),
        generation,
        LINEAGE_ID,
        EPOCH_SEQUENCE,
        Vec::new(),
        Vec::new(),
        "retain_compatible",
        Some(1),
        Some(1),
        None,
    )?)
}

/// The same I1.12 shape, refused, so an incompatible candidate is expressible.
fn refused_compatibility_evidence(
    generation: u64,
) -> Result<CompatibilityEvidence, Box<dyn Error>> {
    let refusal = CompatibilityRefusal::new(
        "canonical_format",
        "the candidate offers no overlapping canonical format",
        OBSERVED_AT_MS,
    )?;
    Ok(CompatibilityEvidence::new(
        1,
        1,
        1,
        hex_digest('d'),
        1,
        1,
        hex_digest('9'),
        hex_digest('8'),
        generation,
        LINEAGE_ID,
        EPOCH_SEQUENCE,
        Vec::new(),
        Vec::new(),
        "retain_compatible",
        Some(1),
        Some(1),
        Some(refusal),
    )?)
}

/// One restart request carrying the manifest's own recorded values for every
/// launch coordinate, so a refusal is always about the ONE coordinate the test
/// changed and never about an unrelated mismatch.
fn restart_request(
    module_id: &str,
    manifest: &KernelExecutionManifest,
    catalog_view: CatalogPolicyView,
) -> Result<KernelExecutionRestartRequest, Box<dyn Error>> {
    Ok(KernelExecutionRestartRequest {
        module_id: module_id.to_owned(),
        generation: manifest.admission.generation,
        bound_manifest_sha256: manifest.manifest_sha256.clone(),
        candidate: manifest.launch_binding(),
        candidate_dependency_order: manifest.projection.dependency_order.clone(),
        // Both coordinates are OBSERVATIONS, not required values: the two that
        // have no observing owner arrive as `None` and the decision refuses
        // them with their own unobserved kinds. A request that states what the
        // manifest records is therefore `Some` of the manifest's own values.
        candidate_resource_limits: Some(manifest.projection.resource_limits.clone()),
        candidate_health_readiness_contract_ref: Some(
            manifest.projection.health_readiness_contract_ref.clone(),
        ),
        candidate_restart_budget: manifest.projection.restart_budget.clone(),
        current_authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        current_catalog_revision: CATALOG_REVISION,
        current_policy_revision: POLICY_REVISION,
        catalog_view,
        revocation: RevocationAcknowledgement::None,
        delivery: EffectDeliveryAcknowledgement::Acknowledged,
        compatibility: compatibility_evidence(manifest.admission.generation.value())?,
        restarts_spent: 0,
        observed_at_ms: OBSERVED_AT_MS,
    })
}

/// Cause A of the refusal history: the recorded candidate carries refused I1.12
/// evidence.
fn cause_a_request(
    manifest: &KernelExecutionManifest,
    observed_at_ms: i64,
) -> Result<KernelExecutionRestartRequest, Box<dyn Error>> {
    let mut request = restart_request(MODULE_ID, manifest, CatalogPolicyView::Current)?;
    request.compatibility = refused_compatibility_evidence(manifest.admission.generation.value())?;
    request.observed_at_ms = observed_at_ms;
    Ok(request)
}

/// Cause B of the refusal history: a differently-caused refusal of the SAME
/// `{module_id, generation}`, so it lands under the same identity prefix.
fn cause_b_request(
    manifest: &KernelExecutionManifest,
    observed_at_ms: i64,
) -> Result<KernelExecutionRestartRequest, Box<dyn Error>> {
    let mut request = restart_request(MODULE_ID, manifest, CatalogPolicyView::Current)?;
    "eliot-module-1884 --other".clone_into(&mut request.candidate.start_command);
    request.observed_at_ms = observed_at_ms;
    Ok(request)
}

/// The recorded reason of one integrity refusal, or `None` when the failure is
/// not one. A refusal is proved by its recorded type and reason, never by the
/// mere absence of success.
fn integrity_reason<'a>(error: &'a OrsError, record_type: &str) -> Option<&'a str> {
    match error {
        OrsError::IntegrityProblem {
            record_type: recorded,
            reason,
        } if *recorded == record_type => Some(reason.as_str()),
        _ => None,
    }
}

/// The typed field refusal one construction refusal recorded, or `None` when the
/// failure is not one.
fn invalid_field(error: &OrsError) -> Option<(&'static str, &'static str)> {
    match error {
        OrsError::InvalidField { field, reason } => Some((*field, *reason)),
        _ => None,
    }
}

/// The single durable refusal kind one decision recorded. An unexpected item
/// count fails the test rather than being folded into an expected kind.
fn only_reconciliation_kind(items: &[KernelReconciliationItem]) -> KernelReconciliationKind {
    assert_eq!(
        items.len(),
        1,
        "1884: exactly one durable refusal item is recorded"
    );
    items[0].kind
}

/// Asserts that each of the four launch-binding coordinates a caller could
/// substitute is refused on the exact recorded binding.
fn assert_changed_launch_binding_coordinates_block_launch(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
) -> Result<(), Box<dyn Error>> {
    let recorded = manifest.launch_binding();
    let candidates = [
        (
            "artifact_sha256",
            KernelLaunchBinding {
                artifact_sha256: hex_digest('e'),
                ..recorded.clone()
            },
        ),
        (
            "config_sha256",
            KernelLaunchBinding {
                config_sha256: hex_digest('e'),
                ..recorded.clone()
            },
        ),
        (
            "protocol_sha256",
            KernelLaunchBinding {
                protocol_sha256: hex_digest('e'),
                ..recorded.clone()
            },
        ),
        (
            "start_command",
            KernelLaunchBinding {
                start_command: "eliot-module-1884 --other".to_owned(),
                ..recorded.clone()
            },
        ),
    ];
    for (field, candidate) in candidates {
        let mut request = restart_request(MODULE_ID, manifest, CatalogPolicyView::Current)?;
        request.candidate = candidate;
        let refused = store.load_and_verify_kernel_execution_restart(&request)?;
        assert!(
            matches!(refused.admission, KernelServiceAdmission::None),
            "1884: a changed {field} must block the launch"
        );
        assert_eq!(
            only_reconciliation_kind(&refused.reconciliation),
            KernelReconciliationKind::ManifestCandidateBindingMismatch,
            "1884: a changed {field} is refused on the exact recorded launch binding"
        );
    }
    Ok(())
}

/// Asserts that one substituted request-side coordinate is refused as itself,
/// through the store-backed restart entry point.
fn assert_changed_coordinate_blocks_launch(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
    coordinate: &str,
    expected: KernelReconciliationKind,
    substitute: impl Fn(&mut KernelExecutionRestartRequest),
) -> Result<(), Box<dyn Error>> {
    let mut request = restart_request(MODULE_ID, manifest, CatalogPolicyView::Current)?;
    substitute(&mut request);
    let refused = store.load_and_verify_kernel_execution_restart(&request)?;
    assert!(
        matches!(refused.admission, KernelServiceAdmission::None),
        "1884: a changed {coordinate} must block the launch"
    );
    assert_eq!(
        only_reconciliation_kind(&refused.reconciliation),
        expected,
        "1884: a changed {coordinate} is refused as that coordinate and not as another"
    );
    Ok(())
}

/// Asserts that the general restart of an effect-capable generation never opens
/// a normal `EffectService` while the Module Catalog/Policy view is not current,
/// both at the class predicate where that rule is decided and at the restart
/// verifier, and that the same manifest does open one on a current view so the
/// refusal above is about the stale view and nothing else.
fn assert_stale_view_never_opens_a_general_effect_service(
    manifest: &KernelExecutionManifest,
) -> Result<(), Box<dyn Error>> {
    for class in [
        RestartAuthorizationClass::EffectExactLease,
        RestartAuthorizationClass::CurrentCatalogRequired,
    ] {
        assert!(
            !class.admits_normal_effect_service(CatalogPolicyView::Stale),
            "1884: {class:?} must not admit normal-effect service on a stale view"
        );
        assert!(
            !class.admits_normal_effect_service(CatalogPolicyView::Unavailable),
            "1884: {class:?} must not admit normal-effect service on an unavailable view"
        );
        assert!(
            class.admits_normal_effect_service(CatalogPolicyView::Current),
            "1884: {class:?} admits normal-effect service only on a current view"
        );
    }

    let stale = verify_kernel_execution_restart(
        Some(manifest),
        &restart_request(MODULE_ID, manifest, CatalogPolicyView::Stale)?,
    )?;
    assert!(
        matches!(
            stale.admission,
            KernelServiceAdmission::ShadowDiagnosticsOnly(_)
        ),
        "1884: a stale view caps an effect_exact_lease generation at shadow diagnostics"
    );
    assert_eq!(
        only_reconciliation_kind(&stale.reconciliation),
        KernelReconciliationKind::ManifestCatalogPolicyStale,
        "1884: the general restart is refused for the stale view"
    );

    let current = verify_kernel_execution_restart(
        Some(manifest),
        &restart_request(MODULE_ID, manifest, CatalogPolicyView::Current)?,
    )?;
    assert!(
        matches!(current.admission, KernelServiceAdmission::EffectService(_)),
        "1884: the same manifest does open a general EffectService on a current view"
    );
    assert!(
        current.reconciliation.is_empty(),
        "1884: that current-view admission escalates nothing"
    );
    Ok(())
}

/// Asserts that the only effect authority any seam reaches is the one exact,
/// unexpired leased operation.
fn assert_only_the_exact_unexpired_leased_operation_is_authorized(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
) -> Result<(), Box<dyn Error>> {
    let lease = issue_exact_effect_lease(store, manifest, scope)?;
    let exact = exact_effect_replay_request(
        manifest,
        scope,
        &lease,
        lease.operation_id.clone(),
        OBSERVED_AT_MS,
        observed_lifecycle(store, manifest)?,
    )?;

    // A NEW operation: no lease record at all is supplied for it.
    let names_no_lease = exact_effect_replay_request(
        manifest,
        scope,
        &lease,
        OperationIdentity::new("operation-ors-1884-new-effect")?,
        OBSERVED_AT_MS,
        observed_lifecycle(store, manifest)?,
    )?;
    let denied = verify_exact_effect_replay(Some(manifest), None, &names_no_lease)?;
    assert!(
        denied.authorized_lease.is_none(),
        "1884: a new operation names no lease record and is refused"
    );
    assert_eq!(
        only_reconciliation_kind(&denied.reconciliation),
        KernelReconciliationKind::EffectLeaseIdentityAbsent,
        "1884: only an exact unexpired leased operation is permitted"
    );

    // The exact unexpired leased operation, and no general effect authority.
    let admitted = verify_exact_effect_replay(Some(manifest), Some(&lease), &exact)?;
    let authority = admitted
        .authorized_lease
        .as_ref()
        .ok_or("1884: the exact unexpired leased operation must be admitted")?;
    assert!(
        admitted.reconciliation.is_empty(),
        "1884: an admitted exact replay escalates nothing"
    );
    assert_eq!(authority.lease_id(), &lease.lease_id);
    assert_eq!(authority.operation_id(), &lease.operation_id);
    assert_eq!(
        authority.allowed_scope_hash(),
        scope.route_scope_hash.as_str()
    );
    assert_eq!(
        authority.bound_manifest_sha256(),
        manifest.manifest_sha256.as_str()
    );

    // The same lease authorizes no other operation.
    let other_operation = exact_effect_replay_request(
        manifest,
        scope,
        &lease,
        OperationIdentity::new("operation-ors-1884-another-effect")?,
        OBSERVED_AT_MS,
        observed_lifecycle(store, manifest)?,
    )?;
    let refused = verify_exact_effect_replay(Some(manifest), Some(&lease), &other_operation)?;
    assert!(refused.authorized_lease.is_none());
    assert_eq!(
        only_reconciliation_kind(&refused.reconciliation),
        KernelReconciliationKind::EffectOperationIdentityMismatch,
        "1884: the lease authorizes its own operation only"
    );

    // And it authorizes nothing once it has expired.
    let after_expiry = exact_effect_replay_request(
        manifest,
        scope,
        &lease,
        lease.operation_id.clone(),
        lease.expires_at_ms + 1,
        observed_lifecycle(store, manifest)?,
    )?;
    let expired = verify_exact_effect_replay(Some(manifest), Some(&lease), &after_expiry)?;
    assert!(expired.authorized_lease.is_none());
    assert_eq!(
        only_reconciliation_kind(&expired.reconciliation),
        KernelReconciliationKind::EffectLeaseExpired,
        "1884: an expired lease authorizes nothing"
    );
    Ok(())
}

/// Asserts what the PRODUCTION store-backed effect gate does with an operation
/// no recorded lease covers. It is the seam
/// `ProcessExecutionGateway::require_effect_replay_authority` reaches, so this is
/// the effect-dispatch gate and not a fixture-only verifier.
fn assert_the_production_gate_authorizes_no_unleased_operation(
    store: &RedbRecoveryStore,
) -> Result<(), Box<dyn Error>> {
    let unleased_operation = OperationIdentity::new("operation-ors-1884-unleased")?;
    let gated = store.authorize_effect_replay_for_operation(
        &unleased_operation,
        MODULE_ID,
        GENERATION,
        AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        OBSERVED_AT_MS,
    )?;
    assert!(
        gated.authority.authorized_lease().is_none(),
        "1884: the production effect gate authorizes no operation no lease covers"
    );
    let item = gated
        .reconciliation
        .as_ref()
        .ok_or("1884: the production gate must escalate its refusal durably")?;
    item.validate()?;
    assert_eq!(
        item.kind,
        KernelReconciliationKind::EffectLeaseAbsent,
        "1884: the production gate refuses an unleased operation outright"
    );
    assert_eq!(item.operation_id.as_ref(), Some(&unleased_operation));
    Ok(())
}

/// Audit check 3: a receipt issued from the same parts the seal was sealed from
/// persists the exact Generation Registry copy, and a MISSING canonical receipt
/// refuses that same manifest before any row exists.
///
/// The ORS half of the chain is proved here; see the module documentation for
/// where the Governor half lives and why it is not exercised from this crate.
#[test]
fn a_receipt_issued_from_the_sealed_parts_persists_the_exact_generation_registry_copy()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-governor-copy")?;
    let store = fixture.store().as_ref();
    let parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    let seal = seal_of(&parts)?;
    let receipt = receipt_of(&parts)?;
    receipt.validate()?;
    receipt.verify_seal(&seal)?;
    let stored_receipt = store.persist_governor_admission_receipt(&receipt)?;
    assert_eq!(
        stored_receipt.receipt_sha256()?,
        receipt.receipt_sha256()?,
        "1884: the canonical owner receipt is recorded with its own integrity digest"
    );

    let recorded = store.persist_admitted_kernel_execution_manifest(
        &admission_from_parts(&parts)?,
        &read_rebuild_projection(),
    )?;
    let row = recorded_manifest(store, MODULE_ID, GENERATION)?;
    assert_eq!(
        row.manifest_sha256, recorded,
        "1884: the persisted digest is the recorded row's own identity"
    );
    assert_eq!(
        row.admission.governor_admission_seal.module_id(),
        MODULE_ID,
        "1884: the copy is recorded under the accepted module identity"
    );
    assert_eq!(
        row.admission.governor_admission_seal.generation().value(),
        GENERATION,
        "1884: the copy is recorded under the accepted generation identity"
    );
    assert_eq!(
        row.admission
            .governor_admission_seal
            .accepted_manifest_sha256(),
        hex_digest('a'),
        "1884: the copy keeps the owner's accepted-manifest digest verbatim"
    );
    assert_eq!(
        row.admission
            .governor_admission_seal
            .owner_canonical_sha256(),
        receipt.owner_canonical_sha256,
        "1884: the copy keeps the owner's canonical digest the receipt recorded"
    );
    assert_eq!(
        row.projection.artifact_sha256,
        hex_digest('a'),
        "1884: the copy records the exact admitted artifact digest"
    );

    // The negative half: the same manifest, with no canonical owner receipt.
    let bare_fixture = KernelRouteStoreFixture::open("1884-receiptless-manifest")?;
    let bare = bare_fixture.store().as_ref();
    let unrecorded_parts = read_rebuild_parts(OTHER_MODULE_ID, GENERATION, hex_digest('a'))?;
    let error = bare
        .persist_admitted_kernel_execution_manifest(
            &admission_from_parts(&unrecorded_parts)?,
            &read_rebuild_projection(),
        )
        .err()
        .ok_or("1884: a manifest with no canonical owner receipt must not be persisted")?;
    let reason = integrity_reason(&error, RECEIPT_RECORD_TYPE).ok_or(format!(
        "1884: expected a canonical-receipt refusal, got {error}"
    ))?;
    assert!(
        reason.starts_with(REASON_RECEIPT_ABSENT_PREFIX),
        "1884: the ingress refuses on the absent canonical owner receipt, got {reason}"
    );
    assert!(
        bare.load_governor_admission_receipt(&OperationIdentity::new(ADMISSION_OPERATION_ID)?)?
            .is_none(),
        "1884: no receipt was recorded for this admission's operation identity"
    );
    assert!(
        bare.load_kernel_execution_manifest(OTHER_MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the refused manifest wrote no row"
    );
    Ok(())
}

/// Audit check 1 and admission negative discriminator 1: an invented non-blank
/// receipt is recorded nowhere, and therefore persists no manifest.
///
/// The receipt's own fields are private-free but the record derives
/// `Deserialize` under `deny_unknown_fields`, so an invented issuer-evidence
/// value can only arrive the way a forged durable row arrives: through
/// `Deserialize`, which every persist and every readback re-checks.
#[test]
fn invented_non_blank_receipt_does_not_persist_a_manifest() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-invented-receipt")?;
    let store = fixture.store().as_ref();
    let parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    let genuine = receipt_of(&parts)?;

    // (a) a non-blank receipt TEXT in the issuer-evidence field.
    let mut text_value = serde_json::to_value(&genuine)?;
    text_value["owner_canonical_sha256"] =
        serde_json::Value::String(INVENTED_RECEIPT_TEXT.to_owned());
    let text_receipt: GovernorAdmissionReceipt = serde_json::from_value(text_value)?;
    let text_error = store
        .persist_governor_admission_receipt(&text_receipt)
        .err()
        .ok_or("1884: an invented non-blank receipt must not be recorded")?;
    assert_eq!(
        invalid_field(&text_error),
        Some((FIELD_OWNER_DIGEST, REASON_NOT_A_DIGEST)),
        "1884: invented receipt text is refused as not being a canonical digest"
    );

    // (b) an invented digest shape the receipt's own fields do not bind.
    let mut digest_value = serde_json::to_value(&genuine)?;
    digest_value["owner_canonical_sha256"] = serde_json::Value::String(hex_digest('f'));
    let digest_receipt: GovernorAdmissionReceipt = serde_json::from_value(digest_value)?;
    let digest_error = store
        .persist_governor_admission_receipt(&digest_receipt)
        .err()
        .ok_or("1884: an invented owner digest must not be recorded")?;
    assert_eq!(
        integrity_reason(&digest_error, RECEIPT_RECORD_TYPE),
        Some(REASON_RECEIPT_NOT_BINDING),
        "1884: the invented owner digest is refused because it does not bind the receipt's own fields"
    );

    // Neither invented receipt reached durable state ...
    assert!(
        store
            .load_governor_admission_receipt(&OperationIdentity::new(ADMISSION_OPERATION_ID)?)?
            .is_none(),
        "1884: both refusals happen before any ORS mutation"
    );
    // ... and the manifest is refused because no canonical owner receipt exists.
    let manifest_error = store
        .persist_admitted_kernel_execution_manifest(
            &admission_from_parts(&parts)?,
            &read_rebuild_projection(),
        )
        .err()
        .ok_or("1884: an invented receipt must not persist a manifest")?;
    let reason = integrity_reason(&manifest_error, RECEIPT_RECORD_TYPE).ok_or(format!(
        "1884: expected a canonical-receipt refusal, got {manifest_error}"
    ))?;
    assert!(
        reason.starts_with(REASON_RECEIPT_ABSENT_PREFIX),
        "1884: the ingress refuses on the absent canonical owner receipt, got {reason}"
    );
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: no manifest row exists for the invented receipt"
    );
    Ok(())
}

/// Admission negative discriminator 2: a receipt belonging to ANOTHER
/// generation must be refused before any manifest mutation.
#[test]
fn receipt_seal_for_another_generation_is_refused_before_any_ors_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-foreign-generation")?;
    let store = fixture.store().as_ref();
    let other_generation = GENERATION + 1;
    // The foreign seal is genuinely sealed by its own owner; it simply names
    // another generation than the record it is carried on.
    let foreign_parts = read_rebuild_parts(MODULE_ID, other_generation, hex_digest('a'))?;
    let foreign_seal = seal_of(&foreign_parts)?;
    assert_eq!(
        foreign_seal.generation().value(),
        other_generation,
        "1884: the foreign seal is a well-formed sealed admission for another generation"
    );
    // The only ORS mutation here is the canonical receipt row of the FOREIGN
    // admission, so the refusal below cannot be "no receipt at all".
    store.persist_governor_admission_receipt(&receipt_of(&foreign_parts)?)?;
    let stored_receipt = store
        .load_governor_admission_receipt(&OperationIdentity::new(ADMISSION_OPERATION_ID)?)?
        .ok_or("1884: the foreign canonical receipt must be readable")?;
    assert_eq!(
        stored_receipt.generation.value(),
        other_generation,
        "1884: the recorded receipt really is the foreign generation's"
    );

    let presented = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    let error = store
        .persist_admitted_kernel_execution_manifest(
            &admission_with_seal(&presented, foreign_seal)?,
            &read_rebuild_projection(),
        )
        .err()
        .ok_or("1884: a receipt of another generation must not persist a manifest")?;
    let reason = integrity_reason(&error, SEAL_RECORD_TYPE).ok_or(format!(
        "1884: expected a sealed-admission refusal, got {error}"
    ))?;
    assert_eq!(
        reason, REASON_SEAL_IDENTITY,
        "1884: the foreign receipt is refused as a module/generation mismatch"
    );
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the refusal happens before any manifest mutation"
    );
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, other_generation)?
            .is_none(),
        "1884: neither the presented nor the sealed generation records a row"
    );
    Ok(())
}

/// Admission negative discriminator 3: a receipt with the SAME text id but a
/// DIFFERENT manifest digest must not persist a manifest.
///
/// The binding lives in the durable canonical owner receipt, read and verified
/// against the seal field by field by
/// `RedbRecoveryStore::persist_admitted_kernel_execution_manifest` before any
/// manifest mutation.
#[test]
fn receipt_seal_with_the_same_text_id_and_a_different_manifest_digest_is_refused()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-reused-receipt-id")?;
    let store = fixture.store().as_ref();
    let first_parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    let second_parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('e'))?;
    let first = seal_of(&first_parts)?;
    let second = seal_of(&second_parts)?;
    assert_eq!(
        (
            first.operation_id().as_str(),
            first.module_id(),
            first.generation().value()
        ),
        (
            second.operation_id().as_str(),
            second.module_id(),
            second.generation().value()
        ),
        "1884: only the accepted manifest digest differs between the two seals"
    );
    // This is a genuine fixture sanity check, and it is load bearing: collapsing
    // these two digests would turn the second persist into an exact replay and
    // the test would stop discriminating a refused persist from an accepted one.
    assert_ne!(
        first.accepted_manifest_sha256(),
        second.accepted_manifest_sha256(),
        "1884: the two seals really do name different manifests"
    );

    store.persist_governor_admission_receipt(&receipt_of(&first_parts)?)?;
    let recorded = store.persist_admitted_kernel_execution_manifest(
        &admission_from_parts(&first_parts)?,
        &read_rebuild_projection(),
    )?;

    // Same operation text id, different recorded accepted-manifest digest: the
    // durable canonical receipt is the FIRST one and refuses the second seal.
    let error = store
        .persist_admitted_kernel_execution_manifest(
            &admission_from_parts(&second_parts)?,
            &read_rebuild_projection(),
        )
        .err()
        .ok_or("1884: a reused receipt text id must not persist another manifest")?;
    assert_eq!(
        invalid_field(&error),
        Some((FIELD_ACCEPTED_DIGEST, REASON_ACCEPTED_DIGEST_MISMATCH)),
        "1884: the second seal is refused against the stored canonical receipt"
    );
    let row = recorded_manifest(store, MODULE_ID, GENERATION)?;
    assert_eq!(
        row.manifest_sha256, recorded,
        "1884: the refused second persist mutated nothing"
    );
    assert_eq!(
        row.admission
            .governor_admission_seal
            .accepted_manifest_sha256(),
        hex_digest('a'),
        "1884: the stored row still records the first accepted manifest digest"
    );
    assert_eq!(
        store
            .load_governor_admission_receipt(&OperationIdentity::new(ADMISSION_OPERATION_ID)?)?
            .map(|receipt| receipt.accepted_manifest_sha256),
        Some(hex_digest('a')),
        "1884: the stored canonical receipt is still the first one"
    );
    Ok(())
}

/// Audit check 2: changed content under the same module/generation must not
/// overwrite the recorded row.
#[test]
fn changed_content_under_the_same_module_and_generation_does_not_overwrite_the_row()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-immutable-row")?;
    let store = fixture.store().as_ref();
    let parts = read_rebuild_parts(MODULE_ID, GENERATION, hex_digest('a'))?;
    store.persist_governor_admission_receipt(&receipt_of(&parts)?)?;
    let admission = admission_from_parts(&parts)?;
    let projection = read_rebuild_projection();
    let recorded = store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;

    // The same admitted identity with changed artifact bytes.
    let changed = KernelExecutionProjection {
        artifact_sha256: hex_digest('e'),
        ..projection.clone()
    };
    let error = store
        .persist_admitted_kernel_execution_manifest(&admission, &changed)
        .err()
        .ok_or("1884: changed content under the same module/generation must not be persisted")?;
    let reason = integrity_reason(&error, MANIFEST_RECORD_TYPE).ok_or(format!(
        "1884: expected a recorded identity conflict, got {error}"
    ))?;
    assert!(
        reason.starts_with(REASON_IDENTITY_CONFLICT_PREFIX),
        "1884: the changed row is refused, got {reason}"
    );

    // An exact re-persist of the same content is an idempotent replay.
    let replayed = store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;
    assert_eq!(
        replayed, recorded,
        "1884: an exact replay returns the recorded digest"
    );
    let row = recorded_manifest(store, MODULE_ID, GENERATION)?;
    row.validate()?;
    assert_eq!(
        row.manifest_sha256, recorded,
        "1884: the recorded row still holds the originally admitted manifest"
    );
    assert_eq!(
        row.projection.artifact_sha256,
        hex_digest('a'),
        "1884: the changed artifact never reached the immutable row"
    );
    Ok(())
}

/// Audit check 4: the restart entry points admit nothing without a recorded
/// manifest under any observed Module Catalog/Policy view, and admit a
/// recorded one only as that manifest's own sealed recorded binding.
///
/// The name says which entry points are exercised, not that EVERY restart in the
/// tree is covered: the body drives
/// `RedbRecoveryStore::load_and_verify_kernel_execution_restart` and the pure
/// `verify_kernel_execution_restart` it delegates to, and no production launch
/// primitive exists in this crate to drive instead.
#[test]
fn the_restart_entry_points_admit_only_a_recorded_sealed_manifest_and_its_recorded_binding()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-sealed-binding-required")?;
    let store = fixture.store().as_ref();
    let candidate = read_rebuild_manifest()?;

    // No recorded manifest: no view can substitute for a sealed bound manifest.
    for view in [
        CatalogPolicyView::Current,
        CatalogPolicyView::Stale,
        CatalogPolicyView::Unavailable,
    ] {
        let refused = verify_kernel_execution_restart(
            None,
            &restart_request(OTHER_MODULE_ID, &candidate, view)?,
        )?;
        assert!(
            matches!(refused.admission, KernelServiceAdmission::None),
            "1884: view {view:?} must not substitute for a sealed bound manifest"
        );
        assert!(
            refused.evidence.restart_authorization_class.is_none(),
            "1884: without a manifest no class is read, so no binding is issued"
        );
    }

    // The store-backed entry point starts nothing and leaves the refusal durable.
    let absent = store.load_and_verify_kernel_execution_restart(&restart_request(
        OTHER_MODULE_ID,
        &candidate,
        CatalogPolicyView::Current,
    )?)?;
    assert!(
        matches!(absent.admission, KernelServiceAdmission::None),
        "1884: no recorded manifest means no service is admitted"
    );
    assert_eq!(
        only_reconciliation_kind(&absent.reconciliation),
        KernelReconciliationKind::ManifestAbsent
    );
    assert!(
        store
            .load_kernel_restart_reconciliation(OTHER_MODULE_ID, GENERATION)?
            .is_some(),
        "1884: the store-backed refusal is durable"
    );

    // With the receipted manifest recorded, the SAME entry point admits the
    // restart only as the sealed recorded binding.
    let recorded = persist_receipted_read_rebuild_manifest(store)?;
    let decision = store.load_and_verify_kernel_execution_restart(&restart_request(
        MODULE_ID,
        &recorded,
        CatalogPolicyView::Current,
    )?)?;
    let KernelServiceAdmission::ReadRebuildService(binding) = &decision.admission else {
        return Err("1884: the recorded manifest must restart read/rebuild".into());
    };
    assert!(decision.reconciliation.is_empty());
    assert_eq!(binding.manifest_sha256(), recorded.manifest_sha256);
    assert_eq!(binding.launch_binding(), recorded.launch_binding());
    assert_eq!(
        binding.resource_limits(),
        &recorded.projection.resource_limits
    );
    assert_eq!(
        binding.restart_budget(),
        &recorded.projection.restart_budget
    );
    assert_eq!(
        binding.health_readiness_contract_ref(),
        recorded.projection.health_readiness_contract_ref.as_str()
    );
    Ok(())
}

/// Audit check 5, the four launch-binding coordinates: a changed artifact,
/// config or protocol digest, or a changed start command, each blocks the launch
/// on the exact recorded binding.
#[test]
fn changed_launch_binding_coordinates_block_the_launch() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-changed-binding")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;
    assert_changed_launch_binding_coordinates_block_launch(store, &manifest)
}

/// Audit check 5, the three remaining request-side coordinates: a substituted
/// Job Object/resource limit set, a substituted health/readiness contract
/// reference and a substituted bounded restart budget each block the launch and
/// are refused AS THEMSELVES, and a restart that has already spent the RECORDED
/// budget is refused as that spent budget rather than as a substitution.
///
/// This case is decidable today because `KernelExecutionRestartRequest` carries
/// all three observed values; an earlier delivery of this file ignored it on the
/// stated ground that no request-side input existed for them.
#[test]
fn changed_job_limits_readiness_contract_and_restart_budget_block_the_launch()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-changed-limits")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;

    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_resource_limits",
        KernelReconciliationKind::ManifestResourceLimitsMismatch,
        |request| {
            // The substitution is stated as an OBSERVED value, so the decision
            // compares it against the sealed binding and refuses the mismatch
            // itself. Dropping the observation instead would be the `unobserved`
            // kind, which is a different refusal and is proved elsewhere.
            request.candidate_resource_limits =
                request
                    .candidate_resource_limits
                    .as_ref()
                    .map(|limits| ManifestResourceLimits {
                        max_processes: limits.max_processes + 1,
                        ..limits.clone()
                    });
        },
    )?;
    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_health_readiness_contract_ref",
        KernelReconciliationKind::ManifestReadinessContractMismatch,
        |request| {
            request.candidate_health_readiness_contract_ref =
                Some("readiness-contract-1884-other".to_owned());
        },
    )?;
    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_restart_budget",
        KernelReconciliationKind::ManifestRestartBudgetMismatch,
        |request| request.candidate_restart_budget.max_restarts += 1,
    )?;

    // The recorded bounded budget itself, spent.
    let mut spent = restart_request(MODULE_ID, &manifest, CatalogPolicyView::Current)?;
    spent.restarts_spent = manifest.projection.restart_budget.max_restarts;
    let refused = store.load_and_verify_kernel_execution_restart(&spent)?;
    assert!(
        matches!(refused.admission, KernelServiceAdmission::None),
        "1884: a restart that has already spent the recorded budget must block the launch"
    );
    assert_eq!(
        only_reconciliation_kind(&refused.reconciliation),
        KernelReconciliationKind::ManifestRestartBudgetExhausted,
        "1884: the refusal names the SPENT recorded budget, not a substituted one"
    );
    Ok(())
}

/// Audit check 5, the one limit field nothing at the process edge could notice
/// being dropped: substituting the declared `job_object_policy` TOKEN ALONE —
/// every other limit and every other request coordinate equal to the recorded
/// ones — still blocks the launch and is refused as a resource-limits MISMATCH.
///
/// The other limits case in this file changes `max_processes`, which any process
/// adapter compares numerically anyway. The policy token is a policy identity
/// with no OS representation of its own, so a comparison of the limits that
/// omitted it would leave every other case in this file passing; the refusal
/// below is read through the production store entry point
/// `RedbRecoveryStore::load_and_verify_kernel_execution_restart` and is the only
/// evidence here that ORS compares that field.
#[test]
fn a_substituted_job_object_policy_token_alone_blocks_the_launch() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-substituted-job-object-policy")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;

    let recorded = manifest.projection.resource_limits.clone();
    let substituted = ManifestResourceLimits {
        job_object_policy: SUBSTITUTED_JOB_OBJECT_POLICY.to_owned(),
        ..recorded.clone()
    };
    // The substituted limits are a well-formed OBSERVATION, so the refusal below
    // is a substitution and not the request validator refusing the token's shape.
    substituted.validate()?;
    assert_ne!(
        substituted.job_object_policy, recorded.job_object_policy,
        "1884: the substituted token really is a different token"
    );
    assert_eq!(
        (
            substituted.max_processes,
            substituted.max_working_set_bytes,
            substituted.cpu_rate_control_percent
        ),
        (
            recorded.max_processes,
            recorded.max_working_set_bytes,
            recorded.cpu_rate_control_percent
        ),
        "1884: the substituted limits differ from the recorded ones in the policy token and in no other limit"
    );

    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_resource_limits.job_object_policy",
        KernelReconciliationKind::ManifestResourceLimitsMismatch,
        |request| request.candidate_resource_limits = Some(substituted.clone()),
    )
}

/// Audit check 5, the two coordinates a caller may state nothing about: an
/// unobserved Job Object limit set and an unobserved health/readiness contract
/// reference each block the launch under their OWN reconciliation kind, which is
/// a different kind from the mismatch above. So an omission is never recorded as
/// a substitution, and the substitution above is never recorded as an omission.
///
/// `KernelExecutionRestartRequest` makes both coordinates `Option` precisely so a
/// caller that cannot see one can say so instead of inventing a value for it;
/// these two refusals are what stops that honesty from becoming an admission.
#[test]
fn an_unobserved_job_limits_or_readiness_coordinate_is_refused_as_unobserved()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-unobserved-launch-coordinates")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;

    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_resource_limits",
        KernelReconciliationKind::ManifestResourceLimitsUnobserved,
        |request| request.candidate_resource_limits = None,
    )?;
    assert_changed_coordinate_blocks_launch(
        store,
        &manifest,
        "candidate_health_readiness_contract_ref",
        KernelReconciliationKind::ManifestReadinessContractUnobserved,
        |request| request.candidate_health_readiness_contract_ref = None,
    )
}

/// Audit check 5, the two bounds that are NOT launch-seam refusals: an effect
/// ceiling and a route-scope set beyond the sealed, admitted bounds are refused
/// at PERSIST time, by `KernelExecutionManifest::check_admitted_bounds` while
/// the manifest is being built. No manifest therefore exists for them at all, so
/// there is no launch binding to refuse later.
#[test]
fn a_projection_beyond_the_sealed_admitted_ceiling_or_scopes_is_refused_at_persist()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-admitted-bounds")?;
    let store = fixture.store().as_ref();
    let scope = declared_scope()?;

    // The seal, the record derived from it and the projection all state the
    // SAME admitted bounds, so the only defect left is the projection exceeding
    // them.
    let capped_parts = admission_seal_parts(
        MODULE_ID,
        GENERATION,
        hex_digest('a'),
        RestartAuthorizationClass::EffectExactLease,
        ManifestEffectCeiling::CandidateNoEffect,
        vec![scope.clone()],
    )?;
    let over_ceiling = KernelExecutionProjection {
        effect_ceiling: ManifestEffectCeiling::EffectExactLease,
        allowed_scopes: vec![scope.clone()],
        ..read_rebuild_projection()
    };
    let ceiling_error = store
        .persist_admitted_kernel_execution_manifest(
            &admission_from_parts(&capped_parts)?,
            &over_ceiling,
        )
        .err()
        .ok_or("1884: an effect ceiling above the sealed admitted ceiling must be refused")?;
    assert_eq!(
        invalid_field(&ceiling_error),
        Some((FIELD_EFFECT_CEILING, REASON_CEILING_EXCEEDED)),
        "1884: the over-ceiling projection is refused before any launch binding"
    );

    let widened_parts = effect_exact_lease_parts(&scope)?;
    let out_of_scope = KernelExecutionProjection {
        allowed_scopes: vec![foreign_scope()?],
        ..effect_exact_lease_projection(&scope)
    };
    let scope_error = store
        .persist_admitted_kernel_execution_manifest(
            &admission_from_parts(&widened_parts)?,
            &out_of_scope,
        )
        .err()
        .ok_or("1884: a route scope the Catalog never admitted must be refused")?;
    assert_eq!(
        invalid_field(&scope_error),
        Some((FIELD_ALLOWED_SCOPES, REASON_SCOPES_NOT_ADMITTED)),
        "1884: the out-of-scope projection is refused before any launch binding"
    );

    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: neither refusal left a manifest row, so neither can produce a launch binding"
    );
    Ok(())
}

/// Audit check 6: a stale Module Catalog plus `effect_exact_lease` opens no
/// normal `EffectService`, and the only effect authority any seam reaches is one
/// exact, unexpired leased operation.
#[test]
fn a_stale_catalog_opens_no_effect_service_and_only_an_exact_unexpired_lease_is_authorized()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-exact-lease")?;
    let store = fixture.store().as_ref();
    let scope = declared_scope()?;
    let manifest = persist_receipted_effect_exact_lease_manifest(store, &scope)?;
    assert_stale_view_never_opens_a_general_effect_service(&manifest)?;
    assert_only_the_exact_unexpired_leased_operation_is_authorized(store, &manifest, &scope)?;
    assert_the_production_gate_authorizes_no_unleased_operation(store)
}

/// Audit check 7: a missing manifest moves the REAL affected generation into a
/// visible degraded state and prevents a bypass restart.
///
/// What replaces the ceiling paragraph an earlier delivery carried: there IS a
/// Generation Registry lifecycle owner on this branch
/// (`crates/kernel/eliot-ors/src/generation_lifecycle.rs`), and
/// `RedbRecoveryStore::persist_kernel_restart_reconciliation` applies
/// `transition_to_degraded` in the same transaction that appends the escalation
/// row, so the refusal is visible to the launch, route and lease gates and not
/// only in a side table. See the module documentation for the full statement.
#[test]
fn a_missing_manifest_degrades_the_generation_and_refuses_every_restart_of_it()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-degraded-generation")?;
    let store = fixture.store().as_ref();
    let candidate = read_rebuild_manifest()?;

    // 1. ORS has recorded no lifecycle for this generation at all, so the
    //    composed disposition refuses rather than defaulting to Undegraded.
    assert!(
        store
            .load_generation_lifecycle(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the generation holds no recorded lifecycle row yet"
    );
    let unrecorded = store
        .load_observed_generation_lifecycle(MODULE_ID, GENERATION)
        .err()
        .ok_or("1884: a generation ORS has observed for neither fact is not Undegraded")?;
    assert!(
        matches!(
            unrecorded,
            OrsError::EffectOperationLeaseGenerationUnrecorded { .. }
        ),
        "1884: the unobserved generation is refused as unrecorded, got {unrecorded}"
    );

    // 2. The manifest refusal.
    let decision = store.load_and_verify_kernel_execution_restart(&restart_request(
        MODULE_ID,
        &candidate,
        CatalogPolicyView::Current,
    )?)?;
    assert!(
        matches!(decision.admission, KernelServiceAdmission::None),
        "1884: a missing manifest starts nothing"
    );
    assert_eq!(
        only_reconciliation_kind(&decision.reconciliation),
        KernelReconciliationKind::ManifestAbsent
    );

    // 3. The REAL lifecycle owner now reads Degraded.
    assert_eq!(
        store
            .load_observed_generation_lifecycle(MODULE_ID, GENERATION)?
            .disposition(),
        GenerationDisposition::Degraded,
        "1884: the missing manifest moved the real generation to Degraded"
    );
    let record = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    record.validate()?;
    assert_eq!(
        record.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestAbsent),
        "1884: the degradation names the cause it happened for"
    );
    assert!(
        !record.admits_launch(),
        "1884: a degraded generation admits no launch"
    );
    assert!(
        !record.admits_new_effect_leases(),
        "1884: a degraded generation is issued no new effect operation lease"
    );
    assert!(record.blocks_routes(), "1884: routes are blocked");

    // 4. A bypass restart — a different bound digest, a current view, an unspent
    //    budget — is refused exactly like the first attempt.
    let mut bypass = restart_request(MODULE_ID, &candidate, CatalogPolicyView::Current)?;
    bypass.bound_manifest_sha256 = hex_digest('e');
    let bypassed = store.load_and_verify_kernel_execution_restart(&bypass)?;
    assert!(
        matches!(bypassed.admission, KernelServiceAdmission::None),
        "1884: a substituted bound digest must not bypass the missing manifest"
    );
    assert_eq!(
        store
            .load_observed_generation_lifecycle(MODULE_ID, GENERATION)?
            .disposition(),
        GenerationDisposition::Degraded,
        "1884: the bypass attempt left the generation degraded"
    );

    // 5. And no NEW effect operation lease is issued for the degraded generation.
    assert_no_new_effect_lease_for_a_degraded_generation(&record)?;
    Ok(())
}

/// Asserts that a generation whose recorded lifecycle is `Degraded` is issued no
/// new effect operation lease, through the one lease issuer there is.
fn assert_no_new_effect_lease_for_a_degraded_generation(
    record: &GenerationLifecycleRecord,
) -> Result<(), Box<dyn Error>> {
    let scope = declared_scope()?;
    let manifest = effect_exact_lease_manifest(&scope)?;
    let lifecycle = ObservedGenerationLifecycle::compose(Some(record.clone()), &manifest)?;
    assert!(
        !lifecycle.admits_new_effect_leases(),
        "1884: the composed observation reports the recorded degraded disposition"
    );
    let lease_error = EffectOperationLease::issue(
        &manifest,
        effect_lease_admission(&manifest, &scope, lifecycle)?,
    )
    .err()
    .ok_or("1884: a degraded generation must be issued no new effect operation lease")?;
    assert!(
        matches!(
            lease_error,
            OrsError::EffectOperationLeaseGenerationDegraded { .. }
        ),
        "1884: the issuance is refused as a degraded generation, got {lease_error}"
    );
    Ok(())
}

/// Audit check 8: a restart refusal history is not erased by a subsequent
/// observation of the SAME affected generation.
///
/// How the row COUNT is observed is stated in the module documentation: the
/// reader resolves the NEWEST attempt, so the newest row's identity and clock
/// are the count, and the FIRST cause is read through the lifecycle owner that
/// keeps it. Two decoded rows are never compared with each other.
#[test]
fn restart_refusal_causes_append_so_a_later_observation_does_not_erase_the_earlier_one()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-refusal-history")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;
    let later = OBSERVED_AT_MS + 5_000;
    let latest = OBSERVED_AT_MS + 9_000;

    // Cause A: the recorded candidate carries refused I1.12 evidence.
    store.load_and_verify_kernel_execution_restart(&cause_a_request(&manifest, OBSERVED_AT_MS)?)?;
    let first = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the first refusal must leave durable evidence")?;
    first.validate()?;
    assert_eq!(
        first.kind,
        KernelReconciliationKind::ManifestIncompatible,
        "1884: the first recorded cause is the refused I1.12 evidence"
    );

    // The SAME cause observed again at a LATER clock is the same recorded
    // refusal, so it adds no row. The reader resolves the newest row, so a
    // second row would be the one it returns, carrying the later clock.
    store.load_and_verify_kernel_execution_restart(&cause_a_request(&manifest, later)?)?;
    let after_repeat = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded cause must stay readable")?;
    assert_eq!(
        after_repeat.observed_at_ms, OBSERVED_AT_MS,
        "1884: a second observation of the same cause appended no row: the newest row still carries the FIRST clock"
    );

    // A DIFFERENT cause is its own row beside the first.
    store.load_and_verify_kernel_execution_restart(&cause_b_request(&manifest, later)?)?;
    let newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the second refusal must leave durable evidence")?;
    newest.validate()?;
    assert_eq!(
        newest.kind,
        KernelReconciliationKind::ManifestCandidateBindingMismatch,
        "1884: the second, differently-caused refusal is the newest recorded cause"
    );
    assert_eq!(
        newest.observed_at_ms, later,
        "1884: the second row keeps its own clock, so the first row is still under an earlier one"
    );

    // The FIRST cause is still readable, through the lifecycle owner that keeps
    // it, and the disposition is the one the FIRST cause produced.
    let record = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    record.validate()?;
    assert_eq!(
        record.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestIncompatible),
        "1884: a later, differently-caused observation did not replace the first cause"
    );
    assert_eq!(
        store
            .load_observed_generation_lifecycle(MODULE_ID, GENERATION)?
            .disposition(),
        GenerationDisposition::Degraded,
        "1884: the generation is degraded for its first recorded cause"
    );

    // Re-observing the FIRST cause is an idempotent replay of a row that is still
    // stored, so it adds no row and the second cause stays newest. Had the second
    // cause erased the first, this would append the first at a higher ordinal and
    // the readback below would return it instead.
    store.load_and_verify_kernel_execution_restart(&cause_a_request(&manifest, latest)?)?;
    let still_newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: a recorded cause must stay readable")?;
    assert_eq!(
        still_newest.kind,
        KernelReconciliationKind::ManifestCandidateBindingMismatch,
        "1884: re-observing the earlier cause does not make it the newest row, so the later cause did not erase it"
    );
    assert_eq!(
        still_newest.observed_at_ms, later,
        "1884: the second cause's row is untouched by the third observation"
    );
    Ok(())
}

/// The exact durable item the Kernel launch gate records when a fresh contour's
/// digests are not the ones the sealed manifest records.
///
/// `KernelComposition::require_recorded_launch_identity`
/// (`bins/eliot-kernel/src/daemon_runtime.rs`) calls
/// `KernelComposition::refuse_daemon_restart_under_manifest` with the kind
/// `ManifestCandidateBindingMismatch` and, as the affected identity, the bound
/// manifest's own `admission.module_id` and `admission.generation`; that
/// refusal writer persists exactly this item shape through
/// `RedbRecoveryStore::persist_kernel_restart_reconciliation` — both manifest
/// digest fields carrying the bound manifest's own recorded digest, no replayed
/// operation and no lease, and the caller's observation clock.
///
/// Every coordinate therefore comes from the recorded manifest this argument is,
/// and none is invented here. The gate itself cannot be reached from this crate
/// (`eliot-module-registry` is not a dependency of the `eliot-kernel` bin and
/// reaching its composition root needs a real `BoundKernelExecutionManifest`),
/// so what is proved below is the store half that writer depends on.
fn launch_identity_refusal(
    manifest: &KernelExecutionManifest,
    kind: KernelReconciliationKind,
    observed_at_ms: i64,
) -> KernelReconciliationItem {
    KernelReconciliationItem {
        kind,
        module_id: manifest.admission.module_id.clone(),
        generation: manifest.admission.generation,
        bound_manifest_sha256: Some(manifest.manifest_sha256.clone()),
        recorded_manifest_sha256: Some(manifest.manifest_sha256.clone()),
        lease_id: None,
        operation_id: None,
        observed_at_ms,
    }
}

/// Audit check 5, the durable half the Kernel launch gate depends on: the
/// refusal it records lands a row in the escalation table AND moves the REAL
/// Generation Registry lifecycle owner to `Degraded` in the same transaction,
/// and a later, differently-caused refusal of that same generation appends its
/// own row without erasing the first cause.
///
/// The disposition is `Degraded`, not `Quarantined`, and the cause is what
/// decides it: the recorded manifest in this fixture does carry a non-empty
/// quarantine rule, but the store quarantines a generation only for a refusal of
/// kind `ManifestRestartBudgetExhausted`, `ManifestRevoked`,
/// `ManifestRevocationUnacknowledged` or `ManifestDeliveryGapOpen`. Neither
/// cause recorded here is one of those, so both degrade the generation and leave
/// it block launch, routes and new effect operation leases.
/// Asserts the state the real generation lifecycle owner holds after a recorded
/// launch-identity refusal: degraded, for THAT cause, at the refusal's own
/// observation time, and refusing launch, new leases and routes - while the
/// composed observation a gate reads agrees with the durable row beside the
/// intact admitted manifest.
///
/// Extracted from its case so the assertions are read once and both the
/// degradation case and the idempotence case assert the same durable facts
/// through the same reader, rather than restating them per case.
fn assert_degraded_for_the_launch_identity_refusal(
    store: &RedbRecoveryStore,
    manifest: &KernelExecutionManifest,
) -> Result<(), Box<dyn Error>> {
    let degraded = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    degraded.validate()?;
    assert_eq!(
        degraded.disposition,
        GenerationDisposition::Degraded,
        "1884: the recorded launch-identity refusal moved the real generation to Degraded"
    );
    assert_eq!(
        degraded.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestCandidateBindingMismatch),
        "1884: the degradation names the cause it happened for"
    );
    assert_eq!(
        degraded.recorded_at_ms, OBSERVED_AT_MS,
        "1884: the lifecycle row records the refusal's own observation time"
    );
    assert!(
        !degraded.admits_launch(),
        "1884: a degraded generation admits no launch"
    );
    assert!(
        !degraded.admits_new_effect_leases(),
        "1884: a degraded generation is issued no new effect operation lease"
    );
    assert!(
        degraded.blocks_routes(),
        "1884: a degraded generation's routes are blocked"
    );
    assert_eq!(
        observed_lifecycle(store, manifest)?.disposition(),
        GenerationDisposition::Degraded,
        "1884: the composed observation a gate reads reports the recorded degradation beside the intact admitted manifest"
    );
    Ok(())
}

#[test]
fn a_persisted_launch_identity_refusal_degrades_the_real_generation_and_keeps_the_first_cause()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-launch-identity-degradation")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;

    // Before the refusal the receipted fixture has landed the admitted manifest
    // and, in the same commit, the positive `Undegraded` lifecycle row: the
    // generation admits its launch and no escalation row exists yet.
    let admitted = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    admitted.validate()?;
    assert_eq!(
        admitted.disposition,
        GenerationDisposition::Undegraded,
        "1884: the receipted manifest landed the generation as Undegraded"
    );
    assert_eq!(
        admitted.first_refusal_cause, None,
        "1884: no manifest refusal is outstanding yet"
    );
    assert!(
        admitted.admits_launch(),
        "1884: the undegraded generation still admits its launch"
    );
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        0,
        "1884: no durable escalation exists before the refusal is recorded"
    );

    // The gate's own refusal, persisted through the store's durable writer.
    let first = launch_identity_refusal(
        &manifest,
        KernelReconciliationKind::ManifestCandidateBindingMismatch,
        OBSERVED_AT_MS,
    );
    first.validate()?;
    store.persist_kernel_restart_reconciliation(&first)?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        1,
        "1884: the recorded refusal is one durable attempt row"
    );
    let recorded_escalation = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded refusal must leave durable evidence")?;
    recorded_escalation.validate()?;
    assert_eq!(
        recorded_escalation, first,
        "1884: the escalation row reads back as the item the gate recorded"
    );
    assert!(
        !manifest
            .projection
            .restart_budget
            .quarantine_rule
            .trim()
            .is_empty(),
        "1884: the recorded manifest does carry a non-empty quarantine rule, so the Degraded disposition below is decided by the recorded cause and not by an absent rule"
    );

    // The REAL lifecycle owner now reads Degraded, for the cause it happened for.
    assert_degraded_for_the_launch_identity_refusal(store, &manifest)?;

    // A differently-caused later refusal of the SAME generation APPENDS.
    let later = OBSERVED_AT_MS + 5_000;
    store.persist_kernel_restart_reconciliation(&launch_identity_refusal(
        &manifest,
        KernelReconciliationKind::ManifestIncompatible,
        later,
    ))?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        2,
        "1884: a later, differently-caused refusal appended beside the first one instead of replacing it"
    );
    let newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the second refusal must leave durable evidence")?;
    newest.validate()?;
    assert_eq!(
        newest.kind,
        KernelReconciliationKind::ManifestIncompatible,
        "1884: the second, differently-caused refusal is the newest recorded cause"
    );
    assert_eq!(
        newest.observed_at_ms, later,
        "1884: the second row keeps its own observation time"
    );

    // The FIRST cause survives, and the record is not rewritten by the later one.
    let after = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    after.validate()?;
    assert_eq!(
        after.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestCandidateBindingMismatch),
        "1884: a later, differently-caused observation did not replace the first cause"
    );
    assert_eq!(
        after.disposition,
        GenerationDisposition::Degraded,
        "1884: the later cause did not move the generation out of Degraded"
    );
    assert_eq!(
        after.recorded_at_ms, OBSERVED_AT_MS,
        "1884: the later observation did not rewrite the recorded time of the first one"
    );
    Ok(())
}

/// Audit check 5, the idempotence half: re-persisting the EXACT same item
/// appends nothing and changes nothing, the same cause re-stated at a later
/// clock is the same recorded refusal, and a differently-caused later refusal
/// appends beside it so the first cause survives.
///
/// The row COUNT is read through the public counter
/// `RedbRecoveryStore::count_kernel_restart_reconciliations` rather than
/// through the newest-only reader, because "nothing was appended" is the
/// assertion; the newest row's own identity and clock are read separately so
/// which row survived is stated too.
#[test]
fn re_persisting_the_exact_same_refusal_appends_nothing_and_a_new_cause_appends_beside_it()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-refusal-idempotence")?;
    let store = fixture.store().as_ref();
    let manifest = persist_receipted_read_rebuild_manifest(store)?;
    let later = OBSERVED_AT_MS + 5_000;
    let first = launch_identity_refusal(
        &manifest,
        KernelReconciliationKind::ManifestCandidateBindingMismatch,
        OBSERVED_AT_MS,
    );

    // The exact same item, twice.
    store.persist_kernel_restart_reconciliation(&first)?;
    store.persist_kernel_restart_reconciliation(&first)?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        1,
        "1884: re-persisting the exact same item appended no second attempt"
    );
    let only = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded refusal must leave durable evidence")?;
    only.validate()?;
    assert_eq!(
        only, first,
        "1884: the idempotent replay left the recorded row exactly as it stands"
    );
    let after_replay = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    after_replay.validate()?;
    assert_eq!(
        after_replay.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestCandidateBindingMismatch),
        "1884: the idempotent replay left the recorded first cause untouched"
    );
    assert_eq!(
        after_replay.recorded_at_ms, OBSERVED_AT_MS,
        "1884: the idempotent replay did not rewrite the recorded observation time"
    );

    // The SAME cause re-stated at a LATER clock is the same recorded refusal:
    // the clock is not part of the cause.
    store.persist_kernel_restart_reconciliation(&launch_identity_refusal(
        &manifest,
        KernelReconciliationKind::ManifestCandidateBindingMismatch,
        later,
    ))?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        1,
        "1884: a later statement of the same cause appended nothing"
    );
    let restated = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded refusal must stay readable")?;
    assert_eq!(
        restated.observed_at_ms, OBSERVED_AT_MS,
        "1884: the first recorded clock is first-write-wins"
    );

    // A differently-caused later refusal APPENDS, so the first cause survives.
    store.persist_kernel_restart_reconciliation(&launch_identity_refusal(
        &manifest,
        KernelReconciliationKind::ManifestIncompatible,
        later,
    ))?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        2,
        "1884: a differently-caused refusal appended a second attempt beside the first"
    );
    let newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the second refusal must leave durable evidence")?;
    newest.validate()?;
    assert_eq!(
        newest.kind,
        KernelReconciliationKind::ManifestIncompatible,
        "1884: the later cause is the newest recorded row"
    );
    assert_eq!(
        newest.observed_at_ms, later,
        "1884: the appended row keeps its own observation time"
    );
    // The FIRST cause survives the append, and the lifecycle row was not
    // rewritten by it - the same durable facts the degradation case asserts.
    assert_degraded_for_the_launch_identity_refusal(store, &manifest)?;

    // And the exact first item is still idempotent BESIDE it: nothing is
    // appended, the first cause is unchanged and the second cause stays newest.
    store.persist_kernel_restart_reconciliation(&first)?;
    assert_eq!(
        store.count_kernel_restart_reconciliations(MODULE_ID, GENERATION)?,
        2,
        "1884: replaying the first item beside the second appended no third attempt"
    );
    let still_newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: a recorded cause must stay readable")?;
    assert_eq!(
        still_newest.kind,
        KernelReconciliationKind::ManifestIncompatible,
        "1884: the later cause did not erase the earlier one and is still newest"
    );
    assert_eq!(
        still_newest.observed_at_ms, later,
        "1884: the later cause's row is untouched by the replay"
    );
    assert_first_cause_and_clock_survive_the_append(store)?;
    Ok(())
}

/// Asserts that after a later, differently-caused append the FIRST recorded cause
/// and its observation time are still what the lifecycle owner holds, and that the
/// generation is still degraded. Shared by the idempotence case so the claim is
/// read once and asserted through the same reader in both cases.
fn assert_first_cause_and_clock_survive_the_append(
    store: &RedbRecoveryStore,
) -> Result<(), Box<dyn Error>> {
    let record = recorded_lifecycle(store, MODULE_ID, GENERATION)?;
    record.validate()?;
    assert_eq!(
        record.first_refusal_cause,
        Some(KernelReconciliationKind::ManifestCandidateBindingMismatch),
        "1884: the appended later cause did not replace the first recorded cause"
    );
    assert_eq!(
        record.disposition,
        GenerationDisposition::Degraded,
        "1884: the generation stays Degraded for its first recorded cause"
    );
    assert_eq!(
        record.recorded_at_ms, OBSERVED_AT_MS,
        "1884: neither the append nor the replay rewrote the first recorded time"
    );
    Ok(())
}
