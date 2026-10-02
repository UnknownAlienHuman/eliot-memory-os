//! Issue #1884 — immutable `KernelExecutionManifest` admission and enforcement.
//!
//! One `#[test]` per mandatory check of the owner audit (issue #1884 comment
//! 5946154380) — check 5 is split where a coordinate has no request-side input —
//! plus the audit's three admission negative discriminators and its positive
//! control. Every value is built through the crate's own canonical
//! constructors (`GovernorGenerationAdmissionSeal::canonical_sha256`,
//! `GovernorGenerationAdmissionSeal::seal`, `StateFenceSnapshot::capture`,
//! `CapabilityRouteScope::declare`, `CompatibilityEvidence::new`,
//! `CompatibilityRefusal::new`, `KernelExecutionManifest::admit`,
//! `EffectOperationLease::issue`), never hand-rolled, and every refusal is proved
//! by matching the crate's typed `OrsError` / `KernelReconciliationKind` rather
//! than by "it did not succeed".
//!
//! Three checks are `#[ignore]`d and name the exact missing symbol or input that
//! owns them; every other check runs. No test name claims more than its body
//! asserts.

use std::error::Error;
use std::num::NonZeroU64;

use eliot_contracts::{AuthorityEpoch, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ors::test_support::KernelRouteStoreFixture;
use eliot_ors::{
    AdmittedModuleGeneration, CapabilityRouteScope, CatalogPolicyView, CompatibilityEvidence,
    CompatibilityRefusal, EffectDeliveryAcknowledgement, EffectOperationLease,
    EffectOperationLeaseAdmission, EffectOperationLeaseGenerationDisposition,
    GovernorGenerationAdmissionSeal, GovernorGenerationAdmissionSealParts,
    KernelExactEffectReplayRequest, KernelExecutionManifest, KernelExecutionProjection,
    KernelExecutionRestartRequest, KernelLaunchBinding, KernelReconciliationItem,
    KernelReconciliationKind, KernelServiceAdmission, LifecycleAdmissionDisposition,
    ManifestDependencyEntry, ManifestEffectCeiling, ManifestResourceLimits, ManifestRestartBudget,
    OperationIdentity, OrsError, RedbRecoveryStore, RestartAuthorizationClass,
    RevocationAcknowledgement, StateFenceSnapshot, StateMigrationDecision,
    verify_exact_effect_replay, verify_kernel_execution_restart,
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

/// A non-blank invented receipt. It is deliberately well-formed text: the point
/// of check 1 is that a non-blank string is not admission evidence.
const INVENTED_RECEIPT: &str = "receipt-oracle-1884-invented-non-blank";

/// The record type every sealed-Governor-admission defect is recorded under by
/// `seal_refusal` in `execution_manifest.rs`.
const SEAL_RECORD_TYPE: &str = "kernel_execution_manifest_governor_admission_seal";
const REASON_OWNER_DIGEST: &str =
    "the sealed admission carries a Governor canonical digest that does not recompute";
const REASON_IDENTITY: &str = "the sealed admission names a different module or generation";

/// A 64-lowercase-hex placeholder of the recorded kind. These are fixture
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

/// Builds owner parts and computes the owner digest with the canonical function
/// the seal verifies against, so no fixture is self-consistent in the wrong way.
fn admission_seal_parts(
    module_id: &str,
    generation: u64,
    accepted_manifest_sha256: String,
    state_fence: StateFenceSnapshot,
) -> Result<GovernorGenerationAdmissionSealParts, Box<dyn Error>> {
    let mut parts = GovernorGenerationAdmissionSealParts {
        operation_id: OperationIdentity::new(ADMISSION_OPERATION_ID)?,
        idempotency_key: ADMISSION_IDEMPOTENCY_KEY.to_owned(),
        module_id: module_id.to_owned(),
        generation: ResourceGeneration::new(generation)?,
        catalog_revision: CATALOG_REVISION,
        policy_revision: POLICY_REVISION,
        accepted_manifest_sha256,
        state_fence,
        lifecycle_disposition: LifecycleAdmissionDisposition::Admitted,
        owner_canonical_sha256: String::new(),
    };
    parts.owner_canonical_sha256 = GovernorGenerationAdmissionSeal::canonical_sha256(&parts)?;
    Ok(parts)
}

/// The canonical constructor: a genuinely sealed, Governor-issued admission.
fn sealed_admission(
    module_id: &str,
    generation: u64,
    accepted_manifest_sha256: String,
) -> Result<GovernorGenerationAdmissionSeal, Box<dyn Error>> {
    let parts = admission_seal_parts(
        module_id,
        generation,
        accepted_manifest_sha256,
        fence_snapshot()?,
    )?;
    Ok(GovernorGenerationAdmissionSeal::seal(parts)?)
}

/// The negative discriminator: a sealed admission whose recorded Governor
/// canonical digest is replaced by an invented non-blank receipt.
///
/// The seal's fields are private and `seal()` refuses a digest that does not
/// recompute, so an invented receipt can only arrive the way a forged durable
/// row arrives: through `Deserialize`, which every validation re-checks.
fn invented_receipt_admission(
    module_id: &str,
    generation: u64,
) -> Result<GovernorGenerationAdmissionSeal, Box<dyn Error>> {
    let genuine = sealed_admission(module_id, generation, hex_digest('a'))?;
    let mut forged = serde_json::to_value(&genuine)?;
    forged["owner_canonical_sha256"] = serde_json::Value::String(INVENTED_RECEIPT.to_owned());
    Ok(serde_json::from_value(forged)?)
}

fn read_rebuild_admission(
    module_id: &str,
    generation: u64,
    seal: GovernorGenerationAdmissionSeal,
) -> Result<AdmittedModuleGeneration, Box<dyn Error>> {
    Ok(AdmittedModuleGeneration {
        module_id: module_id.to_owned(),
        generation: ResourceGeneration::new(generation)?,
        authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        catalog_revision: CATALOG_REVISION,
        policy_revision: POLICY_REVISION,
        governor_admission_seal: seal,
        restart_authorization_class: RestartAuthorizationClass::ReadRebuild,
        admitted_effect_ceiling: ManifestEffectCeiling::ReadRebuild,
        admitted_allowed_scopes: Vec::new(),
    })
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

fn effect_exact_lease_admission(
    module_id: &str,
    generation: u64,
    seal: GovernorGenerationAdmissionSeal,
    scope: &CapabilityRouteScope,
) -> Result<AdmittedModuleGeneration, Box<dyn Error>> {
    let base = read_rebuild_admission(module_id, generation, seal)?;
    Ok(AdmittedModuleGeneration {
        restart_authorization_class: RestartAuthorizationClass::EffectExactLease,
        admitted_effect_ceiling: ManifestEffectCeiling::EffectExactLease,
        admitted_allowed_scopes: vec![scope.clone()],
        ..base
    })
}

fn effect_exact_lease_projection(scope: &CapabilityRouteScope) -> KernelExecutionProjection {
    let base = read_rebuild_projection();
    KernelExecutionProjection {
        effect_ceiling: ManifestEffectCeiling::EffectExactLease,
        allowed_scopes: vec![scope.clone()],
        ..base
    }
}

fn effect_exact_lease_manifest() -> Result<KernelExecutionManifest, Box<dyn Error>> {
    let scope = declared_scope()?;
    let admission = effect_exact_lease_admission(
        MODULE_ID,
        GENERATION,
        sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
        &scope,
    )?;
    let projection = effect_exact_lease_projection(&scope);
    Ok(KernelExecutionManifest::admit(admission, projection)?)
}

/// Issues the one exact, unexpired operation lease an effect-capable manifest
/// may hold.
///
/// `Undegraded` is the disposition a readback that positively establishes no
/// outstanding manifest refusal for this generation supplies; the ORS-side
/// durable-degraded mapping for the other dispositions is covered by the
/// ignored check 7.
fn issue_exact_effect_lease(
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
) -> Result<EffectOperationLease, Box<dyn Error>> {
    Ok(EffectOperationLease::issue(
        manifest,
        EffectOperationLeaseAdmission {
            lease_id: OperationIdentity::new("lease-ors-1884-exact-effect")?,
            operation_id: OperationIdentity::new("operation-ors-1884-exact-effect")?,
            effect_receipt_sha256: hex_digest('7'),
            allowed_scope: scope.clone(),
            authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
            catalog_revision: CATALOG_REVISION,
            policy_revision: POLICY_REVISION,
            revocation: RevocationAcknowledgement::None,
            delivery: EffectDeliveryAcknowledgement::Acknowledged,
            generation_disposition: EffectOperationLeaseGenerationDisposition::Undegraded,
            issued_at_ms: OBSERVED_AT_MS,
            expires_at_ms: OBSERVED_AT_MS + 60_000,
        },
    )?)
}

fn exact_effect_replay_request(
    manifest: &KernelExecutionManifest,
    scope: &CapabilityRouteScope,
    lease: &EffectOperationLease,
    observed_at_ms: i64,
) -> Result<KernelExactEffectReplayRequest, Box<dyn Error>> {
    Ok(KernelExactEffectReplayRequest {
        operation_id: lease.operation_id.clone(),
        lease_id: lease.lease_id.clone(),
        module_id: MODULE_ID.to_owned(),
        generation: ResourceGeneration::new(GENERATION)?,
        bound_manifest_sha256: manifest.manifest_sha256.clone(),
        effect_receipt_sha256: lease.effect_receipt_sha256.clone(),
        allowed_scope: scope.clone(),
        authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        current_catalog_revision: CATALOG_REVISION,
        current_policy_revision: POLICY_REVISION,
        catalog_view: CatalogPolicyView::Current,
        revocation: RevocationAcknowledgement::None,
        delivery: EffectDeliveryAcknowledgement::Acknowledged,
        observed_at_ms,
    })
}

/// The I1.12 verdict the request validator requires, bound to `generation`.
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

fn recorded_launch_binding() -> KernelLaunchBinding {
    KernelLaunchBinding {
        artifact_sha256: hex_digest('a'),
        config_sha256: hex_digest('b'),
        protocol_sha256: hex_digest('c'),
        start_command: "eliot-module-1884 --serve".to_owned(),
    }
}

fn restart_request(
    module_id: &str,
    generation: u64,
    bound_manifest_sha256: &str,
    catalog_view: CatalogPolicyView,
) -> Result<KernelExecutionRestartRequest, Box<dyn Error>> {
    Ok(KernelExecutionRestartRequest {
        module_id: module_id.to_owned(),
        generation: ResourceGeneration::new(generation)?,
        bound_manifest_sha256: bound_manifest_sha256.to_owned(),
        candidate: recorded_launch_binding(),
        current_authority_epoch: AuthorityEpoch::new(EPOCH_SEQUENCE)?,
        current_catalog_revision: CATALOG_REVISION,
        current_policy_revision: POLICY_REVISION,
        catalog_view,
        revocation: RevocationAcknowledgement::None,
        delivery: EffectDeliveryAcknowledgement::Acknowledged,
        compatibility: compatibility_evidence(generation)?,
        restarts_spent: 0,
        observed_at_ms: OBSERVED_AT_MS,
    })
}

/// The reason a sealed-Governor-admission refusal recorded, or `None` when the
/// failure is not one. A refusal is proved by the recorded reason, never by the
/// mere absence of success.
fn seal_refusal_reason(error: &OrsError) -> Option<&str> {
    match error {
        OrsError::IntegrityProblem {
            record_type,
            reason,
        } if *record_type == SEAL_RECORD_TYPE => Some(reason.as_str()),
        _ => None,
    }
}

/// The recorded refusal of a second, changed persist of one
/// `{module_id, generation}`, or `None` when the failure is not one.
fn identity_conflict_reason(error: &OrsError) -> Option<&str> {
    match error {
        OrsError::IntegrityProblem {
            record_type,
            reason,
        } if *record_type == "kernel_execution_manifest" => Some(reason.as_str()),
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
fn assert_changed_launch_coordinates_block_launch(
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
        let mut request = restart_request(
            MODULE_ID,
            GENERATION,
            &manifest.manifest_sha256,
            CatalogPolicyView::Current,
        )?;
        request.candidate = candidate;
        let refused = verify_kernel_execution_restart(Some(manifest), &request)?;
        assert!(
            matches!(refused.admission, KernelServiceAdmission::None),
            "1884: a changed {field} must block the launch"
        );
        assert_eq!(
            only_reconciliation_kind(&refused.reconciliation),
            KernelReconciliationKind::ManifestCandidateBindingMismatch,
            "1884: a changed {field} is refused on the exact launch binding"
        );
    }
    Ok(())
}

/// The audit's positive control: a genuinely sealed admission, built by the
/// canonical constructor with a correctly recomputed owner digest, is ACCEPTED
/// by the only manifest construction path — so the refusals below discriminate
/// instead of rejecting everything.
///
/// The admission here is SELF-SEALED by this test through
/// `GovernorGenerationAdmissionSeal::canonical_sha256` and
/// `GovernorGenerationAdmissionSeal::seal`, which is exactly the call the
/// Governor owner adapter would make. It is not a Governor-issued admission:
/// `eliot_module_registry::seal_generation_admission` cannot return a seal on
/// this branch (see the ignored check 3), so no real Governor seal exists to
/// admit here.
#[test]
fn governor_sealed_admission_is_accepted_by_the_only_construction_path()
-> Result<(), Box<dyn Error>> {
    let seal = sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?;
    let admission = read_rebuild_admission(MODULE_ID, GENERATION, seal)?;
    let manifest = KernelExecutionManifest::admit(admission, read_rebuild_projection())?;
    manifest.validate()?;
    assert!(
        manifest.has_governor_admission(),
        "1884: the accepted manifest carries its sealed Governor admission"
    );
    assert_eq!(
        manifest
            .admission
            .governor_admission_seal
            .accepted_manifest_sha256(),
        hex_digest('a'),
        "1884: the owner's recorded accepted-manifest digest is carried verbatim"
    );
    assert_eq!(
        manifest.manifest_sha256.len(),
        64,
        "1884: the manifest carries its own canonical identity digest"
    );
    assert_eq!(
        manifest.launch_binding(),
        recorded_launch_binding(),
        "1884: the accepted manifest carries the exact recorded launch binding"
    );
    Ok(())
}

/// Audit check 1 and admission negative discriminator 1: an invented non-blank
/// receipt must not persist a manifest.
#[test]
fn invented_non_blank_receipt_does_not_persist_a_manifest() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-invented-receipt")?;
    let store = fixture.store().as_ref();
    let admission = read_rebuild_admission(
        MODULE_ID,
        GENERATION,
        invented_receipt_admission(MODULE_ID, GENERATION)?,
    )?;
    let projection = read_rebuild_projection();

    let error = store
        .persist_admitted_kernel_execution_manifest(&admission, &projection)
        .err()
        .ok_or("1884: an invented non-blank receipt must not persist a manifest")?;
    let reason = seal_refusal_reason(&error).ok_or(format!(
        "1884: expected a sealed-admission refusal, got {error}"
    ))?;
    assert_eq!(
        reason, REASON_OWNER_DIGEST,
        "1884: the invented receipt is refused as a non-recomputing Governor digest"
    );
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the refusal happens before any ORS mutation, so no manifest row exists"
    );
    Ok(())
}

/// Admission negative discriminator 2: a receipt belonging to ANOTHER
/// generation must be refused before any ORS mutation.
#[test]
fn receipt_seal_for_another_generation_is_refused_before_any_ors_mutation()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-foreign-generation")?;
    let store = fixture.store().as_ref();
    let other_generation = GENERATION + 1;
    // The seal is genuinely sealed by its own owner; it simply names another
    // generation than the admission carries.
    let foreign = sealed_admission(MODULE_ID, other_generation, hex_digest('a'))?;
    assert_eq!(
        foreign.generation().value(),
        other_generation,
        "1884: the foreign receipt is a well-formed sealed admission for another generation"
    );
    let admission = read_rebuild_admission(MODULE_ID, GENERATION, foreign)?;
    let projection = read_rebuild_projection();

    let error = store
        .persist_admitted_kernel_execution_manifest(&admission, &projection)
        .err()
        .ok_or("1884: a receipt of another generation must not persist a manifest")?;
    let reason = seal_refusal_reason(&error).ok_or(format!(
        "1884: expected a sealed-admission refusal, got {error}"
    ))?;
    assert_eq!(
        reason, REASON_IDENTITY,
        "1884: the foreign receipt is refused as a module/generation mismatch"
    );
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the refusal happens before any ORS mutation"
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
/// The binding lives in the durable immutable row, decided by
/// `RedbRecoveryStore::persist_admitted_kernel_execution_manifest` against the
/// exact state that would be overwritten.
#[test]
fn receipt_seal_with_the_same_text_id_and_a_different_manifest_digest_is_refused()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-reused-receipt-id")?;
    let store = fixture.store().as_ref();
    let first = sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?;
    let second = sealed_admission(MODULE_ID, GENERATION, hex_digest('e'))?;
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
    assert_ne!(
        first.accepted_manifest_sha256(),
        second.accepted_manifest_sha256(),
        "1884: the two seals really do name different manifests"
    );

    let projection = read_rebuild_projection();
    let recorded = store.persist_admitted_kernel_execution_manifest(
        &read_rebuild_admission(MODULE_ID, GENERATION, first)?,
        &projection,
    )?;

    // Same `{module_id, generation}`, same receipt text id, different recorded
    // accepted-manifest digest: refused, and the stored row is left as recorded.
    let error = store
        .persist_admitted_kernel_execution_manifest(
            &read_rebuild_admission(MODULE_ID, GENERATION, second)?,
            &projection,
        )
        .err()
        .ok_or("1884: a reused receipt text id must not persist another manifest")?;
    let reason = identity_conflict_reason(&error).ok_or(format!(
        "1884: expected a recorded identity conflict, got {error}"
    ))?;
    assert!(
        reason.starts_with("IDENTITY_CONFLICT:"),
        "1884: the reused receipt is refused as an identity conflict, got {reason}"
    );
    let row = store
        .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
        .ok_or("1884: the first recorded manifest must still be readable")?;
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
    Ok(())
}

/// Audit check 2: changed content under the same module/generation must not
/// overwrite the recorded row.
#[test]
fn changed_content_under_the_same_module_and_generation_does_not_overwrite_the_row()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-immutable-row")?;
    let store = fixture.store().as_ref();
    let admission = read_rebuild_admission(
        MODULE_ID,
        GENERATION,
        sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
    )?;
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
    let reason = identity_conflict_reason(&error).ok_or(format!(
        "1884: expected a recorded identity conflict, got {error}"
    ))?;
    assert!(
        reason.starts_with("IDENTITY_CONFLICT:"),
        "1884: the changed row is refused, got {reason}"
    );

    // An exact re-persist of the same content is idempotent and keeps the row.
    let replayed = store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;
    assert_eq!(
        replayed, recorded,
        "1884: an exact replay returns the recorded digest"
    );
    let row = store
        .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded manifest must still be readable")?;
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

/// Audit check 4: every restart requires a sealed bound manifest. Proved at the
/// store-backed restart entry point
/// `RedbRecoveryStore::load_and_verify_kernel_execution_restart` and at the pure
/// verifier it delegates to: with no recorded manifest nothing is admitted under
/// any observed Module Catalog/Policy view, and with one the admitted restart
/// carries exactly the recorded sealed binding.
#[test]
fn every_restart_requires_a_sealed_manifest_and_admits_only_its_recorded_binding()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-sealed-binding-required")?;
    let store = fixture.store().as_ref();

    // No recorded manifest: the store-backed entry point starts nothing, names
    // the missing manifest, and leaves the refusal as durable evidence.
    let absent = store.load_and_verify_kernel_execution_restart(&restart_request(
        OTHER_MODULE_ID,
        GENERATION,
        &hex_digest('a'),
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

    // The pure verifier refuses the same way under every observed view: no view
    // can substitute for a sealed bound manifest.
    let request = restart_request(
        OTHER_MODULE_ID,
        GENERATION,
        &hex_digest('a'),
        CatalogPolicyView::Current,
    )?;
    for view in [
        CatalogPolicyView::Current,
        CatalogPolicyView::Stale,
        CatalogPolicyView::Unavailable,
    ] {
        let mut attempt = request.clone();
        attempt.catalog_view = view;
        let refused = verify_kernel_execution_restart(None, &attempt)?;
        assert!(
            matches!(refused.admission, KernelServiceAdmission::None),
            "1884: view {view:?} must not substitute for a sealed bound manifest"
        );
        assert!(
            refused.evidence.restart_authorization_class.is_none(),
            "1884: without a manifest no class is read, so no binding is issued"
        );
    }

    // With the sealed manifest recorded, the same store-backed entry point admits
    // the restart only as the sealed binding under the exact recorded values.
    let admission = read_rebuild_admission(
        MODULE_ID,
        GENERATION,
        sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
    )?;
    let projection = read_rebuild_projection();
    store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;
    let recorded = store
        .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded manifest must be readable")?;
    recorded.validate()?;
    let decision = store.load_and_verify_kernel_execution_restart(&restart_request(
        MODULE_ID,
        GENERATION,
        &recorded.manifest_sha256,
        CatalogPolicyView::Current,
    )?)?;
    let KernelServiceAdmission::ReadRebuildService(binding) = &decision.admission else {
        return Err("1884: the recorded manifest must restart read/rebuild".into());
    };
    assert!(decision.reconciliation.is_empty());
    assert_eq!(binding.manifest_sha256(), recorded.manifest_sha256);
    assert_eq!(binding.launch_binding(), recorded.launch_binding());
    Ok(())
}

/// Audit check 5, the coordinates with a real request-side input: a changed
/// artifact/config/protocol/start-command, a route scope or an effect ceiling the
/// Catalog never admitted, and a spent bounded restart budget each block the
/// launch.
#[test]
fn changed_launch_binding_scopes_ceiling_and_a_spent_restart_budget_block_launch()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-blocked-launch")?;
    let store = fixture.store().as_ref();
    let admission = read_rebuild_admission(
        MODULE_ID,
        GENERATION,
        sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
    )?;
    let projection = read_rebuild_projection();
    store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;
    let manifest = store
        .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
        .ok_or("1884: the recorded manifest must be readable")?;

    // The four launch-binding coordinates are refused from the request side.
    assert_changed_launch_coordinates_block_launch(&manifest)?;

    // The recorded bounded restart budget has a request-side input: a restart
    // that has already spent it is refused.
    let mut spent = restart_request(
        MODULE_ID,
        GENERATION,
        &manifest.manifest_sha256,
        CatalogPolicyView::Current,
    )?;
    spent.restarts_spent = manifest.projection.restart_budget.max_restarts;
    let refused = store.load_and_verify_kernel_execution_restart(&spent)?;
    assert!(
        matches!(refused.admission, KernelServiceAdmission::None),
        "1884: a spent bounded restart budget must block the launch"
    );
    assert_eq!(
        only_reconciliation_kind(&refused.reconciliation),
        KernelReconciliationKind::ManifestRestartBudgetExhausted,
        "1884: the refusal names the spent recorded restart budget"
    );

    // An effect ceiling above the admitted one, and a route scope outside the
    // admitted set, are refused by the only construction path, so no manifest and
    // therefore no launch binding can exist for them at all.
    let scope = declared_scope()?;
    let foreign_scope = CapabilityRouteScope::declare(
        MODULE_ID,
        "not-admitted-capability",
        "work-scope-1884",
        "effect-domain-1884",
    )?;
    let capped = AdmittedModuleGeneration {
        admitted_effect_ceiling: ManifestEffectCeiling::CandidateNoEffect,
        ..effect_exact_lease_admission(
            MODULE_ID,
            GENERATION,
            sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
            &scope,
        )?
    };
    let over_ceiling = store
        .persist_admitted_kernel_execution_manifest(&capped, &effect_exact_lease_projection(&scope))
        .err()
        .ok_or("1884: an effect ceiling above the admitted one must be refused")?;
    assert_eq!(
        invalid_field(&over_ceiling),
        Some((
            "kernel_execution_manifest_effect_ceiling",
            "must not exceed the admitted effect ceiling"
        )),
        "1884: the over-ceiling projection is refused before any launch binding"
    );

    let out_of_scope = KernelExecutionProjection {
        allowed_scopes: vec![foreign_scope],
        ..effect_exact_lease_projection(&scope)
    };
    let widened = store
        .persist_admitted_kernel_execution_manifest(
            &effect_exact_lease_admission(
                MODULE_ID,
                GENERATION,
                sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
                &scope,
            )?,
            &out_of_scope,
        )
        .err()
        .ok_or("1884: a route scope the Catalog never admitted must be refused")?;
    assert_eq!(
        invalid_field(&widened),
        Some((
            "kernel_execution_manifest_allowed_scopes",
            "must be a subset of the admitted route scopes"
        )),
        "1884: the out-of-scope projection is refused before any launch binding"
    );
    Ok(())
}

/// Audit check 5, the coordinates with NO request-side input: the Job Object and
/// resource limits and the health/readiness contract reference.
///
/// Ceiling (issue #1884): `KernelExecutionRestartRequest`
/// (`crates/kernel/eliot-ors/src/execution_manifest.rs`) has no field carrying a
/// Job Object/resource-limit value or a health/readiness contract reference.
/// Both are readable only from `BoundKernelExecutionManifest::{resource_limits,
/// health_readiness_contract_ref}`, which `verify_kernel_execution_restart`
/// issues only for a manifest it already accepted, so a caller cannot present a
/// changed value to be refused at launch. The only way to change either recorded
/// value is a second persist of the same `{module_id, generation}`, which
/// `RedbRecoveryStore::persist_admitted_kernel_execution_manifest` refuses as a
/// recorded identity conflict — that much is asserted below, and it is a
/// persistence refusal, not a launch refusal.
#[test]
#[ignore = "issue #1884: no request-side input exists for resource limits or the readiness contract reference"]
fn changed_job_limits_and_readiness_contract_block_launch() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-limits-not-provable")?;
    let store = fixture.store().as_ref();
    let admission = read_rebuild_admission(
        MODULE_ID,
        GENERATION,
        sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
    )?;
    let projection = read_rebuild_projection();
    store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;

    for changed in [
        KernelExecutionProjection {
            resource_limits: ManifestResourceLimits {
                max_processes: 64,
                ..projection.resource_limits.clone()
            },
            ..projection.clone()
        },
        KernelExecutionProjection {
            health_readiness_contract_ref: "readiness-contract-1884-other".to_owned(),
            ..projection.clone()
        },
    ] {
        let error = store
            .persist_admitted_kernel_execution_manifest(&admission, &changed)
            .err()
            .ok_or("1884: changed limits/readiness must not replace the row")?;
        let reason = identity_conflict_reason(&error).ok_or(format!(
            "1884: expected a recorded identity conflict, got {error}"
        ))?;
        assert!(
            reason.starts_with("IDENTITY_CONFLICT:"),
            "1884: the changed record is refused, got {reason}"
        );
    }

    // Launch itself is not exercised here: there is no input with which to change
    // these two recorded coordinates, which is why this case is ignored.
    Ok(())
}

/// Audit check 6: a stale Catalog plus `effect_exact_lease` opens no normal
/// `EffectService`, and the only effect authority any seam reaches is one exact,
/// unexpired leased operation.
///
/// Which seam authorizes what, stated exactly: the exact-lease authorization
/// below is reached through the PURE `verify_exact_effect_replay`, with the
/// caller's observed revocation and delivery state. The store-backed gate
/// `RedbRecoveryStore::authorize_effect_replay_for_operation` authorizes NOTHING
/// today — it has no revocation-event readback and no independent delivery
/// readback — and the same test asserts that refusal and its typed reason rather
/// than claiming an authorization that seam cannot produce.
#[test]
fn a_stale_catalog_opens_no_effect_service_and_only_an_exact_unexpired_lease_is_authorized()
-> Result<(), Box<dyn Error>> {
    let manifest = effect_exact_lease_manifest()?;
    assert_stale_view_never_opens_a_general_effect_service(&manifest)?;

    let fixture = KernelRouteStoreFixture::open("1884-exact-lease")?;
    let store = fixture.store().as_ref();
    store.persist_admitted_kernel_execution_manifest(&manifest.admission, &manifest.projection)?;
    let scope = declared_scope()?;
    let lease = issue_exact_effect_lease(&manifest, &scope)?;
    let exact = exact_effect_replay_request(&manifest, &scope, &lease, OBSERVED_AT_MS)?;

    // A new operation (no lease record at all) is refused outright.
    let new_operation = KernelExactEffectReplayRequest {
        operation_id: OperationIdentity::new("operation-ors-1884-new-effect")?,
        lease_id: OperationIdentity::new("lease-ors-1884-new-effect")?,
        ..exact.clone()
    };
    let denied = verify_exact_effect_replay(Some(&manifest), None, &new_operation)?;
    assert!(
        denied.authorized_lease.is_none(),
        "1884: a new operation names no lease and is refused"
    );
    assert_eq!(
        only_reconciliation_kind(&denied.reconciliation),
        KernelReconciliationKind::EffectLeaseIdentityAbsent,
        "1884: only an exact unexpired leased operation is permitted"
    );

    // The exact unexpired leased operation is the one thing this PURE seam
    // authorizes, and it carries no general effect authority.
    let admitted = verify_exact_effect_replay(Some(&manifest), Some(&lease), &exact)?;
    let authority = admitted
        .authorized_lease
        .as_ref()
        .ok_or("1884: the exact unexpired leased operation must be admitted")?;
    assert!(admitted.reconciliation.is_empty());
    assert_eq!(authority.lease_id(), &lease.lease_id);
    assert_eq!(authority.operation_id(), &lease.operation_id);
    assert_eq!(authority.allowed_scope_hash(), scope.route_scope_hash);

    // The same lease authorizes no other operation.
    let other_operation = KernelExactEffectReplayRequest {
        operation_id: OperationIdentity::new("operation-ors-1884-another-effect")?,
        ..exact.clone()
    };
    let refused = verify_exact_effect_replay(Some(&manifest), Some(&lease), &other_operation)?;
    assert!(refused.authorized_lease.is_none());
    assert_eq!(
        only_reconciliation_kind(&refused.reconciliation),
        KernelReconciliationKind::EffectOperationIdentityMismatch,
        "1884: the lease authorizes its own operation only"
    );

    // And it authorizes nothing once it has expired.
    let after_expiry =
        exact_effect_replay_request(&manifest, &scope, &lease, lease.expires_at_ms + 1)?;
    let expired = verify_exact_effect_replay(Some(&manifest), Some(&lease), &after_expiry)?;
    assert!(expired.authorized_lease.is_none());
    assert_eq!(
        only_reconciliation_kind(&expired.reconciliation),
        KernelReconciliationKind::EffectLeaseExpired,
        "1884: an expired lease authorizes nothing"
    );

    // The store-backed gate is stricter today: ORS has no revocation-event
    // readback and no independent delivery readback at this seam, so it presents
    // an outstanding revocation and an open delivery gap and refuses every
    // replay. That refusal is asserted as it really is, not papered over.
    assert_store_gate_refuses_every_replay(store, &lease)?;
    Ok(())
}

/// Audit check 7: a missing/deleted/corrupt manifest must put the real affected
/// generation into a degraded/quarantined state and prevent a bypass restart.
///
/// Ceiling (issue #1884): there is no Generation Registry lifecycle owner on
/// this branch — `crates/kernel/eliot-ors/src/generation_registry.rs` is absent —
/// so nothing can move a real generation into `degraded` or `quarantined` state,
/// apply the recorded `quarantine_rule`, or map a
/// `load_kernel_restart_reconciliation` readback onto
/// `EffectOperationLeaseGenerationDisposition::{Degraded, Quarantined}`. The
/// durable refusal evidence this check would read is produced and preserved by
/// `restart_refusal_causes_append_so_a_later_observation_does_not_erase_the_earlier_one`, which runs.
#[test]
#[ignore = "issue #1884: no Generation Registry lifecycle owner (crates/kernel/eliot-ors/src/generation_registry.rs)"]
fn missing_manifest_puts_the_affected_generation_into_a_visible_degraded_state()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-degraded-generation")?;
    let store = fixture.store().as_ref();
    assert!(
        store
            .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
            .is_none(),
        "1884: the generation holds no recorded manifest"
    );

    let decision = store.load_and_verify_kernel_execution_restart(&restart_request(
        MODULE_ID,
        GENERATION,
        &hex_digest('a'),
        CatalogPolicyView::Current,
    )?)?;
    assert!(
        decision.is_degraded(),
        "1884: a missing manifest starts nothing"
    );
    let degraded = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the refusal must be visible as durable degraded state")?;
    degraded.validate()?;
    assert_eq!(degraded.kind, KernelReconciliationKind::ManifestAbsent);
    assert_eq!(degraded.module_id, MODULE_ID);
    assert_eq!(degraded.generation.value(), GENERATION);
    Ok(())
}

/// Audit check 8: a restart refusal history is not erased by a subsequent
/// observation of the SAME affected generation.
///
/// Both refusals below are real `KernelServiceAdmission::None` decisions taken
/// through the store's own path, with two different
/// [`KernelReconciliationKind`]s: A is `ManifestIncompatible` and B is
/// `ManifestCandidateBindingMismatch`. `persist_kernel_restart_reconciliation`
/// keys them `{module_id}::{generation}::{attempt}` and appends, and
/// `load_kernel_restart_reconciliation` resolves only the newest attempt.
///
/// Observation limit, stated honestly: the store exposes no public enumeration of
/// the rows under one identity prefix and the reader resolves only the newest
/// attempt, so A cannot be read back directly. A's survival is therefore proved
/// through the attempt ordinal: re-observing A after B must leave B as the newest
/// attempt. Had B erased A, that third decision would append A at a higher
/// ordinal than B, and A would become the newest readback instead of B.
#[test]
fn restart_refusal_causes_append_so_a_later_observation_does_not_erase_the_earlier_one()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-refusal-history")?;
    let store = fixture.store().as_ref();
    let manifest = KernelExecutionManifest::admit(
        read_rebuild_admission(
            MODULE_ID,
            GENERATION,
            sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?,
        )?,
        read_rebuild_projection(),
    )?;
    store.persist_admitted_kernel_execution_manifest(&manifest.admission, &manifest.projection)?;

    // Cause A: the recorded candidate carries refused I1.12 evidence.
    let mut request_for_cause_a = restart_request(
        MODULE_ID,
        GENERATION,
        &manifest.manifest_sha256,
        CatalogPolicyView::Current,
    )?;
    request_for_cause_a.compatibility = refused_compatibility_evidence(GENERATION)?;
    let cause_a = store.load_and_verify_kernel_execution_restart(&request_for_cause_a)?;
    let recorded_a = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the first refusal must leave durable evidence")?;
    recorded_a.validate()?;
    assert_eq!(cause_a.reconciliation, vec![recorded_a.clone()]);
    assert_eq!(
        recorded_a.kind,
        KernelReconciliationKind::ManifestIncompatible
    );

    // Cause B: a differently-caused refusal of the SAME {module_id, generation},
    // so it lands under the same identity prefix rather than another one.
    let mut request_for_cause_b = restart_request(
        MODULE_ID,
        GENERATION,
        &manifest.manifest_sha256,
        CatalogPolicyView::Current,
    )?;
    request_for_cause_b.candidate.start_command = "eliot-module-1884 --other".to_owned();
    let cause_b = store.load_and_verify_kernel_execution_restart(&request_for_cause_b)?;
    let recorded_b = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the second refusal must leave durable evidence")?;
    recorded_b.validate()?;
    assert_eq!(cause_b.reconciliation, vec![recorded_b.clone()]);
    assert_eq!(
        recorded_b.kind,
        KernelReconciliationKind::ManifestCandidateBindingMismatch
    );
    assert_eq!(
        recorded_a.module_id, recorded_b.module_id,
        "1884: both causes name the same affected module"
    );
    assert_eq!(recorded_a.generation, recorded_b.generation);

    // The second, differently-caused refusal did not replace the first: the
    // reader resolves the newest attempt, and B is it.
    let newest_after_b = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: the newest recorded cause must be readable")?;
    assert_eq!(newest_after_b, recorded_b);

    // Re-observing the earlier cause A is an idempotent replay of an attempt that
    // is still stored, so it adds no row and B stays the newest attempt. Had B
    // erased A, this decision would append A at a higher ordinal and the
    // readback below would return A instead of B.
    store.load_and_verify_kernel_execution_restart(&request_for_cause_a)?;
    let newest = store
        .load_kernel_restart_reconciliation(MODULE_ID, GENERATION)?
        .ok_or("1884: a recorded cause must stay readable")?;
    assert_eq!(
        newest.kind, recorded_b.kind,
        "1884: re-observing the earlier cause does not make it the newest attempt"
    );
    assert_eq!(newest, recorded_b);
    Ok(())
}

/// Audit check 3: a Governor-issued accepted generation automatically creates
/// the exact Generation Registry copy.
///
/// Ceiling (issue #1884, Module Registry owner):
/// `eliot_module_registry::seal_generation_admission` cannot return a seal. It
/// states the admitted generation through `sealed_generation_counter`, and
/// `GenerationAdmission` records the generation as opaque `GenerationId` text
/// while the ORS seal records a numeric `ResourceGeneration`, with no owner
/// accessor relating the two. `GenerationAdmission` and
/// `CatalogMutation::AcceptGeneration` have zero producers and
/// `ModuleCatalog::apply_mutation` refuses every admission, and `eliot-ors`
/// declares no dependency on `eliot-module-registry`.
///
/// The ORS-side copy mechanism this Governor decision would drive is proved by
/// `governor_sealed_admission_is_accepted_by_the_only_construction_path`.
#[test]
#[ignore = "issue #1884: eliot_module_registry::seal_generation_admission cannot return a seal"]
fn governor_issued_accepted_generation_creates_the_exact_generation_registry_copy()
-> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1884-governor-copy")?;
    let store = fixture.store().as_ref();
    // The Governor owner would supply the seal here; the ORS side must record
    // exactly that accepted generation and nothing else.
    let seal = sealed_admission(MODULE_ID, GENERATION, hex_digest('a'))?;
    let admission = read_rebuild_admission(MODULE_ID, GENERATION, seal)?;
    let projection = read_rebuild_projection();
    let recorded = store.persist_admitted_kernel_execution_manifest(&admission, &projection)?;
    let row = store
        .load_kernel_execution_manifest(MODULE_ID, GENERATION)?
        .ok_or("1884: an accepted generation must produce its Generation Registry copy")?;
    row.validate()?;
    assert_eq!(
        row.manifest_sha256, recorded,
        "1884: the copied row is the exact manifest that was admitted"
    );
    assert_eq!(
        row.admission
            .governor_admission_seal
            .accepted_manifest_sha256(),
        hex_digest('a'),
        "1884: the copy keeps the Governor's own accepted manifest digest verbatim"
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
    Ok(())
}

/// Asserts that the general restart of an effect-capable generation never opens
/// a normal `EffectService` while the Module Catalog/Policy view is not current,
/// both at the class predicate where that rule is decided and at the restart
/// verifier.
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
        &restart_request(
            MODULE_ID,
            GENERATION,
            &manifest.manifest_sha256,
            CatalogPolicyView::Stale,
        )?,
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
    Ok(())
}

/// Asserts the store-backed effect gate exactly as it behaves today.
///
/// ORS has no revocation-event readback and no independent delivery readback at
/// this seam, so it presents an outstanding revocation and an open delivery gap
/// and refuses every replay, including one whose lease is active, unexpired and
/// bound to exactly this operation. That refusal is asserted under its own typed
/// kinds; no authorized replay is claimed from a seam that cannot produce one.
fn assert_store_gate_refuses_every_replay(
    store: &RedbRecoveryStore,
    lease: &EffectOperationLease,
) -> Result<(), Box<dyn Error>> {
    let epoch = AuthorityEpoch::new(EPOCH_SEQUENCE)?;
    store.persist_effect_operation_lease(lease)?;
    let stored = store.authorize_effect_replay_for_operation(
        &lease.operation_id,
        MODULE_ID,
        GENERATION,
        epoch,
        OBSERVED_AT_MS,
    )?;
    assert!(
        stored.authority.authorized_lease().is_none(),
        "1884: the store gate authorizes no replay without a revocation readback"
    );
    let item = stored
        .reconciliation
        .as_ref()
        .ok_or("1884: the store gate must escalate its refusal durably")?;
    item.validate()?;
    assert_eq!(
        item.kind,
        KernelReconciliationKind::EffectLeaseRevocationUnacknowledged,
        "1884: the store gate refuses on the revocation state it cannot observe"
    );
    assert_eq!(item.operation_id.as_ref(), Some(&lease.operation_id));

    // An operation no recorded lease covers is a new operation: the gate refuses
    // it outright at `RedbRecoveryStore::authorize_effect_replay_for_operation`
    // before any request is fabricated for it.
    let unleased_operation = OperationIdentity::new("operation-ors-1884-unleased")?;
    let unleased_decision = store.authorize_effect_replay_for_operation(
        &unleased_operation,
        MODULE_ID,
        GENERATION,
        epoch,
        OBSERVED_AT_MS,
    )?;
    assert!(
        unleased_decision.authority.authorized_lease().is_none(),
        "1884: an operation with no recorded lease authorizes nothing"
    );
    let unleased_item = unleased_decision
        .reconciliation
        .ok_or("1884: the unleased refusal must be escalated durably")?;
    unleased_item.validate()?;
    assert_eq!(
        unleased_item.kind,
        KernelReconciliationKind::EffectLeaseAbsent,
        "1884: an operation with no recorded lease is refused outright"
    );
    assert_eq!(
        unleased_item.operation_id.as_ref(),
        Some(&unleased_operation)
    );
    Ok(())
}
