//! #1872 W1 / I2 / W3: refusal-path evidence for the Kernel-owned
//! `canonical_store` storage-replacement cutover coordinator
//! (`eliot_kernel_service::StorageReplacement`).
//!
//! These three checklist rows are TEST-PHASE: the product code exists and the
//! missing artefact is its evidence. They are proved here as REFUSALS, not as
//! a happy path, because what each row claims is what the coordinator withholds
//! when the durable evidence is absent:
//!
//! - W1 — the coordinator is bound to exactly one `canonical_store`
//!   `CapabilityRouteScope` in the Kernel Generation Registry, and
//!   `StorageReplacement::begin` refuses a candidate generation that already
//!   owns that route through a committed cutover, so a restart cannot reopen a
//!   replacement from the top. A committed cutover of a DIFFERENT route scope
//!   that carries the same `canonical_store` capability string is proven NOT to
//!   claim the candidate, so the binding is to the pinned four-tuple and not to
//!   the capability spelling.
//! - I2 — the eleven `I5.11` stages admit only their exact predecessor, stage 8
//!   cannot be presented as a plain stage, the two data-transferring stages
//!   cannot be reached without an `ECXF/1` transfer record, and
//!   `StorageReplacement::commit_canonical_store_route_cutover` re-derives the
//!   durable cutover receipt from ORS rather than accepting a record, so neither
//!   an unknown cutover identity nor a merely STAGED `Armed` row can produce a
//!   receipt.
//! - W3 — irreversibility is tracked BEFORE a rollback is allowed: a committed
//!   cutover row whose `migration` decision contradicts the coordinator's own
//!   irreversible-effect ledger is refused in both directions, and once an
//!   irreversible effect is recorded the rollback request is refused as
//!   `GenerationFenced` with the forward-repair disposition.
//!
//! Every arrangement below uses the existing owners: the real
//! `eliot_ors::RedbRecoveryStore` on a temp redb file, the real
//! `GenerationCutoverOwnership` staged/committed through the existing ORS
//! writers, and the coordinator's own stage/transfer/receipt types. There is no
//! second validator, no hand-built receipt and no test double for the durable
//! record. No external provider is involved: `redb` is an in-process embedded
//! database, so this proof runs anywhere the crate's own proof entrypoint
//! (`cargo test -p eliot-kernel-service`) runs — it never silently no-ops.
//!
//! Nothing here weakens a guarantee to make a test pass. Each refusal is
//! asserted on the exact typed `KernelServiceError` variant AND field the
//! coordinator produces, and the arrangements below are the ones the product
//! actually admits; where a refusal turns out to be structurally unreachable
//! that is reported to the manager rather than staged artificially.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_kernel_service::{
    CANONICAL_STORE_CAPABILITY, CANONICAL_STORE_MODULE_ID, IrreversibleStorageEffect,
    KernelServiceError, STORAGE_REPLACEMENT_TRANSFER_FORMAT, StorageReplacement,
    StorageReplacementStage, StorageReplacementTransfer, StorageRollbackDisposition,
    canonical_store_route_scope,
};
use eliot_ors::{
    CapabilityRouteScope, GenerationCutoverOwnership, ModuleArtifactIdentity, RedbRecoveryStore,
    StateMigrationDecision,
};
use eliot_runtime_contracts::GenerationCutoverState;

/// One `I5.10` `ECXF/1` exchange. `payload` selects the exact exported bytes,
/// so the snapshot-import record and the canonical-event-tail record are
/// distinguishable and the receipt's binding to the TAIL is observable.
fn ecxf_transfer(payload: &str) -> StorageReplacementTransfer {
    StorageReplacementTransfer {
        format: STORAGE_REPLACEMENT_TRANSFER_FORMAT.to_owned(),
        payload_digest: payload.repeat(64),
        export_fence_digest: "3".repeat(64),
    }
}

/// The `I5.10` logical transfer format identity the two data-transferring
/// stages must name. Anything else is refused.
const FOREIGN_TRANSFER_FORMAT: &str = "ECXF/0";

/// The payload identity of the `I5.11` stage-2 snapshot import.
const SNAPSHOT_PAYLOAD: &str = "1";

/// The payload identity of the `I5.11` stage-5 canonical event tail, which is
/// the transfer the cutover receipt binds.
const EVENT_TAIL_PAYLOAD: &str = "2";

fn generation(value: u64) -> ResourceGeneration {
    ResourceGeneration::new(value).expect("nonzero resource generation")
}

fn epoch(value: u64) -> AuthorityEpoch {
    AuthorityEpoch::new(value).expect("nonzero authority epoch")
}

fn artifact_identity(module_id: &str, hash_character: char) -> ModuleArtifactIdentity {
    let artifact_hash = hash_character.to_string().repeat(64);
    let semver = "1.2.0";
    ModuleArtifactIdentity {
        module_id: module_id.to_owned(),
        semver: semver.to_owned(),
        manifest_digest: "f".repeat(64),
        layout_root: format!("modules/{module_id}/{semver}/{artifact_hash}"),
        artifact_hash,
    }
}

/// Builds one `Armed` (pre-commit) `GenerationCutoverOwnership` row through the
/// existing ORS type, with the artifact identity the ORS owner requires for the
/// scope's own module.
fn armed_cutover_row(
    cutover_id: &str,
    scope: &CapabilityRouteScope,
    old_generation: Option<u64>,
    new_generation: u64,
    old_epoch: u64,
    new_epoch: u64,
    migration: StateMigrationDecision,
) -> GenerationCutoverOwnership {
    GenerationCutoverOwnership {
        cutover_id: cutover_id.to_owned(),
        candidate_artifact: artifact_identity(&scope.module_id, 'a'),
        incumbent_artifact: None,
        scope: scope.clone(),
        old_generation: old_generation.map(generation),
        new_generation: generation(new_generation),
        old_epoch: epoch(old_epoch),
        new_epoch: epoch(new_epoch),
        in_flight: Vec::new(),
        migration,
        health_proof_ref: format!("health-proof-{cutover_id}"),
        rollback_boundary: "forward-only".to_owned(),
        unresolved_scopes: Vec::new(),
        linearization_record_id: None,
        state: GenerationCutoverState::Armed,
    }
}

/// Opens a real `eliot_ors::RedbRecoveryStore` on its own temp file. `redb` is
/// embedded and in-process, so no external database server is required.
fn open_ors(name: &str) -> (PathBuf, RedbRecoveryStore) {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "eliot-kernel-storage-replacement-{name}-{}-{}.redb",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let store = RedbRecoveryStore::open(&path).expect("open ORS on a temp file");
    (path, store)
}

fn remove_ors(path: PathBuf, store: RedbRecoveryStore) {
    drop(store);
    let _ = std::fs::remove_file(path);
}

/// Returns the `(field, reason)` of a typed `InvalidField` refusal, or fails
/// loudly. Matching on the variant keeps the proof honest: an ORS class that
/// arrived as `Platform(String)` or as any other variant does not satisfy a row
/// that claims a typed refusal.
fn invalid_field(error: KernelServiceError) -> (&'static str, &'static str) {
    match error {
        KernelServiceError::InvalidField { field, reason } => (field, reason),
        other => panic!("expected a typed InvalidField refusal, got {other:?}"),
    }
}

fn handshake_mismatch_field(error: KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::HandshakeMismatch { field } => field,
        other => panic!("expected a typed HandshakeMismatch refusal, got {other:?}"),
    }
}

fn assert_generation_fenced(error: KernelServiceError) {
    assert!(
        matches!(error, KernelServiceError::GenerationFenced),
        "expected the generation-rollback fence, got {error:?}"
    );
}

/// Records `I5.11` stages 1 through 7 in their required order and leaves the
/// machine positioned exactly at stage 8, the canonical store route cutover.
fn drive_to_route_cutover(replacement: &mut StorageReplacement) {
    replacement
        .record_stage(
            StorageReplacementStage::InstallCandidateStoreBridge,
            "candidate store bridge installed",
        )
        .expect("I5.11 stage 1");
    replacement
        .record_transfer_stage(
            StorageReplacementStage::ImportSnapshotIntoCandidate,
            &ecxf_transfer(SNAPSHOT_PAYLOAD),
            "snapshot imported into the candidate",
        )
        .expect("I5.11 stage 2");
    replacement
        .record_stage(
            StorageReplacementStage::VerifyCountsHashesAndInvariants,
            "counts, hashes and graph/projection invariants verified",
        )
        .expect("I5.11 stage 3");
    replacement
        .record_stage(
            StorageReplacementStage::ShadowReadBothStores,
            "shadow reads compared against both stores",
        )
        .expect("I5.11 stage 4");
    replacement
        .record_transfer_stage(
            StorageReplacementStage::TailCanonicalEventsIntoCandidate,
            &ecxf_transfer(EVENT_TAIL_PAYLOAD),
            "canonical events tailed into the candidate",
        )
        .expect("I5.11 stage 5");
    replacement
        .record_stage(
            StorageReplacementStage::QuiesceAffectedWrites,
            "affected writes quiesced",
        )
        .expect("I5.11 stage 6");
    replacement
        .record_stage(
            StorageReplacementStage::ReconcileFinalSequence,
            "final sequence reconciled",
        )
        .expect("I5.11 stage 7");
    assert_eq!(
        replacement.next_stage(),
        Some(StorageReplacementStage::CommitCanonicalStoreRouteCutover),
        "stages 1 through 7 must leave the machine exactly at the route cutover"
    );
}

/// W1 — the coordinator is bound to exactly one `canonical_store`
/// `CapabilityRouteScope`, and `StorageReplacement::begin` will not reopen a
/// replacement whose candidate already owns that route through a committed
/// cutover.
///
/// Guarantee covered: the binding is to the pinned four-tuple declared by
/// `canonical_store_route_scope()` (module `store_bridge`, capability
/// `canonical_store`, work `work`, effects `effects`), and the durable
/// "already owns the route" refusal is what stops a restarted process from
/// restarting a replacement from stage 1. The negative case matters as much as
/// the positive one: a committed cutover under a DIFFERENT route scope that
/// carries the same `canonical_store` capability string must NOT claim the
/// candidate, which is what makes this a route-scope binding rather than a
/// capability-string filter.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one focused fixture covers the pinned-scope binding and both begin() refusals"
)]
fn begin_binds_to_the_pinned_canonical_store_scope_and_refuses_a_committed_candidate() {
    let (path, ors) = open_ors("w1-binding");
    let pinned = canonical_store_route_scope().expect("the pinned canonical_store route scope");

    // A foreign route scope that carries the SAME `canonical_store` capability
    // string and differs only in its owning module.
    let foreign = CapabilityRouteScope::declare(
        "other_module",
        CANONICAL_STORE_CAPABILITY,
        "work",
        "effects",
    )
    .expect("declare the foreign capability route scope");
    assert_ne!(
        foreign.route_scope_hash, pinned.route_scope_hash,
        "the foreign scope must be a different four-tuple"
    );
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-foreign-scope",
        &foreign,
        None,
        9,
        1,
        2,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the foreign-scope cutover");
    ors.commit_cutover_ownership("cutover-foreign-scope")
        .expect("commit the foreign-scope cutover");

    // W1: a generation that owns a DIFFERENT route scope does not claim the
    // candidate of this replacement, and the replacement that begins is bound to
    // the pinned scope no matter what the caller presented.
    let bound = StorageReplacement::begin(&ors, "replacement-foreign-scope", None, generation(9))
        .expect("a foreign-scope cutover must not claim the candidate");
    assert_eq!(bound.route_scope().route_scope_hash, pinned.route_scope_hash);
    assert_eq!(bound.route_scope().capability, CANONICAL_STORE_CAPABILITY);
    assert_eq!(bound.route_scope().module_id, CANONICAL_STORE_MODULE_ID);
    assert_eq!(bound.route_scope().work_scope, pinned.work_scope);
    assert_eq!(bound.route_scope().effect_domain, pinned.effect_domain);

    // The pinned route scope's own first committed cutover, naming generation 1.
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-pinned-genesis",
        &pinned,
        None,
        1,
        2,
        3,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the pinned-scope genesis cutover");
    ors.commit_cutover_ownership("cutover-pinned-genesis")
        .expect("commit the pinned-scope genesis cutover");

    // W1 refusal: generation 1 now owns the pinned route through a committed
    // cutover, so a replacement presenting it as a fresh candidate is refused
    // and must be resumed from its durable cutover receipt instead. (The
    // incumbent is `None` on purpose: a same-generation pair is the OTHER
    // refusal, asserted separately below, and it is decided first.)
    let (field, reason) = invalid_field(
        StorageReplacement::begin(&ors, "replacement-restarted", None, generation(1))
            .expect_err("a candidate that already owns the pinned route must be refused"),
    );
    assert_eq!(field, "storage_replacement_candidate_generation");
    assert_eq!(
        reason,
        "the candidate generation already owns the canonical_store route through a committed cutover, so the replacement must be resumed from its durable cutover receipt"
    );

    // W1 refusal: a replacement must name two distinct store generations, so an
    // incumbent re-presented as its own candidate is refused before ORS is
    // consulted for anything else.
    let (field, reason) = invalid_field(
        StorageReplacement::begin(
            &ors,
            "replacement-same-generation",
            Some(generation(1)),
            generation(1),
        )
        .expect_err("a replacement must select a distinct candidate generation"),
    );
    assert_eq!(field, "storage_replacement_candidate_generation");
    assert_eq!(
        reason,
        "a replacement must select a distinct candidate store generation"
    );

    // W1: the route a committed cutover actually switched is the active owner of
    // the pinned scope, and it is the one every Store read and write is
    // admitted against.
    assert_eq!(
        eliot_kernel_service::active_canonical_store_generation(&ors)
            .expect("read the active owner"),
        Some(generation(1)),
        "the pinned route owner is read from the committed cutover row"
    );
    assert_eq!(
        eliot_kernel_service::canonical_store_route_owner(&ors).expect("read the route owner"),
        Some(generation(1))
    );

    remove_ors(path, ors);
}

/// I2 — the ordered `I5.11` stage machine, the required `ECXF/1` transfer
/// records, and the durable cutover receipt that is re-derived from ORS.
///
/// Guarantee covered: a stage is reached only through its exact predecessor;
/// stage 8 is never accepted as a presented stage; the two transferring stages
/// cannot be reached without their `ECXF/1` record and a non-transferring stage
/// cannot carry one; and `commit_canonical_store_route_cutover` loads the
/// ORS-committed row, so neither an unknown cutover identity nor a row that is
/// only `Armed` can produce a receipt. The receipt that IS produced names both
/// store generations, the pinned route scope, and the stage-5 event-tail
/// transfer.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one focused fixture covers stage ordering, ECXF binding, and the durable-receipt refusal"
)]
fn replacement_stages_run_in_order_and_a_cutover_receipt_needs_a_committed_ors_row() {
    let (path, ors) = open_ors("i2-stages");
    let pinned = canonical_store_route_scope().expect("the pinned canonical_store route scope");
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-genesis",
        &pinned,
        None,
        1,
        1,
        2,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the genesis cutover");
    ors.commit_cutover_ownership("cutover-genesis").expect("commit the genesis cutover");

    let mut replacement = StorageReplacement::begin(
        &ors,
        "replacement-i2",
        Some(generation(1)),
        generation(2),
    )
    .expect("begin the replacement");
    assert_eq!(
        replacement.next_stage(),
        Some(StorageReplacementStage::InstallCandidateStoreBridge)
    );

    // I2 refusal: a skipped stage. Stage 3 is presented as the first stage.
    let (field, reason) = invalid_field(
        replacement
            .record_stage(
                StorageReplacementStage::VerifyCountsHashesAndInvariants,
                "skipped straight to verification",
            )
            .expect_err("a skipped stage must be refused"),
    );
    assert_eq!(field, "storage_replacement_stage");
    assert_eq!(
        reason,
        "a storage replacement stage may only be reached through its exact predecessor"
    );

    // I2 refusal: `I5.11` stage 8 is never presented as a plain stage; it is
    // recorded only by re-deriving a committed ORS cutover ownership record.
    let (field, reason) = invalid_field(
        replacement
            .record_stage(
                StorageReplacementStage::CommitCanonicalStoreRouteCutover,
                "presented the cutover as a stage",
            )
            .expect_err("stage 8 must not be presented as a plain stage"),
    );
    assert_eq!(field, "storage_replacement_stage");
    assert_eq!(
        reason,
        "the canonical_store route cutover is recorded by re-deriving its committed ORS cutover ownership record"
    );

    // I2 refusal: a data-transferring stage cannot be reached without its
    // `I5.10` transfer record.
    let (field, reason) = invalid_field(
        replacement
            .record_stage(
                StorageReplacementStage::ImportSnapshotIntoCandidate,
                "imported without a transfer record",
            )
            .expect_err("a transferring stage must be refused here"),
    );
    assert_eq!(field, "storage_replacement_stage");
    assert_eq!(
        reason,
        "a stage that transfers data is recorded together with its I5.10 transfer record"
    );

    // I2 refusal: a stage that does not transfer data cannot be recorded with
    // one, so the transfer record cannot be smuggled onto a non-transferring
    // stage.
    let (field, reason) = invalid_field(
        replacement
            .record_transfer_stage(
                StorageReplacementStage::InstallCandidateStoreBridge,
                &ecxf_transfer(SNAPSHOT_PAYLOAD),
                "installed with a transfer record",
            )
            .expect_err("only stages 2 and 5 may carry a transfer record"),
    );
    assert_eq!(field, "storage_replacement_stage");
    assert_eq!(
        reason,
        "only the snapshot import and the canonical event tail transfer data into the candidate"
    );

    // I2 refusal: the transfer record must name the `I5.10` `ECXF/1` format.
    let foreign_format = StorageReplacementTransfer {
        format: FOREIGN_TRANSFER_FORMAT.to_owned(),
        ..ecxf_transfer(SNAPSHOT_PAYLOAD)
    };
    let (field, reason) = invalid_field(
        replacement
            .record_transfer_stage(
                StorageReplacementStage::ImportSnapshotIntoCandidate,
                &foreign_format,
                "imported under a foreign transfer format",
            )
            .expect_err("a foreign transfer format must be refused"),
    );
    assert_eq!(field, "storage_replacement_transfer_format");
    assert_eq!(
        reason,
        "the storage replacement transfer format is the I5.10 ECXF/1 exchange"
    );

    // From here the seven recorded stages run in their required order.
    drive_to_route_cutover(&mut replacement);

    // I2 refusal: the receipt is re-derived from ORS, never accepted from the
    // caller, so a cutover identity the durable owner has never heard of cannot
    // produce one.
    let (field, reason) = invalid_field(
        replacement
            .commit_canonical_store_route_cutover(
                &ors,
                "cutover-i2",
                "route cutover committed",
            )
            .expect_err("an unknown cutover identity must be refused"),
    );
    assert_eq!(field, "storage_replacement_cutover_record");
    assert_eq!(
        reason,
        "the canonical_store route cutover must be an ORS-committed cutover ownership record"
    );
    assert!(
        replacement.cutover_receipt().is_none(),
        "a refused cutover must not store a receipt"
    );

    // I2 refusal: a row that is durable but only `Armed` is not a committed
    // cutover, so the receipt cannot be re-derived from it. The refusal is the
    // existing ORS `InvalidTransition` class projected by the coordinator's
    // exhaustive class map — it is still a typed refusal, and still no receipt.
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-i2",
        &pinned,
        Some(1),
        2,
        2,
        3,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the cutover without committing it");
    let (field, _) = invalid_field(
        replacement
            .commit_canonical_store_route_cutover(
                &ors,
                "cutover-i2",
                "route cutover committed",
            )
            .expect_err("a staged but uncommitted cutover must be refused"),
    );
    assert_eq!(
        field, "reservation_lifecycle",
        "a staged `Armed` row is refused by the ORS invalid-transition class"
    );
    assert!(
        replacement.cutover_receipt().is_none(),
        "a staged row must not produce a durable cutover receipt"
    );
    assert_eq!(
        replacement.next_stage(),
        Some(StorageReplacementStage::CommitCanonicalStoreRouteCutover),
        "a refused cutover must not advance the stage machine"
    );

    // The same coordinator, against the now-committed row, produces the durable
    // cutover receipt: both store generations, the pinned route scope, and the
    // stage-5 canonical event tail transfer (NOT the stage-2 snapshot import).
    ors.commit_cutover_ownership("cutover-i2").expect("commit the cutover");
    let receipt = replacement
        .commit_canonical_store_route_cutover(&ors, "cutover-i2", "route cutover committed")
        .expect("derive the receipt from the committed row");
    assert_eq!(receipt.replacement_id, "replacement-i2");
    assert_eq!(receipt.incumbent_generation, Some(generation(1)));
    assert_eq!(receipt.candidate_generation, generation(2));
    assert_eq!(receipt.route_scope, pinned);
    assert_eq!(receipt.transfer, ecxf_transfer(EVENT_TAIL_PAYLOAD));
    assert_ne!(receipt.transfer, ecxf_transfer(SNAPSHOT_PAYLOAD));
    assert_eq!(receipt.committed_cutover.state, GenerationCutoverState::Committed);
    assert_eq!(receipt.committed_cutover.cutover_id, "cutover-i2");
    assert!(
        receipt
            .committed_cutover
            .linearization_record_id
            .starts_with("ors:cutover-ownership:cutover-i2#"),
        "the receipt binds the ORS-minted linearization identity"
    );
    assert!(
        receipt.irreversible_effects.is_empty(),
        "no irreversible effect was recorded for this replacement"
    );
    assert_eq!(replacement.next_stage(), Some(StorageReplacementStage::CanaryReadsAndWrites));

    remove_ors(path, ors);
}

/// W3 — irreversibility is tracked BEFORE a rollback is allowed.
///
/// Guarantee covered: the committed cutover row's `migration` decision and the
/// coordinator's own irreversible-effect ledger must agree, in BOTH directions,
/// before any cutover receipt is issued — a `retain_compatible` row is refused
/// when the ledger records an irreversible effect, and a `forward_repair_required`
/// row is refused when the ledger is silent. And once an irreversible effect is
/// recorded the rollback request is refused as a generation rollback
/// (`GenerationFenced`) with the forward-repair disposition, while a replacement
/// with no committed cutover is refused because no route was switched.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one focused fixture covers both migration/ledger contradictions and both rollback refusals"
)]
fn irreversibility_is_tracked_before_rollback_and_contradicting_cutovers_are_refused() {
    let (path, ors) = open_ors("w3-irreversibility");
    let pinned = canonical_store_route_scope().expect("the pinned canonical_store route scope");
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-genesis",
        &pinned,
        None,
        1,
        1,
        2,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the genesis cutover");
    ors.commit_cutover_ownership("cutover-genesis").expect("commit the genesis cutover");

    // Two coordinators for the SAME candidate cutover: one whose irreversible
    // ledger is silent, one that has already observed an irreversible migration.
    let mut clean = StorageReplacement::begin(
        &ors,
        "replacement-clean",
        Some(generation(1)),
        generation(2),
    )
    .expect("begin the clean replacement");
    let mut irreversible = StorageReplacement::begin(
        &ors,
        "replacement-irreversible",
        Some(generation(1)),
        generation(2),
    )
    .expect("begin the irreversible replacement");
    irreversible.record_irreversible_effect(IrreversibleStorageEffect::IrreversibleMigration);
    drive_to_route_cutover(&mut clean);
    drive_to_route_cutover(&mut irreversible);

    // W3 refusal: a rollback request before the cutover committed is refused,
    // because no route was switched and there is nothing to roll back.
    let (field, reason) = invalid_field(
        clean
            .request_rollback(&ors)
            .expect_err("a rollback before the cutover must be refused"),
    );
    assert_eq!(field, "storage_replacement_cutover_receipt");
    assert_eq!(
        reason,
        "the canonical_store route cutover is not committed, so no route was switched"
    );

    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-retain",
        &pinned,
        Some(1),
        2,
        2,
        3,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the retain-compatible cutover");
    ors.commit_cutover_ownership("cutover-retain").expect("commit the retain-compatible cutover");

    // W3 refusal, first direction: the committed row declares the state migration
    // is compatible while the coordinator's own ledger records an irreversible
    // migration. The two can never disagree about whether a generation rollback
    // is still available, so the cutover receipt is refused.
    let (field, reason) = invalid_field(
        irreversible
            .commit_canonical_store_route_cutover(
                &ors,
                "cutover-retain",
                "route cutover committed",
            )
            .expect_err("a migration decision contradicting the ledger must be refused"),
    );
    assert_eq!(field, "storage_replacement_migration");
    assert_eq!(
        reason,
        "the declared state migration must name forward repair exactly when an irreversible effect is recorded"
    );
    assert!(irreversible.cutover_receipt().is_none());
    assert_eq!(
        irreversible.next_stage(),
        Some(StorageReplacementStage::CommitCanonicalStoreRouteCutover)
    );

    // The clean coordinator against the same committed row is admitted, and the
    // rollback is permitted only while no irreversible effect is recorded.
    let receipt = clean
        .commit_canonical_store_route_cutover(&ors, "cutover-retain", "route cutover committed")
        .expect("a matching migration decision is admitted");
    assert!(receipt.irreversible_effects.is_empty());
    assert_eq!(
        clean
            .request_rollback(&ors)
            .expect("no irreversible effect is recorded"),
        StorageRollbackDisposition::GenerationRollbackPermitted
    );

    // W3: once an irreversible effect IS recorded the rollback is refused as a
    // generation rollback and the disposition names the forward-repair path.
    clean.record_irreversible_effect(IrreversibleStorageEffect::ExternalEffectIssued);
    assert_eq!(
        clean.rollback_disposition(),
        StorageRollbackDisposition::ForwardRepairRequired {
            state: GenerationCutoverState::FailedRequiresForwardCutover,
        }
    );
    assert_generation_fenced(
        clean
            .request_rollback(&ors)
            .expect_err("an irreversible effect must fence the generation rollback"),
    );

    // W3 refusal, second direction: a committed row that names forward repair
    // while the coordinator's ledger is silent is refused for the same reason —
    // the caller cannot obtain a permitted generation rollback by declining to
    // record an effect.
    let mut forward_silent = StorageReplacement::begin(
        &ors,
        "replacement-forward-silent",
        Some(generation(2)),
        generation(3),
    )
    .expect("begin the forward-repair replacement with a silent ledger");
    let mut forward_observed = StorageReplacement::begin(
        &ors,
        "replacement-forward-observed",
        Some(generation(2)),
        generation(3),
    )
    .expect("begin the forward-repair replacement with an observed effect");
    forward_observed
        .record_irreversible_effect(IrreversibleStorageEffect::ExternalEffectIssued);
    drive_to_route_cutover(&mut forward_silent);
    drive_to_route_cutover(&mut forward_observed);
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-forward-repair",
        &pinned,
        Some(2),
        3,
        3,
        4,
        StateMigrationDecision::ForwardRepairRequired,
    ))
    .expect("stage the forward-repair cutover");
    ors.commit_cutover_ownership("cutover-forward-repair")
        .expect("commit the forward-repair cutover");

    let (field, reason) = invalid_field(
        forward_silent
            .commit_canonical_store_route_cutover(
                &ors,
                "cutover-forward-repair",
                "route cutover committed",
            )
            .expect_err("a forward-repair row with a silent ledger must be refused"),
    );
    assert_eq!(field, "storage_replacement_migration");
    assert_eq!(
        reason,
        "the declared state migration must name forward repair exactly when an irreversible effect is recorded"
    );
    assert!(forward_silent.cutover_receipt().is_none());

    // With the effect recorded the same row is admitted, the receipt carries the
    // irreversible ledger, and the rollback stays fenced on the durable record.
    let receipt = forward_observed
        .commit_canonical_store_route_cutover(
            &ors,
            "cutover-forward-repair",
            "route cutover committed",
        )
        .expect("a ledger that matches the forward-repair row is admitted");
    assert_eq!(
        receipt.irreversible_effects,
        BTreeSet::from([IrreversibleStorageEffect::ExternalEffectIssued])
    );
    assert_eq!(receipt.committed_cutover.migration, StateMigrationDecision::ForwardRepairRequired);
    assert_eq!(
        forward_observed.rollback_disposition(),
        StorageRollbackDisposition::ForwardRepairRequired {
            state: GenerationCutoverState::FailedRequiresForwardCutover,
        }
    );
    assert_generation_fenced(
        forward_observed
            .request_rollback(&ors)
            .expect_err("the committed forward-repair row must fence the generation rollback"),
    );

    // W1/I2 cross-check already proven above, restated here on the same store so
    // the receipt-bound owner is the one every Store read and write is admitted
    // against after both cutovers.
    assert_eq!(
        eliot_kernel_service::active_canonical_store_generation(&ors)
            .expect("read the active owner after both cutovers"),
        Some(generation(3))
    );

    remove_ors(path, ors);
}

/// A `HandshakeMismatch` cross-check on the receipt's own binding, kept as a
/// separate test so the `MISMATCH`-shaped refusals of the two cutover anchors
/// are witnessed even if the arrangement above is ever reordered.
///
/// Guarantee covered: `StorageReplacementCutoverReceipt::validate` refuses a
/// receipt whose committed cutover names different store generations than the
/// replacement it claims, so a receipt cannot be re-pointed at another pair of
/// store generations than the one the coordinator cut over.
#[test]
fn cutover_receipt_validation_refuses_a_rebound_generation_pair() {
    use eliot_kernel_service::StorageReplacementCutoverReceipt;

    let (path, ors) = open_ors("receipt-binding");
    let pinned = canonical_store_route_scope().expect("the pinned canonical_store route scope");
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-genesis",
        &pinned,
        None,
        1,
        1,
        2,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the genesis cutover");
    ors.commit_cutover_ownership("cutover-genesis").expect("commit the genesis cutover");

    let mut replacement = StorageReplacement::begin(
        &ors,
        "replacement-binding",
        Some(generation(1)),
        generation(2),
    )
    .expect("begin the replacement");
    drive_to_route_cutover(&mut replacement);
    ors.stage_cutover_ownership(armed_cutover_row(
        "cutover-i2",
        &pinned,
        Some(1),
        2,
        2,
        3,
        StateMigrationDecision::RetainCompatible,
    ))
    .expect("stage the cutover");
    ors.commit_cutover_ownership("cutover-i2").expect("commit the cutover");
    let receipt = replacement
        .commit_canonical_store_route_cutover(&ors, "cutover-i2", "route cutover committed")
        .expect("derive the receipt");

    // The receipt is serializable and deny-unknown-fields; a hand-built receipt
    // re-pointed at a different incumbent is refused by `validate`, which runs
    // before the coordinator stores one.
    let mut rebound = receipt.clone();
    rebound.incumbent_generation = Some(generation(7));
    let field = handshake_mismatch_field(
        rebound
            .validate()
            .expect_err("a rebound receipt must be refused"),
    );
    assert_eq!(field, "storage_replacement_cutover_receipt_binding");

    // A receipt whose two store generations are the same is refused too.
    let mut self_cutover = receipt;
    self_cutover.incumbent_generation = Some(generation(2));
    let (field, reason) = invalid_field(
        StorageReplacementCutoverReceipt::validate(&self_cutover)
            .expect_err("a self cutover receipt must be refused"),
    );
    assert_eq!(field, "storage_replacement_cutover_receipt_generations");
    assert_eq!(
        reason,
        "a cutover receipt must name two distinct store generations"
    );

    remove_ors(path, ors);
}