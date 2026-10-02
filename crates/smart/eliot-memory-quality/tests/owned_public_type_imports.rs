//! #196 W3: a consumer imports every public type the owning package exports.
//!
//! This is a **compile-time** fixture. It contains no behavioural assertion
//! about the contracts — those live in `quality.rs`. What it proves is
//! narrower and exactly what `cargo clippy --all-targets` can prove: every
//! public item of `eliot-memory-projection-contracts` is reachable by name from
//! a consumer crate that is not the owner. A type that is `pub` in the owner but
//! unreachable from outside, or renamed without a re-export, breaks this file's
//! compilation and nothing else would notice.
//!
//! ## Why this consumer
//!
//! `eliot-memory-quality` is the assessment consumer that #196's denominator
//! work actually runs through: `QualityRequest` carries a
//! `MemoryProjectionBatch` and an `ApplicableMemorySet`, so this crate is a
//! real consumer rather than a synthetic one. Its `Cargo.toml` already depends
//! on `eliot-memory-projection-contracts`, so no dependency, lockfile, or
//! manifest change is introduced here.
//!
//! ## Coverage of the owner's surface
//!
//! The import list below is the owner's complete public surface, read from
//! `crates/foundation/eliot-memory-projection-contracts/src/lib.rs`,
//! `src/contracts.rs` and `src/workflow_view.rs`:
//!
//! - `CONTRACT_NAME`, `CONTRACT_VERSION` — the identity pair.
//! - `batch`: `MEMORY_PROJECTION_MAX_RECORDS`, `MAX_BATCH_OMISSIONS`,
//!   `MAX_BATCH_FRONTIER`, `CoverageOmission`, `DenominatorState`,
//!   `MemoryProjectionBatch`, `ProjectionCoverage`.
//! - `error`: `MemoryProjectionError`.
//! - `record`: `MAX_RECORD_ROLES`, `MAX_PRECONDITIONS`,
//!   `MAX_APPLICABILITY_LIMITS`, `MAX_CUE_TRIGGERS`, `MAX_SCOPE_CHARS`,
//!   `CueTrigger`, `FreshnessState`, `MemoryFreshness`, `MemoryKind`,
//!   `MemoryProjectionRecord`, `MemoryRole`, `MemoryScopeBinding`,
//!   `NegativeTrigger`, `Precondition`.
//! - `selection`: `MemoryQueryIntent`, `MemorySelectionPolicy`,
//!   `MemorySelectionTrace`, `SelectionCoverage`, `SelectionDisposition`,
//!   `SelectionEntry`, `SelectionError`, `select`.
//! - `set`: `ApplicableMemory`, `ApplicableMemorySet`, `ExcludedMemory`,
//!   `ExclusionReason`.
//! - `workflow_view`: `MAX_WORKFLOW_ENTRIES`, `MAX_WORKFLOW_GAPS`,
//!   `WorkflowIdempotency`, `WorkflowStateView`.
//!
//! ## Registration
//!
//! A new file under `tests/` is a Cargo integration-test target and is
//! auto-discovered by target discovery; there is no crate-root `mod` line for
//! one, and adding one would be wrong (it would pull the fixture into the
//! library build instead of the consumer's test build). Nothing outside this
//! file is edited to make it compile.

#![allow(clippy::expect_used, clippy::too_many_lines, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, SessionId, SourceId,
    StateFence, TaskId,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    ApplicableMemory, ApplicableMemorySet, CONTRACT_NAME, CONTRACT_VERSION, CoverageOmission,
    CueTrigger, DenominatorState, ExcludedMemory, ExclusionReason, FreshnessState,
    MAX_APPLICABILITY_LIMITS, MAX_BATCH_FRONTIER, MAX_BATCH_OMISSIONS, MAX_CUE_TRIGGERS,
    MAX_PRECONDITIONS, MAX_RECORD_ROLES, MAX_SCOPE_CHARS, MAX_WORKFLOW_ENTRIES, MAX_WORKFLOW_GAPS,
    MEMORY_PROJECTION_MAX_RECORDS, MemoryFreshness, MemoryKind, MemoryProjectionBatch,
    MemoryProjectionError, MemoryProjectionRecord, MemoryQueryIntent, MemoryRole,
    MemoryScopeBinding, MemorySelectionPolicy, MemorySelectionTrace, NegativeTrigger, Precondition,
    ProjectionCoverage, SelectionCoverage, SelectionDisposition, SelectionEntry, SelectionError,
    WorkflowIdempotency, WorkflowStateView, select,
};
use eliot_receipts::WorkScopeId;

fn task() -> TaskId {
    TaskId::new("task-import").expect("fixture task")
}

fn scope() -> WorkScopeId {
    WorkScopeId::new("scope-import").expect("fixture scope")
}

fn session() -> SessionId {
    SessionId::new("session-import").expect("fixture session")
}

fn source() -> SourceId {
    SourceId::new("source-import").expect("fixture source")
}

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact")
}

fn fence() -> StateFence {
    // `StateFence::new` returns the fence itself, not a `Result`: the epoch and
    // generation are the only fallible steps and they are `.expect`ed above.
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("fixture lineage"),
            NonZeroU64::new(1).expect("non-zero sequence"),
        )
        .expect("fixture epoch"),
        ResourceGeneration::new(1).expect("fixture generation"),
    )
}

fn binding() -> MemoryScopeBinding {
    MemoryScopeBinding {
        task_id: task(),
        scope_id: scope(),
        session_id: Some(session()),
        state_fence: fence(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        source_id: source(),
        capture_route: "governor.read.memory".to_owned(),
        scope: "scope-import".to_owned(),
        raw_handle: None,
        revision: Some("rev-1".to_owned()),
    }
}

fn record(handle: &str) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: CONTRACT_VERSION,
        handle: aid(handle),
        kind: MemoryKind::Episode,
        binding: binding(),
        state_fence: fence(),
        projection_revision: 1,
        epistemic: EpistemicStatus::Supported,
        assertability: Assertability::NonAssertableUnverified,
        lifecycle: LifecycleState::Active,
        freshness: MemoryFreshness {
            state: FreshnessState::Current,
            note: "projected at the batch fence".to_owned(),
        },
        provenance: provenance(),
        predecessor: None,
        roles: vec![MemoryRole::Minority],
        influence_eligible: true,
        preconditions: Vec::new(),
        applicability_limits: Vec::new(),
        cue_triggers: Vec::new(),
        negative_trigger: None,
        source_id: source(),
    }
}

fn batch() -> MemoryProjectionBatch {
    MemoryProjectionBatch {
        contract_version: CONTRACT_VERSION,
        binding: binding(),
        records: vec![record("mem-1")],
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known { total: 1 },
            truncated: false,
            frontier: Vec::new(),
            omissions: Vec::new(),
            revalidation_required: false,
        },
    }
}

// WORK_UNIT_CASE: 196/W3-5
#[test]
fn every_owned_public_type_is_importable_and_usable_by_this_consumer() {
    // Identity pair.
    assert_eq!(
        CONTRACT_NAME,
        "eliot.foundation.memory-projection-contracts"
    );
    assert_eq!(CONTRACT_VERSION, ContractVersion::new(0, 2, 0));

    // Every owner-declared bound is nameable and readable from here. These are
    // the ceilings a consumer sizes its own buffers against, so an unreadable
    // one is a real consumer defect rather than a cosmetic import failure.
    assert_eq!(MEMORY_PROJECTION_MAX_RECORDS, 256);
    assert_eq!(MAX_BATCH_OMISSIONS, 256);
    assert_eq!(MAX_BATCH_FRONTIER, 256);
    assert_eq!(MAX_RECORD_ROLES, 8);
    assert_eq!(MAX_PRECONDITIONS, 32);
    assert_eq!(MAX_APPLICABILITY_LIMITS, 32);
    assert_eq!(MAX_CUE_TRIGGERS, 32);
    assert_eq!(MAX_SCOPE_CHARS, 256);
    assert_eq!(MAX_WORKFLOW_ENTRIES, 64);
    assert_eq!(MAX_WORKFLOW_GAPS, 32);

    // `record`, `batch`, and the coverage/denominator/omission trio, exercised
    // through the owner's own validators so the fixture cannot pass against a
    // stub that merely has the right names.
    let value = batch();
    value.validate().expect("batch validates");
    value.records[0].validate().expect("record validates");
    value.coverage.validate().expect("coverage validates");
    value
        .coverage
        .denominator
        .validate()
        .expect("denominator validates");
    assert!(matches!(
        value.coverage.denominator,
        DenominatorState::Known { total: 1 }
    ));
    let omission = CoverageOmission {
        handle: aid("mem-2"),
        reason: "fence-mismatch".to_owned(),
    };
    omission.validate().expect("named omission validates");

    // `MemoryFreshness`, `Precondition`, `CueTrigger`, `NegativeTrigger` — each
    // is a distinct owner type with its own validator.
    let freshness = MemoryFreshness {
        state: FreshnessState::Unknown,
        note: "freshness owner has not answered".to_owned(),
    };
    freshness.validate().expect("freshness validates");
    let precondition = Precondition {
        id: "pre-1".to_owned(),
        satisfied: Some(true),
    };
    precondition.validate().expect("precondition validates");
    let cue = CueTrigger {
        cue_id: "cue-1".to_owned(),
        exact_match_required: true,
    };
    cue.validate().expect("cue trigger validates");
    let negative = NegativeTrigger {
        trigger: "task-import".to_owned(),
        failed_action: "summarize".to_owned(),
        outcome: "lost the minority record".to_owned(),
        violated_invariant: "minority evidence is retained".to_owned(),
        reopen_condition: "a revalidation admits the record".to_owned(),
        extinction_condition: "the trigger is superseded".to_owned(),
    };
    negative.validate().expect("negative trigger validates");

    // The selection family: intent, policy, the `select` entry point, and every
    // trace member, joined through the owner's own consumer-side recheck.
    let intent =
        MemoryQueryIntent::new(binding(), vec![MemoryKind::Episode], 4).expect("intent validates");
    let policy = MemorySelectionPolicy::new(8).expect("policy validates");
    // The annotation is load-bearing, not decorative: it is what makes the
    // `MemorySelectionTrace` import used, and it proves at compile time that
    // `select` returns exactly the owner's public trace type rather than a
    // look-alike. Deleting the import would weaken this case's own claim that
    // every owned public type is usable from this consumer.
    let trace: MemorySelectionTrace =
        select(&intent, &policy, &value).expect("selection over the batch");
    trace.validate().expect("trace validates");
    trace
        .validate_against(&intent, &policy, &value)
        .expect("trace is bound to its intent, policy, and batch");
    assert!(matches!(
        trace.entries[0].disposition,
        SelectionDisposition::Selected
    ));
    assert_eq!(trace.coverage.considered, 1);
    assert_eq!(trace.coverage.selected, 1);
    assert_eq!(trace.coverage.not_selected, 0);
    let entry: &SelectionEntry = &trace.entries[0];
    assert_eq!(entry.handle, aid("mem-1"));
    assert_eq!(entry.kind, MemoryKind::Episode);
    let coverage: &SelectionCoverage = &trace.coverage;
    assert_eq!(
        coverage.considered,
        coverage.selected + coverage.not_selected
    );

    // The verdict family, joined against the same batch it describes.
    let set = ApplicableMemorySet {
        contract_version: CONTRACT_VERSION,
        binding: value.binding.clone(),
        applicable: vec![ApplicableMemory {
            handle: aid("mem-1"),
            kind: MemoryKind::Episode,
            roles: vec![MemoryRole::Minority],
            cue_hit: false,
        }],
        excluded: Vec::<ExcludedMemory>::new(),
        denominator: DenominatorState::Known { total: 1 },
        truncated: false,
        revalidation_required: false,
        cue_hits_considered: 0,
    };
    set.validate().expect("verdict validates");
    set.validate_against_batch(&value)
        .expect("verdict is bound to the batch");

    // Every `ExclusionReason` variant, each named from here.
    for reason in [
        ExclusionReason::Stale,
        ExclusionReason::Conflicted,
        ExclusionReason::Rejected,
        ExclusionReason::EpistemicallyUnknown,
        ExclusionReason::Protected,
        ExclusionReason::InfluenceIneligible,
        ExclusionReason::NegativeMemory,
        ExclusionReason::PreconditionFailed {
            id: "pre-1".to_owned(),
        },
        ExclusionReason::PreconditionUnassessed {
            id: "pre-2".to_owned(),
        },
        ExclusionReason::LifecycleInactive,
        ExclusionReason::FenceMismatch,
        ExclusionReason::ScopeMismatch,
    ] {
        reason.validate().expect("owner reason validates");
    }

    // The typed error type, reached by the consumer's own refusal rather than
    // by naming a variant only: a wrong-scope record must surface as the owner's
    // `MemoryProjectionError` from this crate's call site.
    let mut wrong_scope = batch();
    wrong_scope.records[0].binding.scope_id =
        WorkScopeId::new("scope-elsewhere").expect("other scope");
    let refused: MemoryProjectionError = wrong_scope
        .validate()
        .expect_err("wrong-scope record is refused");
    assert!(matches!(
        refused,
        MemoryProjectionError::ScopeMismatch { .. }
    ));

    // The workflow view family, which the owner's root re-exports beside the
    // CC-008 cell.
    let view = WorkflowStateView {
        workflow_id: "workflow:import".to_owned(),
        task_id: task(),
        scope_id: scope(),
        current_step: "step:capture".to_owned(),
        previous_step: Some("step:plan".to_owned()),
        step_owner: "owner:operator".to_owned(),
        inputs: vec!["blob:raw".to_owned()],
        outputs: vec!["blob:thumbnail".to_owned()],
        pending_commitments: Vec::new(),
        external_effects: Vec::new(),
        expected_observable: "thumbnail at 640x480".to_owned(),
        verifier_ref: "verifier:vision".to_owned(),
        resume_boundary: "boundary:after-capture".to_owned(),
        idempotency: WorkflowIdempotency::Idempotent {
            key: "idempotency:capture-1".to_owned(),
        },
        artifact_lineage: vec!["artifact:panel".to_owned()],
        unresolved_representation_gaps: vec!["sub-pixel hue unmeasured".to_owned()],
    };
    view.validate().expect("workflow view validates");
    let idempotent_key = match &view.idempotency {
        WorkflowIdempotency::Idempotent { key } => key.clone(),
        other => panic!("fixture must be idempotent, got {other:?}"),
    };
    assert_eq!(idempotent_key.as_str(), "idempotency:capture-1");
    let _: SelectionError = SelectionError::EmptyKinds;
}
