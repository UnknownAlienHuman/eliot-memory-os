//! Issue #804 acceptance matrix: the 42 cases missing from `contract_shape.rs`.
//!
//! Each test name appears verbatim in `module.toml` under
//! `[acceptance].required_tests`, and each carries its `WORK_UNIT_CASE`
//! marker, so a case cannot be dropped without the gate noticing. The eight
//! cases already covered in `contract_shape.rs` are not repeated here.

// Assertions in a test use `expect`/`unwrap` deliberately; the workspace lints
// target production paths.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ReceiptId, ResourceGeneration, SourceId, StateFence,
};
use eliot_cue_contracts::{
    ActivationBounds, ActivationBoundsSpec, ActivationRequest, ActivationRequestId,
    ActivationRequestSpec, ActivationResult, ActivationResultSpec, ActivationStrength,
    ActivationTrace, BindingCandidateId, BindingDisposition, BindingRole, BoundKind,
    CanonicalCueId, CanonicalCueIdentity, ComparisonForm, ComparisonKey, ComparisonKeyId,
    Completeness, CueBindingAdmissionRef, CueBindingCandidate, CueContext, CueContractError,
    CueKind, CueSnapshot, CueSnapshotBuildCandidate, DerivedActivation, DerivedTarget, Digest,
    DirectActivation, InvalidationCause, MatchMode, NormalizationOutcome, NormalizationProfile,
    NormalizedCue, ObservedCue, ObservedCueId, RedactedDiagnostic, RelationEdgeId,
    RelationEdgeInput, RetrievalLineage, SnapshotId, SnapshotInvalidation, SnapshotMember,
    SourceHandle, TargetHandle, is_supported_schema_revision,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, Provenance, RelationKind,
};
use eliot_receipts::{ProofCeiling, ReceiptIdentity, WorkScopeId};
use eliot_security_contracts::PrivacyClass;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REVISION: &str = "2.0.0";

fn digest(seed: u8) -> Digest {
    Digest::new(format!("{seed:02x}").repeat(32)).expect("64 hex characters")
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn next_fence() -> StateFence {
    StateFence::new(
        AuthorityEpoch::new(2).expect("non-genesis epoch"),
        ResourceGeneration::genesis(),
    )
}

fn provenance() -> Provenance {
    Provenance {
        source_id: SourceId::new("eliot-cue-contracts-tests").expect("source id"),
        capture_route: "unit-test".to_owned(),
        scope: "scope-1".to_owned(),
        raw_handle: None,
        revision: None,
    }
}

fn source() -> SourceHandle {
    SourceHandle::new(
        TargetHandle::new("crates/smart/eliot-cue-contracts/src/lib.rs").expect("target"),
        digest(0xa1),
        provenance(),
    )
}

fn context() -> CueContext {
    CueContext::new(
        eliot_contracts::TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
        EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: provenance(),
            verification: None,
            state_fence: fence(),
        },
        LifecycleState::Active,
        PrivacyClass::Public,
        ProofCeiling::Observation,
    )
}

fn profile() -> NormalizationProfile {
    NormalizationProfile::new("symbol-v1".to_owned(), 1, digest(0xb2))
}

fn observed_kind(value: &str, kind: CueKind) -> ObservedCue {
    ObservedCue::new(
        REVISION.to_owned(),
        ObservedCueId::new("observed-1").expect("id"),
        kind,
        value.to_owned(),
        source(),
        context(),
    )
}

fn observed(value: &str) -> ObservedCue {
    observed_kind(value, CueKind::Symbol)
}

fn canonical_kind(value: &str, kind: CueKind, seed: u8) -> CanonicalCueIdentity {
    CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{seed}")).expect("id"),
        kind,
        value.to_owned(),
        digest(seed),
    )
}

fn canonical(value: &str, seed: u8) -> CanonicalCueIdentity {
    canonical_kind(value, CueKind::Symbol, seed)
}

fn key_with(value: &str, mode: MatchMode, form: ComparisonForm, seed: u8) -> ComparisonKey {
    ComparisonKey::new(
        ComparisonKeyId::new(format!("key-{seed}")).expect("id"),
        profile(),
        value.to_owned(),
        mode,
        form,
    )
}

fn key(value: &str, mode: MatchMode, seed: u8) -> ComparisonKey {
    key_with(value, mode, ComparisonForm::CaseInsensitive, seed)
}

fn normalized(value: &str, keys: Vec<ComparisonKey>) -> NormalizedCue {
    NormalizedCue::new(
        REVISION.to_owned(),
        observed(value),
        profile(),
        Some(canonical(value, 0xc3)),
        keys,
        NormalizationOutcome::Lossless,
        Vec::new(),
    )
}

fn edge(index: usize) -> RelationEdgeId {
    RelationEdgeId::new(format!("edge-{index}")).expect("edge id")
}

fn bounds_spec(depth: u8) -> ActivationBoundsSpec {
    ActivationBoundsSpec {
        max_depth: depth,
        max_fanout: 16,
        max_results: 64,
        max_nodes: 256,
        max_edges: 4096,
        max_work: 100_000,
        max_path_len: 8,
        max_seeds: 64,
        max_direct: 256,
        max_derived: 512,
        max_trace_steps: 1024,
        max_output_bytes: 1_000_000,
        activation_threshold: ActivationStrength(1),
    }
}

fn request_full(
    seeds: Vec<NormalizedCue>,
    edges: Vec<RelationEdgeInput>,
    bounds: ActivationBounds,
) -> ActivationRequest {
    ActivationRequest::new(ActivationRequestSpec {
        schema_revision: REVISION.to_owned(),
        request_id: ActivationRequestId::new("request-1").expect("id"),
        seeds,
        snapshot_id: SnapshotId::new("snapshot-1").expect("id"),
        relation_edges: edges,
        bounds,
        state_fence: fence(),
        normalization_profile: profile(),
        observed_at: ClockReading::default(),
        deadline_ms: None,
        cancelled: false,
    })
}

fn request(edges: Vec<RelationEdgeInput>, depth: u8) -> ActivationRequest {
    request_full(
        vec![normalized(
            "TaskContract",
            vec![key("taskcontract", MatchMode::Exact, 1)],
        )],
        edges,
        ActivationBounds::new(bounds_spec(depth)),
    )
}

fn relation_edge(index: usize, from: TargetHandle, to: TargetHandle) -> RelationEdgeInput {
    RelationEdgeInput::new(
        edge(index),
        RelationKind::Supports,
        from,
        to,
        REVISION.to_owned(),
        digest(u8::try_from(index).unwrap_or(1)),
        context().evidence,
    )
}

fn direct_hit() -> DirectActivation {
    DirectActivation::new(
        TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        key("taskcontract", MatchMode::Exact, 1),
        ActivationStrength(10),
    )
}

fn result(
    direct: Vec<DirectActivation>,
    derived: Vec<DerivedActivation>,
    completeness: Completeness,
) -> ActivationResult {
    let asked = request(Vec::new(), 0);
    ActivationResult::new(ActivationResultSpec {
        schema_revision: REVISION.to_owned(),
        request_id: ActivationRequestId::new("request-1").expect("id"),
        snapshot_id: asked.snapshot_id,
        normalization_profile: asked.normalization_profile,
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct,
        derived,
        completeness,
        trace: ActivationTrace::empty(),
    })
}

fn snapshot_with(recorded: Digest) -> CueSnapshot {
    CueSnapshot::new(
        REVISION.to_owned(),
        SnapshotId::new("snapshot-1").expect("id"),
        vec![SnapshotMember::new(
            canonical("TaskContract", 0xc3),
            TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        )],
        eliot_cue_contracts::RebuildIdentity::new(profile(), vec![source()], recorded),
        fence(),
    )
}

fn valid_snapshot() -> CueSnapshot {
    let staging = snapshot_with(digest(0xd4));
    let mut valid = staging;
    valid.rebuild.digest = valid.canonical_digest().expect("digest");
    valid
}

fn candidate_for(cue: &NormalizedCue, target: &str, seed: u8) -> CueBindingCandidate {
    CueBindingCandidate::new(
        BindingCandidateId::new(format!("candidate-{seed}")).expect("id"),
        cue.canonical.clone().expect("lossless canonical"),
        TargetHandle::new(target).expect("target"),
        BindingRole::Names,
        EvidenceFreshness::ExactCandidate,
        BindingDisposition::Withheld,
        digest(seed),
    )
}

fn admission_for(candidate: &CueBindingCandidate, seed: u8) -> CueBindingAdmissionRef {
    let receipt_digest = digest(seed.wrapping_add(1));
    CueBindingAdmissionRef::new(
        ReceiptIdentity {
            receipt_id: ReceiptId::new(format!("receipt-{}", receipt_digest.as_str()))
                .expect("receipt id"),
            canonical_sha256: receipt_digest.as_str().to_owned(),
        },
        candidate.binding_candidate_id.clone(),
        candidate.digest.clone(),
        eliot_contracts::TaskId::new("task-1").expect("task"),
        WorkScopeId::new("scope-1").expect("scope"),
        fence(),
    )
}

fn projection_for(
    id: &str,
    cue: &str,
    target: &str,
    seed: u8,
) -> eliot_cue_contracts::AdmittedCueBindingProjection {
    let canonical = CanonicalCueIdentity::new(
        CanonicalCueId::new(format!("canonical-{id}")).expect("id"),
        CueKind::Symbol,
        cue.to_owned(),
        digest(3),
    );
    let observed = ObservedCue::new(
        REVISION.to_owned(),
        ObservedCueId::new(format!("obs-{id}")).expect("id"),
        CueKind::Symbol,
        cue.to_owned(),
        SourceHandle::new(
            TargetHandle::new(target).expect("target"),
            digest(2),
            provenance(),
        ),
        context(),
    );
    let comparison = ComparisonKey::new(
        ComparisonKeyId::new(format!("key-{id}")).expect("id"),
        profile(),
        cue.to_owned(),
        MatchMode::Exact,
        ComparisonForm::Exact,
    );
    let normalized = NormalizedCue::new(
        REVISION.to_owned(),
        observed,
        profile(),
        Some(canonical.clone()),
        vec![comparison],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    let candidate = CueBindingCandidate::new(
        BindingCandidateId::new(format!("candidate-{id}")).expect("id"),
        canonical,
        TargetHandle::new(target).expect("target"),
        BindingRole::Names,
        EvidenceFreshness::ExactCandidate,
        BindingDisposition::Withheld,
        digest(seed),
    );
    let admission = admission_for(&candidate, seed);
    eliot_cue_contracts::AdmittedCueBindingProjection::new(candidate, normalized, admission)
}

fn snapshot_for(projections: &[eliot_cue_contracts::AdmittedCueBindingProjection]) -> CueSnapshot {
    let members = projections
        .iter()
        .map(|projection| {
            SnapshotMember::new(
                projection.candidate.canonical.clone(),
                projection.candidate.target.clone(),
            )
        })
        .collect();
    let mut sources = Vec::new();
    for projection in projections {
        let found = projection.normalized.observed.source.clone();
        if !sources.iter().any(|known: &SourceHandle| known == &found) {
            sources.push(found);
        }
    }
    let mut snapshot = CueSnapshot::new(
        REVISION.to_owned(),
        SnapshotId::new("snapshot-1").expect("id"),
        members,
        eliot_cue_contracts::RebuildIdentity::new(profile(), sources, digest(9)),
        fence(),
    );
    snapshot.rebuild.digest = snapshot.canonical_digest().expect("digest");
    snapshot
}

fn lineage() -> RetrievalLineage {
    RetrievalLineage::seal(
        SnapshotId::new("snapshot-1").expect("id"),
        vec![source()],
        vec![TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target")],
        vec![
            DerivedTarget::new(
                TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
            )
            .expect("derived"),
        ],
        vec![BindingCandidateId::new("candidate-1").expect("id")],
        vec![digest(0xe1)],
    )
    .expect("valid lineage")
}

fn invalidation() -> SnapshotInvalidation {
    SnapshotInvalidation::seal(
        SnapshotId::new("snapshot-2").expect("id"),
        InvalidationCause::ProfileChanged {
            prior_profile_digest: digest(0xb2),
            current_profile_digest: digest(0xb3),
        },
        context().evidence,
        SnapshotId::new("snapshot-1").expect("id"),
        Vec::new(),
    )
    .expect("valid invalidation")
}

// Case 2 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/2
#[test]
fn cue_kind_is_defined_once_without_eliot_types_dependency() -> TestResult {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("eliot-types"),
        "the vocabulary owner must not depend on eliot-types"
    );
    assert!(
        manifest.contains("[dependencies]"),
        "the manifest shape must still be intact"
    );
    // The kind is defined and usable locally: every variant round-trips here,
    // and the array pins the declared vocabulary at ten variants.
    let kinds = [
        CueKind::FilePath,
        CueKind::DirPath,
        CueKind::Symbol,
        CueKind::ErrorSignature,
        CueKind::CommandPattern,
        CueKind::Dependency,
        CueKind::ApiSurface,
        CueKind::TaskClass,
        CueKind::Subsystem,
        CueKind::Concept,
    ];
    assert_eq!(kinds.len(), 10);
    for kind in kinds {
        let round_trip: CueKind = serde_json::from_str(&serde_json::to_string(&kind)?)?;
        assert_eq!(round_trip, kind);
    }
    Ok(())
}

// Case 3 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/3
#[test]
fn observed_cue_supports_every_current_kind() -> TestResult {
    let kinds = [
        CueKind::FilePath,
        CueKind::DirPath,
        CueKind::Symbol,
        CueKind::ErrorSignature,
        CueKind::CommandPattern,
        CueKind::Dependency,
        CueKind::ApiSurface,
        CueKind::TaskClass,
        CueKind::Subsystem,
        CueKind::Concept,
    ];
    for kind in kinds {
        let cue = observed_kind("TaskContract", kind);
        cue.validate()?;
        let round_trip: ObservedCue = serde_json::from_str(&serde_json::to_string(&cue)?)?;
        assert_eq!(round_trip.kind, kind);
        round_trip.validate()?;
    }
    Ok(())
}

// Case 4 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/4
#[test]
fn unknown_schema_field_variant_mode_and_status_are_rejected() -> TestResult {
    fn rejects_extra<T>(value: &T) -> TestResult
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json::to_string(value)?;
        let tampered = json.replacen('{', "{\"__smuggled__\":1,", 1);
        assert_ne!(json, tampered, "the fixture must actually gain a field");
        assert!(
            serde_json::from_str::<T>(&tampered).is_err(),
            "an unknown field must be rejected, not ignored"
        );
        Ok(())
    }

    rejects_extra(&observed("TaskContract"))?;
    rejects_extra(&normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    ))?;
    rejects_extra(&canonical("TaskContract", 0xc3))?;
    rejects_extra(&key("taskcontract", MatchMode::Exact, 1))?;
    rejects_extra(&candidate_for(
        &normalized(
            "TaskContract",
            vec![key("taskcontract", MatchMode::Exact, 1)],
        ),
        "crates/eliot-types/src/lib.rs",
        7,
    ))?;
    rejects_extra(&valid_snapshot())?;
    rejects_extra(&request(Vec::new(), 0))?;
    rejects_extra(&result(
        vec![direct_hit()],
        Vec::new(),
        Completeness::Complete,
    ))?;
    rejects_extra(&lineage())?;
    rejects_extra(&invalidation())?;
    rejects_extra(&RedactedDiagnostic::redact(
        CueKind::ErrorSignature,
        "E001: clean diagnostic",
    )?)?;

    // Unknown kind, mode, outcome and completeness variants are rejected too.
    for payload in [
        "\"fuzzy_kind\"",
        "\"embedding\"",
        "\"semantic\"",
        "\"substring\"",
    ] {
        assert!(
            serde_json::from_str::<CueKind>(payload).is_err(),
            "{payload} is not a cue kind"
        );
        assert!(
            serde_json::from_str::<MatchMode>(payload).is_err(),
            "{payload} is not a match mode"
        );
    }
    for payload in [
        "{\"outcome\":\"fuzzy\"}",
        "{\"outcome\":\"semantic_match\"}",
        "{\"completeness\":\"fuzzy\"}",
        "{\"completeness\":\"delivered\"}",
    ] {
        assert!(
            serde_json::from_str::<NormalizationOutcome>(payload).is_err()
                || serde_json::from_str::<Completeness>(payload).is_err(),
            "{payload} must be rejected"
        );
    }
    Ok(())
}

// Case 5 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/5
#[test]
fn missing_empty_and_unknown_source_identity_are_distinct() -> TestResult {
    // Missing: the `source` member is absent from the wire record.
    let mut wire: serde_json::Value = serde_json::to_value(observed("TaskContract"))?;
    wire.as_object_mut().expect("object").remove("source");
    let missing = serde_json::from_value::<ObservedCue>(wire);
    assert!(missing.is_err(), "a missing source must be rejected");

    // Empty: a blank target handle is rejected at construction.
    let empty = TargetHandle::new("");
    assert_eq!(
        empty,
        Err(CueContractError::InvalidText {
            field: "target_handle"
        })
    );

    // Unknown: a malformed digest is rejected at construction, distinctly.
    let unknown = Digest::new("z".repeat(64));
    assert_eq!(
        unknown,
        Err(CueContractError::InvalidText { field: "digest" })
    );
    let Err(empty_error) = empty else {
        panic!("a blank target must be rejected");
    };
    let Err(unknown_error) = Digest::new("z".repeat(64)) else {
        panic!("a malformed digest must be rejected");
    };
    assert_ne!(empty_error, unknown_error);
    Ok(())
}

// Case 7 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/7
#[test]
fn identical_text_in_different_cue_kinds_remains_distinct() -> TestResult {
    let symbol = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("TaskContract", CueKind::Symbol),
        profile(),
        Some(canonical_kind("TaskContract", CueKind::Symbol, 1)),
        vec![key("taskcontract", MatchMode::Exact, 1)],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    let concept = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("TaskContract", CueKind::Concept),
        profile(),
        Some(canonical_kind("TaskContract", CueKind::Concept, 2)),
        vec![key("taskcontract", MatchMode::Exact, 2)],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    symbol.validate()?;
    concept.validate()?;
    assert_ne!(symbol, concept, "kind is part of identity");

    // A canonical identity whose kind disagrees with its observation is
    // rejected rather than folded into the other kind.
    let mismatched = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("TaskContract", CueKind::Symbol),
        profile(),
        Some(canonical_kind("TaskContract", CueKind::Concept, 2)),
        vec![key("taskcontract", MatchMode::Exact, 2)],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    assert_eq!(
        mismatched.validate(),
        Err(CueContractError::Foundation {
            field: "canonical.kind"
        })
    );
    Ok(())
}

// Case 8 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/8
#[test]
fn exact_mode_rejects_fuzzy_embedding_substring_and_semantic_matching() -> TestResult {
    // The closed vocabulary has exactly three modes; every fuzzy-adjacent
    // spelling is rejected at the schema boundary.
    for wire in ["\"exact\"", "\"prefix\"", "\"signature\""] {
        let mode: MatchMode = serde_json::from_str(wire)?;
        let round_trip: MatchMode = serde_json::from_str(&serde_json::to_string(&mode)?)?;
        assert_eq!(mode, round_trip);
    }
    for wire in [
        "\"fuzzy\"",
        "\"embedding\"",
        "\"substring\"",
        "\"semantic\"",
        "\"similarity\"",
    ] {
        assert!(
            serde_json::from_str::<MatchMode>(wire).is_err(),
            "{wire} must not decode as a match mode"
        );
    }

    // Exact comparison is byte equality: case, affix and truncation differences
    // do not match, and only an identical key proves an exact hit.
    let exact = key("TaskContract", MatchMode::Exact, 1);
    assert_ne!(exact.key_value, "taskcontract");
    assert_ne!(exact.key_value, "TaskContractX");
    assert_ne!(exact.key_value, "TaskContrac");
    assert_eq!(exact.key_value, "TaskContract");

    // Prefix and Signature stay explicitly permitted compatible forms with
    // kind-gated validity, not general fuzzy fallbacks.
    let path_cue = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("crates/a.rs", CueKind::FilePath),
        profile(),
        Some(canonical_kind("crates/a.rs", CueKind::FilePath, 3)),
        vec![key_with(
            "crates/",
            MatchMode::Prefix,
            ComparisonForm::PathNormalized,
            3,
        )],
        NormalizationOutcome::Lossless,
        Vec::new(),
    );
    path_cue.validate()?;
    let mut fuzzy_prefix = path_cue;
    fuzzy_prefix.comparison_keys[0].match_mode = MatchMode::Exact;
    fuzzy_prefix.comparison_keys[0].key_value = "crates".to_owned();
    assert_ne!(
        fuzzy_prefix.comparison_keys[0].key_value, "crates/a.rs",
        "a non-identical key never proves an exact hit"
    );
    Ok(())
}

// Case 9 ---------------------------------------------------------------------
// WORK_UNIT_CASE: 804/9
#[test]
fn normalization_outcomes_cover_lossless_authorized_loss_ambiguous_and_unsupported() -> TestResult {
    let lossless = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    lossless.validate()?;

    let authorized_loss = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("crates/a.rs", CueKind::FilePath),
        profile(),
        Some(canonical_kind("crates/a.rs", CueKind::FilePath, 4)),
        vec![key_with(
            "crates/",
            MatchMode::Prefix,
            ComparisonForm::PathNormalized,
            4,
        )],
        NormalizationOutcome::AuthorizedLoss {
            policy_ref: "path-prefix-fold".to_owned(),
        },
        Vec::new(),
    );
    authorized_loss.validate()?;

    let ambiguous = NormalizedCue::new(
        REVISION.to_owned(),
        observed("TaskContract"),
        profile(),
        None,
        Vec::new(),
        NormalizationOutcome::Ambiguous {
            rivals: vec![canonical("TaskContract", 5), canonical("TaskContract", 6)],
        },
        Vec::new(),
    );
    ambiguous.validate()?;

    let unsupported = NormalizedCue::new(
        REVISION.to_owned(),
        observed("TaskContract"),
        profile(),
        None,
        Vec::new(),
        NormalizationOutcome::Unsupported {
            reason: "profile does not cover this cue".to_owned(),
        },
        Vec::new(),
    );
    unsupported.validate()?;

    let wires = [
        serde_json::to_value(&lossless)?,
        serde_json::to_value(&authorized_loss)?,
        serde_json::to_value(&ambiguous)?,
        serde_json::to_value(&unsupported)?,
    ];
    for pair in wires.windows(2) {
        assert_ne!(pair[0], pair[1], "outcomes must stay distinct");
    }
    Ok(())
}

// Case 10 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/10
#[test]
fn lossy_or_ambiguous_normalization_cannot_prove_exact_match() -> TestResult {
    // An authorized loss with an exact key claims lossless proof it did not earn.
    let mut lossy_exact = NormalizedCue::new(
        REVISION.to_owned(),
        observed_kind("crates/a.rs", CueKind::FilePath),
        profile(),
        Some(canonical_kind("crates/a.rs", CueKind::FilePath, 4)),
        vec![key_with(
            "crates/a.rs",
            MatchMode::Exact,
            ComparisonForm::PathNormalized,
            4,
        )],
        NormalizationOutcome::AuthorizedLoss {
            policy_ref: "path-prefix-fold".to_owned(),
        },
        Vec::new(),
    );
    assert_eq!(
        lossy_exact.validate(),
        Err(CueContractError::Foundation {
            field: "comparison_key.match_mode"
        })
    );
    lossy_exact.comparison_keys.clear();
    lossy_exact.validate()?;

    // An ambiguous record with keys resolves what it declared unresolved.
    let mut ambiguous_keys = NormalizedCue::new(
        REVISION.to_owned(),
        observed("TaskContract"),
        profile(),
        None,
        vec![key("taskcontract", MatchMode::Exact, 1)],
        NormalizationOutcome::Ambiguous {
            rivals: vec![canonical("TaskContract", 5), canonical("TaskContract", 6)],
        },
        Vec::new(),
    );
    assert!(ambiguous_keys.validate().is_err());
    ambiguous_keys.comparison_keys.clear();
    ambiguous_keys.validate()?;

    // A request refuses lossy-unproven seeds outright: neither ambiguous nor
    // unsupported outcomes can seed activation.
    for outcome in [
        NormalizationOutcome::Ambiguous {
            rivals: vec![canonical("TaskContract", 5), canonical("TaskContract", 6)],
        },
        NormalizationOutcome::Unsupported {
            reason: "profile does not cover this cue".to_owned(),
        },
    ] {
        let seed = NormalizedCue::new(
            REVISION.to_owned(),
            observed("TaskContract"),
            profile(),
            None,
            Vec::new(),
            outcome,
            Vec::new(),
        );
        assert_eq!(
            request_full(
                vec![seed],
                Vec::new(),
                ActivationBounds::new(bounds_spec(0))
            )
            .validate(),
            Err(CueContractError::Foundation {
                field: "request.seed_outcome"
            })
        );
    }
    Ok(())
}

// Case 11 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/11
#[test]
fn valid_binding_candidate_preserves_immutable_target() -> TestResult {
    let cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    let candidate = candidate_for(&cue, "crates/eliot-types/src/lib.rs", 7);
    candidate.validate()?;

    let round_trip: CueBindingCandidate =
        serde_json::from_str(&serde_json::to_string(&candidate)?)?;
    round_trip.validate()?;
    assert_eq!(
        round_trip.target.as_str(),
        "crates/eliot-types/src/lib.rs",
        "the target handle is preserved byte-exact"
    );
    assert_eq!(round_trip.digest, candidate.digest);
    assert_eq!(round_trip.canonical, candidate.canonical);
    assert_eq!(round_trip, candidate);
    Ok(())
}

// Case 12 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/12
#[test]
fn binding_rejects_target_source_scope_fence_and_revision_mismatch() {
    // Blank targets and malformed digests never become candidates.
    assert!(TargetHandle::new("").is_err());
    assert!(Digest::new("short").is_err());
    let cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    let candidate = candidate_for(&cue, "crates/eliot-types/src/lib.rs", 7);

    // A scope the observation was not captured under is rejected at the join.
    let mut scoped = admission_for(&candidate, 7);
    scoped.scope_id = WorkScopeId::new("scope-2").expect("scope");
    assert_eq!(
        scoped.validate_against(&candidate, &cue),
        Err(CueContractError::Foundation {
            field: "admission.context"
        })
    );

    // A task that does not own the observation is rejected at the join.
    let mut tasked = admission_for(&candidate, 7);
    tasked.task_id = eliot_contracts::TaskId::new("task-2").expect("task");
    assert_eq!(
        tasked.validate_against(&candidate, &cue),
        Err(CueContractError::Foundation {
            field: "admission.context"
        })
    );

    // A tampered candidate digest breaks the admission join.
    let mut tampered = admission_for(&candidate, 7);
    tampered.candidate_digest = digest(0xff);
    assert_eq!(
        tampered.validate_against(&candidate, &cue),
        Err(CueContractError::Foundation {
            field: "admission.candidate"
        })
    );

    // A blank registry revision is not an edge.
    let mut edge = relation_edge(
        1,
        TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
    );
    edge.registry_revision = String::new();
    assert_eq!(
        edge.validate(),
        Err(CueContractError::InvalidText {
            field: "relation.registry_revision"
        })
    );

    // A seed fenced outside the request is rejected before activation. The seed
    // stays internally consistent (its evidence fence moves with it) so the
    // request-level fence join is what rejects it.
    let mut fenced = request(Vec::new(), 0);
    fenced.seeds[0].observed.context.state_fence = next_fence();
    fenced.seeds[0].observed.context.evidence.state_fence = next_fence();
    assert_eq!(
        fenced.validate(),
        Err(CueContractError::Foundation {
            field: "request.seed_fence"
        })
    );
}

// Case 13 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/13
#[test]
fn binding_candidate_cannot_carry_canonical_action_or_status_mutation() -> TestResult {
    let cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    let candidate = candidate_for(&cue, "crates/eliot-types/src/lib.rs", 7);
    let wire: serde_json::Value = serde_json::to_value(&candidate)?;
    let mut keys: Vec<&str> = wire
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "binding_candidate_id",
            "canonical",
            "digest",
            "disposition",
            "freshness",
            "role",
            "target"
        ],
        "the candidate carries exactly its declared fields"
    );
    for smuggled in ["action", "status", "mutation", "effect", "command"] {
        let tampered = serde_json::to_string(&candidate)?.replacen(
            '{',
            &format!("{{\"{smuggled}\":\"run\","),
            1,
        );
        assert!(
            serde_json::from_str::<CueBindingCandidate>(&tampered).is_err(),
            "{smuggled} must be rejected, not carried"
        );
    }
    Ok(())
}

// Case 14 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/14
#[test]
fn complete_snapshot_is_rebuildable_from_exact_inputs() -> TestResult {
    let mut snapshot = snapshot_with(digest(0xd4));
    assert_eq!(
        snapshot.validate(),
        Err(CueContractError::SnapshotNotRebuildable),
        "a placeholder digest never validates"
    );
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    snapshot.validate()?;

    // Rebuilding from the exact recorded inputs reproduces the digest.
    let rebuilt = CueSnapshot::new(
        snapshot.schema_revision.clone(),
        snapshot.snapshot_id.clone(),
        snapshot.members.clone(),
        eliot_cue_contracts::RebuildIdentity::new(
            snapshot.rebuild.normalization_profile.clone(),
            snapshot.rebuild.source_denominator.clone(),
            snapshot.rebuild.digest.clone(),
        ),
        snapshot.state_fence.clone(),
    );
    rebuilt.validate()?;
    assert_eq!(rebuilt.canonical_digest()?, snapshot.canonical_digest()?);

    // Any member change breaks the rebuild.
    let mut tampered = snapshot.clone();
    tampered.members[0].target =
        TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target");
    assert_eq!(
        tampered.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );
    Ok(())
}

// Case 15 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/15
#[test]
fn snapshot_denominator_arithmetic_reconciles() -> TestResult {
    let second_source = SourceHandle::new(
        TargetHandle::new("crates/smart/eliot-cue-contracts/src/snapshot.rs").expect("target"),
        digest(0xa2),
        provenance(),
    );
    let mut snapshot = valid_snapshot();
    snapshot.rebuild.source_denominator.push(second_source);
    snapshot.members.push(SnapshotMember::new(
        canonical("AnotherCue", 0xc5),
        TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("target"),
    ));
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    snapshot.validate()?;
    assert_eq!(snapshot.rebuild.source_denominator.len(), 2);
    assert_eq!(snapshot.members.len(), 2);

    // A duplicated denominator entry is a conflicting claim, not a second vote.
    let mut duplicated = snapshot.clone();
    duplicated
        .rebuild
        .source_denominator
        .push(duplicated.rebuild.source_denominator[0].clone());
    assert_eq!(
        duplicated.validate(),
        Err(CueContractError::DuplicateIdentity {
            field: "source_denominator"
        })
    );

    // The zero case reconciles: no sources and no members is a valid snapshot.
    let mut empty = CueSnapshot::new(
        REVISION.to_owned(),
        SnapshotId::new("snapshot-empty").expect("id"),
        Vec::new(),
        eliot_cue_contracts::RebuildIdentity::new(profile(), Vec::new(), digest(0xd4)),
        fence(),
    );
    empty.rebuild.digest = empty.canonical_digest()?;
    empty.validate()?;
    assert!(empty.members.is_empty() && empty.rebuild.source_denominator.is_empty());
    Ok(())
}

// Case 16 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/16
#[test]
fn snapshot_digest_is_stable_under_set_like_input_order() -> TestResult {
    let mut first = valid_snapshot();
    first.members.push(SnapshotMember::new(
        canonical("AnotherCue", 0xc5),
        TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("target"),
    ));
    first.rebuild.source_denominator.push(SourceHandle::new(
        TargetHandle::new("crates/smart/eliot-cue-contracts/src/snapshot.rs").expect("target"),
        digest(0xa2),
        provenance(),
    ));
    first.rebuild.digest = first.canonical_digest()?;
    let mut second = first.clone();
    second.members.reverse();
    second.rebuild.source_denominator.reverse();
    assert_eq!(
        first.canonical_payload_bytes()?,
        second.canonical_payload_bytes()?,
        "members and denominator are sets for digest purposes"
    );
    assert_eq!(first.canonical_digest()?, second.canonical_digest()?);
    first.validate()?;
    second.rebuild.digest = second.canonical_digest()?;
    second.validate()?;
    Ok(())
}

// Case 17 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/17
#[test]
fn profile_source_or_fence_change_invalidates_snapshot_identity() -> TestResult {
    let base = valid_snapshot();
    let base_input = base.canonical_payload_bytes()?;

    // A profile revision change invalidates the recorded identity.
    let mut profiled = base.clone();
    profiled.rebuild.normalization_profile.profile_revision = 2;
    assert_ne!(
        profiled.canonical_payload_bytes()?,
        base_input,
        "a profile change must change the rebuild input"
    );
    assert_eq!(
        profiled.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );

    // A source change invalidates the recorded identity.
    let mut sourced = base.clone();
    sourced.rebuild.source_denominator[0] = SourceHandle::new(
        TargetHandle::new("crates/smart/eliot-cue-contracts/src/snapshot.rs").expect("target"),
        digest(0xa2),
        provenance(),
    );
    assert_ne!(sourced.canonical_payload_bytes()?, base_input);
    assert_eq!(
        sourced.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );

    // A fence change invalidates the recorded identity.
    let mut fenced = base.clone();
    fenced.state_fence = next_fence();
    assert_ne!(fenced.canonical_payload_bytes()?, base_input);
    assert_eq!(
        fenced.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );
    Ok(())
}

// Case 18 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/18
#[test]
fn snapshot_states_keep_complete_partial_unavailable_stale_and_unknown_distinct() -> TestResult {
    let states = [
        Completeness::Complete,
        Completeness::Partial {
            frontier: vec![edge(1)],
        },
        Completeness::Unavailable {
            reason: "projection unreadable".to_owned(),
        },
        Completeness::Stale {
            snapshot_fence: fence(),
        },
        Completeness::Unknown {
            reason: "unclassified source".to_owned(),
        },
    ];
    for state in &states {
        result(Vec::new(), Vec::new(), state.clone()).validate()?;
    }
    let wires: Vec<serde_json::Value> = states
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    for (index, pair) in wires.windows(2).enumerate() {
        assert_ne!(
            pair[0],
            pair[1],
            "states {index} and {} must differ",
            index + 1
        );
    }
    // No state collapses into "found nothing": only Complete with no hits is
    // known-empty; every other state is an explicit unknown.
    assert!(result(Vec::new(), Vec::new(), Completeness::Complete).is_known_empty());
    for state in states.into_iter().skip(1) {
        assert!(!result(Vec::new(), Vec::new(), state).is_known_empty());
    }
    Ok(())
}

// Case 19 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/19
#[test]
fn invalidation_causes_require_exact_owner_evidence() -> TestResult {
    let causes = [
        InvalidationCause::ProfileChanged {
            prior_profile_digest: digest(0xb2),
            current_profile_digest: digest(0xb3),
        },
        InvalidationCause::SourceChanged {
            prior_source_digest: digest(0xa1),
            current_source_digest: digest(0xa2),
        },
        InvalidationCause::FenceChanged {
            prior_fence: fence(),
            current_fence: next_fence(),
        },
        InvalidationCause::RegistryChanged {
            prior_registry_revision: "registry-1".to_owned(),
            current_registry_revision: "registry-2".to_owned(),
        },
        InvalidationCause::SnapshotSuperseded {
            successor: SnapshotId::new("snapshot-3").expect("id"),
        },
    ];
    for (index, cause) in causes.into_iter().enumerate() {
        cause.validate()?;
        let record = SnapshotInvalidation::seal(
            SnapshotId::new(format!("snapshot-retired-{index}")).expect("id"),
            cause,
            context().evidence,
            SnapshotId::new("snapshot-1").expect("id"),
            Vec::new(),
        )?;
        record.validate()?;
    }

    // A changeless cause is not an invalidation.
    for cause in [
        InvalidationCause::ProfileChanged {
            prior_profile_digest: digest(0xb2),
            current_profile_digest: digest(0xb2),
        },
        InvalidationCause::SourceChanged {
            prior_source_digest: digest(0xa1),
            current_source_digest: digest(0xa1),
        },
        InvalidationCause::FenceChanged {
            prior_fence: fence(),
            current_fence: fence(),
        },
        InvalidationCause::RegistryChanged {
            prior_registry_revision: "registry-1".to_owned(),
            current_registry_revision: "registry-1".to_owned(),
        },
    ] {
        assert_eq!(
            cause.validate(),
            Err(CueContractError::InvalidText {
                field: "invalidation.cause"
            })
        );
    }

    // Owner-rejected evidence cannot support an invalidation: a `Verified`
    // status without a verification binding is rejected by the evidence owner.
    let mut unverified = context().evidence;
    unverified.status = EpistemicStatus::Verified;
    assert!(unverified.validate().is_err());
    assert_eq!(
        SnapshotInvalidation::seal(
            SnapshotId::new("snapshot-2").expect("id"),
            InvalidationCause::SnapshotSuperseded {
                successor: SnapshotId::new("snapshot-3").expect("id"),
            },
            unverified,
            SnapshotId::new("snapshot-1").expect("id"),
            Vec::new(),
        ),
        Err(CueContractError::Foundation {
            field: "invalidation.evidence"
        })
    );
    Ok(())
}

// Case 20 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/20
#[test]
fn invalidation_preserves_prior_history_and_predecessor() -> TestResult {
    let record = SnapshotInvalidation::seal(
        SnapshotId::new("snapshot-3").expect("id"),
        InvalidationCause::SnapshotSuperseded {
            successor: SnapshotId::new("snapshot-4").expect("id"),
        },
        context().evidence,
        SnapshotId::new("snapshot-2").expect("id"),
        vec![
            SnapshotId::new("snapshot-1").expect("id"),
            SnapshotId::new("snapshot-0").expect("id"),
        ],
    )?;
    record.validate()?;
    let round_trip: SnapshotInvalidation = serde_json::from_str(&serde_json::to_string(&record)?)?;
    assert_eq!(round_trip.predecessor.as_str(), "snapshot-2");
    assert_eq!(round_trip.history.len(), 2);
    assert_eq!(round_trip.history[0].as_str(), "snapshot-1");
    assert_eq!(round_trip.history[1].as_str(), "snapshot-0");
    round_trip.validate()?;

    // The snapshot cannot be its own predecessor.
    assert_eq!(
        SnapshotInvalidation::seal(
            SnapshotId::new("snapshot-2").expect("id"),
            InvalidationCause::SnapshotSuperseded {
                successor: SnapshotId::new("snapshot-4").expect("id"),
            },
            context().evidence,
            SnapshotId::new("snapshot-2").expect("id"),
            Vec::new(),
        ),
        Err(CueContractError::InvalidText {
            field: "invalidation.predecessor"
        })
    );

    // History never repeats the predecessor or itself: overlap is rejected,
    // never last-write-wins.
    for history in [
        vec![SnapshotId::new("snapshot-2").expect("id")],
        vec![
            SnapshotId::new("snapshot-1").expect("id"),
            SnapshotId::new("snapshot-1").expect("id"),
        ],
        vec![SnapshotId::new("snapshot-3").expect("id")],
    ] {
        assert_eq!(
            SnapshotInvalidation::seal(
                SnapshotId::new("snapshot-3").expect("id"),
                InvalidationCause::SnapshotSuperseded {
                    successor: SnapshotId::new("snapshot-4").expect("id"),
                },
                context().evidence,
                SnapshotId::new("snapshot-2").expect("id"),
                history,
            ),
            Err(CueContractError::DuplicateIdentity {
                field: "invalidation.history"
            })
        );
    }

    // History order is significant: reordering changes the digest.
    let mut reordered = record.clone();
    reordered.history.reverse();
    assert_ne!(
        reordered.canonical_payload_bytes()?,
        record.canonical_payload_bytes()?
    );
    assert_eq!(
        reordered.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );
    Ok(())
}

// Case 21 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/21
#[test]
fn relation_edge_requires_registry_direction_revision_digest_and_evidence() -> TestResult {
    let from = TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target");
    let to = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target");
    let edge = relation_edge(1, from.clone(), to.clone());
    edge.validate()?;

    // Direction is data: swapping endpoints names a different edge.
    let swapped = relation_edge(1, to.clone(), from.clone());
    assert_ne!(edge, swapped);
    swapped.validate()?;

    // A blank registry revision resolves nothing.
    let mut unrevised = edge.clone();
    unrevised.registry_revision = String::new();
    assert_eq!(
        unrevised.validate(),
        Err(CueContractError::InvalidText {
            field: "relation.registry_revision"
        })
    );

    // Blank endpoints are rejected at construction.
    assert!(TargetHandle::new("").is_err());

    // A malformed edge digest never becomes an edge.
    assert!(Digest::new("not-a-digest").is_err());

    // Evidence its owner rejects cannot support an edge.
    let mut unverified = context().evidence;
    unverified.status = EpistemicStatus::Verified;
    let mut bad_evidence = edge.clone();
    bad_evidence.evidence = unverified;
    assert_eq!(
        bad_evidence.validate(),
        Err(CueContractError::Foundation {
            field: "relation.evidence"
        })
    );

    // Every field is required on the wire.
    let wire: serde_json::Value = serde_json::to_value(&edge)?;
    for field in [
        "relation_edge_id",
        "kind",
        "from",
        "to",
        "registry_revision",
        "edge_digest",
        "evidence",
    ] {
        let mut partial = wire.clone();
        partial.as_object_mut().expect("object").remove(field);
        assert!(
            serde_json::from_value::<RelationEdgeInput>(partial).is_err(),
            "{field} must be required"
        );
    }
    Ok(())
}

// Case 22 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/22
#[test]
fn broken_reordered_and_disconnected_paths_are_rejected() -> TestResult {
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let final_target = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("final");
    let first = relation_edge(1, direct.target.clone(), middle.clone());
    let second = relation_edge(2, middle.clone(), final_target.clone());
    let asked = request(vec![first, second], 2);
    let valid = DerivedActivation::try_new(
        final_target.clone(),
        direct.target.clone(),
        vec![edge(1), edge(2)],
        ActivationStrength(2),
    )?;
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct.clone()],
        derived: vec![valid],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;

    // A reordered path no longer follows the registry edges.
    let mut reordered = answer.clone();
    reordered.derived[0].path = vec![edge(2), edge(1)];
    assert_eq!(
        reordered.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );

    // A path that does not start at a direct seed is disconnected.
    let mut unseeded = answer.clone();
    unseeded.derived[0] = DerivedActivation::try_new(
        final_target.clone(),
        middle.clone(),
        vec![edge(2)],
        ActivationStrength(2),
    )?;
    assert_eq!(
        unseeded.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );

    // A path through an edge the request never offered is broken.
    let mut unknown_edge = answer.clone();
    unknown_edge.derived[0] = DerivedActivation::try_new(
        final_target.clone(),
        direct.target.clone(),
        vec![edge(1), edge(9)],
        ActivationStrength(2),
    )?;
    assert_eq!(
        unknown_edge.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );

    // A gapped path that skips the middle edge is disconnected.
    let mut gapped = answer.clone();
    gapped.derived[0] = DerivedActivation::try_new(
        final_target,
        direct.target.clone(),
        vec![edge(2)],
        ActivationStrength(2),
    )?;
    assert_eq!(
        gapped.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );
    Ok(())
}

// Case 23 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/23
#[test]
fn depth_zero_direct_only_profile_request_and_result_are_valid() -> TestResult {
    let asked = request(Vec::new(), 0);
    asked.validate()?;
    assert!(asked.is_direct_only());
    assert_eq!(asked.normalization_profile, profile());

    // Every seed key was folded under the request profile.
    for seed in &asked.seeds {
        for comparison in &seed.comparison_keys {
            assert_eq!(comparison.profile, asked.normalization_profile);
        }
    }

    let answered = result(vec![direct_hit()], Vec::new(), Completeness::Complete);
    answered.validate_against(&asked)?;
    assert_eq!(answered.normalization_profile, asked.normalization_profile);
    assert_eq!(answered.state_fence, asked.state_fence);

    // A result bound to a different profile does not answer this request.
    let mut reprofiled = answered.clone();
    reprofiled.normalization_profile.profile_revision = 2;
    assert_eq!(
        reprofiled.validate_against(&asked),
        Err(CueContractError::Foundation {
            field: "result.request_binding"
        })
    );
    Ok(())
}

// Case 26 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/26
#[test]
fn one_hop_and_bounded_multi_hop_candidates_preserve_shape() -> TestResult {
    let direct = direct_hit();
    let mut targets = vec![direct.target.clone()];
    for index in 1..=8 {
        targets.push(TargetHandle::new(format!("crates/gen-{index}.rs")).expect("target"));
    }
    let edges: Vec<RelationEdgeInput> = (1..=8)
        .map(|index| relation_edge(index, targets[index - 1].clone(), targets[index].clone()))
        .collect();
    let asked = request(edges, 8);

    // One hop preserves target, seed, path and depth.
    let one_hop = DerivedActivation::try_new(
        targets[1].clone(),
        direct.target.clone(),
        vec![edge(1)],
        ActivationStrength(3),
    )?;
    assert_eq!(one_hop.depth, 1);
    assert_eq!(one_hop.path.len(), 1);

    // Eight hops — the declared maximum — still preserve shape.
    let eight_hop = DerivedActivation::try_new(
        targets[8].clone(),
        direct.target.clone(),
        (1..=8).map(edge).collect(),
        ActivationStrength(2),
    )?;
    assert_eq!(eight_hop.depth, 8);
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: vec![one_hop, eight_hop],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;

    // Nine hops exceed the declared path bound.
    let too_long = DerivedActivation::try_new(
        TargetHandle::new("crates/gen-9.rs").expect("target"),
        targets[0].clone(),
        (1..=9).map(edge).collect(),
        ActivationStrength(2),
    )?;
    let over = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: Vec::new(),
        derived: vec![too_long],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    assert_eq!(
        over.validate(),
        Err(CueContractError::BoundExceeded {
            field: "derived.path",
            limit: eliot_cue_contracts::MAX_PATH_LEN,
        })
    );
    Ok(())
}

// Case 27 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/27
#[test]
fn every_independent_activation_bound_enforces_boundary_and_one_over() -> TestResult {
    ActivationBounds::new(bounds_spec(0)).validate()?;
    ActivationBounds::new(bounds_spec(1)).validate()?;

    // Each limit is independent: zeroing exactly one rejects the set.
    let mut cases: Vec<(&str, ActivationBoundsSpec)> = Vec::new();
    let mut zeroed = bounds_spec(0);
    zeroed.max_results = 0;
    cases.push(("max_results", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_nodes = 0;
    cases.push(("max_nodes", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_work = 0;
    cases.push(("max_work", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_seeds = 0;
    cases.push(("max_seeds", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_direct = 0;
    cases.push(("max_direct", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_trace_steps = 0;
    cases.push(("max_trace_steps", zeroed));
    let mut zeroed = bounds_spec(0);
    zeroed.max_output_bytes = 0;
    cases.push(("max_output_bytes", zeroed));
    // Traversal limits are required as soon as any depth is allowed.
    for field in ["max_fanout", "max_edges", "max_path_len", "max_derived"] {
        let mut zeroed = bounds_spec(1);
        match field {
            "max_fanout" => zeroed.max_fanout = 0,
            "max_edges" => zeroed.max_edges = 0,
            "max_path_len" => zeroed.max_path_len = 0,
            _ => zeroed.max_derived = 0,
        }
        cases.push((field, zeroed));
    }
    for (field, spec) in cases {
        assert_eq!(
            ActivationBounds::new(spec).validate(),
            Err(CueContractError::InvalidText { field: "bounds" }),
            "{field} must be an explicit finite limit"
        );
    }

    // One over the output ceiling is rejected; the ceiling itself is legal.
    let mut at_ceiling = bounds_spec(0);
    at_ceiling.max_output_bytes = 4 * 1024 * 1024;
    ActivationBounds::new(at_ceiling).validate()?;
    let mut over_ceiling = bounds_spec(0);
    over_ceiling.max_output_bytes = 4 * 1024 * 1024 + 1;
    assert_eq!(
        ActivationBounds::new(over_ceiling).validate(),
        Err(CueContractError::InvalidText { field: "bounds" })
    );
    Ok(())
}

// Case 28 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/28
#[test]
fn zero_unknown_and_invalid_limits_are_not_unlimited() -> TestResult {
    // Zero is rejected, never read as "no limit".
    let mut zeroed = bounds_spec(0);
    zeroed.max_results = 0;
    assert!(ActivationBounds::new(zeroed).validate().is_err());

    // Unknown (`null`) does not decode as a limit at all.
    let mut wire: serde_json::Value = serde_json::to_value(ActivationBounds::new(bounds_spec(0)))?;
    wire.as_object_mut()
        .expect("object")
        .insert("max_results".to_owned(), serde_json::Value::Null);
    assert!(serde_json::from_value::<ActivationBounds>(wire).is_err());

    // A direct-only request still runs under explicit bounds, and offered
    // edges do not sneak traversal back in.
    let asked = request(Vec::new(), 0);
    asked.validate()?;
    assert!(asked.is_direct_only());
    assert_eq!(asked.bounds.max_depth, 0);

    // Even the largest expressible bound stays finite: the contract-wide
    // collection bound still caps what a result may carry.
    let mut broad = bounds_spec(0);
    broad.max_direct = u16::MAX;
    broad.max_results = u16::MAX;
    ActivationBounds::new(broad).validate()?;
    let mut crowded = result(Vec::new(), Vec::new(), Completeness::Complete);
    crowded.direct = (0..257)
        .map(|index| {
            DirectActivation::new(
                TargetHandle::new(format!("crates/crowd-{index}.rs")).expect("target"),
                key("taskcontract", MatchMode::Exact, 1),
                ActivationStrength(10),
            )
        })
        .collect();
    assert_eq!(
        crowded.validate(),
        Err(CueContractError::BoundExceeded {
            field: "direct",
            limit: eliot_cue_contracts::MAX_DIRECT,
        })
    );
    Ok(())
}

// Case 29 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/29
#[test]
fn duplicate_target_preserves_bounded_multiple_path_evidence() -> TestResult {
    let direct = direct_hit();
    let target = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target");
    // Two distinct registry edges reach the same target from the same seed.
    let first = relation_edge(1, direct.target.clone(), target.clone());
    let second = relation_edge(2, direct.target.clone(), target.clone());
    assert_ne!(
        first.relation_edge_id, second.relation_edge_id,
        "the paths differ even though the endpoints agree"
    );
    let asked = request(vec![first, second], 1);
    let via_first = DerivedActivation::try_new(
        target.clone(),
        direct.target.clone(),
        vec![edge(1)],
        ActivationStrength(2),
    )?;
    let via_second = DerivedActivation::try_new(
        target.clone(),
        direct.target.clone(),
        vec![edge(2)],
        ActivationStrength(4),
    )?;
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: vec![via_first, via_second],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;
    assert_eq!(answer.derived.len(), 2, "both paths are preserved");
    assert_ne!(answer.derived[0].path, answer.derived[1].path);
    Ok(())
}

// Case 30 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/30
#[test]
fn cycles_duplicates_paths_and_members_do_not_inflate_arithmetic() -> TestResult {
    // A duplicated snapshot member is a conflicting claim, not extra coverage.
    let mut snapshot = valid_snapshot();
    snapshot.members.push(snapshot.members[0].clone());
    assert_eq!(
        snapshot.validate(),
        Err(CueContractError::DuplicateIdentity { field: "members" })
    );

    // A duplicated request edge is rejected before any traversal accounting.
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let first = relation_edge(1, direct.target.clone(), middle.clone());
    let over_edged = request(vec![first.clone(), first.clone()], 2);
    assert_eq!(
        over_edged.validate(),
        Err(CueContractError::DuplicateIdentity {
            field: "request.relation_edges"
        })
    );

    // A two-cycle back to the seed validates with exact — not inflated —
    // accounting: three path edges are counted as three.
    let back = relation_edge(2, middle.clone(), direct.target.clone());
    let asked = request(vec![first, back], 4);
    let cycled = DerivedActivation::try_new(
        middle.clone(),
        direct.target.clone(),
        vec![edge(1), edge(2), edge(1)],
        ActivationStrength(2),
    )?;
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: vec![cycled],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;
    let mut tight = asked.bounds;
    tight.max_edges = 2;
    let limited = ActivationRequest::new(ActivationRequestSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        seeds: asked.seeds.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        relation_edges: asked.relation_edges.clone(),
        bounds: tight,
        state_fence: asked.state_fence.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
    });
    assert_eq!(
        answer.validate_against(&limited),
        Err(CueContractError::BoundExceeded {
            field: "result.path_edges",
            limit: 2,
        })
    );
    Ok(())
}

// Case 31 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/31
#[test]
fn direct_complete_and_derived_partial_are_representable_together() -> TestResult {
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let final_target = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("final");
    let asked = request(
        vec![
            relation_edge(1, direct.target.clone(), middle.clone()),
            relation_edge(2, middle, final_target.clone()),
        ],
        2,
    );
    let derived = DerivedActivation::try_new(
        final_target,
        direct.target.clone(),
        vec![edge(1), edge(2)],
        ActivationStrength(2),
    )?;
    // Direct hits stand beside derived ones while the search stays resumable.
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: vec![derived],
        completeness: Completeness::Partial {
            frontier: vec![edge(2)],
        },
        trace: ActivationTrace::empty(),
    });
    answer.validate()?;
    answer.validate_against(&asked)?;
    assert!(!answer.direct.is_empty() && !answer.derived.is_empty());
    Ok(())
}

// Case 32 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/32
#[test]
fn complete_partial_truncated_blocked_unavailable_stale_and_unknown_are_distinct() -> TestResult {
    let states = [
        Completeness::Complete,
        Completeness::Partial {
            frontier: vec![edge(1)],
        },
        Completeness::Truncated {
            frontier: vec![edge(1)],
            bound_hit: BoundKind::Depth,
        },
        Completeness::Blocked {
            reason: "policy hold".to_owned(),
        },
        Completeness::Unavailable {
            reason: "projection unreadable".to_owned(),
        },
        Completeness::Stale {
            snapshot_fence: fence(),
        },
        Completeness::Unknown {
            reason: "unclassified source".to_owned(),
        },
        Completeness::SourceUnavailable {
            reason: "snapshot store unreachable".to_owned(),
        },
        Completeness::NoDirectMatch {
            reason: "no seed matched directly".to_owned(),
        },
    ];
    for state in &states {
        let answered = result(Vec::new(), Vec::new(), state.clone());
        if matches!(state, Completeness::Complete) {
            assert!(answered.is_known_empty());
        }
        answered.validate()?;
    }
    let wires: Vec<serde_json::Value> = states
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    for left in 0..wires.len() {
        for right in (left + 1)..wires.len() {
            assert_ne!(
                wires[left], wires[right],
                "states {left} and {right} must differ"
            );
        }
    }
    Ok(())
}

// Case 33 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/33
#[test]
fn truncation_preserves_frontier_omission_and_continuation() -> TestResult {
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let asked = request(
        vec![
            relation_edge(1, direct.target.clone(), middle.clone()),
            relation_edge(
                2,
                middle,
                TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
            ),
        ],
        1,
    );
    // The frontier names the omitted work: edge 2 was never followed.
    let truncated = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: Vec::new(),
        completeness: Completeness::Truncated {
            frontier: vec![edge(2)],
            bound_hit: BoundKind::Depth,
        },
        trace: ActivationTrace::empty(),
    });
    truncated.validate()?;
    truncated.validate_against(&asked)?;
    let round_trip: ActivationResult = serde_json::from_str(&serde_json::to_string(&truncated)?)?;
    assert_eq!(round_trip, truncated, "frontier and bound survive the wire");
    match &round_trip.completeness {
        Completeness::Truncated {
            frontier,
            bound_hit,
        } => {
            assert_eq!(frontier, &vec![edge(2)]);
            assert_eq!(*bound_hit, BoundKind::Depth);
            // Continuation linkage: the frontier edge is one the request offered.
            assert!(
                asked
                    .relation_edges
                    .iter()
                    .any(|offered| offered.relation_edge_id == frontier[0])
            );
        }
        other => panic!("expected a truncation, got {other:?}"),
    }
    // An unnamed omission is indistinguishable from completion: rejected.
    let silent = result(
        Vec::new(),
        Vec::new(),
        Completeness::Truncated {
            frontier: Vec::new(),
            bound_hit: BoundKind::Depth,
        },
    );
    assert_eq!(
        silent.validate(),
        Err(CueContractError::TruncationWithoutBound)
    );
    Ok(())
}

// Case 36 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/36
#[test]
fn retrieval_stage_lineage_is_exact() -> TestResult {
    let sealed = lineage();
    sealed.validate()?;
    assert_eq!(
        sealed.canonical_digest()?,
        sealed.digest,
        "the sealed digest matches the recorded references"
    );

    // Set-like references digest stably regardless of construction order.
    let mut reordered = sealed.clone();
    reordered.direct_targets.reverse();
    reordered.selected_candidates.reverse();
    assert_eq!(
        reordered.canonical_payload_bytes()?,
        sealed.canonical_payload_bytes()?
    );

    // A lineage over a no-direct-match retrieval is exact with empty hits.
    let unmatched = RetrievalLineage::seal(
        SnapshotId::new("snapshot-1").expect("id"),
        vec![source()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    unmatched.validate()?;
    assert!(unmatched.direct_targets.is_empty() && unmatched.derived_targets.is_empty());

    // Any reference change breaks the lineage; duplicates never merge.
    let mut tampered = sealed.clone();
    tampered
        .direct_targets
        .push(TargetHandle::new("crates/extra.rs").expect("target"));
    assert_eq!(
        tampered.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );
    let mut duplicated = sealed.clone();
    duplicated
        .direct_targets
        .push(duplicated.direct_targets[0].clone());
    assert_eq!(
        duplicated.validate(),
        Err(CueContractError::DuplicateIdentity {
            field: "lineage.direct_targets"
        })
    );

    // No proof-of-delivery semantics: the wire carries no delivery, visibility,
    // use, adherence or outcome member.
    let wire: serde_json::Value = serde_json::to_value(&sealed)?;
    let mut keys = Vec::new();
    collect_keys(&wire, &mut keys);
    for forbidden in [
        "delivery",
        "delivered",
        "visibility",
        "visible",
        "use",
        "used",
        "adherence",
        "outcome",
    ] {
        assert!(
            !keys.iter().any(|key| key == forbidden),
            "{forbidden} must not appear in lineage"
        );
    }
    Ok(())
}

fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (name, nested) in map {
                out.push(name.clone());
                collect_keys(nested, out);
            }
        }
        serde_json::Value::Array(items) => {
            for nested in items {
                collect_keys(nested, out);
            }
        }
        _ => {}
    }
}

// Case 37 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/37
#[test]
fn activation_candidate_cannot_claim_delivery_visibility_use_adherence_or_outcome() -> TestResult {
    for wire in [
        serde_json::to_value(result(
            vec![direct_hit()],
            Vec::new(),
            Completeness::Complete,
        ))?,
        serde_json::to_value(request(Vec::new(), 0))?,
        serde_json::to_value(candidate_for(
            &normalized(
                "TaskContract",
                vec![key("taskcontract", MatchMode::Exact, 1)],
            ),
            "crates/eliot-types/src/lib.rs",
            7,
        ))?,
        serde_json::to_value(lineage())?,
    ] {
        let shape = wire.as_object().expect("top-level object");
        for forbidden in ["delivery", "visibility", "use", "adherence", "outcome"] {
            assert!(
                !shape.contains_key(forbidden),
                "{forbidden} must not appear on activation shapes"
            );
        }
    }
    // Injecting a delivery claim is rejected at the schema boundary.
    let tampered = serde_json::to_string(&result(Vec::new(), Vec::new(), Completeness::Complete))?
        .replacen('{', "{\"delivery\":\"seen\",", 1);
    assert!(serde_json::from_str::<ActivationResult>(&tampered).is_err());
    Ok(())
}

// Case 38 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/38
#[test]
fn activation_candidate_cannot_mutate_support_accessibility_influence_or_lifecycle() -> TestResult {
    // Scoped to the activation/binding/lineage/invalidation/diagnostic records
    // themselves; task context and provenance closures are foundation-owned.
    for wire in [
        serde_json::to_value(result(
            vec![direct_hit()],
            Vec::new(),
            Completeness::Complete,
        ))?,
        serde_json::to_value(request(Vec::new(), 0))?,
        serde_json::to_value(candidate_for(
            &normalized(
                "TaskContract",
                vec![key("taskcontract", MatchMode::Exact, 1)],
            ),
            "crates/eliot-types/src/lib.rs",
            7,
        ))?,
        serde_json::to_value(lineage())?,
        serde_json::to_value(invalidation())?,
        serde_json::to_value(RedactedDiagnostic::redact(
            CueKind::ErrorSignature,
            "E001: clean diagnostic",
        )?)?,
    ] {
        let shape = wire.as_object().expect("top-level object");
        for forbidden in ["support", "accessibility", "influence", "lifecycle"] {
            assert!(
                !shape.contains_key(forbidden),
                "{forbidden} must not appear on activation shapes"
            );
        }
    }
    let tampered = serde_json::to_string(&result(Vec::new(), Vec::new(), Completeness::Complete))?
        .replacen('{', "{\"lifecycle\":\"ACTIVE\",", 1);
    assert!(serde_json::from_str::<ActivationResult>(&tampered).is_err());
    Ok(())
}

// Case 39 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/39
#[test]
fn privacy_authority_effect_and_proof_escalation_is_rejected() -> TestResult {
    // A rejected candidate cannot validate as an admitted projection.
    let cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    let mut rejected = candidate_for(&cue, "crates/eliot-types/src/lib.rs", 7);
    rejected.disposition = BindingDisposition::Rejected;
    let projection = eliot_cue_contracts::AdmittedCueBindingProjection::new(
        rejected,
        cue,
        admission_for(
            &candidate_for(
                &normalized(
                    "TaskContract",
                    vec![key("taskcontract", MatchMode::Exact, 1)],
                ),
                "crates/eliot-types/src/lib.rs",
                7,
            ),
            7,
        ),
    );
    assert_eq!(
        projection.validate(),
        Err(CueContractError::Foundation {
            field: "projection.rejected"
        })
    );

    // A build candidate cannot escalate its proof ceiling.
    let member = projection_for("one", "TaskContract", "src/a.rs", 10);
    let sealed = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").expect("scope"),
        snapshot_for(std::slice::from_ref(&member)),
        vec![member],
        Vec::new(),
    )?;
    let mut wire: serde_json::Value = serde_json::to_value(&sealed)?;
    wire.as_object_mut()
        .expect("object")
        .insert("proof_ceiling".to_owned(), serde_json::json!("OBSERVATION"));
    let escalated: CueSnapshotBuildCandidate = serde_json::from_value(wire)?;
    assert_eq!(
        escalated.validate(),
        Err(CueContractError::InvalidText {
            field: "index.schema_revision"
        })
    );

    // A result cannot escalate the request fence.
    let asked = request(Vec::new(), 0);
    let mut fenced = result(vec![direct_hit()], Vec::new(), Completeness::Complete);
    fenced.state_fence = next_fence();
    assert_eq!(
        fenced.validate_against(&asked),
        Err(CueContractError::Foundation {
            field: "result.request_binding"
        })
    );

    // Proof without a binding is rejected by the evidence owner: a `Verified`
    // status with no verification binding cannot support a context.
    let mut escalated_evidence = context().evidence;
    escalated_evidence.status = EpistemicStatus::Verified;
    let mut escalated_context = context();
    escalated_context.evidence = escalated_evidence;
    assert_eq!(
        escalated_context.validate(),
        Err(CueContractError::Foundation {
            field: "context.evidence"
        })
    );

    // Privacy classes round-trip exactly; none is silently promoted.
    let mut classified = context();
    classified.privacy = PrivacyClass::Secret;
    let round_trip: CueContext = serde_json::from_str(&serde_json::to_string(&classified)?)?;
    assert_eq!(round_trip.privacy, PrivacyClass::Secret);
    round_trip.validate()?;
    Ok(())
}

// Case 40 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/40
#[test]
fn canonical_round_trip_and_digest_are_deterministic() -> TestResult {
    let snapshot = valid_snapshot();
    assert_eq!(
        snapshot.canonical_payload_bytes()?,
        snapshot.canonical_payload_bytes()?
    );
    assert_eq!(snapshot.canonical_digest()?, snapshot.canonical_digest()?);
    let round_trip: CueSnapshot = serde_json::from_str(&serde_json::to_string(&snapshot)?)?;
    assert_eq!(round_trip, snapshot);
    round_trip.validate()?;

    let sealed = lineage();
    assert_eq!(
        sealed.canonical_payload_bytes()?,
        sealed.canonical_payload_bytes()?
    );
    let round_trip: RetrievalLineage = serde_json::from_str(&serde_json::to_string(&sealed)?)?;
    assert_eq!(round_trip.canonical_digest()?, sealed.canonical_digest()?);

    let retired = invalidation();
    assert_eq!(
        retired.canonical_payload_bytes()?,
        retired.canonical_payload_bytes()?
    );
    let round_trip: SnapshotInvalidation = serde_json::from_str(&serde_json::to_string(&retired)?)?;
    assert_eq!(round_trip, retired);

    let diagnostic = RedactedDiagnostic::redact(CueKind::ErrorSignature, "E001: clean diagnostic")?;
    assert_eq!(
        diagnostic.canonical_payload_bytes()?,
        diagnostic.canonical_payload_bytes()?
    );
    let round_trip: RedactedDiagnostic =
        serde_json::from_str(&serde_json::to_string(&diagnostic)?)?;
    assert_eq!(
        round_trip.canonical_digest()?,
        diagnostic.canonical_digest()?
    );

    let cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    let round_trip: NormalizedCue = serde_json::from_str(&serde_json::to_string(&cue)?)?;
    assert_eq!(round_trip, cue);

    let member = projection_for("one", "TaskContract", "src/a.rs", 10);
    let left = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").expect("scope"),
        snapshot_for(std::slice::from_ref(&member)),
        vec![member.clone()],
        Vec::new(),
    )?;
    let right = CueSnapshotBuildCandidate::seal(
        WorkScopeId::new("scope-1").expect("scope"),
        snapshot_for(std::slice::from_ref(&member)),
        vec![member],
        Vec::new(),
    )?;
    assert_eq!(left.build_digest, right.build_digest);
    assert_eq!(
        left.canonical_payload_bytes()?,
        right.canonical_payload_bytes()?
    );
    Ok(())
}

// Case 41 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/41
#[test]
fn semantic_path_and_transformation_order_are_preserved() -> TestResult {
    // Transformation evidence is ordered: reversing it names a different record.
    let mut cue = normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    );
    cue.transformation_evidence = vec![
        eliot_cue_contracts::TransformationStep::new(
            "fold-case".to_owned(),
            "taskcontract".to_owned(),
        ),
        eliot_cue_contracts::TransformationStep::new(
            "strip-prefix".to_owned(),
            "taskcontract".to_owned(),
        ),
    ];
    cue.validate()?;
    let mut reordered = cue.clone();
    reordered.transformation_evidence.reverse();
    reordered.validate()?;
    assert_ne!(cue, reordered, "step order is significant");
    let round_trip: NormalizedCue = serde_json::from_str(&serde_json::to_string(&cue)?)?;
    assert_eq!(
        round_trip.transformation_evidence, cue.transformation_evidence,
        "step order survives the wire"
    );

    // A derived path is ordered: it survives the wire in order, and any
    // reordering breaks registry contiguity.
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let final_target = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("final");
    let asked = request(
        vec![
            relation_edge(1, direct.target.clone(), middle.clone()),
            relation_edge(2, middle, final_target.clone()),
        ],
        2,
    );
    let derived = DerivedActivation::try_new(
        final_target,
        direct.target.clone(),
        vec![edge(1), edge(2)],
        ActivationStrength(2),
    )?;
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct],
        derived: vec![derived],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;
    let round_trip: ActivationResult = serde_json::from_str(&serde_json::to_string(&answer)?)?;
    assert_eq!(round_trip.derived[0].path, vec![edge(1), edge(2)]);
    let mut swapped = answer.clone();
    swapped.derived[0].path = vec![edge(2), edge(1)];
    assert_eq!(
        swapped.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );
    Ok(())
}

// Case 42 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/42
#[test]
fn legacy_payload_is_rejected_by_current_decoder() -> TestResult {
    assert!(is_supported_schema_revision(REVISION));
    for legacy in ["1.0.0", "0.1.0", "2.0.0-legacy", ""] {
        assert!(
            !is_supported_schema_revision(legacy),
            "{legacy:?} must not decode as current"
        );
    }

    // Every vocabulary shape rejects a retired revision after decoding.
    let legacy_json = serde_json::to_string(&observed("TaskContract"))?.replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<ObservedCue>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json = serde_json::to_string(&normalized(
        "TaskContract",
        vec![key("taskcontract", MatchMode::Exact, 1)],
    ))?
    .replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<NormalizedCue>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json = serde_json::to_string(&valid_snapshot())?.replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<CueSnapshot>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json = serde_json::to_string(&request(Vec::new(), 0))?.replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<ActivationRequest>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json =
        serde_json::to_string(&result(Vec::new(), Vec::new(), Completeness::Complete))?
            .replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<ActivationResult>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json = serde_json::to_string(&lineage())?.replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<RetrievalLineage>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    let legacy_json = serde_json::to_string(&invalidation())?.replace(REVISION, "1.0.0");
    assert_eq!(
        serde_json::from_str::<SnapshotInvalidation>(&legacy_json)?.validate(),
        Err(CueContractError::InvalidText {
            field: "schema_revision"
        })
    );
    Ok(())
}

// Case 43 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/43
#[test]
fn every_variable_field_enforces_its_declared_bound() {
    let oversized = "x".repeat(8_193);
    assert_oversized_text_rejected(&oversized);
    assert_oversized_collection_rejected();
}

fn assert_oversized_text_rejected(oversized: &str) {
    // Every bounded text field rejects oversize input with `BoundExceeded`.
    assert!(matches!(
        observed(oversized).validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        key(oversized, MatchMode::Exact, 1).validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        NormalizationProfile::new("symbol-v1".to_owned(), 1, digest(1)).validate(),
        Ok(())
    ));
    assert!(matches!(
        NormalizationProfile::new(oversized.to_owned(), 1, digest(1)).validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        NormalizedCue::new(
            REVISION.to_owned(),
            observed("TaskContract"),
            profile(),
            None,
            Vec::new(),
            NormalizationOutcome::Unsupported {
                reason: oversized.to_owned(),
            },
            Vec::new(),
        )
        .validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        NormalizedCue::new(
            REVISION.to_owned(),
            observed("TaskContract"),
            profile(),
            Some(canonical("TaskContract", 9)),
            Vec::new(),
            NormalizationOutcome::AuthorizedLoss {
                policy_ref: oversized.to_owned(),
            },
            Vec::new(),
        )
        .validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        canonical(oversized, 9).validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        TargetHandle::new("x".repeat(513)),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        relation_edge(
            1,
            TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
            TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
        )
        .validate(),
        Ok(())
    ));
    let mut revised = relation_edge(
        1,
        TargetHandle::new("crates/eliot-types/src/lib.rs").expect("target"),
        TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
    );
    oversized.clone_into(&mut revised.registry_revision);
    assert!(matches!(
        revised.validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));
    assert!(matches!(
        RedactedDiagnostic::redact(CueKind::ErrorSignature, oversized),
        Err(CueContractError::BoundExceeded { .. })
    ));
}

fn assert_oversized_collection_rejected() {
    // Bounded collections reject one-over with `BoundExceeded`, never truncate.
    let mut crowded_history: Vec<SnapshotId> = Vec::new();
    for index in 0..65 {
        crowded_history.push(SnapshotId::new(format!("snapshot-{index}")).expect("id"));
    }
    assert_eq!(
        SnapshotInvalidation::seal(
            SnapshotId::new("snapshot-9").expect("id"),
            InvalidationCause::SnapshotSuperseded {
                successor: SnapshotId::new("snapshot-10").expect("id"),
            },
            context().evidence,
            SnapshotId::new("snapshot-8").expect("id"),
            crowded_history,
        ),
        Err(CueContractError::BoundExceeded {
            field: "invalidation.history",
            limit: eliot_cue_contracts::MAX_INVALIDATION_HISTORY,
        })
    );
    let mut crowded_selections: Vec<BindingCandidateId> = Vec::new();
    for index in 0..769 {
        crowded_selections.push(BindingCandidateId::new(format!("candidate-{index}")).expect("id"));
    }
    assert_eq!(
        RetrievalLineage::seal(
            SnapshotId::new("snapshot-1").expect("id"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            crowded_selections,
            Vec::new(),
        ),
        Err(CueContractError::BoundExceeded {
            field: "lineage.selected_candidates",
            limit: eliot_cue_contracts::MAX_LINEAGE_SELECTIONS,
        })
    );
}

// Case 44 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/44
#[test]
fn sensitive_diagnostics_are_redacted() -> TestResult {
    let leaked = "E001: auth failed for token=hunter2\nretry with password s3cret!";
    let redacted = RedactedDiagnostic::redact(CueKind::ErrorSignature, leaked)?;
    redacted.validate()?;
    assert!(!redacted.redacted_value.contains("hunter2"));
    assert!(!redacted.redacted_value.contains("s3cret"));
    assert!(
        redacted.redacted_value.contains("[redacted]"),
        "redaction must be visible, not silent deletion"
    );

    // The original value is never retained on the wire.
    let wire = serde_json::to_string(&redacted)?;
    assert!(!wire.contains("hunter2") && !wire.contains("s3cret"));
    assert!(!wire.contains("original"));

    // Clean diagnostics pass through unchanged: redaction destroys nothing it
    // was not asked to remove.
    let clean = RedactedDiagnostic::redact(CueKind::ErrorSignature, "E002: file not found")?;
    assert_eq!(clean.redacted_value, "E002: file not found");
    clean.validate()?;

    // A multi-line secret block redacts through its end marker while later
    // clean lines survive.
    let blocked = RedactedDiagnostic::redact(
        CueKind::ErrorSignature,
        "note: -----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----\ndone",
    )?;
    assert!(!blocked.redacted_value.contains("abc123"));
    assert!(!blocked.redacted_value.contains("PRIVATE"));
    assert!(blocked.redacted_value.contains("done"));
    blocked.validate()?;

    // Every marker in the closed set forces redaction.
    for marker in eliot_cue_contracts::SENSITIVE_MARKERS {
        let value = format!("E009: {marker}=classified");
        let redacted = RedactedDiagnostic::redact(CueKind::ErrorSignature, &value)?;
        assert!(
            !redacted.redacted_value.contains("classified"),
            "{marker} must force redaction"
        );
        redacted.validate()?;
    }

    // A hand-built record that still carries a marker is rejected.
    let mut smuggled = RedactedDiagnostic::redact(CueKind::ErrorSignature, "E003: clean")?;
    smuggled.redacted_value = "E003: token=hunter2".to_owned();
    assert_eq!(
        smuggled.validate(),
        Err(CueContractError::InvalidText {
            field: "diagnostic.redacted_value"
        })
    );
    Ok(())
}

// Case 46 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/46
#[test]
fn derived_paths_are_contiguous_bounded_and_start_from_direct_seeds() -> TestResult {
    // An empty path names no derivation.
    let empty = result(
        vec![direct_hit()],
        vec![
            DerivedActivation::try_new(
                TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
                direct_hit().target,
                Vec::new(),
                ActivationStrength(2),
            )
            .expect("empty path shape"),
        ],
        Completeness::Complete,
    );
    assert_eq!(
        empty.validate(),
        Err(CueContractError::BrokenActivationPath)
    );

    // A path longer than the declared bound is rejected by shape alone.
    let long = DerivedActivation::try_new(
        TargetHandle::new("crates/gen-9.rs").expect("target"),
        direct_hit().target,
        (1..=9).map(edge).collect(),
        ActivationStrength(2),
    )?;
    let over = result(vec![direct_hit()], vec![long], Completeness::Complete);
    assert_eq!(
        over.validate(),
        Err(CueContractError::BoundExceeded {
            field: "derived.path",
            limit: eliot_cue_contracts::MAX_PATH_LEN,
        })
    );

    // Depth must equal the path length: a disagreeing record is corrupt input.
    let disagreed = result(
        vec![direct_hit()],
        vec![DerivedActivation::from_parts(
            TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target"),
            direct_hit().target,
            vec![edge(1), edge(2)],
            1,
            ActivationStrength(2),
        )],
        Completeness::Complete,
    );
    assert_eq!(
        disagreed.validate(),
        Err(CueContractError::BrokenActivationPath)
    );

    // Contiguity and seed-start are checked against the request edges.
    let direct = direct_hit();
    let middle = TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("middle");
    let final_target = TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("final");
    let asked = request(
        vec![
            relation_edge(1, direct.target.clone(), middle.clone()),
            relation_edge(2, middle.clone(), final_target.clone()),
        ],
        2,
    );
    let contiguous = DerivedActivation::try_new(
        final_target.clone(),
        direct.target.clone(),
        vec![edge(1), edge(2)],
        ActivationStrength(2),
    )?;
    let answer = ActivationResult::new(ActivationResultSpec {
        schema_revision: asked.schema_revision.clone(),
        request_id: asked.request_id.clone(),
        snapshot_id: asked.snapshot_id.clone(),
        normalization_profile: asked.normalization_profile.clone(),
        state_fence: asked.state_fence.clone(),
        observed_at: asked.observed_at,
        deadline_ms: asked.deadline_ms,
        cancelled: asked.cancelled,
        direct: vec![direct.clone()],
        derived: vec![contiguous],
        completeness: Completeness::Complete,
        trace: ActivationTrace::empty(),
    });
    answer.validate_against(&asked)?;

    // Starting from a non-seed target breaks the seed-start rule.
    let mut unseeded = answer.clone();
    unseeded.derived[0] =
        DerivedActivation::try_new(final_target, middle, vec![edge(2)], ActivationStrength(2))?;
    assert_eq!(
        unseeded.validate_against(&asked),
        Err(CueContractError::BrokenActivationPath)
    );
    Ok(())
}

// Case 47 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/47
#[test]
fn complete_denominator_member_and_frontier_arithmetic_reconciles() -> TestResult {
    let mut snapshot = valid_snapshot();
    snapshot.members.push(SnapshotMember::new(
        canonical("AnotherCue", 0xc5),
        TargetHandle::new("crates/eliot-types/src/ul/cue.rs").expect("target"),
    ));
    snapshot.rebuild.digest = snapshot.canonical_digest()?;
    snapshot.validate()?;
    assert_eq!(snapshot.rebuild.source_denominator.len(), 1);
    assert_eq!(snapshot.members.len(), 2);

    // Result counts reconcile against the request budget exactly.
    let asked = request(Vec::new(), 0);
    assert_eq!(usize::from(asked.bounds.max_results), 64);
    let answered = result(vec![direct_hit()], Vec::new(), Completeness::Complete);
    answered.validate_against(&asked)?;
    assert!(
        answered.direct.len() + answered.derived.len() <= usize::from(asked.bounds.max_results)
    );

    // One hit over the direct budget is rejected, not trimmed.
    let mut tight_spec = bounds_spec(0);
    tight_spec.max_direct = 1;
    tight_spec.max_results = 1;
    let tight = request_full(
        vec![normalized(
            "TaskContract",
            vec![key("taskcontract", MatchMode::Exact, 1)],
        )],
        Vec::new(),
        ActivationBounds::new(tight_spec),
    );
    let mut crowded = result(
        vec![direct_hit(), direct_hit()],
        Vec::new(),
        Completeness::Complete,
    );
    crowded.request_id = tight.request_id.clone();
    crowded.snapshot_id = tight.snapshot_id.clone();
    crowded.normalization_profile = tight.normalization_profile.clone();
    crowded.state_fence = tight.state_fence.clone();
    crowded.observed_at = tight.observed_at;
    assert_eq!(
        crowded.validate_against(&tight),
        Err(CueContractError::BoundExceeded {
            field: "result.request_bounds",
            limit: 1,
        })
    );

    // Frontier arithmetic is bounded: an oversized frontier is rejected.
    let mut frontier = Vec::new();
    for index in 0..4_097 {
        frontier.push(RelationEdgeId::new(format!("edge-{index}")).expect("edge"));
    }
    let oversized = result(
        Vec::new(),
        Vec::new(),
        Completeness::Truncated {
            frontier,
            bound_hit: BoundKind::Results,
        },
    );
    assert!(matches!(
        oversized.validate(),
        Err(CueContractError::BoundExceeded { .. })
    ));

    // Bounded work accounting holds: too little work budget rejects the result.
    let mut starved_spec = bounds_spec(0);
    starved_spec.max_work = 1;
    let starved = request_full(
        vec![normalized(
            "TaskContract",
            vec![key("taskcontract", MatchMode::Exact, 1)],
        )],
        Vec::new(),
        ActivationBounds::new(starved_spec),
    );
    let mut hungry = result(
        vec![direct_hit(), direct_hit()],
        Vec::new(),
        Completeness::Complete,
    );
    hungry.request_id = starved.request_id.clone();
    hungry.snapshot_id = starved.snapshot_id.clone();
    hungry.normalization_profile = starved.normalization_profile.clone();
    hungry.state_fence = starved.state_fence.clone();
    hungry.observed_at = starved.observed_at;
    assert_eq!(
        hungry.validate_against(&starved),
        Err(CueContractError::BoundExceeded {
            field: "result.work",
            limit: 1,
        })
    );
    Ok(())
}

// Case 48 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/48
#[test]
fn every_identity_bearing_mutation_changes_digest_or_is_rejected() -> TestResult {
    // Snapshot members, profile and sources are all digest-bearing.
    let base = valid_snapshot();
    let base_digest = base.canonical_digest()?;
    let mut member = base.clone();
    member.members[0].target =
        TargetHandle::new("crates/smart/eliot-cues/src/lib.rs").expect("target");
    assert_ne!(
        member.canonical_payload_bytes()?,
        base.canonical_payload_bytes()?
    );
    assert_eq!(
        member.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );
    let mut profiled = base.clone();
    profiled.rebuild.normalization_profile.profile_revision = 2;
    assert_ne!(
        profiled.canonical_payload_bytes()?,
        base.canonical_payload_bytes()?
    );
    assert_eq!(
        profiled.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );

    // Lineage references are digest-bearing.
    let sealed = lineage();
    let mut reselected = sealed.clone();
    reselected
        .selected_candidates
        .push(BindingCandidateId::new("candidate-9").expect("id"));
    assert_ne!(
        reselected.canonical_payload_bytes()?,
        sealed.canonical_payload_bytes()?
    );
    assert_eq!(
        reselected.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );

    // Invalidation cause and history are digest-bearing.
    let retired = invalidation();
    let mut recaused = retired.clone();
    recaused.cause = InvalidationCause::SourceChanged {
        prior_source_digest: digest(0xa1),
        current_source_digest: digest(0xa2),
    };
    assert_ne!(
        recaused.canonical_payload_bytes()?,
        retired.canonical_payload_bytes()?
    );
    assert_eq!(
        recaused.validate(),
        Err(CueContractError::SnapshotNotRebuildable)
    );

    // A structurally invalid digest never decodes.
    assert!(Digest::new("not-a-digest").is_err());
    assert!(Digest::new("A".repeat(64)).is_err());
    assert_eq!(base_digest, base.rebuild.digest);
    Ok(())
}

// Case 50 --------------------------------------------------------------------
// WORK_UNIT_CASE: 804/50
#[test]
fn source_api_contains_no_algorithm_io_store_provider_model_mutation_authority_effect_or_finish() {
    for (name, source) in API_SOURCES {
        assert!(
            api_violations(source).is_empty(),
            "{name} carries forbidden surface: {:?}",
            api_violations(source)
        );
    }
    // The scanner is live, not vacuous: it flags each forbidden class.
    assert!(api_violations("pub struct Store;").contains(&"Store"));
    assert!(api_violations("impl Provider for X {}").contains(&"Provider"));
    assert!(api_violations("fn normalize(value: &str) {}").contains(&"fn normalize("));
    assert!(api_violations("std::fs::read(path)").contains(&"std::fs"));
    assert!(!api_violations("let done = task.finish();").contains(&"Finish"));
    assert!(api_violations("let done: Finish = task.finish();").contains(&"Finish"));
    assert!(api_violations("todo!()").contains(&"todo!"));
    // And it does not flag the documented vocabulary prose.
    assert!(api_violations("//! Provider-neutral cue vocabulary").is_empty());
    assert!(api_violations("#![forbid(unsafe_code)]").is_empty());
}

const API_SOURCES: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("activation.rs", include_str!("../src/activation.rs")),
    ("binding.rs", include_str!("../src/binding.rs")),
    ("bounds.rs", include_str!("../src/bounds.rs")),
    ("context.rs", include_str!("../src/context.rs")),
    ("diagnostic.rs", include_str!("../src/diagnostic.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("identity.rs", include_str!("../src/identity.rs")),
    ("index_bounds.rs", include_str!("../src/index_bounds.rs")),
    (
        "index_candidate.rs",
        include_str!("../src/index_candidate.rs"),
    ),
    (
        "index_projection.rs",
        include_str!("../src/index_projection.rs"),
    ),
    ("invalidation.rs", include_str!("../src/invalidation.rs")),
    ("lineage.rs", include_str!("../src/lineage.rs")),
    ("normalization.rs", include_str!("../src/normalization.rs")),
    ("observation.rs", include_str!("../src/observation.rs")),
    ("relation.rs", include_str!("../src/relation.rs")),
    ("snapshot.rs", include_str!("../src/snapshot.rs")),
];

const API_FORBIDDEN_WORDS: &[&str] = &[
    "Store",
    "Provider",
    "Model",
    "Mutation",
    "Authority",
    "Effect",
    "Finish",
    "unsafe",
];

const API_FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "std::fs",
    "std::io",
    "std::net",
    "std::process",
    "tokio::",
    "async fn",
    ".await",
    "std::thread",
    "std::env::",
    "Command::new",
    "serde_json::Value",
    "todo!",
    "unimplemented!",
    "unreachable!",
    "panic!",
    "fn normalize(",
    "fn traverse(",
    "fn evaluate(",
    "fn activate(",
    "fn build_index(",
    "fn plan(",
    "fn schedule(",
    "fn dispatch(",
    "fn execute(",
    "fn run(",
    "fn fetch(",
    "fn load(",
    "fn save(",
];

fn api_is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

// Whole-word scan: `Provider-neutral` prose and `forbid(unsafe_code)` are not
// vocabulary items, so `-` and `_` count as word characters.
fn api_contains_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() || needle.len() > bytes.len() {
        return false;
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .any(|(index, window)| {
            window == needle
                && (index == 0 || !api_is_word(bytes[index - 1]))
                && (index + needle.len() == bytes.len()
                    || !api_is_word(bytes[index + needle.len()]))
        })
}

fn api_violations(source: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for word in API_FORBIDDEN_WORDS {
        if api_contains_word(source, word) {
            found.push(*word);
        }
    }
    for substring in API_FORBIDDEN_SUBSTRINGS {
        if source.contains(substring) {
            found.push(*substring);
        }
    }
    found
}
