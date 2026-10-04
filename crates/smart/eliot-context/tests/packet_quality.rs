//! Issue #868 boundary proof: the eight-Boolean `PacketQualityScorecard` is a
//! re-scoped legacy compatibility record, `eliot_context_contracts` (A-15) owns
//! the current quality contract, and the old payload enters this crate only
//! through one named legacy decode boundary.
//!
//! One substantive test per `// WORK_UNIT_CASE: 868/<n>`, cases exactly 1..24.

// Frozen #40 compat surface: this target exercises the deprecated compat entry
// points on purpose. The crate allows deprecated cross-uses at `src/lib.rs:12`;
// an integration test is a separate crate and does not inherit that allow. Both
// sibling targets (`admission_integrity.rs`, `cue_kind_boundary.rs`) use the same
// entry points and carry no allow of their own.
#![allow(deprecated)]

use std::collections::BTreeSet;
use std::error::Error;

use eliot_context::{
    AdmissionDisposition, ContextAtom, ContextCompiler, ContextError, ContextInput, ContextRecipe,
    ContextRole, LEGACY_DIMENSION_DISPOSITIONS, LegacyQualityDisposition, PacketQualityScorecard,
    RoleBudget, decode_legacy_packet_quality, legacy_packet_quality_to_dimension_results,
};
use eliot_context_contracts::{
    ContextError as ContractContextError, MeasurementRef, QUALITY_APPLICABILITY_INPUTS,
    QUALITY_DIMENSIONS, QUALITY_RESULT_SCHEMA_VERSION, QUALITY_SCORECARD_SCHEMA_VERSION,
    QualityApplicabilityInput, QualityDimension, QualityDimensionResult, QualityDimensionState,
    QualityOperation, QualityRefusal, QualityRefusalKind, QualityScorecard, QualitySuitability,
};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskRevision,
};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};

type TestResult = Result<(), Box<dyn Error>>;

const LEGACY_FIXTURE: &str = include_str!("data/packet_quality_legacy.json");
const CURRENT_FIXTURE: &str = include_str!("data/packet_quality_current.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const FACADE_SOURCE: &str = include_str!("../src/facade.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../../../Cargo.lock");
const A15_QUALITY_SOURCE: &str = include_str!("../../eliot-context-contracts/src/quality.rs");

/// The exact eight frozen legacy wire field names, in declaration order.
const LEGACY_FIELDS: [&str; 8] = [
    "goal_coverage",
    "epistemic_coverage",
    "provenance_coverage",
    "fence_coherent",
    "uncertainty_visible",
    "safety_coverage",
    "decision_readiness",
    "bounded_omission",
];

/// Test golden, not a production list: the twelve exact I12.13 identities and
/// their canonical order, read back from the A-15 owner.
const CANONICAL_DIMENSIONS: [&str; 12] = [
    "ACCEPTANCE_DECISION_COVERAGE",
    "CAUSAL_OPERATIONAL_SUFFICIENCY",
    "EXACT_ANCHOR_PROVENANCE_COVERAGE",
    "FRESHNESS_STATE_FENCE_COHERENCE",
    "RIVALS_CONFLICTS_UNKNOWNS_VISIBILITY",
    "NEGATIVE_MEMORY_INVARIANT_COVERAGE",
    "VERIFIER_ACTION_READINESS",
    "ROUTE_ACCESSIBILITY_LAYOUT_RISK",
    "INSTRUCTION_SUFFICIENCY",
    "PAYLOAD_HANDLE_RECONSTRUCTION_COST",
    "KNOWN_OMISSIONS_EXPANSION_PATHS",
    "TELEMETRY_MEASUREMENT_COST_COVERAGE",
];

/// Test golden for the six closed applicability inputs.
const APPLICABILITY_WIRE: [&str; 6] = [
    "TASK_ACCEPTANCE",
    "ROUTE",
    "IMPACT",
    "GOVERNANCE_PROFILE",
    "PROTECTED_FLOOR",
    "ACTIVE_DIRECTIVE",
];

const RULE_REVISION: &str = "rule:868:legacy-compatibility-record";
const MISSING_EVIDENCE: &str = "evidence:868:absent-from-legacy-wire";
const BLOCKED_INVARIANT: &str = "invariant:868:required-dimension-not-satisfied";

/// The weakest `ProofCeiling`; `eliot_receipts::ProofCeiling::is_at_most`
/// orders it lowest, so it is the only value a legacy Boolean may carry.
const NEUTRAL_PROOF_CEILING: &str = "OBSERVATION";

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn artifact(value: &str) -> Result<ArtifactId, Box<dyn Error>> {
    Ok(ArtifactId::new(value)?)
}

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn canonical_index(dimension: QualityDimension) -> usize {
    QUALITY_DIMENSIONS
        .iter()
        .position(|candidate| *candidate == dimension)
        .unwrap_or_else(|| panic!("{dimension:?} must be one of the twelve A-15 dimensions"))
}

fn json_object(text: &str) -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    match serde_json::from_str::<serde_json::Value>(text)? {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err("fixture must be a JSON object".into()),
    }
}

fn legacy_json() -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    json_object(LEGACY_FIXTURE)
}

fn current_json() -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    json_object(CURRENT_FIXTURE)
}

fn legacy_record() -> Result<PacketQualityScorecard, Box<dyn Error>> {
    Ok(serde_json::from_str(LEGACY_FIXTURE)?)
}

fn current_card() -> Result<QualityScorecard, Box<dyn Error>> {
    Ok(serde_json::from_str(CURRENT_FIXTURE)?)
}

fn sorted_keys(map: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

/// The legacy record with an explicit per-field truth pattern, written out field
/// by field so a renamed or dropped wire field cannot slip through.
fn legacy_with(flags: [bool; 8]) -> PacketQualityScorecard {
    PacketQualityScorecard {
        goal_coverage: flags[0],
        epistemic_coverage: flags[1],
        provenance_coverage: flags[2],
        fence_coherent: flags[3],
        uncertainty_visible: flags[4],
        safety_coverage: flags[5],
        decision_readiness: flags[6],
        bounded_omission: flags[7],
    }
}

fn converted(
    card: &QualityScorecard,
    legacy: &PacketQualityScorecard,
) -> Result<Vec<QualityDimensionResult>, Box<dyn Error>> {
    Ok(legacy_packet_quality_to_dimension_results(
        legacy,
        &card.binding,
        &artifact(RULE_REVISION)?,
        &[artifact(MISSING_EVIDENCE)?],
    )?)
}

/// Overwrite one dimension's state and supply exactly the evidence that state
/// requires under `quality.rs:229-261`.
fn set_state(
    card: &mut QualityScorecard,
    dimension: QualityDimension,
    state: QualityDimensionState,
) -> Result<(), Box<dyn Error>> {
    let failed = matches!(state, QualityDimensionState::Failed);
    let unknown = matches!(state, QualityDimensionState::Unknown);
    let index = canonical_index(dimension);
    let result = &mut card.results[index];
    result.state = state;
    result.failed_invariant = if failed {
        Some(artifact(BLOCKED_INVARIANT)?)
    } else {
        None
    };
    result.unknown_evidence = if unknown {
        vec![artifact(MISSING_EVIDENCE)?]
    } else {
        Vec::new()
    };
    Ok(())
}

fn current_result_without(field: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut map = current_json()?;
    {
        let results = map
            .get_mut("results")
            .ok_or("current fixture must carry results")?;
        let serde_json::Value::Array(array) = results else {
            return Err("results must be a JSON array".into());
        };
        let first = array
            .first_mut()
            .ok_or("current fixture must carry twelve results")?;
        let serde_json::Value::Object(object) = first else {
            return Err("each result must be a JSON object".into());
        };
        if object.remove(field).is_none() {
            return Err(format!("current fixture result must carry `{field}`").into());
        }
    }
    Ok(serde_json::Value::Object(map))
}

fn current_result_tampered(
    field: &str,
    value: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut map = current_json()?;
    {
        let results = map
            .get_mut("results")
            .ok_or("current fixture must carry results")?;
        let serde_json::Value::Array(array) = results else {
            return Err("results must be a JSON array".into());
        };
        let first = array
            .first_mut()
            .ok_or("current fixture must carry twelve results")?;
        let serde_json::Value::Object(object) = first else {
            return Err("each result must be a JSON object".into());
        };
        object.insert(field.to_owned(), value);
    }
    Ok(serde_json::Value::Object(map))
}

/// Every `Scorecard`-named public struct declared in the donor's live code.
fn declared_scorecard_structs(code: &str) -> Vec<&str> {
    code.split("pub struct ")
        .skip(1)
        .filter_map(|rest| {
            rest.split(|character: char| !(character.is_alphanumeric() || character == '_'))
                .next()
        })
        .filter(|name| name.contains("Scorecard"))
        .collect()
}

fn decode_error(payload: &str) -> ContextError {
    match decode_legacy_packet_quality(payload) {
        Ok(_) => panic!("a malformed legacy payload must be rejected, never defaulted"),
        Err(error) => error,
    }
}

fn fence() -> Result<StateFence, Box<dyn Error>> {
    Ok(StateFence::new(
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE)?,
            std::num::NonZeroU64::new(1).ok_or("nonzero test sequence")?,
        )?,
        ResourceGeneration::genesis(),
    ))
}

fn goal_atom(id: &str) -> Result<ContextAtom, Box<dyn Error>> {
    Ok(ContextAtom {
        atom_id: artifact(id)?,
        role: ContextRole::Goal,
        payload: format!("payload for {id}"),
        source_handles: vec![artifact(&format!("source:{id}"))?],
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        freshness: EvidenceFreshness::ExactCommit,
        state_fence: fence()?,
        required: true,
        protected: true,
        cost: 1,
        expected_decision_delta: 10,
        risk: 1,
        cues: Vec::new(),
    })
}

fn revisioned_input(atoms: Vec<ContextAtom>) -> Result<ContextInput, Box<dyn Error>> {
    Ok(ContextInput {
        scope: "scope:868".to_owned(),
        task_id: None,
        task_revision: TaskRevision::new(1)?,
        state_fence: fence()?,
        atoms,
        unknowns: Vec::new(),
    })
}

fn budgeted_recipe(maximum_cost: u32) -> Result<ContextRecipe, Box<dyn Error>> {
    Ok(ContextRecipe {
        recipe_revision: TaskRevision::new(1)?,
        total_cost: 10,
        role_budgets: vec![RoleBudget {
            role: ContextRole::Goal,
            maximum_cost,
        }],
        required_roles: vec![ContextRole::Goal],
    })
}

/// Strip line/block comments, string/char literals and raw strings so the
/// source oracles below cannot false-positive on prose.
fn code_without_comments_and_strings(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(current) = chars.next() {
        if current == '/' && chars.peek() == Some(&'/') {
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if current == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for next in chars.by_ref() {
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
            out.push(' ');
        } else if current == 'r' && matches!(chars.peek(), Some('#' | '"')) {
            let mut hashes = 0usize;
            while chars.peek() == Some(&'#') {
                chars.next();
                hashes += 1;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                let mut previous = '\0';
                let mut closing = 0usize;
                for next in chars.by_ref() {
                    if previous == '"' && next == '#' && closing < hashes {
                        closing += 1;
                        if closing == hashes {
                            break;
                        }
                    } else if next == '"' {
                        previous = '"';
                        closing = 0;
                    } else {
                        previous = next;
                        closing = 0;
                    }
                }
                out.push(' ');
            } else {
                out.push('r');
                for _ in 0..hashes {
                    out.push('#');
                }
            }
        } else if current == '"' {
            let mut previous = '\0';
            for next in chars.by_ref() {
                if previous != '\\' && next == '"' {
                    break;
                }
                previous = next;
            }
            out.push(' ');
        } else if current == '\'' {
            let mut ident = String::new();
            while let Some(&next) = chars.peek() {
                if !(next.is_alphanumeric() || next == '_') {
                    break;
                }
                ident.push(next);
                chars.next();
            }
            if !ident.is_empty() && chars.peek() == Some(&'\'') {
                chars.next();
                out.push(' ');
            } else {
                out.push('\'');
                out.push_str(&ident);
            }
        } else {
            out.push(current);
        }
    }
    out
}

// Fails if: a legacy field is renamed, added or dropped on the wire, if its
// producer expression moves, or if any second consumer of a legacy field name
// appears in the donor's live code or in the facade table.
// WORK_UNIT_CASE: 868/1
#[test]
fn exact_eight_old_fields_producers_and_consumer_absence() -> TestResult {
    let wire = legacy_json()?;
    let mut expected: Vec<String> = LEGACY_FIELDS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    expected.sort();
    assert_eq!(
        sorted_keys(&wire),
        expected,
        "the legacy wire is exactly the eight frozen field names, no more and no fewer"
    );
    let legacy = legacy_record()?;
    let observed = [
        ("goal_coverage", legacy.goal_coverage),
        ("epistemic_coverage", legacy.epistemic_coverage),
        ("provenance_coverage", legacy.provenance_coverage),
        ("fence_coherent", legacy.fence_coherent),
        ("uncertainty_visible", legacy.uncertainty_visible),
        ("safety_coverage", legacy.safety_coverage),
        ("decision_readiness", legacy.decision_readiness),
        ("bounded_omission", legacy.bounded_omission),
    ];
    for (name, value) in observed {
        assert_eq!(
            Some(&serde_json::Value::Bool(value)),
            wire.get(name),
            "legacy field {name} must reach the record unchanged from the frozen wire fixture"
        );
    }
    let code = code_without_comments_and_strings(LIB_SOURCE);
    let producer = code
        .find("fn scorecard(")
        .ok_or("the legacy producer fn must remain")?;
    let declaration = code
        .find("pub struct PacketQualityScorecard")
        .ok_or("the legacy record must remain declared")?;
    assert!(
        declaration < producer,
        "the record is declared before its only producer"
    );
    let facade = code_without_comments_and_strings(FACADE_SOURCE);
    for field in LEGACY_FIELDS {
        assert_eq!(
            code.matches(field).count(),
            2,
            "{field} must appear only as its `pub {field}: bool` declaration and its producer \
             assignment; a third occurrence is an unproven consumer"
        );
        assert!(
            code.contains(&format!("pub {field}: bool")),
            "{field} must still be a named public Boolean on the established layout"
        );
        assert!(
            !facade.contains(field),
            "the facade table must not read the legacy field {field}"
        );
    }
    Ok(())
}

// Fails if: A-15 renames, reorders, adds or drops a dimension, or if the current
// fixture stops carrying exactly one result per dimension in that order.
// WORK_UNIT_CASE: 868/2
#[test]
fn twelve_canonical_dimension_identities_and_order() -> TestResult {
    assert_eq!(QUALITY_DIMENSIONS.len(), CANONICAL_DIMENSIONS.len());
    let distinct: BTreeSet<QualityDimension> = QUALITY_DIMENSIONS.into_iter().collect();
    assert_eq!(
        distinct.len(),
        CANONICAL_DIMENSIONS.len(),
        "the canonical denominator holds twelve distinct dimensions"
    );
    for (index, dimension) in QUALITY_DIMENSIONS.into_iter().enumerate() {
        assert_eq!(
            serde_json::to_value(dimension)?,
            serde_json::Value::String(CANONICAL_DIMENSIONS[index].to_owned()),
            "dimension {index} must keep its exact A-15 wire identity and canonical position"
        );
    }
    let card = current_card()?;
    assert_eq!(card.schema_version, QUALITY_SCORECARD_SCHEMA_VERSION);
    assert_eq!(card.results.len(), QUALITY_DIMENSIONS.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (index, result) in card.results.iter().enumerate() {
        assert_eq!(
            result.dimension, QUALITY_DIMENSIONS[index],
            "result {index} sits at its canonical dimension position"
        );
        let wire = serde_json::to_value(result.dimension)?;
        let wire = wire.as_str().ok_or("a dimension serializes as a string")?;
        assert!(
            seen.insert(wire.to_owned()),
            "dimension {wire} may not repeat on one card"
        );
    }
    card.validate()?;
    Ok(())
}

// Fails if: the disposition table is re-keyed by a local eight-element list, or
// if a fabricated eight-to-twelve bijection makes every dimension look covered.
// WORK_UNIT_CASE: 868/3
#[test]
fn exact_a15_mapping_not_an_invented_bijection() {
    let rows = &LEGACY_DIMENSION_DISPOSITIONS;
    assert_eq!(
        rows.len(),
        QUALITY_DIMENSIONS.len(),
        "the table is indexed by the A-15 owner, so it has exactly twelve rows"
    );
    for (index, row) in rows.iter().enumerate() {
        assert!(
            QUALITY_DIMENSIONS.contains(&row.dimension),
            "row {index} must name an A-15 dimension"
        );
        assert_eq!(
            row.dimension, QUALITY_DIMENSIONS[index],
            "row {index} follows the A-15 owner's own order, not a new local list"
        );
    }
    let mentioned: Vec<&str> = rows
        .iter()
        .flat_map(|row| row.legacy_fields.iter().copied())
        .collect();
    let distinct: BTreeSet<&str> = mentioned.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        LEGACY_FIELDS.len(),
        "all eight legacy field names must be named somewhere in the table"
    );
    let without_legacy = rows
        .iter()
        .filter(|row| row.legacy_fields.is_empty())
        .count();
    assert!(
        without_legacy >= 1,
        "a Boolean cannot supply a numerator, denominator, observation window or grade, so at \
         least one A-15 dimension has no legacy producer and no eight-to-twelve bijection exists"
    );
    assert!(
        rows.iter()
            .any(|row| row.disposition == LegacyQualityDisposition::SaysNothing),
        "at least one dimension must be dispositioned as saying nothing about its legacy evidence"
    );
}

// Fails if: a second production enum, list, constant table or scalar scorecard
// owner is declared next to the A-15 contract in this donor crate.
// WORK_UNIT_CASE: 868/4
#[test]
fn no_duplicate_production_owner_test_goldens_only() {
    assert!(
        A15_QUALITY_SOURCE.contains("pub enum QualityDimension {"),
        "oracle self-check: A-15 must still own the dimension enum"
    );
    assert!(A15_QUALITY_SOURCE.contains("pub struct QualityScorecard"));
    let code = code_without_comments_and_strings(LIB_SOURCE);
    for duplicate in [
        "pub enum QualityDimension {",
        "pub enum QualityDimensionState {",
        "pub enum QualityOperation {",
        "pub struct QualityScorecard {",
        "pub struct QualityDimensionResult {",
        "static QUALITY_DIMENSIONS",
        "const QUALITY_DIMENSIONS",
    ] {
        assert!(
            !code.contains(duplicate),
            "a duplicated production owner may not live here: {duplicate}"
        );
    }
    assert_eq!(
        code.matches("pub struct PacketQualityScorecard").count(),
        1,
        "the legacy record is declared exactly once"
    );
    assert_eq!(
        code.matches("LEGACY_DIMENSION_DISPOSITIONS: [").count(),
        1,
        "the disposition table is one named constant, not a second list"
    );
    for scalar in [
        "fn total(",
        "fn rank(",
        "fn score(",
        "partial_cmp",
        "fn better(",
        "fn worse(",
    ] {
        assert!(
            !code.contains(scalar),
            "no aggregate Boolean, weighted utility or total order may be added: {scalar}"
        );
    }
}

// Fails if: an old field loses its explicit disposition row, or a disposition
// stops being one of the three closed evidence-adjacent values.
// WORK_UNIT_CASE: 868/5
#[test]
fn each_old_field_has_an_explicit_disposition() {
    let rows = &LEGACY_DIMENSION_DISPOSITIONS;
    let closed = ["Supports", "Refutes", "SaysNothing"];
    for field in LEGACY_FIELDS {
        let mut named = 0usize;
        for row in rows.iter().filter(|row| row.legacy_fields.contains(&field)) {
            named += 1;
            let disposition = format!("{:?}", row.disposition);
            assert!(
                closed.contains(&disposition.as_str()),
                "{field} carries disposition {disposition}, which is not one of the three closed \
                 evidence-adjacent values"
            );
        }
        assert_eq!(
            named, 1,
            "{field} must be dispositioned by exactly one row; a dropped field is an unreported \
             loss and a second row would claim the same Boolean twice"
        );
    }
    let unmentioned: Vec<&str> = LEGACY_FIELDS
        .iter()
        .copied()
        .filter(|field| !rows.iter().any(|row| row.legacy_fields.contains(field)))
        .collect();
    assert!(
        unmentioned.is_empty(),
        "every old field needs a disposition; these have none: {unmentioned:?}"
    );
}

// Fails if: any one of the twelve dimensions comes back without a named gap, or
// comes back with invented evidence taken from the Boolean wire.
// WORK_UNIT_CASE: 868/6
#[test]
fn each_new_dimension_has_actual_evidence_or_unknown() -> TestResult {
    let card = current_card()?;
    let results = converted(&card, &legacy_record()?)?;
    assert_eq!(results.len(), QUALITY_DIMENSIONS.len());
    for (index, result) in results.iter().enumerate() {
        assert_eq!(result.dimension, QUALITY_DIMENSIONS[index]);
        assert_eq!(
            result.state,
            QualityDimensionState::Unknown,
            "dimension {index} stays unknown: the legacy Boolean carries no required evidence"
        );
        assert!(
            !result.is_current_pass(),
            "dimension {index} must not read as an observed pass"
        );
        assert!(
            !result.unknown_evidence.is_empty(),
            "dimension {index} must name exactly what it still lacks"
        );
        assert!(
            result
                .unknown_evidence
                .contains(&artifact(MISSING_EVIDENCE)?),
            "dimension {index} must carry the caller-supplied missing evidence handle"
        );
        assert!(
            result.evidence.is_empty(),
            "dimension {index} must not be given evidence the legacy wire never carried"
        );
        assert!(
            result.required_evidence.is_empty(),
            "dimension {index} must not be given a required member set the legacy wire never carried"
        );
        assert_eq!(result.failed_invariant, None);
        assert_eq!(result.invalidation, None);
        assert!(result.measurements.is_empty());
        assert_eq!(result.binding, card.binding);
        assert_eq!(result.schema_version, QUALITY_RESULT_SCHEMA_VERSION);
    }
    Ok(())
}

// Fails if: the current record stops binding its packet/View/recipe/fence, or a
// card validated against one binding starts validating against another.
// WORK_UNIT_CASE: 868/7
#[test]
fn current_record_binds_packet_view_recipe_and_fence() -> TestResult {
    let card = current_card()?;
    card.validate()?;
    for result in &card.results {
        assert_eq!(
            result.binding, card.binding,
            "every dimension is bound to the card's own packet identity"
        );
    }
    assert_eq!(card.output.recipe_digest.len(), 64);
    assert_eq!(card.output.fence_digest.len(), 64);
    assert_eq!(card.output.admitted_digest.len(), 64);
    assert_eq!(card.output.rendered_digest.len(), 64);
    assert_eq!(card.output.serializer_options_digest.len(), 64);
    assert!(!card.output.serializer_id.trim().is_empty());
    assert!(!card.output.serializer_version.trim().is_empty());
    assert!(!card.output.route_id.trim().is_empty());
    assert!(
        !card.output.evidence_revisions.is_empty(),
        "the grades must name the source revisions they were read from"
    );
    assert!(card.applicability.resolved.len() + card.applicability.unknown.len() > 0);
    let mut tampered = current_json()?;
    match tampered
        .get_mut("binding")
        .ok_or("current fixture must carry a binding")?
    {
        serde_json::Value::Object(object) => {
            object.insert(
                "task_id".to_owned(),
                serde_json::Value::String("task:868:other-packet".to_owned()),
            );
        }
        _ => return Err("binding must be a JSON object".into()),
    }
    let swapped: QualityScorecard = serde_json::from_value(serde_json::Value::Object(tampered))?;
    assert_eq!(
        swapped.validate(),
        Err(ContractContextError::QualityIncomplete),
        "a card whose binding differs from its results' binding must be refused"
    );
    assert!(matches!(
        swapped.suitability(QualityOperation::DependentAction, &[]),
        Err(QualityRefusal {
            kind: QualityRefusalKind::InvalidScorecard,
            ..
        })
    ));
    Ok(())
}

// Fails if: an unknown current field or an unknown/undefined current variant
// starts being accepted by trial-decoding or by a permissive fallback.
// WORK_UNIT_CASE: 868/8
#[test]
fn unknown_current_field_or_variant_rejected() -> TestResult {
    for (field, value) in [
        ("passed", serde_json::Value::Bool(true)),
        ("state", serde_json::Value::Bool(false)),
        (
            "state",
            serde_json::Value::String("PARTIALLY_OBSERVED".to_owned()),
        ),
        (
            "dimension",
            serde_json::Value::String("GOAL_COVERAGE".to_owned()),
        ),
        ("state", serde_json::Value::String("MOSTLY_FINE".to_owned())),
    ] {
        let tampered = current_result_tampered(field, value)?;
        assert!(
            serde_json::from_value::<QualityScorecard>(tampered.clone()).is_err(),
            "an unknown or schema-1 `{field}` must be rejected, never reinterpreted"
        );
        assert!(
            serde_json::from_value::<QualityDimensionResult>(tampered).is_err(),
            "a single dimension result must refuse `{field}` too"
        );
    }
    let mut extra = current_json()?;
    extra.insert(
        "total".to_owned(),
        serde_json::Value::Number(serde_json::Number::from(12)),
    );
    assert!(
        serde_json::from_value::<QualityScorecard>(serde_json::Value::Object(extra)).is_err(),
        "the card denies unknown fields, so an aggregate score cannot be introduced"
    );
    assert!(serde_json::from_value::<QualityDimensionState>(serde_json::Value::Null).is_err());
    Ok(())
}

// Fails if: a protected dimension, state or denominator starts being defaulted,
// inferred or omitted instead of being required on the wire.
// WORK_UNIT_CASE: 868/9
#[test]
fn no_protected_dimension_status_or_denominator_defaults() -> TestResult {
    for field in [
        "state",
        "schema_version",
        "dimension",
        "rule_revision",
        "required_evidence",
        "evidence",
        "proof_ceiling",
        "failed_invariant",
        "unknown_evidence",
    ] {
        let stripped = current_result_without(field)?;
        assert!(
            serde_json::from_value::<QualityDimensionResult>(stripped).is_err(),
            "`{field}` has no default: an omitted protected field must be rejected"
        );
    }
    for field in [
        "schema_version",
        "binding",
        "output",
        "applicability",
        "results",
    ] {
        let mut map = current_json()?;
        if map.remove(field).is_none() {
            return Err(format!("current fixture must carry `{field}`").into());
        }
        assert!(
            serde_json::from_value::<QualityScorecard>(serde_json::Value::Object(map)).is_err(),
            "scorecard `{field}` has no default and no clock fallback"
        );
    }
    let mut without_partition = current_json()?;
    match without_partition
        .get_mut("applicability")
        .ok_or("current fixture must carry an applicability partition")?
    {
        serde_json::Value::Object(applicability) => {
            if applicability.remove("unknown").is_none() {
                return Err("the fixture must carry an applicability `unknown` partition".into());
            }
        }
        _ => return Err("applicability must be a JSON object".into()),
    }
    assert!(
        serde_json::from_value::<QualityScorecard>(serde_json::Value::Object(without_partition))
            .is_err(),
        "the applicability partition is required, never inferred from the grades"
    );
    Ok(())
}

// Fails if: a measured zero with a valid denominator collapses into absence, or
// if its measurement stops surviving the wire byte for byte.
// WORK_UNIT_CASE: 868/10
#[test]
fn measured_zero_with_valid_denominator() -> TestResult {
    let mut card = current_card()?;
    let index = canonical_index(QualityDimension::TelemetryMeasurementCostCoverage);
    let measurement = MeasurementRef {
        digest: digest('a'),
        serializer: "eliot-context-test:1.0.0".to_owned(),
    };
    card.results[index].state = QualityDimensionState::Failed;
    card.results[index].failed_invariant = Some(artifact(BLOCKED_INVARIANT)?);
    card.results[index].unknown_evidence = Vec::new();
    card.results[index].measurements = vec![measurement.clone()];
    // A measured zero over a valid denominator: every required member was
    // observed and the measurement still reads zero. This is not an absence.
    card.results[index].evidence = card.results[index].required_evidence.clone();
    assert!(
        !card.results[index].required_evidence.is_empty(),
        "a measured zero needs a valid denominator"
    );
    assert!(
        card.results[index]
            .required_evidence
            .iter()
            .all(|member| card.results[index].evidence.contains(member)),
        "every required member was observed, so this is a measurement and not a gap"
    );
    card.validate()?;
    assert!(
        !card.all_pass()?,
        "a measured zero is a real failure, not a pass"
    );
    let round: QualityScorecard = serde_json::from_str(&serde_json::to_string(&card)?)?;
    assert_eq!(
        round.results[index].measurements,
        vec![measurement],
        "the measurement survives byte for byte"
    );
    assert_eq!(
        round.results[index].failed_invariant,
        Some(artifact(BLOCKED_INVARIANT)?)
    );
    assert!(
        matches!(
            card.suitability(QualityOperation::Compile, &[]),
            Err(QualityRefusal {
                kind: QualityRefusalKind::OperationBlocked,
                ..
            })
        ),
        "a measured zero blocks every operation that requires the dimension"
    );
    Ok(())
}

// Fails if: an absent or zero denominator is accepted, defaulted to success, or
// read against the card's own entry count instead of A-15's declared constant.
// WORK_UNIT_CASE: 868/11
#[test]
fn absent_or_zero_denominator_follows_a15() -> TestResult {
    let mut empty = current_card()?;
    empty.results.clear();
    assert_eq!(
        empty.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    let mut short = current_card()?;
    let _ = short.results.pop();
    assert_eq!(
        short.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    let mut padded = current_card()?;
    let last = padded.results.last().cloned().ok_or("twelve results")?;
    padded.results.push(last);
    assert_eq!(
        padded.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    let mut reordered = current_card()?;
    reordered.results.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    let mut zero_members = current_card()?;
    let index = canonical_index(QualityDimension::AcceptanceDecisionCoverage);
    assert_eq!(
        zero_members.results[index].state,
        QualityDimensionState::Passed,
        "the zero-denominator probe needs a passed dimension to strip"
    );
    zero_members.results[index].required_evidence.clear();
    assert_eq!(
        zero_members.validate(),
        Err(ContractContextError::QualityIncomplete),
        "a zero denominator cannot certify a pass"
    );
    let mut partial_members = current_card()?;
    partial_members.results[index].evidence.clear();
    assert_eq!(
        partial_members.validate(),
        Err(ContractContextError::QualityIncomplete),
        "a partially observed denominator cannot certify a pass either"
    );
    let mut zero_schema = current_card()?;
    zero_schema.schema_version = 0;
    assert_eq!(
        zero_schema.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    Ok(())
}

// Fails if: missing, failed, unavailable, unknown, omitted and not-applicable
// collapse into one another under the A-15 state contract.
// WORK_UNIT_CASE: 868/12
#[test]
fn six_outcomes_remain_distinct_under_a15() -> TestResult {
    let target = QualityDimension::InstructionSufficiency;
    let index = canonical_index(target);
    let mut failed = current_card()?;
    set_state(&mut failed, target, QualityDimensionState::Failed)?;
    failed.validate()?;
    let mut unavailable = current_card()?;
    unavailable.results[index].state = QualityDimensionState::Unknown;
    unavailable.results[index].failed_invariant = None;
    unavailable.results[index].required_evidence = Vec::new();
    unavailable.results[index].evidence = Vec::new();
    unavailable.results[index].unknown_evidence = vec![artifact(MISSING_EVIDENCE)?];
    unavailable.validate()?;
    let mut unknown = current_card()?;
    set_state(&mut unknown, target, QualityDimensionState::Unknown)?;
    let unknown_members = unknown.results[index].required_evidence.clone();
    unknown.results[index].evidence = Vec::new();
    unknown.validate()?;
    let mut inapplicable = current_card()?;
    inapplicable.results[index].state = QualityDimensionState::NotApplicable {
        reason: "governing profile 868 declares this dimension out of scope".to_owned(),
    };
    inapplicable.results[index].failed_invariant = None;
    inapplicable.results[index].unknown_evidence = Vec::new();
    inapplicable.validate()?;
    let mut omitted = current_card()?;
    let _ = omitted.results.remove(index);
    assert_eq!(
        omitted.validate(),
        Err(ContractContextError::QualityIncomplete),
        "an omitted dimension is a structural failure, never a shortcut to success"
    );
    let missing = current_result_without("state")?;
    assert!(
        serde_json::from_value::<QualityDimensionResult>(missing).is_err(),
        "a missing state is refused rather than defaulted"
    );
    let base = current_card()?.results[index].clone();
    let failed_result = failed.results[index].clone();
    let unavailable_result = unavailable.results[index].clone();
    let unknown_result = unknown.results[index].clone();
    let inapplicable_result = inapplicable.results[index].clone();
    let graded = [
        &base,
        &failed_result,
        &unavailable_result,
        &unknown_result,
        &inapplicable_result,
    ];
    let mut wires: BTreeSet<String> = BTreeSet::new();
    for result in &graded {
        wires.insert(serde_json::to_string(&result.state)?);
    }
    assert_eq!(
        wires.len(),
        3,
        "three closed spellings carry five graded outcomes; failed, unknown and not-applicable \
         stay distinct, and the two UNKNOWN cases are separated by their denominator rather than \
         by their spelling"
    );
    for result in [
        &failed_result,
        &unavailable_result,
        &unknown_result,
        &inapplicable_result,
    ] {
        assert!(
            !result.is_current_pass(),
            "{:?} is never a pass",
            result.state
        );
    }
    assert!(
        !unknown_members.is_empty() && unavailable_result.required_evidence.is_empty(),
        "unavailable (no denominator) and unknown (a named gap inside a denominator) stay distinct"
    );
    assert_ne!(failed_result, unavailable_result);
    assert_ne!(unavailable_result, unknown_result);
    let mut hiding = inapplicable;
    hiding.results[index].failed_invariant = Some(artifact(BLOCKED_INVARIANT)?);
    assert_eq!(
        hiding.validate(),
        Err(ContractContextError::QualityIncomplete),
        "a policy reason may not hide a failed invariant"
    );
    Ok(())
}

// Fails if: an absent legacy field defaults to false, or an invented version
// field is imposed on the established eight-Boolean layout.
// WORK_UNIT_CASE: 868/13
#[test]
fn absent_old_field_cannot_become_false() -> TestResult {
    let complete = legacy_json()?;
    for field in LEGACY_FIELDS {
        let mut absent = complete.clone();
        if absent.remove(field).is_none() {
            return Err(format!("the legacy fixture must carry `{field}`").into());
        }
        let absent_bytes = serde_json::to_string(&serde_json::Value::Object(absent))?;
        assert!(
            serde_json::from_str::<PacketQualityScorecard>(&absent_bytes).is_err(),
            "an absent `{field}` must be rejected, never defaulted to false"
        );
        assert!(
            decode_legacy_packet_quality(&absent_bytes).is_err(),
            "the named legacy boundary must reject an absent `{field}` too"
        );
        let mut nulled = complete.clone();
        nulled.insert(field.to_owned(), serde_json::Value::Null);
        let nulled_bytes = serde_json::to_string(&serde_json::Value::Object(nulled))?;
        assert!(
            serde_json::from_str::<PacketQualityScorecard>(&nulled_bytes).is_err(),
            "`{field}: null` is not a Boolean and must be rejected"
        );
    }
    for invented in ["version", "schema_version", "state", "score"] {
        let mut extended = complete.clone();
        extended.insert(
            invented.to_owned(),
            serde_json::Value::Number(serde_json::Number::from(2)),
        );
        let extended_bytes = serde_json::to_string(&serde_json::Value::Object(extended))?;
        assert!(
            serde_json::from_str::<PacketQualityScorecard>(&extended_bytes).is_err(),
            "no invented `{invented}` field may be imposed on the established legacy layout"
        );
    }
    Ok(())
}

// Fails if: the eight-Boolean payload gains a second entry point, or the named
// boundary stops applying its bounded `text` check (blank and control-character
// payloads refused) and surfacing a typed, payload-free error.
// WORK_UNIT_CASE: 868/14
#[test]
fn old_eight_boolean_payload_only_through_named_legacy_boundary() -> TestResult {
    assert!(
        code_without_comments_and_strings(LIB_SOURCE)
            .contains("pub fn decode_legacy_packet_quality("),
        "the one named legacy decode boundary must exist under its frozen name"
    );
    assert_eq!(
        decode_legacy_packet_quality(LEGACY_FIXTURE)?,
        legacy_record()?,
        "the named boundary and the legacy record agree field for field"
    );
    for malformed in [
        "",
        "{}",
        "not json",
        "[1,2,3]",
        "{\"goal_coverage\":true}",
        "{ trailing",
    ] {
        assert!(
            decode_legacy_packet_quality(malformed).is_err(),
            "a malformed legacy payload must be refused without a silent default"
        );
    }
    assert!(
        decode_legacy_packet_quality("").is_err(),
        "the boundary's real bound is `text`: a blank payload is refused"
    );
    assert!(
        decode_legacy_packet_quality("   ").is_err(),
        "a whitespace-only payload is blank and refused before any parse"
    );
    assert!(
        decode_legacy_packet_quality("{\"goal_coverage\":true}\u{0}").is_err(),
        "the boundary's real bound is `text`: a payload carrying a control character is refused"
    );
    let message = decode_error("{\"goal_coverage\":true}").to_string();
    assert!(
        !message.is_empty() && message.len() < 200,
        "the rejection is a typed bounded ContextError, never a payload echo"
    );
    Ok(())
}

// Fails if: a current type trial-decodes the legacy eight-Boolean payload, or
// the donor starts routing an old Boolean through untyped JSON.
// WORK_UNIT_CASE: 868/15
#[test]
fn no_current_trial_decoding_of_legacy() -> TestResult {
    assert!(serde_json::from_str::<QualityScorecard>(LEGACY_FIXTURE).is_err());
    assert!(serde_json::from_str::<QualityDimensionResult>(LEGACY_FIXTURE).is_err());
    assert!(serde_json::from_str::<QualityDimensionState>(LEGACY_FIXTURE).is_err());
    let mut hybrid = current_json()?;
    {
        let results = hybrid
            .get_mut("results")
            .ok_or("current fixture must carry results")?;
        let serde_json::Value::Array(array) = results else {
            return Err("results must be a JSON array".into());
        };
        let first = array
            .first_mut()
            .ok_or("current fixture must carry twelve results")?;
        let serde_json::Value::Object(object) = first else {
            return Err("each result must be a JSON object".into());
        };
        if object.remove("state").is_none() {
            return Err("current fixture result must carry `state`".into());
        }
        object.insert("goal_coverage".to_owned(), serde_json::Value::Bool(true));
    }
    assert!(
        serde_json::from_value::<QualityScorecard>(serde_json::Value::Object(hybrid)).is_err(),
        "a legacy Boolean grafted onto a current result must be refused"
    );
    assert!(
        !code_without_comments_and_strings(LIB_SOURCE).contains("serde_json::Value"),
        "no untyped JSON may stand in for a field-level contract"
    );
    Ok(())
}

// Fails if: the legacy Booleans stop resolving their own original bounded
// computation, or the conversion starts consuming them as evidence.
// WORK_UNIT_CASE: 868/16
#[test]
fn old_boolean_retains_actual_evidence_resolution() -> TestResult {
    let fixture = legacy_record()?;
    let truthy = legacy_with([true, true, true, true, true, true, true, false]);
    let falsy = legacy_with([false, false, false, false, false, false, false, true]);
    assert_ne!(
        truthy, falsy,
        "the legacy Booleans are unchanged and still independently observable"
    );
    assert_eq!(
        serde_json::to_string(&truthy)?,
        "{\"goal_coverage\":true,\"epistemic_coverage\":true,\"provenance_coverage\":true,\
         \"fence_coherent\":true,\"uncertainty_visible\":true,\"safety_coverage\":true,\
         \"decision_readiness\":true,\"bounded_omission\":false}"
    );
    assert!(legacy_with([true; 8]).goal_coverage);
    assert!(!legacy_with([false; 8]).safety_coverage);
    assert!(!legacy_with([false; 8]).decision_readiness);
    let card = current_card()?;
    for record in [truthy, falsy, fixture] {
        let results = converted(&card, &record)?;
        assert_eq!(results.len(), QUALITY_DIMENSIONS.len());
        for result in &results {
            assert!(
                result
                    .unknown_evidence
                    .contains(&artifact(MISSING_EVIDENCE)?),
                "the caller-supplied gap handle is the only evidence reference the conversion uses"
            );
            assert!(
                result.evidence.is_empty(),
                "a legacy Boolean is not evidence and must never enter `evidence`"
            );
        }
    }
    Ok(())
}

// Fails if: an ambiguous or unsupported legacy value manufactures a definite
// grade, so that a schema-1 `true` or `false` becomes a `Passed` or `Failed`.
// WORK_UNIT_CASE: 868/17
#[test]
fn ambiguous_mapping_cannot_invent_a_grade() -> TestResult {
    let card = current_card()?;
    let patterns = [
        legacy_with([true; 8]),
        legacy_with([false; 8]),
        legacy_with([true, false, true, false, true, false, true, false]),
        legacy_record()?,
    ];
    let mut baseline: Vec<QualityDimensionState> = Vec::new();
    let mut first_run = true;
    for record in &patterns {
        let results = converted(&card, record)?;
        let states: Vec<QualityDimensionState> =
            results.iter().map(|result| result.state.clone()).collect();
        if first_run {
            baseline = states;
            first_run = false;
        } else {
            assert_eq!(
                states, baseline,
                "the legacy Boolean value must not change any returned grade"
            );
        }
        for (index, result) in results.iter().enumerate() {
            assert_eq!(
                result.state,
                QualityDimensionState::Unknown,
                "dimension {index} is never graded from a legacy Boolean"
            );
            assert_eq!(result.rule_revision, artifact(RULE_REVISION)?);
            assert_eq!(result.binding, card.binding);
            assert!(
                result
                    .unknown_evidence
                    .contains(&artifact(MISSING_EVIDENCE)?),
                "the ambiguous mapping stays unknown instead of resolving into a grade"
            );
        }
    }
    Ok(())
}

// Fails if: a current-only dimension with no legacy producer resolves to a pass,
// or if an unresolved applicability input is hidden behind a diagnostic display.
// WORK_UNIT_CASE: 868/18
#[test]
fn current_only_field_without_evidence_remains_unknown() -> TestResult {
    let current_only: Vec<QualityDimension> = LEGACY_DIMENSION_DISPOSITIONS
        .iter()
        .filter(|row| row.legacy_fields.is_empty())
        .map(|row| row.dimension)
        .collect();
    assert!(
        !current_only.is_empty(),
        "at least one A-15 dimension is current-only and has no legacy producer"
    );
    let card = current_card()?;
    let results = converted(&card, &legacy_with([true; 8]))?;
    for dimension in &current_only {
        let index = canonical_index(*dimension);
        assert_eq!(
            results[index].state,
            QualityDimensionState::Unknown,
            "{dimension:?} has no legacy producer and stays unknown even when every legacy Boolean \
             is true"
        );
    }
    let mut unresolved = current_card()?;
    unresolved
        .applicability
        .resolved
        .retain(|input| *input != QualityApplicabilityInput::GovernanceProfile);
    unresolved
        .applicability
        .unknown
        .push(QualityApplicabilityInput::GovernanceProfile);
    unresolved.validate()?;
    assert_eq!(
        unresolved.applicability.unresolved(),
        vec![QualityApplicabilityInput::GovernanceProfile]
    );
    assert!(matches!(
        unresolved.suitability(QualityOperation::DependentAction, &[]),
        Err(QualityRefusal {
            kind: QualityRefusalKind::ApplicabilityUnknown,
            unresolved_applicability,
            ..
        }) if unresolved_applicability == vec![QualityApplicabilityInput::GovernanceProfile]
    ));
    let display: QualitySuitability =
        match unresolved.suitability(QualityOperation::DiagnosticDisplay, &[]) {
            Ok(suitability) => suitability,
            Err(refusal) => {
                return Err(format!(
                    "read-only display must stay available and report the unresolved input, got \
                     {refusal:?}"
                )
                .into());
            }
        };
    assert_eq!(
        display.unresolved_applicability,
        vec![QualityApplicabilityInput::GovernanceProfile],
        "read-only display stays available with the unresolved input still reported"
    );
    Ok(())
}

// Fails if: component equality stops being field-exact and deterministic, or a
// component change stops making two otherwise identical cards unequal.
// WORK_UNIT_CASE: 868/19
#[test]
fn canonical_component_equality_is_deterministic() -> TestResult {
    let card = current_card()?;
    assert_eq!(card, current_card()?);
    assert_eq!(
        serde_json::to_string(&card)?,
        serde_json::to_string(&current_card()?)?
    );
    let round: QualityScorecard = serde_json::from_str(&serde_json::to_string(&card)?)?;
    assert_eq!(
        round, card,
        "canonical identity survives the wire unchanged"
    );
    let index = canonical_index(QualityDimension::VerifierActionReadiness);
    let mut changed_rule = current_card()?;
    changed_rule.results[index].rule_revision = artifact("rule:868:other")?;
    assert_ne!(changed_rule, card, "the rule revision is part of identity");
    let mut changed_evidence = current_card()?;
    let _ = changed_evidence.results[index].evidence.pop();
    assert_ne!(
        changed_evidence, card,
        "observed evidence is part of identity"
    );
    let mut changed_measurement = current_card()?;
    changed_measurement.results[index].measurements = vec![MeasurementRef {
        digest: digest('b'),
        serializer: "eliot-context-test:1.0.0".to_owned(),
    }];
    assert_ne!(
        changed_measurement, card,
        "measurement state is part of identity"
    );
    let mut changed_output = current_card()?;
    changed_output.output.rendered_digest = digest('c');
    assert_ne!(
        changed_output, card,
        "the graded output binding is part of identity"
    );
    let mut reordered = current_card()?;
    reordered.results.swap(index, index + 1);
    assert_ne!(
        reordered, card,
        "component order is part of canonical identity"
    );
    assert_eq!(
        reordered.validate(),
        Err(ContractContextError::QualityIncomplete)
    );
    Ok(())
}

// Card row 20 verbatim: "better/worse only for comparable dimensions".
// Card DEFER verbatim: "If cases 20/21 are meant as real partial-order
// comparisons rather than no-compensation guards, that contract must be added to
// A-15 by its own owner first - and A-15 is already CLOSED." A-15 exposes no
// `better`/`worse`/`partial_cmp`/rank/scalar API, so this case proves the same
// property on A-15's real surface instead of inventing an ordering.
// Fails if: `QualityScorecard::suitability` starts compensating one required
// dimension against a stronger observation in another dimension of the same card.
// WORK_UNIT_CASE: 868/20
#[test]
fn no_cross_dimension_compensation_on_a15_surface() -> TestResult {
    let card = current_card()?;
    let required: Vec<QualityDimension> = QualityOperation::DependentAction
        .required_dimensions()
        .to_vec();
    let refusal: QualityRefusal = match card.suitability(QualityOperation::DependentAction, &[]) {
        Ok(suitability) => panic!(
            "a required dimension that is not an observed pass must refuse, got {suitability:?}"
        ),
        Err(refusal) => refusal,
    };
    assert_eq!(refusal.kind, QualityRefusalKind::OperationBlocked);
    assert_eq!(refusal.operation, QualityOperation::DependentAction);
    let blocking: BTreeSet<QualityDimension> = refusal
        .blocking
        .iter()
        .map(|result| result.dimension)
        .collect();
    assert!(
        !blocking.is_empty(),
        "at least one required dimension is not a current pass on this card"
    );
    assert!(
        required
            .iter()
            .any(|dimension| card.results[canonical_index(*dimension)].is_current_pass()),
        "a different required dimension in the SAME card is a fully observed pass, so \
         cross-dimension compensation was available and must not be applied"
    );
    for dimension in required.iter().copied() {
        let result = &card.results[canonical_index(dimension)];
        assert_eq!(
            blocking.contains(&dimension),
            !result.is_current_pass(),
            "{dimension:?} blocks exactly when it is not a current pass"
        );
    }
    assert_eq!(refusal.blocking.len(), blocking.len());
    assert!(
        refusal
            .blocking
            .iter()
            .all(|result| !result.is_current_pass()),
        "the refusal names blocking results, never an aggregate or a compensated verdict"
    );
    // The same blocking dimension refuses while another required dimension of the
    // same card stays an observed pass: there is no trade to make.
    let mut blocked = current_card()?;
    let blocked_dimension = QualityDimension::VerifierActionReadiness;
    set_state(
        &mut blocked,
        blocked_dimension,
        QualityDimensionState::Unknown,
    )?;
    blocked.validate()?;
    let second: QualityRefusal = match blocked.suitability(QualityOperation::DependentAction, &[]) {
        Ok(suitability) => panic!("the blocked card must refuse, got {suitability:?}"),
        Err(refusal) => refusal,
    };
    assert_eq!(second.kind, QualityRefusalKind::OperationBlocked);
    assert!(
        second
            .blocking
            .iter()
            .any(|result| result.dimension == blocked_dimension)
    );
    let strongest = canonical_index(QualityDimension::ExactAnchorProvenanceCoverage);
    assert!(
        blocked.results[strongest].is_current_pass(),
        "ExactAnchorProvenanceCoverage stays an observed pass and still rescues nothing"
    );
    assert!(
        !card.all_pass()?,
        "the card is not a better card; it is a refused card"
    );
    assert!(
        card.suitability(QualityOperation::DiagnosticDisplay, &[])
            .is_ok(),
        "read-only display stays available with every blocking result visible"
    );
    Ok(())
}

// Card row 21 verbatim: "trade-offs remain incomparable".
// Card DEFER verbatim: "If cases 20/21 are meant as real partial-order
// comparisons rather than no-compensation guards, that contract must be added to
// A-15 by its own owner first - and A-15 is already CLOSED." Two cards each
// failing a different dimension are asserted as two refusals for the same
// operation, never ordered against each other.
// Fails if: a card blocking one operation can be made to satisfy a different one,
// if the per-operation required sets drift, or if A-15 gains an ordering API that
// this deferral premise no longer covers.
// WORK_UNIT_CASE: 868/21
#[test]
fn two_trade_off_cards_both_refuse_the_same_operation() -> TestResult {
    let left_only = QualityDimension::ExactAnchorProvenanceCoverage;
    let right_only = QualityDimension::VerifierActionReadiness;
    let mut left = current_card()?;
    set_state(&mut left, left_only, QualityDimensionState::Failed)?;
    left.validate()?;
    let mut right = current_card()?;
    set_state(&mut right, right_only, QualityDimensionState::Failed)?;
    right.validate()?;
    let left_refusal: QualityRefusal =
        match left.suitability(QualityOperation::DependentAction, &[]) {
            Ok(suitability) => panic!("the left card must refuse, got {suitability:?}"),
            Err(refusal) => refusal,
        };
    let right_refusal: QualityRefusal =
        match right.suitability(QualityOperation::DependentAction, &[]) {
            Ok(suitability) => panic!("the right card must refuse, got {suitability:?}"),
            Err(refusal) => refusal,
        };
    assert_eq!(left_refusal.kind, QualityRefusalKind::OperationBlocked);
    assert_eq!(right_refusal.kind, QualityRefusalKind::OperationBlocked);
    assert_eq!(left_refusal.operation, right_refusal.operation);
    let left_blocking: BTreeSet<QualityDimension> = left_refusal
        .blocking
        .iter()
        .map(|result| result.dimension)
        .collect();
    let right_blocking: BTreeSet<QualityDimension> = right_refusal
        .blocking
        .iter()
        .map(|result| result.dimension)
        .collect();
    assert!(left_blocking.contains(&left_only));
    assert!(right_blocking.contains(&right_only));
    assert!(
        !right_blocking.contains(&left_only),
        "the left card's own failure is absent from the right card"
    );
    assert!(
        !left_blocking.contains(&right_only),
        "the right card's own failure is absent from the left card"
    );
    assert!(
        !left_blocking.is_subset(&right_blocking) || !right_blocking.is_subset(&left_blocking),
        "neither blocking set contains the other, so neither card can be ordered above the other; \
         A-15 offers no `better`/`worse` symbol that could say so"
    );
    assert!(!left.all_pass()? && !right.all_pass()?);
    assert!(
        left_refusal != right_refusal,
        "the two refusals are distinct and are not collapsible into one verdict"
    );
    assert!(
        QualityOperation::DiagnosticDisplay
            .required_dimensions()
            .is_empty()
    );
    assert_eq!(
        QualityOperation::Compile.required_dimensions().len(),
        QUALITY_DIMENSIONS.len()
    );
    assert_eq!(
        QualityOperation::DependentAction.required_dimensions(),
        &[
            QualityDimension::ExactAnchorProvenanceCoverage,
            QualityDimension::InstructionSufficiency,
            QualityDimension::VerifierActionReadiness,
        ]
    );
    for absent in [
        "partial_cmp",
        "fn better(",
        "fn worse(",
        "fn incomparable(",
        "fn total(",
        "fn rank(",
        "fn score(",
    ] {
        assert!(
            !A15_QUALITY_SOURCE.contains(absent),
            "A-15 has no ordering API: a real partial order must be added to A-15 by its own owner \
             first, and cases 20/21 must then be re-routed instead of guessed here: {absent}"
        );
    }
    Ok(())
}

// Card row 22 verbatim: "failed/unknown mandatory dimension cannot be
// compensated".
// Card DEFER verbatim: "If cases 20/21 are meant as real partial-order
// comparisons rather than no-compensation guards, that contract must be added to
// A-15 by its own owner first - and A-15 is already CLOSED." Same A-15 surface.
// Fails if: a mandatory `Failed` or `Unknown` result becomes compensable, or if
// `additional_required` ever removes a constraint instead of only adding one.
// WORK_UNIT_CASE: 868/22
#[test]
fn failed_and_unknown_mandatory_dimensions_cannot_be_compensated() -> TestResult {
    let mandatory = QualityDimension::VerifierActionReadiness;
    let extra = QualityDimension::PayloadHandleReconstructionCost;
    let mut failed = current_card()?;
    set_state(&mut failed, mandatory, QualityDimensionState::Failed)?;
    failed.validate()?;
    let mut unknown = current_card()?;
    set_state(&mut unknown, mandatory, QualityDimensionState::Unknown)?;
    unknown.validate()?;
    for (label, card) in [("failed", &failed), ("unknown", &unknown)] {
        let refusal = match card.suitability(QualityOperation::DependentAction, &[]) {
            Ok(suitability) => {
                panic!("a {label} mandatory dimension must refuse, got {suitability:?}")
            }
            Err(refusal) => refusal,
        };
        assert_eq!(
            refusal.kind,
            QualityRefusalKind::OperationBlocked,
            "{label}"
        );
        let blocking: BTreeSet<QualityDimension> = refusal
            .blocking
            .iter()
            .map(|result| result.dimension)
            .collect();
        assert!(
            blocking.contains(&mandatory),
            "{label}: the mandatory dimension blocks"
        );
        let index = canonical_index(mandatory);
        assert!(
            !card.results[index].is_current_pass(),
            "{label}: the mandatory dimension is not a current pass"
        );
        let observed = canonical_index(QualityDimension::ExactAnchorProvenanceCoverage);
        assert!(
            card.results[observed].is_current_pass(),
            "{label}: ExactAnchorProvenanceCoverage is an observed pass in the same card and still \
             compensates nothing"
        );
        assert!(!card.all_pass()?, "{label}");
    }
    assert!(
        matches!(
            failed.suitability(QualityOperation::DependentAction, &[extra]),
            Err(QualityRefusal { .. })
        ),
        "additional_required can only add a constraint, never remove the mandatory block"
    );
    let mut extra_blocked = current_card()?;
    set_state(&mut extra_blocked, extra, QualityDimensionState::Unknown)?;
    extra_blocked.validate()?;
    assert!(
        extra_blocked
            .suitability(QualityOperation::DiagnosticDisplay, &[])
            .is_ok(),
        "no dimension is mandatory for read-only display"
    );
    assert!(
        matches!(
            extra_blocked.suitability(QualityOperation::DiagnosticDisplay, &[extra]),
            Err(QualityRefusal {
                kind: QualityRefusalKind::OperationBlocked,
                ..
            })
        ),
        "additional_required adds exactly the constraint the caller selected"
    );
    Ok(())
}

// Fails if: candidate/admitted/rendered membership, whole atoms,
// source/provenance/taint, recipe or measurement state changes across the
// migration, or if the eight-boolean producer stops computing what it computed.
// WORK_UNIT_CASE: 868/23
#[test]
fn candidate_admitted_rendered_membership_and_measurement_unchanged() -> TestResult {
    let goal = goal_atom("atom:868:goal")?;
    let input = revisioned_input(vec![goal.clone()])?;
    let rendered = ContextCompiler::compile(&input, &budgeted_recipe(10)?)?;
    let again = ContextCompiler::compile(&input, &budgeted_recipe(10)?)?;
    assert_eq!(
        rendered, again,
        "compilation stays deterministic and stateless"
    );
    assert_eq!(
        rendered.units,
        vec![goal.clone()],
        "the whole atom is admitted intact"
    );
    assert!(
        rendered.handle_only.is_empty(),
        "nothing is dropped for boundedness"
    );
    assert!(rendered.unknowns.is_empty(), "nothing new became unknown");
    assert_eq!(
        rendered.quality,
        legacy_with([true, false, true, true, false, false, false, false]),
        "the eight-boolean producer keeps its exact original computation"
    );
    assert_eq!(
        rendered.admissions.len(),
        1,
        "candidate membership is unchanged"
    );
    assert_eq!(rendered.admissions[0].atom_id, goal.atom_id);
    assert_eq!(
        rendered.admissions[0].disposition,
        AdmissionDisposition::Included
    );
    assert!(rendered.admissions[0].protected);
    assert_eq!(rendered.revision, TaskRevision::new(1)?);
    assert_eq!(rendered.state_fence, input.state_fence);
    assert_eq!(
        serde_json::to_string(&rendered.units)?,
        serde_json::to_string(std::slice::from_ref(&goal))?,
        "source/provenance/taint and the whole atom survive byte for byte"
    );
    let bounded = ContextCompiler::compile(&input, &budgeted_recipe(0)?)?;
    assert!(
        bounded.units.is_empty(),
        "a zero budget yields no whole unit"
    );
    assert_eq!(bounded.handle_only, vec![goal.atom_id.clone()]);
    assert_eq!(
        bounded.admissions[0].disposition,
        AdmissionDisposition::HandleOnly
    );
    assert_eq!(
        bounded.quality,
        // `goal_coverage` is false here because the frozen producer computes it
        // from the emitted `units`, and a zero budget emits none. The atom
        // survives as a handle, not as a whole unit, so no role is covered.
        legacy_with([false, false, true, true, true, false, false, true]),
        "the omission producer keeps its exact original computation"
    );
    assert!(
        !bounded.unknowns.is_empty(),
        "bounded omission stays visible"
    );
    let mut card = current_card()?;
    let index = canonical_index(QualityDimension::PayloadHandleReconstructionCost);
    card.results[index].measurements = vec![MeasurementRef {
        digest: digest('d'),
        serializer: "eliot-context-test:1.0.0".to_owned(),
    }];
    let round: QualityScorecard = serde_json::from_str(&serde_json::to_string(&card)?)?;
    assert_eq!(
        round, card,
        "recipe and measurement state survive byte for byte"
    );
    Ok(())
}

// Fails if: the migration inflates a proof ceiling, adds a scalar or a copied
// A-15 algorithm, loosens the bounded malformed-input behaviour, or leaves the
// A-15 dependency preparation to an unowned future lock step.
// WORK_UNIT_CASE: 868/24
#[test]
fn bounded_guard_rejects_inflation_and_verifies_preparation_readiness() -> TestResult {
    let card = current_card()?;
    for result in converted(&card, &legacy_with([true; 8]))? {
        assert_eq!(
            serde_json::to_value(result.proof_ceiling)?,
            serde_json::Value::String(NEUTRAL_PROOF_CEILING.to_owned()),
            "a legacy Boolean may only carry the weakest proof ceiling"
        );
        assert!(
            result.measurements.is_empty(),
            "no measurement may be invented"
        );
        assert_eq!(result.invalidation, None);
    }
    let code = code_without_comments_and_strings(LIB_SOURCE);
    for copied in [
        "fn required_dimensions(",
        "fn from_resolutions(",
        "fn all_pass(",
        "fn is_current_pass(",
        "fn validate_digest(",
        "fn canonical_output_digest(",
    ] {
        assert!(
            !code.contains(copied),
            "no copied A-15 algorithm may live in the donor: {copied}"
        );
    }
    for inflated in [
        "SCOPED_VERIFICATION",
        "OBSERVED_EXTERNAL_EFFECT",
        "CANDIDATE_ARTIFACT",
    ] {
        assert!(
            !code.contains(inflated),
            "the migration must not name a stronger proof ceiling: {inflated}"
        );
    }
    let declared = declared_scorecard_structs(&code);
    assert_eq!(
        declared,
        vec!["PacketQualityScorecard"],
        "there is exactly one Scorecard-named public type in the donor"
    );
    assert!(
        MANIFEST.contains(
            "eliot-context-contracts = { path = \"../eliot-context-contracts\", version = \"0.1.0\" }"
        ),
        "the exact A-15 dependency preparation is present now, not deferred to a future step"
    );
    let section = WORKSPACE_LOCK
        .split("name = \"eliot-context\"")
        .nth(1)
        .ok_or("lock must contain the exact eliot-context entry")?;
    let section = section
        .split("\n\n")
        .next()
        .ok_or("lock entry must terminate")?;
    assert!(
        section.contains("\"eliot-context-contracts\","),
        "the lock must already resolve the A-15 edge under eliot-context"
    );
    for malformed in [
        "",
        "{",
        "{\"goal_coverage\":true,\"bounded_omission\":}",
        "null",
        "{\"goal_coverage\":\"true\"}",
    ] {
        assert!(
            decode_legacy_packet_quality(malformed).is_err(),
            "bounded malformed-input behaviour must stay closed"
        );
    }
    let first = converted(&card, &legacy_record()?)?;
    let second = converted(&current_card()?, &legacy_record()?)?;
    assert_eq!(
        serde_json::to_string(&first)?,
        serde_json::to_string(&second)?,
        "the conversion is a pure deterministic projection"
    );
    assert_eq!(APPLICABILITY_WIRE.len(), QUALITY_APPLICABILITY_INPUTS.len());
    for (index, input) in QUALITY_APPLICABILITY_INPUTS.into_iter().enumerate() {
        assert_eq!(
            serde_json::to_value(input)?,
            serde_json::Value::String(APPLICABILITY_WIRE[index].to_owned()),
            "the six applicability inputs keep their exact identities"
        );
    }
    Ok(())
}
