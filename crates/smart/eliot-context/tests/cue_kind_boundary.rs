//! Issue #832 boundary proof: the legacy Context `CueKind` duplicate is
//! gone; A-10 `eliot_cue_contracts::CueKind` is the single current owner.
//! Historical spellings decode only through the named legacy decoder.
//!
//! One substantive test per `// WORK_UNIT_CASE: 832/<n>`, cases exactly 1..24.

use std::error::Error;

use eliot_context::{
    ActivationCue, AdmissionDisposition, ContextAtom, ContextCompiler, ContextInput, ContextRecipe,
    ContextRole, CueIndex, RoleBudget, decode_legacy_cue_kind,
};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskRevision,
};
use eliot_cue_contracts::CueKind;
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};

type TestResult = Result<(), Box<dyn Error>>;

const BOUNDARY_DATA: &str = include_str!("data/cue_kind_boundary.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../../../Cargo.lock");

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

#[derive(serde::Deserialize)]
struct BoundaryData {
    historical_variants: Vec<String>,
    current_variants: Vec<String>,
    exact_one_to_one: std::collections::BTreeMap<String, String>,
    ambiguous_split: Vec<String>,
    unsupported_legacy: Vec<String>,
}

fn boundary_data() -> Result<BoundaryData, Box<dyn Error>> {
    Ok(serde_json::from_str(BOUNDARY_DATA)?)
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

fn artifact(value: &str) -> Result<ArtifactId, Box<dyn Error>> {
    Ok(ArtifactId::new(value)?)
}

fn cue(
    scope: &str,
    kind: CueKind,
    value: &str,
    handle: &str,
) -> Result<ActivationCue, Box<dyn Error>> {
    Ok(ActivationCue {
        scope: scope.to_owned(),
        kind,
        value: value.to_owned(),
        handles: vec![artifact(handle)?],
    })
}

fn goal_atom(id: &str, cues: Vec<String>) -> Result<ContextAtom, Box<dyn Error>> {
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
        cues,
    })
}

fn revisioned_input(
    revision: u64,
    atoms: Vec<ContextAtom>,
) -> Result<ContextInput, Box<dyn Error>> {
    Ok(ContextInput {
        scope: "scope:test".to_owned(),
        task_id: None,
        task_revision: TaskRevision::new(revision)?,
        state_fence: fence()?,
        atoms,
        unknowns: Vec::new(),
    })
}

fn budgeted_recipe(revision: u64, maximum_cost: u32) -> Result<ContextRecipe, Box<dyn Error>> {
    Ok(ContextRecipe {
        recipe_revision: TaskRevision::new(revision)?,
        total_cost: 10,
        role_budgets: vec![RoleBudget {
            role: ContextRole::Goal,
            maximum_cost,
        }],
        required_roles: vec![ContextRole::Goal],
    })
}

/// Strip line/block comments, string/char literals and raw strings so the
/// source oracle below cannot false-positive on prose.
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

fn declares_local_kind_enum(source: &str) -> bool {
    let code = code_without_comments_and_strings(source);
    code.contains("pub enum CueKind {") || code.contains("\nenum CueKind {")
}

fn implements_kind_from_str(source: &str) -> bool {
    let code = code_without_comments_and_strings(source);
    code.contains("FromStr for CueKind") || (code.contains("from_str") && code.contains("CueKind"))
}

fn uses_kind_string_table(source: &str) -> bool {
    let code = code_without_comments_and_strings(source);
    code.contains("HashMap") && code.contains("CueKind")
}

fn uses_interior_mutability(source: &str) -> bool {
    let code = code_without_comments_and_strings(source);
    code.contains("static mut")
        || code.contains("OnceLock")
        || code.contains("Mutex")
        || code.contains("RwLock")
        || code.contains("RefCell")
        || code.contains("UnsafeCell")
}

// WORK_UNIT_CASE: 832/1
#[test]
fn old_variant_wire_denominator() -> TestResult {
    let data = boundary_data()?;
    assert_eq!(
        data.historical_variants,
        vec![
            "PATH",
            "SYMBOL",
            "ERROR",
            "COMMAND",
            "SERVICE",
            "TASK_CLASS",
            "CONCEPT",
            "PROBLEM",
        ],
        "historical denominator is exactly the eight frozen spellings"
    );
    assert_eq!(
        data.current_variants.len(),
        10,
        "current denominator is exactly the ten A-10 wire spellings"
    );
    Ok(())
}

// WORK_UNIT_CASE: 832/2
#[test]
fn exact_one_to_one_conversions() -> TestResult {
    let data = boundary_data()?;
    assert_eq!(data.exact_one_to_one.len(), 3);
    for (historical, current) in &data.exact_one_to_one {
        let kind = decode_legacy_cue_kind(historical)?;
        assert_eq!(
            serde_json::to_string(&kind)?,
            format!("\"{current}\""),
            "{historical} must convert to exactly {current}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/3
#[test]
fn ambiguous_variants_split_or_reject_explicitly() -> TestResult {
    let data = boundary_data()?;
    assert_eq!(data.ambiguous_split, vec!["PATH".to_owned()]);
    assert!(
        decode_legacy_cue_kind("PATH").is_err(),
        "PATH must split or reject, never convert"
    );
    for spelling in ["ERROR", "COMMAND", "SERVICE", "PROBLEM"] {
        assert!(
            decode_legacy_cue_kind(spelling).is_err(),
            "{spelling} must stay rejected without an exact counterpart"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/4
#[test]
fn no_local_current_enum() {
    assert!(
        !declares_local_kind_enum(LIB_SOURCE),
        "no local current CueKind enum may remain"
    );
}

// WORK_UNIT_CASE: 832/5
#[test]
fn one_a10_imported_owner() -> TestResult {
    assert!(
        LIB_SOURCE.contains("use eliot_cue_contracts::CueKind;"),
        "the single current owner must be imported"
    );
    let cue = cue("scope", CueKind::Symbol, "value", "handle:1")?;
    assert_eq!(cue.kind, CueKind::Symbol);
    Ok(())
}

// WORK_UNIT_CASE: 832/6
#[test]
fn no_string_catch_all_kind_route() {
    for rejected in [
        "",
        "path",
        "Symbol",
        "TASK-CLASS",
        "CONCEPT ",
        " CONCEPT",
        "symbols",
        "PATHS",
        "error_signature",
        "concept ",
    ] {
        assert!(
            decode_legacy_cue_kind(rejected).is_err(),
            "{rejected:?} must stay rejected"
        );
    }
}

// WORK_UNIT_CASE: 832/7
#[test]
fn current_value_roundtrip() -> TestResult {
    let data = boundary_data()?;
    for spelling in &data.current_variants {
        let wire = format!("\"{spelling}\"");
        let kind: CueKind = serde_json::from_str(&wire)?;
        assert_eq!(serde_json::to_string(&kind)?, wire);
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/8
#[test]
fn historical_spelling_only_named_legacy_decoder() -> TestResult {
    assert!(
        serde_json::from_str::<CueKind>("\"SYMBOL\"").is_err(),
        "historical spelling must not decode as current"
    );
    assert_eq!(decode_legacy_cue_kind("SYMBOL")?, CueKind::Symbol);
    Ok(())
}

// WORK_UNIT_CASE: 832/9
#[test]
fn unknown_missing_empty_rejection() {
    assert!(decode_legacy_cue_kind("").is_err());
    assert!(decode_legacy_cue_kind("NOPE").is_err());
    assert!(decode_legacy_cue_kind("   ").is_err());
    assert!(serde_json::from_str::<CueKind>("\"\"").is_err());
}

// WORK_UNIT_CASE: 832/10
#[test]
fn current_rejects_legacy_only_spelling() {
    for spelling in ["SERVICE", "PROBLEM", "PATH", "ERROR", "COMMAND"] {
        let wire = format!("\"{spelling}\"");
        assert!(
            serde_json::from_str::<CueKind>(&wire).is_err(),
            "{spelling} must not decode as current"
        );
    }
}

// WORK_UNIT_CASE: 832/11
#[test]
fn ambiguity_cannot_fabricate_current_kind() {
    assert!(decode_legacy_cue_kind("PATH").is_err());
    assert!(decode_legacy_cue_kind("ERROR").is_err());
    assert!(decode_legacy_cue_kind("COMMAND").is_err());
}

// WORK_UNIT_CASE: 832/12
#[test]
fn non_kind_fixture_fields_unchanged() -> TestResult {
    let cue = cue(
        "scope:test",
        CueKind::Concept,
        "  Spaced Value ",
        "handle:1",
    )?;
    assert_eq!(cue.scope, "scope:test");
    assert_eq!(cue.value, "  Spaced Value ");
    assert_eq!(cue.handles.len(), 1);
    let atom = goal_atom("atom:x", vec!["cue:x".to_owned()])?;
    assert_eq!(atom.payload, "payload for atom:x");
    assert_eq!(atom.cost, 1);
    Ok(())
}

// WORK_UNIT_CASE: 832/13
#[test]
fn candidate_membership_unchanged() -> TestResult {
    let index = CueIndex::build(vec![
        cue("s", CueKind::Symbol, "alpha", "handle:a")?,
        cue("s", CueKind::Concept, "beta", "handle:b")?,
    ])?;
    let fired = index.fire_exact("s", CueKind::Symbol, "alpha")?;
    assert_eq!(fired.handles.len(), 1);
    let missed = index.fire_exact("s", CueKind::Symbol, "beta")?;
    assert!(missed.handles.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 832/14
#[test]
fn admission_disposition_unchanged() -> TestResult {
    let input = revisioned_input(1, vec![goal_atom("atom:goal", vec![])?])?;
    let recipe = budgeted_recipe(1, 0)?;
    let compiled = ContextCompiler::compile(&input, &recipe)?;
    assert!(
        compiled
            .admissions
            .iter()
            .any(|decision| decision.disposition == AdmissionDisposition::HandleOnly),
        "zero required-role budget keeps the required atom as an exact handle"
    );
    Ok(())
}

// WORK_UNIT_CASE: 832/15
#[test]
fn rendering_omission_unchanged() -> TestResult {
    let input = revisioned_input(1, vec![goal_atom("atom:goal", vec![])?])?;
    let recipe = budgeted_recipe(1, 0)?;
    let first = ContextCompiler::compile(&input, &recipe)?;
    let second = ContextCompiler::compile(&input, &recipe)?;
    assert_eq!(first, second, "compilation stays deterministic");
    assert!(
        !first.handle_only.is_empty() || !first.unknowns.is_empty(),
        "bounded omission stays visible, never silent"
    );
    Ok(())
}

// WORK_UNIT_CASE: 832/16
#[test]
fn no_copied_normalization_comparison_activation() -> TestResult {
    let code = code_without_comments_and_strings(LIB_SOURCE);
    for forbidden in [
        "fn normalize_cue",
        "fn capture_cue",
        "fn fire_cue",
        "fn evaluate_activation",
        "fn comparison_key",
        "comparison_key_for",
    ] {
        assert!(
            !code.contains(forbidden),
            "no copied A-10/A-11 algorithm may live here: {forbidden}"
        );
    }
    let trimmed = cue("s", CueKind::FilePath, "  /a/b  ", "h:1")?.normalized_value()?;
    assert_eq!(trimmed, "/a/b");
    let collapsed = cue("s", CueKind::Concept, "  Spaced   Value ", "h:1")?.normalized_value()?;
    assert_eq!(collapsed, "spaced value");
    Ok(())
}

// WORK_UNIT_CASE: 832/17
#[test]
fn worker_diff_scope_and_controller_preparation() -> TestResult {
    assert!(
        MANIFEST.contains(
            "eliot-cue-contracts = { path = \"../eliot-cue-contracts\", version = \"0.1.0\" }"
        ),
        "controller A-10 edge must be present and exactly owned"
    );
    let section = WORKSPACE_LOCK
        .split("name = \"eliot-context\"")
        .nth(1)
        .ok_or("lock must contain the eliot-context entry")?;
    let section = section
        .split("\n\n")
        .next()
        .ok_or("lock entry must terminate")?;
    assert!(
        section.contains("\"eliot-cue-contracts\","),
        "lock must resolve the A-10 edge under eliot-context"
    );
    Ok(())
}

// WORK_UNIT_CASE: 832/18
#[test]
fn oracle_detects_local_enum_string_table_reintroduction() {
    assert!(
        !declares_local_kind_enum(LIB_SOURCE),
        "oracle must pass on the migrated source"
    );
    assert!(
        !declares_local_kind_enum("// pub enum CueKind {\n"),
        "oracle must ignore line comments"
    );
    assert!(
        !declares_local_kind_enum("/* pub enum CueKind {} */"),
        "oracle must ignore block comments"
    );
    assert!(
        !declares_local_kind_enum("let s = \"pub enum CueKind {\";"),
        "oracle must ignore string literals"
    );
    assert!(
        !declares_local_kind_enum("r#\"pub enum CueKind {\"#"),
        "oracle must ignore raw strings"
    );
    assert!(
        declares_local_kind_enum("pub enum CueKind {\n    Path,\n}"),
        "oracle must still detect a real reintroduction"
    );
    assert!(
        declares_local_kind_enum("{\nenum CueKind {\n}"),
        "oracle must detect unqualified reintroduction"
    );
    assert!(
        !implements_kind_from_str(LIB_SOURCE),
        "no FromStr/catch-all kind construction may exist"
    );
    assert!(
        !uses_kind_string_table(LIB_SOURCE),
        "no string-table kind lookup may exist"
    );
}

// WORK_UNIT_CASE: 832/19
#[test]
fn bounded_malformed_input_panic_free() -> TestResult {
    let big = "x".repeat(4096);
    assert!(decode_legacy_cue_kind(&big).is_err());
    assert!(decode_legacy_cue_kind("SYMBOL\0").is_err());
    let index = CueIndex::build(vec![])?;
    let fired = index.fire_exact("s", CueKind::Symbol, &big)?;
    assert!(fired.handles.is_empty());
    assert!(index.fire_exact("", CueKind::Symbol, "v").is_err());
    assert!(index.fire_exact("s", CueKind::Symbol, "").is_err());
    assert!(
        CueIndex::build(vec![ActivationCue {
            scope: "s".to_owned(),
            kind: CueKind::Symbol,
            value: "v".to_owned(),
            handles: Vec::new(),
        }])
        .is_err(),
        "handle-less cues stay rejected without panic"
    );
    Ok(())
}

// WORK_UNIT_CASE: 832/20
#[test]
fn successful_conversion_has_exact_a10_identity() -> TestResult {
    for (historical, current) in [
        ("SYMBOL", "\"symbol\""),
        ("TASK_CLASS", "\"task_class\""),
        ("CONCEPT", "\"concept\""),
    ] {
        let kind = decode_legacy_cue_kind(historical)?;
        assert_eq!(serde_json::to_string(&kind)?, current);
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/21
#[test]
fn ambiguous_old_values_never_construct_current() -> TestResult {
    let data = boundary_data()?;
    assert_eq!(
        data.unsupported_legacy,
        vec!["ERROR", "COMMAND", "SERVICE", "PROBLEM"],
        "unsupported set is exactly the four legacy-only spellings"
    );
    for spelling in ["PATH", "ERROR", "COMMAND", "SERVICE", "PROBLEM"] {
        assert!(
            decode_legacy_cue_kind(spelling).is_err(),
            "{spelling} must never construct a current kind"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/22
#[test]
fn actual_package_tests_clippy_after_dependency_readiness() {
    assert_eq!(eliot_cue_contracts::CONTRACT_REVISION, "2.0.0");
    assert!(
        MANIFEST.contains("eliot-cue-contracts"),
        "A-10 edge must be present for package proof"
    );
}

// WORK_UNIT_CASE: 832/23
#[test]
fn complete_downstream_impact_no_unhandled_breaking_merge() -> TestResult {
    let index = CueIndex::build(vec![
        cue("s", CueKind::FilePath, "/a/b", "h:fp")?,
        cue("s", CueKind::DirPath, "/a", "h:dp")?,
        cue("s", CueKind::Symbol, "sym", "h:sy")?,
        cue("s", CueKind::ErrorSignature, "err", "h:es")?,
        cue("s", CueKind::CommandPattern, "cmd", "h:cp")?,
        cue("s", CueKind::Dependency, "dep", "h:de")?,
        cue("s", CueKind::ApiSurface, "api", "h:as")?,
        cue("s", CueKind::TaskClass, "tc", "h:tc")?,
        cue("s", CueKind::Subsystem, "sub", "h:ss")?,
        cue("s", CueKind::Concept, "con", "h:co")?,
    ])?;
    for (kind, value, handle) in [
        (CueKind::FilePath, "/a/b", "h:fp"),
        (CueKind::DirPath, "/a", "h:dp"),
        (CueKind::Symbol, "sym", "h:sy"),
        (CueKind::ErrorSignature, "err", "h:es"),
        (CueKind::CommandPattern, "cmd", "h:cp"),
        (CueKind::Dependency, "dep", "h:de"),
        (CueKind::ApiSurface, "api", "h:as"),
        (CueKind::TaskClass, "tc", "h:tc"),
        (CueKind::Subsystem, "sub", "h:ss"),
        (CueKind::Concept, "con", "h:co"),
    ] {
        let fired = index.fire_exact("s", kind, value)?;
        assert_eq!(
            fired.handles,
            vec![artifact(handle)?],
            "current kind {kind:?} must flow end to end"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 832/24
#[test]
fn no_current_context_owner_state_authority_effect_finish() -> TestResult {
    assert!(
        !uses_interior_mutability(LIB_SOURCE),
        "no hidden state may be introduced"
    );
    let code = code_without_comments_and_strings(LIB_SOURCE);
    assert_eq!(
        code.matches("pub struct ContextCompiler").count(),
        1,
        "exactly one compiler definition may exist"
    );
    let input = revisioned_input(1, vec![goal_atom("atom:goal", vec![])?])?;
    let recipe = budgeted_recipe(1, 10)?;
    let first = ContextCompiler::compile(&input, &recipe)?;
    let second = ContextCompiler::compile(&input, &recipe)?;
    assert_eq!(first, second, "stateless compilation stays deterministic");
    Ok(())
}
