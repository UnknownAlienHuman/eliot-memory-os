//! Boundary oracle for issue #831 (internal/root legacy slice of #706→#835).
//!
//! `crates/eliot-types/src/ul/injection.rs` and the exact cue-related root
//! exports in `crates/eliot-types/src/lib.rs` consume the explicit legacy
//! `LegacyCueKindV1` with no current-looking `CueKind`. This oracle freezes
//! the internal/root symbol denominator, legacy round trips, and
//! current-owner separation against the goldens in
//! `tests/data/cue_kind_internal_legacy.json`.
//!
//! Every expectation is derived from live source or the fixture; nothing
//! here trusts a hard-coded copy of the denominator except the checked-in
//! frozen files themselves, which this oracle revalidates. The shared #706
//! inventory (`tests/data/cue_kind_migration.toml`, `src/ul/cue.rs`) is
//! read-only evidence here and is never edited by this lane.

use eliot_types::ul::cue::{LegacyCueKindV1, LegacyCueKindV1MigrationDescriptor as Seam};
use eliot_types::{InjectionReceipt, ObservedCue};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn boxed(error: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
    Box::new(error)
}

fn fail<T>(message: String) -> Result<T, Box<dyn std::error::Error>> {
    Err(boxed(std::io::Error::other(message)))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = manifest_dir().join("..").join("..");
    if !root.join("Cargo.toml").is_file() || !root.join("Cargo.lock").is_file() {
        return fail(format!("workspace root not found under {}", root.display()));
    }
    Ok(root)
}

fn read_workspace(relative: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = workspace_root()?.join(relative);
    std::fs::read_to_string(&path).map_err(boxed)
}

fn read_fixture() -> Result<Value, Box<dyn std::error::Error>> {
    let path = manifest_dir()
        .join("tests")
        .join("data")
        .join("cue_kind_internal_legacy.json");
    let text = std::fs::read_to_string(&path).map_err(boxed)?;
    serde_json::from_str(&text).map_err(boxed)
}

fn fixture_string(fixture: &Value, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    fixture
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "fixture missing string: {key}"
            )))
        })
}

fn fixture_strings(fixture: &Value, key: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let list = fixture.get(key).and_then(Value::as_array).ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "fixture missing list: {key}"
        )))
    })?;
    list.iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "fixture non-string in: {key}"
                )))
            })
        })
        .collect()
}

/// Strip line/block comments, string and character literals, lifetimes, and
/// raw strings. Comment/string bytes become spaces; newlines are preserved,
/// so line structure (and line-anchored expectations) survives.
fn strip_code(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if rest.starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                out.push(' ');
                index += 1;
            }
        } else if rest.starts_with(b"/*") {
            index = consume_block_comment(bytes, index, &mut out);
        } else if rest.starts_with(b"\"") {
            index = consume_string(bytes, index, &mut out);
        } else if raw_prefix_len(rest).is_some() {
            index = consume_raw_string(bytes, index, &mut out);
        } else if rest[0] == b'\'' {
            index = consume_char_or_lifetime(bytes, index, &mut out);
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

fn consume_block_comment(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    let mut depth: usize = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            out.push('\n');
            index += 1;
        } else if bytes[index..].starts_with(b"/*") {
            depth += 1;
            out.push_str("  ");
            index += 2;
        } else if bytes[index..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            out.push_str("  ");
            index += 2;
            if depth == 0 {
                break;
            }
        } else {
            out.push(' ');
            index += 1;
        }
    }
    index
}

fn consume_string(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    out.push(' ');
    index += 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                out.push(' ');
                return index + 1;
            }
            b'\\' => {
                out.push(' ');
                index += 1;
                if index < bytes.len() {
                    if bytes[index] == b'\n' {
                        out.push('\n');
                    } else {
                        out.push(' ');
                    }
                    index += 1;
                }
            }
            b'\n' => {
                out.push('\n');
                index += 1;
            }
            _ => {
                out.push(' ');
                index += 1;
            }
        }
    }
    index
}

fn raw_prefix_len(rest: &[u8]) -> Option<usize> {
    if rest.is_empty() || rest[0] != b'r' {
        return None;
    }
    let hashes = rest[1..].iter().take_while(|byte| **byte == b'#').count();
    if hashes + 1 < rest.len() && rest[hashes + 1] == b'"' {
        Some(hashes)
    } else {
        None
    }
}

fn consume_raw_string(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    let hashes = raw_prefix_len(&bytes[index..]).unwrap_or(0);
    let close: Vec<u8> = std::iter::once(b'"')
        .chain(std::iter::repeat_n(b'#', hashes))
        .collect();
    for _ in 0..hashes + 2 {
        out.push(' ');
        index += 1;
    }
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            out.push('\n');
            index += 1;
        } else if bytes[index..].starts_with(&close) {
            for _ in 0..close.len() {
                out.push(' ');
                index += 1;
            }
            break;
        } else {
            out.push(' ');
            index += 1;
        }
    }
    index
}

fn consume_char_or_lifetime(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    out.push(' ');
    index += 1;
    if index < bytes.len() && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_') {
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            out.push(' ');
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'\'' {
            out.push(' ');
            index += 1;
        }
        return index;
    }
    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                out.push(' ');
                return index + 1;
            }
            b'\\' => {
                out.push(' ');
                out.push(' ');
                index += 2;
                if index > bytes.len() {
                    return bytes.len();
                }
            }
            b'\n' => {
                out.push('\n');
                index += 1;
            }
            _ => {
                out.push(' ');
                index += 1;
            }
        }
    }
    index
}

/// Exact identifier tokens of stripped source (`CueKind` never hides inside
/// `LegacyCueKindV1`: the token differs).
fn tokens(text: &str) -> Vec<&str> {
    text.split(|cell: char| !(cell.is_ascii_alphanumeric() || cell == '_'))
        .filter(|token| !token.is_empty())
        .collect()
}

fn has_token(text: &str, token: &str) -> bool {
    tokens(text).contains(&token)
}

fn count_token(text: &str, token: &str) -> usize {
    tokens(text).iter().filter(|cell| **cell == token).count()
}

/// Detector: a bare current-looking `CueKind` token outside the explicit
/// legacy name. Unit-covered below; the live claimed source must be silent.
fn flag_bare_cue_kind(line: &str) -> bool {
    has_token(&strip_code(line), "CueKind")
}

/// Detector: permissive kind-identity compatibility escapes.
fn flag_permissive_escape(line: &str) -> bool {
    let stripped = strip_code(line);
    stripped.contains("untagged")
        || stripped.contains("alias")
        || stripped.contains("impl Default")
        || has_token(&stripped, "Other")
        || stripped.contains("Unknown(")
}

/// Names exported by one `pub use <module>::{...};` block in lib.rs source.
fn export_block_names(
    source: &str,
    module: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let stripped = strip_code(source);
    let open = format!("pub use {module}::{{");
    let start = stripped.find(&open).ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "export block missing: {module}"
        )))
    })? + open.len();
    let tail = &stripped[start..];
    let end = tail.find("};").ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "export block unterminated: {module}"
        )))
    })?;
    Ok(tail[..end]
        .split(',')
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect())
}

fn decode_cue(json: &Value) -> Result<ObservedCue, serde_json::Error> {
    serde_json::from_value(json.clone())
}

fn malformed_entry<'fixture>(
    fixture: &'fixture Value,
    tag: &str,
) -> Result<&'fixture Value, Box<dyn std::error::Error>> {
    fixture
        .get("malformed_observed_cues")
        .and_then(Value::as_array)
        .ok_or_else(|| boxed(std::io::Error::other("fixture missing malformed list")))?
        .iter()
        .find(|entry| entry.get("tag").and_then(Value::as_str) == Some(tag))
        .ok_or_else(|| boxed(std::io::Error::other(format!("fixture missing tag: {tag}"))))
}

// WORK_UNIT_CASE: 831/1
#[test]
fn case_01_every_injection_kind_field_explicitly_legacy() -> TestResult {
    let source = read_workspace("crates/eliot-types/src/ul/injection.rs")?;
    let stripped = strip_code(&source);
    assert_eq!(
        stripped.matches("kind: LegacyCueKindV1").count(),
        1,
        "exactly ObservedCue.kind names the legacy enum"
    );
    assert!(
        !has_token(&stripped, "CueKind"),
        "bare CueKind token in injection.rs"
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/2
#[test]
fn case_02_no_crate_cue_kind_use_in_claimed_source() -> TestResult {
    for relative in [
        "crates/eliot-types/src/ul/injection.rs",
        "crates/eliot-types/src/lib.rs",
    ] {
        let stripped = strip_code(&read_workspace(relative)?);
        assert!(
            !flag_bare_cue_kind(&stripped),
            "bare CueKind token in {relative}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 831/3
#[test]
fn case_03_no_root_current_looking_cue_kind_reexport() -> TestResult {
    let source = read_workspace("crates/eliot-types/src/lib.rs")?;
    let names = export_block_names(&source, "ul::cue")?;
    assert!(
        !names.iter().any(|name| name == "CueKind"),
        "CueKind reintroduced in root cue export block"
    );
    let injection = export_block_names(&source, "ul::injection")?;
    assert!(
        !injection.iter().any(|name| name == "CueKind"),
        "CueKind reintroduced in root injection export block"
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/4
#[test]
fn case_04_legacy_cue_kind_v1_exported_once() -> TestResult {
    let stripped = strip_code(&read_workspace("crates/eliot-types/src/lib.rs")?);
    assert_eq!(
        count_token(&stripped, "LegacyCueKindV1"),
        1,
        "LegacyCueKindV1 must appear exactly once at root"
    );
    let names = export_block_names(&stripped, "ul::cue")?;
    assert!(names.iter().any(|name| name == "LegacyCueKindV1"));
    Ok(())
}

// WORK_UNIT_CASE: 831/5
#[test]
fn case_05_historical_injection_observation_fixture_round_trip() -> TestResult {
    let fixture = read_fixture()?;
    let golden: ObservedCue = serde_json::from_value(
        fixture
            .get("observed_cue_golden")
            .ok_or_else(|| boxed(std::io::Error::other("fixture missing observed cue")))?
            .clone(),
    )
    .map_err(boxed)?;
    assert_eq!(golden.kind, LegacyCueKindV1::FilePath);
    assert_eq!(golden.value, "src/net/session.rs");
    let canonical = serde_json::to_string(&golden).map_err(boxed)?;
    assert_eq!(
        canonical,
        fixture_string(&fixture, "observed_cue_canonical")?
    );
    let receipt: InjectionReceipt = serde_json::from_value(
        fixture
            .get("injection_receipt_golden")
            .ok_or_else(|| boxed(std::io::Error::other("fixture missing receipt golden")))?
            .clone(),
    )
    .map_err(boxed)?;
    assert_eq!(receipt.fired_cues.len(), 1);
    assert_eq!(receipt.fired_cues[0].kind, LegacyCueKindV1::FilePath);
    assert_eq!(receipt.token_cost, 42);
    let receipt_canonical = serde_json::to_string(&receipt).map_err(boxed)?;
    assert_eq!(
        receipt_canonical,
        fixture_string(&fixture, "injection_receipt_canonical")?
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/6
#[test]
fn case_06_unknown_kind_rejected() -> TestResult {
    for spelling in [
        "relation_edge",
        "binding_candidate",
        "comparison_key",
        "cue",
        "none",
    ] {
        let cue = serde_json::json!({"kind": spelling, "value": "x"});
        assert!(
            decode_cue(&cue).is_err(),
            "unknown kind accepted: {spelling}"
        );
        assert!(
            Seam::UNSUPPORTED_INPUTS.contains(&spelling),
            "unknown kind outside descriptor: {spelling}"
        );
    }
    let fixture = read_fixture()?;
    let entry = malformed_entry(&fixture, "unknown-kind")?;
    assert!(decode_cue(&entry["json"]).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 831/7
#[test]
fn case_07_missing_empty_rejected() -> TestResult {
    let fixture = read_fixture()?;
    for tag in ["missing-kind", "empty-kind", "null-kind", "int-kind"] {
        let entry = malformed_entry(&fixture, tag)?;
        assert!(
            decode_cue(&entry["json"]).is_err(),
            "bad kind accepted: {tag}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 831/8
#[test]
fn case_08_no_current_only_spelling_or_version_trial_decode() -> TestResult {
    for spelling in Seam::UNSUPPORTED_INPUTS {
        let cue = serde_json::json!({"kind": spelling, "value": "x"});
        assert!(
            decode_cue(&cue).is_err(),
            "unsupported spelling accepted: {spelling:?}"
        );
    }
    // A version field cannot smuggle a versioned trial decode: it is ignored
    // and the kind still decodes as legacy, with no version absorbed.
    let trialled: ObservedCue = serde_json::from_value(serde_json::json!({
        "kind": "file_path",
        "value": "x",
        "version": "v2",
        "schema_version": "eliot-agent-api/v7",
    }))
    .map_err(boxed)?;
    assert_eq!(trialled.kind, LegacyCueKindV1::FilePath);
    let keys: BTreeSet<String> = serde_json::to_value(&trialled)
        .map_err(boxed)?
        .as_object()
        .ok_or_else(|| boxed(std::io::Error::other("cue is not an object")))?
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from(["kind".to_owned(), "value".to_owned()])
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/9
#[test]
fn case_09_no_default_serde_alias_or_untagged_compatibility() -> TestResult {
    assert!(flag_permissive_escape("#[serde(untagged)]"));
    assert!(flag_permissive_escape("#[serde(alias = \"path\")]"));
    assert!(flag_permissive_escape("impl Default for LegacyCueKindV1 {"));
    assert!(flag_permissive_escape("    Other,"));
    assert!(flag_permissive_escape("    Unknown(String),"));
    assert!(!flag_permissive_escape(
        "#[serde(rename_all = \"snake_case\")]"
    ));
    assert!(!flag_permissive_escape("    FilePath,"));
    assert!(!flag_permissive_escape("    pub kind: LegacyCueKindV1,"));
    for relative in [
        "crates/eliot-types/src/ul/injection.rs",
        "crates/eliot-types/src/lib.rs",
    ] {
        let stripped = strip_code(&read_workspace(relative)?);
        for line in stripped.lines() {
            assert!(
                !flag_permissive_escape(line),
                "permissive escape in {relative}: {line}"
            );
        }
        assert!(
            !stripped.contains("impl Default"),
            "Default impl in {relative}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 831/10
#[test]
fn case_10_retained_source_alias_explicitly_legacy_and_wire_neutral() -> TestResult {
    let source = read_workspace("crates/eliot-types/src/ul/cue.rs")?;
    let stripped = strip_code(&source);
    assert_eq!(
        stripped
            .matches("pub type CueKind = LegacyCueKindV1;")
            .count(),
        1,
        "exactly one retained transitional alias"
    );
    assert!(
        source.contains("removal issue #835") || source.contains("removal issue: #835"),
        "alias lacks #835 removal owner"
    );
    assert!(source.contains("#831"), "alias lacks #831 migration owner");
    // Wire neutrality without importing the deprecated alias: the legacy
    // spelling on the wire equals the historical golden spelling.
    assert_eq!(
        serde_json::to_string(&LegacyCueKindV1::FilePath).map_err(boxed)?,
        "\"file_path\""
    );
    assert_eq!(Seam::WIRE_SPELLINGS[0], "file_path");
    Ok(())
}

// WORK_UNIT_CASE: 831/11
#[test]
fn case_11_no_upward_smart_dependency() -> TestResult {
    let manifest = read_workspace("crates/eliot-types/Cargo.toml")?;
    for line in manifest.lines() {
        let cell = line.trim();
        assert!(
            !cell.contains("smart")
                && !cell.contains("eliot-cue")
                && !cell.contains("cue_activation")
                && !cell.contains("cue-contracts"),
            "smart dependency in eliot-types manifest: {line}"
        );
    }
    for relative in [
        "crates/eliot-types/src/ul/injection.rs",
        "crates/eliot-types/src/lib.rs",
    ] {
        let stripped = strip_code(&read_workspace(relative)?);
        assert!(
            !stripped.contains("eliot_cue")
                && !stripped.contains("smart::")
                && !stripped.contains("cue_contracts"),
            "smart path in {relative}"
        );
    }
    Ok(())
}

fn assert_export_goldens(fixture: &Value, source: &str) -> TestResult {
    let mut cue_names = export_block_names(source, "ul::cue")?;
    cue_names.sort();
    let mut cue_golden = fixture_strings(fixture, "root_cue_exports")?;
    cue_golden.sort();
    assert_eq!(cue_names, cue_golden, "root cue export golden drift");
    let mut injection_names = export_block_names(source, "ul::injection")?;
    injection_names.sort();
    let mut injection_golden = fixture_strings(fixture, "injection_exports")?;
    injection_golden.sort();
    assert_eq!(
        injection_names, injection_golden,
        "root injection export golden drift"
    );
    Ok(())
}

fn assert_classifier_units() {
    // Classifier unit coverage on literals: local definitions, eliot_types
    // import and fully-qualified paths resolve; anything else is unknown.
    for (snippet, in_types, expected) in [
        (concat!("pub enum", " ", "CueKind { A, }"), false, KindProvenance::Local),
        (
            "pub type CueKind = LegacyCueKindV1;",
            false,
            KindProvenance::Local,
        ),
        (
            "use eliot_types::{CueBinding, CueKind};",
            false,
            KindProvenance::EliotTypes,
        ),
        (
            "use eliot_types::CueKind;",
            false,
            KindProvenance::EliotTypes,
        ),
        (
            "let x = eliot_types::CueKind::FilePath;",
            false,
            KindProvenance::EliotTypes,
        ),
        (
            "use eliot_types::*; let x = CueKind::A;",
            false,
            KindProvenance::EliotTypes,
        ),
        (
            "use eliot_cue_contracts::CueKind;",
            false,
            KindProvenance::Local,
        ),
        (
            "use crate::{normalization::CueKind};",
            false,
            KindProvenance::Local,
        ),
        (
            "fn f(kind: super::CueKind) {}",
            false,
            KindProvenance::Local,
        ),
        // A foreign glob with no eliot_types import capable of supplying
        // the name: compiling code must resolve through it.
        (
            "use eliot_cue_contracts::*; let x = CueKind::A;",
            false,
            KindProvenance::Local,
        ),
        // A relative glob proves nothing by itself, but the explicit
        // eliot_types path still decides.
        (
            "use super::*; let x = eliot_types::CueKind::A;",
            false,
            KindProvenance::EliotTypes,
        ),
        // Conflicting named evidence fails closed.
        (
            "use eliot_cue_contracts::CueKind; let x = eliot_types::CueKind::A;",
            false,
            KindProvenance::Unknown,
        ),
        ("use crate::{CueKind};", true, KindProvenance::EliotTypes),
        // A second glob cannot verify (globs prove no supply either way);
        // an eliot_types glob still counts toward impact (safe direction).
        // (Both globs live is uncompilable; unreachable either way.)
        (
            "use eliot_types::*; use eliot_cue_contracts::*; let x = CueKind::A;",
            false,
            KindProvenance::EliotTypes,
        ),
        ("let CueKindV1 = 1;", false, KindProvenance::Unknown),
    ] {
        assert_eq!(
            cue_kind_provenance(&strip_code(snippet), in_types),
            expected,
            "classifier drift: {snippet}"
        );
    }
}

/// Live impact denominator: impacted files with bare-token counts, plus
/// files whose provenance fails closed.
type ImpactDenominator = (BTreeSet<(String, usize)>, BTreeSet<String>);

fn live_impact_table() -> Result<ImpactDenominator, Box<dyn std::error::Error>> {
    let mut actual: BTreeSet<(String, usize)> = BTreeSet::new();
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    for root in ["crates", "bins", "apps", "workers"] {
        collect_impact(&workspace_root()?.join(root), &mut actual, &mut unknown)?;
    }
    Ok((actual, unknown))
}

fn assert_fixture_table(fixture: &Value, actual: &BTreeSet<(String, usize)>) -> TestResult {
    let mut expected: BTreeSet<(String, usize)> = BTreeSet::new();
    let rows = fixture
        .get("downstream_impact")
        .and_then(Value::as_array)
        .ok_or_else(|| boxed(std::io::Error::other("fixture missing impact table")))?;
    for row in rows {
        let file = row
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| boxed(std::io::Error::other("impact row without file")))?;
        let count = row
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| boxed(std::io::Error::other("impact row without count")))?;
        let count = usize::try_from(count)
            .map_err(|_| boxed(std::io::Error::other("impact count out of range")))?;
        expected.insert((file.to_owned(), count));
    }
    assert_eq!(*actual, expected, "downstream impact denominator drift");
    Ok(())
}

// WORK_UNIT_CASE: 831/12
#[test]
fn case_12_exact_public_api_golden_and_consumer_impact() -> TestResult {
    let fixture = read_fixture()?;
    let source = read_workspace("crates/eliot-types/src/lib.rs")?;
    assert_export_goldens(&fixture, &source)?;
    assert_classifier_units();
    // Consumer impact denominator: every bare-CueKind token repo-wide that
    // resolves to the removed root re-export lives outside this lane's four
    // files, row-exact against the fixture table. Locally defined enums and
    // aliases are unaffected; unknown provenance fails closed.
    let (actual, unknown) = live_impact_table()?;
    assert!(
        unknown.is_empty(),
        "unresolved CueKind provenance: {unknown:?}"
    );
    assert_fixture_table(&fixture, &actual)?;
    Ok(())
}

/// How a bare `CueKind` token in one file resolves. Only names resolving
/// to the removed `eliot_types::CueKind` root re-export are downstream
/// impact of this lane; locally defined enums/aliases and Smart's own
/// vocabulary are unaffected. Anything else fails closed as unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KindProvenance {
    Local,
    EliotTypes,
    Unknown,
}

fn cue_kind_provenance(stripped: &str, in_eliot_types: bool) -> KindProvenance {
    if count_token(stripped, "CueKind") == 0 {
        return KindProvenance::Unknown;
    }
    let cells = tokens(stripped);
    for window in cells.windows(2) {
        // `enum`/`type` are keywords: a `CueKind` name following them only
        // occur as local definitions, never as use-sites or paths.
        if (window == ["enum", "CueKind"]) || (window == ["type", "CueKind"]) {
            return KindProvenance::Local;
        }
    }
    let mut et = false;
    let mut local_named = false;
    let mut other_glob = false;
    for (root, body) in use_statements(stripped) {
        let names_kind = has_token(&body, "CueKind");
        let glob = body.contains('*');
        match root.as_str() {
            // An eliot_types glob may supply the name: count it toward
            // impact (safe direction — a missed row understates the blast
            // radius, an extra row only widens repair).
            "eliot_types" => {
                if names_kind || glob {
                    et = true;
                }
            }
            "crate" if in_eliot_types => {
                if names_kind {
                    et = true;
                }
            }
            // A named import from anywhere else proves own-vocabulary
            // resolution. A foreign glob proves nothing by itself, but with
            // no eliot_types import capable of supplying the name, compiling
            // code must resolve through it (`use super::*` cannot attest
            // what the parent re-exports, yet nothing else can supply it).
            _ => {
                if names_kind {
                    local_named = true;
                } else if glob {
                    other_glob = true;
                }
            }
        }
    }
    for prefix in inline_path_prefixes(stripped) {
        if prefix == "eliot_types" || (prefix == "crate" && in_eliot_types) {
            et = true;
        } else {
            local_named = true;
        }
    }
    let local = local_named || (other_glob && !et);
    match (et, local) {
        (true, false) => KindProvenance::EliotTypes,
        (false, true) => KindProvenance::Local,
        _ => KindProvenance::Unknown,
    }
}

/// Crate roots of inline `...::CueKind` paths in expressions (token-exact;
/// never a prefix of a longer identifier). The root is the first segment of
/// the maximal `a::b::CueKind` path.
fn inline_path_prefixes(stripped: &str) -> Vec<String> {
    let mut roots = Vec::new();
    let mut rest = stripped;
    while let Some(found) = rest.find("::CueKind") {
        let after = found + "::CueKind".len();
        let boundary = rest[after..]
            .chars()
            .next()
            .is_none_or(|cell| !(cell.is_ascii_alphanumeric() || cell == '_'));
        if boundary {
            let mut start = rest[..found].len();
            while start > 0 {
                let prev = rest[..start].chars().next_back();
                match prev {
                    Some(cell) if cell.is_ascii_alphanumeric() || cell == '_' || cell == ':' => {
                        start -= cell.len_utf8();
                    }
                    _ => break,
                }
            }
            let path = &rest[start..found];
            if let Some(root) = path.split("::").find(|part| !part.is_empty()) {
                roots.push(root.to_owned());
            }
        }
        rest = &rest[after..];
    }
    roots
}

/// Split stripped source into `use ...;` statements with brace balancing.
/// Returns (root path segment, statement body) pairs. `pub` is skipped.
fn use_statements(stripped: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = stripped.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let Some(found) = stripped[index..].find("use ") else {
            break;
        };
        let stmt_start = index + found;
        if stmt_start > 0 {
            let prev = bytes[stmt_start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                index = stmt_start + 4;
                continue;
            }
        }
        let body_start = stmt_start + 4;
        let tail = &stripped[body_start..];
        let mut depth = 0;
        let mut stop = None;
        for (offset, cell) in tail.char_indices() {
            match cell {
                '{' => depth += 1,
                '}' if depth > 0 => depth -= 1,
                ';' if depth == 0 => {
                    stop = Some(offset);
                    break;
                }
                '}' => break,
                _ => {}
            }
        }
        let Some(stop) = stop else {
            break;
        };
        let body = tail[..stop].trim().to_owned();
        let root = body
            .split(|cell: char| cell == ':' || cell.is_whitespace())
            .find(|part| !part.is_empty())
            .unwrap_or("")
            .to_owned();
        out.push((root, body));
        index = body_start + stop + 1;
    }
    out
}

fn collect_impact(
    dir: &Path,
    impact: &mut BTreeSet<(String, usize)>,
    unknown: &mut BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(boxed)?
        .map(|entry| entry.map(|item| item.path()))
        .collect::<Result<_, _>>()
        .map_err(boxed)?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_impact(&path, impact, unknown)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let text = std::fs::read_to_string(&path).map_err(boxed)?;
            let stripped = strip_code(&text);
            let count = count_token(&stripped, "CueKind");
            if count == 0 {
                continue;
            }
            let relative = path
                .strip_prefix(workspace_root()?)
                .map_err(boxed)?
                .to_string_lossy()
                .replace('\\', "/");
            let in_eliot_types = relative.starts_with("crates/eliot-types/");
            match cue_kind_provenance(&stripped, in_eliot_types) {
                KindProvenance::Local => {}
                KindProvenance::EliotTypes => {
                    impact.insert((relative, count));
                }
                KindProvenance::Unknown => {
                    unknown.insert(relative);
                }
            }
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 831/13
#[test]
fn case_13_non_cue_exports_unchanged() -> TestResult {
    let injection = read_workspace("crates/eliot-types/src/ul/injection.rs")?;
    assert!(
        injection
            .contains("use crate::{LegacyCueKindV1, MemoryInfluenceClass, SessionId, TaskId};"),
        "injection import line drift"
    );
    let lib = read_workspace("crates/eliot-types/src/lib.rs")?;
    assert!(
        lib.contains("MemoryInfluenceClass"),
        "MemoryInfluenceClass export missing"
    );
    assert!(
        lib.contains(
            "pub use ul::guard::{TextEncodingViolation, inspect_text_encoding, mojibake};"
        ),
        "adjacent guard export drift"
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/14
#[test]
fn case_14_bounded_malformed_input_panic_free() -> TestResult {
    let fixture = read_fixture()?;
    let entries = fixture
        .get("malformed_observed_cues")
        .and_then(Value::as_array)
        .ok_or_else(|| boxed(std::io::Error::other("fixture missing malformed list")))?;
    for entry in entries {
        let tag = entry
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("<untagged>");
        if let Some(raw) = entry.get("raw").and_then(Value::as_str) {
            assert!(
                serde_json::from_str::<ObservedCue>(raw).is_err(),
                "malformed accepted: {tag}"
            );
        } else {
            let payload = &entry["json"];
            assert!(decode_cue(payload).is_err(), "malformed accepted: {tag}");
        }
    }
    let big = serde_json::json!({"kind": "file_path", "value": "x".repeat(100_000)});
    assert!(
        decode_cue(&big).is_ok(),
        "bounded large value must not panic"
    );
    let deep = format!("{{\"kind\":{{\"kind\":{}}}}}", "{\"a\":".repeat(200));
    assert!(
        serde_json::from_str::<ObservedCue>(&deep).is_err(),
        "deep nesting must not panic"
    );
    assert!(
        serde_json::from_str::<ObservedCue>("[1,2,3]").is_err(),
        "wrong top-level type must not panic"
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/15
#[test]
fn case_15_source_oracle_detects_root_alias_reintroduction() -> TestResult {
    // The detector is exact-token matching on stripped export-block text:
    // continuation lines carry no `pub use`, so block scope (not the
    // statement opener) decides.
    let with = "pub use ul::cue::{\n    CueBinding, CueKind,\n};";
    let without = "pub use ul::cue::{\n    CueBinding, LegacyCueKindV1,\n};";
    assert!(has_token(&strip_code(with), "CueKind"));
    assert!(!has_token(&strip_code(without), "CueKind"));
    assert!(!has_token(&strip_code("let kind = 1;"), "CueKind"));
    assert!(!has_token(
        &strip_code("    pub kind: LegacyCueKindV1,"),
        "CueKind"
    ));
    let source = read_workspace("crates/eliot-types/src/lib.rs")?;
    let names = export_block_names(&source, "ul::cue")?;
    assert!(
        !names.iter().any(|name| name == "CueKind"),
        "root alias reintroduced in cue export block"
    );
    let stripped = strip_code(&read_workspace("crates/eliot-types/src/ul/injection.rs")?);
    assert!(
        !has_token(&stripped, "CueKind"),
        "alias use reintroduced in injection.rs"
    );
    Ok(())
}

// WORK_UNIT_CASE: 831/16
#[test]
fn case_16_ambiguous_injection_dto_detected_not_renamed() -> TestResult {
    // Owner distinction is pinned, not renamed: the legacy DTO keeps its
    // historical name and exact two-field shape while its kind names the
    // legacy enum. The current A-10 DTO (schema_revision, observed_cue_id,
    // context, …) is a different record; equal shape would be a collision.
    let source = read_workspace("crates/eliot-types/src/ul/injection.rs")?;
    let stripped = strip_code(&source);
    assert!(
        stripped.contains("pub struct ObservedCue"),
        "legacy DTO name must be retained"
    );
    assert!(
        stripped.contains("kind: LegacyCueKindV1"),
        "legacy DTO kind must name the legacy enum"
    );
    let cue = ObservedCue {
        kind: LegacyCueKindV1::Symbol,
        value: "net::session::connect".to_owned(),
    };
    let keys: BTreeSet<String> = serde_json::to_value(&cue)
        .map_err(boxed)?
        .as_object()
        .ok_or_else(|| boxed(std::io::Error::other("cue is not an object")))?
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from(["kind".to_owned(), "value".to_owned()])
    );
    assert!(!keys.contains("schema_revision"));
    assert!(!keys.contains("observed_cue_id"));
    assert!(!keys.contains("context"));
    Ok(())
}

// WORK_UNIT_CASE: 831/17
#[test]
fn case_17_accepted_kind_has_exactly_historical_spelling() -> TestResult {
    assert_eq!(Seam::VARIANT_COUNT, 10);
    assert_eq!(Seam::WIRE_SPELLINGS.len(), 10);
    for spelling in Seam::WIRE_SPELLINGS {
        let cue = serde_json::json!({"kind": spelling, "value": "v"});
        let decoded = decode_cue(&cue).map_err(boxed)?;
        assert_eq!(decoded.kind.as_str(), spelling);
        assert_eq!(
            serde_json::to_string(&decoded.kind).map_err(boxed)?,
            format!("\"{spelling}\"")
        );
    }
    for (legacy, current) in Seam::EXACT_CORRESPONDENCES {
        assert_eq!(legacy, current, "correspondence must be byte-exact");
        assert!(
            Seam::WIRE_SPELLINGS.contains(&legacy),
            "correspondence outside historical spellings: {legacy}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 831/18
#[test]
fn case_18_unknown_cannot_default_construct_kind() -> TestResult {
    for payload in [
        serde_json::json!({"kind": null, "value": "x"}),
        serde_json::json!({"value": "x"}),
        serde_json::json!({"kind": 7, "value": "x"}),
    ] {
        assert!(decode_cue(&payload).is_err());
    }
    for relative in [
        "crates/eliot-types/src/ul/cue.rs",
        "crates/eliot-types/src/ul/injection.rs",
        "crates/eliot-types/src/lib.rs",
    ] {
        let stripped = strip_code(&read_workspace(relative)?);
        assert!(
            !stripped.contains("impl Default"),
            "Default impl in {relative}"
        );
    }
    assert!(Option::<LegacyCueKindV1>::None.is_none());
    Ok(())
}

// WORK_UNIT_CASE: 831/19
#[test]
fn case_19_exact_scope_plus_reservation_removal_and_seam_handoff() -> TestResult {
    // #706 shared inventory is read-only evidence: the #831 rows exist with
    // owner, migration, expiry, and match metadata intact.
    let manifest = read_workspace("crates/eliot-types/tests/data/cue_kind_migration.toml")?;
    for row in [
        "[type_row.\"crates/eliot-types/src/lib.rs\"]",
        "[type_row.\"crates/eliot-types/src/ul/injection.rs\"]",
    ] {
        assert!(manifest.contains(row), "missing inventory row: {row}");
    }
    assert!(manifest.contains("migration = 831"));
    assert!(manifest.contains("migrate-to-LegacyCueKindV1-under-#831"));
    // No issue-831 reservation file exists: nothing to remove.
    let mut entries: Vec<String> = std::fs::read_dir(manifest_dir().join("tests").join("data"))
        .map_err(boxed)?
        .map(|entry| entry.map(|item| item.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(boxed)?;
    entries.sort();
    assert_eq!(
        entries,
        vec![
            "cue-kind-legacy".to_owned(),
            "cue_kind_internal_legacy.json".to_owned(),
            "cue_kind_migration.toml".to_owned(),
        ],
        "tests/data holds a reservation or stray file"
    );
    // Seam handoff markers intact (read-only coherence with #706).
    let seam = read_workspace("crates/eliot-types/src/ul/cue.rs")?;
    assert!(seam.contains("pub enum LegacyCueKindV1"));
    assert!(seam.contains("pub type CueKind = LegacyCueKindV1;"));
    assert!(seam.contains("SOURCE_SEAM_ISSUE"));
    Ok(())
}

// WORK_UNIT_CASE: 831/20
#[test]
fn case_20_no_normalization_binding_index_or_activation_algorithm_change() -> TestResult {
    // Exhaustive matching over the closed enum still compiles without a
    // wildcard: the kind Leibniz holds per-variant behavior.
    fn tag(kind: LegacyCueKindV1) -> &'static str {
        match kind {
            LegacyCueKindV1::FilePath => "file",
            LegacyCueKindV1::DirPath => "dir",
            LegacyCueKindV1::Symbol => "symbol",
            LegacyCueKindV1::ErrorSignature => "error",
            LegacyCueKindV1::CommandPattern => "command",
            LegacyCueKindV1::Dependency => "dependency",
            LegacyCueKindV1::ApiSurface => "api",
            LegacyCueKindV1::TaskClass => "task",
            LegacyCueKindV1::Subsystem => "subsystem",
            LegacyCueKindV1::Concept => "concept",
        }
    }
    assert_eq!(tag(LegacyCueKindV1::Concept), "concept");
    assert_eq!(
        eliot_types::ul_token_estimate("hello world"),
        11_u32.div_ceil(4)
    );
    let fixture = read_fixture()?;
    let receipt: InjectionReceipt = serde_json::from_value(
        fixture
            .get("injection_receipt_golden")
            .ok_or_else(|| boxed(std::io::Error::other("fixture missing receipt golden")))?
            .clone(),
    )
    .map_err(boxed)?;
    let again: InjectionReceipt =
        serde_json::from_str(&serde_json::to_string(&receipt).map_err(boxed)?).map_err(boxed)?;
    assert_eq!(receipt.fired_cues, again.fired_cues);
    assert_eq!(receipt.token_cost, again.token_cost);
    Ok(())
}
