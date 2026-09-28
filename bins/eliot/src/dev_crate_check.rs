//! Per-crate Instrument Plane verification entrypoint for issue #1913.
//!
//! `eliot dev crate check <package>` resolves the generated
//! `ModuleTestCapsule` for exactly one first-party package out of the checked-in
//! capsule corpus (`docs/code-navigation/capsules/`) and emits one structured
//! receipt. `eliot dev crate dispositions` emits the explicit disposition of
//! every package the corpus reports as unreachable from a binary and every
//! excluded standalone package, so no package is left outside the proof and
//! runtime topology without a recorded verdict.
//!
//! Two rules govern every value here. First, a value is emitted only when the
//! corpus, the repository metadata, or the command input carries it; a value
//! the corpus does not carry is reported as an explicit undeclared state, never
//! as a guess and never as a silent default. Second, workspace membership is
//! not applicability: a package whose capsule declares no proof entrypoint, or
//! whose support ceiling is `CURRENT_UNVERIFIED`, is reported as pending
//! evidence, never as a pass.
//!
//! The receipt's `BuildFingerprint` is the owning
//! `eliot_build_test_graph::BuildFingerprint` type itself, and the receipt
//! reports the verdict of that type's own `validate()`. It is not a JSON object
//! that borrows the field names: every field is read from a checked-in source,
//! and a field no source carries stays empty, is listed in `typed_gaps`, and
//! fails the owning validator instead of being invented.
//!
//! Source of record for dispositions is the #1860 ledger
//! (`docs/migration/1860-dispositions.md`), closed over the I19.3 verb set, and
//! the #1811 excluded-scope rows it mirrors verbatim. The issue names a
//! coarser five-value vocabulary, so `disposition_verb` carries the source verb
//! verbatim next to the mapped `disposition`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use eliot_build_test_graph::{BuildFingerprint, GraphError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Checked-in generated capsule index: the per-package resolution corpus.
const CAPSULE_INDEX: &str = "docs/code-navigation/capsules/index.json";
/// Checked-in workspace manifest: the declared workspace, profile and feature surface.
const WORKSPACE_MANIFEST: &str = "Cargo.toml";
/// Checked-in pinned toolchain file: the declared compiler identity.
const TOOLCHAIN_FILE: &str = "rust-toolchain.toml";
/// The explicit state of a value no checked-in source carries.
const UNDECLARED_STATE: &str = "UNDECLARED";
/// Checked-in #1860 disposition ledger; the source of record for every
/// unreachable-package and excluded-package disposition.
const DISPOSITION_LEDGER: &str = "docs/migration/1860-dispositions.md";
/// The I19.3 disposition verbs the ledger is closed over.
const LEDGER_VERBS: [&str; 7] = [
    "KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN",
];

#[derive(Debug, Subcommand)]
pub(crate) enum DevCommand {
    /// Per-crate Instrument Plane verification surfaces.
    Crate {
        #[command(subcommand)]
        command: CrateCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum CrateCommand {
    /// Resolve the `ModuleTestCapsule` of one package and emit its receipt.
    Check {
        /// First-party Cargo package name to resolve.
        package: String,
        /// Absolute repository root; never inferred from the current directory.
        #[arg(long)]
        repo_root: PathBuf,
    },
    /// Emit the explicit disposition of every unreachable and excluded package.
    Dispositions {
        /// Absolute repository root; never inferred from the current directory.
        #[arg(long)]
        repo_root: PathBuf,
    },
}

#[derive(Debug, Error)]
pub(crate) enum DevCrateCheckError {
    #[error("input invalid: {0}")]
    InvalidInput(String),
    #[error("unknown package: {package}")]
    UnknownPackage { package: String },
    #[error("capsule corpus unreadable at {path}: {detail}")]
    CorpusUnreadable { path: String, detail: String },
    #[error("capsule corpus malformed at {path}: {detail}")]
    CorpusMalformed { path: String, detail: String },
    #[error("disposition ledger unusable at {path}: {detail}")]
    LedgerUnusable { path: String, detail: String },
    #[error("receipt could not be emitted: {detail}")]
    ReceiptEmission { detail: String },
}

impl DevCrateCheckError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => 2,
            Self::UnknownPackage { .. } => 3,
            Self::CorpusUnreadable { .. }
            | Self::CorpusMalformed { .. }
            | Self::LedgerUnusable { .. }
            | Self::ReceiptEmission { .. } => 65,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::UnknownPackage { .. } => "UNKNOWN_PACKAGE",
            Self::CorpusUnreadable { .. } => "CORPUS_UNREADABLE",
            Self::CorpusMalformed { .. } => "CORPUS_MALFORMED",
            Self::LedgerUnusable { .. } => "LEDGER_UNUSABLE",
            Self::ReceiptEmission { .. } => "RECEIPT_EMISSION",
        }
    }

    pub(crate) fn envelope(&self) -> Value {
        json!({
            "status": "error",
            "code": self.code(),
            "detail": self.to_string(),
        })
    }
}

/// The closed disposition vocabulary the issue names, plus the explicit
/// pending state the issue requires when the corpus records no disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Disposition {
    RuntimeOwned,
    ToolOnly,
    IntentionallyDormant,
    Externalized,
    RemovalCandidate,
    /// The corpus records no disposition for this package. Fail-closed, and
    /// never reported as a pass.
    Undispositioned,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeOwned => "runtime-owned",
            Self::ToolOnly => "tool-only",
            Self::IntentionallyDormant => "intentionally dormant",
            Self::Externalized => "externalized",
            Self::RemovalCandidate => "removal candidate",
            Self::Undispositioned => "undispositioned",
        }
    }
}

/// Map one ledger row onto the issue's five-value vocabulary.
///
/// The I19.3 verb is the source of truth and is carried verbatim beside the
/// mapped value, because the issue's vocabulary is strictly coarser than the
/// verb set: `REPLACE`/`RETIRE` are the documented "do not promote" verbs, so
/// they are removal candidates; `WRAP` is a thin adapter over an admitted owner
/// and `EXTRACT` is a role-separation boundary, so in both the owning capability
/// lives outside the package; `REWORK` is the documented prototype verb
/// ("concept valid, contract pending"), so the package is dormant by decision.
/// `KEEP` splits by the ledger's own sub-grouping: instrumentation and
/// workspace tooling is never a production runtime dependency, while an admitted
/// capability cell awaiting production wiring is runtime-owned.
fn disposition_for(verb: &str, group: &str) -> Disposition {
    match (verb, group) {
        ("REPLACE" | "RETIRE", _) => Disposition::RemovalCandidate,
        ("WRAP" | "EXTRACT", _) => Disposition::Externalized,
        ("REWORK", _) => Disposition::IntentionallyDormant,
        ("KEEP", "KEEP_INSTRUMENT" | "KEEP_NAMED_OWNER_TOOL") => Disposition::ToolOnly,
        ("KEEP", "KEEP_ADMITTED_CELL" | "KEEP_NAMED_OWNER") => Disposition::RuntimeOwned,
        _ => Disposition::Undispositioned,
    }
}

fn read_text(path: &Path) -> Result<String, DevCrateCheckError> {
    fs::read_to_string(path).map_err(|error| DevCrateCheckError::CorpusUnreadable {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn read_json(path: &Path) -> Result<Value, DevCrateCheckError> {
    let text = read_text(path)?;
    serde_json::from_str(&text).map_err(|error| DevCrateCheckError::CorpusMalformed {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

fn array<'a>(value: &'a Value, key: &str, path: &Path) -> Result<&'a [Value], DevCrateCheckError> {
    value.get(key).and_then(Value::as_array).map_or_else(
        || {
            Err(DevCrateCheckError::CorpusMalformed {
                path: path.display().to_string(),
                detail: format!("`{key}` is not an array"),
            })
        },
        |items| Ok(items.as_slice()),
    )
}

fn text(value: &Value, key: &str, path: &Path) -> Result<String, DevCrateCheckError> {
    value.get(key).and_then(Value::as_str).map_or_else(
        || {
            Err(DevCrateCheckError::CorpusMalformed {
                path: path.display().to_string(),
                detail: format!("`{key}` is not a string"),
            })
        },
        |item| Ok(item.to_owned()),
    )
}

/// Resolve the target root from the environment Cargo itself uses, stating the
/// rule that produced it. Never inferred from proximity or recency.
fn target_root(repo_root: &Path) -> (PathBuf, &'static str) {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(value) if !value.is_empty() => (PathBuf::from(value), "CARGO_TARGET_DIR"),
        _ => (repo_root.join("target"), "cargo default `target/`"),
    }
}

fn undeclared(fields: &[&str]) -> Value {
    json!({
        "state": UNDECLARED_STATE,
        "origin": "no value for this field is carried by the capsule corpus, the package manifest, or the command input",
        "fields": fields,
    })
}

fn sha256_file(path: &Path) -> Result<String, DevCrateCheckError> {
    let bytes = fs::read(path).map_err(|error| DevCrateCheckError::CorpusUnreadable {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// One resolved ledger row: the verbatim I19.3 verb, the ledger sub-group the
/// row was published under, and the mapped issue vocabulary.
struct LedgerRow {
    package: String,
    verb: &'static str,
    group: String,
    owner: String,
    /// The ledger published this row under its excluded-scope section, so the
    /// package is a standalone excluded crate and not a workspace member that is
    /// merely unreachable from a binary.
    excluded: bool,
}

impl LedgerRow {
    fn parse(
        line: &str,
        heading_verb: Option<&'static str>,
        sub: Option<&'static str>,
        excluded: bool,
    ) -> Option<Self> {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 2 {
            return None;
        }
        let package = cells.get(1)?.trim_matches('`').to_owned();
        if !package.starts_with("eliot") {
            return None;
        }
        let verb = cells
            .iter()
            .find_map(|cell| verb_of(cell.trim_matches('`')))
            .or(heading_verb)?;
        let group = match (heading_verb, sub) {
            (Some("KEEP"), Some(sub)) => sub,
            _ => group_of(verb),
        };
        Some(Self {
            package,
            verb,
            group: group.to_owned(),
            owner: cells.get(2).unwrap_or(&"").trim_matches('`').to_owned(),
            excluded,
        })
    }

    /// A named-owner `KEEP` row is tool-only when the ledger's own row says the
    /// package is workspace tooling or a test-support asset; the remaining
    /// named-owner rows are product-plane or admitted-cell owners.
    fn effective_group(&self) -> &str {
        if self.group != "KEEP_NAMED_OWNER" {
            return &self.group;
        }
        if self.owner.contains("test-support") || self.owner.contains("workspace tooling") {
            "KEEP_NAMED_OWNER_TOOL"
        } else {
            self.group.as_str()
        }
    }
}

fn opt_text(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |item| Value::from(item.clone()))
}

fn verb_of(cell: &str) -> Option<&'static str> {
    LEDGER_VERBS.iter().copied().find(|verb| *verb == cell)
}

fn group_of(verb: &str) -> &'static str {
    match verb {
        "RETIRE" | "REPLACE" => "RETIRE",
        "WRAP" | "EXTRACT" => "WRAP",
        "REWORK" => "REWORK",
        "UNKNOWN" => "UNKNOWN",
        _ => "KEEP",
    }
}

fn is_package_token(token: &str) -> bool {
    token.starts_with("eliot-")
        && token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

/// Parse the #1860 ledger into one row per dispositioned package.
///
/// Table rows carry their verb in a cell or in the `##` heading; the `KEEP`
/// section publishes its packages as prose lists under three named
/// sub-headings, which are the source of the `KEEP` split.
fn parse_ledger(path: &Path) -> Result<BTreeMap<String, LedgerRow>, DevCrateCheckError> {
    let text = fs::read_to_string(path).map_err(|error| DevCrateCheckError::LedgerUnusable {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let mut rows: BTreeMap<String, LedgerRow> = BTreeMap::new();
    let mut heading_verb: Option<&'static str> = None;
    let mut sub: Option<&'static str> = None;
    let mut excluded = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("## ") {
            heading_verb = LEDGER_VERBS
                .iter()
                .copied()
                .find(|verb| heading.starts_with(&format!("{verb} ")));
            excluded = heading.starts_with("Excluded scope");
            sub = None;
            continue;
        }
        if heading_verb == Some("KEEP") {
            if trimmed.starts_with("Instrument-plane support") {
                sub = Some("KEEP_INSTRUMENT");
            } else if trimmed.starts_with("Admitted capability cells awaiting production wiring") {
                sub = Some("KEEP_ADMITTED_CELL");
            } else if trimmed.starts_with("Named-owner KEEP rows") {
                sub = Some("KEEP_NAMED_OWNER");
            }
        }
        if trimmed.starts_with('|') {
            if let Some(row) = LedgerRow::parse(trimmed, heading_verb, sub, excluded) {
                rows.entry(row.package.clone()).or_insert(row);
            }
            continue;
        }
        if heading_verb == Some("KEEP") && sub.is_some() {
            for token in trimmed.split('`').skip(1).step_by(2) {
                if is_package_token(token) {
                    let row = LedgerRow {
                        package: token.to_owned(),
                        verb: "KEEP",
                        group: sub.unwrap_or("KEEP").to_owned(),
                        owner: String::new(),
                        excluded,
                    };
                    rows.entry(row.package.clone()).or_insert(row);
                }
            }
        }
    }
    if rows.is_empty() {
        return Err(DevCrateCheckError::LedgerUnusable {
            path: path.display().to_string(),
            detail: "no dispositioned package row was found".to_owned(),
        });
    }
    Ok(rows)
}

/// Emit an explicit disposition for every package the ledger enumerates.
///
/// The ledger is the closed enumeration of unreachable and excluded packages,
/// so it is the driver: a package the corpus reports as unreachable or excluded
/// but that the ledger omits is still reported, as `undispositioned`, because a
/// package may not fall outside the proof and runtime topology without a
/// recorded verdict. The corpus `reachability` is carried beside each row as
/// the independent corroboration, and its absence is reported rather than
/// defaulted.
fn dispositions(repo_root: &Path) -> Result<Value, DevCrateCheckError> {
    let index_path = repo_root.join(CAPSULE_INDEX);
    let index = read_json(&index_path)?;
    let ledger = parse_ledger(&repo_root.join(DISPOSITION_LEDGER))?;
    let cells = array(&index, "cells", &index_path)?;
    let corpus: BTreeMap<String, String> = cells
        .iter()
        .filter_map(|cell| {
            Some((
                text(cell, "crate", &index_path).ok()?,
                text(cell, "reachability", &index_path).ok()?,
            ))
        })
        .collect();
    // The ledger's excluded-scope section is the only source that separates an
    // excluded standalone package from a workspace member unreachable from a
    // binary; the corpus reachability corroborates but never overrides it.
    let scope_of = |row: &LedgerRow, reachability: Option<&String>| -> &'static str {
        if row.excluded || reachability.is_some_and(|value| value == "EXCLUDED") {
            "excluded"
        } else {
            "unreachable-from-binary"
        }
    };
    let mut entries: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut undisp: Vec<&String> = corpus
        .keys()
        .filter(|package| {
            matches!(
                corpus.get(*package).map(String::as_str),
                Some("UNREACHABLE" | "EXCLUDED")
            ) && !ledger.contains_key(*package)
        })
        .collect();
    undisp.sort();
    for row in ledger.values() {
        let reachability = corpus.get(&row.package);
        let scope = scope_of(row, reachability);
        let disposition = disposition_for(row.verb, row.effective_group());
        *counts
            .entry(format!("{scope} {}", disposition.as_str()))
            .or_default() += 1;
        entries.push(json!({
            "package": row.package,
            "scope": scope,
            "disposition": disposition.as_str(),
            "disposition_verb": row.verb,
            "disposition_group": row.effective_group(),
            "owner": row.owner,
            "corpus_reachability": opt_text(reachability),
            "disposition_source": DISPOSITION_LEDGER,
        }));
    }
    for package in undisp {
        *counts.entry("undispositioned".to_owned()).or_default() += 1;
        entries.push(json!({
            "package": package,
            "scope": "unreachable-from-binary",
            "disposition": Disposition::Undispositioned.as_str(),
            "disposition_verb": Value::Null,
            "disposition_group": Value::Null,
            "owner": Value::Null,
            "corpus_reachability": opt_text(corpus.get(package)),
            "disposition_source": DISPOSITION_LEDGER,
            "note": "The corpus reports this package as unreachable or excluded, but the ledger carries no disposition row for it. It stays fail-closed and is never reported as a pass.",
        }));
    }
    entries.sort_by(|left, right| {
        left.get("package")
            .and_then(Value::as_str)
            .cmp(&right.get("package").and_then(Value::as_str))
    });
    Ok(json!({
        "status": "dispositioned",
        "ledger": DISPOSITION_LEDGER,
        "ledger_rows": ledger.len(),
        "reported": entries.len(),
        "corpus_index": CAPSULE_INDEX,
        "corpus_capability_coverage": index
            .get("capability_coverage")
            .cloned()
            .unwrap_or(Value::Null),
        "counts": counts,
        "dispositions": entries,
    }))
}

/// One `key = value` assignment of a checked-in TOML file, with the table that
/// declares it. Only the shapes a build identity needs are read: a bare key, a
/// quoted string, a boolean, and a bracket-balanced array. A value the reader
/// does not recognise is never guessed at; the field it belongs to stays absent.
struct TomlEntry {
    table: String,
    key: String,
    value: String,
}

/// The feature surface a package manifest declares, in the three forms Cargo
/// resolves a feature selection from.
struct DeclaredFeatures {
    /// Keys of the manifest `[features]` table.
    declared: Vec<String>,
    /// Cargo's implicit features for optional dependencies, which
    /// `--all-features` also selects.
    implicit: Vec<String>,
    /// Members of the `default` feature, which Cargo enables without a flag.
    default: Vec<String>,
}

/// The compiler identity the repository pins in its checked-in toolchain file.
/// A key the file does not declare stays absent: the toolchain that happens to
/// be running is never substituted for a pinned one.
struct PinnedToolchain {
    channel: Option<String>,
    targets: Vec<String>,
    evidence: Value,
}

/// The compilation target of this run, with the checked-in source that stated it.
struct ResolvedTarget {
    value: Option<String>,
    origin: String,
    evidence: Value,
}

/// The package manifest of the checked package, read from the path the corpus records.
struct ResolvedManifest {
    relative: String,
    features: DeclaredFeatures,
    build_script: Option<String>,
    proc_macro: bool,
    /// Digest recomputed from the manifest bytes. It is only ever COMPARED
    /// against the digest the corpus recorded; it never replaces it.
    recomputed: Result<String, String>,
}

/// The corpus-declared proof entrypoint of one package.
///
/// The corpus publishes the exact command it declares as this package's proof
/// entrypoint, so the Cargo build identity that command selects - profile,
/// feature set, governed output class - is read from that command instead of
/// assumed for the package.
struct ProofEntrypoint {
    tokens: Vec<String>,
}

/// The checked-in inputs one package's `BuildFingerprint` is constructed from.
struct FingerprintInputs<'a> {
    /// Absolute repository root: the workspace identity of the fingerprint.
    repo_root: &'a Path,
    cell: &'a Value,
    capsule: &'a Value,
    toolchain: &'a PinnedToolchain,
    target: &'a ResolvedTarget,
    manifest: &'a ResolvedManifest,
    /// The corpus-declared proof entrypoint, when the corpus declares one.
    entrypoint: &'a Option<ProofEntrypoint>,
}

/// Drop a trailing TOML comment, keeping any `#` inside a quoted string.
fn strip_toml_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Net unclosed `[`/`{` count of one line, ignoring brackets inside strings.
fn bracket_delta(line: &str) -> i32 {
    let mut quoted = false;
    let mut delta = 0;
    for character in line.chars() {
        match character {
            '"' => quoted = !quoted,
            '[' | '{' if !quoted => delta += 1,
            ']' | '}' if !quoted => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// Join wrapped declarations into whole logical lines.
///
/// A value spanning several lines (a wrapped array or inline table) is joined
/// until its brackets balance, so a wrapped `targets = [` or
/// `features = [` declaration is never read as a truncated value.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    for raw in text.lines() {
        let line = strip_toml_comment(raw).trim();
        if current.is_empty() && line.is_empty() {
            continue;
        }
        depth += bracket_delta(line);
        if current.is_empty() {
            current.push_str(line);
        } else {
            current.push(' ');
            current.push_str(line);
        }
        if depth <= 0 {
            lines.push(std::mem::take(&mut current));
            depth = 0;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Read every `key = value` assignment of a checked-in TOML file, tagged with
/// the table that declares it.
fn toml_entries(text: &str) -> Vec<TomlEntry> {
    let mut entries: Vec<TomlEntry> = Vec::new();
    let mut table = String::new();
    for line in logical_lines(text) {
        if line.starts_with("[[") {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            name.trim().trim_matches('"').clone_into(&mut table);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains(['.', '[', ']', '{', '}']) {
            continue;
        }
        entries.push(TomlEntry {
            table: table.clone(),
            key: key.to_owned(),
            value: value.trim().to_owned(),
        });
    }
    entries
}

fn unquote(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map(ToOwned::to_owned)
}

fn toml_value<'a>(entries: &'a [TomlEntry], table: &str, key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|entry| entry.table == table && entry.key == key)
        .map(|entry| entry.value.as_str())
}

fn toml_string(entries: &[TomlEntry], table: &str, key: &str) -> Option<String> {
    toml_value(entries, table, key).and_then(unquote)
}

fn toml_bool(entries: &[TomlEntry], table: &str, key: &str) -> Option<bool> {
    match toml_value(entries, table, key) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// Read a declared string array. An entry that is not a quoted string makes the
/// whole array absent rather than partially read.
fn toml_string_array(entries: &[TomlEntry], table: &str, key: &str) -> Option<Vec<String>> {
    let raw = toml_value(entries, table, key)?;
    let inner = raw.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut items: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    let mut quoted = false;
    for character in inner.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted && depth == 0 => items.push(std::mem::take(&mut current)),
            '[' | '{' if !quoted => {
                depth += 1;
                current.push(character);
            }
            ']' | '}' if !quoted => {
                depth -= 1;
                current.push(character);
            }
            _ => current.push(character),
        }
    }
    items.push(current);
    items
        .into_iter()
        .map(|item| unquote(item.trim()))
        .collect::<Option<Vec<String>>>()
}

/// The keys a table declares, in declaration order.
fn toml_keys(entries: &[TomlEntry], table: &str) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry.table == table)
        .map(|entry| entry.key.clone())
        .collect()
}

/// Cargo's implicit features for optional dependencies, which `--all-features`
/// selects in addition to the declared `[features]` keys.
fn implicit_feature_names(entries: &[TomlEntry]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let optional =
            entry.value.contains("optional = true") || entry.value.contains("optional=true");
        if entry.table == "dependencies" && optional {
            names.push(entry.key.clone());
        } else if let Some(dependency) = entry.table.strip_prefix("dependencies.")
            && entry.key == "optional"
            && entry.value.trim() == "true"
        {
            names.push(dependency.to_owned());
        }
    }
    names.sort();
    names.dedup();
    names
}

impl ProofEntrypoint {
    /// The declared proof entrypoint, when the corpus declares one.
    fn parse(capsule: &Value) -> Option<Self> {
        let entrypoint = capsule
            .get("independent_proof_entrypoint")
            .and_then(|declared| declared.get("entrypoint"))?;
        if entrypoint.get("state").and_then(Value::as_str) != Some("DECLARED") {
            return None;
        }
        let value = entrypoint.get("value").and_then(Value::as_str)?;
        let tokens: Vec<String> = value.split_whitespace().map(ToOwned::to_owned).collect();
        if tokens.is_empty() {
            return None;
        }
        Some(Self { tokens })
    }

    /// The declared command, verbatim.
    fn command(&self) -> String {
        self.tokens.join(" ")
    }

    /// The Cargo subcommand the declared command runs, when it runs Cargo.
    fn subcommand(&self) -> Option<&str> {
        let index = self
            .tokens
            .iter()
            .position(|token| token.as_str() == "cargo")?;
        self.tokens
            .get(index + 1)
            .filter(|token| !token.starts_with('-') && !token.starts_with('+'))
            .map(String::as_str)
    }

    fn has_flag(&self, name: &str) -> bool {
        self.tokens.iter().any(|token| token == name)
    }

    /// The value of a flag, in either `--flag value` or `--flag=value` form.
    fn flag(&self, name: &str) -> Option<&str> {
        let inline = format!("{name}=");
        self.tokens.iter().enumerate().find_map(|(index, token)| {
            if let Some(value) = token.strip_prefix(inline.as_str()) {
                return Some(value);
            }
            if token == name {
                return self.tokens.get(index + 1).map(String::as_str);
            }
            None
        })
    }

    /// The Cargo profile the declared command builds under.
    ///
    /// An explicit `--profile`/`--release` selection wins; otherwise the
    /// profile is Cargo's default for the declared subcommand (`test` and
    /// `bench` build under `test`, every other build under `dev`).
    fn profile(&self) -> Option<String> {
        if let Some(named) = self.flag("--profile") {
            return Some(named.to_owned());
        }
        if self.has_flag("--release") {
            return Some("release".to_owned());
        }
        match self.subcommand()? {
            "test" | "bench" => Some("test".to_owned()),
            "build" | "check" | "clippy" | "doc" | "fix" | "fmt" | "run" | "rustc" => {
                Some("dev".to_owned())
            }
            _ => None,
        }
    }

    /// The governed build-output class the declared command writes to, in the
    /// `eliot-instrument-api` `BuildClass` directory vocabulary.
    ///
    /// The mapping is the owner's own instrument-kind mapping: test execution
    /// writes the `nextest` class, lint compilation the `clippy` class, and a
    /// build/check the `interactive` class. A command with no admitted output
    /// class resolves to none and is reported as a gap.
    fn build_class(&self) -> Option<&'static str> {
        match self.subcommand()? {
            "test" | "bench" | "nextest" => Some("nextest"),
            "clippy" => Some("clippy"),
            "build" | "check" | "run" => Some("interactive"),
            _ => None,
        }
    }

    /// The exact feature set the declared command selects.
    ///
    /// `--all-features` selects every feature the package manifest declares
    /// (including Cargo's implicit optional-dependency features), `--features`
    /// adds exactly the features it lists, and `--no-default-features` removes
    /// the package `default` feature members. A command with no feature flag
    /// selects Cargo's default feature set: the `default` feature members, or
    /// no feature at all when the package declares no `default` feature.
    fn feature_selection(&self, declared: &DeclaredFeatures) -> (Vec<String>, String) {
        let mut features: Vec<String> = Vec::new();
        let mut rules: Vec<&str> = Vec::new();
        if self.has_flag("--all-features") {
            features.extend(declared.declared.iter().cloned());
            features.extend(declared.implicit.iter().cloned());
            rules.push("the declared command passes `--all-features`, which selects every feature the package manifest declares");
        } else if self.has_flag("--no-default-features") {
            rules.push("the declared command passes `--no-default-features`, which removes the package default feature members");
        } else {
            features.extend(declared.default.iter().cloned());
            rules.push("the declared command passes no feature flag, so Cargo's default feature set applies: the package `default` feature members, or no feature when the package declares none");
        }
        if let Some(listed) = self.flag("--features") {
            features.extend(
                listed
                    .split(',')
                    .map(str::trim)
                    .filter(|feature| !feature.is_empty())
                    .map(ToOwned::to_owned),
            );
            rules
                .push("the declared command selects exactly the features it lists in `--features`");
        }
        features.sort();
        features.dedup();
        (features, rules.join("; "))
    }
}

/// The compiler identity the repository pins in its checked-in toolchain file.
fn pinned_toolchain(repo_root: &Path) -> PinnedToolchain {
    let path = repo_root.join(TOOLCHAIN_FILE);
    let read = read_text(&path);
    let entries = read.as_deref().map(toml_entries).unwrap_or_default();
    let channel = toml_string(&entries, "toolchain", "channel");
    let targets = toml_string_array(&entries, "toolchain", "targets").unwrap_or_default();
    let components = toml_string_array(&entries, "toolchain", "components").unwrap_or_default();
    let file_profile = toml_string(&entries, "toolchain", "profile");
    let (digest, read_error) = match sha256_file(&path) {
        Ok(digest) => (json!(digest), Value::Null),
        Err(error) => (Value::Null, json!(error.to_string())),
    };
    PinnedToolchain {
        channel: channel.clone(),
        targets: targets.clone(),
        evidence: json!({
            "path": TOOLCHAIN_FILE,
            "sha256": digest,
            "channel": opt_text(channel.as_ref()),
            "components": components,
            "toolchain_file_profile": file_profile,
            "targets": targets,
            "read_error": read_error,
            "note": "`toolchain_file_profile` is the rustup component profile of the pinned toolchain and is not the Cargo build profile of a BuildFingerprint.",
        }),
    }
}

/// The `[profile.*]` tables the workspace manifest declares. A profile override
/// changes the build identity beyond the profile name, so the declared tables
/// are reported beside the profile the fingerprint carries.
fn workspace_profile_tables(repo_root: &Path) -> (Vec<String>, Value) {
    let read = read_text(&repo_root.join(WORKSPACE_MANIFEST));
    let tables: Vec<String> = read
        .as_deref()
        .map(toml_entries)
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry.table.strip_prefix("profile.").map(ToOwned::to_owned))
        .collect();
    let evidence = json!({
        "path": WORKSPACE_MANIFEST,
        "profile_tables": tables,
        "read_error": read.err().map(|error| error.to_string()),
    });
    (tables, evidence)
}

/// The compilation target this run builds for.
///
/// `CARGO_BUILD_TARGET` states it exactly when the environment sets it.
/// Otherwise the pinned toolchain file names the targets it installs, and the
/// host target is the pinned entry whose architecture and operating-system
/// segments match this binary's host. When neither states it, the field stays
/// absent and the owning validator rejects it.
fn resolve_target(toolchain: &PinnedToolchain) -> ResolvedTarget {
    let host_arch = std::env::consts::ARCH;
    let host_os = std::env::consts::OS;
    let os_segments: &[&str] = match host_os {
        "windows" => &["windows"],
        "linux" => &["linux"],
        "macos" => &["apple", "darwin"],
        _ => &[],
    };
    let pinned = || {
        json!({
            "pinned_targets": toolchain.targets.clone(),
            "host_arch": host_arch,
            "host_os": host_os,
        })
    };
    if let Some(explicit) = std::env::var("CARGO_BUILD_TARGET")
        .ok()
        .filter(|value| !value.is_empty())
    {
        let mut evidence = pinned();
        evidence["CARGO_BUILD_TARGET"] = json!(explicit);
        return ResolvedTarget {
            value: Some(explicit.clone()),
            origin: format!(
                "the compilation target the process environment sets in CARGO_BUILD_TARGET ({explicit})"
            ),
            evidence,
        };
    }
    let matched = toolchain.targets.iter().find(|triple| {
        triple.split('-').next() == Some(host_arch)
            && triple
                .split('-')
                .any(|segment| os_segments.contains(&segment))
    });
    let mut evidence = pinned();
    evidence["CARGO_BUILD_TARGET"] = Value::Null;
    match matched {
        Some(triple) => ResolvedTarget {
            value: Some(triple.clone()),
            origin: format!(
                "the `{TOOLCHAIN_FILE}` target whose architecture segment is the host architecture `{host_arch}` and whose operating-system segment is the host operating system `{host_os}`"
            ),
            evidence,
        },
        None => ResolvedTarget {
            value: None,
            origin: format!(
                "no source: CARGO_BUILD_TARGET is unset and no `{TOOLCHAIN_FILE}` target names the host architecture `{host_arch}` on the host operating system `{host_os}`"
            ),
            evidence,
        },
    }
}

/// The build-mode environment class of this run, in the I18.33 build-mode
/// vocabulary.
///
/// I18.33 separates the build modes by whether Cargo incremental compilation is
/// on, and the process environment states that exactly, so the class is read
/// from `CARGO_INCREMENTAL` and every observed input is reported beside it.
fn build_environment() -> (String, String, Value) {
    let observed = json!({
        "CARGO_INCREMENTAL": env_value("CARGO_INCREMENTAL"),
        "CARGO_TARGET_DIR": env_value("CARGO_TARGET_DIR"),
        "CARGO_BUILD_TARGET": env_value("CARGO_BUILD_TARGET"),
        "CARGO_ENCODED_RUSTFLAGS": env_value("CARGO_ENCODED_RUSTFLAGS"),
        "RUSTC_WRAPPER": env_value("RUSTC_WRAPPER"),
        "host_arch": std::env::consts::ARCH,
        "host_os": std::env::consts::OS,
    });
    let incremental = env_value("CARGO_INCREMENTAL");
    let (class, origin) = match incremental.as_str() {
        Some("0" | "false") => (
            "shared-non-incremental",
            "Cargo incremental compilation is off in the process environment, which is the I18.33 shared non-incremental build mode",
        ),
        Some("1" | "true") => (
            "interactive-incremental",
            "Cargo incremental compilation is on in the process environment, which is the I18.33 interactive incremental build mode",
        ),
        _ => (
            "interactive-incremental",
            "CARGO_INCREMENTAL is unset, so Cargo's default incremental behaviour applies, which is the I18.33 interactive incremental build mode",
        ),
    };
    (
        class.to_owned(),
        format!(
            "{origin}; the class names the build mode, not the governed output class, which `build_class` carries"
        ),
        observed,
    )
}

/// One process environment input, reported verbatim or as an explicit absence.
fn env_value(key: &str) -> Value {
    match std::env::var(key) {
        Ok(value) => Value::from(value),
        Err(_) => Value::Null,
    }
}

/// The package manifest of the checked package, read from the corpus-recorded path.
fn resolve_manifest(repo_root: &Path, cell: &Value) -> ResolvedManifest {
    let relative = cell
        .get("source_manifest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let path = repo_root.join(&relative);
    let read = if relative.is_empty() {
        Err("no package manifest path in the corpus".to_owned())
    } else {
        read_text(&path).map_err(|error| error.to_string())
    };
    let entries = read.as_deref().map(toml_entries).unwrap_or_default();
    let recomputed = if relative.is_empty() {
        Err("no package manifest path in the corpus".to_owned())
    } else {
        sha256_file(&path).map_err(|error| format!("{}: {error}", path.display()))
    };
    ResolvedManifest {
        relative,
        features: DeclaredFeatures {
            declared: toml_keys(&entries, "features"),
            implicit: implicit_feature_names(&entries),
            default: toml_string_array(&entries, "features", "default").unwrap_or_default(),
        },
        build_script: toml_string(&entries, "package", "build"),
        proc_macro: toml_bool(&entries, "package", "proc-macro") == Some(true),
        recomputed,
    }
}

/// A recorded corpus digest, or the explicit absence of one.
fn recorded_digest(provenance: Option<&Value>, key: &str) -> Option<String> {
    provenance
        .and_then(|digests| digests.get(key))
        .and_then(|entry| entry.get("sha256"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// The `input_digests` block of the capsule provenance.
fn input_digests(capsule: &Value) -> Option<&Value> {
    capsule
        .get("source_provenance")
        .and_then(|provenance| provenance.get("input_digests"))
}

/// One `BuildFingerprint` field resolved from a checked-in source: the value the
/// fingerprint carries, the source it was read from, and the evidence that
/// source was resolved from.
fn sourced(value: &Value, origin: &str, evidence: &Value) -> Value {
    json!({ "state": "RESOLVED", "value": value, "origin": origin, "evidence": evidence })
}

/// One `BuildFingerprint` field no checked-in source carries. The value stays
/// absent, the owning validator decides whether that absence is admissible,
/// and the field is reported as a typed gap rather than filled with a guess.
fn unsourced(origin: &str) -> Value {
    json!({ "state": UNDECLARED_STATE, "value": Value::Null, "origin": origin, "evidence": Value::Null })
}

/// One resolved field value as text. An unresolved field reads as empty, which
/// is exactly what the owning validator then rejects.
fn field_text(sources: &BTreeMap<&'static str, Value>, field: &str) -> String {
    sources
        .get(field)
        .and_then(|source| source.get("value"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// One resolved field value as an optional build input.
fn field_optional(sources: &BTreeMap<&'static str, Value>, field: &str) -> Option<String> {
    sources
        .get(field)
        .and_then(|source| source.get("value"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// One resolved field value as a string list.
fn field_list(sources: &BTreeMap<&'static str, Value>, field: &str) -> Vec<String> {
    sources
        .get(field)
        .and_then(|source| source.get("value"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The fields no checked-in source could resolve, reported as typed gaps.
fn typed_gaps(sources: &BTreeMap<&'static str, Value>) -> Vec<Value> {
    sources
        .iter()
        .filter(|(_, source)| source.get("state").and_then(Value::as_str) == Some(UNDECLARED_STATE))
        .map(|(field, source)| {
            json!({
                "state": UNDECLARED_STATE,
                "field": field,
                "origin": source.get("origin").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

/// The field an owner-side validation error names, so a rejected field is
/// reported by name and not only as prose.
fn graph_error_field(error: &GraphError) -> Value {
    match error {
        GraphError::InvalidText { field }
        | GraphError::InvalidDigest { field }
        | GraphError::Empty { field } => Value::from(*field),
        _ => Value::Null,
    }
}

/// The `BuildFingerprint` identity fields the checked-in repository declares.
fn identity_field_sources(inputs: &FingerprintInputs) -> Vec<(&'static str, Value)> {
    let candidate = inputs.cell.get("crate").and_then(Value::as_str);
    vec![
        (
            "workspace",
            sourced(
                &Value::from(inputs.repo_root.display().to_string()),
                "the absolute --repo-root the receipt was resolved against",
                &Value::Null,
            ),
        ),
        (
            "candidate",
            match candidate {
                Some(candidate) => sourced(
                    &Value::from(candidate.to_owned()),
                    &format!("the `crate` of the corpus cell in `{CAPSULE_INDEX}`"),
                    &Value::Null,
                ),
                None => unsourced(&format!(
                    "the corpus cell in `{CAPSULE_INDEX}` declares no `crate` for this package"
                )),
            },
        ),
        (
            "toolchain",
            match &inputs.toolchain.channel {
                Some(channel) => sourced(
                    &Value::from(channel.clone()),
                    &format!("the pinned `[toolchain] channel` of `{TOOLCHAIN_FILE}`"),
                    &inputs.toolchain.evidence,
                ),
                None => unsourced(&format!(
                    "`{TOOLCHAIN_FILE}` declares no `[toolchain] channel`; the toolchain that happens to be running is never substituted for a pinned one"
                )),
            },
        ),
        (
            "target",
            match &inputs.target.value {
                Some(value) => sourced(
                    &Value::from(value.clone()),
                    &inputs.target.origin,
                    &inputs.target.evidence,
                ),
                None => unsourced(&inputs.target.origin),
            },
        ),
    ]
}

/// The `BuildFingerprint` fields the corpus-declared proof entrypoint selects.
fn entrypoint_field_sources(inputs: &FingerprintInputs) -> Vec<(&'static str, Value)> {
    let entrypoint = inputs.entrypoint.as_ref();
    let profile = entrypoint.and_then(ProofEntrypoint::profile);
    let build_class = entrypoint.and_then(ProofEntrypoint::build_class);
    let command = entrypoint.map_or_else(String::new, ProofEntrypoint::command);
    let (features, feature_rule) = match entrypoint {
        Some(entrypoint) => entrypoint.feature_selection(&inputs.manifest.features),
        None => (
            Vec::new(),
            format!(
                "the corpus declares no executable proof entrypoint for this package, so it selects no feature set; the package manifest declares {:?}",
                inputs.manifest.features.declared
            ),
        ),
    };
    let (profile_tables, profile_evidence) = workspace_profile_tables(inputs.repo_root);
    let contract_revision = inputs
        .cell
        .get("artifacts")
        .and_then(|artifacts| artifacts.get("contract_kit"))
        .and_then(|kit| kit.get("contract_revision"))
        .and_then(Value::as_str);
    vec![
        (
            "profile",
            match &profile {
                Some(profile) => sourced(
                    &Value::from(profile.clone()),
                    &format!(
                        "the Cargo profile the corpus-declared proof entrypoint `{command}` selects; the workspace manifest declares the profile overrides {profile_tables:?}"
                    ),
                    &profile_evidence,
                ),
                None => unsourced(&format!(
                    "the corpus-declared proof entrypoint `{command}` selects no Cargo profile this reader can resolve"
                )),
            },
        ),
        (
            "features",
            sourced(
                &Value::from(features),
                &feature_rule,
                &json!({
                    "declared_features": inputs.manifest.features.declared,
                    "implicit_optional_dependency_features": inputs.manifest.features.implicit,
                    "default_feature_members": inputs.manifest.features.default,
                    "declared_entrypoint": if command.is_empty() { Value::Null } else { Value::from(command.clone()) },
                }),
            ),
        ),
        (
            "build_class",
            match build_class {
                Some(class) => sourced(
                    &Value::from(class),
                    &format!(
                        "the governed build-output class of the corpus-declared proof entrypoint `{command}`, mapped by the `eliot-instrument-api` instrument-kind mapping (test execution is `nextest`, lint compilation is `clippy`, a build/check is `interactive`)"
                    ),
                    &Value::Null,
                ),
                None => unsourced(&format!(
                    "the corpus-declared proof entrypoint `{command}` has no governed build-output class in the `eliot-instrument-api` `BuildClass` vocabulary"
                )),
            },
        ),
        (
            "contract_revision",
            match contract_revision {
                Some(revision) => sourced(
                    &Value::from(revision.to_owned()),
                    &format!(
                        "the `contract_kit.contract_revision` the corpus cell in `{CAPSULE_INDEX}` records"
                    ),
                    &Value::Null,
                ),
                None => unsourced(&format!(
                    "the corpus cell in `{CAPSULE_INDEX}` records no `contract_kit.contract_revision`"
                )),
            },
        ),
    ]
}

/// The two optional build-input digests of the owning type.
///
/// The owning type declares both optional, so an input the corpus does not
/// record stays `None`: an absent optional digest is an honest absence, never
/// a fabricated digest and never an undeclared marker.
fn optional_build_input_sources(
    inputs: &FingerprintInputs,
    provenance: Option<&Value>,
) -> Vec<(&'static str, Value)> {
    let build_script = match &inputs.manifest.build_script {
        Some(script) => format!("declares the build script `{script}`"),
        None => "declares no build script".to_owned(),
    };
    let proc_macro = if inputs.manifest.proc_macro {
        "declares `proc-macro = true`".to_owned()
    } else {
        "does not declare `proc-macro = true`".to_owned()
    };
    let origin = |key: &str, declared: &str| {
        format!(
            "the capsule `source_provenance.input_digests` records no `{key}` digest and the package manifest {declared}; the owning type declares this build input optional, so its absence is reported and never fabricated"
        )
    };
    let entry = |key: &'static str, declared: &str| {
        (
            key,
            sourced(
                &opt_text(recorded_digest(provenance, key).as_ref()),
                &origin(key, declared),
                &json!({ "manifest_path": inputs.manifest.relative }),
            ),
        )
    };
    vec![
        entry("build_script_digest", &build_script),
        entry("proc_macro_digest", &proc_macro),
    ]
}

/// The `BuildFingerprint` fields the recorded capsule provenance and this
/// process's build-mode environment carry.
fn observed_field_sources(inputs: &FingerprintInputs) -> Vec<(&'static str, Value)> {
    let provenance = input_digests(inputs.capsule);
    let (environment_class, environment_origin, environment_evidence) = build_environment();
    let (recomputed, recompute_error) = match &inputs.manifest.recomputed {
        Ok(digest) => (Value::from(digest.clone()), Value::Null),
        Err(detail) => (Value::Null, Value::from(detail.clone())),
    };
    let recorded = |key: &str| recorded_digest(provenance, key);
    let origin = |key: &str| {
        format!("the `source_provenance.input_digests.{key}.sha256` the corpus capsule records")
    };
    let mut fields = vec![
        (
            "environment_class",
            sourced(
                &Value::from(environment_class),
                &environment_origin,
                &environment_evidence,
            ),
        ),
        (
            "source_closure_digest",
            match recorded("selected_source") {
                Some(digest) => sourced(
                    &Value::from(digest),
                    &origin("selected_source"),
                    &Value::Null,
                ),
                None => unsourced(
                    "the capsule `source_provenance.input_digests` records no `selected_source` digest",
                ),
            },
        ),
        (
            "manifest_digest",
            match recorded("package_manifest") {
                Some(digest) => sourced(
                    &Value::from(digest),
                    &format!(
                        "{}, which is the recorded identity the recomputed digest is compared against and never replaces",
                        origin("package_manifest")
                    ),
                    &json!({
                        "manifest_path": inputs.manifest.relative,
                        "digest_recomputed": recomputed,
                        "digest_recompute_error": recompute_error,
                    }),
                ),
                None => unsourced(
                    "the capsule `source_provenance.input_digests` records no `package_manifest` digest",
                ),
            },
        ),
    ];
    fields.extend(optional_build_input_sources(inputs, provenance));
    fields
}

/// The source of every `BuildFingerprint` field, keyed by field name.
fn build_field_sources(inputs: &FingerprintInputs) -> BTreeMap<&'static str, Value> {
    let mut sources: BTreeMap<&'static str, Value> = BTreeMap::new();
    for (field, source) in identity_field_sources(inputs)
        .into_iter()
        .chain(entrypoint_field_sources(inputs))
        .chain(observed_field_sources(inputs))
    {
        sources.insert(field, source);
    }
    sources
}

/// The owning `BuildFingerprint`, built from the resolved field sources.
///
/// Every field is read back out of the single resolved source map, so the
/// fingerprint carries exactly the values the receipt reports as sourced.
fn fingerprint_from_sources(sources: &BTreeMap<&'static str, Value>) -> BuildFingerprint {
    BuildFingerprint {
        workspace: field_text(sources, "workspace"),
        candidate: field_text(sources, "candidate"),
        toolchain: field_text(sources, "toolchain"),
        target: field_text(sources, "target"),
        profile: field_text(sources, "profile"),
        features: field_list(sources, "features"),
        environment_class: field_text(sources, "environment_class"),
        source_closure_digest: field_text(sources, "source_closure_digest"),
        manifest_digest: field_text(sources, "manifest_digest"),
        build_script_digest: field_optional(sources, "build_script_digest"),
        proc_macro_digest: field_optional(sources, "proc_macro_digest"),
        build_class: field_text(sources, "build_class"),
        contract_revision: field_text(sources, "contract_revision"),
    }
}

/// Construct the owning `BuildFingerprint` type and run its own validation.
///
/// The digest the fingerprint carries is the identity the corpus RECORDED. The
/// digest recomputed from the manifest bytes is reported beside it and compared
/// against the recorded one; it never replaces it, so a verified digest still
/// means the original recorded value was checked. A field no checked-in source
/// carries stays absent, is reported as a typed gap, and fails the owning
/// validator: it is never filled with an invented value.
fn build_fingerprint(
    repo_root: &Path,
    cell: &Value,
    capsule: &Value,
    target: &Path,
    target_origin: &str,
) -> Result<Value, DevCrateCheckError> {
    let toolchain = pinned_toolchain(repo_root);
    let resolved_target = resolve_target(&toolchain);
    let manifest = resolve_manifest(repo_root, cell);
    let entrypoint = ProofEntrypoint::parse(capsule);
    let inputs = FingerprintInputs {
        repo_root,
        cell,
        capsule,
        toolchain: &toolchain,
        target: &resolved_target,
        manifest: &manifest,
        entrypoint: &entrypoint,
    };
    let sources = build_field_sources(&inputs);
    let fingerprint = fingerprint_from_sources(&sources);
    let validation = fingerprint.validate();
    let (state, errors) = match &validation {
        Ok(()) => ("PASSED", Vec::new()),
        Err(error) => (
            "FAILED",
            vec![json!({
                "field": graph_error_field(error),
                "error": error.to_string(),
            })],
        ),
    };
    let normalized_digest = match fingerprint.digest() {
        Ok(digest) => json!({ "state": "DERIVED", "value": digest }),
        Err(error) => json!({
            "state": "NOT_DERIVED",
            "value": Value::Null,
            "error": error.to_string(),
        }),
    };
    let serialized = serde_json::to_value(&fingerprint).map_err(|error| {
        DevCrateCheckError::ReceiptEmission {
            detail: format!("the validated BuildFingerprint could not be serialized: {error}"),
        }
    })?;
    let manifest_recomputed = match &inputs.manifest.recomputed {
        Ok(digest) => Value::from(digest.clone()),
        Err(_) => Value::Null,
    };
    let manifest_error = match &inputs.manifest.recomputed {
        Err(detail) => Value::from(detail.clone()),
        Ok(_) => Value::Null,
    };
    let manifest_recorded = field_text(&sources, "manifest_digest");
    let manifest_verified = match &inputs.manifest.recomputed {
        Ok(recomputed) => *recomputed == manifest_recorded,
        Err(_) => false,
    };
    let gaps = typed_gaps(&sources);
    Ok(json!({
        "kind": "eliot_build_test_graph::BuildFingerprint",
        "owner_crate": "eliot-build-test-graph",
        "owner_contract": eliot_build_test_graph::CONTRACT_NAME,
        "owner_contract_version": eliot_build_test_graph::CONTRACT_VERSION,
        "fingerprint": serialized,
        "validate": {
            "state": state,
            "validator": "eliot_build_test_graph::BuildFingerprint::validate",
            "checks": "non-blank control-character-free text for workspace, candidate, toolchain, target, profile, environment_class, build_class and contract_revision; lowercase 64-hex SHA-256 digests for source_closure_digest and manifest_digest and for each present optional build input digest",
            "errors": errors,
        },
        "normalized_digest": {
            "derivation": "sha256 over the canonical serialization of the validated fingerprint (eliot_build_test_graph::BuildFingerprint::digest)",
            "result": normalized_digest,
        },
        "field_sources": sources,
        "typed_gaps": gaps,
        "target_root": {
            "path": target.display().to_string(),
            "origin": target_origin,
        },
        "manifest_path": inputs.manifest.relative,
        "manifest_digest_recorded": manifest_recorded,
        "manifest_digest_recomputed": manifest_recomputed,
        "manifest_digest_error": manifest_error,
        "manifest_digest_verified": manifest_verified,
        "source_closure_recorded": inputs
            .capsule
            .get("source_provenance")
            .and_then(|provenance| provenance.get("input_digests"))
            .and_then(|digests| digests.get("selected_source"))
            .cloned()
            .unwrap_or(Value::Null),
        "note": "The fingerprint is the owning eliot-build-test-graph type and its own validator decides admissibility; a field no checked-in source carries stays empty and is reported in `typed_gaps` rather than filled with a guess.",
    }))
}

fn pending_consumer_edge_proof(capsule: &Value) -> Value {
    let edge = capsule.get("real_edge_profiles");
    let consumers = edge
        .and_then(|edge| edge.get("one_hop_consumers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let edge_tests = edge
        .and_then(|edge| edge.get("edge_profile_tests"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let uncovered: Vec<Value> = consumers
        .iter()
        .filter(|consumer| {
            !edge_tests
                .iter()
                .any(|test| test.as_str() == consumer.as_str())
        })
        .cloned()
        .collect();
    json!({
        "one_hop_consumers": consumers,
        "edge_profile_tests": edge_tests,
        "consumers_without_edge_profile_test": uncovered,
        "declared_consumers": edge
            .and_then(|edge| edge.get("declared_consumers"))
            .cloned()
            .unwrap_or(Value::Null),
        "declared_required_tests": capsule
            .get("known_uncovered_behavior")
            .and_then(|behavior| behavior.get("declared_required_tests"))
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// Resolve one package against the corpus and emit its receipt.
///
/// A package that the corpus does not know at all is rejected. A package the
/// corpus knows but that carries no declared capability cell is reported as an
/// explicit pending state, never as a pass: the corpus records the package, but
/// it publishes no `ModuleTestCapsule` for it, so nothing is applicable yet.
fn check(repo_root: &Path, package: &str) -> Result<Value, DevCrateCheckError> {
    if !repo_root.is_absolute() {
        return Err(DevCrateCheckError::InvalidInput(
            "repo-root must be absolute".to_owned(),
        ));
    }
    if package.trim().is_empty() {
        return Err(DevCrateCheckError::InvalidInput(
            "package must be a Cargo package name".to_owned(),
        ));
    }
    let index_path = repo_root.join(CAPSULE_INDEX);
    let index = read_json(&index_path)?;
    let coverage = index
        .get("capability_coverage")
        .cloned()
        .unwrap_or(Value::Null);
    let cell = array(&index, "cells", &index_path)?
        .iter()
        .find(|cell| cell.get("crate").and_then(Value::as_str) == Some(package))
        .cloned();
    let Some(cell) = cell else {
        return undeclared_cell_receipt(repo_root, &index_path, package, &coverage);
    };
    let cell_path = repo_root.join(
        cell.get("source_manifest")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let capsule_ref = cell
        .get("artifacts")
        .and_then(|artifacts| artifacts.get("test_capsule"))
        .cloned()
        .unwrap_or(Value::Null);
    let capsule_path = repo_root.join(
        capsule_ref
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let capsule = read_json(&capsule_path)?;
    let recorded_digest = capsule_ref
        .get("artifact_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let recomputed_digest = sha256_file(&capsule_path)?;
    let (target, target_origin) = target_root(repo_root);
    let selected = capsule
        .get("unit_property_model_tests")
        .and_then(|unit| unit.get("selected_tests"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let support = cell
        .get("implementation_support")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "receipt": "eliot.dev.crate.check",
        "package": package,
        "cell": cell_identity(&cell),
        "capsule": {
            "kind": "ModuleTestCapsule",
            "path": capsule_ref.get("path").cloned().unwrap_or(Value::Null),
            "artifact_digest_recorded": recorded_digest,
            "artifact_digest_recomputed": recomputed_digest,
            "artifact_digest_verified": recomputed_digest == recorded_digest,
            "governing_handle": capsule.get("governing_handle").cloned().unwrap_or(Value::Null),
            "governing_fragment": capsule.get("governing_fragment").cloned().unwrap_or(Value::Null),
        },
        "build_fingerprint": build_fingerprint(
            repo_root, &cell, &capsule, &target, target_origin
        )?,
        "target_root": {
            "path": target.display().to_string(),
            "origin": target_origin,
        },
        "applicability": applicability(&capsule, &support),
        "selected_count": selected.len(),
        "executed_count": 0,
        "counts_origin": "selected is the corpus capsule selected_tests slice; executed is zero because this receipt records resolution, not execution",
        "raw_evidence": raw_evidence(&capsule),
        "normalized_evidence": normalized_evidence(&capsule, &selected),
        "proof_ceiling": proof_ceiling(&capsule, &support, &index),
        "pending_consumer_edge_proof": pending_consumer_edge_proof(&capsule),
        "capability_coverage": coverage,
        "corpus": {
            "index": CAPSULE_INDEX,
            "disposition_ledger": DISPOSITION_LEDGER,
            "package_manifest": cell_path.display().to_string(),
        },
    }))
}

fn cell_identity(cell: &Value) -> Value {
    json!({
        "cell_id": cell.get("cell_id").cloned().unwrap_or(Value::Null),
        "crate": cell.get("crate").cloned().unwrap_or(Value::Null),
        "source_manifest": cell.get("source_manifest").cloned().unwrap_or(Value::Null),
        "module_manifest": cell.get("module_manifest").cloned().unwrap_or(Value::Null),
        "reachability": cell.get("reachability").cloned().unwrap_or(Value::Null),
        "workspace_admission": cell.get("workspace_admission").cloned().unwrap_or(Value::Null),
        "excluded_scope": cell.get("excluded_scope").cloned().unwrap_or(Value::Null),
    })
}

/// Applicability is decided only by the corpus: a package is applicable when
/// the corpus declares an independently executable proof entrypoint for it.
/// Workspace membership is recorded beside the verdict and is never the reason.
fn applicability(capsule: &Value, support: &Value) -> Value {
    let entrypoint = capsule
        .get("independent_proof_entrypoint")
        .cloned()
        .unwrap_or(Value::Null);
    let declared = entrypoint
        .get("entrypoint")
        .and_then(|entry| entry.get("state"))
        .and_then(Value::as_str)
        == Some("DECLARED");
    let executable = entrypoint
        .get("executable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "state": if declared && executable {
            "APPLICABLE_CHECKS_SELECTED"
        } else {
            "PENDING_NO_EXECUTABLE_PROOF_ENTRYPOINT"
        },
        "independent_proof_entrypoint": entrypoint,
        "implementation_support": support.get("implementation_support").cloned().unwrap_or(Value::Null),
        "support_ceiling": support.get("support_ceiling").cloned().unwrap_or(Value::Null),
        "evidence_execution_status": support.get("evidence_execution_status").cloned().unwrap_or(Value::Null),
        "blocking_codes": support.get("blocking_codes").cloned().unwrap_or(Value::Null),
        "note": "Workspace membership is not applicability: a package is applicable only when the corpus declares an independently executable proof entrypoint for it.",
    })
}

fn raw_evidence(capsule: &Value) -> Value {
    json!({
        "unit_property_model_tests": capsule.get("unit_property_model_tests").cloned().unwrap_or(Value::Null),
        "expected_nonzero_test_count": capsule.get("expected_nonzero_test_count").cloned().unwrap_or(Value::Null),
        "source_provenance": capsule.get("source_provenance").cloned().unwrap_or(Value::Null),
    })
}

fn normalized_evidence(capsule: &Value, selected: &[Value]) -> Value {
    let tests: Vec<Value> = selected
        .iter()
        .map(|test| {
            json!({
                "path": test.get("path").cloned().unwrap_or(Value::Null),
                "sha256": test.get("sha256").cloned().unwrap_or(Value::Null),
                "test_attributes": test.get("test_attributes").cloned().unwrap_or(Value::Null),
                "inline_cfg_test": test.get("inline_cfg_test").cloned().unwrap_or(Value::Null),
                "classes": test.get("classes").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    json!({
        "selected_tests": tests,
        "test_attribute_count": capsule
            .get("unit_property_model_tests")
            .and_then(|unit| unit.get("test_attribute_count"))
            .cloned()
            .unwrap_or(Value::Null),
        "fake_port_contract_tests": capsule.get("fake_port_contract_tests").cloned().unwrap_or(Value::Null),
        "fault_restart_replay_cases": capsule.get("fault_restart_replay_cases").cloned().unwrap_or(Value::Null),
    })
}

fn proof_ceiling(capsule: &Value, support: &Value, index: &Value) -> Value {
    json!({
        "proof_level_ceiling": capsule.get("proof_level_ceiling").cloned().unwrap_or(Value::Null),
        "support_ceiling": support.get("support_ceiling").cloned().unwrap_or(Value::Null),
        "triad_complete": support.get("triad_complete").cloned().unwrap_or(Value::Null),
        "index_support_ceiling_with_complete_triad": index
            .get("support_ceiling_with_complete_triad")
            .cloned()
            .unwrap_or(Value::Null),
        "index_triad_rule": index.get("triad_rule").cloned().unwrap_or(Value::Null),
    })
}

fn undeclared_cell_receipt(
    repo_root: &Path,
    index_path: &Path,
    package: &str,
    coverage: &Value,
) -> Result<Value, DevCrateCheckError> {
    let index = read_json(index_path)?;
    let known = array(&index, "packages_with_undeclared_cell_id_paths", index_path)?;
    let manifests: Vec<&str> = known
        .iter()
        .filter_map(Value::as_str)
        .filter(|path| {
            Path::new(path)
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some(package)
        })
        .collect();
    if manifests.is_empty() {
        return Err(DevCrateCheckError::UnknownPackage {
            package: package.to_owned(),
        });
    }
    let (target, target_origin) = target_root(repo_root);
    Ok(json!({
        "receipt": "eliot.dev.crate.check",
        "package": package,
        "status": "PENDING_NO_DECLARED_CAPABILITY_CELL",
        "selected_count": 0,
        "executed_count": 0,
        "build_fingerprint": {
            "kind": "eliot_build_test_graph::BuildFingerprint",
            "validated": false,
            "note": "The corpus records this first-party package but publishes no ModuleTestCapsule for it, so no recorded manifest, source-closure or contract-revision digest and no declared proof entrypoint exist to construct a BuildFingerprint. No fingerprint is constructed and none is validated.",
            "undeclared": undeclared(&[
                "workspace",
                "candidate",
                "toolchain",
                "target",
                "profile",
                "features",
                "environment_class",
                "source_closure_digest",
                "manifest_digest",
                "build_script_digest",
                "proc_macro_digest",
                "build_class",
                "contract_revision",
            ]),
        },
        "target_root": { "path": target.display().to_string(), "origin": target_origin },
        "raw_evidence": {
            "packages_with_undeclared_cell_id_paths": manifests,
        },
        "normalized_evidence": Value::Null,
        "proof_ceiling": undeclared(&["proof_level_ceiling"]),
        "pending_consumer_edge_proof": undeclared(&["one_hop_consumers", "edge_profile_tests"]),
        "capability_coverage": coverage,
        "note": "The corpus records this first-party package but publishes no ModuleTestCapsule for it, so no package-scoped check is selected and nothing is executed. Workspace membership alone is never applicability.",
    }))
}

pub(crate) fn run(command: DevCommand) -> Result<Value, DevCrateCheckError> {
    let DevCommand::Crate { command } = command;
    match command {
        CrateCommand::Check { package, repo_root } => check(&repo_root, &package),
        CrateCommand::Dispositions { repo_root } => {
            if !repo_root.is_absolute() {
                return Err(DevCrateCheckError::InvalidInput(
                    "repo-root must be absolute".to_owned(),
                ));
            }
            dispositions(&repo_root)
        }
    }
}
