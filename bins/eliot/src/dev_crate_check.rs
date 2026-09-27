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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Checked-in generated capsule index: the per-package resolution corpus.
const CAPSULE_INDEX: &str = "docs/code-navigation/capsules/index.json";
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
}

impl DevCrateCheckError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => 2,
            Self::UnknownPackage { .. } => 3,
            Self::CorpusUnreadable { .. }
            | Self::CorpusMalformed { .. }
            | Self::LedgerUnusable { .. } => 65,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::UnknownPackage { .. } => "UNKNOWN_PACKAGE",
            Self::CorpusUnreadable { .. } => "CORPUS_UNREADABLE",
            Self::CorpusMalformed { .. } => "CORPUS_MALFORMED",
            Self::LedgerUnusable { .. } => "LEDGER_UNUSABLE",
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

fn read_json(path: &Path) -> Result<Value, DevCrateCheckError> {
    let text = fs::read_to_string(path).map_err(|error| DevCrateCheckError::CorpusUnreadable {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
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
        "state": "UNDECLARED",
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
}

impl LedgerRow {
    fn parse(
        line: &str,
        heading_verb: Option<&'static str>,
        sub: Option<&'static str>,
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
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("## ") {
            heading_verb = LEDGER_VERBS
                .iter()
                .copied()
                .find(|verb| heading.starts_with(&format!("{verb} ")));
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
            if let Some(row) = LedgerRow::parse(trimmed, heading_verb, sub) {
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

fn dispositions(repo_root: &Path) -> Result<Value, DevCrateCheckError> {
    let index_path = repo_root.join(CAPSULE_INDEX);
    let index = read_json(&index_path)?;
    let ledger = parse_ledger(&repo_root.join(DISPOSITION_LEDGER))?;
    let cells = array(&index, "cells", &index_path)?;
    let mut entries: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for cell in cells {
        let reachability = text(cell, "reachability", &index_path)?;
        if reachability != "UNREACHABLE" && reachability != "EXCLUDED" {
            continue;
        }
        let package = text(cell, "crate", &index_path)?;
        let (disposition, verb, group, owner) = match ledger.get(&package) {
            Some(row) => (
                disposition_for(row.verb, row.effective_group()),
                Value::from(row.verb),
                Value::from(row.effective_group()),
                json!(row.owner),
            ),
            None => (
                Disposition::Undispositioned,
                Value::Null,
                Value::Null,
                Value::Null,
            ),
        };
        *counts
            .entry(format!(
                "{reachability} {} {}",
                disposition.as_str(),
                verb.as_str().unwrap_or("UNRECORDED")
            ))
            .or_default() += 1;
        entries.push(json!({
            "package": package,
            "reachability": reachability,
            "disposition": disposition.as_str(),
            "disposition_verb": verb,
            "disposition_group": group,
            "owner": owner,
            "disposition_source": DISPOSITION_LEDGER,
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
        "counts": counts,
        "dispositions": entries,
    }))
}

fn build_fingerprint(
    repo_root: &Path,
    cell: &Value,
    capsule: &Value,
    target: &Path,
    target_origin: &str,
) -> Value {
    let digests = capsule
        .get("source_provenance")
        .and_then(|provenance| provenance.get("input_digests"));
    let manifest_recorded = digests
        .and_then(|all| all.get("package_manifest"))
        .and_then(|manifest| manifest.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let manifest_path = cell
        .get("source_manifest")
        .and_then(Value::as_str)
        .map_or_else(String::new, ToOwned::to_owned);
    let manifest_recomputed = if manifest_path.is_empty() {
        Err("no package manifest path in the corpus".to_owned())
    } else {
        sha256_file(&repo_root.join(&manifest_path))
            .map_err(|error| format!("{}: {error}", repo_root.join(&manifest_path).display()))
    };
    let manifest_verified = manifest_recomputed
        .as_ref()
        .is_ok_and(|recomputed| *recomputed == manifest_recorded);
    let source_closure = digests
        .and_then(|all| all.get("selected_source"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "workspace": repo_root.display().to_string(),
        "candidate": cell.get("crate").cloned().unwrap_or(Value::Null),
        "target": target.display().to_string(),
        "target_root_origin": target_origin,
        "manifest_path": manifest_path,
        "manifest_digest_recorded": manifest_recorded,
        "manifest_digest_recomputed": manifest_recomputed
            .as_ref()
            .map_or(Value::Null, |digest| Value::from(digest.clone())),
        "manifest_digest_error": manifest_recomputed
            .as_ref()
            .err()
            .map_or(Value::Null, |detail| Value::from(detail.clone())),
        "manifest_digest_verified": manifest_verified,
        "source_closure_digest": source_closure,
        "contract_revision": cell
            .get("artifacts")
            .and_then(|artifacts| artifacts.get("contract_kit"))
            .and_then(|kit| kit.get("contract_revision"))
            .cloned()
            .unwrap_or(Value::Null),
        "undeclared": undeclared(&[
            "toolchain",
            "profile",
            "features",
            "environment_class",
            "build_class",
            "build_script_digest",
            "proc_macro_digest",
        ]),
    })
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
        ),
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
        "build_fingerprint": undeclared(&["source_closure_digest", "manifest_digest"]),
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
