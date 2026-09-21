#![forbid(unsafe_code)]

//! Installation-visible `SurrealDB` compatibility decision (issue #1932, I5.9).
//!
//! Architecture: I5.9 compatibility gate (`docs/architecture/I05-09-surrealdb-implementation.md#i59-surrealdb-implementation`)
//! plus I0.5 evidence discipline (`docs/architecture/I00-05-conformance-support-and-evidence-status.md#i05-conformance-support-and-evidence-status`).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! A matching binary checksum proves artifact identity, not datastore
//! compatibility. This cell owns the `compatibility.toml` decision record only:
//! bounded parsing, validation, startup reporting and the pure canonical-writer
//! admission verdict. It performs no provider I/O, holds no credentials and
//! owns no migration, write or recovery semantics.
//!
//! Expected installation-visible shape (sibling of the Store launch config):
//!
//! ```toml
//! [surrealdb]
//! active_version = "3.1.4"
//! artifact_sha256 = "<lowercase hex sha256 of the qualified surreal.exe>"
//! transport = "ws"
//! schema_generation = "2.0.0"
//! migration_id = "surreal-schema-v2"
//! qualified_fallback_line = "3.1.x"
//! canonical_writes_admitted = true
//! evidence_snapshots = ["snapshot-2026-09-12-r1"]
//! ```
//!
//! Writer admission requires ALL of: the observed provider artifact digest
//! exactly equals the recorded digest; the active version line exactly equals
//! the qualified fallback line (so 3.1.4 is kept only while it is explicitly
//! the latest locally qualified fallback, and 3.2.x is never promoted merely
//! because it is the target); both the active version and the fallback line
//! name the adapter-pinned server major (a record for an unpinned major is
//! malformed for this binary, not merely unevaluated); the transport is the
//! admitted remote RPC/WebSocket path; the schema generation matches the
//! bridge expectation; canonical writes are admitted; and at least one
//! evidence snapshot is recorded. Anything else is an explicit maintenance
//! (non-writer) verdict.
//!
//! Scope honesty: this gate binds the RECORD to config claims and to the
//! compiled pin. It does not observe the live server version: the adapter
//! proves spawned-artifact identity, listener ownership and server major
//! over its ownership-verified channel at connect time, and only the startup
//! order (gate → connect → re-verify → serve) plus the backend handoff carry
//! that proof to the writer decision. Snapshot strings are audit trail, never
//! qualification proof.

use std::path::{Path, PathBuf};

use eliot_store_surreal_adapter::PINNED_SURREALDB_MAJOR;

/// File name of the installation-visible compatibility decision.
pub const COMPATIBILITY_FILE_NAME: &str = "compatibility.toml";

/// Only admitted store transport: the remote RPC/WebSocket path.
pub const ADMITTED_TRANSPORT: &str = "ws";

/// Upper bound for a compatibility file read.
const MAX_COMPATIBILITY_BYTES: usize = 64 * 1024;

/// Upper bound for recorded evidence snapshot identifiers.
const MAX_EVIDENCE_SNAPSHOTS: usize = 32;

/// Upper bound for one evidence snapshot identifier.
const MAX_EVIDENCE_SNAPSHOT_LEN: usize = 256;

/// Legacy all-zero digest: artifact identity, never a qualification.
const LEGACY_ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Installation-visible compatibility file.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityFile {
    /// Active `SurrealDB` store decision.
    pub surrealdb: SurrealCompatibility,
}

/// Active `SurrealDB` store decision record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealCompatibility {
    /// Exact `SurrealDB` version admitted for canonical writes (e.g. `3.1.4`).
    pub active_version: String,
    /// Lowercase hex SHA-256 of the qualified server binary.
    pub artifact_sha256: String,
    /// Admitted transport; only [`ADMITTED_TRANSPORT`] admits writers.
    pub transport: String,
    /// Schema/migration generation of the qualified store (e.g. `2.0.0`).
    pub schema_generation: String,
    /// Migration identity that produced the qualified generation.
    pub migration_id: String,
    /// Latest locally qualified fallback line (e.g. `3.1.x` or `3.1.4`).
    pub qualified_fallback_line: String,
    /// Whether the active generation is admitted for canonical writes.
    pub canonical_writes_admitted: bool,
    /// Evidence snapshot identifiers backing the admission.
    #[serde(default)]
    pub evidence_snapshots: Vec<String>,
}

/// Canonical-writer admission verdict for one compatibility record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityVerdict {
    /// The active generation is admitted for canonical writes.
    WriterAdmitted {
        /// Startup-visible report line.
        report: String,
    },
    /// The installation is in explicit maintenance: no canonical writes.
    Maintenance {
        /// Bounded machine-readable reason.
        reason: String,
        /// Startup-visible report line.
        report: String,
    },
}

impl CompatibilityVerdict {
    /// Returns true only for an admitted canonical writer.
    #[must_use]
    pub const fn is_writer_admitted(&self) -> bool {
        matches!(self, Self::WriterAdmitted { .. })
    }

    /// Returns the startup-visible report line for either verdict.
    #[must_use]
    pub fn report(&self) -> &str {
        match self {
            Self::WriterAdmitted { report } | Self::Maintenance { report, .. } => report,
        }
    }
}

/// Parses and validates one compatibility file's bytes.
pub fn parse_compatibility_bytes(bytes: &[u8]) -> Result<CompatibilityFile, String> {
    if bytes.len() > MAX_COMPATIBILITY_BYTES {
        return Err("compatibility.toml exceeds the bounded size".to_owned());
    }
    let file: CompatibilityFile =
        toml::from_slice(bytes).map_err(|error| format!("parse compatibility.toml: {error}"))?;
    validate_record(&file.surrealdb)?;
    Ok(file)
}

/// Resolves the sibling compatibility path for one Store launch config path.
#[must_use]
pub fn compatibility_path_for_config(config_path: &Path) -> Option<PathBuf> {
    config_path
        .parent()
        .map(|parent| parent.join(COMPATIBILITY_FILE_NAME))
}

/// Loads and validates the sibling compatibility file for one config path.
///
/// A missing or unreadable file is an explicit error: without a recorded
/// qualified decision the installation cannot admit canonical writes.
pub fn load_compatibility_for_config(config_path: &Path) -> Result<CompatibilityFile, String> {
    let Some(path) = compatibility_path_for_config(config_path) else {
        return Err(
            "compatibility.toml has no parent directory for the Store config path".to_owned(),
        );
    };
    let metadata = std::fs::metadata(&path).map_err(|_| {
        "compatibility.toml is not recorded; canonical writes are not admitted".to_owned()
    })?;
    if metadata.len() > MAX_COMPATIBILITY_BYTES as u64 {
        return Err("compatibility.toml exceeds the bounded size".to_owned());
    }
    let bytes = std::fs::read(&path).map_err(|_| {
        "compatibility.toml is not readable; canonical writes are not admitted".to_owned()
    })?;
    parse_compatibility_bytes(&bytes)
}

/// Evaluates one validated record against the observed installation state.
///
/// `observed_artifact_digest` is the installation-approved provider binary
/// digest (from the validated runtime launch descriptor); it must exactly
/// equal the recorded digest. `expected_schema_generation` is the bridge's
/// configured schema generation; it must exactly equal the recorded one.
#[must_use]
pub fn evaluate_compatibility(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
) -> CompatibilityVerdict {
    let failure = evaluate_failure(record, observed_artifact_digest, expected_schema_generation);
    let decision = if failure.is_none() {
        "writer-admitted"
    } else {
        "maintenance"
    };
    let report = startup_report(record, decision, failure.as_deref().unwrap_or("admitted"));
    match failure {
        None => CompatibilityVerdict::WriterAdmitted { report },
        Some(reason) => CompatibilityVerdict::Maintenance { reason, report },
    }
}

/// Enforces writer admission: returns the startup report when admitted, or a
/// visible maintenance refusal when the installation must not write.
pub fn require_compatibility_for_writer(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
) -> Result<String, String> {
    match evaluate_compatibility(record, observed_artifact_digest, expected_schema_generation) {
        CompatibilityVerdict::WriterAdmitted { report } => Ok(report),
        CompatibilityVerdict::Maintenance { report, .. } => Err(report),
    }
}

/// Requires the recorded decision to match the LIVE observed provider
/// identity before canonical writes (issue #1932, backend handoff §3).
///
/// `observed_version` is the exact `major.minor.patch` triple from the live
/// `provider.version` RPC answered over the ownership-verified channel;
/// `observed_digest` is the spawn-validated artifact digest. Both must equal
/// the record: a rotated binary or a drifted record fails closed here, never
/// at the first canonical write. Record echo alone never satisfies this
/// gate. Returns the startup report when bound.
pub fn require_observed_identity_match(
    record: &SurrealCompatibility,
    observed_version: &str,
    observed_digest: &str,
) -> Result<String, String> {
    if record.active_version != observed_version {
        return Err(format!(
            "recorded active_version {} does not match the observed provider version {observed_version}; canonical writes are not admitted",
            record.active_version,
        ));
    }
    if normalize_digest(&record.artifact_sha256) != normalize_digest(observed_digest) {
        return Err(
            "recorded artifact digest does not match the observed provider artifact; canonical writes are not admitted".to_owned(),
        );
    }
    Ok(startup_report(
        record,
        "writer-admitted",
        "observed provider identity bound",
    ))
}

/// Renders the startup-visible report binding the exact active version to its
/// compatibility decision. The line always carries `active_version` and
/// `decision`; it never carries credentials.
fn startup_report(record: &SurrealCompatibility, decision: &str, detail: &str) -> String {
    format!(
        "surrealdb compatibility: active_version={} transport={} schema_generation={} migration_id={} fallback_line={} canonical_writes={} evidence_snapshots={} decision={} detail={}",
        record.active_version,
        record.transport,
        record.schema_generation,
        record.migration_id,
        record.qualified_fallback_line,
        if record.canonical_writes_admitted {
            "admitted"
        } else {
            "withheld"
        },
        record.evidence_snapshots.len(),
        decision,
        detail,
    )
}

/// Returns the maintenance reason when the record must not admit writers.
///
/// Scope honesty: this cell binds the record to CONFIG claims (observed
/// descriptor digest, bridge schema expectation) and to the COMPILED adapter
/// pin. It does not observe the live server: the adapter proves the spawned
/// artifact identity, listener ownership and server major over its
/// ownership-verified channel at connect time, but the full observed version
/// is not re-surfaced to this gate (see the A1780 handoff). A record naming
/// an unpinned major is therefore refused here rather than admitted on echo.
fn evaluate_failure(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
) -> Option<String> {
    let pinned = pinned_major_text();
    if record_major(&record.active_version) != Some(pinned.as_str()) {
        return Some(format!(
            "active_version {} does not name the adapter-pinned major {}",
            record.active_version, PINNED_SURREALDB_MAJOR
        ));
    }
    if record_major(&record.qualified_fallback_line) != Some(pinned.as_str()) {
        return Some(format!(
            "qualified_fallback_line {} does not name the adapter-pinned major {}",
            record.qualified_fallback_line, PINNED_SURREALDB_MAJOR
        ));
    }
    if record.transport != ADMITTED_TRANSPORT {
        return Some(format!(
            "transport {} is not the admitted remote RPC/WebSocket path",
            record.transport
        ));
    }
    if !line_matches_version(&record.qualified_fallback_line, &record.active_version) {
        return Some(format!(
            "active_version {} is not the qualified fallback line {}",
            record.active_version, record.qualified_fallback_line
        ));
    }
    if normalize_digest(observed_artifact_digest) != normalize_digest(&record.artifact_sha256) {
        return Some(
            "observed provider binary does not match the qualified artifact digest".to_owned(),
        );
    }
    if record.schema_generation != expected_schema_generation {
        return Some(format!(
            "recorded schema_generation {} does not match the bridge expectation {expected_schema_generation}",
            record.schema_generation
        ));
    }
    if !record.canonical_writes_admitted {
        return Some("active generation is not admitted for canonical writes".to_owned());
    }
    if record.evidence_snapshots.is_empty() {
        return Some("admitted generation has no recorded evidence snapshot".to_owned());
    }
    None
}

fn validate_record(record: &SurrealCompatibility) -> Result<(), String> {
    validate_version(&record.active_version)?;
    validate_digest(&record.artifact_sha256)?;
    validate_text(&record.transport, "transport")?;
    validate_text(&record.schema_generation, "schema_generation")?;
    validate_text(&record.migration_id, "migration_id")?;
    validate_fallback_line(&record.qualified_fallback_line)?;
    // A record naming an unpinned major can never be served by this binary
    // (the adapter refuses it at connect), so it is malformed here rather
    // than admitted on echo and failed later.
    let pinned = pinned_major_text();
    if record_major(&record.active_version) != Some(pinned.as_str()) {
        return Err(format!(
            "active_version {} does not name the adapter-pinned major {}",
            record.active_version, PINNED_SURREALDB_MAJOR
        ));
    }
    if record_major(&record.qualified_fallback_line) != Some(pinned.as_str()) {
        return Err(format!(
            "qualified_fallback_line {} does not name the adapter-pinned major {}",
            record.qualified_fallback_line, PINNED_SURREALDB_MAJOR
        ));
    }
    if record.evidence_snapshots.len() > MAX_EVIDENCE_SNAPSHOTS {
        return Err("evidence_snapshots exceeds the bounded count".to_owned());
    }
    for snapshot in &record.evidence_snapshots {
        validate_text(snapshot, "evidence_snapshots entry")?;
        if snapshot.len() > MAX_EVIDENCE_SNAPSHOT_LEN {
            return Err("evidence_snapshots entry exceeds the bounded length".to_owned());
        }
    }
    if record.canonical_writes_admitted && record.evidence_snapshots.is_empty() {
        return Err("an admitted generation must record at least one evidence snapshot".to_owned());
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), String> {
    validate_text(value, "active_version")?;
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 5 || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("active_version must be an exact major.minor.patch version".to_owned());
    }
    Ok(())
}

fn validate_fallback_line(value: &str) -> Result<(), String> {
    validate_text(value, "qualified_fallback_line")?;
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(
            "qualified_fallback_line must be major.minor.x or major.minor.patch".to_owned(),
        );
    }
    for part in &parts[0..2] {
        if part.is_empty() || part.len() > 5 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(
                "qualified_fallback_line must be major.minor.x or major.minor.patch".to_owned(),
            );
        }
    }
    let patch = parts[2];
    let patch_ok = patch == "x"
        || (!patch.is_empty()
            && patch.len() <= 5
            && patch.bytes().all(|byte| byte.is_ascii_digit()));
    if !patch_ok {
        return Err(
            "qualified_fallback_line must be major.minor.x or major.minor.patch".to_owned(),
        );
    }
    Ok(())
}

/// Returns true when `version` (`major.minor.patch`) is inside `line`
/// (`major.minor.x` or an exact `major.minor.patch`).
fn line_matches_version(line: &str, version: &str) -> bool {
    let line_parts: Vec<&str> = line.split('.').collect();
    let version_parts: Vec<&str> = version.split('.').collect();
    if line_parts.len() != 3 || version_parts.len() != 3 {
        return false;
    }
    if line_parts[0] != version_parts[0] || line_parts[1] != version_parts[1] {
        return false;
    }
    line_parts[2] == "x" || line_parts[2] == version_parts[2]
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value == LEGACY_ZERO_DIGEST {
        return Err("artifact_sha256 cannot use the legacy zero digest".to_owned());
    }
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("artifact_sha256 must be a lowercase SHA-256 digest".to_owned());
    }
    Ok(())
}

fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Major segment of a validated `major.minor.patch` or `major.minor.x`
/// value. Compared as an exact string so oversized numeric segments can
/// never overflow an integer parse on the way to a fail-closed refusal.
fn record_major(value: &str) -> Option<&str> {
    value.split('.').next()
}

/// Adapter-pinned server major, rendered for exact segment comparison.
fn pinned_major_text() -> String {
    PINNED_SURREALDB_MAJOR.to_string()
}

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-blank and contain no control characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const QUALIFIED_TOML: &str = r#"
[surrealdb]
active_version = "3.1.4"
artifact_sha256 = "13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1"
transport = "ws"
schema_generation = "2.0.0"
migration_id = "surreal-schema-v2"
qualified_fallback_line = "3.1.x"
canonical_writes_admitted = true
evidence_snapshots = ["snapshot-2026-09-12-r1"]
"#;

    const OBSERVED_DIGEST: &str =
        "13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1";

    fn qualified_record() -> SurrealCompatibility {
        parse_compatibility_bytes(QUALIFIED_TOML.as_bytes())
            .expect("qualified fixture parses")
            .surrealdb
    }

    #[test]
    fn startup_reports_exact_active_version_and_decision() {
        let record = qualified_record();
        let verdict = evaluate_compatibility(&record, OBSERVED_DIGEST, "2.0.0");
        assert!(verdict.is_writer_admitted());
        let report = verdict.report();
        assert!(
            report.contains("active_version=3.1.4"),
            "report must carry the exact active version: {report}"
        );
        assert!(
            report.contains("decision=writer-admitted"),
            "report must carry the compatibility decision: {report}"
        );
        assert!(
            !report.contains("password") && !report.contains("credential"),
            "report must not carry credentials: {report}"
        );
        require_compatibility_for_writer(&record, OBSERVED_DIGEST, "2.0.0")
            .expect("qualified fallback admits writers");
    }

    #[test]
    fn unrecorded_or_unqualified_binary_denies_canonical_writes() {
        let record = qualified_record();
        // Changed binary without a matching qualified decision.
        let rotated = evaluate_compatibility(&record, &"f".repeat(64), "2.0.0");
        assert!(!rotated.is_writer_admitted());
        assert!(rotated.report().contains("decision=maintenance"));
        assert!(require_compatibility_for_writer(&record, &"f".repeat(64), "2.0.0").is_err());

        // Recorded but explicitly unqualified generation.
        let mut withheld = record.clone();
        withheld.canonical_writes_admitted = false;
        let verdict = evaluate_compatibility(&withheld, OBSERVED_DIGEST, "2.0.0");
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("canonical_writes=withheld"));

        // Admitted flag without evidence is rejected at parse time.
        let no_evidence = QUALIFIED_TOML.replace(
            r#"evidence_snapshots = ["snapshot-2026-09-12-r1"]"#,
            "evidence_snapshots = []",
        );
        assert!(parse_compatibility_bytes(no_evidence.as_bytes()).is_err());
    }

    #[test]
    fn version_change_without_matching_decision_becomes_maintenance() {
        let record = qualified_record();
        // Target-line promotion without qualification is refused: 3.2.x is
        // not inside the qualified 3.1.x fallback line.
        let mut promoted = record.clone();
        promoted.active_version = "3.2.3".to_owned();
        let verdict = evaluate_compatibility(&promoted, OBSERVED_DIGEST, "2.0.0");
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("decision=maintenance"));

        // Schema/migration drift against the bridge expectation is refused.
        let drifted = evaluate_compatibility(&record, OBSERVED_DIGEST, "1.0.0");
        assert!(!drifted.is_writer_admitted());
        assert!(drifted.report().contains("decision=maintenance"));

        // Non-remote transport is refused without silent fallback.
        let mut http = record.clone();
        http.transport = "http".to_owned();
        assert!(!evaluate_compatibility(&http, OBSERVED_DIGEST, "2.0.0").is_writer_admitted());
    }

    // PROOF (fails on 410813d6): a record naming an unpinned major is
    // malformed at parse and refused at evaluation even with otherwise
    // matching evidence — the adapter binary can never serve it, so echo
    // admission would be self-attestation.
    #[test]
    fn record_naming_unpinned_major_is_refused() {
        let forged_major = QUALIFIED_TOML
            .replace(r#"active_version = "3.1.4""#, r#"active_version = "4.0.0""#)
            .replace(
                r#"qualified_fallback_line = "3.1.x""#,
                r#"qualified_fallback_line = "4.0.x""#,
            );
        assert!(parse_compatibility_bytes(forged_major.as_bytes()).is_err());

        let mut forged = qualified_record();
        forged.active_version = "4.0.0".to_owned();
        forged.qualified_fallback_line = "4.0.x".to_owned();
        let verdict = evaluate_compatibility(&forged, OBSERVED_DIGEST, "2.0.0");
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("decision=maintenance"));
        assert!(require_compatibility_for_writer(&forged, OBSERVED_DIGEST, "2.0.0").is_err());

        // A stale-major fallback line is refused even when the active
        // version itself is pinned.
        let mut stale_line = qualified_record();
        stale_line.qualified_fallback_line = "2.1.x".to_owned();
        assert!(
            !evaluate_compatibility(&stale_line, OBSERVED_DIGEST, "2.0.0").is_writer_admitted()
        );

        // The pinned line still admits with fresh matching evidence.
        let record = qualified_record();
        assert!(evaluate_compatibility(&record, OBSERVED_DIGEST, "2.0.0").is_writer_admitted());
    }

    // Observed-identity binding (issue #1932, backend handoff §3): the
    // record echo binds to the live provider observation, never alone.
    #[test]
    fn observed_identity_match_admits_bound_record() {
        let record = qualified_record();
        let report =
            require_observed_identity_match(&record, "3.1.4", OBSERVED_DIGEST).expect("bound");
        assert!(report.contains("active_version=3.1.4"));
        assert!(report.contains("observed provider identity bound"));
    }

    #[test]
    fn observed_version_drift_refuses_before_any_write() {
        let record = qualified_record();
        for drifted in ["3.1.5", "3.2.0", "4.0.0"] {
            let refusal = require_observed_identity_match(&record, drifted, OBSERVED_DIGEST)
                .expect_err("drift must refuse");
            assert!(
                refusal.contains("does not match the observed provider version"),
                "version drift refuses: {refusal}"
            );
        }
    }

    #[test]
    fn observed_digest_drift_refuses_before_any_write() {
        let record = qualified_record();
        let refusal =
            require_observed_identity_match(&record, "3.1.4", &"f".repeat(64)).expect_err("drift");
        assert!(
            refusal.contains("does not match the observed provider artifact"),
            "digest drift refuses: {refusal}"
        );
        // Case-insensitive record form still binds the same artifact.
        let mut upper = record.clone();
        upper.artifact_sha256 = OBSERVED_DIGEST.to_ascii_uppercase();
        assert!(
            parse_compatibility_bytes(
                QUALIFIED_TOML
                    .replace(OBSERVED_DIGEST, &upper.artifact_sha256)
                    .as_bytes()
            )
            .is_err()
        );
        require_observed_identity_match(&upper, "3.1.4", OBSERVED_DIGEST).expect("case-bound");
    }
}
