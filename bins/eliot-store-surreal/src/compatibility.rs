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
//! Expected installation-visible shape (sibling of the Store launch config,
//! beside [`EVIDENCE_SNAPSHOT_FILE_NAME`]):
//!
//! ```toml
//! [surrealdb]
//! active_version = "3.1.4"
//! artifact_sha256 = "<lowercase hex sha256 of the qualified surreal.exe>"
//! transport = "ws"
//! schema_generation = "2.0.0"
//! migration_id = "surreal-schema-v2"
//! qualified_fallback_line = "3.1.x"
//! qualified_fallback_version = "3.1.4"
//! qualified_fallback_sha256 = "<lowercase hex sha256 of the qualified fallback surreal.exe>"
//! canonical_writes_admitted = true
//! evidence_snapshot_sha256 = "<lowercase hex I0.5 CurrentSystemEvidenceSnapshot.snapshot_sha256>"
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
//! bridge expectation; canonical writes are admitted; the record's qualified
//! fallback line is anchored to a QUALIFIED ARTIFACT — the fallback version
//! lies inside the line and equals the active generation, so the active store
//! is exactly the latest locally qualified fallback; its recorded digest is
//! coherent with the active artifact; and the recorded
//! I0.5 evidence-snapshot content address has been verified against the
//! snapshot document actually installed beside the decision record. Anything
//! else is an explicit maintenance (non-writer) verdict.
//!
//! Record-shape change: a record that does not state its exact I0.5
//! evidence-snapshot content address and its qualified fallback artifact is an
//! UNQUALIFIED record and is refused. There is no grace period and no
//! label-only form: a free-form snapshot label is audit trail, never
//! qualification proof, so `validate_record` rejects such a record at parse
//! time and the verdict is maintenance.
//!
//! Maintenance is a RUNNING state, not a startup abort: an unrecorded or
//! unqualified installation resolves through [`resolve_compatibility_verdict`]
//! to [`CompatibilityVerdict::Maintenance`], the bridge comes up, its startup
//! report names the exact active version and decision, and every canonical
//! mutation is refused through [`require_installation_writer`] with that same
//! report as the refusal's bounded detail. Only the writer path maps a
//! maintenance verdict to an `Err`.
//!
//! Scope honesty: this gate binds the RECORD to installation-visible bytes
//! (the sibling evidence-snapshot document) and to config claims and the
//! compiled pin. It does not re-derive the snapshot content address — that
//! canonical digest belongs to `eliot-bootstrap` — so it verifies that the
//! installed document states the EXACT recorded `snapshot_sha256` and names a
//! source head. It does not observe the live server version: the adapter
//! proves spawned-artifact identity, listener ownership and server major
//! over its ownership-verified channel at connect time, and only the startup
//! order (gate → connect → re-verify → serve) plus the backend handoff carry
//! that proof to the writer decision.
//!
//! PRODUCER (issue #1932, audit 5856162900 defect 1).
//! [`install_compatibility_decision`] is the production producer of both
//! installation-visible documents: it renders the record, verifies it and the
//! I0.5 evidence snapshot BEFORE either is installed, and installs the pair
//! atomically beside the selected Store config, the evidence snapshot FIRST,
//! so an interruption leaves the pair refusing rather than admitting.
//!
//! What this cell deliberately does NOT do is DECIDE the record or QUALIFY a
//! generation. The party that qualifies a generation must not be the party that
//! consumes the qualification (I0.5: "report wording, test count, trait
//! presence or manual status edit cannot promote support"), so the record and
//! the I0.5 `CurrentSystemEvidenceSnapshot` bytes are supplied by the
//! installation / release owner and this producer only refuses a pair that does
//! not qualify. The owner's remaining steps are:
//!
//! ```text
//! 1. decide the record      — owner-approved; `active_version` is the exact
//!                             `major.minor.patch` from the release lock
//!                             `docs/release/SURREALDB_WINDOWS_X64.lock.json`,
//!                             and `qualified_fallback_*` names the artifact
//!                             that actually qualified;
//! 2. obtain the evidence    — the I0.5 `CurrentSystemEvidenceSnapshot` bytes
//!                             from `eliot-bootstrap`
//!                             (`CurrentSystemEvidenceCompiler::compile`), and
//!                             its `snapshot_sha256` verbatim;
//! 3. install the pair       — run the service binary with
//!                             `ELIOT_STORE_SURREAL_COMPATIBILITY_CONFIG` (the
//!                             Store launch config to bind to),
//!                             `ELIOT_STORE_SURREAL_COMPATIBILITY_RECORD` (the
//!                             owner-decided record) and
//!                             `ELIOT_STORE_SURREAL_COMPATIBILITY_EVIDENCE` (the
//!                             I0.5 snapshot document it cites); `main.rs`
//!                             installs the pair and exits.
//! ```
//!
//! A launch that installs no decision resolves to
//! [`CompatibilityVerdict::Maintenance`] — visible, queryable, and refusing
//! every mutation, which is the fail-closed outcome, but not a writer.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use eliot_store_surreal_adapter::PINNED_SURREALDB_MAJOR;

/// File name of the installation-visible compatibility decision.
pub const COMPATIBILITY_FILE_NAME: &str = "compatibility.toml";

/// File name of the installation-visible I0.5 `CurrentSystemEvidenceSnapshot`
/// that classifies current support, installed beside [`COMPATIBILITY_FILE_NAME`].
///
/// The record's `evidence_snapshot_sha256` is verified against THIS document:
/// a snapshot identifier that is not resolvable to an installed document with
/// the exact recorded content address admits no canonical writer.
pub const EVIDENCE_SNAPSHOT_FILE_NAME: &str = "current-system-evidence-snapshot.json";

/// Only admitted store transport: the remote RPC/WebSocket path.
pub const ADMITTED_TRANSPORT: &str = "ws";

/// Upper bound for a compatibility file read.
const MAX_COMPATIBILITY_BYTES: usize = 64 * 1024;

/// Upper bound for one evidence-snapshot document read. Larger than
/// [`MAX_COMPATIBILITY_BYTES`] because the snapshot is the I0.5 evidence
/// corpus the decision cites, not a decision record, but still a hard bound:
/// an oversized document is refused rather than streamed.
const MAX_EVIDENCE_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

/// Legacy all-zero digest: artifact identity, never a qualification.
const LEGACY_ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Installation-visible compatibility file.
///
/// `Serialize` is the producer half of the SAME shape [`Self`] parses. The
/// emitting and the parsing view are one struct, so a field name or a type can
/// never drift between the document the installation/release owner writes and
/// the document this gate reads. `PartialEq` is what lets that agreement be
/// proved by a round trip rather than asserted.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityFile {
    /// Active `SurrealDB` store decision.
    pub surrealdb: SurrealCompatibility,
}

/// Outcome of verifying a record's I0.5 evidence-snapshot identity against the
/// snapshot document actually installed beside the decision record
/// (I5.9 compatibility gate; I0.5 evidence discipline).
///
/// Only [`Self::Matched`] admits canonical writes. A missing, unreadable,
/// oversized, malformed or differently-addressed document is
/// [`Self::Refused`], never a silent fallback to admitting the record.
///
/// This is NOT state on the record: it is a property of the installation bytes
/// this gate reads, so it is an EXPLICIT argument of [`evaluate_compatibility`]
/// and [`require_compatibility_for_writer`] and is produced by
/// [`load_evidence_snapshot_verification`]. A record parsed from bytes has no
/// verification, so the caller must supply one, and the type signature of every
/// admission path therefore states that qualification is part of the decision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum EvidenceSnapshotVerification {
    /// No snapshot document was resolved for this record. What a caller that
    /// has only record bytes passes when it resolved nothing; it refuses,
    /// because an unverified evidence identity is not a qualification.
    #[default]
    Unresolved,
    /// The installed document states exactly the recorded content address and
    /// names a source head.
    Matched,
    /// The document could not be qualified; the reason names the failure.
    Refused(String),
}

/// Active `SurrealDB` store decision record.
///
/// `Serialize` is derived from this same struct [`parse_compatibility_bytes`]
/// deserializes, for the reason given on [`CompatibilityFile`].
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
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
    /// Exact `major.minor.patch` of the qualified fallback ARTIFACT, which
    /// anchors the fallback line to a qualified generation rather than to a
    /// self-asserted label.
    pub qualified_fallback_version: String,
    /// Lowercase hex SHA-256 of the qualified fallback artifact; the artifact
    /// identity that makes the fallback line a qualification.
    pub qualified_fallback_sha256: String,
    /// Whether the active generation is admitted for canonical writes.
    pub canonical_writes_admitted: bool,
    /// Exact I0.5 `CurrentSystemEvidenceSnapshot.snapshot_sha256` classifying
    /// the admitted generation; never a free-form label.
    pub evidence_snapshot_sha256: String,
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

    /// Returns the bounded machine-readable maintenance reason, when this
    /// verdict is a maintenance one.
    #[must_use]
    pub fn maintenance_reason(&self) -> Option<&str> {
        match self {
            Self::WriterAdmitted { .. } => None,
            Self::Maintenance { reason, .. } => Some(reason),
        }
    }

    /// Combines two startup-stage verdicts of one launch, fail-closed.
    ///
    /// The startup order is gate → connect → re-verify → observed identity, and
    /// each stage observes a strictly stronger fact than the previous one. A
    /// maintenance verdict at ANY stage therefore keeps the installation in
    /// visible non-writer readiness; a later admitted verdict can never
    /// re-admit a writer an earlier stage refused. When both stages are
    /// maintenance the earlier reason is kept, because it names the first
    /// qualification that was missing.
    #[must_use]
    pub fn combine(self, later: Self) -> Self {
        if self.is_writer_admitted() {
            later
        } else {
            self
        }
    }
}

/// Parses and validates one compatibility file's bytes.
///
/// Bytes alone cannot establish an evidence identity, so the returned record
/// carries none: an admission caller must resolve the installed snapshot
/// document through [`load_evidence_snapshot_verification`] and pass the
/// result to [`require_compatibility_for_writer`]. An unresolved qualification
/// never admits a canonical writer.
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

/// Resolves the sibling I0.5 evidence-snapshot path for one Store launch
/// config path, by the same parent-directory rule as
/// [`compatibility_path_for_config`].
#[must_use]
pub fn evidence_snapshot_path_for_config(config_path: &Path) -> Option<PathBuf> {
    config_path
        .parent()
        .map(|parent| parent.join(EVIDENCE_SNAPSHOT_FILE_NAME))
}

/// Loads and validates the sibling compatibility file for one config path.
///
/// A missing or unreadable file is an explicit error: without a recorded
/// qualified decision the installation cannot admit canonical writes.
///
/// This reads the decision record only. The record's `evidence_snapshot_sha256`
/// is resolved separately by [`load_evidence_snapshot_verification`] against the
/// sibling [`EVIDENCE_SNAPSHOT_FILE_NAME`] document, and the resolved outcome is
/// passed explicitly to [`require_compatibility_for_writer`].
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

/// Resolves the observed I0.5 evidence qualification for one loaded record by
/// verifying its `evidence_snapshot_sha256` against the
/// [`EVIDENCE_SNAPSHOT_FILE_NAME`] document installed beside the decision
/// record.
///
/// This is the production source of the explicit
/// [`EvidenceSnapshotVerification`] that admission callers pass to
/// [`require_compatibility_for_writer`]: it is a property of the installation
/// bytes, never a claim the record can make about itself. A failure to qualify
/// is a [`EvidenceSnapshotVerification::Refused`] value, not an error, so the
/// verdict reached from it stays a visible maintenance decision that still
/// reports the exact active version and decision.
#[must_use]
pub fn load_evidence_snapshot_verification(
    config_path: &Path,
    record: &SurrealCompatibility,
) -> EvidenceSnapshotVerification {
    verify_recorded_evidence_snapshot(config_path, &record.evidence_snapshot_sha256)
}

/// The installation-visible identity fields of an I0.5
/// `CurrentSystemEvidenceSnapshot` this gate depends on. Fields the snapshot
/// does not classify support with are not read here: only the content
/// address that names the classification and the source head it was taken at.
#[derive(serde::Deserialize)]
struct EvidenceSnapshotIdentity {
    /// Content address of all other snapshot fields.
    snapshot_sha256: String,
    /// Source projection the classification was taken at.
    selected_source_head: String,
}

/// Verifies the recorded evidence-snapshot identity against the document
/// installed beside the decision record.
///
/// A missing, unreadable or oversized document is an explicit
/// [`EvidenceSnapshotVerification::Refused`] naming the reason; the bytes of an
/// installed document are then qualified by
/// [`verify_evidence_snapshot_bytes`], which is the single validator both this
/// reader and [`install_compatibility_decision`] use.
fn verify_recorded_evidence_snapshot(
    config_path: &Path,
    recorded_digest: &str,
) -> EvidenceSnapshotVerification {
    let Some(path) = evidence_snapshot_path_for_config(config_path) else {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} has no parent directory for the Store config path"
        ));
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} is not installed beside the compatibility decision"
        ));
    };
    if metadata.len() > MAX_EVIDENCE_SNAPSHOT_BYTES as u64 {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} exceeds the bounded size"
        ));
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} is not readable"
        ));
    };
    verify_evidence_snapshot_bytes(&bytes, recorded_digest)
}

/// Qualifies one I0.5 evidence-snapshot DOCUMENT against the record's recorded
/// content address.
///
/// This is the independent source the recorded `evidence_snapshot_sha256` is
/// checked against: the snapshot must parse as JSON, must state EXACTLY the
/// recorded `snapshot_sha256`, and must name a non-blank `selected_source_head`.
/// The record can therefore never qualify itself — a record whose stated
/// address the document does not carry is refused, whoever supplied the bytes.
/// Every other outcome (oversized, malformed, different content address, blank
/// source head) is an explicit [`EvidenceSnapshotVerification::Refused`] naming
/// the reason.
fn verify_evidence_snapshot_bytes(
    bytes: &[u8],
    recorded_digest: &str,
) -> EvidenceSnapshotVerification {
    if bytes.len() > MAX_EVIDENCE_SNAPSHOT_BYTES {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} exceeds the bounded size"
        ));
    }
    let Ok(identity) = serde_json::from_slice::<EvidenceSnapshotIdentity>(bytes) else {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} is not an I0.5 evidence snapshot document"
        ));
    };
    if normalize_digest(&identity.snapshot_sha256) != normalize_digest(recorded_digest) {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} states content address {} which is not the recorded evidence_snapshot_sha256",
            identity.snapshot_sha256
        ));
    }
    if identity.selected_source_head.trim().is_empty() {
        return EvidenceSnapshotVerification::Refused(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} names no selected_source_head"
        ));
    }
    EvidenceSnapshotVerification::Matched
}

/// Installs the installation-visible compatibility decision and the I0.5
/// evidence snapshot it cites beside one Store launch config
/// (issue #1932, audit 5856162900 defect 1).
///
/// This is the production producer of both sibling documents, and it runs the
/// gate's OWN parser and validator on what it is about to install, so the
/// installed record is the same shape and satisfies the same rules as the
/// record this module later reads:
///
/// 1. `record` is rendered with `toml::to_string_pretty` from
///    [`CompatibilityFile`] — the same struct [`parse_compatibility_bytes`]
///    deserializes, so the emitted shape cannot drift from the accepted one;
/// 2. the rendered bytes go back through [`parse_compatibility_bytes`], which
///    runs [`validate_record`] on them, and the parsed record must equal the
///    `record` argument. The ORIGINAL decided record is what is validated, and
///    a render that lost or altered a field refuses instead of installing;
/// 3. the supplied snapshot bytes go through the same
///    [`verify_evidence_snapshot_bytes`] the reader uses, so the pair is
///    qualified against the INDEPENDENT I0.5 document, never against the
///    record's own claim about itself;
/// 4. only then is each document written to a same-directory temporary file and
///    renamed into place, the evidence snapshot FIRST. An interruption between
///    the two renames therefore leaves a decision whose evidence document is
///    absent or differently addressed, which refuses — never a pair that admits.
///
/// The caller is the installation / release owner: it decides the record and
/// obtains the I0.5 snapshot bytes, and this function installs them. It does not
/// decide or qualify a generation, because the party that qualifies a
/// generation must not be the party that consumes the qualification (I0.5
/// evidence discipline).
///
/// Fail-closed: any error above leaves the installation with either no record
/// or the previously installed one, and an unrecorded installation resolves to
/// [`CompatibilityVerdict::Maintenance`], which refuses every canonical write.
pub fn install_compatibility_decision(
    config_path: &Path,
    record: &SurrealCompatibility,
    evidence_snapshot_bytes: &[u8],
) -> Result<(), String> {
    let compatibility_path = compatibility_path_for_config(config_path).ok_or_else(|| {
        format!("{COMPATIBILITY_FILE_NAME} has no parent directory for the Store config path")
    })?;
    let snapshot_path = evidence_snapshot_path_for_config(config_path).ok_or_else(|| {
        format!("{EVIDENCE_SNAPSHOT_FILE_NAME} has no parent directory for the Store config path")
    })?;
    let rendered = toml::to_string_pretty(&CompatibilityFile {
        surrealdb: record.clone(),
    })
    .map_err(|error| format!("render {COMPATIBILITY_FILE_NAME}: {error}"))?;
    // Verify BEFORE install, through the parser this module reads with: the
    // rendered bytes must parse, validate and round-trip to the decided record.
    let round_trip = parse_compatibility_bytes(rendered.as_bytes())?;
    if round_trip.surrealdb != *record {
        return Err(format!(
            "rendered {COMPATIBILITY_FILE_NAME} does not round-trip to the decided record"
        ));
    }
    if let EvidenceSnapshotVerification::Refused(reason) =
        verify_evidence_snapshot_bytes(evidence_snapshot_bytes, &record.evidence_snapshot_sha256)
    {
        return Err(format!(
            "{EVIDENCE_SNAPSHOT_FILE_NAME} is not the recorded qualification: {reason}"
        ));
    }
    // Evidence snapshot FIRST, so an interruption never leaves an admitting
    // record without the document that qualifies it.
    install_document_atomically(&snapshot_path, evidence_snapshot_bytes)?;
    install_document_atomically(&compatibility_path, rendered.as_bytes())
}

/// Installs one document by writing a same-directory temporary file and
/// renaming it into place, so a reader never observes a partial document.
fn install_document_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let directory = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    let staging = directory.join(format!("{name}.new"));
    std::fs::write(&staging, bytes)
        .map_err(|error| format!("write staged {name}: {error}"))?;
    std::fs::rename(&staging, path).map_err(|error| format!("install {name}: {error}"))
}

/// Resolves the installation-visible compatibility decision for one Store
/// config path (issue #1932, I5.9).
///
/// This is the production decision source of the whole bridge: the recorded
/// `compatibility.toml` beside the selected Store config, qualified against the
/// I0.5 evidence snapshot installed beside it and against the
/// installation-approved artifact digest and bridge schema expectation.
///
/// A missing, unreadable or malformed record is an EXPLICIT
/// [`CompatibilityVerdict::Maintenance`] value, not an error: the
/// installation has no qualified decision, so the bridge must come up in
/// visible non-writer readiness and refuse mutations instead of aborting
/// startup before the provider, the readiness surface and the authenticated
/// pipe exist. The verdict therefore always states the exact active version
/// and decision, and the refusal path is
/// [`require_installation_writer`].
#[must_use]
pub fn resolve_compatibility_verdict(
    config_path: &Path,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
) -> CompatibilityVerdict {
    match load_compatibility_for_config(config_path) {
        Ok(file) => {
            // The I0.5 evidence qualification is an observed property of the
            // installed snapshot document, never state of the record.
            let evidence_verification =
                load_evidence_snapshot_verification(config_path, &file.surrealdb);
            evaluate_compatibility(
                &file.surrealdb,
                observed_artifact_digest,
                expected_schema_generation,
                &evidence_verification,
            )
        }
        Err(reason) => unrecorded_maintenance(&reason),
    }
}

/// Enforces the installation-visible decision on the canonical write path.
///
/// Returns the startup-shaped report when the installation's decision admits a
/// canonical writer, and the same report as an explicit refusal otherwise, so a
/// refused mutation is queryable with the exact active version, decision and
/// reason. The refusal is fail-closed for every unrecorded or unqualified
/// record: no qualified generation, no canonical write.
///
/// This is deliberately NOT [`resolve_compatibility_verdict`]: the write path
/// must not admit on a cached verdict. It re-reads the installation-visible
/// record, so a decision record that is rotated, revoked or removed while the
/// process runs stops admitting writers at the next mutation instead of
/// leaving a process-local decision in charge.
pub fn require_installation_writer(
    config_path: &Path,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
) -> Result<String, String> {
    let file =
        load_compatibility_for_config(config_path).map_err(|reason| unrecorded_report(&reason))?;
    let evidence_verification = load_evidence_snapshot_verification(config_path, &file.surrealdb);
    require_compatibility_for_writer(
        &file.surrealdb,
        observed_artifact_digest,
        expected_schema_generation,
        &evidence_verification,
    )
}

/// Binds one recorded decision to the LIVE observed provider identity and
/// returns the resulting verdict (issue #1932, backend handoff §3).
///
/// The provider child has by now been spawned and its artifact identity proved
/// over the ownership-verified channel, so the observed digest is the observed
/// side of the qualification check and record echo alone can never admit: the
/// recorded digest must equal the observed one, and the recorded active
/// version must equal the observed `provider.version`.
///
/// A rotated binary or a drifted record is an explicit
/// [`CompatibilityVerdict::Maintenance`] verdict naming the drift, not a
/// startup abort. The installation stays running and queryable as a non-writer
/// so the operator can observe the exact decision that refused the write.
///
/// The schema generation is compared against the record itself here because
/// this stage runs after the configuration gate, which already compared it
/// against the bridge's configured expectation; the caller combines the two
/// fail-closed, so a schema drift observed there keeps the installation
/// non-writer.
#[must_use]
pub fn observed_identity_verdict(
    record: &SurrealCompatibility,
    observed_version: &str,
    observed_digest: &str,
    evidence_verification: &EvidenceSnapshotVerification,
) -> CompatibilityVerdict {
    let verdict = evaluate_compatibility(
        record,
        observed_digest,
        record.schema_generation.as_str(),
        evidence_verification,
    );
    if !verdict.is_writer_admitted() {
        return verdict;
    }
    match require_observed_identity_match(record, observed_version, observed_digest) {
        Ok(report) => CompatibilityVerdict::WriterAdmitted { report },
        Err(reason) => CompatibilityVerdict::Maintenance {
            report: startup_report(record, "maintenance", &reason, evidence_verification),
            reason,
        },
    }
}

/// Renders the maintenance verdict for an installation that has no readable
/// qualified decision record at all. The report keeps the exact field shape of
/// a recorded decision so one bounded line states `unrecorded` for every absent
/// fact instead of silently reporting an empty or default version.
fn unrecorded_maintenance(reason: &str) -> CompatibilityVerdict {
    CompatibilityVerdict::Maintenance {
        reason: reason.to_owned(),
        report: unrecorded_report(reason),
    }
}

/// Renders the startup-visible report for an installation with no decision
/// record. `detail` is the exact load refusal, so an unrecorded installation
/// still names why no qualified generation is available.
fn unrecorded_report(detail: &str) -> String {
    format!(
        "surrealdb compatibility: active_version=unrecorded transport=unrecorded schema_generation=unrecorded migration_id=unrecorded fallback_line=unrecorded fallback_version=unrecorded canonical_writes=withheld evidence_snapshot=unrecorded evidence_verified=no decision=maintenance detail={detail}"
    )
}

/// Evaluates one validated record against the observed installation state.
///
/// `observed_artifact_digest` is the installation-approved provider binary
/// digest (from the validated runtime launch descriptor); it must exactly
/// equal the recorded digest. `expected_schema_generation` is the bridge's
/// configured schema generation; it must exactly equal the recorded one.
/// `evidence_verification` is the OBSERVED qualification of the record's exact
/// I0.5 evidence-snapshot content address against the snapshot document
/// installed beside it, as resolved by
/// [`load_evidence_snapshot_verification`]. It is an explicit argument rather
/// than state on the record: only the installation bytes can establish it, and
/// any other outcome refuses.
#[must_use]
pub fn evaluate_compatibility(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
    evidence_verification: &EvidenceSnapshotVerification,
) -> CompatibilityVerdict {
    let failure = evaluate_failure(
        record,
        observed_artifact_digest,
        expected_schema_generation,
        evidence_verification,
    );
    let decision = if failure.is_none() {
        "writer-admitted"
    } else {
        "maintenance"
    };
    let report = startup_report(
        record,
        decision,
        failure.as_deref().unwrap_or("admitted"),
        evidence_verification,
    );
    match failure {
        None => CompatibilityVerdict::WriterAdmitted { report },
        Some(reason) => CompatibilityVerdict::Maintenance { reason, report },
    }
}

/// Enforces writer admission: returns the startup report when admitted, or a
/// visible maintenance refusal when the installation must not write.
///
/// `evidence_verification` is the observed I0.5 evidence qualification; see
/// [`evaluate_compatibility`]. Only [`EvidenceSnapshotVerification::Matched`]
/// admits.
pub fn require_compatibility_for_writer(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
    evidence_verification: &EvidenceSnapshotVerification,
) -> Result<String, String> {
    match evaluate_compatibility(
        record,
        observed_artifact_digest,
        expected_schema_generation,
        evidence_verification,
    ) {
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
///
/// The report states `evidence_verified=no`: this binding gate resolves no
/// evidence document and holds no evidence qualification, so it says so
/// literally. The qualification decision itself belongs to
/// [`require_compatibility_for_writer`], which reports it.
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
        &EvidenceSnapshotVerification::Unresolved,
    ))
}

/// Renders the startup-visible report binding the exact active version to its
/// compatibility decision. The line always carries `active_version` and
/// `decision`; it never carries credentials. `evidence_verification` is the
/// observed qualification supplied by the caller, rendered as
/// `evidence_verified=yes` only for [`EvidenceSnapshotVerification::Matched`].
fn startup_report(
    record: &SurrealCompatibility,
    decision: &str,
    detail: &str,
    evidence_verification: &EvidenceSnapshotVerification,
) -> String {
    format!(
        "surrealdb compatibility: active_version={} transport={} schema_generation={} migration_id={} fallback_line={} fallback_version={} canonical_writes={} evidence_snapshot={} evidence_verified={} decision={} detail={}",
        record.active_version,
        record.transport,
        record.schema_generation,
        record.migration_id,
        record.qualified_fallback_line,
        record.qualified_fallback_version,
        if record.canonical_writes_admitted {
            "admitted"
        } else {
            "withheld"
        },
        record.evidence_snapshot_sha256,
        if matches!(evidence_verification, EvidenceSnapshotVerification::Matched) {
            "yes"
        } else {
            "no"
        },
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
///
/// The fallback line is anchored to a qualified ARTIFACT, not to a label: the
/// record must name the exact qualified fallback version and its digest, the
/// version must lie inside the line and equal the active generation, and the
/// two artifacts must be coherent. Requiring equality makes the active store
/// exactly the latest locally qualified fallback: a newer or older fallback
/// means this generation is not the one qualified for canonical writes. The
/// recorded I0.5 evidence-snapshot identity
/// must additionally have been verified against the installed document; that
/// observed qualification is passed in as `evidence_verification`, and an
/// unresolved or refused one is maintenance, never admission.
fn evaluate_failure(
    record: &SurrealCompatibility,
    observed_artifact_digest: &str,
    expected_schema_generation: &str,
    evidence_verification: &EvidenceSnapshotVerification,
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
    if !line_matches_version(
        &record.qualified_fallback_line,
        &record.qualified_fallback_version,
    ) {
        return Some(format!(
            "qualified_fallback_version {} is not the qualified fallback line {}",
            record.qualified_fallback_version, record.qualified_fallback_line
        ));
    }
    match compare_versions(&record.qualified_fallback_version, &record.active_version) {
        None => {
            return Some(format!(
                "qualified_fallback_version {} is not an exact major.minor.patch generation",
                record.qualified_fallback_version
            ));
        }
        Some(Ordering::Less) => {
            return Some(format!(
                "qualified fallback generation {} is older than the admitted generation {}; the latest locally qualified fallback is not the admitted one",
                record.qualified_fallback_version, record.active_version
            ));
        }
        Some(Ordering::Greater) => {
            return Some(format!(
                "active generation {} is older than the latest locally qualified fallback {}; only the latest locally qualified fallback may admit canonical writes",
                record.active_version, record.qualified_fallback_version
            ));
        }
        Some(Ordering::Equal) => {}
    }
    let same_generation = record.qualified_fallback_version == record.active_version;
    let same_artifact = normalize_digest(&record.qualified_fallback_sha256)
        == normalize_digest(&record.artifact_sha256);
    if same_generation != same_artifact {
        return Some(format!(
            "qualified fallback artifact {} does not name the active artifact for generation {}",
            record.qualified_fallback_sha256, record.qualified_fallback_version
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
    match evidence_verification {
        EvidenceSnapshotVerification::Matched => {}
        EvidenceSnapshotVerification::Unresolved => {
            return Some(
                "recorded evidence_snapshot_sha256 was not verified against the installed I0.5 evidence snapshot document"
                    .to_owned(),
            );
        }
        EvidenceSnapshotVerification::Refused(reason) => {
            return Some(format!(
                "recorded evidence_snapshot_sha256 is not qualified: {reason}"
            ));
        }
    }
    None
}

fn validate_record(record: &SurrealCompatibility) -> Result<(), String> {
    validate_version(&record.active_version)?;
    validate_digest(&record.artifact_sha256, "artifact_sha256")?;
    validate_text(&record.transport, "transport")?;
    validate_text(&record.schema_generation, "schema_generation")?;
    validate_text(&record.migration_id, "migration_id")?;
    validate_fallback_line(&record.qualified_fallback_line)?;
    validate_version(&record.qualified_fallback_version)?;
    validate_digest(
        &record.qualified_fallback_sha256,
        "qualified_fallback_sha256",
    )?;
    // A record that does not state the exact I0.5 evidence-snapshot content
    // address is unqualified, not merely unevaluated: a free-form label is
    // audit trail. It is malformed here, and the verdict stays maintenance.
    validate_digest(&record.evidence_snapshot_sha256, "evidence_snapshot_sha256")?;
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
    if !line_matches_version(
        &record.qualified_fallback_line,
        &record.qualified_fallback_version,
    ) {
        return Err(format!(
            "qualified_fallback_version {} is not the qualified fallback line {}",
            record.qualified_fallback_version, record.qualified_fallback_line
        ));
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

/// Orders two validated `major.minor.patch` values, or `None` when either is
/// not exact. Segments are compared as length-then-digits keys, so an
/// oversized numeric segment can never overflow an integer parse on the way to
/// a fail-closed refusal.
fn compare_versions(left: &str, right: &str) -> Option<Ordering> {
    let left_parts: Vec<&str> = left.split('.').collect();
    let right_parts: Vec<&str> = right.split('.').collect();
    if left_parts.len() != 3 || right_parts.len() != 3 {
        return None;
    }
    let mut ordering = Ordering::Equal;
    for (left_part, right_part) in left_parts.iter().zip(right_parts.iter()) {
        let comparison = (left_part.len(), *left_part).cmp(&(right_part.len(), *right_part));
        if comparison != Ordering::Equal && ordering == Ordering::Equal {
            ordering = comparison;
        }
    }
    Some(ordering)
}

/// Rejects any digest that is not a lowercase, non-legacy-zero SHA-256. One
/// validator for every recorded content address: artifact, qualified fallback
/// artifact and I0.5 evidence snapshot.
fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    if value == LEGACY_ZERO_DIGEST {
        return Err(format!("{field} cannot use the legacy zero digest"));
    }
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
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
qualified_fallback_version = "3.1.4"
qualified_fallback_sha256 = "13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1"
canonical_writes_admitted = true
evidence_snapshot_sha256 = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
"#;

    const OBSERVED_DIGEST: &str =
        "13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1";

    /// The exact I0.5 evidence content address this fixture states. A
    /// syntactically valid, semantically inert fixture value: nothing in the
    /// unit-test surface resolves an installed snapshot document against it.
    const EVIDENCE_DIGEST: &str =
        "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

    fn qualified_record() -> SurrealCompatibility {
        parse_compatibility_bytes(QUALIFIED_TOML.as_bytes())
            .expect("qualified fixture parses")
            .surrealdb
    }

    #[test]
    fn startup_reports_exact_active_version_and_decision() {
        let record = qualified_record();
        let verdict = evaluate_compatibility(
            &record,
            OBSERVED_DIGEST,
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
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
        require_compatibility_for_writer(
            &record,
            OBSERVED_DIGEST,
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        )
        .expect("qualified fallback admits writers");
    }

    #[test]
    fn unrecorded_or_unqualified_binary_denies_canonical_writes() {
        let record = qualified_record();
        // Changed binary without a matching qualified decision.
        let rotated = evaluate_compatibility(
            &record,
            &"f".repeat(64),
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
        assert!(!rotated.is_writer_admitted());
        assert!(rotated.report().contains("decision=maintenance"));
        assert!(
            require_compatibility_for_writer(
                &record,
                &"f".repeat(64),
                "2.0.0",
                &EvidenceSnapshotVerification::Matched,
            )
            .is_err()
        );

        // Recorded but explicitly unqualified generation.
        let mut withheld = record.clone();
        withheld.canonical_writes_admitted = false;
        let verdict = evaluate_compatibility(
            &withheld,
            OBSERVED_DIGEST,
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("canonical_writes=withheld"));

        // Admitted flag without evidence is rejected at parse time. The
        // unqualified shape under this record is a record that states no I0.5
        // evidence content address at all, not a free-form label list.
        let evidence_line = format!("evidence_snapshot_sha256 = \"{EVIDENCE_DIGEST}\"");
        let no_evidence =
            QUALIFIED_TOML.replace(evidence_line.as_str(), "evidence_snapshot_sha256 = \"\"");
        assert!(parse_compatibility_bytes(no_evidence.as_bytes()).is_err());
    }

    #[test]
    fn version_change_without_matching_decision_becomes_maintenance() {
        let record = qualified_record();
        // Target-line promotion without qualification is refused: 3.2.x is
        // not inside the qualified 3.1.x fallback line.
        let mut promoted = record.clone();
        promoted.active_version = "3.2.3".to_owned();
        let verdict = evaluate_compatibility(
            &promoted,
            OBSERVED_DIGEST,
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("decision=maintenance"));

        // Schema/migration drift against the bridge expectation is refused.
        let drifted = evaluate_compatibility(
            &record,
            OBSERVED_DIGEST,
            "1.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
        assert!(!drifted.is_writer_admitted());
        assert!(drifted.report().contains("decision=maintenance"));

        // Non-remote transport is refused without silent fallback.
        let mut http = record.clone();
        http.transport = "http".to_owned();
        assert!(
            !evaluate_compatibility(
                &http,
                OBSERVED_DIGEST,
                "2.0.0",
                &EvidenceSnapshotVerification::Matched,
            )
            .is_writer_admitted()
        );
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
        let verdict = evaluate_compatibility(
            &forged,
            OBSERVED_DIGEST,
            "2.0.0",
            &EvidenceSnapshotVerification::Matched,
        );
        assert!(!verdict.is_writer_admitted());
        assert!(verdict.report().contains("decision=maintenance"));
        assert!(
            require_compatibility_for_writer(
                &forged,
                OBSERVED_DIGEST,
                "2.0.0",
                &EvidenceSnapshotVerification::Matched,
            )
            .is_err()
        );

        // A stale-major fallback line is refused even when the active
        // version itself is pinned.
        let mut stale_line = qualified_record();
        stale_line.qualified_fallback_line = "2.1.x".to_owned();
        assert!(
            !evaluate_compatibility(
                &stale_line,
                OBSERVED_DIGEST,
                "2.0.0",
                &EvidenceSnapshotVerification::Matched,
            )
            .is_writer_admitted()
        );

        // The pinned line still admits with fresh matching evidence.
        let record = qualified_record();
        assert!(
            evaluate_compatibility(
                &record,
                OBSERVED_DIGEST,
                "2.0.0",
                &EvidenceSnapshotVerification::Matched,
            )
            .is_writer_admitted()
        );
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
