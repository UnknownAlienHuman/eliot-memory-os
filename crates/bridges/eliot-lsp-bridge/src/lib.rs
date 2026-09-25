//! Instrument Plane Rust semantic-navigation and diagnostics bridge (I10.10).
//!
//! The bridge executes one-shot `rust-analyzer` subcommands (`diagnostics`,
//! `scip`, `--version`) through the shared process layer. Every invocation
//! spawns exactly one process and reconciles it; the bridge keeps no
//! persistent language-server session. A persistent-session profile may only
//! be introduced as a separately measured and admitted profile.
//!
//! Normalized outputs cover definitions, references, symbols, diagnostics,
//! and rename/edit candidates. Every result carries an [`ObservationReceipt`]
//! with exact executable identity/version, configuration hash, candidate
//! reference, invocation time, freshness, coverage, output handles, and
//! failure disposition.
//!
//! Diagnostics are tool observations, never model facts: they are exposed
//! only as [`DiagnosticObservation`] values bound to a receipt, and this
//! crate offers no conversion of observations into pass/fail verdicts.
//! Rename output is an unapplied [`RenameCandidate`]; the bridge never writes
//! to source files. No CodeCortex-private execution path exists in this
//! crate; all launches go through [`LspBridge`] and the shared
//! [`ProcessExecutor`](eliot_process::ProcessExecutor) contract.

#![forbid(unsafe_code)]

mod scip_cache;

pub use scip_cache::{
    CachedProjection, CachedScipItems, ScipIndexerProvenance, ScipProjectionCache,
};

use std::sync::Arc;

use eliot_evidence::{
    AbsenceVerdict, EvidenceCoverage, EvidenceFreshness, UnknownOutcome,
    check_absence_preconditions,
};
use eliot_instrument_scip::ScipIndex;
use eliot_process::{
    CancellationReceipt, ExitDisposition, OperationId, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessRequest,
    ProcessStartReceipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Stable identity of this bridge contract surface.
pub const LSP_BRIDGE_CONTRACT: &str = "eliot.instrument.lsp-bridge";
/// Default executable for both one-shot analyzer paths.
pub const RUST_ANALYZER_EXECUTABLE: &str = "rust-analyzer";
/// Maximum analyzer output stream accepted by the parsers.
pub const MAX_TOOL_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum single analyzer output line accepted by the parsers.
pub const MAX_TOOL_LINE_BYTES: usize = 512 * 1024;
/// Maximum normalized records produced from one tool output.
pub const MAX_NORMALIZED_RECORDS: usize = 10_000;
/// Maximum SCIP sidecar index accepted for decoding.
pub const MAX_SCIP_SIDECAR_BYTES: u64 = 256 * 1024 * 1024;
/// SCIP occurrence role bit marking a definition occurrence.
pub const SCIP_ROLE_DEFINITION: u64 = 0x01;

/// One-shot analyzer path. Both variants invoke terminating subcommands of
/// the configured executable; neither opens a persistent session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnalyzerKind {
    /// `rust-analyzer diagnostics <root>`: one-shot project diagnostics.
    RustAnalyzer,
    /// `rust-analyzer scip <root> --output <file>`: one-shot SCIP emission.
    Scip,
}

impl AnalyzerKind {
    /// Reports whether this analyzer serves the requested operation.
    #[must_use]
    pub const fn supports(self, operation: &SemanticOperation) -> bool {
        match self {
            Self::RustAnalyzer => matches!(
                operation,
                SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion
            ),
            Self::Scip => matches!(
                operation,
                SemanticOperation::Definitions { .. }
                    | SemanticOperation::References { .. }
                    | SemanticOperation::Symbols { .. }
                    | SemanticOperation::Rename { .. }
            ),
        }
    }

    /// Stable subcommand name used by this analyzer path.
    #[must_use]
    pub const fn subcommand(self) -> &'static str {
        match self {
            Self::RustAnalyzer => "diagnostics",
            Self::Scip => "scip",
        }
    }
}

/// Semantic operation requested against a source candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SemanticOperation {
    /// Definition occurrences of an exact SCIP symbol string.
    Definitions {
        /// Exact SCIP symbol string to resolve.
        symbol: String,
    },
    /// Non-definition occurrences of an exact SCIP symbol string.
    References {
        /// Exact SCIP symbol string to resolve.
        symbol: String,
    },
    /// Symbol table entries scoped to a repository-relative path prefix.
    Symbols {
        /// Repository-relative path prefix; empty scopes to the whole index.
        path_scope: String,
    },
    /// One-shot project diagnostics for the candidate workspace.
    Diagnostics,
    /// Unapplied rename edit candidate for an exact SCIP symbol string.
    Rename {
        /// Exact SCIP symbol string to rename.
        symbol: String,
        /// Proposed replacement name; validated as a Rust identifier.
        new_name: String,
    },
    /// Analyzer health/version probe (`--version`).
    ProbeVersion,
}

/// Source candidate under analysis: workspace plus optional file/symbol ref.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceCandidate {
    /// Workspace root directory containing `Cargo.toml` or equivalent.
    pub workspace_root: String,
    /// Optional repository-relative file scoping the request.
    pub path: Option<String>,
    /// Optional exact SCIP symbol string scoping the request.
    pub symbol: Option<String>,
}

impl SourceCandidate {
    /// Validates text shape without touching the filesystem.
    pub fn validate(&self) -> Result<(), BridgeError> {
        checked_text(&self.workspace_root, "workspace_root")?;
        if let Some(path) = &self.path {
            checked_text(path, "path")?;
        }
        if let Some(symbol) = &self.symbol {
            checked_text(symbol, "symbol")?;
        }
        Ok(())
    }

    /// Canonical candidate reference bound into observation receipts.
    #[must_use]
    pub fn reference(&self) -> String {
        format!(
            "{}|{}|{}",
            self.workspace_root,
            self.path.as_deref().unwrap_or("-"),
            self.symbol.as_deref().unwrap_or("-")
        )
    }
}

/// Validated analyzer configuration. The bridge owns no ambient discovery:
/// every field is explicit and enters the configuration hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Exact analyzer executable as invoked (pinning is explicit).
    pub executable: String,
    /// Pass `--disable-build-scripts` to one-shot subcommands.
    pub disable_build_scripts: bool,
    /// Pass `--disable-proc-macros` to one-shot subcommands.
    pub disable_proc_macros: bool,
    /// Minimum severity forwarded to `diagnostics` (`error`, `warning`, ...).
    pub severity_minimum: Option<String>,
    /// Bridge-named SCIP sidecar output path (required for [`AnalyzerKind::Scip`]).
    pub scip_output_path: Option<String>,
}

impl AnalyzerConfig {
    /// Builds a default configuration invoking `rust-analyzer` on `PATH`.
    pub fn for_workspace(executable: impl Into<String>) -> Result<Self, BridgeError> {
        let executable = checked_text_owned(executable.into(), "executable")?;
        Ok(Self {
            executable,
            disable_build_scripts: false,
            disable_proc_macros: false,
            severity_minimum: None,
            scip_output_path: None,
        })
    }

    /// Validates text shape and flag vocabulary.
    pub fn validate(&self) -> Result<(), BridgeError> {
        checked_text(&self.executable, "executable")?;
        if let Some(severity) = &self.severity_minimum {
            checked_text(severity, "severity_minimum")?;
            if !matches!(
                severity.to_ascii_lowercase().as_str(),
                "error" | "warning" | "information" | "hint"
            ) {
                return Err(BridgeError::InvalidConfig(
                    "severity_minimum must be error, warning, information, or hint".to_owned(),
                ));
            }
        }
        if let Some(path) = &self.scip_output_path {
            checked_text(path, "scip_output_path")?;
        }
        Ok(())
    }

    /// Deterministic configuration hash bound into observation receipts.
    #[must_use]
    pub fn config_hash(&self) -> String {
        let canonical = format!(
            "{}\0{}\0{}\0{}\0{}",
            self.executable,
            self.disable_build_scripts,
            self.disable_proc_macros,
            self.severity_minimum.as_deref().unwrap_or("-"),
            self.scip_output_path.as_deref().unwrap_or("-")
        );
        hex_bytes(Sha256::digest(canonical.as_bytes()).as_slice())
    }

    fn diagnostic_flags(&self) -> Vec<String> {
        let mut flags = Vec::new();
        if self.disable_build_scripts {
            flags.push("--disable-build-scripts".to_owned());
        }
        if self.disable_proc_macros {
            flags.push("--disable-proc-macros".to_owned());
        }
        if let Some(severity) = &self.severity_minimum {
            flags.push("--severity".to_owned());
            flags.push(severity.clone());
        }
        flags
    }
}

/// Exact one-shot command projection. Arguments stay separated and are never
/// rendered into a shell command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LspCommand {
    /// Analyzer selected for this invocation.
    pub analyzer: AnalyzerKind,
    /// Exact executable as invoked.
    pub executable: String,
    /// Exact argument vector.
    pub arguments: Vec<String>,
    /// Working directory of the invocation.
    pub working_directory: String,
}

impl LspCommand {
    /// Projects `rust-analyzer --version` for identity/health probing.
    pub fn version(
        config: &AnalyzerConfig,
        candidate: &SourceCandidate,
    ) -> Result<Self, BridgeError> {
        config.validate()?;
        candidate.validate()?;
        Ok(Self {
            analyzer: AnalyzerKind::RustAnalyzer,
            executable: config.executable.clone(),
            arguments: vec!["--version".to_owned()],
            working_directory: candidate.workspace_root.clone(),
        })
    }

    /// Projects `rust-analyzer diagnostics <root> [flags]`.
    pub fn diagnostics(
        config: &AnalyzerConfig,
        candidate: &SourceCandidate,
    ) -> Result<Self, BridgeError> {
        config.validate()?;
        candidate.validate()?;
        let mut arguments = vec![
            AnalyzerKind::RustAnalyzer.subcommand().to_owned(),
            candidate.workspace_root.clone(),
        ];
        arguments.extend(config.diagnostic_flags());
        Ok(Self {
            analyzer: AnalyzerKind::RustAnalyzer,
            executable: config.executable.clone(),
            arguments,
            working_directory: candidate.workspace_root.clone(),
        })
    }

    /// Projects `rust-analyzer scip <root> --output <sidecar> [flags]`.
    pub fn scip(config: &AnalyzerConfig, candidate: &SourceCandidate) -> Result<Self, BridgeError> {
        config.validate()?;
        candidate.validate()?;
        let sidecar = config
            .scip_output_path
            .clone()
            .ok_or(BridgeError::MissingScipOutput)?;
        let mut arguments = vec![
            AnalyzerKind::Scip.subcommand().to_owned(),
            candidate.workspace_root.clone(),
            "--output".to_owned(),
            sidecar,
        ];
        if config.disable_build_scripts {
            arguments.push("--disable-build-scripts".to_owned());
        }
        if config.disable_proc_macros {
            arguments.push("--disable-proc-macros".to_owned());
        }
        Ok(Self {
            analyzer: AnalyzerKind::Scip,
            executable: config.executable.clone(),
            arguments,
            working_directory: candidate.workspace_root.clone(),
        })
    }

    /// Checks that a caller-owned process request is exactly this projection.
    #[must_use]
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable().eq_ignore_ascii_case(&self.executable)
            && request.working_directory() == self.working_directory
            && request.argv() == self.arguments
    }
}

/// Normalized definition location (SCIP coordinates are zero-based).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Definition {
    /// Exact SCIP symbol string.
    pub symbol: String,
    /// Repository-relative document path.
    pub path: String,
    /// Zero-based line.
    pub line: u32,
    /// Zero-based column.
    pub column: u32,
}

/// Normalized reference location (SCIP coordinates are zero-based).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    /// Exact SCIP symbol string.
    pub symbol: String,
    /// Repository-relative document path.
    pub path: String,
    /// Zero-based line.
    pub line: u32,
    /// Zero-based column.
    pub column: u32,
}

/// Normalized symbol-table entry projected from a SCIP index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// Exact SCIP symbol string.
    pub symbol: String,
    /// Display name recorded by the indexer, when present.
    pub display_name: Option<String>,
    /// Opaque SCIP symbol kind recorded by the indexer.
    pub kind: u64,
}

/// Normalized diagnostic severity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticSeverity {
    /// Compiler or analyzer error.
    Error,
    /// Compiler or analyzer warning.
    Warning,
    /// Informational note.
    Information,
    /// Hint or suggestion.
    Hint,
    /// Unrecognized severity token; the observation is preserved anyway.
    Unknown,
}

/// A single diagnostic as a tool observation.
///
/// Values of this type are evidence about one analyzer run. They are not
/// model facts and must not be converted into verification verdicts; this
/// crate provides no such conversion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticObservation {
    /// File path as reported by the analyzer.
    pub file: String,
    /// Normalized severity.
    pub severity: DiagnosticSeverity,
    /// Analyzer diagnostic code (for example `E0308`), or `unknown`.
    pub code: String,
    /// Zero-based start line.
    pub line: u32,
    /// Zero-based start column.
    pub column: u32,
    /// Zero-based end line.
    pub end_line: u32,
    /// Zero-based end column.
    pub end_column: u32,
    /// Analyzer message text.
    pub message: String,
}

impl DiagnosticObservation {
    /// States the observation-only contract for consumers.
    #[must_use]
    pub const fn observation_note() -> &'static str {
        "tool observation only: exact executable, config, candidate, freshness, and coverage are on the attached receipt; not a model fact"
    }
}

/// One anchor-only text edit of a rename candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextEdit {
    /// Repository-relative document path.
    pub path: String,
    /// Zero-based anchor line.
    pub line: u32,
    /// Zero-based anchor column.
    pub column: u32,
    /// Range end; equals the anchor because one-shot SCIP occurrences carry
    /// start positions only. Applying requires LSP range resolution.
    pub end_line: u32,
    /// Range end column; equals the anchor (see [`TextEdit::line`]).
    pub end_column: u32,
    /// Replacement text.
    pub replacement: String,
}

/// Rename output as an explicitly unapplied edit candidate.
///
/// The bridge never writes to source files; `applied` is always `false`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenameCandidate {
    /// Exact SCIP symbol string the candidate renames.
    pub symbol: String,
    /// Proposed replacement name.
    pub new_name: String,
    /// Anchor-only edits, one per definition/reference occurrence.
    pub edits: Vec<TextEdit>,
    /// Always `false`: the bridge applies nothing.
    pub applied: bool,
}

impl RenameCandidate {
    /// Reports that this candidate was not applied to any file.
    #[must_use]
    pub const fn is_unapplied(&self) -> bool {
        !self.applied
    }
}

/// Freshness of a normalized result relative to its tool invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Freshness {
    /// The tool completed and its full output was normalized.
    Current,
    /// The result must not be treated as current; the reason is recorded.
    Stale {
        /// Why the result is stale (incomplete run, truncation, ...).
        reason: String,
    },
}

/// Declared coverage scope of a normalized result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Coverage {
    /// The analyzer scanned the whole workspace root.
    Workspace {
        /// Workspace root that was scanned.
        root: String,
    },
    /// Symbols were projected under one path scope of the index.
    SymbolSubset {
        /// Path scope applied to the index.
        path_scope: String,
    },
    /// Definitions, references, or rename anchors for one symbol.
    SingleSymbol {
        /// Exact SCIP symbol string covered.
        symbol: String,
    },
    /// Version/health probe only; no source was analyzed.
    ProbeOnly,
}

/// Failure disposition carried by every observation receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureDisposition {
    /// The tool completed and its output normalized cleanly.
    Success,
    /// The tool run did not complete; the exit code is preserved when known.
    ToolFailed {
        /// Process exit code when observed.
        exit_code: Option<i32>,
    },
    /// Tool output exceeded a bound and was truncated before normalization.
    OutputTruncated,
    /// Tool output could not be normalized; the detail is preserved.
    ParseFailed {
        /// Stable parse-failure detail.
        detail: String,
    },
    /// The requested operation is not served by the selected analyzer.
    UnsupportedOperation,
}

/// Observation receipt attached to every normalized result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReceipt {
    /// Exact analyzer executable as invoked.
    pub executable: String,
    /// Analyzer version text from the identity probe, when available.
    pub executable_version: Option<String>,
    /// Deterministic hash of the analyzer configuration.
    pub config_hash: String,
    /// Canonical candidate reference (`workspace|path|symbol`).
    pub candidate: String,
    /// Invocation time as Unix milliseconds, supplied by the caller.
    pub invoked_at_unix_ms: u64,
    /// Freshness of the result.
    pub freshness: Freshness,
    /// Declared coverage scope.
    pub coverage: Coverage,
    /// Output handles (`<stream>:sha256:<hex>:<bytes>B` or sidecar handles).
    pub output_handles: Vec<String>,
    /// Observed tool exit code, when the reconciled view carries one.
    pub tool_exit_code: Option<i32>,
    /// Failure disposition of the run.
    pub disposition: FailureDisposition,
}

impl ObservationReceipt {
    /// Assembles a receipt from exact run evidence. Freshness and the success
    /// dispositions derive deterministically from completion and truncation;
    /// parse failures are reported by the `finalize_*` constructors.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn assemble(
        executable: &str,
        executable_version: Option<String>,
        config_hash: &str,
        candidate: &str,
        invoked_at_unix_ms: u64,
        coverage: Coverage,
        output_handles: Vec<String>,
        exit_code: Option<i32>,
        completed: bool,
        truncated: bool,
    ) -> Self {
        let (freshness, disposition) = if !completed {
            (
                Freshness::Stale {
                    reason: "tool run did not complete".to_owned(),
                },
                FailureDisposition::ToolFailed { exit_code },
            )
        } else if truncated {
            (
                Freshness::Stale {
                    reason: "tool output exceeded the bounded capture limit".to_owned(),
                },
                FailureDisposition::OutputTruncated,
            )
        } else {
            (Freshness::Current, FailureDisposition::Success)
        };
        Self {
            executable: executable.to_owned(),
            executable_version,
            config_hash: config_hash.to_owned(),
            candidate: candidate.to_owned(),
            invoked_at_unix_ms,
            freshness,
            coverage,
            output_handles,
            tool_exit_code: exit_code,
            disposition,
        }
    }
}

/// Normalized bridge result. Diagnostics appear only as observations;
/// rename output appears only as an unapplied candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizedResult {
    /// Definition locations for one symbol.
    Definitions {
        /// Normalized definition locations.
        items: Vec<Definition>,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
    /// Reference locations for one symbol.
    References {
        /// Normalized reference locations.
        items: Vec<Reference>,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
    /// Symbol-table entries under one path scope.
    Symbols {
        /// Normalized symbol entries.
        items: Vec<SymbolInfo>,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
    /// Diagnostics as tool observations with their receipt.
    Diagnostics {
        /// Tool observations; not model facts.
        observations: Vec<DiagnosticObservation>,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
    /// Rename output as an unapplied edit candidate with its receipt.
    Rename {
        /// Unapplied edit candidate; never applied by the bridge.
        candidate: RenameCandidate,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
    /// Analyzer identity probe result with its receipt.
    Version {
        /// Raw analyzer version line.
        version: String,
        /// Observation receipt for the run.
        receipt: ObservationReceipt,
    },
}

impl NormalizedResult {
    /// Returns the observation receipt attached to this result.
    #[must_use]
    pub const fn receipt(&self) -> &ObservationReceipt {
        match self {
            Self::Definitions { receipt, .. }
            | Self::References { receipt, .. }
            | Self::Symbols { receipt, .. }
            | Self::Diagnostics { receipt, .. }
            | Self::Rename { receipt, .. }
            | Self::Version { receipt, .. } => receipt,
        }
    }

    /// Classifies this result's lookup through the I10.8.6 absence gate.
    ///
    /// `scope_complete_for_query` attests that the receipt's declared scope
    /// covers the query (a subset listing answers only its own scope, never
    /// the workspace). `exact_candidate_binding` attests that the analyzed
    /// index is bound to the exact candidate and scope under evaluation; the
    /// receipt alone never proves that binding. The bridge tracks no
    /// counterevidence, so contradiction is always unattested here and
    /// downstream disagreement handling (I10.8.19) owns it instead.
    #[must_use]
    pub fn lookup_outcome(
        &self,
        scope_complete_for_query: bool,
        exact_candidate_binding: bool,
    ) -> LookupOutcome {
        let found_any = match self {
            Self::Definitions { items, .. } => !items.is_empty(),
            Self::References { items, .. } => !items.is_empty(),
            Self::Symbols { items, .. } => !items.is_empty(),
            Self::Diagnostics { observations, .. } => !observations.is_empty(),
            Self::Rename { candidate, .. } => !candidate.edits.is_empty(),
            Self::Version { version, .. } => !version.is_empty(),
        };
        classify_lookup(
            self.receipt(),
            LookupClassification {
                scope_complete_for_query,
                found_any,
                exact_candidate_binding,
                contradicted_by_higher_authority: false,
            },
        )
    }
}

/// Lookup outcome classified from an observation receipt (I10.8.6).
///
/// An empty lookup is `ProvenAbsent` only when the receipt records a
/// complete run over a complete scope with an exact candidate binding;
/// every other empty lookup is a typed [`UnknownOutcome`] or
/// [`LookupOutcome::Contradicted`], never "not found".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupOutcome {
    /// The lookup returned items. They are observations, never absence
    /// proof, and their receipt still bounds their use.
    Found,
    /// The empty lookup proves absence for the queried scope.
    ProvenAbsent,
    /// The empty lookup cannot prove absence; absence is this typed
    /// unknown and must not be treated as proof.
    Unknown(UnknownOutcome),
    /// Higher-authority evidence contradicts the absence; the claim is
    /// contested rather than unknown.
    Contradicted,
}

/// Caller attestations for one lookup classification.
///
/// The receipt records what the run observed; these flags record what the
/// caller has established about the query: whether the receipt's declared
/// scope covers it, whether the lookup returned anything, whether the
/// analyzed index is bound to the exact candidate and scope, and whether
/// higher-authority evidence contradicts the absence.
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent caller attestations; an enum per flag would quadruple the vocabulary for one call"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupClassification {
    /// The receipt's declared scope covers the query.
    pub scope_complete_for_query: bool,
    /// The lookup returned at least one item.
    pub found_any: bool,
    /// The analyzed index is bound to the exact candidate and scope.
    pub exact_candidate_binding: bool,
    /// Higher-authority evidence contradicts the absence.
    pub contradicted_by_higher_authority: bool,
}

/// Classifies one lookup from its observation receipt.
///
/// A run that failed, truncated, or did not normalize reports
/// [`UnknownOutcome::UnknownDueToTruncationOrToolFailure`] even though the
/// receipt also records stale freshness: the disposition names the root
/// cause while staleness is its derived symptom. A merely current run is
/// still freshness-unknown for absence until the caller attests the exact
/// candidate binding, because run currency never proves candidate identity.
#[must_use]
pub fn classify_lookup(
    receipt: &ObservationReceipt,
    classification: LookupClassification,
) -> LookupOutcome {
    if classification.found_any {
        return LookupOutcome::Found;
    }
    let absence_capability = match receipt.disposition {
        FailureDisposition::Success => Ok(()),
        FailureDisposition::ToolFailed { .. }
        | FailureDisposition::OutputTruncated
        | FailureDisposition::ParseFailed { .. }
        | FailureDisposition::UnsupportedOperation => {
            Err(UnknownOutcome::UnknownDueToTruncationOrToolFailure)
        }
    };
    let freshness = match receipt.freshness {
        Freshness::Current if classification.exact_candidate_binding => {
            EvidenceFreshness::ExactCandidate
        }
        Freshness::Current => EvidenceFreshness::Unknown,
        Freshness::Stale { .. } => EvidenceFreshness::Stale,
    };
    let coverage = match receipt.coverage {
        Coverage::ProbeOnly => EvidenceCoverage::Unknown,
        _ if !classification.scope_complete_for_query => EvidenceCoverage::PartialForScope,
        _ => EvidenceCoverage::CompleteForScope,
    };
    match check_absence_preconditions(
        freshness,
        coverage,
        absence_capability,
        classification.contradicted_by_higher_authority,
    ) {
        AbsenceVerdict::Admitted => LookupOutcome::ProvenAbsent,
        AbsenceVerdict::Unknown(outcome) => LookupOutcome::Unknown(outcome),
        AbsenceVerdict::Contested => LookupOutcome::Contradicted,
    }
}

/// Parses `rust-analyzer --version` output into the raw version line.
pub fn parse_version_output(bytes: &[u8]) -> Result<String, BridgeError> {
    if bytes.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(BridgeError::OutputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BridgeError::MalformedVersion)?;
    for line in text.lines() {
        let line = line.trim().trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("rust-analyzer ") {
            checked_text(rest, "version")?;
            return Ok(line.to_owned());
        }
        return Err(BridgeError::MalformedVersion);
    }
    Err(BridgeError::MalformedVersion)
}

/// Parses one-shot `rust-analyzer diagnostics` output into observations.
///
/// Progress noise is skipped line by line; a clean scan with no diagnostic
/// lines is a valid empty result (tool failure travels on the receipt
/// disposition, never as a parse error).
pub fn parse_diagnostics_output(bytes: &[u8]) -> Result<Vec<DiagnosticObservation>, BridgeError> {
    if bytes.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err(BridgeError::OutputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| BridgeError::MalformedDiagnostics)?;
    let mut observations = Vec::new();
    for raw in text.split('\n') {
        if raw.len() > MAX_TOOL_LINE_BYTES {
            return Err(BridgeError::DiagnosticTooLarge);
        }
        let Some(start) = raw.find("at crate ") else {
            continue;
        };
        let line = &raw[start..];
        let Some(observation) = parse_diagnostic_line(line) else {
            continue;
        };
        if observations.len() >= MAX_NORMALIZED_RECORDS {
            return Err(BridgeError::TooManyRecords);
        }
        observations.push(observation);
    }
    Ok(observations)
}

fn parse_diagnostic_line(line: &str) -> Option<DiagnosticObservation> {
    // Shape: `at crate <c>, file <path>: <Sev> <code...>
    //   from LineCol { line: A, col: B } to LineCol { line: C, col: D }: <msg>`
    let after_crate = line.strip_prefix("at crate ")?;
    let (_crate_name, rest) = after_crate.split_once(", file ")?;
    let (path, rest) = rest.split_once(": ")?;
    if path.trim().is_empty() || path.chars().any(char::is_control) {
        return None;
    }
    let rest = rest.trim_start();
    let (severity_token, mut rest) = rest.split_once(char::is_whitespace)?;
    let severity = match severity_token {
        "Error" | "error" => DiagnosticSeverity::Error,
        "Warning" | "warning" => DiagnosticSeverity::Warning,
        "Note" | "note" | "Information" => DiagnosticSeverity::Information,
        "Help" | "help" | "Hint" => DiagnosticSeverity::Hint,
        _ => DiagnosticSeverity::Unknown,
    };
    rest = rest.trim_start();
    let code = first_quoted(rest).unwrap_or("unknown").to_owned();
    let from_marker = rest.find("from LineCol")?;
    let from = &rest[from_marker..];
    let (line_no, column) = line_col(from)?;
    let to_marker = from.find("to LineCol")?;
    let (end_line, end_column) = line_col(&from[to_marker..])?;
    let message_marker = from[to_marker..].find("}: ")?;
    let message = from[to_marker..][message_marker + 3..].trim();
    if message.is_empty() || message.chars().any(char::is_control) {
        return None;
    }
    Some(DiagnosticObservation {
        file: path.to_owned(),
        severity,
        code,
        line: line_no,
        column,
        end_line,
        end_column,
        message: message.to_owned(),
    })
}

fn first_quoted(text: &str) -> Option<&str> {
    let start = text.find('"')?;
    let end = text[start + 1..].find('"')?;
    let value = &text[start + 1..start + 1 + end];
    if value.is_empty() || value.chars().any(char::is_control) {
        None
    } else {
        Some(value)
    }
}

fn line_col(text: &str) -> Option<(u32, u32)> {
    let line_marker = text.find("line:")?;
    let after_line = text[line_marker + "line:".len()..].trim_start();
    let line_digits: String = after_line.chars().take_while(|c| c.is_numeric()).collect();
    let col_marker = after_line.find("col:")?;
    let after_col = after_line[col_marker + "col:".len()..].trim_start();
    let col_digits: String = after_col.chars().take_while(|c| c.is_numeric()).collect();
    Some((line_digits.parse().ok()?, col_digits.parse().ok()?))
}

/// Projects definition locations for one exact symbol from a SCIP index.
pub fn project_definitions(
    index: &ScipIndex,
    symbol: &str,
) -> Result<Vec<Definition>, BridgeError> {
    checked_text(symbol, "symbol")?;
    let mut items = Vec::new();
    for document in &index.documents {
        for occurrence in &document.occurrences {
            if occurrence.symbol == symbol && occurrence.roles & SCIP_ROLE_DEFINITION != 0 {
                if items.len() >= MAX_NORMALIZED_RECORDS {
                    return Err(BridgeError::TooManyRecords);
                }
                items.push(Definition {
                    symbol: symbol.to_owned(),
                    path: document.relative_path.clone(),
                    line: occurrence.line,
                    column: occurrence.column,
                });
            }
        }
    }
    Ok(items)
}

/// Projects reference (non-definition) locations for one exact symbol.
pub fn project_references(index: &ScipIndex, symbol: &str) -> Result<Vec<Reference>, BridgeError> {
    checked_text(symbol, "symbol")?;
    let mut items = Vec::new();
    for document in &index.documents {
        for occurrence in &document.occurrences {
            if occurrence.symbol == symbol && occurrence.roles & SCIP_ROLE_DEFINITION == 0 {
                if items.len() >= MAX_NORMALIZED_RECORDS {
                    return Err(BridgeError::TooManyRecords);
                }
                items.push(Reference {
                    symbol: symbol.to_owned(),
                    path: document.relative_path.clone(),
                    line: occurrence.line,
                    column: occurrence.column,
                });
            }
        }
    }
    Ok(items)
}

/// Projects symbol-table entries whose repository-relative path starts with
/// `path_scope` (empty scope selects the whole index).
pub fn project_symbols(
    index: &ScipIndex,
    path_scope: &str,
) -> Result<Vec<SymbolInfo>, BridgeError> {
    if !path_scope.is_empty() {
        checked_text(path_scope, "path_scope")?;
    }
    let mut items = Vec::new();
    for document in &index.documents {
        if !path_scope.is_empty() && !document.relative_path.starts_with(path_scope) {
            continue;
        }
        for symbol in &document.symbols {
            let mentioned = document
                .occurrences
                .iter()
                .any(|occurrence| occurrence.symbol == symbol.symbol);
            if mentioned {
                if items.len() >= MAX_NORMALIZED_RECORDS {
                    return Err(BridgeError::TooManyRecords);
                }
                items.push(SymbolInfo {
                    symbol: symbol.symbol.clone(),
                    display_name: symbol.display_name.clone(),
                    kind: symbol.kind,
                });
            }
        }
    }
    items.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    items.dedup_by(|right, left| left.symbol == right.symbol);
    Ok(items)
}

/// Builds an unapplied rename candidate from every occurrence of `symbol`.
///
/// Occurrence anchors are start positions only, so edits are anchor-only:
/// applying them requires LSP range resolution, which the bridge never
/// performs. The returned candidate is always unapplied.
pub fn rename_candidate(
    index: &ScipIndex,
    symbol: &str,
    new_name: &str,
) -> Result<RenameCandidate, BridgeError> {
    checked_text(symbol, "symbol")?;
    checked_identifier(new_name)?;
    let mut edits = Vec::new();
    for document in &index.documents {
        for occurrence in &document.occurrences {
            if occurrence.symbol == symbol {
                if edits.len() >= MAX_NORMALIZED_RECORDS {
                    return Err(BridgeError::TooManyRecords);
                }
                edits.push(TextEdit {
                    path: document.relative_path.clone(),
                    line: occurrence.line,
                    column: occurrence.column,
                    end_line: occurrence.line,
                    end_column: occurrence.column,
                    replacement: new_name.to_owned(),
                });
            }
        }
    }
    Ok(RenameCandidate {
        symbol: symbol.to_owned(),
        new_name: new_name.to_owned(),
        edits,
        applied: false,
    })
}

/// Reads a bridge-named SCIP sidecar index with a byte bound.
///
/// The size pre-check rejects obviously oversized sidecars early; the bound
/// is enforced again after the read so a sidecar that grows mid-read still
/// cannot pass an over-limit payload to the decoder.
pub fn read_scip_sidecar(path: &str) -> Result<Vec<u8>, BridgeError> {
    checked_text(path, "scip_output_path")?;
    let metadata = std::fs::metadata(path).map_err(|error| BridgeError::SidecarUnreadable {
        detail: error.to_string(),
    })?;
    if metadata.len() > MAX_SCIP_SIDECAR_BYTES {
        return Err(BridgeError::OutputTooLarge);
    }
    let bytes = std::fs::read(path).map_err(|error| BridgeError::SidecarUnreadable {
        detail: error.to_string(),
    })?;
    if bytes.len() as u64 > MAX_SCIP_SIDECAR_BYTES {
        return Err(BridgeError::OutputTooLarge);
    }
    Ok(bytes)
}

/// Builds a stable output handle for a captured stream.
#[must_use]
pub fn stream_handle(stream: &str, bytes: &[u8]) -> String {
    format!(
        "{stream}:sha256:{}:{}B",
        hex_bytes(Sha256::digest(bytes).as_slice()),
        bytes.len()
    )
}

/// Builds a stable output handle for a SCIP sidecar file.
#[must_use]
pub fn sidecar_handle(path: &str, bytes: &[u8]) -> String {
    format!(
        "scip:{path}:sha256:{}:{}B",
        hex_bytes(Sha256::digest(bytes).as_slice()),
        bytes.len()
    )
}

/// Maps a normalization failure to receipt freshness and disposition.
///
/// Bound-exceeded input is truncation (the tool emitted more than the bridge
/// normalizes), never a parse failure; only genuinely malformed input is
/// `ParseFailed`. The detail of a bound-exceeded run is the stable truncation
/// reason, so consumers can rely on the disposition discriminant.
fn normalize_failure(reason: &str, error: &BridgeError) -> (Freshness, FailureDisposition) {
    if matches!(
        error,
        BridgeError::OutputTooLarge | BridgeError::DiagnosticTooLarge | BridgeError::TooManyRecords
    ) {
        (
            Freshness::Stale {
                reason: "tool output exceeded the bounded capture limit".to_owned(),
            },
            FailureDisposition::OutputTruncated,
        )
    } else {
        (
            Freshness::Stale {
                reason: reason.to_owned(),
            },
            FailureDisposition::ParseFailed {
                detail: error.to_string(),
            },
        )
    }
}

/// Builds the shape-correct empty result for an operation whose SCIP input
/// could not be served or normalized. Failure travels on the receipt; the
/// envelope always matches the requested operation.
fn empty_scip_result(
    operation: &SemanticOperation,
    receipt: ObservationReceipt,
) -> NormalizedResult {
    match operation {
        SemanticOperation::Definitions { .. } => NormalizedResult::Definitions {
            items: Vec::new(),
            receipt,
        },
        SemanticOperation::References { .. } => NormalizedResult::References {
            items: Vec::new(),
            receipt,
        },
        SemanticOperation::Symbols { .. } => NormalizedResult::Symbols {
            items: Vec::new(),
            receipt,
        },
        SemanticOperation::Diagnostics => NormalizedResult::Diagnostics {
            observations: Vec::new(),
            receipt,
        },
        SemanticOperation::Rename { symbol, new_name } => NormalizedResult::Rename {
            candidate: RenameCandidate {
                symbol: symbol.clone(),
                new_name: new_name.clone(),
                edits: Vec::new(),
                applied: false,
            },
            receipt,
        },
        SemanticOperation::ProbeVersion => NormalizedResult::Version {
            version: String::new(),
            receipt,
        },
    }
}

/// Finalizes one-shot diagnostics evidence into observations plus receipt.
///
/// Tool failure travels on the receipt disposition; unparseable output
/// yields an empty observation set with a `ParseFailed` disposition so that
/// every result still carries its exact identity, config, candidate,
/// freshness, coverage, and handles.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn finalize_diagnostics(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    executable_version: Option<&str>,
    stdout: &[u8],
    truncated: bool,
    exit_code: Option<i32>,
    completed: bool,
    invoked_at_unix_ms: u64,
) -> NormalizedResult {
    let coverage = Coverage::Workspace {
        root: candidate.workspace_root.clone(),
    };
    let receipt_base = || {
        ObservationReceipt::assemble(
            &config.executable,
            executable_version.map(str::to_owned),
            &config.config_hash(),
            &candidate.reference(),
            invoked_at_unix_ms,
            coverage.clone(),
            vec![stream_handle("stdout", stdout)],
            exit_code,
            completed,
            truncated,
        )
    };
    if !completed || truncated {
        return NormalizedResult::Diagnostics {
            observations: Vec::new(),
            receipt: receipt_base(),
        };
    }
    match parse_diagnostics_output(stdout) {
        Ok(observations) => NormalizedResult::Diagnostics {
            observations,
            receipt: receipt_base(),
        },
        Err(error) => {
            let mut receipt = receipt_base();
            let (freshness, disposition) =
                normalize_failure("diagnostics output did not normalize", &error);
            receipt.disposition = disposition;
            receipt.freshness = freshness;
            NormalizedResult::Diagnostics {
                observations: Vec::new(),
                receipt,
            }
        }
    }
}

/// Finalizes a version-probe run into its normalized result.
#[must_use]
pub fn finalize_version(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    stdout: &[u8],
    truncated: bool,
    exit_code: Option<i32>,
    completed: bool,
    invoked_at_unix_ms: u64,
) -> NormalizedResult {
    let mut receipt = ObservationReceipt::assemble(
        &config.executable,
        None,
        &config.config_hash(),
        &candidate.reference(),
        invoked_at_unix_ms,
        Coverage::ProbeOnly,
        vec![stream_handle("stdout", stdout)],
        exit_code,
        completed,
        truncated,
    );
    if !completed || truncated {
        return NormalizedResult::Version {
            version: String::new(),
            receipt,
        };
    }
    match parse_version_output(stdout) {
        Ok(version) => {
            receipt.executable_version = Some(version.clone());
            NormalizedResult::Version { version, receipt }
        }
        Err(error) => {
            let (freshness, disposition) =
                normalize_failure("version output did not normalize", &error);
            receipt.disposition = disposition;
            receipt.freshness = freshness;
            NormalizedResult::Version {
                version: String::new(),
                receipt,
            }
        }
    }
}

/// Projects one SCIP-served operation into cacheable typed items.
///
/// Shared by the cached `finalize_scip` path; the legacy uncached path keeps
/// its inline arms untouched for review. Diagnostics and version probes never
/// reach here (they return before any decode).
fn project_cached_items(
    index: &ScipIndex,
    operation: &SemanticOperation,
) -> Result<CachedScipItems, BridgeError> {
    match operation {
        SemanticOperation::Definitions { symbol } => Ok(CachedScipItems::Definitions(
            project_definitions(index, symbol)?,
        )),
        SemanticOperation::References { symbol } => Ok(CachedScipItems::References(
            project_references(index, symbol)?,
        )),
        SemanticOperation::Symbols { path_scope } => Ok(CachedScipItems::Symbols(project_symbols(
            index, path_scope,
        )?)),
        SemanticOperation::Rename { symbol, new_name } => Ok(CachedScipItems::Rename(
            rename_candidate(index, symbol, new_name)?,
        )),
        SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => {
            Err(BridgeError::UnsupportedOperation)
        }
    }
}

/// Wraps cached items with a freshly assembled receipt.
///
/// The operation is bound into the cache key, so a variant mismatch is
/// unreachable in practice; it still fails closed with a parse-failed
/// receipt instead of inventing items.
fn wrap_cached_items(
    operation: &SemanticOperation,
    items: CachedScipItems,
    receipt: ObservationReceipt,
) -> NormalizedResult {
    match (operation, items) {
        (SemanticOperation::Definitions { .. }, CachedScipItems::Definitions(items)) => {
            NormalizedResult::Definitions { items, receipt }
        }
        (SemanticOperation::References { .. }, CachedScipItems::References(items)) => {
            NormalizedResult::References { items, receipt }
        }
        (SemanticOperation::Symbols { .. }, CachedScipItems::Symbols(items)) => {
            NormalizedResult::Symbols { items, receipt }
        }
        (SemanticOperation::Rename { .. }, CachedScipItems::Rename(candidate)) => {
            NormalizedResult::Rename { candidate, receipt }
        }
        (_, _) => {
            let mut receipt = receipt;
            let (freshness, disposition) = normalize_failure(
                "cached projection mismatched its operation",
                &BridgeError::ScipDecode("cached projection mismatched its operation".to_owned()),
            );
            receipt.freshness = freshness;
            receipt.disposition = disposition;
            empty_scip_result(operation, receipt)
        }
    }
}

/// Finalizes decoded SCIP bytes into definitions, references, symbols, or a
/// rename candidate plus receipt. `operation` must be SCIP-served.
///
/// When `cache` is `None`, the call decodes and projects exactly as before
/// (no behavior change). When `Some`, the call consults the derived
/// projection cache first: a verified hit skips decode and projection and
/// returns cached items with a freshly assembled receipt, while any miss or
/// invalid entry runs the genuine derivation. Failures are never cached, and
/// a hit never carries a verdict — this subsystem cannot express one.
#[allow(
    clippy::too_many_lines,
    reason = "operation dispatch is exhaustive and each arm pairs one projection with its receipt; splitting would separate results from their evidence"
)]
#[must_use]
pub fn finalize_scip(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
    index_bytes: &[u8],
    sidecar_path: &str,
    invoked_at_unix_ms: u64,
    cache: Option<&mut ScipProjectionCache>,
) -> NormalizedResult {
    let coverage = match operation {
        SemanticOperation::Definitions { symbol }
        | SemanticOperation::References { symbol }
        | SemanticOperation::Rename { symbol, .. } => Coverage::SingleSymbol {
            symbol: symbol.clone(),
        },
        SemanticOperation::Symbols { path_scope } => Coverage::SymbolSubset {
            path_scope: path_scope.clone(),
        },
        SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => {
            let mut receipt = ObservationReceipt::assemble(
                &config.executable,
                None,
                &config.config_hash(),
                &candidate.reference(),
                invoked_at_unix_ms,
                Coverage::ProbeOnly,
                vec![sidecar_handle(sidecar_path, index_bytes)],
                None,
                true,
                false,
            );
            receipt.disposition = FailureDisposition::UnsupportedOperation;
            receipt.freshness = Freshness::Stale {
                reason: "operation is not served by the SCIP analyzer path".to_owned(),
            };
            return empty_scip_result(operation, receipt);
        }
    };
    let ok_receipt = || {
        ObservationReceipt::assemble(
            &config.executable,
            None,
            &config.config_hash(),
            &candidate.reference(),
            invoked_at_unix_ms,
            coverage.clone(),
            vec![sidecar_handle(sidecar_path, index_bytes)],
            Some(0),
            true,
            false,
        )
    };
    let parse_failed = |error: &BridgeError| {
        let mut receipt = ok_receipt();
        let (freshness, disposition) = normalize_failure("SCIP index did not normalize", error);
        receipt.disposition = disposition;
        receipt.freshness = freshness;
        receipt
    };
    if let Some(cache) = cache {
        let target = candidate.reference();
        let config_hash = config.config_hash();
        match cache.reuse_or_derive(index_bytes, &config_hash, operation, &target, |index| {
            project_cached_items(index, operation)
        }) {
            Ok(cached) => return wrap_cached_items(operation, cached.items, ok_receipt()),
            Err(error) => {
                let receipt = parse_failed(&error);
                return empty_scip_result(operation, receipt);
            }
        }
    }
    let index = match ScipIndex::decode(index_bytes) {
        Ok(index) => index,
        Err(error) => {
            let bridge_error = BridgeError::from(error);
            let receipt = parse_failed(&bridge_error);
            return empty_scip_result(operation, receipt);
        }
    };
    match operation {
        SemanticOperation::Definitions { symbol } => match project_definitions(&index, symbol) {
            Ok(items) => NormalizedResult::Definitions {
                items,
                receipt: ok_receipt(),
            },
            Err(error) => NormalizedResult::Definitions {
                items: Vec::new(),
                receipt: parse_failed(&error),
            },
        },
        SemanticOperation::References { symbol } => match project_references(&index, symbol) {
            Ok(items) => NormalizedResult::References {
                items,
                receipt: ok_receipt(),
            },
            Err(error) => NormalizedResult::References {
                items: Vec::new(),
                receipt: parse_failed(&error),
            },
        },
        SemanticOperation::Symbols { path_scope } => match project_symbols(&index, path_scope) {
            Ok(items) => NormalizedResult::Symbols {
                items,
                receipt: ok_receipt(),
            },
            Err(error) => NormalizedResult::Symbols {
                items: Vec::new(),
                receipt: parse_failed(&error),
            },
        },
        SemanticOperation::Rename { symbol, new_name } => {
            match rename_candidate(&index, symbol, new_name) {
                Ok(candidate_result) => NormalizedResult::Rename {
                    candidate: candidate_result,
                    receipt: ok_receipt(),
                },
                Err(error) => NormalizedResult::Rename {
                    candidate: RenameCandidate {
                        symbol: symbol.clone(),
                        new_name: new_name.clone(),
                        edits: Vec::new(),
                        applied: false,
                    },
                    receipt: parse_failed(&error),
                },
            }
        }
        // Defensive: diagnostics and version probes return before decode, so
        // this arm is unreachable; it still yields a shape-correct failure.
        SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => {
            let receipt = parse_failed(&BridgeError::UnsupportedOperation);
            empty_scip_result(operation, receipt)
        }
    }
}

/// Facade over the shared process contract for one-shot analyzer launches.
///
/// The bridge holds only the executor handle: no child, session, or cache
/// survives a call. Each request spawns exactly one process through `start`
/// and reconciles it through `reconcile`.
pub struct LspBridge<E> {
    executor: Arc<E>,
}

impl<E> LspBridge<E> {
    /// Creates a bridge over the supplied process implementation.
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> LspBridge<E> {
    /// Validates and starts one exact analyzer invocation.
    pub async fn launch(
        &self,
        command: &LspCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, BridgeError> {
        if !command.matches_request(&request) {
            return Err(BridgeError::CommandMismatch);
        }
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        let generation = request.generation().get();
        let receipt = self.executor.start(request, sink).await?;
        if receipt.operation_id() != &operation_id
            || receipt.request_digest() != request_digest
            || receipt.accepted_generation().get() != generation
        {
            return Err(BridgeError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    /// Returns the current process view for an operation.
    pub async fn inspect(
        &self,
        operation: &OperationId,
    ) -> Result<ProcessExecutionView, BridgeError> {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    /// Requests cancellation using the process implementation's fence.
    pub async fn cancel(
        &self,
        operation: &OperationId,
    ) -> Result<CancellationReceipt, BridgeError> {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles durable process evidence without inventing analyzer output.
    pub async fn reconcile(&self, operation: &OperationId) -> Result<ProcessEvidence, BridgeError> {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }

    /// Returns captured stdout preview bytes, or an empty slice when the
    /// reconciled evidence carries no stdout stream.
    #[must_use]
    pub fn stdout_bytes(evidence: &ProcessEvidence) -> &[u8] {
        evidence
            .stdout()
            .map_or(&[], |stream| stream.preview().bytes())
    }

    /// Reports whether the reconciled evidence carries captured stdout.
    #[must_use]
    pub fn stdout_truncated(evidence: &ProcessEvidence) -> bool {
        evidence
            .stdout()
            .is_some_and(|stream| stream.preview().is_truncated())
    }

    /// Returns the observed exit code when the reconciled view carries one.
    ///
    /// The contract exposes the exit disposition directly; the numeric code
    /// is read through the public serialized shape.
    #[must_use]
    pub fn exit_code(evidence: &ProcessEvidence) -> Option<i32> {
        let exit = evidence.view().exit()?;
        let value = serde_json::to_value(exit).ok()?;
        value
            .get("code")?
            .as_i64()
            .and_then(|code| i32::try_from(code).ok())
    }

    /// Reports whether the reconciled view observed a completed disposition.
    #[must_use]
    pub fn completed(evidence: &ProcessEvidence) -> bool {
        evidence
            .view()
            .exit()
            .is_some_and(|exit| exit.disposition() == ExitDisposition::Completed)
    }
}

/// Bridge errors. Tool failure is not an error here: it travels on the
/// observation receipt disposition while parsing stays total.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Analyzer configuration failed validation.
    #[error("invalid analyzer configuration: {0}")]
    InvalidConfig(String),
    /// Candidate, symbol, or text field failed validation.
    #[error("invalid {field}: must be non-blank and free of control characters")]
    InvalidText {
        /// Field name.
        field: &'static str,
    },
    /// Rename target is not a valid Rust identifier.
    #[error("invalid rename target: must be a Rust identifier")]
    InvalidRenameTarget,
    /// Command projection does not match the admitted process request.
    #[error("analyzer command does not match the admitted process request")]
    CommandMismatch,
    /// Process receipt does not bind to the admitted request.
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    /// Operation is not served by the selected analyzer path.
    #[error("operation is not served by the selected analyzer path")]
    UnsupportedOperation,
    /// SCIP analyzer path requires an explicit bridge-named sidecar path.
    #[error("SCIP analyzer path requires an explicit bridge-named sidecar path")]
    MissingScipOutput,
    /// Tool output exceeds the bounded capture limit.
    #[error("analyzer output exceeds the bounded capture limit")]
    OutputTooLarge,
    /// A single analyzer output line exceeds the bounded limit.
    #[error("analyzer output line exceeds the bounded limit")]
    DiagnosticTooLarge,
    /// Normalized record count exceeds the bounded limit.
    #[error("normalized record count exceeds the bounded limit")]
    TooManyRecords,
    /// Version output is not a rust-analyzer version line.
    #[error("analyzer version output is malformed")]
    MalformedVersion,
    /// Diagnostics output is not valid UTF-8.
    #[error("analyzer diagnostics output is malformed")]
    MalformedDiagnostics,
    /// SCIP sidecar cannot be read.
    #[error("SCIP sidecar is unreadable: {detail}")]
    SidecarUnreadable {
        /// Filesystem error detail.
        detail: String,
    },
    /// SCIP index bytes failed to decode.
    #[error("SCIP index failed to decode: {0}")]
    ScipDecode(String),
    /// Shared process layer failed.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

impl From<eliot_instrument_scip::ScipError> for BridgeError {
    fn from(error: eliot_instrument_scip::ScipError) -> Self {
        Self::ScipDecode(error.to_string())
    }
}

fn checked_text(value: &str, field: &'static str) -> Result<(), BridgeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BridgeError::InvalidText { field });
    }
    Ok(())
}

fn checked_text_owned(value: String, field: &'static str) -> Result<String, BridgeError> {
    checked_text(&value, field)?;
    Ok(value)
}

fn checked_identifier(value: &str) -> Result<(), BridgeError> {
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic());
    if !first_ok || !chars.all(|next| next == '_' || next.is_ascii_alphanumeric()) {
        return Err(BridgeError::InvalidRenameTarget);
    }
    Ok(())
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::fmt::Write as _;

    const VERSION_LINE: &str = "rust-analyzer 1.97.1 (8bab26f4 2026-07-14)\n";

    const DIAGNOSTICS_SAMPLE: &str = "0/1 0% processing C:\\Temp\\ra-probe\\src\\main.rs\r\nat crate ra_probe, file C:\\Temp\\ra-probe\\src\\main.rs: Error RustcHardError(\"E0308\") from LineCol { line: 1, col: 17 } to LineCol { line: 1, col: 23 }: expected i32, found &'static str\r\ndiagnostic scan complete\r\n";

    fn test_config() -> AnalyzerConfig {
        AnalyzerConfig {
            executable: RUST_ANALYZER_EXECUTABLE.to_owned(),
            disable_build_scripts: false,
            disable_proc_macros: false,
            severity_minimum: None,
            scip_output_path: None,
        }
    }

    fn test_candidate() -> SourceCandidate {
        SourceCandidate {
            workspace_root: "C:/Temp/ra-probe".to_owned(),
            path: Some("src/main.rs".to_owned()),
            symbol: None,
        }
    }

    #[test]
    fn version_output_parses_exact_identity() {
        let version = parse_version_output(VERSION_LINE.as_bytes()).expect("version must parse");
        assert_eq!(version, "rust-analyzer 1.97.1 (8bab26f4 2026-07-14)");
    }

    #[test]
    fn diagnostics_output_parses_observed_error() {
        let observations =
            parse_diagnostics_output(DIAGNOSTICS_SAMPLE.as_bytes()).expect("diagnostics parse");
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(observation.severity, DiagnosticSeverity::Error);
        assert_eq!(observation.code, "E0308");
        assert_eq!(observation.line, 1);
        assert_eq!(observation.column, 17);
        assert_eq!(observation.end_line, 1);
        assert_eq!(observation.end_column, 23);
        assert!(observation.message.contains("expected i32"));
    }

    #[test]
    fn clean_scan_is_an_empty_observation_set() {
        let observations =
            parse_diagnostics_output(b"diagnostic scan complete\n").expect("clean scan");
        assert!(observations.is_empty());
    }

    #[test]
    fn command_projections_match_expected_argv() {
        let config = test_config();
        let candidate = test_candidate();
        let diagnostics =
            LspCommand::diagnostics(&config, &candidate).expect("diagnostics command");
        assert_eq!(diagnostics.executable, RUST_ANALYZER_EXECUTABLE);
        assert_eq!(
            diagnostics.arguments,
            vec!["diagnostics".to_owned(), "C:/Temp/ra-probe".to_owned()]
        );
        assert_eq!(diagnostics.working_directory, "C:/Temp/ra-probe");
        let version = LspCommand::version(&config, &candidate).expect("version command");
        assert_eq!(version.arguments, vec!["--version".to_owned()]);
    }

    #[test]
    fn analyzer_operation_matrix_matches_contract() {
        assert!(AnalyzerKind::RustAnalyzer.supports(&SemanticOperation::Diagnostics));
        assert!(AnalyzerKind::RustAnalyzer.supports(&SemanticOperation::ProbeVersion));
        assert!(
            !AnalyzerKind::RustAnalyzer.supports(&SemanticOperation::Rename {
                symbol: "s".to_owned(),
                new_name: "n".to_owned(),
            })
        );
        assert!(
            AnalyzerKind::Scip.supports(&SemanticOperation::Definitions {
                symbol: "s".to_owned(),
            })
        );
        assert!(!AnalyzerKind::Scip.supports(&SemanticOperation::Diagnostics));
    }

    #[test]
    fn config_hash_is_deterministic_and_sensitive() {
        let config = test_config();
        assert_eq!(config.config_hash(), config.config_hash());
        let mut other = config.clone();
        other.disable_build_scripts = true;
        assert_ne!(config.config_hash(), other.config_hash());
    }

    #[test]
    fn rename_candidate_is_always_unapplied() {
        let index = eliot_instrument_scip::ScipIndex {
            documents: vec![eliot_instrument_scip::ScipDocument {
                relative_path: "src/main.rs".to_owned(),
                symbols: Vec::new(),
                occurrences: vec![
                    eliot_instrument_scip::ScipOccurrence {
                        symbol: "rust-analyzer cargo ra_probe 0.1.0 main()".to_owned(),
                        line: 0,
                        column: 3,
                        roles: SCIP_ROLE_DEFINITION,
                    },
                    eliot_instrument_scip::ScipOccurrence {
                        symbol: "rust-analyzer cargo ra_probe 0.1.0 main()".to_owned(),
                        line: 4,
                        column: 0,
                        roles: 0,
                    },
                ],
            }],
        };
        let candidate = rename_candidate(
            &index,
            "rust-analyzer cargo ra_probe 0.1.0 main()",
            "main_entry",
        )
        .expect("rename candidate");
        assert!(candidate.is_unapplied());
        assert!(!candidate.applied);
        assert_eq!(candidate.edits.len(), 2);
        assert!(
            rename_candidate(&index, "rust-analyzer cargo ra_probe 0.1.0 main()", "0bad").is_err()
        );
    }

    fn scip_test_config() -> AnalyzerConfig {
        AnalyzerConfig {
            scip_output_path: Some("C:/Temp/ra-probe/index.scip".to_owned()),
            ..test_config()
        }
    }

    /// A lone continuation byte is a truncated varint, so the SCIP decoder
    /// deterministically rejects it.
    const TRUNCATED_SCIP: &[u8] = b"\xff";

    #[test]
    fn scip_decode_failure_preserves_operation_envelope() {
        let config = scip_test_config();
        let owner = test_candidate();
        let result = finalize_scip(
            &config,
            &owner,
            &SemanticOperation::Definitions {
                symbol: "sym".to_owned(),
            },
            TRUNCATED_SCIP,
            "sidecar",
            7,
            None,
        );
        let NormalizedResult::Definitions { items, receipt } = result else {
            panic!("decode failure must keep the definitions envelope");
        };
        assert!(items.is_empty());
        assert!(matches!(
            receipt.disposition,
            FailureDisposition::ParseFailed { .. }
        ));
        assert!(matches!(receipt.freshness, Freshness::Stale { .. }));

        let result = finalize_scip(
            &config,
            &owner,
            &SemanticOperation::References {
                symbol: "sym".to_owned(),
            },
            TRUNCATED_SCIP,
            "sidecar",
            7,
            None,
        );
        let NormalizedResult::References { items, receipt } = result else {
            panic!("decode failure must keep the references envelope");
        };
        assert!(items.is_empty());
        assert!(matches!(
            receipt.disposition,
            FailureDisposition::ParseFailed { .. }
        ));

        let result = finalize_scip(
            &config,
            &owner,
            &SemanticOperation::Rename {
                symbol: "sym".to_owned(),
                new_name: "renamed".to_owned(),
            },
            TRUNCATED_SCIP,
            "sidecar",
            7,
            None,
        );
        let NormalizedResult::Rename { candidate, receipt } = result else {
            panic!("decode failure must keep the rename envelope");
        };
        assert!(candidate.is_unapplied());
        assert!(candidate.edits.is_empty());
        assert!(matches!(
            receipt.disposition,
            FailureDisposition::ParseFailed { .. }
        ));
    }

    #[test]
    fn scip_unsupported_operation_preserves_operation_envelope() {
        let config = scip_test_config();
        let owner = test_candidate();
        let result = finalize_scip(
            &config,
            &owner,
            &SemanticOperation::Diagnostics,
            &[],
            "sidecar",
            7,
            None,
        );
        let NormalizedResult::Diagnostics {
            observations,
            receipt,
        } = result
        else {
            panic!("unsupported diagnostics must keep the diagnostics envelope");
        };
        assert!(observations.is_empty());
        assert_eq!(
            receipt.disposition,
            FailureDisposition::UnsupportedOperation
        );
        assert!(matches!(receipt.freshness, Freshness::Stale { .. }));

        let result = finalize_scip(
            &config,
            &owner,
            &SemanticOperation::ProbeVersion,
            &[],
            "sidecar",
            7,
            None,
        );
        let NormalizedResult::Version { version, receipt } = result else {
            panic!("unsupported probe must keep the version envelope");
        };
        assert!(version.is_empty());
        assert_eq!(
            receipt.disposition,
            FailureDisposition::UnsupportedOperation
        );
    }

    #[test]
    fn bound_exceeded_reports_truncation_not_parse_failure() {
        for error in [
            BridgeError::OutputTooLarge,
            BridgeError::DiagnosticTooLarge,
            BridgeError::TooManyRecords,
        ] {
            let (freshness, disposition) = normalize_failure("unused", &error);
            assert_eq!(disposition, FailureDisposition::OutputTruncated);
            assert!(matches!(freshness, Freshness::Stale { .. }));
        }
        let (_, disposition) = normalize_failure("reason", &BridgeError::MalformedVersion);
        assert!(matches!(
            disposition,
            FailureDisposition::ParseFailed { .. }
        ));

        // End to end: more diagnostic lines than the record bound finalize as
        // truncation with an empty observation set.
        let mut big = String::new();
        for i in 0..=MAX_NORMALIZED_RECORDS {
            let _ = writeln!(
                big,
                "at crate c, file f.rs: Error \"E{i:05}\" from LineCol {{ line: 0, col: 0 }} to LineCol {{ line: 0, col: 1 }}: message {i}"
            );
        }
        let config = test_config();
        let owner = test_candidate();
        let result = finalize_diagnostics(
            &config,
            &owner,
            None,
            big.as_bytes(),
            false,
            Some(0),
            true,
            7,
        );
        let NormalizedResult::Diagnostics {
            observations,
            receipt,
        } = result
        else {
            panic!("expected diagnostics result");
        };
        assert!(observations.is_empty());
        assert_eq!(receipt.disposition, FailureDisposition::OutputTruncated);
        assert!(matches!(receipt.freshness, Freshness::Stale { .. }));
    }

    #[test]
    fn symbol_scope_is_a_path_prefix() {
        let index = eliot_instrument_scip::ScipIndex {
            documents: vec![
                eliot_instrument_scip::ScipDocument {
                    relative_path: "src/main.rs".to_owned(),
                    symbols: vec![eliot_instrument_scip::ScipSymbol {
                        symbol: "sym-a".to_owned(),
                        kind: 6,
                        display_name: None,
                        enclosing_symbol: None,
                        relationships: Vec::new(),
                    }],
                    occurrences: vec![eliot_instrument_scip::ScipOccurrence {
                        symbol: "sym-a".to_owned(),
                        line: 0,
                        column: 0,
                        roles: SCIP_ROLE_DEFINITION,
                    }],
                },
                eliot_instrument_scip::ScipDocument {
                    relative_path: "other/main.rs".to_owned(),
                    symbols: vec![eliot_instrument_scip::ScipSymbol {
                        symbol: "sym-b".to_owned(),
                        kind: 6,
                        display_name: None,
                        enclosing_symbol: None,
                        relationships: Vec::new(),
                    }],
                    occurrences: vec![eliot_instrument_scip::ScipOccurrence {
                        symbol: "sym-b".to_owned(),
                        line: 0,
                        column: 0,
                        roles: SCIP_ROLE_DEFINITION,
                    }],
                },
            ],
        };
        // A bare file name is contained in both paths but prefixes neither.
        let scoped = project_symbols(&index, "main.rs").expect("prefix scope");
        assert!(scoped.is_empty());
        let scoped = project_symbols(&index, "src/").expect("prefix scope");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].symbol, "sym-a");
    }

    #[test]
    fn sidecar_read_round_trips_and_rejects_missing() {
        let dir = std::env::temp_dir().join("eliot-lsp-bridge-sidecar-proof");
        std::fs::create_dir_all(&dir).expect("sidecar dir");
        let path = dir.join("index.scip");
        let bytes = vec![0x12u8, 0x00];
        std::fs::write(&path, &bytes).expect("sidecar write");
        let path_text = path.to_str().expect("utf8 sidecar path");
        let read = read_scip_sidecar(path_text).expect("sidecar read");
        assert_eq!(read, bytes);
        std::fs::remove_file(&path).expect("sidecar cleanup");
        assert!(matches!(
            read_scip_sidecar(path_text),
            Err(BridgeError::SidecarUnreadable { .. })
        ));
    }

    #[test]
    fn scip_projection_splits_definitions_and_references() {
        let index = eliot_instrument_scip::ScipIndex {
            documents: vec![eliot_instrument_scip::ScipDocument {
                relative_path: "src/main.rs".to_owned(),
                symbols: vec![eliot_instrument_scip::ScipSymbol {
                    symbol: "sym".to_owned(),
                    kind: 6,
                    display_name: Some("main".to_owned()),
                    enclosing_symbol: None,
                    relationships: Vec::new(),
                }],
                occurrences: vec![
                    eliot_instrument_scip::ScipOccurrence {
                        symbol: "sym".to_owned(),
                        line: 0,
                        column: 3,
                        roles: SCIP_ROLE_DEFINITION,
                    },
                    eliot_instrument_scip::ScipOccurrence {
                        symbol: "sym".to_owned(),
                        line: 4,
                        column: 0,
                        roles: 0,
                    },
                ],
            }],
        };
        let definitions = project_definitions(&index, "sym").expect("definitions");
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].line, 0);
        let references = project_references(&index, "sym").expect("references");
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].line, 4);
        let symbols = project_symbols(&index, "src/").expect("symbols");
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].display_name.as_deref(), Some("main"));
    }
}
