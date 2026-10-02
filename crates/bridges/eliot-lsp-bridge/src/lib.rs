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
//! Rename output is an unapplied [`RenameCandidate`] (also named
//! [`EditCandidate`] for the I10.10 "rename/edits as candidates" row); the
//! bridge never writes to source files. No CodeCortex-private execution path
//! exists: observations, candidates, and receipts are `#[non_exhaustive]`,
//! so downstream crates cannot forge them with struct literals and must
//! obtain them from the bridge constructors; all launches go through
//! [`LspBridge`] and the shared
//! [`ProcessExecutor`](eliot_process::ProcessExecutor) contract.

#![forbid(unsafe_code)]

mod generation;
mod removal;
mod scip_cache;

pub use generation::{
    ActiveGeneration, AdmittedLine, CanaryVerdict, GenerationError, InFlightLedger,
    StagedGeneration, shadow_admits,
};
pub use removal::{
    BridgeStatusProjection, ObservedHealth, OperationStatusRow, OwnedSidecar, RemovalError,
    RemovalPhase, RemovalPlan, RemovalReceipt, RevocationKind, RevocationRecord,
};
pub use scip_cache::{
    CachedProjection, CachedScipItems, ScipIndexerProvenance, ScipProjectionCache,
};

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use eliot_artifact::{ArtifactError, ArtifactKind};
pub use eliot_artifact::{ArtifactOwner, ArtifactReadReceipt, ArtifactReference, VerifiedArtifact};
use eliot_blob_api::{BlobError, BlobReadChunk};
pub use eliot_build_test_graph::{BuildFingerprint, CandidateIdentity};
use eliot_contracts::{ArtifactId, ContractId, ContractVersion, sha256_hex};
pub use eliot_contracts::{ClockReading, RequestMetadata};
use eliot_evidence::{
    AbsenceVerdict, EvidenceCoverage, EvidenceFreshness, UnknownOutcome,
    check_absence_preconditions,
};
use eliot_git_bridge::GitSnapshotError;
pub use eliot_git_bridge::{AsyncProcessRunner as GitProcessRunner, RepoRoot, SourceTreeSnapshot};
pub use eliot_instrument_api::InstrumentInvocation;
use eliot_instrument_api::{
    InstrumentContractError, InstrumentKind, RawEvidence, RawEvidenceSource,
};
use eliot_instrument_runner::profile::{BUILTIN_PARSER_GENERATION, DIAGNOSTIC_PARSER_CONTRACT};
pub use eliot_instrument_runner::{
    InstrumentSpec, InstrumentSpecParams, RegistryEntry, ResolvedExecutableIdentity,
};
use eliot_instrument_scip::{SCIP_INSTRUMENT, ScipIndex};
pub use eliot_platform_windows::OwnedDirectoryPublication;
use eliot_process::{
    CancellationReceipt, ContractError as ProcessContractError, ExitDisposition,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessIntent, ProcessRequest,
    ProcessStreamKind, StreamPreviewRepresentation,
};
pub use eliot_process::{
    OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest, ProcessExecutionView,
    ProcessLifecycle, ProcessStartReceipt,
};
use eliot_process_executor::environment_projection_digest;
pub use eliot_types::memory::GovernedGitScope;
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
            let relative_path = Path::new(path);
            if path.contains('\\')
                || relative_path.is_absolute()
                || path
                    .split('/')
                    .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
                || relative_path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(BridgeError::InvalidConfig(
                    "candidate path must be a normalized repository-relative path".to_owned(),
                ));
            }
        }
        if let Some(symbol) = &self.symbol {
            checked_text(symbol, "symbol")?;
        }
        Ok(())
    }

    /// Versioned structured candidate identity bound into observation receipts.
    #[must_use]
    pub fn reference(&self) -> String {
        let mut identity = serde_json::Map::new();
        identity.insert("schema_version".to_owned(), serde_json::Value::from(1));
        identity.insert(
            "workspace_root".to_owned(),
            serde_json::Value::from(self.workspace_root.clone()),
        );
        identity.insert(
            "path".to_owned(),
            self.path
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        );
        identity.insert(
            "symbol".to_owned(),
            self.symbol
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        );
        serde_json::Value::Object(identity).to_string()
    }

    /// Versioned source identity containing the candidate selectors and the
    /// exact source-owner facts captured for one admitted invocation.
    pub fn reference_with_source_binding(
        &self,
        source_binding: &LspSourceBindingV1,
    ) -> Result<String, BridgeError> {
        #[derive(Serialize)]
        struct BoundCandidateReference<'a> {
            schema_version: u16,
            workspace_root: &'a str,
            path: &'a Option<String>,
            symbol: &'a Option<String>,
            source_binding: &'a LspSourceBindingV1,
        }

        serde_json::to_string(&BoundCandidateReference {
            schema_version: 2,
            workspace_root: &self.workspace_root,
            path: &self.path,
            symbol: &self.symbol,
            source_binding,
        })
        .map_err(|error| BridgeError::InconsistentBinding(error.to_string()))
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
        let mut canonical = b"eliot.instrument.lsp-analyzer-config.v1\0".to_vec();
        append_frame(&mut canonical, self.executable.as_bytes());
        canonical.push(u8::from(self.disable_build_scripts));
        canonical.push(u8::from(self.disable_proc_macros));
        append_optional_frame(&mut canonical, self.severity_minimum.as_deref());
        append_optional_frame(&mut canonical, self.scip_output_path.as_deref());
        hex_bytes(Sha256::digest(&canonical).as_slice())
    }

    /// Reports whether this configuration narrows analyzed coverage past what
    /// the receipt records. Disabled build scripts leave build-generated cfg
    /// unevaluated and disabled proc macros leave macro-generated code
    /// unobserved, so an empty lookup under either flag cannot prove absence
    /// for the affected scope (I10.8.6
    /// `unknown_due_to_cfg_or_macro_coverage`).
    #[must_use]
    pub const fn cfg_or_macro_coverage_limited(&self) -> bool {
        self.disable_build_scripts || self.disable_proc_macros
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

    /// Renders the exact invocation identity for failure attribution.
    ///
    /// Carried on launch failures so a refused or failed dispatch reconciles
    /// under its original identity instead of being retried as a new
    /// operation.
    fn describe(&self) -> String {
        format!(
            "{} {} @ {}",
            self.executable,
            self.arguments.join(" "),
            self.working_directory
        )
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
///
/// The struct is `#[non_exhaustive]` so only the bridge parsers
/// ([`parse_diagnostics_output`], [`finalize_diagnostics`]) can mint
/// observations. Downstream crates — including `CodeCortex` — cannot forge
/// them with struct literals and must consume bridge results as evidence.
/// There is no CodeCortex-private diagnostics execution path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
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
///
/// The struct is `#[non_exhaustive]` so only the bridge constructors
/// ([`rename_candidate`], [`finalize_scip`]) can mint candidates.
/// Downstream crates cannot forge them with struct literals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
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

/// Explicit edit-candidate name for the I10.10 "rename/edits as candidates"
/// row.
///
/// This is the same unapplied [`RenameCandidate`] type under its edit
/// spelling: one type, one bridge constructor path, always unapplied.
pub type EditCandidate = RenameCandidate;

impl RenameCandidate {
    /// Reports that this candidate was not applied to any file.
    #[must_use]
    pub const fn is_unapplied(&self) -> bool {
        !self.applied
    }

    /// States the candidate-only contract for consumers.
    #[must_use]
    pub const fn candidate_note() -> &'static str {
        "edit candidate only: unapplied anchor edits; the bridge never writes to source files"
    }
}

/// Freshness of a normalized result relative to its source snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Freshness {
    /// The tool completed and its full output was normalized against an
    /// independently revalidated clean source snapshot.
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
///
/// The struct is `#[non_exhaustive]` so receipts are assembled only via
/// [`ObservationReceipt::assemble`], which derives freshness and the success
/// dispositions deterministically from run evidence instead of accepting
/// caller-invented values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct ObservationReceipt {
    /// Exact analyzer executable as invoked.
    pub executable: String,
    /// Analyzer version text from the identity probe, when available.
    pub executable_version: Option<String>,
    /// Deterministic hash of the analyzer configuration.
    pub config_hash: String,
    /// Versioned structured candidate identity JSON.
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
    /// Versioned source-owner facts used to bind this observation to a
    /// candidate tree and any admitted overlay commitment.
    pub source_binding: Option<LspSourceBindingV1>,
    /// Exact existing executable-owner identity projected into this result.
    /// Historical receipts without this field remain decodable but cannot be
    /// adopted as retained bridge observations.
    #[serde(default)]
    pub resolved_executable_identity: Option<ResolvedExecutableIdentityRecord>,
    /// Exact admitted parser/spec identity used to normalize this result.
    #[serde(default)]
    pub instrument_spec: Option<InstrumentSpec>,
    /// Exact existing registry parser and normalizer identities used by the
    /// original `RegistryEntry`. They remain distinct from the bridge's final
    /// operation-specific normalization.
    #[serde(default)]
    pub registry_identity: Option<LspRegistryIdentity>,
    /// Compiled normalizer that produced this normalized semantic result.
    #[serde(default)]
    pub normalized_result_normalizer: Option<ContractId>,
}

impl ObservationReceipt {
    /// Assembles a receipt from exact run evidence. A successful run starts
    /// stale until the source owner independently confirms the same clean
    /// source snapshot after completion; parse failures are reported by the
    /// `finalize_*` constructors.
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
            (
                Freshness::Stale {
                    reason: "source snapshot was not independently revalidated".to_owned(),
                },
                FailureDisposition::Success,
            )
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
            source_binding: None,
            resolved_executable_identity: None,
            instrument_spec: None,
            registry_identity: None,
            normalized_result_normalizer: None,
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

    fn receipt_mut(&mut self) -> &mut ObservationReceipt {
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
    /// `config` is the analyzer configuration that produced this result; its
    /// build-script and proc-macro flags are read here because they narrow
    /// analyzed coverage past what the receipt records. `scope_complete_for_query`
    /// attests that the receipt's declared scope covers the query (a subset
    /// listing answers only its own scope, never the workspace).
    /// `exact_candidate_binding` attests that the analyzed index is bound to
    /// the exact candidate and scope under evaluation; the receipt alone never
    /// proves that binding. The bridge tracks no counterevidence, so
    /// contradiction is always unattested here and downstream disagreement
    /// handling (I10.8.19) owns it instead.
    #[must_use]
    pub fn lookup_outcome(
        &self,
        config: &AnalyzerConfig,
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
                cfg_or_macro_coverage_limited: config.cfg_or_macro_coverage_limited(),
                contradicted_by_higher_authority: false,
            },
        )
    }
}

/// Canonical `ToolObservation` receipt kind for a retained bridge invocation.
pub const LSP_TOOL_OBSERVATION_RECEIPT_KIND: &str = "instrument.lsp_observation.v1";
/// Retained bridge observation envelope version.
pub const LSP_RETAINED_OBSERVATION_SCHEMA_VERSION: u16 = 1;
/// Exact file emitted by one invocation inside its retained owned directory.
pub const LSP_SCIP_SIDECAR_FILE_NAME: &str = "index.scip";

/// Exact source-owner facts attached to a retained observation receipt.
/// Git scope is a source observation, not Kernel candidate admission;
/// optional `CandidateIdentity`/`BuildFingerprint` values are correlation data
/// only. This serialized projection does not authenticate candidate admission
/// or establish immutable source-artifact ownership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspSourceBindingV1 {
    /// Version of this structured source binding.
    pub schema_version: u16,
    /// Independent source scope at dispatch.
    pub source_scope_at_dispatch: Option<GovernedGitScope>,
    /// Independent source scope after process reconciliation.
    pub source_scope_after_run: Option<GovernedGitScope>,
    /// Candidate identity projection before launch, when supplied.
    pub candidate_identity_at_dispatch: Option<CandidateIdentity>,
    /// Build fingerprint projection before launch, when supplied.
    pub build_fingerprint_at_dispatch: Option<BuildFingerprint>,
    /// Independently resolved candidate identity after run, when supplied.
    pub candidate_identity_after_run: Option<CandidateIdentity>,
    /// Independently resolved build fingerprint after run, when supplied.
    pub build_fingerprint_after_run: Option<BuildFingerprint>,
    /// Original process owner's inert start correlation.
    pub process_start: LspProcessStartBindingV1,
    /// Original `Instrument` request identity captured before the process request
    /// was consumed.
    pub instrument_request_id: String,
    /// Exact target admitted by the `Instrument` request.
    pub instrument_target: String,
    /// Exact declared scope admitted by the `Instrument` request.
    pub instrument_declared_scope: String,
    /// Existing source artifact identities admitted by the `Instrument` request.
    pub instrument_input_artifacts: Vec<ArtifactId>,
    /// Inert projection of the non-serializable source artifact proof captured
    /// at dispatch. Current adoption requires a fresh owner readback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_artifact_at_dispatch: Option<LspSourceArtifactProjectionV1>,
    /// Source owner readback after process reconciliation. Missing means the
    /// historical receipt cannot establish source freshness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_artifact_after_run: Option<LspSourceArtifactProjectionV1>,
    /// Exact shared-process operation identity captured before launch.
    pub process_operation_id: String,
    /// Exact shared-process generation accepted at launch.
    pub process_generation: u64,
    /// Exact process working directory bound to the LSP workspace.
    pub process_working_directory: String,
}

/// Serialized fields copied from the owner-issued source artifact readback.
/// Deserialization alone never issues source authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspSourceArtifactProjectionV1 {
    /// Version of this inert artifact/read-receipt projection.
    pub schema_version: u16,
    /// Supplemental Git tree identity; artifact bytes are the content proof.
    pub git_tree_id: String,
    /// Exact immutable artifact reference used for the source snapshot.
    pub artifact_reference: ArtifactReference,
    /// Inert copy of the original non-deserializable `ArtifactReadReceipt`.
    pub read_receipt: LspArtifactReadReceiptProjectionV1,
}

/// Inert projection of the original I-01/S-04 read receipt. The actual
/// `ArtifactReadReceipt` remains non-deserializable in the live proof handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspArtifactReadReceiptProjectionV1 {
    /// Digest of the complete artifact identity accepted by I-01.
    pub identity_digest: String,
    /// Digest of the exact source archive bytes accepted by I-01.
    pub content_digest: String,
    /// Authenticated metadata digest from the S-04 receipt.
    pub metadata_sha256: String,
    /// Exact S-04 ready receipt identity used for the read.
    pub ready_receipt_id: String,
    /// S-04 trust-anchor fingerprint used for the read.
    pub anchor_fingerprint: String,
    /// Number of verified source archive bytes.
    pub byte_count: u64,
}

/// Live source proof assembled only from an owner-minted Git snapshot and the
/// actual I-01/S-04 readback for the same full workspace archive. None of its
/// authority-bearing members are serializable.
#[derive(Debug)]
pub struct LspSourceArtifactProof {
    snapshot: SourceTreeSnapshot,
    reference: ArtifactReference,
    artifact: VerifiedArtifact,
    read_receipt: ArtifactReadReceipt,
}

impl LspSourceArtifactProof {
    /// Joins an opaque Git source snapshot to its exact verified artifact read.
    pub fn from_owner_readback(
        artifact_owner: &ArtifactOwner,
        snapshot: SourceTreeSnapshot,
        reference: ArtifactReference,
        artifact: VerifiedArtifact,
        read_receipt: ArtifactReadReceipt,
        source_candidate: &SourceCandidate,
    ) -> Result<Self, BridgeError> {
        source_candidate.validate()?;
        let workspace_matches = snapshot
            .validates_workspace_root(Path::new(&source_candidate.workspace_root))
            .map_err(BridgeError::SourceSnapshot)?;
        validate_source_artifact_identity(&snapshot, &reference)?;
        if snapshot.max_archive_bytes() != artifact_owner.max_read_bytes() {
            return Err(BridgeError::InconsistentBinding(
                "source snapshot and immutable artifact owner use different archive ceilings"
                    .to_owned(),
            ));
        }
        artifact_owner
            .validate_source_readback(
                &reference,
                &artifact,
                &read_receipt,
                snapshot.archive_bytes(),
            )
            .map_err(BridgeError::SourceArtifact)?;
        if !workspace_matches || snapshot.archive_bytes() != artifact.bytes() {
            return Err(BridgeError::InconsistentBinding(
                "Git source snapshot does not match the original immutable artifact readback"
                    .to_owned(),
            ));
        }
        Ok(Self {
            snapshot,
            reference,
            artifact,
            read_receipt,
        })
    }

    fn projection(&self) -> LspSourceArtifactProjectionV1 {
        LspSourceArtifactProjectionV1 {
            schema_version: 1,
            git_tree_id: self.snapshot.tree_id().to_owned(),
            artifact_reference: self.reference.clone(),
            read_receipt: LspArtifactReadReceiptProjectionV1 {
                identity_digest: self.read_receipt.identity_digest().to_owned(),
                content_digest: self.read_receipt.content_digest().to_owned(),
                metadata_sha256: self.read_receipt.metadata_sha256().to_owned(),
                ready_receipt_id: self.read_receipt.ready_receipt_id().to_owned(),
                anchor_fingerprint: self.read_receipt.anchor_fingerprint().to_owned(),
                byte_count: self.read_receipt.byte_count(),
            },
        }
    }

    fn matches_current_source(&self, other: &Self) -> bool {
        self.snapshot.same_source(&other.snapshot)
            && self.reference == other.reference
            && self.artifact == other.artifact
            && self.read_receipt == other.read_receipt
    }

    async fn revalidate_current(
        &self,
        source_root: &RepoRoot,
        runner: &dyn GitProcessRunner,
        source_candidate: &SourceCandidate,
    ) -> Result<(), BridgeError> {
        let root_matches = self
            .snapshot
            .validates_workspace_root(source_root.path())
            .map_err(BridgeError::SourceSnapshot)?;
        let candidate_matches = self
            .snapshot
            .validates_workspace_root(Path::new(&source_candidate.workspace_root))
            .map_err(BridgeError::SourceSnapshot)?;
        if !root_matches || !candidate_matches {
            return Err(BridgeError::InconsistentBinding(
                "source owner root differs from the captured analyzer workspace".to_owned(),
            ));
        }
        self.snapshot
            .revalidate_current_async(source_root, runner)
            .await
            .map_err(BridgeError::SourceSnapshot)?;
        Ok(())
    }
}

/// Non-authoritative subset of the Kernel `ProcessStartReceipt` needed to correlate
/// retained output with the one admitted process request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspProcessStartBindingV1 {
    /// Version of this inert correlation record.
    pub schema_version: u16,
    /// Operation accepted by the process owner.
    pub operation_id: String,
    /// Original request digest issued by the process owner.
    pub request_digest: String,
    /// Generation accepted by the process owner.
    pub accepted_generation: u64,
}

/// A captured process output stream or invocation-owned SCIP sidecar.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspRawOutputKind {
    /// Analyzer stdout.
    Stdout,
    /// Analyzer stderr.
    Stderr,
    /// The SCIP sidecar written by this exact invocation.
    ScipSidecar,
}

/// Original raw bytes plus the channel to which they belong.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspRawOutput {
    /// Output stream or sidecar role.
    pub kind: LspRawOutputKind,
    /// Original immutable capture. Live values are minted only from the
    /// original process reconcile or invocation-owned sidecar readback.
    pub evidence: RawEvidence,
}

/// Serializable projection of the existing #1814 resolved executable
/// identity. The projection is never process authority; it reconstructs the
/// owning type for typed equality and admission checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedExecutableIdentityRecord {
    /// Canonical executable path observed by the shared executor.
    pub canonical_path: String,
    /// SHA-256 over the exact executable bytes.
    pub content_digest: String,
    /// Observed tool version, when available.
    pub tool_version: Option<String>,
    /// SHA-256 identity of the resolved environment projection.
    pub environment_digest: String,
    /// Exact argv observed at launch.
    pub arguments: Vec<String>,
}

impl From<&ResolvedExecutableIdentity> for ResolvedExecutableIdentityRecord {
    fn from(value: &ResolvedExecutableIdentity) -> Self {
        Self {
            canonical_path: value.canonical_path.clone(),
            content_digest: value.content_digest.clone(),
            tool_version: value.tool_version.clone(),
            environment_digest: value.environment_digest.clone(),
            arguments: value.arguments.clone(),
        }
    }
}

impl ResolvedExecutableIdentityRecord {
    fn resolve(&self, instrument: &str) -> Result<ResolvedExecutableIdentity, BridgeError> {
        ResolvedExecutableIdentity::new(
            instrument,
            self.canonical_path.clone(),
            self.content_digest.clone(),
            self.tool_version.clone(),
            self.environment_digest.clone(),
            self.arguments.clone(),
        )
        .map_err(|error| BridgeError::ExecutableIdentity(error.to_string()))
    }
}

/// Existing runner registry fields needed to reject a foreign instrument or
/// parser when a retained observation is adopted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspRegistryIdentity {
    /// Admitted profile contract identity.
    pub profile: ContractId,
    /// Admitted profile version.
    pub profile_version: ContractVersion,
    /// Admitted instrument contract identity.
    pub instrument: ContractId,
    /// Supported coarse invocation kinds.
    pub kinds: Vec<InstrumentKind>,
    /// Provider adapter identity.
    pub adapter: String,
    /// Provider adapter version.
    pub adapter_version: ContractVersion,
    /// Registry executable name and acquisition rule.
    pub executable: LspRegistryExecutableIdentity,
    /// Required toolchain family identity.
    pub toolchain: String,
    /// Supported target classes.
    pub targets: Vec<String>,
    /// Required environment class.
    pub environment_class: String,
    /// Process resource and cancellation contracts.
    pub resource_contract: String,
    pub cancellation_contract: String,
    /// Admitted parser identity.
    pub parser: ContractId,
    /// Admitted normalizer identity.
    pub normalizer: ContractId,
    /// Admitted evaluator and verifier identities.
    pub evaluator: ContractId,
    pub verifier: ContractId,
    /// Registry invalidation fingerprints.
    pub invalidation: LspRegistryInvalidation,
    /// Exact declared profile identity slots.
    pub identities: LspRegistryIdentitySlots,
    /// Registry generation used at admission.
    pub generation: u64,
}

/// Serializable projection of the runner's existing registry executable
/// identity; it carries no process authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspRegistryExecutableIdentity {
    /// Pinned executable name, or absent for decoder-only entries.
    pub executable: Option<String>,
    /// Acquisition rule owned by the environment/toolchain authority.
    pub acquisition_rule: String,
    /// Decoder identity, present only for decoder-only entries.
    pub decoder: Option<String>,
}

/// Serializable invalidation fingerprints from the existing runner registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspRegistryInvalidation {
    /// Source snapshot fingerprint.
    pub source: String,
    /// Lockfile fingerprint.
    pub lock: String,
    /// Toolchain fingerprint.
    pub toolchain: String,
    /// Environment fingerprint.
    pub environment: String,
    /// Executable fingerprint.
    pub executable: String,
    /// Profile fingerprint.
    pub profile: String,
    /// Parser fingerprint.
    pub parser: String,
}

/// Serializable exact profile slots checked by `RegistryEntry` before launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspRegistryIdentitySlots {
    /// Source snapshot identity.
    pub source: String,
    /// Lockfile identity.
    pub lock: String,
    /// Toolchain identity.
    pub toolchain: String,
    /// Executable or decoder identity.
    pub executable: String,
    /// Admitted feature-set identity.
    pub features: String,
    /// Environment class identity.
    pub environment: String,
    /// Expected artifact identity.
    pub artifact: String,
    /// Work scope and state fence identity.
    pub fence: String,
    /// Admitted operation identity.
    pub operation: String,
    /// Timeout policy identity.
    pub timeout: String,
    /// Cancellation contract identity.
    pub cancellation: String,
    /// Resource contract identity.
    pub resource: String,
}

impl From<&RegistryEntry> for LspRegistryIdentity {
    fn from(value: &RegistryEntry) -> Self {
        Self {
            profile: value.profile.clone(),
            profile_version: value.profile_version,
            instrument: value.instrument.clone(),
            kinds: value.kinds.clone(),
            adapter: value.adapter.clone(),
            adapter_version: value.adapter_version,
            executable: LspRegistryExecutableIdentity {
                executable: value.executable.executable.clone(),
                acquisition_rule: value.executable.acquisition_rule.clone(),
                decoder: value.executable.decoder.clone(),
            },
            toolchain: value.toolchain.clone(),
            targets: value.targets.iter().cloned().collect(),
            environment_class: value.environment_class.clone(),
            resource_contract: value.resource_contract.clone(),
            cancellation_contract: value.cancellation_contract.clone(),
            parser: value.parser.clone(),
            normalizer: value.normalizer.clone(),
            evaluator: value.evaluator.clone(),
            verifier: value.verifier.clone(),
            invalidation: LspRegistryInvalidation {
                source: value.invalidation.source.clone(),
                lock: value.invalidation.lock.clone(),
                toolchain: value.invalidation.toolchain.clone(),
                environment: value.invalidation.env.clone(),
                executable: value.invalidation.exe.clone(),
                profile: value.invalidation.profile.clone(),
                parser: value.invalidation.parser.clone(),
            },
            identities: LspRegistryIdentitySlots {
                source: value.identities.source.clone(),
                lock: value.identities.lock.clone(),
                toolchain: value.identities.toolchain.clone(),
                executable: value.identities.executable.clone(),
                features: value.identities.features.clone(),
                environment: value.identities.environment.clone(),
                artifact: value.identities.artifact.clone(),
                fence: value.identities.fence.clone(),
                operation: value.identities.operation.clone(),
                timeout: value.identities.timeout.clone(),
                cancellation: value.identities.cancellation.clone(),
                resource: value.identities.resource.clone(),
            },
            generation: value.generation,
        }
    }
}

/// In-memory launch handle that carries exact admitted, non-authoritative
/// invocation facts across the consuming `ProcessRequest`. It is deliberately
/// not serializable and never contains permit authority.
#[derive(Debug)]
pub struct LspStartedInvocation {
    process_start: ProcessStartReceipt,
    instrument_invocation: InstrumentInvocation,
    source_candidate: SourceCandidate,
    source_scope_at_dispatch: Option<GovernedGitScope>,
    candidate_identity: Option<CandidateIdentity>,
    build_fingerprint: Option<BuildFingerprint>,
    config: AnalyzerConfig,
    operation: SemanticOperation,
    process_intent: ProcessIntent,
    invocation_digest: String,
    resolved_executable: ResolvedExecutableIdentityRecord,
    instrument_spec: InstrumentSpec,
    registry_identity: LspRegistryIdentity,
    source_artifact_proof: Option<LspSourceArtifactProof>,
    scip_output_owner: Option<OwnedDirectoryPublication>,
}

impl LspStartedInvocation {
    /// Returns the physical start receipt for ordinary process supervision.
    #[must_use]
    pub const fn process_start(&self) -> &ProcessStartReceipt {
        &self.process_start
    }

    /// Returns the non-authoritative request digest captured before launch.
    #[must_use]
    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }
}

/// Versioned retained LSP observation suitable for the canonical blob store.
/// The sole normalized receipt remains nested in result; no `ProcessRequest`,
/// permit, or start-receipt authority is serialized.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RetainedLspObservationV1 {
    /// Version of this complete retained envelope.
    pub schema_version: u16,
    /// Canonical `ToolObservation` receipt kind.
    pub receipt_kind: String,
    /// Exact analyzer operation retained before launch.
    pub operation: SemanticOperation,
    /// Exact analyzer config used for the request.
    pub config: AnalyzerConfig,
    /// Analyzer scope and workspace request.
    pub source_candidate: SourceCandidate,
    /// Original admitted Instrument request, which contains no process permit.
    pub instrument_invocation: InstrumentInvocation,
    /// Exact immutable `ProcessIntent` consumed by the shared process executor.
    pub process_intent: ProcessIntent,
    /// Original sealed request digest; this value is retained, never reminted.
    pub invocation_digest: String,
    /// #1814 resolved executable identity projection.
    pub resolved_executable: ResolvedExecutableIdentityRecord,
    /// Full admitted parser/spec identity.
    pub instrument_spec: InstrumentSpec,
    /// Existing runner registry identity slots needed at adoption.
    pub registry_identity: LspRegistryIdentity,
    /// Original reconciled process evidence for this request.
    pub process_evidence: ProcessEvidence,
    /// Original bounded outputs and immutable SCIP sidecar bytes.
    pub raw_outputs: Vec<LspRawOutput>,
    /// Re-normalized result with its sole observation receipt.
    pub result: NormalizedResult,
}

/// Independently supplied current expectations at a result-adoption boundary.
/// Values must come from current task/source/executable owners, never from the
/// retained envelope being checked. They support exact comparison but do not
/// replace original process or immutable source-artifact owner readback.
pub struct CurrentLspAdoptionContext<'a> {
    /// Current source candidate selected by the task.
    pub source_candidate: &'a SourceCandidate,
    /// Independently resolved current source snapshot, when available.
    pub source_scope: Option<&'a GovernedGitScope>,
    /// Independently admitted candidate identity, when available.
    pub candidate_identity: Option<&'a CandidateIdentity>,
    /// Independently admitted build fingerprint, when available.
    pub build_fingerprint: Option<&'a BuildFingerprint>,
    /// Current analyzer config requested by the task.
    pub config: &'a AnalyzerConfig,
    /// Current analyzer operation requested by the task.
    pub operation: &'a SemanticOperation,
    /// Current admitted `Instrument` request.
    pub instrument_invocation: &'a InstrumentInvocation,
    /// Current #1814 executable observation.
    pub resolved_executable: &'a ResolvedExecutableIdentity,
    /// Current registry admission entry.
    pub registry_entry: &'a RegistryEntry,
    /// Current complete admitted instrument spec/parser identity.
    pub instrument_spec: &'a InstrumentSpec,
}

/// Non-authoritative currentness projection over an immutable retained
/// observation. The observation keeps its original Stale receipt; a live
/// adoption never rewrites that historical receipt to claim Current.
#[derive(Debug)]
pub struct LspAdoptionProjection {
    /// Original normalized semantic result with its original receipt intact.
    observation: NormalizedResult,
    /// Freshness established at this adoption boundary, separate from the
    /// historical receipt carried by `observation`.
    currentness: Freshness,
    /// Original immutable retained envelope reconciled and revalidated by the
    /// owners; downstream consumers must compare their received value to it.
    retained_observation: Arc<RetainedLspObservationV1>,
    /// Original non-serializable launch handle, retained only for a genuine
    /// live projection minted after process and output-owner readback.
    started: Arc<LspStartedInvocation>,
}

/// Boxed future type returned by the capture publication callback.
pub type LspCapturePublicationFuture<'a, Output, Error> =
    Pin<Box<dyn Future<Output = Result<Output, Error>> + 'a>>;

/// One-shot callback that publishes the exact live capture before the bridge
/// returns its retained record to a caller. Implementations keep their
/// original Governor/Store admission on-stack and receive only the immutable
/// serialized bytes plus the bridge-minted non-Serde projection.
pub trait LspCapturePublicationPort {
    /// Output produced by the existing capture/publication owner.
    type Output;
    /// Original typed publication failure.
    type Error: std::error::Error + 'static;

    /// Publishes this exact record after live process and sidecar owner
    /// readback. `original_payload` is serialized from the same `record`.
    fn publish<'a>(
        &'a self,
        record: &'a RetainedLspObservationV1,
        projection: &'a LspAdoptionProjection,
        original_payload: &'a [u8],
    ) -> LspCapturePublicationFuture<'a, Self::Output, Self::Error>;
}

/// Failure to complete one live capture, preserving bridge and publisher
/// errors as their original typed values.
#[derive(Debug, Error)]
pub enum LspCaptureCompletionError<PublicationError>
where
    PublicationError: std::error::Error + 'static,
{
    /// The bridge could not validate or construct the original live capture.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// The existing owner rejected or failed publication of the exact capture.
    #[error("LSP capture publication failed")]
    Publication(#[source] PublicationError),
}

impl LspAdoptionProjection {
    /// Returns the unchanged retained semantic result and its original receipt.
    #[must_use]
    pub const fn observation(&self) -> &NormalizedResult {
        &self.observation
    }

    /// Returns currentness assessed at this non-persistent adoption boundary.
    #[must_use]
    pub const fn currentness(&self) -> &Freshness {
        &self.currentness
    }

    /// Checks that this owner-adopted projection belongs to the exact
    /// retained envelope supplied to a downstream evidence consumer.
    ///
    /// Equality covers the complete source, request, process, executable,
    /// parser, raw-output, and normalized-result envelope, so another
    /// invocation with the same semantic items cannot be paired here.
    #[must_use]
    pub fn matches_retained_observation(&self, record: &RetainedLspObservationV1) -> bool {
        self.retained_observation.as_ref() == record
    }
}

/// Lookup outcome classified from an observation receipt (I10.8.6).
///
/// An empty lookup is `ProvenAbsent` only when the receipt records a
/// complete run over a complete scope with an exact candidate binding;
/// every other empty lookup is a typed [`UnknownOutcome`] or
/// [`LookupOutcome::Contradicted`], never "not found". The outcome is
/// serializable so a typed unknown can be returned and persisted as its
/// contract token instead of collapsing to "not found".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
/// analyzed index is bound to the exact candidate and scope, whether the
/// analyzer configuration narrowed cfg/macro coverage, and whether
/// higher-authority evidence contradicts the absence.
#[allow(
    clippy::struct_excessive_bools,
    reason = "five independent caller attestations; an enum per flag would quintuple the vocabulary for one call"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupClassification {
    /// The receipt's declared scope covers the query.
    pub scope_complete_for_query: bool,
    /// The lookup returned at least one item.
    pub found_any: bool,
    /// The analyzed index is bound to the exact candidate and scope.
    pub exact_candidate_binding: bool,
    /// Disabled build scripts or proc macros narrowed cfg/macro coverage.
    pub cfg_or_macro_coverage_limited: bool,
    /// Higher-authority evidence contradicts the absence.
    pub contradicted_by_higher_authority: bool,
}

/// Classifies one lookup from its observation receipt.
///
/// A run that failed, truncated, or did not normalize reports
/// [`UnknownOutcome::UnknownDueToTruncationOrToolFailure`] even though the
/// receipt also records stale freshness: the disposition names the root
/// cause while staleness is its derived symptom. A successful run under a
/// cfg/macro-narrowed configuration reports
/// [`UnknownOutcome::UnknownDueToCfgOrMacroCoverage`] before freshness and
/// coverage are consulted, because the narrowed view bounds what the run
/// could have observed. A merely current run is still freshness-unknown for
/// absence until the caller attests the exact candidate binding, because run
/// currency never proves candidate identity.
#[must_use]
pub fn classify_lookup(
    receipt: &ObservationReceipt,
    classification: LookupClassification,
) -> LookupOutcome {
    if classification.found_any {
        return LookupOutcome::Found;
    }
    let absence_capability = match receipt.disposition {
        FailureDisposition::Success => {
            if classification.cfg_or_macro_coverage_limited {
                Err(UnknownOutcome::UnknownDueToCfgOrMacroCoverage)
            } else {
                Ok(())
            }
        }
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
///
/// This is a pure projection over the borrowed `&ScipIndex`: it performs no
/// filesystem writes and launches no process, so the rename path cannot
/// modify files. The acceptance proof holds a witness file across both the
/// direct and the `finalize_scip` rename paths and asserts it is unchanged.
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

/// Reads a test fixture sidecar with a byte bound.
///
/// Production captures read only through their original retained output
/// directory owner; this path helper exists solely for legacy unit fixtures.
#[cfg(test)]
fn read_scip_sidecar(path: &str) -> Result<Vec<u8>, BridgeError> {
    checked_text(path, "scip_output_path")?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    if !metadata.file_type().is_file() {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
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
    finalize_scip_with_cache_mode(
        config,
        candidate,
        operation,
        index_bytes,
        sidecar_path,
        invoked_at_unix_ms,
        cache.map(ScipCacheUse::Unbound),
    )
}

enum ScipCacheUse<'a> {
    Unbound(&'a mut ScipProjectionCache),
    Invocation(&'a mut ScipProjectionCache, &'a LspStartedInvocation),
}

fn finalize_scip_for_invocation(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
    index_bytes: &[u8],
    sidecar_path: &str,
    invoked_at_unix_ms: u64,
    cache: &mut ScipProjectionCache,
    invocation: &LspStartedInvocation,
) -> NormalizedResult {
    finalize_scip_with_cache_mode(
        config,
        candidate,
        operation,
        index_bytes,
        sidecar_path,
        invoked_at_unix_ms,
        Some(ScipCacheUse::Invocation(cache, invocation)),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "operation dispatch is exhaustive and each arm pairs one projection with its receipt; splitting would separate results from their evidence"
)]
fn finalize_scip_with_cache_mode(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
    index_bytes: &[u8],
    sidecar_path: &str,
    invoked_at_unix_ms: u64,
    cache: Option<ScipCacheUse<'_>>,
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
        match cache {
            ScipCacheUse::Unbound(cache) => {
                let config_hash = config.config_hash();
                match cache.reuse_or_derive(
                    index_bytes,
                    &config_hash,
                    operation,
                    &target,
                    |index| project_cached_items(index, operation),
                ) {
                    Ok(cached) => {
                        return wrap_cached_items(operation, cached.items, ok_receipt());
                    }
                    Err(error) => {
                        let receipt = parse_failed(&error);
                        return empty_scip_result(operation, receipt);
                    }
                }
            }
            ScipCacheUse::Invocation(cache, invocation) => {
                match cache.try_reuse_or_derive_for_invocation(
                    index_bytes,
                    invocation,
                    &target,
                    |index| project_cached_items(index, operation),
                ) {
                    Ok(Some(cached)) => {
                        return wrap_cached_items(operation, cached.items, ok_receipt());
                    }
                    // A failed live source/root identity measurement disables
                    // only cache consultation. Continue through the original
                    // uncached decoder below so the derived optimization
                    // cannot turn otherwise valid output into a parse failure.
                    Ok(None) => {}
                    Err(error) => {
                        let receipt = parse_failed(&error);
                        return empty_scip_result(operation, receipt);
                    }
                }
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

// ---------------------------------------------------------------------------
// I10.13 application obligations and the W5 pre-dispatch call gate
// ---------------------------------------------------------------------------

/// Exact first-argv tokens this bridge admits.
///
/// Single source for the `supported_operations` declaration below and the
/// pre-dispatch gate: adding a token here without an [`LspCommand`]
/// constructor that projects its argv changes nothing, and no other
/// first-argv token can pass the gate.
const LSP_ADMITTED_SUBCOMMANDS: &[&str] = &["diagnostics", "scip", "--version"];

/// Denial-of-weirdness ceilings for one dispatch. Generous on purpose: every
/// typed [`LspCommand`] projection carries at most seven short arguments, so
/// anything beyond is refused before any process is launched.
const LSP_ARGV_CAP: usize = 256;
const LSP_ARG_BYTES_CAP: usize = 16_384;
const LSP_ARGV_BYTES_CAP: usize = 262_144;

/// I10.13 application obligations for the rust-analyzer
/// professional-application bridge: exact supported artifacts/actions,
/// API-versus-UI observation quality, side effects, undo/recovery scope,
/// artifact verifier, representation loss, and the interactive Human/session
/// requirement, resolved per application (the `rust-analyzer` executable
/// bound to the executor port). There is no universal pipeline: these
/// statements describe only what the typed operations in this crate do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LspApplicationObligations {
    /// Exact admitted first-argv tokens.
    pub supported_operations: &'static [&'static str],
    /// Exact supported artifacts and actions.
    pub supported_artifacts_actions: &'static str,
    /// API versus UI observation quality.
    pub observation_quality: &'static str,
    /// Side effects of the admitted operations.
    pub side_effects: &'static str,
    /// Undo and recovery scope.
    pub undo_recovery_scope: &'static str,
    /// Artifact verifier carried on every receipt.
    pub artifact_verifier: &'static str,
    /// Representation loss in normalized output.
    pub representation_loss: &'static str,
    /// Interactive Human and session requirement.
    pub human_session_requirement: &'static str,
}

/// Returns the I10.13 declaration for the analyzer application bridged here.
///
/// Consumed by the pre-dispatch gate on every launch (exact-operation
/// check), so the declaration and the enforcement cannot drift apart.
#[must_use]
pub fn lsp_application_obligations() -> LspApplicationObligations {
    LspApplicationObligations {
        supported_operations: LSP_ADMITTED_SUBCOMMANDS,
        supported_artifacts_actions: "Rust workspaces addressed by workspace_root; one-shot \
            diagnostics observations, one-shot SCIP semantic navigation (definitions, references, \
            symbols) and unapplied rename/edit candidates, plus the --version identity probe. \
            Source-tree mutations do not exist here: the bridge never writes to source files and \
            every rename candidate is unapplied",
        observation_quality: "CLI/API capture only, no UI automation and no screenshots: exact \
            exit code with full stdout hashed over the observed bytes; the diagnostics parser \
            normalizes best-effort, skipping lines that do not match the expected porcelain shape \
            rather than failing, and the version probe accepts only an exact rust-analyzer line",
        side_effects: "Every admitted operation launches exactly one process and keeps no \
            session; the bridge itself performs no filesystem writes. The analyzer writes only \
            the bridge-named SCIP sidecar required by the scip path, and rename output is \
            candidate-only, never applied",
        undo_recovery_scope: "No bridge-local undo: there is nothing to revert (no source \
            writes, no leases, no mutable bridge state). A stale or partial sidecar is \
            regenerated by a new authorized run, never repaired in place; recovery is a new \
            operation under its own identity, never restoration of old state",
        artifact_verifier: "Every receipt carries the exact executable, the probed executable \
            version when available, the deterministic configuration hash, the canonical \
            candidate reference, invocation time, freshness, coverage, SHA-256 output handles \
            over the complete observed bytes, the observed exit code and the failure disposition",
        representation_loss: "Parsers skip non-conforming lines as an explicit observation \
            limit, never as silent success; SCIP rename anchors are start positions only and \
            applying them requires LSP range resolution the bridge never performs; over-bound \
            output normalizes to a stale truncated receipt instead of a complete result",
        human_session_requirement: "Every launch goes through the shared ProcessExecutor \
            admission with its own operation identity and generation binding; a command/request \
            or receipt/identity mismatch is refused and is never bypassed by cached credentials \
            or another session",
    }
}

/// Revision of the versioned lsp-bridge declaration schema.
///
/// Stamped into every [`LspBridgeDeclaration`] and every staged and admitted
/// generation. A declaration-schema change mints a new revision; generations
/// staged under another revision are refused as updates, never reinterpreted.
pub const LSP_DECLARATION_REVISION: u64 = 1;

/// Reports whether a caller-attested upstream artifact digest is well shaped:
/// exactly 64 hexadecimal characters (SHA-256 hex).
pub(crate) fn is_artifact_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Versioned, artifact-bound bridge declaration for the analyzer application.
///
/// This is the A1 declaration for the lsp bridge: the I10.13 obligations
/// above plus the exact bound artifact (route executable, caller-observed
/// upstream identity line, caller-attested upstream artifact digest) under one
/// declaration revision, with a binding digest over the whole. The snapshot
/// of admitted operations comes from [`lsp_application_obligations`], so the
/// declaration and the generation staged from it cannot drift apart. Unknown
/// required metadata stays a refusal (typed error), never a qualification
/// silently absorbed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LspBridgeDeclaration {
    revision: u64,
    route_executable: String,
    upstream_version_line: String,
    upstream_artifact_digest: String,
    admitted_operations: Vec<String>,
    binding_digest: String,
}

impl LspBridgeDeclaration {
    /// Admits a declaration for one caller-observed upstream artifact.
    ///
    /// Records the observed `rust-analyzer --version` identity line (in its
    /// parser-validated form) and the attested artifact digest; installs and
    /// probes nothing. The admitted-operation snapshot is taken from
    /// [`lsp_application_obligations`].
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::BlankField`] on a blank identity line or
    /// digest, [`GenerationError::ArtifactDigestShape`] on a malformed
    /// digest, or [`GenerationError::UpstreamIdentity`] when the line is not
    /// an exact analyzer version line. No authority, operation identity, or
    /// task decision is created.
    pub fn admit(
        upstream_version_line: impl Into<String>,
        upstream_artifact_digest: impl Into<String>,
    ) -> Result<Self, GenerationError> {
        let upstream_version_line = upstream_version_line.into();
        let upstream_artifact_digest = upstream_artifact_digest.into();
        if upstream_version_line.trim().is_empty() {
            return Err(GenerationError::BlankField {
                field: "upstream_version_line",
            });
        }
        if upstream_artifact_digest.trim().is_empty() {
            return Err(GenerationError::BlankField {
                field: "upstream_artifact_digest",
            });
        }
        if !is_artifact_digest(&upstream_artifact_digest) {
            return Err(GenerationError::ArtifactDigestShape {
                detail: "upstream_artifact_digest must be 64 hexadecimal characters".to_owned(),
            });
        }
        let upstream_version_line = parse_version_output(upstream_version_line.as_bytes())
            .map_err(|error| GenerationError::UpstreamIdentity {
                detail: error.to_string(),
            })?;
        let obligations = lsp_application_obligations();
        let admitted_operations: Vec<String> = obligations
            .supported_operations
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect();
        let binding_digest = Self::compute_binding_digest(
            LSP_DECLARATION_REVISION,
            RUST_ANALYZER_EXECUTABLE,
            &upstream_version_line,
            &upstream_artifact_digest,
            &admitted_operations,
        );
        Ok(Self {
            revision: LSP_DECLARATION_REVISION,
            route_executable: RUST_ANALYZER_EXECUTABLE.to_owned(),
            upstream_version_line,
            upstream_artifact_digest,
            admitted_operations,
            binding_digest,
        })
    }

    /// Computes the binding digest over one declaration snapshot.
    ///
    /// The encoding is fixed (`revision`, route, upstream identity line,
    /// artifact digest, admitted operations in declaration order), so the
    /// digest binds the exact contract the loader and the gate recheck.
    fn compute_binding_digest(
        revision: u64,
        route_executable: &str,
        upstream_version_line: &str,
        upstream_artifact_digest: &str,
        admitted_operations: &[String],
    ) -> String {
        let mut canonical = format!(
            "lsp-bridge-declaration\nrevision: {revision}\nroute: {route_executable}\n\
             upstream-version-line: {upstream_version_line}\nupstream-artifact-digest: {upstream_artifact_digest}\n\
             operations:\n"
        );
        for operation in admitted_operations {
            canonical.push_str(operation);
            canonical.push('\n');
        }
        hex_bytes(Sha256::digest(canonical.as_bytes()).as_slice())
    }

    /// Recomputes the binding digest and reports whether it still covers
    /// this declaration exactly.
    #[must_use]
    pub fn binding_verifies(&self) -> bool {
        Self::compute_binding_digest(
            self.revision,
            &self.route_executable,
            &self.upstream_version_line,
            &self.upstream_artifact_digest,
            &self.admitted_operations,
        ) == self.binding_digest
    }

    /// Returns the declaration schema revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the bound route executable.
    #[must_use]
    pub fn route_executable(&self) -> &str {
        &self.route_executable
    }

    /// Returns the parser-validated upstream identity line.
    #[must_use]
    pub fn upstream_version_line(&self) -> &str {
        &self.upstream_version_line
    }

    /// Returns the caller-attested upstream artifact digest.
    #[must_use]
    pub fn upstream_artifact_digest(&self) -> &str {
        &self.upstream_artifact_digest
    }

    /// Returns the admitted operation snapshot bound to this declaration.
    #[must_use]
    pub fn admitted_operations(&self) -> &[String] {
        &self.admitted_operations
    }

    /// Returns the binding digest over this declaration snapshot.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

/// Reports whether `executable` names the admitted analyzer route.
///
/// Explicit pinning (`C:/tools/rust-analyzer.exe`, `./rust-analyzer`) is
/// admitted; a differently-named provider under the same operation is a
/// route mismatch and is refused: no provider is ever substituted under
/// the same operation.
fn admitted_analyzer_executable(executable: &str) -> bool {
    let base = executable.rsplit('/').next().unwrap_or(executable);
    let base = base.rsplit('\\').next().unwrap_or(base);
    base.eq_ignore_ascii_case(RUST_ANALYZER_EXECUTABLE)
        || base.eq_ignore_ascii_case("rust-analyzer.exe")
}

/// Validates bounded input and the exact operation/route before the
/// underlying call. Executor admission (operation identity, generation
/// binding) stays in [`LspBridge::launch`]; this gate covers what admission
/// cannot see: the concrete projection.
///
/// Refusals are typed and create no authority, no operation identity, no
/// task decision and no permission. A refused call is never dispatched, so
/// there is nothing to reconcile; retries repeat the same invocation
/// identity and no provider is ever substituted under the same operation.
///
/// Deadline, cancellation and uncertain post-dispatch outcomes stay with
/// their existing owners: expiry and cancellation surface as incomplete
/// evidence reconciled under the original operation identity (a cancellation
/// acknowledgement is not proof of process or descendant termination), and
/// malformed output normalizes to a stale receipt disposition, never to a
/// proven no-effect claim. Every admitted operation is read-only with
/// respect to sources, so unlike a mutating bridge this gate needs no
/// uncertain-effect error: post-dispatch unknowns travel on the receipt.
fn gate_lsp_call(
    obligations: &LspApplicationObligations,
    analyzer: AnalyzerKind,
    executable: &str,
    arguments: &[String],
    working_directory: &str,
) -> Result<(), BridgeError> {
    if !admitted_analyzer_executable(executable) {
        return Err(BridgeError::RouteMismatch {
            observed: executable.to_owned(),
        });
    }
    if !Path::new(working_directory).is_absolute() {
        return Err(BridgeError::CallOverBound {
            what: "working directory must be absolute",
        });
    }
    if working_directory.contains('\0') {
        return Err(BridgeError::CallOverBound {
            what: "working directory must not contain NUL bytes",
        });
    }
    let Some(first) = arguments.first() else {
        return Err(BridgeError::OperationNotAdmitted {
            operation: "<empty argv>".to_owned(),
        });
    };
    if !obligations.supported_operations.contains(&first.as_str()) {
        return Err(BridgeError::OperationNotAdmitted {
            operation: first.clone(),
        });
    }
    // The analyzer path must serve the projected argv: `--version` is a
    // RustAnalyzer probe; any other first token must be that analyzer's own
    // subcommand. A crossed projection (Scip analyzer, diagnostics argv)
    // cannot dispatch.
    let served = match analyzer {
        AnalyzerKind::RustAnalyzer => {
            first.as_str() == "--version" || first.as_str() == analyzer.subcommand()
        }
        AnalyzerKind::Scip => first.as_str() == analyzer.subcommand(),
    };
    if !served {
        return Err(BridgeError::OperationNotAdmitted {
            operation: format!("{} via {analyzer:?}", first.as_str()),
        });
    }
    if arguments.len() > LSP_ARGV_CAP {
        return Err(BridgeError::CallOverBound {
            what: "argv exceeds the admitted argument count",
        });
    }
    let mut total = 0usize;
    for arg in arguments {
        if arg.contains('\0') {
            return Err(BridgeError::CallOverBound {
                what: "argv must not contain NUL bytes",
            });
        }
        if arg.len() > LSP_ARG_BYTES_CAP {
            return Err(BridgeError::CallOverBound {
                what: "single argument exceeds the admitted byte length",
            });
        }
        total += arg.len();
    }
    if total > LSP_ARGV_BYTES_CAP {
        return Err(BridgeError::CallOverBound {
            what: "argv exceeds the admitted total byte length",
        });
    }
    Ok(())
}

/// Facade over the shared process contract for one-shot analyzer launches.
///
/// The bridge holds only the executor handle: no child, session, or cache
/// survives a call. Each request spawns exactly one process through `start`
/// and reconciles it through `reconcile`.
///
/// This is the sole analyzer launch path: the bridge constructor takes the
/// shared executor handle (no ambient process access), [`LspCommand`] is the
/// sole `rust-analyzer` argv projection, and [`LspBridge::launch`] admits
/// only requests that match that projection with a bound receipt. There is
/// no CodeCortex-private execution path around it.
pub struct LspBridge<E> {
    executor: Arc<E>,
    stitch: Mutex<StitchState>,
}

/// Dispatch-held stitch state for the generation/removal sequence.
///
/// The bridge never stages generations or attests canaries itself: staged
/// values come from [`lsp_application_obligations`] through
/// [`LspBridge::stage_generation`] or [`LspBridge::load_admitted`] with a
/// caller-observed upstream identity line and a caller-attested artifact
/// digest, and the canary-gated switch stays with the composition owner
/// holding the [`AdmittedLine`]. What dispatch owns is fence consultation,
/// exact-identity in-flight tracking across the launch/reconcile boundary
/// (a launch notes the operation identity with its admitted first-argv
/// token; reconcile settles it and feeds the observed exit), and
/// receipt-exit evidence — recorded here under one lock that is never held
/// across an executor call. A poisoned lock fails the call that still needs
/// the state; paths whose outcome is already decided settle best-effort
/// instead.
#[derive(Debug, Default)]
struct StitchState {
    removal: RemovalPlan,
    ledger: InFlightLedger,
    pending_tokens: BTreeMap<String, String>,
    per_operation_exits: BTreeMap<String, i32>,
    last_exit: Option<i32>,
}

/// Typed failure returned by the original admitted Kernel process owner.
#[derive(Debug)]
pub enum LspProcessOwnerError {
    /// The Kernel rejected the original admission.
    Rejected { code: String, detail: String },
    /// The original process-owner boundary failed before returning a typed
    /// process receipt. Keep the concrete owner error as the source instead
    /// of flattening its contract, transport, or outcome category into text.
    Owner(Box<dyn std::error::Error + Send + Sync>),
    /// The admitted process operation failed at its owner boundary.
    Process(ProcessExecutionError),
}

impl std::fmt::Display for LspProcessOwnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { code, detail } => {
                write!(
                    f,
                    "Kernel rejected LSP process admission ({code}): {detail}"
                )
            }
            Self::Owner(error) => write!(f, "LSP process owner failed: {error}"),
            Self::Process(error) => write!(f, "LSP process owner failed: {error}"),
        }
    }
}

impl std::error::Error for LspProcessOwnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected { .. } => None,
            Self::Owner(error) => Some(error.as_ref()),
            Self::Process(error) => Some(error),
        }
    }
}

/// Sendable future returned by the original process owner.
pub type LspProcessOwnerFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LspProcessOwnerError>> + Send + 'a>>;

/// Complete process streams read back from the original Kernel owner.
///
/// `None` means no separate full-byte readback was returned. The bridge may
/// use a complete inline preview directly; a truncated preview remains
/// incomplete evidence and cannot be promoted into a current result. Bytes
/// returned here are accepted only when their exact length and digest match
/// the corresponding `ProcessStreamEvidence`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LspProcessStreamReadback {
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

impl LspProcessStreamReadback {
    /// Packages exact original-owner stdout/stderr bytes when available.
    #[must_use]
    pub fn new(stdout: Option<Vec<u8>>, stderr: Option<Vec<u8>>) -> Self {
        Self { stdout, stderr }
    }

    fn bytes(&self, kind: ProcessStreamKind) -> Option<&[u8]> {
        match kind {
            ProcessStreamKind::Stdout => self.stdout.as_deref(),
            ProcessStreamKind::Stderr => self.stderr.as_deref(),
        }
    }
}

/// Capability over the original session-bound Kernel process owner.
///
/// Start accepts only an already owner-created admission. Reconciliation and
/// complete stream readback are always keyed from the original non-Clone
/// bridge launch handle; serialized or fabricated process evidence cannot
/// supply replacement output bytes.
pub trait LspProcessOwnerPort: Send + Sync {
    /// Starts one exact admitted process request through the original Kernel.
    fn start(
        &self,
        admission: ProcessExecutionAdmissionRequest,
    ) -> LspProcessOwnerFuture<'_, ProcessStartReceipt>;

    /// Reconciles one operation through the same session-bound owner.
    fn reconcile(&self, operation_id: OperationId) -> LspProcessOwnerFuture<'_, ProcessEvidence>;

    /// Reads complete stdout/stderr bytes through the original process owner.
    ///
    /// The bridge verifies every returned stream against the full digest and
    /// byte count in `evidence`. If a stream's inline preview is truncated and
    /// this owner cannot retrieve the complete bytes, it must return `None`;
    /// the retained observation will stay incomplete/stale.
    fn read_streams<'a>(
        &'a self,
        process_start: &'a ProcessStartReceipt,
        evidence: &'a ProcessEvidence,
    ) -> LspProcessOwnerFuture<'a, LspProcessStreamReadback>;
}

/// Proof-bound Current path over original Kernel process and Git owners.
pub struct LspCurrentBridge<P, G> {
    process_owner: Arc<P>,
    git_owner: Arc<G>,
    scip_cache: Option<Mutex<ScipProjectionCache>>,
}

impl<P, G> LspCurrentBridge<P, G> {
    /// Creates a Current path over the admitted process owner and Git runner.
    pub fn new(process_owner: Arc<P>, git_owner: Arc<G>) -> Self {
        Self {
            process_owner,
            git_owner,
            scip_cache: None,
        }
    }

    /// Creates a Current path that retains the supplied bounded SCIP cache for
    /// live retained normalization. The cache keeps its original store and
    /// trust owner; each cache key still comes from the original admitted
    /// invocation and live source proof.
    #[must_use]
    pub fn new_with_scip_cache(
        process_owner: Arc<P>,
        git_owner: Arc<G>,
        scip_cache: ScipProjectionCache,
    ) -> Self {
        Self {
            process_owner,
            git_owner,
            scip_cache: Some(Mutex::new(scip_cache)),
        }
    }
}

impl<E> LspBridge<E> {
    /// Creates a bridge over the supplied process implementation.
    pub fn new(executor: Arc<E>) -> Self {
        Self {
            executor,
            stitch: Mutex::new(StitchState::default()),
        }
    }

    /// Stages one generation candidate bound to this bridge's declaration.
    ///
    /// The admitted-operation snapshot comes from
    /// [`lsp_application_obligations`], so the declaration and the staged
    /// generation cannot drift apart. The upstream identity line is the
    /// caller-observed `rust-analyzer --version` output, validated through
    /// the original identity parser, and `upstream_artifact_digest` is the
    /// caller-attested digest of the bound artifact (64 hexadecimal
    /// characters): staging records both and never installs
    /// anything. The route is the default analyzer executable; an explicitly
    /// pinned route is staged directly by the composition owner holding the
    /// [`AdmittedLine`], as is the canary-gated switch.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::BlankField`] on a blank identity line or
    /// digest, [`GenerationError::ArtifactDigestShape`] on a malformed
    /// digest, or [`GenerationError::UpstreamIdentity`] when the line is not
    /// an exact analyzer version line.
    pub fn stage_generation(
        upstream_version_line: &str,
        upstream_artifact_digest: &str,
    ) -> Result<StagedGeneration, GenerationError> {
        let obligations = lsp_application_obligations();
        StagedGeneration::stage(
            RUST_ANALYZER_EXECUTABLE,
            upstream_version_line,
            upstream_artifact_digest,
            obligations.supported_operations,
        )
    }

    /// Loads the admitted generation line from a versioned declaration.
    ///
    /// This is the artifact-bound loader for the lsp bridge: it consumes the
    /// presented [`LspBridgeDeclaration`], refuses revision, route, digest,
    /// or operation-set drift against the live bridge declaration with a
    /// typed error, and only then admits the initial generation. The
    /// canary-gated switch to a later generation stays with the composition
    /// owner holding the returned [`AdmittedLine`].
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::RouteMismatch`] when the declaration names
    /// another route, [`GenerationError::OperationsMismatch`] on revision or
    /// operation-set drift, [`GenerationError::ArtifactDigestShape`] on a
    /// malformed digest, [`GenerationError::UpstreamIdentity`] on an
    /// unrecognized identity line, or [`GenerationError::BlankField`] on a
    /// blank input. Nothing is admitted on these paths.
    pub fn load_admitted(
        declaration: &LspBridgeDeclaration,
    ) -> Result<AdmittedLine, GenerationError> {
        if declaration.route_executable() != RUST_ANALYZER_EXECUTABLE {
            return Err(GenerationError::RouteMismatch {
                staged: declaration.route_executable().to_owned(),
                admitted: RUST_ANALYZER_EXECUTABLE.to_owned(),
            });
        }
        if declaration.revision() != LSP_DECLARATION_REVISION {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "presented declaration revision {} does not match bridge revision {}",
                    declaration.revision(),
                    LSP_DECLARATION_REVISION
                ),
            });
        }
        if !declaration.binding_verifies() {
            return Err(GenerationError::OperationsMismatch {
                detail: "presented declaration binding digest does not cover its snapshot"
                    .to_owned(),
            });
        }
        let obligations = lsp_application_obligations();
        let live: Vec<String> = obligations
            .supported_operations
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect();
        if declaration.admitted_operations() != live.as_slice() {
            return Err(GenerationError::OperationsMismatch {
                detail: format!(
                    "presented declaration admits {} operations, bridge admits {}",
                    declaration.admitted_operations().len(),
                    live.len()
                ),
            });
        }
        let admitted: Vec<&str> = live.iter().map(String::as_str).collect();
        let staged = StagedGeneration::stage(
            declaration.route_executable(),
            declaration.upstream_version_line(),
            declaration.upstream_artifact_digest(),
            &admitted,
        )?;
        Ok(AdmittedLine::admit_initial(staged))
    }
}

impl<E: ProcessExecutor + 'static> LspBridge<E> {
    /// Validates, starts, and retains the admitted facts needed to bind the
    /// eventual normalized observation. The consumed `ProcessRequest` remains
    /// inside the Kernel process boundary; only its inert intent and original
    /// digest are carried on this in-memory handle.
    #[allow(clippy::too_many_arguments)]
    pub async fn launch_retained(
        &self,
        command: &LspCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
        instrument_invocation: &InstrumentInvocation,
        source_candidate: &SourceCandidate,
        source_scope: Option<&GovernedGitScope>,
        candidate_identity: Option<&CandidateIdentity>,
        build_fingerprint: Option<&BuildFingerprint>,
        config: &AnalyzerConfig,
        operation: &SemanticOperation,
        resolved_executable: &ResolvedExecutableIdentity,
        registry_entry: &RegistryEntry,
        instrument_spec: &InstrumentSpec,
    ) -> Result<LspStartedInvocation, BridgeError> {
        self.launch_retained_inner(
            command,
            request,
            sink,
            instrument_invocation,
            source_candidate,
            source_scope,
            candidate_identity,
            build_fingerprint,
            config,
            operation,
            resolved_executable,
            registry_entry,
            instrument_spec,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_retained_inner(
        &self,
        command: &LspCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
        instrument_invocation: &InstrumentInvocation,
        source_candidate: &SourceCandidate,
        source_scope: Option<&GovernedGitScope>,
        candidate_identity: Option<&CandidateIdentity>,
        build_fingerprint: Option<&BuildFingerprint>,
        config: &AnalyzerConfig,
        operation: &SemanticOperation,
        resolved_executable: &ResolvedExecutableIdentity,
        registry_entry: &RegistryEntry,
        instrument_spec: &InstrumentSpec,
    ) -> Result<LspStartedInvocation, BridgeError> {
        config.validate()?;
        source_candidate.validate()?;
        if let Some(source_scope) = source_scope {
            validate_git_scope(source_scope)?;
        }
        instrument_invocation
            .validate()
            .map_err(BridgeError::InstrumentContract)?;
        request.validate().map_err(BridgeError::ProcessEvidence)?;
        validate_instrument_process_request(&request, instrument_invocation)?;
        validate_candidate_identity(candidate_identity, build_fingerprint)?;
        registry_entry
            .verify_profile_identities()
            .and_then(|()| registry_entry.check_resolved_executable(Some(resolved_executable)))
            .map_err(|error| BridgeError::ExecutableIdentity(error.to_string()))?;
        validate_instrument_binding(
            command,
            request.intent(),
            source_candidate,
            config,
            operation,
            &LspInstrumentBindingOwner {
                invocation: instrument_invocation,
                resolved: resolved_executable,
                registry: registry_entry,
                spec: instrument_spec,
            },
        )?;
        validate_invocation_sidecar(command, config, operation, None)?;

        let request_intent = request.intent().clone();
        let invocation_digest = request.invocation_digest().to_owned();
        let expected_operation = request.operation_id().clone();
        let expected_generation = request.generation().get();
        let expected_fence = request.fence().clone();
        let process_start = self.launch(command, request, sink).await?;
        process_start
            .validate()
            .map_err(BridgeError::ProcessEvidence)?;
        if process_start.operation_id() != &expected_operation
            || process_start.request_digest() != invocation_digest
            || process_start.accepted_generation().get() != expected_generation
            || process_start.binding().state_fence() != &expected_fence
        {
            return Err(BridgeError::ReceiptMismatch);
        }
        Ok(LspStartedInvocation {
            process_start,
            instrument_invocation: instrument_invocation.clone(),
            source_candidate: source_candidate.clone(),
            source_scope_at_dispatch: source_scope.cloned(),
            candidate_identity: candidate_identity.cloned(),
            build_fingerprint: build_fingerprint.cloned(),
            config: config.clone(),
            operation: operation.clone(),
            process_intent: request_intent,
            invocation_digest,
            resolved_executable: ResolvedExecutableIdentityRecord::from(resolved_executable),
            instrument_spec: instrument_spec.clone(),
            registry_identity: LspRegistryIdentity::from(registry_entry),
            source_artifact_proof: None,
            scip_output_owner: None,
        })
    }

    /// Validates and starts one exact analyzer invocation.
    pub async fn launch(
        &self,
        command: &LspCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, BridgeError> {
        gate_lsp_call(
            &lsp_application_obligations(),
            command.analyzer,
            &command.executable,
            &command.arguments,
            &command.working_directory,
        )?;
        if !command.matches_request(&request) {
            return Err(BridgeError::CommandMismatch);
        }
        let Some(first) = command.arguments.first() else {
            return Err(BridgeError::OperationNotAdmitted {
                operation: "<empty argv>".to_owned(),
            });
        };
        let operation_id = request.operation_id().clone();
        let identity = operation_id.as_str().to_owned();
        self.note_launched(&identity, first)?;
        let request_digest = request.invocation_digest().to_owned();
        let generation = request.generation().get();
        let receipt = match self.executor.start(request, sink).await {
            Ok(receipt) => receipt,
            Err(error) => {
                self.settle_unstarted(&identity);
                return Err(BridgeError::ProcessLaunch {
                    invocation: command.describe(),
                    error,
                });
            }
        };
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
    ///
    /// The returned receipt is the executor's acknowledgement, not proof of
    /// process or descendant termination and not a rollback: the outcome
    /// stays unknown until [`LspBridge::reconcile`] reports evidence under
    /// the original operation identity. A retry repeats the same admitted
    /// command; no provider is substituted under the same operation.
    pub async fn cancel(
        &self,
        operation: &OperationId,
    ) -> Result<CancellationReceipt, BridgeError> {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles durable process evidence without inventing analyzer output.
    ///
    /// Settling is exact-identity: the operation noted at launch is settled
    /// here and its observed exit feeds the per-operation evidence. An
    /// identity this bridge never launched (or already reconciled) still
    /// returns its evidence unmodified — evidence readback repeats under the
    /// same identity, but only this bridge's own launches attribute exits.
    pub async fn reconcile(&self, operation: &OperationId) -> Result<ProcessEvidence, BridgeError> {
        let evidence = self.executor.reconcile(operation.clone()).await?;
        self.settle_reconciled(operation.as_str(), &evidence);
        Ok(evidence)
    }

    /// Refuses fenced launches and notes one exact operation identity with
    /// its admitted first-argv token.
    ///
    /// Runs after the call gate and the request match, before the executor
    /// start, so refused calls are never noted and noted calls always reach
    /// the executor. The token lets [`LspBridge::reconcile`] attribute the
    /// observed exit to the admitted operation that produced it.
    fn note_launched(&self, identity: &str, token: &str) -> Result<(), BridgeError> {
        let mut stitch = self.stitch.lock().map_err(|_| {
            BridgeError::Process(ProcessExecutionError::Unavailable(
                "bridge stitch state lock poisoned".to_owned(),
            ))
        })?;
        if stitch.removal.blocks_new_calls() {
            return Err(BridgeError::RemovalFenced);
        }
        stitch.ledger.note_dispatched(identity);
        stitch
            .pending_tokens
            .insert(identity.to_owned(), token.to_owned());
        Ok(())
    }

    /// Settles one noted launch whose executor start never completed.
    ///
    /// Best-effort: the start was refused atomically, so nothing was
    /// dispatched and there is nothing to reconcile. The pending token goes
    /// back with the identity; a later reconcile under the same identity
    /// still returns its evidence unmodified, only without exit attribution.
    fn settle_unstarted(&self, identity: &str) {
        let Ok(mut stitch) = self.stitch.lock() else {
            return;
        };
        stitch.pending_tokens.remove(identity);
        let _ = stitch.ledger.note_settled(identity);
    }

    /// Settles one launched identity against its reconciled evidence,
    /// feeding the observed exit into the per-operation evidence.
    ///
    /// Only launches this bridge noted attribute exits: an identity with no
    /// pending token is either already reconciled or belongs to another
    /// bridge sharing the executor, so its evidence is returned untouched
    /// and nothing is recorded. Exit recording itself is total — an evidence
    /// without an observed exit code leaves the previous evidence in place.
    fn settle_reconciled(&self, identity: &str, evidence: &ProcessEvidence) {
        let Ok(mut stitch) = self.stitch.lock() else {
            return;
        };
        let Some(token) = stitch.pending_tokens.remove(identity) else {
            return;
        };
        let _ = stitch.ledger.note_settled(identity);
        if let Some(code) = Self::exit_code(evidence) {
            stitch.per_operation_exits.insert(token, code);
            stitch.last_exit = Some(code);
        }
    }

    /// Fences new launches for removal.
    ///
    /// Held by the composition owner: dispatch consults
    /// [`RemovalPlan::blocks_new_calls`] on every launch and refuses fenced
    /// launches with [`BridgeError::RemovalFenced`] before any process
    /// starts. Draining, owner revocation, and artifact release stay with
    /// the owner.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Removal`] when the plan is already fenced, or
    /// [`BridgeError::Process`] when the stitch lock is poisoned.
    pub fn fence_new_calls(&self) -> Result<(), BridgeError> {
        self.stitch
            .lock()
            .map_err(|_| {
                BridgeError::Process(ProcessExecutionError::Unavailable(
                    "bridge stitch state lock poisoned".to_owned(),
                ))
            })?
            .removal
            .fence_new_calls()?;
        Ok(())
    }

    /// Projects declared-versus-observed status against the owner's line.
    ///
    /// The declaration side comes from the caller-held [`AdmittedLine`], and
    /// the presented [`LspBridgeDeclaration`] must bind that live generation
    /// (revision, route, identity line, artifact digest, and operation set);
    /// the evidence side (overall and per-operation exits) is dispatch's own
    /// reconciled evidence recorded on this bridge. Operations with no
    /// observed exit stay explicitly unknown instead of inheriting bridge
    /// health.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Declaration`] when the presented declaration
    /// does not bind the live generation, or [`BridgeError::Process`] when
    /// the stitch lock is poisoned.
    pub fn status_against(
        &self,
        line: &AdmittedLine,
        declaration: &LspBridgeDeclaration,
    ) -> Result<BridgeStatusProjection, BridgeError> {
        line.check_bound(
            declaration.revision(),
            declaration.route_executable(),
            declaration.upstream_version_line(),
            declaration.upstream_artifact_digest(),
            declaration.admitted_operations(),
        )
        .map_err(BridgeError::Declaration)?;
        let stitch = self.stitch.lock().map_err(|_| {
            BridgeError::Process(ProcessExecutionError::Unavailable(
                "bridge stitch state lock poisoned".to_owned(),
            ))
        })?;
        Ok(BridgeStatusProjection::project(
            line.current(),
            line.retained(),
            ObservedHealth::from_last_exit(stitch.last_exit),
            &stitch.per_operation_exits,
        ))
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

    /// Reports whether reconciled stderr capture retained only a prefix.
    #[must_use]
    pub fn stderr_truncated(evidence: &ProcessEvidence) -> bool {
        evidence
            .stderr()
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

impl<P: LspProcessOwnerPort, G: GitProcessRunner> LspCurrentBridge<P, G> {
    /// Starts only through the original Kernel admission and only when the
    /// exact source snapshot is still current immediately before start.
    #[allow(clippy::too_many_arguments)]
    pub async fn launch_retained_with_source_artifact_proof(
        &self,
        command: &LspCommand,
        admission: ProcessExecutionAdmissionRequest,
        instrument_invocation: &InstrumentInvocation,
        source_candidate: &SourceCandidate,
        source_root: &RepoRoot,
        source_scope: Option<&GovernedGitScope>,
        candidate_identity: Option<&CandidateIdentity>,
        build_fingerprint: Option<&BuildFingerprint>,
        config: &AnalyzerConfig,
        operation: &SemanticOperation,
        resolved_executable: &ResolvedExecutableIdentity,
        registry_entry: &RegistryEntry,
        instrument_spec: &InstrumentSpec,
        source_artifact_proof: LspSourceArtifactProof,
        scip_output_owner: Option<OwnedDirectoryPublication>,
    ) -> Result<LspStartedInvocation, BridgeError> {
        config.validate()?;
        source_candidate.validate()?;
        if let Some(source_scope) = source_scope {
            validate_git_scope(source_scope)?;
        }
        instrument_invocation
            .validate()
            .map_err(BridgeError::InstrumentContract)?;
        validate_instrument_process_admission(&admission, instrument_invocation)?;
        validate_candidate_identity(candidate_identity, build_fingerprint)?;
        registry_entry
            .verify_profile_identities()
            .and_then(|()| registry_entry.check_resolved_executable(Some(resolved_executable)))
            .map_err(|error| BridgeError::ExecutableIdentity(error.to_string()))?;
        validate_instrument_binding(
            command,
            admission.intent(),
            source_candidate,
            config,
            operation,
            &LspInstrumentBindingOwner {
                invocation: instrument_invocation,
                resolved: resolved_executable,
                registry: registry_entry,
                spec: instrument_spec,
            },
        )?;
        validate_invocation_sidecar(command, config, operation, scip_output_owner.as_ref())?;
        let source_artifact_id = &source_artifact_proof.reference.identity.artifact_id;
        if !source_artifact_proof
            .snapshot
            .validates_workspace_root(Path::new(&source_candidate.workspace_root))
            .map_err(BridgeError::SourceSnapshot)?
            || !source_artifact_binds_invocation(&source_artifact_proof, instrument_invocation)
            || instrument_invocation
                .input_artifacts
                .iter()
                .filter(|artifact| *artifact == source_artifact_id)
                .count()
                != 1
        {
            return Err(BridgeError::InconsistentBinding(
                "source artifact, selected workspace, and admitted invocation do not join"
                    .to_owned(),
            ));
        }

        // This is the final live Git readback before the original Kernel owner
        // receives the already-created admission.
        source_artifact_proof
            .revalidate_current(source_root, self.git_owner.as_ref(), source_candidate)
            .await?;
        let expected_intent = admission.intent().clone();
        let expected_fence = admission.state_fence().clone();
        let expected_operation = expected_intent.operation_id().clone();
        let expected_generation = expected_intent.generation().get();
        let process_start = self
            .process_owner
            .start(admission)
            .await
            .map_err(BridgeError::ProcessOwner)?;
        process_start
            .validate()
            .map_err(BridgeError::ProcessEvidence)?;
        if process_start.operation_id() != &expected_operation
            || process_start.accepted_generation().get() != expected_generation
            || process_start.binding().state_fence() != &expected_fence
            || process_start.binding().authority_epoch() != expected_fence.authority_epoch()
            || process_start.binding().process_tree_id() != expected_intent.process_tree_id()
            || process_start.binding().job_id() != expected_intent.job_id()
            || process_start.binding().image_id() != expected_intent.image_id()
            || process_start.binding().session_id() != expected_intent.session_id()
        {
            return Err(BridgeError::ReceiptMismatch);
        }
        let invocation_digest = process_start.request_digest().to_owned();
        Ok(LspStartedInvocation {
            process_start,
            instrument_invocation: instrument_invocation.clone(),
            source_candidate: source_candidate.clone(),
            source_scope_at_dispatch: source_scope.cloned(),
            candidate_identity: candidate_identity.cloned(),
            build_fingerprint: build_fingerprint.cloned(),
            config: config.clone(),
            operation: operation.clone(),
            process_intent: expected_intent,
            invocation_digest,
            resolved_executable: ResolvedExecutableIdentityRecord::from(resolved_executable),
            instrument_spec: instrument_spec.clone(),
            registry_identity: LspRegistryIdentity::from(registry_entry),
            source_artifact_proof: Some(source_artifact_proof),
            scip_output_owner,
        })
    }

    /// Reconciles the original operation through its session-bound owner,
    /// revalidates source after the run, and keeps the retained observation
    /// Stale until adoption repeats live source validation. When post-run
    /// source readback is unavailable, `None` still retains the original
    /// observation as Stale.
    #[allow(clippy::too_many_arguments)]
    pub async fn retain_reconciled_result_with_source_artifact_proof<
        Pub: LspCapturePublicationPort,
    >(
        &self,
        started: LspStartedInvocation,
        source_scope_after_run: Option<&GovernedGitScope>,
        candidate_identity_after_run: Option<&CandidateIdentity>,
        build_fingerprint_after_run: Option<&BuildFingerprint>,
        source_root: &RepoRoot,
        after_run_source_proof: Option<LspSourceArtifactProof>,
        publisher: &Pub,
    ) -> Result<
        (RetainedLspObservationV1, LspAdoptionProjection, Pub::Output),
        LspCaptureCompletionError<Pub::Error>,
    > {
        let started = Arc::new(started);
        let operation_id = started.process_start.operation_id().clone();
        let process_evidence = self
            .process_owner
            .reconcile(operation_id)
            .await
            .map_err(BridgeError::ProcessOwner)?;
        validate_process_owner_readback(&started, &process_evidence)?;
        let stream_readback = self
            .process_owner
            .read_streams(&started.process_start, &process_evidence)
            .await
            .map_err(BridgeError::ProcessOwner)?;
        let raw_outputs = capture_live_raw_outputs(&started, &process_evidence, &stream_readback)?;
        let mut retained = {
            let mut cache = self.scip_cache.as_ref().and_then(|cache| cache.lock().ok());
            Self::retain_result(
                &started,
                process_evidence,
                raw_outputs,
                source_scope_after_run,
                candidate_identity_after_run,
                build_fingerprint_after_run,
                cache.as_deref_mut(),
            )?
        };
        if let Some(dispatch_proof) = started.source_artifact_proof.as_ref()
            && dispatch_proof
                .revalidate_current(
                    source_root,
                    self.git_owner.as_ref(),
                    &started.source_candidate,
                )
                .await
                .is_ok()
            && let Some(after_run_source_proof) = after_run_source_proof
            && dispatch_proof.matches_current_source(&after_run_source_proof)
            && started
                .instrument_invocation
                .input_artifacts
                .contains(&after_run_source_proof.reference.identity.artifact_id)
        {
            let source_binding = retained
                .result
                .receipt_mut()
                .source_binding
                .as_mut()
                .ok_or_else(|| {
                    BridgeError::InconsistentBinding(
                        "retained result omitted its source binding".to_owned(),
                    )
                })?;
            source_binding.source_artifact_after_run = Some(after_run_source_proof.projection());
            validate_source_binding(source_binding)?;
            let candidate = retained
                .source_candidate
                .reference_with_source_binding(source_binding)?;
            retained.result.receipt_mut().candidate = candidate;
        }
        let projection = live_capture_projection(retained, started);
        let record = projection.retained_observation.as_ref();
        let original_payload =
            serde_json::to_vec(record).map_err(BridgeError::CaptureSerialization)?;
        let output = publisher
            .publish(record, &projection, &original_payload)
            .await
            .map_err(LspCaptureCompletionError::Publication)?;
        Ok((record.clone(), projection, output))
    }

    /// Adopts only after same-owner reconciliation and fresh source
    /// revalidation at the adoption boundary. When current source readback is
    /// unavailable, `None` returns a stale observation. Matching endpoint
    /// captures also remain stale: the analyzer reads a mutable workspace,
    /// so equality cannot exclude a source edit and reversal during indexing.
    pub async fn adopt_received_result_with_source_artifact_proof(
        &self,
        readback: &BlobReadChunk,
        projection: &LspAdoptionProjection,
        current: &CurrentLspAdoptionContext<'_>,
        source_root: &RepoRoot,
        current_source_proof: Option<LspSourceArtifactProof>,
    ) -> Result<LspAdoptionProjection, BridgeError> {
        let (record, result) = adopt_captured_observation_from_blob_readback(readback)?;
        if !projection.matches_retained_observation(&record) || projection.observation() != &result
        {
            return Err(BridgeError::InconsistentBinding(
                "received Blob observation differs from the original live capture projection"
                    .to_owned(),
            ));
        }
        let record = Arc::new(record);
        let started = projection.started.as_ref();
        validate_retained_record_matches_started(&record, started)?;
        let operation_id = started.process_start.operation_id().clone();
        let process_evidence = self
            .process_owner
            .reconcile(operation_id)
            .await
            .map_err(BridgeError::ProcessOwner)?;
        validate_process_owner_readback(started, &process_evidence)?;
        if record.process_evidence != process_evidence {
            return Err(BridgeError::InconsistentBinding(
                "received process evidence differs from original process-owner readback".to_owned(),
            ));
        }
        let currentness = self
            .source_artifact_currentness(
                &record,
                started,
                current,
                source_root,
                received_result_currentness(&record, current),
                current_source_proof,
            )
            .await;
        Ok(LspAdoptionProjection {
            observation: adopt_received_result(record.as_ref().clone(), current)?,
            currentness,
            retained_observation: record,
            started: Arc::clone(&projection.started),
        })
    }

    async fn source_artifact_currentness(
        &self,
        record: &RetainedLspObservationV1,
        started: &LspStartedInvocation,
        current: &CurrentLspAdoptionContext<'_>,
        source_root: &RepoRoot,
        mut currentness: Freshness,
        current_source_proof: Option<LspSourceArtifactProof>,
    ) -> Freshness {
        let Some(dispatch_proof) = started.source_artifact_proof.as_ref() else {
            return currentness;
        };
        if let Err(error) = dispatch_proof
            .revalidate_current(
                source_root,
                self.git_owner.as_ref(),
                current.source_candidate,
            )
            .await
        {
            return Freshness::Stale {
                reason: format!("source changed or became unavailable at adoption: {error}"),
            };
        }
        let Some(current_source_proof) = current_source_proof else {
            return currentness;
        };
        let Some(binding) = record.result.receipt().source_binding.as_ref() else {
            return currentness;
        };
        let current_registry = LspRegistryIdentity::from(current.registry_entry);
        let executable_matches =
            ResolvedExecutableIdentityRecord::from(current.resolved_executable)
                == started.resolved_executable;
        let profile_matches = current_registry == record.registry_identity
            && current.instrument_spec == &started.instrument_spec
            && current.registry_entry.instrument == started.instrument_invocation.instrument
            && current.registry_entry.parser == current.instrument_spec.parser
            && current
                .registry_entry
                .supports(started.instrument_invocation.kind)
            && current.registry_entry.verify_profile_identities().is_ok()
            && current
                .registry_entry
                .check_resolved_executable(Some(current.resolved_executable))
                .is_ok();
        let workspace_matches = match current_source_proof
            .snapshot
            .validates_workspace_root(Path::new(&current.source_candidate.workspace_root))
        {
            Ok(matches) => matches,
            Err(error) => {
                return Freshness::Stale {
                    reason: format!("current source workspace is unavailable: {error}"),
                };
            }
        };
        if !workspace_matches {
            return Freshness::Stale {
                reason: "current source artifact belongs to another workspace root".to_owned(),
            };
        }
        let current_projection = current_source_proof.projection();
        let owner_matches = dispatch_proof.matches_current_source(&current_source_proof)
            && source_artifact_binds_invocation(
                &current_source_proof,
                current.instrument_invocation,
            )
            && binding.source_artifact_at_dispatch.as_ref() == Some(&dispatch_proof.projection())
            && binding.source_artifact_after_run.as_ref() == Some(&current_projection)
            && workspace_matches
            && current_source_proof
                .snapshot
                .same_source(&dispatch_proof.snapshot)
            && current_source_proof.artifact.identity().artifact_id
                == current_source_proof.reference.identity.artifact_id
            && current
                .instrument_invocation
                .input_artifacts
                .iter()
                .filter(|artifact| {
                    *artifact == &current_source_proof.reference.identity.artifact_id
                })
                .count()
                == 1
            && current.build_fingerprint == started.build_fingerprint.as_ref()
            && current.candidate_identity == started.candidate_identity.as_ref();
        let process_complete =
            process_succeeded(
                process_evidence_completed(&record.process_evidence),
                process_evidence_exit_code(&record.process_evidence),
            ) && !process_outputs_incomplete(&record.process_evidence, &record.raw_outputs);
        if executable_matches
            && profile_matches
            && owner_matches
            && process_complete
            && source_binding_matches_current(binding, current)
        {
            currentness = Freshness::Stale {
                reason: "matching endpoint source captures do not prove that the mutable analyzer workspace remained unchanged during indexing".to_owned(),
            };
        }
        currentness
    }

    #[allow(clippy::too_many_arguments)]
    fn retain_result(
        started: &LspStartedInvocation,
        process_evidence: ProcessEvidence,
        raw_outputs: Vec<LspRawOutput>,
        source_scope_after_run: Option<&GovernedGitScope>,
        candidate_identity_after_run: Option<&CandidateIdentity>,
        build_fingerprint_after_run: Option<&BuildFingerprint>,
        cache: Option<&mut ScipProjectionCache>,
    ) -> Result<RetainedLspObservationV1, BridgeError> {
        process_evidence
            .validate()
            .map_err(BridgeError::ProcessEvidence)?;
        let process_start = process_start_binding(&started.process_start)?;
        if process_evidence.request_digest() != started.invocation_digest
            || process_evidence.operation_id() != started.process_intent.operation_id()
            || started.process_start.request_digest() != started.invocation_digest
            || started.process_start.operation_id() != started.process_intent.operation_id()
            || process_start.accepted_generation != started.process_intent.generation().get()
        {
            return Err(BridgeError::ReceiptMismatch);
        }
        validate_candidate_identity(candidate_identity_after_run, build_fingerprint_after_run)?;
        validate_raw_outputs(
            &started.instrument_invocation,
            &process_evidence,
            &started.operation,
            &raw_outputs,
        )?;
        let process_completed = process_evidence_completed(&process_evidence);
        let process_truncated = process_outputs_incomplete(&process_evidence, &raw_outputs);
        let exit_code = process_evidence_exit_code(&process_evidence);
        let invoked_at_unix_ms = started.process_start.identity().resumed_at_unix_ms();
        let mut result = normalize_retained_operation(
            &started.config,
            &started.source_candidate,
            &started.operation,
            (
                &started.resolved_executable,
                &started.instrument_spec,
                &started.registry_identity,
            ),
            &raw_outputs,
            &process_evidence,
            invoked_at_unix_ms,
            cache,
            Some(started),
        )?;
        apply_process_completion(&mut result, process_completed, process_truncated, exit_code);
        let source_binding = LspSourceBindingV1 {
            schema_version: 1,
            source_scope_at_dispatch: started.source_scope_at_dispatch.clone(),
            source_scope_after_run: source_scope_after_run.cloned(),
            candidate_identity_at_dispatch: started.candidate_identity.clone(),
            build_fingerprint_at_dispatch: started.build_fingerprint.clone(),
            candidate_identity_after_run: candidate_identity_after_run.cloned(),
            build_fingerprint_after_run: build_fingerprint_after_run.cloned(),
            process_start,
            instrument_request_id: started
                .instrument_invocation
                .request
                .request_id
                .as_str()
                .to_owned(),
            instrument_target: started.instrument_invocation.target.clone(),
            instrument_declared_scope: started.instrument_invocation.declared_scope.clone(),
            instrument_input_artifacts: started.instrument_invocation.input_artifacts.clone(),
            source_artifact_at_dispatch: started
                .source_artifact_proof
                .as_ref()
                .map(LspSourceArtifactProof::projection),
            source_artifact_after_run: None,
            process_operation_id: started.process_intent.operation_id().as_str().to_owned(),
            process_generation: started.process_intent.generation().get(),
            process_working_directory: started.process_intent.working_directory().to_owned(),
        };
        validate_source_binding(&source_binding)?;
        result.receipt_mut().candidate = started
            .source_candidate
            .reference_with_source_binding(&source_binding)?;
        result.receipt_mut().source_binding = Some(source_binding);
        if matches!(&result.receipt().freshness, Freshness::Current) {
            result.receipt_mut().freshness = Freshness::Stale {
                reason: "current source-artifact owner readback is required for adoption"
                    .to_owned(),
            };
        }
        Ok(RetainedLspObservationV1 {
            schema_version: LSP_RETAINED_OBSERVATION_SCHEMA_VERSION,
            receipt_kind: LSP_TOOL_OBSERVATION_RECEIPT_KIND.to_owned(),
            operation: started.operation.clone(),
            config: started.config.clone(),
            source_candidate: started.source_candidate.clone(),
            instrument_invocation: started.instrument_invocation.clone(),
            process_intent: started.process_intent.clone(),
            invocation_digest: started.invocation_digest.clone(),
            resolved_executable: started.resolved_executable.clone(),
            instrument_spec: started.instrument_spec.clone(),
            registry_identity: started.registry_identity.clone(),
            process_evidence,
            raw_outputs,
            result,
        })
    }
}

fn process_evidence_completed(evidence: &ProcessEvidence) -> bool {
    evidence
        .view()
        .exit()
        .is_some_and(|exit| exit.disposition() == ExitDisposition::Completed)
}

fn process_evidence_exit_code(evidence: &ProcessEvidence) -> Option<i32> {
    let exit = evidence.view().exit()?;
    let value = serde_json::to_value(exit).ok()?;
    value
        .get("code")?
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
}

/// Decodes and adopts the original retained envelope from an S-04-authenticated
/// immutable payload read. The returned result preserves the original stale
/// observation receipt; this readback does not establish source or process
/// currentness. The consumer that selected the payload reference must join
/// that reference and its Store task binding before using the decoded record.
pub fn adopt_captured_observation_from_blob_readback(
    readback: &BlobReadChunk,
) -> Result<(RetainedLspObservationV1, NormalizedResult), BridgeError> {
    readback.validate()?;
    let record: RetainedLspObservationV1 = serde_json::from_slice(readback.bytes())?;
    validate_lsp_blob_receipt_binding(readback, &record)?;
    validate_retained_observation(&record)?;
    let result = record.result.clone();
    Ok((record, result))
}

/// Compares one retained result with current task, source, executable,
/// registry, and parser expectations. The record remains Stale because those
/// values cannot replace original process-owner reconciliation and an
/// immutable source-artifact readback.
fn adopt_received_result(
    record: RetainedLspObservationV1,
    current: &CurrentLspAdoptionContext<'_>,
) -> Result<NormalizedResult, BridgeError> {
    validate_retained_observation(&record)?;
    validate_received_result_request(&record, current)?;
    Ok(record.result)
}

fn validate_lsp_blob_receipt_binding(
    readback: &BlobReadChunk,
    record: &RetainedLspObservationV1,
) -> Result<(), BridgeError> {
    let ready_receipt = readback.ready_receipt().receipt();
    let core = &ready_receipt.core;
    let request = &record.instrument_invocation.request;
    let task_matches = match (&request.task_id, &core.task) {
        (Some(task_id), Some(task)) => {
            &task.task_id == task_id && task.state_fence == request.state_fence
        }
        (None, None) => true,
        _ => false,
    };
    let session_matches = match (&request.session_id, &core.session) {
        (Some(session_id), Some(session)) => {
            &session.session_id == session_id && session.state_fence == request.state_fence
        }
        (None, None) => true,
        _ => false,
    };
    if core.operation.operation_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND
        || core.request.metadata != *request
        || core.request.state_fence != request.state_fence
        || core.operation.request_id != request.request_id
        || core.operation.state_fence != request.state_fence
        || core.causal.state_fence != request.state_fence
        || core.authority.state_fence != request.state_fence
        || core.work_scope.state_fence != request.state_fence
        || core.work_scope.product_id != request.product_id
        || !task_matches
        || !session_matches
    {
        return Err(BridgeError::InconsistentBinding(
            "authenticated Blob receipt does not join to the original LSP request metadata, task, session, or work scope".to_owned(),
        ));
    }
    Ok(())
}

fn validate_received_result_request(
    record: &RetainedLspObservationV1,
    current: &CurrentLspAdoptionContext<'_>,
) -> Result<(), BridgeError> {
    current.source_candidate.validate()?;
    current.config.validate()?;
    current
        .instrument_invocation
        .validate()
        .map_err(BridgeError::InstrumentContract)?;
    validate_candidate_identity(current.candidate_identity, current.build_fingerprint)?;
    if let Some(source_scope) = current.source_scope {
        validate_git_scope(source_scope)?;
    }
    if current.source_candidate != &record.source_candidate
        || current.config != &record.config
        || current.operation != &record.operation
        || current.instrument_invocation != &record.instrument_invocation
    {
        return Err(BridgeError::InconsistentBinding(
            "retained invocation does not match the current task request".to_owned(),
        ));
    }
    Ok(())
}

fn received_result_currentness(
    record: &RetainedLspObservationV1,
    current: &CurrentLspAdoptionContext<'_>,
) -> Freshness {
    let current_registry = LspRegistryIdentity::from(current.registry_entry);
    let executable_matches = ResolvedExecutableIdentityRecord::from(current.resolved_executable)
        == record.resolved_executable;
    let profile_matches = current_registry == record.registry_identity
        && current.instrument_spec == &record.instrument_spec
        && current.registry_entry.instrument == record.instrument_invocation.instrument
        && current.registry_entry.parser == current.instrument_spec.parser
        && current
            .registry_entry
            .supports(current.instrument_invocation.kind)
        && current.registry_entry.verify_profile_identities().is_ok()
        && current
            .registry_entry
            .check_resolved_executable(Some(current.resolved_executable))
            .is_ok();
    let source_matches = record
        .result
        .receipt()
        .source_binding
        .as_ref()
        .is_some_and(|binding| source_binding_matches_current(binding, current));
    let process_matches =
        process_succeeded(
            process_evidence_completed(&record.process_evidence),
            process_evidence_exit_code(&record.process_evidence),
        ) && !process_outputs_incomplete(&record.process_evidence, &record.raw_outputs);
    Freshness::Stale {
        reason: if !process_matches {
            "original tool process did not complete successfully with complete output".to_owned()
        } else if !executable_matches || !profile_matches {
            "current executable or admitted profile differs from the captured invocation".to_owned()
        } else if !source_matches {
            "current source or admitted candidate identity differs from the captured invocation"
                .to_owned()
        } else {
            "current source has no owner-read immutable source-artifact join".to_owned()
        },
    }
}

fn validate_retained_observation(record: &RetainedLspObservationV1) -> Result<(), BridgeError> {
    let source_binding = validate_retained_request_and_receipt(record)?;
    let resolved = record
        .resolved_executable
        .resolve(record.registry_identity.instrument.as_str())?;
    record
        .process_evidence
        .validate()
        .map_err(BridgeError::ProcessEvidence)?;
    let process_invoked_at = record
        .process_evidence
        .view()
        .identity()
        .ok_or(BridgeError::ReceiptMismatch)?
        .resumed_at_unix_ms();
    if record.result.receipt().invoked_at_unix_ms != process_invoked_at {
        return Err(BridgeError::ReceiptMismatch);
    }
    validate_record_identities(record, &resolved)?;
    validate_source_binding(source_binding)?;
    validate_process_source_binding(record, source_binding)?;
    validate_raw_outputs(
        &record.instrument_invocation,
        &record.process_evidence,
        &record.operation,
        &record.raw_outputs,
    )?;
    let process_completed = process_completed(&record.process_evidence);
    let process_truncated =
        process_outputs_incomplete(&record.process_evidence, &record.raw_outputs);
    let exit_code = process_exit_code(&record.process_evidence);
    validate_recorded_scip_artifact(record, process_completed, exit_code)?;

    let receipt = record.result.receipt();
    let mut normalized = normalize_retained_operation(
        &record.config,
        &record.source_candidate,
        &record.operation,
        (
            &record.resolved_executable,
            &record.instrument_spec,
            &record.registry_identity,
        ),
        &record.raw_outputs,
        &record.process_evidence,
        receipt.invoked_at_unix_ms,
        None,
        None,
    )?;
    if let NormalizedResult::Version { version, .. } = &normalized
        && !version.is_empty()
        && record.resolved_executable.tool_version.as_deref() != Some(version.as_str())
    {
        return Err(BridgeError::InconsistentBinding(
            "version-probe output differs from the resolved executable version identity".to_owned(),
        ));
    }
    apply_process_completion(
        &mut normalized,
        process_completed,
        process_truncated,
        exit_code,
    );
    normalized.receipt_mut().candidate = record
        .source_candidate
        .reference_with_source_binding(source_binding)?;
    normalized
        .receipt_mut()
        .source_binding
        .clone_from(&receipt.source_binding);
    validate_recorded_freshness(record, process_completed, process_truncated, exit_code)?;
    normalized.receipt_mut().freshness = receipt.freshness.clone();
    if normalized != record.result {
        return Err(BridgeError::InconsistentBinding(
            "typed result differs from re-normalization of the retained raw bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retained_request_and_receipt(
    record: &RetainedLspObservationV1,
) -> Result<&LspSourceBindingV1, BridgeError> {
    if record.schema_version != LSP_RETAINED_OBSERVATION_SCHEMA_VERSION
        || record.receipt_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND
    {
        return Err(BridgeError::UnsupportedObservationSchema);
    }
    record.config.validate()?;
    record.source_candidate.validate()?;
    record
        .instrument_invocation
        .validate()
        .map_err(BridgeError::InstrumentContract)?;
    if !operation_matches_config(&record.operation, &record.config)
        || !candidate_selectors_match_operation(&record.source_candidate, &record.operation)
    {
        return Err(BridgeError::UnsupportedOperation);
    }
    let receipt = record.result.receipt();
    let (_, expected_normalizer) = expected_parser_and_normalizer(&record.operation);
    let expected_normalizer = ContractId::new(expected_normalizer)
        .map_err(|error| BridgeError::InstrumentIdentity(error.to_string()))?;
    if receipt.config_hash != record.config.config_hash()
        || receipt.executable != record.config.executable
        || receipt.resolved_executable_identity.as_ref() != Some(&record.resolved_executable)
        || receipt.instrument_spec.as_ref() != Some(&record.instrument_spec)
        || receipt.registry_identity.as_ref() != Some(&record.registry_identity)
        || receipt.normalized_result_normalizer.as_ref() != Some(&expected_normalizer)
        || !coverage_matches_operation(
            &receipt.coverage,
            &record.source_candidate,
            &record.operation,
        )
    {
        return Err(BridgeError::InconsistentBinding(
            "result receipt does not match the retained candidate, config, or operation".to_owned(),
        ));
    }
    let source_binding = receipt
        .source_binding
        .as_ref()
        .ok_or_else(|| BridgeError::InconsistentBinding("source binding missing".to_owned()))?;
    if receipt.candidate
        != record
            .source_candidate
            .reference_with_source_binding(source_binding)?
    {
        return Err(BridgeError::InconsistentBinding(
            "receipt candidate does not include the retained source-owner binding".to_owned(),
        ));
    }
    if let NormalizedResult::Rename { candidate, .. } = &record.result
        && candidate.applied
    {
        return Err(BridgeError::AppliedRename);
    }
    Ok(source_binding)
}

fn validate_recorded_scip_artifact(
    record: &RetainedLspObservationV1,
    process_completed: bool,
    exit_code: Option<i32>,
) -> Result<(), BridgeError> {
    if process_succeeded(process_completed, exit_code)
        && matches!(
            &record.operation,
            SemanticOperation::Definitions { .. }
                | SemanticOperation::References { .. }
                | SemanticOperation::Symbols { .. }
                | SemanticOperation::Rename { .. }
        )
    {
        let sidecar = output_for(&record.raw_outputs, LspRawOutputKind::ScipSidecar)
            .ok_or(BridgeError::ScipArtifactNotInvocationOwned)?;
        if sidecar.evidence.truncated {
            return Err(BridgeError::OutputTooLarge);
        }
    }
    Ok(())
}

fn operation_matches_config(operation: &SemanticOperation, config: &AnalyzerConfig) -> bool {
    match operation {
        SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => true,
        SemanticOperation::Definitions { .. }
        | SemanticOperation::References { .. }
        | SemanticOperation::Symbols { .. }
        | SemanticOperation::Rename { .. } => config.scip_output_path.is_some(),
    }
}

fn candidate_selectors_match_operation(
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
) -> bool {
    match operation {
        SemanticOperation::Definitions { symbol }
        | SemanticOperation::References { symbol }
        | SemanticOperation::Rename { symbol, .. } => candidate
            .symbol
            .as_ref()
            .is_none_or(|selected| selected == symbol),
        SemanticOperation::Symbols { path_scope } => candidate
            .path
            .as_ref()
            .is_none_or(|selected| selected == path_scope),
        SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => true,
    }
}

fn coverage_matches_operation(
    coverage: &Coverage,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
) -> bool {
    match (coverage, operation) {
        (Coverage::Workspace { root }, SemanticOperation::Diagnostics) => {
            root == &candidate.workspace_root
        }
        (Coverage::ProbeOnly, SemanticOperation::ProbeVersion) => true,
        (
            Coverage::SingleSymbol { symbol },
            SemanticOperation::Definitions { symbol: expected }
            | SemanticOperation::References { symbol: expected }
            | SemanticOperation::Rename {
                symbol: expected, ..
            },
        ) => symbol == expected,
        (
            Coverage::SymbolSubset { path_scope },
            SemanticOperation::Symbols {
                path_scope: expected,
            },
        ) => path_scope == expected,
        _ => false,
    }
}

fn expected_parser_and_normalizer(operation: &SemanticOperation) -> (&'static str, &'static str) {
    match operation {
        SemanticOperation::Definitions { .. }
        | SemanticOperation::References { .. }
        | SemanticOperation::Symbols { .. }
        | SemanticOperation::Rename { .. } => (SCIP_INSTRUMENT, LSP_BRIDGE_CONTRACT),
        SemanticOperation::Diagnostics => (DIAGNOSTIC_PARSER_CONTRACT, LSP_BRIDGE_CONTRACT),
        SemanticOperation::ProbeVersion => (LSP_BRIDGE_CONTRACT, LSP_BRIDGE_CONTRACT),
    }
}

fn validate_record_identities(
    record: &RetainedLspObservationV1,
    resolved: &ResolvedExecutableIdentity,
) -> Result<(), BridgeError> {
    record
        .process_intent
        .validate()
        .map_err(BridgeError::ProcessEvidence)?;
    validate_instrument_spec(&record.instrument_spec)?;
    let command = command_for(&record.config, &record.source_candidate, &record.operation)?;
    let intent = &record.process_intent;
    let registry = &record.registry_identity;
    let spec = &record.instrument_spec;
    let (expected_parser, _) = expected_parser_and_normalizer(&record.operation);
    if !is_lower_hex_digest(&record.invocation_digest)
        || !resolved.is_complete()
        || intent.executable() != command.executable.as_str()
        || intent.argv() != command.arguments.as_slice()
        || intent.working_directory() != command.working_directory.as_str()
        || intent.executable() != resolved.canonical_path.as_str()
        || intent.executable_sha256() != resolved.content_digest.as_str()
        || resolved.arguments.as_slice() != intent.argv()
        || resolved.environment_digest != environment_projection_digest(intent.environment())
        || resolved.executable_file_name() != path_file_name(&spec.executable)
        || registry
            .executable
            .executable
            .as_deref()
            .map(path_file_name)
            != Some(resolved.executable_file_name())
        || registry.executable.decoder.is_some()
        || registry.instrument != record.instrument_invocation.instrument
        || spec.kind.as_str() != registry.instrument.as_str()
        || registry.parser != spec.parser
        || registry.parser.as_str() != expected_parser
        || !registry.kinds.contains(&record.instrument_invocation.kind)
        || spec.class.coarse_kind() != record.instrument_invocation.kind
        || record.instrument_invocation.arguments != spec.argument_template
        || spec.parser_generation != BUILTIN_PARSER_GENERATION
        || spec.environment_profile != registry.environment_class
        || !registry_projection_is_internally_consistent(registry)
        || record.process_evidence.request_digest() != record.invocation_digest
        || record.process_evidence.operation_id() != intent.operation_id()
        || record.process_evidence.binding().request_digest() != record.invocation_digest
        || record.process_evidence.binding().operation_id() != intent.operation_id()
    {
        return Err(BridgeError::InconsistentBinding(
            "request intent, executable, instrument spec, registry, or process evidence disagree"
                .to_owned(),
        ));
    }
    if !operation_matches_config(&record.operation, &record.config) {
        return Err(BridgeError::UnsupportedOperation);
    }
    validate_invocation_sidecar_path(&record.config, &record.operation)?;
    Ok(())
}

fn registry_projection_is_internally_consistent(registry: &LspRegistryIdentity) -> bool {
    let executable_identity = registry
        .executable
        .executable
        .as_deref()
        .or(registry.executable.decoder.as_deref());
    let required_text = [
        registry.adapter.as_str(),
        registry.toolchain.as_str(),
        registry.environment_class.as_str(),
        registry.resource_contract.as_str(),
        registry.cancellation_contract.as_str(),
        registry.executable.acquisition_rule.as_str(),
        registry.identities.source.as_str(),
        registry.identities.lock.as_str(),
        registry.identities.toolchain.as_str(),
        registry.identities.executable.as_str(),
        registry.identities.features.as_str(),
        registry.identities.environment.as_str(),
        registry.identities.artifact.as_str(),
        registry.identities.fence.as_str(),
        registry.identities.operation.as_str(),
        registry.identities.timeout.as_str(),
        registry.identities.cancellation.as_str(),
        registry.identities.resource.as_str(),
        registry.invalidation.source.as_str(),
        registry.invalidation.lock.as_str(),
        registry.invalidation.toolchain.as_str(),
        registry.invalidation.environment.as_str(),
        registry.invalidation.executable.as_str(),
        registry.invalidation.profile.as_str(),
        registry.invalidation.parser.as_str(),
    ];
    registry.generation > 0
        && !registry.kinds.is_empty()
        && required_text
            .iter()
            .all(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && registry.executable.executable.is_some() != registry.executable.decoder.is_some()
        && registry
            .executable
            .executable
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && registry
            .executable
            .decoder
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && registry
            .targets
            .iter()
            .all(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && registry.identities.toolchain == registry.toolchain
        && registry.identities.executable == executable_identity.unwrap_or_default()
        && registry.identities.environment == registry.environment_class
        && registry.identities.cancellation == registry.cancellation_contract
        && registry.identities.resource == registry.resource_contract
        && !registry.targets.windows(2).any(|pair| pair[0] >= pair[1])
}

fn validate_instrument_spec(spec: &InstrumentSpec) -> Result<(), BridgeError> {
    if spec.parser_generation == 0 || spec.max_concurrency == 0 {
        return Err(BridgeError::InstrumentIdentity(
            "instrument spec has a zero parser generation or concurrency limit".to_owned(),
        ));
    }
    let rebuilt = InstrumentSpec::new(InstrumentSpecParams {
        kind: spec.kind.clone(),
        class: spec.class,
        revision: spec.revision,
        executable: spec.executable.clone(),
        executable_version: spec.executable_version.clone(),
        parser: spec.parser.clone(),
        parser_generation: spec.parser_generation,
        environment_profile: spec.environment_profile.clone(),
        schema: spec.schema.clone(),
        argument_template: spec.argument_template.clone(),
        credential_policy: spec.credential_policy.clone(),
        network_policy: spec.network_policy.clone(),
        limits: spec.limits,
        max_concurrency: spec.max_concurrency,
        verification_command: spec.verification_command.clone(),
    })
    .map_err(|error| BridgeError::InstrumentIdentity(error.to_string()))?;
    if rebuilt != *spec {
        return Err(BridgeError::InstrumentIdentity(
            "instrument spec did not survive its owner validation constructor".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_binding(binding: &LspSourceBindingV1) -> Result<(), BridgeError> {
    if binding.schema_version != 1 {
        return Err(BridgeError::UnsupportedObservationSchema);
    }
    validate_candidate_identity(
        binding.candidate_identity_at_dispatch.as_ref(),
        binding.build_fingerprint_at_dispatch.as_ref(),
    )?;
    if let Some(scope) = binding.source_scope_at_dispatch.as_ref() {
        validate_git_scope(scope)?;
    }
    if let Some(scope) = binding.source_scope_after_run.as_ref() {
        validate_git_scope(scope)?;
    }
    validate_candidate_identity(
        binding.candidate_identity_after_run.as_ref(),
        binding.build_fingerprint_after_run.as_ref(),
    )?;
    match (
        binding.source_artifact_at_dispatch.as_ref(),
        binding.source_artifact_after_run.as_ref(),
    ) {
        (Some(dispatch), Some(after_run)) => {
            validate_source_artifact_projection(binding, dispatch)?;
            validate_source_artifact_projection(binding, after_run)?;
            if dispatch != after_run {
                return Err(BridgeError::InconsistentBinding(
                    "source owner identity moved during the analyzer invocation".to_owned(),
                ));
            }
        }
        (Some(dispatch), None) => validate_source_artifact_projection(binding, dispatch)?,
        (None, Some(_)) => {
            return Err(BridgeError::InconsistentBinding(
                "after-run source owner readback has no dispatch binding".to_owned(),
            ));
        }
        (None, None) => {}
    }
    for (value, field) in [
        (
            binding.instrument_request_id.as_str(),
            "instrument_request_id",
        ),
        (binding.instrument_target.as_str(), "instrument_target"),
        (
            binding.instrument_declared_scope.as_str(),
            "instrument_declared_scope",
        ),
        (
            binding.process_operation_id.as_str(),
            "process_operation_id",
        ),
        (
            binding.process_working_directory.as_str(),
            "process_working_directory",
        ),
    ] {
        checked_text(value, field)?;
    }
    if binding.process_generation == 0
        || binding.process_start.schema_version != 1
        || !is_lower_hex_digest(&binding.process_start.request_digest)
        || binding.process_start.operation_id != binding.process_operation_id
        || binding.process_start.accepted_generation != binding.process_generation
        || binding.instrument_request_id != binding.process_operation_id
    {
        return Err(BridgeError::InconsistentBinding(
            "source binding does not match the admitted process start identity".to_owned(),
        ));
    }
    if let (Some(before), Some(after)) = (
        binding.source_scope_at_dispatch.as_ref(),
        binding.source_scope_after_run.as_ref(),
    ) && before.project_id != after.project_id
    {
        return Err(BridgeError::InconsistentBinding(
            "source owner changed the project identity during one invocation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_artifact_projection(
    binding: &LspSourceBindingV1,
    source: &LspSourceArtifactProjectionV1,
) -> Result<(), BridgeError> {
    let reference = &source.artifact_reference;
    let receipt = &source.read_receipt;
    reference.validate()?;
    let identity_digest = reference.identity.identity_digest()?;
    let identity_source = reference.identity.source.as_ref();
    if source.schema_version != 1
        || !is_git_object_id(&source.git_tree_id)
        || !is_lower_hex_digest(&identity_digest)
        || !is_lower_hex_digest(&receipt.content_digest)
        || !is_lower_hex_digest(&receipt.metadata_sha256)
        || !is_lower_hex_digest(&receipt.anchor_fingerprint)
        || receipt.ready_receipt_id.trim().is_empty()
        || receipt.ready_receipt_id.chars().any(char::is_control)
        || receipt.identity_digest != identity_digest
        || receipt.content_digest != reference.identity.content.digest_hex
        || receipt.metadata_sha256 != reference.expected_metadata_sha256
        || receipt.ready_receipt_id != reference.expected_ready_receipt_id
        || receipt.byte_count != reference.identity.content.size_bytes
        || reference.identity.kind != ArtifactKind::RawEvidence
        || identity_source.is_none_or(|source_binding| {
            source_binding.integrity.as_deref()
                != Some(reference.identity.content.digest_hex.as_str())
                || source_binding.revision != source.git_tree_id
        })
        || binding
            .instrument_input_artifacts
            .iter()
            .filter(|artifact| *artifact == &reference.identity.artifact_id)
            .count()
            != 1
    {
        return Err(BridgeError::InconsistentBinding(
            "source artifact reference, read receipt projection, and admitted input do not join"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_artifact_identity(
    snapshot: &SourceTreeSnapshot,
    reference: &ArtifactReference,
) -> Result<(), BridgeError> {
    let identity = &reference.identity;
    let content_digest = &identity.content.digest_hex;
    if identity.kind != ArtifactKind::RawEvidence
        || !is_lower_hex_digest(content_digest)
        || identity.source.as_ref().is_none_or(|source| {
            source.integrity.as_deref() != Some(content_digest.as_str())
                || source.revision != snapshot.tree_id()
        })
    {
        return Err(BridgeError::InconsistentBinding(
            "immutable source artifact identity does not bind the captured archive and tree revision"
                .to_owned(),
        ));
    }
    Ok(())
}

fn source_artifact_binds_invocation(
    proof: &LspSourceArtifactProof,
    invocation: &InstrumentInvocation,
) -> bool {
    let expected_id = format!("source-snapshot:{}", invocation.request.request_id.as_str());
    proof.reference.identity.artifact_id.as_str() == expected_id
        && proof.reference.identity.kind == ArtifactKind::RawEvidence
        && proof
            .reference
            .identity
            .source
            .as_ref()
            .is_some_and(|source| {
                source.integrity.as_deref()
                    == Some(proof.reference.identity.content.digest_hex.as_str())
                    && source.revision == proof.snapshot.tree_id()
            })
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_process_source_binding(
    record: &RetainedLspObservationV1,
    binding: &LspSourceBindingV1,
) -> Result<(), BridgeError> {
    let invocation = &record.instrument_invocation;
    let intent = &record.process_intent;
    let evidence = &record.process_evidence;
    let process_binding = evidence.binding();
    let request_generation = invocation.request.state_fence.resource_generation.value();
    let exact_source_request = binding.instrument_request_id
        == invocation.request.request_id.as_str()
        && binding.instrument_target == invocation.target
        && binding.instrument_declared_scope == invocation.declared_scope
        && binding.instrument_input_artifacts == invocation.input_artifacts
        && binding.process_operation_id == intent.operation_id().as_str()
        && binding.process_generation == intent.generation().get()
        && binding.process_working_directory == intent.working_directory()
        && intent.working_directory() == record.source_candidate.workspace_root
        && binding.instrument_request_id == binding.process_operation_id
        && binding.process_generation == request_generation
        && binding.process_start.operation_id == intent.operation_id().as_str()
        && binding.process_start.request_digest == record.invocation_digest
        && binding.process_start.accepted_generation == intent.generation().get()
        && record.invocation_digest == evidence.request_digest()
        && record.invocation_digest == process_binding.request_digest()
        && intent.operation_id() == evidence.operation_id()
        && intent.operation_id() == process_binding.operation_id()
        && process_binding.state_fence().generation().get() == request_generation
        && process_binding.state_fence().authority_epoch()
            == &invocation.request.state_fence.authority_epoch
        && invocation
            .request
            .session_id
            .as_ref()
            .is_none_or(|session| session.as_str() == process_binding.session_id().as_str());
    if !exact_source_request {
        return Err(BridgeError::InconsistentBinding(
            "candidate source binding disagrees with the admitted Instrument request or process-owner receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_process_owner_readback(
    started: &LspStartedInvocation,
    evidence: &ProcessEvidence,
) -> Result<(), BridgeError> {
    started
        .process_start
        .validate()
        .map_err(BridgeError::ProcessEvidence)?;
    evidence.validate().map_err(BridgeError::ProcessEvidence)?;
    if evidence.binding() != started.process_start.binding()
        || evidence.operation_id() != started.process_start.operation_id()
        || evidence.request_digest() != started.invocation_digest
        || started.process_start.request_digest() != started.invocation_digest
        || started.process_start.operation_id() != started.process_intent.operation_id()
        || started.process_start.accepted_generation().get()
            != started.process_intent.generation().get()
        || evidence.view().identity() != Some(started.process_start.identity())
    {
        return Err(BridgeError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_retained_record_matches_started(
    record: &RetainedLspObservationV1,
    started: &LspStartedInvocation,
) -> Result<(), BridgeError> {
    if record.instrument_invocation != started.instrument_invocation
        || record.source_candidate != started.source_candidate
        || record.process_intent != started.process_intent
        || record.invocation_digest != started.invocation_digest
        || record.config != started.config
        || record.operation != started.operation
        || record.resolved_executable != started.resolved_executable
        || record.instrument_spec != started.instrument_spec
        || record.registry_identity != started.registry_identity
        || record.process_evidence.binding() != started.process_start.binding()
        || record.process_evidence.operation_id() != started.process_start.operation_id()
        || record.process_evidence.request_digest() != started.invocation_digest
        || started.process_start.request_digest() != started.invocation_digest
        || started.process_start.accepted_generation().get()
            != started.process_intent.generation().get()
        || record.process_evidence.view().identity() != Some(started.process_start.identity())
    {
        return Err(BridgeError::InconsistentBinding(
            "received observation differs from the original private launch handle".to_owned(),
        ));
    }
    Ok(())
}

fn live_capture_projection(
    retained: RetainedLspObservationV1,
    started: Arc<LspStartedInvocation>,
) -> LspAdoptionProjection {
    let observation = retained.result.clone();
    let currentness = observation.receipt().freshness.clone();
    let retained_observation = Arc::new(retained);
    LspAdoptionProjection {
        observation,
        currentness,
        retained_observation,
        started,
    }
}

fn capture_live_raw_outputs(
    started: &LspStartedInvocation,
    process_evidence: &ProcessEvidence,
    stream_readback: &LspProcessStreamReadback,
) -> Result<Vec<LspRawOutput>, BridgeError> {
    if !matches!(
        process_evidence.view().lifecycle(),
        eliot_process::ProcessLifecycle::Exited
            | eliot_process::ProcessLifecycle::Failed
            | eliot_process::ProcessLifecycle::Reconciled
    ) {
        return Err(BridgeError::CaptureNotTerminal);
    }
    let mut outputs = Vec::with_capacity(3);
    for stream_kind in [ProcessStreamKind::Stdout, ProcessStreamKind::Stderr] {
        let stream = match stream_kind {
            ProcessStreamKind::Stdout => process_evidence.stdout(),
            ProcessStreamKind::Stderr => process_evidence.stderr(),
        };
        let owner_bytes = stream_readback.bytes(stream_kind);
        let Some(stream) = stream else {
            if owner_bytes.is_some() {
                return Err(BridgeError::InconsistentBinding(
                    "original process owner returned bytes for a stream absent from its evidence"
                        .to_owned(),
                ));
            }
            continue;
        };
        if stream.stream() != stream_kind
            || stream.preview().representation() != StreamPreviewRepresentation::TransportBytes
        {
            return Err(BridgeError::InconsistentBinding(
                "process stream readback is not exact transport evidence".to_owned(),
            ));
        }
        let preview = stream.preview().bytes();
        let (bytes, truncated) = if let Some(owner_bytes) = owner_bytes {
            let owner_length = u64::try_from(owner_bytes.len()).map_err(|_| {
                BridgeError::InconsistentBinding(
                    "original process stream length does not fit its evidence".to_owned(),
                )
            })?;
            if owner_length != stream.observed_bytes()
                || sha256_hex(owner_bytes) != stream.observed_sha256()
                || !owner_bytes.starts_with(preview)
                || (!stream.preview().is_truncated() && owner_bytes != preview)
            {
                return Err(BridgeError::InconsistentBinding(
                    "original process stream bytes differ from the reconciled full identity or prefix"
                        .to_owned(),
                ));
            }
            if owner_bytes.len() > MAX_TOOL_OUTPUT_BYTES {
                (preview.to_vec(), true)
            } else {
                (owner_bytes.to_vec(), false)
            }
        } else if stream.preview().is_truncated() {
            (preview.to_vec(), true)
        } else {
            let preview_length = u64::try_from(preview.len()).map_err(|_| {
                BridgeError::InconsistentBinding(
                    "original process preview length does not fit its evidence".to_owned(),
                )
            })?;
            if preview_length != stream.observed_bytes()
                || sha256_hex(preview) != stream.observed_sha256()
            {
                return Err(BridgeError::InconsistentBinding(
                    "complete process preview differs from the reconciled full identity".to_owned(),
                ));
            }
            (preview.to_vec(), false)
        };
        let kind = match stream_kind {
            ProcessStreamKind::Stdout => LspRawOutputKind::Stdout,
            ProcessStreamKind::Stderr => LspRawOutputKind::Stderr,
        };
        outputs.push(live_raw_output(started, kind, bytes, truncated)?);
    }

    let is_scip = is_scip_operation(&started.operation);
    if !is_scip && started.scip_output_owner.is_some() {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    if is_scip {
        let owner = started
            .scip_output_owner
            .as_ref()
            .ok_or(BridgeError::ScipArtifactNotInvocationOwned)?;
        let process_succeeded = process_succeeded(
            process_evidence_completed(process_evidence),
            process_evidence_exit_code(process_evidence),
        );
        let Some(bytes) = capture_owned_scip_sidecar(owner)? else {
            if !process_succeeded {
                return Ok(outputs);
            }
            return Err(BridgeError::ScipArtifactNotInvocationOwned);
        };
        outputs.push(live_raw_output(
            started,
            LspRawOutputKind::ScipSidecar,
            bytes,
            false,
        )?);
    }
    Ok(outputs)
}

/// Reads the one exact sidecar under the live invocation-owned directory
/// handle. Empty means no output was emitted; every non-empty different file
/// set is a refusal. The file lease and before/after owner observations bind
/// the bytes to one measured object for this readback.
fn capture_owned_scip_sidecar(
    owner: &OwnedDirectoryPublication,
) -> Result<Option<Vec<u8>>, BridgeError> {
    let source = owner
        .trusted_source_bundle()
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    let observed_before = source
        .observe()
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    if observed_before.files.is_empty() {
        return Ok(None);
    }
    if observed_before.files.len() != 1
        || observed_before.files[0].relative_path != LSP_SCIP_SIDECAR_FILE_NAME
    {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    if observed_before.files[0].size > MAX_SCIP_SIDECAR_BYTES {
        return Err(BridgeError::OutputTooLarge);
    }

    // Pin the exact emitted file before trusting it. The file lease denies
    // write/delete sharing; two directory observations must agree with that
    // retained identity and digest, so a pathname replacement between
    // enumeration and open cannot be captured as this invocation.
    let sidecar = source
        .retain_file(LSP_SCIP_SIDECAR_FILE_NAME)
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    let observed_while_pinned =
        source
            .observe()
            .map_err(|error| BridgeError::SidecarUnreadable {
                detail: error.to_string(),
            })?;
    if observed_while_pinned != observed_before
        || observed_while_pinned.files.len() != 1
        || observed_while_pinned.files[0].identity != sidecar.identity()
        || observed_while_pinned.files[0].size != sidecar.size()
        || observed_while_pinned.files[0].sha256 != sidecar.sha256()
    {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    let bytes = sidecar
        .read_bounded(MAX_SCIP_SIDECAR_BYTES)
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    let observed_after_read = source
        .observe()
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    if observed_after_read != observed_while_pinned
        || u64::try_from(bytes.len()).ok() != Some(sidecar.size())
        || sha256_hex(&bytes) != sidecar.sha256()
    {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    Ok(Some(bytes))
}

fn live_raw_output(
    started: &LspStartedInvocation,
    kind: LspRawOutputKind,
    bytes: Vec<u8>,
    truncated: bool,
) -> Result<LspRawOutput, BridgeError> {
    let channel = match kind {
        LspRawOutputKind::Stdout => "stdout",
        LspRawOutputKind::Stderr => "stderr",
        LspRawOutputKind::ScipSidecar => "scip-sidecar",
    };
    let artifact_id = ArtifactId::new(format!(
        "lsp-raw:{}:{channel}",
        started.process_intent.operation_id().as_str()
    ))
    .map_err(|_| BridgeError::InvalidText {
        field: "raw_output.artifact_id",
    })?;
    let source = match kind {
        LspRawOutputKind::Stdout | LspRawOutputKind::Stderr => RawEvidenceSource::Process,
        LspRawOutputKind::ScipSidecar => RawEvidenceSource::File,
    };
    let evidence = RawEvidence {
        artifact_id,
        invocation_id: started.instrument_invocation.request.request_id.clone(),
        source,
        content_type: "application/octet-stream".to_owned(),
        sha256: sha256_hex(&bytes),
        bytes,
        // The owner supplies a process-resume time, not an independent time
        // for when terminal stream/sidecar bytes were captured. Preserve the
        // existing unknown-clock representation instead of relabeling resume
        // time as a later raw-output capture time.
        captured_at: ClockReading::default(),
        truncated,
    };
    evidence.validate().map_err(BridgeError::RawEvidence)?;
    Ok(LspRawOutput { kind, evidence })
}

fn validate_git_scope(scope: &GovernedGitScope) -> Result<(), BridgeError> {
    if scope.branch.trim().is_empty()
        || scope.branch.chars().any(char::is_control)
        || !matches!(scope.commit.len(), 40 | 64)
        || !scope
            .commit
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || scope.ancestor_commits.iter().any(|commit| {
            !matches!(commit.len(), 40 | 64)
                || !commit
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        return Err(BridgeError::InconsistentBinding(
            "governed Git source scope has malformed branch or commit identities".to_owned(),
        ));
    }
    let mut previous: Option<&str> = None;
    for artifact in &scope.artifact_refs {
        let path = Path::new(&artifact.resource_ref);
        if artifact.resource_ref.is_empty()
            || artifact.resource_ref.contains('\\')
            || artifact
                .resource_ref
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !is_lower_hex_digest(&artifact.content_hash)
            || previous.is_some_and(|before| before >= artifact.resource_ref.as_str())
        {
            return Err(BridgeError::InconsistentBinding(
                "governed Git source scope contains malformed or unordered tracked artifact identities".to_owned(),
            ));
        }
        previous = Some(&artifact.resource_ref);
    }
    if scope
        .ancestor_commits
        .iter()
        .any(|commit| commit == &scope.commit)
    {
        return Err(BridgeError::InconsistentBinding(
            "governed Git source ancestry contains its current commit".to_owned(),
        ));
    }
    Ok(())
}

fn validate_candidate_identity(
    candidate_identity: Option<&CandidateIdentity>,
    build_fingerprint: Option<&BuildFingerprint>,
) -> Result<(), BridgeError> {
    match (candidate_identity, build_fingerprint) {
        (None, None) => Ok(()),
        (Some(identity), Some(fingerprint)) => {
            fingerprint
                .validate()
                .map_err(|error| BridgeError::InconsistentBinding(error.to_string()))?;
            if identity.candidate != fingerprint.candidate
                || identity.contract_revision != fingerprint.contract_revision
                || !is_lower_hex_digest(&identity.build_fingerprint)
            {
                return Err(BridgeError::InconsistentBinding(
                    "admitted candidate identity does not match the existing build fingerprint fields".to_owned(),
                ));
            }
            Ok(())
        }
        _ => Err(BridgeError::InconsistentBinding(
            "candidate identity and build fingerprint must be supplied together".to_owned(),
        )),
    }
}

fn process_start_binding(
    start: &ProcessStartReceipt,
) -> Result<LspProcessStartBindingV1, BridgeError> {
    start.validate().map_err(BridgeError::ProcessEvidence)?;
    Ok(LspProcessStartBindingV1 {
        schema_version: 1,
        operation_id: start.operation_id().as_str().to_owned(),
        request_digest: start.request_digest().to_owned(),
        accepted_generation: start.accepted_generation().get(),
    })
}

fn validate_raw_outputs(
    invocation: &InstrumentInvocation,
    process_evidence: &ProcessEvidence,
    operation: &SemanticOperation,
    outputs: &[LspRawOutput],
) -> Result<(), BridgeError> {
    let mut seen = std::collections::BTreeSet::new();
    for (index, output) in outputs.iter().enumerate() {
        if !seen.insert(output.kind) {
            return Err(BridgeError::InconsistentBinding(
                "duplicate raw output channel".to_owned(),
            ));
        }
        if outputs[..index]
            .iter()
            .any(|previous| previous.evidence.artifact_id == output.evidence.artifact_id)
        {
            return Err(BridgeError::InconsistentBinding(
                "multiple raw channels reuse one artifact identity".to_owned(),
            ));
        }
        output
            .evidence
            .validate()
            .map_err(BridgeError::RawEvidence)?;
        if output.kind == LspRawOutputKind::ScipSidecar
            && !matches!(
                operation,
                SemanticOperation::Definitions { .. }
                    | SemanticOperation::References { .. }
                    | SemanticOperation::Symbols { .. }
                    | SemanticOperation::Rename { .. }
            )
        {
            return Err(BridgeError::InconsistentBinding(
                "non-SCIP invocation contains a SCIP sidecar artifact".to_owned(),
            ));
        }
        if output.evidence.invocation_id != invocation.request.request_id {
            return Err(BridgeError::InconsistentBinding(
                "raw output belongs to a different Instrument invocation".to_owned(),
            ));
        }
        match output.kind {
            LspRawOutputKind::Stdout | LspRawOutputKind::Stderr => {
                if output.evidence.source != RawEvidenceSource::Process
                    || output.evidence.bytes.len() > MAX_TOOL_OUTPUT_BYTES
                {
                    return Err(BridgeError::OutputTooLarge);
                }
            }
            LspRawOutputKind::ScipSidecar => {
                if output.evidence.source != RawEvidenceSource::File
                    || output.evidence.bytes.len() as u64 > MAX_SCIP_SIDECAR_BYTES
                {
                    return Err(BridgeError::OutputTooLarge);
                }
            }
        }
    }
    validate_stream_output(outputs, process_evidence, ProcessStreamKind::Stdout)?;
    validate_stream_output(outputs, process_evidence, ProcessStreamKind::Stderr)?;
    let process_completed = process_completed(process_evidence);
    let exit_code = process_exit_code(process_evidence);
    if process_succeeded(process_completed, exit_code)
        && matches!(
            operation,
            SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion
        )
        && output_for(outputs, LspRawOutputKind::Stdout).is_none()
    {
        return Err(BridgeError::InconsistentBinding(
            "successful analyzer invocation has no retained stdout artifact".to_owned(),
        ));
    }
    if process_succeeded(process_completed, exit_code)
        && matches!(
            operation,
            SemanticOperation::Definitions { .. }
                | SemanticOperation::References { .. }
                | SemanticOperation::Symbols { .. }
                | SemanticOperation::Rename { .. }
        )
        && output_for(outputs, LspRawOutputKind::ScipSidecar).is_none()
    {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    Ok(())
}

fn validate_stream_output(
    outputs: &[LspRawOutput],
    process_evidence: &ProcessEvidence,
    stream_kind: ProcessStreamKind,
) -> Result<(), BridgeError> {
    let output_kind = match stream_kind {
        ProcessStreamKind::Stdout => LspRawOutputKind::Stdout,
        ProcessStreamKind::Stderr => LspRawOutputKind::Stderr,
    };
    let raw = output_for(outputs, output_kind);
    let stream = match stream_kind {
        ProcessStreamKind::Stdout => process_evidence.stdout(),
        ProcessStreamKind::Stderr => process_evidence.stderr(),
    };
    match (raw, stream) {
        (None, None) => Ok(()),
        (Some(raw), Some(stream)) => {
            if stream.stream() != stream_kind
                || stream.binding().request_digest() != process_evidence.request_digest()
                || stream.binding().operation_id() != process_evidence.operation_id()
                || stream.preview().representation() != StreamPreviewRepresentation::TransportBytes
            {
                return Err(BridgeError::InconsistentBinding(
                    "process stream evidence belongs to a different request or is not raw transport bytes".to_owned(),
                ));
            }
            let exact_full_stream = !raw.evidence.truncated
                && raw.evidence.bytes.len() as u64 == stream.observed_bytes()
                && raw.evidence.sha256 == stream.observed_sha256();
            let exact_preview = raw.evidence.bytes.as_slice() == stream.preview().bytes()
                && raw.evidence.truncated == stream.preview().is_truncated();
            let bounded_prefix = stream.preview().is_truncated()
                && raw.evidence.truncated
                && raw
                    .evidence
                    .bytes
                    .as_slice()
                    .starts_with(stream.preview().bytes());
            if exact_full_stream || exact_preview || bounded_prefix {
                Ok(())
            } else {
                Err(BridgeError::InconsistentBinding(
                    "raw process bytes disagree with the reconciled stream evidence".to_owned(),
                ))
            }
        }
        _ => Err(BridgeError::InconsistentBinding(
            "raw stream artifact is missing or has no reconciled process owner".to_owned(),
        )),
    }
}

fn output_for(outputs: &[LspRawOutput], kind: LspRawOutputKind) -> Option<&LspRawOutput> {
    outputs.iter().find(|output| output.kind == kind)
}

fn command_for(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
) -> Result<LspCommand, BridgeError> {
    match operation {
        SemanticOperation::Diagnostics => LspCommand::diagnostics(config, candidate),
        SemanticOperation::ProbeVersion => LspCommand::version(config, candidate),
        SemanticOperation::Definitions { .. }
        | SemanticOperation::References { .. }
        | SemanticOperation::Symbols { .. }
        | SemanticOperation::Rename { .. } => LspCommand::scip(config, candidate),
    }
}

struct LspInstrumentBindingOwner<'a> {
    invocation: &'a InstrumentInvocation,
    resolved: &'a ResolvedExecutableIdentity,
    registry: &'a RegistryEntry,
    spec: &'a InstrumentSpec,
}

fn validate_instrument_process_request(
    request: &ProcessRequest,
    invocation: &InstrumentInvocation,
) -> Result<(), BridgeError> {
    if request.operation_id().as_str() != invocation.request.request_id.as_str()
        || request.generation().get() != invocation.request.state_fence.resource_generation.value()
        || request.fence().authority_epoch() != &invocation.request.state_fence.authority_epoch
        || invocation
            .request
            .session_id
            .as_ref()
            .is_some_and(|session| session.as_str() != request.session_id().as_str())
    {
        return Err(BridgeError::InconsistentBinding(
            "shared process request does not match the Instrument request id, session, generation, or authority epoch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_instrument_process_admission(
    admission: &ProcessExecutionAdmissionRequest,
    invocation: &InstrumentInvocation,
) -> Result<(), BridgeError> {
    admission.validate().map_err(BridgeError::ProcessEvidence)?;
    let intent = admission.intent();
    if intent.operation_id().as_str() != invocation.request.request_id.as_str()
        || intent.generation().get() != invocation.request.state_fence.resource_generation.value()
        || admission.state_fence().authority_epoch()
            != &invocation.request.state_fence.authority_epoch
        || invocation
            .request
            .session_id
            .as_ref()
            .is_some_and(|session| session.as_str() != intent.session_id().as_str())
    {
        return Err(BridgeError::InconsistentBinding(
            "original Kernel admission does not match the Instrument request id, session, generation, or authority epoch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_instrument_binding(
    command: &LspCommand,
    intent: &ProcessIntent,
    candidate: &SourceCandidate,
    config: &AnalyzerConfig,
    operation: &SemanticOperation,
    owner: &LspInstrumentBindingOwner<'_>,
) -> Result<(), BridgeError> {
    let projected = command_for(config, candidate, operation)?;
    let invocation = owner.invocation;
    let resolved = owner.resolved;
    let registry = owner.registry;
    let spec = owner.spec;
    let (expected_parser, _) = expected_parser_and_normalizer(operation);
    if command != &projected
        || !intent
            .executable()
            .eq_ignore_ascii_case(&command.executable)
        || intent.argv() != command.arguments.as_slice()
        || intent.working_directory() != command.working_directory
        || !registry.supports(invocation.kind)
        || registry.instrument != invocation.instrument
        || spec.kind.as_str() != registry.instrument.as_str()
        || registry.parser != spec.parser
        || registry.parser.as_str() != expected_parser
        || spec.parser.as_str() != expected_parser
        || spec.parser_generation != BUILTIN_PARSER_GENERATION
        || spec.class.coarse_kind() != invocation.kind
        || spec
            .executable_version
            .as_deref()
            .is_some_and(|version| resolved.tool_version.as_deref() != Some(version))
        || spec.environment_profile != registry.environment_class
        || intent.executable() != resolved.canonical_path.as_str()
        || intent.executable_sha256() != resolved.content_digest.as_str()
        || resolved.environment_digest != environment_projection_digest(intent.environment())
        || intent.argv() != command.arguments.as_slice()
        || intent.working_directory() != command.working_directory.as_str()
        || spec
            .limits
            .timeout_ms
            .is_some_and(|ceiling| intent.resource_limits().wall_timeout_ms() > ceiling)
        || spec.limits.max_output_bytes.is_some_and(|ceiling| {
            intent.resource_limits().stdout_bytes() > ceiling
                || intent.resource_limits().stderr_bytes() > ceiling
        })
        || resolved.arguments.as_slice() != intent.argv()
        || invocation.arguments.as_slice() != spec.argument_template.as_slice()
        || path_file_name(&spec.executable) != resolved.executable_file_name()
        || !resolved.binds_argv(intent.argv())
    {
        return Err(BridgeError::InconsistentBinding(
            "analyzer command does not match the admitted Instrument, #1814 executable, registry, or parser".to_owned(),
        ));
    }
    Ok(())
}

fn validate_invocation_sidecar(
    command: &LspCommand,
    config: &AnalyzerConfig,
    operation: &SemanticOperation,
    output_owner: Option<&OwnedDirectoryPublication>,
) -> Result<(), BridgeError> {
    if !is_scip_operation(operation) {
        if output_owner.is_some() || config.scip_output_path.is_some() {
            return Err(BridgeError::ScipArtifactNotInvocationOwned);
        }
        return Ok(());
    }
    if command.analyzer != AnalyzerKind::Scip {
        return Err(BridgeError::UnsupportedOperation);
    }
    let output_owner = output_owner.ok_or(BridgeError::ScipArtifactNotInvocationOwned)?;
    let path = config
        .scip_output_path
        .as_deref()
        .ok_or(BridgeError::MissingScipOutput)?;
    let expected_path = output_owner
        .temporary_path()
        .join(LSP_SCIP_SIDECAR_FILE_NAME);
    if expected_path.to_str() != Some(path) {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    let source =
        output_owner
            .trusted_source_bundle()
            .map_err(|error| BridgeError::SidecarUnreadable {
                detail: error.to_string(),
            })?;
    let observed = source
        .observe()
        .map_err(|error| BridgeError::SidecarUnreadable {
            detail: error.to_string(),
        })?;
    if !observed.files.is_empty() {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    Ok(())
}

fn validate_invocation_sidecar_path(
    config: &AnalyzerConfig,
    operation: &SemanticOperation,
) -> Result<(), BridgeError> {
    if !is_scip_operation(operation) {
        if config.scip_output_path.is_some() {
            return Err(BridgeError::ScipArtifactNotInvocationOwned);
        }
        return Ok(());
    }
    let path = config
        .scip_output_path
        .as_deref()
        .ok_or(BridgeError::MissingScipOutput)?;
    let candidate_path = Path::new(path);
    if !candidate_path.is_absolute()
        || candidate_path.file_name().and_then(std::ffi::OsStr::to_str)
            != Some(LSP_SCIP_SIDECAR_FILE_NAME)
        || candidate_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(BridgeError::ScipArtifactNotInvocationOwned);
    }
    Ok(())
}

fn is_scip_operation(operation: &SemanticOperation) -> bool {
    matches!(
        operation,
        SemanticOperation::Definitions { .. }
            | SemanticOperation::References { .. }
            | SemanticOperation::Symbols { .. }
            | SemanticOperation::Rename { .. }
    )
}

fn normalize_retained_operation(
    config: &AnalyzerConfig,
    candidate: &SourceCandidate,
    operation: &SemanticOperation,
    identities: (
        &ResolvedExecutableIdentityRecord,
        &InstrumentSpec,
        &LspRegistryIdentity,
    ),
    raw_outputs: &[LspRawOutput],
    process_evidence: &ProcessEvidence,
    invoked_at_unix_ms: u64,
    cache: Option<&mut ScipProjectionCache>,
    invocation: Option<&LspStartedInvocation>,
) -> Result<NormalizedResult, BridgeError> {
    let (resolved_identity, instrument_spec, registry_identity) = identities;
    let resolved = resolved_identity.resolve("lsp-retained-observation")?;
    let process_completed = process_completed(process_evidence);
    let exit_code = process_exit_code(process_evidence);
    let process_truncated = process_outputs_incomplete(process_evidence, raw_outputs);
    let stdout = output_for(raw_outputs, LspRawOutputKind::Stdout)
        .map_or(&[][..], |output| output.evidence.bytes.as_slice());
    let mut result = match operation {
        SemanticOperation::Diagnostics => finalize_diagnostics(
            config,
            candidate,
            resolved.tool_version.as_deref(),
            stdout,
            process_truncated,
            exit_code,
            process_completed,
            invoked_at_unix_ms,
        ),
        SemanticOperation::ProbeVersion => finalize_version(
            config,
            candidate,
            stdout,
            process_truncated,
            exit_code,
            process_completed,
            invoked_at_unix_ms,
        ),
        SemanticOperation::Definitions { .. }
        | SemanticOperation::References { .. }
        | SemanticOperation::Symbols { .. }
        | SemanticOperation::Rename { .. } => {
            let sidecar_path = config
                .scip_output_path
                .as_deref()
                .ok_or(BridgeError::MissingScipOutput)?;
            let sidecar = output_for(raw_outputs, LspRawOutputKind::ScipSidecar)
                .map_or(&[][..], |output| output.evidence.bytes.as_slice());
            match (cache, invocation) {
                (Some(cache), Some(invocation))
                    if process_succeeded(process_completed, exit_code) && !process_truncated =>
                {
                    finalize_scip_for_invocation(
                        config,
                        candidate,
                        operation,
                        sidecar,
                        sidecar_path,
                        invoked_at_unix_ms,
                        cache,
                        invocation,
                    )
                }
                _ => finalize_scip(
                    config,
                    candidate,
                    operation,
                    sidecar,
                    sidecar_path,
                    invoked_at_unix_ms,
                    None,
                ),
            }
        }
    };
    let mut handles = Vec::new();
    for kind in [
        LspRawOutputKind::Stdout,
        LspRawOutputKind::Stderr,
        LspRawOutputKind::ScipSidecar,
    ] {
        if let Some(output) = output_for(raw_outputs, kind) {
            let handle = match kind {
                LspRawOutputKind::Stdout => raw_stream_handle("stdout", &output.evidence),
                LspRawOutputKind::Stderr => raw_stream_handle("stderr", &output.evidence),
                LspRawOutputKind::ScipSidecar => raw_sidecar_handle(
                    config.scip_output_path.as_deref().unwrap_or_default(),
                    &output.evidence,
                ),
            };
            handles.push(handle);
        }
    }
    result.receipt_mut().output_handles = handles;
    result.receipt_mut().tool_exit_code = exit_code;
    let receipt = result.receipt_mut();
    receipt.resolved_executable_identity = Some(resolved_identity.clone());
    receipt.instrument_spec = Some(instrument_spec.clone());
    receipt.registry_identity = Some(registry_identity.clone());
    let (_, normalized_result_normalizer) = expected_parser_and_normalizer(operation);
    receipt.normalized_result_normalizer = Some(
        ContractId::new(normalized_result_normalizer)
            .map_err(|error| BridgeError::InstrumentIdentity(error.to_string()))?,
    );
    Ok(result)
}

fn apply_process_completion(
    result: &mut NormalizedResult,
    completed: bool,
    truncated: bool,
    exit_code: Option<i32>,
) {
    let clear_payload = {
        let receipt = result.receipt_mut();
        receipt.tool_exit_code = exit_code;
        if truncated {
            receipt.freshness = Freshness::Stale {
                reason: "tool output exceeded the bounded capture limit".to_owned(),
            };
            receipt.disposition = FailureDisposition::OutputTruncated;
            true
        } else if !process_succeeded(completed, exit_code) {
            receipt.freshness = Freshness::Stale {
                reason: "tool run did not complete successfully".to_owned(),
            };
            receipt.disposition = FailureDisposition::ToolFailed { exit_code };
            true
        } else {
            false
        }
    };
    if clear_payload {
        clear_normalized_payload(result);
    }
}

fn clear_normalized_payload(result: &mut NormalizedResult) {
    match result {
        NormalizedResult::Definitions { items, .. } => items.clear(),
        NormalizedResult::References { items, .. } => items.clear(),
        NormalizedResult::Symbols { items, .. } => items.clear(),
        NormalizedResult::Diagnostics { observations, .. } => observations.clear(),
        NormalizedResult::Rename { candidate, .. } => candidate.edits.clear(),
        NormalizedResult::Version { version, .. } => version.clear(),
    }
}

fn source_binding_matches_current(
    binding: &LspSourceBindingV1,
    current: &CurrentLspAdoptionContext<'_>,
) -> bool {
    let scopes_match = binding.source_scope_at_dispatch == binding.source_scope_after_run
        && binding.source_scope_after_run.as_ref() == current.source_scope;
    let identities_match = binding.candidate_identity_at_dispatch
        == binding.candidate_identity_after_run
        && binding.build_fingerprint_at_dispatch == binding.build_fingerprint_after_run
        && binding.candidate_identity_after_run.as_ref() == current.candidate_identity
        && binding.build_fingerprint_after_run.as_ref() == current.build_fingerprint;
    let request_matches = binding.process_start.schema_version == 1
        && binding.instrument_request_id
            == current.instrument_invocation.request.request_id.as_str()
        && binding.instrument_target == current.instrument_invocation.target
        && binding.instrument_declared_scope == current.instrument_invocation.declared_scope
        && binding.instrument_input_artifacts == current.instrument_invocation.input_artifacts
        && binding.process_operation_id
            == current.instrument_invocation.request.request_id.as_str()
        && binding.process_generation
            == current
                .instrument_invocation
                .request
                .state_fence
                .resource_generation
                .value()
        && binding.process_working_directory == current.source_candidate.workspace_root;
    scopes_match && identities_match && request_matches
}

fn validate_recorded_freshness(
    record: &RetainedLspObservationV1,
    completed: bool,
    truncated: bool,
    exit_code: Option<i32>,
) -> Result<(), BridgeError> {
    let claims_current = matches!(&record.result.receipt().freshness, Freshness::Current);
    if claims_current
        || completed != process_completed(&record.process_evidence)
        || truncated != process_outputs_incomplete(&record.process_evidence, &record.raw_outputs)
        || exit_code != process_exit_code(&record.process_evidence)
    {
        return Err(BridgeError::InconsistentBinding(
            "serialized retained observations cannot assert Current; freshness requires a live process and source-owner readback".to_owned(),
        ));
    }
    Ok(())
}

fn process_completed(evidence: &ProcessEvidence) -> bool {
    evidence
        .view()
        .exit()
        .is_some_and(|exit| exit.disposition() == ExitDisposition::Completed)
}

fn process_exit_code(evidence: &ProcessEvidence) -> Option<i32> {
    let exit = evidence.view().exit()?;
    let value = serde_json::to_value(exit).ok()?;
    value
        .get("code")?
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
}

fn process_outputs_incomplete(evidence: &ProcessEvidence, outputs: &[LspRawOutput]) -> bool {
    [
        (
            ProcessStreamKind::Stdout,
            LspRawOutputKind::Stdout,
            evidence.stdout(),
        ),
        (
            ProcessStreamKind::Stderr,
            LspRawOutputKind::Stderr,
            evidence.stderr(),
        ),
    ]
    .into_iter()
    .any(|(stream_kind, output_kind, stream)| {
        let Some(stream) = stream else {
            return false;
        };
        let Some(raw) = output_for(outputs, output_kind) else {
            return true;
        };
        let full_raw_matches = !raw.evidence.truncated
            && raw.evidence.bytes.len() as u64 == stream.observed_bytes()
            && raw.evidence.sha256 == stream.observed_sha256();
        raw.evidence.truncated
            || stream.stream() != stream_kind
            || stream.transport() != eliot_process::StreamTransportStatus::Complete
            || (stream.preview().is_truncated() && !full_raw_matches)
    }) || outputs
        .iter()
        .any(|output| output.kind == LspRawOutputKind::ScipSidecar && output.evidence.truncated)
}

fn process_succeeded(completed: bool, exit_code: Option<i32>) -> bool {
    completed && exit_code == Some(0)
}

fn raw_stream_handle(stream: &str, evidence: &RawEvidence) -> String {
    format!(
        "{stream}:sha256:{}:{}B",
        evidence.sha256,
        evidence.bytes.len()
    )
}

fn raw_sidecar_handle(path: &str, evidence: &RawEvidence) -> String {
    format!(
        "scip:{path}:sha256:{}:{}B",
        evidence.sha256,
        evidence.bytes.len()
    )
}

fn path_file_name(path: &str) -> String {
    let tail = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let lower = tail.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Bridge errors. Tool failure is not an error here: it travels on the
/// observation receipt disposition while parsing stays total.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// S-04 rejected the authenticated retained-payload readback.
    #[error("captured Blob readback failed validation: {0}")]
    BlobReadback(#[from] BlobError),
    /// Authenticated Blob bytes are not a retained LSP observation envelope.
    #[error("captured LSP payload could not be decoded: {0}")]
    CapturedObservationDecode(#[from] serde_json::Error),
    /// The original live retained observation could not be serialized for publication.
    #[error("original LSP capture could not be serialized: {0}")]
    CaptureSerialization(#[source] serde_json::Error),
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
    /// The requested first-argv token or analyzer pairing is outside the
    /// declared supported set: the bridge serves a closed, already-admitted
    /// operation list and creates no task policy to accommodate anything
    /// else (capability outcome, pre-dispatch).
    #[error("operation not admitted by the lsp bridge: {operation}")]
    OperationNotAdmitted {
        /// Observed first-argv token or analyzer pairing.
        operation: String,
    },
    /// The call did not target the admitted analyzer route. No provider is
    /// substituted under the same operation (identity/route outcome,
    /// pre-dispatch).
    #[error(
        "route mismatch: bridge serves the admitted rust-analyzer executable, observed '{observed}'"
    )]
    RouteMismatch {
        /// Observed executable.
        observed: String,
    },
    /// Bounded-input violation: non-absolute working directory, NUL byte, or
    /// over-long argv (protocol outcome, pre-dispatch).
    #[error("call over bound: {what}")]
    CallOverBound {
        /// Stable bound description.
        what: &'static str,
    },
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
    /// The shared executor refused or failed a launch. The attempted
    /// invocation is retained so the failure reconciles under its original
    /// identity instead of being retried as a new operation (identity
    /// outcome: no analyzer output exists for this call).
    #[error("analyzer launch failed for '{invocation}': {error}")]
    ProcessLaunch {
        /// Exact attempted invocation (`executable argv… @ cwd`).
        invocation: String,
        /// Executor refusal or failure.
        #[source]
        error: ProcessExecutionError,
    },
    /// Retained request, process, source, or typed result bindings disagree.
    #[error("retained LSP observation has inconsistent bindings: {0}")]
    InconsistentBinding(String),
    /// The retained observation uses an unsupported envelope revision.
    #[error("retained LSP observation schema or receipt kind is unsupported")]
    UnsupportedObservationSchema,
    /// An original Instrument output artifact failed its owner validation.
    #[error("raw Instrument evidence is invalid: {0}")]
    RawEvidence(#[source] InstrumentContractError),
    /// Reconciled process evidence failed its owner validation.
    #[error("reconciled process evidence is invalid: {0}")]
    ProcessEvidence(#[source] ProcessContractError),
    /// The existing Instrument invocation failed its typed owner validation.
    #[error("instrument invocation is invalid: {0}")]
    InstrumentContract(#[source] InstrumentContractError),
    /// The existing #1814 executable identity is inconsistent or invalid.
    #[error("resolved executable identity is invalid: {0}")]
    ExecutableIdentity(String),
    /// Current source could not be revalidated by the original Git owner.
    #[error("source snapshot revalidation failed: {0}")]
    SourceSnapshot(#[source] GitSnapshotError),
    /// The existing Artifact owner rejected the immutable source readback.
    #[error("source artifact readback failed validation: {0}")]
    SourceArtifact(#[from] ArtifactError),
    /// The original session-bound Kernel process owner rejected or failed the operation.
    #[error("original Kernel process owner failed: {0}")]
    ProcessOwner(#[source] LspProcessOwnerError),
    /// The retained instrument/spec/parser identity is invalid.
    #[error("instrument identity is invalid: {0}")]
    InstrumentIdentity(String),
    /// The SCIP sidecar path did not bind uniquely to this process invocation.
    #[error("SCIP sidecar is not bound to this invocation")]
    ScipArtifactNotInvocationOwned,
    /// The original process owner has not reconciled a terminal disposition.
    #[error("LSP capture requires terminal process-owner evidence")]
    CaptureNotTerminal,
    /// Capture time cannot be represented by the existing clock contract.
    #[error("LSP capture clock exceeds the existing clock contract")]
    InvalidCaptureClock,
    /// A purported rename result claims that the bridge applied its edits.
    #[error("retained rename result claims applied edits")]
    AppliedRename,
    /// Shared process layer failed.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// Removal fenced new launches: dispatch refused before any process ran.
    #[error("bridge fenced for removal: new launches refused")]
    RemovalFenced,
    /// A presented bridge declaration does not bind the live generation:
    /// admission or status was refused before any process ran.
    #[error("declaration does not bind the bridge: {0}")]
    Declaration(GenerationError),
    /// A removal-plan step refused the call.
    #[error(transparent)]
    Removal(#[from] RemovalError),
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

fn append_frame(target: &mut Vec<u8>, bytes: &[u8]) {
    let length = bytes.len() as u64;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(bytes);
}

fn append_optional_frame(target: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            target.push(1);
            append_frame(target, value.as_bytes());
        }
        None => target.push(0),
    }
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
    #[cfg(windows)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    const VERSION_LINE: &str = "rust-analyzer 1.97.1 (8bab26f4 2026-07-14)\n";

    const DIAGNOSTICS_SAMPLE: &str = "0/1 0% processing C:\\Temp\\ra-probe\\src\\main.rs\r\nat crate ra_probe, file C:\\Temp\\ra-probe\\src\\main.rs: Error RustcHardError(\"E0308\") from LineCol { line: 1, col: 17 } to LineCol { line: 1, col: 23 }: expected i32, found &'static str\r\ndiagnostic scan complete\r\n";

    #[cfg(windows)]
    static NEXT_SIDECAR_FIXTURE: AtomicUsize = AtomicUsize::new(0);

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

    #[cfg(windows)]
    fn sidecar_fixture_owner() -> OwnedDirectoryPublication {
        let sequence = NEXT_SIDECAR_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let destination = std::env::temp_dir().join(format!(
            "eliot-lsp-sidecar-owner-{}-{sequence}",
            std::process::id()
        ));
        OwnedDirectoryPublication::create(&destination)
            .expect("original directory owner retains a fresh sidecar root")
    }

    #[cfg(windows)]
    fn sidecar_config_for(owner: &OwnedDirectoryPublication) -> AnalyzerConfig {
        AnalyzerConfig {
            scip_output_path: Some(
                owner
                    .temporary_path()
                    .join(LSP_SCIP_SIDECAR_FILE_NAME)
                    .to_str()
                    .expect("owned sidecar path is UTF-8")
                    .to_owned(),
            ),
            ..test_config()
        }
    }

    #[cfg(windows)]
    fn retire_sidecar_fixture_owner(owner: OwnedDirectoryPublication) {
        let observed = eliot_platform_windows::observe_owned_directory_exact(
            owner.temporary_path(),
            &[LSP_SCIP_SIDECAR_FILE_NAME],
            16 * 1024 * 1024,
        )
        .expect("original retirement owner measures the exact sidecar fixture");
        assert_eq!(observed.directory_identity, owner.temporary_identity());
        let expected = observed.retirement_precondition();
        assert!(matches!(
            owner
                .retire_unpublished_tree(&expected)
                .expect("original publication owner retires the exact measured fixture"),
            eliot_platform_windows::OwnedDirectoryRetirementOutcome::Retired
        ));
    }

    #[cfg(windows)]
    #[test]
    fn invocation_owned_scip_sidecar_readback_matches_original_file_handle_facts() {
        let owner = sidecar_fixture_owner();
        let operation = SemanticOperation::Definitions {
            symbol: "sym".to_owned(),
        };
        let candidate = test_candidate();
        let config = sidecar_config_for(&owner);
        let command = LspCommand::scip(&config, &candidate).expect("SCIP command validates");
        validate_invocation_sidecar(&command, &config, &operation, Some(&owner))
            .expect("fresh operation-owned output root is empty before launch");

        let exact_bytes = b"owned-sidecar-readback";
        let sidecar_path = owner.temporary_path().join(LSP_SCIP_SIDECAR_FILE_NAME);
        std::fs::write(&sidecar_path, exact_bytes)
            .expect("simulated analyzer emits into the owner-chosen path");
        let source = owner
            .trusted_source_bundle()
            .expect("original directory owner supplies trusted file observation");
        let before = source
            .observe()
            .expect("original source bundle measures the emitted sidecar");
        assert_eq!(before.files.len(), 1);
        assert_eq!(before.files[0].relative_path, LSP_SCIP_SIDECAR_FILE_NAME);

        let readback = capture_owned_scip_sidecar(&owner)
            .expect("production readback accepts the exact operation-owned file")
            .expect("the analyzer emitted a sidecar");
        let after = source
            .observe()
            .expect("original source bundle remeasures the retained sidecar");
        assert_eq!(readback, exact_bytes);
        assert_eq!(before, after);
        assert_eq!(
            sha256_hex(&readback),
            before.files[0].sha256,
            "the physical readback digest equals the original owner's measured file digest"
        );
        assert_eq!(readback.len() as u64, before.files[0].size);
        assert_eq!(before.files[0].identity, after.files[0].identity);
        drop(source);
        retire_sidecar_fixture_owner(owner);
    }

    #[cfg(windows)]
    #[test]
    fn invocation_sidecar_preflight_refuses_a_nonempty_original_owner_root() {
        let owner = sidecar_fixture_owner();
        let config = sidecar_config_for(&owner);
        let operation = SemanticOperation::Definitions {
            symbol: "sym".to_owned(),
        };
        let candidate = test_candidate();
        let command = LspCommand::scip(&config, &candidate).expect("SCIP command validates");
        let stale_path = owner.temporary_path().join(LSP_SCIP_SIDECAR_FILE_NAME);
        std::fs::write(&stale_path, b"old invocation output")
            .expect("fixture writes a real stale sidecar under the owner root");
        let source = owner
            .trusted_source_bundle()
            .expect("original owner retains the pre-existing sidecar root");
        let observed = source
            .observe()
            .expect("original owner measures the pre-existing sidecar");
        assert_eq!(observed.files.len(), 1);
        assert_eq!(observed.files[0].relative_path, LSP_SCIP_SIDECAR_FILE_NAME);
        assert_eq!(
            observed.files[0].sha256,
            sha256_hex(b"old invocation output")
        );

        assert!(matches!(
            validate_invocation_sidecar(&command, &config, &operation, Some(&owner)),
            Err(BridgeError::ScipArtifactNotInvocationOwned)
        ));
        drop(source);
        retire_sidecar_fixture_owner(owner);
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
