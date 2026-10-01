//! Canonical `dev-fast` profile orchestration (issue #1802, I18.6).
//!
//! This module holds the closed versioned `dev-fast` profile: its stage
//! plan, candidate/budget/tool bindings, preflight checks, per-stage
//! dispatch routes, and aggregation rules. Public data stays with the
//! existing contract owners: profile admission with [`crate::profile`],
//! run records with [`crate::profile_run`], discovery identities with the
//! nextest adapter, and selection with `eliot-test-selection`. Nothing here
//! launches a process, schedules a task, writes canonical state, or decides
//! verification; the executing composition root supplies the launcher and
//! the Governor admits the persisted evidence.
//!
//! The first productive slice is labeled partial (see
//! [`DEV_FAST_SLICE_PARTIAL`]) until every retained I18.6 obligation is
//! present; a partial slice never closes #1813/#1814 and grants no
//! Product/Release proof.

use eliot_contracts::{ArtifactId, canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{InstrumentAdmissionGrant, InstrumentKind, VerificationOutcome};
use eliot_process::ProcessExecutor;
use eliot_test_selection::{FrozenDisposition, FrozenSelection, TestSelectionReceipt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::InstrumentRunner;
use crate::profile::{
    InstrumentProfile, InstrumentRegistry, ProfileCompiler, ProfileError, StageEnvironment,
    TargetLayout, WorkScope, admitted_profile_for_alias,
};
use crate::profile_run::{
    AggregateStatus, InstrumentRun, ProfileAggregate, RetainedExitOutcome, RetainedToolIdentity,
    StageEvidence, StageLauncher, StageOrchestrator, StagePlan, StageTargetLayout,
    TestExecutionPlaneRoute,
};
use crate::registry::SupplyChainReceipt;
use crate::verification_profile::{
    DeclaredEnvironmentDependency, ParityVerdict, VerificationProfileReceipt,
    build_verification_profile_receipt, verify_profile_parity,
};

/// Canonical `dev-fast` profile name (I18.6).
pub const DEV_FAST_PROFILE: &str = "dev-fast";
/// Exact admitted `dev-fast` revision shipped by this slice.
pub const DEV_FAST_PROFILE_REVISION: u64 = 1;
/// First-slice completeness label: partial until every retained I18.6
/// obligation (live discovery dispatch, frozen selection execution,
/// admitted evidence persistence) is present. Final disposition already
/// binds the complete candidate/configuration identity, so this label
/// records the remaining assembly obligations, not an unbound identity.
pub const DEV_FAST_SLICE_PARTIAL: &str = "partial:first-slice";
/// Discovery stage: source-bound nextest inventory (I18.6 step 3).
pub const DEV_FAST_STAGE_LIST: &str = "nextest-list";
/// Diagnostics stage: affected Clippy/rustc machine diagnostics (I18.6
/// step 5), parsed under the admitted rustc JSON contract.
pub const DEV_FAST_STAGE_CLIPPY: &str = "clippy-diagnostics";
/// Execution stage: selected nextest with declared policy (I18.6 step 6).
pub const DEV_FAST_STAGE_RUN: &str = "nextest-run";
/// Format stage: separately reported rustfmt check (I18.6 step 7).
pub const DEV_FAST_STAGE_RUSTFMT: &str = "rustfmt-check";
/// First productive scoped package for the partial slice (issue #1802 step
/// 7): the small receipt-owner crate changed by this slice. Later callers
/// widen scope through the same compiler, never by redefining the profile.
pub const DEV_FAST_FIRST_PACKAGE: &str = "eliot-test-selection";
/// Version of the persisted `VerificationProfileRun` semantics (I18.6 step
/// 9).
///
/// This is the current record semantics version. It moves whenever the
/// record's own meaning or its digest preimage changes, so a retained
/// record is only ever interpreted under the encoding that produced it
/// (I5.27 `canonical_encoding_version`).
pub const VERIFICATION_PROFILE_RUN_VERSION: &str = "eliot-verification-profile-run-v3";

/// Retired record encoding whose `run_digest` is not a commitment.
///
/// The `v2` encoding hashed a NUL-joined field list whose raw-reference
/// vector was flattened with `join(",")` while `validate_text` admits
/// commas inside a reference. Two distinct admitted vectors —
/// `["raw:a,raw:b", "raw:c"]` and `["raw:a", "raw:b,raw:c"]` — therefore
/// produced identical preimages, so `run_digest` did not bind list
/// boundaries and readback could not detect a rewritten vector. A `v2`
/// digest is an unversioned hash of caller spelling (I5.27), so it is
/// never re-derived, compared, or certified under the current encoding:
/// [`VerificationProfileRun::check_digest`] and
/// [`VerificationProfileRun::resolve_lost_ack`] refuse the retired
/// version before recomputing anything. Such a record stays readable as
/// its own historical evidence; it is never re-interpreted as a
/// current record.
pub const VERIFICATION_PROFILE_RUN_LEGACY_VERSION: &str = "eliot-verification-profile-run-v2";

/// Domain separator of the profile-run digest preimage (I5.27
/// `domain_separator`).
const PROFILE_RUN_PREIMAGE_DOMAIN: &str = "eliot-verification-profile-run-digest";

/// Canonical encoding version of the profile-run digest preimage (I5.27
/// `canonical_encoding_version`).
///
/// The preimage is the project's canonical serialization of the complete
/// record with object keys sorted recursively, so every scalar field keeps
/// its own JSON encoding and every vector stays an actual JSON array. No
/// field is joined by a character a field may itself contain, so no two
/// distinct admitted records can share a preimage.
const PROFILE_RUN_PREIMAGE_ENCODING: &str = "v1";

/// Failures raised while binding, freezing, or aggregating `dev-fast`.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DevFastError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A digest value is not a lowercase SHA-256 digest.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A numeric bound is zero or out of range.
    #[error("{field} is outside its admitted bound")]
    OutOfBound {
        /// Field that failed validation.
        field: &'static str,
    },
    /// The candidate identity drifted after the selection froze.
    #[error("candidate drift: {coordinate} is frozen as '{expected}', not '{observed}'")]
    CandidateDrift {
        /// Coordinate that drifted (`candidate` revision or
        /// `candidate_identity` complete build configuration).
        coordinate: &'static str,
        /// Frozen value of that coordinate.
        expected: String,
        /// Observed value of that coordinate.
        observed: String,
    },
    /// An expected-nonzero selection executed zero tests.
    #[error("expected {expected} executions but observed zero; zero execution never passes")]
    ZeroExecution {
        /// Expected executions from the frozen selection.
        expected: u64,
    },
    /// A mandatory stage is missing, failed, or unknown.
    #[error("mandatory stage '{stage}' is {status}; the profile cannot pass")]
    MandatoryStage {
        /// Offending stage identity.
        stage: String,
        /// Observed aggregate status.
        status: String,
    },
    /// The selection carries explicit incomplete coverage.
    #[error("selection is explicitly incomplete: {0}")]
    IncompleteCoverage(String),
    /// A preflight gate refused the run.
    #[error("preflight refused: {0}")]
    Preflight(String),
    /// The receipt does not bind this run.
    #[error("selection receipt does not bind this run: {0}")]
    ReceiptMismatch(String),
    /// The dev-fast admission or registry build failed.
    #[error("dev-fast admission failed: {0}")]
    Admission(String),
    /// A retained stage capture is not a well-formed message stream of the
    /// stage's admitted parser, so no normalized outcome exists for it.
    #[error("stage '{stage}' capture is not well-formed {parser} output: {detail}")]
    StageParse {
        /// Stage whose capture failed to parse.
        stage: String,
        /// Admitted parser the capture was offered to.
        parser: &'static str,
        /// Owning-parser detail text (evidence, never control flow).
        detail: String,
    },
}

impl From<ProfileError> for DevFastError {
    fn from(error: ProfileError) -> Self {
        Self::Admission(error.to_string())
    }
}

impl From<crate::profile_run::ProfileRunError> for DevFastError {
    fn from(error: crate::profile_run::ProfileRunError) -> Self {
        Self::Admission(error.to_string())
    }
}

/// Validates one required text value.
fn validate_text(value: &str, field: &'static str) -> Result<(), DevFastError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DevFastError::InvalidText { field });
    }
    Ok(())
}

/// Validates one lowercase SHA-256 digest value.
fn validate_digest(value: &str, field: &'static str) -> Result<(), DevFastError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(DevFastError::InvalidDigest { field });
    }
    Ok(())
}

/// Exact source/candidate/configuration identity one `dev-fast` run binds.
///
/// Working directory, Cargo target root, and target triple stay separate
/// fields: they are different bindings and must never collapse into one
/// path or string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevFastCandidate {
    /// Product identity under verification.
    pub product: String,
    /// `WorkScope` identity under verification.
    pub workscope: String,
    /// Base revision the candidate is measured against.
    pub base: String,
    /// Exact candidate revision under verification.
    pub candidate: String,
    /// Checkout identity carrying the candidate.
    pub checkout: String,
    /// Digest of the base-to-candidate diff.
    pub diff_digest: String,
    /// Cargo target triple under verification.
    pub target_triple: String,
    /// Cargo features under verification, sorted and deduplicated.
    pub features: Vec<String>,
    /// Source closure digest.
    pub source_digest: String,
    /// Lockfile digest.
    pub lock_digest: String,
    /// Toolchain digest.
    pub toolchain_digest: String,
    /// Configuration digest.
    pub config_digest: String,
    /// Stage working directory (source root).
    pub working_dir: String,
    /// External Cargo target root (never the repository `target/`).
    pub cargo_target_root: String,
}

impl DevFastCandidate {
    /// Binds one candidate identity, validating every field.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        product: String,
        workscope: String,
        base: String,
        candidate: String,
        checkout: String,
        diff_digest: String,
        target_triple: String,
        mut features: Vec<String>,
        source_digest: String,
        lock_digest: String,
        toolchain_digest: String,
        config_digest: String,
        working_dir: String,
        cargo_target_root: String,
    ) -> Result<Self, DevFastError> {
        for (value, field) in [
            (product.as_str(), "product"),
            (workscope.as_str(), "workscope"),
            (base.as_str(), "base"),
            (candidate.as_str(), "candidate"),
            (checkout.as_str(), "checkout"),
            (target_triple.as_str(), "target_triple"),
            (working_dir.as_str(), "working_dir"),
            (cargo_target_root.as_str(), "cargo_target_root"),
        ] {
            validate_text(value, field)?;
        }
        for feature in &features {
            validate_text(feature, "features")?;
        }
        for (value, field) in [
            (diff_digest.as_str(), "diff_digest"),
            (source_digest.as_str(), "source_digest"),
            (lock_digest.as_str(), "lock_digest"),
            (toolchain_digest.as_str(), "toolchain_digest"),
            (config_digest.as_str(), "config_digest"),
        ] {
            validate_digest(value, field)?;
        }
        features.sort();
        features.dedup();
        Ok(Self {
            product,
            workscope,
            base,
            candidate,
            checkout,
            diff_digest,
            target_triple,
            features,
            source_digest,
            lock_digest,
            toolchain_digest,
            config_digest,
            working_dir,
            cargo_target_root,
        })
    }

    /// Deterministic identity over every bound field.
    ///
    /// This is the single complete candidate/configuration identity: it is
    /// the value frozen in [`FrozenSelection`], quoted by
    /// [`TestSelectionReceipt`], and compared against the observed identity
    /// at final disposition. It is not a second fingerprint scheme.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.product,
            self.workscope,
            self.base,
            self.candidate,
            self.checkout,
            self.diff_digest,
            self.target_triple,
            self.features.join(","),
            self.source_digest,
            self.lock_digest,
            self.toolchain_digest,
            self.config_digest,
            self.working_dir,
            self.cargo_target_root,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Declared `dev-fast` resource budgets (I18.6 steps 3/6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevFastBudgets {
    /// Discovery wall timeout in milliseconds.
    pub discovery_timeout_ms: u64,
    /// Discovery raw capture bound in bytes.
    pub discovery_max_bytes: u64,
    /// Per-test wall timeout in milliseconds.
    pub per_test_timeout_ms: u64,
    /// Per-test retry count.
    pub per_test_retries: u32,
    /// Nextest run wall timeout in milliseconds.
    pub run_timeout_ms: u64,
    /// Nextest run memory ceiling in bytes.
    pub run_memory_bytes: u64,
    /// Maximum selected tests.
    pub max_selected_tests: u32,
    /// Maximum selection cost.
    pub max_selection_cost: u32,
}

impl DevFastBudgets {
    /// Records the declared budgets, validating every bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        discovery_timeout_ms: u64,
        discovery_max_bytes: u64,
        per_test_timeout_ms: u64,
        per_test_retries: u32,
        run_timeout_ms: u64,
        run_memory_bytes: u64,
        max_selected_tests: u32,
        max_selection_cost: u32,
    ) -> Result<Self, DevFastError> {
        for (value, field) in [
            (discovery_timeout_ms, "discovery_timeout_ms"),
            (discovery_max_bytes, "discovery_max_bytes"),
            (per_test_timeout_ms, "per_test_timeout_ms"),
            (run_timeout_ms, "run_timeout_ms"),
            (run_memory_bytes, "run_memory_bytes"),
        ] {
            if value == 0 {
                return Err(DevFastError::OutOfBound { field });
            }
        }
        if max_selected_tests == 0 {
            return Err(DevFastError::OutOfBound {
                field: "max_selected_tests",
            });
        }
        if max_selection_cost == 0 {
            return Err(DevFastError::OutOfBound {
                field: "max_selection_cost",
            });
        }
        Ok(Self {
            discovery_timeout_ms,
            discovery_max_bytes,
            per_test_timeout_ms,
            per_test_retries,
            run_timeout_ms,
            run_memory_bytes,
            max_selected_tests,
            max_selection_cost,
        })
    }
}

/// Admitted tool/parser/profile revisions one `dev-fast` run binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevFastToolRevisions {
    /// Admitted nextest tool revision.
    pub nextest: String,
    /// Admitted rustc/Clippy JSON parser revision.
    pub rustc_parser: String,
    /// Admitted nextest run-event parser revision.
    pub nextest_parser: String,
    /// Admitted nextest inventory parser revision.
    pub list_parser: String,
    /// Admitted rustfmt parser revision.
    pub rustfmt_parser: String,
    /// Admitted testd list profile revision.
    pub testd_list_profile: String,
    /// Admitted testd scoped-run profile revision.
    pub testd_scoped_profile: String,
}

impl DevFastToolRevisions {
    /// Records the admitted revisions, validating every value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nextest: String,
        rustc_parser: String,
        nextest_parser: String,
        list_parser: String,
        rustfmt_parser: String,
        testd_list_profile: String,
        testd_scoped_profile: String,
    ) -> Result<Self, DevFastError> {
        for (value, field) in [
            (nextest.as_str(), "nextest"),
            (rustc_parser.as_str(), "rustc_parser"),
            (nextest_parser.as_str(), "nextest_parser"),
            (list_parser.as_str(), "list_parser"),
            (rustfmt_parser.as_str(), "rustfmt_parser"),
            (testd_list_profile.as_str(), "testd_list_profile"),
            (testd_scoped_profile.as_str(), "testd_scoped_profile"),
        ] {
            validate_text(value, field)?;
        }
        Ok(Self {
            nextest,
            rustc_parser,
            nextest_parser,
            list_parser,
            rustfmt_parser,
            testd_list_profile,
            testd_scoped_profile,
        })
    }
}

/// Declared failure handling for one `dev-fast` run.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag gates an independent fail-closed dimension of the canonical policy; a bitflag would obscure the per-dimension meaning"
)]
pub struct DevFastFailurePolicy {
    /// Discovery failure fails the profile (never silently empty).
    pub discovery_failure_fails: bool,
    /// Unknown impact yields explicit incomplete coverage.
    pub unknown_impact_is_incomplete: bool,
    /// A missing mandatory stage fails the profile.
    pub missing_stage_fails: bool,
    /// Candidate drift fails the profile.
    pub drift_fails: bool,
}

impl DevFastFailurePolicy {
    /// The canonical fail-closed policy: every flag is set.
    pub fn canonical() -> Self {
        Self {
            discovery_failure_fails: true,
            unknown_impact_is_incomplete: true,
            missing_stage_fails: true,
            drift_fails: true,
        }
    }
}

/// Target/cache identity agreed with #1806 (I18.6 target layout).
///
/// The layout derives `%LOCALAPPDATA%\Eliot\build\<workspace-id>\
/// <worktree-id>\<build-class>`; this binding carries the derivation
/// inputs plus the admitted roots so the receipt and the #1806 owner share
/// one identity shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevFastTargetIdentity {
    /// Workspace identity.
    pub workspace_id: String,
    /// Worktree/checkout identity.
    pub worktree_id: String,
    /// Build class (`clippy`, `nextest`, `interactive`, ...).
    pub build_class: String,
    /// Admitted external target root.
    pub target_root: String,
    /// Admitted cache root.
    pub cache_root: String,
}

impl DevFastTargetIdentity {
    /// Binds one target identity, validating every field.
    pub fn bind(
        workspace_id: String,
        worktree_id: String,
        build_class: String,
        target_root: String,
        cache_root: String,
    ) -> Result<Self, DevFastError> {
        for (value, field) in [
            (workspace_id.as_str(), "workspace_id"),
            (worktree_id.as_str(), "worktree_id"),
            (build_class.as_str(), "build_class"),
            (target_root.as_str(), "target_root"),
            (cache_root.as_str(), "cache_root"),
        ] {
            validate_text(value, field)?;
        }
        Ok(Self {
            workspace_id,
            worktree_id,
            build_class,
            target_root,
            cache_root,
        })
    }

    /// Canonical `workspace/worktree/class` identity plus roots digest.
    pub fn identity(&self) -> String {
        let roots = sha256_hex(format!("{}\0{}", self.target_root, self.cache_root).as_bytes());
        format!(
            "{}/{}/{}:{roots}",
            self.workspace_id, self.worktree_id, self.build_class,
        )
    }
}

/// Preflight observations supplied by the owning composition root (I18.6
/// steps 1-2).
///
/// The check is pure: it validates caller-observed change/path/tool state
/// against the admitted candidate without touching the filesystem. The
/// owners of the observations (Git bridge, toolchain registry) stay
/// authoritative; this gate only refuses admittedly bad input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevFastPreflight {
    /// Changed paths admitted for this run.
    pub changed_paths: Vec<String>,
    /// Protected paths that must stay untouched.
    pub protected_paths: Vec<String>,
    /// Observed Cargo lock digest.
    pub lock_digest: String,
    /// Observed toolchain digest.
    pub toolchain_digest: String,
    /// Observed configuration digest.
    pub config_digest: String,
}

impl DevFastPreflight {
    /// Checks preflight observations against the bound candidate.
    ///
    /// A changed protected path, an unlisted change, or a lock/toolchain/
    /// config digest mismatch fails closed here, before any instrument
    /// runs. An empty change set is admitted: it selects nothing and the
    /// empty selection stays exact.
    pub fn check(&self, candidate: &DevFastCandidate) -> Result<(), DevFastError> {
        for path in &self.changed_paths {
            validate_text(path, "changed_paths")?;
            if self.protected_paths.iter().any(|guard| guard == path) {
                return Err(DevFastError::Preflight(format!(
                    "changed path '{path}' is protected"
                )));
            }
        }
        for path in &self.protected_paths {
            validate_text(path, "protected_paths")?;
        }
        for (observed, bound, field) in [
            (
                self.lock_digest.as_str(),
                candidate.lock_digest.as_str(),
                "lock_digest",
            ),
            (
                self.toolchain_digest.as_str(),
                candidate.toolchain_digest.as_str(),
                "toolchain_digest",
            ),
            (
                self.config_digest.as_str(),
                candidate.config_digest.as_str(),
                "config_digest",
            ),
        ] {
            validate_digest(observed, field)?;
            if observed != bound {
                return Err(DevFastError::Preflight(format!(
                    "{field} drifted after candidate binding"
                )));
            }
        }
        Ok(())
    }
}

/// Dispatch route for one `dev-fast` stage (issue #1802 step 4).
///
/// Test stages dispatch through Testd/Kernel admission under their closed
/// testd profile with validated slots; Build and Format stages dispatch
/// through the runner provider registry plus Kernel admission under their
/// admitted instrument and kind. No stage takes arbitrary shell text,
/// executable overrides, raw argv passthrough, or ambient features: slots
/// are validated values rendered by the owning adapter into sealed argv.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevFastDispatch {
    /// Dispatch through Testd under a closed profile with sealed slots.
    Testd {
        /// Closed admitted testd profile name.
        profile: String,
    },
    /// Dispatch through the runner registry plus Kernel admission.
    Kernel {
        /// Admitted instrument identity.
        instrument: String,
        /// Admitted instrument class.
        kind: InstrumentKind,
    },
}

/// Returns the closed dispatch route for one `dev-fast` stage identity.
///
/// Unknown stage identities fail closed: only the four declared I18.6
/// stages dispatch.
pub fn dev_fast_stage_dispatch(stage_id: &str) -> Result<DevFastDispatch, DevFastError> {
    if stage_id == DEV_FAST_STAGE_LIST {
        return Ok(DevFastDispatch::Testd {
            profile: "cargo-nextest-list".to_owned(),
        });
    }
    if stage_id == DEV_FAST_STAGE_RUN {
        return Ok(DevFastDispatch::Testd {
            profile: "cargo-nextest-scoped".to_owned(),
        });
    }
    if stage_id == DEV_FAST_STAGE_CLIPPY {
        return Ok(DevFastDispatch::Kernel {
            instrument: eliot_instrument_rustc::RUSTC_INSTRUMENT.to_owned(),
            kind: InstrumentKind::Build,
        });
    }
    if stage_id == DEV_FAST_STAGE_RUSTFMT {
        return Ok(DevFastDispatch::Kernel {
            instrument: eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT.to_owned(),
            kind: InstrumentKind::Format,
        });
    }
    Err(DevFastError::InvalidText { field: "stage_id" })
}

/// Builds the closed versioned `dev-fast` profile with its I18.6 stage
/// plan: discovery, affected diagnostics, selected execution, and the
/// separately reported format check. Scoped stages depend on discovery;
/// the selection freeze is a dev-fast orchestration gate between discovery
/// observation and scoped dispatch. There is no duplicate `cargo-check`
/// stage: Clippy performs the same compilation (I18.6).
pub(crate) fn dev_fast_profile() -> Result<InstrumentProfile, ProfileError> {
    use crate::profile::{
        ADMITTED_SCOPE_CLASS, ADMITTED_WORKTREE_CLASS, BUILTIN_SPEC_VERSION,
        ISOLATED_PROCESS_CLASS, ProfileScopeClasses, StageDag, StageDecl,
    };
    use eliot_contracts::ContractId;
    let dag = StageDag::build(
        DEV_FAST_PROFILE,
        vec![
            StageDecl::new(
                DEV_FAST_STAGE_LIST.to_owned(),
                ContractId::new(eliot_instrument_nextest::NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                Vec::new(),
                true,
                true,
            )?,
            StageDecl::new(
                DEV_FAST_STAGE_CLIPPY.to_owned(),
                ContractId::new(eliot_instrument_rustc::RUSTC_INSTRUMENT)?,
                InstrumentKind::Build,
                vec![DEV_FAST_STAGE_LIST.to_owned()],
                true,
                true,
            )?,
            StageDecl::new(
                DEV_FAST_STAGE_RUN.to_owned(),
                ContractId::new(eliot_instrument_nextest::NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                vec![DEV_FAST_STAGE_LIST.to_owned()],
                true,
                true,
            )?,
            StageDecl::new(
                DEV_FAST_STAGE_RUSTFMT.to_owned(),
                ContractId::new(eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT)?,
                InstrumentKind::Format,
                Vec::new(),
                true,
                true,
            )?,
        ],
    )?;
    InstrumentProfile::new(
        DEV_FAST_PROFILE.to_owned(),
        DEV_FAST_PROFILE_REVISION,
        BUILTIN_SPEC_VERSION,
        vec![
            InstrumentKind::Build,
            InstrumentKind::Test,
            InstrumentKind::Format,
        ],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            ISOLATED_PROCESS_CLASS.to_owned(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Surfaces every run the aggregate did not count as success (issue #1802
/// A5).
///
/// Failed, partial, cancelled, blocked, unknown, omitted, and missing runs
/// stay in the aggregate by construction; this accessor returns exactly those
/// runs in plan order so reporters and the evidence commit persist them
/// visibly instead of re-deriving success. An empty result means every
/// planned stage succeeded.
pub fn dev_fast_unresolved_runs(aggregate: &ProfileAggregate) -> Vec<&InstrumentRun> {
    aggregate
        .runs
        .iter()
        .filter(|run| !run.is_success())
        .collect()
}

/// Refuses an expected-nonzero selection that executed zero tests.
///
/// A complete known expected-nonzero selection with zero execution is
/// failure; missing output/parser coverage is failed or unknown, never
/// Pass. An expected-zero selection with zero execution stays exact.
pub fn check_zero_execution(expected: u64, executed: u64) -> Result<(), DevFastError> {
    if expected > 0 && executed == 0 {
        return Err(DevFastError::ZeroExecution { expected });
    }
    Ok(())
}

/// Canonical `dev-fast` disposition over the aggregate, receipt, and
/// candidate binding.
///
/// Pass requires all of: the aggregate succeeded, the receipt binds this
/// exact profile revision/candidate/disposition, the frozen selection is
/// `Ready` or exact `Empty` (never `WidenedTier` or `Incomplete`), the
/// receipt's selected and omitted rows match that frozen selection, its
/// coverage is complete, its expected and observed execution counts match,
/// the observed candidate revision equals the frozen revision, and the
/// observed complete candidate/configuration identity
/// ([`DevFastCandidate::digest`]) equals the identity frozen in the
/// selection, quoted by the receipt, and bound to the execution aggregate.
/// The same source commit verified under a different target triple, feature
/// set, or configuration is a different verification result and is refused
/// here. A substituted executable, changed candidate, missing mandatory
/// stage, unmatched output, or incomplete cleanup never returns Pass.
pub fn dev_fast_disposition(
    aggregate: &ProfileAggregate,
    receipt: &TestSelectionReceipt,
    candidate: &DevFastCandidate,
    frozen: &FrozenSelection,
) -> Result<(), DevFastError> {
    if aggregate.profile != DEV_FAST_PROFILE || aggregate.revision != DEV_FAST_PROFILE_REVISION {
        return Err(DevFastError::ReceiptMismatch(
            "aggregate is not the admitted dev-fast revision".to_owned(),
        ));
    }
    if let Some(run) = aggregate.runs.iter().find(|run| {
        matches!(&run.evidence, StageEvidence::RetainedProcessStreams { .. })
    }) {
        return Err(DevFastError::MandatoryStage {
            stage: run.stage.stage_id.clone(),
            status: "ProfileResolver immutable-stream evidence is not dev-fast artifact evidence"
                .to_owned(),
        });
    }
    if !matches!(aggregate.status, AggregateStatus::Succeeded) {
        let stage = aggregate
            .runs
            .iter()
            .find(|run| !run.is_success())
            .map_or_else(|| "unknown".to_owned(), |run| run.stage.stage_id.clone());
        return Err(DevFastError::MandatoryStage {
            stage,
            status: format!("{:?}", aggregate.status),
        });
    }
    receipt
        .validate()
        .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
    if receipt.profile != DEV_FAST_PROFILE
        || receipt.profile_revision != DEV_FAST_PROFILE_REVISION
        || receipt.profile_digest != aggregate.profile_digest
        || receipt.dag_digest != aggregate.dag_digest
    {
        return Err(DevFastError::ReceiptMismatch(
            "receipt does not bind the aggregated dev-fast revision".to_owned(),
        ));
    }
    frozen
        .validate()
        .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
    if receipt.frozen_digest != frozen.frozen_digest {
        return Err(DevFastError::ReceiptMismatch(
            "receipt does not bind the frozen selection".to_owned(),
        ));
    }
    let frozen_expected_count = u64::try_from(frozen.selected.len()).unwrap_or(u64::MAX);
    if receipt.candidate != frozen.candidate
        || receipt.plan_digest != frozen.plan_digest
        || receipt.discovery_digest != frozen.discovery_digest
        || receipt.discovered_count != frozen.discovered_count
        || receipt.disposition != frozen.disposition
        || receipt.selected != frozen.selected
        || receipt.omitted != frozen.omitted
        || receipt.expected_count != frozen_expected_count
    {
        return Err(DevFastError::ReceiptMismatch(
            "receipt selection fields do not match the frozen selection".to_owned(),
        ));
    }
    if receipt.unknown_coverage || !receipt.impact_gaps.is_empty() {
        return Err(DevFastError::IncompleteCoverage(
            "selection receipt carries unknown coverage or impact gaps".to_owned(),
        ));
    }
    if !matches!(
        frozen.disposition,
        FrozenDisposition::Ready | FrozenDisposition::Empty
    ) {
        return Err(DevFastError::IncompleteCoverage(format!(
            "frozen disposition is {:?}, not an exact selection",
            frozen.disposition
        )));
    }
    if candidate.candidate != frozen.candidate || candidate.candidate != receipt.candidate {
        return Err(DevFastError::CandidateDrift {
            coordinate: "candidate",
            expected: frozen.candidate.clone(),
            observed: candidate.candidate.clone(),
        });
    }
    // The bare revision is not the verification identity: the same source
    // commit built for another target triple, feature set, or configuration
    // is a different result. Bind the observed complete identity to the one
    // frozen in the selection, quoted by the receipt, and bound to the
    // aggregate that retains the stage executions.
    let observed_identity = candidate.digest();
    if aggregate.candidate_identity.as_deref() != Some(observed_identity.as_str()) {
        return Err(DevFastError::CandidateDrift {
            coordinate: "candidate_identity",
            expected: aggregate.candidate_identity.clone().unwrap_or_default(),
            observed: observed_identity,
        });
    }
    if observed_identity != frozen.candidate_identity
        || observed_identity != receipt.candidate_identity
    {
        return Err(DevFastError::CandidateDrift {
            coordinate: "candidate_identity",
            expected: frozen.candidate_identity.clone(),
            observed: observed_identity,
        });
    }
    check_zero_execution(receipt.expected_count, receipt.executed_count)?;
    if receipt.expected_count != receipt.executed_count {
        return Err(DevFastError::MandatoryStage {
            stage: DEV_FAST_STAGE_RUN.to_owned(),
            status: format!(
                "incomplete execution count: expected {}, observed {}",
                receipt.expected_count, receipt.executed_count
            ),
        });
    }
    Ok(())
}

/// Builds the registry admitting the builtin profiles plus closed
/// versioned `dev-fast` (issue #1802 step 1).
///
/// Registration validates every stage against its spec class, so a
/// dangling or mismatched dev-fast stage fails here, never at launch.
pub fn dev_fast_registry(
    generation: u64,
    receipts: Vec<crate::registry::SupplyChainReceipt>,
) -> Result<InstrumentRegistry, DevFastError> {
    use crate::profile::{
        builtin_specs, bundle_verification_profile, compiler_profile, package_verification_profile,
        test_profile,
    };
    let specs = builtin_specs()?;
    let profiles = vec![
        compiler_profile()?,
        test_profile()?,
        dev_fast_profile()?,
        package_verification_profile()?,
        bundle_verification_profile()?,
    ];
    Ok(InstrumentRegistry::build(
        specs, profiles, generation, receipts,
    )?)
}

/// Compiles `dev-fast` through the single shared profile compiler and
/// expands its deterministic stage plan (issue #1802 step 7).
///
/// Every caller — local verify, agent verifier requests, wrappers, CI,
/// `FinishService` — reaches the same revision, candidate identity, digests,
/// and stage sequence through this one function; there is no second
/// admission path. The executing composition root supplies the
/// [`StageLauncher`](crate::profile_run::StageLauncher) that turns the plan
/// into launches.
pub fn dev_fast_caller_plan(
    registry: &InstrumentRegistry,
    candidate: &DevFastCandidate,
) -> Result<StagePlan, DevFastError> {
    let compiler = ProfileCompiler::new(registry);
    let admitted = compiler.compile(DEV_FAST_PROFILE).admitted()?.clone();
    let mut plan = StageOrchestrator::plan(&admitted);
    plan.bind_candidate_identity(candidate.digest())
        .map_err(|error| DevFastError::Admission(error.to_string()))?;
    Ok(plan)
}

/// Resolves one verification route through the single shared profile compiler
/// and issues its shared receipt (issue #1914 W2 + W4).
///
/// This is the ONE function a local entrypoint and CI both call, so a local run
/// and a CI run of the same route reach the same resolver, the same admitted
/// revision, and the same receipt schema. I18.21 requires "CI builds the ELIOT
/// verifier/runner bootstrap and then calls the same versioned profiles used
/// locally", and I10.8.4 lists "Justfile wrappers" and "CI" as callers of the
/// same profile compiler; both are satisfied by this single call, so there is no
/// second gate-order source and no CI-only stage list.
///
/// The registry is built here from
/// [`InstrumentRegistry::with_verification_route_profiles`] rather than
/// supplied by the caller, because the registry is what decides which revision
/// a route name admits. A caller that assembled its own registry could admit a
/// different revision than the one CI resolves, which is exactly the divergence
/// this function exists to remove. `receipts` are the caller-attested
/// executable supply-chain receipts; they are validated against the admitted
/// spec digest at exactly `generation`, so a drifted or orphan receipt refuses
/// here and the route never resolves at all.
///
/// The run is then receipted through
/// [`build_verification_profile_receipt`](crate::verification_profile::build_verification_profile_receipt),
/// which calls `require_provenance` and therefore REFUSES a run whose required
/// identity or provenance data is absent: a stage with no recorded executable
/// identity, or an external stage with no admitted supply-chain receipt, fails
/// closed here instead of producing a receipt that defaults to an identity.
/// There is no path from this function to a receipt whose identity is missing.
///
/// The exact admitted revision, the profile digest, the stage DAG digest, the
/// resolution digest, and the admitted scope classes are all read back from the
/// same [`ProfileCompiler::resolve_full`] result, so local and CI cannot report
/// different revisions, or receipt one route under different declared classes,
/// for one route name.
///
/// `request.route` is a profile ALIAS, not a profile name, a command, or a
/// stage list: it must appear in the closed
/// [`PROFILE_ALIASES`](crate::profile::PROFILE_ALIASES) table, which pins one
/// exact admitted revision per alias. An alias outside that table fails closed,
/// a pinned revision the registry does not admit fails closed, and there is no
/// fallback to a neighbouring route and no default.
///
/// # Errors
///
/// Returns [`DevFastError::Admission`] carrying the registry or
/// [`admitted_profile_for_alias`] failure when a receipt is refused, the alias
/// is outside the closed table, the pinned revision admits nothing, or a
/// binding is refused, and [`DevFastError::ReceiptMismatch`] when
/// [`build_verification_profile_receipt`](crate::verification_profile::build_verification_profile_receipt)
/// refuses the run for a missing identity, a missing provenance receipt, a
/// profile-identity divergence, or an undeclared stage.
///
/// The exact resolution request one verification route is admitted under.
///
/// Grouped so the route, its layout, scope, environment and the receipts that
/// must cover them travel together as one closed value: a caller cannot resolve
/// a route against a different environment than the one the receipt binds.
pub struct VerificationRouteRequest {
    /// Executable supply-chain receipts the run must be covered by.
    pub receipts: Vec<SupplyChainReceipt>,
    /// Closed route name, never a caller-selected executable or shell string.
    pub route: String,
    /// Target layout the route resolves against.
    pub layout: TargetLayout,
    /// Work scope the route is bounded to.
    pub scope: WorkScope,
    /// Stage environment the run executes under.
    pub environment: StageEnvironment,
}

/// Resolves one admitted verification route and receipts the run, failing
/// closed when the required identity or provenance data is absent.
pub fn resolve_verification_route(
    generation: u64,
    request: VerificationRouteRequest,
    aggregate: &ProfileAggregate,
    environment_dependencies: &[DeclaredEnvironmentDependency],
) -> Result<VerificationProfileReceipt, DevFastError> {
    let VerificationRouteRequest {
        receipts,
        route,
        layout,
        scope,
        environment,
    } = request;
    let registry = InstrumentRegistry::with_verification_route_profiles(generation, receipts)
        .map_err(|error| {
            DevFastError::Admission(format!("verification registry refused: {error}"))
        })?;
    let compiler = ProfileCompiler::new(&registry);
    // The route is an alias, not a command: `route` must be a name in the
    // closed alias table, and it resolves to the exact revision that table
    // pins. A free-form profile name that is not an alias, or a registry that
    // does not admit the pinned revision, refuses here before any receipt is
    // built — there is no fallback to a neighbouring route and no default.
    let route_profile = admitted_profile_for_alias(&route, &registry)
        .map_err(|error| DevFastError::Admission(format!("profile alias refused: {error}")))?;
    let route_revision = route_profile.revision;
    let route_name = route_profile.name.clone();
    // The full resolution takes the environment by value, but the receipt
    // below still has to bind the exact environment this resolution ran
    // under, so the owned value is cloned for the move and the original is
    // what the receipt reads.
    let environment_identity = environment.clone();
    let resolved = compiler
        .resolve_full(&route_name, route_revision, layout, scope, environment)
        .map_err(|error| DevFastError::Admission(format!("profile route refused: {error}")))?;
    let admitted = compiler
        .compile_exact(&resolved.name, resolved.revision)
        .map_err(|error| {
            DevFastError::Admission(format!("resolved route did not compile: {error}"))
        })?;
    // The scope classes the receipt validates the declared environment
    // dependencies against are the ones the resolution above admitted, read
    // back from the registry's own profile revision. Taking them from the
    // resolution instead of a caller argument is what keeps local and CI on
    // one identity: a caller cannot receipt a route under classes the
    // registry never admitted, so the same route always validates its
    // environment dependencies against the same admitted class text.
    build_verification_profile_receipt(
        &admitted,
        &resolved.classes,
        aggregate,
        &environment_identity,
        environment_dependencies,
    )
    .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))
}

/// Normalized outcome of one retained `dev-fast` stage capture.
///
/// The outcome is the admitted parser's reading of real tool output only:
/// it never synthesizes a result, and anything the parser cannot answer
/// stays [`DevFastStageOutcome::Unknown`], never a pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevFastStageOutcome {
    /// The admitted parser read real tool output as a pass.
    Pass,
    /// The admitted parser read real tool output as a failure.
    Fail,
    /// The admitted parser read real tool output with no passing verdict
    /// (empty, truncated, or cancelled stream).
    Unknown,
}

/// Normalizes one retained `dev-fast` stage capture through the stage's
/// admitted real-output parser (issue #1852 W3).
///
/// Every `dev-fast` stage has exactly one owner per fact: discovery through
/// the nextest inventory parser, affected diagnostics through the Clippy lint
/// parser plus the Cargo build projection over the same stream (Cargo owns
/// the build facts, Clippy owns the lint facts — never two normalizers over
/// one fact), selected execution through the nextest run-event parser, and
/// the format check through the rustfmt parser. The raw bytes stay retained
/// under the caller's artifact handle; this projection adds no verdict of
/// its own beyond the parser's reading.
///
/// # Errors
///
/// Returns [`DevFastError::InvalidText`] for an undeclared stage identity
/// and [`DevFastError::StageParse`] when the capture is not a well-formed
/// stream of the admitted parser.
pub fn normalize_dev_fast_stage_bytes(
    stage_id: &str,
    bytes: &[u8],
    exit: RetainedExitOutcome,
) -> Result<DevFastStageOutcome, DevFastError> {
    if stage_id == DEV_FAST_STAGE_LIST {
        let inventory = eliot_instrument_nextest::parse_list_json(bytes).map_err(|error| {
            DevFastError::StageParse {
                stage: stage_id.to_owned(),
                parser: "nextest-list",
                detail: error.to_string(),
            }
        })?;
        return Ok(if inventory.is_empty() {
            DevFastStageOutcome::Unknown
        } else {
            DevFastStageOutcome::Pass
        });
    }
    if stage_id == DEV_FAST_STAGE_CLIPPY {
        let build = eliot_instrument_cargo::parse_jsonl(bytes).map_err(|error| {
            DevFastError::StageParse {
                stage: stage_id.to_owned(),
                parser: "cargo-build",
                detail: error.to_string(),
            }
        })?;
        let lints = eliot_instrument_rustc::parse_clippy_jsonl(bytes).map_err(|error| {
            DevFastError::StageParse {
                stage: stage_id.to_owned(),
                parser: "clippy-lint",
                detail: error.to_string(),
            }
        })?;
        return Ok(match (build.outcome(), lints.outcome()) {
            (VerificationOutcome::Fail, _) | (_, VerificationOutcome::Fail) => {
                DevFastStageOutcome::Fail
            }
            (VerificationOutcome::Pass, VerificationOutcome::Pass) => DevFastStageOutcome::Pass,
            _ => DevFastStageOutcome::Unknown,
        });
    }
    if stage_id == DEV_FAST_STAGE_RUN {
        let report = eliot_instrument_nextest::parse_jsonl(bytes).map_err(|error| {
            DevFastError::StageParse {
                stage: stage_id.to_owned(),
                parser: "nextest-run",
                detail: error.to_string(),
            }
        })?;
        return Ok(match report.outcome() {
            VerificationOutcome::Pass => DevFastStageOutcome::Pass,
            VerificationOutcome::Fail => DevFastStageOutcome::Fail,
            _ => DevFastStageOutcome::Unknown,
        });
    }
    if stage_id == DEV_FAST_STAGE_RUSTFMT {
        let report = eliot_instrument_rustfmt::parse_output(bytes).map_err(|error| {
            DevFastError::StageParse {
                stage: stage_id.to_owned(),
                parser: "rustfmt-check",
                detail: error.to_string(),
            }
        })?;
        // `RetainedExitOutcome::sealed` admits only a completed exit with a
        // code or an unknown outcome without one; cancellation is never a
        // retained dev-fast capture, so `cancelled` stays false here.
        let outcome = report.outcome(exit.code, false);
        return Ok(match outcome {
            VerificationOutcome::Pass => DevFastStageOutcome::Pass,
            VerificationOutcome::Fail => DevFastStageOutcome::Fail,
            _ => DevFastStageOutcome::Unknown,
        });
    }
    Err(DevFastError::InvalidText { field: "stage_id" })
}

/// Finalizes one launched `dev-fast` stage whose supervising lane retained
/// the exact raw bytes under an immutable artifact handle (issue #1852 W2).
///
/// The sealed tool identity is bound here, at finalization, from the
/// executable, argument vector, environment projection digest, and terminal
/// exit outcome the lane observed — never reconstructed later from the
/// bytes. The returned run is the first production constructor of
/// [`StageEvidence::Retained`](crate::profile_run::StageEvidence).
///
/// # Errors
///
/// Returns [`DevFastError::Admission`] when the tool identity, the operation
/// binding, or the executable digest is not an observed sealed value.
#[allow(clippy::too_many_arguments)]
pub fn finalize_dev_fast_stage(
    route: &TestExecutionPlaneRoute,
    operation_id: String,
    grant: &InstrumentAdmissionGrant,
    target_layout: Option<StageTargetLayout>,
    artifact: ArtifactId,
    byte_len: u64,
    executable: &str,
    arguments: &[String],
    environment_digest: &str,
    exit: RetainedExitOutcome,
    executable_digest: String,
) -> Result<InstrumentRun, DevFastError> {
    let tool = RetainedToolIdentity::sealed(executable, arguments, environment_digest, exit)?;
    Ok(InstrumentRun::finalize_retained(
        route,
        operation_id,
        grant,
        target_layout,
        artifact,
        byte_len,
        tool,
        executable_digest,
    )?)
}

/// Runs the closed versioned `dev-fast` profile end to end through the one
/// shared [`InstrumentRunner`]/[`ProcessExecutor`] path (issue #1852 W1).
///
/// Every caller — local verify, agent verifier requests, Justfile wrappers,
/// CI, `FinishService` — reaches the same admitted revision, the same
/// candidate-bound stage plan, and the same aggregate shape through this one
/// function; there is no second admission path (I10.8.4: no fifth
/// verification path). The owning composition root supplies the runner
/// around the production process executor and the [`StageLauncher`] that
/// turns the admitted plan into launches; transports differ only in how they
/// provision those two values, never in which profile they run.
///
/// # Errors
///
/// Returns [`DevFastError::Admission`] when the registry, the compilation,
/// or the candidate binding fails. Launch, admission, and invocation
/// failures of individual stages never surface here: they become explicit
/// missing runs inside the returned aggregate. New admission is checked
/// against the live registry, so a replaced spec, parser, receipt, or route
/// becomes a missing run instead of a launch.
pub async fn run_dev_fast_profile<E: ProcessExecutor + 'static>(
    runner: &InstrumentRunner<E>,
    generation: u64,
    receipts: Vec<SupplyChainReceipt>,
    candidate: &DevFastCandidate,
    launcher: &dyn StageLauncher,
) -> Result<ProfileAggregate, DevFastError> {
    let registry = dev_fast_registry(generation, receipts)?;
    let plan = dev_fast_caller_plan(&registry, candidate)?;
    let runs = StageOrchestrator::launch_plan_live(runner, &registry, &plan, launcher).await;
    Ok(ProfileAggregate::assemble(&plan, runs))
}

/// Confirms one `dev-fast` run as the canonical finish input: real tool
/// failures block, nothing else passes (issue #1852 A2).
///
/// [`dev_fast_disposition`] reads the aggregate the shared runner assembled
/// over retained stage evidence plus the frozen selection and its receipt;
/// an intentionally introduced Clippy, nextest, or rustfmt failure surfaces
/// here as a failed or missing mandatory stage and is refused. Only a passed
/// disposition assembles the persisted [`VerificationProfileRun`], whose raw
/// references are derived from the aggregate's own retained artifact
/// handles — never invented. Persistence still never upgrades a failed
/// aggregate into a pass.
///
/// # Errors
///
/// Returns the [`dev_fast_disposition`] refusal when the run is not the
/// admitted revision, a mandatory stage did not succeed, the receipt does
/// not bind the frozen selection and candidate identity, or execution was
/// incomplete.
pub fn confirm_dev_fast_finish(
    candidate: &DevFastCandidate,
    aggregate: &ProfileAggregate,
    receipt: &TestSelectionReceipt,
    frozen: &FrozenSelection,
) -> Result<VerificationProfileRun, DevFastError> {
    dev_fast_disposition(aggregate, receipt, candidate, frozen)?;
    let raw_refs = aggregate
        .runs
        .iter()
        .filter_map(|run| match &run.evidence {
            StageEvidence::Retained { artifact, .. } => Some(artifact.as_str().to_owned()),
            // Dev-fast raw refs remain artifact handles from its existing
            // retention owner. Verification-profile stream readbacks are a
            // separate evidence path and are not promoted into this record.
            StageEvidence::RetainedProcessStreams { .. }
            | StageEvidence::Omitted { .. }
            | StageEvidence::Missing { .. } => None,
        })
        .collect::<Vec<_>>();
    VerificationProfileRun::assemble(
        candidate,
        aggregate,
        receipt,
        raw_refs,
        DEV_FAST_SLICE_PARTIAL,
    )
}

/// Requires local/CI parity over one named `dev-fast` profile run (issue
/// #1852 A1).
///
/// Both receipts must record the same profile name, revision, definition and
/// stage-graph digests, tool identities, and aggregate shape through the one
/// shared receipt schema; any divergence — including a CI verifier command
/// the local receipt never declared — refuses parity instead of passing
/// silently. A non-PASS normalized outcome on either side is never parity.
///
/// # Errors
///
/// Returns [`DevFastError::ReceiptMismatch`] when either receipt is
/// internally inconsistent or the two receipts diverge.
pub fn require_dev_fast_parity(
    local: &VerificationProfileReceipt,
    ci: &VerificationProfileReceipt,
) -> Result<(), DevFastError> {
    let verdict = verify_profile_parity(local, ci)
        .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
    match verdict {
        ParityVerdict::Pass { .. } => Ok(()),
        ParityVerdict::NonPass { reason } => Err(DevFastError::ReceiptMismatch(reason)),
    }
}

/// Executes the candidate-bound `dev-fast` plan and aggregates its canonical
/// stages (issue #1802 step 5).
///
/// The plan must be the admitted `dev-fast` revision, normally compiled by
/// [`dev_fast_caller_plan`], which binds the complete candidate/configuration
/// identity the aggregate inherits. Launching walks the existing total
/// orchestrator: admitted stages launch through the executing composition
/// root's [`StageLauncher`] provisions, and every refusal, failure, or
/// unlaunched dependency becomes an explicit missing run the aggregate keeps
/// visible. The executor behind `runner` belongs to the owning supervision
/// lane (Kernel/`testd`); this entry supplies orchestration only and invents
/// no invocation, process, or verdict.
pub async fn dev_fast_execute<E: ProcessExecutor + 'static>(
    runner: &InstrumentRunner<E>,
    plan: &StagePlan,
    launcher: &dyn StageLauncher,
) -> Result<ProfileAggregate, DevFastError> {
    if plan.profile != DEV_FAST_PROFILE || plan.revision != DEV_FAST_PROFILE_REVISION {
        return Err(DevFastError::Admission(
            "stage plan is not the admitted dev-fast revision".to_owned(),
        ));
    }
    let runs = StageOrchestrator::launch_plan(runner, plan, launcher).await;
    Ok(ProfileAggregate::assemble(plan, runs))
}

/// One persisted dev-fast profile run bound to its aggregate, receipt,
/// and retained raw outputs (I18.6 step 9).
///
/// The record carries no semantic verdict beyond the aggregate status it
/// quotes: persistence is observation, and only the Governor admits
/// evidence while only `FinishService` decides completion. A lost
/// acknowledgement resolves through [`VerificationProfileRun::resolve_lost_ack`]
/// against the retained inputs; it never reruns build/test effects.
///
/// The record serializes to the evidence owner (I18.6 step 9) as canonical
/// JSON. Unknown fields are refused on readback, so a record written by a
/// newer semantics version fails closed instead of decoding as this version.
/// `run_digest` is a versioned canonical commitment over the complete record
/// (I5.27): the raw references are hashed as an actual array, so list
/// boundaries, order, and content are bound and a rewritten vector fails
/// readback. The retired [`VERIFICATION_PROFILE_RUN_LEGACY_VERSION`] encoding
/// is refused, never re-interpreted under the current preimage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationProfileRun {
    /// Record semantics version.
    pub version: String,
    /// Deterministic run identity over candidate/configuration identity,
    /// profile revision, aggregate digest, and receipt digest.
    pub run_id: String,
    /// Candidate the run is bound to.
    pub candidate: String,
    /// Complete candidate/configuration identity from the validated
    /// [`TestSelectionReceipt`], produced by [`DevFastCandidate::digest`].
    pub candidate_identity: String,
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Aggregate digest over definition plus ordered runs.
    pub aggregate_digest: String,
    /// Digest of the bound [`TestSelectionReceipt`].
    pub receipt_digest: String,
    /// Aggregate status quoted from the profile aggregate.
    pub status: AggregateStatus,
    /// Slice completeness label ([`DEV_FAST_SLICE_PARTIAL`]).
    pub slice: String,
    /// Raw retained output references bound to the run, as an actual array.
    pub raw_refs: Vec<String>,
    /// Stable digest binding the complete record, including the
    /// raw-reference list boundaries.
    pub run_digest: String,
}

impl VerificationProfileRun {
    /// Assembles one profile run over a candidate, aggregate, and receipt.
    ///
    /// The aggregate must be the admitted dev-fast revision and retain the
    /// complete identity computed by [`DevFastCandidate::digest`]. The
    /// validated receipt must bind its profile digests, candidate revision,
    /// and that same identity; a receipt or aggregate for another
    /// configuration at the same source revision is refused. Persistence
    /// never upgrades a failed aggregate into a pass.
    pub fn assemble(
        candidate: &DevFastCandidate,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
        raw_refs: Vec<String>,
        slice: &str,
    ) -> Result<Self, DevFastError> {
        validate_text(&candidate.candidate, "candidate")?;
        validate_text(slice, "slice")?;
        for raw in &raw_refs {
            validate_text(raw, "raw_refs")?;
        }
        if aggregate.profile != DEV_FAST_PROFILE || aggregate.revision != DEV_FAST_PROFILE_REVISION
        {
            return Err(DevFastError::ReceiptMismatch(
                "aggregate is not the admitted dev-fast revision".to_owned(),
            ));
        }
        receipt
            .validate()
            .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
        let candidate_identity = candidate.digest();
        if receipt.profile != DEV_FAST_PROFILE
            || receipt.profile_revision != DEV_FAST_PROFILE_REVISION
            || receipt.profile_digest != aggregate.profile_digest
            || receipt.dag_digest != aggregate.dag_digest
            || aggregate.candidate_identity.as_deref() != Some(candidate_identity.as_str())
            || receipt.candidate != candidate.candidate
            || receipt.candidate_identity != candidate_identity
        {
            return Err(DevFastError::ReceiptMismatch(
                "aggregate and receipt do not bind the dev-fast candidate, configuration, and revision"
                    .to_owned(),
            ));
        }
        let run_id = profile_run_id(
            &candidate.candidate,
            DEV_FAST_PROFILE,
            DEV_FAST_PROFILE_REVISION,
            &aggregate.aggregate_digest,
            &receipt.receipt_digest,
            &candidate_identity,
        );
        let mut record = Self {
            version: VERIFICATION_PROFILE_RUN_VERSION.to_owned(),
            run_id,
            candidate: candidate.candidate.clone(),
            candidate_identity: receipt.candidate_identity.clone(),
            profile: DEV_FAST_PROFILE.to_owned(),
            profile_revision: DEV_FAST_PROFILE_REVISION,
            aggregate_digest: aggregate.aggregate_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            status: aggregate.status,
            slice: slice.to_owned(),
            raw_refs,
            run_digest: String::new(),
        };
        record.run_digest = record.compute_digest()?;
        Ok(record)
    }

    /// Computes the digest binding every record field.
    ///
    /// The preimage is the project's canonical serialization
    /// ([`canonical_json_bytes`]) of this record with `run_digest` itself
    /// blanked, prefixed by the preimage domain separator and its
    /// encoding version. Two consequences matter for readback:
    ///
    /// * the raw references are hashed as an actual JSON array of their
    ///   own strings, so list boundaries, order, and content are all
    ///   bound; changing only a boundary produces a different preimage;
    /// * every scalar field keeps its own JSON encoding, so no field can
    ///   be shifted across a separator by embedding one.
    ///
    /// The preimage carries the record's own `version` field, so a digest
    /// produced by another encoding can never be reproduced here. The
    /// digest owner remains the single [`sha256_hex`] helper this module
    /// already used; no second digest authority is introduced.
    ///
    /// # Errors
    ///
    /// Returns [`DevFastError::Admission`] when the record cannot be
    /// serialized to its canonical preimage. It never falls back to an
    /// unversioned or delimiter-joined encoding.
    fn compute_digest(&self) -> Result<String, DevFastError> {
        let mut preimage = self.clone();
        preimage.run_digest = String::new();
        let canonical = canonical_json_bytes(&preimage).map_err(|error| {
            DevFastError::Admission(format!(
                "profile run canonical preimage could not be serialized: {error}"
            ))
        })?;
        let mut material = Vec::with_capacity(
            PROFILE_RUN_PREIMAGE_DOMAIN.len()
                + PROFILE_RUN_PREIMAGE_ENCODING.len()
                + canonical.len()
                + 2,
        );
        material.extend_from_slice(PROFILE_RUN_PREIMAGE_DOMAIN.as_bytes());
        material.push(0);
        material.extend_from_slice(PROFILE_RUN_PREIMAGE_ENCODING.as_bytes());
        material.push(0);
        material.extend_from_slice(&canonical);
        Ok(sha256_hex(&material))
    }

    /// Verifies the record still binds every field it carries.
    ///
    /// Readback calls this before trusting a deserialized record: a record
    /// under the retired [`VERIFICATION_PROFILE_RUN_LEGACY_VERSION`], whose
    /// digest never bound the raw-reference list boundaries, is refused
    /// here without being recomputed, and a digest that no longer matches
    /// the fields of a current record fails here instead of travelling on
    /// as retained evidence.
    pub fn check_digest(&self) -> Result<(), DevFastError> {
        self.require_current_encoding()?;
        if self.compute_digest()? != self.run_digest {
            return Err(DevFastError::ReceiptMismatch(
                "profile run record digest does not bind its fields".to_owned(),
            ));
        }
        Ok(())
    }

    /// Refuses any record not written under the current encoding.
    ///
    /// The persisted encoding version is the record's own disposition:
    /// [`VERIFICATION_PROFILE_RUN_LEGACY_VERSION`] is not re-interpreted
    /// under the current preimage, and a newer unknown version fails
    /// closed the same way. Nothing here inspects a retired digest, so an
    /// old encoding can never certify the current interpretation.
    fn require_current_encoding(&self) -> Result<(), DevFastError> {
        if self.version == VERIFICATION_PROFILE_RUN_VERSION {
            return Ok(());
        }
        // The retired version is named rather than treated as an anonymous
        // mismatch, so the disposition of retained `v2` evidence is explicit
        // in the refusal itself.
        let disposition = if self.version == VERIFICATION_PROFILE_RUN_LEGACY_VERSION {
            "it is the retired encoding whose preimage did not bind \
             raw-reference list boundaries, and it is never re-interpreted \
             under the current one"
        } else {
            "it is an unknown encoding and is never re-interpreted under the \
             current one"
        };
        Err(DevFastError::ReceiptMismatch(format!(
            "profile run record encoding '{}' is not the current encoding \
             '{}': {disposition}",
            self.version, VERIFICATION_PROFILE_RUN_VERSION,
        )))
    }

    /// Resolves a lost acknowledgement against retained inputs without
    /// rerunning effects.
    ///
    /// The expected run identity is recomputed deterministically from the
    /// retained candidate/configuration identity, aggregate, and receipt:
    /// when it names this exact record, the caller reuses the retained record
    /// as the answer. A renamed candidate, changed configuration, different
    /// aggregate, rebound receipt, or record under a non-current encoding
    /// fails here instead of reconstructing an answer by rerunning build/test
    /// effects.
    pub fn resolve_lost_ack(
        &self,
        candidate: &DevFastCandidate,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
    ) -> Result<(), DevFastError> {
        receipt
            .validate()
            .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
        self.require_current_encoding()?;
        let candidate_identity = candidate.digest();
        let expected = profile_run_id(
            &candidate.candidate,
            &aggregate.profile,
            aggregate.revision,
            &aggregate.aggregate_digest,
            &receipt.receipt_digest,
            &candidate_identity,
        );
        if self.version != VERIFICATION_PROFILE_RUN_VERSION
            || aggregate.profile != DEV_FAST_PROFILE
            || aggregate.revision != DEV_FAST_PROFILE_REVISION
            || expected != self.run_id
            || candidate.candidate != self.candidate
            || candidate_identity != self.candidate_identity
            || receipt.candidate != self.candidate
            || receipt.candidate_identity != self.candidate_identity
            || aggregate.candidate_identity.as_deref() != Some(self.candidate_identity.as_str())
            || aggregate.profile != self.profile
            || aggregate.revision != self.profile_revision
            || aggregate.aggregate_digest != self.aggregate_digest
            || aggregate.status != self.status
            || receipt.profile != self.profile
            || receipt.profile_revision != self.profile_revision
            || receipt.profile_digest != aggregate.profile_digest
            || receipt.dag_digest != aggregate.dag_digest
            || receipt.receipt_digest != self.receipt_digest
            || self.compute_digest()? != self.run_digest
        {
            return Err(DevFastError::ReceiptMismatch(
                "lost acknowledgement does not resolve the retained profile run".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Replays the retained profile run without starting any process (issue
/// #1802 A5).
///
/// The retained record resolves against the retained candidate, aggregate,
/// and receipt through [`VerificationProfileRun::resolve_lost_ack`]; when
/// they name this exact record, the retained record itself is the answer.
/// The signature takes no executor, launcher, or process handle, so replay
/// cannot rerun build/test effects to reconstruct an answer: a renamed
/// candidate, changed configuration, different aggregate, or rebound receipt
/// fails instead.
pub fn dev_fast_replay(
    retained: &VerificationProfileRun,
    candidate: &DevFastCandidate,
    aggregate: &ProfileAggregate,
    receipt: &TestSelectionReceipt,
) -> Result<VerificationProfileRun, DevFastError> {
    retained.resolve_lost_ack(candidate, aggregate, receipt)?;
    Ok(retained.clone())
}

/// Deterministic profile-run identity over candidate/configuration identity,
/// profile revision, aggregate digest, and receipt digest.
fn profile_run_id(
    candidate: &str,
    profile: &str,
    revision: u64,
    aggregate_digest: &str,
    receipt_digest: &str,
    candidate_identity: &str,
) -> String {
    sha256_hex(
        format!(
            "{candidate}\0{profile}\0{revision}\0{aggregate_digest}\0{receipt_digest}\0\
             {candidate_identity}"
        )
        .as_bytes(),
    )
}
