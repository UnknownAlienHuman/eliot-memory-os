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

use eliot_contracts::sha256_hex;
use eliot_instrument_api::InstrumentKind;
use eliot_test_selection::{FrozenDisposition, FrozenSelection, TestSelectionReceipt};
use thiserror::Error;

use crate::profile::{InstrumentProfile, InstrumentRegistry, ProfileCompiler, ProfileError};
use crate::profile_run::{AggregateStatus, ProfileAggregate, StageOrchestrator, StagePlan};

/// Canonical `dev-fast` profile name (I18.6).
pub const DEV_FAST_PROFILE: &str = "dev-fast";
/// Exact admitted `dev-fast` revision shipped by this slice.
pub const DEV_FAST_PROFILE_REVISION: u64 = 1;
/// First-slice completeness label: partial until every retained I18.6
/// obligation (live discovery dispatch, frozen selection execution,
/// admitted evidence persistence) is present.
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
pub const VERIFICATION_PROFILE_RUN_VERSION: &str = "eliot-verification-profile-run-v1";

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
    #[error("candidate drift: selection is frozen for '{expected}', not '{observed}'")]
    CandidateDrift {
        /// Frozen candidate.
        expected: String,
        /// Observed candidate.
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
}

impl From<ProfileError> for DevFastError {
    fn from(error: ProfileError) -> Self {
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
/// expected/executed counts satisfy [`check_zero_execution`], and the
/// observed candidate equals the frozen candidate. A substituted
/// executable, changed candidate, missing mandatory stage, unmatched
/// output, or incomplete cleanup never returns Pass.
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
            expected: frozen.candidate.clone(),
            observed: candidate.candidate.clone(),
        });
    }
    check_zero_execution(receipt.expected_count, receipt.executed_count)?;
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
    use crate::profile::{builtin_specs, compiler_profile, test_profile};
    let specs = builtin_specs()?;
    let profiles = vec![compiler_profile()?, test_profile()?, dev_fast_profile()?];
    Ok(InstrumentRegistry::build(
        specs, profiles, generation, receipts,
    )?)
}

/// Compiles `dev-fast` through the single shared profile compiler and
/// expands its deterministic stage plan (issue #1802 step 7).
///
/// Every caller — local verify, agent verifier requests, wrappers, CI,
/// `FinishService` — reaches the same revision, digests, and stage sequence
/// through this one function; there is no second admission path. The
/// executing composition root supplies the [`StageLauncher`](crate::profile_run::StageLauncher)
/// that turns the plan into launches.
pub fn dev_fast_caller_plan(registry: &InstrumentRegistry) -> Result<StagePlan, DevFastError> {
    let compiler = ProfileCompiler::new(registry);
    let admitted = compiler.compile(DEV_FAST_PROFILE).admitted()?.clone();
    Ok(StageOrchestrator::plan(&admitted))
}

/// One persisted dev-fast profile run bound to its aggregate, receipt,
/// and retained raw outputs (I18.6 step 9).
///
/// The record carries no semantic verdict beyond the aggregate status it
/// quotes: persistence is observation, and only the Governor admits
/// evidence while only `FinishService` decides completion. A lost
/// acknowledgement resolves through [`VerificationProfileRun::resolve_lost_ack`]
/// against the retained inputs; it never reruns build/test effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationProfileRun {
    /// Record semantics version.
    pub version: String,
    /// Deterministic run identity over candidate, profile revision,
    /// aggregate digest, and receipt digest.
    pub run_id: String,
    /// Candidate the run is bound to.
    pub candidate: String,
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
    /// Raw retained output references bound to the run.
    pub raw_refs: Vec<String>,
    /// Stable digest binding the complete record.
    pub run_digest: String,
}

impl VerificationProfileRun {
    /// Assembles one profile run over an aggregate and its receipt.
    ///
    /// The aggregate must be the admitted dev-fast revision and the receipt
    /// must bind the aggregate digests and the candidate; persistence never
    /// upgrades a failed aggregate into a pass.
    pub fn assemble(
        candidate: &str,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
        raw_refs: Vec<String>,
        slice: &str,
    ) -> Result<Self, DevFastError> {
        validate_text(candidate, "candidate")?;
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
        if receipt.profile != DEV_FAST_PROFILE
            || receipt.profile_revision != DEV_FAST_PROFILE_REVISION
            || receipt.profile_digest != aggregate.profile_digest
            || receipt.dag_digest != aggregate.dag_digest
            || receipt.candidate != candidate
        {
            return Err(DevFastError::ReceiptMismatch(
                "receipt does not bind the aggregated dev-fast candidate and revision".to_owned(),
            ));
        }
        let run_id = profile_run_id(
            candidate,
            DEV_FAST_PROFILE,
            DEV_FAST_PROFILE_REVISION,
            &aggregate.aggregate_digest,
            &receipt.receipt_digest,
        );
        let mut record = Self {
            version: VERIFICATION_PROFILE_RUN_VERSION.to_owned(),
            run_id,
            candidate: candidate.to_owned(),
            profile: DEV_FAST_PROFILE.to_owned(),
            profile_revision: DEV_FAST_PROFILE_REVISION,
            aggregate_digest: aggregate.aggregate_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            status: aggregate.status,
            slice: slice.to_owned(),
            raw_refs,
            run_digest: String::new(),
        };
        record.run_digest = record.compute_digest();
        Ok(record)
    }

    /// Computes the digest binding every record field.
    fn compute_digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{:?}\0{}\0{}",
            self.version,
            self.run_id,
            self.candidate,
            self.profile,
            self.profile_revision,
            self.aggregate_digest,
            self.receipt_digest,
            self.status,
            self.slice,
            self.raw_refs.join(","),
        );
        sha256_hex(material.as_bytes())
    }

    /// Resolves a lost acknowledgement against retained inputs without
    /// rerunning effects.
    ///
    /// The expected run identity is recomputed deterministically from the
    /// retained candidate, aggregate, and receipt: when it names this exact
    /// record, the caller reuses the retained record as the answer. A
    /// renamed candidate, a different aggregate, or a rebound receipt fails
    /// here instead of reconstructing an answer by rerunning build/test
    /// effects.
    pub fn resolve_lost_ack(
        &self,
        candidate: &str,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
    ) -> Result<(), DevFastError> {
        receipt
            .validate()
            .map_err(|error| DevFastError::ReceiptMismatch(error.to_string()))?;
        let expected = profile_run_id(
            candidate,
            &aggregate.profile,
            aggregate.revision,
            &aggregate.aggregate_digest,
            &receipt.receipt_digest,
        );
        if expected != self.run_id
            || candidate != self.candidate
            || aggregate.aggregate_digest != self.aggregate_digest
            || receipt.receipt_digest != self.receipt_digest
            || self.compute_digest() != self.run_digest
        {
            return Err(DevFastError::ReceiptMismatch(
                "lost acknowledgement does not resolve the retained profile run".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Deterministic profile-run identity over candidate, profile revision,
/// aggregate digest, and receipt digest.
fn profile_run_id(
    candidate: &str,
    profile: &str,
    revision: u64,
    aggregate_digest: &str,
    receipt_digest: &str,
) -> String {
    sha256_hex(
        format!("{candidate}\0{profile}\0{revision}\0{aggregate_digest}\0{receipt_digest}")
            .as_bytes(),
    )
}
