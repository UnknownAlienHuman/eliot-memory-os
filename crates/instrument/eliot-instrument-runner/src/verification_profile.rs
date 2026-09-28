//! Versioned local/CI verification profiles with one shared evidence receipt.
//!
//! This module implements issue #1914 over the contracts that already exist.
//! [`crate::profile::InstrumentProfile`] is already the versioned profile —
//! its [`InstrumentProfile::digest`](crate::profile::InstrumentProfile::digest)
//! over revision, classes, and stage graph *is* the profile revision identity,
//! and [`crate::profile::ProfileCompiler`] is already the single resolver every
//! verification entry point calls. This module adds only what I18.21
//! (`docs/architecture/I18-21-local-and-ci-parity.md`) still requires of those
//! results and deliberately invents no second profile or version type:
//!
//! * CI-specific environment differences become explicit, declared profile
//!   dependencies ([`DeclaredEnvironmentDependency`]) rather than an ambient
//!   variable sniff. The check reuses the existing
//!   [`ProfileError::EnvironmentMismatch`] and [`StageEnvironment`].
//! * Local and CI share one receipt schema: [`VerificationProfileReceipt`],
//!   which records the profile revision, the tool/executable identities, the
//!   external-tool digest/provenance receipts, the declared environment
//!   dependencies, the raw stage evidence, the normalized outcome, and the
//!   proof ceiling, and is issued as an
//!   [`eliot_receipts::ReceiptEnvelope`] of kind
//!   [`ReceiptKind::Verification`].
//! * [`verify_profile_parity`] compares one local receipt against one CI
//!   receipt and fails closed on any revision, digest, or schema divergence and
//!   on any undeclared verifier command or missing identity/provenance.
//! * [`require_provenance`] refuses a profile whose stages lack a recorded tool
//!   identity or supply-chain receipt, so an external binary can never run
//!   without its digest/provenance receipt.
//!
//! Per I18.24 this module never decides task completion: the aggregate status
//! stays a normalized outcome, and `PARTIAL`, `UNKNOWN`, `BLOCKED`, and
//! `CANCELLED` can never be reported as PASS. Nothing here persists a receipt,
//! reads `CI`/`GITHUB_*` ambient state, spawns a process, or takes canonical
//! store authority.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, ProductId, RequestMetadata, StateFence,
    TransactionSequence,
};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, OperationId,
    ProofCeiling, ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptError, ReceiptKind,
    RequestBinding, VerifierBinding, WorkScopeBinding, WorkScopeId, contract_identity, sha256_hex,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profile::{AdmittedProfile, ProfileError, ProfileScopeClasses, StageEnvironment};
use crate::profile_run::{AggregateStatus, ProfileAggregate, RetainedToolIdentity, StageEvidence};
use crate::registry::SupplyChainReceipt;

/// Stable verifier identity recorded in every profile verification receipt.
///
/// The receipt names this contract family so a local and a CI receipt compare
/// under one verifier identity rather than under whatever entrypoint happened
/// to build them.
pub const VERIFICATION_PROFILE_VERIFIER: &str = "eliot.instrument.verification-profile";
/// Exact verifier revision recorded alongside
/// [`VERIFICATION_PROFILE_VERIFIER`].
pub const VERIFICATION_PROFILE_VERIFIER_REVISION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Receipt `operation_kind` recorded for one issued profile verification
/// receipt.
pub const VERIFICATION_OPERATION_KIND: &str = "instrument.profile.verify";
/// Strongest proof ceiling a profile verification receipt may claim.
///
/// I18.24 and the Instrument boundary keep profile-run evidence below task
/// finish: a profile run observes scoped verification of the declared stages
/// and never an observed external effect, so the ceiling is
/// [`ProofCeiling::ScopedVerification`].
pub const PROFILE_PROOF_CEILING: ProofCeiling = ProofCeiling::ScopedVerification;

/// Failures raised while declaring, issuing, or comparing profile receipts.
///
/// Every variant is typed and fail-closed; no stringly-typed catch-all decides
/// whether a local/CI pair may claim parity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VerificationProfileError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A required digest was not a lowercase SHA-256 hex digest.
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A declared environment dependency was declared twice.
    #[error("declared environment dependency '{dependency}' is declared more than once")]
    DuplicateEnvironmentDependency {
        /// Offending dependency name.
        dependency: String,
    },
    /// A declared environment dependency does not hold the admitted profile
    /// environment class.
    #[error(
        "declared environment dependency '{dependency}' expects class '{expected}' but observed '{observed}'"
    )]
    DeclaredEnvironmentMismatch {
        /// Offending dependency name.
        dependency: String,
        /// Class the profile declares.
        expected: String,
        /// Class actually attested.
        observed: String,
    },
    /// The admitted environment or a caller-supplied value failed the existing
    /// profile admission checks.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// A stage in the admitted profile is not represented by an aggregate run,
    /// or an aggregate run names a stage the admitted profile never declares.
    #[error("stage '{stage}' does not correspond to one admitted profile stage")]
    UndeclaredStage {
        /// Offending stage identity.
        stage: String,
    },
    /// A stage run carries no recorded tool identity.
    #[error("stage '{stage}' carries no executable identity digest")]
    MissingExecutableIdentity {
        /// Offending stage identity.
        stage: String,
    },
    /// An external stage carries no digest/provenance receipt.
    #[error(
        "external stage '{stage}' for instrument '{instrument}' carries no supply-chain receipt"
    )]
    MissingProvenanceReceipt {
        /// Offending stage identity.
        stage: String,
        /// Instrument contract the stage executes.
        instrument: String,
    },
    /// A stage's recorded executable identity disagrees with its admitted
    /// supply-chain receipt.
    #[error(
        "stage '{stage}' executable identity does not match its supply-chain receipt: {detail}"
    )]
    ProvenanceMismatch {
        /// Offending stage identity.
        stage: String,
        /// How the identity and receipt differ.
        detail: String,
    },
    /// A PASS receipt records a stage run with no retained evidence.
    #[error("stage '{stage}' has no retained evidence, so the receipt cannot be PASS")]
    PassWithoutRetainedEvidence {
        /// Offending stage identity.
        stage: String,
    },
    /// The receipt claims a proof ceiling other than the pinned family ceiling.
    #[error("receipt proof ceiling is {observed:?}, not the pinned SCOPED_VERIFICATION")]
    ProofCeilingMismatch {
        /// Ceiling the receipt claims.
        observed: ProofCeiling,
    },
    /// The aggregate records a different profile identity than the admitted
    /// profile it is being receipted against.
    #[error(
        "aggregate profile '{observed}' revision {observed_revision} does not match admitted profile '{expected}' revision {expected_revision}"
    )]
    ProfileIdentityMismatch {
        /// Admitted profile name.
        expected: String,
        /// Admitted profile revision.
        expected_revision: u64,
        /// Profile name recorded by the aggregate.
        observed: String,
        /// Profile revision recorded by the aggregate.
        observed_revision: u64,
    },
    /// The shared receipt contract rejected the issued envelope.
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    /// A contract identity value was rejected.
    #[error(transparent)]
    Contract(#[from] eliot_contracts::ContractError),
}

/// Validates one required text value.
fn validate_text(value: &str, field: &'static str) -> Result<(), VerificationProfileError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(VerificationProfileError::InvalidText { field });
    }
    Ok(())
}

/// Validates one required lowercase SHA-256 hex digest.
fn validate_digest(value: &str, field: &'static str) -> Result<(), VerificationProfileError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VerificationProfileError::InvalidDigest { field });
    }
    Ok(())
}

/// One declared environment difference a profile depends on (I18.21).
///
/// I18.21 requires "CI-specific environment differences are explicit profile
/// dependencies". A difference is therefore declared here, bound to the
/// attested [`StageEnvironment`] it names, and checked against the profile's
/// admitted environment class — never sniffed from ambient CI variables. The
/// caller attests the environment; this module compares.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEnvironmentDependency {
    /// Stable dependency name, such as the concrete CI environment label.
    pub name: String,
    /// Environment class the profile admits.
    pub expected_class: String,
    /// Environment class actually attested for this run.
    pub observed_class: String,
    /// Digest of the attested environment material.
    pub environment_digest: String,
}

impl DeclaredEnvironmentDependency {
    /// Records one declared dependency, validating every field.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationProfileError::InvalidText`] when the name or the
    /// expected class is blank or carries control characters, and
    /// [`VerificationProfileError::InvalidDigest`] when the attested
    /// environment digest is not a lowercase SHA-256 hex digest.
    pub fn new(
        name: String,
        expected_class: String,
        attested: &StageEnvironment,
    ) -> Result<Self, VerificationProfileError> {
        validate_text(&name, "environment_dependency_name")?;
        validate_text(&expected_class, "environment_dependency_class")?;
        validate_digest(&attested.digest, "environment_dependency_digest")?;
        Ok(Self {
            name,
            expected_class,
            observed_class: attested.class.clone(),
            environment_digest: attested.digest.clone(),
        })
    }

    /// Deterministic identity over the declared dependency.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}",
            self.name, self.expected_class, self.observed_class, self.environment_digest,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Checks declared environment dependencies against the admitted profile
/// classes.
///
/// A dependency whose attested class differs from the profile's admitted
/// environment class fails closed with the same typed
/// [`ProfileError::EnvironmentMismatch`] the profile resolver already raises,
/// so a CI-only environment difference can never be reported as a run of the
/// shared profile. The admitted `environment` must equal the admitted
/// environment class, and a dependency name may appear only once.
///
/// # Errors
///
/// Returns [`VerificationProfileError::DuplicateEnvironmentDependency`] for a
/// repeated name, [`VerificationProfileError::DeclaredEnvironmentMismatch`]
/// for a dependency that does not hold the admitted class, and the transparent
/// [`VerificationProfileError::Profile`] when the attested environment itself
/// does not hold the admitted class.
pub fn check_declared_environment_dependencies(
    classes: &ProfileScopeClasses,
    admitted: &StageEnvironment,
    dependencies: &[DeclaredEnvironmentDependency],
) -> Result<(), VerificationProfileError> {
    if admitted.class != classes.environment {
        return Err(ProfileError::EnvironmentMismatch {
            profile: classes.environment.clone(),
            expected: classes.environment.clone(),
            observed: admitted.class.clone(),
        }
        .into());
    }
    let mut seen = BTreeSet::new();
    for dependency in dependencies {
        if !seen.insert(dependency.name.as_str()) {
            return Err(VerificationProfileError::DuplicateEnvironmentDependency {
                dependency: dependency.name.clone(),
            });
        }
        if dependency.expected_class != classes.environment
            || dependency.observed_class != classes.environment
        {
            return Err(VerificationProfileError::DeclaredEnvironmentMismatch {
                dependency: dependency.name.clone(),
                expected: classes.environment.clone(),
                observed: dependency.observed_class.clone(),
            });
        }
    }
    Ok(())
}

/// One raw stage run recorded in a profile verification receipt (I18.24).
///
/// The evidence state mirrors [`StageEvidence`] exactly, so the raw evidence
/// a local run retained is the raw evidence the CI receipt records; omission
/// and absence stay explicit and can never become a successful outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRunEvidence {
    /// Durable stage identity.
    pub stage_id: String,
    /// Execution axis class of the run.
    pub execution: String,
    /// Raw evidence state for the stage.
    pub evidence: StageEvidenceRecord,
    /// Machine-derived executable identity digest, when one was recorded.
    pub executable_digest: Option<String>,
    /// Pre-launch admission grant digest, when the stage was admitted.
    pub grant_digest: Option<String>,
}

/// Raw evidence state for one receipt-recorded stage run.
///
/// The retained state carries the same [`RetainedToolIdentity`] the in-memory
/// [`StageEvidence`] carries, so a serialized receipt states which
/// executable, argument vector, environment projection, and exit outcome
/// produced the retained bytes instead of leaving them to be reconstructed
/// later. That is why the receipt schema is versioned forward below: a `1.x`
/// retained record names no tool identity and must be refused rather than read
/// as one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "state")]
pub enum StageEvidenceRecord {
    /// Material output retained under an immutable artifact handle.
    Retained {
        /// Stable handle for the retained bytes.
        artifact: String,
        /// Exact retained byte length.
        byte_len: u64,
        /// Exact tool identity that produced the retained bytes.
        tool: RetainedToolIdentity,
    },
    /// Material output absent for an explicit, typed reason.
    Omitted {
        /// Why the output is absent.
        reason: String,
    },
    /// The stage never produced evidence.
    Missing {
        /// Exact missing proof.
        reason: String,
    },
}

impl From<&StageEvidence> for StageEvidenceRecord {
    fn from(evidence: &StageEvidence) -> Self {
        match evidence {
            StageEvidence::Retained {
                artifact,
                byte_len,
                tool,
            } => Self::Retained {
                artifact: artifact.as_str().to_owned(),
                byte_len: *byte_len,
                tool: tool.clone(),
            },
            StageEvidence::Omitted { reason } => Self::Omitted {
                reason: reason.clone(),
            },
            StageEvidence::Missing { reason } => Self::Missing {
                reason: reason.clone(),
            },
        }
    }
}

impl ProfileRunEvidence {
    /// Deterministic identity over one raw stage run.
    pub fn digest(&self) -> String {
        let evidence = match &self.evidence {
            StageEvidenceRecord::Retained {
                artifact,
                byte_len,
                tool,
            } => {
                format!("retained\0{artifact}\0{byte_len}\0{}", tool.digest())
            }
            StageEvidenceRecord::Omitted { reason } => format!("omitted\0{reason}"),
            StageEvidenceRecord::Missing { reason } => format!("missing\0{reason}"),
        };
        let material = format!(
            "{}\0{}\0{}\0{}\0{}",
            self.stage_id,
            self.execution,
            evidence,
            self.executable_digest.as_deref().unwrap_or(""),
            self.grant_digest.as_deref().unwrap_or(""),
        );
        sha256_hex(material.as_bytes())
    }
}

/// Digest/provenance receipt for one external tool (I18.21).
///
/// I18.21 requires "external binaries require digest/provenance receipt". The
/// pinned executable content digest, admitted tool version, and spec/generation
/// it was verified against are bound here so a receipt states exactly which
/// bytes and which admitted revision the external identity was proven under.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalToolProvenance {
    /// Lowercase SHA-256 hex over the exact executable bytes.
    pub content_digest: String,
    /// Admitted tool version text, when the verification pinned one.
    pub tool_version: Option<String>,
    /// Digest of the admitted spec revision the receipt was verified against.
    pub spec_digest: String,
    /// Registry generation the verification was validated against.
    pub generation: u64,
}

impl From<&SupplyChainReceipt> for ExternalToolProvenance {
    fn from(receipt: &SupplyChainReceipt) -> Self {
        Self {
            content_digest: receipt.content_digest.clone(),
            tool_version: receipt.tool_version.clone(),
            spec_digest: receipt.spec_digest.clone(),
            generation: receipt.generation,
        }
    }
}

/// One external tool identity pinned for a stage of the profile (I18.21).
///
/// I18.21 requires executable/tool identities to be "pinned or recorded". The
/// per-stage executable identity digest and pre-launch grant digest are the
/// recorded form; the admitted [`SupplyChainReceipt`] projected into
/// [`ExternalToolProvenance`] is the pinned form. Both travel in one record so
/// a receipt never reports a tool whose provenance source is unstated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentityRecord {
    /// Durable stage identity this tool ran as.
    pub stage_id: String,
    /// Instrument contract the stage executes.
    pub instrument: String,
    /// Exact admitted executable file identity.
    pub executable: String,
    /// Machine-derived executable identity digest recorded for the run.
    pub executable_digest: Option<String>,
    /// Pre-launch admission grant digest recorded for the run.
    pub grant_digest: Option<String>,
    /// Digest/provenance receipt pinning the external binary, when admitted.
    pub provenance: Option<ExternalToolProvenance>,
}

/// One schema identity of a shared profile verification receipt (I18.21).
///
/// I18.21 requires "results share one schema and evidence model". Both the
/// local and the CI receipt carry the same schema identity, so a schema change
/// is visible as a divergence rather than as two silently different results.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSchemaIdentity {
    /// Stable schema name.
    pub schema: String,
    /// Exact schema wire version.
    pub version: String,
    /// Verifier contract identity the receipt is issued under.
    pub verifier: String,
    /// Verifier revision the receipt is issued under.
    pub verifier_revision: String,
}

/// Stable schema name of the shared profile verification receipt.
pub const RECEIPT_SCHEMA: &str = "eliot.instrument.verification-profile-receipt";
/// Exact schema wire version of the shared profile verification receipt.
///
/// The version is the schema revision, deliberately independent of the
/// `InstrumentProfile::revision` the receipt carries: a profile revision bump
/// does not change the receipt schema, and a schema change is exactly what a
/// local/CI pair must refuse.
///
/// `2.0.0` makes the retained-evidence change wire-breaking on purpose: a
/// `StageEvidenceRecord::Retained` value now carries the required tool identity
/// (executable, argument vector, environment projection digest, exit outcome),
/// so a `1.x` retained record that names no tool identity can no longer be read
/// as a retained run. It is refused rather than upgraded, because inventing the
/// missing identity after the fact is exactly the reconstruction this schema
/// exists to prevent.
pub const RECEIPT_SCHEMA_VERSION: &str = "2.0.0";

/// The one receipt schema shared by local and CI profile runs (I18.21).
///
/// The issue's named fields are present one-to-one:
///
/// * profile revision — [`Self::profile`], [`Self::profile_revision`],
///   [`Self::profile_digest`], [`Self::dag_digest`];
/// * tool/executable identities — [`Self::tool_identities`];
/// * external-tool digest/provenance receipts —
///   [`ToolIdentityRecord::provenance`];
/// * declared environment dependencies — [`Self::environment_dependencies`];
/// * raw evidence — [`Self::runs`];
/// * normalized outcome — [`Self::outcome`];
/// * proof ceiling — [`Self::proof_ceiling`].
///
/// The schema identity ([`Self::schema`]) is additionally recorded because
/// I18.21 requires both results to "share one schema and evidence model".
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationProfileReceipt {
    /// Schema identity both local and CI receipts must share.
    pub schema: ReceiptSchemaIdentity,
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// `InstrumentProfile::digest` of the admitted profile.
    pub profile_digest: String,
    /// Stage DAG digest of the admitted profile.
    pub dag_digest: String,
    /// Aggregate digest over the profile definition and ordered runs.
    pub aggregate_digest: String,
    /// Declared environment dependencies of this run.
    pub environment_dependencies: Vec<DeclaredEnvironmentDependency>,
    /// Tool/executable identities with their provenance receipts.
    pub tool_identities: Vec<ToolIdentityRecord>,
    /// Raw stage evidence, in plan order.
    pub runs: Vec<ProfileRunEvidence>,
    /// Normalized outcome of the aggregate; never a task-finish decision.
    pub outcome: AggregateOutcome,
    /// Strongest proof interpretation this receipt may carry.
    pub proof_ceiling: ProofCeiling,
}

impl VerificationProfileReceipt {
    /// The shared receipt schema identity every profile receipt carries.
    #[must_use]
    pub fn schema_identity() -> ReceiptSchemaIdentity {
        ReceiptSchemaIdentity {
            schema: RECEIPT_SCHEMA.to_owned(),
            version: RECEIPT_SCHEMA_VERSION.to_owned(),
            verifier: VERIFICATION_PROFILE_VERIFIER.to_owned(),
            verifier_revision: format!(
                "{}.{}.{}",
                VERIFICATION_PROFILE_VERIFIER_REVISION.major,
                VERIFICATION_PROFILE_VERIFIER_REVISION.minor,
                VERIFICATION_PROFILE_VERIFIER_REVISION.patch,
            ),
        }
    }

    /// Validates the receipt's internal consistency before issuance or parity.
    ///
    /// A deserialized receipt bypassed every check in
    /// [`build_verification_profile_receipt`], so both issuance and parity
    /// must run this gate first. The proof ceiling is pinned to
    /// [`PROFILE_PROOF_CEILING`], and a PASS outcome additionally requires
    /// every recorded run to carry retained evidence plus a recorded tool
    /// identity — omission and absence stay explicit and can never become a
    /// successful outcome.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationProfileError::ProofCeilingMismatch`] when the
    /// receipt claims any other ceiling,
    /// [`VerificationProfileError::PassWithoutRetainedEvidence`] when a PASS
    /// receipt records a run with no retained evidence, and
    /// [`VerificationProfileError::MissingExecutableIdentity`] when a PASS
    /// receipt records a run with no tool identity.
    pub fn validate(&self) -> Result<(), VerificationProfileError> {
        if self.proof_ceiling != PROFILE_PROOF_CEILING {
            return Err(VerificationProfileError::ProofCeilingMismatch {
                observed: self.proof_ceiling,
            });
        }
        if !self.outcome.is_pass() {
            return Ok(());
        }
        for run in &self.runs {
            if !matches!(run.evidence, StageEvidenceRecord::Retained { .. }) {
                return Err(VerificationProfileError::PassWithoutRetainedEvidence {
                    stage: run.stage_id.clone(),
                });
            }
            let identified = run.executable_digest.is_some()
                && self.tool_identities.iter().any(|identity| {
                    identity.stage_id == run.stage_id && identity.executable_digest.is_some()
                });
            if !identified {
                return Err(VerificationProfileError::MissingExecutableIdentity {
                    stage: run.stage_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Deterministic identity over the shared receipt schema.
    ///
    /// The digest covers the schema identity and the profile revision
    /// identity (`profile`, `profile_revision`, `profile_digest`,
    /// `dag_digest`), which is exactly what I18.21's "local profile revision ==
    /// CI profile revision" compares. A changed profile revision changes this
    /// digest, so a divergent pair cannot claim parity.
    pub fn revision_digest(&self) -> String {
        let mut material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.schema.schema,
            self.schema.version,
            self.schema.verifier,
            self.schema.verifier_revision,
            self.profile,
            self.profile_revision,
            self.profile_digest,
            self.dag_digest,
            self.aggregate_digest,
            self.outcome_code(),
            self.proof_ceiling_code(),
            self.environment_dependencies
                .iter()
                .map(DeclaredEnvironmentDependency::digest)
                .collect::<Vec<_>>()
                .join(","),
            self.tool_identities
                .iter()
                .map(|identity| {
                    let provenance = identity.provenance.as_ref().map_or_else(
                        || "\0\0\0".to_owned(),
                        |provenance| {
                            format!(
                                "{}\0{}\0{}\0{}",
                                provenance.content_digest,
                                provenance.tool_version.as_deref().unwrap_or(""),
                                provenance.spec_digest,
                                provenance.generation,
                            )
                        },
                    );
                    format!(
                        "{}\0{}\0{}\0{}\0{}\0{provenance}",
                        identity.stage_id,
                        identity.instrument,
                        identity.executable,
                        identity.executable_digest.as_deref().unwrap_or(""),
                        identity.grant_digest.as_deref().unwrap_or(""),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
            self.runs
                .iter()
                .map(ProfileRunEvidence::digest)
                .collect::<Vec<_>>()
                .join(","),
        );
        material.push('\0');
        sha256_hex(material.as_bytes())
    }

    /// Stable wire code of the normalized outcome.
    const fn outcome_code(&self) -> &'static str {
        match self.outcome {
            AggregateOutcome::Pass => "PASS",
            AggregateOutcome::Partial => "PARTIAL",
            AggregateOutcome::Fail => "FAIL",
            AggregateOutcome::MissingRequired => "MISSING_REQUIRED",
            AggregateOutcome::Unknown => "UNKNOWN",
        }
    }

    /// Stable wire code of the recorded proof ceiling.
    const fn proof_ceiling_code(&self) -> &'static str {
        match self.proof_ceiling {
            ProofCeiling::Observation => "OBSERVATION",
            ProofCeiling::CandidateArtifact => "CANDIDATE_ARTIFACT",
            ProofCeiling::ScopedVerification => "SCOPED_VERIFICATION",
            ProofCeiling::ObservedExternalEffect => "OBSERVED_EXTERNAL_EFFECT",
        }
    }
}

/// Normalized aggregate outcome of one profile run (I18.24).
///
/// The mapping preserves I18.24's non-binary outcomes: only
/// [`AggregateStatus::Succeeded`] becomes [`AggregateOutcome::Pass`]. Every
/// other normalized outcome stays non-PASS, so aggregation can never promote a
/// partial, unknown, blocked, or cancelled run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregateOutcome {
    /// Every required stage succeeded; no optional stage failed.
    Pass,
    /// Every required stage succeeded; an optional stage did not.
    Partial,
    /// A required stage failed, was cancelled, or was blocked.
    Fail,
    /// A required stage has no evidence.
    MissingRequired,
    /// A required stage has not reached a terminal successful state.
    Unknown,
}

impl From<AggregateStatus> for AggregateOutcome {
    fn from(status: AggregateStatus) -> Self {
        match status {
            AggregateStatus::Succeeded => Self::Pass,
            AggregateStatus::PartialFailure => Self::Partial,
            AggregateStatus::Failed => Self::Fail,
            AggregateStatus::MissingRequired => Self::MissingRequired,
            AggregateStatus::Unknown => Self::Unknown,
        }
    }
}

impl AggregateOutcome {
    /// Whether this outcome may be reported as PASS (I18.24).
    ///
    /// Only [`AggregateOutcome::Pass`] is PASS; every other normalized outcome
    /// stays non-PASS so aggregation can never promote a partial, unknown,
    /// blocked, or cancelled run.
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Refuses a profile whose required identity or provenance data is absent
/// (I18.21).
///
/// I18.21 requires "executable/tool identities are pinned or recorded" and
/// "external binaries require digest/provenance receipt". Every stage the
/// admitted profile declares must be represented by exactly one aggregate run,
/// every represented stage must carry a recorded executable identity, and
/// every external stage must additionally carry its admitted
/// [`SupplyChainReceipt`] whose pinned content digest equals the recorded
/// identity. A missing identity, a missing receipt, a stage the aggregate never
/// ran, or a run for an undeclared stage all fail closed before any receipt is
/// issued.
///
/// # Errors
///
/// Returns [`VerificationProfileError::ProfileIdentityMismatch`] when the
/// aggregate does not name the admitted profile revision,
/// [`VerificationProfileError::UndeclaredStage`] for a plan/run divergence,
/// [`VerificationProfileError::MissingExecutableIdentity`] when a run carries
/// no tool identity, [`VerificationProfileError::MissingProvenanceReceipt`]
/// when an external stage carries no receipt, and
/// [`VerificationProfileError::ProvenanceMismatch`] when the recorded
/// identity disagrees with the admitted receipt.
pub fn require_provenance(
    admitted: &AdmittedProfile,
    aggregate: &ProfileAggregate,
) -> Result<Vec<ToolIdentityRecord>, VerificationProfileError> {
    if aggregate.profile != admitted.name || aggregate.revision != admitted.revision {
        return Err(VerificationProfileError::ProfileIdentityMismatch {
            expected: admitted.name.clone(),
            expected_revision: admitted.revision,
            observed: aggregate.profile.clone(),
            observed_revision: aggregate.revision,
        });
    }
    let mut identities = Vec::with_capacity(admitted.stages.len());
    for stage in &admitted.stages {
        let run = aggregate
            .runs
            .iter()
            .find(|run| run.stage.stage_id == stage.stage_id)
            .ok_or_else(|| VerificationProfileError::UndeclaredStage {
                stage: stage.stage_id.clone(),
            })?;
        let Some(executable_digest) = run.executable_digest.as_deref() else {
            return Err(VerificationProfileError::MissingExecutableIdentity {
                stage: stage.stage_id.clone(),
            });
        };
        validate_digest(executable_digest, "executable_identity_digest")?;
        if let Some(grant_digest) = run.grant_digest.as_deref() {
            validate_digest(grant_digest, "grant_digest")?;
        }
        let provenance = match stage.supply_receipt.as_ref() {
            Some(receipt) => {
                if receipt.content_digest != executable_digest {
                    return Err(VerificationProfileError::ProvenanceMismatch {
                        stage: stage.stage_id.clone(),
                        detail: format!(
                            "receipt pins '{}', run recorded '{executable_digest}'",
                            receipt.content_digest
                        ),
                    });
                }
                Some(ExternalToolProvenance::from(receipt))
            }
            None if stage.external => {
                return Err(VerificationProfileError::MissingProvenanceReceipt {
                    stage: stage.stage_id.clone(),
                    instrument: stage.spec.as_str().to_owned(),
                });
            }
            None => None,
        };
        identities.push(ToolIdentityRecord {
            stage_id: stage.stage_id.clone(),
            instrument: stage.spec.as_str().to_owned(),
            executable: stage.executable.clone(),
            executable_digest: Some(executable_digest.to_owned()),
            grant_digest: run.grant_digest.clone(),
            provenance,
        });
    }
    if let Some(run) = aggregate.runs.iter().find(|run| {
        !admitted
            .stages
            .iter()
            .any(|stage| stage.stage_id == run.stage.stage_id)
    }) {
        return Err(VerificationProfileError::UndeclaredStage {
            stage: run.stage.stage_id.clone(),
        });
    }
    Ok(identities)
}

/// Caller-admitted governance bindings the shared receipt envelope requires.
///
/// The envelope's `request`/`work_scope`/`causal`/`authority` bindings are
/// governance facts owned by the composition root; this module never invents a
/// State Fence, an authority, or a request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBindings {
    /// Request metadata the run was issued under.
    pub request: RequestMetadata,
    /// Stable `WorkScope` identity for the run.
    pub work_scope_id: WorkScopeId,
    /// Product identity bound to the request.
    pub product_id: ProductId,
    /// Authority contract identity that admitted the run.
    pub authority_id: ContractId,
    /// Owner of that authority.
    pub authority_owner: String,
    /// Causal transaction sequence for the run.
    pub transaction_sequence: TransactionSequence,
    /// Idempotency identity of the run.
    pub idempotency_key: String,
    /// Exact operation identity of the run.
    pub operation_id: String,
}

impl ReceiptBindings {
    /// Validates the caller-admitted bindings, rejecting unusable text.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationProfileError::InvalidText`] when the authority
    /// owner, operation identity, or idempotency key is blank or carries
    /// control characters, and the transparent
    /// [`VerificationProfileError::Contract`] when the request metadata itself
    /// fails contract validation.
    pub fn validated(&self) -> Result<(), VerificationProfileError> {
        validate_text(&self.authority_owner, "authority_owner")?;
        validate_text(&self.idempotency_key, "idempotency_key")?;
        validate_text(&self.operation_id, "operation_id")?;
        self.request.validate()?;
        Ok(())
    }
}

/// Binds one shared profile verification receipt into a
/// [`ReceiptEnvelope`] of kind [`ReceiptKind::Verification`].
///
/// Every one of the issue's named fields is already present in `receipt`; this
/// function issues the store-neutral envelope the shared contract defines and
/// never persists it, never decides task completion, and never exceeds
/// [`Self::proof_ceiling`]. The admitted profile identity travels in
/// `verifier_id` and `source_revision`, and the raw stage evidence travels as
/// one `ArtifactBinding` per stage whose `sha256` is that stage's canonical
/// evidence digest, so the envelope's canonical bytes bind the whole run.
///
/// # Errors
///
/// Returns the transparent [`VerificationProfileError::Receipt`] when a
/// binding, fence, disposition, or canonical serialization is invalid,
/// [`VerificationProfileError::Contract`] when a derived identity value is
/// rejected, and the [`VerificationProfileReceipt::validate`] failures
/// ([`VerificationProfileError::ProofCeilingMismatch`],
/// [`VerificationProfileError::PassWithoutRetainedEvidence`],
/// [`VerificationProfileError::MissingExecutableIdentity`]) when the receipt
/// itself is internally inconsistent.
pub fn issue_receipt_envelope(
    receipt: &VerificationProfileReceipt,
    bindings: &ReceiptBindings,
) -> Result<ReceiptEnvelope, VerificationProfileError> {
    bindings.validated()?;
    receipt.validate()?;
    validate_digest(&receipt.profile_digest, "profile_digest")?;
    validate_digest(&receipt.dag_digest, "dag_digest")?;
    validate_digest(&receipt.aggregate_digest, "aggregate_digest")?;

    let mut artifacts = Vec::with_capacity(receipt.runs.len());
    for run in &receipt.runs {
        artifacts.push(ArtifactBinding {
            artifact_id: ArtifactId::new(format!(
                "profile-evidence-{}-{}-{}",
                receipt.profile, receipt.profile_revision, run.stage_id
            ))?,
            sha256: run.digest(),
            role: ReceiptKind::Verification,
            source_revision: Some(receipt.profile_revision.to_string()),
        });
    }
    let verifier_artifact_ids = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<Vec<_>>();

    let state_fence = bindings.request.state_fence.clone();
    let core = ReceiptCore {
        contract: contract_identity()?,
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: bindings.work_scope_id.clone(),
            product_id: bindings.product_id.clone(),
            resource_generation: state_fence.resource_generation,
            state_fence: state_fence.clone(),
        },
        task: None,
        session: None,
        causal: CausalBinding {
            state_fence: state_fence.clone(),
            transaction_sequence: bindings.transaction_sequence,
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata: bindings.request.clone(),
            state_fence: state_fence.clone(),
        },
        operation: OperationBinding {
            operation_id: OperationId::new(bindings.operation_id.clone())?,
            request_id: bindings.request.request_id.clone(),
            idempotency_key: bindings.idempotency_key.clone(),
            operation_kind: VERIFICATION_OPERATION_KIND.to_owned(),
            effect: EffectClass::Read,
            state_fence: state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: bindings.authority_id.clone(),
            authority_owner: bindings.authority_owner.clone(),
            authority_epoch: state_fence.authority_epoch.clone(),
            state_fence: state_fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: receipt.proof_ceiling,
        },
        artifacts,
        verifier: verifier_binding(receipt, &verifier_artifact_ids, state_fence.clone())?,
        problem: None,
        coordination: None,
        disposition: disposition_for(receipt)?,
    };
    Ok(ReceiptEnvelope::issue(core)?)
}

/// Builds the verifier binding that names the exact admitted profile revision.
///
/// The binding is absent only when the receipt records no stage evidence at
/// all; the shared contract then requires no verifier reference rather than an
/// empty one. Every issued profile receipt names its profile and revision, so
/// a local/CI pair compares under one verifier identity.
fn verifier_binding(
    receipt: &VerificationProfileReceipt,
    artifact_ids: &[ArtifactId],
    state_fence: StateFence,
) -> Result<Option<VerifierBinding>, VerificationProfileError> {
    if artifact_ids.is_empty() {
        return Ok(None);
    }
    Ok(Some(VerifierBinding {
        verifier_id: ContractId::new(format!(
            "{VERIFICATION_PROFILE_VERIFIER}/{}@{}",
            receipt.profile, receipt.profile_revision
        ))?,
        verifier_revision: VERIFICATION_PROFILE_VERIFIER_REVISION,
        artifact_ids: artifact_ids.to_vec(),
        proof_ceiling: receipt.proof_ceiling,
        state_fence,
    }))
}

/// Maps the normalized outcome onto the shared receipt disposition (I18.24).
///
/// Only a `PASS` aggregate may become `Success`; every other normalized
/// outcome becomes a non-PASS disposition, so `PARTIAL`, `UNKNOWN`,
/// `MISSING_REQUIRED`, and `FAIL` never become PASS through this mapping. A
/// partial aggregate that retains no unresolved item is reported as `Unknown`
/// rather than being rounded up to a success. A `PASS` aggregate that records
/// a run with no retained evidence is refused instead of becoming `Success`,
/// so a deserialized receipt can never smuggle absence into a success.
///
/// # Errors
///
/// Returns [`VerificationProfileError::PassWithoutRetainedEvidence`] when a
/// `PASS` receipt records a run with no retained evidence.
fn disposition_for(
    receipt: &VerificationProfileReceipt,
) -> Result<ReceiptDisposition, VerificationProfileError> {
    let proof = receipt.proof_ceiling;
    let unretained = receipt
        .runs
        .iter()
        .filter(|run| !matches!(run.evidence, StageEvidenceRecord::Retained { .. }))
        .collect::<Vec<_>>();
    let unresolved = unretained
        .iter()
        .map(|run| format!("stage '{}' has no retained evidence", run.stage_id))
        .collect::<Vec<_>>();
    match receipt.outcome {
        AggregateOutcome::Pass if unresolved.is_empty() => {
            Ok(ReceiptDisposition::Success { proof })
        }
        AggregateOutcome::Pass => Err(VerificationProfileError::PassWithoutRetainedEvidence {
            stage: unretained
                .first()
                .map_or_else(|| "unknown".to_owned(), |run| run.stage_id.clone()),
        }),
        AggregateOutcome::Partial if unresolved.is_empty() => Ok(ReceiptDisposition::Unknown {
            reason: "an optional stage did not succeed; no required coverage is missing".to_owned(),
        }),
        AggregateOutcome::Partial => Ok(ReceiptDisposition::Partial { proof, unresolved }),
        AggregateOutcome::Fail => Ok(ReceiptDisposition::Failure {
            code: eliot_receipts::ErrorCode::InvalidIdentity,
            proof,
        }),
        AggregateOutcome::MissingRequired => Ok(ReceiptDisposition::Failure {
            code: eliot_receipts::ErrorCode::NotFound,
            proof,
        }),
        AggregateOutcome::Unknown => Ok(ReceiptDisposition::Unknown {
            reason: "a required stage has not reached a terminal successful state".to_owned(),
        }),
    }
}

/// Builds the shared receipt for one profile run (I18.21).
///
/// The same function serves every entrypoint: the local route and the CI route
/// both compile through [`crate::profile::ProfileCompiler`] and then call this,
/// so one schema records both results. I18.21's "The minimal bootstrap build is
/// the only unavoidable pre-run exception" is honored by taking the already
/// compiled and admitted profile as input: this function performs no build, no
/// command selection, and no environment sniffing.
///
/// # Errors
///
/// Returns [`VerificationProfileError::ProfileIdentityMismatch`],
/// [`VerificationProfileError::UndeclaredStage`],
/// [`VerificationProfileError::MissingExecutableIdentity`],
/// [`VerificationProfileError::MissingProvenanceReceipt`], and
/// [`VerificationProfileError::ProvenanceMismatch`] from
/// [`require_provenance`], the transparent
/// [`VerificationProfileError::Profile`] when a declared environment
/// dependency does not hold the admitted class, and
/// [`VerificationProfileError::InvalidDigest`] when a recorded identity is
/// malformed.
pub fn build_verification_profile_receipt(
    admitted: &AdmittedProfile,
    classes: &ProfileScopeClasses,
    aggregate: &ProfileAggregate,
    admitted_environment: &StageEnvironment,
    environment_dependencies: &[DeclaredEnvironmentDependency],
) -> Result<VerificationProfileReceipt, VerificationProfileError> {
    check_declared_environment_dependencies(
        classes,
        admitted_environment,
        environment_dependencies,
    )?;
    let tool_identities = require_provenance(admitted, aggregate)?;
    let runs = aggregate
        .runs
        .iter()
        .map(|run| ProfileRunEvidence {
            stage_id: run.stage.stage_id.clone(),
            execution: format!("{:?}", run.execution),
            evidence: StageEvidenceRecord::from(&run.evidence),
            executable_digest: run.executable_digest.clone(),
            grant_digest: run.grant_digest.clone(),
        })
        .collect::<Vec<_>>();
    Ok(VerificationProfileReceipt {
        schema: VerificationProfileReceipt::schema_identity(),
        profile: admitted.name.clone(),
        profile_revision: admitted.revision,
        profile_digest: admitted.profile_digest.clone(),
        dag_digest: admitted.dag_digest.clone(),
        aggregate_digest: aggregate.aggregate_digest.clone(),
        environment_dependencies: environment_dependencies.to_vec(),
        tool_identities,
        runs,
        outcome: AggregateOutcome::from(aggregate.status),
        proof_ceiling: PROFILE_PROOF_CEILING,
    })
}

/// One typed local/CI parity outcome (I18.21).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParityVerdict {
    /// The two receipts share one profile revision and one receipt schema.
    Pass {
        /// Shared profile revision identity digest.
        revision_digest: String,
    },
    /// The two receipts diverged and parity is refused.
    NonPass {
        /// Exact divergence that refuses parity.
        reason: String,
    },
}

impl ParityVerdict {
    /// Whether this verdict may be reported as parity PASS.
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}

/// Verifies that one local receipt and one CI receipt report the same profile
/// revision under one receipt schema (I18.21).
///
/// I18.21's "local profile revision == CI profile revision" is checked as
/// `profile` + `profile_revision` + `profile_digest` + `dag_digest` equality
/// over the existing `InstrumentProfile::digest`, and "results share one schema
/// and evidence model" is checked as `ReceiptSchemaIdentity` equality. The
/// check also refuses an undeclared verifier command: a CI tool identity for a
/// stage the local receipt does not record is a non-PASS, never a silent pass.
///
/// This is the whole of the issue's parity surface that is reachable without
/// editing the CI workflow or the legacy engine profiles: those alias sites
/// are the next slice and are not owned by this change.
///
/// # Errors
///
/// Returns [`VerificationProfileError::InvalidDigest`] when a recorded
/// profile or stage-graph identity is malformed, and the
/// [`VerificationProfileReceipt::validate`] failures
/// ([`VerificationProfileError::ProofCeilingMismatch`],
/// [`VerificationProfileError::PassWithoutRetainedEvidence`],
/// [`VerificationProfileError::MissingExecutableIdentity`]) when either
/// receipt is internally inconsistent. Every divergence is reported
/// as [`ParityVerdict::NonPass`] rather than raised, so a caller records the
/// non-PASS outcome instead of losing the run.
pub fn verify_profile_parity(
    local: &VerificationProfileReceipt,
    ci: &VerificationProfileReceipt,
) -> Result<ParityVerdict, VerificationProfileError> {
    local.validate()?;
    ci.validate()?;
    for receipt in [local, ci] {
        validate_digest(&receipt.profile_digest, "profile_digest")?;
        validate_digest(&receipt.dag_digest, "dag_digest")?;
    }
    if local.schema != ci.schema {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "receipt schema '{}@{}' does not match '{}@{}'",
                local.schema.schema, local.schema.version, ci.schema.schema, ci.schema.version
            ),
        });
    }
    if local.profile != ci.profile {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "local profile '{}' does not match CI profile '{}'",
                local.profile, ci.profile
            ),
        });
    }
    if local.profile_revision != ci.profile_revision {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "local profile revision {} does not match CI profile revision {}",
                local.profile_revision, ci.profile_revision
            ),
        });
    }
    if local.profile_digest != ci.profile_digest {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "local profile digest '{}' does not match CI profile digest '{}'",
                local.profile_digest, ci.profile_digest
            ),
        });
    }
    if local.dag_digest != ci.dag_digest {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "local stage graph digest '{}' does not match CI stage graph digest '{}'",
                local.dag_digest, ci.dag_digest
            ),
        });
    }
    for dependency in &local.environment_dependencies {
        if !ci
            .environment_dependencies
            .iter()
            .any(|other| other.digest() == dependency.digest())
        {
            return Ok(ParityVerdict::NonPass {
                reason: format!(
                    "CI receipt does not declare local environment dependency '{}'",
                    dependency.name
                ),
            });
        }
    }
    for dependency in &ci.environment_dependencies {
        if !local
            .environment_dependencies
            .iter()
            .any(|other| other.digest() == dependency.digest())
        {
            return Ok(ParityVerdict::NonPass {
                reason: format!(
                    "local receipt does not declare CI environment dependency '{}'",
                    dependency.name
                ),
            });
        }
    }
    if let Some(reason) = tool_identity_divergence(local, ci) {
        return Ok(ParityVerdict::NonPass { reason });
    }
    if local.aggregate_digest != ci.aggregate_digest {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "local aggregate digest '{}' does not match CI aggregate digest '{}'",
                local.aggregate_digest, ci.aggregate_digest
            ),
        });
    }
    if !local.outcome.is_pass() || !ci.outcome.is_pass() {
        return Ok(ParityVerdict::NonPass {
            reason: format!(
                "normalized outcome is local={} ci={}; a non-PASS outcome is never parity PASS",
                local.outcome_code(),
                ci.outcome_code()
            ),
        });
    }
    Ok(ParityVerdict::Pass {
        revision_digest: local.revision_digest(),
    })
}

/// Returns the exact tool-identity divergence between one local and one CI
/// receipt, or `None` when the two record identical tool identities.
///
/// A CI tool identity for a stage the local receipt does not record is the
/// undeclared verifier command I18.21 forbids; a stage recorded on only one
/// side is likewise missing identity or provenance data, and both are
/// divergences rather than a silent pass.
fn tool_identity_divergence(
    local: &VerificationProfileReceipt,
    ci: &VerificationProfileReceipt,
) -> Option<String> {
    for identity in &local.tool_identities {
        let Some(other) = ci
            .tool_identities
            .iter()
            .find(|other| other.stage_id == identity.stage_id)
        else {
            return Some(format!(
                "CI receipt records no tool identity for stage '{}'",
                identity.stage_id
            ));
        };
        if other.instrument != identity.instrument || other.executable != identity.executable {
            return Some(format!(
                "stage '{}' runs '{}/{}' locally and '{}/{}' in CI",
                identity.stage_id,
                identity.instrument,
                identity.executable,
                other.instrument,
                other.executable
            ));
        }
        if other.executable_digest != identity.executable_digest {
            return Some(format!(
                "stage '{0}' executable identity differs between local and CI; identity or provenance data is absent on one side",
                identity.stage_id
            ));
        }
        if other.grant_digest != identity.grant_digest {
            return Some(format!(
                "stage '{0}' admission grant digest differs between local and CI",
                identity.stage_id
            ));
        }
        if other.provenance != identity.provenance {
            return Some(format!(
                "stage '{0}' external-tool provenance receipt differs between local and CI",
                identity.stage_id
            ));
        }
    }
    ci.tool_identities
        .iter()
        .find(|identity| {
            !local
                .tool_identities
                .iter()
                .any(|other| other.stage_id == identity.stage_id)
        })
        .map(|identity| {
            format!(
                "CI receipt invokes undeclared verifier command '{}' for stage '{}'",
                identity.executable, identity.stage_id
            )
        })
}

/// Renders one stable, human-readable parity summary line.
///
/// The summary records the verdict only; it never becomes authority.
#[must_use]
pub fn parity_summary(verdict: &ParityVerdict) -> String {
    match verdict {
        ParityVerdict::Pass { revision_digest } => {
            let mut line = String::from("PARITY_PASS profile_revision_digest=");
            let _ = write!(line, "{revision_digest}");
            line
        }
        ParityVerdict::NonPass { reason } => {
            let mut line = String::from("PARITY_NON_PASS reason=");
            let _ = write!(line, "{reason}");
            line
        }
    }
}
