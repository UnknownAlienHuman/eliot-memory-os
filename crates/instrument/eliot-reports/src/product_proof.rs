//! The product-proof status record at the ProductProof/FinishService
//! acceptance-owner boundary (issue #1903).
//!
//! I0.13 pins current product status at `NOT_ACCEPTED / UNVERIFIED` because
//! the live Windows installation has never run. That label is informative but
//! it does not say *why* the required proof is absent, so it cannot drive a
//! correct escalation. This module records that fact exactly:
//!
//! * one terminal I18.24 [`VerificationOutcome`] with its factual reason, the
//!   owner/authority that imposed the stop, and the required evidence that is
//!   still missing;
//! * build evidence as a separate, typed [`ProductProofBuildEvidence`] handle
//!   that carries no live-product outcome at all, so a successful release build
//!   can be linked as non-product proof and can never be read as live `PASS`;
//! * the I18.22 failure class of a Windows run attempt that did not complete,
//!   kept on the separate [`ExecutionStatus`] lifecycle axis so a launch failure
//!   is never conflated with a block;
//! * the retained raw logs, executable identity, environment identity, and the
//!   observed-or-missing stage receipts.
//!
//! The pass rule is structural, not advisory: [`ProductProofStatus::rollup`]
//! returns [`ProductProofRollup::Refused`], naming the missing installed-route
//! stage, whenever the outcome is not an I18.24 `PASS` or the required
//! installed-route execution was not actually observed. I18.24's
//! "`UNKNOWN`, `PARTIAL` and `BLOCKED` never become PASS through aggregation"
//! is therefore a return path in code, not a comment.
//!
//! The record reuses [`VerificationOutcome`] and [`ExecutionStatus`] from
//! `eliot-instrument-api` rather than declaring a fourth outcome vocabulary, and
//! it never widens the closed single-variant [`ProductSupportState`] support
//! projection: this record adds a status beside it, not a promotable state
//! inside it.

use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::projection::ReportInputRevision;
use crate::{ReportError, valid_text};

/// Stable identity of the product-proof status contract.
pub const PRODUCT_PROOF_CONTRACT: &str = "eliot.instrument.reports.product-proof/v1";

/// The I18.22 failure class of one incomplete verification attempt.
///
/// These are the seven distinctions I18.22 requires a failure report to keep
/// apart. A class is *why* a run did not complete; it is a different question
/// from the I18.24 semantic outcome, and the two are never collapsed into one
/// enum here. The lifecycle position itself (for example whether the process
/// was blocked before launch or failed during it) stays on
/// [`ExecutionStatus`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductProofFailureClass {
    /// The candidate did not build.
    Build,
    /// The admitted executable could not be started.
    Launch,
    /// The run completed and a declared property was contradicted.
    Assertion,
    /// The run exceeded its timeout or hung.
    TimeoutHang,
    /// Infrastructure or a resource limit prevented the run.
    InfrastructureResource,
    /// The output could not be parsed into evidence.
    ParserEvidence,
    /// The outcome differs across repeated attempts.
    Intermittent,
}

/// Which evidence axis a retained proof handle belongs to.
///
/// I0.5 keeps source, build, runtime, store and integration evidence on
/// separate domains, and its rule that "source-only evidence stays
/// `CURRENT_UNVERIFIED` at most" is why a build handle cannot stand in for a
/// runtime one. Only [`ProductProofEvidenceDomain::Runtime`] can support a live
/// product outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductProofEvidenceDomain {
    /// Compile/build evidence for the exact candidate.
    Build,
    /// Live execution of the installed route.
    Runtime,
}

/// One retained evidence handle, on exactly one I0.5 domain.
///
/// A build handle and a runtime handle are different types of value, so a
/// successful build cannot be substituted for a live run anywhere downstream:
/// the rollup rule reads the domain, not the prose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofEvidence {
    /// Evidence domain this handle belongs to.
    pub domain: ProductProofEvidenceDomain,
    /// Stable identity of the exact evidence.
    pub evidence_id: String,
    /// What the evidence actually observed, in one factual clause.
    pub description: String,
    /// Canonical source revision this handle was read from.
    pub observed_by: ReportInputRevision,
}

impl ProductProofEvidence {
    /// Binds one retained evidence handle to its domain and source.
    pub fn new(
        domain: ProductProofEvidenceDomain,
        evidence_id: impl Into<String>,
        description: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, ProductProofError> {
        let handle = Self {
            domain,
            evidence_id: evidence_id.into(),
            description: description.into(),
            observed_by,
        };
        handle.validate()?;
        Ok(handle)
    }

    /// Whether this handle can support a live-product outcome.
    #[must_use]
    pub const fn is_live_product(&self) -> bool {
        matches!(self.domain, ProductProofEvidenceDomain::Runtime)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        valid_text(&self.evidence_id, "product_proof.evidence.evidence_id")
            .map_err(ProductProofError::Report)?;
        valid_text(&self.description, "product_proof.evidence.description")
            .map_err(ProductProofError::Report)?;
        self.observed_by
            .validate()
            .map_err(ProductProofError::Report)
    }
}

/// The successful release build, recorded as build evidence only.
///
/// This type has no outcome field and no path to one. It exists so the
/// nine-binary release build can be linked from a product-proof record as
/// non-product proof while remaining structurally incapable of being read as a
/// live-product `PASS`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofBuildEvidence {
    /// Identity of the build evidence the record links.
    pub evidence: ProductProofEvidence,
    /// Binaries the exact build produced, in canonical order.
    pub binary_names: Vec<String>,
}

impl ProductProofBuildEvidence {
    /// Binds one release build to its retained handle and produced binaries.
    pub fn new(
        evidence: ProductProofEvidence,
        mut binary_names: Vec<String>,
    ) -> Result<Self, ProductProofError> {
        if evidence.domain != ProductProofEvidenceDomain::Build {
            return Err(ProductProofError::BuildEvidenceWrongDomain {
                evidence_id: evidence.evidence_id.clone(),
            });
        }
        if binary_names.is_empty() {
            return Err(ProductProofError::EmptyField {
                field: "product_proof.build_evidence.binary_names",
            });
        }
        binary_names.sort();
        let build = Self {
            evidence,
            binary_names,
        };
        build.validate()?;
        Ok(build)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        self.evidence.validate()?;
        for name in &self.binary_names {
            valid_text(name, "product_proof.build_evidence.binary_name")
                .map_err(ProductProofError::Report)?;
        }
        Ok(())
    }
}

/// What a run attempt did and did not execute.
///
/// Each required stage is either observed with its receipt, or explicitly
/// missing. An absent receipt is therefore a recorded fact, never a silent
/// success: I18.24's "a required stage that is missing" reads here as an
/// explicit entry rather than an omission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofStageReceipts {
    /// The installed-route execution required for a live-product outcome.
    pub installed_route: ProductProofStageReceipt,
}

/// The observed-or-missing state of one required stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ProductProofStageReceipt {
    /// The stage ran and its receipt is retained.
    Observed {
        /// Stable identity of the retained stage receipt.
        receipt_id: String,
    },
    /// The stage was required and did not run; no receipt exists.
    Missing {
        /// What the absent stage would have proven.
        required_proof: String,
    },
}

impl ProductProofStageReceipt {
    /// Whether this stage was actually observed with a retained receipt.
    #[must_use]
    pub const fn is_observed(&self) -> bool {
        matches!(self, Self::Observed { .. })
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        match self {
            Self::Observed { receipt_id } => {
                valid_text(receipt_id, "product_proof.stage.receipt_id")
                    .map_err(ProductProofError::Report)
            }
            Self::Missing { required_proof } => {
                valid_text(required_proof, "product_proof.stage.required_proof")
                    .map_err(ProductProofError::Report)
            }
        }
    }
}

/// The parked Windows run attempt that produced this record.
///
/// A `None` attempt is the current state of the product: no installed Windows
/// run has ever been attempted, so there is no execution to report. When an
/// attempt exists it carries its own lifecycle position and, if it did not
/// complete, exactly one I18.22 failure class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofRunAttempt {
    /// Stable identity of the attempted run.
    pub run_id: String,
    /// Lifecycle position of the attempt; separate from the semantic outcome.
    pub execution: ExecutionStatus,
    /// I18.22 failure class; present exactly when the attempt did not complete.
    pub failure_class: Option<ProductProofFailureClass>,
    /// Factual reason for the recorded position, in one clause.
    pub reason: String,
}

impl ProductProofRunAttempt {
    /// Records a completed attempt that reached a terminal semantic outcome.
    pub fn completed(
        run_id: impl Into<String>,
        execution: ExecutionStatus,
        reason: impl Into<String>,
    ) -> Result<Self, ProductProofError> {
        let attempt = Self {
            run_id: run_id.into(),
            execution,
            failure_class: None,
            reason: reason.into(),
        };
        attempt.validate()?;
        Ok(attempt)
    }

    /// Records an attempt that did not complete, under exactly one I18.22
    /// failure class.
    pub fn incomplete(
        run_id: impl Into<String>,
        execution: ExecutionStatus,
        failure_class: ProductProofFailureClass,
        reason: impl Into<String>,
    ) -> Result<Self, ProductProofError> {
        if execution == ExecutionStatus::Succeeded {
            return Err(ProductProofError::CompletedRunCannotBeIncomplete {
                run_id: run_id.into(),
            });
        }
        let attempt = Self {
            run_id: run_id.into(),
            execution,
            failure_class: Some(failure_class),
            reason: reason.into(),
        };
        attempt.validate()?;
        Ok(attempt)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        valid_text(&self.run_id, "product_proof.attempt.run_id")
            .map_err(ProductProofError::Report)?;
        valid_text(&self.reason, "product_proof.attempt.reason")
            .map_err(ProductProofError::Report)?;
        if !self.execution.is_terminal() {
            return Err(ProductProofError::NonTerminalAttempt {
                run_id: self.run_id.clone(),
            });
        }
        if self.execution == ExecutionStatus::Succeeded && self.failure_class.is_some() {
            return Err(ProductProofError::CompletedRunCannotBeIncomplete {
                run_id: self.run_id.clone(),
            });
        }
        Ok(())
    }
}

/// Identity of the executable that was or would be launched.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofExecutableIdentity {
    /// Executable name as it was resolved.
    pub executable_name: String,
    /// Content digest of the exact executable bytes, when the bytes are known.
    pub content_digest: Option<String>,
    /// Whether the executable is installed on the target host.
    pub installed: bool,
}

impl ProductProofExecutableIdentity {
    /// Binds one executable identity, including whether it is installed.
    pub fn new(
        executable_name: impl Into<String>,
        content_digest: Option<String>,
        installed: bool,
    ) -> Result<Self, ProductProofError> {
        let identity = Self {
            executable_name: executable_name.into(),
            content_digest,
            installed,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        valid_text(
            &self.executable_name,
            "product_proof.executable.executable_name",
        )
        .map_err(ProductProofError::Report)?;
        Ok(())
    }
}

/// Identity of the environment the proof would run in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofEnvironmentIdentity {
    /// Exact target platform the route targets.
    pub platform: String,
    /// Installation identity on that platform, when one exists.
    pub installation_id: Option<String>,
}

impl ProductProofEnvironmentIdentity {
    /// Binds one environment identity.
    pub fn new(
        platform: impl Into<String>,
        installation_id: Option<String>,
    ) -> Result<Self, ProductProofError> {
        let identity = Self {
            platform: platform.into(),
            installation_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        valid_text(&self.platform, "product_proof.environment.platform")
            .map_err(ProductProofError::Report)?;
        Ok(())
    }
}

/// Who imposed the stop condition, and under what authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofAuthority {
    /// The acceptance owner accountable for this proof.
    pub owner: String,
    /// The authority that imposed the stop condition.
    pub authority_ref: String,
}

impl ProductProofAuthority {
    /// Binds the accountable owner and the stop-imposing authority.
    pub fn new(
        owner: impl Into<String>,
        authority_ref: impl Into<String>,
    ) -> Result<Self, ProductProofError> {
        let authority = Self {
            owner: owner.into(),
            authority_ref: authority_ref.into(),
        };
        authority.validate()?;
        Ok(authority)
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        valid_text(&self.owner, "product_proof.authority.owner")
            .map_err(ProductProofError::Report)?;
        valid_text(&self.authority_ref, "product_proof.authority.authority_ref")
            .map_err(ProductProofError::Report)?;
        Ok(())
    }
}

/// The retained evidence a product-proof record must keep for readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofRetainedEvidence {
    /// Raw log handles retained for forensic readback.
    pub raw_log_refs: Vec<String>,
    /// The executable that was or would be launched.
    pub executable: Option<ProductProofExecutableIdentity>,
    /// The environment the proof runs in.
    pub environment: Option<ProductProofEnvironmentIdentity>,
    /// The observed-or-missing stage receipts.
    pub stage_receipts: ProductProofStageReceipts,
}

impl ProductProofRetainedEvidence {
    /// Whether the required installed-route execution was actually observed.
    #[must_use]
    pub const fn installed_route_observed(&self) -> bool {
        self.stage_receipts.installed_route.is_observed()
    }

    fn validate(&self) -> Result<(), ProductProofError> {
        for reference in &self.raw_log_refs {
            valid_text(reference, "product_proof.retained.raw_log_ref")
                .map_err(ProductProofError::Report)?;
        }
        if let Some(executable) = &self.executable {
            executable.validate()?;
        }
        if let Some(environment) = &self.environment {
            environment.validate()?;
        }
        self.stage_receipts.validate()
    }
}

impl ProductProofStageReceipts {
    fn validate(&self) -> Result<(), ProductProofError> {
        self.installed_route.validate()
    }
}

/// The terminal product-proof status for one acceptance item.
///
/// This is the record the issue asks for: exactly one I18.24 outcome, its
/// factual reason, the owner/authority that imposed the stop, the required
/// evidence that is still missing, build evidence kept apart from live-product
/// outcome, the failure class of any incomplete run attempt, and the retained
/// readback evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofStatus {
    /// Stable identity of the acceptance item this status describes.
    pub proof_id: String,
    /// Always [`PRODUCT_PROOF_CONTRACT`].
    pub contract: String,
    /// Exactly one I18.24 semantic outcome for the required product property.
    pub outcome: VerificationOutcome,
    /// Factual reason for that outcome, in one clause.
    pub reason: String,
    /// Owner and stop-imposing authority.
    pub authority: ProductProofAuthority,
    /// Required evidence that is still absent, in canonical order.
    pub missing_evidence: Vec<String>,
    /// Live-product evidence, if any was actually observed.
    pub live_evidence: Vec<ProductProofEvidence>,
    /// Release-build evidence, retained and never a live-product outcome.
    pub build_evidence: Option<ProductProofBuildEvidence>,
    /// The Windows run attempt, absent when no run was ever attempted.
    pub attempt: Option<ProductProofRunAttempt>,
    /// Retained logs, identities, and stage receipts.
    pub retained: ProductProofRetainedEvidence,
}

impl ProductProofStatus {
    /// Captures the current parked Windows run as one explicit I18.24 outcome.
    ///
    /// A parked run was never attempted, so the record carries no attempt and
    /// no live evidence. The caller supplies the observed outcome, the factual
    /// reason, the stop-imposing authority, the required evidence that is
    /// still missing, the retained build handle, and the retained readback
    /// evidence whose installed-route stage must be explicitly missing. A
    /// parked outcome is never `PASS`: I18.24 never aggregates `UNKNOWN`,
    /// `PARTIAL` or `BLOCKED` into a pass, and compilation alone leaves the
    /// product `NOT_ACCEPTED / UNVERIFIED` until an identity-bound installed
    /// Windows proof exists.
    pub fn parked(
        proof_id: impl Into<String>,
        outcome: VerificationOutcome,
        reason: impl Into<String>,
        authority: ProductProofAuthority,
        mut missing_evidence: Vec<String>,
        build_evidence: Option<ProductProofBuildEvidence>,
        retained: ProductProofRetainedEvidence,
    ) -> Result<Self, ProductProofError> {
        if outcome == VerificationOutcome::Pass {
            return Err(ProductProofError::ParkedRunCannotPass);
        }
        if retained.installed_route_observed() {
            return Err(ProductProofError::ParkedRunCannotObserveInstalledRoute);
        }
        missing_evidence.sort();
        let status = Self {
            proof_id: proof_id.into(),
            contract: PRODUCT_PROOF_CONTRACT.to_owned(),
            outcome,
            reason: reason.into(),
            authority,
            missing_evidence,
            live_evidence: Vec::new(),
            build_evidence,
            attempt: None,
            retained,
        };
        status.validate()?;
        Ok(status)
    }

    /// Updates this record from the next installed Windows run attempt.
    ///
    /// The attempt carries its own lifecycle position and, when it did not
    /// complete, exactly one I18.22 failure class. The caller supplies the
    /// observed I18.24 outcome, the factual reason, the still-missing
    /// evidence, the observed live evidence, and the updated retained
    /// evidence. Identity, authority, and build evidence are preserved;
    /// prior attempts stay readable through the retained raw logs. The
    /// fail-closed rule still applies: a `PASS` outcome validates only with
    /// an observed installed-route execution, no missing evidence, and a
    /// succeeded run.
    pub fn record_attempt(
        &self,
        attempt: ProductProofRunAttempt,
        outcome: VerificationOutcome,
        reason: impl Into<String>,
        mut missing_evidence: Vec<String>,
        live_evidence: Vec<ProductProofEvidence>,
        retained: ProductProofRetainedEvidence,
    ) -> Result<Self, ProductProofError> {
        missing_evidence.sort();
        let status = Self {
            proof_id: self.proof_id.clone(),
            contract: PRODUCT_PROOF_CONTRACT.to_owned(),
            outcome,
            reason: reason.into(),
            authority: self.authority.clone(),
            missing_evidence,
            live_evidence,
            build_evidence: self.build_evidence.clone(),
            attempt: Some(attempt),
            retained,
        };
        status.validate()?;
        Ok(status)
    }

    /// Validates the record's internal consistency.
    ///
    /// Two refusals are structural rather than advisory:
    ///
    /// * a `PASS` outcome requires the required installed-route execution to
    ///   be observed and no missing evidence — a record can never claim the
    ///   property is proven while the required run is absent;
    /// * build evidence is a build-domain handle, so a non-`PASS` product
    ///   outcome is never contradicted by a successful build.
    pub fn validate(&self) -> Result<(), ProductProofError> {
        if self.contract != PRODUCT_PROOF_CONTRACT {
            return Err(ProductProofError::ContractMismatch {
                contract: self.contract.clone(),
            });
        }
        valid_text(&self.proof_id, "product_proof.proof_id").map_err(ProductProofError::Report)?;
        valid_text(&self.reason, "product_proof.reason").map_err(ProductProofError::Report)?;
        self.authority.validate()?;
        let mut seen = std::collections::BTreeSet::new();
        for reference in &self.missing_evidence {
            valid_text(reference, "product_proof.missing_evidence")
                .map_err(ProductProofError::Report)?;
            if !seen.insert(reference.as_str()) {
                return Err(ProductProofError::DuplicateField {
                    field: "product_proof.missing_evidence",
                });
            }
        }
        if self
            .missing_evidence
            .windows(2)
            .any(|pair| pair[0] > pair[1])
        {
            return Err(ProductProofError::UnorderedField {
                field: "product_proof.missing_evidence",
            });
        }
        let mut live_ids = std::collections::BTreeSet::new();
        for evidence in &self.live_evidence {
            evidence.validate()?;
            if !evidence.is_live_product() {
                return Err(ProductProofError::LiveEvidenceWrongDomain {
                    evidence_id: evidence.evidence_id.clone(),
                });
            }
            if !live_ids.insert(evidence.evidence_id.as_str()) {
                return Err(ProductProofError::DuplicateField {
                    field: "product_proof.live_evidence",
                });
            }
        }
        if let Some(build) = &self.build_evidence {
            build.validate()?;
        }
        if let Some(attempt) = &self.attempt {
            attempt.validate()?;
        }
        self.retained.validate()?;
        if self.outcome == VerificationOutcome::Pass {
            if !self.retained.installed_route_observed() || !self.missing_evidence.is_empty() {
                return Err(ProductProofError::PassWithoutInstalledRoute);
            }
            if let Some(attempt) = &self.attempt
                && attempt.execution != ExecutionStatus::Succeeded
            {
                return Err(ProductProofError::PassWithoutSucceededRun {
                    run_id: attempt.run_id.clone(),
                    execution: attempt.execution,
                });
            }
        }
        Ok(())
    }

    /// Rolls this record up for presentation.
    ///
    /// The refusal is the rule, not a comment: an I18.24 `PASS` is returned
    /// only when the record itself validated *and* the required installed-route
    /// execution was actually observed. Any other case returns
    /// [`ProductProofRollup::Refused`] carrying the exact outcome, the reason,
    /// and the required missing evidence, so `UNKNOWN`, `PARTIAL` and `BLOCKED`
    /// can never be aggregated into a pass.
    pub fn rollup(&self) -> ProductProofRollup {
        if self.validate().is_ok()
            && self.outcome == VerificationOutcome::Pass
            && self.retained.installed_route_observed()
        {
            ProductProofRollup::Pass {
                proof_id: self.proof_id.clone(),
                live_evidence_ids: self
                    .live_evidence
                    .iter()
                    .map(|evidence| evidence.evidence_id.clone())
                    .collect(),
            }
        } else {
            ProductProofRollup::Refused {
                proof_id: self.proof_id.clone(),
                outcome: self.outcome,
                reason: self.reason.clone(),
                authority_ref: self.authority.authority_ref.clone(),
                missing_evidence: self.missing_evidence.clone(),
            }
        }
    }
}

/// The result of rolling one product-proof record up.
///
/// There is exactly one `Pass` variant and it is reachable only through
/// [`ProductProofStatus::rollup`], which refuses unless the installed-route
/// execution was observed. Every other case keeps the exact I18.24 outcome
/// visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum ProductProofRollup {
    /// The required product property is proven in the declared scope.
    Pass {
        /// Acceptance item that is proven.
        proof_id: String,
        /// Live-product evidence that carries the proof.
        live_evidence_ids: Vec<String>,
    },
    /// The proof is not a pass; the exact outcome and its reason are retained.
    Refused {
        /// Acceptance item that is not proven.
        proof_id: String,
        /// The exact I18.24 outcome that was observed.
        outcome: VerificationOutcome,
        /// Factual reason for the refusal.
        reason: String,
        /// Authority that imposed the stop condition.
        authority_ref: String,
        /// Required evidence that is still absent.
        missing_evidence: Vec<String>,
    },
}

impl ProductProofRollup {
    /// Whether this rollup presents the proof as `PASS`.
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}

/// Typed failures of the product-proof record.
#[derive(Debug, Error)]
pub enum ProductProofError {
    /// A required field was blank, malformed, or unordered.
    #[error("invalid field: {0}")]
    Report(#[from] ReportError),
    /// A required field was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field that must not be empty.
        field: &'static str,
    },
    /// A collection contains a duplicate identity.
    #[error("duplicate identity in {field}")]
    DuplicateField {
        /// Field that contains a duplicate.
        field: &'static str,
    },
    /// A collection is not in canonical order.
    #[error("{field} is not in canonical order")]
    UnorderedField {
        /// Field that is not canonically ordered.
        field: &'static str,
    },
    /// The record does not carry the product-proof contract identity.
    #[error("product proof contract mismatch: {contract}")]
    ContractMismatch {
        /// Contract identity the record carried.
        contract: String,
    },
    /// Build evidence was supplied on a non-build domain.
    #[error("build evidence {evidence_id} is not a build-domain handle")]
    BuildEvidenceWrongDomain {
        /// Evidence identity with the wrong domain.
        evidence_id: String,
    },
    /// Live-product evidence was supplied on a non-runtime domain.
    #[error("live evidence {evidence_id} is not a runtime-domain handle")]
    LiveEvidenceWrongDomain {
        /// Evidence identity with the wrong domain.
        evidence_id: String,
    },
    /// A run attempt claimed to be incomplete while having succeeded.
    #[error("run {run_id} succeeded and cannot carry a failure class")]
    CompletedRunCannotBeIncomplete {
        /// Run identity that claimed an impossible state.
        run_id: String,
    },
    /// A run attempt was recorded in a non-terminal lifecycle position.
    #[error("run attempt {run_id} is not terminal")]
    NonTerminalAttempt {
        /// Run identity that is not terminal.
        run_id: String,
    },
    /// A `PASS` outcome was recorded against a run attempt that did not
    /// execute successfully.
    #[error("PASS requires a succeeded run attempt: run {run_id} is {execution:?}")]
    PassWithoutSucceededRun {
        /// Run identity that did not succeed.
        run_id: String,
        /// Lifecycle position that was actually observed.
        execution: ExecutionStatus,
    },
    /// A `PASS` outcome was recorded while the required installed-route
    /// execution is absent or evidence is still missing.
    #[error("PASS requires an observed installed-route execution and no missing evidence")]
    PassWithoutInstalledRoute,
    /// A parked run was recorded with a `PASS` outcome.
    #[error("a parked run cannot carry a PASS outcome")]
    ParkedRunCannotPass,
    /// A parked run was recorded with an observed installed-route execution.
    #[error("a parked run cannot observe an installed-route execution")]
    ParkedRunCannotObserveInstalledRoute,
}
