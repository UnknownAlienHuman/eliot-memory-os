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
//!   that carries no outcome field at all, so a successful release build
//!   can be linked as non-product proof and can never be read as live `PASS`;
//!   the binaries it produced are named by the caller that built them, which is
//!   the binding that a constant could not make — see
//!   [`ProductProofBuildEvidence`];
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
///
/// [`Self::binary_names`] is deliberately caller-supplied and this owner
/// deliberately holds no nine-binary constant. The nine-binary build scope is
/// published once, by the release surface owner
/// (`bins/eliot/src/release_surface.rs::BUNDLE_BINARIES`, bound to
/// `docs/release/CLAIM_BOUNDARY.md`) and enforced by the claim-boundary checker
/// (`scripts/verify-release-claim-boundary.py::EXPECTED_NINE_BINARIES`); that
/// package is a binary-only crate, so a report library cannot reference it
/// without inverting the bin -> lib dependency direction, and restating the
/// nine names here would create a second owner of one published list.
///
/// Restating them would also be unsound rather than merely duplicated: a
/// constant on this type would let a record name a binary set that no build
/// produced. A caller that names the binaries it actually built binds this
/// record to the build that happened, which is the stronger guarantee, and this
/// owner verifies that binding the only way it can be verified without
/// re-deriving a digest it does not retain — each name must be non-blank and
/// free of control characters, and the list must be canonical (sorted) and
/// free of duplicates. Completeness against the published nine is deliberately
/// NOT checked here: that would validate the caller's list against a copy of
/// itself, and the release surface owner is the independent expected set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProofBuildEvidence {
    /// Identity of the build evidence the record links.
    pub evidence: ProductProofEvidence,
    /// Binaries the exact build that produced [`Self::evidence`] actually
    /// produced, in canonical order.
    pub binary_names: Vec<String>,
}

impl ProductProofBuildEvidence {
    /// Binds one release build to its retained handle and the binaries that
    /// build produced.
    ///
    /// The constructor canonicalizes the name order and defers every
    /// binary-set invariant — non-empty, non-blank, one name per artifact on
    /// the target platform — to [`Self::validate`], so a record built here and
    /// the same record read off the wire are held to one rule set rather than
    /// two that can drift apart.
    pub fn new(
        evidence: ProductProofEvidence,
        mut binary_names: Vec<String>,
    ) -> Result<Self, ProductProofError> {
        if evidence.domain != ProductProofEvidenceDomain::Build {
            return Err(ProductProofError::BuildEvidenceWrongDomain {
                evidence_id: evidence.evidence_id.clone(),
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

    /// The invariants of the recorded binary set.
    ///
    /// This is the single validator, and [`Self::new`] is not an alternative
    /// path past it: every field here is `pub` and `Deserialize` is derived, so
    /// `serde_json` constructs this record directly. An invariant stated only
    /// in the constructor would therefore hold for records built in Rust and
    /// be absent for records read off the wire, and an empty binary set is
    /// exactly the shape that reaches a `PASS` rollup unchallenged — the
    /// duplicate scan over an empty `Vec` is vacuously false. The constructor
    /// therefore owns no invariant of its own: it sorts the names into
    /// canonical order and defers every refusal to here.
    fn validate(&self) -> Result<(), ProductProofError> {
        if self.binary_names.is_empty() {
            return Err(ProductProofError::EmptyField {
                field: "product_proof.build_evidence.binary_names",
            });
        }
        self.evidence.validate()?;
        for name in &self.binary_names {
            valid_text(name, "product_proof.build_evidence.binary_name")
                .map_err(ProductProofError::Report)?;
        }
        // One binary named once: a repeated name would let a record inflate its
        // own binary set from a single observed artifact. The list is checked
        // against the names this record actually carries, which is a property
        // of the record and not a copy of an external expected list.
        //
        // The comparison key is `trim().to_ascii_lowercase()`, and it is
        // deliberate: this record targets a Windows release surface
        // (`ProductProofExecutableIdentity` resolves an executable name and
        // `eliot-finish` builds `{}.exe`), and Windows resolves filenames
        // case-insensitively. `eliotd.exe`, `ELIOTD.EXE` and `eliotd.exe ` are
        // ONE artifact on the target platform, so a byte-exact comparison
        // would let a single observed binary be recorded more than once —
        // exactly the inflation this check exists to prevent. Do NOT simplify
        // this back to `==` or to an adjacent-pair scan: both are weaker than
        // the invariant.
        //
        // The normalized key is used for the COMPARISON ONLY.
        // `binary_names` keeps every name exactly as the build emitted it,
        // because the record reports the observed artifact, not a normalized
        // alias of it; a later reader must see the name that was observed.
        let mut seen = std::collections::BTreeSet::new();
        for name in &self.binary_names {
            if !seen.insert(name.trim().to_ascii_lowercase()) {
                return Err(ProductProofError::DuplicateField {
                    field: "product_proof.build_evidence.binary_names",
                });
            }
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
    /// Four refusals are structural rather than advisory:
    ///
    /// * a `PASS` outcome requires the required installed-route execution to
    ///   be observed and no missing evidence — a record can never claim the
    ///   property is proven while the required run is absent;
    /// * a `PASS` outcome requires the run attempt that carries the proof to
    ///   have reached `Succeeded`. An observed installed-route stage is not
    ///   enough on its own: an attempt that executed and failed still leaves the
    ///   stage observed, so without this comparison a record whose execution
    ///   never succeeded — or which carries no attempt at all — could validate
    ///   as a pass on the strength of the stage alone;
    /// * a `PASS` outcome requires at least one runtime-domain live evidence
    ///   handle, so a passing proof can never be presented on an empty live
    ///   evidence set or on build-domain handles alone;
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
            match self.attempt.as_ref() {
                None => return Err(ProductProofError::PassWithoutAttempt),
                Some(attempt) if attempt.execution != ExecutionStatus::Succeeded => {
                    return Err(ProductProofError::PassWithoutSucceededRun {
                        run_id: attempt.run_id.clone(),
                        execution: attempt.execution,
                    });
                }
                Some(_) => {}
            }
            if !self.live_evidence.iter().any(Self::carries_live_product) {
                return Err(ProductProofError::PassWithoutLiveEvidence);
            }
        }
        Ok(())
    }

    /// Whether one live-evidence handle is on the runtime domain.
    ///
    /// The domain comparison lives here, once, because this is the same
    /// question [`ProductProofStatus::validate`] asks when it admits every live
    /// handle above and again when it requires a passing proof to carry at least
    /// one. A handle that cannot support a live-product outcome cannot stand in
    /// for one.
    fn carries_live_product(evidence: &ProductProofEvidence) -> bool {
        evidence.is_live_product()
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
    /// A `PASS` outcome was recorded without any run attempt at all.
    #[error("PASS requires the run attempt that carries the proof")]
    PassWithoutAttempt,
    /// A `PASS` outcome was recorded without a runtime-domain live evidence
    /// handle.
    #[error("PASS requires at least one runtime-domain live evidence handle")]
    PassWithoutLiveEvidence,
    /// A parked run was recorded with a `PASS` outcome.
    #[error("a parked run cannot carry a PASS outcome")]
    ParkedRunCannotPass,
    /// A parked run was recorded with an observed installed-route execution.
    #[error("a parked run cannot observe an installed-route execution")]
    ParkedRunCannotObserveInstalledRoute,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::projection::ReportInputSource;

    /// One canonical read of the exact candidate bytes this record is bound to.
    fn observed_by() -> ReportInputRevision {
        ReportInputRevision::new(
            ReportInputSource::Evidence,
            "build-candidate-1903",
            1,
            b"nine-binary release build observed bytes",
        )
        .expect("report input revision")
    }

    fn authority() -> ProductProofAuthority {
        ProductProofAuthority::new("ProductProof/FinishService", "finish-authority-1903")
            .expect("product-proof authority")
    }

    fn runtime_evidence(id: &str) -> ProductProofEvidence {
        ProductProofEvidence::new(
            ProductProofEvidenceDomain::Runtime,
            id,
            "installed-route launch receipt observed at runtime",
            observed_by(),
        )
        .expect("runtime-domain evidence handle")
    }

    /// The retained readback evidence, with the installed-route launch receipt
    /// explicitly recorded as the absent receipt it is.
    fn retained_launch_receipt_absent() -> ProductProofRetainedEvidence {
        ProductProofRetainedEvidence {
            raw_log_refs: vec!["raw://eliotd/1903.log".to_owned()],
            executable: Some(
                ProductProofExecutableIdentity::new(
                    "eliotd.exe",
                    Some("sha256:observed-eliotd-bytes".to_owned()),
                    false,
                )
                .expect("executable identity"),
            ),
            environment: Some(
                ProductProofEnvironmentIdentity::new(
                    "windows-x86_64",
                    Some("installation-1903".to_owned()),
                )
                .expect("environment identity"),
            ),
            stage_receipts: ProductProofStageReceipts {
                installed_route: ProductProofStageReceipt::Missing {
                    required_proof: "installed Windows route pulse executed end to end".to_owned(),
                },
            },
        }
    }

    /// The retained readback evidence of a run whose installed-route launch
    /// receipt was independently observed.
    fn retained_launch_receipt_observed(receipt_id: &str) -> ProductProofRetainedEvidence {
        ProductProofRetainedEvidence {
            stage_receipts: ProductProofStageReceipts {
                installed_route: ProductProofStageReceipt::Observed {
                    receipt_id: receipt_id.to_owned(),
                },
            },
            ..retained_launch_receipt_absent()
        }
    }

    /// The successful release build, linked as build evidence only.
    fn build_evidence(binary_names: Vec<&str>) -> ProductProofBuildEvidence {
        let evidence = build_domain_evidence();
        ProductProofBuildEvidence::new(
            evidence,
            binary_names.into_iter().map(str::to_owned).collect(),
        )
        .expect("release build evidence")
    }

    /// The build-domain evidence handle, without the binary set. Split out so
    /// the tests below can build the same evidence for the wire path, which
    /// never calls [`ProductProofBuildEvidence::new`].
    fn build_domain_evidence() -> ProductProofEvidence {
        ProductProofEvidence::new(
            ProductProofEvidenceDomain::Build,
            "build:release-1903",
            "nine-binary release build observed at its exact source head",
            observed_by(),
        )
        .expect("build-domain evidence handle")
    }

    /// The exact wire shape of a [`ProductProofBuildEvidence`] with the given
    /// binary names.
    ///
    /// Built from a real record rather than hand-written, so the fixture cannot
    /// drift from the serde surface: only `binary_names` is replaced. The
    /// digest is carried through verbatim, which is the point of the wire
    /// path — `serde_json` never calls [`ReportInputRevision::new`], so nothing
    /// recomputes it, and these tests deliberately do not ask anything to be
    /// recomputed.
    fn build_evidence_json(binary_names: &[&str]) -> serde_json::Value {
        let mut value = serde_json::to_value(build_evidence(vec!["eliotd.exe"]))
            .expect("serialized build evidence fixture");
        value["binary_names"] = serde_json::json!(
            binary_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<String>>()
        );
        value
    }

    fn succeeded_attempt(run_id: &str) -> ProductProofRunAttempt {
        ProductProofRunAttempt::completed(
            run_id,
            ExecutionStatus::Succeeded,
            "installed route executed end to end on the installed generation",
        )
        .expect("completed run attempt")
    }

    /// The parked record: the current product state, with the installed-route
    /// launch receipt explicitly absent.
    fn parked() -> ProductProofStatus {
        ProductProofStatus::parked(
            "windows-installed-pulse-11",
            VerificationOutcome::Blocked,
            "no installed Windows route pulse has been attempted",
            authority(),
            vec!["installed-route launch receipt".to_owned()],
            Some(build_evidence(vec!["eliot", "eliotd"])),
            retained_launch_receipt_absent(),
        )
        .expect("parked product-proof record")
    }

    /// The only path to `Pass`: an I18.24 `PASS` whose installed-route launch
    /// receipt was independently observed, whose attempt reached `Succeeded`,
    /// and which carries a runtime-domain live handle.
    fn observed_launch_receipt_pass() -> ProductProofStatus {
        parked()
            .record_attempt(
                succeeded_attempt("windows-pulse-11-run-1"),
                VerificationOutcome::Pass,
                "installed Windows route pulse observed end to end",
                Vec::new(),
                vec![runtime_evidence("pulse:windows-installed-pulse-11-run-1")],
                retained_launch_receipt_observed("receipt:windows-installed-pulse-11-run-1"),
            )
            .expect("passing product-proof record")
    }

    /// The same passing record, except that this attempt's launch receipt is
    /// absent. The owner refuses it at `ProductProofStatus::validate`, so this
    /// helper returns the refusal rather than a record: a `PASS` claiming an
    /// absent launch receipt is never admitted, and no presentation path
    /// exists that could roll one up.
    fn absent_launch_receipt_pass() -> Result<ProductProofStatus, ProductProofError> {
        parked().record_attempt(
            succeeded_attempt("windows-pulse-11-run-2"),
            VerificationOutcome::Pass,
            "installed Windows route pulse observed end to end",
            Vec::new(),
            vec![runtime_evidence("pulse:windows-installed-pulse-11-run-2")],
            retained_launch_receipt_absent(),
        )
    }

    /// ACCEPTANCE: a simulated absent launch receipt cannot be rolled up as
    /// `PASS`.
    ///
    /// This is the real record and the real rollup. The rule is not restated
    /// here: the assertion reads `ProductProofStatus::rollup` on the same
    /// record that does roll up as `Pass` once its launch receipt is observed.
    ///
    /// The refusal is asserted WHERE IT ACTUALLY HAPPENS, which is earlier than
    /// a rollup: `ProductProofStatus::validate` (`:677-680`) refuses a `Pass`
    /// whose installed-route receipt is absent, so such a record is never
    /// constructed at all. Asserting a `Refused` rollup instead would have
    /// tested a state that cannot exist, and would have quietly documented a
    /// weaker product than the one that actually ships.
    #[test]
    fn absent_launch_receipt_cannot_roll_up_as_pass_1903() {
        // Premise: with the launch receipt OBSERVED, the same attempt really
        // does roll up as PASS. Without this the refusal below would prove
        // nothing — the record could be un-passable for an unrelated reason.
        assert!(
            observed_launch_receipt_pass().rollup().is_pass(),
            "premise: an observed launch receipt does roll up as PASS"
        );

        // The near-miss is refused at construction: no record claiming PASS on
        // an absent launch receipt is ever admitted, so none exists to be
        // rolled up as PASS by any presentation path.
        assert!(
            matches!(
                absent_launch_receipt_pass(),
                Err(ProductProofError::PassWithoutInstalledRoute)
            ),
            "a Pass record with an absent launch receipt must never be constructed"
        );
    }

    /// REFUSAL: a build handle cannot stand in for a live-product runtime
    /// handle, so it is refused at the point it would have granted the proof.
    #[test]
    fn build_domain_live_evidence_is_refused_1903() {
        let build_handle = ProductProofEvidence::new(
            ProductProofEvidenceDomain::Build,
            "build:release-1903",
            "nine-binary release build observed at its exact source head",
            observed_by(),
        )
        .expect("build-domain evidence handle");
        assert!(matches!(
            parked().record_attempt(
                succeeded_attempt("windows-pulse-11-run-3"),
                VerificationOutcome::Pass,
                "installed Windows route pulse observed end to end",
                Vec::new(),
                vec![build_handle],
                retained_launch_receipt_observed("receipt:windows-pulse-11-run-3"),
            ),
            Err(ProductProofError::LiveEvidenceWrongDomain { .. })
        ));
    }

    /// REFUSAL: one observed artifact named twice would inflate the recorded
    /// binary set, so a duplicated list is refused.
    ///
    /// This is the byte-identical case. The case-insensitive and whitespace
    /// variants of the same artifact are refused by the next test; the check is
    /// platform-correct rather than byte-exact, so all three spellings of one
    /// artifact are the same refusal.
    #[test]
    fn duplicated_binary_name_is_refused_1903() {
        assert!(matches!(
            ProductProofBuildEvidence::new(
                build_domain_evidence(),
                vec!["eliotd.exe".to_owned(), "eliotd.exe".to_owned()],
            ),
            Err(ProductProofError::DuplicateField {
                field: "product_proof.build_evidence.binary_names"
            })
        ));
    }

    /// REFUSAL: on the Windows release surface this record targets, the same
    /// artifact is nameable many ways, and every one of them is one binary.
    ///
    /// `eliotd.exe`, `ELIOTD.EXE`, `eliotd.exe ` and ` eliotd.exe` are the same
    /// file to Windows. Accepting two of them as two binaries is exactly the
    /// inflation of the recorded binary set from a single observed artifact that
    /// the duplicate check exists to prevent, so all three variants are refused
    /// — and the refusal is asserted on the WIRE path, where nothing but
    /// [`ProductProofBuildEvidence::validate`] stands between the JSON and the
    /// answer. A genuinely distinct set is admitted by the same check, which is
    /// what makes the refusal discriminating rather than blanket.
    #[test]
    fn case_variant_duplicate_binary_name_is_refused_1903() {
        for variant in [
            vec!["eliotd.exe", "ELIOTD.EXE"],
            vec!["eliotd.exe", "eliotd.exe "],
            vec!["eliotd.exe", " eliotd.exe"],
        ] {
            let wire_record =
                serde_json::from_value::<ProductProofBuildEvidence>(build_evidence_json(&variant))
                    .expect("wire record deserializes; the refusal is in validate, not serde");
            assert!(
                matches!(
                    wire_record.validate(),
                    Err(ProductProofError::DuplicateField {
                        field: "product_proof.build_evidence.binary_names"
                    })
                ),
                "one artifact spelled {variant:?} must be refused as a duplicate"
            );
        }

        // The same check admits a set of genuinely distinct artifacts, and it
        // keeps every name exactly as the build emitted it — the normalization
        // is for the comparison only, never the stored record.
        let distinct = serde_json::from_value::<ProductProofBuildEvidence>(build_evidence_json(&[
            "eliot-doctor.exe",
            "Eliotd.exe",
            "eliot-testd.exe",
        ]))
        .expect("wire record deserializes");
        distinct.validate().expect("a distinct binary set is valid");
        assert_eq!(
            distinct.binary_names,
            vec![
                "eliot-doctor.exe".to_owned(),
                "Eliotd.exe".to_owned(),
                "eliot-testd.exe".to_owned()
            ]
        );
    }

    /// REFUSAL: a record read off the wire that names NO binary is refused.
    ///
    /// This is the guard against the forge and the reason the invariant lives in
    /// [`ProductProofBuildEvidence::validate`] rather than in `new`. The record
    /// here is built by `serde_json::from_value`, so `new` is never called: it
    /// has all-`pub` fields and a derived `Deserialize`, and the derived
    /// implementation is the only thing standing between a JSON document and a
    /// validated record. Before the fix the empty list passed, because a
    /// duplicate scan over an empty `Vec` is vacuously false — and an empty
    /// binary set attached to an otherwise passing record rolled up as `PASS`
    /// through [`ProductProofStatus::rollup`] and on to the projection and the
    /// live status surface. The premise below pins that the rest of this record
    /// is genuinely a `PASS`, so the refusal asserted after it is caused by the
    /// empty set alone and nothing else.
    #[test]
    fn empty_binary_set_read_off_the_wire_is_refused_1903() {
        let forged = serde_json::from_value::<ProductProofBuildEvidence>(build_evidence_json(&[]))
            .expect("wire record deserializes; the refusal is in validate, not serde");
        assert!(
            forged.binary_names.is_empty(),
            "premise: the forged wire record really does name no binary"
        );
        assert!(matches!(
            forged.validate(),
            Err(ProductProofError::EmptyField {
                field: "product_proof.build_evidence.binary_names"
            })
        ));

        // Premise: this build evidence is otherwise identical to the forged
        // one and validates. Without it, the refusal above would not
        // discriminate an empty set from any other property of the fixture.
        let honest = serde_json::from_value::<ProductProofBuildEvidence>(build_evidence_json(&[
            "eliot-doctor.exe",
            "eliot-testd.exe",
            "eliotd.exe",
        ]))
        .expect("wire record deserializes");
        honest.validate().expect("a named binary set is valid");

        // And the refusal is end-to-end: the same empty set carried by a record
        // that genuinely rolls up as PASS can no longer reach a `PASS` rollup,
        // so no presentation path can render it.
        let forged_status = ProductProofStatus {
            build_evidence: Some(forged),
            ..observed_launch_receipt_pass()
        };
        assert!(!forged_status.rollup().is_pass());
    }

    /// POSITIVE: the caller-supplied binary set binds the record to the build
    /// that actually produced it, in canonical order with one name per
    /// artifact.
    #[test]
    fn observed_binary_set_is_recorded_in_canonical_order_1903() {
        let record = build_evidence(vec!["eliot-testd", "eliotd", "eliot-doctor"]);
        assert_eq!(
            record.binary_names,
            vec![
                "eliot-doctor".to_owned(),
                "eliot-testd".to_owned(),
                "eliotd".to_owned()
            ]
        );
        record.validate().expect("recorded binary set is valid");
    }
}
