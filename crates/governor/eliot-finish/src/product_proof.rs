//! The acceptance-owner product-proof record for the parked Windows installed
//! route (issue #1903).
//!
//! [`ProductProofStatus`](eliot_reports::product_proof::ProductProofStatus) is
//! the terminal status type `eliot-reports` already owns, and this module is
//! its ProductProof/FinishService acceptance owner. The record is built from
//! facts the acceptance owner holds, never from composed literals:
//!
//! * the installed-route stage is observed only when this owner holds a
//!   retained installed-route receipt identity. A `None` receipt is recorded as
//!   the explicit `Missing` stage, so an absent launch receipt is a retained
//!   fact rather than a silent success;
//! * release-build evidence is a build-domain handle with no outcome field, so
//!   a successful compile can be linked here and can never be read as a
//!   live-product `PASS`;
//! * the semantic outcome and the failure class are the record's own I18.24
//!   and I18.22 values, never a second taxonomy declared in this module.
//!
//! The fail-closed rule is not relaxed anywhere below: `PASS` still requires an
//! observed installed-route execution, no missing evidence, and a succeeded
//! run, and every published disposition is re-read against the record it
//! summarizes.

#![forbid(unsafe_code)]

use eliot_canonical::{FinishDecision, FinishDecisionOutcome};
use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use eliot_reports::product_proof::{
    ProductProofAuthority, ProductProofBuildEvidence, ProductProofEnvironmentIdentity,
    ProductProofEvidence, ProductProofEvidenceDomain, ProductProofExecutableIdentity,
    ProductProofFailureClass, ProductProofRetainedEvidence, ProductProofRollup,
    ProductProofRunAttempt, ProductProofStageReceipt, ProductProofStageReceipts, ProductProofStatus,
};
use eliot_reports::projection::{ReportInputRevision, ReportInputSource};
use thiserror::Error;

use crate::FinishService;

/// Stable identity of the parked Windows acceptance item this owner records.
///
/// The plan (`docs/migration/1860-product-proof-plan.md`) authorizes exactly
/// one bounded installed pulse for the #11 coordination owner, so this is a
/// stable identity for the acceptance item rather than a per-run id: the same
/// record is revised across attempts instead of being replaced by a parallel
/// one.
pub const PRODUCT_PROOF_ID: &str = "windows-installed-pulse-11";

/// What the absent installed-route execution would have proven.
///
/// This is the single required stage text, held here so the record and the
/// required-missing-evidence list cannot disagree about what is absent.
pub const INSTALLED_ROUTE_REQUIRED_PROOF: &str =
    "installed Windows route pulse executed end to end on the target generation";

/// Typed failures of the acceptance-owner product-proof producer.
#[derive(Debug, Error)]
pub enum ProductProofRecordError {
    /// The product-proof contract rejected the record this owner built.
    #[error("product proof record rejected: {0}")]
    Record(String),
}

/// The retained stage facts one acceptance evaluation contributes.
///
/// Every field is a fact the acceptance owner already holds. A `None` is a
/// retained fact rather than a default: the required stage did not run, so
/// there is no receipt to cite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductProofStageInputs<'a> {
    /// Authority this evaluation ran under.
    pub authority_ref: &'a str,
    /// Acceptance owner accountable for the proof.
    pub owner: &'a str,
    /// Highest proof ceiling the retained evidence actually reached.
    ///
    /// This is the acceptance owner's own evidence-only ceiling, so the build
    /// handle it produces can never be read as a live-product outcome.
    pub proof_ceiling: &'a str,
    /// Identity of the retained installed-route receipt, when one exists.
    ///
    /// This is the only field that can mark the required installed-route
    /// stage observed. It is the receipt identity the owner holds, never a
    /// composed or assumed value.
    pub installed_route_receipt: Option<&'a str>,
    /// Raw log handles retained for forensic readback.
    pub raw_log_refs: &'a [String],
    /// Executable that was or would be launched, when the owner resolved one.
    pub executable: Option<ProductProofExecutableIdentity>,
    /// Environment the proof would run in, when the owner resolved one.
    pub environment: Option<ProductProofEnvironmentIdentity>,
}

impl FinishService {
    /// Constructs the parked terminal product-proof record for the Windows
    /// acceptance item from the retained stage facts of one evaluation.
    ///
    /// A parked run was never attempted, so the record carries no attempt and
    /// no live evidence. An observed installed-route execution reaches this
    /// record only through [`Self::revise_product_proof_status`], which updates
    /// this same record from a real attempt; the parked record is therefore
    /// exactly the current truthful state, and its rollup is refused whenever
    /// the required stage is absent.
    ///
    /// The build handle is a build-domain value with no outcome field, so the
    /// successful release build can be linked here as non-product proof and
    /// can never be read as a live-product `PASS`.
    pub fn product_proof_parked(
        inputs: &ProductProofStageInputs<'_>,
    ) -> Result<ProductProofStatus, ProductProofRecordError> {
        text_field(inputs.authority_ref, "authority_ref")?;
        text_field(inputs.owner, "owner")?;
        let source_bytes = retained_source_bytes(inputs);
        let observed_by = ReportInputRevision::new(
            ReportInputSource::ProductSupport,
            inputs.authority_ref,
            1,
            source_bytes.as_bytes(),
        )
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        let retained = ProductProofRetainedEvidence {
            raw_log_refs: inputs.raw_log_refs.to_vec(),
            executable: inputs.executable.clone(),
            environment: inputs.environment.clone(),
            stage_receipts: ProductProofStageReceipts {
                installed_route: installed_route_receipt(inputs.installed_route_receipt),
            },
        };
        // Read the observation back off the retained stage rather than
        // carrying a second literal beside it, so the one place that decides
        // the stage is the only place the fact can come from.
        let installed_route_observed = retained.installed_route_observed();
        let build_evidence = build_evidence(inputs.proof_ceiling, &observed_by)?;
        let missing_evidence = missing_evidence(&retained, build_evidence.is_some());
        let reason = format!(
            "installed Windows route has never executed for acceptance authority {}; {build}",
            inputs.authority_ref,
            build = build_clause(build_evidence.is_some()),
        );
        let authority = ProductProofAuthority::new(inputs.owner, inputs.authority_ref)
            .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        // The parked state is a block imposed by the owner authority rather
        // than an unknown: the required installed Windows execution has never
        // run, so the record is BLOCKED with its factual reason and authority
        // instead of an optimistic unknown that could later read as a partial
        // pass. This is the I18.24 vocabulary, not a new one.
        let status = ProductProofStatus::parked(
            PRODUCT_PROOF_ID,
            VerificationOutcome::Blocked,
            reason,
            authority,
            missing_evidence,
            build_evidence,
            retained,
        )
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        fail_closed_rollup(&status.rollup(), &status)?;
        Ok(status)
    }

    /// Revises the same record from the next installed Windows attempt.
    ///
    /// The attempt is described by the I18.22 failure class the caller
    /// observed for that run and by the I18.24 outcome it actually read, and
    /// the retained stage receipts are the ones the caller holds. Identity,
    /// authority, and build evidence are carried forward from `previous`, so
    /// one acceptance item keeps one record across attempts rather than
    /// accumulating a parallel one.
    ///
    /// The fail-closed pass rule is unchanged: `PASS` still requires an
    /// observed installed-route execution, no missing evidence, and a
    /// succeeded run, and that check runs again on the revised record.
    pub fn revise_product_proof_status(
        previous: &ProductProofStatus,
        revision: ProductProofRevision,
    ) -> Result<ProductProofStatus, ProductProofRecordError> {
        previous
            .validate()
            .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        let status = previous
            .record_attempt(
                revision.attempt,
                revision.outcome,
                revision.reason,
                revision.missing_evidence,
                revision.live_evidence,
                revision.retained,
            )
            .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        fail_closed_rollup(&status.rollup(), &status)?;
        Ok(status)
    }
}

/// The observed facts of one real installed Windows attempt.
///
/// The owner derives the attempt's failure class and semantic outcome from the
/// same run it observed, so the two axes cannot disagree about what happened.
pub struct ProductProofRevision {
    /// The attempt's own identity, lifecycle position, and failure class.
    pub attempt: ProductProofRunAttempt,
    /// The exact I18.24 outcome observed for the required product property.
    pub outcome: VerificationOutcome,
    /// Factual reason for that outcome, in one clause.
    pub reason: String,
    /// Required evidence that is still absent after this attempt.
    pub missing_evidence: Vec<String>,
    /// Live-product evidence this attempt actually produced.
    pub live_evidence: Vec<ProductProofEvidence>,
    /// Updated retained logs, identities, and stage receipts.
    pub retained: ProductProofRetainedEvidence,
}

fn text_field(value: &str, field: &'static str) -> Result<(), ProductProofRecordError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProductProofRecordError::Record(format!(
            "product proof field {field} must be non-blank and contain no control characters"
        )));
    }
    Ok(())
}

/// The exact retained bytes this record was read from.
///
/// Binding the source revision to this text means the record's evidence digest
/// is the digest of what the owner actually held. No stage value, digest, or
/// timestamp is produced here — only the presence or absence of an owner-held
/// receipt.
fn retained_source_bytes(inputs: &ProductProofStageInputs<'_>) -> String {
    format!(
        "authority={}|installed-route-receipt={}|proof-ceiling={}|raw-logs={}",
        inputs.authority_ref,
        inputs.installed_route_receipt.unwrap_or("absent"),
        inputs.proof_ceiling,
        inputs.raw_log_refs.len(),
    )
}

/// Derives the installed-route stage receipt from the owner's retained receipt.
///
/// An observed receipt is cited by the identity the owner holds. Its absence
/// is an explicit `Missing` stage naming what the absent execution would have
/// proven, so an absent launch receipt can never be read as a success.
fn installed_route_receipt(receipt: Option<&str>) -> ProductProofStageReceipt {
    match receipt {
        Some(receipt_id) => ProductProofStageReceipt::Observed {
            receipt_id: receipt_id.to_owned(),
        },
        None => ProductProofStageReceipt::Missing {
            required_proof: INSTALLED_ROUTE_REQUIRED_PROOF.to_owned(),
        },
    }
}

/// Builds the build-domain evidence handle for the evaluated candidate.
///
/// The handle is a build-domain value with no outcome field, so linking the
/// successful release build here cannot present it as a live-product result.
fn build_evidence(
    proof_ceiling: &str,
    observed_by: &ReportInputRevision,
) -> Result<Option<ProductProofBuildEvidence>, ProductProofRecordError> {
    let evidence = ProductProofEvidence::new(
        ProductProofEvidenceDomain::Build,
        format!("finish-build:{proof_ceiling}"),
        format!("candidate evaluated at proof ceiling {proof_ceiling}; build evidence only"),
        observed_by.clone(),
    )
    .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
    ProductProofBuildEvidence::new(evidence, vec![proof_ceiling.to_owned()])
        .map(Some)
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))
}

/// The evidence that is still required but was not observed.
///
/// The list is derived from the record's own retained stage rather than
/// supplied by the caller, so the required-missing-evidence field and the
/// stage cannot disagree.
fn missing_evidence(
    retained: &ProductProofRetainedEvidence,
    build_evidence_present: bool,
) -> Vec<String> {
    let mut missing = Vec::new();
    if !retained.installed_route_observed()
        && let ProductProofStageReceipt::Missing { required_proof } =
            &retained.stage_receipts.installed_route
    {
        missing.push(required_proof.clone());
    }
    if !build_evidence_present {
        missing.push("release build evidence for the exact candidate".to_owned());
    }
    missing
}

/// The build clause of the recorded reason.
fn build_clause(build_evidence_present: bool) -> &'static str {
    if build_evidence_present {
        "release build evidence retained"
    } else {
        "release build evidence absent"
    }
}

/// Fails closed when a rollup and the record it summarizes disagree.
///
/// A rollup may report `Pass` only when the record itself validated through
/// its own `validate()`, its outcome is `PASS`, and the required installed-route
/// execution was actually observed. This check re-reads the record rather than
/// trusting the caller's summary, so a rollup can never present a product proof
/// as proven while the required execution is absent.
///
/// This is a free function rather than a method on [`ProductProofRollup`]
/// because the rollup is owned by `eliot-reports` and Rust forbids an inherent
/// impl for a foreign type. The contract's own `rollup()` remains the single
/// producer of a disposition: this re-reads that producer's output against the
/// record it came from, so it declares no second verdict and no second
/// taxonomy.
fn fail_closed_rollup(
    rollup: &ProductProofRollup,
    status: &ProductProofStatus,
) -> Result<(), ProductProofRecordError> {
    let claimed_pass = rollup.is_pass();
    let record_passes = status.validate().is_ok()
        && status.outcome == VerificationOutcome::Pass
        && status.retained.installed_route_observed();
    if claimed_pass != record_passes {
        return Err(ProductProofRecordError::Record(
            "product proof rollup disagrees with the record it summarizes".to_owned(),
        ));
    }
    Ok(())
}

/// The I18.24 outcome this owner records for a derived finish decision.
///
/// The mapping reuses the existing finish vocabulary and the I18.24 outcome
/// type; it declares no new outcome axis. The execution position is mapped
/// separately, so a launch failure is never conflated with a policy block.
#[must_use]
pub fn outcome_of_decision(decision: &FinishDecision) -> VerificationOutcome {
    match decision.outcome {
        FinishDecisionOutcome::VerifiedComplete => VerificationOutcome::Pass,
        FinishDecisionOutcome::FailedVerification => VerificationOutcome::Fail,
        FinishDecisionOutcome::Partial => VerificationOutcome::Partial,
        FinishDecisionOutcome::DegradedNoProof
        | FinishDecisionOutcome::Superseded
        | FinishDecisionOutcome::UnsafeToFinish => VerificationOutcome::Unknown,
        FinishDecisionOutcome::Blocked => VerificationOutcome::Blocked,
        FinishDecisionOutcome::Cancelled => VerificationOutcome::Cancelled,
    }
}

/// The I18.22 failure class this owner records for an incomplete attempt.
///
/// The class stays on the separate execution axis from the semantic outcome,
/// so why a run did not complete remains distinct from what it would have
/// proven. A `Succeeded` execution is not an incomplete attempt and is refused
/// by the record builder rather than being given a class here.
#[must_use]
pub fn failure_class_of_execution(execution: ExecutionStatus) -> Option<ProductProofFailureClass> {
    let class = match execution {
        ExecutionStatus::Accepted | ExecutionStatus::Running => {
            ProductProofFailureClass::InfrastructureResource
        }
        ExecutionStatus::Failed => ProductProofFailureClass::Launch,
        ExecutionStatus::Partial => ProductProofFailureClass::Assertion,
        ExecutionStatus::Unknown => ProductProofFailureClass::ParserEvidence,
        ExecutionStatus::Blocked => ProductProofFailureClass::InfrastructureResource,
        ExecutionStatus::Cancelled => ProductProofFailureClass::TimeoutHang,
        ExecutionStatus::Succeeded => return None,
    };
    Some(class)
}
