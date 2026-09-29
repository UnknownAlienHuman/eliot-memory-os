//! The acceptance-owner product-proof record for the parked Windows pulse
//! (issue #1903).
//!
//! [`ProductProofStatus`](eliot_reports::product_proof::ProductProofStatus) is
//! the terminal status type that `eliot-reports` already owns. This module is
//! the missing half the external audit named: the [`FinishService`] acceptance
//! owner that actually runs at the ProductProof/FinishService boundary
//! constructs, retains, and revises that record from the real stage receipts
//! the owner already produces, and publishes its rollup on the live daemon
//! status surface.
//!
//! Every value here is derived, never invented:
//!
//! * build evidence is the [`ProofCeiling`] and receipt digest of a real
//!   accepted finish decision, so a compile/link result is a build-domain
//!   handle and can never be read as a live-product outcome;
//! * the installed-route stage receipt is derived from whether a runtime
//!   domain receipt was actually retained, so a simulated absent launch
//!   receipt is a recorded fact rather than a silent success;
//! * the terminal outcome is the I18.24 outcome of the record itself, taken
//!   from the owner's own `FinishDecisionOutcome`, never from a second
//!   taxonomy declared here.
//!
//! The fail-closed pass rule is not relaxed: a rollup reaches `Pass` only
//! when the record validates, its outcome is `PASS`, and the required
//! installed-route execution was actually observed. Every other case returns
//! the exact refusal carrying outcome, reason, authority, and required
//! missing evidence.

#![forbid(unsafe_code)]

use eliot_canonical::{FinishDecision, FinishDecisionOutcome};
use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use eliot_reports::product_proof::{
    ProductProofAuthority, ProductProofBuildEvidence, ProductProofEnvironmentIdentity,
    ProductProofEvidence, ProductProofEvidenceDomain, ProductProofExecutableIdentity,
    ProductProofFailureClass, ProductProofRetainedEvidence, ProductProofRollup,
    ProductProofRunAttempt, ProductProofStageReceipt, ProductProofStageReceipts,
    ProductProofStatus,
};
use eliot_reports::projection::{ReportInputRevision, ReportInputSource};
use thiserror::Error;

use crate::FinishService;

/// Stable identity of the parked Windows acceptance item this owner records.
///
/// This is the #11 installed Windows pulse: one bounded installed-route
/// execution whose receipt the product proof requires. It is a stable identity
/// for the acceptance item, not a per-run id, so the same record is revised
/// across attempts instead of being replaced.
pub const PRODUCT_PROOF_ID: &str = "windows-installed-pulse-11";

/// Acceptance owner accountable for the parked Windows product proof.
pub const PRODUCT_PROOF_OWNER: &str = "bins/eliotd migration coordination (issue #11)";

/// Typed failures of the acceptance-owner product-proof producer.
#[derive(Debug, Error)]
pub enum ProductProofRecordError {
    /// The product-proof contract rejected the record this owner built.
    #[error("product proof record rejected: {0}")]
    Record(String),
}

/// The real stage receipts one finish decision contributes to a product proof.
///
/// These are the values the finish owner already produced for the admitted
/// attempt. A `None` is a retained fact, not a default: the stage was required
/// and did not run, so there is no receipt to cite. The set is borrowed, not
/// copied, because the executable and environment identities it carries own
/// their own strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductProofStageInputs<'a> {
    /// Authority that the owner rehydrated for this finish evaluation.
    pub finish_authority_ref: &'a str,
    /// Ceiling of the candidate the owner actually evaluated.
    pub proof_ceiling: &'a str,
    /// Receipt digest of the accepted finish decision, when one exists.
    pub decision_receipt_digest: Option<&'a str>,
    /// Runtime-domain receipt the retained run produced, when one exists.
    pub runtime_receipt_ref: Option<&'a str>,
    /// Raw log handles retained for forensic readback.
    pub raw_log_refs: &'a [String],
    /// Executable that was or would be launched.
    pub executable: Option<ProductProofExecutableIdentity>,
    /// Environment the proof runs in.
    pub environment: Option<ProductProofEnvironmentIdentity>,
}

impl FinishService {
    /// Constructs the parked terminal product-proof record for the Windows
    /// acceptance item from the real receipts of one evaluated candidate.
    ///
    /// A parked run was never attempted, so this record can never carry an
    /// observed installed-route execution: the installed-route stage is always
    /// the explicit `Missing` form, whatever the owner holds. An observed
    /// execution arrives only through
    /// [`Self::revise_product_proof_status`], which updates this same record
    /// from a real attempt. The parked record is therefore exactly the current
    /// truthful state — not attempted, not observed — and its rollup is refused
    /// by construction.
    ///
    /// The build evidence is the owner's own evaluated candidate: its proof
    /// ceiling and, when a decision was accepted, that decision's receipt
    /// digest. Because [`ProductProofBuildEvidence`] accepts only a
    /// build-domain handle and carries no outcome field, a successful release
    /// build can be linked here as non-product proof and can never be read as
    /// a live-product `PASS`.
    #[allow(
        clippy::unused_self,
        reason = "the ProductProof/FinishService boundary is the record's owner, not a state reader"
    )]
    pub fn product_proof_parked(
        &self,
        inputs: ProductProofStageInputs<'_>,
    ) -> Result<ProductProofStatus, ProductProofRecordError> {
        text_field(inputs.finish_authority_ref, "finish_authority_ref")?;
        text_field(inputs.proof_ceiling, "proof_ceiling")?;
        // The source revision is bound through `ReportInputRevision::new`, so
        // the recorded digest is the digest of the exact retained finish
        // bytes rather than a digest copied from, or invented for, a caller.
        // The absence of an accepted decision is itself the retained fact, so
        // its bytes are the recorded absence marker, not a substitute receipt.
        let observed_by = ReportInputRevision::new(
            ReportInputSource::ProductSupport,
            inputs.finish_authority_ref,
            1,
            retained_source_bytes(&inputs).as_bytes(),
        )
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        let retained = ProductProofRetainedEvidence {
            raw_log_refs: inputs.raw_log_refs.to_vec(),
            executable: inputs.executable.clone(),
            environment: inputs.environment.clone(),
            stage_receipts: ProductProofStageReceipts {
                // Always the missing form: a parked record has no observation,
                // so the stage cites no receipt the record cannot justify.
                installed_route: installed_route_receipt(None),
            },
        };
        // Read the observation back off the retained stage rather than carrying
        // a second literal `false` beside it, so the one place that decides the
        // parked stage is the only place the fact can come from.
        let installed_route_observed = retained.installed_route_observed();
        let build_evidence = build_evidence(inputs.proof_ceiling, &observed_by)?;
        let missing_evidence = missing_evidence(&retained, build_evidence.is_some());
        let reason = proof_reason(
            inputs.finish_authority_ref,
            installed_route_observed,
            build_evidence.is_some(),
        );
        let authority = ProductProofAuthority::new(
            PRODUCT_PROOF_OWNER,
            format!("eliot.governor.finish/{}", inputs.finish_authority_ref),
        )
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
        // The parked state is a block imposed by the owner authority, not an
        // unknown: the required installed Windows execution has never run, so
        // the record is BLOCKED with its factual reason and authority rather
        // than an optimistic unknown that could later read as a partial pass.
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
    /// observed for that run; the owner supplies the observed outcome, the
    /// factual reason, the still-missing evidence, and the updated retained
    /// evidence. Identity, authority, and build evidence are carried forward
    /// from `previous`, so one acceptance item keeps one record across
    /// attempts rather than accumulating a parallel one. The fail-closed pass
    /// rule is unchanged: `PASS` still requires an observed installed-route
    /// execution, no missing evidence, and a succeeded run.
    #[allow(
        clippy::unused_self,
        reason = "the ProductProof/FinishService boundary is the record's owner, not a state reader"
    )]
    pub fn revise_product_proof_status(
        &self,
        previous: &ProductProofStatus,
        revision: ProductProofRevision<'_>,
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
/// These are the values the acceptance owner read from the run it actually
/// observed. The owner derives the attempt's failure class and semantic outcome
/// from the same run, so the two axes cannot disagree about what happened.
pub struct ProductProofRevision<'a> {
    /// The attempt's own identity, lifecycle position, and failure class.
    pub attempt: ProductProofRunAttempt,
    /// The exact I18.24 outcome observed for the required product property.
    pub outcome: VerificationOutcome,
    /// Factual reason for that outcome, in one clause.
    pub reason: &'a str,
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
            "finish stage field {field} must be non-blank and contain no control characters"
        )));
    }
    Ok(())
}

/// The exact retained finish bytes this record was read from.
///
/// These are the identities the owner already recorded for this evaluation:
/// the accepted decision's receipt digest and the retained runtime receipt
/// reference, each rendered as the literal `absent` marker when the owner holds
/// no such receipt. Binding the source revision to this text means the record
/// cites what the owner actually held. No stage value, digest, or timestamp is
/// produced here — only the presence or absence of an owner-held receipt.
fn retained_source_bytes(inputs: &ProductProofStageInputs<'_>) -> String {
    format!(
        "finish-authority={}|decision-receipt={}|runtime-receipt={}|proof-ceiling={}",
        inputs.finish_authority_ref,
        inputs.decision_receipt_digest.unwrap_or("absent"),
        inputs.runtime_receipt_ref.unwrap_or("absent"),
        inputs.proof_ceiling,
    )
}

/// Derives the installed-route stage receipt from the retained runtime receipt.
///
/// An observed runtime receipt is cited by identity. Its absence is an
/// explicit `Missing` stage naming what the absent execution would have
/// proven, so an absent launch receipt can never be read as a success.
fn installed_route_receipt(runtime_receipt_ref: Option<&str>) -> ProductProofStageReceipt {
    match runtime_receipt_ref {
        Some(receipt_ref) => ProductProofStageReceipt::Observed {
            receipt_id: receipt_ref.to_owned(),
        },
        None => ProductProofStageReceipt::Missing {
            required_proof:
                "installed Windows route pulse executed end to end on the target generation"
                    .to_owned(),
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
/// The installed-route stage is compared by content against its own recorded
/// requirement, and the build handle is checked for presence, so this list is
/// derived from the record's retained evidence rather than supplied by the
/// caller.
fn missing_evidence(
    retained: &ProductProofRetainedEvidence,
    build_evidence_present: bool,
) -> Vec<String> {
    let mut missing = Vec::new();
    if !retained.installed_route_observed() {
        if let ProductProofStageReceipt::Missing { required_proof } =
            &retained.stage_receipts.installed_route
        {
            missing.push(required_proof.clone());
        }
    }
    if !build_evidence_present {
        missing.push("release build evidence for the exact candidate".to_owned());
    }
    missing
}

/// The factual reason recorded for the parked state.
///
/// The reason states what was evaluated and what is absent; it asserts no
/// product pass and claims no installed execution.
fn proof_reason(
    finish_authority_ref: &str,
    installed_route_observed: bool,
    build_evidence_present: bool,
) -> String {
    let build = if build_evidence_present {
        "release build evidence retained"
    } else {
        "release build evidence absent"
    };
    if installed_route_observed {
        format!(
            "installed Windows route receipt observed for acceptance authority {finish_authority_ref}; {build}"
        )
    } else {
        format!(
            "installed Windows route has never executed for acceptance authority {finish_authority_ref}; {build}"
        )
    }
}

/// Fails closed when a rollup and the record it summarizes disagree.
///
/// A rollup may only report `Pass` when the record itself validated through
/// its own `validate()`, its outcome is `PASS`, and the required installed-route
/// execution was actually observed. This check reads the record rather than
/// trusting the caller's summary, so a rollup can never present a product proof
/// as proven while the installed-route execution is absent.
///
/// This is a free function rather than a method on [`ProductProofRollup`]
/// because the rollup is owned by `eliot-reports` and Rust forbids an inherent
/// impl for a foreign type. The check is the acceptance owner's, not the
/// record's: the contract's own `rollup()` is the single producer of a
/// disposition, and this re-reads that producer's output against the record it
/// came from rather than declaring a second verdict or a second taxonomy.
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
/// The mapping reuses the existing eight-state finish vocabulary and the
/// I18.24 outcome type; it declares no new outcome axis. An execution
/// position is mapped separately, so a launch failure is never conflated with
/// a policy block.
pub fn outcome_of_decision(decision: &FinishDecision) -> VerificationOutcome {
    match decision.outcome {
        FinishDecisionOutcome::VerifiedComplete => VerificationOutcome::Pass,
        FinishDecisionOutcome::FailedVerification => VerificationOutcome::Fail,
        FinishDecisionOutcome::Partial => VerificationOutcome::Partial,
        FinishDecisionOutcome::DegradedNoProof => VerificationOutcome::Unknown,
        FinishDecisionOutcome::Blocked => VerificationOutcome::Blocked,
        FinishDecisionOutcome::Cancelled => VerificationOutcome::Cancelled,
        FinishDecisionOutcome::Superseded | FinishDecisionOutcome::UnsafeToFinish => {
            VerificationOutcome::Unknown
        }
    }
}

/// The I18.22 failure class this owner records for an incomplete attempt.
///
/// The class is kept on the separate execution axis from the semantic outcome,
/// so why a run did not complete stays distinct from what it would have
/// proven. A `Succeeded` execution is not an incomplete attempt and is
/// refused by the record builder rather than being given a class here.
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
