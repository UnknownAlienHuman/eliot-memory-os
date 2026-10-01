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
//! installed-route execution was actually observed. The record itself refuses a
//! `PASS` that carries no attempt, an attempt that did not succeed, or no
//! runtime-domain live evidence handle, so those cases never reach the rollup.
//! Every other case returns the exact refusal carrying outcome, reason,
//! authority, and required missing evidence.
//!
//! Every evidence handle the record publishes is inside the canonical bytes its
//! source digest is computed over, so the digest distinguishes two records that
//! differ in any retained identity rather than colliding on a subset of them.

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
        inputs: &ProductProofStageInputs<'_>,
    ) -> Result<ProductProofStatus, ProductProofRecordError> {
        text_field(inputs.finish_authority_ref, "finish_authority_ref")?;
        text_field(inputs.proof_ceiling, "proof_ceiling")?;
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
        retained_identities(&retained)?;
        // The retained evidence is built first and the source digest is taken
        // from it second, so the binding is computed over state that already
        // exists rather than over a subset chosen before the record was
        // assembled. The absence of an accepted decision stays an absent
        // optional in the canonical bytes, so it is recorded as an absence
        // rather than folded into a substitute value.
        let source_bytes = retained_source_bytes(inputs, &retained)?;
        // The source revision is bound through `ReportInputRevision::new`, so
        // the recorded digest is the digest of the exact retained finish
        // bytes rather than a digest copied from, or invented for, a caller.
        let observed_by = ReportInputRevision::new(
            ReportInputSource::ProductSupport,
            inputs.finish_authority_ref,
            1,
            &source_bytes,
        )
        .map_err(|error| ProductProofRecordError::Record(error.to_string()))?;
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
    /// attempts rather than accumulating a parallel one. An installed-route
    /// receipt that a prior attempt actually observed is carried forward too,
    /// because an observation the owner really made is not retracted by a later
    /// attempt that carried no receipt of its own. The fail-closed pass rule is
    /// unchanged: `PASS` still requires an observed installed-route execution,
    /// no missing evidence, a succeeded run, and at least one runtime-domain
    /// live evidence handle.
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
        // An observed installed-route receipt is a retained observation, not a
        // per-attempt claim: it names the installed-route execution that
        // actually ran, so it stays observed once it has been observed. A later
        // revision that dropped it would silently retract an observation that
        // nothing ever proved false, and would leave a record that had already
        // observed the route reading that it had not. The observation is
        // therefore carried forward unless this very revision re-establishes it
        // from its own receipt, and a record carrying an observation must also
        // carry live evidence on the runtime domain or the rollup is refused.
        let retained = if revision.retained.installed_route_observed() {
            revision.retained
        } else if previous.retained.installed_route_observed() {
            let mut carried = revision.retained;
            carried.stage_receipts.installed_route =
                previous.retained.stage_receipts.installed_route.clone();
            carried
        } else {
            revision.retained
        };
        let status = previous
            .record_attempt(
                revision.attempt,
                revision.outcome,
                revision.reason,
                revision.missing_evidence,
                revision.live_evidence,
                retained,
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

/// The exact retained finish bytes this record is read from and bound to.
///
/// The digest this record carries must bind the evidence it is published
/// beside, not a subset of it. The previous preimage named only four receipt
/// identities, so the retained executable identity, the environment identity
/// and every retained raw log handle fell outside the digest: two parked
/// records built from a different executable, a different environment or a
/// different log handle set produced a byte-identical preimage and therefore a
/// byte-identical `input_digest`, while the records themselves differed in the
/// very identities a product proof exists to publish. A digest that cannot
/// distinguish those records detects nothing about them.
///
/// The preimage is therefore the canonical serialisation of the retained
/// evidence itself, plus the finish identities that are not part of it. This
/// reuses the existing [`ReportInputRevision`] digest helper and the existing
/// `eliot_contracts::canonical_json_bytes` canonicaliser: no new digest
/// scheme, no new domain-separation constant and no parallel hasher is
/// introduced. Canonical JSON sorts object keys recursively, so field order
/// cannot produce two digests for one record, and an absent optional
/// serialises as JSON `null` rather than as the literal string `absent`, so an
/// absent receipt is distinguishable from a receipt whose identity is the
/// seven characters `absent`.
///
/// The digest is computed over state that already exists — the retained
/// evidence is assembled before this is called — so the binding is not
/// evaluated over partially-populated input.
fn retained_source_bytes(
    inputs: &ProductProofStageInputs<'_>,
    retained: &ProductProofRetainedEvidence,
) -> Result<Vec<u8>, ProductProofRecordError> {
    eliot_contracts::canonical_json_bytes(&serde_json::json!({
        "finish_authority_ref": inputs.finish_authority_ref,
        "proof_ceiling": inputs.proof_ceiling,
        "decision_receipt_digest": inputs.decision_receipt_digest,
        "runtime_receipt_ref": inputs.runtime_receipt_ref,
        "retained": retained,
    }))
    .map_err(|error| ProductProofRecordError::Record(error.to_string()))
}

/// Refuses retained identities that cannot bind anything.
///
/// The digest above is computed over these identities, so an empty one would
/// let an unbound record hash exactly like a bound one. The record's own
/// `validate()` already refuses blank and control-bearing text for the
/// executable name, the platform and every log handle; this checks the two
/// optional halves that `validate()` admits as `None` and that therefore have
/// no text to refuse, so a caller cannot drop an optional identity and still
/// receive a digest that claims to cover it.
fn retained_identities(
    retained: &ProductProofRetainedEvidence,
) -> Result<(), ProductProofRecordError> {
    if let Some(executable) = &retained.executable {
        text_field(&executable.executable_name, "retained.executable_name")?;
        if let Some(content_digest) = &executable.content_digest {
            text_field(content_digest, "retained.executable.content_digest")?;
        }
    }
    if let Some(environment) = &retained.environment {
        text_field(&environment.platform, "retained.environment.platform")?;
        if let Some(installation_id) = &environment.installation_id {
            text_field(installation_id, "retained.environment.installation_id")?;
        }
    }
    Ok(())
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
