//! Whether a maintenance source result's observation is durably recorded, and
//! what is still owed when it is not.
//!
//! Work performed, an observation durably recorded, and actual improvement are
//! three different facts. This module keeps the first two apart and never
//! asserts the third:
//!
//! * **Work performed** is what the source transition persisted: the
//!   [`MaintenanceJob`](crate::MaintenanceJob) lifecycle state and the
//!   [`MaintenanceResultObligation`](crate::MaintenanceResultObligation) chain
//!   its result-bearing transitions appended.
//! * **An observation durably recorded** is a store receipt the canonical
//!   observation route actually returned. Only that receipt can produce it; a
//!   publication identity, a lifecycle state, or the presence of the job's own
//!   `outcome_ref` are all references a caller could predict, and none of them
//!   is an admission.
//! * **Actual improvement** is never derived here. It belongs to the
//!   observation contract's utility evaluation over admitted metric evidence —
//!   `MaintenanceResultV1` already refuses a `BENEFICIAL` verdict without
//!   complete, unblinded evidence for every required metric — and nothing in
//!   this module writes a verdict.
//!
//! Two rules follow, and they are the point of the module:
//!
//! * **No back-filling.** A job that reached a result state while no admitted
//!   observation exists for it is
//!   [`MaintenanceOutcomeDisposition::ObservationOwed`]: an explicit
//!   outstanding obligation carrying a visible owner and a named resolution
//!   condition. Its execution history is left exactly as the transition
//!   recorded it, no outcome is written after the fact, and nothing is
//!   reconciled to make the record look consistent.
//! * **Completeness is measured against an independent expected set.** The
//!   declared set of jobs that owe an outcome is supplied by the caller from
//!   the durable trigger and decision records; it is never rebuilt from the
//!   obligations a coverage pass happens to be walking. A job in that set with
//!   no retained revision is unavailable, not observed.

use eliot_observation_contracts::{MaintenanceDeliveryState, MaintenanceExecutionOutcome};

use crate::result_obligation::{publication_id_for, result_outcome};
use crate::{MaintenanceError, MaintenanceJob};

/// The owner accountable for discharging a maintenance result-to-observation
/// obligation.
///
/// This is the maintenance contract that owns the decision and the durable job
/// revision, not a label derived from the job: a per-job name is not an owner.
pub const OUTCOME_OBSERVATION_OWNER: &str = crate::CONTRACT_NAME;

/// The condition that discharges one outstanding result-to-observation
/// obligation.
///
/// Stated as the thing that can be checked, not as a promise: the canonical
/// observation route must return a store receipt for this exact publication
/// identity. A completed job, a written outcome reference and a diagnostic line
/// discharge nothing.
pub const OUTCOME_OBSERVATION_RESOLUTION: &str =
    "the canonical observation route returns a store receipt for this exact publication identity";

/// One observation the canonical observation route actually admitted.
///
/// The store receipt is the admission. A publication identity on its own is a
/// reference a caller could have predicted, so this type exists to make the
/// admitted set fillable only from a value the route returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedObservationReceipt {
    /// The exact publication identity the admitted record carries.
    pub publication_id: String,
    /// The exact store receipt the canonical owner returned for it.
    pub observation_receipt_ref: String,
}

impl AdmittedObservationReceipt {
    /// Validates that this receipt names exactly one admitted observation.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] when either identity is
    /// empty or carries a control character. An admission that cannot be named
    /// cannot be checked against anything, so it is refused rather than
    /// counted.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.publication_id, "admitted_observation.publication_id")?;
        text(
            &self.observation_receipt_ref,
            "admitted_observation.observation_receipt_ref",
        )
    }
}

/// One performed maintenance result whose observation is not durably
/// recorded.
///
/// This is the outstanding obligation, and it is recorded rather than
/// resolved. The job's execution history stays exactly as the transition left
/// it; the only thing that discharges this is the named condition, satisfied
/// by an admitted store receipt under the same publication identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutstandingOutcomeObligation {
    /// The durable job whose transition performed the work.
    pub job_ref: String,
    /// The exact publication identity that owes an admitted observation.
    pub publication_id: String,
    /// The work that was actually performed. Preserved so the obligation never
    /// reads as though the work itself is in doubt.
    pub work_performed: MaintenanceExecutionOutcome,
    /// The visible owner accountable for discharging the obligation.
    pub obligation_owner: String,
    /// The exact condition that discharges it.
    pub resolution_condition: String,
}

/// What is durably known about the observation one maintenance job owes.
///
/// The arms are separate facts. Collapsing any two of them is the defect this
/// type exists to prevent: work performed is not an admitted observation, and
/// neither one is evidence that the maintained subsystem improved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceOutcomeDisposition {
    /// The job has reached no result-bearing lifecycle state, so it owes no
    /// observation. `ADMITTED`, `RUNNING` and `DEFERRED` are not results, and
    /// their non-execution consequences are recorded through the decision's own
    /// obligation rather than invented here.
    NoResultDeclared,
    /// The job performed work and an observation for that exact publication
    /// identity was admitted with an exact store receipt. The observation
    /// records the result; it does not assert that the maintained subsystem
    /// improved.
    ResultObserved {
        /// The admitted publication identity.
        publication_id: String,
        /// The exact store receipt that proves the admission.
        observation_receipt_ref: String,
    },
    /// The job performed work and no observation has been admitted for it.
    ///
    /// This is an explicit outstanding obligation. It is never reconciled
    /// against a plausible outcome and never back-filled with one written
    /// after the fact.
    ObservationOwed(OutstandingOutcomeObligation),
}

/// One job identity the maintenance owner declares owes an outcome
/// observation.
///
/// This is the independent expected set: it is declared from the durable
/// trigger and decision records, never rebuilt from the obligations a coverage
/// pass happens to be walking. A completeness claim measured against the list
/// it is iterating proves nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedOutcomeObservation {
    /// The durable job identity that owes an outcome observation.
    pub job_id: String,
}

/// One declared job's admitted result observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedOutcomeObservation {
    /// The durable job identity.
    pub job_id: String,
    /// The admitted publication identity.
    pub publication_id: String,
    /// The exact store receipt that proves the admission.
    pub observation_receipt_ref: String,
}

/// One declared job that is not fully observed.
///
/// Each arm is outstanding on the observation path, and none of them is a
/// reconciled result. One is an explicit obligation over work that really
/// happened, one is a revision that could not be read at all, and one is a
/// declared job that has not reached a result state — its owed outcome does not
/// exist yet rather than having been lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutstandingOutcome {
    /// The job performed work and no observation was admitted for it.
    ObservationOwed(OutstandingOutcomeObligation),
    /// The declared job has no retained revision in the set that was read.
    RevisionUnavailable {
        /// The durable job identity the expected set declared.
        job_ref: String,
    },
    /// The declared job is retained but has reached no result-bearing state, so
    /// it owes no outcome yet. Kept distinct from an admitted observation and
    /// from a lost one.
    NoResultDeclared {
        /// The durable job identity the expected set declared.
        job_ref: String,
    },
}

/// Outcome-observation completeness for one independently declared set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutcomeObservationCoverage {
    /// Declared jobs whose owed result observation is admitted, each with the
    /// exact receipt that proves it.
    pub observed: Vec<ObservedOutcomeObservation>,
    /// Every declared job that is not fully observed, in declaration order.
    pub outstanding: Vec<OutstandingOutcome>,
}

impl OutcomeObservationCoverage {
    /// Whether every declared job's owed observation is admitted.
    ///
    /// A coverage claim is true only when nothing is outstanding. An
    /// unreadable revision keeps it false, so an unavailable read cannot be
    /// reported as complete coverage.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outstanding.is_empty()
    }
}

/// The result this job's own current state owes an observation for, as the
/// publication identity that owes it and the work that was performed.
///
/// Read from the job's retained obligation history when it recorded one, and
/// otherwise derived from the exact lifecycle state and attempt ordinal. A
/// result-bearing state whose obligation was never recorded still owes one,
/// and that is exactly the case this derivation exists to keep visible: a
/// completed job with no obligation is not a job with nothing to observe.
fn owed_result(job: &MaintenanceJob) -> Option<(String, MaintenanceExecutionOutcome)> {
    if let Some(latest) = job.result_obligations.last() {
        return Some((latest.publication_id.clone(), latest.execution_outcome));
    }
    result_outcome(job.state).map(|outcome| {
        (
            publication_id_for(&job.job_id, job.state, job.attempts),
            outcome,
        )
    })
}

/// Decides what the observation path actually holds for one job that owes an
/// outcome.
///
/// `admitted` is the independent admitted set: it is filled only from store
/// receipts the canonical route returned, never from the obligation list this
/// function reads. The job's own `outcome_ref` is deliberately not consulted:
/// it is a reference the transition recorded, and a dangling reference is a
/// broken link rather than evidence that an observation exists.
///
/// # Errors
///
/// Returns [`MaintenanceError`] when the retained job revision fails its own
/// validation, or when an admitted receipt does not name one observation.
pub fn outcome_observation_disposition(
    job: &MaintenanceJob,
    admitted: &[AdmittedObservationReceipt],
) -> Result<MaintenanceOutcomeDisposition, MaintenanceError> {
    job.validate()?;
    for receipt in admitted {
        receipt.validate()?;
    }
    let Some((publication_id, work_performed)) = owed_result(job) else {
        return Ok(MaintenanceOutcomeDisposition::NoResultDeclared);
    };
    // The admission test: an entry in the receipt set whose publication
    // identity is exactly the identity this job owes. A receipt for any other
    // identity settles nothing, and the job's own outcome reference settles
    // nothing.
    match admitted
        .iter()
        .find(|receipt| receipt.publication_id == publication_id.as_str())
    {
        Some(receipt) => Ok(MaintenanceOutcomeDisposition::ResultObserved {
            publication_id,
            observation_receipt_ref: receipt.observation_receipt_ref.clone(),
        }),
        None => Ok(MaintenanceOutcomeDisposition::ObservationOwed(
            OutstandingOutcomeObligation {
                job_ref: job.job_id.clone(),
                publication_id,
                work_performed,
                obligation_owner: OUTCOME_OBSERVATION_OWNER.to_owned(),
                resolution_condition: OUTCOME_OBSERVATION_RESOLUTION.to_owned(),
            },
        )),
    }
}

/// Measures outcome-observation completeness against an independent expected
/// set of jobs that owe an outcome.
///
/// The iteration is over `expected`, never over `jobs`: a completeness claim
/// measured against the list being checked proves nothing. A declared job with
/// no retained revision in `jobs` is reported as
/// [`OutstandingOutcome::RevisionUnavailable`] rather than skipped, so an
/// unavailable read cannot disappear behind a pass over the revisions that did
/// load.
///
/// # Errors
///
/// Returns [`MaintenanceError::InvalidField`] when a declared job identity is
/// empty or carries a control character, [`MaintenanceError::IdentityConflict`]
/// when the expected set names one job twice, and every
/// [`MaintenanceError`] from [`outcome_observation_disposition`].
pub fn outcome_observation_coverage(
    expected: &[ExpectedOutcomeObservation],
    jobs: &[MaintenanceJob],
    admitted: &[AdmittedObservationReceipt],
) -> Result<OutcomeObservationCoverage, MaintenanceError> {
    let mut declared = std::collections::BTreeSet::new();
    for entry in expected {
        text(&entry.job_id, "expected_outcome_observation.job_id")?;
        if !declared.insert(entry.job_id.clone()) {
            return Err(MaintenanceError::IdentityConflict);
        }
    }
    let mut coverage = OutcomeObservationCoverage {
        observed: Vec::new(),
        outstanding: Vec::new(),
    };
    for entry in expected {
        match jobs.iter().find(|job| job.job_id == entry.job_id) {
            None => coverage
                .outstanding
                .push(OutstandingOutcome::RevisionUnavailable {
                    job_ref: entry.job_id.clone(),
                }),
            Some(job) => match outcome_observation_disposition(job, admitted)? {
                MaintenanceOutcomeDisposition::NoResultDeclared => {
                    coverage
                        .outstanding
                        .push(OutstandingOutcome::NoResultDeclared {
                            job_ref: entry.job_id.clone(),
                        });
                }
                MaintenanceOutcomeDisposition::ResultObserved {
                    publication_id,
                    observation_receipt_ref,
                } => coverage.observed.push(ObservedOutcomeObservation {
                    job_id: entry.job_id.clone(),
                    publication_id,
                    observation_receipt_ref,
                }),
                MaintenanceOutcomeDisposition::ObservationOwed(obligation) => {
                    coverage
                        .outstanding
                        .push(OutstandingOutcome::ObservationOwed(obligation));
                }
            },
        }
    }
    Ok(coverage)
}

/// Records that the canonical observation route admitted one result this job
/// owed an observation for.
///
/// This is the only transition that turns the second of the three states on.
/// Before it, the obligation is `Pending`: the work happened and the
/// observation does not exist yet. After it, the obligation carries the exact
/// store receipt. It never touches the lifecycle state, the outcome reference
/// or any earlier obligation, so admitting an observation cannot rewrite the
/// execution history it observes — and it never writes an outcome, because the
/// only thing it can add is a receipt the caller already holds.
///
/// Replaying the same receipt under the same publication identity reconciles
/// and returns the retained revision unchanged. A different receipt under that
/// identity is a conflict and is refused: one source event cannot have two
/// admissions. A recorded gap is not silently upgraded either; a later
/// admission publishes a new evaluation revision under its own identity, so
/// the recorded unavailability stays visible beside it.
///
/// # Errors
///
/// Returns [`MaintenanceError::InvalidField`] when either identity is empty or
/// carries a control character, when this job owes no result observation with
/// the named publication identity, or when its delivery is already settled as
/// unavailable; [`MaintenanceError::IdentityConflict`] when a different
/// receipt is already admitted under that identity.
pub fn admit_observation_delivery(
    job: &MaintenanceJob,
    publication_id: &str,
    observation_receipt_ref: &str,
) -> Result<MaintenanceJob, MaintenanceError> {
    text(publication_id, "admitted_observation.publication_id")?;
    text(
        observation_receipt_ref,
        "admitted_observation.observation_receipt_ref",
    )?;
    let Some(index) = job
        .result_obligations
        .iter()
        .position(|obligation| obligation.publication_id == publication_id)
    else {
        // This job owes no result observation under that identity. Admitting
        // one anyway would publish under an identity the job never declared.
        return Err(MaintenanceError::InvalidField(
            "admitted_observation.publication_id",
        ));
    };
    let mut next = job.clone();
    let obligation = &mut next.result_obligations[index];
    match &obligation.delivery {
        MaintenanceDeliveryState::Published {
            observation_receipt_ref: settled,
        } if settled.as_str() == observation_receipt_ref => return Ok(job.clone()),
        MaintenanceDeliveryState::Published { .. } => {
            return Err(MaintenanceError::IdentityConflict);
        }
        MaintenanceDeliveryState::Unavailable { .. } => {
            return Err(MaintenanceError::InvalidField(
                "admitted_observation.delivery",
            ));
        }
        MaintenanceDeliveryState::Pending { .. } => {}
    }
    obligation.delivery = MaintenanceDeliveryState::Published {
        observation_receipt_ref: observation_receipt_ref.to_owned(),
    };
    next.validate()?;
    Ok(next)
}

fn text(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}
