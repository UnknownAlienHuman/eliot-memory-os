//! Durable owner surface for research exchange jobs (issue #1766).
//!
//! I21.11: "The federation is asynchronous and durable: jobs expose progress,
//! cancellation, partial results, source coverage and terminal disposition",
//! and "Pending exports/imports remain durable exchange jobs and resume by
//! idempotency identity rather than duplicate transfer". The in-memory
//! `ExchangeSnapshot` is not that durability: it lives and dies with the
//! process that holds it. This module is the owner's durable seam over
//! `ExchangeJobLifecycleRecord`. It persists one job's record through the
//! store-neutral `ExchangeJobLedger`, resumes an interrupted exchange from that
//! store by idempotency identity, and projects the typed dependent-inquiry gap
//! one job's degradation opens for a current task.
//!
//! It adds no database, no remote-store fallback, no scheduler and no provider
//! launcher. The store implementation belongs to the owning ELIOT store, and a
//! store failure stays a typed failure instead of a silently lost job.

use eliot_research_exchange_api::{
    CancellationState, ExchangeJobLedger, ExchangeJobLifecycleRecord, ResearchContractError,
    ResearchHeldSourceGap, ResearchQueryRequest,
};
use thiserror::Error;

use crate::{ExchangeError, ExchangeJob, ExchangeStatus, GovernedExchange, ResearchBridge};

/// Typed durable-exchange failure. Every variant names one cause: a store
/// failure keeps the owner's own typed error instead of collapsing into a
/// string, and a divergence between the stored identity and the presented
/// request stays a conflict instead of becoming a second transfer.
#[derive(Debug, Error)]
pub enum DurableExchangeError<E: std::error::Error + Send + Sync + 'static> {
    /// The supplied request or durable record is invalid under the research
    /// contract.
    #[error("research contract rejected: {0}")]
    Contract(#[from] ResearchContractError),
    /// The live exchange holds no job with the presented identity.
    #[error("exchange refused the presented identity: {0}")]
    UnknownJob(#[from] ExchangeError),
    /// The owning durable store failed to read or write the record. The owner's
    /// own typed failure is preserved instead of collapsing into a string; it is
    /// not a blanket conversion, so a store that reports a contract failure
    /// still names the store as its cause.
    #[error("durable exchange store failed: {0}")]
    Store(E),
    /// The owning durable store holds no record for this idempotency identity.
    #[error("no durable exchange record answers this idempotency identity")]
    UnboundIdentity,
    /// The idempotency identity is already bound to different request content.
    #[error("exchange idempotency key is already bound to different content")]
    IdempotencyConflict,
}

impl<B> GovernedExchange<B> {
    /// The durable lifecycle record of one job, exactly as this exchange holds
    /// it: the identity, idempotency key, progress, cancellation state,
    /// partial bundles, coverage limits, disclosure and invalidation state, and
    /// the terminal typed outcome this job reached.
    pub fn lifecycle_record(
        &self,
        job_id: &str,
    ) -> Result<ExchangeJobLifecycleRecord, ExchangeError> {
        self.snapshot
            .jobs
            .get(job_id)
            .map(|job| job.lifecycle.clone())
            .ok_or(ExchangeError::NotFound)
    }

    /// The typed dependent-inquiry gap this job's degradation opens for one
    /// dependent current task.
    ///
    /// I21.11: "If the required bundle cannot be fetched or its
    /// disclosure/source generation cannot be verified, the dependent inquiry
    /// returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`, while
    /// unrelated local cognitive work continues." `None` means this job declares
    /// no such gap for the named inquiry, so that inquiry continues on its own
    /// evidence. The call is a pure projection: it changes nothing, which keeps
    /// the failure localized to the dependent external-knowledge dependency
    /// (I21.13).
    pub fn dependent_inquiry_gap(
        &self,
        job_id: &str,
        inquiry_id: &str,
    ) -> Result<Option<ResearchHeldSourceGap>, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get(job_id)
            .ok_or(ExchangeError::NotFound)?;
        Ok(job.lifecycle.dependent_inquiry_gap(inquiry_id)?)
    }
}

impl<B: ResearchBridge> GovernedExchange<B> {
    /// Persists the durable lifecycle record of one job through the owning
    /// store, keyed by the record's own idempotency key.
    ///
    /// The record is validated before it leaves this exchange, so a store never
    /// receives a record whose identity, progress or terminal outcome its owner
    /// did not accept.
    pub fn persist_lifecycle<L: ExchangeJobLedger>(
        &self,
        job_id: &str,
        ledger: &mut L,
    ) -> Result<ExchangeJobLifecycleRecord, DurableExchangeError<L::Error>> {
        let record = self.lifecycle_record(job_id)?;
        record.validate()?;
        ledger
            .store(record.clone())
            .map_err(DurableExchangeError::Store)?;
        Ok(record)
    }

    /// Resumes an interrupted exchange from the owning store by idempotency
    /// identity and reports the prior progress and partial results it
    /// preserved.
    ///
    /// The stored record must bind this exact request content: a divergence is
    /// an idempotency conflict, never a second transfer. The record is
    /// re-validated on load, so a record the store no longer hashes to is
    /// refused instead of replayed. The bridge is not contacted here; once the
    /// job is restored, a later `submit` of the same idempotency key is served
    /// from the restored job and cannot mint a second provider job.
    pub fn resume_from_ledger<L: ExchangeJobLedger>(
        &mut self,
        idempotency_key: &str,
        request: &ResearchQueryRequest,
        ledger: &L,
    ) -> Result<ExchangeJobLifecycleRecord, DurableExchangeError<L::Error>> {
        request.validate()?;
        let record = ledger
            .load(idempotency_key)
            .map_err(DurableExchangeError::Store)?
            .ok_or(DurableExchangeError::UnboundIdentity)?;
        record.validate()?;
        if record.idempotency_key != idempotency_key
            || record.request_digest != ExchangeJobLifecycleRecord::request_digest(request)?
        {
            return Err(DurableExchangeError::IdempotencyConflict);
        }
        self.restore_lifecycle(record.clone(), request);
        Ok(record)
    }

    /// Rehydrates one durable record into the live exchange, so a resumed
    /// exchange keeps the identity, progress, cancellation state and partial
    /// results its record preserved.
    ///
    /// A record that already reached its terminal outcome is restored as a
    /// closed job without the delivered evidence: the evidence owner holds those
    /// bytes, and this exchange never claims a finished job it cannot prove.
    /// Such a job therefore fails closed on export and handoff audit until the
    /// evidence owner restores it.
    fn restore_lifecycle(
        &mut self,
        record: ExchangeJobLifecycleRecord,
        request: &ResearchQueryRequest,
    ) {
        if self.snapshot.jobs.contains_key(&record.job_id) {
            // A store read never regresses a live exchange: the live job already
            // holds the admitted request and at least the stored progress.
            return;
        }
        let job = ExchangeJob {
            exchange_id: record.exchange_id.clone(),
            job_id: record.job_id.clone(),
            state_fence: request.state_fence.clone(),
            request: request.clone(),
            status: resumed_status(&record),
            progress_units: record.progress.spent_units,
            result: None,
            failure: None,
            lifecycle: record.clone(),
        };
        self.snapshot
            .idempotency
            .insert(record.idempotency_key, job.job_id.clone());
        self.snapshot.jobs.insert(job.job_id.clone(), job);
    }
}

/// The live status a rehydrated durable record resumes at. The record carries
/// the lifecycle facts; the live status is their projection, so a restored job
/// never claims more than its record proves.
fn resumed_status(record: &ExchangeJobLifecycleRecord) -> ExchangeStatus {
    if record.is_terminal() {
        ExchangeStatus::Completed
    } else if record.cancellation.is_confirmed() {
        ExchangeStatus::Cancelled
    } else if matches!(record.cancellation, CancellationState::Requested { .. }) {
        ExchangeStatus::CancelRequested
    } else if record.has_prior_progress() {
        ExchangeStatus::Partial
    } else {
        ExchangeStatus::Accepted
    }
}
