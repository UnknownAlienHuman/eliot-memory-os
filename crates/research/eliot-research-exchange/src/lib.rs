//! Governed exchange state machine for a replaceable Research bridge.
//!
//! Every job this state machine accepts carries a durable lifecycle record
//! (`ExchangeJobLifecycleRecord`): exchange, request, job, Research system and
//! protocol identity, the idempotency key, progress, cancellation state, the
//! partial bundles already transferred, the coverage and failed-acquisition
//! detail, the disclosure and invalidation state, and the terminal typed
//! outcome. The live `ExchangeSnapshot` is only the process-local projection of
//! that record: a resumed key is served only from a record that still
//! validates, so a retry resumes the same exchange by idempotency identity
//! instead of duplicating a transfer. `DurableExchange` is the durable form: it
//! drives this one state machine and writes the record it produced through the
//! store-neutral `ExchangeJobLedger` port the owning ELIOT store implements.
//! This crate owns no database, remote-store fallback or scheduler.

#![forbid(unsafe_code)]

pub mod handoff;

use std::collections::BTreeMap;

use eliot_contracts::{ContractVersion, StateFence};
use eliot_research_exchange_api::{
    CancellationState, CompletionDisposition, ExchangeJobLedger, ExchangeJobLifecycleRecord,
    GapContinuation, IdempotentResume, ResearchContractError, ResearchEvidenceBundle,
    ResearchExportBundle, ResearchHeldSourceGap, ResearchQueryRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const EXCHANGE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Why a cancellation was recorded as issued, before the bridge was contacted.
const CANCELLATION_REQUESTED_REASON: &str = "governed cancellation request";
/// Why a cancellation was recorded as confirmed by the bridge.
const CANCELLATION_CONFIRMED_REASON: &str = "bridge confirmed the governed cancellation";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExchangeStatus {
    Accepted,
    Running,
    Partial,
    Completed,
    CancelRequested,
    Cancelled,
    Failed,
}

impl ExchangeStatus {
    /// The live status one durable record states.
    ///
    /// The live status is derived from the record, never the other way round, so
    /// a job rebuilt from a durable store cannot claim a cleaner state than the
    /// record carries. A cancellation the bridge never confirmed stays
    /// cancellation-unconfirmed rather than decoding as a clean stop, and a
    /// cancelled terminal outcome is a cancelled job however the record reached
    /// it.
    #[must_use]
    pub fn of(record: &ExchangeJobLifecycleRecord) -> Self {
        match &record.cancellation {
            CancellationState::Confirmed { .. } => return Self::Cancelled,
            CancellationState::Requested { .. } => return Self::CancelRequested,
            CancellationState::NotRequested => {}
        }
        match &record.terminal {
            Some(terminal) if terminal.disposition() == CompletionDisposition::Cancelled => {
                Self::Cancelled
            }
            Some(_) => Self::Completed,
            None if !record.transferred_partials().is_empty()
                || record.progress.spent_units > 0 =>
            {
                Self::Partial
            }
            None => Self::Accepted,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExchangeJob {
    pub exchange_id: String,
    pub job_id: String,
    pub request: ResearchQueryRequest,
    pub status: ExchangeStatus,
    pub state_fence: StateFence,
    pub progress_units: u64,
    pub result: Option<ResearchEvidenceBundle>,
    pub failure: Option<String>,
    /// The durable lifecycle record of this job. Progress, cancellation, partial
    /// results, coverage, disclosure and the terminal typed outcome are written
    /// through this record, so the live fields above never state a lifecycle
    /// fact the durable record does not carry.
    pub lifecycle: ExchangeJobLifecycleRecord,
}

impl ExchangeJob {
    /// Rebuilds the live projection of one job from its durable record.
    ///
    /// I21.11: an interrupted exchange "resume[s] by idempotency identity
    /// rather than duplicate transfer", so a retry that arrives with the
    /// identity already admitted is served the job the store holds, with the
    /// progress and partial results it had already paid for. The record is
    /// validated first, so a stored record is only ever served when it still
    /// hashes to its own digest, still satisfies its lifecycle invariants and
    /// still binds this request's canonical content digest; anything else is a
    /// conflict, never a second job.
    ///
    /// The delivered evidence stays with the evidence owner — the durable record
    /// binds its digest — so a rebuilt job carries no delivered bundle and can
    /// present no result until the owner hands that bundle back.
    pub fn resumed(
        request: ResearchQueryRequest,
        record: ExchangeJobLifecycleRecord,
    ) -> Result<Self, ExchangeError> {
        record.validate()?;
        if record.resumes(&request)? != IdempotentResume::SameJob {
            return Err(ExchangeError::IdempotencyConflict);
        }
        Ok(Self {
            status: ExchangeStatus::of(&record),
            progress_units: record.progress.spent_units,
            exchange_id: record.exchange_id.clone(),
            job_id: record.job_id.clone(),
            state_fence: record.state_fence.clone(),
            lifecycle: record,
            request,
            result: None,
            failure: None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExchangeError {
    #[error("research contract rejected: {0}")]
    Contract(#[from] ResearchContractError),
    #[error("exchange idempotency key is already bound to different content")]
    IdempotencyConflict,
    #[error("exchange job was not found")]
    NotFound,
    #[error("exchange job is not accepting this transition")]
    InvalidTransition,
    #[error("state fence is stale")]
    StaleFence,
    #[error("export is not permitted for this exchange")]
    ExportDenied,
}

pub trait ResearchBridge {
    type Error: std::error::Error + Send + Sync + 'static;
    fn submit(&mut self, request: &ResearchQueryRequest) -> Result<String, Self::Error>;
    fn cancel(&mut self, job_id: &str) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExchangeSnapshot {
    pub jobs: BTreeMap<String, ExchangeJob>,
    pub idempotency: BTreeMap<String, String>,
}

pub struct GovernedExchange<B> {
    bridge: B,
    snapshot: ExchangeSnapshot,
}

impl<B> GovernedExchange<B> {
    pub fn new(bridge: B) -> Self {
        Self {
            bridge,
            snapshot: ExchangeSnapshot::default(),
        }
    }
    pub fn from_snapshot(bridge: B, snapshot: ExchangeSnapshot) -> Self {
        Self { bridge, snapshot }
    }
    #[must_use]
    pub fn snapshot(&self) -> &ExchangeSnapshot {
        &self.snapshot
    }
    pub fn into_parts(self) -> (B, ExchangeSnapshot) {
        (self.bridge, self.snapshot)
    }

    /// Read-only resume lookup: returns the durable job bound to one
    /// idempotency key, preserving partial progress across restarts.
    /// Returns `None` when the key was never accepted.
    #[must_use]
    pub fn job_by_idempotency(&self, idempotency_key: &str) -> Option<ExchangeJob> {
        self.snapshot
            .idempotency
            .get(idempotency_key)
            .and_then(|job_id| self.snapshot.jobs.get(job_id))
            .cloned()
    }

    /// Resumes an interrupted exchange by idempotency identity without
    /// contacting the bridge: the stored request must equal the supplied
    /// request, otherwise the key is bound to different content. Partial
    /// progress (`status`, `progress_units`, delivered `result`) is preserved
    /// exactly as captured in the snapshot.
    ///
    /// The durable record is re-validated here, so a restored snapshot is
    /// served only from a record that still binds this request's canonical
    /// content digest and still satisfies its own lifecycle invariants.
    pub fn resume(
        &self,
        idempotency_key: &str,
        request: &ResearchQueryRequest,
    ) -> Result<ExchangeJob, ExchangeError> {
        request.validate()?;
        let job = self
            .job_by_idempotency(idempotency_key)
            .ok_or(ExchangeError::NotFound)?;
        if job.request != *request
            || job.lifecycle.request_digest != ExchangeJobLifecycleRecord::request_digest(request)?
        {
            return Err(ExchangeError::IdempotencyConflict);
        }
        job.lifecycle.validate()?;
        Ok(job)
    }

    /// The typed dependent-inquiry gap this job's degradation opens for one
    /// dependent current task.
    ///
    /// I21.11: "If the required bundle cannot be fetched or its
    /// disclosure/source generation cannot be verified, the dependent inquiry
    /// returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`, while
    /// unrelated local cognitive work continues." `None` means this job declares
    /// no such gap for the named inquiry, so that inquiry continues on its own
    /// evidence. The call is a pure projection over the durable record: it
    /// changes nothing, which keeps the failure localized to the dependent
    /// external-knowledge dependency (I21.13).
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

    /// Installs one job rebuilt from a durable record into the process-local
    /// projection.
    ///
    /// The duplicate-suppression is structural, not advisory: an identity this
    /// exchange already holds is never rebound, and a job identity already held
    /// under a different idempotency key is never claimed. A replayed load of
    /// the same record therefore reports the job already held instead of
    /// installing a second copy of it, so the live projection can never hold two
    /// jobs for one durable identity and a reloaded transfer cannot re-open a
    /// job that already closed.
    pub fn adopt_resumed(&mut self, job: ExchangeJob) -> Result<ExchangeJob, ExchangeError> {
        job.lifecycle.validate()?;
        let idempotency_key = job.request.idempotency_key.clone();
        if let Some(bound) = self.snapshot.idempotency.get(&idempotency_key) {
            let held = self
                .snapshot
                .jobs
                .get(bound)
                .ok_or(ExchangeError::NotFound)?;
            if held.lifecycle.record_digest != job.lifecycle.record_digest {
                return Err(ExchangeError::IdempotencyConflict);
            }
            return Ok(held.clone());
        }
        if self.snapshot.jobs.contains_key(&job.job_id) {
            return Err(ExchangeError::IdempotencyConflict);
        }
        self.snapshot
            .idempotency
            .insert(idempotency_key, job.job_id.clone());
        self.snapshot.jobs.insert(job.job_id.clone(), job.clone());
        Ok(job)
    }
}

impl<B: ResearchBridge> GovernedExchange<B> {
    /// Accepts one query, or resumes the interrupted exchange already bound
    /// to its idempotency key with partial progress preserved.
    pub fn submit(&mut self, request: ResearchQueryRequest) -> Result<ExchangeJob, ExchangeError> {
        self.admit(request).map(|admission| admission.job().clone())
    }

    /// Accepts one query, or resumes the interrupted exchange already bound to
    /// its idempotency key, and reports which of the two happened.
    ///
    /// A resumed key never re-contacts the bridge, so at most one provider job
    /// exists per identity. A resumed job is served only from a durable record
    /// that still validates, so a restored snapshot can never decode a drifted
    /// record as a live job.
    pub fn admit(
        &mut self,
        request: ResearchQueryRequest,
    ) -> Result<ExchangeAdmission, ExchangeError> {
        request.validate()?;
        if let Some(job_id) = self.snapshot.idempotency.get(&request.idempotency_key) {
            let existing = self
                .snapshot
                .jobs
                .get(job_id)
                .ok_or(ExchangeError::NotFound)?;
            if existing.request != request {
                return Err(ExchangeError::IdempotencyConflict);
            }
            existing.lifecycle.validate()?;
            return Ok(ExchangeAdmission::Resumed(existing.clone()));
        }
        let job_id = self
            .bridge
            .submit(&request)
            .map_err(|_| ExchangeError::InvalidTransition)?;
        if job_id.trim().is_empty() {
            return Err(ExchangeError::InvalidTransition);
        }
        let job = ExchangeJob {
            exchange_id: request.exchange_id.clone(),
            job_id: job_id.clone(),
            state_fence: request.state_fence.clone(),
            lifecycle: ExchangeJobLifecycleRecord::opened(&request, &job_id)?,
            request,
            status: ExchangeStatus::Accepted,
            progress_units: 0,
            result: None,
            failure: None,
        };
        self.snapshot
            .idempotency
            .insert(job.request.idempotency_key.clone(), job_id.clone());
        self.snapshot.jobs.insert(job_id, job.clone());
        Ok(ExchangeAdmission::Started(job))
    }

    pub fn mark_running(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.transition(job_id, fence, ExchangeStatus::Running)
    }

    pub fn record_progress(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        units: u64,
    ) -> Result<ExchangeJob, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
        if job.state_fence != *fence
            || !matches!(
                job.status,
                ExchangeStatus::Accepted | ExchangeStatus::Running | ExchangeStatus::Partial
            )
        {
            return Err(ExchangeError::InvalidTransition);
        }
        job.lifecycle = job.lifecycle.advanced(units)?;
        job.status = ExchangeStatus::Partial;
        job.progress_units = job.lifecycle.progress.spent_units;
        Ok(job.clone())
    }

    /// Records verified partial evidence for a running job.
    ///
    /// I21.11: jobs expose partial results, so the durable record keeps what
    /// this exchange already transferred under the bound job identity and an
    /// interrupted exchange can report it instead of repeating the transfer. A
    /// running job cannot present a closable disposition as partial work: only
    /// a terminal close may, and only through the supported-close witness.
    pub fn record_partial_bundle(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        units: u64,
        bundle: &ResearchEvidenceBundle,
    ) -> Result<ExchangeJob, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
        if job.state_fence != *fence
            || !matches!(
                job.status,
                ExchangeStatus::Accepted | ExchangeStatus::Running | ExchangeStatus::Partial
            )
        {
            return Err(ExchangeError::InvalidTransition);
        }
        bundle.validate_against(&job.request)?;
        if bundle.disposition.may_close_inquiry() {
            return Err(ExchangeError::Contract(
                ResearchContractError::InvalidDisposition,
            ));
        }
        job.lifecycle = job.lifecycle.with_partial(bundle, units)?;
        job.status = ExchangeStatus::Partial;
        job.progress_units = job.lifecycle.progress.spent_units;
        Ok(job.clone())
    }

    /// Closes one job with a delivered evidence bundle.
    ///
    /// This is the I21.7 pre-promotion firewall: the delivered bundle is
    /// validated against the admitted request, so every citation must be a
    /// manifest-admitted handle at a permitted anchor precision with delivered
    /// source lineage behind it, every delivered source handle must itself be
    /// admitted, every absolute external locator URL must be an admitted URL
    /// handle, every delivered artifact handle must be admitted, and every typed
    /// coverage-gap handle must be admitted too — the handoff seal publishes
    /// `coverage_gap_handles` inside its own digest, so an unadmitted gap handle
    /// would cross a sealed boundary. A bundle that fails any of these is
    /// refused and never becomes this job's result, so it can produce no
    /// evidence edge and no supported citation.
    pub fn import_bundle(
        &mut self,
        bundle: ResearchEvidenceBundle,
    ) -> Result<ExchangeJob, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get_mut(&bundle.job_id)
            .ok_or(ExchangeError::NotFound)?;
        bundle.validate_against(&job.request)?;
        if !matches!(
            job.status,
            ExchangeStatus::Accepted | ExchangeStatus::Running | ExchangeStatus::Partial
        ) {
            return Err(ExchangeError::InvalidTransition);
        }
        // A13.11: on budget exhaustion paid jobs stop while verified partial
        // work AND the coverage gap remain. The durable record fails the close
        // closed when a spent budget hides its exhaustion behind other gap
        // kinds, so degradation stays visible and local (ARCH-RES-04).
        job.lifecycle = job
            .lifecycle
            .closed(&bundle, GapContinuation::declared_by(&bundle))?;
        job.result = Some(bundle);
        job.status = ExchangeStatus::Completed;
        Ok(job.clone())
    }

    pub fn cancel(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<ExchangeJob, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
        if job.state_fence != *fence
            || matches!(
                job.status,
                ExchangeStatus::Completed | ExchangeStatus::Cancelled | ExchangeStatus::Failed
            )
        {
            return Err(ExchangeError::InvalidTransition);
        }
        // The issued cancellation is recorded durably before the bridge is
        // contacted: an interruption in between leaves the job
        // cancellation-unconfirmed instead of decoding as a clean stop.
        job.lifecycle = job
            .lifecycle
            .cancellation_requested(CANCELLATION_REQUESTED_REASON)?;
        job.status = ExchangeStatus::CancelRequested;
        self.bridge
            .cancel(job_id)
            .map_err(|_| ExchangeError::InvalidTransition)?;
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
        job.lifecycle = job
            .lifecycle
            .cancellation_confirmed(CANCELLATION_CONFIRMED_REASON)?;
        job.status = ExchangeStatus::Cancelled;
        Ok(job.clone())
    }

    /// Exports one completed job's result to another route.
    ///
    /// I21.7: "Reference validation occurs before candidate promotion and again
    /// when a result is packed into a shared packet or exported to another
    /// route." This is that second validation point, so the export boundary does
    /// not trust the promotion boundary: it re-proves the admitted manifest
    /// (including its digest over its own content), refuses a job whose State
    /// Fence moved, re-runs the full pre-promotion firewall over the delivered
    /// bundle, requires every exported source handle to still be admitted
    /// by that manifest, and requires the export's return channel to be an
    /// admitted expansion route. A result admitted under one manifest can never
    /// be exported against another, a stale or revoked handle can never leave,
    /// an unadmitted handle can never be named in an export, and a result can
    /// never be routed somewhere the manifest does not admit.
    pub fn export(
        &self,
        job_id: &str,
        export: ResearchExportBundle,
    ) -> Result<ResearchExportBundle, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get(job_id)
            .ok_or(ExchangeError::NotFound)?;
        export.validate()?;
        if export.exchange_id != job.exchange_id || !matches!(job.status, ExchangeStatus::Completed)
        {
            return Err(ExchangeError::ExportDenied);
        }
        let manifest = &job.request.allowed_references;
        manifest.validate()?;
        if job.request.state_fence != job.state_fence {
            return Err(ExchangeError::StaleFence);
        }
        if !manifest.permits_expansion(&export.return_channel) {
            return Err(ExchangeError::ExportDenied);
        }
        let result = job.result.as_ref().ok_or(ExchangeError::ExportDenied)?;
        // The pre-promotion firewall, re-run at the export boundary: citation
        // membership, anchor precision, delivered source lineage, URL locators
        // and artifact handles are all re-checked against this manifest.
        result.validate_against(&job.request)?;
        if export.source_handles.iter().any(|h| {
            !result
                .sources
                .iter()
                .any(|source| &source.source_handle == h)
                || !manifest.allows(h)
        }) {
            return Err(ExchangeError::ExportDenied);
        }
        Ok(export)
    }

    fn transition(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        status: ExchangeStatus,
    ) -> Result<ExchangeJob, ExchangeError> {
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
        if job.state_fence != *fence
            || !matches!(
                job.status,
                ExchangeStatus::Accepted | ExchangeStatus::Partial | ExchangeStatus::Running
            )
        {
            return Err(ExchangeError::InvalidTransition);
        }
        job.status = status;
        Ok(job.clone())
    }
}

/// How one idempotency identity resolved against the durable ledger.
///
/// I21.11: a retry "resume[s] by idempotency identity rather than duplicate
/// transfer". The two cases are distinct types rather than a flag so a caller
/// cannot read a resumed job as a newly started transfer, or the reverse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeAdmission {
    /// The identity was never admitted: a provider job was created for it and
    /// its opened durable record was stored.
    Started(ExchangeJob),
    /// The identity was already admitted: the interrupted job was recovered from
    /// its durable record, carrying the progress and partial results it had
    /// already paid for. No provider job was created and no transfer repeated.
    Resumed(ExchangeJob),
}

impl ExchangeAdmission {
    /// The admitted job, whichever way the identity resolved.
    #[must_use]
    pub const fn job(&self) -> &ExchangeJob {
        match self {
            Self::Started(job) | Self::Resumed(job) => job,
        }
    }
}

/// A refused durable exchange transition, with the owner-reported ledger failure
/// kept in the owner's own error type.
///
/// A record that cannot be persisted is a typed failure rather than a silently
/// lost job, and the two causes stay distinct: `Exchange` is this crate's
/// refusal (a conflicting identity, an illegal transition, a contract
/// violation), `Ledger` is the owning store's own reported failure.
#[derive(Debug, Error)]
pub enum DurableExchangeError<E: std::error::Error + Send + Sync + 'static> {
    /// The exchange refused the transition.
    #[error("exchange transition refused: {0}")]
    Exchange(#[from] ExchangeError),
    /// The owning store refused the durable record.
    #[error("durable exchange-job ledger refused the record: {0}")]
    Ledger(E),
}

/// A [`GovernedExchange`] whose durable lifecycle record is persisted through the
/// owning ELIOT store's store-neutral [`ExchangeJobLedger`] port.
///
/// # Why this is the durable path
///
/// I21.11 requires a pending import/export to "remain durable exchange job[s] and
/// resume by idempotency identity rather than duplicate transfer", while the
/// federation "never shares ELIOT's canonical database". So the record is durable
/// only when the owning store holds it, and this type is the seam: it drives the
/// one [`GovernedExchange`] state machine and writes the record it produced
/// through the port after every transition. It defines no database, no
/// remote-store fallback and no scheduler, and the concrete store implementor
/// belongs to the canonical store owner.
///
/// # What the port buys
///
/// * A submit that loads first resumes an already-admitted identity and never
///   contacts the bridge for it, so a retry across a restart is one provider job
///   and one transfer.
/// * A refusal cannot hide a state change that did happen: the record reached is
///   written whether or not the transition succeeded, which is what keeps an
///   issued-but-unconfirmed cancellation from decoding as a clean stop after a
///   restart.
/// * A durable record is only ever served after it re-validates, so a stored
///   record cannot resurrect a supported answer on an exhausted job.
pub struct DurableExchange<B, L> {
    exchange: GovernedExchange<B>,
    ledger: L,
}

impl<B, L> DurableExchange<B, L> {
    /// Binds one exchange to the store that holds its durable records.
    #[must_use]
    pub fn new(bridge: B, ledger: L) -> Self {
        Self {
            exchange: GovernedExchange::new(bridge),
            ledger,
        }
    }

    /// Rebuilds one exchange over an already-restored process-local projection
    /// and the store that holds its durable records.
    #[must_use]
    pub fn from_snapshot(bridge: B, snapshot: ExchangeSnapshot, ledger: L) -> Self {
        Self {
            exchange: GovernedExchange::from_snapshot(bridge, snapshot),
            ledger,
        }
    }

    /// The process-local projection of the jobs this exchange holds.
    #[must_use]
    pub fn snapshot(&self) -> &ExchangeSnapshot {
        self.exchange.snapshot()
    }

    /// The state machine behind this durable exchange.
    #[must_use]
    pub fn exchange(&self) -> &GovernedExchange<B> {
        &self.exchange
    }

    /// Splits the exchange back into its bridge, its store and its projection,
    /// so a store owner can hold the port across process boundaries.
    #[must_use]
    pub fn into_parts(self) -> (B, L, ExchangeSnapshot) {
        let (bridge, snapshot) = self.exchange.into_parts();
        (bridge, self.ledger, snapshot)
    }
}

impl<B: ResearchBridge, L: ExchangeJobLedger> DurableExchange<B, L> {
    /// Admits one query, or resumes the interrupted exchange already durable
    /// under its idempotency key.
    ///
    /// The ledger is read before the bridge is contacted, so an identity that is
    /// already admitted never starts a second transfer: the stored record is
    /// re-validated, rebuilt through [`ExchangeJob::resumed`] and installed
    /// through [`GovernedExchange::adopt_resumed`], which report the progress and
    /// partial results that job had already paid for. An identity bound to
    /// different request content is a conflict, never a second job. Only a
    /// genuinely new identity reaches the bridge, and its opened record is stored
    /// before this call returns, so an interruption right after cannot lose the
    /// job.
    pub fn submit(
        &mut self,
        request: ResearchQueryRequest,
    ) -> Result<ExchangeAdmission, DurableExchangeError<L::Error>> {
        request.validate().map_err(ExchangeError::from)?;
        if let Some(record) = self
            .ledger
            .load(&request.idempotency_key)
            .map_err(DurableExchangeError::Ledger)?
        {
            let job = ExchangeJob::resumed(request, record)?;
            return Ok(ExchangeAdmission::Resumed(
                self.exchange.adopt_resumed(job)?,
            ));
        }
        let job = self.exchange.admit(request)?;
        self.ledger
            .store(job.job().lifecycle.clone())
            .map_err(DurableExchangeError::Ledger)?;
        Ok(job)
    }

    /// Spends progress against the admitted budget and stores the record.
    pub fn record_progress(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        units: u64,
    ) -> Result<ExchangeJob, DurableExchangeError<L::Error>> {
        let job = self.exchange.record_progress(job_id, fence, units)?;
        self.persist(&job.job_id)?;
        Ok(job)
    }

    /// Records verified partial evidence and stores the record.
    ///
    /// A replayed delivery of a bundle this job already transferred leaves the
    /// record unchanged — no second partial, no second charge against the
    /// admitted budget — so a retry reports prior partial results instead of
    /// repeating the transfer.
    pub fn record_partial_bundle(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        units: u64,
        bundle: &ResearchEvidenceBundle,
    ) -> Result<ExchangeJob, DurableExchangeError<L::Error>> {
        let job = self
            .exchange
            .record_partial_bundle(job_id, fence, units, bundle)?;
        self.persist(&job.job_id)?;
        Ok(job)
    }

    /// Closes one job with a delivered evidence bundle and stores the record.
    ///
    /// A supported answer is still reachable only through the bundle's
    /// supported-close witness, so a durable close of an empty or exhausted
    /// exchange is refused here exactly as it is in the live state machine.
    pub fn import_bundle(
        &mut self,
        bundle: ResearchEvidenceBundle,
    ) -> Result<ExchangeJob, DurableExchangeError<L::Error>> {
        let job = self.exchange.import_bundle(bundle)?;
        self.persist(&job.job_id)?;
        Ok(job)
    }

    /// Cancels one job and stores the record the exchange actually reached.
    ///
    /// The record is written even when the bridge refuses to confirm, because the
    /// issued cancellation is itself a durable fact: without it an interrupted
    /// cancellation would restart as a clean job. The refusal is still returned.
    pub fn cancel(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<ExchangeJob, DurableExchangeError<L::Error>> {
        let outcome = self.exchange.cancel(job_id, fence);
        self.persist(job_id)?;
        outcome.map_err(Into::into)
    }

    /// The typed dependent-inquiry gap this exchange's degradation opens for one
    /// dependent current task, or `None` when this exchange declares no such gap
    /// and the inquiry continues on its own evidence.
    ///
    /// This is a pure projection over the durable record, so it writes nothing
    /// and keeps the failure local to the dependent external-knowledge dependency.
    pub fn dependent_inquiry_gap(
        &self,
        job_id: &str,
        inquiry_id: &str,
    ) -> Result<Option<ResearchHeldSourceGap>, DurableExchangeError<L::Error>> {
        self.exchange
            .dependent_inquiry_gap(job_id, inquiry_id)
            .map_err(Into::into)
    }

    /// Writes the durable record of one job through the port.
    ///
    /// The record is validated before it is stored, so a store is never handed a
    /// record that contradicts its own invariants, and the write is keyed by the
    /// record's own idempotency identity.
    fn persist(&mut self, job_id: &str) -> Result<(), DurableExchangeError<L::Error>> {
        let job = self
            .exchange
            .snapshot()
            .jobs
            .get(job_id)
            .ok_or(ExchangeError::NotFound)?;
        job.lifecycle.validate().map_err(ExchangeError::from)?;
        self.ledger
            .store(job.lifecycle.clone())
            .map_err(DurableExchangeError::Ledger)
    }
}
