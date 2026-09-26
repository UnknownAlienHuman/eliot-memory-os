//! Governed exchange state machine for a replaceable Research bridge.
//!
//! Every job this state machine accepts carries a durable lifecycle record
//! (`ExchangeJobLifecycleRecord`): exchange, request, job, Research system and
//! protocol identity, the idempotency key, progress, cancellation state, the
//! partial bundles already transferred, the coverage and failed-acquisition
//! detail, the disclosure and invalidation state, and the terminal typed
//! outcome. The live `ExchangeSnapshot` is only the process-local projection of
//! that record; `lifecycle` is the owner's durable seam over the store-neutral
//! ledger, so a retry resumes the same exchange by idempotency identity instead
//! of duplicating a transfer.

#![forbid(unsafe_code)]

pub mod handoff;
mod lifecycle;

pub use lifecycle::DurableExchangeError;

use std::collections::BTreeMap;

use eliot_contracts::{ContractVersion, StateFence};
use eliot_research_exchange_api::{
    ExchangeJobLifecycleRecord, GapContinuation, ResearchContractError, ResearchEvidenceBundle,
    ResearchExportBundle, ResearchQueryRequest,
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
    pub fn resume(
        &self,
        idempotency_key: &str,
        request: &ResearchQueryRequest,
    ) -> Result<ExchangeJob, ExchangeError> {
        request.validate()?;
        let job = self
            .job_by_idempotency(idempotency_key)
            .ok_or(ExchangeError::NotFound)?;
        if job.request != *request {
            return Err(ExchangeError::IdempotencyConflict);
        }
        Ok(job)
    }
}

impl<B: ResearchBridge> GovernedExchange<B> {
    /// Accepts one query, or resumes the interrupted exchange already bound
    /// to its idempotency key with partial progress preserved. A resumed
    /// key never re-contacts the bridge, so at most one provider job exists
    /// per identity.
    pub fn submit(&mut self, request: ResearchQueryRequest) -> Result<ExchangeJob, ExchangeError> {
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
            return Ok(existing.clone());
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
        Ok(job)
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
        let result = job.result.as_ref().ok_or(ExchangeError::ExportDenied)?;
        if export.source_handles.iter().any(|h| {
            !result
                .sources
                .iter()
                .any(|source| &source.source_handle == h)
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
