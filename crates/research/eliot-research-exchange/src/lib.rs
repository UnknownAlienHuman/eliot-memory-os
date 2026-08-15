//! Governed exchange state machine for a replaceable Research bridge.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{ContractVersion, StateFence};
use eliot_research_exchange_api::{
    ResearchContractError, ResearchEvidenceBundle, ResearchExportBundle, ResearchQueryRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const EXCHANGE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

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
}

impl<B: ResearchBridge> GovernedExchange<B> {
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
            .get(job_id)
            .ok_or(ExchangeError::NotFound)?;
        if job.state_fence != *fence
            || !matches!(
                job.status,
                ExchangeStatus::Accepted | ExchangeStatus::Running | ExchangeStatus::Partial
            )
        {
            return Err(ExchangeError::InvalidTransition);
        }
        job.status = ExchangeStatus::Partial;
        job.progress_units = job.progress_units.saturating_add(units);
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
        self.bridge
            .cancel(job_id)
            .map_err(|_| ExchangeError::InvalidTransition)?;
        let job = self
            .snapshot
            .jobs
            .get_mut(job_id)
            .ok_or(ExchangeError::NotFound)?;
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
