//! Governed exchange state machine for a replaceable Research bridge.

#![forbid(unsafe_code)]

pub mod handoff;

use std::collections::BTreeMap;

use eliot_contracts::{ContractVersion, StateFence};
use eliot_research_exchange_api::{
    CoverageGap, CoverageGapKind, ResearchContractError, ResearchEvidenceBundle,
    ResearchExportBundle, ResearchProviderFailure, ResearchQueryRequest,
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
    /// Candidate/evidence material returned by the provider. It remains
    /// unadmitted until the normal Governor path accepts it.
    pub result: Option<ResearchEvidenceBundle>,
    /// Typed acquisition failure, when the provider degraded coverage.
    #[serde(default)]
    pub failure: Option<ResearchProviderFailure>,
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
    #[error("research provider acquisition failed: {failure}")]
    Provider {
        /// Stable provider/acquisition failure projection.
        failure: ResearchProviderFailure,
        /// Candidate material retained even when the provider degraded.
        candidate: Option<Box<ResearchEvidenceBundle>>,
    },
    #[error("state fence is stale")]
    StaleFence,
    #[error("export is not permitted for this exchange")]
    ExportDenied,
}

impl ExchangeError {
    /// Returns the typed coverage gap carried by a provider failure.
    #[must_use]
    pub fn coverage_gap(&self) -> Option<CoverageGap> {
        match self {
            Self::Provider { failure, .. } => Some(failure.coverage_gap()),
            _ => None,
        }
    }

    /// Returns the typed provider failure, when this error is acquisition-scoped.
    #[must_use]
    pub fn provider_failure(&self) -> Option<&ResearchProviderFailure> {
        match self {
            Self::Provider { failure, .. } => Some(failure),
            _ => None,
        }
    }

    /// Borrows candidate-only material retained alongside a provider failure.
    #[must_use]
    pub fn candidate_bundle(&self) -> Option<&ResearchEvidenceBundle> {
        match self {
            Self::Provider { candidate, .. } => candidate.as_deref(),
            _ => None,
        }
    }
}

pub trait ResearchBridge {
    type Error: std::error::Error + Send + Sync + 'static;
    fn submit(&mut self, request: &ResearchQueryRequest) -> Result<String, Self::Error>;
    fn cancel(&mut self, job_id: &str) -> Result<(), Self::Error>;

    /// Returns the last typed provider failure without exposing raw provider
    /// bytes. Existing non-provider bridges retain the default `None`.
    fn last_failure(&self) -> Option<ResearchProviderFailure> {
        None
    }

    /// Takes candidate/evidence material produced by the last provider call.
    /// The exchange never promotes it; a later Governor admission is required.
    fn take_candidate_bundle(&mut self) -> Option<ResearchEvidenceBundle> {
        None
    }

    /// Returns the canonical operation identity when the bridge has contacted
    /// an external provider. `None` means the refusal occurred before any
    /// provider effect and therefore must not create a replayable job.
    fn last_operation_id(&self) -> Option<&str> {
        None
    }
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
        let Ok(job_id) = self.bridge.submit(&request) else {
            let failure = self.bridge.last_failure().unwrap_or_else(|| {
                ResearchProviderFailure::new(
                    "RESEARCH_SOURCE_UNAVAILABLE",
                    CoverageGapKind::SourceUnavailable,
                    "provider:unavailable",
                    "the research provider returned no admitted acquisition result",
                )
            });
            let candidate = self.bridge.take_candidate_bundle();
            if let Some(operation_id) = self.bridge.last_operation_id() {
                let degraded = ExchangeJob {
                    exchange_id: request.exchange_id.clone(),
                    job_id: operation_id.to_owned(),
                    request: request.clone(),
                    status: if candidate.is_some() {
                        ExchangeStatus::Partial
                    } else {
                        ExchangeStatus::Failed
                    },
                    state_fence: request.state_fence.clone(),
                    progress_units: 0,
                    result: candidate.clone(),
                    failure: Some(failure.clone()),
                };
                self.snapshot
                    .idempotency
                    .insert(request.idempotency_key.clone(), operation_id.to_owned());
                self.snapshot.jobs.insert(operation_id.to_owned(), degraded);
            }
            return Err(ExchangeError::Provider {
                failure,
                candidate: candidate.map(Box::new),
            });
        };
        if job_id.trim().is_empty() {
            return Err(ExchangeError::Provider {
                failure: ResearchProviderFailure::new(
                    "RESEARCH_SOURCE_UNAVAILABLE",
                    CoverageGapKind::SourceUnavailable,
                    "provider:unavailable",
                    "the provider returned an empty operation identity",
                ),
                candidate: self.bridge.take_candidate_bundle().map(Box::new),
            });
        }
        let candidate = self.bridge.take_candidate_bundle();
        let job = ExchangeJob {
            exchange_id: request.exchange_id.clone(),
            job_id: job_id.clone(),
            state_fence: request.state_fence.clone(),
            request,
            status: if candidate.is_some() {
                ExchangeStatus::Partial
            } else {
                ExchangeStatus::Accepted
            },
            progress_units: 0,
            result: candidate,
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
        // A13.11: on budget exhaustion paid jobs stop while verified partial
        // work AND the coverage gap remain. Fail closed: an exhausted bundle
        // (spent progress reached the admitted budget) must carry an explicit
        // BudgetExhausted gap entry; other gap kinds alone hide exhaustion
        // and violate ARCH-RES-04 (degradation visible and local).
        let exhausted = job.progress_units >= job.request.budget_units;
        if exhausted && !bundle.has_budget_exhausted_gap() {
            return Err(ExchangeError::Contract(
                ResearchContractError::InvalidDisposition,
            ));
        }
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
        if self.bridge.cancel(job_id).is_err() {
            let failure = self.bridge.last_failure().unwrap_or_else(|| {
                ResearchProviderFailure::new(
                    "RESEARCH_SOURCE_UNAVAILABLE",
                    CoverageGapKind::Cancelled,
                    "provider:cancel",
                    "provider cancellation was not admitted or could not be receipted",
                )
            });
            let candidate = self.bridge.take_candidate_bundle().map(Box::new);
            return Err(ExchangeError::Provider { failure, candidate });
        }
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
