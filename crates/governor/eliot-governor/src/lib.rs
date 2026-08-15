//! The single orchestration owner for the Governor service graph.
//!
//! This crate deliberately owns coordination state, startup ordering, readiness,
//! degradation, and shutdown admission only.  Individual services own their
//! data and effects; they report observations here and never mutate this state
//! directly.  The owner is deterministic and synchronous so that callers can
//! place it behind any chosen Tokio task or IPC boundary without introducing a
//! second lifecycle authority.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_runtime_contracts::{HealthDimension, HealthVector, ServiceProcessState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this orchestration contract.
pub const CONTRACT_NAME: &str = "eliot.governor.orchestration";
/// Wire revision of this orchestration contract.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

/// The normative startup order from the Governor architecture.
pub const STARTUP_ORDER: [ServiceId; 16] = [
    ServiceId::Config,
    ServiceId::ControlWal,
    ServiceId::BlobStore,
    ServiceId::Database,
    ServiceId::Migration,
    ServiceId::Writer,
    ServiceId::Read,
    ServiceId::Policy,
    ServiceId::Agent,
    ServiceId::Adapter,
    ServiceId::Cognitive,
    ServiceId::Jobs,
    ServiceId::Report,
    ServiceId::Ipc,
    ServiceId::Http,
    ServiceId::Maintenance,
];

/// A supervised Governor service.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ServiceId {
    Config,
    ControlWal,
    BlobStore,
    Database,
    Migration,
    Writer,
    Read,
    Policy,
    Agent,
    Adapter,
    Cognitive,
    Jobs,
    Report,
    Ipc,
    Http,
    Maintenance,
}

impl ServiceId {
    /// Returns whether this service is required for full daemon readiness.
    #[must_use]
    pub const fn required_for_ready(self) -> bool {
        matches!(
            self,
            Self::Config
                | Self::ControlWal
                | Self::BlobStore
                | Self::Database
                | Self::Migration
                | Self::Writer
                | Self::Read
                | Self::Policy
        )
    }
}

/// Public Governor lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernorState {
    Constructed,
    Starting,
    Ready,
    Degraded,
    ReadOnly,
    Quiescing,
    Stopped,
    Failed,
}

/// A bounded queue class exposed as an admission policy, not an unbounded heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueClass {
    Interactive,
    Verification,
    NormalWrite,
    Background,
    Report,
    Adapter,
}

/// Explicit queue limits used by admission layers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueueLimits {
    pub interactive: usize,
    pub verification: usize,
    pub normal_write: usize,
    pub background: usize,
    pub report: usize,
    pub adapter: usize,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            interactive: 512,
            verification: 512,
            normal_write: 2048,
            background: 1024,
            report: 128,
            adapter: 64,
        }
    }
}

impl QueueLimits {
    fn validate(&self) -> Result<(), GovernorError> {
        if [
            self.interactive,
            self.verification,
            self.normal_write,
            self.background,
            self.report,
            self.adapter,
        ]
        .into_iter()
        .any(|value| value == 0)
        {
            return Err(GovernorError::InvalidConfiguration(
                "queue limits must be nonzero",
            ));
        }
        Ok(())
    }

    /// Returns the configured bound for one queue class.
    #[must_use]
    pub const fn for_class(&self, class: QueueClass) -> usize {
        match class {
            QueueClass::Interactive => self.interactive,
            QueueClass::Verification => self.verification,
            QueueClass::NormalWrite => self.normal_write,
            QueueClass::Background => self.background,
            QueueClass::Report => self.report,
            QueueClass::Adapter => self.adapter,
        }
    }
}

/// Immutable construction policy for one Governor owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorConfig {
    pub authority_epoch: AuthorityEpoch,
    pub resource_generation: ResourceGeneration,
    pub queues: QueueLimits,
    pub background_pause_interactive_depth: usize,
}

impl GovernorConfig {
    /// Validates the identity and bounded admission policy.
    pub fn validate(&self) -> Result<(), GovernorError> {
        self.queues.validate()?;
        if self.background_pause_interactive_depth == 0
            || self.background_pause_interactive_depth > self.queues.interactive
        {
            return Err(GovernorError::InvalidConfiguration(
                "background pause threshold must be within interactive capacity",
            ));
        }
        Ok(())
    }
}

/// One service's observation supplied by its owning implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceObservation {
    pub state: ServiceProcessState,
    pub health: HealthVector,
    pub generation: ResourceGeneration,
    pub authority_epoch: AuthorityEpoch,
}

impl ServiceObservation {
    fn validate(&self, config: &GovernorConfig) -> Result<(), GovernorError> {
        if self.generation != config.resource_generation {
            return Err(GovernorError::GenerationMismatch);
        }
        if self.authority_epoch != config.authority_epoch {
            return Err(GovernorError::AuthorityEpochMismatch);
        }
        Ok(())
    }
}

/// Current service record retained by the orchestration owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    pub observation: ServiceObservation,
    pub required: bool,
}

/// Fail-closed orchestration errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GovernorError {
    #[error("invalid Governor configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("service {0:?} is not the next service in startup order")]
    OutOfOrder(ServiceId),
    #[error("service {0:?} has already been admitted")]
    DuplicateService(ServiceId),
    #[error("service {0:?} has not been admitted")]
    UnknownService(ServiceId),
    #[error("service observation has a stale authority epoch")]
    AuthorityEpochMismatch,
    #[error("service observation has a stale resource generation")]
    GenerationMismatch,
    #[error("required service {0:?} is not ready")]
    RequiredServiceUnavailable(ServiceId),
    #[error("Governor is no longer accepting lifecycle changes")]
    LifecycleClosed,
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycle {
        from: GovernorState,
        to: GovernorState,
    },
}

/// Result of a bounded service admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorSnapshot {
    pub state: GovernorState,
    pub next_service: Option<ServiceId>,
    pub services: BTreeMap<ServiceId, ServiceRecord>,
    pub interactive_depth: usize,
}

/// The sole in-process owner of Governor orchestration state.
#[derive(Clone, Debug)]
pub struct Governor {
    config: GovernorConfig,
    state: GovernorState,
    services: BTreeMap<ServiceId, ServiceRecord>,
    interactive_depth: usize,
}

impl Governor {
    /// Creates a new owner in the non-running constructed state.
    pub fn new(config: GovernorConfig) -> Result<Self, GovernorError> {
        config.validate()?;
        Ok(Self {
            config,
            state: GovernorState::Constructed,
            services: BTreeMap::new(),
            interactive_depth: 0,
        })
    }

    /// Returns the immutable configuration used by this owner.
    #[must_use]
    pub const fn config(&self) -> &GovernorConfig {
        &self.config
    }

    /// Returns a complete immutable projection of orchestration state.
    #[must_use]
    pub fn snapshot(&self) -> GovernorSnapshot {
        GovernorSnapshot {
            state: self.state,
            next_service: self.next_service(),
            services: self.services.clone(),
            interactive_depth: self.interactive_depth,
        }
    }

    /// Starts admission of services. Repeated calls are idempotent.
    pub fn begin_startup(&mut self) -> Result<(), GovernorError> {
        match self.state {
            GovernorState::Constructed => {
                self.state = GovernorState::Starting;
                Ok(())
            }
            GovernorState::Starting => Ok(()),
            state => Err(GovernorError::InvalidLifecycle {
                from: state,
                to: GovernorState::Starting,
            }),
        }
    }

    /// Admits the next service's complete observation in the normative order.
    pub fn admit_service(
        &mut self,
        service: ServiceId,
        observation: ServiceObservation,
    ) -> Result<(), GovernorError> {
        if matches!(
            self.state,
            GovernorState::Constructed
                | GovernorState::Quiescing
                | GovernorState::Stopped
                | GovernorState::Failed
        ) {
            return Err(GovernorError::LifecycleClosed);
        }
        if self.next_service() != Some(service) {
            return Err(GovernorError::OutOfOrder(service));
        }
        observation.validate(&self.config)?;
        if self.services.contains_key(&service) {
            return Err(GovernorError::DuplicateService(service));
        }
        self.services.insert(
            service,
            ServiceRecord {
                observation,
                required: service.required_for_ready(),
            },
        );
        self.recompute_state()?;
        Ok(())
    }

    /// Records a fresh observation for an already admitted service.
    pub fn update_service(
        &mut self,
        service: ServiceId,
        observation: ServiceObservation,
    ) -> Result<(), GovernorError> {
        if matches!(
            self.state,
            GovernorState::Quiescing | GovernorState::Stopped
        ) {
            return Err(GovernorError::LifecycleClosed);
        }
        observation.validate(&self.config)?;
        let record = self
            .services
            .get_mut(&service)
            .ok_or(GovernorError::UnknownService(service))?;
        record.observation = observation;
        self.recompute_state()
    }

    /// Begins sticky ordered shutdown. Later service admission is refused.
    pub fn begin_shutdown(&mut self) -> Result<(), GovernorError> {
        match self.state {
            GovernorState::Stopped => Ok(()),
            GovernorState::Quiescing
            | GovernorState::Ready
            | GovernorState::Degraded
            | GovernorState::ReadOnly
            | GovernorState::Failed => {
                self.state = GovernorState::Quiescing;
                Ok(())
            }
            state => Err(GovernorError::InvalidLifecycle {
                from: state,
                to: GovernorState::Quiescing,
            }),
        }
    }

    /// Completes shutdown after callers have stopped owned services.
    pub fn finish_shutdown(&mut self) -> Result<(), GovernorError> {
        if self.state != GovernorState::Quiescing {
            return Err(GovernorError::InvalidLifecycle {
                from: self.state,
                to: GovernorState::Stopped,
            });
        }
        self.state = GovernorState::Stopped;
        Ok(())
    }

    /// Updates bounded interactive demand used to pause background work.
    pub fn set_interactive_depth(&mut self, depth: usize) -> Result<(), GovernorError> {
        if depth > self.config.queues.interactive {
            return Err(GovernorError::InvalidConfiguration(
                "interactive depth exceeds queue capacity",
            ));
        }
        self.interactive_depth = depth;
        Ok(())
    }

    /// Returns whether maintenance admission is currently allowed.
    #[must_use]
    pub const fn background_admitted(&self) -> bool {
        self.interactive_depth < self.config.background_pause_interactive_depth
            && !matches!(
                self.state,
                GovernorState::Quiescing | GovernorState::Stopped | GovernorState::Failed
            )
    }

    fn next_service(&self) -> Option<ServiceId> {
        STARTUP_ORDER
            .into_iter()
            .find(|service| !self.services.contains_key(service))
    }

    fn recompute_state(&mut self) -> Result<(), GovernorError> {
        let required_ready = STARTUP_ORDER
            .iter()
            .copied()
            .filter(|service| service.required_for_ready())
            .all(|service| {
                self.services.get(&service).is_some_and(|record| {
                    record.observation.state == ServiceProcessState::Ready
                        && record.observation.health.is_fully_healthy()
                })
            });
        let any_required_failed = STARTUP_ORDER
            .iter()
            .copied()
            .filter(|service| service.required_for_ready())
            .find(|service| {
                self.services.get(service).is_some_and(|record| {
                    matches!(
                        record.observation.state,
                        ServiceProcessState::Failed
                            | ServiceProcessState::Quarantined
                            | ServiceProcessState::ManualRecovery
                    )
                })
            });
        if let Some(service) = any_required_failed {
            self.state = GovernorState::Failed;
            return Err(GovernorError::RequiredServiceUnavailable(service));
        }
        let optional_failed = self.services.iter().any(|(service, record)| {
            !service.required_for_ready()
                && matches!(
                    record.observation.state,
                    ServiceProcessState::Failed
                        | ServiceProcessState::Quarantined
                        | ServiceProcessState::ManualRecovery
                )
        });
        let required_present = STARTUP_ORDER
            .iter()
            .copied()
            .filter(|service| service.required_for_ready())
            .all(|service| self.services.contains_key(&service));
        if !required_present {
            self.state = GovernorState::Starting;
        } else if required_ready && !optional_failed {
            self.state = GovernorState::Ready;
        } else if required_ready {
            self.state = GovernorState::Degraded;
        } else if self.services.len() >= 8 {
            self.state = GovernorState::ReadOnly;
        } else {
            self.state = GovernorState::Degraded;
        }
        Ok(())
    }
}

/// Converts a failed health vector into the public degraded dimension.
#[must_use]
pub const fn degraded_health() -> HealthVector {
    HealthVector {
        liveness: HealthDimension::Degraded,
        readiness: HealthDimension::Degraded,
        freshness: HealthDimension::Unknown,
        compatibility: HealthDimension::Unknown,
        integrity: HealthDimension::Unknown,
        capacity: HealthDimension::Unknown,
    }
}
