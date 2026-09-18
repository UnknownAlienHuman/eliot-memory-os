//! Pure bounded one-step Dreamer controller transition.
//!
//! The crate consumes immutable state, a frozen policy and already-observed
//! owner receipts. It emits at most one adjacent candidate revision and inert
//! requests. It performs no scheduling, provider/model call, storage access,
//! authority mutation or task completion.

#![forbid(unsafe_code)]

mod bounds;
mod durable;
mod error;
mod plan;
mod policy;
mod receipt;
mod sample;
mod step;

pub mod contract;

pub use contract::{
    CYCLE_SCHEMA_VERSION, CyclePhase, CyclePolicy, CycleStep, DreamerCycleState, ExpectedArtifact,
    InertOwnerRequest, ObservedOutcome, OutcomeDisposition, PendingRequest, PhasePolicyRule,
    RequestKind, StepDisposition,
};
pub use durable::{
    AckEvidence, AdvanceStageCommand, DURABLE_SCHEMA_VERSION, DeadlineEvidence, DeliveryEvidence,
    DurableCommand, DurableDisposition, DurableEvent, DurableJobState, DurablePhase, DurableStage,
    DurableTransition, EscalateCommand, FenceEvidence, InFlightOperation, MAX_DURABLE_COMMANDS,
    MAX_NO_PROGRESS, MAX_SETTLED_OPERATIONS, OperationOutcome, ReconcileCommand, RestartEvidence,
    SettledOperation, StageEvidence, StageReconciled, StageRequest, StageResolution,
    step_durable_job,
};
pub use error::CycleError;
pub use plan::{CyclePlan, ExperimentCandidate, ExperimentKind, PlanHorizon, plan_cycle};
pub use sample::{CycleSample, SampleDenominator, SampleLimits, sample_cycle};
pub use step::{step_dreamer_cycle, step_dreamer_cycle_at};
