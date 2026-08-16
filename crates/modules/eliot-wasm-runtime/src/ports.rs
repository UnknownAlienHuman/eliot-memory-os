use eliot_process::{CancellationReceipt, ProcessEvidence, ProcessRequest, ProcessStartReceipt};
use thiserror::Error;

use crate::{
    AuthorityResolution, DerivedExecutionEvidence, EngineBinding, EngineInvocation, EngineReport,
    GovernorResolution, InvocationRequest, ProcessBinding, ProcessLaunchEnvelope, PromotionQuery,
    PromotionVerification, SourceVerification,
};

/// Typed failure shared by injected authority and execution ports.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PortError {
    #[error("request denied by owning authority")]
    Denied,
    #[error("required provider unavailable")]
    Unavailable,
    #[error("provider outcome unknown")]
    UnknownOutcome,
}

/// Governor-owned resolver for manifest, generation, lease, revisions and limits.
pub trait GovernorResolutionPort: Send {
    fn resolve(&mut self, request: &InvocationRequest) -> Result<GovernorResolution, PortError>;
}

/// Authority-owner resolver for owner, `WorkScope`, work unit and effect ceilings.
pub trait AuthorityResolutionPort: Send {
    fn resolve(&mut self, request: &InvocationRequest) -> Result<AuthorityResolution, PortError>;
}

/// Independent source-verifier boundary.
pub trait SourceVerificationPort: Send {
    fn verify(&mut self, request: &InvocationRequest) -> Result<SourceVerification, PortError>;
}

/// Conformance/shadow/canary/rollback/cutover verifier boundary.
pub trait PromotionVerificationPort: Send {
    fn verify(&mut self, query: &PromotionQuery) -> Result<PromotionVerification, PortError>;

    fn verify_execution(
        &mut self,
        invocation: &EngineInvocation,
        report: &EngineReport,
        derived: &DerivedExecutionEvidence,
    ) -> Result<(), PortError>;
}

/// P-03 executor boundary. It alone creates and consumes process authority.
pub trait P03ProcessPort: Send {
    fn prepare(&mut self, envelope: &ProcessLaunchEnvelope) -> Result<ProcessRequest, PortError>;

    fn start(&mut self, request: ProcessRequest) -> Result<ProcessStartReceipt, PortError>;

    fn cancel(&mut self, binding: &ProcessBinding) -> Result<CancellationReceipt, PortError>;

    fn reconcile(&mut self, binding: &ProcessBinding) -> Result<ProcessEvidence, PortError>;
}

/// Separate P-03 receipt verifier; neither A-12 nor the engine mints proof.
pub trait P03ReceiptVerifierPort: Send {
    fn verify_start(
        &mut self,
        binding: &ProcessBinding,
        receipt: &ProcessStartReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError>;

    fn verify_cancellation(
        &mut self,
        binding: &ProcessBinding,
        receipt: &CancellationReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError>;

    fn verify_reconciliation(
        &mut self,
        binding: &ProcessBinding,
        evidence: &ProcessEvidence,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError>;
}

/// Engine boundary. Reports actual values only and never returns P-03 receipts.
pub trait ComponentEnginePort: Send {
    fn binding(&self) -> &EngineBinding;

    fn invoke(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError>;

    fn reconcile(&mut self, invocation: &EngineInvocation) -> Result<EngineReport, PortError>;
}

/// Complete injected dependency set. Missing any set yields typed `PLAN_GAP`.
pub struct RuntimePorts {
    pub governor: Box<dyn GovernorResolutionPort>,
    pub authority: Box<dyn AuthorityResolutionPort>,
    pub source_verifier: Box<dyn SourceVerificationPort>,
    pub promotion_verifier: Box<dyn PromotionVerificationPort>,
    pub process: Box<dyn P03ProcessPort>,
    pub process_receipt_verifier: Box<dyn P03ReceiptVerifierPort>,
    pub engine: Box<dyn ComponentEnginePort>,
}

impl RuntimePorts {
    /// Binds the exact independently owned ports selected by composition.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        governor: Box<dyn GovernorResolutionPort>,
        authority: Box<dyn AuthorityResolutionPort>,
        source_verifier: Box<dyn SourceVerificationPort>,
        promotion_verifier: Box<dyn PromotionVerificationPort>,
        process: Box<dyn P03ProcessPort>,
        process_receipt_verifier: Box<dyn P03ReceiptVerifierPort>,
        engine: Box<dyn ComponentEnginePort>,
    ) -> Self {
        Self {
            governor,
            authority,
            source_verifier,
            promotion_verifier,
            process,
            process_receipt_verifier,
            engine,
        }
    }
}
