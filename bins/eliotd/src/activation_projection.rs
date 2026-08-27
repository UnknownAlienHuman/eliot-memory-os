//! Read-only activation resolution projection.
//!
//! # Architecture
//! - **A2.3 Modular architecture** — bounded pure projection cell; no new runtime/process/failure boundary.
//! - **A13.2 Kernel and failure domains** — Kernel remains sole authority/fencing owner; this projection only reads the admitted Governor snapshot.
//! - **A13.10 Observability and Diagnostic Brief** — decision is a derived projection/receipt; it does not prove a transition.
//! - **ARCH-MOD-02 Depth is additive and micro-modular** — extracted as independently understandable/testable/replaceable capability cell; size and physical form remain empirical.
//!
//! # Implementation
//! - **I1.11 Startup algorithm** — resolution is available only after Governor/Kernel admission; no startup authority issuance here.
//! - **I2.2 When a capability becomes a separate crate** — pure contract/test seam justifies isolated module; no placeholder proliferation.
//! - **I2.23 Capability-family topology and crate extraction decisions** — Governor task/authority/canonical-transition family; validated via `CrateExtractionDecision`.
//! - **Semantic-grant handle: `eliot_governor::GovernorActivationSnapshot` / `eliot_protocol::AgentActivationResolutionTicket` -> `eliot_protocol::AgentActivationResolutionDecision` via `GovernorComposition::read_unique_agent_activation`** — Kernel-issued ticket resolved against the current Governor owner set.
//!
//! This is a read-only activation resolution projection and owns no authority issuance, write/effect, fence, default, retry, Kernel, Store, or lifecycle semantics.

use eliot_protocol::{AgentActivationResolutionDecision, AgentActivationResolutionTicket};

use crate::DaemonError;

/// Read-only semantic-resolution boundary owned by eliotd.
///
/// The boundary accepts only a Kernel-issued correlation ticket. It does not
/// accept caller-selected semantic IDs and does not issue transport sessions,
/// fences, capabilities, or effects.
pub trait AgentActivationResolver {
    /// Resolves one exact ticket against the current Governor owner set.
    fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError>;
}

pub(super) fn map_activation_snapshot(
    ticket: &AgentActivationResolutionTicket,
    snapshot: eliot_governor::GovernorActivationSnapshot,
) -> Result<AgentActivationResolutionDecision, DaemonError> {
    AgentActivationResolutionDecision {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionDecision::CONTRACT_VERSION,
        ticket_id: ticket.ticket_id.clone(),
        ticket_sha256: ticket.ticket_sha256.clone(),
        state_fence: snapshot.state_fence,
        principal_id: snapshot.principal_id,
        session_id: snapshot.session_id,
        task_id: snapshot.task_id.to_string(),
        work_unit_id: snapshot.work_unit_id,
        work_scope_id: snapshot.work_scope_id,
        task_revision: snapshot.task_revision.to_string(),
        plan_id: snapshot.plan_id,
        plan_revision: snapshot.plan_revision,
        decision_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}
