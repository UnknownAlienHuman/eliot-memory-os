//! I4.4.1 readiness delivery to agent and Human callers (issue #1790,
//! W6-surface).
//!
//! [`GovernorComposition::cold_start_agent_surface_for_claim`] projects the
//! compact agent-facing readiness surface for one retained cold-start
//! terminal: the current readiness state, the single smallest missing
//! question (`None` when nothing is missing), the next safe action, and the
//! lease deadline after which the readiness expires. It reuses the canonical
//! [`ReadinessSurface`](eliot_workscope::ReadinessSurface) owner projection,
//! so the agent receives exactly what the receipt compiled — never a stronger
//! readiness.
//!
//! [`GovernorComposition::cold_start_human_board_for_claim`] projects the
//! Human-board view for the same terminal: readiness, smallest missing
//! question, and next safe action plus the memory state, minimum
//! understanding seed, and proposed (never started) maintenance
//! recommendations a Human needs to bind the task and documents directly.
//! Both projections are read-only over the retained terminal receipt: they
//! create no `WorkScope`, infer no latest task, and mutate no receipt —
//! identity or generation changes invalidate through a new receipt revision
//! elsewhere instead.
//!
//! Live status: owning delivery legs for the agent and Human paths. Live
//! terminal readback exists on the daemon side
//! (`DaemonComposition::read_cold_start_surface_for_attach` through
//! `cold_start_owner_readback_for_claim`); these legs project that retained
//! terminal. Residual: the bridge note path consumes no governor surface yet
//! (BLOCKED-BY bridge-transport: `bins/eliot-agent-bridge` intake), so no
//! compiled terminal reaches the bridge and Status readers see the retained
//! snapshot preview instead. Callers: STITCH (agent-bridge intake for the
//! agent surface, Human board for the board view).

use crate::composition::{
    ColdStartReadinessClaim, CompositionError, GovernorComposition, KernelGenerationPort,
};
use eliot_workscope::{MemoryState, ReadinessLifecycle, ReadinessSurface};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Human-board projection of one retained cold-start terminal readiness
/// receipt.
///
/// This is what the Human surface shows instead of an internal setup log: the
/// current readiness state, the single smallest missing question (`None` when
/// nothing is missing), the next safe action, the memory assessment, the
/// minimum understanding seed the first useful work must ground on, the
/// proposed first-maintenance jobs, and the lease deadline plus receipt
/// revision that bound the projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColdStartHumanBoardView {
    pub receipt_ref: String,
    pub lease_ref: String,
    pub readiness: ReadinessLifecycle,
    pub smallest_missing_question: Option<String>,
    pub next_safe_action: String,
    pub memory_state: MemoryState,
    pub minimum_understanding_seed: Vec<String>,
    pub maintenance_recommendations: Vec<String>,
    pub lease_deadline: u64,
    pub receipt_revision: u64,
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Projects the compact agent-facing readiness surface for the exact
    /// durable cold-start terminal named by a full owner claim (issue #1790,
    /// agent delivery leg).
    ///
    /// Reads revalidate the stored lease, terminal revision, current
    /// `StateFence`, and freshly matched `WorkScope` through the terminal
    /// readback, then returns the canonical owner surface: current readiness
    /// state, smallest missing question, next safe action, and lease
    /// deadline. The readiness travels with the receipt instead of staying
    /// buried in internal setup state.
    ///
    /// # Errors
    ///
    /// Returns the terminal readback's typed [`CompositionError`] when the
    /// claim is not bound, the lease moved or expired, the terminal is
    /// missing, or the retained scope drifted; [`CompositionError::Recovery`]
    /// when the lease does not own the terminal receipt.
    pub fn cold_start_agent_surface_for_claim(
        &self,
        claim: &ColdStartReadinessClaim,
        now: u64,
    ) -> Result<ReadinessSurface, CompositionError> {
        let (lease, receipt) = self.cold_start_readiness_terminal_for_claim(claim, now)?;
        receipt
            .surface(&lease)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Projects the Human-board readiness view for the exact durable
    /// cold-start terminal named by a full owner claim (issue #1790, Human
    /// delivery leg).
    ///
    /// Reads revalidate exactly like the agent leg, then copies the readiness
    /// state, smallest missing question, next safe action, memory state,
    /// minimum understanding seed, maintenance recommendations, lease
    /// deadline, and receipt revision from the retained terminal receipt. A
    /// Human caller can bind the task and documents directly from this view;
    /// proposals stay proposed here and are never started.
    ///
    /// # Errors
    ///
    /// Returns the same typed [`CompositionError`] causes as
    /// [`Self::cold_start_agent_surface_for_claim`].
    pub fn cold_start_human_board_for_claim(
        &self,
        claim: &ColdStartReadinessClaim,
        now: u64,
    ) -> Result<ColdStartHumanBoardView, CompositionError> {
        let (lease, receipt) = self.cold_start_readiness_terminal_for_claim(claim, now)?;
        let surface = receipt
            .surface(&lease)
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(ColdStartHumanBoardView {
            receipt_ref: receipt.receipt_ref.clone(),
            lease_ref: lease.lease_ref.clone(),
            readiness: receipt.readiness,
            smallest_missing_question: surface.smallest_missing_question,
            next_safe_action: receipt.next_safe_action.clone(),
            memory_state: receipt.memory_state,
            minimum_understanding_seed: receipt.minimum_understanding_seed.clone(),
            maintenance_recommendations: receipt.maintenance_recommendations.clone(),
            lease_deadline: lease.deadline,
            receipt_revision: receipt.receipt_revision,
        })
    }
}
