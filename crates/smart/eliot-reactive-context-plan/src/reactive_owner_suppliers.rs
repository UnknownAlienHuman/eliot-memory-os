//! Owner supplier bundle for the six reactive planning inputs (#1942).
//!
//! A [`ReactiveOwnerSupply`] carries the six live owner artifacts for ONE
//! evaluation, each as an `Option`: `None` means the owning lane has not
//! served that artifact on this tick. [`ReactiveOwnerSupply::assemble`]
//! runs the six [`super::reactive_owner_producers`] in join order (view
//! first — every other input binds to it) and returns either the complete
//! [`AssembledReactiveInputs`] or the exact missing-owner inventory.
//!
//! Withheld semantics (MGR-B row D): a missing owner is reported, never
//! defaulted. The daemon feed maps a missing bundle to a withheld/idle
//! outcome; it must not plan, deliver, or claim coverage from absent
//! owners.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextPlanningView, CriticalAttentionProjection,
    IntegrationCoverageProfile, ReactiveInputError, SessionDeliverySnapshot,
};
use eliot_contracts::ArtifactId;
use eliot_cue_contracts::{ActivationRequest, ActivationResult};

use super::input::{ReactiveCueActivation, ReactiveDeliveryPolicy, ReactiveTargetBinding};
use super::reactive_owner_producers::{
    produce_attention_projection, produce_coverage_profile, produce_cue_activation,
    produce_delivery_policy, produce_planning_view, produce_session_snapshot,
};
use super::result::ReactiveContextPlanResult;

/// Live assembly-closure bundle for the planning-view producer.
pub struct PlanningViewSupply {
    /// Retained view identity minted with the assembled closure.
    pub view_id: ArtifactId,
    /// The assembled understanding view (context assembly owner).
    pub view: ActiveUnderstandingView,
    /// The exact admitted set the view was rendered from.
    pub admitted: AdmittedContextSet,
    /// Rendered canonical bytes travelling with the closure (re-proved,
    /// never trusted).
    pub canonical_bytes: Vec<u8>,
    /// Admitted canonical bytes travelling with the closure (re-proved,
    /// never trusted).
    pub admitted_canonical_bytes: Vec<u8>,
}

/// Live cue-firing bundle for the cue-activation producer.
pub struct CueActivationSupply {
    /// The exact firing request (cue activation owner).
    pub request: ActivationRequest,
    /// The exact firing result for that request.
    pub result: ActivationResult,
    /// Target-to-atom mapping for the joined view.
    pub target_bindings: Vec<ReactiveTargetBinding>,
}

/// The six live owner artifacts for one evaluation. `None` = the owner
/// has not served this artifact on this tick (withheld, never defaulted).
#[derive(Default)]
pub struct ReactiveOwnerSupply {
    /// Assembly closure (context assembly owner).
    pub view: Option<PlanningViewSupply>,
    /// Firing pair + target mapping (cue activation owner).
    pub cue: Option<CueActivationSupply>,
    /// Issued delivery history (Governor session projection owner).
    pub session: Option<SessionDeliverySnapshot>,
    /// Issued attention members (critical attention owner).
    pub attention: Option<CriticalAttentionProjection>,
    /// Issued capability profile (host/runtime coverage owner).
    pub coverage: Option<IntegrationCoverageProfile>,
    /// Admitted delivery limits (delivery policy owner).
    pub policy: Option<ReactiveDeliveryPolicy>,
}

/// One owner whose artifact is absent on this evaluation: honest idle,
/// never an error and never a default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveMissingOwner {
    /// Owning lane that serves the artifact.
    pub owner: &'static str,
    /// Planner input the artifact would have produced.
    pub artifact: &'static str,
    /// Exact read that is absent.
    pub absent_read: &'static str,
}

/// The six validated planner inputs, joined to one view and one fence.
pub struct AssembledReactiveInputs {
    /// Adopted planning view; every other input binds to it.
    pub view: ContextPlanningView,
    /// Adopted exact firing pair + target-to-atom mapping.
    pub cue_activation: ReactiveCueActivation,
    /// Adopted session delivery history (dedup evidence).
    pub session_snapshot: SessionDeliverySnapshot,
    /// Adopted attention members (sticky obligations).
    pub critical_attention: CriticalAttentionProjection,
    /// Adopted capability profile (delivery limitations).
    pub integration_coverage: IntegrationCoverageProfile,
    /// Adopted delivery limits.
    pub policy: ReactiveDeliveryPolicy,
}

impl AssembledReactiveInputs {
    /// Run the existing planner over the six joined inputs.
    #[must_use]
    pub fn plan(&self) -> ReactiveContextPlanResult {
        super::plan::plan_pending_context_injection(
            &self.view,
            &self.cue_activation,
            &self.session_snapshot,
            &self.critical_attention,
            &self.integration_coverage,
            &self.policy,
        )
    }
}

/// Assembly failure: missing owners (withhold) or a present-but-refusing
/// artifact (fail closed with the exact owner error and its lane).
#[derive(Debug)]
pub enum OwnerAssembleError {
    /// One or more owners absent: idle, never defaulted.
    Missing {
        /// Every absent owner on this evaluation, in deterministic order.
        missing: Vec<ReactiveMissingOwner>,
    },
    /// A served artifact refused adoption: the owning lane and its exact
    /// error. The value is preserved, never substituted.
    Refused {
        /// Owning lane whose artifact refused.
        owner: &'static str,
        /// The exact owner refusal.
        error: ReactiveInputError,
    },
}

impl ReactiveOwnerSupply {
    /// Inventory every absent owner on this evaluation, in deterministic
    /// slot order. Empty means all six owners served.
    #[must_use]
    pub fn missing_owners(&self) -> Vec<ReactiveMissingOwner> {
        let mut missing = Vec::new();
        if self.view.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "context assembly",
                artifact: "ContextPlanningView",
                absent_read: "no assembled view closure retained for this evaluation",
            });
        }
        if self.cue.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "cue activation",
                artifact: "ReactiveCueActivation",
                absent_read: "no exact firing pair retained for this evaluation",
            });
        }
        if self.session.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "Governor session projection",
                artifact: "SessionDeliverySnapshot",
                absent_read: "no issued session delivery history retained for this evaluation",
            });
        }
        if self.attention.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "critical attention",
                artifact: "CriticalAttentionProjection",
                absent_read: "no issued attention projection retained for this evaluation",
            });
        }
        if self.coverage.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "host/runtime coverage",
                artifact: "IntegrationCoverageProfile",
                absent_read: "no issued capability profile retained for this evaluation",
            });
        }
        if self.policy.is_none() {
            missing.push(ReactiveMissingOwner {
                owner: "delivery policy",
                artifact: "ReactiveDeliveryPolicy",
                absent_read: "no admitted delivery policy retained for this evaluation",
            });
        }
        missing
    }

    /// Adopt and join the six served artifacts, or report absence/refusal.
    ///
    /// Missing owners short-circuit before any producer runs: a partial
    /// join is never planned from, and absence is inventoried slot by
    /// slot, never defaulted. Producer order is view, cue, session,
    /// attention, coverage, policy; the first refusal stops assembly with
    /// its lane named.
    pub fn assemble(self) -> Result<AssembledReactiveInputs, OwnerAssembleError> {
        let ReactiveOwnerSupply {
            view,
            cue,
            session,
            attention,
            coverage,
            policy,
        } = self;
        match (view, cue, session, attention, coverage, policy) {
            (
                Some(view_supply),
                Some(cue_supply),
                Some(session_snapshot),
                Some(attention_projection),
                Some(coverage_profile),
                Some(policy_value),
            ) => {
                let view = produce_planning_view(
                    view_supply.view_id,
                    view_supply.view,
                    view_supply.admitted,
                    view_supply.canonical_bytes,
                    view_supply.admitted_canonical_bytes,
                )
                .map_err(|error| OwnerAssembleError::Refused {
                    owner: "context assembly",
                    error,
                })?;
                let cue_activation = produce_cue_activation(
                    cue_supply.request,
                    cue_supply.result,
                    cue_supply.target_bindings,
                    &view,
                )
                .map_err(|error| OwnerAssembleError::Refused {
                    owner: "cue activation",
                    error,
                })?;
                let session_snapshot =
                    produce_session_snapshot(session_snapshot, &view).map_err(|error| {
                        OwnerAssembleError::Refused {
                            owner: "Governor session projection",
                            error,
                        }
                    })?;
                let critical_attention = produce_attention_projection(attention_projection, &view)
                    .map_err(|error| OwnerAssembleError::Refused {
                        owner: "critical attention",
                        error,
                    })?;
                let integration_coverage = produce_coverage_profile(coverage_profile, &view)
                    .map_err(|error| OwnerAssembleError::Refused {
                        owner: "host/runtime coverage",
                        error,
                    })?;
                let policy = produce_delivery_policy(policy_value).map_err(|error| {
                    OwnerAssembleError::Refused {
                        owner: "delivery policy",
                        error,
                    }
                })?;
                Ok(AssembledReactiveInputs {
                    view,
                    cue_activation,
                    session_snapshot,
                    critical_attention,
                    integration_coverage,
                    policy,
                })
            }
            (view, cue, session, attention, coverage, policy) => {
                let partial = ReactiveOwnerSupply {
                    view,
                    cue,
                    session,
                    attention,
                    coverage,
                    policy,
                };
                Err(OwnerAssembleError::Missing {
                    missing: partial.missing_owners(),
                })
            }
        }
    }
}
