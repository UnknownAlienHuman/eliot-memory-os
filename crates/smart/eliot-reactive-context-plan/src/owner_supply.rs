//! Owner-supply reads for the six reactive projections (#1942 lane D).
//!
//! Each `supply_*` function reads one canonical owner snapshot — the owner's
//! immutable canonical JSON bytes served through the durable restore path
//! (Store/Kernel) — decodes it under an explicit [`StateFence`], and runs the
//! existing intrinsic validation. The six reads compose into one coherent
//! fence-bound set via [`read_owner_projection_set`], which additionally
//! checks the task/scope/attempt/host joins the planner requires. Feed
//! drivers (bridge `reactive_runtime_composition`, daemon
//! `reactive_projection_feed`) consume the set; planning/selection stay in
//! the planner.
//!
//! Canonical owners and stores (per value):
//!
//! ```text
//! view            context-assembly owner: assembled A15 closure snapshot;
//!                   bound by view.binding.(task, attempt, scope, fence).
//! cue_activation  cue-activation owner: live A10 request/result pair plus
//!                   explicit target-to-atom bindings; bound by request seeds
//!                   and request fence to the live view binding.
//! session         session/delivery owner: delivery-history snapshot with
//!                   original operation identity; bound by
//!                   (task, attempt, scope, fence).
//! attention       attention owner: obligation snapshot with retained owner
//!                   closures; bound by (task, scope, fence). Open critical
//!                   members stay sticky downstream; supply resolves nothing.
//! coverage        host/coverage owner: capability-observation snapshot;
//!                   bound by fence plus recipient/host/runtime identity and
//!                   generations. Gaps stay explicit; supply infers nothing.
//! policy          policy owner: versioned limits/choices record; bound by
//!                   operation/request/plan identity (checked at feed time
//!                   against the session history and live activation — the
//!                   policy carries no fence of its own).
//! ```
//!
//! Fail-closed supply: empty, oversize, undecodable, invalid, or
//! fence/binding-mismatched owner bytes are returned as
//! [`OwnerSupplyError`] — a missing owner stays withheld upstream, never a
//! fabricated projection and never a silent default. Digests are always the
//! owner-issued stored values re-validated here, never recomputed guesses:
//! a digest mismatch fails the read.
//!
//! Residual ownership note: no live in-tree handle for the six owner stores
//! exists yet (no typed snapshot reads keyed by session/fence serving these
//! canonical JSON snapshots). Reads therefore operate on owner-issued
//! snapshot bytes threaded through the restore/central-export path. The
//! missing piece is the owner-snapshot publication contract (canonical
//! snapshot identities per I07-18 plus serving reads), owned by the
//! Store/Kernel restore path and the daemon central export — reported to the
//! manager as the exact blocker, not rerouted silently.
//!
//! Read-path discipline: the decoders below are the ingestion edge ONLY.
//! Validated sets are retained by
//! [`crate::owner_retention::ReactiveOwnerRetention`] keyed by
//! (session, fence), and feed drivers read from retention — never from fresh
//! caller bytes. [`OwnerProjectionSet`] fields are private so only
//! [`read_owner_projection_set`] can construct a set.

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection, IntegrationCoverageProfile,
    SessionDeliverySnapshot,
};
use eliot_contracts::StateFence;
use serde::de::DeserializeOwned;

use crate::input::{ReactiveCueActivation, ReactiveDeliveryPolicy};
use crate::settled_plan_feed::SettledPlanFeedInputs;

/// Maximum canonical JSON bytes accepted for one owner snapshot.
///
/// Mirrors the A15 retained-input ceiling so a single projection can never
/// exceed what the planner itself retains.
pub const MAX_OWNER_SNAPSHOT_BYTES: usize = 256 * 1024;

/// Maximum characters retained in one supply diagnostic detail.
const MAX_SUPPLY_DETAIL_CHARS: usize = 256;

/// Owner-issued canonical snapshot bytes for one read-set evaluation.
///
/// Every field is the owning owner's immutable snapshot; empty means the
/// owner has nothing served (withheld upstream), never an empty projection.
#[derive(Clone, Copy, Debug)]
pub struct OwnerProjectionBytes<'a> {
    /// Context-assembly owner snapshot (`ContextPlanningView` JSON).
    pub view: &'a [u8],
    /// Cue-activation owner snapshot (`ReactiveCueActivation` JSON).
    pub cue_activation: &'a [u8],
    /// Session/delivery owner snapshot (`SessionDeliverySnapshot` JSON).
    pub session: &'a [u8],
    /// Attention owner snapshot (`CriticalAttentionProjection` JSON).
    pub attention: &'a [u8],
    /// Host/coverage owner snapshot (`IntegrationCoverageProfile` JSON).
    pub coverage: &'a [u8],
    /// Policy owner record (`ReactiveDeliveryPolicy` JSON).
    pub policy: &'a [u8],
}

/// Six validated owner projections coherent under one fence.
///
/// Constructible only via [`read_owner_projection_set`]: field privacy plus
/// the retention read path below guarantee no literal-assembled set ever
/// reaches planning. The validated set is retained by
/// [`crate::owner_retention::ReactiveOwnerRetention`] keyed by
/// (session, fence); feed drivers read from retention, never from fresh
/// caller bytes.
#[derive(Clone, Debug)]
pub struct OwnerProjectionSet {
    /// Supplied planning view closure.
    view: ContextPlanningView,
    /// Supplied cue activation joined to `view`.
    cue_activation: ReactiveCueActivation,
    /// Supplied session delivery snapshot.
    session: SessionDeliverySnapshot,
    /// Supplied critical attention projection.
    attention: CriticalAttentionProjection,
    /// Supplied integration coverage profile.
    coverage: IntegrationCoverageProfile,
    /// Supplied delivery policy.
    policy: ReactiveDeliveryPolicy,
}

impl OwnerProjectionSet {
    /// Borrow the supplied planning view closure.
    pub fn view(&self) -> &ContextPlanningView {
        &self.view
    }

    /// Borrow the supplied cue activation joined to the view.
    pub fn cue_activation(&self) -> &ReactiveCueActivation {
        &self.cue_activation
    }

    /// Borrow the supplied session delivery snapshot.
    pub fn session(&self) -> &SessionDeliverySnapshot {
        &self.session
    }

    /// Borrow the supplied critical attention projection.
    pub fn attention(&self) -> &CriticalAttentionProjection {
        &self.attention
    }

    /// Borrow the supplied integration coverage profile.
    pub fn coverage(&self) -> &IntegrationCoverageProfile {
        &self.coverage
    }

    /// Borrow the supplied delivery policy.
    pub fn policy(&self) -> &ReactiveDeliveryPolicy {
        &self.policy
    }
    /// Borrow the set as feed inputs for one settled-plan evaluation.
    pub fn feed_inputs(&self) -> SettledPlanFeedInputs<'_> {
        SettledPlanFeedInputs {
            view: &self.view,
            cue_activation: &self.cue_activation,
            session_snapshot: &self.session,
            critical_attention: &self.attention,
            integration_coverage: &self.coverage,
            policy: &self.policy,
        }
    }

    /// Check the planner's cross-projection joins under the explicit fence.
    ///
    /// Mirrors the task/scope/attempt/fence/identity joins of the planner's
    /// own cross-binding validation without re-running selection: view,
    /// session, attention, and coverage must agree with the fence and with
    /// each other; the cue request must agree with the fence (its view join
    /// was already enforced at supply time).
    fn check_coherent(&self, fence: &StateFence) -> Result<(), OwnerSupplyError> {
        let binding = &self.view.view.binding;
        if binding.state_fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch { projection: "view" });
        }
        if self.session.state_fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch { projection: "session" });
        }
        if self.attention.state_fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch {
                projection: "attention",
            });
        }
        if self.coverage.state_fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch {
                projection: "coverage",
            });
        }
        if self.cue_activation.request.state_fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch {
                projection: "cue_activation",
            });
        }
        if self.session.task_id != binding.task_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "session",
                field: "session.task_id",
            });
        }
        if self.session.attempt_id.as_str() != binding.attempt_id.as_str() {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "session",
                field: "session.attempt_id",
            });
        }
        if self.session.scope_id != binding.scope_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "session",
                field: "session.scope_id",
            });
        }
        if self.attention.task_id != binding.task_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "attention",
                field: "attention.task_id",
            });
        }
        if self.attention.scope_id != binding.scope_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "attention",
                field: "attention.scope_id",
            });
        }
        if self.coverage.recipient_id != self.session.recipient_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "coverage",
                field: "coverage.recipient_id",
            });
        }
        if self.coverage.host_id != self.session.host_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "coverage",
                field: "coverage.host_id",
            });
        }
        if self.coverage.runtime_id != self.session.runtime_id {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "coverage",
                field: "coverage.runtime_id",
            });
        }
        if self.coverage.host_generation != self.session.host_generation {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "coverage",
                field: "coverage.host_generation",
            });
        }
        if self.coverage.runtime_generation != self.session.runtime_generation {
            return Err(OwnerSupplyError::BindingMismatch {
                projection: "coverage",
                field: "coverage.runtime_generation",
            });
        }
        Ok(())
    }
}

/// Fail-closed owner-supply errors. Any arm withholds the read set: nothing
/// is planned, admitted, or delivered after the error point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerSupplyError {
    /// The evaluation fence itself is invalid (zero resource generation).
    InvalidFence,
    /// The owner has no snapshot served for this projection.
    Empty {
        /// Projection without served owner bytes.
        projection: &'static str,
    },
    /// The served bytes exceed the retained-input ceiling.
    Oversize {
        /// Projection whose bytes exceed the ceiling.
        projection: &'static str,
    },
    /// The served bytes do not decode as the projection.
    Decode {
        /// Projection whose bytes failed to decode.
        projection: &'static str,
        /// Bounded decode diagnostic.
        detail: String,
    },
    /// The decoded projection fails its intrinsic validation.
    Invalid {
        /// Projection that failed validation.
        projection: &'static str,
        /// Bounded validation diagnostic.
        detail: String,
    },
    /// The projection's fence disagrees with the explicit read fence.
    FenceMismatch {
        /// Projection evaluated under a foreign fence.
        projection: &'static str,
    },
    /// A cross-projection identity join disagrees.
    BindingMismatch {
        /// Projection carrying the disagreeing join.
        projection: &'static str,
        /// Exact disagreeing field.
        field: &'static str,
    },
    /// The process-scoped projection retention is full.
    RetentionFull,
}

impl std::fmt::Display for OwnerSupplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFence => write!(formatter, "owner supply fence is invalid"),
            Self::Empty { projection } => {
                write!(formatter, "owner supply withheld: no {projection} snapshot served")
            }
            Self::Oversize { projection } => {
                write!(formatter, "owner supply rejected: {projection} exceeds byte ceiling")
            }
            Self::Decode { projection, detail } => {
                write!(formatter, "owner supply rejected: {projection} decode: {detail}")
            }
            Self::Invalid { projection, detail } => {
                write!(formatter, "owner supply rejected: {projection} invalid: {detail}")
            }
            Self::FenceMismatch { projection } => write!(
                formatter,
                "owner supply stale: {projection} disagrees with the read fence"
            ),
            Self::BindingMismatch { projection, field } => write!(
                formatter,
                "owner supply conflicted: {projection}.{field} disagrees"
            ),
            Self::RetentionFull => write!(
                formatter,
                "owner supply rejected: projection retention is full"
            ),
        }
    }
}

impl std::error::Error for OwnerSupplyError {}

fn bounded_detail(detail: String) -> String {
    if detail.chars().count() > MAX_SUPPLY_DETAIL_CHARS {
        detail.chars().take(MAX_SUPPLY_DETAIL_CHARS).collect()
    } else {
        detail
    }
}

fn decode_owner_snapshot<T: DeserializeOwned>(
    projection: &'static str,
    bytes: &[u8],
) -> Result<T, OwnerSupplyError> {
    if bytes.is_empty() {
        return Err(OwnerSupplyError::Empty { projection });
    }
    if bytes.len() > MAX_OWNER_SNAPSHOT_BYTES {
        return Err(OwnerSupplyError::Oversize { projection });
    }
    serde_json::from_slice(bytes).map_err(|error| OwnerSupplyError::Decode {
        projection,
        detail: bounded_detail(error.to_string()),
    })
}

fn check_read_fence(fence: &StateFence) -> Result<(), OwnerSupplyError> {
    fence
        .validate()
        .map_err(|_| OwnerSupplyError::InvalidFence)
}

/// Supply the planning view from the context-assembly owner's snapshot.
///
/// Reads the owner's canonical snapshot bytes, runs the existing intrinsic
/// validation, and binds the closure to the explicit read fence via its
/// view binding. The assembly owner owns view content; supply retains and
/// checks it but mints nothing.
pub fn supply_context_planning_view(
    fence: &StateFence,
    bytes: &[u8],
) -> Result<ContextPlanningView, OwnerSupplyError> {
    const PROJECTION: &str = "view";
    check_read_fence(fence)?;
    let view: ContextPlanningView = decode_owner_snapshot(PROJECTION, bytes)?;
    view.validate().map_err(|error| OwnerSupplyError::Invalid {
        projection: PROJECTION,
        detail: bounded_detail(error.to_string()),
    })?;
    if view.view.binding.state_fence != *fence {
        return Err(OwnerSupplyError::FenceMismatch {
            projection: PROJECTION,
        });
    }
    Ok(view)
}

/// Supply the cue activation from the cue-activation owner's snapshot.
///
/// Reads the owner's canonical A10 request/result snapshot (including the
/// explicit target-to-atom bindings), runs the existing join validation
/// against the supplied live view, and binds the request fence to the
/// explicit read fence. Cues enter only through request seeds whose
/// task/scope/fence equal the view binding; a target without a binding stays
/// frontier evidence. The cue owner owns firing evaluation; supply retains
/// and checks the pair but evaluates nothing.
pub fn supply_reactive_cue_activation(
    fence: &StateFence,
    bytes: &[u8],
    view: &ContextPlanningView,
) -> Result<ReactiveCueActivation, OwnerSupplyError> {
    const PROJECTION: &str = "cue_activation";
    check_read_fence(fence)?;
    let activation: ReactiveCueActivation = decode_owner_snapshot(PROJECTION, bytes)?;
    activation
        .validate_against(view)
        .map_err(|error| OwnerSupplyError::Invalid {
            projection: PROJECTION,
            detail: bounded_detail(error.to_string()),
        })?;
    if activation.request.state_fence != *fence {
        return Err(OwnerSupplyError::FenceMismatch {
            projection: PROJECTION,
        });
    }
    Ok(activation)
}

/// Supply the session snapshot from the session/delivery owner's snapshot.
///
/// Reads the owner's canonical delivery-history snapshot (original operation
/// identity preserved per record), runs the existing intrinsic validation
/// including denominator and digest binds, and binds the history to the
/// explicit read fence. The session owner owns delivery history; supply
/// retains and checks it but rewrites no original operation.
pub fn supply_session_delivery_snapshot(
    fence: &StateFence,
    bytes: &[u8],
) -> Result<SessionDeliverySnapshot, OwnerSupplyError> {
    const PROJECTION: &str = "session";
    check_read_fence(fence)?;
    let snapshot: SessionDeliverySnapshot = decode_owner_snapshot(PROJECTION, bytes)?;
    snapshot
        .validate()
        .map_err(|error| OwnerSupplyError::Invalid {
            projection: PROJECTION,
            detail: bounded_detail(error.to_string()),
        })?;
    if snapshot.state_fence != *fence {
        return Err(OwnerSupplyError::FenceMismatch {
            projection: PROJECTION,
        });
    }
    Ok(snapshot)
}

/// Supply the attention projection from the attention owner's snapshot.
///
/// Reads the owner's canonical obligation snapshot with retained owner
/// closures, runs the existing intrinsic validation (terminal members must
/// already carry verified evidence or a resolution receipt), and binds the
/// obligations to the explicit read fence. Open critical members stay sticky
/// downstream until the resolving owner records a durable terminal
/// disposition; supply resolves, waives, or supersedes nothing.
pub fn supply_critical_attention_projection(
    fence: &StateFence,
    bytes: &[u8],
) -> Result<CriticalAttentionProjection, OwnerSupplyError> {
    const PROJECTION: &str = "attention";
    check_read_fence(fence)?;
    let projection: CriticalAttentionProjection = decode_owner_snapshot(PROJECTION, bytes)?;
    projection
        .validate()
        .map_err(|error| OwnerSupplyError::Invalid {
            projection: PROJECTION,
            detail: bounded_detail(error.to_string()),
        })?;
    if projection.state_fence != *fence {
        return Err(OwnerSupplyError::FenceMismatch {
            projection: PROJECTION,
        });
    }
    Ok(projection)
}

/// Supply the coverage profile from the host/coverage owner's snapshot.
///
/// Reads the owner's canonical capability-observation snapshot, runs the
/// existing intrinsic validation (fresh claims require retained evidence;
/// incomplete profiles require explicit gaps), and binds the observations to
/// the explicit read fence. A disappeared advisory hook stays an explicit
/// gap; supply derives no coverage and infers no enforcement.
pub fn supply_integration_coverage_profile(
    fence: &StateFence,
    bytes: &[u8],
) -> Result<IntegrationCoverageProfile, OwnerSupplyError> {
    const PROJECTION: &str = "coverage";
    check_read_fence(fence)?;
    let profile: IntegrationCoverageProfile = decode_owner_snapshot(PROJECTION, bytes)?;
    profile
        .validate()
        .map_err(|error| OwnerSupplyError::Invalid {
            projection: PROJECTION,
            detail: bounded_detail(error.to_string()),
        })?;
    if profile.state_fence != *fence {
        return Err(OwnerSupplyError::FenceMismatch {
            projection: PROJECTION,
        });
    }
    Ok(profile)
}

/// Supply the delivery policy from the policy owner's record.
///
/// Reads the owner's canonical versioned limits/choices record and runs the
/// existing intrinsic validation including the self-verifying digest. The
/// policy carries operation/request/plan identity rather than a fence: it is
/// bound at feed time against the session history and the live activation
/// (plan identity), so supply takes no fence. The policy owner owns limits
/// and choices; supply grants no authority and admits nothing.
pub fn supply_reactive_delivery_policy(
    bytes: &[u8],
) -> Result<ReactiveDeliveryPolicy, OwnerSupplyError> {
    const PROJECTION: &str = "policy";
    let policy: ReactiveDeliveryPolicy = decode_owner_snapshot(PROJECTION, bytes)?;
    policy
        .validate()
        .map_err(|error| OwnerSupplyError::Invalid {
            projection: PROJECTION,
            detail: bounded_detail(error.to_string()),
        })?;
    Ok(policy)
}

/// Read the six owner projections as one coherent fence-bound set.
///
/// Supplies each projection from its owner snapshot bytes in dependency
/// order (view first — the cue join needs it), then checks the
/// task/scope/attempt/host joins the planner requires. Any absent,
/// oversize, undecodable, invalid, or mismatched owner withholds the whole
/// set: a partial set is never returned for planning.
pub fn read_owner_projection_set(
    fence: &StateFence,
    bytes: &OwnerProjectionBytes<'_>,
) -> Result<OwnerProjectionSet, OwnerSupplyError> {
    check_read_fence(fence)?;
    let view = supply_context_planning_view(fence, bytes.view)?;
    let cue_activation = supply_reactive_cue_activation(fence, bytes.cue_activation, &view)?;
    let session = supply_session_delivery_snapshot(fence, bytes.session)?;
    let attention = supply_critical_attention_projection(fence, bytes.attention)?;
    let coverage = supply_integration_coverage_profile(fence, bytes.coverage)?;
    let policy = supply_reactive_delivery_policy(bytes.policy)?;
    let set = OwnerProjectionSet {
        view,
        cue_activation,
        session,
        attention,
        coverage,
        policy,
    };
    set.check_coherent(fence)?;
    Ok(set)
}
