//! Explicit activation lifecycle state and resume-identity revalidation.
//!
//! Implementation: I1.5 (demand-start, observable use, supervision and idle
//! shutdown) and I18.53 (ACT-2/3/4 scenario identities). This module owns only
//! the contract shapes: the activation contour state vocabulary, the one
//! record binding the seven lifecycle identity families for an activation,
//! and the suspend/resume identity comparison. It stores nothing, observes
//! nothing, and admits nothing.
//!
//! Durable ownership boundary: the `HostStateJournal` owns the activation
//! lineage (`EliotActivationRecord`); the Kernel owns leases in ORS. This
//! record is the shared shape both sides project, never a second lineage.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_contracts::{EpochId, ProductId, ResourceGeneration, StateFence};

use super::{RuntimeContractError, RuntimeLease, SupervisionLease};

/// Kernel-visible activation contour state (I1.5 `EliotActivationRecord`
/// state vocabulary). A projection of Kernel-owned facts, never a rival
/// durable lineage: only [`ActivationContourState::Active`] contours may
/// carry admitted work, and only together with the Kernel and independent
/// Watchdog readiness signals the admission path proves separately.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationContourState {
    /// Fully stopped; the next trigger starts a fresh activation.
    Stopped,
    /// Activation branches are starting.
    Starting,
    /// Control contour is ready; supervised work is not admitted yet.
    ControlReady,
    /// Live contour with admitted work.
    Active,
    /// Ordered drain is running.
    Draining,
    /// Clean stop after a linearized drain.
    StoppedClean,
    /// Failed or timed-out drain awaiting recovery.
    DegradedRecovery,
    /// Terminal failure.
    Failed,
}

impl ActivationContourState {
    /// Frozen activation-state spelling shared with the durable record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "STOPPED",
            Self::Starting => "STARTING",
            Self::ControlReady => "CONTROL_READY",
            Self::Active => "ACTIVE",
            Self::Draining => "DRAINING",
            Self::StoppedClean => "STOPPED_CLEAN",
            Self::DegradedRecovery => "DEGRADED_RECOVERY",
            Self::Failed => "FAILED",
        }
    }

    /// Whether this contour state may carry admitted work at all. Material
    /// admission additionally requires the live Kernel readiness signal and
    /// the independently supervised Watchdog readiness signal for the exact
    /// current fence; this predicate never grants either by itself.
    #[must_use]
    pub const fn may_carry_admitted_work(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// One explicit lifecycle record binding the seven identity families of an
/// activation (I18.53: every scenario records exact Product, Activation and
/// WorkScope identities): Product, Activation, WorkScope, runtime lease,
/// supervision lease, epoch/generation, and descendant registration.
///
/// The record binds identities only. Liveness, readiness, coverage and
/// authority are proven by the owning paths at use time, never read from
/// this record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationLifecycle {
    /// Product identity this activation serves.
    pub product: ProductId,
    /// Host-issued activation operation identity.
    pub activation_operation_id: String,
    /// Installation-scoped activation generation of this record.
    pub activation_generation: ResourceGeneration,
    /// Kernel authority epoch bound to this activation.
    pub authority_epoch: EpochId,
    /// State fence bound to this activation.
    pub state_fence: StateFence,
    /// Governed scope references associated with this activation.
    pub workscope_refs: Vec<String>,
    /// Runtime lease held by this activation, when one is issued.
    pub runtime_lease: Option<RuntimeLease>,
    /// Supervision lease held by this activation, when one is issued.
    pub supervision_lease: Option<SupervisionLease>,
    /// Operation identities registered as process descendants of this
    /// activation before their launch.
    pub descendant_operation_refs: Vec<String>,
    /// Current contour state of this activation.
    pub state: ActivationContourState,
}

impl ActivationLifecycle {
    /// Validates identity bindings: exact fence coherence with the carried
    /// epoch and generation, unique scope and descendant references, and
    /// lease validity with lease fences bound to this activation fence.
    /// Lease lifecycle state is owned by the lease paths and is never
    /// decided here.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        non_blank(&self.activation_operation_id, "activation_operation_id")?;
        self.state_fence.validate()?;
        if self.state_fence.authority_epoch != self.authority_epoch
            || self.state_fence.resource_generation != self.activation_generation
        {
            return Err(RuntimeContractError::InvalidField {
                field: "state_fence",
                reason: "fence is not bound to this activation epoch and generation",
            });
        }
        unique_non_blank(&self.workscope_refs, "workscope_refs")?;
        unique_non_blank(&self.descendant_operation_refs, "descendant_operation_refs")?;
        if let Some(lease) = &self.runtime_lease {
            lease.validate()?;
            if lease.state_fence != self.state_fence {
                return Err(RuntimeContractError::InvalidField {
                    field: "runtime_lease.state_fence",
                    reason: "lease fence is not bound to this activation fence",
                });
            }
        }
        if let Some(lease) = &self.supervision_lease {
            lease.validate()?;
            if lease.state_fence != self.state_fence {
                return Err(RuntimeContractError::InvalidField {
                    field: "supervision_lease.state_fence",
                    reason: "lease fence is not bound to this activation fence",
                });
            }
        }
        Ok(())
    }
}

/// Process identity that survives PID reuse: the PID plus the OS start
/// instant that disambiguates a recycled PID value (I1.4: surviving child
/// PIDs are never adopted as a new lineage).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeProcessIdentity {
    /// OS process identifier.
    pub pid: u32,
    /// Process start instant in 100ns ticks.
    pub start_100ns: u64,
}

/// User-broker registration identity (I1.3/I1.6: installation, authorized
/// SID, user-session ID, boot session, artifact hash, launch nonce). A new
/// `user_broker_epoch` fences the previous registration (I1.4).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeBrokerIdentity {
    /// Authorized Windows SID of the registration.
    pub windows_sid: String,
    /// Interactive session identity of the registration.
    pub interactive_session_id: String,
    /// Boot session identity the registration was taken under.
    pub boot_session_id: String,
    /// Broker-local epoch fencing previous registrations.
    pub user_broker_epoch: u64,
}

/// Exact identity snapshot compared across a suspend/hibernate/logoff resume
/// (I1.5: resume never trusts pre-suspend PID, pipe, `UserBrokerEpoch`, lease
/// expiry or store lock; ACT-4 adds the authority epoch).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeIdentitySnapshot {
    /// OS boot identity current when the snapshot was taken.
    pub boot_id: String,
    /// Process identity current when the snapshot was taken.
    pub process: ResumeProcessIdentity,
    /// Named-pipe peer expectation current when the snapshot was taken.
    pub pipe_expectation: String,
    /// Authority epoch current when the snapshot was taken.
    pub authority_epoch: EpochId,
    /// Broker registration identity current when the snapshot was taken.
    pub broker: ResumeBrokerIdentity,
    /// Live runtime and supervision lease identities current when the
    /// snapshot was taken.
    pub lease_ids: Vec<String>,
}

impl ResumeIdentitySnapshot {
    /// Validates snapshot shape. Malformed snapshots cannot anchor a resume
    /// comparison and are rejected before any trust decision.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        non_blank(&self.boot_id, "boot_id")?;
        non_blank(&self.pipe_expectation, "pipe_expectation")?;
        non_blank(&self.broker.windows_sid, "broker.windows_sid")?;
        non_blank(
            &self.broker.interactive_session_id,
            "broker.interactive_session_id",
        )?;
        non_blank(&self.broker.boot_session_id, "broker.boot_session_id")?;
        unique_non_blank(&self.lease_ids, "lease_ids")?;
        Ok(())
    }
}

/// One compared resume-identity family.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResumeIdentityFamily {
    /// OS boot identity.
    Boot,
    /// PID plus start instant.
    Process,
    /// Named-pipe peer expectation.
    Pipe,
    /// Authority epoch.
    Epoch,
    /// Broker registration (`UserBrokerEpoch` contour).
    Broker,
    /// Runtime and supervision lease identities.
    Lease,
}

impl ResumeIdentityFamily {
    /// Frozen family spelling for the recorded coverage gap.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Process => "pid",
            Self::Pipe => "pipe",
            Self::Epoch => "epoch",
            Self::Broker => "broker",
            Self::Lease => "lease",
        }
    }
}

/// Verdict for one compared resume-identity family. Trust requires positive
/// equality; anything else is stale, never silently continuous.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResumeIdentityVerdict {
    /// Presented identity exactly matches current observation.
    Current,
    /// Presented identity differs from current observation and must not be
    /// reused.
    Stale,
}

/// Outcome of one suspend/resume identity revalidation. When any family is
/// stale the caller records the coverage gap (ACT-4) and revalidates
/// boot/session identity, generations, cursors, ORS and pending effects
/// before reopening `ACTIVE`; the intervening interval is replayed, partial
/// or blind, never silently continuous (I1.5).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRevalidation {
    /// Per-family verdicts in comparison order.
    pub verdicts: Vec<(ResumeIdentityFamily, ResumeIdentityVerdict)>,
    /// True only when every compared family is current.
    pub all_current: bool,
    /// Stale families the caller must record as the coverage gap. Empty
    /// exactly when `all_current` holds.
    pub coverage_gap_families: Vec<ResumeIdentityFamily>,
}

/// Revalidates pre-suspend identities against current observation.
///
/// Every presented pre-suspend identity is honored only on exact equality
/// with current observation: a changed boot, a recycled or replaced PID, a
/// different pipe expectation, a moved authority epoch, a fenced broker
/// registration, or a lease identity that is no longer live is stale and
/// must not be reused. A presented lease set must be fully live in current
/// observation; newly issued current leases beyond the presented set are
/// the owner's business, not resume trust.
///
/// # Errors
///
/// Returns the shape error when either snapshot is malformed. A malformed
/// snapshot anchors nothing: the caller treats the error as fully stale.
pub fn revalidate_resume_identities(
    current: &ResumeIdentitySnapshot,
    presented: &ResumeIdentitySnapshot,
) -> Result<ResumeRevalidation, RuntimeContractError> {
    current.validate()?;
    presented.validate()?;
    let mut verdicts = Vec::with_capacity(6);
    let mut stale = Vec::new();
    let mut compare = |family: ResumeIdentityFamily, is_current: bool| {
        verdicts.push((
            family,
            if is_current {
                ResumeIdentityVerdict::Current
            } else {
                ResumeIdentityVerdict::Stale
            },
        ));
        if !is_current {
            stale.push(family);
        }
    };
    compare(
        ResumeIdentityFamily::Boot,
        presented.boot_id == current.boot_id,
    );
    compare(
        ResumeIdentityFamily::Process,
        presented.process == current.process,
    );
    compare(
        ResumeIdentityFamily::Pipe,
        presented.pipe_expectation == current.pipe_expectation,
    );
    compare(
        ResumeIdentityFamily::Epoch,
        presented.authority_epoch == current.authority_epoch,
    );
    compare(
        ResumeIdentityFamily::Broker,
        presented.broker == current.broker,
    );
    compare(
        ResumeIdentityFamily::Lease,
        presented
            .lease_ids
            .iter()
            .all(|lease| current.lease_ids.contains(lease)),
    );
    Ok(ResumeRevalidation {
        verdicts,
        all_current: stale.is_empty(),
        coverage_gap_families: stale,
    })
}

fn non_blank(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.trim().is_empty() {
        return Err(RuntimeContractError::Blank { field });
    }
    Ok(())
}

fn unique_non_blank(values: &[String], field: &'static str) -> Result<(), RuntimeContractError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        non_blank(value, field)?;
        if !seen.insert(value) {
            return Err(RuntimeContractError::InvalidField {
                field,
                reason: "duplicate identity",
            });
        }
    }
    Ok(())
}
