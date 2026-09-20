//! Deterministic fault injection: failpoints, scripted faults, and plans.
//!
//! Faults strike only at named transition boundaries ([`Failpoint`]). A
//! [`ScriptedFault`] names the n-th submitted command of one
//! [`CommandKind`](crate::command::CommandKind) and the [`DeliveryFault`](crate::event::DeliveryFault)
//! to apply to it. A [`FaultPlan`] bundles the armed failpoints, the script,
//! and the background jitter budget. [`FaultPlan::validate`] fails closed:
//! a script entry whose failpoint is not armed is rejected before the run
//! starts instead of silently changing the schedule.

use crate::command::CommandKind;
use crate::digest::{Canonical, SimDigest};
use crate::event::DeliveryFault;

/// Named transition boundary where a fault may strike.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Failpoint {
    /// Command submission path.
    SubmitPath,
    /// Completion path.
    CommitPath,
    /// Acknowledgement path.
    AckPath,
    /// Store response path, including torn and unknown commits.
    StoreResponsePath,
    /// Supervisor heartbeat path.
    SupervisionPath,
    /// Epoch promotion, cutover, and rollback path.
    EpochPath,
    /// Mailbox and load-shedding path.
    MailboxPath,
    /// Writer lifecycle and restart path.
    LifecyclePath,
}

impl Failpoint {
    /// Returns the failpoint guarding one command kind.
    #[must_use]
    pub const fn for_kind(kind: CommandKind) -> Self {
        match kind {
            CommandKind::Submit | CommandKind::Cancel => Self::SubmitPath,
            CommandKind::Complete => Self::CommitPath,
            CommandKind::StoreRespond => Self::StoreResponsePath,
            CommandKind::Ack => Self::AckPath,
            CommandKind::Heartbeat | CommandKind::DropSupervision => Self::SupervisionPath,
            CommandKind::EpochMove => Self::EpochPath,
            CommandKind::ShedLoad => Self::MailboxPath,
            CommandKind::RestartWriter => Self::LifecyclePath,
        }
    }

    /// Returns the stable tag used in canonical encodings.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::SubmitPath => "submit-path",
            Self::CommitPath => "commit-path",
            Self::AckPath => "ack-path",
            Self::StoreResponsePath => "store-response-path",
            Self::SupervisionPath => "supervision-path",
            Self::EpochPath => "epoch-path",
            Self::MailboxPath => "mailbox-path",
            Self::LifecyclePath => "lifecycle-path",
        }
    }
}

/// One scripted fault: the n-th submitted command of `kind` (zero-based
/// `occurrence`) suffers `fault`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ScriptedFault {
    /// Command kind to target.
    pub kind: CommandKind,
    /// Zero-based occurrence of that kind to target.
    pub occurrence: u32,
    /// Fault to apply.
    pub fault: DeliveryFault,
    /// Ticks of delay for [`DeliveryFault::Delayed`] and [`DeliveryFault::Reordered`].
    pub delay_ticks: u64,
}

/// Error for fail-closed fault-plan validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultPlanError {
    /// A script entry targets a failpoint that is not armed.
    UnarmedFailpoint {
        /// Command kind tag.
        kind_tag: &'static str,
        /// Failpoint tag.
        failpoint_tag: &'static str,
    },
    /// A loss was scripted for a command kind that scenarios must deliver.
    LossOnRequiredPath {
        /// Command kind tag.
        kind_tag: &'static str,
    },
}

/// Deterministic fault-injection plan for one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    /// Failpoints allowed to strike during the run.
    pub armed: Vec<Failpoint>,
    /// Scripted faults in declaration order.
    pub script: Vec<ScriptedFault>,
    /// Background jitter budget: every envelope may gain up to this many
    /// extra ticks of seeded delay. Zero disables jitter. All mandatory
    /// scenarios use zero so each fault in the trace is explicitly scripted.
    pub background_jitter_max_ticks: u64,
}

impl FaultPlan {
    /// Builds a plan with no armed failpoints, no script, and no jitter.
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            armed: Vec::new(),
            script: Vec::new(),
            background_jitter_max_ticks: 0,
        }
    }

    /// Returns true when the failpoint guarding `kind` is armed.
    #[must_use]
    pub fn armed_for(&self, kind: CommandKind) -> bool {
        self.armed.contains(&Failpoint::for_kind(kind))
    }

    /// Fails closed on unarmed script entries and on loss scripted for
    /// submissions and store responses, which mandatory scenarios must
    /// always deliver at least once.
    pub fn validate(&self) -> Result<(), FaultPlanError> {
        for entry in &self.script {
            let failpoint = Failpoint::for_kind(entry.kind);
            if !self.armed.contains(&failpoint) {
                return Err(FaultPlanError::UnarmedFailpoint {
                    kind_tag: kind_tag(entry.kind),
                    failpoint_tag: failpoint.tag(),
                });
            }
            if entry.fault == DeliveryFault::Lost
                && matches!(entry.kind, CommandKind::Submit | CommandKind::StoreRespond)
            {
                return Err(FaultPlanError::LossOnRequiredPath {
                    kind_tag: kind_tag(entry.kind),
                });
            }
        }
        Ok(())
    }
}

/// Returns the stable tag for one command kind.
#[must_use]
pub const fn kind_tag(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::Submit => "submit",
        CommandKind::Cancel => "cancel",
        CommandKind::Complete => "complete",
        CommandKind::StoreRespond => "store-respond",
        CommandKind::Ack => "ack",
        CommandKind::Heartbeat => "heartbeat",
        CommandKind::DropSupervision => "drop-supervision",
        CommandKind::EpochMove => "epoch-move",
        CommandKind::ShedLoad => "shed-load",
        CommandKind::RestartWriter => "restart-writer",
    }
}

impl Canonical for Failpoint {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("failpoint");
        digest.feed_str(self.tag());
    }
}

impl Canonical for ScriptedFault {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("scripted-fault");
        digest.feed_str(kind_tag(self.kind));
        digest.feed_u32(self.occurrence);
        self.fault.feed(digest);
        digest.feed_u64(self.delay_ticks);
    }
}

impl Canonical for FaultPlan {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("fault-plan");
        digest.feed_u64(u64::try_from(self.armed.len()).unwrap_or(u64::MAX));
        for failpoint in &self.armed {
            failpoint.feed(digest);
        }
        digest.feed_u64(u64::try_from(self.script.len()).unwrap_or(u64::MAX));
        for entry in &self.script {
            entry.feed(digest);
        }
        digest.feed_u64(self.background_jitter_max_ticks);
    }
}

impl std::fmt::Display for FaultPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnarmedFailpoint {
                kind_tag,
                failpoint_tag,
            } => write!(
                f,
                "scripted fault for {kind_tag} targets unarmed failpoint {failpoint_tag}"
            ),
            Self::LossOnRequiredPath { kind_tag } => write!(
                f,
                "loss scripted for required path {kind_tag}; scenarios must deliver it"
            ),
        }
    }
}

impl std::error::Error for FaultPlanError {}
