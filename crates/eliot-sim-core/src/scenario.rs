//! Mandatory scenario set with explicit dispositions.
//!
//! The eleven scenarios below are the minimum from `I18.41`. Each one is
//! either [`ScenarioDisposition::Modeled`] — the pure core drives it end to
//! end — or [`ScenarioDisposition::CoverageGap`] — the pure core models the
//! contract fragment and names the live proof that must cover the rest.
//! Anything outside the pure boundary is [`ScenarioDisposition::Unsupported`]
//! and fails closed through [`ScenarioId::from_slug`]. Watchdog and testd
//! loss are modeled as loss of supervision signal only; the watchdog and
//! testd crates are intentionally untouched by this crate.

use crate::command::CommandKind;
use crate::command::{
    EffectClass, FencingToken, OpId, PromotionAction, SimCommand, StoreOutcome, SupervisionSource,
};
use crate::digest::{Canonical, SimDigest};
use crate::event::DeliveryFault;
use crate::fault::{Failpoint, FaultPlan, FaultPlanError, ScriptedFault};

/// Identifier of one mandatory simulation scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ScenarioId {
    /// A stale lease/fencing token must never commit.
    StaleFencing,
    /// A duplicated command or effect must apply at most once.
    DuplicateDelivery,
    /// An effect committed, then its acknowledgement was lost.
    AckLossAfterCommit,
    /// The writer/scheduler/kernel restarted mid-run.
    WriterRestart,
    /// The store outcome is unknown: torn write, timeout, or lost reply.
    UnknownStoreOutcome,
    /// Cancellation raced completion.
    CancelCompleteRace,
    /// Promotion, cutover, and rollback raced.
    PromotionCutoverRollbackRace,
    /// Mailbox overload shed load within bound.
    OverloadShedding,
    /// Output from an old generation arrived after an epoch change.
    OldGenerationRejection,
    /// Watchdog liveness was lost during a run.
    WatchdogLoss,
    /// Test daemon liveness was lost during a run.
    TestdLoss,
}

impl ScenarioId {
    /// All eleven mandatory scenarios in stable order.
    pub const ALL: [Self; 11] = [
        Self::StaleFencing,
        Self::DuplicateDelivery,
        Self::AckLossAfterCommit,
        Self::WriterRestart,
        Self::UnknownStoreOutcome,
        Self::CancelCompleteRace,
        Self::PromotionCutoverRollbackRace,
        Self::OverloadShedding,
        Self::OldGenerationRejection,
        Self::WatchdogLoss,
        Self::TestdLoss,
    ];

    /// Returns the stable slug used in artifacts and canonical encodings.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::StaleFencing => "stale-fencing",
            Self::DuplicateDelivery => "duplicate-delivery",
            Self::AckLossAfterCommit => "ack-loss-after-commit",
            Self::WriterRestart => "writer-restart",
            Self::UnknownStoreOutcome => "unknown-store-outcome",
            Self::CancelCompleteRace => "cancel-complete-race",
            Self::PromotionCutoverRollbackRace => "promotion-cutover-rollback-race",
            Self::OverloadShedding => "overload-shedding",
            Self::OldGenerationRejection => "old-generation-rejection",
            Self::WatchdogLoss => "watchdog-loss",
            Self::TestdLoss => "testd-loss",
        }
    }

    /// Returns the human-readable title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Self::StaleFencing => "Stale lease and fencing token refusal",
            Self::DuplicateDelivery => "Duplicate command and effect delivery",
            Self::AckLossAfterCommit => "Effect committed then acknowledgement lost",
            Self::WriterRestart => "Writer, scheduler, and kernel restart",
            Self::UnknownStoreOutcome => "Unknown store outcome",
            Self::CancelCompleteRace => "Cancellation versus completion race",
            Self::PromotionCutoverRollbackRace => "Promotion, cutover, and rollback race",
            Self::OverloadShedding => "Mailbox overload and load shedding",
            Self::OldGenerationRejection => "Old generation output after epoch change",
            Self::WatchdogLoss => "Watchdog loss during a run",
            Self::TestdLoss => "Test daemon loss during a run",
        }
    }

    /// Resolves a slug to its scenario. Unknown slugs fail closed as
    /// [`SimError::UnsupportedScenario`]: the pure boundary cannot model
    /// them, and the error names the adapter scope that could.
    pub fn from_slug(slug: &str) -> Result<Self, SimError> {
        Self::ALL
            .iter()
            .find(|id| id.slug() == slug)
            .copied()
            .ok_or_else(|| SimError::UnsupportedScenario {
                slug: slug.to_owned(),
                reason: "outside the pure simulation boundary; model it through an external adapter scope instead",
            })
    }
}

/// Disposition of one scenario against the pure boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioDisposition {
    /// The pure core drives the scenario end to end.
    Modeled,
    /// The pure core models the contract fragment; the named live proof
    /// must cover the remainder. A gap is explicit, never silent.
    CoverageGap {
        /// What the pure model cannot cover.
        reason: &'static str,
        /// Proof class that must cover the remainder.
        compensating_proof: &'static str,
    },
    /// Outside the pure boundary; not runnable here.
    Unsupported {
        /// Why this crate cannot run it.
        reason: &'static str,
    },
}

impl Canonical for ScenarioDisposition {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("scenario-disposition");
        match self {
            Self::Modeled => digest.feed_str("modeled"),
            Self::CoverageGap {
                reason,
                compensating_proof,
            } => {
                digest.feed_str("coverage-gap");
                digest.feed_str(reason);
                digest.feed_str(compensating_proof);
            }
            Self::Unsupported { reason } => {
                digest.feed_str("unsupported");
                digest.feed_str(reason);
            }
        }
    }
}

/// One mandatory scenario with its disposition and remaining live proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryScenario {
    /// Scenario identifier.
    pub id: ScenarioId,
    /// Boundary disposition.
    pub disposition: ScenarioDisposition,
    /// Real-edge or live fault proof still required per `I18.41`. A
    /// simulation `PASS` proves only the modeled contracts.
    pub live_proof_required: &'static str,
}

/// The eleven mandatory scenarios in stable order.
pub const MANDATORY_SCENARIOS: [MandatoryScenario; 11] = [
    MandatoryScenario {
        id: ScenarioId::StaleFencing,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live fencing-token rotation against the real store edge",
    },
    MandatoryScenario {
        id: ScenarioId::DuplicateDelivery,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live redelivery through the real transport edge",
    },
    MandatoryScenario {
        id: ScenarioId::AckLossAfterCommit,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live acknowledgement-loss injection on the real commit path",
    },
    MandatoryScenario {
        id: ScenarioId::WriterRestart,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live writer kill and restart with durable readback",
    },
    MandatoryScenario {
        id: ScenarioId::UnknownStoreOutcome,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live torn-write and timeout injection on the real store edge",
    },
    MandatoryScenario {
        id: ScenarioId::CancelCompleteRace,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live cancel-during-complete injection with real preemption",
    },
    MandatoryScenario {
        id: ScenarioId::PromotionCutoverRollbackRace,
        disposition: ScenarioDisposition::CoverageGap {
            reason: "logical race order modeled; wall-clock preemption interleavings need a real scheduler",
            compensating_proof: "Loom, Shuttle, or Turmoil adapter race proof plus a live cutover drill",
        },
        live_proof_required: "live promotion, cutover, and rollback drill with real preemption",
    },
    MandatoryScenario {
        id: ScenarioId::OverloadShedding,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live overload against the real mailbox with shed accounting readback",
    },
    MandatoryScenario {
        id: ScenarioId::OldGenerationRejection,
        disposition: ScenarioDisposition::Modeled,
        live_proof_required: "live epoch change with a lagging writer on the real generation edge",
    },
    MandatoryScenario {
        id: ScenarioId::WatchdogLoss,
        disposition: ScenarioDisposition::CoverageGap {
            reason: "pure core models loss of supervision signal only; watchdog timing and sibling-domain behavior live in the watchdog crates, which this crate must not edit",
            compensating_proof: "live watchdog-kill drill proving PARTIAL or UNKNOWN coverage, never false success",
        },
        live_proof_required: "live watchdog loss with independent coverage readback",
    },
    MandatoryScenario {
        id: ScenarioId::TestdLoss,
        disposition: ScenarioDisposition::CoverageGap {
            reason: "pure core models loss of test-daemon signal only; real scheduling and evidence behavior live outside",
            compensating_proof: "live test-daemon loss drill proving UNKNOWN outcome handling, never false pass",
        },
        live_proof_required: "live test-daemon loss with outcome-denominator readback",
    },
];

/// Error for scenario resolution and definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimError {
    /// The slug names no mandatory scenario.
    UnsupportedScenario {
        /// Requested slug.
        slug: String,
        /// Why the pure boundary cannot run it.
        reason: &'static str,
    },
    /// The fault plan failed closed validation.
    InvalidPlan(FaultPlanError),
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedScenario { slug, reason } => {
                write!(f, "unsupported scenario {slug}: {reason}")
            }
            Self::InvalidPlan(error) => write!(f, "invalid fault plan: {error}"),
        }
    }
}

impl std::error::Error for SimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedScenario { .. } => None,
            Self::InvalidPlan(error) => Some(error),
        }
    }
}

/// Executable definition of one scenario: mailbox capacity, the initial
/// command queue in submission order, and the fault plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioDefinition {
    /// Scenario identifier.
    pub id: ScenarioId,
    /// Mailbox capacity for the run.
    pub mailbox_capacity: u32,
    /// Initial commands in submission order.
    pub initial: Vec<SimCommand>,
    /// Fault plan.
    pub plan: FaultPlan,
}

impl Canonical for ScenarioDefinition {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("scenario-definition");
        digest.feed_str(self.id.slug());
        digest.feed_u32(self.mailbox_capacity);
        digest.feed_u64(u64::try_from(self.initial.len()).unwrap_or(u64::MAX));
        for command in &self.initial {
            command.feed(digest);
        }
        self.plan.feed(digest);
    }
}

fn fencing(epoch: u64, seq: u64) -> FencingToken {
    FencingToken { epoch, seq }
}

fn submit(op: u32, epoch: u64, seq: u64, generation: u64) -> SimCommand {
    SimCommand::Submit {
        op: OpId(op),
        fencing: fencing(epoch, seq),
        effect: EffectClass::ExactlyOnce,
        generation,
    }
}

fn scripted(
    kind: CommandKind,
    occurrence: u32,
    fault: DeliveryFault,
    delay_ticks: u64,
) -> ScriptedFault {
    ScriptedFault {
        kind,
        occurrence,
        fault,
        delay_ticks,
    }
}

/// Builds the executable definition for one mandatory scenario.
#[allow(
    clippy::too_many_lines,
    reason = "declarative scenario table: one literal definition per mandatory scenario"
)]
#[must_use]
pub fn define(id: ScenarioId) -> ScenarioDefinition {
    match id {
        ScenarioId::StaleFencing => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 3, 7, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                submit(2, 2, 9, 1),
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::DuplicateDelivery => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::Ack { op: OpId(1) },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::AckPath,
                    Failpoint::CommitPath,
                ],
                script: vec![
                    scripted(CommandKind::Submit, 0, DeliveryFault::Duplicated, 0),
                    scripted(CommandKind::Ack, 0, DeliveryFault::Duplicated, 0),
                ],
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::AckLossAfterCommit => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::Ack { op: OpId(1) },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::AckPath,
                ],
                script: vec![scripted(CommandKind::Ack, 0, DeliveryFault::Lost, 0)],
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::WriterRestart => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                submit(2, 1, 2, 1),
                SimCommand::RestartWriter,
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 2,
                },
                SimCommand::Complete {
                    op: OpId(2),
                    generation: 2,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::LifecyclePath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::UnknownStoreOutcome => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Unknown,
                },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::CancelCompleteRace => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            // Two opposed races in one deterministic run. Op 1 cancels while
            // still pending, so cancellation wins; op 2's cancel is scripted
            // two ticks late, so it arrives after a durable commit and
            // completion, and completion wins with the commit standing.
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::Cancel { op: OpId(1) },
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
                submit(2, 1, 2, 1),
                SimCommand::StoreRespond {
                    op: OpId(2),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::Cancel { op: OpId(2) },
                SimCommand::Complete {
                    op: OpId(2),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::CommitPath,
                ],
                script: vec![scripted(CommandKind::Cancel, 1, DeliveryFault::Delayed, 2)],
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::PromotionCutoverRollbackRace => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                SimCommand::EpochMove {
                    action: PromotionAction::Promote,
                    epoch: 2,
                },
                SimCommand::EpochMove {
                    action: PromotionAction::Cutover,
                    epoch: 3,
                },
                SimCommand::EpochMove {
                    action: PromotionAction::Rollback,
                    epoch: 2,
                },
            ],
            plan: FaultPlan {
                armed: vec![Failpoint::EpochPath],
                // Genuine reorder virtualization: the first and third moves
                // are held past the second, so delivery order inverts
                // submission order and the last delivered move still wins.
                script: vec![
                    scripted(CommandKind::EpochMove, 0, DeliveryFault::Reordered, 2),
                    scripted(CommandKind::EpochMove, 2, DeliveryFault::Reordered, 1),
                ],
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::OverloadShedding => ScenarioDefinition {
            id,
            mailbox_capacity: 2,
            initial: vec![
                submit(1, 1, 1, 1),
                submit(2, 1, 2, 1),
                submit(3, 1, 3, 1),
                submit(4, 1, 4, 1),
                SimCommand::ShedLoad { count: 1 },
            ],
            plan: FaultPlan {
                armed: vec![Failpoint::SubmitPath, Failpoint::MailboxPath],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::OldGenerationRejection => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::EpochMove {
                    action: PromotionAction::Promote,
                    epoch: 2,
                },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
                submit(2, 2, 1, 1),
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::EpochPath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::WatchdogLoss => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                SimCommand::Heartbeat {
                    source: SupervisionSource::Watchdog,
                },
                SimCommand::Heartbeat {
                    source: SupervisionSource::Testd,
                },
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::DropSupervision {
                    source: SupervisionSource::Watchdog,
                },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SupervisionPath,
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
        ScenarioId::TestdLoss => ScenarioDefinition {
            id,
            mailbox_capacity: 8,
            initial: vec![
                SimCommand::Heartbeat {
                    source: SupervisionSource::Watchdog,
                },
                SimCommand::Heartbeat {
                    source: SupervisionSource::Testd,
                },
                submit(1, 1, 1, 1),
                SimCommand::StoreRespond {
                    op: OpId(1),
                    outcome: StoreOutcome::Committed,
                },
                SimCommand::DropSupervision {
                    source: SupervisionSource::Testd,
                },
                SimCommand::Complete {
                    op: OpId(1),
                    generation: 1,
                },
            ],
            plan: FaultPlan {
                armed: vec![
                    Failpoint::SupervisionPath,
                    Failpoint::SubmitPath,
                    Failpoint::StoreResponsePath,
                    Failpoint::CommitPath,
                ],
                script: Vec::new(),
                background_jitter_max_ticks: 0,
            },
        },
    }
}
