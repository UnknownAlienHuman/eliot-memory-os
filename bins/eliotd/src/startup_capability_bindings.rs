//! Explicit startup capability binding ledger for the `eliotd` composition root
//! (issue #18, item A).
//!
//! The composition root declares seven startup capabilities it must be bound to
//! before it may report Governor readiness. Control flow alone cannot express
//! that: a `?` on an attach call removes the daemon from the process, and a
//! `let _context = …; Ok(())` proves a binding only by dropping the value that
//! proves it. Both were rejected. This module makes each declared capability
//! carry one explicit, retained disposition instead:
//!
//! ```text
//! Bound(RetainedStartupBinding)  — the exact admitted identity/descriptor the
//!                                  attach produced is retained here;
//! Unbound(reason)                — the exact reason the attach did not bind.
//! ```
//!
//! The denominator is closed and compile-checked: a
//! [`StartupCapabilityBindings`] value cannot be constructed without a
//! disposition for every entry of [`DeclaredStartupCapability::ALL`], and
//! readiness is derived from the recorded slots rather than from a literal.
//! Nothing here owns a capability, a lifecycle, or readiness semantics: the
//! Governor composition stays the single owner of the underlying state, and the
//! ledger only records what the composition root observed at startup.
//!
//! #2560: "all seven bound" is not a readiness question, so this module
//! refuses to answer one. It exposes three genuinely different queries and the
//! evidence each one rests on:
//!
//! ```text
//! all_slots_accounted_for                  — does every declared slot carry a
//!                                            disposition, and does every
//!                                            retained proof belong to the slot
//!                                            that files it;
//! every_declared_capability_bound          — the strict union of all seven
//!                                            slots (full-health startup only);
//! per-slot disposition / declared_slot     — the availability of the one
//!                                            capability an operation uses.
//! ```
//!
//! The core-readiness and per-operation verdicts live in
//! [`crate::startup_readiness`], which reads this ledger and the composition's
//! live owners. A name like "is complete" cannot be read as "ready" from here,
//! because no such name exists any more.
//!
//! Architecture traceability: A2.3 (a material capability has one causal owner
//! and an explicit public contract) and A13.8 (integrity evidence and visible
//! degradation). Implementation traceability: I1.5 starts only the capabilities
//! an admitted request requires, so a capability that did not bind stays
//! visibly not-ready instead of being reported as ready.

use eliot_contracts::RequestMetadata;

use crate::AgentFabricDescriptor;

/// The closed denominator of startup capabilities the composition root declares
/// it must bind before reporting Governor readiness.
///
/// Exactly one entry exists per startup attach site in
/// `daemon_runtime::run`. The order is the declaration order and is mirrored
/// by the ledger's slot array and by the ledger's constructor parameters, so a
/// declared capability can never be added, dropped, or reordered silently.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeclaredStartupCapability {
    /// Kernel-issued owner session binding noted into the composition
    /// (AUD-C02-B / #1187).
    OwnerSessionBinding,
    /// Canonical notification snapshot hydrated into the board (#1780).
    NotificationSnapshot,
    /// Gated Dreamer intake registration (T12-06).
    DreamerIntake,
    /// Gated Dreamer model-call registration (T12-07).
    DreamerModel,
    /// Durable agent-fabric registration (#872).
    AgentFabric,
    /// Canonical Skill tool source built through the Governor hook (#1882).
    SkillToolSource,
    /// Installed-Skill tool-basis reconciliation against the live canonical
    /// tool view (#1882).
    SkillToolBasis,
}

impl DeclaredStartupCapability {
    /// The closed declaration order, one entry per startup attach site.
    pub const ALL: [Self; Self::COUNT] = [
        Self::OwnerSessionBinding,
        Self::NotificationSnapshot,
        Self::DreamerIntake,
        Self::DreamerModel,
        Self::AgentFabric,
        Self::SkillToolSource,
        Self::SkillToolBasis,
    ];

    /// Number of declared startup capabilities.
    pub const COUNT: usize = 7;

    /// The slot index of this declared capability in [`Self::ALL`].
    ///
    /// Total by construction and total over the same closed denominator, so
    /// the ledger can index its slot array by declaration without an optional
    /// lookup that could silently miss.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::OwnerSessionBinding => 0,
            Self::NotificationSnapshot => 1,
            Self::DreamerIntake => 2,
            Self::DreamerModel => 3,
            Self::AgentFabric => 4,
            Self::SkillToolSource => 5,
            Self::SkillToolBasis => 6,
        }
    }

    /// Returns the stable capability name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerSessionBinding => "owner-session-binding",
            Self::NotificationSnapshot => "notification-snapshot",
            Self::DreamerIntake => "dreamer-intake",
            Self::DreamerModel => "dreamer-model",
            Self::AgentFabric => "agent-fabric",
            Self::SkillToolSource => "skill-tool-source",
            Self::SkillToolBasis => "skill-tool-basis",
        }
    }
}

/// The exact retained evidence that one attach produced.
///
/// Each variant keeps the admitted identity or descriptor the attach proved,
/// not a boolean: the value is retained by the composition root for the
/// lifetime of the process and rendered into the startup readiness record, so
/// nothing that proves a binding is dropped at the end of a helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedStartupBinding {
    /// The validated Kernel-issued session binding the composition was noted
    /// with. Identity refs only, never a secret.
    OwnerSession {
        /// Validated `sid=..;session=..` binding string.
        session_binding: String,
        /// Local connection correlation id.
        connection_id: String,
    },
    /// The verified canonical notification page noted into the board.
    NotificationSnapshot {
        /// Records retained in the composition.
        record_count: usize,
    },
    /// The fence-bound read context the Dreamer intake route admitted.
    DreamerIntakeRoute(RequestMetadata),
    /// The fence-bound read context the Dreamer model route admitted.
    DreamerModelRoute(RequestMetadata),
    /// The admitted durable agent-fabric descriptor (#872).
    AgentFabric(AgentFabricDescriptor),
    /// The Governor-admitted canonical Skill tool definition version.
    SkillToolSource {
        /// Definition version the Skill delivery driver runs under.
        admitted_definition_version: String,
    },
    /// The installed-Skill entries this startup pass marked stale.
    SkillToolBasis {
        /// Entries newly marked stale against the live canonical tool view.
        marked_stale: usize,
    },
}

impl RetainedStartupBinding {
    /// The one declared slot whose own attach produces this retained proof.
    ///
    /// The mapping is total and one-to-one, which is what lets the ledger
    /// reject a proof filed under a foreign slot. Positional construction
    /// cannot express that check — `StartupCapabilityBindings::new` takes seven
    /// arguments in declaration order, so a refactor can hand slot *n* the
    /// value slot *m* produced without a type error. That is a binding defect,
    /// not a satisfied capability, and it stays fail-closed.
    #[must_use]
    pub const fn declared_slot(&self) -> DeclaredStartupCapability {
        match self {
            Self::OwnerSession { .. } => DeclaredStartupCapability::OwnerSessionBinding,
            Self::NotificationSnapshot { .. } => DeclaredStartupCapability::NotificationSnapshot,
            Self::DreamerIntakeRoute(_) => DeclaredStartupCapability::DreamerIntake,
            Self::DreamerModelRoute(_) => DeclaredStartupCapability::DreamerModel,
            Self::AgentFabric(_) => DeclaredStartupCapability::AgentFabric,
            Self::SkillToolSource { .. } => DeclaredStartupCapability::SkillToolSource,
            Self::SkillToolBasis { .. } => DeclaredStartupCapability::SkillToolBasis,
        }
    }

    /// Renders the exact retained identity as a bounded diagnostic fragment.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::OwnerSession {
                session_binding,
                connection_id,
            } => format!("session={session_binding} connection={connection_id}"),
            Self::NotificationSnapshot { record_count } => {
                format!("record_count={record_count}")
            }
            Self::DreamerIntakeRoute(metadata) => route_identity("dreamer_intake", metadata),
            Self::DreamerModelRoute(metadata) => route_identity("dreamer_model", metadata),
            Self::AgentFabric(descriptor) => format!(
                "service={} generation={} authority_epoch={} capacity_identity={}",
                descriptor.service,
                descriptor.generation,
                descriptor.authority_epoch,
                descriptor.capacity_identity
            ),
            Self::SkillToolSource {
                admitted_definition_version,
            } => format!("admitted_definition_version={admitted_definition_version}"),
            Self::SkillToolBasis { marked_stale } => format!("marked_stale={marked_stale}"),
        }
    }
}

fn route_identity(route: &str, metadata: &RequestMetadata) -> String {
    format!(
        "route={route} request_id={} product_id={} source_id={} generation={} authority_epoch={} task_revision={}",
        metadata.request_id.as_str(),
        metadata.product_id.as_str(),
        metadata.source_id.as_str(),
        metadata.state_fence.resource_generation.value(),
        metadata.state_fence.authority_epoch.sequence.get(),
        metadata
            .state_fence
            .task_revision
            .as_ref()
            .map_or("none".to_owned(), |revision| revision.value().to_string())
    )
}

/// One declared capability's explicit binding disposition.
///
/// The retained evidence is boxed so the disposition stays a small
/// two-word value: the ledger holds seven of them, and only the unbound arm
/// ever carries a reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartupBindingDisposition {
    /// The capability is bound and its proof is retained.
    Bound(Box<RetainedStartupBinding>),
    /// The capability is not bound, with the exact reason observed at the
    /// attach site. A non-empty reason is a fail-closed requirement: an
    /// unattached capability can never read as bound.
    Unbound(String),
}

impl StartupBindingDisposition {
    /// Returns whether this capability is bound.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        matches!(self, Self::Bound(_))
    }

    /// Returns the exact reason this capability is unbound, or `None` when it
    /// is bound.
    #[must_use]
    pub fn unbound_reason(&self) -> Option<&str> {
        match self {
            Self::Bound(_) => None,
            Self::Unbound(reason) => Some(reason.as_str()),
        }
    }

    /// Returns whether this disposition answers for `capability`.
    ///
    /// An exact unbound reason always answers: a missing capability is a real,
    /// fail-closed account of its slot, distinct from a bound one. A bound
    /// disposition answers only when the retained proof is the evidence that
    /// slot's own attach produced. A proof filed under a foreign slot answers
    /// for nothing — neither accounted nor available.
    #[must_use]
    pub fn proves_slot(&self, capability: DeclaredStartupCapability) -> bool {
        match self {
            Self::Bound(retained) => retained.declared_slot() == capability,
            Self::Unbound(_) => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupBindingSlot {
    capability: DeclaredStartupCapability,
    disposition: StartupBindingDisposition,
}

/// Whole-ledger accounting outcome: are all declared slots accounted for?
///
/// Deliberately distinct from the other two questions a caller can ask this
/// ledger. A ledger can be fully accounted while an optional capability is
/// unavailable, and a single misfiled optional proof breaks accounting without
/// touching any core prerequisite. Callers that treat this as readiness would
/// reintroduce exactly the #2560 conflation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotAccounting {
    /// Every declared capability carries one disposition, and every retained
    /// proof belongs to the slot that files it.
    Accounted {
        /// Declared slots whose own attach produced a retained proof.
        bound: usize,
        /// Declared slots holding an exact unbound reason. These are visible
        /// degradation, not an accounting gap.
        unavailable: usize,
    },
    /// A slot files proof produced by a different declared capability's
    /// attach. Fail-closed: the misfiled slot is neither accounted nor bound,
    /// whatever the other six slots record.
    Misattributed {
        /// The declared slot whose retained proof came from another attach.
        slot: DeclaredStartupCapability,
        /// The declared slot whose attach actually produced that proof.
        retained_for: DeclaredStartupCapability,
    },
}

impl SlotAccounting {
    /// Returns whether every declared slot is accounted for.
    #[must_use]
    pub const fn is_accounted(&self) -> bool {
        matches!(self, Self::Accounted { .. })
    }
}

/// The retained startup binding ledger for one daemon generation.
///
/// Construction requires one disposition per declared capability, so a
/// generation cannot reach any verdict with a capability silently skipped.
/// The verdicts themselves are read from the recorded slots, never from a
/// hard-coded constant that could disagree with what was actually observed:
/// [`Self::all_slots_accounted_for`] answers the accounting question,
/// [`Self::every_declared_capability_bound`] answers the strict full-health
/// question, and [`Self::disposition`] answers the per-operation question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupCapabilityBindings {
    slots: [StartupBindingSlot; DeclaredStartupCapability::COUNT],
}

impl StartupCapabilityBindings {
    /// Records the seven declared dispositions in declaration order.
    ///
    /// The parameter list is the denominator: adding, removing, or reordering a
    /// declared capability is a compile error at this call site, and no site can
    /// drop one silently.
    #[must_use]
    pub fn new(
        owner_session_binding: StartupBindingDisposition,
        notification_snapshot: StartupBindingDisposition,
        dreamer_intake: StartupBindingDisposition,
        dreamer_model: StartupBindingDisposition,
        agent_fabric: StartupBindingDisposition,
        skill_tool_source: StartupBindingDisposition,
        skill_tool_basis: StartupBindingDisposition,
    ) -> Self {
        Self {
            slots: [
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::OwnerSessionBinding,
                    disposition: owner_session_binding,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::NotificationSnapshot,
                    disposition: notification_snapshot,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::DreamerIntake,
                    disposition: dreamer_intake,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::DreamerModel,
                    disposition: dreamer_model,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::AgentFabric,
                    disposition: agent_fabric,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::SkillToolSource,
                    disposition: skill_tool_source,
                },
                StartupBindingSlot {
                    capability: DeclaredStartupCapability::SkillToolBasis,
                    disposition: skill_tool_basis,
                },
            ],
        }
    }

    /// Returns true when every declared capability is bound.
    ///
    /// This is the strict union of all seven slots — a fully healthy startup,
    /// nothing weaker and nothing stronger. It is deliberately **not** a
    /// readiness answer: a notification, Dreamer, Skill or agent-fabric attach
    /// can fail and leave this `false` while core control readiness still
    /// holds, and (once a slot is re-evaluated) it can become `true` again
    /// after a later generation binds. Use
    /// [`crate::startup_readiness::StartupReadinessProjection::core_readiness_prerequisites_satisfied`]
    /// for the core verdict and
    /// [`Self::all_slots_accounted_for`] for the accounting verdict.
    #[must_use]
    pub fn every_declared_capability_bound(&self) -> bool {
        self.slots.iter().all(|slot| {
            slot.disposition.is_bound() && slot.disposition.proves_slot(slot.capability)
        })
    }

    /// Returns the accounting verdict for the whole declared denominator.
    ///
    /// Every declared capability is accounted for when it carries one
    /// disposition, including an exact unbound reason, and every bound
    /// disposition files the proof its own slot's attach produced. A single
    /// misfiled proof fails the whole ledger: a misattributed slot is not a
    /// bound capability, and it is not a missing one either.
    #[must_use]
    pub fn all_slots_accounted_for(&self) -> SlotAccounting {
        let mut bound = 0_usize;
        let mut unavailable = 0_usize;
        for slot in &self.slots {
            match &slot.disposition {
                StartupBindingDisposition::Bound(retained)
                    if retained.declared_slot() == slot.capability =>
                {
                    bound += 1;
                }
                StartupBindingDisposition::Bound(retained) => {
                    return SlotAccounting::Misattributed {
                        slot: slot.capability,
                        retained_for: retained.declared_slot(),
                    };
                }
                StartupBindingDisposition::Unbound(_) => unavailable += 1,
            }
        }
        SlotAccounting::Accounted { bound, unavailable }
    }

    /// Returns the recorded disposition for one declared capability.
    ///
    /// `slots` is built in [`DeclaredStartupCapability::ALL`] order and
    /// [`DeclaredStartupCapability::index`] is total over the same closed
    /// denominator, so the lookup cannot miss; the assertion keeps the two
    /// denominators from drifting apart silently.
    #[must_use]
    pub fn disposition(&self, capability: DeclaredStartupCapability) -> &StartupBindingDisposition {
        &self.slots[capability.index()].disposition
    }

    /// Files a freshly observed disposition for exactly one declared slot and
    /// returns the disposition it replaced.
    ///
    /// Crate-internal on purpose: only the startup readiness projection may
    /// re-file a slot, from evidence the owning attach or a demand-driven
    /// re-read actually produced. A caller cannot hand the ledger a
    /// disposition for a capability it did not observe, cannot widen the
    /// affected set past one slot, and cannot re-file the whole ledger in one
    /// call. It is also not a way to mark a capability bound: `Bound` still
    /// requires a [`RetainedStartupBinding`] the owner produced.
    pub(crate) fn replace_disposition(
        &mut self,
        capability: DeclaredStartupCapability,
        disposition: StartupBindingDisposition,
    ) -> StartupBindingDisposition {
        let slot = &mut self.slots[capability.index()];
        debug_assert_eq!(
            slot.capability, capability,
            "startup slot array diverged from the declared declaration order"
        );
        std::mem::replace(&mut slot.disposition, disposition)
    }

    /// Returns the exact reason each unbound capability did not bind, in
    /// declaration order. Empty exactly when
    /// [`Self::every_declared_capability_bound`] holds.
    #[must_use]
    pub fn unbound_reasons(&self) -> Vec<(DeclaredStartupCapability, String)> {
        self.slots
            .iter()
            .filter_map(|slot| {
                slot.disposition
                    .unbound_reason()
                    .map(|reason| (slot.capability, reason.to_owned()))
            })
            .collect()
    }

    /// Renders the whole ledger as one bounded, deterministic record: every
    /// declared capability with its exact retained identity or its exact
    /// unbound reason. This is what makes the retained evidence observable
    /// instead of dropped.
    #[must_use]
    pub fn report(&self) -> String {
        self.slots
            .iter()
            .map(|slot| match &slot.disposition {
                StartupBindingDisposition::Bound(retained) => {
                    format!(
                        "{}:bound({})",
                        slot.capability.as_str(),
                        retained.identity()
                    )
                }
                StartupBindingDisposition::Unbound(reason) => {
                    format!("{}:unbound({reason})", slot.capability.as_str())
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}
