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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupBindingSlot {
    capability: DeclaredStartupCapability,
    disposition: StartupBindingDisposition,
}

/// The retained startup binding ledger for one daemon generation.
///
/// Construction requires one disposition per declared capability, so a
/// generation cannot reach the readiness decision with a capability silently
/// skipped. Readiness is read from the recorded slots through
/// [`Self::is_complete`]; there is no separate hard-coded readiness constant
/// that could disagree with what was actually observed.
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
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.slots.iter().all(|slot| slot.disposition.is_bound())
    }

    /// Returns the exact reason each unbound capability did not bind, in
    /// declaration order. Empty exactly when [`Self::is_complete`] holds.
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
