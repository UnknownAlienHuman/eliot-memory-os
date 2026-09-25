//! Startup readiness projection: required core prerequisites separated from
//! optional startup capability availability (issue #2560).
//!
//! The startup binding ledger ([`crate::startup_capability_bindings`]) records
//! what each of the seven declared attach sites produced. It deliberately
//! answers no readiness question, because "all seven bound", "core control is
//! ready", and "the capability this operation needs is available" are three
//! different questions with three different answers. This module owns the
//! other two and keeps them honest:
//!
//! ```text
//! core_readiness_prerequisites_satisfied   — may this generation report core
//!                                             control readiness at all?
//! capability_available_for_operation       — may this one operation use this
//!                                             one capability?
//! all_slots_accounted_for                  — is the declared denominator
//!                                             fully accounted for? (delegated)
//! ```
//!
//! # The required set is derived, never supplied
//!
//! [`CoreReadinessRequirements`] is built from exactly two sources: the closed
//! [`MANDATORY_CORE_CAPABILITIES`] constant and the composition's own reported
//! owner state. There is no public constructor that accepts a capability list,
//! so no caller — and no accepted runtime profile — can widen or narrow the
//! mandatory set, and nothing here can mark an unavailable slot bound. A
//! profile can still require a capability *for its own operation*, which is
//! what [`StartupReadinessProjection::capabilities_available_for_operation`]
//! expresses; it cannot erase a mandatory security or recovery prerequisite,
//! because the mandatory set is required unconditionally in the core verdict.
//!
//! `AgentFabric` is the worked example: it is required for work that actually
//! uses the fabric, and is not automatically required for an unrelated core
//! read. Notification, Dreamer and Skill are likewise optional: their failure
//! degrades exactly the operations that name them, and withholds nothing else.
//!
//! # No IO, no probe, no new owner
//!
//! This module performs no IO, holds no Kernel client, starts no thread, and
//! launches no model or worker. It is a pure projection over evidence that the
//! owning attach or a demand-driven re-read already returned, so a startup
//! probe here cannot become a capability start. It also owns no registry,
//! service or transport: the existing composition, Kernel client and
//! supervision producer remain the only owners.
//!
//! # Updateable without a latch and without polling
//!
//! [`StartupReadinessProjection::reevaluate_capability`] re-files exactly one
//! slot from one real owner event, so a bound capability is not a permanent
//! verdict in either direction: a startup failure can be recovered from, and a
//! later failure is recorded rather than assumed away. It re-evaluates only the
//! named slot, so it can neither sweep every optional provider nor block on
//! one. The one operation that legitimately affects every slot is owner
//! generation replacement, which goes through
//! [`StartupReadinessProjection::invalidate_for_replaced_generation`] and is
//! driven by the existing owners, not by this module.
//!
//! # Late completions adopt deltas, never snapshots
//!
//! A local-read flight prepares its operation from an immutable snapshot but
//! returns only what it actually observed: at most one [`LocalReadinessDelta`]
//! bound to the exact slot, owner outcome, owner/fence identity and
//! observation tokens captured for that work.
//! [`StartupReadinessProjection::adopt_local_delta`] files it only while that
//! basis is still current, through the existing single-slot reevaluation. A
//! late or conflicting delta is refused without touching the loop's
//! requirements, other slots or their history, while the flight's own
//! read/submit outcome still settles exactly once.
//!
//! Architecture traceability: A2.3 (dependencies are required, optional, or
//! advisory; failure of an optional Module reduces only the associated
//! capability) and A13.8 (integrity evidence and visible degradation).
//! Implementation traceability: I1.5 (startup starts only the capabilities an
//! admitted request requires; a lease or ready claim is never manufactured from
//! process survival) and I1.8 (one logical Governor with one authentic
//! generation-bound session attach).

use eliot_governor::CompositionReadiness;

use crate::DaemonComposition;
use crate::startup_capability_bindings::{
    DeclaredStartupCapability, RetainedStartupBinding, SlotAccounting, StartupBindingDisposition,
    StartupCapabilityBindings,
};

/// The closed set of declared capabilities whose bound state gates core
/// readiness for governed work.
///
/// Exactly one entry: the authenticated Kernel-issued owner session (AUD-C02-B
/// / I1.8 session attach). Session exists only while transport identity and
/// the semantic Session refer to the same State Fence and epoch, so an
/// unauthenticated or unbound owner cannot serve governed work at all.
///
/// This is a `const` in this module, not a parameter: no caller and no accepted
/// profile can widen or narrow it. The composition's own generation, fence and
/// recovery preconditions are not capabilities and are required unconditionally
/// by [`StartupReadinessProjection::core_readiness_prerequisites_satisfied`]
/// regardless of what a profile asks for.
pub const MANDATORY_CORE_CAPABILITIES: &[DeclaredStartupCapability] =
    &[DeclaredStartupCapability::OwnerSessionBinding];

/// Owner state the required-set mapping reads, at one observation.
///
/// Every field is the composition's own reported value. There is no public
/// constructor: [`observe_core_owner_state`] is the only way to obtain one, so
/// the core verdict can never be evaluated from a caller-assembled flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreOwnerState {
    /// Resource generation the composition's owners are admitted at.
    pub generation: u64,
    /// Authority epoch sequence the composition's owners are admitted at.
    pub authority_epoch: u64,
    /// The composition's own startup phase. `Ready` is the exact Kernel and
    /// owner-recovery admission the Governor reports; anything else means
    /// mandatory recovery is unresolved.
    pub readiness: CompositionReadiness,
    /// Whether the composition's dependent view is fresh at this generation.
    /// A stale view cannot serve governed work even under a `Ready` Governor.
    pub view_fresh: bool,
    /// Whether the composition reports its owner set admitted and accepting.
    pub owner_set_admitted: bool,
}

/// Reads the required-set mapping's owner facts from the live composition.
///
/// The only constructor of [`CoreOwnerState`], and the only place this module
/// touches a composition. Keeping it here is what makes "derived from the
/// accepted runtime and existing owners" structural rather than a convention.
#[must_use]
pub fn observe_core_owner_state(composition: &DaemonComposition) -> CoreOwnerState {
    let status = composition.status();
    CoreOwnerState {
        generation: status.generation,
        authority_epoch: status.authority_epoch,
        readiness: composition.readiness(),
        // `DaemonComposition::status` publishes `stale` exactly for a stale
        // dependent view. An allow-list rather than a `!= "stale"` test, so a
        // future label is fail-closed instead of silently read as fresh.
        view_fresh: matches!(status.health.as_str(), "healthy" | "degraded"),
        owner_set_admitted: status.ready,
    }
}

/// The required-set mapping for one accepted runtime and its live owners.
///
/// Holds the closed mandatory capability set together with the owner facts it
/// was derived against. Fields are private and the only constructor takes the
/// composition, so a caller cannot supply a required set of its own, cannot
/// drop a mandatory capability, and cannot mark an unavailable slot bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreReadinessRequirements {
    mandatory: &'static [DeclaredStartupCapability],
    owner_state: CoreOwnerState,
}

impl CoreReadinessRequirements {
    /// Derives the required set from the accepted runtime's live owners.
    #[must_use]
    pub fn derive(composition: &DaemonComposition) -> Self {
        Self {
            mandatory: MANDATORY_CORE_CAPABILITIES,
            owner_state: observe_core_owner_state(composition),
        }
    }

    /// The closed mandatory capability set. Read-only: nothing here can add to
    /// it or remove from it.
    #[must_use]
    pub const fn mandatory(&self) -> &'static [DeclaredStartupCapability] {
        self.mandatory
    }

    /// The owner facts this mapping was derived against.
    #[must_use]
    pub const fn owner_state(&self) -> &CoreOwnerState {
        &self.owner_state
    }
}

/// The core-readiness verdict for one daemon generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreReadiness {
    /// Every mandatory capability is bound at the current owner generation and
    /// the composition's own owner set, generation/fence and recovery
    /// preconditions hold. Optional capability availability is deliberately
    /// not part of this verdict.
    Satisfied,
    /// Core readiness is withheld. `reasons` names each unmet precondition and
    /// each mandatory capability that is not available, in declaration order,
    /// so the withholding is exact rather than a bare flag.
    Withheld {
        /// The exact unmet preconditions and mandatory-capability refusals.
        reasons: Vec<String>,
    },
}

impl CoreReadiness {
    /// Returns whether core readiness is satisfied.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// Availability of one capability for one operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAvailability {
    /// The capability is bound at the current owner generation, with the exact
    /// retained proof its own attach produced.
    Available {
        /// The declared capability being served.
        capability: DeclaredStartupCapability,
        /// The exact admitted identity or descriptor the attach produced.
        retained: String,
    },
    /// The capability is not available to this operation. `reason` is the
    /// exact fail-closed evidence: the attach's own reason, a binding defect,
    /// or a retained proof that no longer belongs to the current owner
    /// generation. It is never empty and never a count or a descriptor.
    Unavailable {
        /// The declared capability being served.
        capability: DeclaredStartupCapability,
        /// The exact fail-closed reason this operation is refused.
        reason: String,
    },
}

impl CapabilityAvailability {
    /// The declared capability this verdict is about.
    #[must_use]
    pub const fn capability(&self) -> DeclaredStartupCapability {
        match self {
            Self::Available { capability, .. } | Self::Unavailable { capability, .. } => {
                *capability
            }
        }
    }

    /// Returns whether the operation may proceed on this capability.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Returns the exact capability-specific refusal a dependent request
    /// receives, or `None` when the capability is available.
    ///
    /// This is the seam a dispatch path refuses on: it names the one missing
    /// capability, so a dependent request is refused specifically and unrelated
    /// admitted requests keep running.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&str> {
        match self {
            Self::Available { .. } => None,
            Self::Unavailable { reason, .. } => Some(reason.as_str()),
        }
    }
}

/// The real owner event that makes one slot worth reevaluating.
///
/// There is no `Tick` or `Periodic` variant on purpose: an unchanged owner
/// performs no work, and this module never sweeps every optional provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupRefreshReason {
    /// The owner advanced to a new generation or epoch and this slot's attach
    /// re-ran under it.
    OwnerRevisionAdvanced,
    /// An admitted operation demands this capability and its attach or re-read
    /// produced fresh evidence.
    CapabilityDemanded,
    /// The owner revoked or invalidated this binding. Only the owner's own
    /// evidence decides that a retained binding is no longer usable.
    OwnerInvalidated,
}

/// Fresh owner evidence for exactly one declared capability.
///
/// The caller has already run the owning attach or re-read and is handing over
/// what it returned. `observed` is therefore evidence, never an instruction:
/// `Ok` still requires the real retained proof the owner's attach produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRefresh {
    /// The declared slot the owner reevaluated.
    pub capability: DeclaredStartupCapability,
    /// The real owner event that prompted the reevaluation.
    pub reason: StartupRefreshReason,
    /// The outcome the owner returned, or the exact reason it could not bind.
    pub observed: Result<RetainedStartupBinding, String>,
}

/// What one bounded reevaluation changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRefreshOutcome {
    /// The slot now holds the freshly observed bound proof.
    Rebound {
        /// Whether the slot was already bound before this refresh. `false` is
        /// a recovery from an earlier failure, not a first bind.
        previously_bound: bool,
    },
    /// The slot is now unavailable with the owner's exact reason, or with the
    /// exact reason the accompanying observation could not be accepted.
    Unavailable {
        /// Whether the slot was bound before this refresh.
        previously_bound: bool,
    },
    /// The owner's proof belongs to a different declared slot, so the slot was
    /// filed as a binding defect and is unavailable. Fail-closed.
    Misattributed {
        /// The declared slot whose attach actually produced the proof.
        retained_for: DeclaredStartupCapability,
    },
}

/// Explicit failure when the loop-local adoption token counter exhausts.
///
/// The counter never wraps into an old token: once `u64::MAX` is issued,
/// every further mint fails with this instead of reusing a live basis. These
/// tokens are local concurrency controls, not persisted proof and not a new
/// authority epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAdoptionTokenExhausted;

impl std::fmt::Display for LocalAdoptionTokenExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("startup readiness adoption token counter exhausted; refusing to reuse a token")
    }
}

impl std::error::Error for LocalAdoptionTokenExhausted {}

/// One local-read flight's readiness observation, bound to the exact basis it
/// was observed under (issue #2647).
///
/// A flight returns at most one of these, and only when its own attach or
/// re-read actually produced an observation: empty claims and ordinary reads
/// with no refresh carry none. The delta names its exact slot, the real owner
/// outcome, the full owner/fence identity, and the owner/slot observation
/// tokens captured for that work — the delta's whole dependency set, so
/// adoption can prove it is still current without trusting a bare slot write
/// or a scalar generation comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalReadinessDelta {
    refresh: CapabilityRefresh,
    expected_owner: CoreOwnerState,
    expected_owner_token: u64,
    expected_slot_token: u64,
}

impl LocalReadinessDelta {
    /// The declared slot this delta's observation belongs to.
    #[must_use]
    pub const fn capability(&self) -> DeclaredStartupCapability {
        self.refresh.capability
    }
}

/// How one local-read delta settled against the loop's current projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalDeltaAdoption {
    /// The basis was current and the observation was filed through the
    /// existing single-slot reevaluation, with its exact outcome.
    Adopted {
        /// What the single-slot reevaluation changed.
        outcome: CapabilityRefreshOutcome,
    },
    /// The delta changed nothing: either an exact re-presentation of the last
    /// adoption for this slot, or an observation whose filing is already in
    /// place. No history rewrite, no new token, no refresh triggered.
    Duplicate,
    /// The delta's basis moved before settlement, so nothing was filed and
    /// nothing was erased. Revalidation rides the existing heartbeat owner
    /// observation and demand-driven refresh paths.
    Stale {
        /// Which half of the delta's dependency set moved.
        conflict: LocalDeltaConflict,
    },
}

/// Which half of a stale delta's dependency set moved before settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDeltaConflict {
    /// The owner context (observed fence/flag identity or its token) changed
    /// after the delta's basis was captured.
    OwnerContextChanged,
    /// The delta's own slot was re-filed after the basis was captured,
    /// including a change that later returned to equal flags.
    SlotChanged,
}

/// One slot's current projection row.
///
/// Feeds stdout, diagnostics and Kernel-facing reporting from the same
/// evaluation, so those three surfaces cannot disagree about which capability
/// is degraded or why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySlotProjection {
    /// The declared capability this row describes.
    pub capability: DeclaredStartupCapability,
    /// Whether this capability currently gates core readiness.
    pub mandatory_for_core: bool,
    /// The current availability verdict for this capability.
    pub availability: CapabilityAvailability,
    /// The immediately preceding failure reason for this slot, once the slot
    /// has moved on from it. Bounded: at most one per slot, never a log.
    pub prior_failure: Option<String>,
}

impl CapabilitySlotProjection {
    /// Renders the bounded single-line record for this slot.
    #[must_use]
    pub fn line(&self) -> String {
        let body = match &self.availability {
            CapabilityAvailability::Available { retained, .. } => {
                format!("available({retained})")
            }
            CapabilityAvailability::Unavailable { reason, .. } => {
                format!("unavailable({reason})")
            }
        };
        let mandatory = if self.mandatory_for_core {
            " mandatory"
        } else {
            ""
        };
        match &self.prior_failure {
            Some(prior) => format!(
                "{}:{body}{mandatory} prior_failure({prior})",
                self.capability.as_str()
            ),
            None => format!("{}:{body}{mandatory}", self.capability.as_str()),
        }
    }
}

/// The startup capability projection for one daemon generation.
///
/// Holds the retained ledger, the required-set mapping derived from the
/// accepted runtime's live owners, and a bounded per-slot record of the
/// failure each slot most recently moved past. It owns no capability and
/// performs no IO; see the module documentation for the lifecycle rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupReadinessProjection {
    bindings: StartupCapabilityBindings,
    requirements: CoreReadinessRequirements,
    prior_failures: [Option<String>; DeclaredStartupCapability::COUNT],
    /// #2647: loop-local adoption control. `issued_tokens` is the monotonic
    /// mint counter; `owner_token` marks the last real owner-context change;
    /// `slot_tokens` marks each slot's last disposition/history change; and
    /// `last_adopted` records each slot's most recent adopted delta plus the
    /// slot token that adoption minted, so an exact re-presentation is an
    /// idempotent duplicate rather than a second filing. Records are boxed so
    /// seven of them stay pointer-sized. These detect conflicting projection
    /// updates; they grant no capability, persist nothing, and never appear in
    /// any report.
    issued_tokens: u64,
    owner_token: u64,
    slot_tokens: [u64; DeclaredStartupCapability::COUNT],
    last_adopted: [Option<Box<(LocalReadinessDelta, u64)>>; DeclaredStartupCapability::COUNT],
}

impl StartupReadinessProjection {
    /// Builds the projection for one daemon generation from the retained
    /// startup ledger and the live composition.
    ///
    /// This is the setup step: it records what the startup attach sites
    /// actually produced and derives the required set from the composition's
    /// own owner state. It starts nothing and probes nothing.
    #[must_use]
    pub fn new(bindings: StartupCapabilityBindings, composition: &DaemonComposition) -> Self {
        Self {
            bindings,
            requirements: CoreReadinessRequirements::derive(composition),
            prior_failures: std::array::from_fn(|_| None),
            issued_tokens: 0,
            owner_token: 0,
            slot_tokens: [0; DeclaredStartupCapability::COUNT],
            last_adopted: std::array::from_fn(|_| None),
        }
    }

    /// Refreshes the owner facts the core verdict is derived from.
    ///
    /// An operational pass: it re-reads the composition's own reported
    /// generation, epoch, readiness and view freshness, and re-checks retained
    /// generation-bound proofs against them. It performs no capability IO and
    /// never re-files a slot, so a slow optional attach cannot block it.
    ///
    /// #2647: an identical periodic observation retires nothing, so a
    /// wall-clock tick alone never invalidates an in-flight delta's basis. A
    /// real owner-context change — including one within the same generation
    /// and change-away-then-back — mints a fresh owner token, which retires
    /// every basis captured under the old context.
    pub fn observe_owner(
        &mut self,
        composition: &DaemonComposition,
    ) -> Result<(), LocalAdoptionTokenExhausted> {
        let observed = CoreReadinessRequirements::derive(composition);
        if observed.owner_state() == self.requirements.owner_state() {
            return Ok(());
        }
        self.requirements = observed;
        self.owner_token = self.mint_token()?;
        Ok(())
    }

    /// Reevaluates exactly one slot from fresh owner evidence.
    ///
    /// Bounded by construction: one slot, one disposition, no IO, no other slot
    /// touched. The previous disposition is preserved as bounded history, so
    /// recovering a slot never erases the failure it recovered from and a later
    /// failure is recorded rather than assumed away. There is no permanent
    /// startup-failure latch in either direction.
    ///
    /// #2647: only a real slot change mints a fresh slot token and retires
    /// captured bases. Re-filing an identical disposition/history pair files
    /// nothing new and retires nothing.
    pub fn reevaluate_capability(
        &mut self,
        refresh: &CapabilityRefresh,
    ) -> Result<CapabilityRefreshOutcome, LocalAdoptionTokenExhausted> {
        let capability = refresh.capability;
        let previously_bound = self.bindings.disposition(capability).is_bound();
        let prior_before = self.prior_failures[capability.index()].clone();
        self.remember_prior_failure(capability);
        let filed = disposition_for_refresh(refresh);
        let misattributed = match &refresh.observed {
            Ok(retained)
                if refresh.reason != StartupRefreshReason::OwnerInvalidated
                    && retained.declared_slot() != capability =>
            {
                Some(retained.declared_slot())
            }
            _ => None,
        };
        let outcome = if let Some(retained_for) = misattributed {
            CapabilityRefreshOutcome::Misattributed { retained_for }
        } else if matches!(filed, StartupBindingDisposition::Bound(_)) {
            CapabilityRefreshOutcome::Rebound { previously_bound }
        } else {
            CapabilityRefreshOutcome::Unavailable { previously_bound }
        };
        let disposition_before = self.bindings.disposition(capability).clone();
        self.bindings.replace_disposition(capability, filed);
        let disposition_changed = self.bindings.disposition(capability) != &disposition_before;
        let history_changed = self.prior_failures[capability.index()] != prior_before;
        if disposition_changed || history_changed {
            let minted = self.mint_token()?;
            self.slot_tokens[capability.index()] = minted;
        }
        Ok(outcome)
    }

    /// Binds one flight's observation to the exact basis it was observed under.
    ///
    /// Pure: capturing a basis mints nothing and files nothing. The returned
    /// delta carries the slot, the attach's real outcome, the full owner/fence
    /// identity, and the owner/slot observation tokens read here, so
    /// [`Self::adopt_local_delta`] can prove the observation is still current.
    #[must_use]
    pub fn prepare_local_delta(&self, refresh: CapabilityRefresh) -> LocalReadinessDelta {
        let expected_slot_token = self.slot_tokens[refresh.capability.index()];
        LocalReadinessDelta {
            expected_owner: *self.requirements.owner_state(),
            expected_owner_token: self.owner_token,
            expected_slot_token,
            refresh,
        }
    }

    /// Adopts one flight's delta into the loop's projection iff its basis is
    /// still current.
    ///
    /// Only the delta's own slot can change, and only through the existing
    /// [`Self::reevaluate_capability`] filing: requirements, other slots and
    /// their failure history are preserved. A conflicting owner-context or
    /// slot change refuses adoption without touching anything; no revalidation
    /// is queued here — the heartbeat owner observation and the next
    /// demand-driven refresh re-observe through the existing paths, which
    /// coalesces any number of late completions into that one revalidation.
    /// An exact duplicate is idempotent: no history rewrite, no new token.
    pub fn adopt_local_delta(
        &mut self,
        delta: &LocalReadinessDelta,
    ) -> Result<LocalDeltaAdoption, LocalAdoptionTokenExhausted> {
        let index = delta.refresh.capability.index();
        // An exact re-presentation of the last adopted delta for this slot is
        // a duplicate — but only while neither the owner context nor the slot
        // moved since that adoption. Any intervening change falls through to
        // the freshness checks below, so change-away-then-back still refuses.
        if let Some(record) = &self.last_adopted[index] {
            let (recorded, minted) = record.as_ref();
            if recorded == delta
                && *minted == self.slot_tokens[index]
                && self.owner_token == delta.expected_owner_token
            {
                return Ok(LocalDeltaAdoption::Duplicate);
            }
        }
        // Freshness over the delta's actual dependency set only: the owner
        // context it was observed under and its own slot. Other slots never
        // gate this adoption. Owner identity is compared whole — full
        // fence/flag identity, not an ordering over scalar epochs.
        if self.owner_token != delta.expected_owner_token
            || self.requirements.owner_state() != &delta.expected_owner
        {
            return Ok(LocalDeltaAdoption::Stale {
                conflict: LocalDeltaConflict::OwnerContextChanged,
            });
        }
        if self.slot_tokens[index] != delta.expected_slot_token {
            return Ok(LocalDeltaAdoption::Stale {
                conflict: LocalDeltaConflict::SlotChanged,
            });
        }
        // The basis is current and the filing is already in place: adopting
        // would only rewrite history, so this is a duplicate, not a refresh.
        let already_filed = disposition_for_refresh(&delta.refresh);
        if self.bindings.disposition(delta.refresh.capability) == &already_filed {
            return Ok(LocalDeltaAdoption::Duplicate);
        }
        let outcome = self.reevaluate_capability(&delta.refresh)?;
        self.last_adopted[index] = Some(Box::new((delta.clone(), self.slot_tokens[index])));
        Ok(LocalDeltaAdoption::Adopted { outcome })
    }

    /// Retires every retained *generation-scoped* binding because the owner
    /// moved to a new generation, and returns how many slots were retired.
    ///
    /// Generation replacement is a real owner event that revokes every
    /// generation-bound proof at once (I1.5, I14.14), so the affected slots are
    /// retired through their owner rather than left readable.
    ///
    /// It is deliberately **not** a whole-ledger invalidation. The owner
    /// session binding, the notification page and the Skill catalogue terms
    /// carry no generation identity, and the authenticated owner session is the
    /// one mandatory core capability: retiring it here would withhold core
    /// readiness for the whole daemon on an ordinary generation advance, which
    /// is the exact conflation this issue removes. Those three slots stay with
    /// the owning owner that established them, which is also what
    /// [`retained_matches_owner_generation`] already relies on.
    ///
    /// It is not a refresh sweep: it does not re-attach, re-read or poll
    /// anything, and each retired slot keeps its prior disposition as bounded
    /// history. A retired slot is re-evaluated on the next event that actually
    /// concerns it (see [`Self::reevaluate_capability`]).
    pub fn retire_generation_scoped_bindings(
        &mut self,
        reason: &str,
    ) -> Result<usize, LocalAdoptionTokenExhausted> {
        let mut retired = 0_usize;
        for capability in DeclaredStartupCapability::ALL {
            if !is_generation_scoped(capability) {
                continue;
            }
            let disposition_before = self.bindings.disposition(capability).clone();
            let prior_before = self.prior_failures[capability.index()].clone();
            self.remember_prior_failure(capability);
            self.bindings.replace_disposition(
                capability,
                StartupBindingDisposition::Unbound(reason.to_owned()),
            );
            // #2647: retirement is a real invalidation only where it changed
            // the slot; an already-retired slot keeps its basis valid.
            let disposition_changed = self.bindings.disposition(capability) != &disposition_before;
            let history_changed = self.prior_failures[capability.index()] != prior_before;
            if disposition_changed || history_changed {
                let minted = self.mint_token()?;
                self.slot_tokens[capability.index()] = minted;
            }
            retired += 1;
        }
        Ok(retired)
    }

    /// Returns the accounting verdict for the whole declared denominator.
    #[must_use]
    pub fn all_slots_accounted_for(&self) -> SlotAccounting {
        self.bindings.all_slots_accounted_for()
    }

    /// Returns true only when every declared slot is bound with its own proof.
    ///
    /// The strict full-health union of all seven slots. It is not the core
    /// readiness answer and must not be used as one; see
    /// [`Self::core_readiness_prerequisites_satisfied`].
    #[must_use]
    pub fn every_declared_capability_bound(&self) -> bool {
        self.bindings.every_declared_capability_bound()
    }

    /// Returns the core-readiness verdict from actual owner state.
    ///
    /// The mandatory capability set and the composition's own owner set,
    /// generation/fence and recovery preconditions are all required
    /// unconditionally: optional availability is not an input, and no accepted
    /// profile can subtract from the mandatory side. A withheld verdict names
    /// each unmet precondition and each mandatory refusal, so a missing owner
    /// session, a stale view, or unresolved recovery is visible instead of
    /// inferred.
    #[must_use]
    pub fn core_readiness_prerequisites_satisfied(&self) -> CoreReadiness {
        let owner = self.requirements.owner_state();
        let mut reasons = Vec::new();
        if owner.generation == 0 || owner.authority_epoch == 0 {
            reasons.push(format!(
                "composition owner state has no admitted generation/epoch (generation={} authority_epoch={})",
                owner.generation, owner.authority_epoch
            ));
        }
        if !owner.owner_set_admitted {
            reasons.push(
                "composition reports no admitted owner set (composition status is not ready)"
                    .to_owned(),
            );
        }
        if !owner.view_fresh {
            reasons.push("composition dependent view is stale at this generation".to_owned());
        }
        if owner.readiness != CompositionReadiness::Ready {
            reasons.push(format!(
                "Governor recovery is not admitted at this generation (readiness={owner:?})"
            ));
        }
        for capability in self.requirements.mandatory() {
            let availability = self.capability_available_for_operation(*capability);
            if let CapabilityAvailability::Unavailable { capability, reason } = availability {
                reasons.push(format!(
                    "mandatory {} unavailable: {reason}",
                    capability.as_str()
                ));
            }
        }
        if reasons.is_empty() {
            CoreReadiness::Satisfied
        } else {
            CoreReadiness::Withheld { reasons }
        }
    }

    /// Returns whether one capability is available to one operation.
    ///
    /// Availability is a property of the recorded disposition and of the
    /// retained proof's own generation binding, never of a count, a non-empty
    /// descriptor or an empty page: an empty notification page proves the
    /// fenced read executed, and a non-empty one proves no more. A proof
    /// admitted at an earlier generation or epoch is not usable merely because
    /// it was retained at startup, and a proof filed under a foreign slot is
    /// never usable at all.
    #[must_use]
    pub fn capability_available_for_operation(
        &self,
        capability: DeclaredStartupCapability,
    ) -> CapabilityAvailability {
        match self.bindings.disposition(capability) {
            StartupBindingDisposition::Unbound(reason) => CapabilityAvailability::Unavailable {
                capability,
                reason: reason.clone(),
            },
            StartupBindingDisposition::Bound(retained) => {
                if retained.declared_slot() != capability {
                    return CapabilityAvailability::Unavailable {
                        capability,
                        reason: format!(
                            "startup capability {} retains proof produced by the {} attach",
                            capability.as_str(),
                            retained.declared_slot().as_str()
                        ),
                    };
                }
                if !retained_matches_owner_generation(retained, self.requirements.owner_state()) {
                    return CapabilityAvailability::Unavailable {
                        capability,
                        reason: format!(
                            "startup capability {} retains proof admitted at an earlier owner generation/epoch",
                            capability.as_str()
                        ),
                    };
                }
                CapabilityAvailability::Available {
                    capability,
                    retained: retained.identity(),
                }
            }
        }
    }

    /// Returns one availability verdict per capability one operation uses.
    ///
    /// The operation-scoped required set, as opposed to the mandatory core
    /// set: an operation names the capabilities it actually needs (the agent
    /// fabric for fabric work, the Skill slots for the Skill path) and is
    /// refused against exactly the one that is missing. Unrelated admitted
    /// work is untouched, and nothing here can relax the core verdict.
    #[must_use]
    pub fn capabilities_available_for_operation(
        &self,
        required: &[DeclaredStartupCapability],
    ) -> Vec<CapabilityAvailability> {
        required
            .iter()
            .map(|capability| self.capability_available_for_operation(*capability))
            .collect()
    }

    /// Returns the optional capabilities currently degraded, in declaration
    /// order.
    ///
    /// The exact degradation a ready-with-capability-degradation record has to
    /// show. Mandatory capabilities are excluded because their unavailability
    /// is already a withheld core verdict, not optional degradation.
    #[must_use]
    pub fn degraded_capabilities(&self) -> Vec<DeclaredStartupCapability> {
        DeclaredStartupCapability::ALL
            .into_iter()
            .filter(|capability| !self.is_mandatory_for_core(*capability))
            .filter(|capability| {
                !self
                    .capability_available_for_operation(*capability)
                    .is_available()
            })
            .collect()
    }

    /// Returns every declared slot's current projection row, in declaration
    /// order: exactly [`DeclaredStartupCapability::COUNT`] rows, so the whole
    /// declared denominator stays visible in stdout, diagnostics and
    /// Kernel-facing reporting alike.
    #[must_use]
    pub fn slot_projections(&self) -> Vec<CapabilitySlotProjection> {
        DeclaredStartupCapability::ALL
            .into_iter()
            .map(|capability| CapabilitySlotProjection {
                capability,
                mandatory_for_core: self.is_mandatory_for_core(capability),
                availability: self.capability_available_for_operation(capability),
                prior_failure: self.prior_failures[capability.index()].clone(),
            })
            .collect()
    }

    /// Renders the whole ledger as one bounded, deterministic record.
    ///
    /// The same seven dispositions the startup attach sites produced, at their
    /// original fidelity. Use [`Self::report`] for the readiness-facing record.
    #[must_use]
    pub fn ledger_report(&self) -> String {
        self.bindings.report()
    }

    /// Renders the bounded readiness record: the core verdict, the owner
    /// generation it was derived from, and every declared slot with its
    /// mandatory flag, current availability and any prior failure.
    ///
    /// A generation that is ready with degraded optional capabilities renders
    /// `core_readiness=satisfied` together with the exact degradation, so no
    /// surface can present it as a wholly healthy integration.
    #[must_use]
    pub fn report(&self) -> String {
        let owner = self.requirements.owner_state();
        let readiness = self.core_readiness_prerequisites_satisfied();
        let verdict = match &readiness {
            CoreReadiness::Satisfied => "satisfied".to_owned(),
            CoreReadiness::Withheld { reasons } => format!("withheld({})", reasons.join("; ")),
        };
        let slots = self
            .slot_projections()
            .iter()
            .map(CapabilitySlotProjection::line)
            .collect::<Vec<_>>()
            .join(", ");
        let degraded = self
            .degraded_capabilities()
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "core_readiness={verdict} owner_generation={} owner_authority_epoch={} degraded=[{degraded}] slots=[{slots}]",
            owner.generation, owner.authority_epoch
        )
    }

    fn is_mandatory_for_core(&self, capability: DeclaredStartupCapability) -> bool {
        self.requirements.mandatory().contains(&capability)
    }

    /// Records the failure a slot is about to move past, if it had one.
    ///
    /// Bounded to one retained reason per slot: the immediately preceding
    /// failure stays observable after the slot recovers, without turning the
    /// projection into an unbounded failure log.
    fn remember_prior_failure(&mut self, capability: DeclaredStartupCapability) {
        if let Some(reason) = self
            .bindings
            .disposition(capability)
            .unbound_reason()
            .map(str::to_owned)
        {
            self.prior_failures[capability.index()] = Some(reason);
        }
    }

    /// Mints one fresh adoption token. The counter never wraps: exhaustion is
    /// an explicit error, never a silent return to an old token.
    fn mint_token(&mut self) -> Result<u64, LocalAdoptionTokenExhausted> {
        let minted = self
            .issued_tokens
            .checked_add(1)
            .ok_or(LocalAdoptionTokenExhausted)?;
        self.issued_tokens = minted;
        Ok(minted)
    }
}

/// The readiness verdict one generation reports, in the exact terms
/// `DaemonStatus` publishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupReadinessVerdict {
    /// Whether this generation may report core control readiness.
    pub ready: bool,
    /// Whether normal admission is closed while the process stays observable.
    pub degraded: bool,
    /// The bounded health label. `DaemonStatus`'s own wire shape is unchanged.
    pub health: String,
    /// The core prerequisite verdict, with every unmet precondition named.
    pub core: CoreReadiness,
    /// Whether at least one optional capability is degraded.
    pub capability_degraded: bool,
}

impl StartupReadinessVerdict {
    /// Whether the mandatory core prerequisites hold.
    #[must_use]
    pub const fn core_satisfied(&self) -> bool {
        self.core.is_satisfied()
    }
}

/// Computes the reported readiness for one generation from actual owner state.
///
/// Core readiness is the composition's own readiness combined with the
/// mandatory prerequisite verdict; optional availability never withholds it,
/// only degrades it. A withheld core verdict is always also a degraded generation, so a
/// process is never reported as healthy while refusing governed work. The
/// composition's own health ladder is preserved exactly: a stopped or stale
/// composition still reports that, and only a ready generation with no degraded
/// optional capability is reported healthy.
#[must_use]
pub fn evaluate_startup_readiness(
    projection: &StartupReadinessProjection,
    composition_status: &crate::DaemonStatus,
    capability_model_restricted: bool,
) -> StartupReadinessVerdict {
    let core = projection.core_readiness_prerequisites_satisfied();
    let capability_degraded = !projection.degraded_capabilities().is_empty();
    let ready = composition_status.ready && core.is_satisfied();
    let degraded = composition_status.degraded
        || !core.is_satisfied()
        || capability_degraded
        || capability_model_restricted;
    let health = if composition_status.health == "stopped"
        || composition_status.health == "stale"
        || (ready && !capability_degraded)
    {
        composition_status.health.clone()
    } else {
        "degraded".to_owned()
    };
    StartupReadinessVerdict {
        ready,
        degraded,
        health,
        core,
        capability_degraded,
    }
}

/// Emits the bounded per-slot readiness record on the existing diagnostics sink.
///
/// The same evaluation that produced the published readiness reaches diagnostics
/// here, so stdout, diagnostics and dispatch cannot disagree about which
/// capability is degraded or why. Every declared slot is shown with its
/// mandatory flag, its exact retained binding or exact reason, its current
/// availability and any prior failure. No new transport, registry or service.
pub fn emit_startup_readiness_record(
    projection: &StartupReadinessProjection,
    verdict: &StartupReadinessVerdict,
) {
    tracing::info!(
        target: "eliotd::diagnostics",
        event = "eliotd.startup_readiness",
        core_ready = verdict.ready,
        core_satisfied = verdict.core_satisfied(),
        capability_degraded = verdict.capability_degraded,
        slots_accounted = projection.all_slots_accounted_for().is_accounted(),
        readiness = %projection.report(),
    );
}

/// Re-evaluates exactly one declared capability from evidence an admitted
/// demand produced, and reports what the reevaluation changed.
///
/// This is the demand-driven refresh an operation triggers: the operation names
/// the capability it actually needs, the owning caller supplies the re-run of
/// that capability's real attach, and the owner's own outcome is filed here.
/// Only the named slot is touched, so a demand never sweeps every optional
/// provider and never blocks on one it does not use.
///
/// `reattach` is called **only** when the slot is currently unavailable, so the
/// healthy path performs no work at all and an available capability is never
/// re-proved for an operation that already has it. This function performs no IO
/// itself: the attach belongs to the owner, which is why it arrives as a closure
/// rather than being called from here.
pub fn reevaluate_demanded_capability<F>(
    projection: &mut StartupReadinessProjection,
    capability: DeclaredStartupCapability,
    reattach: F,
) -> Result<CapabilityRefreshOutcome, LocalAdoptionTokenExhausted>
where
    F: FnOnce() -> Result<RetainedStartupBinding, String>,
{
    if projection
        .capability_available_for_operation(capability)
        .is_available()
    {
        return Ok(CapabilityRefreshOutcome::Rebound {
            previously_bound: true,
        });
    }
    projection.reevaluate_capability(&CapabilityRefresh {
        capability,
        reason: StartupRefreshReason::CapabilityDemanded,
        observed: reattach(),
    })
}

/// Returns the exact capability-specific refusal when any capability one
/// operation names is still unavailable, and `None` when the operation may
/// proceed.
///
/// This is the seam a dispatch path refuses on. It names the one missing
/// capability with the owner's own fail-closed reason, so a dependent request is
/// refused specifically and unrelated admitted requests keep running. An empty
/// required set is a caller bug rather than a permit: it refuses.
#[must_use]
pub fn refuse_unavailable_capabilities(
    projection: &StartupReadinessProjection,
    required: &[DeclaredStartupCapability],
) -> Option<String> {
    if required.is_empty() {
        return Some(
            "operation named no startup capability to check, so it cannot be admitted".to_owned(),
        );
    }
    let missing = projection
        .capabilities_available_for_operation(required)
        .into_iter()
        .find(|availability| !availability.is_available())?;
    Some(format!(
        "startup capability {} is unavailable: {}",
        missing.capability().as_str(),
        missing.refusal_reason().unwrap_or("no owner evidence")
    ))
}

/// Computes the disposition one refresh would file, without filing it.
///
/// Single source of truth for [`StartupReadinessProjection::reevaluate_capability`]
/// and the adoption duplicate check, so "already filed" can be tested without
/// rewriting history.
fn disposition_for_refresh(refresh: &CapabilityRefresh) -> StartupBindingDisposition {
    match &refresh.observed {
        // The owner reported a revocation, so a value travelling with it
        // cannot rebind the slot: a withdrawal is not undone by whatever
        // accompanied it. Fail closed with the exact reason rather than
        // letting an invalidated capability read as available again.
        Ok(_) if refresh.reason == StartupRefreshReason::OwnerInvalidated => {
            StartupBindingDisposition::Unbound(format!(
                "owner invalidated the {} binding; an accompanying observation cannot rebind it",
                refresh.capability.as_str()
            ))
        }
        Ok(retained) if retained.declared_slot() != refresh.capability => {
            StartupBindingDisposition::Unbound(format!(
                "startup capability {} retains proof produced by the {} attach",
                refresh.capability.as_str(),
                retained.declared_slot().as_str()
            ))
        }
        Ok(retained) => StartupBindingDisposition::Bound(Box::new(retained.clone())),
        Err(reason) => StartupBindingDisposition::Unbound(reason.clone()),
    }
}

/// Whether a declared slot's retained proof carries owner generation identity.
///
/// The three that do are the two Dreamer route contexts and the agent-fabric
/// descriptor. The owner session binding, the notification page and the Skill
/// catalogue terms do not, and are left to the owning owner that established
/// them; the check below never invents a revocation the owner did not report.
fn is_generation_scoped(capability: DeclaredStartupCapability) -> bool {
    matches!(
        capability,
        DeclaredStartupCapability::DreamerIntake
            | DeclaredStartupCapability::DreamerModel
            | DeclaredStartupCapability::AgentFabric
    )
}

/// Whether a retained proof was admitted under the current owner generation.
///
/// Only the retained evidence that actually carries generation or epoch
/// identity is checked. The owner session binding string, the notification page
/// and the Skill catalogue terms are not generation-scoped, so this returns
/// `true` for them and lets the owning owner's own revocation or generation
/// replacement decide their validity — the check never invents a revocation
/// the owner did not report.
fn retained_matches_owner_generation(
    retained: &RetainedStartupBinding,
    owner: &CoreOwnerState,
) -> bool {
    match retained {
        RetainedStartupBinding::DreamerIntakeRoute(metadata)
        | RetainedStartupBinding::DreamerModelRoute(metadata) => {
            metadata.state_fence.resource_generation.value() == owner.generation
                && metadata.state_fence.authority_epoch.sequence.get() == owner.authority_epoch
        }
        RetainedStartupBinding::AgentFabric(descriptor) => {
            descriptor.generation == owner.generation
                && descriptor.authority_epoch == owner.authority_epoch
        }
        RetainedStartupBinding::OwnerSession { .. }
        | RetainedStartupBinding::NotificationSnapshot { .. }
        | RetainedStartupBinding::SkillToolSource { .. }
        | RetainedStartupBinding::SkillToolBasis { .. } => true,
    }
}
