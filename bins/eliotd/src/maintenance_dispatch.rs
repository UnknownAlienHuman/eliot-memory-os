//! Owner dispatch for one Governor maintenance decision (I14.22, issue #1688).
//!
//! The Governor owner decides. This module only answers the question the
//! decision asks of the rest of the system: **which existing owner must now
//! act, and on what exact condition.** It is a closed mapping over the owner's
//! own [`AutomationDecision`] — one arm per value, no second decision
//! vocabulary, no re-decision and no default.
//!
//! Three properties are load-bearing:
//!
//! * **Dispatch by the decision, never by a Boolean summary.** The owner
//!   already publishes its exact action in
//!   [`AutomationTriggerDecision::decision`]. A caller that reduced it to
//!   "does this admit a job?" conflated `START` with a job that was never
//!   admitted, `DEFER` with `BLOCK`, and `SUPPRESS_DUPLICATE` with a failure,
//!   and could not tell a recommendation from an escalation. Each arm below
//!   names the owner and the exact condition, so the six contract decisions
//!   stay distinguishable all the way to the record.
//! * **Execution stays with the existing owners.** An admitted start is routed
//!   to the Durable Job admission owner by name; a recommendation is routed to
//!   the Human-board adapter; a duplicate is routed to the job that already
//!   owns the work. This module executes nothing, opens no queue, starts no
//!   timer and runs no background loop.
//! * **Every produced reference names the owner record it claims.** The start
//!   arm carries the admission owner's own `path::symbol` and the exact route
//!   `eliotd` does not hold, read from the registered family entry rather than
//!   restated here, so it cannot drift from the catalog it is rendered from.
//!
//! # Live status
//!
//! Two different things live in this module, and only one of them runs.
//!
//! The **owner dispatch** half — [`MaintenanceDispatch::for_decision`] and the
//! [`decision_gap`] table — **is** live. `daemon_runtime.rs` reaches it through
//! `maintenance_trigger_evaluator::DaemonComposition::evaluate_maintenance_trigger`,
//! and `notification_state_emit.rs` builds the same dispatch value for its
//! notification-policy check. Those are production call sites.
//!
//! The **#1694 W2–W7 maintenance-trigger route** below is not. Every leg of it
//! currently has **zero production call sites**: intake
//! ([`admit_maintenance_trigger_intake`]), claim
//! ([`claim_maintenance_trigger_for_daemon`]), timeout redelivery
//! ([`redeliver_maintenance_trigger_after_timeout`]), decision commit
//! ([`record_committed_maintenance_decision`]), crash recovery
//! ([`recover_maintenance_trigger_handoff`]), acknowledgement
//! ([`acknowledge_recovered_maintenance_commit`]), ambiguous-commit marking
//! ([`mark_maintenance_trigger_commit_ambiguous_after_loss`]), ledger restore
//! ([`restore_maintenance_trigger_ledger_at_startup`]), consumer revocation
//! ([`revoke_lost_daemon_consumer_for_replacement`]), replacement pending-set
//! surfacing ([`surface_replacement_pending_set`]), replacement startup
//! ([`recover_replacement_generation`]), protected-route selection
//! ([`select_protected_route_deliveries`]), terminal expiry
//! ([`expire_inapplicable_maintenance_trigger`]), supersession
//! ([`supersede_maintenance_trigger_with_successor`]), and damage recording
//! ([`record_maintenance_trigger_damage`]). [`collect_pending_maintenance_triggers`]
//! is uncalled outright. Three of those legs are additionally *transitively*
//! dead: each has exactly one caller, and that caller is itself in this
//! zero-caller set, so a name-level scan reports a caller where no live path
//! exists.
//!
//! The route's own doc comments cross-reference one another, so a reader
//! following them sees a complete, coherent maintenance sequence with no way in.
//! Every entry below therefore states its own live status under a
//! `# Live status` heading, and the cross-references say which further legs are
//! also unwired. The functions are retained unchanged: removing a `pub` item
//! from a public module, or wiring one of these legs to a caller, is an owner
//! decision for the `eliotd` composition root, not a documentation one.

#![forbid(unsafe_code)]

use std::num::NonZeroU32;

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_kernel_service::{
    KernelStoreGateway, MAX_MAINTENANCE_TRIGGER_CLAIM_LEASE_MS, MaintenanceTriggerClaimRequest,
    MaintenanceTriggerDeliveryError, MaintenanceTriggerDeliveryRow,
    MaintenanceTriggerRedeliveryOutcome,
};
use eliot_maintenance::{
    AutomationDecision, AutomationTriggerDecision, DecisionReason, MaintenanceError,
    MaintenanceFamily, MaintenanceTriggerIntake, TriggerIntakePayload, TriggerIntakePosition,
    TriggerIntakeRequest, TriggerIntakeRouting, derive_trigger_intake,
};
use eliot_ors::{
    MaintenanceTriggerStagingPayload, MaintenanceTriggerStagingPosition,
    MaintenanceTriggerStagingRequest, MaintenanceTriggerStagingRoute, OpaqueLabel,
    OperationalRecoveryStore, OrsError, stage_maintenance_trigger_intake,
};
use eliot_protocol::{
    MAINTENANCE_TRIGGER_ACK_WIRE_ID, MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
    MAINTENANCE_TRIGGER_WIRE_ID, MAINTENANCE_TRIGGER_WIRE_VERSION, MaintenanceTriggerAck,
    MaintenanceTriggerClaim, MaintenanceTriggerContentRef, MaintenanceTriggerDecisionReceipt,
    MaintenanceTriggerDisposition, MaintenanceTriggerGap, MaintenanceTriggerGapKind,
    MaintenanceTriggerIntakeReceipt, MaintenanceTriggerPayloadRef,
    MaintenanceTriggerPendingSummary, MaintenanceTriggerPosition, MaintenanceTriggerRecord,
    MaintenanceTriggerRevocation, MaintenanceTriggerRoute, MaintenanceTriggerRouteGrant,
    MaintenanceTriggerRoutingClass, MaintenanceTriggerSourceEvent, ProtocolError,
};
use thiserror::Error;

use crate::maintenance_family_catalog::{MaintenanceAdmissionBlocker, MaintenanceFamilyDecision};

/// The exact absent owner and the exact condition that reopens one decision.
///
/// Every entry is read from the Governor owner's own evaluation order in
/// [`eliot_maintenance::MaintenanceController::evaluate_trigger`]: the
/// `reopen_condition` is the name of the [`MaintenanceTriggerInput`] field that
/// owner's matching arm tests for that reason, and the `missing_owner` is the
/// authority whose absence makes that field false. Nothing here is a timer, a
/// retry budget, or a locally invented occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceDecisionGap {
    /// The exact owner that must act, or the explicit statement that no owner
    /// is missing and the reason is an observed gate rather than an absent
    /// authority. Never empty.
    pub missing_owner: &'static str,
    /// The exact observation that would reopen this decision, named by the
    /// input field the owner evaluates. Never empty.
    pub reopen_condition: &'static str,
}

/// The exact owner gap and reopen condition for one Governor decision reason.
///
/// Total over [`DecisionReason`], so a new reason is a compile error here
/// rather than a silently un-gapped decision. The `AutomationOff` and
/// `SuggestOnly` arms share the maintenance-policy owner because they are the
/// same unresolved policy read at two different modes; `Eligible` and
/// `DuplicateActiveJob` state plainly that no owner is missing, because their
/// reasons are observed gates rather than absent authorities.
#[must_use]
pub const fn decision_gap(reason: DecisionReason) -> MaintenanceDecisionGap {
    match reason {
        DecisionReason::Eligible => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: every gate in the Governor owner's evaluation is satisfied",
            reopen_condition: "not applicable: the decision is already eligible and no reopening is owed",
        },
        DecisionReason::AutomationOff | DecisionReason::SuggestOnly => MaintenanceDecisionGap {
            missing_owner: "the Human maintenance-policy owner that publishes MaintenanceAutomationMode to eliotd (issue #1692); eliotd holds no such publisher and the registered catalog mode is off, so an unresolved policy denies automation instead of defaulting to it",
            reopen_condition: "MaintenanceTriggerInput::mode reads a published mode other than off for this registered family",
        },
        DecisionReason::ExplicitRequestRequired => MaintenanceDecisionGap {
            missing_owner: "the authenticated Human maintenance-request ingress (issue #1692); eliotd exposes no authenticated Human UI or CLI maintenance-request entry, and an untrusted flag is not a request",
            reopen_condition: "MaintenanceTriggerInput::explicit_request reads true from that authenticated ingress",
        },
        DecisionReason::NotIdle => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: the affected scope is observed not idle, which is the condition itself",
            reopen_condition: "MaintenanceTriggerInput::idle reads true, i.e. an observation with no in-flight admitted activation in the affected scope",
        },
        DecisionReason::OutsideSchedule => MaintenanceDecisionGap {
            missing_owner: "the Host wake and Task Scheduler occurrence owner (issue #1692); eliotd holds no real scheduled occurrence, and a locally invented clock event is forbidden",
            reopen_condition: "MaintenanceTriggerInput::scheduled_window reads true from that real Host or Task Scheduler occurrence",
        },
        DecisionReason::RouteUnavailable => MaintenanceDecisionGap {
            missing_owner: "the maintenance route and credential owner (issue #1692); no owner publishes a service-safe unattended route to eliotd",
            reopen_condition: "MaintenanceTriggerInput::route_available reads true from that published service-safe route",
        },
        DecisionReason::BudgetUnavailable => MaintenanceDecisionGap {
            missing_owner: "the maintenance budget and quota owner (issue #1692); no owner publishes an admitted budget slice to eliotd",
            reopen_condition: "MaintenanceTriggerInput::budget_available reads true from that admitted budget slice",
        },
        DecisionReason::UserSessionRequired => MaintenanceDecisionGap {
            missing_owner: "the authenticated User Broker session owner together with the separate interactive_maintenance permission (issue #1692); transport session presence is not broker admission",
            reopen_condition: "MaintenanceTriggerInput::user_session_available reads true from an authenticated interactive session admitted under that separate permission",
        },
        DecisionReason::DuplicateActiveJob => MaintenanceDecisionGap {
            missing_owner: "no owner is missing: an equivalent active request already owns this work, and that request is the owner",
            reopen_condition: "MaintenanceTriggerInput::active_job_id stops naming an active job for this registered deduplication scope",
        },
        DecisionReason::Expired => MaintenanceDecisionGap {
            missing_owner: "the maintenance expiry-policy owner (issue #1694); no owner publishes a maintenance expiry to eliotd",
            reopen_condition: "MaintenanceTriggerInput::expires_at_ms is Some and strictly greater than now_ms",
        },
        DecisionReason::SafetyRecovery => MaintenanceDecisionGap {
            missing_owner: "the protected safety and recovery obligation owner (issue #1692); the registered protected-obligation authority needed to admit safety work is not published to this path",
            reopen_condition: "MaintenanceTriggerInput::safety_required is cleared by that protected recovery owner rather than asserted by the caller",
        },
    }
}

/// Where one Governor maintenance decision must be handed, and on what exact
/// condition.
///
/// One arm per [`AutomationDecision`] value, so the dispatch cannot lose or
/// merge a decision. No arm executes anything: each names an existing owner and
/// the record that owner must produce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceDispatch {
    /// `START`: the existing Durable Job admission owner holds the request.
    ///
    /// The job identity, the lease, the budget slice and the receipt all belong
    /// to `eliot_maintenance::MaintenanceController::admit` and its Kernel
    /// durable-job port. This arm names that owner and the exact route `eliotd`
    /// does not hold, and admits nothing itself: the record it produces is a
    /// retained admission request, never a claim that a job was admitted or
    /// started. The shared admission blockers travel beside the route, so the
    /// record states the exact missing owners — lease, budget, job wire — and
    /// not just the family route.
    StartDurableJob {
        /// `path::symbol` of the existing admission owner.
        admission_owner: &'static str,
        /// The exact route `eliotd` does not hold to that owner.
        missing_route: &'static str,
        /// The shared Durable Job admission blockers that stop this start,
        /// read from the family decision's own catalog entry rather than
        /// restated here. Empty states explicitly that no shared blocker
        /// remains and only the Governor admission and the family route decide.
        admission_blockers: &'static [MaintenanceAdmissionBlocker],
    },
    /// `SUGGEST`: exactly one Human-board recommendation, and no work started.
    SuggestBoardItem {
        /// The exact owner gap and reopen condition behind the suggestion.
        gap: MaintenanceDecisionGap,
    },
    /// `DEFER`: the trigger is retained for a later eligible window. No work
    /// starts; the Human-board adapter records the exact deferral under the
    /// stable family/scope/reason/policy episode identity.
    Defer {
        /// The exact owner gap and reopen condition behind the deferral.
        gap: MaintenanceDecisionGap,
    },
    /// `BLOCK`: policy, route, budget or session requirements deny execution.
    /// The exact missing owner and reopen condition are retained with the
    /// record.
    Block {
        /// The exact owner gap and reopen condition behind the block.
        gap: MaintenanceDecisionGap,
    },
    /// `SUPPRESS_DUPLICATE`: an equivalent active request already owns this
    /// work.
    ///
    /// This is not a failure and not a new occurrence, so it must not create a
    /// record: I11.12 forbids one alert per occurrence, and a record here
    /// would report a duplicate as blocked work. The existing job is the
    /// reference, and the decision that named it is already inspectable
    /// through the operational decision line the evaluator emits.
    ExistingDurableJob {
        /// The existing job identity the owner reported, when it carried one.
        durable_job_ref: Option<String>,
    },
    /// `ESCALATE`: a Human or recovery owner must act rather than wait.
    Escalate {
        /// The exact owner gap and reopen condition behind the escalation.
        gap: MaintenanceDecisionGap,
    },
}

impl MaintenanceDispatch {
    /// Routes one evaluated decision to the owner that must act.
    ///
    /// Pure: it reads the Governor owner's own action and the registered
    /// family's own resolved route, and invents neither. The admission owner and
    /// the missing route come from the family decision's own catalog entry, so a
    /// dispatch can never name a route the catalog does not, and the gap comes
    /// from the owner's own reason, so it cannot disagree with the decision that
    /// produced it.
    #[must_use]
    pub fn for_decision(
        decision: &AutomationTriggerDecision,
        family_decision: &MaintenanceFamilyDecision,
    ) -> Self {
        let gap = decision_gap(decision.reason);
        match decision.decision {
            AutomationDecision::Start => Self::StartDurableJob {
                admission_owner: family_decision.route.target(),
                missing_route: family_decision.route.missing(),
                admission_blockers: family_decision.admission_blockers,
            },
            AutomationDecision::Suggest => Self::SuggestBoardItem { gap },
            AutomationDecision::Defer => Self::Defer { gap },
            AutomationDecision::Block => Self::Block { gap },
            AutomationDecision::SuppressDuplicate => Self::ExistingDurableJob {
                durable_job_ref: decision.durable_job_ref.clone(),
            },
            AutomationDecision::Escalate => Self::Escalate { gap },
        }
    }

    /// The closed wire name of the arm, for inspection.
    ///
    /// It names the dispatch, not the decision: the decision keeps the owner's
    /// own spelling, and a reader that has both can see the routing without
    /// either vocabulary being restated in the other.
    #[must_use]
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::StartDurableJob { .. } => "START_DURABLE_JOB",
            Self::SuggestBoardItem { .. } => "SUGGEST_BOARD_ITEM",
            Self::Defer { .. } => "DEFER",
            Self::Block { .. } => "BLOCK",
            Self::ExistingDurableJob { .. } => "EXISTING_DURABLE_JOB",
            Self::Escalate { .. } => "ESCALATE",
        }
    }

    /// The operator-facing subject line for the record this dispatch produces.
    #[must_use]
    pub fn subject(&self, family: &MaintenanceFamily) -> String {
        match self {
            Self::StartDurableJob { .. } => {
                format!("maintenance start cannot be admitted for {family}")
            }
            Self::SuggestBoardItem { .. } => format!("maintenance recommendation for {family}"),
            Self::Defer { .. } => format!("maintenance deferred for {family}"),
            Self::Block { .. } => format!("blocked maintenance automation {family}"),
            // Never rendered: this arm produces no record. It exists so the
            // subject function stays total over the dispatch.
            Self::ExistingDurableJob { .. } => format!("active maintenance job for {family}"),
            Self::Escalate { .. } => format!("maintenance automation escalated for {family}"),
        }
    }

    /// The owner gap and reopen condition this dispatch retains, when it has
    /// one.
    ///
    /// A start's gap is its admission route, and a duplicate's is the job that
    /// already owns the work, so this is total over the arms that name an
    /// owner rather than over the arms that hold a reference.
    #[must_use]
    pub fn gap(&self) -> MaintenanceDecisionGap {
        match self {
            Self::StartDurableJob {
                admission_owner,
                missing_route,
                ..
            } => MaintenanceDecisionGap {
                missing_owner: admission_owner,
                reopen_condition: missing_route,
            },
            Self::SuggestBoardItem { gap }
            | Self::Defer { gap }
            | Self::Block { gap }
            | Self::Escalate { gap } => *gap,
            Self::ExistingDurableJob { .. } => MaintenanceDecisionGap {
                missing_owner: "the equivalent active request that already owns this work",
                reopen_condition: "that request reaches a terminal state, after which active_job_id stops naming it",
            },
        }
    }

    /// The one line added to the record's summary: the owner that must act and
    /// the observation that reopens the decision.
    ///
    /// A start additionally retains the shared admission blockers, so the
    /// summary states the exact missing lease, budget and job-wire owners
    /// beside the family route.
    #[must_use]
    pub fn detail(&self) -> String {
        let gap = self.gap();
        let base = format!(
            "dispatch={dispatch}; missing owner: {owner}; reopens when: {reopen}",
            dispatch = self.wire_name(),
            owner = gap.missing_owner,
            reopen = gap.reopen_condition,
        );
        match self.admission_blockers_text() {
            Some(blockers) => format!("{base}; admission blocked by: {blockers}"),
            None => base,
        }
    }

    /// The shared Durable Job admission blockers this dispatch retains, when
    /// it is a start.
    ///
    /// Only the start arm carries them: every other arm names its own missing
    /// owner in [`Self::gap`] instead of the shared admission. `Some` with the
    /// empty-set rendering states explicitly that no shared blocker remains.
    #[must_use]
    pub fn admission_blockers_text(&self) -> Option<String> {
        match self {
            Self::StartDurableJob {
                admission_blockers, ..
            } => Some(admission_blocker_summary(admission_blockers)),
            _ => None,
        }
    }

    /// Emits the routing decision for one evaluated trigger, so a reader can
    /// see which owner the decision was handed to and on what exact condition
    /// without reading the canonical record.
    ///
    /// This is an operational line, not the durable record: it rotates, and the
    /// record for the arms that owe one is the canonical notification the
    /// Human-board owner commits. It is written here rather than in the caller
    /// so the emitted line and the dispatch the emitter acted on are the same
    /// value, computed once.
    pub fn record(&self, decision: &AutomationTriggerDecision) {
        let gap = self.gap();
        // Only the duplicate arm holds a job reference. The other arms name an
        // owner instead, so the field is reported as unavailable rather than
        // filled with a placeholder a reader could mistake for an identity.
        let existing_job = match self {
            Self::ExistingDurableJob {
                durable_job_ref: Some(reference),
            } => crate::diagnostics::sanitize_identity(reference),
            Self::ExistingDurableJob {
                durable_job_ref: None,
            } => "the owner reported no job identity".to_owned(),
            _ => "unavailable: this dispatch names an owner, not an existing job".to_owned(),
        };
        // Only the start arm carries the shared admission blockers. The other
        // arms name their own missing owner in the gap fields above, so the
        // field is reported as not applicable rather than filled with a
        // placeholder a reader could mistake for a retained blocker.
        let admission_blockers = self.admission_blockers_text().unwrap_or_else(|| {
            "not applicable: this dispatch names its owner, not the shared Durable Job admission"
                .to_owned()
        });
        tracing::info!(
            target: "eliotd::diagnostics",
            event = "eliotd.maintenance_dispatch",
            service = crate::SERVICE_NAME,
            dispatch = self.wire_name(),
            family = %decision.family,
            trigger = %crate::diagnostics::sanitize_identity(&decision.trigger_id),
            scope = %crate::diagnostics::sanitize_identity(&decision.scope_ref),
            governor_decision = ?decision.decision,
            governor_reason = ?decision.reason,
            governor_admits_job = decision.admits_job,
            missing_owner = gap.missing_owner,
            reopen_condition = gap.reopen_condition,
            existing_job = %existing_job,
            admission_blockers = %admission_blockers,
        );
    }
}

/// Joins the exact missing-owner statements of the shared Durable Job
/// admission blockers into one inspectable line.
///
/// Each statement is the blocker's own [`MaintenanceAdmissionBlocker::as_str`];
/// only the separator is local. An empty set states explicitly that no shared
/// blocker remains, so clearing the last blocker cannot render a start as
/// silently admittable.
fn admission_blocker_summary(blockers: &[MaintenanceAdmissionBlocker]) -> String {
    if blockers.is_empty() {
        return "no shared admission blocker remains: the Governor admission and the family route decide"
            .to_owned();
    }
    blockers
        .iter()
        .copied()
        .map(MaintenanceAdmissionBlocker::as_str)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Owner-supplied durable payload binding for one front-door intake.
///
/// The delivery-obligation reference and payload digest name the exact staged
/// bytes: for a retained canonical source they name the already-staged source
/// envelope (re-proved by the ORS owner's read-back at staging time); for a
/// complete opaque input they must equal the supplied envelope's own identity
/// and digest, which the mapper checks before any write. The envelope itself
/// is built by the payload owner under the existing `RecoveryPayloadEnvelope`
/// rules — this front door never mints, encrypts, or re-wraps bytes.
#[derive(Clone, Debug)]
pub struct TriggerIntakeDurableBinding {
    /// Complete durable payload: a retained source operation identity the
    /// ORS owner resolves, or the full owner-built opaque envelope to stage.
    pub payload: MaintenanceTriggerStagingPayload,
    /// Lowercase SHA-256 of the exact staged envelope payload bytes.
    pub payload_hash: String,
}

/// Owner-supplied producer authentication binding for one front-door intake.
///
/// The signer identity and signature authenticate the intake producer through
/// the existing signer seam; the scheme is the caller's and verification is
/// the bound evidence provider's. This front door invents neither.
#[derive(Clone, Debug)]
pub struct TriggerIntakeSignerBinding {
    /// Intake producer authenticated through the existing signer seam.
    pub signer_id: OpaqueLabel,
    /// Producer signature over the staged item.
    pub signature: Vec<u8>,
    /// Intake arrival time as Unix milliseconds.
    pub arrived_at_ms: i64,
}

/// Owner bindings the front-door intake caller does not derive itself.
///
/// The derived statement carries every verbatim field; these bindings carry
/// only what derivation cannot produce: the owner-built durable payload with
/// its digest, the producer signer binding, the admitted source fence, and
/// the owner-issued protected-route grant when the intake is protected.
#[derive(Clone, Debug)]
pub struct TriggerIntakeOwnerBindings {
    /// Owner-built durable payload with its staged-bytes digest.
    pub durable: TriggerIntakeDurableBinding,
    /// Producer signer binding for the staged inbox item.
    pub signer: TriggerIntakeSignerBinding,
    /// Source authority and resource fence carried on the wire record.
    /// Producer generation travels separately in the source event.
    pub source_fence: StateFence,
    /// Owner-issued protected-route classification; present exactly when the
    /// derived routing is protected.
    pub route_grant: Option<MaintenanceTriggerRouteGrant>,
}

/// Fail-closed refusals of the front-door maintenance-trigger intake (I14.22,
/// issue #1694 W2).
///
/// Every variant keeps its owner's exact typed failure and the producer's
/// retry identity (trigger identity plus operation hash): a derivation
/// refusal stays a [`MaintenanceError`], a statement-to-owner binding refusal
/// stays a [`ProtocolError`], the ORS owner's durable-staging refusal stays
/// an [`OrsError`], and the Kernel delivery owner's admission refusal stays a
/// [`MaintenanceTriggerDeliveryError`]. No failure acknowledges acceptance or
/// advances the producer cursor, and no variant invents a spill file:
/// critical gaps travel the existing protected owner, never a new unbounded
/// store.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerIntakeError {
    /// The intake request failed persist-before-ack derivation.
    #[error("maintenance trigger intake derivation refused for trigger {trigger_id}: {source}")]
    Derivation {
        /// Stable trigger identity the producer retries under.
        trigger_id: String,
        /// Operation hash the producer retries under.
        operation_hash: String,
        /// Exact derivation refusal; nothing was staged.
        #[source]
        source: Box<MaintenanceError>,
    },
    /// The derived statement and the owner bindings name different
    /// obligations, so the intake would acknowledge the wrong bytes.
    #[error("maintenance trigger intake binding mismatch for trigger {trigger_id}: {source}")]
    BindingConflict {
        /// Stable trigger identity the producer retries under.
        trigger_id: String,
        /// Operation hash the producer retries under.
        operation_hash: String,
        /// Exact binding refusal; changed content conflicts.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The ORS owner could not durably stage the complete input (capacity,
    /// key, integrity, or durable-write refusal).
    #[error("maintenance trigger intake staging refused for trigger {trigger_id}: {source}")]
    Staging {
        /// Stable trigger identity the producer retries under.
        trigger_id: String,
        /// Operation hash the producer retries under.
        operation_hash: String,
        /// Exact owner refusal; no receipt was issued.
        #[source]
        source: Box<OrsError>,
    },
    /// The Kernel delivery owner refused admission of the staged trigger, or
    /// answered with a receipt that does not echo the admitted record.
    #[error("maintenance trigger intake admission refused for trigger {trigger_id}: {source}")]
    Admission {
        /// Stable trigger identity the producer retries under.
        trigger_id: String,
        /// Operation hash the producer retries under.
        operation_hash: String,
        /// Exact owner refusal; nothing was admitted.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
}

impl MaintenanceTriggerIntakeError {
    /// Returns the stable trigger identity the producer retries under.
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        match self {
            Self::Derivation { trigger_id, .. }
            | Self::BindingConflict { trigger_id, .. }
            | Self::Staging { trigger_id, .. }
            | Self::Admission { trigger_id, .. } => trigger_id,
        }
    }

    /// Returns the operation hash the producer retries under.
    #[must_use]
    pub fn operation_hash(&self) -> &str {
        match self {
            Self::Derivation { operation_hash, .. }
            | Self::BindingConflict { operation_hash, .. }
            | Self::Staging { operation_hash, .. }
            | Self::Admission { operation_hash, .. } => operation_hash,
        }
    }
}

/// Admits one retained maintenance trigger through the existing ORS and
/// Kernel owners before any acknowledgement (I14.22, issue #1694 W2).
///
/// It derives first, stages second, admits third, and acknowledges nothing
/// itself. The producer cursor advances only on the returned
/// [`MaintenanceTriggerIntakeReceipt`]; every error returns with the
/// producer's retry identity and no acceptance.
///
/// Derivation is [`derive_trigger_intake`], so the source-attested operation
/// hash travels verbatim and an exact identity/hash replay converges while
/// changed content conflicts. Persistence is the Governor seam's two steps
/// performed with owner-typed errors: [`stage_maintenance_trigger_intake`]
/// commits the complete input (or the retained-source delivery obligation)
/// through the ORS owner, then
/// [`MaintenanceTriggerIntake::bind_staging_proof`] binds the owner-issued
/// envelope reference and payload digest. The seam entry
/// [`MaintenanceTriggerIntake::persist_before_ack`] is not used here on
/// purpose: its seam error type is [`MaintenanceError`], which can only carry
/// an owner staging refusal as an opaque string, while this caller must
/// preserve the exact bounded [`OrsError`]. Admission is
/// [`KernelStoreGateway::admit_maintenance_trigger`], which re-proves staging
/// through the ORS read-back before admitting the wire record into the owned
/// delivery ledger: an exact replay returns the same receipt, changed content
/// conflicts, and any failure admits nothing.
///
/// This caller holds no ledger, opens no poller, creates no second database,
/// and writes no spill file: delivery metadata stays with the Kernel ledger,
/// staged bytes stay with the ORS inbox owner, and protected safety/recovery
/// routing travels the existing owner-issued grant on both the staging
/// request and the wire record.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door intake route
/// caller" was false and has been removed.
///
/// It is the W2 entry leg of the #1694 W2–W7 route, and that route has no
/// entry point: every other leg in it is also uncalled, so nothing in the
/// daemon run loop can reach this intake and no trigger can arrive for the
/// legs downstream of it to act on. The nearest real thing is the read-only
/// maintenance evaluation the daemon run loop does drive,
/// `maintenance_trigger_evaluator::DaemonComposition::evaluate_maintenance_trigger`,
/// which resolves the family decision and never admits a trigger into the
/// Kernel delivery ledger. Its owner bindings,
/// [`TriggerIntakeOwnerBindings`], are likewise constructed nowhere in the
/// repository.
///
/// Whether this entry is wired to that evaluation or retired is an owner
/// decision, not a documentation one. It is retained unchanged because
/// removing a `pub` entry from this public module is an API decision for the
/// `eliotd` owner (#18), not a documentation fix.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerIntakeError`] keeping each owner's typed
/// refusal: a derivation refusal, a statement-to-owner binding mismatch, an
/// ORS staging refusal, or a Kernel admission refusal.
pub fn admit_maintenance_trigger_intake(
    store: &impl OperationalRecoveryStore,
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    request: &TriggerIntakeRequest,
    owner: &TriggerIntakeOwnerBindings,
) -> Result<MaintenanceTriggerIntakeReceipt, MaintenanceTriggerIntakeError> {
    let retry_id = (
        request.input.trigger_id.clone(),
        request.operation.operation_hash.clone(),
    );
    let statement = derive_trigger_intake(request).map_err(|source| {
        MaintenanceTriggerIntakeError::Derivation {
            trigger_id: retry_id.0.clone(),
            operation_hash: retry_id.1.clone(),
            source: Box::new(source),
        }
    })?;
    let staging = map_intake_to_staging_request(&statement, &owner.durable, &owner.signer)
        .map_err(|source| intake_binding_conflict(&statement, source))?;
    // Persist before acknowledging: the complete opaque input (or the
    // retained-source delivery obligation) commits through the ORS owner. An
    // exact replay converges on the owner's existing receipt; changed content
    // fails with a duplicate conflict. Any failure carries no receipt, so the
    // producer keeps its retry identity and its cursor must not advance.
    let staged = stage_maintenance_trigger_intake(store, &staging).map_err(|source| {
        MaintenanceTriggerIntakeError::Staging {
            trigger_id: statement.trigger_id.clone(),
            operation_hash: statement.operation_hash.clone(),
            source: Box::new(source),
        }
    })?;
    // Bind the owner-issued staging output before it may advance any cursor.
    // The receipt echoes the committed obligation: a substituted answer
    // naming a different trigger, hash, envelope, or digest conflicts here as
    // changed content instead of replaying. The inbox order and state digest
    // stay the ORS owner's internal durability evidence; the obligation the
    // Kernel re-proves at admission is the envelope reference plus payload
    // hash.
    if staged.trigger_id != staging.trigger_id
        || staged.operation_hash != staging.operation_hash
        || staged.envelope_reference != staging.envelope_reference
        || staged.payload_hash != staging.payload_hash
    {
        return Err(MaintenanceTriggerIntakeError::BindingConflict {
            trigger_id: statement.trigger_id.clone(),
            operation_hash: statement.operation_hash.clone(),
            source: Box::new(ProtocolError::ReplayConflict),
        });
    }
    // A mismatch is changed content under this identity and conflicts instead
    // of replaying.
    let persist = statement
        .bind_staging_proof(&staged.envelope_reference, &staged.payload_hash)
        .map_err(|source| {
            let source = match source {
                MaintenanceError::IdentityConflict => ProtocolError::ReplayConflict,
                _ => ProtocolError::InvalidField {
                    field: "maintenance_trigger.persist",
                    reason: "staging binding is not well formed",
                },
            };
            MaintenanceTriggerIntakeError::BindingConflict {
                trigger_id: statement.trigger_id.clone(),
                operation_hash: statement.operation_hash.clone(),
                source: Box::new(source),
            }
        })?;
    let record = map_intake_to_wire_record(
        &statement,
        &persist.envelope_reference,
        &persist.payload_hash,
        owner,
    )
    .map_err(|source| MaintenanceTriggerIntakeError::BindingConflict {
        trigger_id: statement.trigger_id.clone(),
        operation_hash: statement.operation_hash.clone(),
        source: Box::new(source),
    })?;
    // Bind the delivery obligation before admission: the staged envelope
    // reference, payload hash, trigger identity, and operation hash must name
    // the same obligation on both sides. A staging that pointed beside its
    // bytes would acknowledge the wrong obligation, so changed content
    // conflicts here before any cursor could advance.
    if staging.trigger_id != record.trigger_id
        || staging.operation_hash != record.operation_hash
        || staging.envelope_reference != record.payload.envelope_reference
        || staging.payload_hash != record.payload.payload_hash
    {
        return Err(MaintenanceTriggerIntakeError::BindingConflict {
            trigger_id: record.trigger_id.clone(),
            operation_hash: record.operation_hash.clone(),
            source: Box::new(ProtocolError::ReplayConflict),
        });
    }
    // Admit the staged record into the owned delivery ledger. The owner entry
    // re-proves staging through the ORS read-back, then admits: exact
    // identity/hash replay returns the same receipt, changed content
    // conflicts, and any failure admits nothing.
    let (receipt, _) = gateway
        .admit_maintenance_trigger(principal_ref, record)
        .map_err(|source| MaintenanceTriggerIntakeError::Admission {
            trigger_id: staging.trigger_id.clone(),
            operation_hash: staging.operation_hash.clone(),
            source: Box::new(source),
        })?;
    receipt
        .validate()
        .map_err(|source| MaintenanceTriggerIntakeError::Admission {
            trigger_id: staging.trigger_id.clone(),
            operation_hash: staging.operation_hash.clone(),
            source: Box::new(MaintenanceTriggerDeliveryError::Protocol(source)),
        })?;
    if receipt.trigger_id != staging.trigger_id
        || receipt.operation_hash != staging.operation_hash
        || receipt.envelope_reference != staging.envelope_reference
        || receipt.payload_hash != staging.payload_hash
    {
        return Err(MaintenanceTriggerIntakeError::Admission {
            trigger_id: staging.trigger_id.clone(),
            operation_hash: staging.operation_hash.clone(),
            source: Box::new(MaintenanceTriggerDeliveryError::Protocol(
                ProtocolError::ReplayConflict,
            )),
        });
    }
    Ok(receipt)
}

/// Builds the binding-conflict refusal for one derived intake statement.
///
/// The statement carries the retry identity, so every mapper, proof-binding,
/// and obligation-equality refusal keeps the trigger identity and operation
/// hash the producer retries under.
fn intake_binding_conflict(
    statement: &MaintenanceTriggerIntake,
    source: ProtocolError,
) -> MaintenanceTriggerIntakeError {
    MaintenanceTriggerIntakeError::BindingConflict {
        trigger_id: statement.trigger_id.clone(),
        operation_hash: statement.operation_hash.clone(),
        source: Box::new(source),
    }
}

/// Copies one derived intake statement verbatim onto the ORS staging request.
///
/// Identity, generation, position, operation label and hash, opaque
/// family/scope references, evidence locators, window, and routing travel
/// unchanged; the durable payload, its digest, and the signer binding arrive
/// from their owners. For a complete opaque input the supplied digest must
/// equal the envelope's own digest, so a caller mix-up fails here before any
/// write; for a retained source the digest is the expected content the ORS
/// owner re-proves by read-back.
fn map_intake_to_staging_request(
    statement: &MaintenanceTriggerIntake,
    durable: &TriggerIntakeDurableBinding,
    signer: &TriggerIntakeSignerBinding,
) -> Result<MaintenanceTriggerStagingRequest, ProtocolError> {
    let (envelope_reference, payload) = match &durable.payload {
        MaintenanceTriggerStagingPayload::RetainedCanonicalSource { operation_id } => {
            if !matches!(
                statement.payload,
                TriggerIntakePayload::RetainedCanonicalSource { .. }
            ) {
                return Err(ProtocolError::ReplayConflict);
            }
            (
                operation_id.as_str().to_owned(),
                MaintenanceTriggerStagingPayload::RetainedCanonicalSource {
                    operation_id: operation_id.clone(),
                },
            )
        }
        MaintenanceTriggerStagingPayload::CompleteOpaqueInput { envelope } => {
            if !matches!(
                statement.payload,
                TriggerIntakePayload::CompleteOpaqueInput { .. }
            ) {
                return Err(ProtocolError::ReplayConflict);
            }
            if durable.payload_hash != envelope.payload_sha256 {
                return Err(ProtocolError::ReplayConflict);
            }
            (
                envelope.operation_or_checkpoint_id.as_str().to_owned(),
                MaintenanceTriggerStagingPayload::CompleteOpaqueInput {
                    envelope: envelope.clone(),
                },
            )
        }
    };
    Ok(MaintenanceTriggerStagingRequest {
        trigger_id: statement.trigger_id.clone(),
        operation_hash: statement.operation_hash.clone(),
        producer_id: statement.source_event.producer_id.clone(),
        producer_generation: statement.source_event.producer_generation,
        stream_id: statement.source_event.stream_id.clone(),
        event_id: statement.source_event.event_id.clone(),
        position: match &statement.source_position {
            TriggerIntakePosition::Cursor { value } => {
                MaintenanceTriggerStagingPosition::Cursor { value: *value }
            }
            TriggerIntakePosition::AcceptedOccurrence { occurrence_id } => {
                MaintenanceTriggerStagingPosition::AcceptedOccurrence {
                    occurrence_id: occurrence_id.clone(),
                }
            }
        },
        operation_label: statement.operation_label.clone(),
        family_ref: statement.family_ref.clone(),
        scope_ref: statement.scope_ref.clone(),
        evidence_locators: statement.evidence_locators.clone(),
        envelope_reference,
        payload_hash: durable.payload_hash.clone(),
        created_at_ms: statement.created_at_ms,
        applicable_until_ms: statement.applicable_until_ms,
        routing: match &statement.routing {
            TriggerIntakeRouting::Ordinary => MaintenanceTriggerStagingRoute::Ordinary,
            TriggerIntakeRouting::Protected {
                owner_id,
                route,
                key_id,
                grant_digest,
            } => MaintenanceTriggerStagingRoute::Protected {
                owner_id: owner_id.clone(),
                route: route.clone(),
                key_id: key_id.clone(),
                grant_digest: grant_digest.clone(),
            },
        },
        payload,
        signer_id: signer.signer_id.clone(),
        signature: signer.signature.clone(),
        arrived_at_ms: signer.arrived_at_ms,
    })
}

/// Copies one derived intake statement verbatim onto the provider-neutral
/// wire record.
///
/// The source-attested operation hash travels unchanged — it is never
/// recomputed here — and the payload obligation echoes the owner-bound
/// staging proof, never the derivation-local payload binding. The source
/// fence and the protected-route grant arrive from their owners; routing
/// class and grant presence must agree, and the grant must bind this exact
/// trigger identity and operation hash. Grant issuance proof stays with the
/// issuing owner and the Kernel intake path.
fn map_intake_to_wire_record(
    statement: &MaintenanceTriggerIntake,
    envelope_reference: &str,
    payload_hash: &str,
    owner: &TriggerIntakeOwnerBindings,
) -> Result<MaintenanceTriggerRecord, ProtocolError> {
    // Derivation already refused a zero producer generation, so this
    // conversion cannot fail on a derived statement; a hand-built statement
    // carrying one fails here before any write.
    let producer_generation = ResourceGeneration::new(statement.source_event.producer_generation)
        .map_err(ProtocolError::Foundation)?;
    let created_at_unix_ms =
        u64::try_from(statement.created_at_ms).map_err(|_| ProtocolError::InvalidField {
            field: "maintenance_trigger.created_at_unix_ms",
            reason: "must be a non-negative time",
        })?;
    let applicable_until_unix_ms =
        u64::try_from(statement.applicable_until_ms).map_err(|_| ProtocolError::InvalidField {
            field: "maintenance_trigger.applicable_until_unix_ms",
            reason: "must be a non-negative time",
        })?;
    let (routing_class, route_grant) = match (&statement.routing, &owner.route_grant) {
        (TriggerIntakeRouting::Ordinary, None) => (MaintenanceTriggerRoutingClass::Ordinary, None),
        (
            TriggerIntakeRouting::Protected {
                owner_id,
                key_id,
                grant_digest,
                ..
            },
            Some(grant),
        ) => {
            grant.validate()?;
            if !grant.binds(&statement.trigger_id, &statement.operation_hash)
                || grant.owner_id != *owner_id
                || grant.key_id != *key_id
                || grant.grant_digest != *grant_digest
            {
                return Err(ProtocolError::ReplayConflict);
            }
            (
                MaintenanceTriggerRoutingClass::Protected,
                Some(grant.clone()),
            )
        }
        _ => {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger.route_grant",
                reason: "routing class and grant presence must agree",
            });
        }
    };
    let record = MaintenanceTriggerRecord {
        wire_id: MAINTENANCE_TRIGGER_WIRE_ID.to_owned(),
        wire_version: MAINTENANCE_TRIGGER_WIRE_VERSION,
        source_event: MaintenanceTriggerSourceEvent {
            producer_id: statement.source_event.producer_id.clone(),
            producer_generation,
            stream_id: statement.source_event.stream_id.clone(),
            event_id: statement.source_event.event_id.clone(),
        },
        trigger_id: statement.trigger_id.clone(),
        source_position: match &statement.source_position {
            TriggerIntakePosition::Cursor { value } => {
                MaintenanceTriggerPosition::Cursor { value: *value }
            }
            TriggerIntakePosition::AcceptedOccurrence { occurrence_id } => {
                MaintenanceTriggerPosition::AcceptedOccurrence {
                    occurrence_id: occurrence_id.clone(),
                }
            }
        },
        source_state_fence: owner.source_fence.clone(),
        operation: statement.operation_label.clone(),
        operation_hash: statement.operation_hash.clone(),
        family: MaintenanceTriggerContentRef {
            reference: statement.family_ref.clone(),
        },
        scope: MaintenanceTriggerContentRef {
            reference: statement.scope_ref.clone(),
        },
        evidence_locators: statement.evidence_locators.clone(),
        privacy_class_reference: statement.privacy_class_reference.clone(),
        visibility_reference: statement.visibility_reference.clone(),
        payload: MaintenanceTriggerPayloadRef {
            envelope_reference: envelope_reference.to_owned(),
            payload_hash: payload_hash.to_owned(),
        },
        routing_class,
        route_grant,
        created_at_unix_ms,
        applicable_until_unix_ms,
    };
    record.validate()?;
    Ok(record)
}

/// Daemon claim identity for one fenced maintenance-trigger claim.
///
/// Binds the claiming daemon's session within its generation, the stable
/// delivery identity for this claim epoch, and the finite lease the claim
/// authorizes. The fence itself travels separately as the live admitted
/// fence: daemon fence and current fence are the same live value for a
/// same-generation daemon, and a replacement generation passes its own new
/// live fence so old-generation responses fail.
#[derive(Clone, Debug)]
pub struct TriggerClaimIdentity {
    /// Claiming daemon's session identity within its generation.
    pub daemon_session: String,
    /// Stable delivery identity for this claim epoch.
    pub delivery_id: String,
    /// Latest time at which this claim authorizes delivery; must be finite
    /// and within the owner lease bound.
    pub claim_deadline_unix_ms: u64,
    /// Issuance time as Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Fail-closed refusals of the front-door maintenance-trigger claim and page
/// walk (I14.22, issue #1694 W3).
///
/// Every variant keeps the producer-visible identity (trigger identity plus
/// delivery identity, or the page cursor): a malformed request stays a
/// [`ProtocolError`], a Kernel delivery owner refusal stays a
/// [`MaintenanceTriggerDeliveryError`], and a claim that fails the live
/// fence, the identity echo, or expiry stays a stale-claim refusal. No
/// failure mints a new trigger ID, authorizes repeating an uncertain effect,
/// or resets a reconnect to a guessed complete-empty set.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerClaimError {
    /// The claim request is malformed: blank identities or a non-finite
    /// deadline.
    #[error("maintenance trigger claim request refused for trigger {trigger_id}: {source}")]
    Request {
        /// Stable trigger identity being claimed.
        trigger_id: String,
        /// Stable delivery identity for this claim epoch.
        delivery_id: String,
        /// Exact request refusal; nothing was issued.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The Kernel delivery owner refused the claim or a page read.
    #[error("maintenance trigger claim owner refused for trigger {trigger_id}: {source}")]
    Owner {
        /// Stable trigger identity being claimed.
        trigger_id: String,
        /// Stable delivery identity for this claim epoch.
        delivery_id: String,
        /// Exact owner refusal; concurrent claims conflict here.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The issued claim does not answer this trigger under the live fence:
    /// a stale generation, a substituted identity, or a lapsed deadline.
    #[error("maintenance trigger claim is stale for trigger {trigger_id}: {source}")]
    StaleClaim {
        /// Stable trigger identity being claimed.
        trigger_id: String,
        /// Stable delivery identity for this claim epoch.
        delivery_id: String,
        /// Exact fence, echo, or expiry refusal.
        #[source]
        source: Box<ProtocolError>,
    },
    /// A bounded pending-page read failed or answered outside the page
    /// contract.
    #[error("maintenance trigger page walk refused: {source}")]
    Page {
        /// Exact page refusal; the walk resumes from its held cursor.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
}

impl MaintenanceTriggerClaimError {
    /// Returns the stable trigger identity being claimed, when the failure
    /// is claim-scoped.
    #[must_use]
    pub fn trigger_id(&self) -> Option<&str> {
        match self {
            Self::Request { trigger_id, .. }
            | Self::Owner { trigger_id, .. }
            | Self::StaleClaim { trigger_id, .. } => Some(trigger_id),
            Self::Page { .. } => None,
        }
    }

    /// Returns the stable delivery identity for this claim epoch, when the
    /// failure is claim-scoped.
    #[must_use]
    pub fn delivery_id(&self) -> Option<&str> {
        match self {
            Self::Request { delivery_id, .. }
            | Self::Owner { delivery_id, .. }
            | Self::StaleClaim { delivery_id, .. } => Some(delivery_id),
            Self::Page { .. } => None,
        }
    }
}

/// Builds the request refusal for one daemon claim attempt.
///
/// The retained record and the presented delivery identity carry the retry
/// identity, so a malformed request keeps what the caller retries under.
fn claim_request_error(
    record: &MaintenanceTriggerRecord,
    identity: &TriggerClaimIdentity,
    source: ProtocolError,
) -> MaintenanceTriggerClaimError {
    MaintenanceTriggerClaimError::Request {
        trigger_id: record.trigger_id.clone(),
        delivery_id: identity.delivery_id.clone(),
        source: Box::new(source),
    }
}

/// Builds the owner refusal for one daemon claim attempt.
fn claim_owner_error(
    record: &MaintenanceTriggerRecord,
    identity: &TriggerClaimIdentity,
    source: MaintenanceTriggerDeliveryError,
) -> MaintenanceTriggerClaimError {
    MaintenanceTriggerClaimError::Owner {
        trigger_id: record.trigger_id.clone(),
        delivery_id: identity.delivery_id.clone(),
        source: Box::new(source),
    }
}

/// Builds the stale-claim refusal for one owner answer that does not
/// authorize under the live fence.
fn claim_stale_error(
    record: &MaintenanceTriggerRecord,
    identity: &TriggerClaimIdentity,
    source: ProtocolError,
) -> MaintenanceTriggerClaimError {
    MaintenanceTriggerClaimError::StaleClaim {
        trigger_id: record.trigger_id.clone(),
        delivery_id: identity.delivery_id.clone(),
        source: Box::new(source),
    }
}

/// Builds the page-walk refusal for one failed or off-contract page read.
fn page_walk_error(source: MaintenanceTriggerDeliveryError) -> MaintenanceTriggerClaimError {
    MaintenanceTriggerClaimError::Page {
        source: Box::new(source),
    }
}

/// Issues one finite fenced claim for the calling daemon generation (I14.22,
/// issue #1694 W3).
///
/// It binds the claim to the current compatible daemon generation/session, the
/// retained trigger revision, and the delivery identity, then verifies the
/// owner's answer before returning it. An exact retry returns the live claim
/// from the owner; a concurrent claim under another identity is refused by the
/// owner with `ClaimConflict`, never returned here; an old-generation response
/// fails the fence check. Claim timeout permits owner-mediated redelivery under
/// the same identity, never a new trigger ID or authority to repeat an
/// uncertain downstream effect.
///
/// # Live status
///
/// This entry has NO production caller. It is *transitively* dead rather than
/// name-level dead, so a scan for call sites reports one: the single call is
/// inside [`redeliver_maintenance_trigger_after_timeout`], which is itself
/// uncalled. The earlier claim that this "is the production front-door claim
/// caller" was therefore false and has been removed. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon claim loop or retired is an owner
/// decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerClaimError`]: a malformed request, a Kernel
/// owner refusal, or a stale-claim fence/echo/expiry refusal.
pub fn claim_maintenance_trigger_for_daemon(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    record: &MaintenanceTriggerRecord,
    live_fence: &StateFence,
    identity: &TriggerClaimIdentity,
) -> Result<MaintenanceTriggerClaim, MaintenanceTriggerClaimError> {
    record
        .validate()
        .map_err(|source| claim_request_error(record, identity, source))?;
    if identity.daemon_session.trim().is_empty() {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.daemon_session",
                reason: "claiming session must be named",
            },
        ));
    }
    if identity.delivery_id.trim().is_empty() {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.delivery_id",
                reason: "delivery identity must be named",
            },
        ));
    }
    // The lease is finite and bounded by the owner's own ceiling: a stale
    // deadline fails here, before any ledger transition, and the row stays
    // open under its existing disposition.
    if identity.claim_deadline_unix_ms <= identity.now_unix_ms
        || identity.claim_deadline_unix_ms - identity.now_unix_ms
            > MAX_MAINTENANCE_TRIGGER_CLAIM_LEASE_MS
    {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.claim_deadline_unix_ms",
                reason: "claim must be finite and within the claim lease bound",
            },
        ));
    }
    live_fence.validate().map_err(|source| {
        claim_request_error(record, identity, ProtocolError::Foundation(source))
    })?;
    let (claim, _) = gateway
        .claim_maintenance_trigger(
            principal_ref,
            MaintenanceTriggerClaimRequest {
                trigger_id: record.trigger_id.clone(),
                daemon_fence: live_fence.clone(),
                daemon_session: identity.daemon_session.clone(),
                delivery_id: identity.delivery_id.clone(),
                claim_deadline_unix_ms: identity.claim_deadline_unix_ms,
                current_fence: live_fence.clone(),
                now_unix_ms: identity.now_unix_ms,
            },
        )
        .map_err(|source| claim_owner_error(record, identity, source))?;
    claim
        .validate()
        .map_err(MaintenanceTriggerDeliveryError::Protocol)
        .map_err(|source| claim_owner_error(record, identity, source))?;
    // The claim must answer this trigger under this delivery identity and
    // session: a substituted answer fails here rather than authorizing work
    // under the wrong obligation.
    if claim.trigger_id != record.trigger_id
        || claim.delivery_id != identity.delivery_id
        || claim.daemon_session != identity.daemon_session
        || claim.daemon_fence != *live_fence
    {
        return Err(claim_stale_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.delivery_id",
                reason: "claim answers a different trigger, delivery, session, or generation",
            },
        ));
    }
    // Old-generation claims fail after revocation and lapsed claims fail
    // without minting a new trigger or delivery identity.
    claim
        .authorize_for(record, live_fence, identity.now_unix_ms)
        .map_err(|source| claim_stale_error(record, identity, source))?;
    Ok(claim)
}

/// One bounded walk over the pending-trigger set.
#[derive(Clone, Debug)]
pub struct PendingTriggerWalk {
    /// Pending summaries listed across the walked pages, in owner order.
    pub members: Vec<MaintenanceTriggerPendingSummary>,
    /// Explicit gap records carried across the walked pages.
    pub gaps: Vec<MaintenanceTriggerGap>,
    /// Resume cursor for the next walk; `None` only when the owner closed
    /// the set with no further page.
    pub continuation: Option<String>,
    /// Pages read during this walk, bounded by the caller's page budget.
    pub pages_walked: u32,
}

/// Enumerates the pending set in bounded pages with stable continuation
/// (I14.22, issue #1694 W3).
///
/// A reconnect resumes from its held cursor and never resets progress to a
/// guessed complete-empty set: continuations are threaded opaquely — the
/// caller's cursor starts the walk and only owner-issued cursors advance it
/// — and every page is validated, so an empty page always carries at least
/// one explicit gap. The walk stops after `max_pages` pages even when the
/// owner has more: the partial accumulation returns with the resume cursor
/// for the next walk rather than growing without bound.
///
/// # Live status
///
/// This entry currently has NO caller anywhere: not in production and not in
/// this file. It is the W3 enumeration leg the daemon run loop would need to
/// see pending maintenance debt, and the daemon does not walk that set. The
/// mirror-gated variant [`surface_replacement_pending_set`] is likewise
/// uncalled. This doc block made no production claim of its own; the status is
/// recorded here so the module's enumeration legs are not read as live.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerClaimError::Page`] for a Kernel owner page
/// refusal or a page that answers outside the page contract.
pub fn collect_pending_maintenance_triggers(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    continuation: Option<&str>,
    now_unix_ms: u64,
    max_pages: NonZeroU32,
) -> Result<PendingTriggerWalk, MaintenanceTriggerClaimError> {
    let mut walk = PendingTriggerWalk {
        members: Vec::new(),
        gaps: Vec::new(),
        continuation: continuation.map(str::to_owned),
        pages_walked: 0,
    };
    while walk.pages_walked < max_pages.get() {
        let page = gateway
            .maintenance_trigger_pending_page(
                principal_ref,
                walk.continuation.as_deref(),
                now_unix_ms,
            )
            .map_err(page_walk_error)?;
        page.validate()
            .map_err(|source| page_walk_error(MaintenanceTriggerDeliveryError::Protocol(source)))?;
        walk.members.extend(page.members);
        walk.gaps.extend(page.gaps);
        walk.pages_walked += 1;
        if page.has_more {
            // Validated above: a further page always carries its cursor.
            walk.continuation = page.continuation;
        } else {
            walk.continuation = None;
            break;
        }
    }
    // A closed walk with no members still carries the owner's explicit gaps:
    // page validation refuses an empty gapless page, so absence here is the
    // owner's witnessed incompleteness, never a certified-complete set.
    Ok(walk)
}

/// Reclaims one timed-out claim through owner-mediated redelivery (I14.22,
/// issue #1694 W3).
///
/// It releases the timed-out claim through
/// [`KernelStoreGateway::release_expired_maintenance_trigger_claim`] — a
/// `Claimed` row returns to `Pending`, a `DecisionRecorded` row moves to
/// `Reconciling` with its committed receipt preserved — then routes on the
/// owner's post-release snapshot under the same trigger identity and
/// revision. A row carrying a committed decision receipt returns
/// [`MaintenanceTriggerRedeliveryOutcome::ReconcileByReceipt`]: the owner
/// must acknowledge that exact receipt without another job, recommendation,
/// or wake — never repeat the uncertain downstream effect — by claiming
/// first through [`claim_maintenance_trigger_for_daemon`] and completing
/// through [`acknowledge_recovered_maintenance_commit`]. Both of those are
/// also uncalled; see the module-level `# Live status`. A row with no
/// committed receipt re-issues one fresh finite claim through
/// [`claim_maintenance_trigger_for_daemon`] under the same identity and
/// revision, so an exact retry reuses the live claim and a concurrent claim
/// conflicts there instead of producing a competing accepted decision.
///
/// A timeout never mints a new trigger ID and never widens the lease: the
/// presented identity must already carry a fresh finite deadline, checked
/// before any ledger transition, so a stale deadline fails with the row left
/// open under its existing disposition. Settled rows (`Acknowledged`,
/// `Expired`, `Superseded`) carry no releasable claim, so the owner refuses
/// the release and they reconcile through the stored outcome instead of a
/// fresh claim.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door timeout-redelivery
/// caller" was false and has been removed. Nothing in the daemon polls for a
/// timed-out maintenance claim, so no claim is ever reclaimed on a live path.
/// See the module-level `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon poll loop or retired is an owner
/// decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerClaimError`]: a malformed request, the exact
/// Kernel owner release/claim refusal, or a stale-claim refusal when the
/// owner's receipt answers another trigger, revision, or scope.
pub fn redeliver_maintenance_trigger_after_timeout(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    record: &MaintenanceTriggerRecord,
    live_fence: &StateFence,
    identity: &TriggerClaimIdentity,
) -> Result<MaintenanceTriggerRedeliveryOutcome, MaintenanceTriggerClaimError> {
    record
        .validate()
        .map_err(|source| claim_request_error(record, identity, source))?;
    if identity.daemon_session.trim().is_empty() {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.daemon_session",
                reason: "claiming session must be named",
            },
        ));
    }
    if identity.delivery_id.trim().is_empty() {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.delivery_id",
                reason: "delivery identity must be named",
            },
        ));
    }
    // Redelivery always needs a fresh finite claim, never a new trigger ID:
    // a stale deadline fails here, before any ledger transition, and the row
    // stays open under its existing disposition.
    if identity.claim_deadline_unix_ms <= identity.now_unix_ms
        || identity.claim_deadline_unix_ms - identity.now_unix_ms
            > MAX_MAINTENANCE_TRIGGER_CLAIM_LEASE_MS
    {
        return Err(claim_request_error(
            record,
            identity,
            ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.claim_deadline_unix_ms",
                reason: "redelivery must carry a fresh finite deadline within the claim lease bound",
            },
        ));
    }
    live_fence.validate().map_err(|source| {
        claim_request_error(record, identity, ProtocolError::Foundation(source))
    })?;
    // Owner-mediated release under the same trigger identity: the owner
    // refuses a still-live claim, an unknown trigger, and a settled row, so
    // none of those can reach a fresh claim below.
    let rows = gateway
        .release_expired_maintenance_trigger_claim(
            principal_ref,
            &record.trigger_id,
            identity.now_unix_ms,
        )
        .map_err(|source| claim_owner_error(record, identity, source))?;
    let row = rows
        .iter()
        .find(|row| row.record.trigger_id == record.trigger_id)
        .ok_or_else(|| {
            claim_owner_error(
                record,
                identity,
                MaintenanceTriggerDeliveryError::UnknownTrigger,
            )
        })?;
    if let Some(receipt) = row.decision_receipt.as_ref() {
        // A decision is already committed: return its exact receipt for
        // acknowledgement. The receipt must validate and answer this exact
        // retained trigger at this exact row revision; a substituted answer
        // fails here rather than authorizing an ack under the wrong
        // obligation, and never authorizes repeating the downstream effect.
        receipt
            .validate()
            .map_err(MaintenanceTriggerDeliveryError::Protocol)
            .map_err(|source| claim_owner_error(record, identity, source))?;
        receipt
            .matches_trigger(record)
            .map_err(|source| claim_stale_error(record, identity, source))?;
        if receipt.revision != row.revision {
            return Err(claim_stale_error(
                record,
                identity,
                ProtocolError::ReplayConflict,
            ));
        }
        return Ok(MaintenanceTriggerRedeliveryOutcome::ReconcileByReceipt(
            receipt.clone(),
        ));
    }
    // No committed decision: re-issue one fresh finite claim under the same
    // identity and revision. The claim join re-checks the fence, the finite
    // deadline, the revision echo, and the exact-retry/conflict rules, so
    // concurrent claims and exact retries cannot produce competing accepted
    // decisions.
    let claim =
        claim_maintenance_trigger_for_daemon(gateway, principal_ref, record, live_fence, identity)?;
    Ok(MaintenanceTriggerRedeliveryOutcome::Reclaimed(claim))
}

/// Fail-closed refusals of the decision-commit route (I14.22, issue #1694 W4).
///
/// Every variant keeps the producer-visible retry identity (trigger identity
/// plus delivery identity) and the exact typed refusal: a local binding
/// refusal stays a [`ProtocolError`], while the Kernel delivery owner's
/// refusal — including its exact canonical Store receipt proof — stays a
/// [`MaintenanceTriggerDeliveryError`]. No failure records a decision, and no
/// failure authorizes the delivery acknowledgement.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerDecisionCommitError {
    /// The retained record, the live claim, or the decision receipt does not
    /// bind this operation: unvalidatable shape, a lapsed or foreign claim,
    /// or a receipt answering another trigger, hash, scope, or claim revision.
    #[error("maintenance trigger decision binding refused for trigger {trigger_id}: {source}")]
    Binding {
        /// Stable trigger identity the decision must answer.
        trigger_id: String,
        /// Stable delivery identity of the live claim.
        delivery_id: String,
        /// Exact binding refusal; nothing was submitted.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The Kernel delivery owner refused the commit, including its exact
    /// canonical receipt proof: an arbitrary receipt ID or a transport `Ok`
    /// never completes this transition.
    #[error("maintenance trigger decision owner refused for trigger {trigger_id}: {source}")]
    Owner {
        /// Stable trigger identity the decision must answer.
        trigger_id: String,
        /// Stable delivery identity of the live claim.
        delivery_id: String,
        /// Exact owner refusal; nothing was recorded.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The owner answered without carrying this exact committed receipt, so
    /// the commit is unproven and the acknowledgement must not proceed.
    #[error("maintenance trigger decision unproven for trigger {trigger_id}: {source}")]
    Unproven {
        /// Stable trigger identity the decision must answer.
        trigger_id: String,
        /// Stable delivery identity of the live claim.
        delivery_id: String,
        /// Exact content refusal; the returned rows name another outcome.
        #[source]
        source: Box<ProtocolError>,
    },
}

impl MaintenanceTriggerDecisionCommitError {
    /// Returns the stable trigger identity the decision must answer.
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        match self {
            Self::Binding { trigger_id, .. }
            | Self::Owner { trigger_id, .. }
            | Self::Unproven { trigger_id, .. } => trigger_id,
        }
    }

    /// Returns the stable delivery identity of the live claim.
    #[must_use]
    pub fn delivery_id(&self) -> &str {
        match self {
            Self::Binding { delivery_id, .. }
            | Self::Owner { delivery_id, .. }
            | Self::Unproven { delivery_id, .. } => delivery_id,
        }
    }
}

/// Builds the binding refusal for one decision-commit attempt.
///
/// The retained record and the live claim carry the retry identity, so every
/// shape, fence, and content-binding refusal keeps what the caller retries
/// under.
fn commit_binding_error(
    record: &MaintenanceTriggerRecord,
    claim: &MaintenanceTriggerClaim,
    source: ProtocolError,
) -> MaintenanceTriggerDecisionCommitError {
    MaintenanceTriggerDecisionCommitError::Binding {
        trigger_id: record.trigger_id.clone(),
        delivery_id: claim.delivery_id.clone(),
        source: Box::new(source),
    }
}

/// Builds the owner refusal for one decision-commit attempt.
fn commit_owner_error(
    record: &MaintenanceTriggerRecord,
    claim: &MaintenanceTriggerClaim,
    source: MaintenanceTriggerDeliveryError,
) -> MaintenanceTriggerDecisionCommitError {
    MaintenanceTriggerDecisionCommitError::Owner {
        trigger_id: record.trigger_id.clone(),
        delivery_id: claim.delivery_id.clone(),
        source: Box::new(source),
    }
}

/// Builds the unproven-commit refusal for an owner answer that does not carry
/// this exact committed receipt.
fn commit_unproven_error(
    record: &MaintenanceTriggerRecord,
    claim: &MaintenanceTriggerClaim,
) -> MaintenanceTriggerDecisionCommitError {
    MaintenanceTriggerDecisionCommitError::Unproven {
        trigger_id: record.trigger_id.clone(),
        delivery_id: claim.delivery_id.clone(),
        source: Box::new(ProtocolError::InvalidField {
            field: "maintenance_trigger_delivery.decision_receipt",
            reason: "returned rows do not carry this committed decision",
        }),
    }
}

/// Records one committed maintenance decision before any delivery
/// acknowledgement (I14.22, issue #1694 W4).
///
/// It is the intended follow-up daemon-to-Kernel leg after
/// `maintenance_trigger_evaluator::DaemonComposition::commit_maintenance_trigger_decision`
/// resolves the current #1692 policy, reuses the #1688 evaluator, and retains
/// the durable downstream intent through its existing outbox owner
/// (Governor `PreparedTransition` -> Kernel -> named Store transaction, I1.8).
/// That leg proves the canonical Store receipt in hand; this route would bind
/// that exact receipt into the Kernel delivery ledger, which alone may later be
/// acknowledged. A decision plus a durable downstream intent is distinct from
/// an executed job or a delivered notification: this route admits no job,
/// starts nothing, and delivers nothing — it records the commitment the
/// acknowledgement must echo.
///
/// The receipt binds the retained trigger identity and operation hash, the
/// exact claim revision it was evaluated against, the evaluation and policy
/// revisions, the affected scope, and at least one durable
/// job/recommendation/wake intent reference; the owner entry re-reads the
/// exact canonical Store receipt — `Committed` status, canonical-bytes
/// digest, live-authority fence — before recording, so an arbitrary receipt
/// ID or a transport `Ok(())` can never complete this transition. Bound
/// evidence is content, not receipt-ID existence: the returned durable rows
/// must carry this exact receipt at `DecisionRecorded`. An identical receipt
/// replays idempotently through the owner, while a different receipt under a
/// recorded row conflicts there.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door decision-commit
/// route" was false and has been removed.
///
/// The preceding leg this doc points at,
/// `maintenance_trigger_evaluator::DaemonComposition::commit_maintenance_trigger_decision`,
/// is *also* uncalled, so the follow-up relationship this block described was
/// aspirational on both sides: the daemon run loop reaches
/// `evaluate_maintenance_trigger` (which does run) and then stops. The nearest
/// real thing is that read-only evaluation. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to that evaluation or retired is an owner
/// decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerDecisionCommitError`]: a local binding
/// refusal, the exact Kernel owner refusal, or an unproven owner answer that
/// must not be acknowledged.
pub async fn record_committed_maintenance_decision(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    record: &MaintenanceTriggerRecord,
    claim: &MaintenanceTriggerClaim,
    decision_receipt: MaintenanceTriggerDecisionReceipt,
    live_fence: &StateFence,
    now_unix_ms: u64,
) -> Result<MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDecisionCommitError> {
    record
        .validate()
        .map_err(|source| commit_binding_error(record, claim, source))?;
    claim
        .validate()
        .map_err(|source| commit_binding_error(record, claim, source))?;
    decision_receipt
        .validate()
        .map_err(|source| commit_binding_error(record, claim, source))?;
    // The commit authorizes under the live claim only: a stale generation, a
    // foreign session, or a lapsed deadline fails here before any ledger
    // transition, and the row keeps its existing disposition.
    claim
        .authorize_for(record, live_fence, now_unix_ms)
        .map_err(|source| commit_binding_error(record, claim, source))?;
    // The receipt must answer this exact retained trigger: identical
    // identity, operation hash, and scope. Changed content conflicts; it
    // never re-binds.
    decision_receipt
        .matches_trigger(record)
        .map_err(|source| commit_binding_error(record, claim, source))?;
    // ... and the exact claim revision it was evaluated against, matching
    // the row the owner records under.
    if decision_receipt.revision != claim.revision {
        return Err(commit_binding_error(
            record,
            claim,
            ProtocolError::ReplayConflict,
        ));
    }
    // Submit the full receipt content through the Kernel owner, which
    // re-reads the exact canonical Store receipt before recording.
    let rows = gateway
        .record_maintenance_trigger_decision(
            principal_ref,
            &record.trigger_id,
            decision_receipt.clone(),
        )
        .await
        .map_err(|source| commit_owner_error(record, claim, source))?;
    // Bound evidence is content, not receipt-ID existence: the durable
    // snapshot must carry this exact receipt at `DecisionRecorded`.
    let proven = rows.iter().any(|row| {
        row.record.trigger_id == record.trigger_id
            && row.disposition == MaintenanceTriggerDisposition::DecisionRecorded
            && row.decision_receipt.as_ref() == Some(&decision_receipt)
    });
    if !proven {
        return Err(commit_unproven_error(record, claim));
    }
    Ok(decision_receipt)
}

/// Fail-closed refusals of the crash-recovery handoff route (I14.22, issue
/// #1694 W5).
///
/// Every variant keeps the stable trigger identity (plus the delivery identity
/// on the ack path) and the exact Kernel owner refusal: a replay/read refusal
/// stays a [`MaintenanceTriggerDeliveryError`], and a locally unvalidatable
/// recovered shape stays a [`ProtocolError`]. No failure mints a new trigger
/// ID, synthesizes a receipt, or authorizes repeating an uncertain downstream
/// effect.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerRecoveryError {
    /// Crash replay through the Kernel owner failed: no retained record
    /// could be re-presented under this identity.
    #[error("maintenance trigger crash replay refused for trigger {trigger_id}: {source}")]
    Replay {
        /// Stable trigger identity being recovered.
        trigger_id: String,
        /// Exact owner refusal; nothing was re-presented.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The owner returned a decision receipt that does not validate, so it
    /// must not be acknowledged.
    #[error("maintenance trigger recovered receipt refused for trigger {trigger_id}: {source}")]
    Receipt {
        /// Stable trigger identity being recovered.
        trigger_id: String,
        /// Exact shape refusal; the receipt was not reused.
        #[source]
        source: Box<ProtocolError>,
    },
    /// Marking a lost or ambiguous commit as reconciling failed.
    #[error("maintenance trigger ambiguous-commit mark refused for trigger {trigger_id}: {source}")]
    Ambiguous {
        /// Stable trigger identity staying open.
        trigger_id: String,
        /// Exact owner refusal; the row keeps its existing disposition.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The locally built ack echoes a shape the wire contract refuses, so it
    /// never reached the owner.
    #[error("maintenance trigger recovered ack malformed for trigger {trigger_id}: {source}")]
    AckShape {
        /// Stable trigger identity being acknowledged.
        trigger_id: String,
        /// Delivery identity of the claim being acknowledged.
        delivery_id: String,
        /// Exact shape refusal; nothing was acknowledged.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The Kernel owner refused the recovered acknowledgement.
    #[error("maintenance trigger recovered ack refused for trigger {trigger_id}: {source}")]
    Ack {
        /// Stable trigger identity being acknowledged.
        trigger_id: String,
        /// Delivery identity of the claim being acknowledged.
        delivery_id: String,
        /// Exact owner refusal; delivery stays unacknowledged.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
}

impl MaintenanceTriggerRecoveryError {
    /// Returns the stable trigger identity being recovered.
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        match self {
            Self::Replay { trigger_id, .. }
            | Self::Receipt { trigger_id, .. }
            | Self::Ambiguous { trigger_id, .. }
            | Self::AckShape { trigger_id, .. }
            | Self::Ack { trigger_id, .. } => trigger_id,
        }
    }

    /// Returns the delivery identity being acknowledged, when the failure is
    /// on the ack path.
    #[must_use]
    pub fn delivery_id(&self) -> Option<&str> {
        match self {
            Self::AckShape { delivery_id, .. } | Self::Ack { delivery_id, .. } => Some(delivery_id),
            Self::Replay { .. } | Self::Receipt { .. } | Self::Ambiguous { .. } => None,
        }
    }
}

/// Where one interrupted trigger must resume after a crash (I14.22, issue
/// #1694 W5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerRecoveryOutcome {
    /// Crash before decision commit: re-present this exact retained record to
    /// the evaluator under the same identity. Never mint a new trigger, and
    /// never treat receipt absence during an outage as proof of non-commit.
    ReplayRecord {
        /// The exact retained record, byte-identical to the admitted one.
        record: Box<MaintenanceTriggerRecord>,
    },
    /// Commit before ack: acknowledge this exact owner-looked-up receipt
    /// without another job, recommendation, or wake. The receipt is the
    /// Kernel owner's read-back, never a locally synthesized value.
    AcknowledgeReceipt {
        /// The committed decision receipt to acknowledge.
        receipt: Box<MaintenanceTriggerDecisionReceipt>,
    },
}

/// Routes one interrupted trigger to its crash-recovery handoff (I14.22,
/// issue #1694 W5).
///
/// It reads the owner's committed state first through
/// [`KernelStoreGateway::recover_maintenance_trigger_commit`], and only when
/// no committed receipt answers does it fall back to
/// [`KernelStoreGateway::replay_maintenance_trigger_after_crash`]. A committed
/// receipt therefore reuses the bound durable decision — idempotent accepted
/// results, not exactly one physical evaluation call — while a pre-commit
/// crash replays the same retained trigger for a fresh evaluation under the
/// same identity.
///
/// A lost or ambiguous commit response is not routed here: it stays
/// pending/reconciling through
/// [`mark_maintenance_trigger_commit_ambiguous_after_loss`] — which is itself
/// uncalled — and receipt absence during an outage is never reported as proof
/// of non-commit.
/// Materially new policy or source evidence never overwrites the old result:
/// it arrives as an explicitly linked new trigger through
/// [`admit_maintenance_trigger_intake`] and links via
/// [`supersede_maintenance_trigger_with_successor`]. Both of those are
/// uncalled too, so the "new trigger arrives, then links" sequence described
/// here cannot currently happen; see the module-level `# Live status`.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door recovery router"
/// was false and has been removed. The daemon run loop performs no
/// crash-recovery read of a maintenance trigger after startup, so no trigger is
/// ever routed to this handoff on a live path. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon startup recovery pass or retired is
/// an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRecoveryError`]: an unvalidatable recovered
/// receipt, or an owner refusal to replay under this identity (which also
/// covers the owner being unreachable — both reads fail closed then).
pub fn recover_maintenance_trigger_handoff(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    trigger_id: &str,
) -> Result<MaintenanceTriggerRecoveryOutcome, MaintenanceTriggerRecoveryError> {
    if trigger_id.trim().is_empty() {
        return Err(MaintenanceTriggerRecoveryError::Replay {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(MaintenanceTriggerDeliveryError::Protocol(
                ProtocolError::InvalidField {
                    field: "maintenance_trigger.trigger_id",
                    reason: "trigger identity must be named",
                },
            )),
        });
    }
    if let Ok(receipt) = gateway.recover_maintenance_trigger_commit(principal_ref, trigger_id) {
        receipt
            .validate()
            .map_err(|source| MaintenanceTriggerRecoveryError::Receipt {
                trigger_id: trigger_id.to_owned(),
                source: Box::new(source),
            })?;
        Ok(MaintenanceTriggerRecoveryOutcome::AcknowledgeReceipt {
            receipt: Box::new(receipt),
        })
    } else {
        // No committed receipt answers this identity (open row, unknown
        // trigger, or owner refusal): the crash happened before decision
        // commit, so replay the same retained trigger. An owner outage
        // fails this read too, and that refusal is the returned error.
        let record = gateway
            .replay_maintenance_trigger_after_crash(principal_ref, trigger_id)
            .map_err(|source| MaintenanceTriggerRecoveryError::Replay {
                trigger_id: trigger_id.to_owned(),
                source: Box::new(source),
            })?;
        Ok(MaintenanceTriggerRecoveryOutcome::ReplayRecord {
            record: Box::new(record),
        })
    }
}

/// Acknowledges one recovered commit with its exact decision receipt (I14.22,
/// issue #1694 W5).
///
/// It echoes the live claim exactly (trigger, delivery identity, fence,
/// session) and embeds the owner-looked-up receipt content byte for byte
/// through [`KernelStoreGateway::acknowledge_maintenance_trigger`]. No job is
/// admitted, no recommendation is suggested, and no wake is scheduled here —
/// the receipt already binds those durable intents.
///
/// The claim must be live under the current generation: claim first through
/// [`claim_maintenance_trigger_for_daemon`] — also uncalled — and after a
/// revocation reclaim under the replacement identity. A
/// `DecisionRecorded`/`Reconciling` row whose live claim lapsed re-submits this
/// same receipt through [`KernelStoreGateway::record_maintenance_trigger_decision`]
/// first — the
/// owner reuses the identical receipt idempotently — so the live claim binds
/// the committed row before this ack. Expired eligibility blocks the ack at
/// the owner; record terminal expiry through
/// [`expire_inapplicable_maintenance_trigger`] instead, which is uncalled as
/// well. An ack refusal on an already-settled row reconciles through the
/// recorded outcome, never through a fresh claim.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. This doc block named itself "the commit-before-ack
/// completion caller" while the whole commit-before-ack route around it is
/// unwired, so the label described a role rather than a live edge. Nothing in
/// the daemon acknowledges a maintenance trigger, so no maintenance delivery is
/// ever completed on a live path. See the module-level `# Live status` for the
/// whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon acknowledgement pass or retired is
/// an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRecoveryError`]: a locally malformed ack, or
/// the exact Kernel owner ack refusal (stale consumer, lapsed claim, receipt
/// mismatch, expired eligibility).
pub fn acknowledge_recovered_maintenance_commit(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    claim: &MaintenanceTriggerClaim,
    decision_receipt: &MaintenanceTriggerDecisionReceipt,
    current_fence: &StateFence,
    now_unix_ms: u64,
) -> Result<(), MaintenanceTriggerRecoveryError> {
    let ack = MaintenanceTriggerAck {
        wire_id: MAINTENANCE_TRIGGER_ACK_WIRE_ID.to_owned(),
        wire_version: MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
        trigger_id: claim.trigger_id.clone(),
        delivery_id: claim.delivery_id.clone(),
        daemon_fence: claim.daemon_fence.clone(),
        daemon_session: claim.daemon_session.clone(),
        decision_receipt: decision_receipt.clone(),
    };
    ack.validate()
        .map_err(|source| MaintenanceTriggerRecoveryError::AckShape {
            trigger_id: claim.trigger_id.clone(),
            delivery_id: claim.delivery_id.clone(),
            source: Box::new(source),
        })?;
    gateway
        .acknowledge_maintenance_trigger(principal_ref, &ack, current_fence, now_unix_ms)
        .map_err(|source| MaintenanceTriggerRecoveryError::Ack {
            trigger_id: claim.trigger_id.clone(),
            delivery_id: claim.delivery_id.clone(),
            source: Box::new(source),
        })?;
    Ok(())
}

/// Holds one lost or ambiguous commit response open for reconciliation
/// (I14.22, issue #1694 W5).
///
/// It marks the trigger reconciling through
/// [`KernelStoreGateway::mark_maintenance_trigger_commit_ambiguous`], which
/// keeps the row open and attaches a visible `AmbiguousCommit` gap record.
/// The trigger must then be reconciled by receipt lookup through
/// [`recover_maintenance_trigger_handoff`] — also uncalled — before any further
/// effect; it is never blindly re-executed and its external effects are never
/// rerun on a guess.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door ambiguous-commit
/// caller" was false and has been removed. Nothing in the daemon observes a
/// lost commit response, so no maintenance trigger is ever marked reconciling
/// on a live path. See the module-level `# Live status` for the whole
/// zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon commit-failure handler or retired is
/// an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRecoveryError::Ambiguous`] for the exact
/// Kernel owner refusal.
pub fn mark_maintenance_trigger_commit_ambiguous_after_loss(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    trigger_id: &str,
    now_unix_ms: u64,
) -> Result<(), MaintenanceTriggerRecoveryError> {
    gateway
        .mark_maintenance_trigger_commit_ambiguous(principal_ref, trigger_id, now_unix_ms)
        .map_err(|source| MaintenanceTriggerRecoveryError::Ambiguous {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(source),
        })?;
    Ok(())
}

/// Fail-closed refusals of the replacement-startup route (I14.22/I14.24,
/// issue #1694 W6).
///
/// Every variant keeps the exact Kernel owner refusal: a ledger-restore
/// refusal, a consumer-revocation refusal, or a mirror-gated pending-set
/// refusal stays a [`MaintenanceTriggerDeliveryError`]. A replacement never
/// claims reconciliation complete before the required mirror recovery, and
/// ordinary pending debt never acquires a runtime lease here.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerStartupError {
    /// The owned delivery ledger refused the once-only startup restore.
    #[error("maintenance trigger ledger restore refused: {source}")]
    Restore {
        /// Exact owner refusal; no claim has been served.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The Kernel owner refused the lost-consumer revocation.
    #[error("maintenance trigger consumer revocation refused: {source}")]
    Revoke {
        /// Exact owner refusal; old consumer authority is unchanged.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The mirror-gated replacement pending set could not be surfaced,
    /// including the owner refusing before mirror recovery completes.
    #[error("maintenance trigger replacement pending set refused: {source}")]
    Surface {
        /// Exact owner refusal; reconciliation is not complete.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
}

/// Restores the owned delivery ledger once at startup (I14.22, issue #1694
/// W6).
///
/// It hands the previously persisted durable rows to
/// [`KernelStoreGateway::restore_maintenance_trigger_ledger`] before any
/// claim is served. The rows source is the startup composition's read-back of
/// the persisted rows through the Store-lane rows backend — this caller owns
/// neither the read-back nor the persistence, only the handoff. The owner
/// refuses when it already holds rows and revalidates every row, so a damaged
/// row fails the restore instead of entering as a guessed-complete entry.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door restore caller"
/// was false and has been removed. `daemon_runtime.rs` performs a real startup
/// sequence and reaches the maintenance family catalog
/// (`maintenance_family_catalog::record_registered_catalog`), but it never
/// reads persisted maintenance delivery rows back and never hands them to the
/// Kernel ledger, so no restore runs at daemon startup. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to the daemon startup sequence or retired is an
/// owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerStartupError::Restore`] for the exact owner
/// refusal.
pub fn restore_maintenance_trigger_ledger_at_startup(
    gateway: &KernelStoreGateway,
    rows: Vec<MaintenanceTriggerDeliveryRow>,
) -> Result<Vec<MaintenanceTriggerDeliveryRow>, MaintenanceTriggerStartupError> {
    gateway
        .restore_maintenance_trigger_ledger(rows)
        .map_err(|source| MaintenanceTriggerStartupError::Restore {
            source: Box::new(source),
        })
}

/// Revokes one lost daemon generation's trigger-consumer authority (I14.24,
/// issue #1694 W6).
///
/// It revokes the old consumer fence/session through
/// [`KernelStoreGateway::revoke_maintenance_trigger_consumer`], which is the
/// existing Kernel owner. Pending claims are retained under the same identity
/// and revision for the replacement generation; committed rows move to
/// `Reconciling` with their receipts preserved; every later old-generation
/// claim or ack fails. The revocation value itself names the lost fence and
/// session observed by the startup composition.
///
/// # Live status
///
/// This entry has NO production caller. It is *transitively* dead rather than
/// name-level dead, so a scan for call sites reports one: the single call is
/// inside [`recover_replacement_generation`], which is itself uncalled. The
/// earlier claim that this "is the production front-door revocation caller"
/// was therefore false and has been removed. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon generation-replacement path or
/// retired is an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerStartupError::Revoke`] for the exact owner
/// refusal.
pub fn revoke_lost_daemon_consumer_for_replacement(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    revocation: MaintenanceTriggerRevocation,
) -> Result<(), MaintenanceTriggerStartupError> {
    revocation
        .validate()
        .map_err(MaintenanceTriggerDeliveryError::Protocol)
        .map_err(|source| MaintenanceTriggerStartupError::Revoke {
            source: Box::new(source),
        })?;
    gateway
        .revoke_maintenance_trigger_consumer(principal_ref, revocation)
        .map_err(|source| MaintenanceTriggerStartupError::Revoke {
            source: Box::new(source),
        })?;
    Ok(())
}

/// Surfaces the bounded pending set to a replacement generation (I14.22,
/// issue #1694 W6).
///
/// It walks [`KernelStoreGateway::maintenance_trigger_replacement_pending_set`]
/// in bounded pages with stable continuation, exactly like
/// [`collect_pending_maintenance_triggers`] but through the mirror-gated
/// owner entry. Replacement authentication plus the required mirror recovery
/// must already be complete — `mirror_recovered == false` is refused by the
/// owner with `MirrorRecoveryRequired`, so maintenance reconciliation can
/// never be claimed complete before the mirrors are rebuilt. A reconnect
/// resumes from its held cursor and never resets progress to a guessed
/// complete-empty set: only owner-issued cursors advance the walk, every page
/// is validated, and the walk stops after `max_pages` pages with the resume
/// cursor held. Ordinary pending debt acquires no runtime lease and blocks no
/// unrelated safe work; safety/recovery triggers stay visible to their
/// registered Host/Kernel/Watchdog/Doctor route through the owner-issued
/// grant they already carry, and duplicated delivery authorizes no duplicated
/// containment.
///
/// # Live status
///
/// This entry has NO production caller. It is *transitively* dead rather than
/// name-level dead, so a scan for call sites reports one: the single call is
/// inside [`recover_replacement_generation`], which is itself uncalled. The
/// earlier claim that this "is the production front-door replacement-enumeration
/// caller" was therefore false and has been removed. See the module-level
/// `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon generation-replacement path or
/// retired is an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerStartupError::Surface`] for a Kernel owner
/// page refusal (including missing mirror recovery) or a page that answers
/// outside the page contract.
pub fn surface_replacement_pending_set(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    continuation: Option<&str>,
    mirror_recovered: bool,
    now_unix_ms: u64,
    max_pages: NonZeroU32,
) -> Result<PendingTriggerWalk, MaintenanceTriggerStartupError> {
    let mut walk = PendingTriggerWalk {
        members: Vec::new(),
        gaps: Vec::new(),
        continuation: continuation.map(str::to_owned),
        pages_walked: 0,
    };
    while walk.pages_walked < max_pages.get() {
        let page = gateway
            .maintenance_trigger_replacement_pending_set(
                principal_ref,
                walk.continuation.as_deref(),
                mirror_recovered,
                now_unix_ms,
            )
            .map_err(|source| MaintenanceTriggerStartupError::Surface {
                source: Box::new(source),
            })?;
        page.validate()
            .map_err(MaintenanceTriggerDeliveryError::Protocol)
            .map_err(|source| MaintenanceTriggerStartupError::Surface {
                source: Box::new(source),
            })?;
        walk.members.extend(page.members);
        walk.gaps.extend(page.gaps);
        walk.pages_walked += 1;
        if page.has_more {
            // Validated above: a further page always carries its cursor.
            walk.continuation = page.continuation;
        } else {
            walk.continuation = None;
            break;
        }
    }
    Ok(walk)
}

/// Recovers one replacement daemon generation in revoke-then-surface order
/// (I14.24, issue #1694 W6).
///
/// It revokes the lost generation's consumer authority first, then surfaces
/// the bounded pending set, matching the I14.24 `eliotd`-crash row ("Kernel
/// revokes daemon epoch … compatible daemon generation; rebuild hot mirrors").
/// Revocation before surfacing is load-bearing — the replacement reclaims the
/// same trigger identities only after the old consumer can no longer answer.
/// Ordinary pending debt keeps no runtime alive here.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door replacement-startup
/// wiring" was false and has been removed. It is the W6 composition leg: it is
/// the only caller of [`revoke_lost_daemon_consumer_for_replacement`] and
/// [`surface_replacement_pending_set`], so those two are transitively dead with
/// it, and its own absence is what leaves the replacement-startup route with no
/// entry. `daemon_runtime.rs` does perform a real startup sequence, but it
/// never revokes a lost generation's maintenance consumer authority. See the
/// module-level `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to the daemon startup sequence or retired is an
/// owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerStartupError`]: a revocation refusal, or a
/// mirror-gated pending-set refusal.
pub fn recover_replacement_generation(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    revocation: MaintenanceTriggerRevocation,
    continuation: Option<&str>,
    mirror_recovered: bool,
    now_unix_ms: u64,
    max_pages: NonZeroU32,
) -> Result<PendingTriggerWalk, MaintenanceTriggerStartupError> {
    revoke_lost_daemon_consumer_for_replacement(gateway, principal_ref, revocation)?;
    surface_replacement_pending_set(
        gateway,
        principal_ref,
        continuation,
        mirror_recovered,
        now_unix_ms,
        max_pages,
    )
}

/// One protected-routing assignment verified for route visibility (I14.24,
/// issue #1694 W6).
///
/// Names the registered safety/recovery route one retained trigger stays
/// visible to while the evaluator is down. Visibility only: the assignment
/// authorizes no evaluation, no claim, no acknowledgement, and no
/// containment — containment still requires the evaluator plus the fenced
/// claim/commit/ack path, so a duplicated delivery can never authorize
/// duplicated containment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRouteAssignment {
    /// Stable trigger identity staying visible to its registered route.
    pub trigger_id: String,
    /// Operation hash the assignment is bound under.
    pub operation_hash: String,
    /// Registered safety/recovery route from the owner-issued grant.
    pub route: MaintenanceTriggerRoute,
    /// Owner principal that issued the classification.
    pub owner_id: String,
}

/// Fail-closed refusals of the protected-route visibility selector (I14.24,
/// issue #1694 W6).
///
/// Every variant keeps the stable trigger identity and the exact wire refusal
/// as a [`ProtocolError`]: owner-signature issuance proof stays with the
/// issuing owner and the Kernel intake path, which already admitted the
/// record. Nothing is routed and no containment is authorized on any failure.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerProtectedRouteError {
    /// The retained record fails validation, so no route can be read from it.
    #[error("maintenance trigger route record refused for trigger {trigger_id}: {source}")]
    Shape {
        /// Stable trigger identity that could not be routed.
        trigger_id: String,
        /// Exact shape refusal; nothing was routed.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The protected classification is missing, expired, not bound to this
    /// trigger, or changed content arrives under a known identity.
    #[error("maintenance trigger route classification refused for trigger {trigger_id}: {source}")]
    Classification {
        /// Stable trigger identity that could not be routed.
        trigger_id: String,
        /// Operation hash the refused classification arrived under.
        operation_hash: String,
        /// Exact classification refusal; no containment was authorized.
        #[source]
        source: Box<ProtocolError>,
    },
}

impl MaintenanceTriggerProtectedRouteError {
    /// Returns the stable trigger identity that could not be routed.
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        match self {
            Self::Shape { trigger_id, .. } | Self::Classification { trigger_id, .. } => trigger_id,
        }
    }
}

/// Builds the classification refusal for one retained record.
///
/// The record carries the retry identity, so every missing, expired,
/// unbound, or conflicting classification keeps the trigger identity and
/// operation hash it arrived under.
fn protected_route_classification_error(
    record: &MaintenanceTriggerRecord,
    source: ProtocolError,
) -> MaintenanceTriggerProtectedRouteError {
    MaintenanceTriggerProtectedRouteError::Classification {
        trigger_id: record.trigger_id.clone(),
        operation_hash: record.operation_hash.clone(),
        source: Box::new(source),
    }
}

/// Selects the protected-routing deliveries visible to their registered route
/// while the evaluator is down (I14.24, issue #1694 W6).
///
/// It runs over retained records a caller supplies, and assigns each
/// safety/recovery trigger to the registered
/// Host/Kernel/Watchdog/Doctor route its owner-issued grant opens. The grant
/// must validate at `now_unix_ms` and bind this exact trigger identity and
/// operation hash — classification is owner-issued, never caller-asserted,
/// and expiry withdraws the classification without deleting the retained
/// trigger. Ordinary records are skipped, never promoted: ordinary pending
/// debt stays visible through the bounded pending set only, and gains no
/// protected authority here.
///
/// A duplicated delivery assigns once: an exact identity/hash repeat reuses
/// the first assignment, while changed content under a known identity
/// conflicts instead of re-routing. The selector performs no evaluation,
/// admits no job, issues no claim or acknowledgement, and performs no
/// containment, so a duplicated delivery cannot authorize duplicated
/// containment; containment still requires the evaluator plus the fenced
/// claim/commit/ack path. The walk is bounded by its input slice, holds no
/// lease, keeps no runtime alive, and blocks no unrelated safe work.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door
/// protected-visibility selector" was false and has been removed. The records
/// it would read are the ones [`recover_replacement_generation`] and
/// [`collect_pending_maintenance_triggers`] would surface, and both are
/// uncalled, so the input slice this selector walks is never produced on a
/// live path. The owner-issued `MaintenanceTriggerRouteGrant` classification it
/// verifies does exist and is carried on the wire record; what does not exist
/// is the daemon-side reader. See the module-level `# Live status`.
///
/// Whether this entry is wired to the daemon replacement path or retired is an
/// owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerProtectedRouteError`]: an unvalidatable
/// retained record, or a protected classification that is missing, expired,
/// unbound, or conflicting.
pub fn select_protected_route_deliveries(
    records: &[MaintenanceTriggerRecord],
    now_unix_ms: u64,
) -> Result<Vec<ProtectedRouteAssignment>, MaintenanceTriggerProtectedRouteError> {
    let mut assignments: Vec<ProtectedRouteAssignment> = Vec::new();
    for record in records {
        record
            .validate()
            .map_err(|source| MaintenanceTriggerProtectedRouteError::Shape {
                trigger_id: record.trigger_id.clone(),
                source: Box::new(source),
            })?;
        if record.routing_class == MaintenanceTriggerRoutingClass::Ordinary {
            // Ordinary pending debt never gains protected visibility: it
            // stays on the bounded pending set under its existing policy
            // owner, and ordinary authority never widens here.
            continue;
        }
        let Some(grant) = record.route_grant.as_ref() else {
            return Err(protected_route_classification_error(
                record,
                ProtocolError::InvalidField {
                    field: "maintenance_trigger.route_grant",
                    reason: "protected routing requires an owner-issued grant",
                },
            ));
        };
        grant
            .validate_at(now_unix_ms)
            .map_err(|source| protected_route_classification_error(record, source))?;
        if !grant.binds(&record.trigger_id, &record.operation_hash) {
            return Err(protected_route_classification_error(
                record,
                ProtocolError::ReplayConflict,
            ));
        }
        if let Some(assigned) = assignments
            .iter()
            .find(|assigned| assigned.trigger_id == record.trigger_id)
        {
            if assigned.operation_hash == record.operation_hash {
                // Exact duplicate delivery: already visible under this
                // assignment, so nothing further is authorized.
                continue;
            }
            return Err(protected_route_classification_error(
                record,
                ProtocolError::ReplayConflict,
            ));
        }
        assignments.push(ProtectedRouteAssignment {
            trigger_id: record.trigger_id.clone(),
            operation_hash: record.operation_hash.clone(),
            route: grant.route,
            owner_id: grant.owner_id.clone(),
        });
    }
    Ok(assignments)
}

/// Fail-closed refusals of the expiry/damage/retention route (I14.22/I5.2,
/// issue #1694 W7).
///
/// Every variant keeps the stable trigger identity and the exact Kernel owner
/// refusal, except a damage kind owned by another transition, which stays a
/// [`ProtocolError`] before any owner call. Expired eligibility blocks stale
/// execution but never deletes the row, its record, or its evidence locators;
/// damage produces a visible recovery/gap record, never a plaintext fallback
/// and never silent deletion.
#[derive(Debug, Error)]
pub enum MaintenanceTriggerRetentionError {
    /// Terminal expiry was refused by the Kernel owner.
    #[error("maintenance trigger expiry refused for trigger {trigger_id}: {source}")]
    Expiry {
        /// Stable trigger identity past its applicability window.
        trigger_id: String,
        /// Exact owner refusal; the row keeps its existing disposition.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// Supersession by an explicitly linked successor was refused.
    #[error("maintenance trigger supersession refused for trigger {trigger_id}: {source}")]
    Supersession {
        /// Stable trigger identity being superseded.
        trigger_id: String,
        /// Exact owner refusal; the old result is unchanged.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
    /// The damage kind belongs to another owning transition, so it never
    /// reached the gap owner.
    #[error("maintenance trigger gap kind refused for trigger {trigger_id}: {source}")]
    GapKind {
        /// Stable trigger identity carrying the damage.
        trigger_id: String,
        /// Exact kind refusal; nothing was recorded.
        #[source]
        source: Box<ProtocolError>,
    },
    /// The visible recovery/gap record was refused by the Kernel owner.
    #[error("maintenance trigger gap record refused for trigger {trigger_id}: {source}")]
    Gap {
        /// Stable trigger identity carrying the damage.
        trigger_id: String,
        /// Exact owner refusal; nothing was recorded.
        #[source]
        source: Box<MaintenanceTriggerDeliveryError>,
    },
}

impl MaintenanceTriggerRetentionError {
    /// Returns the stable trigger identity this retention refusal names.
    #[must_use]
    pub fn trigger_id(&self) -> &str {
        match self {
            Self::Expiry { trigger_id, .. }
            | Self::Supersession { trigger_id, .. }
            | Self::GapKind { trigger_id, .. }
            | Self::Gap { trigger_id, .. } => trigger_id,
        }
    }
}

/// Records terminal expiry for one past-window trigger (I14.22, issue #1694
/// W7).
///
/// It records the terminal `Expired` disposition through
/// [`KernelStoreGateway::expire_maintenance_trigger`]. Expired eligibility
/// blocks stale execution — claims and acks against the row fail at the owner
/// afterwards — but the row, its record, and its evidence locators are
/// preserved under the retention policy; nothing unresolved is deleted. Call
/// this only when `now_unix_ms` is past the record's
/// `applicable_until_unix_ms`: the owner refuses a still-applicable trigger,
/// and an unknown identity stays unknown.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door expiry caller"
/// was false and has been removed. The daemon run loop runs a maintenance
/// cadence but never expires a past-window maintenance trigger, so an
/// over-applicability window is not enforced by any live caller. See the
/// module-level `# Live status` for the whole zero-caller W2–W7 route.
///
/// Whether this entry is wired to the daemon maintenance cadence or retired is
/// an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRetentionError::Expiry`] for the exact owner
/// refusal.
pub fn expire_inapplicable_maintenance_trigger(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    trigger_id: &str,
    reason: &str,
    now_unix_ms: u64,
) -> Result<(), MaintenanceTriggerRetentionError> {
    gateway
        .expire_maintenance_trigger(principal_ref, trigger_id, reason, now_unix_ms)
        .map_err(|source| MaintenanceTriggerRetentionError::Expiry {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(source),
        })?;
    Ok(())
}

/// Records supersession by one explicitly linked successor trigger (I14.22,
/// issue #1694 W7).
///
/// It links the successor through
/// [`KernelStoreGateway::supersede_maintenance_trigger`]. The old result is
/// never overwritten — the successor is named on the terminal disposition and
/// both rows stay readable with their records and receipts. The successor
/// must already be admitted through [`admit_maintenance_trigger_intake`],
/// which is itself uncalled, so no successor can currently be admitted and this
/// link cannot currently be formed; see the module-level `# Live status`.
/// Materially new policy or source evidence would therefore have to arrive as a
/// new admitted trigger first and link here, instead of rerunning the old row's
/// external effects blindly.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door supersession
/// caller" was false and has been removed. The precondition this block relied
/// on is itself unwired, which is the sharper half of the problem: a reader
/// following "the successor must already be admitted through
/// [`admit_maintenance_trigger_intake`]" would arrive at an entry with no
/// caller either. See the module-level `# Live status` for the whole
/// zero-caller W2–W7 route.
///
/// Whether this entry is wired to a daemon supersession pass or retired is an
/// owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRetentionError::Supersession`] for the exact
/// owner refusal, including an unadmitted successor identity.
pub fn supersede_maintenance_trigger_with_successor(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    trigger_id: &str,
    successor_trigger_id: &str,
    reason: &str,
    now_unix_ms: u64,
) -> Result<(), MaintenanceTriggerRetentionError> {
    gateway
        .supersede_maintenance_trigger(
            principal_ref,
            trigger_id,
            successor_trigger_id,
            reason,
            now_unix_ms,
        )
        .map_err(|source| MaintenanceTriggerRetentionError::Supersession {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(source),
        })?;
    Ok(())
}

/// Records a visible recovery/gap record for unrepairable damage (I14.22/I5.2,
/// issue #1694 W7).
///
/// It records the gap through [`KernelStoreGateway::record_maintenance_trigger_gap`].
/// Missing keys, corrupt payloads, and inaccessible sources produce this record —
/// never a plaintext fallback, never a bare `no_action`, and never silent
/// deletion, per the I5.2 opaque-payload rules. Only those three kinds travel
/// this entry: `AmbiguousCommit` belongs to the W5 ambiguous-commit
/// transition ([`mark_maintenance_trigger_commit_ambiguous_after_loss`], also
/// uncalled) and `IncompleteEnumeration` belongs to the page-owning
/// transitions, and the owner refuses both here, so this entry refuses them
/// before any write.
/// Compaction stays with the ledger owner and happens only after exact
/// ack or terminal disposition plus required downstream retention — this
/// entry compacts nothing and deletes nothing — and per-disposition counts
/// stay on the existing role-filtered recovery surface.
///
/// # Live status
///
/// This entry currently has NO production caller; the body is reachable only
/// by naming it. A source implementation is not evidence of a live edge, so
/// the earlier claim that this "is the production front-door damage caller"
/// was false and has been removed. Nothing in the daemon classifies a
/// maintenance trigger as damaged, so no visible recovery/gap record is
/// produced for one on a live path. The refusal behaviour described above
/// (refusing `AmbiguousCommit` and `IncompleteEnumeration` before any write) is
/// unaffected by the missing caller; it is simply never exercised by the
/// daemon. See the module-level `# Live status` for the whole zero-caller
/// W2–W7 route.
///
/// Whether this entry is wired to a daemon damage-detection pass or retired is
/// an owner decision, not a documentation one.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerRetentionError`]: a kind owned by another
/// transition, or the exact owner gap-record refusal.
pub fn record_maintenance_trigger_damage(
    gateway: &KernelStoreGateway,
    principal_ref: &str,
    trigger_id: &str,
    kind: MaintenanceTriggerGapKind,
    detail: &str,
    now_unix_ms: u64,
) -> Result<(), MaintenanceTriggerRetentionError> {
    if matches!(
        kind,
        MaintenanceTriggerGapKind::AmbiguousCommit
            | MaintenanceTriggerGapKind::IncompleteEnumeration
    ) {
        return Err(MaintenanceTriggerRetentionError::GapKind {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(ProtocolError::InvalidField {
                field: "maintenance_trigger_gap.kind",
                reason: "enumeration and commit gaps are recorded by their owning transitions",
            }),
        });
    }
    gateway
        .record_maintenance_trigger_gap(principal_ref, trigger_id, kind, detail, now_unix_ms)
        .map_err(|source| MaintenanceTriggerRetentionError::Gap {
            trigger_id: trigger_id.to_owned(),
            source: Box::new(source),
        })?;
    Ok(())
}
