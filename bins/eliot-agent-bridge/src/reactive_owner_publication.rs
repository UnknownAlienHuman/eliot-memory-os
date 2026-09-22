//! D2 live-ledger owner publication: typed session/attention publishers,
//! governor-coverage and policy-owner adapters, and the deterministic
//! six-slot assembly.
//!
//! Position in the I7.19 sequence (`docs/architecture/I07-19-reactive-context-sequence.md`):
//!
//! ```text
//! pending injection -> host hook or next bridge response
//! -> Delivery/Injection Receipt -> attention output (published live here)
//! -> six-slot publication (assembled live here)
//! ```
//!
//! # What publishes live today
//!
//! - [`publish_live_attention_projection`]: `CriticalAttentionProjection`
//!   built entirely from live ledger + live binding facts through the
//!   in-tree validated constructors (`CriticalAttentionMember::validate`,
//!   `CriticalAttentionProjection::validate` + `canonical_digest`). Every
//!   field's provenance is documented on the builder.
//! - [`governor_coverage_posture`]: bridge-owned observation of the live
//!   `GovernorCoverageDerivation` (revision, completeness, verified,
//!   fingerprint, freshness intent). Fully live.
//! - [`live_policy_frame`]: bridge-owned observation of the live policy
//!   binding facts (plan identity, observation clock). Fully live.
//! - [`publish_live_ledger_session`] / [`publish_live_ledger_attention`]:
//!   ledger-native observations under the exact live session/fence.
//! - [`assemble_live_six_slot`]: deterministic publication over D1-served
//!   view/cue (consumed through the plan-crate port shape
//!   [`SettledPlanFeedInputs`](eliot_reactive_context_plan::SettledPlanFeedInputs))
//!   plus the four D2 values, with liveness checks against the live attach
//!   before delegating to the plan-crate binder. Deterministic by
//!   construction; runnable end-to-end once all four values are live.
//! - [`serve_live_six_slot`]: one production serving call through the four
//!   D2 resolvers into the assembly (resolver order session → attention →
//!   coverage → policy → assembly; first missing inventory fails the call).
//!
//! # What fails closed, and on exactly which missing owner facts
//!
//! [`publish_live_session_snapshot`], [`adapt_contract_coverage`], and
//! [`adapt_delivery_policy`] derive every field live owner state supplies
//! and fail closed with [`OwnerPublicationError::MissingOwnerFacts`] naming
//! the exact unowned fields. No field is fabricated to satisfy a validator:
//!
//! - session snapshot (9): `runtime_id`, `host_id`, `runtime_generation`,
//!   `host_generation`, `recipient_id`, `attempt_id` (no runtime/host/
//!   recipient/attempt owner in the bridge; see [`resolve_runtime_envelope`]),
//!   plus per-record `operation_id`, `request_id`, `idempotency_key`
//!   (bridge hook/response deliveries are piggybacks, never operations; see
//!   [`resolve_record_envelope`]). Per-record `source_revision` already
//!   resolves through the [`BridgeRunner::reactive_item_cue`] probe.
//! - contract coverage (14 + candidate state): the host/runtime/interface/
//!   recipient identity envelope, generations, contract, modes, ceilings,
//!   owner-claim events, and owner gaps (I7.16 discovery/owner state; see
//!   [`resolve_coverage_envelope`]). The verified governor candidate binds
//!   by fingerprint and contributes live gap evidence; unverified or foreign
//!   candidates fail closed with their exact cause.
//! - delivery policy (22): the policy-owner envelope (see
//!   [`resolve_policy_envelope`]). The live frame carries only plan
//!   identity and the (empty) observation clock; `tie_break_revision = 1`,
//!   no deadline, and `cancelled = false` are contract-fixed or observed
//!   bridge facts.
//!
//! # Authority separation
//!
//! - **This module owns:** one causal read of live state per call. It holds
//!   no state across calls, mints no session, fence, receipt, disposition,
//!   or digest beyond the contract-specified canonical digests of values it
//!   assembled from live facts.
//! - **Bridge owns (never produced here):** the live attach session/fence
//!   binding, ledger mutation, receipts, stickiness enforcement, normal
//!   dedup. Observed through `BridgeRunner::attach_view` and
//!   `BridgeRunner::reactive_attention`/`reactive_receipt`
//!   (`bins/eliot-agent-bridge/src/lib.rs`), and
//!   `ReactiveInjectionLedger::attention_output`
//!   (`bins/eliot-agent-bridge/src/reactive_injection_receipts.rs`).
//! - **Governor owns (never produced here):** `GovernanceProfile` revisions
//!   (`GovernorCoverageDerivation::derive`,
//!   `crates/governor/eliot-integration-coverage/src/lib.rs`) and per-item
//!   risk tiers (`assess_reactive_risk`,
//!   `crates/governor/eliot-governor/src/reactive_admission.rs`). This
//!   module only reads `derivation.current()` / `revision()`.
//! - **D1 owns (never produced here):** the assembled A15 view and the A10
//!   cue activation. Consumed by borrow through the plan-crate port shape.
//!
//! # Type-difference log (never conflated, no `From` bridges)
//!
//! - Coverage: this module adapts the governor
//!   `eliot_integration_coverage::IntegrationCoverageProfile`
//!   (fingerprint/verified candidate vocabulary) and its derived
//!   `GovernanceProfile` into the planner's
//!   `eliot_context_contracts::IntegrationCoverageProfile` (host/runtime/
//!   interface capability vocabulary). The two profile types share a name
//!   and nothing else.
//! - Policy: this module adapts toward the plan-crate
//!   `ReactiveDeliveryPolicy` (self-verifying `policy_digest`).
//!   `eliot_governor::PolicyOwner` / `HumanOwner` `policy_owner` snapshots
//!   are by-name lookalikes and are never accepted here.
//! - Risk: the governor `ReactiveRiskTier` renders to the bridge `RiskTier`
//!   through the explicit match in `governor_assess`
//!   (`bins/eliot-agent-bridge/src/settled_plan_transport.rs`); that
//!   rendering is reused by reference, never duplicated here.
//!
//! # Stickiness honesty
//!
//! The ledger's `attention_output` already excludes only terminal-disposition
//! items; this module clones that open set unchanged — it never re-adds a
//! resolved, waived, or superseded item and never infers resolution.
//! Delivered normal items stay absent until invalidation re-admits them.
//! Absence of later use evidence stays `Unknown` on the receipt and maps to
//! `AttentionInfluence::Unknown`; use is never inferred here.
//!
//! # REAL ledger-to-publication path per value
//!
//! - live session/fence: `BridgeRunner::attach_view` →
//!   `binding.session_id()` / `state_fence()` (`lib.rs`, `live_reactive_session`)
//!   echoed as `StateFence` exactly like `live_state_fence`
//!   (`reactive_runtime_composition.rs`).
//! - open rows: `BridgeRunner::reactive_attention` (`lib.rs`) ←
//!   `ReactiveInjectionLedger::attention_output`
//!   (`reactive_injection_receipts.rs`).
//! - per-delivered-row use facts: `BridgeRunner::reactive_receipt`
//!   (`lib.rs`) ← `ReactiveInjectionLedger::receipt`.
//! - per-row cue facts: `BridgeRunner::reactive_item_cue` (`lib.rs`) ←
//!   `ReactiveInjectionLedger::item_cue` (`reactive_injection_receipts.rs`,
//!   mirroring the `item_session` probe).
//! - task/scope/plan/principal: `binding.task_binding()` (`TaskId`,
//!   work-scope string, plan identity) and `binding.principal_id()`.
//! - governor posture: `GovernorCoverageDerivation::current` / `revision`
//!   (`crates/governor/eliot-integration-coverage/src/lib.rs`); candidate
//!   gaps/fingerprint from the integrator-held verified governor candidate
//!   profile (same crate, candidate vocabulary).

use eliot_agent_bridge_core::BridgeError;
use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::PriorDeliveryBinding;
use eliot_context_contracts::{
    AttentionAcknowledgement, AttentionInfluence, AttentionOwnerClosure, AttentionResolution,
    CoverageEvidence, CriticalAttentionMember, CriticalAttentionProjection,
    IntegrationCoverageProfile, ReactiveDeliveryMode, ReactiveInputError, SemanticRole,
    SessionDeliverySnapshot, SnapshotCompleteness, SnapshotDenominator,
};
use eliot_contracts::{
    ArtifactId, ClockReading, ContractIdentity, ContractVersion, OperationId, RequestId,
    ResourceGeneration, SourceId, StateFence, canonical_json_bytes, contract_identity, sha256_hex,
};
use eliot_integration_coverage::{EventCompleteness, GovernorCoverageDerivation};
use eliot_protocol::{
    ReactiveContextContentRef, ReactiveContextLifecycleEvidence, ReactiveContextPrivacy,
    ReactiveContextStage, ReactiveContextValidity,
};
use eliot_reactive_context_plan::{
    AttentionDisclosureRule, OwnerBindError, OwnerBoundPublication, ReactiveDeliveryPolicy,
    SettledPlanFeedInputs, bind_owner_publication,
};
use eliot_receipts::{EffectClass, ProofCeiling, WorkScopeId};

use super::BridgeRunner;
use super::reactive_injection_receipts::{
    AttentionItem, REACTIVE_INJECTION_CONTRACT, Severity, UseOutcome,
};

/// Bound on attention members / session records in one live publication.
///
/// Mirrors the contract bounds (`MAX_MEMBERS` in
/// `crates/smart/eliot-context-contracts/src/reactive_attention.rs`,
/// `MAX_RECORDS` in `reactive_session.rs`); the ledger itself retains more,
/// so the publishers fail closed instead of truncating.
const MAX_PUBLISHED_ROWS: usize = 256;

/// Bridge-issued observation owner: the delivery-record contract that backs
/// every value this module issues. Naming the bridge's own contract as owner
/// claims exactly the provenance this module has.
const BRIDGE_OBSERVATION_OWNER: &str = REACTIVE_INJECTION_CONTRACT;

/// Ledger source identity for bridge-issued delivery history.
const LEDGER_SOURCE_ID: &str = "eliot.agent-bridge.reactive-ledger";

/// Revision of the ledger delivery-record source vocabulary.
const LEDGER_SOURCE_REVISION: &str = "ledger-delivery-records-v1";

/// Member/projection source revision when the per-item source revision is
/// not available. Members now carry their exact ledger source revision via
/// the [`BridgeRunner::reactive_item_cue`] probe; the projection-level
/// revision stays coarse (members may span sources) and declares that
/// in-band.
const SOURCE_REVISION_UNEXPOSED: &str = "unknown:bridge-ledger-item-cue-unexposed";

/// Resolution condition carried by every bridge-published open member: the
/// ledger shows no terminal disposition for the item.
const RESOLUTION_CONDITION_OPEN: &str = "ledger-open-no-terminal-disposition";

/// Freshness gap declared by the coverage posture: the bridge retains no
/// owner claim receipts, so the adapted profile can never be `Fresh`.
const COVERAGE_FRESHNESS_GAP: &str = "bridge-retains-no-owner-claim-receipts";

/// Coverage gap declared by the attention projection: the bridge tracks no
/// coverage state, so it declares the gap instead of claiming completeness.
const ATTENTION_COVERAGE_GAP: &str = "bridge-tracks-no-coverage-state";

/// Fail-closed publication errors. The ledger/owners own the reason detail;
/// this module owns only the transport-facing classification, mirroring
/// `reactive_ledger_error` in `bins/eliot-agent-bridge/src/lib.rs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerPublicationError {
    /// No live attach: there is no session or fence to publish under.
    NotAttached,
    /// The live attach fence carries a zero generation and cannot key a
    /// publication.
    InvalidFence,
    /// A live binding text was rejected by its validated constructor.
    InvalidBinding {
        /// Binding field that failed validation.
        field: &'static str,
    },
    /// The live open set exceeds the contract publication bound.
    CapacityExceeded {
        /// What exceeded the bound.
        what: &'static str,
    },
    /// Live owner state does not supply the named facts. Each entry names
    /// one exact unowned field; see the resolver docs for the owning lane.
    MissingOwnerFacts {
        /// Exact missing owner facts, envelope-first in deterministic order.
        facts: Vec<&'static str>,
    },
    /// A contract value failed its in-tree validation or digest check.
    Invalid(ReactiveInputError),
    /// The six-slot binder rejected individually valid projections.
    Bind(OwnerBindError),
}

impl core::fmt::Display for OwnerPublicationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAttached => write!(formatter, "no live attach session to publish under"),
            Self::InvalidFence => {
                write!(formatter, "live attach fence generation must be non-zero")
            }
            Self::InvalidBinding { field } => write!(formatter, "live binding rejected: {field}"),
            Self::CapacityExceeded { what } => write!(formatter, "{what} exceeds bounded capacity"),
            Self::MissingOwnerFacts { facts } => {
                write!(formatter, "missing owner facts: {}", facts.join(", "))
            }
            Self::Invalid(error) => write!(formatter, "owner projection invalid: {error:?}"),
            Self::Bind(error) => write!(formatter, "owner bind rejected: {error}"),
        }
    }
}

impl std::error::Error for OwnerPublicationError {}

impl OwnerPublicationError {
    /// Project onto the closed bridge error set without inventing a variant.
    #[must_use]
    pub fn to_bridge_error(&self) -> BridgeError {
        match self {
            Self::NotAttached => BridgeError::NotAttached,
            Self::InvalidFence => BridgeError::InvalidContract {
                field: "attach.state_fence.generation",
                reason: "generation must be non-zero",
            },
            Self::InvalidBinding { field } => BridgeError::InvalidContract {
                field,
                reason: "live binding rejected",
            },
            Self::CapacityExceeded { what } => {
                BridgeError::ProviderContract(format!("{what} exceeds bounded capacity"))
            }
            Self::MissingOwnerFacts { facts } => {
                BridgeError::ProviderContract(format!("missing owner facts: {}", facts.join(", ")))
            }
            Self::Invalid(error) => {
                BridgeError::ProviderContract(format!("owner projection invalid: {error:?}"))
            }
            Self::Bind(error) => {
                BridgeError::ProviderContract(format!("owner bind rejected: {error}"))
            }
        }
    }
}

/// Live fence echoed from the attach binding, exactly as
/// `live_state_fence` does in
/// `bins/eliot-agent-bridge/src/reactive_runtime_composition.rs`:
/// epoch clone plus generation value; authority stays with the binding.
fn live_state_fence(runner: &BridgeRunner) -> Result<(String, StateFence), OwnerPublicationError> {
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let binding = view.binding();
    let session_id = binding.session_id().as_str().to_owned();
    let generation = ResourceGeneration::new(binding.state_fence().generation().get())
        .map_err(|_| OwnerPublicationError::InvalidFence)?;
    let fence = StateFence::new(binding.state_fence().authority_epoch().clone(), generation);
    Ok((session_id, fence))
}

/// Live-ledger session publication: the exact live session/fence plus the
/// ledger's honest open set for that session.
///
/// - `pending_item_ids`: open items not yet delivered (`delivered == false`
///   in `BridgeRunner::reactive_attention`).
/// - `open_delivered_receipt_ids`: open items already delivered, by receipt
///   identity (`receipt_id` on delivered attention rows). Delivered normal
///   items that the ledger deduplicated are honestly absent here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveLedgerSession {
    /// Exact live attach session the ledger was read under.
    pub session_id: String,
    /// Exact live attach fence the ledger was read under.
    pub fence: StateFence,
    /// Open undelivered item identities in ledger order.
    pub pending_item_ids: Vec<String>,
    /// Receipt identities of open delivered items in ledger order.
    pub open_delivered_receipt_ids: Vec<String>,
}

/// Live-ledger attention publication: the sticky-critical set plus pending
/// normals, cloned unchanged from `BridgeRunner::reactive_attention`.
///
/// Every open critical item stays present (pending or delivered) until the
/// ledger records a durable resolved, waived, or superseded disposition;
/// delivered normals appear only after invalidation re-admits them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveLedgerAttention {
    /// Exact live attach session the attention was read under.
    pub session_id: String,
    /// Exact live attach fence the attention was read under.
    pub fence: StateFence,
    /// Open critical items, sticky until a terminal disposition.
    pub open_critical: Vec<AttentionItem>,
    /// Pending (undelivered) normal item identities in ledger order.
    pub pending_normal_ids: Vec<String>,
}

/// Publish the live-ledger session observation under the exact live
/// session/fence. Fails closed while detached.
pub fn publish_live_ledger_session(
    runner: &BridgeRunner,
) -> Result<LiveLedgerSession, OwnerPublicationError> {
    let (session_id, fence) = live_state_fence(runner)?;
    let attention = runner.reactive_attention();
    let mut pending_item_ids = Vec::new();
    let mut open_delivered_receipt_ids = Vec::new();
    for item in &attention {
        if item.delivered {
            if let Some(receipt_id) = item.receipt_id.clone() {
                open_delivered_receipt_ids.push(receipt_id);
            }
        } else {
            pending_item_ids.push(item.item_id.clone());
        }
    }
    Ok(LiveLedgerSession {
        session_id,
        fence,
        pending_item_ids,
        open_delivered_receipt_ids,
    })
}

/// Publish the live-ledger attention observation under the exact live
/// session/fence. Fails closed while detached. The critical set is the
/// ledger's own sticky projection, cloned without filtering.
pub fn publish_live_ledger_attention(
    runner: &BridgeRunner,
) -> Result<LiveLedgerAttention, OwnerPublicationError> {
    let (session_id, fence) = live_state_fence(runner)?;
    let attention = runner.reactive_attention();
    let mut open_critical = Vec::new();
    let mut pending_normal_ids = Vec::new();
    for item in attention {
        match item.severity {
            Severity::Critical => open_critical.push(item),
            Severity::Normal => {
                if !item.delivered {
                    pending_normal_ids.push(item.item_id.clone());
                }
            }
        }
    }
    Ok(LiveLedgerAttention {
        session_id,
        fence,
        open_critical,
        pending_normal_ids,
    })
}

/// Map one ledger row to its honest delivery stage.
///
/// Pending rows were admitted and persisted but never delivered
/// (`EnqueuedPersisted`); delivered rows were attempted through a host hook
/// or the next bridge response (`DeliveryAttempted`). Neither stage needs an
/// owner receipt, and neither claims endpoint delivery (which would require
/// an owner closure this module never mints).
fn ledger_delivery_stage(delivered: bool) -> ReactiveContextStage {
    if delivered {
        ReactiveContextStage::DeliveryAttempted
    } else {
        ReactiveContextStage::EnqueuedPersisted
    }
}

/// Map one receipt use status to its honest influence observation.
///
/// `Unknown` (absence of evidence) stays unknown; any observed use,
/// influence, or outcome becomes `Observed`. Absence is never rendered as
/// `NotObserved`: the bridge cannot distinguish "not used" from "not yet
/// observed".
fn ledger_influence(update: &UseOutcome) -> AttentionInfluence {
    match update {
        UseOutcome::Unknown => AttentionInfluence::Unknown,
        UseOutcome::ObservedUse { .. }
        | UseOutcome::ObservedInfluence { .. }
        | UseOutcome::Outcome { .. } => AttentionInfluence::Observed,
    }
}

/// Build one open attention member from one live ledger row.
///
/// Field provenance (all live, no caller bytes):
///
/// - `attention_id` / `claim_artifact_id`: the ledger item identity
///   (`AttentionItem::item_id`, minted as `reactive-item-{seq}` by
///   `ReactiveInjectionLedger::admit`). The bridge issues no separate claim
///   artifact, so the claim identity is the attention identity.
/// - `claim_digest`: computed with `CriticalAttentionMember::
///   canonical_resolution_claim_digest` after the member is assembled.
/// - `kind`: `CRITICAL` / `NORMAL` from `AttentionItem::severity`.
/// - `source_revision`: the item's exact ledger source revision, resolved
///   through the [`BridgeRunner::reactive_item_cue`] probe (which mirrors
///   the `item_session` probe on the ledger).
/// - `source` / `evidence`: empty — the bridge retains no owner evidence;
///   empty vectors validate and claim nothing.
/// - `task_id`: the live attach task binding (same `TaskId` type, shared
///   ownership, no conversion).
/// - `scope_id`: `WorkScopeId::new` over the live attach work-scope string.
/// - `owner_id`: [`BRIDGE_OBSERVATION_OWNER`] — this projection is issued
///   by the bridge delivery-record owner.
/// - `delivery_stage`: [`ledger_delivery_stage`] of the row.
/// - `acknowledgement`: `Unknown` — the bridge tracks no ack phase;
///   delivery and acknowledgement stay separate per I7.6.
/// - `influence`: [`ledger_influence`] of the row's receipt use status when
///   delivered and the receipt resolves, else `Unknown`.
/// - `resolution`: `Open` — terminal rows never reach this builder (the
///   ledger excludes them from `attention_output`).
/// - `resolution_condition`: [`RESOLUTION_CONDITION_OPEN`].
/// - `waiver_authority` / `superseded_by` / `deadline_unix_ms` /
///   `review_ref` / `escalation_target`: `None` — the row is open.
/// - `affected_action_classes` / `missing_coverage`: empty — the bridge
///   knows no action classes and `missing_coverage` is inert downstream.
/// - `state_fence`: the live attach fence.
/// - `owner_closure`: bound to the same owner/revision/identity/task/scope/
///   fence with empty source, receipts, evidence, and no resolution
///   receipt — validates for non-terminal members.
fn attention_member_from_row(
    item: &AttentionItem,
    influence: AttentionInfluence,
    source_revision: String,
    task_id: eliot_contracts::TaskId,
    scope_id: WorkScopeId,
    fence: StateFence,
) -> Result<CriticalAttentionMember, OwnerPublicationError> {
    let attention_id = ArtifactId::new(item.item_id.clone()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "ledger.item_id",
        }
    })?;
    let kind = match item.severity {
        Severity::Critical => "CRITICAL",
        Severity::Normal => "NORMAL",
    }
    .to_owned();
    let mut member = CriticalAttentionMember {
        attention_id: attention_id.clone(),
        claim_artifact_id: attention_id.clone(),
        claim_digest: String::new(),
        kind,
        source_revision: source_revision.clone(),
        source: Vec::new(),
        evidence: Vec::new(),
        task_id: task_id.clone(),
        scope_id: scope_id.clone(),
        owner_id: BRIDGE_OBSERVATION_OWNER.to_owned(),
        affected_action_classes: Vec::new(),
        delivery_stage: ledger_delivery_stage(item.delivered),
        acknowledgement: AttentionAcknowledgement::Unknown,
        influence,
        resolution: AttentionResolution::Open,
        deadline_unix_ms: None,
        review_ref: None,
        escalation_target: None,
        resolution_condition: RESOLUTION_CONDITION_OPEN.to_owned(),
        waiver_authority: None,
        superseded_by: None,
        missing_coverage: Vec::new(),
        state_fence: fence.clone(),
        owner_closure: AttentionOwnerClosure {
            owner_id: BRIDGE_OBSERVATION_OWNER.to_owned(),
            source_revision,
            attention_id,
            task_id,
            scope_id,
            state_fence: fence,
            source: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
            resolution_receipt: None,
        },
    };
    member.claim_digest = member
        .canonical_resolution_claim_digest()
        .map_err(OwnerPublicationError::Invalid)?;
    member.validate().map_err(OwnerPublicationError::Invalid)?;
    Ok(member)
}

/// Publish the live typed `CriticalAttentionProjection` from the live ledger.
///
/// Every open row of `BridgeRunner::reactive_attention` becomes one `Open`
/// member (open criticals stay sticky; pending normals ride along as
/// obligations). Rows with terminal dispositions never appear: the ledger
/// ends their stickiness at `record_disposition` time and excludes them
/// from `attention_output`. The projection digest is computed over the
/// assembled members, so repeated calls over an unchanged ledger yield the
/// same digest. Fails closed while detached or when the open set exceeds
/// the contract member bound.
pub fn publish_live_attention_projection(
    runner: &BridgeRunner,
) -> Result<CriticalAttentionProjection, OwnerPublicationError> {
    let (_, fence) = live_state_fence(runner)?;
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let task_id = view.binding().task_binding().task_id().clone();
    let scope_id =
        WorkScopeId::new(view.binding().task_binding().work_scope_id()).map_err(|_| {
            OwnerPublicationError::InvalidBinding {
                field: "attach.work_scope_id",
            }
        })?;
    let rows = runner.reactive_attention();
    if rows.len() > MAX_PUBLISHED_ROWS {
        return Err(OwnerPublicationError::CapacityExceeded {
            what: "attention members",
        });
    }
    let pending_count = rows.iter().filter(|row| !row.delivered).count();
    let delivered_count = rows.len() - pending_count;
    let mut members = Vec::with_capacity(rows.len());
    for row in &rows {
        let influence = match (&row.delivered, &row.receipt_id) {
            (true, Some(receipt_id)) => runner
                .reactive_receipt(receipt_id)
                .map(|receipt| ledger_influence(&receipt.use_status))
                .unwrap_or(AttentionInfluence::Unknown),
            _ => AttentionInfluence::Unknown,
        };
        let source_revision = runner
            .reactive_item_cue(&row.item_id)
            .map(|(cue, _)| cue.source_revision)
            .ok_or(OwnerPublicationError::InvalidBinding {
                field: "ledger.item_cue",
            })?;
        members.push(attention_member_from_row(
            row,
            influence,
            source_revision,
            task_id.clone(),
            scope_id.clone(),
            fence.clone(),
        )?);
    }
    let mut projection = CriticalAttentionProjection {
        owner_id: BRIDGE_OBSERVATION_OWNER.to_owned(),
        source_revision: SOURCE_REVISION_UNEXPOSED.to_owned(),
        snapshot_revision: format!("open-{pending_count}-receipts-{delivered_count}"),
        task_id,
        scope_id,
        state_fence: fence,
        members,
        missing_coverage: vec![ATTENTION_COVERAGE_GAP.to_owned()],
        projection_digest: String::new(),
    };
    projection.projection_digest = projection
        .canonical_digest()
        .map_err(OwnerPublicationError::Invalid)?;
    projection
        .validate()
        .map_err(OwnerPublicationError::Invalid)?;
    Ok(projection)
}

/// Runtime/host/recipient/attempt envelope for the session snapshot.
///
/// All six fields are owned outside the bridge lane (runtime owner, host
/// owner, recipient owner, attempt owner). [`resolve_runtime_envelope`]
/// resolves them when those owners thread the facts; until then the
/// session-snapshot assembly fails closed with their exact names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEnvelope {
    /// Recipient runtime identity from the runtime owner.
    pub runtime_id: String,
    /// Host identity from the host owner.
    pub host_id: String,
    /// Recipient runtime generation from the runtime owner (non-zero).
    pub runtime_generation: ResourceGeneration,
    /// Host generation from the host owner (non-zero).
    pub host_generation: ResourceGeneration,
    /// Delivery recipient identity from the recipient owner.
    pub recipient_id: String,
    /// Externally admitted execution attempt identity.
    pub attempt_id: String,
}

/// Resolve the runtime/host/recipient/attempt envelope.
///
/// Returns `Err` with the six exact missing facts today: no runtime, host,
/// recipient, or attempt owner exists in the bridge lane, and per I7.7 no
/// durable session fact is derived from a connection. The owning lanes
/// resolve this by threading the six facts; the assembly in
/// [`publish_live_session_snapshot`] then activates unchanged.
fn resolve_runtime_envelope() -> Result<RuntimeEnvelope, Vec<&'static str>> {
    Err(vec![
        "snapshot.runtime_id",
        "snapshot.host_id",
        "snapshot.runtime_generation",
        "snapshot.host_generation",
        "snapshot.recipient_id",
        "snapshot.attempt_id",
    ])
}

/// Per-record owner envelope for one delivered ledger row.
///
/// Bridge hook/response deliveries are piggybacks, never operations, so the
/// operation envelope (`operation_id`, `request_id`, `idempotency_key`) must
/// come from the owner that performed the original operation; until then
/// the session-snapshot assembly fails closed with their exact names. The
/// per-record `source_revision` already resolves from a ledger fact: the
/// caller supplies the item's cue source revision read through the
/// [`BridgeRunner::reactive_item_cue`] probe (which mirrors the
/// `item_session` probe on the ledger).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordEnvelope {
    /// Canonical operation identity from the operating owner.
    pub operation_id: OperationId,
    /// Request identity from the operating owner.
    pub request_id: RequestId,
    /// Caller idempotency key from the operating owner.
    pub idempotency_key: String,
    /// Source revision of the delivered content (ledger fact).
    pub source_revision: String,
}

/// Resolve the per-record owner envelope for one delivered row.
///
/// The `source_revision` arrives as a ledger fact (item cue via the probe);
/// the operation envelope has no live source and fails closed with its
/// three exact names. The `row`/`receipt_id` parameters name the live facts
/// the envelope binds to once the operating owner resolves them.
fn resolve_record_envelope(
    row: &AttentionItem,
    receipt_id: &str,
    source_revision: String,
) -> Result<RecordEnvelope, Vec<&'static str>> {
    let _ = (row, receipt_id, source_revision);
    Err(vec![
        "record.operation_id",
        "record.request_id",
        "record.idempotency_key",
    ])
}

/// Bridge delivery-record content contract: deterministic identity over the
/// ledger's own contract name, used for every content/source/profile
/// reference this module names. It claims exactly the provenance this
/// module has — never the reactive-context payload contract.
fn ledger_content_contract() -> Result<ContractIdentity, OwnerPublicationError> {
    contract_identity(
        REACTIVE_INJECTION_CONTRACT,
        ContractVersion::new(1, 0, 0),
        &REACTIVE_INJECTION_CONTRACT,
    )
    .map_err(|_| OwnerPublicationError::InvalidBinding {
        field: "ledger.contract",
    })
}

/// Build one historical delivery record from one delivered open row.
///
/// Field provenance: record/item identity from the ledger row; operation
/// envelope from [`resolve_record_envelope`]; content digest from the live
/// receipt's firing evidence (`cue_digest` is the canonical digest of the
/// observed content); profile digest measured over the live admission basis
/// (`sha256` over its canonical JSON, with the measured byte length
/// retained); session/task/scope/fence from the live binding and the
/// runtime envelope; `closure: None` with a pre-delivery stage
/// (`DeliveryAttempted` over `EnqueuedPersisted`), so no owner closure is
/// ever claimed; `replay_identity` from the live receipt identity, which is
/// the replay-stable key of this delivery.
fn session_record_from_row(
    row: &AttentionItem,
    receipt: &super::reactive_injection_receipts::InjectionReceipt,
    record: &RecordEnvelope,
    contract: &ContractIdentity,
    session_id: eliot_contracts::SessionId,
    runtime: &RuntimeEnvelope,
    task_id: eliot_contracts::TaskId,
    attempt_id: AgentAttemptId,
    scope_id: WorkScopeId,
    fence: StateFence,
) -> Result<PriorDeliveryBinding, OwnerPublicationError> {
    let admission_bytes = canonical_json_bytes(&receipt.admission).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "ledger.admission",
        }
    })?;
    let admission_digest = sha256_hex(&admission_bytes);
    let admission_len = u64::try_from(admission_bytes.len()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "ledger.admission",
        }
    })?;
    let item_artifact = ArtifactId::new(row.item_id.clone()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "ledger.item_id",
        }
    })?;
    Ok(PriorDeliveryBinding {
        record_id: row.item_id.clone(),
        operation_id: record.operation_id.clone(),
        request_id: record.request_id.clone(),
        idempotency_key: record.idempotency_key.clone(),
        item_id: row.item_id.clone(),
        content: ReactiveContextContentRef {
            contract: contract.clone(),
            source_revision: record.source_revision.clone(),
            content_sha256: receipt.firing.cue_digest.clone(),
            byte_length: None,
            artifact_id: Some(item_artifact),
        },
        source: ReactiveContextContentRef {
            contract: contract.clone(),
            source_revision: record.source_revision.clone(),
            content_sha256: receipt.firing.cue_digest.clone(),
            byte_length: None,
            artifact_id: None,
        },
        profile: ReactiveContextContentRef {
            contract: contract.clone(),
            source_revision: receipt.admission.governance_profile_rev.clone(),
            content_sha256: admission_digest,
            byte_length: Some(admission_len),
            artifact_id: None,
        },
        validity: ReactiveContextValidity::Current,
        lifecycle: ReactiveContextLifecycleEvidence {
            stage: ReactiveContextStage::DeliveryAttempted,
            predecessor: Some(ReactiveContextStage::EnqueuedPersisted),
            owner_receipt: None,
        },
        stage: ReactiveContextStage::DeliveryAttempted,
        acknowledgement_phase: None,
        predecessor_ids: Vec::new(),
        replay_identity: receipt.receipt_id.clone(),
        session_id,
        runtime_id: runtime.runtime_id.clone(),
        runtime_generation: runtime.runtime_generation,
        host_generation: runtime.host_generation,
        task_id,
        attempt_id,
        scope_id,
        state_fence: fence,
        closure: None,
    })
}

/// Publish the live typed `SessionDeliverySnapshot` from the live ledger.
///
/// Derivation per value (all live, no caller bytes): live attach session,
/// task, scope, fence, and principal; owner/source lineage from the bridge
/// delivery-record vocabulary ([`BRIDGE_OBSERVATION_OWNER`],
/// [`LEDGER_SOURCE_ID`], [`LEDGER_SOURCE_REVISION`]); snapshot revision
/// naming the exact open set; denominator counting the retained records
/// with `Partial` completeness (the live open set is not the complete
/// owner history — terminal and deduplicated items are honestly absent;
/// pending rows are not history and surface through the attention
/// projection and [`LiveLedgerSession`] instead); records from
/// [`session_record_from_row`] for delivered open rows; the snapshot digest
/// computed over the assembly and revalidated before return.
///
/// Fails closed with `MissingOwnerFacts` today: [`resolve_runtime_envelope`]
/// contributes the six envelope facts and [`resolve_record_envelope`]
/// contributes the three per-record operation facts on the first delivered
/// row (its `source_revision` already resolves through the item-cue probe).
/// The inventory is deterministic (envelope first, then record facts) and
/// every other derivation above already runs against live state.
pub fn publish_live_session_snapshot(
    runner: &BridgeRunner,
) -> Result<SessionDeliverySnapshot, OwnerPublicationError> {
    let (live_session_text, fence) = live_state_fence(runner)?;
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let binding = view.binding();
    let task_id = binding.task_binding().task_id().clone();
    let scope_id = WorkScopeId::new(binding.task_binding().work_scope_id()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "attach.work_scope_id",
        }
    })?;
    let session_id = binding.session_id().clone();
    debug_assert_eq!(session_id.as_str(), live_session_text);
    let principal_id = binding.principal_id().as_str().to_owned();
    let rows = runner.reactive_attention();
    if rows.len() > MAX_PUBLISHED_ROWS {
        return Err(OwnerPublicationError::CapacityExceeded {
            what: "session records",
        });
    }
    let runtime = resolve_runtime_envelope()
        .map_err(|facts| OwnerPublicationError::MissingOwnerFacts { facts })?;
    let contract = ledger_content_contract()?;
    let source_id =
        SourceId::new(LEDGER_SOURCE_ID).map_err(|_| OwnerPublicationError::InvalidBinding {
            field: "ledger.source_id",
        })?;
    let attempt_id = AgentAttemptId::new(runtime.attempt_id.clone()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "snapshot.attempt_id",
        }
    })?;
    let pending_count = rows.iter().filter(|row| !row.delivered).count();
    let mut records = Vec::new();
    for row in rows.iter().filter(|row| row.delivered) {
        let Some(receipt_id) = row.receipt_id.clone() else {
            continue;
        };
        let Some(receipt) = runner.reactive_receipt(&receipt_id) else {
            continue;
        };
        let source_revision = runner
            .reactive_item_cue(&row.item_id)
            .map(|(cue, _)| cue.source_revision)
            .ok_or(OwnerPublicationError::InvalidBinding {
                field: "ledger.item_cue",
            })?;
        let record = resolve_record_envelope(row, &receipt_id, source_revision)
            .map_err(|facts| OwnerPublicationError::MissingOwnerFacts { facts })?;
        records.push(session_record_from_row(
            row,
            &receipt,
            &record,
            &contract,
            session_id.clone(),
            &runtime,
            task_id.clone(),
            attempt_id.clone(),
            scope_id.clone(),
            fence.clone(),
        )?);
    }
    let delivered_count = records.len();
    let observed =
        u32::try_from(records.len()).map_err(|_| OwnerPublicationError::InvalidBinding {
            field: "session.records",
        })?;
    let mut snapshot = SessionDeliverySnapshot {
        owner_id: BRIDGE_OBSERVATION_OWNER.to_owned(),
        source_id,
        source_revision: LEDGER_SOURCE_REVISION.to_owned(),
        snapshot_revision: format!("open-{pending_count}-receipts-{delivered_count}"),
        session_id,
        principal_id,
        recipient_id: runtime.recipient_id.clone(),
        runtime_id: runtime.runtime_id.clone(),
        host_id: runtime.host_id.clone(),
        runtime_generation: runtime.runtime_generation,
        host_generation: runtime.host_generation,
        task_id,
        attempt_id,
        scope_id,
        state_fence: fence,
        denominator: SnapshotDenominator {
            observed,
            expected: None,
            completeness: SnapshotCompleteness::Partial,
        },
        records,
        snapshot_digest: String::new(),
    };
    snapshot.snapshot_digest = snapshot
        .canonical_digest()
        .map_err(OwnerPublicationError::Invalid)?;
    snapshot
        .validate()
        .map_err(OwnerPublicationError::Invalid)?;
    Ok(snapshot)
}

/// Bridge-owned observation of the live governor derivation posture.
///
/// Fully live: revision, completeness (mapped 1:1 except `NotApplicable`,
/// which has no snapshot mapping and fails closed), verified posture, and
/// fingerprint come straight from `GovernorCoverageDerivation::current`.
/// Freshness intent is unconditionally `ExplicitlyUnavailable` with
/// [`COVERAGE_FRESHNESS_GAP`]: the bridge retains no owner claim receipts,
/// so it can never report `Fresh` (which requires them).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoveragePosture {
    /// Derivation revision, as the contract profile revision text.
    pub profile_revision: String,
    /// Mapped snapshot completeness.
    pub completeness: SnapshotCompleteness,
    /// Whether the live derivation is verified.
    pub derivation_verified: bool,
    /// Live derivation fingerprint.
    pub derivation_fingerprint: String,
    /// Freshness gap carried into the adapted profile.
    pub freshness_gap: String,
}

/// Observe the live governor derivation posture. Fails closed when nothing
/// has been derived or when the derivation completeness has no snapshot
/// mapping.
pub fn governor_coverage_posture(
    derivation: &GovernorCoverageDerivation,
) -> Result<CoveragePosture, OwnerPublicationError> {
    let profile = derivation
        .current()
        .ok_or(OwnerPublicationError::MissingOwnerFacts {
            facts: vec!["governance-profile (no live derivation)"],
        })?;
    let completeness = match profile.completeness {
        EventCompleteness::Complete => SnapshotCompleteness::Complete,
        EventCompleteness::Partial => SnapshotCompleteness::Partial,
        EventCompleteness::Unknown => SnapshotCompleteness::Unknown,
        EventCompleteness::NotApplicable => {
            return Err(OwnerPublicationError::MissingOwnerFacts {
                facts: vec!["derivation.completeness=NotApplicable (no snapshot mapping)"],
            });
        }
    };
    Ok(CoveragePosture {
        profile_revision: profile.revision.to_string(),
        completeness,
        derivation_verified: profile.verified,
        derivation_fingerprint: profile.fingerprint.clone(),
        freshness_gap: COVERAGE_FRESHNESS_GAP.to_owned(),
    })
}

/// I7.16 discovery/owner envelope for the contract coverage profile.
///
/// The Governor derivation supplies only revision, completeness, verified
/// posture, and fingerprint ([`governor_coverage_posture`]); every field
/// here is host/runtime/interface discovery or owner-claim state from the
/// I7.16 coverage owner. [`resolve_coverage_envelope`] resolves them when
/// that owner threads the facts; until then [`adapt_contract_coverage`]
/// fails closed with their exact names. Owner-built `events` (with owner
/// receipts) ride whole — this module never synthesizes event evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct CoverageEnvelope {
    /// Host identity from the coverage owner.
    pub host_id: String,
    /// Runtime identity from the coverage owner.
    pub runtime_id: String,
    /// Interface identity from the coverage owner.
    pub interface_id: String,
    /// Recipient identity from the coverage owner.
    pub recipient_id: String,
    /// Host generation from the coverage owner (non-zero).
    pub host_generation: ResourceGeneration,
    /// Runtime generation from the coverage owner (non-zero).
    pub runtime_generation: ResourceGeneration,
    /// Recipient generation from the coverage owner (non-zero).
    pub recipient_generation: ResourceGeneration,
    /// Contract identity of the covered surface.
    pub contract: ContractIdentity,
    /// Supported delivery modes from the coverage owner.
    pub supported_modes: Vec<ReactiveDeliveryMode>,
    /// Privacy ceiling from the coverage owner.
    pub privacy_ceiling: ReactiveContextPrivacy,
    /// Effect ceiling from the coverage owner.
    pub effect_ceiling: EffectClass,
    /// Proof ceiling from the coverage owner.
    pub proof_ceiling: ProofCeiling,
    /// Owner-built lifecycle event evidence (with owner receipts).
    pub events: Vec<CoverageEvidence>,
    /// Owner-declared gaps beyond the freshness gap.
    pub owner_gaps: Vec<String>,
}

/// Resolve the I7.16 coverage envelope.
///
/// Returns `Err` with the exact missing facts today: host/runtime/
/// interface discovery and owner-claim events live with the I7.16 coverage
/// owner, never with the Governor derivation or the bridge. The owning lane
/// resolves this by threading the envelope; the assembly in
/// [`adapt_contract_coverage`] then activates unchanged. The governor
/// candidate profile type stays derivation input only — never converted,
/// never conflated with the contract type.
fn resolve_coverage_envelope() -> Result<CoverageEnvelope, Vec<&'static str>> {
    Err(vec![
        "coverage.host_id",
        "coverage.runtime_id",
        "coverage.interface_id",
        "coverage.recipient_id",
        "coverage.host_generation",
        "coverage.runtime_generation",
        "coverage.recipient_generation",
        "coverage.contract",
        "coverage.supported_modes",
        "coverage.privacy_ceiling",
        "coverage.effect_ceiling",
        "coverage.proof_ceiling",
        "coverage.events/owner-claims",
        "coverage.owner_gaps",
    ])
}

/// Adapt the live governor derivation into the planner's contract
/// `IntegrationCoverageProfile`.
///
/// Consumes [`governor_coverage_posture`] (revision → `profile_revision`,
/// mapped completeness, verified posture, fingerprint) for the scalar
/// posture, the verified governor `candidate` for its live gap evidence
/// (bound to the derivation by exact fingerprint equality), and
/// [`resolve_coverage_envelope`] for the I7.16 identity envelope; the
/// profile digest is computed over the assembly and revalidated before
/// return. Freshness is `ExplicitlyUnavailable` with the posture gap plus
/// candidate and owner gaps (never `Fresh`: no owner claim receipts are
/// retained bridge-side).
///
/// Fails closed with `MissingOwnerFacts` today (see
/// [`resolve_coverage_envelope`]; an unverified or foreign candidate also
/// fails closed with its exact cause).
pub fn adapt_contract_coverage(
    derivation: &GovernorCoverageDerivation,
    candidate: &eliot_integration_coverage::IntegrationCoverageProfile,
    fence: &StateFence,
) -> Result<IntegrationCoverageProfile, OwnerPublicationError> {
    let posture = governor_coverage_posture(derivation)?;
    if !candidate.verified {
        return Err(OwnerPublicationError::MissingOwnerFacts {
            facts: vec!["coverage.candidate-unverified"],
        });
    }
    if candidate.fingerprint != posture.derivation_fingerprint {
        return Err(OwnerPublicationError::InvalidBinding {
            field: "coverage.candidate_fingerprint",
        });
    }
    let envelope = resolve_coverage_envelope()
        .map_err(|facts| OwnerPublicationError::MissingOwnerFacts { facts })?;
    let mut gaps = vec![posture.freshness_gap.clone()];
    gaps.extend(candidate.gaps.clone());
    gaps.extend(envelope.owner_gaps.clone());
    let mut profile = IntegrationCoverageProfile {
        host_id: envelope.host_id,
        runtime_id: envelope.runtime_id,
        interface_id: envelope.interface_id,
        contract: envelope.contract,
        recipient_id: envelope.recipient_id,
        host_generation: envelope.host_generation,
        runtime_generation: envelope.runtime_generation,
        recipient_generation: envelope.recipient_generation,
        profile_revision: posture.profile_revision,
        completeness: posture.completeness,
        supported_modes: envelope.supported_modes,
        privacy_ceiling: envelope.privacy_ceiling,
        effect_ceiling: envelope.effect_ceiling,
        proof_ceiling: envelope.proof_ceiling,
        state_fence: fence.clone(),
        events: envelope.events,
        gaps,
        profile_digest: String::new(),
    };
    profile.profile_digest = profile
        .canonical_digest()
        .map_err(OwnerPublicationError::Invalid)?;
    profile.validate().map_err(OwnerPublicationError::Invalid)?;
    Ok(profile)
}

/// Bridge-owned observation of the live delivery-policy binding facts.
///
/// Fully live: the canonical plan identity comes from the live attach task
/// binding (`TaskBinding::plan_id`, sealed at activation), and the
/// observation clock is honestly empty (the bridge owns no clock).
/// Everything else in a `ReactiveDeliveryPolicy` is a policy-owner choice
/// (see [`resolve_policy_envelope`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFrame {
    /// Live canonical plan identity from the attach task binding.
    pub plan_id: ArtifactId,
    /// Honestly empty observation clock (no bridge clock exists).
    pub observed_at: ClockReading,
}

/// Observe the live delivery-policy binding frame. Fails closed while
/// detached or when the live plan identity is rejected.
pub fn live_policy_frame(runner: &BridgeRunner) -> Result<PolicyFrame, OwnerPublicationError> {
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let plan_id = ArtifactId::new(view.binding().task_binding().plan_id()).map_err(|_| {
        OwnerPublicationError::InvalidBinding {
            field: "attach.plan_id",
        }
    })?;
    Ok(PolicyFrame {
        plan_id,
        observed_at: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    })
}

/// Policy-owner envelope for the delivery policy.
///
/// The live frame ([`live_policy_frame`]) supplies plan identity and the
/// empty clock; `tie_break_revision = 1`, no deadline, and
/// `cancelled = false` are contract-fixed bridge facts. Every field here
/// is a policy-owner choice (identities, target event, delivery
/// contract/profile, bounds, reserves, priority, disclosure).
/// [`resolve_policy_envelope`] resolves them when the policy owner threads
/// the facts; until then [`adapt_delivery_policy`] fails closed with their
/// exact names.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyEnvelope {
    /// Policy identity from the policy owner.
    pub policy_id: ArtifactId,
    /// Policy revision from the policy owner (non-zero).
    pub policy_revision: u32,
    /// Request identity from the policy owner.
    pub request_id: RequestId,
    /// Operation identity from the policy owner.
    pub operation_id: OperationId,
    /// Idempotency key from the policy owner.
    pub idempotency_key: String,
    /// Target event identity from the policy owner, when pinned.
    pub target_event_id: Option<ArtifactId>,
    /// Target event name from the policy owner.
    pub target_event: String,
    /// Delivery profile reference from the policy owner.
    pub delivery_profile: ReactiveContextContentRef,
    /// Delivery contract identity from the policy owner.
    pub delivery_contract: ContractIdentity,
    /// Allowed delivery modes from the policy owner.
    pub allowed_modes: Vec<ReactiveDeliveryMode>,
    /// Input byte ceiling from the policy owner.
    pub max_input_bytes: u64,
    /// Item ceiling from the policy owner.
    pub max_items: u64,
    /// Reference ceiling from the policy owner.
    pub max_references: u64,
    /// Planning-work ceiling from the policy owner.
    pub max_work: u64,
    /// Delivery byte ceiling from the policy owner.
    pub max_delivery_bytes: u64,
    /// Delivery STU ceiling from the policy owner, when bounded.
    pub max_delivery_stu: Option<u64>,
    /// Fixed reserve from the policy owner.
    pub fixed_reserve: u64,
    /// Protocol reserve from the policy owner.
    pub protocol_reserve: u64,
    /// Output reserve from the policy owner.
    pub output_reserve: u64,
    /// Review reserve from the policy owner.
    pub review_reserve: u64,
    /// Delivery reserve from the policy owner.
    pub delivery_reserve: u64,
    /// Priority order from the policy owner.
    pub priority: Vec<SemanticRole>,
    /// Attention disclosure rules from the policy owner.
    pub attention_disclosure: Vec<AttentionDisclosureRule>,
}

/// Resolve the policy-owner envelope.
///
/// Returns `Err` with the exact missing facts today: policy identities,
/// target event, delivery contract/profile, bounds, reserves, priority,
/// and disclosure live with the policy owner, never with the bridge. The
/// owning lane resolves this by threading the envelope; the assembly in
/// [`adapt_delivery_policy`] then activates unchanged.
fn resolve_policy_envelope() -> Result<PolicyEnvelope, Vec<&'static str>> {
    Err(vec![
        "policy.policy_id",
        "policy.policy_revision",
        "policy.request_id",
        "policy.operation_id",
        "policy.idempotency_key",
        "policy.target_event_id",
        "policy.target_event",
        "policy.delivery_profile",
        "policy.delivery_contract",
        "policy.max_input_bytes",
        "policy.max_items",
        "policy.max_references",
        "policy.max_work",
        "policy.max_delivery_bytes",
        "policy.max_delivery_stu",
        "policy.fixed_reserve",
        "policy.protocol_reserve",
        "policy.output_reserve",
        "policy.review_reserve",
        "policy.delivery_reserve",
        "policy.priority",
        "policy.attention_disclosure",
    ])
}

/// Adapt the live policy frame into the owner `ReactiveDeliveryPolicy`.
///
/// Consumes [`live_policy_frame`] (plan identity, empty clock) plus the
/// contract-fixed `tie_break_revision = 1`, no deadline, and
/// `cancelled = false`; everything else comes from
/// [`resolve_policy_envelope`]. The stored `policy_digest` is computed with
/// the self-verifying `canonical_digest` and the policy is revalidated
/// before return.
///
/// Fails closed with `MissingOwnerFacts` today (see
/// [`resolve_policy_envelope`]).
pub fn adapt_delivery_policy(
    runner: &BridgeRunner,
) -> Result<ReactiveDeliveryPolicy, OwnerPublicationError> {
    let frame = live_policy_frame(runner)?;
    let envelope = resolve_policy_envelope()
        .map_err(|facts| OwnerPublicationError::MissingOwnerFacts { facts })?;
    let mut policy = ReactiveDeliveryPolicy {
        policy_id: envelope.policy_id,
        policy_revision: envelope.policy_revision,
        policy_digest: String::new(),
        request_id: envelope.request_id,
        operation_id: envelope.operation_id,
        idempotency_key: envelope.idempotency_key,
        plan_id: frame.plan_id,
        target_event_id: envelope.target_event_id,
        target_event: envelope.target_event,
        delivery_profile: envelope.delivery_profile,
        delivery_contract: envelope.delivery_contract,
        allowed_modes: envelope.allowed_modes,
        max_input_bytes: envelope.max_input_bytes,
        max_items: envelope.max_items,
        max_references: envelope.max_references,
        max_work: envelope.max_work,
        max_delivery_bytes: envelope.max_delivery_bytes,
        max_delivery_stu: envelope.max_delivery_stu,
        fixed_reserve: envelope.fixed_reserve,
        protocol_reserve: envelope.protocol_reserve,
        output_reserve: envelope.output_reserve,
        review_reserve: envelope.review_reserve,
        delivery_reserve: envelope.delivery_reserve,
        priority: envelope.priority,
        attention_disclosure: envelope.attention_disclosure,
        tie_break_revision: 1,
        observed_at: frame.observed_at,
        deadline_ms: None,
        cancelled: false,
    };
    policy.policy_digest = policy
        .canonical_digest()
        .map_err(OwnerPublicationError::Invalid)?;
    policy.validate().map_err(OwnerPublicationError::Invalid)?;
    Ok(policy)
}

/// Assemble the deterministic six-slot publication.
///
/// D1-served `view` / `cue_activation` arrive by borrow through the
/// plan-crate port shape (`feed`); the four D2 values arrive owned from the
/// publishers/adapters above. Before delegating to the plan-crate binder
/// (fixed slot order `[view, cue, session, attention, coverage, policy]`,
/// canonical digest), the assembly checks liveness against the live attach:
/// the session snapshot's session/fence, the attention and coverage fences
/// (plus attention task/scope), and the policy plan identity must equal the
/// live binding — mirroring `drive_live_feed`'s stale-activation gate
/// (`crates/smart/eliot-reactive-context-plan/src/settled_plan_feed.rs`).
/// Stale or foreign projections fail closed here; the planner, which only
/// checks the projections against each other, can never observe them.
#[allow(clippy::too_many_arguments)]
pub fn assemble_live_six_slot(
    runner: &BridgeRunner,
    feed: SettledPlanFeedInputs<'_>,
    session_snapshot: &SessionDeliverySnapshot,
    critical_attention: &CriticalAttentionProjection,
    integration_coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Result<OwnerBoundPublication, OwnerPublicationError> {
    let (live_session, live_fence) = live_state_fence(runner)?;
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let binding = view.binding();
    if session_snapshot.session_id.as_str() != live_session
        || session_snapshot.state_fence != live_fence
    {
        return Err(OwnerPublicationError::InvalidBinding {
            field: "session.live_session",
        });
    }
    if critical_attention.task_id != *binding.task_binding().task_id()
        || critical_attention.scope_id.as_str() != binding.task_binding().work_scope_id()
        || critical_attention.state_fence != live_fence
    {
        return Err(OwnerPublicationError::InvalidBinding {
            field: "attention.live_binding",
        });
    }
    if integration_coverage.state_fence != live_fence {
        return Err(OwnerPublicationError::InvalidBinding {
            field: "coverage.live_fence",
        });
    }
    if policy.plan_id.as_str() != binding.task_binding().plan_id() {
        return Err(OwnerPublicationError::InvalidBinding {
            field: "policy.live_plan",
        });
    }
    bind_owner_publication(eliot_reactive_context_plan::OwnerBoundSixSlot {
        view: feed.view,
        cue_activation: feed.cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    })
    .map_err(OwnerPublicationError::Bind)
}

/// Serve one production six-slot publication from live owner state.
///
/// One causal call through the four D2 resolvers into
/// [`assemble_live_six_slot`]: the live session snapshot, the live
/// attention projection, the adapted contract coverage (over the live
/// governor `derivation` plus its verified `candidate`), and the adapted
/// delivery policy — joined with D1-served view/cue from the plan-crate
/// port shape (`feed`). First missing owner inventory fails the whole
/// call in resolver order (session → attention → coverage → policy →
/// assembly); nothing partial is ever published. Deterministic: repeated
/// calls over unchanged live state yield the same publication digest.
pub fn serve_live_six_slot(
    runner: &BridgeRunner,
    feed: SettledPlanFeedInputs<'_>,
    derivation: &GovernorCoverageDerivation,
    candidate: &eliot_integration_coverage::IntegrationCoverageProfile,
) -> Result<OwnerBoundPublication, OwnerPublicationError> {
    let (_, fence) = live_state_fence(runner)?;
    let session_snapshot = publish_live_session_snapshot(runner)?;
    let critical_attention = publish_live_attention_projection(runner)?;
    let integration_coverage = adapt_contract_coverage(derivation, candidate, &fence)?;
    let policy = adapt_delivery_policy(runner)?;
    assemble_live_six_slot(
        runner,
        feed,
        &session_snapshot,
        &critical_attention,
        &integration_coverage,
        &policy,
    )
}
