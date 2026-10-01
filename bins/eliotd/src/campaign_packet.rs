//! Authenticated campaign-packet dispatch for the production daemon.
//!
//! The packet arguments select an optional refresh target and bounded
//! material handles only. The task, scope and fence are derived from the
//! Kernel-admitted envelope and rechecked against the retained Kernel
//! snapshot before any named owner read is made.
//!
//! The packet's product is one immutable campaign learning-state view, and
//! the current owner pipeline decides whether it may be used:
//! `eliot_learning_state_view::validate_campaign_learning_state_view_current`
//! owns the view's own load-bearing revision and State Fence checks against a
//! fresh authenticated owner-read set, and each current owner cell then
//! independently joins that view to the compilation it acts on —
//! `eliot_context_candidates::check_campaign_learning_state_view` against this
//! compilation's request identity,
//! `eliot_context_admission::check_campaign_view_for_admission` against the
//! binding the admission decision would be made under and the owner-issued
//! Decision Safety Floor for that boundary, and
//! `eliot_context_assembly::check_campaign_view_for_assembly` against the
//! admitted set it is about to render. Every one of them re-derives the
//! State-Fence, task/scope identity and load-bearing Context recipe owner
//! revision joins itself, and every one of them compares the recipe revision
//! against `context_recipe_body_digest`, which the Context owner re-derived
//! from the exact recipe body its own publication validator accepted. No cell
//! inherits another's verdict. The `#40`-frozen
//! `eliot_context::ContextCompiler` is deliberately not called here: the
//! frozen donor surface takes no new caller, and no legacy-only helper may
//! accept a view the current owner cells refused.
//!
//! #1724 W5: this route now also reaches the ADMISSION decision's recipe
//! binding, and its terminal outcome is a typed gap/blocked outcome carrying the
//! attempted recipe reference rather than a successful View. The admission cell
//! resolves the approved reusable `ContextRecipePolicy` revision through
//! `eliot_context_admission::bind_admission_policy_revision` — the contract
//! owner's own `ContextRecipePolicy::binds_recipe`, against approved owner
//! content rather than the instance's own recorded claim — and the response
//! delivers that approved revision, the bound instance digest and the re-derived
//! owner body digest as `attempted_context_recipe`. The admission DECISION
//! itself is still not made here, because `PriorityPolicyIdentity`,
//! `AdmissionRuleIdentity`, `MeasurementCompositionProfile` and the candidate
//! denominator have no production construction site; the response therefore
//! reports `CampaignPacketGapCode::AdmissionClosureUnbound` with outcome
//! `Blocked` and publishes the view only as the diagnostic material account
//! this route already publishes for every other refusal. There is no
//! `COMPILED` outcome: see [`CampaignPacketOutcome`].

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context::campaign_publication::{
    ContextCampaignRecipeBody, context_delivery_body_digest, context_recipe_body_digest,
    context_safety_floor_identity,
};
use eliot_context_admission::{bind_admission_policy_revision, check_campaign_view_for_admission};
use eliot_context_candidates::{CandidateRequest, check_campaign_learning_state_view};
use eliot_context_contracts::{
    ContextError, ContextRecipe, ProjectedCitation, RecipePolicyIdentity, SessionDeliverySnapshot,
};
use eliot_contracts::{
    ArtifactId, RequestId, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignOwnerRecordId, CampaignOwnerRevision, CampaignPositionKind,
    CampaignPositionRef, CampaignSourceBinding, CampaignSourceRequirement,
    CampaignSourceResolution, CampaignSourceResolutionStatus, CampaignSourceRevisionRef,
    CampaignSourceRole, CampaignViewRebuildReason, Completeness, LearningStateViewRecipe, MemberId,
    OwnerDisagreement, OwnerId, SlotDisposition, SlotId, TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_learning_state_view::{
    CampaignHistoryPlanInput, CampaignLearningStateCompilationInput,
    compile_campaign_learning_state_view, validate_campaign_learning_state_view_current,
};
use eliot_protocol::{
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestResultBody, HostRequestResultLineage,
    LocalReadAttempt, host_request_operation_id,
};
use eliot_reactive_context_plan::RetrievalPlan;
use eliot_store_api::{
    CampaignHistoryPlanRecord, CampaignLearningStateViewLookup,
    CampaignLearningStateViewPublication, CampaignLearningStateViewRead,
    CampaignLearningStateViewReadStatus, CampaignOwnerReadReceipt, CampaignSourceHead,
    CampaignSourceReadStatus, CampaignSourceRecord, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::DaemonKernelClient;

/// Maximum distinct material selectors admitted by one campaign packet.
pub const MAX_CAMPAIGN_PACKET_MATERIALS: usize = 256;

/// Whether a claimed tool pair selects the campaign packet compiler.
#[must_use]
pub fn is_campaign_packet_tool(tool: &Value) -> bool {
    tool.as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        == Some("eliot.packet")
}

/// Closed selector set from the public `eliot.packet` contract. These values
/// never supply owner, revision, digest or currentness authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPacketSelectors {
    /// Optional packet refresh selector.
    pub packet_ref: Option<String>,
    /// Bounded material handles requested by the caller.
    pub material_refs: Vec<String>,
}

/// Exact task/scope binding authenticated by the admitted invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPacketBinding {
    /// Task identity supplied as a selector and validated by Kernel admission.
    pub task_id: String,
    /// Work scope supplied as a selector and validated by Kernel admission.
    pub work_scope_id: String,
    /// Exact fence carried by the admitted request and retained Kernel client.
    pub state_fence: StateFence,
}

/// Closed packet-pair validation failures. Error text never reflects caller
/// payload bytes or owner material.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignPacketError {
    /// The envelope/tool pair is not a valid `eliot.packet` invocation.
    #[error("campaign packet invocation is malformed or not admitted as eliot.packet")]
    InvalidInvocation,
    /// The request is not bound to a task and work scope.
    #[error("campaign packet requires an admitted task and work scope")]
    MissingTaskBinding,
    /// The task-bound request has no exact task revision in its fence.
    #[error("campaign packet requires an exact task revision in its State Fence")]
    MissingTaskRevision,
    /// The request fence does not equal the retained Kernel fence.
    #[error("campaign packet State Fence differs from the retained Kernel fence")]
    FenceMismatch,
    /// The packet argument object is not in its closed selector shape.
    #[error("campaign packet selectors are malformed or exceed their bound")]
    InvalidSelectors,
    /// The packet's previous immutable view could not be resolved exactly.
    #[error("campaign packet reference does not identify a retained view for this task and scope")]
    PriorViewUnavailable,
    /// A named campaign owner read failed closed or returned an invalid body.
    #[error("campaign owner read failed closed")]
    OwnerReadUnavailable,
    /// A current task recipe is missing, stale, or not bound to the admitted task.
    #[error("campaign TaskPlan recipe does not match the admitted task and fence")]
    InvalidTaskPlan,
    /// The Context owner recipe is invalid or does not bind to the admitted
    /// task, scope and fence.
    #[error("campaign Context recipe does not match the admitted task, scope and fence")]
    UnboundContextRecipe,
    /// The current candidate cell refused the immutable campaign view for this
    /// attempt: a State Fence, task/scope/request identity or load-bearing
    /// Context recipe owner-revision join failed, or the view is invalidated,
    /// stale, blocked or missing its Context recipe row.
    #[error("campaign learning-state view is not current for this attempt")]
    CampaignViewNotCurrent,
}

struct ResolvedCampaignSources {
    resolutions: Vec<CampaignSourceResolution>,
    current_records: Vec<CampaignSourceRecord>,
    authenticated_reads: Vec<AuthenticatedCampaignSourceRead>,
}

#[derive(Clone)]
struct AuthenticatedCampaignSourceRead {
    record: CampaignSourceRecord,
    current_head: CampaignSourceHead,
    read_receipt: CampaignOwnerReadReceipt,
}

/// Terminal disposition of one `eliot.packet` attempt.
///
/// The packet's product is the immutable campaign learning-state view. There
/// is no second, legacy-compiled product on this route: the frozen
/// `eliot_context::ContextCompiler` takes no new caller, so nothing may claim
/// a compiled result that the current owner pipeline did not accept.
///
/// #1724 W5 removed the `COMPILED` outcome rather than leaving it unproducible.
/// I12.13 makes the packet a compiled product only when the admission decision
/// ran and its `ContextEconomyReceipt` and `ActiveUnderstandingView` bound the
/// exact recipe revision, and #1724 step 5 requires an incomplete compilation to
/// return its typed gap/blocked outcome with the attempted recipe reference
/// instead of a successful View. This route cannot assemble the admission
/// closure — see
/// [`CampaignPacketGapCode::AdmissionClosureUnbound`] — so a `COMPILED` value
/// here could only ever mean "a view with no economy evidence", which is the
/// outcome the item forbids. It is deleted rather than kept as an unreachable
/// wire value, so the response cannot read as compiled at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CampaignPacketOutcome {
    /// The view exists but is explicitly marked stale against the current
    /// owner revisions; it is published for diagnosis and never used.
    Stale,
    /// No usable view could be produced, the current owner refused it, or the
    /// admission decision it would need could not be made. The response carries
    /// the typed gap and the attempted recipe reference, and the view it does
    /// publish is a diagnostic account rather than a compiled product.
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CampaignPacketGapCode {
    TaskPlanUnavailable,
    PriorViewUnavailable,
    OwnerReadUnavailable,
    HistoryPlanUnavailable,
    RequiredSourceUnavailable,
    ContextRecipeUnavailable,
    ContextDeliveryUnavailable,
    /// The composition bound no complete admission closure, so this delivery
    /// carries no per-material `FusedRankTrace` and no rank-trace handle.
    ///
    /// The traced join this packet's material would be accounted by is
    /// `eliot_context_admission::admit_context_traced`, reached from the
    /// composition through
    /// `KernelContextReadClient::compile_context_packet`. That composition
    /// closes its owner-minted pieces through the one validating builder
    /// `PacketAdmissionBundle::build`, and the per-identity account of what this
    /// tree can and cannot supply today is:
    ///
    /// - `SafetyFloorIdentity` — SUPPLIED. The Context owner record already
    ///   carries the floor: `GoverningContextRequirements::floor` holds the
    ///   `DecisionSafetyFloor` itself and the resolved policy revision names the
    ///   same record in `RecipeAdmissionPolicy::safety_floor`. This route
    ///   resolves it through the owner's own publication,
    ///   `eliot_context::campaign_publication::context_safety_floor_identity`,
    ///   and hands it to the admission cell's own join
    ///   (`eliot_context_admission::check_campaign_view_for_admission`), which
    ///   checks the floor's binding, its decision identity and its coverage of
    ///   the recipe's mandatory roles.
    /// - `PriorityPolicyIdentity` — ABSENT. It needs one `CandidatePriority` per
    ///   candidate atom, with a class and an ordinal. No owner record in this
    ///   tree declares a per-candidate priority class, and no candidate atom
    ///   exists on this route: `construct_context_candidates` is unreachable
    ///   because the seven role projections have no production owner here, so the
    ///   atom identities the policy must be keyed by do not exist yet. An ordinal
    ///   is available from the owner-declared order in
    ///   `RecipeLayoutPolicy::role_positions`, but that is a per-ROLE position,
    ///   and a per-atom ordinal taken from the caller's own list order is the
    ///   caller-list fabrication the contract forbids. I12.13's
    ///   `SemanticSensitivityProfile` is the object that would own the class and
    ///   the evidence-based order; it is named in that document and has no
    ///   representation here.
    /// - `AdmissionRuleIdentity` — ABSENT as a whole. The resolved revision
    ///   names the rule as an owner reference
    ///   (`RecipeAdmissionPolicy::admission_rule`) and the recipe carries the
    ///   decision revision, but the rule's own record — and therefore the
    ///   `rule_sha256` digest the identity must carry — is deliberately not a
    ///   copy in the recipe body. The missing owner is the admission-rule record
    ///   I12.13's `admission_and_suppression_policy` names as "owner
    ///   references, not copies"; no such record is read or published here.
    /// - `MeasurementCompositionProfile` — ABSENT. It needs a serializer
    ///   identity and version, a serializer-options digest, a route id and a
    ///   model id. I2.16 places those on `SerializedContextMeasurement`, whose
    ///   own inputs are caller-owned `MeasurementParams`; no route in this tree
    ///   issues that record, and the Context owner body carries none of these
    ///   fields.
    /// - `AdmissionMeasurement` (per candidate atom/representation) — ABSENT.
    ///   `AdmissionInput::validate` forces these to equal the candidate atom set
    ///   exactly, and each names the candidate's own subject and measurement
    ///   digests, so no record can exist before the candidate stage produces
    ///   that set. None of the seven role projections has a production owner on
    ///   this route, so the set they would be keyed by does not exist.
    /// - `AssemblyPolicy` — ABSENT, for the same missing serializer/route/model
    ///   identity as the measurement profile, plus a route byte ceiling no owner
    ///   publishes for this packet.
    /// - the twelve-dimension `QualityScorecard`, the seven-role
    ///   `SevenRoleInputs`, the `CandidatePolicy` and the measurement callback —
    ///   ABSENT for the same reason: each needs owner evidence (per-dimension
    ///   rule revision and observed evidence, role acquisitions, a route
    ///   serializer identity) that has no producer on this route.
    ///
    /// The composition's own shape is no longer part of the obstacle:
    /// `KernelContextReadClient::compile_context_packet` now takes the
    /// atom-keyed admission pieces and the quality card as owner suppliers
    /// invoked after the candidate and admission stages that produce what they
    /// are keyed by, so it is callable in principle rather than uncallable by
    /// construction. What remains absent is the owner supply above, which no
    /// amount of reshaping can substitute for.
    ///
    /// The candidate stage is reached today only as far as
    /// `eliot_context_candidates::check_campaign_learning_state_view`, which
    /// owns the campaign view's State Fence, identity and load-bearing Context
    /// recipe revision joins; `construct_context_candidates` itself is still
    /// unreachable because the seven role projections have no production
    /// owner. The admission cell reaches its own join from this route through
    /// `eliot_context_admission::check_campaign_view_for_admission`, which
    /// re-derives the join from the binding admission decides under rather than
    /// inheriting the candidate cell's verdict, and its approved-revision binding
    /// through
    /// `eliot_context_admission::bind_admission_policy_revision`, which resolves
    /// the approved `ContextRecipePolicy` content and runs the contract owner's
    /// `ContextRecipePolicy::binds_recipe` against this attempt's instance. The
    /// assembly cell's join is
    /// reached from `KernelContextReadClient::compile_context_packet`, which is
    /// the only place an actual `AdmittedContextSet` exists to join against;
    /// this route produces none because `admit_context` has no callable
    /// argument set. Both full decisions stay unreachable for that same reason.
    ///
    /// Minting any of the absent pieces here from a constant, a CLI flag, an env
    /// var, or a caller-supplied string would fabricate the exact selection
    /// record I12.26 requires this packet to carry, so the composition reports
    /// the refusal instead. Reporting it is what keeps the withheld rank trace
    /// from being read as support: the absence of a handle is a named, delivered
    /// gap, not a silent omission and not a claim that nothing was withheld.
    ///
    /// #1724 W5: since this gap is the reason no `ContextEconomyReceipt` and no
    /// `ActiveUnderstandingView` exists for the attempt, it is also the reason
    /// the response is `Blocked` and carries `attempted_context_recipe` rather
    /// than a compiled View. It is the terminal condition of this route's
    /// context chain, not a note attached to a delivered packet.
    AdmissionClosureUnbound,
    /// The current learning-state owner refused the view for this attempt:
    /// stale, missing, invalidated, or partial across a load-bearing slot,
    /// owner revision, State Fence, or `RetrievalPlan` history.
    CampaignViewNotCurrent,
    /// A current owner cell below the candidate stage refused the campaign view
    /// for this compilation.
    ///
    /// The view passed both
    /// `eliot_learning_state_view::validate_campaign_learning_state_view_current`
    /// and the candidate cell's
    /// `eliot_context_candidates::check_campaign_learning_state_view`, but
    /// `eliot_context_admission::check_campaign_view_for_admission` compared it
    /// against the binding the admission decision would be made under, together
    /// with the owner-issued Decision Safety Floor for that boundary, and
    /// refused it. The two cells are independent comparisons against different
    /// bindings — and the admission cell's adds the I7.11 floor coverage check —
    /// so passing the candidate cell is never evidence for admission.
    OwnerCellRefusedCampaignView,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignPacketGap {
    code: CampaignPacketGapCode,
    role: Option<CampaignSourceRole>,
}

/// One material this delivery placed, and what the current owner says about it.
///
/// Every field is owner-recorded: the slot and member identities and their
/// dispositions are the ones the learning-state owner compiled into this
/// immutable view, and the evidence handles are that owner's own. Nothing here
/// is re-decided, re-ranked, or inferred from the absence of a rank trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeliveredMaterialTrace {
    /// Declared recipe slot this material was projected into.
    slot_id: SlotId,
    /// Declared member identity within that slot.
    member_id: MemberId,
    /// Owner that issued the projection.
    owner: OwnerId,
    /// The owner's explicit disposition for this member.
    disposition: SlotDisposition,
    /// Packet location: this member's position in the delivered view.
    packet_location: u32,
    /// Owner-issued evidence handles supporting this disposition.
    evidence: Vec<ArtifactId>,
}

/// The I12.26 delivery account for one published packet.
///
/// This is the visible/suppressed count pair and the per-material disposition
/// set I12.26 requires a delivered packet to expose, derived by counting the
/// owner-compiled view itself. `rank_trace_handle` is the full
/// `FusedRankTrace` handle field the contract asks for; it is `None` here
/// because the daemon closes over no COMPLETE owner-minted admission closure —
/// it now holds the owner-issued Decision Safety Floor, but not the priority
/// policy, admission rule, measurement profile, per-atom measurements, quality
/// card or assembly policy the traced join also needs — and
/// [`CampaignPacketGapCode::AdmissionClosureUnbound`] is delivered alongside it
/// to say so. The handle slot is present and typed precisely so an unbound
/// handle can never be read as "nothing was withheld".
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContextDeliveryMaterialAccount {
    /// The owner-recorded view digest this account was derived from.
    view_digest: String,
    /// Members the current owner placed in the delivered view.
    visible: u32,
    /// Members the current owner withheld, each with its own disposition above.
    suppressed: u32,
    /// One explicit disposition per delivered member.
    materials: Vec<DeliveredMaterialTrace>,
    /// The full rank-trace handle, or `None` when no closure could be bound.
    rank_trace_handle: Option<String>,
}

/// The exact Context recipe one packet attempt was made under.
///
/// #1724 W5. The approved reusable policy revision is resolved by the admission
/// cell from the approved owner content and is NOT read off the packet's own
/// compilation-bound instance: `policy` is what
/// `ContextRecipePolicy::binds_recipe` compared the instance against, so it is a
/// content resolution a consumer can re-derive from the owner catalogue rather
/// than a value this route asserts about itself. `instance_digest` is the bound
/// instance that revision was compared with, kept separate because I12.13 keeps
/// the approved reusable policy revision and the compilation-bound instance
/// apart, and `owner_body_digest` is the exact authenticated owner body the
/// Context owner re-derived — the same value the candidate and admission joins
/// compared this attempt against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AttemptedContextRecipeBinding {
    /// The approved reusable policy revision, resolved from owner content.
    policy: RecipePolicyIdentity,
    /// Digest of the compilation-bound instance that revision is bound to.
    instance_digest: String,
    /// The Context owner's re-derived digest of the exact owner body.
    owner_body_digest: String,
}

/// Counts the delivered and suppressed material of one published view.
///
/// The visible/suppressed split is the owner's own disposition, not a budget
/// decision made here: a member the current owner marked `Current` is visible,
/// and every other disposition is a member that was withheld for a stated
/// reason. The per-member counts are derived from this view's own slot
/// vector, so the reported location is where the material actually sits in the
/// delivered packet.
///
/// A view that cannot be counted at all refuses rather than reporting a
/// partial account: an unattributable count would be indistinguishable from a
/// complete one.
///
/// The refusal is returned as the same [`String`] every enclosing packet
/// function already returns, so the whole route reports one error shape. It
/// carries the failure as [`CampaignPacketError::OwnerReadUnavailable`]'s own
/// text, which names the typed failure instead of flattening it.
fn account_delivered_materials(
    view: &CampaignLearningStateView,
) -> Result<ContextDeliveryMaterialAccount, String> {
    let mut materials = Vec::new();
    let mut suppressed = 0_u32;
    for slot in &view.slots {
        for member in &slot.members {
            if member.disposition != SlotDisposition::Current {
                suppressed = suppressed
                    .checked_add(1)
                    .ok_or(CampaignPacketError::OwnerReadUnavailable.to_string())?;
            }
            materials.push(DeliveredMaterialTrace {
                slot_id: slot.slot_id.clone(),
                member_id: member.member_id.clone(),
                owner: member.owner.clone(),
                disposition: member.disposition,
                packet_location: 0,
                evidence: member.evidence.clone(),
            });
        }
    }
    // Packet location is this material's position in the delivered view as a
    // whole, so a consumer resolves a handle to one place in one packet rather
    // than to a per-slot index it would have to re-derive.
    for (position, material) in materials.iter_mut().enumerate() {
        material.packet_location = u32::try_from(position)
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    }
    let visible = u32::try_from(materials.len())
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?
        .checked_sub(suppressed)
        .ok_or(CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(ContextDeliveryMaterialAccount {
        view_digest: view.canonical_digest.clone(),
        visible,
        suppressed,
        materials,
        // The owner-minted admission closure this handle would be derived from
        // has no production construction site, so no handle is asserted.
        rank_trace_handle: None,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignPacketResponse {
    outcome: CampaignPacketOutcome,
    completeness: Completeness,
    #[serde(rename = "campaign_learning_state_view")]
    view: Option<CampaignLearningStateViewPublication>,
    /// Per-material delivery account for the published view, or `None` when no
    /// view was published at all.
    material_account: Option<ContextDeliveryMaterialAccount>,
    /// The governed source-readback citation this packet's Task Plan was cited
    /// through, or `None` when this response publishes no cited support.
    ///
    /// I12.26 requires citation and support to rest on governed source readback,
    /// and the readback gate verifies that citation but does not by itself place
    /// it in front of a consumer. This field is that placement: it carries the
    /// verified `ProjectedCitation` unchanged, so a consumer reads the EXACT
    /// `source_revision` and `anchor` handles the excerpt was read back
    /// through, together with the excerpt digest that binds the excerpt to the
    /// anchor. The handles are copied from the gate's own verified value; they
    /// are never re-derived, re-labelled or synthesised here.
    ///
    /// It is `None` on every outcome that publishes no cited support, including
    /// a gate refusal. That is the fail-closed half of the pair: the refusal
    /// itself is reported through `gaps` with
    /// [`CampaignPacketGapCode::RequiredSourceUnavailable`], and a consumer
    /// never sees a citation for a revision the gate did not verify.
    cited_support: Option<ProjectedCitation>,
    /// The exact Context recipe this attempt was made under, or `None` when the
    /// attempt never reached the admission decision's recipe binding.
    ///
    /// #1724 W5 / I12.13. A refused or incomplete compilation must carry the
    /// recipe it ATTEMPTED rather than publishing a view whose recipe identity
    /// is unreadable, and that attempted reference has to be an independently
    /// resolved approved revision — not the instance's own recorded claim. This
    /// field is that reference, and it is present only where the admission cell
    /// itself resolved the approved policy content and bound this attempt's
    /// instance to it through
    /// `eliot_context_admission::bind_admission_policy_revision` (the contract
    /// owner's `ContextRecipePolicy::binds_recipe`). It is `None` on every
    /// response that refused before that binding, so a consumer can never read
    /// an absent reference as "no recipe was attempted".
    attempted_context_recipe: Option<AttemptedContextRecipeBinding>,
    gaps: Vec<CampaignPacketGap>,
    missing_roles: Vec<CampaignSourceRole>,
    stale_roles: Vec<CampaignSourceRole>,
    blocked_roles: Vec<CampaignSourceRole>,
    prior_view_reused: bool,
    prior_view_rejected_stale: bool,
}

struct ValidatedHistoryPlans {
    plans: Vec<RetrievalPlan>,
    records: Vec<CampaignHistoryPlanRecord>,
}

impl ValidatedHistoryPlans {
    fn compiler_inputs(&self) -> Vec<CampaignHistoryPlanInput<'_>> {
        self.plans
            .iter()
            .zip(&self.records)
            .map(|(plan, record)| CampaignHistoryPlanInput {
                plan,
                selected_handles: record.selected_handles.clone(),
                summary_digest: record.summary_digest.clone(),
                diff_digests: record.diff_digests.clone(),
                policy_slice_handles: record.policy_slice_handles.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PacketArguments {
    #[serde(default)]
    packet_ref: Option<String>,
    #[serde(default)]
    material_refs: Vec<String>,
}

/// Revalidates the admitted packet pair and extracts only its caller selectors
/// plus the authenticated task/scope/fence binding. It performs no owner read.
pub fn validate_campaign_packet_pair(
    envelope: &HostRequestEnvelope,
    tool: &Value,
    retained_kernel_fence: &StateFence,
) -> Result<(CampaignPacketBinding, CampaignPacketSelectors), CampaignPacketError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| CampaignPacketError::InvalidInvocation)?;
    if envelope.identity.capability != "eliot.packet" || !is_campaign_packet_tool(tool) {
        return Err(CampaignPacketError::InvalidInvocation);
    }
    if envelope.state_fence != *retained_kernel_fence {
        return Err(CampaignPacketError::FenceMismatch);
    }
    if envelope.state_fence.task_revision.is_none() {
        return Err(CampaignPacketError::MissingTaskRevision);
    }
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(CampaignPacketError::MissingTaskBinding)?;
    let work_scope_id = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(CampaignPacketError::MissingTaskBinding)?;
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .ok_or(CampaignPacketError::InvalidSelectors)?;
    let arguments: PacketArguments =
        serde_json::from_value(arguments).map_err(|_| CampaignPacketError::InvalidSelectors)?;
    if arguments
        .packet_ref
        .as_deref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        || arguments.material_refs.len() > MAX_CAMPAIGN_PACKET_MATERIALS
    {
        return Err(CampaignPacketError::InvalidSelectors);
    }
    let mut unique_materials = BTreeSet::new();
    for material in &arguments.material_refs {
        if material.trim().is_empty()
            || material.chars().any(char::is_control)
            || !unique_materials.insert(material.as_str())
        {
            return Err(CampaignPacketError::InvalidSelectors);
        }
    }
    Ok((
        CampaignPacketBinding {
            task_id: task_id.to_owned(),
            work_scope_id: work_scope_id.to_owned(),
            state_fence: envelope.state_fence.clone(),
        },
        CampaignPacketSelectors {
            packet_ref: arguments.packet_ref,
            material_refs: arguments.material_refs,
        },
    ))
}

/// Binds the admitted packet to the current compiler's request identity.
///
/// Validation by construction for the #2564 packet-compile edge
/// (`KernelContextReadClient::compile_context_packet`): the owner recipe is
/// re-validated and its task/scope/fence binding is compared against the
/// Kernel-admitted binding field by field, so a substituted recipe fails
/// closed here instead of supporting a compiled packet. The request identity
/// is the deterministic Kernel operation handle and the idempotency key is
/// the Kernel-minted boot-unique attempt identity — never a caller selector.
///
/// #1862: the immutable campaign view is then joined to that request by the
/// current candidate cell itself,
/// `eliot_context_candidates::check_campaign_learning_state_view`. That cell
/// owns the State Fence, task/scope/request identity and load-bearing Context
/// recipe owner-revision joins; it compares the view's recorded binding
/// against this request and the view's recorded Context recipe content digest
/// against `context_recipe_body_digest`, which the Context owner re-derived
/// from the exact body its own publication validator accepted. A stale,
/// missing, blocked or invalidated view is refused here through a current
/// owner and takes the typed `CampaignViewNotCurrent` gap; the learning-state
/// owner has already refused a load-bearing-partial view before this point, and
/// no legacy compiler DTO decides any of it.
///
/// The returned request is the proof artifact the compile edge will consume
/// once its remaining owner suppliers land (STITCH-2564-PACKET-SUPPLY: seven
/// roles, candidate policy, priority policy, admission rule record,
/// measurement profile, per-atom measurements, quality card, assembly policy,
/// measurement). Today its success signal gates the product path: the value
/// proves the owner recipe binds the admitted packet and that the candidate
/// cell accepted the campaign view, and a failure takes the typed gap named by
/// the failing join. The request is not yet handed to
/// `construct_context_candidates` because the seven role projections have no
/// production owner; that composition is reported as
/// `AdmissionClosureUnbound` rather than faked. The compile edge itself is no
/// longer the obstacle: `compile_context_packet` now takes the atom-keyed
/// admission pieces and the quality card as suppliers invoked after the stages
/// that produce what they are keyed by.
fn candidate_request_for_packet(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    recipe: &ContextRecipe,
    binding: &CampaignPacketBinding,
    view: &CampaignLearningStateView,
    context_recipe_body_digest: &str,
) -> Result<CandidateRequest, CampaignPacketError> {
    recipe
        .validate()
        .map_err(|_| CampaignPacketError::UnboundContextRecipe)?;
    if recipe.binding.task_id.as_str() != binding.task_id
        || recipe.binding.scope_id.as_str() != binding.work_scope_id
        || recipe.binding.state_fence != binding.state_fence
    {
        return Err(CampaignPacketError::UnboundContextRecipe);
    }
    let request = CandidateRequest {
        binding: recipe.binding.clone(),
        request_id: RequestId::new(host_request_operation_id(envelope))
            .map_err(|_| CampaignPacketError::InvalidInvocation)?,
        idempotency_key: attempt.attempt_id.clone(),
    };
    request
        .validate()
        .map_err(|_| CampaignPacketError::InvalidInvocation)?;
    check_campaign_learning_state_view(&request, recipe, view, context_recipe_body_digest)
        .map_err(|error| match error {
            ContextError::MissingField(
                "campaign_view.context_recipe" | "campaign_view.context_reference",
            )
            | ContextError::InvalidField("campaign_view.completeness")
            | ContextError::InvalidDigest("campaign_view.context_recipe")
            | ContextError::InvalidFence
            | ContextError::IdentityConflict => CampaignPacketError::CampaignViewNotCurrent,
            _ => CampaignPacketError::UnboundContextRecipe,
        })?;
    Ok(request)
}

/// Resolves one admitted packet into an immutable view and compiles its
/// decision-local context. The implementation uses only authenticated Kernel
/// named reads; caller selectors are not resolved as authority.
pub async fn serve_campaign_packet_pair(
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let retained_kernel_fence = kernel.kernel_fence();
    let (binding, selectors) =
        validate_campaign_packet_pair(envelope, tool, &retained_kernel_fence)
            .map_err(|error| error.to_string())?;
    attempt
        .validate()
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.scope_id != binding.work_scope_id
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    resolve_compile_and_bind_result(kernel, envelope, attempt, binding, selectors).await
}

#[allow(
    clippy::manual_let_else,
    clippy::too_many_lines,
    reason = "the production packet keeps read admission, source binding, and view publication in one branch"
)]
async fn resolve_compile_and_bind_result(
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    binding: CampaignPacketBinding,
    selectors: CampaignPacketSelectors,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let (recipe, task_plan_resolution, task_plan_record, task_plan_receipt) =
        match read_task_plan_recipe(kernel, &binding).await {
            Ok(read) => read,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::TaskPlanUnavailable,
                            role: Some(CampaignSourceRole::TaskPlan),
                        }],
                        missing_roles: vec![CampaignSourceRole::TaskPlan],
                        stale_roles: Vec::new(),
                        blocked_roles: Vec::new(),
                        prior_view_reused: false,
                        prior_view_rejected_stale: false,
                    },
                );
            }
        };
    let prior = if let Some(packet_ref) = selectors.packet_ref.as_deref() {
        match read_prior_campaign_view(kernel, &binding, packet_ref).await {
            Ok(prior) => Some(prior),
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::PriorViewUnavailable,
                            role: None,
                        }],
                        missing_roles: Vec::new(),
                        stale_roles: Vec::new(),
                        blocked_roles: Vec::new(),
                        prior_view_reused: false,
                        prior_view_rejected_stale: false,
                    },
                );
            }
        }
    } else {
        None
    };
    let resolved = match resolve_manifest_sources(
        kernel,
        &binding,
        &recipe,
        task_plan_resolution,
        task_plan_record.clone(),
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                CampaignPacketResponse {
                    outcome: CampaignPacketOutcome::Blocked,
                    completeness: Completeness::Blocked,
                    view: None,
                    material_account: None,
                    cited_support: None,
                    attempted_context_recipe: None,
                    gaps: vec![CampaignPacketGap {
                        code: CampaignPacketGapCode::OwnerReadUnavailable,
                        role: None,
                    }],
                    missing_roles: Vec::new(),
                    stale_roles: Vec::new(),
                    blocked_roles: Vec::new(),
                    prior_view_reused: false,
                    prior_view_rejected_stale: false,
                },
            );
        }
    };
    let history_plan_set =
        match build_history_plan_set(&recipe, &resolved.current_records, &binding.state_fence) {
            Ok(history) => history,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::HistoryPlanUnavailable,
                            role: None,
                        }],
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: false,
                    },
                );
            }
        };
    let current_history_plans = history_plan_set.compiler_inputs();
    let observed_at_ms = current_unix_ms()?;
    if u64::try_from(observed_at_ms).unwrap_or(u64::MAX) >= attempt.expires_at_unix_ms {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    let prior_covers_materials = prior.as_ref().is_some_and(|publication| {
        selectors.material_refs.iter().all(|selector| {
            ArtifactId::new(selector.clone())
                .is_ok_and(|handle| publication.view.required_references.contains(&handle))
        })
    });
    let prior_is_current = prior_covers_materials
        && prior.as_ref().is_some_and(|publication| {
            validate_campaign_learning_state_view_current(
                &publication.view,
                &recipe,
                &binding.state_fence,
                &resolved.resolutions,
                &current_history_plans,
                observed_at_ms,
            )
            .is_ok()
        });

    let view = if prior_is_current {
        prior
            .as_ref()
            .map(|publication| publication.view.clone())
            .ok_or_else(|| CampaignPacketError::PriorViewUnavailable.to_string())?
    } else {
        let projections = match collect_slot_projections(&recipe, &resolved) {
            Ok(projections) => projections,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: source_gaps(&resolved.resolutions),
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let required_references = match collect_required_references(
            &resolved.current_records,
            &selectors.material_refs,
        ) {
            Ok(references) => references,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::RequiredSourceUnavailable,
                            role: None,
                        }],
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let disagreements = collect_disagreements(&resolved.current_records);
        let positions = collect_positions(&resolved);
        let frozen_anchor_digest = resolved
            .resolutions
            .iter()
            .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
            .and_then(|resolution| resolution.reference.as_ref())
            .map(|reference| reference.content_digest.as_str())
            .or_else(|| {
                recipe
                    .source_requirements
                    .iter()
                    .find(|requirement| requirement.role == CampaignSourceRole::FrozenAnchor)
                    .and_then(|requirement| requirement.expected_reference.as_ref())
                    .map(|reference| reference.content_digest.as_str())
            })
            .map(str::to_owned);
        let Some(frozen_anchor_digest) = frozen_anchor_digest else {
            return campaign_packet_result_body(
                envelope,
                attempt,
                CampaignPacketResponse {
                    outcome: CampaignPacketOutcome::Blocked,
                    completeness: Completeness::Blocked,
                    view: None,
                    material_account: None,
                    cited_support: None,
                    attempted_context_recipe: None,
                    gaps: vec![CampaignPacketGap {
                        code: CampaignPacketGapCode::RequiredSourceUnavailable,
                        role: Some(CampaignSourceRole::FrozenAnchor),
                    }],
                    missing_roles: missing_roles(&resolved.resolutions),
                    stale_roles: stale_roles(&resolved.resolutions),
                    blocked_roles: blocked_roles(&resolved.resolutions),
                    prior_view_reused: false,
                    prior_view_rejected_stale: prior.is_some(),
                },
            );
        };
        let rebuild_reason = prior.as_ref().map(|publication| {
            if publication.view.binding.state_fence != binding.state_fence {
                CampaignViewRebuildReason::StateFenceChanged
            } else if publication
                .view
                .provenance
                .expires_at_ms
                .is_some_and(|expires_at| observed_at_ms >= expires_at)
            {
                CampaignViewRebuildReason::Expired
            } else if source_resolutions_differ(
                &publication.view.provenance.source_resolutions,
                &resolved.resolutions,
            ) {
                if policy_source_revision_changed(
                    &publication.view.provenance.source_resolutions,
                    &resolved.resolutions,
                ) {
                    CampaignViewRebuildReason::PolicyChanged
                } else {
                    CampaignViewRebuildReason::OwnerRevisionChanged
                }
            } else {
                CampaignViewRebuildReason::ExplicitRefresh
            }
        });
        match compile_campaign_learning_state_view(CampaignLearningStateCompilationInput {
            recipe: &recipe,
            projections: &projections,
            current_state_fence: &binding.state_fence,
            source_resolutions: &resolved.resolutions,
            required_references: &required_references,
            disagreements: &disagreements,
            positions: &positions,
            frozen_anchor_digest: &frozen_anchor_digest,
            history_plans: &current_history_plans,
            generated_at_ms: observed_at_ms,
            expires_at_ms: None,
            rebuild_reason,
        }) {
            Ok(view) => view,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: source_gaps(&resolved.resolutions),
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        }
    };

    let is_nonusable = matches!(
        view.completeness,
        Completeness::Stale | Completeness::Blocked
    );
    if is_nonusable {
        let publication = match make_view_publication(&binding, view) {
            Ok(publication) => publication,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        material_account: None,
                        cited_support: None,
                        attempted_context_recipe: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::RequiredSourceUnavailable,
                            role: None,
                        }],
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let completeness = publication.view.completeness;
        // A stale or blocked view is still published for diagnosis, so its
        // per-material disposition is still counted and delivered: a consumer
        // must be able to see which material this refusal withheld. A view that
        // cannot be counted fails this whole response closed rather than
        // publishing a view with an unattributable material account.
        let material_account = account_delivered_materials(&publication.view)?;
        return campaign_packet_result_body(
            envelope,
            attempt,
            CampaignPacketResponse {
                outcome: if completeness == Completeness::Stale {
                    CampaignPacketOutcome::Stale
                } else {
                    CampaignPacketOutcome::Blocked
                },
                completeness,
                view: Some(publication),
                material_account: Some(material_account),
                cited_support: None,
                attempted_context_recipe: None,
                gaps: source_gaps(&resolved.resolutions),
                missing_roles: missing_roles(&resolved.resolutions),
                stale_roles: stale_roles(&resolved.resolutions),
                blocked_roles: blocked_roles(&resolved.resolutions),
                prior_view_reused: false,
                prior_view_rejected_stale: prior.is_some() && !prior_is_current,
            },
        );
    }

    // A stale prior view is never reused. The new immutable projection is
    // published only after the current owner pipeline re-verified it against
    // the fresh owner-read set and the packet State Fence.
    let publication = make_view_publication(&binding, view)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;

    // The current owner pipeline, not a legacy-only helper, decides whether
    // this immutable view may be used at all, and it decides first. The
    // learning-state owner re-verifies the exact load-bearing owner revisions,
    // the packet State Fence and the `RetrievalPlan`-bounded history against
    // the fresh authenticated owner-read set, and refuses a stale, missing,
    // invalidated or load-bearing-partial view. This runs for a reused exact
    // prior view and for a freshly compiled one, so no path reaches an
    // accepted result through a check the legacy compiler used to own, and no
    // Context owner row is consumed for a view the owner refused.
    if validate_campaign_learning_state_view_current(
        &publication.view,
        &recipe,
        &binding.state_fence,
        &resolved.resolutions,
        &current_history_plans,
        observed_at_ms,
    )
    .is_err()
    {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::CampaignViewNotCurrent,
                None,
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    let context_owner_reads = match context_owner_source_reads(&recipe, &resolved) {
        Ok(reads) => reads,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    let context_recipe_record = context_owner_reads.recipe.record;
    let context_delivery_record = context_owner_reads.delivery.map(|read| read.record);
    let context_recipe_body: ContextCampaignRecipeBody =
        match serde_json::from_value(context_recipe_record.document.body.clone()) {
            Ok(body) => body,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    context_blocked_response(
                        publication,
                        CampaignPacketGapCode::ContextRecipeUnavailable,
                        Some(CampaignSourceRole::ContextRecipe),
                        &resolved.resolutions,
                        prior.is_some() && !prior_is_current,
                    ),
                );
            }
        };
    let context_delivery_snapshot: Option<SessionDeliverySnapshot> = match context_delivery_record {
        Some(record) => match serde_json::from_value(record.document.body.clone()) {
            Ok(snapshot) => Some(snapshot),
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    context_blocked_response(
                        publication,
                        CampaignPacketGapCode::ContextDeliveryUnavailable,
                        Some(CampaignSourceRole::ContextDelivery),
                        &resolved.resolutions,
                        prior.is_some() && !prior_is_current,
                    ),
                );
            }
        },
        None => None,
    };
    let context_source_schema_invalid = context_recipe_record.document.schema
        != eliot_store_api::CampaignSourceDocumentSchema::ContextRecipe
        || context_delivery_record.is_some_and(|record| {
            record.document.schema != eliot_store_api::CampaignSourceDocumentSchema::ContextDelivery
        });
    let context_recipe_digest = match context_recipe_body_digest(&context_recipe_body) {
        Ok(digest) => digest,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    let context_body_digests_match = canonical_body_digest(&context_recipe_record.document.body)
        .ok()
        .is_some_and(|stored| stored == context_recipe_digest)
        && match (context_delivery_snapshot.as_ref(), context_delivery_record) {
            (Some(snapshot), Some(record)) => context_delivery_body_digest(snapshot)
                .ok()
                .zip(canonical_body_digest(&record.document.body).ok())
                .is_some_and(|(typed, stored)| typed == stored),
            (None, None) => true,
            _ => false,
        };
    if context_source_schema_invalid || !context_body_digests_match {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::ContextRecipeUnavailable,
                Some(CampaignSourceRole::ContextRecipe),
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }

    // Re-run the Context owner's own publication validators at the
    // consumption edge. The exact typed recipe/delivery bodies this attempt
    // decoded from the fresh named owner reads are re-derived by their owner
    // and re-bound to the packet State Fence here; neither a transcript nor a
    // detached Context row can satisfy this step. Delivery is checked only
    // when this recipe requires a current ContextDelivery row; it is separate
    // from `prior`, which refers to the prior campaign learning view.
    if crate::campaign_context_owner::validate_context_owner_bodies(
        &context_recipe_body,
        context_delivery_snapshot.as_ref(),
        &context_owner_reads,
        &binding.state_fence,
    )
    .is_err()
    {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::ContextRecipeUnavailable,
                Some(CampaignSourceRole::ContextRecipe),
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    // Issue #2564 I2: bind the admitted packet to the current compiler's
    // request identity before the product path continues. The owner recipe
    // must bind the admitted task, scope and fence exactly; a substituted
    // recipe fails closed through the same context-recipe gap above rather
    // than supporting a compiled packet. The candidate cell then owns the
    // campaign-view join itself and a refusal there takes the typed
    // `CampaignViewNotCurrent` gap, never a compiled packet.
    if let Err(refusal) = candidate_request_for_packet(
        envelope,
        attempt,
        &context_recipe_body.recipe,
        &binding,
        &publication.view,
        &context_recipe_digest,
    ) {
        let (gap, role) = match refusal {
            CampaignPacketError::CampaignViewNotCurrent => {
                (CampaignPacketGapCode::CampaignViewNotCurrent, None)
            }
            _ => (
                CampaignPacketGapCode::ContextRecipeUnavailable,
                Some(CampaignSourceRole::ContextRecipe),
            ),
        };
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                gap,
                role,
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    // #1862: the ADMISSION cell now reaches its own campaign-view join on this
    // route, and it does not inherit the candidate cell's verdict.
    //
    // Admission re-derives the same class of join from the binding it owns: the
    // exact `ContextBinding` the admission decision would be made under, which
    // is the Context owner's own recipe binding. That value is the one
    // `AdmissionInput::validate` forces equal to the admission input's own
    // binding, its recipe binding and its floor binding, so it is the
    // admission cell's fact and not a value forwarded from the candidate stage.
    // The load-bearing Context recipe revision is compared against
    // `context_recipe_digest`, which the Context owner re-derived from the exact
    // recipe body its own publication validator accepted.
    //
    // The protected floor this decision is made under is resolved here, from the
    // same authenticated Context owner row, through the Context owner's own
    // publication (`eliot_context::campaign_publication::context_safety_floor_identity`).
    // That resolver reads the floor record out of the catalogue's
    // `GoverningContextRequirements` and the resolved revision's own
    // `RecipeAdmissionPolicy::safety_floor` reference, and refuses unless the two
    // agree and the floor is bound to this recipe. Nothing on this route mints
    // it, and a body carrying no usable floor is refused as a Context gap rather
    // than admitted with an empty one.
    let admission_floor = match context_safety_floor_identity(&context_recipe_body) {
        Ok(floor) => floor,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    //
    // The full `admit_context` decision stays unreachable on this route: the
    // remaining owner-minted admission-closure pieces have zero production
    // construction sites (`AdmissionClosureUnbound` above, which now names the
    // floor as the one piece this route does hold). The join is the load-bearing
    // revision, State Fence and Decision Safety Floor check the audit names; the
    // decision it would feed is separately absent and is reported as absent
    // rather than fabricated. #1724 W5 adds the one admission-side fact the
    // decision cannot exist without and that CAN be resolved from owner content
    // today — the approved reusable policy revision — immediately below, and
    // the response now refuses to present this route's product as compiled.
    //
    // #1862: the admission owner's typed refusal crosses this boundary intact.
    // It used to be discarded by `.is_err()`, which flattened five distinct
    // admission-cell refusals — a moved State Fence, a cross-compilation task or
    // scope, a `STALE`/`BLOCKED`/invalidated view, a missing or non-current
    // Context recipe row, and a recipe content-digest mismatch — into one
    // undifferentiated "the admission cell said no". The wire gap code below
    // stays the coarse classification a consumer branches on; the owner's exact
    // typed variant goes to the log, which is what makes the five
    // distinguishable again without changing the response shape.
    if let Err(refusal) = check_campaign_view_for_admission(
        &context_recipe_body.recipe.binding,
        &publication.view,
        &context_recipe_digest,
        &admission_floor,
        &context_recipe_body.recipe,
    ) {
        tracing::warn!(
            reason = %refusal,
            "current admission cell refused the campaign learning-state view"
        );
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::OwnerCellRefusedCampaignView,
                None,
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    // #1724 W5: the ADMISSION DECISION this packet's economy evidence must come
    // from, reached as far as the owner records this tree actually holds.
    //
    // The admission cell names the approved reusable policy revision an
    // admission runs under, and the only fact that can carry it independently of
    // the compilation-bound instance is the approved revision's own content
    // digest. `AdmissionInput` carries the instance and not the approved policy
    // (see `crates/smart/eliot-context-admission/src/lib.rs`), so the approved
    // CONTENT is what this route brings, and the binding itself is made by the
    // admission cell rather than here.
    //
    // It is re-resolved at this consumption edge from the same authenticated
    // Context owner row every other check on this route reads, so the admission
    // cell compares the instance against owner content and not against a value
    // another cell handed over. `ApprovedRecipeCatalogue::resolve` selects
    // exactly one applicable, current, unrevoked revision or refuses with the
    // contract owner's own typed `RecipeResolutionRefusal`; there is no
    // first-match and no newest-revision fallback.
    let approved_policy = match context_recipe_body.catalogue.resolve() {
        Ok(resolved_policy) => resolved_policy,
        Err(refusal) => {
            tracing::warn!(
                reason = %refusal,
                "no approved Context policy revision resolved for this packet attempt"
            );
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    //
    // `bind_admission_policy_revision` is the contract owner's
    // `ContextRecipePolicy::binds_recipe` under the admission cell's name: the
    // approved revision re-derives its own content digest, and the instance's
    // recorded `DecisionRevision::policy_sha256` is compared with it. An
    // instance issued under a stale, revoked, unpointed or substituted revision
    // is refused HERE, before anything this route publishes can be read as
    // bound to the currently approved recipe — and a recipe may not make itself
    // applicable by dropping a mandatory role, admitting an unconfigured role,
    // or declaring a mandatory role suppressible.
    let attempted_policy = match bind_admission_policy_revision(
        &approved_policy.policy,
        &context_recipe_body.recipe,
    ) {
        Ok(policy) => policy,
        Err(refusal) => {
            tracing::warn!(
                reason = %refusal,
                "admission cell refused the approved Context policy binding for this packet attempt"
            );
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    // Issue #1948: the Task Plan is the load-bearing source this packet is
    // compiled from, so before it may support a compiled packet its exact
    // admitted owner document is reopened through the governed source owner and
    // run through the citation gate. A refusal here is a typed narrower outcome
    // (`unsupported` / `replan` / `gap`): the packet is blocked, and the
    // retrieved bytes are never emitted as cited support. This is a
    // read/projection constraint and authorizes no durable mutation.
    //
    // On success the gate's own verified `ProjectedCitation` — carrying the exact
    // source-revision and anchor handles the excerpt was read back through — is
    // captured here and published as `cited_support` on the response below, so a
    // consumer resolves the cited support to the verified handles rather than to
    // whatever bytes a current path happens to hold.
    let mut cited_support = None;
    if let Err(refusal) = gate_task_plan_citation(
        &task_plan_record,
        &task_plan_receipt,
        &binding,
        |citation| cited_support = Some(citation.clone()),
    ) {
        tracing::warn!(
            kind = ?refusal.kind,
            reason = %refusal.reason,
            "governed source readback refused the campaign packet citation"
        );
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::RequiredSourceUnavailable,
                Some(CampaignSourceRole::TaskPlan),
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    // Issue #1949 (I12.26): this packet is the delivery a consumer resolves
    // per-material handles against, so it states its own material account here.
    // The account is counted from the published owner view, and the admission
    // closure that would carry a full `FusedRankTrace` handle is reported as
    // unbound beside it rather than left silently absent.
    let material_account = account_delivered_materials(&publication.view)?;
    let mut gaps = source_gaps(&resolved.resolutions);
    gaps.push(CampaignPacketGap {
        code: CampaignPacketGapCode::AdmissionClosureUnbound,
        role: None,
    });
    //
    // #1724 W5: this is the typed blocked outcome, and it is the whole reason
    // the previous revision of this route was wrong.
    //
    // The approved policy revision bound above is real, independently resolved
    // evidence: `attempted_context_recipe` names it, together with the exact
    // instance it was compared with and the owner body the Context owner
    // re-derived. What is still absent is the admission DECISION and, with it,
    // the `ContextEconomyReceipt` and the `ActiveUnderstandingView` I12.13
    // requires that receipt to bind. `PriorityPolicyIdentity`,
    // `AdmissionRuleIdentity` and `MeasurementCompositionProfile` have no
    // production construction site anywhere in the tree, and the candidate
    // denominator and per-atom measurements have no producer on this route
    // either, so no `AdmissionInput` can be assembled here and `admit_context`
    // stays uncallable. Minting any of them from a constant, a flag or this
    // route's own reading would fabricate the selection record, which
    // `CampaignPacketGapCode::AdmissionClosureUnbound` already states.
    //
    // I12.13 and #1724 step 5 require the typed gap/blocked outcome WITH the
    // attempted recipe reference for an incomplete compilation, never a
    // successful View. So this response is `Blocked`. It keeps the view, for the
    // same reason every other refusal on this route does: a consumer must be
    // able to see which material the attempt withheld, and the counted account
    // above is that account — but it is a diagnostic publication, not a
    // compiled product, and nothing here may be read as recipe-bound Context
    // economy evidence. The `AdmissionClosureUnbound` gap alone was disclosure
    // beside a `Compiled` outcome, not delivery, which is the outcome the
    // cross-check refused.
    campaign_packet_result_body(
        envelope,
        attempt,
        CampaignPacketResponse {
            outcome: CampaignPacketOutcome::Blocked,
            completeness: publication.view.completeness,
            view: Some(publication),
            material_account: Some(material_account),
            // The gate invoked its consumer exactly once on the way here and
            // verified it, and the admission-closure refusal is not a refusal of
            // the cited source revision, so the verified citation is delivered:
            // dropping it here would report the Task Plan as refused when the
            // gate accepted it.
            cited_support,
            attempted_context_recipe: Some(AttemptedContextRecipeBinding {
                policy: attempted_policy,
                instance_digest: context_recipe_body.recipe.recipe_sha256.clone(),
                owner_body_digest: context_recipe_digest,
            }),
            gaps,
            missing_roles: missing_roles(&resolved.resolutions),
            stale_roles: stale_roles(&resolved.resolutions),
            blocked_roles: blocked_roles(&resolved.resolutions),
            prior_view_reused: prior_is_current,
            prior_view_rejected_stale: prior.is_some() && !prior_is_current,
        },
    )
}

async fn resolve_manifest_sources(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    recipe: &LearningStateViewRecipe,
    task_plan_resolution: CampaignSourceResolution,
    task_plan_record: CampaignSourceRecord,
) -> Result<ResolvedCampaignSources, String> {
    let mut resolutions = Vec::with_capacity(recipe.source_requirements.len());
    let mut current_records = Vec::new();
    let mut authenticated_reads = Vec::new();
    for requirement in &recipe.source_requirements {
        match requirement.source_binding {
            CampaignSourceBinding::AuthenticatedTaskAnchor => {
                if requirement.role != CampaignSourceRole::TaskPlan
                    || requirement.expected_reference.is_some()
                {
                    return Err(CampaignPacketError::InvalidTaskPlan.to_string());
                }
                resolutions.push(task_plan_resolution.clone());
                current_records.push(task_plan_record.clone());
            }
            CampaignSourceBinding::ExplicitlyAbsent => {
                if requirement.expected_reference.is_some() {
                    return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
                }
                resolutions.push(CampaignSourceResolution {
                    role: requirement.role,
                    status: CampaignSourceResolutionStatus::Missing,
                    reference: None,
                    read_state_fence: binding.state_fence.clone(),
                });
            }
            CampaignSourceBinding::ExactReference => {
                let (resolution, source_read) =
                    match resolve_exact_source_requirement(kernel, binding, requirement).await {
                        Ok(result) => result,
                        Err(_) => (
                            CampaignSourceResolution {
                                role: requirement.role,
                                status: CampaignSourceResolutionStatus::Blocked,
                                reference: None,
                                read_state_fence: binding.state_fence.clone(),
                            },
                            None,
                        ),
                    };
                resolutions.push(resolution);
                if let Some(source_read) = source_read {
                    current_records.push(source_read.record.clone());
                    authenticated_reads.push(source_read);
                }
            }
        }
    }
    current_records.sort_by_key(|record| record.role);
    Ok(ResolvedCampaignSources {
        resolutions,
        current_records,
        authenticated_reads,
    })
}

async fn resolve_exact_source_requirement(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    requirement: &CampaignSourceRequirement,
) -> Result<
    (
        CampaignSourceResolution,
        Option<AuthenticatedCampaignSourceRead>,
    ),
    String,
> {
    let expected = requirement
        .expected_reference
        .as_ref()
        .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    if expected.role != requirement.role || expected.owner != requirement.owner {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let lookup = CampaignSourceRevisionLookup {
        role: requirement.role,
        owner_id: requirement.owner.clone(),
        record_id: expected.record_id.clone(),
        expected_revision: Some(expected.revision.clone()),
        expected_content_digest: Some(expected.content_digest.clone()),
    };
    let read = read_campaign_source(kernel, binding, lookup).await?;
    let mut current_source = None;
    let reference = match read.status {
        CampaignSourceReadStatus::Current => {
            let source = read
                .source
                .as_ref()
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            let reference = source_reference_from_record(source);
            if &reference != expected {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            let current_head = read
                .current_head
                .as_ref()
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            let read_receipt = read
                .read_receipt
                .as_ref()
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            current_source = Some(AuthenticatedCampaignSourceRead {
                record: source.clone(),
                current_head: current_head.clone(),
                read_receipt: read_receipt.clone(),
            });
            Some(reference)
        }
        CampaignSourceReadStatus::Stale => {
            read.current_head.as_ref().map(source_reference_from_head)
        }
        CampaignSourceReadStatus::Blocked | CampaignSourceReadStatus::Missing => None,
    };
    let status = match read.status {
        CampaignSourceReadStatus::Current => CampaignSourceResolutionStatus::Current,
        CampaignSourceReadStatus::Stale => CampaignSourceResolutionStatus::Stale,
        CampaignSourceReadStatus::Blocked => CampaignSourceResolutionStatus::Blocked,
        CampaignSourceReadStatus::Missing => CampaignSourceResolutionStatus::Missing,
    };
    Ok((
        CampaignSourceResolution {
            role: requirement.role,
            status,
            reference,
            read_state_fence: read.read_state_fence,
        },
        current_source,
    ))
}

fn context_owner_read_for_role<'a>(
    recipe: &LearningStateViewRecipe,
    resolved: &'a ResolvedCampaignSources,
    role: CampaignSourceRole,
    required: bool,
) -> Result<Option<crate::campaign_context_owner::ContextOwnerSourceRead<'a>>, String> {
    let requirements = recipe
        .source_requirements
        .iter()
        .filter(|requirement| requirement.role == role)
        .collect::<Vec<_>>();
    if requirements.len() > 1 || (required && requirements.len() != 1) {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let reads = resolved
        .authenticated_reads
        .iter()
        .filter(|read| read.record.role == role)
        .collect::<Vec<_>>();
    let records = resolved
        .current_records
        .iter()
        .filter(|record| record.role == role)
        .collect::<Vec<_>>();
    let resolutions = resolved
        .resolutions
        .iter()
        .filter(|resolution| resolution.role == role)
        .collect::<Vec<_>>();
    let Some(requirement) = requirements.first() else {
        if required || !reads.is_empty() || !records.is_empty() || !resolutions.is_empty() {
            return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
        }
        return Ok(None);
    };
    match requirement.source_binding {
        CampaignSourceBinding::ExactReference => {
            let expected = requirement
                .expected_reference
                .as_ref()
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            if expected.role != role
                || expected.owner != requirement.owner
                || reads.len() != 1
                || records.len() != 1
                || resolutions.len() != 1
            {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            let read = reads[0];
            let record_reference = source_reference_from_record(&read.record);
            let head_reference = source_reference_from_head(&read.current_head);
            if record_reference != *expected
                || head_reference != *expected
                || records[0] != &read.record
                || resolutions[0].status != CampaignSourceResolutionStatus::Current
                || resolutions[0].reference.as_ref() != Some(expected)
                || resolutions[0].read_state_fence != recipe.binding.state_fence
                || read.read_receipt.validate().is_err()
                || !read.read_receipt.binds_record(&read.record)
                || read.read_receipt.read_state_fence != recipe.binding.state_fence
            {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            Ok(Some(
                crate::campaign_context_owner::ContextOwnerSourceRead {
                    record: &read.record,
                    current_head: &read.current_head,
                    read_receipt: &read.read_receipt,
                },
            ))
        }
        CampaignSourceBinding::ExplicitlyAbsent => {
            if requirement.expected_reference.is_some()
                || !reads.is_empty()
                || !records.is_empty()
                || resolutions.len() != 1
                || resolutions[0].status != CampaignSourceResolutionStatus::Missing
                || resolutions[0].reference.is_some()
                || resolutions[0].read_state_fence != recipe.binding.state_fence
            {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            Ok(None)
        }
        CampaignSourceBinding::AuthenticatedTaskAnchor => {
            Err(CampaignPacketError::OwnerReadUnavailable.to_string())
        }
    }
}

fn context_owner_source_reads<'a>(
    recipe: &LearningStateViewRecipe,
    resolved: &'a ResolvedCampaignSources,
) -> Result<crate::campaign_context_owner::ContextOwnerSourceReads<'a>, String> {
    let recipe_read =
        context_owner_read_for_role(recipe, resolved, CampaignSourceRole::ContextRecipe, true)?
            .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let tool_policy = context_owner_read_for_role(
        recipe,
        resolved,
        CampaignSourceRole::ContextToolPolicy,
        false,
    )?;
    let delivery =
        context_owner_read_for_role(recipe, resolved, CampaignSourceRole::ContextDelivery, false)?;
    Ok(crate::campaign_context_owner::ContextOwnerSourceReads {
        recipe: recipe_read,
        tool_policy,
        delivery,
    })
}

fn source_resolutions_differ(
    previous: &[CampaignSourceResolution],
    current: &[CampaignSourceResolution],
) -> bool {
    let mut previous = previous.to_vec();
    let mut current = current.to_vec();
    previous.sort_by_key(|resolution| resolution.role);
    current.sort_by_key(|resolution| resolution.role);
    previous != current
}

fn policy_source_revision_changed(
    previous: &[CampaignSourceResolution],
    current: &[CampaignSourceResolution],
) -> bool {
    let policy_roles = [
        CampaignSourceRole::GovernorPolicy,
        CampaignSourceRole::ContextToolPolicy,
        CampaignSourceRole::ActiveOverlay,
    ];
    policy_roles.iter().any(|role| {
        let before = previous.iter().find(|resolution| resolution.role == *role);
        let after = current.iter().find(|resolution| resolution.role == *role);
        before != after
    })
}

fn collect_slot_projections(
    recipe: &LearningStateViewRecipe,
    resolved: &ResolvedCampaignSources,
) -> Result<Vec<eliot_learning_contracts::SlotProjection>, String> {
    let mut projections = BTreeMap::new();
    for source in &resolved.current_records {
        let source_ref = source_reference_from_record(source);
        if !resolved.resolutions.iter().any(|resolution| {
            resolution.role == source.role
                && resolution.status == CampaignSourceResolutionStatus::Current
                && resolution.reference.as_ref() == Some(&source_ref)
        }) {
            return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
        }
        for projection in &source.slot_projections {
            let spec = recipe
                .slots
                .iter()
                .find(|slot| slot.slot_id == projection.slot_id)
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            if spec.source_role != source.role || spec.owner != source.owner_id {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            let observed = projection
                .canonical_digest()
                .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            if !source
                .slot_projection_digests
                .iter()
                .any(|digest| digest.slot_id == projection.slot_id && digest.digest == observed)
                || projections
                    .insert(projection.slot_id.as_str().to_owned(), projection.clone())
                    .is_some()
            {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
        }
    }
    Ok(recipe
        .slots
        .iter()
        .filter_map(|slot| projections.remove(slot.slot_id.as_str()))
        .collect())
}

fn collect_required_references(
    current_records: &[CampaignSourceRecord],
    material_refs: &[String],
) -> Result<Vec<ArtifactId>, String> {
    let mut all_owner_handles = BTreeSet::new();
    let mut required = BTreeSet::new();
    for source in current_records {
        required.extend(source.required_references.iter().cloned());
        all_owner_handles.extend(source.required_references.iter().cloned());
        for projection in &source.slot_projections {
            all_owner_handles.extend(projection.evidence.iter().cloned());
            for member in &projection.members {
                all_owner_handles.extend(member.evidence.iter().cloned());
            }
        }
        for history in &source.history_plans {
            all_owner_handles.extend(history.selected_handles.iter().cloned());
            all_owner_handles.extend(history.policy_slice_handles.iter().cloned());
        }
    }
    for selector in material_refs {
        let handle = ArtifactId::new(selector.clone())
            .map_err(|_| CampaignPacketError::InvalidSelectors.to_string())?;
        if !all_owner_handles.contains(&handle) {
            return Err(CampaignPacketError::InvalidSelectors.to_string());
        }
        required.insert(handle);
    }
    Ok(required.into_iter().collect())
}

fn collect_disagreements(current_records: &[CampaignSourceRecord]) -> Vec<OwnerDisagreement> {
    current_records
        .iter()
        .flat_map(|source| source.disagreements.iter().cloned())
        .collect()
}

fn collect_positions(resolved: &ResolvedCampaignSources) -> Vec<CampaignPositionRef> {
    let mut positions = Vec::new();
    for (role, kind) in [
        (
            CampaignSourceRole::CurrentPosition,
            CampaignPositionKind::Current,
        ),
        (
            CampaignSourceRole::ExperiencePosition,
            CampaignPositionKind::Experience,
        ),
        (
            CampaignSourceRole::AdaptationPosition,
            CampaignPositionKind::Adaptation,
        ),
        (
            CampaignSourceRole::EvaluationPosition,
            CampaignPositionKind::Evaluation,
        ),
        (
            CampaignSourceRole::EconomicsProgress,
            CampaignPositionKind::EconomicsProgress,
        ),
    ] {
        if let Some(source) = resolved
            .current_records
            .iter()
            .find(|source| source.role == role)
        {
            positions.push(CampaignPositionRef {
                kind,
                source_role: role,
                record_id: source.record_id.clone(),
                revision: source.revision.clone(),
                source_content_digest: source.content_digest.clone(),
                position_digest: source.content_digest.clone(),
            });
        }
    }
    positions
}

fn build_history_plan_set(
    recipe: &LearningStateViewRecipe,
    current_records: &[CampaignSourceRecord],
    state_fence: &StateFence,
) -> Result<ValidatedHistoryPlans, String> {
    let mut records = Vec::new();
    for source in current_records {
        for record in &source.history_plans {
            record
                .validate_for_source_at_fence(
                    recipe.campaign_id.as_str(),
                    &source.owner_id,
                    state_fence,
                )
                .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            records.push(record.clone());
        }
    }
    if records.is_empty() {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let mut plans = Vec::with_capacity(records.len());
    for record in &records {
        let plan: RetrievalPlan = serde_json::from_value(record.plan.clone())
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        plan.validate()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        let digest = plan
            .canonical_digest()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        if digest != record.plan_digest {
            return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
        }
        plans.push(plan);
    }
    Ok(ValidatedHistoryPlans { plans, records })
}

fn canonical_body_digest(body: &Value) -> Result<String, String> {
    let bytes = canonical_json_bytes(body)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn current_unix_ms() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let millis = i64::try_from(duration.as_millis())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    if millis <= 0 {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    Ok(millis)
}

fn source_reference_from_record(source: &CampaignSourceRecord) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: source.role,
        owner: source.owner_id.clone(),
        record_id: source.record_id.clone(),
        revision: source.revision.clone(),
        content_digest: source.content_digest.clone(),
        slot_projection_digests: source.slot_projection_digests.clone(),
        recorded_state_fence: source.recorded_state_fence.clone(),
    }
}

fn source_reference_from_head(head: &CampaignSourceHead) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: head.role,
        owner: head.owner_id.clone(),
        record_id: head.record_id.clone(),
        revision: head.revision.clone(),
        content_digest: head.content_digest.clone(),
        slot_projection_digests: head.slot_projection_digests.clone(),
        recorded_state_fence: head.recorded_state_fence.clone(),
    }
}

/// Reads the authenticated Task Controller row that IS the task plan, together
/// with the Kernel-authenticated owner-read receipt that binds that exact row.
///
/// The receipt is returned (not dropped) because the governed source readback
/// gate (#1948) must reopen these owner bytes through that same proof: a
/// `CampaignSourceRevisionRead::validate` `Current` read always carries a
/// receipt, so its presence here is guaranteed by the store contract, not
/// re-established by this function.
#[allow(clippy::type_complexity)]
async fn read_task_plan_recipe(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
) -> Result<
    (
        LearningStateViewRecipe,
        CampaignSourceResolution,
        CampaignSourceRecord,
        CampaignOwnerReadReceipt,
    ),
    String,
> {
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let owner_artifact = ArtifactId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID.to_owned())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let owner_id = OwnerId::from_artifact(owner_artifact);
    let lookup = CampaignSourceRevisionLookup {
        role: CampaignSourceRole::TaskPlan,
        owner_id: owner_id.clone(),
        record_id: CampaignOwnerRecordId::Task(task_id.clone()),
        expected_revision: None,
        expected_content_digest: None,
    };
    let read = read_campaign_source(kernel, binding, lookup).await?;
    if read.status != CampaignSourceReadStatus::Current {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let source = read
        .source
        .ok_or_else(|| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let receipt = read
        .read_receipt
        .ok_or_else(|| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let required_revision = binding
        .state_fence
        .task_revision
        .ok_or_else(|| CampaignPacketError::MissingTaskRevision.to_string())?;
    if source.role != CampaignSourceRole::TaskPlan
        || source.owner_id != owner_id
        || source.record_id != CampaignOwnerRecordId::Task(task_id.clone())
        || source.revision != CampaignOwnerRevision::Task(required_revision)
        || source.recorded_state_fence.task_revision != Some(required_revision)
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let recipe: LearningStateViewRecipe = serde_json::from_value(source.document.body.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    recipe
        .validate()
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    if source.document.schema
        != eliot_store_api::CampaignSourceDocumentSchema::LearningStateViewRecipe
        || recipe.binding.task_id.as_str() != binding.task_id
        || recipe.binding.scope.as_str() != binding.work_scope_id
        || recipe.binding.state_fence != binding.state_fence
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let task_plan_requirement = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskPlan)
        .ok_or_else(|| CampaignPacketError::InvalidTaskPlan.to_string())?;
    if task_plan_requirement.source_binding != CampaignSourceBinding::AuthenticatedTaskAnchor
        || task_plan_requirement.expected_reference.is_some()
        || task_plan_requirement.owner != owner_id
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let reference = source_reference_from_record(&source);
    reference
        .validate()
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let resolution = CampaignSourceResolution {
        role: CampaignSourceRole::TaskPlan,
        status: CampaignSourceResolutionStatus::Current,
        reference: Some(reference),
        read_state_fence: read.read_state_fence,
    };
    Ok((recipe, resolution, source, receipt))
}

/// Gates the Task Plan citation for this packet on governed source readback.
///
/// Builds the active source view and workspace-view revision from the owner
/// record that the `Current` authenticated read returned (so both the view
/// revision and the retained-revision id are the owner-issued values, not
/// constants), then reopens those owner bytes and runs the citation gate via
/// [`crate::governed_source_readback::project_owner_document_citation`].
///
/// `project` is the gate's real consumer, not an observer: `project_citation`
/// invokes it exactly once, and only with the verified
/// [`ProjectedCitation`], so this packet receives the gate's own
/// source-revision and anchor handles and publishes them. A refusal returns the
/// typed [`eliot_context_contracts::ReadbackRefusal`] and `project` is never
/// invoked, so no unverified handle can reach a consumer. Nothing here
/// re-derives a handle, re-labels an identity, or reconstructs an excerpt.
fn gate_task_plan_citation(
    record: &CampaignSourceRecord,
    receipt: &CampaignOwnerReadReceipt,
    binding: &CampaignPacketBinding,
    project: impl FnOnce(&ProjectedCitation),
) -> Result<(), eliot_context_contracts::ReadbackRefusal> {
    let (view, workspace_revision) =
        crate::governed_source_readback::owner_source_view(&binding.work_scope_id, record)
            .ok_or_else(|| {
                eliot_context_contracts::ReadbackRefusal::gap("readback.owner.view", None)
            })?;
    // `project_owner_document_citation` returns the same `ProjectedCitation`
    // that `project` has already received by reference, so this call carries
    // only the refusal half: the verified handles themselves were delivered
    // through `project`, and a refusal never invokes it. The returned value is
    // therefore the same handles, not a second source of authority.
    crate::governed_source_readback::project_owner_document_citation(
        record,
        receipt,
        view,
        workspace_revision,
        &binding.state_fence,
        project,
    )
    .map(drop)
}

fn campaign_read_request(
    binding: &CampaignPacketBinding,
    operation: NamedReadOperation,
    parameters: std::collections::BTreeMap<String, Value>,
) -> Result<NamedReadRequest, String> {
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let request = NamedReadRequest {
        operation,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence: binding.state_fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(request)
}

async fn read_campaign_source(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    lookup: CampaignSourceRevisionLookup,
) -> Result<CampaignSourceRevisionRead, String> {
    let request = campaign_read_request(
        binding,
        NamedReadOperation::GetCampaignSourceRevision,
        lookup
            .named_parameters()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?,
    )?;
    let response =
        crate::kernel_context_read_client::KernelContextReadClient::execute_campaign_read(
            kernel, request,
        )
        .await
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let read = CampaignSourceRevisionRead::from_named_read_response(&response)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    if read.read_state_fence != binding.state_fence
        || read.current_head.as_ref().is_some_and(|head| {
            head.role != lookup.role
                || head.owner_id != lookup.owner_id
                || head.record_id != lookup.record_id
        })
        || read.source.as_ref().is_some_and(|source| {
            source.role != lookup.role
                || source.owner_id != lookup.owner_id
                || source.record_id != lookup.record_id
        })
    {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    Ok(read)
}

async fn read_prior_campaign_view(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    view_id: &str,
) -> Result<CampaignLearningStateViewPublication, String> {
    let view_id = ArtifactId::new(view_id.to_owned())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let lookup = CampaignLearningStateViewLookup {
        view_id: view_id.clone(),
        task_id,
        scope_id,
    };
    let request = campaign_read_request(
        binding,
        NamedReadOperation::GetCampaignLearningStateView,
        lookup
            .named_parameters()
            .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?,
    )?;
    let response =
        crate::kernel_context_read_client::KernelContextReadClient::execute_campaign_read(
            kernel, request,
        )
        .await
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let read = CampaignLearningStateViewRead::from_named_read_response(&response)
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    if read.read_state_fence != binding.state_fence
        || read.status != CampaignLearningStateViewReadStatus::Current
    {
        return Err(CampaignPacketError::PriorViewUnavailable.to_string());
    }
    let publication = read
        .publication
        .ok_or_else(|| CampaignPacketError::PriorViewUnavailable.to_string())?;
    if publication.view_id != view_id
        || publication.task_id.as_str() != binding.task_id
        || publication.scope_id.as_str() != binding.work_scope_id
        || publication.view.view_id != publication.view_id
        || publication.view.binding.task_id.as_str() != binding.task_id
        || publication.view.binding.scope.as_str() != binding.work_scope_id
    {
        return Err(CampaignPacketError::PriorViewUnavailable.to_string());
    }
    publication
        .validate()
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    Ok(publication)
}

fn make_view_publication(
    binding: &CampaignPacketBinding,
    view: CampaignLearningStateView,
) -> Result<CampaignLearningStateViewPublication, String> {
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let view_bytes = canonical_json_bytes(&view)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let publication = CampaignLearningStateViewPublication {
        view_id: view.view_id.clone(),
        task_id,
        scope_id,
        state_fence: binding.state_fence.clone(),
        content_digest: sha256_hex(&view_bytes),
        view,
    };
    publication
        .validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(publication)
}

fn context_blocked_response(
    view: CampaignLearningStateViewPublication,
    code: CampaignPacketGapCode,
    role: Option<CampaignSourceRole>,
    resolutions: &[CampaignSourceResolution],
    prior_view_rejected_stale: bool,
) -> CampaignPacketResponse {
    let mut gaps = source_gaps(resolutions);
    gaps.push(CampaignPacketGap { code, role });
    // A context refusal still publishes its view, so the material it withheld
    // is still counted and delivered rather than reduced to a bare gap code. This
    // account is optional for real: the view being published here was already
    // accepted by `make_view_publication`, and a count that still fails on it
    // means the published view and the account disagree. Reporting that as
    // `None` is the fail-closed half of the pair — the named refusal above is
    // what makes an absent account legible, and the alternative would be a
    // zeroed account that reads as "nothing was withheld", the opposite of the
    // refusal this response is reporting.
    let material_account = account_delivered_materials(&view.view).ok();
    CampaignPacketResponse {
        outcome: CampaignPacketOutcome::Blocked,
        completeness: Completeness::Blocked,
        view: Some(view),
        material_account,
        // A blocked response publishes no cited support: the source it names was
        // refused or withheld, so there is no revision any consumer may read
        // back through.
        cited_support: None,
        // A context refusal publishes no recipe binding either: it refused
        // before the admission cell resolved the approved policy revision, so
        // there is no attempted reference to report.
        attempted_context_recipe: None,
        gaps,
        missing_roles: missing_roles(resolutions),
        stale_roles: stale_roles(resolutions),
        blocked_roles: blocked_roles(resolutions),
        prior_view_reused: false,
        prior_view_rejected_stale,
    }
}

fn campaign_packet_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    result: CampaignPacketResponse,
) -> Result<HostRequestResultBody, String> {
    let response = serde_json::to_value(result)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let response_bytes = canonical_json_bytes(&response)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let result_digest = sha256_hex(&response_bytes);
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response,
        attempt: Some(attempt.clone()),
        // A campaign packet is content this daemon COMPILED from owner reads
        // during this attempt; it is not itself a stored record and it was
        // never admitted as a semantic transition. It therefore declares the
        // candidate class and carries no semantic receipt (I15.6: model/derived
        // output remains candidate without an explicit governed promotion).
        // Source revisions stay `None` — the several owner reads behind the
        // packet have their own fences, and naming the request fence here would
        // claim a source revision the packet did not observe. Unknown, not clean.
        lineage: Some(HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: result_digest,
            producer_ref: None,
            source_revisions: None,
            source_state_fence: None,
            input_refs: None,
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: None,
            semantic_receipt_ref: None,
            result_class: eliot_protocol::HostRequestResultClass::NewCandidate,
            proof_ceiling: None,
            influence_state: eliot_security_contracts::InfluenceState::Unknown,
            instruction_taint: None,
        }),
        // Issue #1838 residual: the packet flight wires execution evidence
        // for compiled packets; until then the sealed manifest honestly lists
        // the absent evidence as missing parts.
        evidence: None,
    };
    body.validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(body)
}

fn source_gaps(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignPacketGap> {
    resolutions
        .iter()
        .filter_map(|resolution| {
            let unavailable = matches!(
                resolution.status,
                CampaignSourceResolutionStatus::Missing
                    | CampaignSourceResolutionStatus::Stale
                    | CampaignSourceResolutionStatus::Blocked
            );
            unavailable.then_some(CampaignPacketGap {
                code: CampaignPacketGapCode::RequiredSourceUnavailable,
                role: Some(resolution.role),
            })
        })
        .collect()
}

fn missing_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Missing)
}

fn stale_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Stale)
}

fn blocked_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Blocked)
}

fn roles_with_status(
    resolutions: &[CampaignSourceResolution],
    status: CampaignSourceResolutionStatus,
) -> Vec<CampaignSourceRole> {
    resolutions
        .iter()
        .filter(|resolution| resolution.status == status)
        .map(|resolution| resolution.role)
        .collect()
}
