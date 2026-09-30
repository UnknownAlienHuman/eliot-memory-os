//! Live `eliot.query` ContextReconstruction route (issue #2857 W1/W2/W4).
//!
//! The daemon's local-read poller already admits `eliot.query` pairs whose
//! explicit intent mode is `context_reconstruction`
//! (`bins/eliot-kernel/src/host_request_route.rs::local_read_admission_from_tool`
//! accepts any non-blank, control-free mode other than `current_position`, and
//! `KernelContextReadClient::LOCAL_READ_QUERY_MODES` lists this mode). This
//! module is the ONE production edge that turns that already-admitted intent
//! into the selector-complete seven-role reconstruction: it derives every
//! identity from the admitted envelope and the retained authenticated Kernel
//! session, resolves the closed selector set from the authenticated Task
//! Controller campaign owner, and calls
//! [`KernelContextReadClient::reconstruct_context_inputs`] — the existing
//! Governor composition edge that instantiates
//! [`eliot_governor::GovernorContextInputs`] over the Governor `ReadService`
//! and calls `reconstruct`.
//!
//! Nothing here reimplements the six-read algorithm, the before/after
//! source-head closure, or the seven role slots: those stay with
//! `eliot_governor::context_inputs`. The daemon only resolves identities and
//! shapes the result body.
//!
//! # Identity discipline
//!
//! - **Scope, fence, task, session** come from the admitted envelope and are
//!   rechecked against the retained Kernel snapshot and the fenced attempt.
//!   No MCP argument can select another scope or fence. The task and
//!   `WorkScope` are the ones the bridge's activation exchange resolved and
//!   its `build_invocation_envelope` bound, so on the live route they are the
//!   authenticated identity rather than an absent value. An envelope that
//!   genuinely carries no task identity is still refused with
//!   [`ReconstructionPrerequisite::MissingTaskBinding`] before any read.
//! - **Dependency heads** are the revision head this daemon OBSERVED on the
//!   store's own `GetRevisionHeads` read for that scope, taken under the same
//!   retained Kernel fence, through the catalogue-activated
//!   [`CanonicalReadClient::revision_heads`] the sibling
//!   `experience_runtime::read_current_position` leg already uses. They are
//!   never synthesized, and no other response on this route can supply them:
//!   the campaign-source lookup this route also performs is served by the
//!   Kernel with an empty head list.
//! - **The five remaining selectors** are the owner-declared members of the
//!   authenticated Task Controller `TaskPlan` recipe's slot denominator; the
//!   exact per-member mapping is documented on
//!   [`context_reconstruction_request`]. A slot that is absent, or that
//!   declares anything other than exactly one member, is a typed
//!   [`ReconstructionPrerequisite`] refusal *before* any reconstruction read.
//!   There is no `all` selector, no empty selector and no fallback token.
//! - **Per-role bounds** are the store catalogue's own
//!   `EVIDENCE_PACK_MAX_RECORDS` cap, which every one of the six T11.3
//!   handlers parses as its declared upper bound.
//!
//! # Ceiling
//!
//! The result is a reconstructed INPUT closure, never an admitted
//! `ActiveUnderstandingView`, never admitted Cue arrays, never capability
//! qualification and never action authority. The result body therefore
//! declares the candidate result class with no semantic receipt, exactly as the
//! campaign-packet body does for content this daemon compiled from owner reads.

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SessionId, SourceId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::{ContextReconstructionRequest, SevenRoleInputs};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSourceBinding, CampaignSourceRole,
    LearningStateViewRecipe, OwnerId, SlotRequirement, TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestResultBody,
    HostRequestResultLineage, LocalReadAttempt, host_request_operation_id,
};
use eliot_store_api::{
    CampaignSourceDocumentSchema, CampaignSourceReadStatus, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS,
    NamedReadOperation, NamedReadRequest, ReadConsistency, RevisionKey, ScopeId,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::SERVICE_NAME;
use crate::daemon_kernel_client::{DaemonKernelClient, OwnerSessionFacts};
use crate::kernel_context_read_client::KernelContextReadClient;

/// Wire `intent.mode` of the one admitted `eliot.query` shape this route owns.
///
/// Mirrors `QueryMode::ContextReconstruction`'s `snake_case` serde name
/// (`crates/surfaces/eliot-mcp/src/contract.rs`) and the Kernel's
/// `host_request_binding.rs` mapping of the same token.
const CONTEXT_RECONSTRUCTION_MODE: &str = "context_reconstruction";

/// Declared source-selector required for the single `subject:` query selector
/// of an admitted `eliot.query` pair.
const QUERY_SUBJECT_PREFIX: &str = "subject:";

/// The reconstructed selector each owner slot supplies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorMember {
    /// `GetAttentionAndProblems.problem_id`.
    AttentionProblem,
    /// `GetUnderstandingProjectionInputs.selector` for the cue slot.
    CueProjection,
    /// `GetUnderstandingProjectionInputs.selector` for the negative-memory slot.
    NegativeMemory,
    /// `GetCurrentEpistemicPosition.position`.
    EpistemicPosition,
    /// `GetCapabilityEvidenceState.skill_id`.
    AffordanceSkill,
}

impl SelectorMember {
    /// Stable member label used in prerequisite diagnostics.
    const fn label(self) -> &'static str {
        match self {
            Self::AttentionProblem => "attention_problem_id",
            Self::CueProjection => "projection_selector",
            Self::NegativeMemory => "negative_memory_selector",
            Self::EpistemicPosition => "epistemic_position",
            Self::AffordanceSkill => "affordance_skill_id",
        }
    }
}

/// Closed prerequisite failures of the `ContextReconstruction` route.
///
/// Every variant names the exact missing or unbound owner identity. None of
/// them carries a substitute value, and none is reachable after a read starts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReconstructionPrerequisite {
    /// The claimed pair is not the admitted `eliot.query` `ContextReconstruction`
    /// shape.
    #[error("request is not the admitted eliot.query context-reconstruction shape")]
    InvalidInvocation,
    /// The Kernel-issued attempt does not close over the admitted envelope.
    #[error("attempt does not bind the admitted request, scope, epoch or deadline")]
    UnboundAttempt,
    /// The admitted envelope fence is not the retained Kernel fence.
    #[error("admitted State Fence differs from the retained Kernel fence")]
    FenceMismatch,
    /// The admitted envelope binds no usable task identity.
    #[error("admitted request binds no task identity")]
    MissingTaskBinding,
    /// The daemon holds no Kernel-authenticated owner session.
    #[error("no authenticated owner session is retained for this reconstruction")]
    MissingOwnerSession,
    /// The authenticated Task Controller task recipe is unavailable, stale or
    /// not bound to the admitted task/scope/fence.
    #[error("authenticated Task Controller task recipe is unavailable or unbound")]
    TaskRecipeUnavailable,
    /// The observed revision heads do not carry this scope's head.
    #[error("observed revision heads do not carry this scope's dependency head")]
    DependencyHeadUnavailable,
    /// A required owner slot declared no member.
    #[error("required owner slot {role} declared no member: {member}")]
    MissingOwnerIdentity {
        /// `CampaignSourceRole` of the declared slot.
        role: &'static str,
        /// Reconstructed selector the slot must supply.
        member: &'static str,
    },
    /// A required owner slot declared more than one member, so no single exact
    /// selector exists.
    #[error("required owner slot {role} declared {declared} members: {member}")]
    AmbiguousOwnerIdentity {
        /// `CampaignSourceRole` of the declared slot.
        role: &'static str,
        /// Reconstructed selector the slot must supply.
        member: &'static str,
        /// Number of declared members.
        declared: usize,
    },
    /// The Governor reconstruction owner refused the closure.
    #[error("governor reconstruction owner refused the closure: {0}")]
    ReconstructionRefused(String),
}

/// Returns whether one claimed local-read pair is the admitted
/// `eliot.query` `ContextReconstruction` request this route owns.
///
/// The predicate is the shared closed admission: the envelope capability, the
/// tool name, the explicit `intent` object and its mode token. It never reads
/// `query` text as a selector; the exact `subject:` selector is parsed only
/// after the intent is recognised, and free text remains a refusal.
#[must_use]
pub fn is_context_reconstruction_query(envelope: &HostRequestEnvelope, tool: &Value) -> bool {
    let Some(object) = tool.as_object() else {
        return false;
    };
    if object.get("name").and_then(Value::as_str) != Some("eliot.query")
        || envelope.identity.capability != "eliot.query"
    {
        return false;
    }
    object
        .get("arguments")
        .and_then(Value::as_object)
        .and_then(|arguments| arguments.get("intent"))
        .and_then(Value::as_object)
        .and_then(|intent| intent.get("mode"))
        .and_then(Value::as_str)
        .is_some_and(|mode| mode == CONTEXT_RECONSTRUCTION_MODE)
}

/// Serves one admitted `eliot.query` `ContextReconstruction` pair.
///
/// Production edge: claim → this function → the existing idempotent
/// `local_read_result` submit leg, exactly like every other settled branch of
/// the local-read poller.
pub async fn serve_context_reconstruction(
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, ReconstructionPrerequisite> {
    if !is_context_reconstruction_query(envelope, tool) {
        return Err(ReconstructionPrerequisite::InvalidInvocation);
    }
    attempt
        .validate()
        .map_err(|_| ReconstructionPrerequisite::InvalidInvocation)?;
    let retained_fence = kernel.kernel_fence();
    if envelope.state_fence != retained_fence {
        return Err(ReconstructionPrerequisite::FenceMismatch);
    }
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err(ReconstructionPrerequisite::UnboundAttempt);
    }
    let owner_session = kernel
        .owner_session_facts()
        .ok_or(ReconstructionPrerequisite::MissingOwnerSession)?;
    let scope = trusted_query_scope(envelope, attempt)?;
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(ReconstructionPrerequisite::MissingTaskBinding)?;
    if attempt.scope_id != scope.as_str() {
        return Err(ReconstructionPrerequisite::UnboundAttempt);
    }
    let evidence_subject = exact_query_subject(tool)?;

    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let recipe = read_authenticated_task_recipe(kernel, &envelope.state_fence, &scope, task_id)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "eliotd.context_reconstruction.task_recipe");
            ReconstructionPrerequisite::TaskRecipeUnavailable
        })?;
    // The dependency head is OBSERVED from the store's own revision-head read
    // for this scope, not taken from the campaign-source lookup response above.
    //
    // `GetCampaignSourceRevision` is a Kernel-served operation whose
    // `NamedReadResponse` is built with an EMPTY `revision_heads` list
    // (`bins/eliot-kernel/src/daemon_request_dispatch.rs` arm for that
    // operation, returned un-enriched by `store_named_response` and passed
    // through unchanged by `daemon_kernel_client::store_named_async`), so the
    // heads that came back with the recipe read were never observations at all.
    // Matching a scope key against that list could therefore only ever find zero
    // heads, return `DependencyHeadUnavailable`, and refuse before
    // `context_reconstruction_request` was ever built — so `reconstruct` stayed
    // unreachable from any admitted request.
    //
    // The head's owner is [`CanonicalReadClient::revision_heads`], the one
    // catalogue-activated `GetRevisionHeads` read that the sibling daemon leg
    // `experience_runtime::read_current_position` already uses for exactly this
    // declared minimum. It travels the same authenticated `store_named` route
    // under the same retained fence and is re-checked against that fence here.
    // Nothing is synthesized: an absent, zero, duplicate or foreign-fence head
    // is a typed refusal.
    let dependency_revisions = observed_scope_head(&reads, &scope, &retained_fence).await?;
    let request = context_reconstruction_request(
        &scope,
        &dependency_revisions,
        task_id,
        evidence_subject,
        &recipe.recipe,
    )?;

    let ctx = reconstruction_context(envelope, &owner_session, &retained_fence)?;
    let seven = reads
        .reconstruct_context_inputs(&ctx, &request)
        .await
        .map_err(|error| ReconstructionPrerequisite::ReconstructionRefused(error.to_string()))?;
    context_reconstruction_result_body(envelope, attempt, &scope, task_id, &seven)
}

/// The authenticated task recipe, read under the admitted fence.
struct AuthenticatedTaskRecipe {
    recipe: LearningStateViewRecipe,
}

/// Derives the trusted scope of one admitted query pair: the envelope work
/// scope, else its session — never an MCP argument, exactly as the Kernel's
/// `trusted_local_read_scope` and `KernelContextReadClient::check_local_read_capability`
/// derive it.
///
/// **The work-scope leg is now the live one (#2857).** The only non-test
/// producer of an `eliot.query` envelope is the agent bridge's
/// `build_invocation_envelope`, which binds the `WorkScope` its activation
/// resolved; the session fallback below therefore only applies to a
/// pre-activation or otherwise work-scope-less envelope, whose reconstruction
/// is refused earlier by `MissingTaskBinding` anyway. The derivation is kept
/// identical to the owner's on purpose: the Kernel mints `attempt.scope_id`
/// with exactly this precedence
/// (`local_read_attempt_capability`), and the cross-check below compares the
/// two, so the two implementations must not drift.
fn trusted_query_scope(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
) -> Result<ScopeId, ReconstructionPrerequisite> {
    let work_scope = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control));
    let scope_text = match work_scope {
        Some(scope) => scope,
        None => envelope
            .identity
            .session_id
            .as_deref()
            .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control))
            .ok_or(ReconstructionPrerequisite::InvalidInvocation)?,
    };
    ScopeId::new(scope_text.to_owned())
        .map_err(|_| ReconstructionPrerequisite::InvalidInvocation)
        .and_then(|scope| {
            if scope.as_str() == attempt.scope_id {
                Ok(scope)
            } else {
                Err(ReconstructionPrerequisite::UnboundAttempt)
            }
        })
}

/// Parses the already-admitted exact `subject:` evidence selector.
///
/// Free text, a blank subject, a control-bearing subject and any other prefix
/// are refused: this route never interprets query prose as a selector.
fn exact_query_subject(tool: &Value) -> Result<String, ReconstructionPrerequisite> {
    tool.get("arguments")
        .and_then(Value::as_object)
        .and_then(|arguments| arguments.get("query"))
        .and_then(Value::as_str)
        .and_then(|query| query.strip_prefix(QUERY_SUBJECT_PREFIX))
        .map(str::trim)
        .filter(|subject| !subject.is_empty() && !subject.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(ReconstructionPrerequisite::InvalidInvocation)
}

/// Reads and revalidates the Task Controller `TaskPlan` campaign source record
/// for the admitted task under the admitted fence.
///
/// The checks are the same ones the production campaign-packet route applies to
/// this record: exact owner id, exact task record id, the owner-resolved current
/// task revision, exact documented schema, and an exact recipe task/scope/fence
/// binding. A record that is not the current authenticated row for that task is
/// refused.
///
/// # What this function actually proves
///
/// The lookup carries `expected_revision: None`, so the store resolves the
/// *current* row for the exact `(role, owner, record_id)` this function asked
/// for and returns it as `CampaignSourceReadStatus::Current` with its own
/// `current_head`. What is proved here is:
///
/// - the read is `Current` and its `read_state_fence` is the exact admitted
///   fence, so it answers this operation and no other;
/// - the `CampaignOwnerReadReceipt` validates its ORIGINAL recorded value with
///   the existing `CampaignOwnerReadReceipt::validate()` and binds the returned
///   row through the existing `binds_record()`. No digest is recomputed here;
/// - the returned row is the `(role, owner, record_id)` key this function
///   requested. `CampaignSourceRecord::validate` pins the row's *owner* to the
///   Task Controller and its `(record_id, revision)` to the task/revision
///   family, but pins no specific `TaskId`, so an owner that answers a
///   different task under the same owner id is refused here rather than
///   compiled;
/// - the owner-resolved current revision is a `CampaignOwnerRevision::Task`
///   value, and an absent current head is refused;
/// - the recipe's binding fence declares that same owner-resolved task
///   revision, binds the admitted `TaskId` exactly, binds the admitted scope
///   exactly, and is compatible with this operation's admitted fence.
///
/// # Why the recipe's fence is compared by compatibility, not by equality
///
/// I4.5 is explicit that `StateFence` "contains only load-bearing dependencies"
/// and that revisions are "exact dependency-key/revision pairs, not one global
/// scope counter". `StateFence::I45_KEY_OMISSIONS` names the owner of the
/// revision dimension as `eliot-store-api RevisionHeadExpectation via
/// eliot-canonical CanonicalWriteEnvelope`, resolved and compared at the
/// operation's own owner rather than pinned onto the transport fence.
/// `KernelGenerationSnapshot::state_fence()` is
/// `StateFence::new(authority_epoch, resource_generation)`, which leaves
/// `task_revision` at `None` by construction, and `serve_context_reconstruction`
/// proves `envelope.state_fence == kernel.kernel_fence()` before calling here.
///
/// A `LearningStateViewRecipe` cannot be published without a task revision in
/// its binding fence: `validate_admitted_task_binding` refuses a recipe whose
/// binding fence lacks one, the Task Controller producer takes its
/// `CampaignOwnerRevision::Task` from that field, and
/// `CampaignSourceDocument::validate_owner_binding` re-asserts it. So the
/// recipe's `task_revision` is `Some(_)` and the admitted transport fence's is
/// `None` on every producer, and `recipe.binding.state_fence == *fence` could
/// never be true: the route was unreachable.
///
/// The transport fence therefore cannot be the reference for the task-revision
/// dimension, and this function does not pretend it can. That dimension is
/// matched by value against `required_revision`, the owner-resolved current
/// revision this read returned, which is the value's actual owner. The
/// dimensions the transport fence does carry — authority epoch and resource
/// generation — are held by the existing `StateFence::is_compatible_with`, the
/// one-sided compatibility comparison the Kernel and the Task Controller
/// lifecycle already use at their own admission edges. A recipe published under
/// a different authority epoch or resource generation is refused.
async fn read_authenticated_task_recipe(
    kernel: &DaemonKernelClient,
    fence: &StateFence,
    scope: &ScopeId,
    task_id: &str,
) -> Result<AuthenticatedTaskRecipe, String> {
    let task = TaskId::new(task_id.to_owned()).map_err(|error| error.to_string())?;
    let owner_id = OwnerId::from_artifact(
        eliot_contracts::ArtifactId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID.to_owned())
            .map_err(|error| error.to_string())?,
    );
    let record_id = CampaignOwnerRecordId::Task(task.clone());
    let lookup = CampaignSourceRevisionLookup {
        role: CampaignSourceRole::TaskPlan,
        owner_id: owner_id.clone(),
        record_id: record_id.clone(),
        expected_revision: None,
        expected_content_digest: None,
    };
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetCampaignSourceRevision,
        scope_id: Some(scope.clone()),
        consistency: ReadConsistency::ExactFence,
        state_fence: fence.clone(),
        parameters: lookup
            .named_parameters()
            .map_err(|error| error.to_string())?,
    };
    let response = KernelContextReadClient::execute_campaign_read(kernel, request)
        .await
        .map_err(|error| error.to_string())?;
    let read = CampaignSourceRevisionRead::from_named_read_response(&response)
        .map_err(|error| error.to_string())?;
    if read.status != CampaignSourceReadStatus::Current || read.read_state_fence != *fence {
        return Err("task recipe owner read is not current under the admitted fence".to_owned());
    }
    // The owner-resolved current revision, and the required task revision for
    // this reconstruction. `read.current_head` is the store's own answer to
    // "which revision of this `(role, owner, record_id)` is current";
    // `CampaignSourceRevisionRead::validate` already requires it to agree with
    // the returned row, and a non-`Task` revision cannot appear on a `TaskPlan`
    // row because `CampaignSourceRecord::validate` already refuses one. The
    // match is kept as the exhaustive, typed resolution of the revision family
    // rather than a comparison that can never fire.
    let head = read
        .current_head
        .ok_or_else(|| "task recipe owner read returned no current head".to_owned())?;
    let required_revision = match &head.revision {
        CampaignOwnerRevision::Task(revision) => *revision,
        _ => {
            return Err(
                "task recipe owner read resolved a non-task revision for the task record"
                    .to_owned(),
            );
        }
    };
    let source = read
        .source
        .ok_or_else(|| "task recipe owner read returned no source row".to_owned())?;
    let receipt = read
        .read_receipt
        .ok_or_else(|| "task recipe owner read returned no owner read receipt".to_owned())?;
    if receipt.validate().is_err()
        || receipt.read_state_fence != *fence
        || !receipt.binds_record(&source)
    {
        return Err("task recipe owner read receipt does not bind the returned row".to_owned());
    }
    // The returned row must be the exact `(role, owner, record_id)` key this
    // function asked the Task Controller owner for. `campaign_record_matches_head`
    // and `CampaignOwnerReadReceipt::binds_record` already force the row, the
    // current head and the receipt to agree on that key, and
    // `CampaignSourceRecord::validate` already pins the owner and the
    // `(record_id, revision)` family, so re-asserting their agreement here
    // would be a clause that cannot fire.
    if source.role != CampaignSourceRole::TaskPlan
        || source.owner_id != owner_id
        || source.record_id != record_id
    {
        return Err("task recipe row is not the current row for the admitted task".to_owned());
    }
    if source.document.schema != CampaignSourceDocumentSchema::LearningStateViewRecipe {
        return Err("task recipe row is not the learning-state-view recipe schema".to_owned());
    }
    let recipe: LearningStateViewRecipe = serde_json::from_value(source.document.body.clone())
        .map_err(|error| format!("task recipe body is not a recipe: {error}"))?;
    recipe
        .validate()
        .map_err(|error| format!("task recipe is invalid: {error}"))?;
    // The recipe must be proven to belong to THIS admitted operation.
    //
    // Task identity and scope are compared exactly, against the same admitted
    // values the owner read was scoped to. The task-revision dimension is
    // compared by value against `required_revision`, the owner-resolved current
    // revision, because that is the owner's own answer and the transport fence
    // structurally cannot carry one (see the module note). The remaining fence
    // dimensions the transport fence does carry are compared with the existing
    // one-sided compatibility helper, which rejects a recipe published under a
    // different authority epoch or resource generation. An equality test here
    // would demand `Some(task_revision) == None` and refuse every recipe any
    // Task Controller can produce.
    let recipe_fence = &recipe.binding.state_fence;
    if recipe.binding.task_id != task
        || recipe.binding.scope.as_str() != scope.as_str()
        || recipe_fence.task_revision != Some(required_revision)
        || !fence.is_compatible_with(recipe_fence)
    {
        return Err("task recipe does not bind the admitted task, scope and fence".to_owned());
    }
    let anchored = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskPlan)
        .ok_or_else(|| "task recipe declares no task-plan source requirement".to_owned())?;
    if anchored.source_binding != CampaignSourceBinding::AuthenticatedTaskAnchor
        || anchored.expected_reference.is_some()
        || anchored.owner != owner_id
    {
        return Err("task recipe task-plan requirement is not the task anchor".to_owned());
    }
    Ok(AuthenticatedTaskRecipe { recipe })
}

/// Turns the revision head this daemon OBSERVED on its own store head read
/// into the exact-fence dependency minimum for the reconstruction.
///
/// The key is the store's own scope head key, read through the one
/// catalogue-activated `GetRevisionHeads` operation
/// ([`CanonicalReadClient::revision_heads`]) over the same authenticated
/// `store_named` transport the rest of this route uses. The store projects
/// only the requested keys back, so a head that is absent, zero or bound to
/// another fence is refused; nothing is invented, and no other response on
/// this route can supply a dependency revision.
async fn observed_scope_head(
    reads: &KernelContextReadClient,
    scope: &ScopeId,
    fence: &StateFence,
) -> Result<BTreeMap<RevisionKey, u64>, ReconstructionPrerequisite> {
    let key = RevisionKey::new(format!("scope:{}", scope.as_str()))
        .map_err(|_| ReconstructionPrerequisite::DependencyHeadUnavailable)?;
    let mut matching = reads
        .revision_heads(vec![key.clone()])
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "eliotd.context_reconstruction.scope_head");
            ReconstructionPrerequisite::DependencyHeadUnavailable
        })?
        .into_iter()
        .filter(|head| head.key == key);
    let head = matching
        .next()
        .ok_or(ReconstructionPrerequisite::DependencyHeadUnavailable)?;
    if matching.next().is_some()
        || head.revision == 0
        || head.state_fence != *fence
        || head.validate().is_err()
    {
        return Err(ReconstructionPrerequisite::DependencyHeadUnavailable);
    }
    let mut dependencies = BTreeMap::new();
    dependencies.insert(key, head.revision);
    Ok(dependencies)
}

/// Resolves the exact closed `ContextReconstructionRequest` from the admitted
/// pair and the authenticated owner recipe.
///
/// The scope, fence, dependency heads, task identity and evidence selector come
/// from the admitted route; the remaining five selectors come from the recipe's
/// owner-declared slot members:
///
/// | request member | recipe slot `source_role` |
/// |---|---|
/// | `attention_problem_id` | `TaskOpenItems` (optional slot) |
/// | `projection_selector` | `MemoryProjection` |
/// | `negative_memory_selector` | `ExperienceProjection` |
/// | `epistemic_position` | `CurrentPosition` |
/// | `affordance_skill_id` | `ContextToolPolicy` |
///
/// **ASSUMPTION (recorded in the work-unit report):** no document in this
/// repository states which owner record mints the free-token
/// `GetAttentionAndProblems.problem_id`,
/// `GetUnderstandingProjectionInputs.selector` (cue and negative-memory) and
/// `GetCapabilityEvidenceState.skill_id` selectors for a task. The most
/// specific governing documents are the store catalogue
/// (`operation_catalogue.rs`, which declares the selector key per read) and
/// `eliot_governor::context_inputs` (which requires an exact owner-resolved
/// value per role and forbids a fabricated default). The authenticated Task
/// Controller `TaskPlan` recipe is the one owner-declared, task-bound
/// denominator the daemon already reads and revalidates on this route, so each
/// selector is taken from the sole declared member of the mapped slot. Every one
/// of these is a derived owner identity with an exact refusal when the owner
/// declares none — never a placeholder.
///
/// Every bound is the store catalogue's own `EVIDENCE_PACK_MAX_RECORDS` cap,
/// which each of the six T11.3 handlers parses as its declared upper bound; no
/// per-role value is invented and no selector is defaulted.
fn context_reconstruction_request(
    scope: &ScopeId,
    dependency_revisions: &BTreeMap<RevisionKey, u64>,
    task_id: &str,
    evidence_subject: String,
    recipe: &LearningStateViewRecipe,
) -> Result<ContextReconstructionRequest, ReconstructionPrerequisite> {
    let bound = EVIDENCE_PACK_MAX_RECORDS;
    let optional_problem = optional_slot_member(recipe, CampaignSourceRole::TaskOpenItems)?;
    let request = ContextReconstructionRequest {
        scope_id: scope.clone(),
        dependency_revisions: dependency_revisions.clone(),
        epistemic_position: required_slot_member(
            recipe,
            SelectorMember::EpistemicPosition,
            CampaignSourceRole::CurrentPosition,
        )?,
        evidence_subject,
        evidence_max_records: bound,
        task_id: task_id.to_owned(),
        task_max_records: bound,
        attention_problem_id: optional_problem,
        attention_max_records: bound,
        projection_selector: required_slot_member(
            recipe,
            SelectorMember::CueProjection,
            CampaignSourceRole::MemoryProjection,
        )?,
        projection_max_records: bound,
        negative_memory_selector: required_slot_member(
            recipe,
            SelectorMember::NegativeMemory,
            CampaignSourceRole::ExperienceProjection,
        )?,
        negative_memory_max_records: bound,
        affordance_skill_id: required_slot_member(
            recipe,
            SelectorMember::AffordanceSkill,
            CampaignSourceRole::ContextToolPolicy,
        )?,
        affordance_max_records: bound,
    };
    request
        .validate()
        .map_err(|error| ReconstructionPrerequisite::ReconstructionRefused(error.to_string()))?;
    Ok(request)
}

/// Returns the sole owner-declared member of the recipe slot with this
/// `source_role`, or a typed prerequisite refusal.
fn required_slot_member(
    recipe: &LearningStateViewRecipe,
    member: SelectorMember,
    role: CampaignSourceRole,
) -> Result<String, ReconstructionPrerequisite> {
    declared_slot_member(recipe, role)?.ok_or(ReconstructionPrerequisite::MissingOwnerIdentity {
        role: role_wire(role),
        member: member.label(),
    })
}

/// Returns the sole owner-declared member of an OPTIONAL recipe slot, or
/// `None` when the recipe declares no such slot.
///
/// The optional `attention_problem_id` is the request's only defaulted member,
/// and the request contract declares its absent value as "no specific problem is
/// requested" — a declared contract option, never a substituted selector. An
/// optional slot that nevertheless declares several members is still refused,
/// because then no single exact problem identity exists.
fn optional_slot_member(
    recipe: &LearningStateViewRecipe,
    role: CampaignSourceRole,
) -> Result<Option<String>, ReconstructionPrerequisite> {
    let Some(spec) = recipe.slots.iter().find(|slot| slot.source_role == role) else {
        return Ok(None);
    };
    if spec.requirement == SlotRequirement::Required {
        return declared_slot_member(recipe, role)?.map(Some).ok_or(
            ReconstructionPrerequisite::MissingOwnerIdentity {
                role: role_wire(role),
                member: SelectorMember::AttentionProblem.label(),
            },
        );
    }
    match spec.declared_members.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.as_str().to_owned())),
        members => Err(ReconstructionPrerequisite::AmbiguousOwnerIdentity {
            role: role_wire(role),
            member: SelectorMember::AttentionProblem.label(),
            declared: members.len(),
        }),
    }
}

/// Returns the single member of the recipe slot with this `source_role`, or
/// `None` when the recipe declares none.
fn declared_slot_member(
    recipe: &LearningStateViewRecipe,
    role: CampaignSourceRole,
) -> Result<Option<String>, ReconstructionPrerequisite> {
    let mut matching = recipe.slots.iter().filter(|slot| slot.source_role == role);
    let Some(spec) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(ReconstructionPrerequisite::AmbiguousOwnerIdentity {
            role: role_wire(role),
            member: "slot",
            declared: 2,
        });
    }
    match spec.declared_members.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.as_str().to_owned())),
        members => Err(ReconstructionPrerequisite::AmbiguousOwnerIdentity {
            role: role_wire(role),
            member: "slot",
            declared: members.len(),
        }),
    }
}

/// Stable wire label of a `CampaignSourceRole`, for prerequisite diagnostics.
const fn role_wire(role: CampaignSourceRole) -> &'static str {
    match role {
        CampaignSourceRole::TaskOpenItems => "TASK_OPEN_ITEMS",
        CampaignSourceRole::MemoryProjection => "MEMORY_PROJECTION",
        CampaignSourceRole::ExperienceProjection => "EXPERIENCE_PROJECTION",
        CampaignSourceRole::CurrentPosition => "CURRENT_POSITION",
        CampaignSourceRole::ContextToolPolicy => "CONTEXT_TOOL_POLICY",
        _ => "DECLARED_SLOT",
    }
}

/// Builds the read metadata bound to the admitted envelope and the retained
/// authenticated owner session.
///
/// The principal the Governor read owner records is exactly
/// `ReadPrincipal::from_metadata(ctx)`: this product/source pair, the admitted
/// caller session and the admitted task. The Kernel principal is not copied into
/// a field it does not own; its presence is required through
/// [`ReconstructionPrerequisite::MissingOwnerSession`] and its fence is the
/// fence this metadata carries.
fn reconstruction_context(
    envelope: &HostRequestEnvelope,
    owner_session: &OwnerSessionFacts,
    fence: &StateFence,
) -> Result<RequestMetadata, ReconstructionPrerequisite> {
    let operation = host_request_operation_id(envelope);
    let request_id = RequestId::new(format!(
        "eliotd:context-reconstruction:{}",
        operation.as_str()
    ))
    .map_err(|error| {
        ReconstructionPrerequisite::ReconstructionRefused(format!(
            "reconstruction request id: {error}"
        ))
    })?;
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .map(SessionId::new)
        .transpose()
        .map_err(|error| {
            ReconstructionPrerequisite::ReconstructionRefused(format!(
                "admitted session identity: {error}"
            ))
        })?;
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .map(TaskId::new)
        .transpose()
        .map_err(|error| {
            ReconstructionPrerequisite::ReconstructionRefused(format!(
                "admitted task identity: {error}"
            ))
        })?;
    let context = RequestMetadata {
        request_id,
        session_id,
        task_id,
        product_id: ProductId::new(SERVICE_NAME).map_err(|error| {
            ReconstructionPrerequisite::ReconstructionRefused(error.to_string())
        })?,
        source_id: SourceId::new(SERVICE_NAME).map_err(|error| {
            ReconstructionPrerequisite::ReconstructionRefused(error.to_string())
        })?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context
        .validate()
        .map_err(|error| ReconstructionPrerequisite::ReconstructionRefused(error.to_string()))?;
    // The retained owner session must belong to this live client generation:
    // a missing Kernel-authenticated session is a prerequisite failure, never
    // a substituted principal.
    if owner_session.kernel_principal.trim().is_empty() {
        return Err(ReconstructionPrerequisite::MissingOwnerSession);
    }
    Ok(context)
}

/// Projects the reconstructed closure into the host-request result body.
///
/// The response carries the exact `SevenRoleInputs` value plus the identity it
/// was reconstructed under. The lineage declares the candidate result class and
/// no semantic receipt: a retained source envelope is not an admitted
/// `ActiveUnderstandingView`, admitted Cue array, capability qualification or
/// action authority.
fn context_reconstruction_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    scope: &ScopeId,
    task_id: &str,
    seven: &SevenRoleInputs,
) -> Result<HostRequestResultBody, ReconstructionPrerequisite> {
    let closure = serde_json::to_value(seven)
        .map_err(|error| ReconstructionPrerequisite::ReconstructionRefused(error.to_string()))?;
    let response = json!({
        "operation": CONTEXT_RECONSTRUCTION_MODE,
        "task_id": task_id,
        "scope_id": scope.as_str(),
        "context_reconstruction": closure,
    });
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| ReconstructionPrerequisite::ReconstructionRefused(error.to_string()))?;
    let result_digest = sha256_hex(&bytes);
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response,
        attempt: Some(attempt.clone()),
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
        evidence: None,
    };
    body.validate().map_err(|_| {
        ReconstructionPrerequisite::ReconstructionRefused("result body is not valid".to_owned())
    })?;
    Ok(body)
}
