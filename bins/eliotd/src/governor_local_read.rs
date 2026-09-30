//! Governor local read serving adapter (HANDOFF-LRR-GOV, #18).
//!
//! Per-call factory over [`DaemonComposition::context_read_client`]:
//! builds the `KernelContextReadClient` for the caller-held
//! [`DaemonKernelClient`], wraps it in the Governor `ReadService`, and
//! answers through [`LocalReadPort`]. The composition retains no client and
//! no thread, so a Governor refresh surfaces as an exact fence mismatch
//! instead of silent divergence.
//!
//! Caller chain: MGR01 kernel caller -> this factory -> `ReadService` over
//! `KernelContextReadClient` -> store-backed `QueryResult` consumer
//! (projection via `eliot-mcp`, persistence via the existing ORS result
//! path).
//!
//! Production edges out of this module:
//! [`forward_admitted_local_read`] forwards one admitted `eliot.query` pair
//! to the Kernel `local_read` leg over the retained authenticated session
//! and returns the persisted result body. `eliot.packet` follows the same
//! claim/result lifecycle but is served by the production campaign compiler;
//! [`serve_admitted_local_read`] remains the query-only local twin
//! ([`KernelContextReadClient::execute_local_read`] over
//! [`LocalReadPort::evidence_query`]) and returns the exact evidence record.
//! [`serve_admitted_state_pair`] is the `eliot.state` serving edge: it
//! validates the admitted state shape (never a query), binds the Kernel-issued
//! attempt and the retained fence, resolves the task/scope/attention/health
//! facts through their Governor read owners plus independent Kernel
//! session/fence facts, and returns the bounded preview body for the state
//! submit leg. With no selected task it returns the bounded
//! selection/intake discovery result instead of inventing a `TaskContract`.
//!
//! Caller chain: `fn main` (`bins/eliotd/src/main.rs`) -> daemon poll loop
//! (`daemon_runtime.rs`, state branch over the state carrier/claim/submit leg
//! owned with #2565, reaching this edge as `eliotd::serve_admitted_state_pair`
//! through its `lib.rs` re-export) -> [`serve_admitted_state_pair`] ->
//! [`KernelContextReadClient`] (`revision_heads` dependency minimums,
//! `ReadService` state/query reads) -> Governor `ReadService`/`ReadApi`
//! owner -> Kernel named-read route -> existing ORS result submit leg.
//! The daemon poll branch, the `lib.rs` re-export and the Kernel state
//! carrier/claim/submit queue are outside this module; this edge performs no
//! admission decision, holds no composition lock across owner reads, and never
//! routes State as Query.
//!
//! Query is fully live (`Verification` + `GetEvidencePack`); projection
//! inputs stay port-shape fail-closed `Unavailable` until MGR04 (#19)
//! activates the storage operation.
//!
//! # `eliot.query` Context reconstruction (#2857)
//!
//! [`crate::context_reconstruction_route`] is the daemon's production edge for
//! the one admitted request that names Context reconstruction: an `eliot.query`
//! whose explicit intent mode is `context_reconstruction`. The Kernel admits
//! exactly that intent to this poller
//! (`host_request_route::local_read_selectors_from_tool` accepts any
//! non-blank, control-free mode other than `current_position`), and the
//! `subject:` selector of that pair is the one exact, Kernel-validated
//! selector it carries. The route lives in its own module because it binds a
//! different identity closure than a single bounded evidence read; this module
//! keeps the query-only `GetEvidencePack` twin and the campaign packet lane
//! where they are, and neither of them may reinterpret a reconstruction.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SessionId, SourceId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::KernelPortError;
use eliot_learning_contracts::{CampaignSourceRole, LearningStateViewRecipe};
use eliot_protocol::{
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestResultBody, HostRequestResultLineage,
    LocalReadAttempt, host_request_operation_id,
};
use eliot_read::{
    BoundRead, BranchEnvironmentScope, CurrentStateView, FreshnessPolicy, LocalReadPort,
    NamedParameters, QueryIntent, QueryMode, QueryRequest, QueryResult, ReadApi, ReadError,
    ReadOrderingBinding, ReadService, RequiredAssurance, StateRequest, StoreReadFailure, TimeScope,
};
use eliot_store_api::{
    CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency,
    RevisionKey, ScopeId, StoreError,
};
use thiserror::Error;

use super::{DaemonComposition, DaemonKernelClient, KernelContextReadClient};
use crate::campaign_packet::{CampaignPacketBinding, read_task_plan_recipe};

/// Forwards one admitted `eliot.query` pair to the Kernel `local_read` leg.
///
/// Production kernel-caller bridge over the retained authenticated session:
/// the pair proves its closed linkage and fence binding inside
/// [`DaemonKernelClient::local_read_async`], travels as the `"local_read"`
/// operation with the Kernel-issued attempt capability, and the persisted
/// result body behind the admitted receipt+record returns carrying that same
/// attempt for the submit leg. Kernel remains the admission and persistence
/// authority; this function performs no admission decision and no consistency
/// algorithm. A wrong fence or malformed pair fails closed before any
/// transport. A packet is dispatched by the campaign poller after its exact
/// owner-read and Context-compiler work, then uses this same result-submit
/// contract.
pub async fn forward_admitted_local_read(
    kernel: &DaemonKernelClient,
    envelope: HostRequestEnvelope,
    tool: serde_json::Value,
    attempt: LocalReadAttempt,
) -> Result<HostRequestResultBody, KernelPortError> {
    kernel.local_read_async(envelope, tool, attempt).await
}

/// Serves one admitted `eliot.query` pair through the Governor read port.
///
/// Production local-serving edge twinning the Kernel admission mirror: the
/// closed capability gate runs before any read, the envelope fence must equal
/// the caller-observed admitted fence, and the closed selectors serve exactly
/// one bounded [`LocalReadPort::evidence_query`] whose answer must echo the
/// evidence operation and the admitted fence. Returns the exact evidence
/// record, never a bare admission. `eliot.packet` is dispatched by the
/// production campaign compiler rather than this query-only twin; a wrong
/// fence or substituted answer fails closed, never `Ok`-empty.
///
/// The port and the fence stay per-call parameters (rather than retained
/// state) so the composition retains no client and no thread.
pub async fn serve_admitted_local_read(
    reads: &impl LocalReadPort,
    admitted_fence: &StateFence,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<QueryResult, ReadError> {
    KernelContextReadClient::execute_local_read(reads, admitted_fence, envelope, tool).await
}

/// Answers one bounded Governor evidence query through the local read port.
///
/// Threads the admitted fence via `ctx`, the explicit trusted `scope`, the
/// exact `subject`, and the explicit `max_records` bound. Returns the exact
/// record/provenance on success; a wrong fence or an over-bound request is
/// refused fail-closed.
pub async fn answer_evidence_query(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    subject: String,
    max_records: u32,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .evidence_query(ctx, scope, subject, max_records)
        .await
}

/// Answers one Governor projection-inputs read (port-shape only).
///
/// Validates `packet_ref` / `material_refs` and the facade request shape,
/// then fails closed with a typed `Unavailable` store error until MGR04
/// (#19) activates the storage operation. Never `Ok`-empty, never canned.
pub async fn answer_projection_inputs(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    packet_ref: Option<String>,
    material_refs: Vec<String>,
) -> Result<QueryResult, ReadError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|_| ReadError::Store(StoreReadFailure::Unavailable))?;
    let service = ReadService::new(client);
    service
        .projection_inputs(ctx, scope, packet_ref, material_refs)
        .await
}

/// Whether a claimed pair selects the state preview lane.
///
/// Closed: the tool name and the envelope capability are both `eliot.state`.
/// Anything else — including `eliot.query` — is not state, so a query pair
/// can never be reinterpreted as a state preview through this predicate.
#[must_use]
pub fn is_state_tool(envelope: &HostRequestEnvelope, tool: &serde_json::Value) -> bool {
    envelope.identity.capability == "eliot.state"
        && tool
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some("eliot.state")
}

/// Closed selectors of one admitted `eliot.state` pair.
///
/// Mirrors the Kernel derivation
/// (`host_request_route::local_state_selectors_from_tool`, issue #2563): the
/// trusted envelope scope (work scope else session — never an MCP argument)
/// plus the exact `include` projection-field list. An absent `include` is the
/// default full projection; entries are unique non-blank control-free field
/// names.
pub struct StateSelectors {
    /// Trusted scope the preview is admitted for.
    pub scope: ScopeId,
    /// Requested projection fields, empty for the default full projection.
    pub include: Vec<String>,
}

/// Closed state-preview failures. Error text never reflects caller payload
/// bytes or owner material: every variant renders a static sentence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StateServeError {
    /// The pair is not the admitted `eliot.state` shape, or its linkage,
    /// selectors or read metadata do not close.
    #[error("request is not the admitted eliot.state shape")]
    InvalidInvocation,
    /// The Kernel-issued attempt does not close over the admitted envelope,
    /// scope, epoch, facet or deadline.
    #[error("attempt does not bind the admitted state request, scope, epoch or deadline")]
    UnboundAttempt,
    /// The admitted envelope fence is not the retained Kernel fence.
    #[error("admitted State Fence differs from the retained Kernel fence")]
    FenceMismatch,
    /// The daemon holds no Kernel-authenticated owner session.
    #[error("no authenticated owner session is retained for this state preview")]
    MissingOwnerSession,
    /// The admitted task binding has no usable task or work scope identity.
    #[error("admitted state request binds no usable task and work scope")]
    MissingTaskBinding,
    /// The authenticated Task Controller task recipe is unavailable, stale or
    /// not bound to the admitted task/scope/fence.
    #[error("authenticated Task Controller task recipe is unavailable or unbound")]
    TaskRecipeUnavailable,
    /// The observed revision heads do not carry this scope's dependency head.
    #[error("observed revision heads do not carry this scope's dependency head")]
    DependencyHeadUnavailable,
    /// The task-bound task fact could not be read or did not echo the
    /// admitted task. A task-bound preview without its task fact is refused
    /// rather than served as a healthy empty preview. Carries the static
    /// refusal reason only; owner bytes never cross into diagnostics.
    #[error("task fact is unavailable for the admitted task: {0}")]
    TaskFactUnavailable(&'static str),
    /// A named owner read failed closed or returned an invalid body.
    #[error("state owner read failed closed")]
    OwnerReadUnavailable,
}

/// Known `eliot.state` projection fields (I7.6: task/scope/attention/health
/// preview plus the capability profile the affordance/epistemic reads supply).
/// Requested names outside this set are reported under `unavailable_fields`,
/// never silently dropped and never projected.
const KNOWN_STATE_PROJECTION_FIELDS: [&str; 4] = ["task", "attention", "health", "profile"];

/// Checks the state serving capability before any read is served.
///
/// Runs the exact invoke-read linkage gate plus the closed state-selector
/// derivation, mirroring the Kernel admission
/// (`host_request_route::check_local_state_admission`): the pair must prove
/// its capability/payload-digest linkage, name `eliot.state` on both halves,
/// carry an object `arguments` with an absent-or-closed `include` list, and
/// bind a trusted scope. A query pair fails here as `UnknownOperation` — it
/// is never reinterpreted as state.
fn check_state_capability(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<StateSelectors, StoreError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    // A query (or packet, or anything else) is not state: it fails here as
    // `UnknownOperation` and is never reinterpreted through this lane.
    if !is_state_tool(envelope, tool) {
        return Err(StoreError::UnknownOperation);
    }
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .and_then(serde_json::Value::as_object)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "state arguments must be an object",
        })?;
    let include = match arguments.get("include") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            let mut seen = BTreeSet::new();
            let mut include = Vec::with_capacity(items.len());
            for item in items {
                let field = item
                    .as_str()
                    .filter(|field| {
                        !field.trim().is_empty() && !field.chars().any(char::is_control)
                    })
                    .ok_or(StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "state include must list unique non-blank fields",
                    })?;
                if !seen.insert(field) {
                    return Err(StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "state include must list unique non-blank fields",
                    });
                }
                include.push(field.to_owned());
            }
            include
        }
        Some(_) => {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "state include must list unique non-blank fields",
            });
        }
    };
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
        .or_else(|| {
            envelope
                .identity
                .session_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
        })
        .ok_or(StoreError::InvalidField {
            field: "scope_id",
            reason: "state preview requires an exact trusted scope",
        })?;
    let scope = ScopeId::new(scope_text).map_err(|_| StoreError::InvalidField {
        field: "scope_id",
        reason: "state preview requires an exact trusted scope",
    })?;
    Ok(StateSelectors { scope, include })
}

/// Serves one admitted `eliot.state` pair as an owner-backed bounded preview.
///
/// Production state lane (issue #2564 State-first slice): claim → this
/// function → the state result submit leg, exactly like every other settled
/// branch of a daemon poller. The pair proves its closed state shape (never a
/// query), the Kernel-issued attempt binds the admitted envelope/scope/epoch/
/// facet/deadline, and the envelope fence equals the retained Kernel fence.
/// Task/scope/attention/profile facts resolve through the Governor read owner
/// (`ReadApi::bound_state` for the task/attention/affordance state reads,
/// `ReadApi::bound_query` with the exact ContextReconstruction intent for the
/// epistemic position read — the same facade split the Governor
/// reconstruction owner uses), each carrying its exact-fence dependency
/// minimums observed from the retained scope head; health/session facts are
/// the independent retained Kernel fence plus the authenticated owner session.
/// Every fact keeps its source revision/coverage identity; a fact that cannot
/// be read stays an explicit unavailable entry, never a healthy empty value.
///
/// With no selected task the bounded selection/intake discovery result is
/// returned: the trusted scope, fence, session, scope-bound attention and
/// explicit no-task selection state. No `TaskContract` is invented, and
/// authenticated discovery is never rejected merely because task binding is
/// absent.
///
/// The result body carries the governed attempt and the candidate lineage, so
/// the submit leg persists the exact bounded response through the existing
/// ORS result owner before any readback can claim a completed retained
/// result. Replay of that retained result preserves its original identity; a
/// refresh is a new admitted operation.
#[allow(
    clippy::too_many_lines,
    reason = "the state lane keeps admission binding, owner reads and preview projection in one auditable branch"
)]
pub async fn serve_admitted_state_pair(
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, StateServeError> {
    let selectors = check_state_capability(envelope, tool)
        .map_err(|_| StateServeError::InvalidInvocation)?;
    attempt
        .validate()
        .map_err(|_| StateServeError::InvalidInvocation)?;
    let retained_fence = kernel.kernel_fence();
    if envelope.state_fence != retained_fence {
        return Err(StateServeError::FenceMismatch);
    }
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.scope_id != selectors.scope.as_str()
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err(StateServeError::UnboundAttempt);
    }
    if u64::try_from(current_unix_ms()?).unwrap_or(u64::MAX) >= attempt.expires_at_unix_ms {
        return Err(StateServeError::UnboundAttempt);
    }
    let owner_session = kernel
        .owner_session_facts()
        .ok_or(StateServeError::MissingOwnerSession)?;
    if owner_session.kernel_principal.trim().is_empty() {
        return Err(StateServeError::MissingOwnerSession);
    }
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned);
    let ctx = state_read_context(envelope, task_id.as_deref(), &retained_fence)?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    let dependencies = observed_scope_dependencies(&reads, &selectors.scope, &retained_fence).await?;
    let service = ReadService::new(reads);

    // The task-bound recipe supplies the owner-declared selectors the state
    // reads address (position, skill, optional problem). It is read through
    // the one shared campaign task-plan reader, so the state lane and the
    // packet lane resolve the same authenticated owner row.
    let recipe = match task_id.as_deref() {
        Some(task) => {
            let work_scope_id = envelope
                .identity
                .work_scope_id
                .as_deref()
                .filter(|scope| !scope.trim().is_empty())
                .ok_or(StateServeError::MissingTaskBinding)?;
            let binding = CampaignPacketBinding {
                task_id: task.to_owned(),
                work_scope_id: work_scope_id.to_owned(),
                state_fence: envelope.state_fence.clone(),
            };
            Some(
                read_task_plan_recipe(kernel, &binding)
                    .await
                    .map_err(|_| StateServeError::TaskRecipeUnavailable)?
                    .0,
            )
        }
        None => None,
    };

    let mut facts = serde_json::Map::new();
    let mut unavailable = Vec::new();
    if project_fact_requested(&selectors.include, "task") {
        match task_id.as_deref() {
            Some(task) => {
                let read = read_task_fact(&service, &ctx, &selectors.scope, &dependencies, task)
                    .await
                    .map_err(StateServeError::TaskFactUnavailable)?;
                facts.insert(
                    "task".to_owned(),
                    current_fact(read).map_err(|_| StateServeError::OwnerReadUnavailable)?,
                );
            }
            None => {
                facts.insert(
                    "task".to_owned(),
                    serde_json::json!({
                        "status": "none",
                        "reason": "no task selected; discovery only",
                    }),
                );
            }
        }
    }
    if project_fact_requested(&selectors.include, "attention") {
        let problem = recipe
            .as_ref()
            .and_then(|recipe| sole_slot_member(recipe, CampaignSourceRole::TaskOpenItems));
        match read_attention_fact(&service, &ctx, &selectors.scope, &dependencies, problem.as_deref())
            .await
        {
            Ok(read) => {
                facts.insert(
                    "attention".to_owned(),
                    current_fact(read).map_err(|_| StateServeError::OwnerReadUnavailable)?,
                );
            }
            Err(reason) => unavailable.push(unavailable_fact("attention", reason)),
        }
    }
    if project_fact_requested(&selectors.include, "health") {
        facts.insert(
            "health".to_owned(),
            serde_json::json!({
                "status": "current",
                "fence": retained_fence,
                "session": "bound",
            }),
        );
    }
    if project_fact_requested(&selectors.include, "profile") {
        let epistemic = match profile_selector(
            recipe.as_ref(),
            CampaignSourceRole::CurrentPosition,
            task_id.as_deref(),
        ) {
            Ok(Some(position)) => {
                match read_epistemic_fact(&service, &ctx, &selectors.scope, &dependencies, &position)
                    .await
                {
                    Ok(read) => current_fact(read)
                        .map_err(|_| StateServeError::OwnerReadUnavailable)?,
                    Err(reason) => unavailable_fact("profile.epistemic", reason),
                }
            }
            Ok(None) => unavailable_fact("profile.epistemic", "no task selected; selector unresolvable without a task"),
            Err(reason) => unavailable_fact("profile.epistemic", reason),
        };
        let affordance = match profile_selector(
            recipe.as_ref(),
            CampaignSourceRole::ContextToolPolicy,
            task_id.as_deref(),
        ) {
            Ok(Some(skill)) => {
                match read_affordance_fact(&service, &ctx, &selectors.scope, &dependencies, &skill)
                    .await
                {
                    Ok(read) => current_fact(read)
                        .map_err(|_| StateServeError::OwnerReadUnavailable)?,
                    Err(reason) => unavailable_fact("profile.affordance", reason),
                }
            }
            Ok(None) => unavailable_fact("profile.affordance", "no task selected; selector unresolvable without a task"),
            Err(reason) => unavailable_fact("profile.affordance", reason),
        };
        facts.insert(
            "profile".to_owned(),
            serde_json::json!({"epistemic": epistemic, "affordance": affordance}),
        );
    }
    state_result_body(
        envelope,
        attempt,
        &selectors,
        task_id.as_deref(),
        facts,
        unavailable,
    )
}

/// Builds the read metadata bound to the admitted envelope and the retained
/// fence.
///
/// Mirrors the reconstruction route context: the admitted fence travels in
/// `ctx` so the facade and store gates refuse any substituted fence
/// fail-closed, and the principal the Governor read owner records is exactly
/// this product/session/task triple. The owner session itself is required by
/// the caller; its presence here is the Kernel-authenticated fact, never a
/// copied principal.
fn state_read_context(
    envelope: &HostRequestEnvelope,
    task_id: Option<&str>,
    fence: &StateFence,
) -> Result<RequestMetadata, StateServeError> {
    let operation = host_request_operation_id(envelope);
    let request_id = RequestId::new(format!("eliotd:state:{}", operation.as_str()))
        .map_err(|_| StateServeError::InvalidInvocation)?;
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .map(SessionId::new)
        .transpose()
        .map_err(|_| StateServeError::InvalidInvocation)?;
    let task = task_id
        .map(TaskId::new)
        .transpose()
        .map_err(|_| StateServeError::InvalidInvocation)?;
    let context = RequestMetadata {
        request_id,
        session_id,
        task_id: task,
        product_id: ProductId::new(super::SERVICE_NAME)
            .map_err(|_| StateServeError::InvalidInvocation)?,
        source_id: SourceId::new(super::SERVICE_NAME)
            .map_err(|_| StateServeError::InvalidInvocation)?,
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
        .map_err(|_| StateServeError::InvalidInvocation)?;
    Ok(context)
}

/// Observes the exact-fence dependency minimums for the state reads.
///
/// Reads the scope head this daemon retains for the admitted scope
/// (`GetRevisionHeads` is the one parameter-free read the audit explicitly
/// exempts) and binds every subsequent state read to the observed revision.
/// An absent, zero, duplicated or foreign-fence head is refused; nothing is
/// invented, and no empty map travels as the dependency closure.
async fn observed_scope_dependencies(
    reads: &KernelContextReadClient,
    scope: &ScopeId,
    fence: &StateFence,
) -> Result<BTreeMap<RevisionKey, u64>, StateServeError> {
    let key = RevisionKey::new(format!("scope:{}", scope.as_str()))
        .map_err(|_| StateServeError::DependencyHeadUnavailable)?;
    let heads = reads
        .revision_heads(vec![key.clone()])
        .await
        .map_err(|_| StateServeError::DependencyHeadUnavailable)?;
    let mut matching = heads.iter().filter(|head| head.key == key);
    let head = matching.next().ok_or(StateServeError::DependencyHeadUnavailable)?;
    if matching.next().is_some()
        || head.revision == 0
        || head.state_fence != *fence
        || head.validate().is_err()
    {
        return Err(StateServeError::DependencyHeadUnavailable);
    }
    let mut dependencies = BTreeMap::new();
    dependencies.insert(key, head.revision);
    Ok(dependencies)
}

/// Returns the sole owner-declared member of the recipe slot with this
/// `source_role`, or `None` when the recipe declares none.
///
/// Mirrors the reconstruction route's declared-slot reading: exactly one
/// member is the one exact selector; zero members is an unresolvable (not
/// defaulted) selector. An ambiguous declaration (several members, or several
/// slots for one role) has no single exact selector, so it reports the
/// refusal reason instead of choosing one.
fn sole_slot_member(recipe: &LearningStateViewRecipe, role: CampaignSourceRole) -> Option<String> {
    let mut matching = recipe.slots.iter().filter(|slot| slot.source_role == role);
    let spec = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    match spec.declared_members.as_slice() {
        [only] => Some(only.as_str().to_owned()),
        _ => None,
    }
}

/// Resolves one profile selector (epistemic position, affordance skill) for a
/// task-bound preview.
///
/// `Ok(None)` is the explicit no-task case: without a selected task there is
/// no authenticated recipe to resolve the selector from, so the fact stays
/// unavailable rather than fabricated. `Err` is a missing or ambiguous owner
/// declaration on a task-bound recipe: with no single exact selector, the
/// fact stays unavailable rather than addressed arbitrarily.
fn profile_selector(
    recipe: Option<&LearningStateViewRecipe>,
    role: CampaignSourceRole,
    task_id: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let (Some(recipe), Some(_)) = (recipe, task_id) else {
        return Ok(None);
    };
    sole_slot_member(recipe, role)
        .filter(|member| !member.trim().is_empty() && !member.chars().any(char::is_control))
        .map(Some)
        .ok_or("recipe declares no usable selector")
}

/// Builds one exact-fence state read over the observed dependency minimums.
///
/// The read proves its own coherence through the revision-head closure and
/// the admitted fence; the ordering declaration stays explicitly empty, which
/// the read owner records rather than leaving unstated.
fn state_request_for(
    operation: NamedReadOperation,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    parameters: BTreeMap<String, serde_json::Value>,
) -> Result<StateRequest, StateServeError> {
    let parameters = NamedParameters::from_map(parameters)
        .map_err(|_| StateServeError::OwnerReadUnavailable)?;
    Ok(StateRequest {
        operation,
        scope_id: Some(scope.clone()),
        consistency: ReadConsistency::ExactFence,
        dependency_revisions: dependencies.clone(),
        ordering: ReadOrderingBinding::without_order_dependency(),
        parameters,
        provenance_handles: Vec::new(),
    })
}

/// Builds the epistemic position query over the observed dependency minimums.
///
/// The epistemic read travels the query facade with the exact
/// ContextReconstruction intent — the same facade split the Governor
/// reconstruction owner uses for this role — never the state facade.
fn epistemic_query_for(
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    position: &str,
) -> Result<QueryRequest, StateServeError> {
    let parameters = NamedParameters::from_map(BTreeMap::from([(
        "position".to_owned(),
        serde_json::Value::String(position.to_owned()),
    )]))
    .map_err(|_| StateServeError::OwnerReadUnavailable)?;
    Ok(QueryRequest {
        intent: QueryIntent {
            mode: QueryMode::ContextReconstruction,
            time_scope: TimeScope::DeclaredFence,
            branch_environment_scope: BranchEnvironmentScope::RequestScope,
            freshness_policy: FreshnessPolicy::ExactFence,
            required_assurance: RequiredAssurance::InputReconstructionOnly,
        },
        operation: NamedReadOperation::GetCurrentEpistemicPosition,
        scope_id: Some(scope.clone()),
        consistency: ReadConsistency::ExactFence,
        dependency_revisions: dependencies.clone(),
        ordering: ReadOrderingBinding::without_order_dependency(),
        parameters,
        provenance_handles: Vec::new(),
    })
}

/// Reads the task-bound task fact and binds the echo.
///
/// The response must echo the admitted task identity in its owner payload;
/// a response answering another task is unavailable even when its operation
/// and fence match. (Bound = compared; digest = validate ORIGINAL.)
async fn read_task_fact(
    service: &ReadService<KernelContextReadClient>,
    ctx: &RequestMetadata,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    task_id: &str,
) -> Result<BoundRead<CurrentStateView>, &'static str> {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "task_id".to_owned(),
        serde_json::Value::String(task_id.to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(EVIDENCE_PACK_MAX_RECORDS.to_string()),
    );
    let request = state_request_for(
        NamedReadOperation::GetTaskState,
        scope,
        dependencies,
        parameters,
    )
    .map_err(|_| "task owner read failed closed")?;
    let read = ReadApi::bound_state(service, ctx, request)
        .await
        .map_err(|_| "task owner read failed closed")?;
    if read.view.operation != NamedReadOperation::GetTaskState
        || read.view.payload.get("task_id").and_then(serde_json::Value::as_str) != Some(task_id)
    {
        return Err("task response did not echo the admitted task");
    }
    Ok(read)
}

/// Reads the scope-bound attention fact and binds the echo.
///
/// The optional `problem_id` key is omitted entirely when no specific
/// problem is requested; a present problem must be echoed back, and an
/// unfiltered read must carry the handler's exact null.
async fn read_attention_fact(
    service: &ReadService<KernelContextReadClient>,
    ctx: &RequestMetadata,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    problem_id: Option<&str>,
) -> Result<BoundRead<CurrentStateView>, &'static str> {
    let mut parameters = BTreeMap::from([(
        "max_records".to_owned(),
        serde_json::Value::String(EVIDENCE_PACK_MAX_RECORDS.to_string()),
    )]);
    if let Some(problem) = problem_id {
        parameters.insert(
            "problem_id".to_owned(),
            serde_json::Value::String(problem.to_owned()),
        );
    }
    let request = state_request_for(
        NamedReadOperation::GetAttentionAndProblems,
        scope,
        dependencies,
        parameters,
    )
    .map_err(|_| "attention owner read failed closed")?;
    let read = ReadApi::bound_state(service, ctx, request)
        .await
        .map_err(|_| "attention owner read failed closed")?;
    let echo = read.view.payload.get("problem_id");
    let bound = match problem_id {
        Some(problem) => echo.and_then(serde_json::Value::as_str) == Some(problem),
        None => echo.map_or(true, serde_json::Value::is_null),
    };
    if read.view.operation != NamedReadOperation::GetAttentionAndProblems || !bound {
        return Err("attention response did not echo the requested problem");
    }
    Ok(read)
}

/// Reads the epistemic position fact and binds the echo.
async fn read_epistemic_fact(
    service: &ReadService<KernelContextReadClient>,
    ctx: &RequestMetadata,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    position: &str,
) -> Result<BoundRead<QueryResult>, &'static str> {
    let request = epistemic_query_for(scope, dependencies, position)
        .map_err(|_| "profile owner read failed closed")?;
    let read = ReadApi::bound_query(service, ctx, request)
        .await
        .map_err(|_| "profile owner read failed closed")?;
    if read.view.operation != NamedReadOperation::GetCurrentEpistemicPosition
        || read.view.payload.get("position").and_then(serde_json::Value::as_str) != Some(position)
    {
        return Err("profile response did not echo the requested position");
    }
    Ok(read)
}

/// Reads the affordance (capability evidence) fact and binds the echo.
async fn read_affordance_fact(
    service: &ReadService<KernelContextReadClient>,
    ctx: &RequestMetadata,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    skill_id: &str,
) -> Result<BoundRead<CurrentStateView>, &'static str> {
    let parameters = BTreeMap::from([
        (
            "skill_id".to_owned(),
            serde_json::Value::String(skill_id.to_owned()),
        ),
        (
            "max_records".to_owned(),
            serde_json::Value::String(EVIDENCE_PACK_MAX_RECORDS.to_string()),
        ),
    ]);
    let request = state_request_for(
        NamedReadOperation::GetCapabilityEvidenceState,
        scope,
        dependencies,
        parameters,
    )
    .map_err(|_| "profile owner read failed closed")?;
    let read = ReadApi::bound_state(service, ctx, request)
        .await
        .map_err(|_| "profile owner read failed closed")?;
    if read.view.operation != NamedReadOperation::GetCapabilityEvidenceState
        || read.view.payload.get("skill_id").and_then(serde_json::Value::as_str) != Some(skill_id)
    {
        return Err("profile response did not echo the requested skill");
    }
    Ok(read)
}

/// Projects one current owner read into its preview fact value.
///
/// The bound read crosses with its exact identity (operation, scope, fence,
/// dependency revisions, observed heads, coverage, invalidation), so source
/// revisions and coverage are preserved rather than flattened.
fn current_fact<V: serde::Serialize>(
    read: BoundRead<V>,
) -> Result<serde_json::Value, StateServeError> {
    let bound = serde_json::to_value(read).map_err(|_| StateServeError::OwnerReadUnavailable)?;
    Ok(serde_json::json!({"status": "current", "read": bound}))
}

/// Names one explicitly unavailable fact. The reason is a static sentence;
/// owner bytes never cross into diagnostics.
fn unavailable_fact(fact: &str, reason: &'static str) -> serde_json::Value {
    serde_json::json!({"fact": fact, "status": "unavailable", "reason": reason})
}

/// Whether one projection field is requested. An absent `include` is the
/// default full projection; a present list projects exactly its known names.
fn project_fact_requested(include: &[String], field: &str) -> bool {
    include.is_empty() || include.iter().any(|name| name == field)
}

/// Projects the served preview into the host-request result body.
///
/// The response carries the admitted scope/task/selection binding, the
/// owner-backed facts, the echoed `include` list and every unavailable entry.
/// The lineage declares the candidate result class with no semantic receipt:
/// a compiled preview is content this daemon projected from owner reads, not
/// an admitted view, admitted array, or action authority.
#[allow(
    clippy::too_many_arguments,
    reason = "the state body binds the admitted pair, the resolved selectors and the projected facts in one constructor"
)]
fn state_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    selectors: &StateSelectors,
    task_id: Option<&str>,
    facts: serde_json::Map<String, serde_json::Value>,
    unavailable: Vec<serde_json::Value>,
) -> Result<HostRequestResultBody, StateServeError> {
    let unavailable_fields: Vec<&str> = selectors
        .include
        .iter()
        .map(String::as_str)
        .filter(|name| !KNOWN_STATE_PROJECTION_FIELDS.contains(name))
        .collect();
    let response = serde_json::json!({
        "operation": "eliot.state",
        "scope_id": selectors.scope.as_str(),
        "task_id": task_id,
        "selection": {
            "selected_task": task_id,
            "task_binding": if task_id.is_some() { "current" } else { "none" },
            "session_id": envelope.identity.session_id.as_deref(),
        },
        "facts": facts,
        "unavailable": unavailable,
        "include": selectors.include,
        "unavailable_fields": unavailable_fields,
    });
    let bytes =
        canonical_json_bytes(&response).map_err(|_| StateServeError::OwnerReadUnavailable)?;
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
    body.validate()
        .map_err(|_| StateServeError::OwnerReadUnavailable)?;
    body.validate_for_submission()
        .map_err(|_| StateServeError::OwnerReadUnavailable)?;
    Ok(body)
}

fn current_unix_ms() -> Result<i64, StateServeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StateServeError::InvalidInvocation)?;
    let millis = i64::try_from(duration.as_millis())
        .map_err(|_| StateServeError::InvalidInvocation)?;
    if millis <= 0 {
        return Err(StateServeError::InvalidInvocation);
    }
    Ok(millis)
}
