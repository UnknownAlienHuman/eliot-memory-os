#![forbid(unsafe_code)]

//! Production `eliot.state` claim servicing for the current daemon (issue #1739 W5).
//!
//! This is the ONE production edge that answers a claimed State-form pair. The
//! Kernel half owns the carrier: `check_local_state_admission` content-compares
//! the presented tool bytes against the admitted payload digest, derives the
//! closed `include` selectors and the trusted scope, and retains the pair under
//! `LocalReadPairKind::State` with a fenced attempt
//! (`bins/eliot-kernel/src/host_request_route.rs`). The Kernel refuses the
//! digest-only submit entry for this capability and requires the submitted body
//! to carry the projection owner's receipt
//! (`bins/eliot-kernel/src/host_request_route/state_projection.rs::check_state_result_receipt`).
//! Nothing between those two points existed: no claim, no owner invocation, no
//! submit. This module is that missing leg.
//!
//! # The semantic owner is the Governor read owner, not this file
//!
//! Every projected field is served by issuing the real bounded named read
//! through [`eliot_read::ReadApi::state`] over
//! [`KernelContextReadClient`](crate::KernelContextReadClient) — the daemon's
//! authenticated read adapter over the Kernel `store_named` route. This module
//! resolves which closed read serves which requested field and binds the exact
//! answer; it never authors projection content. A field whose owner read does
//! not exist is refused with its exact missing interface named, never filled
//! with a placeholder (see [`StateProjectionField::Health`] and
//! [`StateProjectionError::HealthOwnerAbsent`]).
//!
//! | requested `include` field | owner read | selectors |
//! |---|---|---|
//! | `task` | `GetTaskState` | `task_id` from the admitted envelope, `max_records` at the catalogue cap |
//! | `attention` | `GetAttentionAndProblems` | `max_records` at the catalogue cap; no `problem_id` (no specific problem is requested) |
//! | `scope` | `GetScopeRevisionView` | parameter-free, `ExactFence` |
//! | `health` | none on this base | refused as [`StateProjectionError::HealthOwnerAbsent`] |
//!
//! # Selector discipline
//!
//! The `include` list is the CALLER's closed selector list and the Kernel never
//! invents one (`local_state_selectors_from_tool`). This owner resolves it
//! against the closed vocabulary below and refuses anything outside it, so no
//! MCP argument can name a field this daemon has no owner read for. An ABSENT
//! or EMPTY `include` resolves to the owner-served preview set above: an empty
//! projection would present the absence of owner data as a complete projection,
//! which is the exact failure the retained-outcome rule forbids. `task_id` is
//! never caller-supplied — it is the admitted envelope's own task identity, and
//! a `task` field with no bound task is a typed refusal
//! ([`StateProjectionError::MissingTaskBinding`]), never a task this daemon
//! picked.
//!
//! # Receipt binding
//!
//! The submitted body declares
//! [`HostRequestResultClass::ExistingEvidenceRead`] and carries NO semantic
//! receipt: a state answer is a bounded read of already-retained owner state
//! (I01-08 read path), so the protocol's own `validate_class` already refuses a
//! receipt on it and the Kernel's state gate refuses the canonical write class
//! outright. `source_revisions` carries the scope heads this daemon OBSERVED
//! through the owner read, so the Kernel's retained-result source-revision check
//! re-verifies those heads against the Store at readback instead of trusting a
//! claim.
//!
//! # Idempotence
//!
//! Nothing here retries, caches or reorders. The poller submits this exact body
//! through the existing idempotent submit helper; an exact replay re-encodes to
//! identical bytes and persists once.

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SessionId, SourceId, StateFence, TaskId,
    canonical_json_bytes, sha256_hex,
};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestResultBody,
    HostRequestResultClass, HostRequestResultLineage, HostRequestResultSourceRevision,
    LocalReadAttempt, host_request_operation_id,
};
use eliot_read::{
    BoundRead, CurrentStateView, NamedParameters, ReadApi, ReadOrderingBinding, ReadService,
    StateRequest,
};
use eliot_receipts::ProofCeiling;
use eliot_store_api::{
    CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency,
    RevisionHead, RevisionKey, ScopeId,
};
use serde_json::{Value, json};
use thiserror::Error;

use crate::SERVICE_NAME;
use crate::daemon_kernel_client::DaemonKernelClient;
use crate::kernel_context_read_client::KernelContextReadClient;

/// The one canonical tool name and capability of this row (I7.6). Single source
/// for the daemon's claim gate, its admission predicate and its result body;
/// the Kernel keeps its own closed copy in
/// `host_request_route::LOCAL_READ_STATE_CAPABILITY`.
pub const STATE_CAPABILITY: &str = "eliot.state";

/// The owner reference this daemon's state answers carry.
const PROJECTION_OWNER_REF: &str = "eliotd.state_projection_owner";

/// One closed projection field of the `eliot.state` preview and the owner read
/// that serves it.
///
/// Exhaustive over the vocabulary this owner serves: a new field is a compile
/// error at every match below until its owner read is recorded, so no
/// caller-supplied token can reach a second answer path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateProjectionField {
    /// The current authorized task frame (`GetTaskState`).
    Task,
    /// Current critical attention and conflicts (`GetAttentionAndProblems`).
    Attention,
    /// The scope's current revision view (`GetScopeRevisionView`).
    Scope,
    /// Runtime health. No activated owner read exists for it on this base; see
    /// [`StateProjectionError::HealthOwnerAbsent`].
    Health,
}

impl StateProjectionField {
    /// Stable wire label of one projection field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Attention => "attention",
            Self::Scope => "scope",
            Self::Health => "health",
        }
    }

    /// Resolves one caller-requested `include` token to its closed field.
    ///
    /// Unknown tokens are refused, never dropped: a silently ignored selector
    /// would return a projection that omits what the caller asked for while
    /// still reading as complete.
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "task" => Some(Self::Task),
            "attention" => Some(Self::Attention),
            "scope" => Some(Self::Scope),
            "health" => Some(Self::Health),
            _ => None,
        }
    }
}

/// Closed prerequisite failures of the `eliot.state` serving edge.
///
/// Every variant names the exact missing or unbound owner identity. None of
/// them carries a substitute value, and none is reachable after a read starts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StateProjectionError {
    /// The claimed pair is not the admitted `eliot.state` shape.
    #[error("request is not the admitted eliot.state shape")]
    InvalidInvocation,
    /// The Kernel-issued attempt does not close over the admitted envelope.
    #[error("attempt does not bind the admitted request, scope, epoch or deadline")]
    UnboundAttempt,
    /// The admitted envelope fence is not the retained Kernel fence.
    #[error("admitted State Fence differs from the retained Kernel fence")]
    FenceMismatch,
    /// The daemon holds no Kernel-authenticated owner session.
    #[error("no authenticated owner session is retained for this projection")]
    MissingOwnerSession,
    /// A requested projection field is outside this owner's closed vocabulary.
    #[error("requested projection field {0} has no owner read on this lane")]
    UnknownProjectionField(String),
    /// `task` was requested but the admitted envelope binds no task identity,
    /// so no `task_id` selector exists. This daemon never selects a task.
    #[error(
        "admitted request binds no task identity, so the task projection has no owner selector"
    )]
    MissingTaskBinding,
    /// The observed revision heads do not carry this scope's head.
    #[error("observed revision heads do not carry this scope's dependency head")]
    DependencyHeadUnavailable,
    /// The `health` field has no activated owner read on this base.
    ///
    /// Named precisely, never substituted: `NamedReadOperation::GetConformanceState`
    /// is declared in `crates/storage/eliot-store-api/src/lib.rs`, but the
    /// activated read catalogue
    /// (`crates/storage/eliot-store-api/src/operation_catalogue.rs::ACTIVATED_READS`)
    /// does not list it, so the read owner's own admission comparison refuses it
    /// as `ReadOutcome::NotRunning`
    /// (`crates/governor/eliot-read/src/owner_inventory.rs::compare_operation_in_catalogue`),
    /// and the daemon read adapter refuses it before transport as
    /// `StoreError::UnknownOperation`
    /// (`bins/eliotd/src/kernel_context_read_client.rs::check_execute_capability`).
    /// No substitute read is issued for it and no placeholder content is served.
    #[error(
        "no activated owner read serves the health projection: NamedReadOperation::GetConformanceState is declared but not activated in operation_catalogue.rs::ACTIVATED_READS"
    )]
    HealthOwnerAbsent,
    /// The Governor read owner refused or degraded one field's read.
    ///
    /// The owner's own typed error travels verbatim, so a refused read is never
    /// reported as an empty projection.
    #[error("governor read owner refused the {field} projection: {reason}")]
    OwnerReadRefused {
        /// Requested projection field whose read was refused.
        field: &'static str,
        /// The read owner's verbatim typed error.
        reason: String,
    },
    /// The owner read answered a different operation or fence than requested.
    #[error("governor read owner answer does not match the requested field and admitted fence")]
    OwnerAnswerMismatch,
    /// The projected response or its lineage is not serializable/valid.
    #[error("projected state response is not presentable: {0}")]
    ResponseProjection(String),
    /// A submitted state result carries no owner receipt at all.
    ///
    /// Named exactly as the Kernel's state gate refuses it
    /// (`state_projection::check_state_result_receipt`): a body with no lineage
    /// names no semantic owner, so it can never complete the operation as its
    /// retained outcome. Refused here before transport so it is never sent.
    #[error("state result carries no projection-owner receipt")]
    MissingOwnerReceipt,
    /// A submitted state result claims the canonical write-receipt class.
    ///
    /// A state answer is a bounded read of already-retained owner state
    /// (I01-08 read path), so this is a laundered read presented as an admitted
    /// canonical record. Refused here before transport, and again by the Kernel.
    #[error("state result may not claim the canonical write-receipt class")]
    LaunderedCanonicalWriteClass,
}

/// Returns whether one claimed pair is the admitted `eliot.state` request this
/// owner serves.
///
/// The predicate is the shared closed admission: the envelope capability, the
/// tool name, and an `include` member that is either absent, null, or an array
/// of unique non-blank control-free tokens. It reads no selector VALUE here;
/// each token is resolved against the closed field vocabulary by
/// [`state_projection_fields`], which is where an unknown token is refused.
#[must_use]
pub fn is_state_projection_request(envelope: &HostRequestEnvelope, tool: &Value) -> bool {
    let Some(object) = tool.as_object() else {
        return false;
    };
    if object.get("name").and_then(Value::as_str) != Some(STATE_CAPABILITY)
        || envelope.identity.capability != STATE_CAPABILITY
    {
        return false;
    }
    let Some(arguments) = object.get("arguments").and_then(Value::as_object) else {
        return false;
    };
    match arguments.get("include") {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => {
            let mut seen = std::collections::BTreeSet::new();
            items.iter().all(|item| {
                item.as_str().is_some_and(|token| {
                    !token.trim().is_empty()
                        && !token.chars().any(char::is_control)
                        && seen.insert(token)
                })
            })
        }
        Some(_) => false,
    }
}

/// Resolves the closed projection field set the admitted pair asks for.
///
/// Returns the requested fields in request order, or the owner-served preview
/// set when `include` is absent or empty. `Err` names the first token outside
/// the closed vocabulary.
pub fn state_projection_fields(
    envelope: &HostRequestEnvelope,
    tool: &Value,
) -> Result<Vec<StateProjectionField>, StateProjectionError> {
    if !is_state_projection_request(envelope, tool) {
        return Err(StateProjectionError::InvalidInvocation);
    }
    let requested = tool
        .get("arguments")
        .and_then(Value::as_object)
        .and_then(|arguments| arguments.get("include"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    if requested.is_empty() {
        return Ok(vec![
            StateProjectionField::Task,
            StateProjectionField::Attention,
            StateProjectionField::Scope,
        ]);
    }
    requested
        .iter()
        .map(|token| {
            StateProjectionField::from_token(token)
                .ok_or_else(|| StateProjectionError::UnknownProjectionField(token.clone()))
        })
        .collect()
}

/// Serves one admitted `eliot.state` pair.
///
/// Production edge: the Kernel `local_state_claim` answer → this function → the
/// existing idempotent `local_state_result` submit leg, exactly like every other
/// settled branch of the local-read poller. It proves the retained Kernel fence
/// and the fenced attempt before any owner read, then runs the owner invocation
/// over the real authenticated read adapter.
pub async fn serve_state_projection_pair(
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, StateProjectionError> {
    if !is_state_projection_request(envelope, tool) {
        return Err(StateProjectionError::InvalidInvocation);
    }
    attempt
        .validate()
        .map_err(|_| StateProjectionError::InvalidInvocation)?;
    let retained_fence = kernel.kernel_fence();
    if envelope.state_fence != retained_fence {
        return Err(StateProjectionError::FenceMismatch);
    }
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err(StateProjectionError::UnboundAttempt);
    }
    if kernel.owner_session_facts().is_none() {
        return Err(StateProjectionError::MissingOwnerSession);
    }
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    project_state_projection(reads, &retained_fence, envelope, tool, attempt).await
}

/// Runs the owner invocation for one claimed State pair over the caller-supplied
/// read client.
///
/// Split from [`serve_state_projection_pair`] on the same contour as
/// [`serve_admitted_local_read`](crate::serve_admitted_local_read) versus
/// [`forward_admitted_local_read`](crate::forward_admitted_local_read): the
/// production edge owns the live fence and session, and this function owns the
/// projection. It issues one bounded named read per requested field through the
/// Governor read owner and binds their exact answers into one receipt-bound
/// result body.
pub async fn project_state_projection<C: CanonicalReadClient>(
    reads: C,
    admitted_fence: &StateFence,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, StateProjectionError> {
    let fields = state_projection_fields(envelope, tool)?;
    if envelope.state_fence != *admitted_fence {
        return Err(StateProjectionError::FenceMismatch);
    }
    let scope = trusted_state_scope(envelope, attempt)?;
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned);
    let dependencies = observed_scope_head(&reads, &scope, admitted_fence).await?;
    let context = state_projection_context(envelope, admitted_fence)?;
    let service = ReadService::new(reads);

    let mut projection = serde_json::Map::new();
    let mut observed_heads: Vec<RevisionHead> = Vec::new();
    for field in &fields {
        let bound = read_projection_field(
            &service,
            &context,
            field,
            &scope,
            &dependencies,
            task_id.as_deref(),
        )
        .await?;
        for head in bound.identity.observed_revision_heads() {
            if !observed_heads
                .iter()
                .any(|seen: &RevisionHead| seen.key == head.key)
            {
                observed_heads.push(head.clone());
            }
        }
        projection.insert(
            (*field).as_str().to_owned(),
            json!({
                "operation": bound.view.operation,
                "state_fence": bound.view.state_fence,
                "payload": bound.view.payload,
                "revision_heads": bound.view.revision_heads,
                "provenance": bound.view.provenance,
                "consistency": bound.view.consistency,
            }),
        );
    }
    state_projection_result_body(
        envelope,
        attempt,
        &scope,
        task_id.as_deref(),
        projection,
        &observed_heads,
    )
}

/// Issues the one bounded named read that serves `field`.
///
/// `ExactFence` with the OBSERVED scope head as the declared dependency minimum,
/// and no declared conflict-serialization head: this projection's coherence is
/// proven by that scope revision head plus the admitted fence, exactly as
/// `experience_runtime::read_current_position` declares it. No order head and no
/// dependency is invented here.
async fn read_projection_field<C: CanonicalReadClient>(
    service: &ReadService<C>,
    context: &RequestMetadata,
    field: &StateProjectionField,
    scope: &ScopeId,
    dependencies: &BTreeMap<RevisionKey, u64>,
    task_id: Option<&str>,
) -> Result<BoundRead<CurrentStateView>, StateProjectionError> {
    let bound = EVIDENCE_PACK_MAX_RECORDS.to_string();
    let (operation, parameters) = match field {
        StateProjectionField::Task => {
            let task_id = task_id.ok_or(StateProjectionError::MissingTaskBinding)?;
            (
                NamedReadOperation::GetTaskState,
                named_parameters(&[("task_id", task_id.to_owned()), ("max_records", bound)])?,
            )
        }
        StateProjectionField::Attention => (
            NamedReadOperation::GetAttentionAndProblems,
            // `problem_id` is the catalogue's OPTIONAL selector and its absence
            // is the declared "no specific problem requested" contract, not a
            // defaulted identity.
            named_parameters(&[("max_records", bound)])?,
        ),
        StateProjectionField::Scope => (
            NamedReadOperation::GetScopeRevisionView,
            NamedParameters::new(),
        ),
        StateProjectionField::Health => {
            return Err(StateProjectionError::HealthOwnerAbsent);
        }
    };
    let bound = service
        .bound_state(
            context,
            StateRequest {
                operation,
                scope_id: Some(scope.clone()),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions: dependencies.clone(),
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters,
                provenance_handles: Vec::new(),
            },
        )
        .await
        .map_err(|error| StateProjectionError::OwnerReadRefused {
            field: (*field).as_str(),
            reason: error.to_string(),
        })?;
    if bound.view.operation != operation || bound.view.state_fence != context.state_fence {
        return Err(StateProjectionError::OwnerAnswerMismatch);
    }
    Ok(bound)
}

/// Projects the served fields into the receipt-bound host-request result body.
///
/// The response is the full `McpResponse` JSON the bridge serves for the
/// admitted operation: request correlation, the canonical request digest over
/// the admitted triple, the closed `eliot.state` tool name, and the exact
/// content bytes bound by `result_digest`. The shape mirrors
/// `eliot_mcp::McpResponse` field-for-field; the bridge re-parses it with
/// `deny_unknown_fields`.
fn state_projection_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    scope: &ScopeId,
    task_id: Option<&str>,
    projection: serde_json::Map<String, Value>,
    observed_heads: &[RevisionHead],
) -> Result<HostRequestResultBody, StateProjectionError> {
    let request_id = envelope.identity.request_id.as_str().to_owned();
    let idempotency_key = envelope.identity.idempotency_key.clone();
    let canonical_request_sha256 = sha256_hex(
        &canonical_json_bytes(&(
            envelope.envelope_sha256.clone(),
            request_id.clone(),
            idempotency_key.clone(),
        ))
        .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
    );
    // Derived BEFORE the response consumes the heads, so the lineage names the
    // same observed closure the content publishes.
    let source_revisions = observed_source_revisions(observed_heads);
    let response = json!({
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "canonical_request_sha256": canonical_request_sha256,
        "kind": "PROJECTION",
        "canonical_tool_name": STATE_CAPABILITY,
        "content": {
            "scope_id": scope.as_str(),
            "task_id": task_id,
            "projection": Value::Object(projection),
            "source_revision_heads": observed_heads,
            "source_state_fence": envelope.state_fence,
        },
        "artifacts": [],
        "proof_ceiling": ProofCeiling::ScopedVerification,
        "resource": null,
        "job": null,
    });
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?;
    let result_digest = sha256_hex(&bytes);
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response,
        attempt: Some(attempt.clone()),
        // A bounded read of already-retained owner state (I01-08 read path), so
        // the class is the read class and NO semantic receipt rides it: the
        // protocol's own `validate_class` refuses a receipt on a non-canonical
        // class, and the Kernel's state gate refuses the canonical write class
        // for this lane outright. `source_revisions` names the heads this daemon
        // OBSERVED through the owner read, so the Kernel re-verifies them
        // against the Store at readback instead of trusting this claim.
        lineage: Some(HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: result_digest,
            producer_ref: Some(PROJECTION_OWNER_REF.to_owned()),
            source_revisions: (!source_revisions.is_empty()).then_some(source_revisions),
            source_state_fence: Some(envelope.state_fence.clone()),
            input_refs: None,
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: None,
            semantic_receipt_ref: None,
            result_class: HostRequestResultClass::ExistingEvidenceRead,
            proof_ceiling: Some(ProofCeiling::ScopedVerification),
            influence_state: eliot_security_contracts::InfluenceState::Unknown,
            instruction_taint: None,
        }),
        // Read-only owner flight: no external effect was produced, so this leg
        // reports no effect evidence. That absence is recorded as an explicit
        // missing part by the trace manifest, never invented.
        evidence: None,
    };
    body.validate_local_read_submission()
        .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?;
    Ok(body)
}

/// Projects the OBSERVED heads into the lineage's source revisions.
///
/// Every head this daemon actually observed under this read closure is named
/// with its own fence, so the Kernel's `check_retained_source_revisions` can
/// re-read the Store's heads and refuse a replay whose source moved. A head this
/// daemon did not observe is absent from the join; it is never named.
fn observed_source_revisions(heads: &[RevisionHead]) -> Vec<HostRequestResultSourceRevision> {
    heads
        .iter()
        .map(|head| HostRequestResultSourceRevision {
            key: head.key.as_str().to_owned(),
            revision: head.revision,
            state_fence: head.state_fence.clone(),
        })
        .collect()
}

/// The trusted scope of one claimed pair, cross-checked against the attempt.
///
/// Work scope else session — never an MCP argument — mirroring the Kernel's own
/// `local_state_selectors_from_tool` derivation, and compared with the
/// Kernel-minted `attempt.scope_id` so the two implementations cannot drift.
fn trusted_state_scope(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
) -> Result<ScopeId, StateProjectionError> {
    let work_scope = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control));
    let scope_text = work_scope.or_else(|| {
        envelope
            .identity
            .session_id
            .as_deref()
            .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control))
    });
    let scope = ScopeId::new(
        scope_text
            .ok_or(StateProjectionError::InvalidInvocation)?
            .to_owned(),
    )
    .map_err(|_| StateProjectionError::InvalidInvocation)?;
    if scope.as_str() != attempt.scope_id {
        return Err(StateProjectionError::UnboundAttempt);
    }
    Ok(scope)
}

/// Turns the observed scope head into the exact-fence dependency minimum.
///
/// The key is the store's own scope head key, read through the one
/// catalogue-activated `GetRevisionHeads` operation over the same authenticated
/// route the rest of this projection uses. The store projects only the requested
/// keys back, so an absent, zero, duplicated or foreign-fence head is refused;
/// nothing is invented, and no other answer on this route can supply a
/// dependency revision.
async fn observed_scope_head<C: CanonicalReadClient>(
    reads: &C,
    scope: &ScopeId,
    fence: &StateFence,
) -> Result<BTreeMap<RevisionKey, u64>, StateProjectionError> {
    let key = RevisionKey::new(format!("scope:{}", scope.as_str()))
        .map_err(|_| StateProjectionError::DependencyHeadUnavailable)?;
    let mut matching = reads
        .revision_heads(vec![key.clone()])
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "eliotd.state_projection.scope_head");
            StateProjectionError::DependencyHeadUnavailable
        })?
        .into_iter()
        .filter(|head| head.key == key);
    let head = matching
        .next()
        .ok_or(StateProjectionError::DependencyHeadUnavailable)?;
    if matching.next().is_some()
        || head.revision == 0
        || head.state_fence != *fence
        || head.validate().is_err()
    {
        return Err(StateProjectionError::DependencyHeadUnavailable);
    }
    let mut dependencies = BTreeMap::new();
    dependencies.insert(key, head.revision);
    Ok(dependencies)
}

/// Builds the read metadata bound to the admitted envelope and its fence.
///
/// The principal the Governor read owner records is exactly
/// `ReadPrincipal::from_metadata(ctx)`: this product/source pair, the admitted
/// caller session and the admitted task. Nothing here mints an identity.
fn state_projection_context(
    envelope: &HostRequestEnvelope,
    fence: &StateFence,
) -> Result<RequestMetadata, StateProjectionError> {
    let operation = host_request_operation_id(envelope);
    let context = RequestMetadata {
        request_id: RequestId::new(format!("eliotd:state-projection:{}", operation.as_str()))
            .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
        session_id: envelope
            .identity
            .session_id
            .as_deref()
            .map(SessionId::new)
            .transpose()
            .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
        task_id: envelope
            .identity
            .task_id
            .as_deref()
            .map(TaskId::new)
            .transpose()
            .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
        source_id: SourceId::new(SERVICE_NAME)
            .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?,
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
        .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))?;
    Ok(context)
}

/// Builds one closed selector map from the catalogue-declared selectors only.
fn named_parameters(entries: &[(&str, String)]) -> Result<NamedParameters, StateProjectionError> {
    NamedParameters::from_map(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), Value::String(value.clone())))
            .collect(),
    )
    .map_err(|error| StateProjectionError::ResponseProjection(error.to_string()))
}

/// Producer-side preflight for one submitted `eliot.state` result (issue #1739 W5).
///
/// The same rule the Kernel's state gate owns
/// (`bins/eliot-kernel/src/host_request_route/state_projection.rs::check_state_result_receipt`),
/// applied on this side of the transport so a body this daemon cannot honestly
/// claim is never put on the wire. It only ever refuses, and it refuses exactly
/// what the Kernel refuses:
///
/// 1. No lineage at all. The state answer is produced by a semantic owner
///    flight, so its lineage is the producer's owner receipt bound to the exact
///    result digest by `HostRequestResultBody::validate`. A receiptless body
///    names no owner, could never complete the operation as its retained
///    outcome, and must not be sent as if it could.
/// 2. The canonical write-receipt class. A state answer is a bounded read of
///    already-retained owner state (I01-08 read path), so presenting it as an
///    admitted canonical record would launder a read into a write.
///
/// Pure: validation performs no IO by construction. Called by
/// `crate::DaemonKernelClient::submit_local_state_result_async` before the
/// result leg touches the transport, so the Kernel's gate stays the authority
/// and this one only ever refuses earlier.
pub fn check_state_result_receipt(
    body: &HostRequestResultBody,
) -> Result<(), StateProjectionError> {
    if body.lineage.is_none() {
        return Err(StateProjectionError::MissingOwnerReceipt);
    }
    if body.lineage.as_ref().is_some_and(|lineage| {
        lineage.result_class == HostRequestResultClass::CanonicalWriteReceipt
    }) {
        return Err(StateProjectionError::LaunderedCanonicalWriteClass);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]
mod state_projection_tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestIdentity, HostRequestKind, LOCAL_READ_ATTEMPT_WIRE_ID,
    };
    use eliot_store_api::{
        NamedReadRequest, NamedReadResponse, OrderingHead, OrderingScopeId, ScopeRevisionView,
        StoreError,
    };

    use super::*;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_SCOPE: &str = "scope-alpha";
    const TEST_TASK: &str = "task-alpha";

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn test_fence(generation: u64) -> TestResult<StateFence> {
        let lineage =
            EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
        let sequence = NonZeroU64::new(1).ok_or("non-zero test sequence")?;
        let epoch = EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}"))?;
        let generation =
            ResourceGeneration::new(generation).map_err(|error| format!("generation: {error}"))?;
        Ok(StateFence::new(epoch, generation))
    }

    fn tool_digest(tool: &Value) -> TestResult<String> {
        let bytes =
            canonical_json_bytes(tool).map_err(|error| format!("canonical tool bytes: {error}"))?;
        Ok(sha256_hex(&bytes))
    }

    fn state_tool(include: Option<&[&str]>) -> Value {
        let mut arguments = serde_json::Map::new();
        if let Some(include) = include {
            arguments.insert(
                "include".to_owned(),
                Value::Array(
                    include
                        .iter()
                        .map(|token| Value::String((*token).to_owned()))
                        .collect(),
                ),
            );
        }
        json!({"name": STATE_CAPABILITY, "arguments": Value::Object(arguments)})
    }

    /// The admitted envelope exactly as the bridge builds it for this row: the
    /// canonical tool bytes are the payload, the scope is the work scope, and
    /// the task is the authenticated task.
    fn test_envelope(tool: &Value) -> TestResult<HostRequestEnvelope> {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-state-1")
                    .map_err(|error| format!("request id: {error}"))?,
                correlation_projection: None,
                idempotency_key: "host-request-state-1:invoke".to_owned(),
                cancellation_id: "host-request-state-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: STATE_CAPABILITY.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: Some(TEST_TASK.to_owned()),
                work_scope_id: Some(TEST_SCOPE.to_owned()),
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: tool_digest(tool)?,
            },
            state_fence: test_fence(1)?,
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| format!("envelope digest: {error}").into())
    }

    /// The fenced attempt exactly as the Kernel claim record mints it.
    fn test_attempt(envelope: &HostRequestEnvelope) -> TestResult<LocalReadAttempt> {
        let operation_id = host_request_operation_id(envelope);
        let attempt = LocalReadAttempt {
            wire_id: LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            attempt_id: format!("{operation_id}:attempt:state-e2e:3:1"),
            fencing_generation: 1,
            session_id: "kernel-session-1".to_owned(),
            authority_epoch: envelope.state_fence.authority_epoch.clone(),
            scope_id: TEST_SCOPE.to_owned(),
            facet_method: STATE_CAPABILITY.to_owned(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        };
        attempt
            .validate()
            .map_err(|error| format!("attempt must validate: {error}"))?;
        Ok(attempt)
    }

    /// The `local_state_claim` answer shape the Kernel arm answers, carrying the
    /// retained carrier `form` alongside the envelope, tool and attempt.
    fn state_claim_answer(
        envelope: &HostRequestEnvelope,
        tool: &Value,
        attempt: &LocalReadAttempt,
    ) -> Value {
        json!({"pair": {
            "form": "state",
            "envelope": envelope,
            "tool": tool,
            "attempt": attempt,
        }})
    }

    /// Hermetic owner store for this route. Every response field is derived from
    /// the incoming request — real request validation, the closed named
    /// operation, exact fence equality, and the declared selectors — so the
    /// projection the daemon publishes is the owner's answer, not a fixture the
    /// daemon could have invented.
    struct OwnerProjectionStore {
        fence: StateFence,
    }

    impl OwnerProjectionStore {
        fn new(fence: StateFence) -> Self {
            Self { fence }
        }

        fn scope_key() -> RevisionKey {
            RevisionKey::new(format!("scope:{TEST_SCOPE}")).expect("scope head key")
        }

        fn scope_head(&self) -> RevisionHead {
            RevisionHead {
                key: Self::scope_key(),
                revision: 3,
                state_fence: self.fence.clone(),
            }
        }

        /// Reads the exact closed selectors this route declares, refusing a
        /// parameter that the store catalogue does not declare for the operation.
        fn selectors(
            query: &NamedReadRequest,
            required: &[&str],
        ) -> Result<BTreeMap<String, Value>, StoreError> {
            for key in required {
                if !query.parameters.contains_key(*key) {
                    return Err(StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "the named read declares no value for a required selector",
                    });
                }
            }
            Ok(query.parameters.clone())
        }
    }

    #[allow(async_fn_in_trait)]
    impl CanonicalReadClient for OwnerProjectionStore {
        async fn revision_heads(
            &self,
            keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            Ok(keys
                .into_iter()
                .filter(|key| *key == Self::scope_key())
                .map(|key| RevisionHead {
                    key,
                    revision: 3,
                    state_fence: self.fence.clone(),
                })
                .collect())
        }

        async fn execute_named(
            &self,
            query: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            query.validate()?;
            if query.state_fence != self.fence {
                return Err(StoreError::FenceMismatch);
            }
            if query.scope_id.is_none() {
                return Err(StoreError::InvalidField {
                    field: "scope_id",
                    reason: "the state projection reads are scope-bound",
                });
            }
            let revision_heads = vec![self.scope_head()];
            let payload = match query.operation {
                NamedReadOperation::GetTaskState => {
                    let selectors = Self::selectors(&query, &["task_id", "max_records"])?;
                    json!({
                        "version": 1,
                        "scope_id": query.scope_id.as_ref().map(ScopeId::as_str),
                        "task_id": selectors.get("task_id"),
                        "records": [{"task_id": TEST_TASK, "state": "active"}],
                    })
                }
                NamedReadOperation::GetAttentionAndProblems => {
                    let selectors = Self::selectors(&query, &["max_records"])?;
                    json!({
                        "version": 1,
                        "scope_id": query.scope_id.as_ref().map(ScopeId::as_str),
                        "records": [{"problem_id": "problem-alpha", "severity": "critical"}],
                        "requested_bound": selectors.get("max_records"),
                    })
                }
                NamedReadOperation::GetScopeRevisionView => {
                    if !query.parameters.is_empty() {
                        return Err(StoreError::InvalidField {
                            field: "operation.parameters",
                            reason: "GetScopeRevisionView takes no parameters",
                        });
                    }
                    serde_json::to_value(ScopeRevisionView {
                        scope_id: query.scope_id.clone().expect("scope checked above"),
                        revision_heads: revision_heads.clone(),
                        ordering_heads: vec![OrderingHead {
                            // `OrderingScopeId::new` already answers
                            // `Result<_, StoreError>`, so its typed refusal
                            // propagates verbatim rather than being restated.
                            scope: OrderingScopeId::new(TEST_SCOPE)?,
                            sequence: 1,
                            state_fence: self.fence.clone(),
                        }],
                        state_fence: self.fence.clone(),
                    })
                    .map_err(|error| StoreError::Serialization(error.to_string()))?
                }
                // `health` has no activated owner read on this base. The store
                // refuses it exactly as the catalogue does, so a test can never
                // pass by having a stand-in answer.
                _ => return Err(StoreError::UnknownOperation),
            };
            let response = NamedReadResponse {
                operation: query.operation,
                state_fence: self.fence.clone(),
                revision_heads,
                payload,
            };
            response.validate()?;
            Ok(response)
        }
    }

    /// Asserts the owner's receipt on `body`: present, binding the exact result
    /// bytes, in the READ class, with no semantic receipt, and naming both the
    /// fence the owner read under and the scope head it actually observed.
    fn assert_owner_receipt_binds_the_read(
        body: &HostRequestResultBody,
        envelope: &HostRequestEnvelope,
    ) {
        let lineage = body
            .lineage
            .as_ref()
            .expect("the owner receipt must ride the result");
        assert_eq!(
            lineage.output_digest, body.result_digest,
            "the receipt binds the exact result bytes"
        );
        assert_eq!(
            lineage.result_class,
            HostRequestResultClass::ExistingEvidenceRead,
            "a state answer is a read of already-retained owner state"
        );
        assert_eq!(
            lineage.semantic_receipt_ref, None,
            "a read projection carries no semantic receipt"
        );
        assert_eq!(
            lineage.source_state_fence.as_ref(),
            Some(&envelope.state_fence),
            "the receipt names the fence the owner read under"
        );
        let revisions = lineage
            .source_revisions
            .as_ref()
            .expect("the observed scope head is the causal join");
        assert!(
            revisions
                .iter()
                .any(|revision| revision.key == format!("scope:{TEST_SCOPE}")
                    && revision.revision == 3),
            "the receipt names the scope head the owner observed, not one the daemon invented"
        );
    }

    /// Positive case (#1739 W5): a real claimed State pair, served by the real
    /// production owner invocation over a real store-backed read client, produces
    /// a receipt-bound result body that validates for submission and reads back
    /// with the exact owner projection. The refusal case follows in the second
    /// test.
    #[tokio::test]
    async fn claimed_state_pair_reaches_its_owner_and_binds_the_owner_receipt() -> TestResult {
        let fence = test_fence(1)?;
        let tool = state_tool(Some(&["task", "attention", "scope"]));
        let envelope = test_envelope(&tool)?;
        let attempt = test_attempt(&envelope)?;

        // The claim leg: the exact `local_state_claim` answer parses to the
        // admitted pair plus its Kernel-minted fenced attempt.
        let claim = state_claim_answer(&envelope, &tool, &attempt);
        let (claimed_envelope, claimed_tool, claimed_attempt) =
            crate::parse_local_read_claimed_pair(&claim)
                .map_err(|error| format!("claim must parse: {error}"))?
                .ok_or("a queued state pair must claim")?;
        assert_eq!(claimed_envelope.envelope_sha256, envelope.envelope_sha256);
        assert_eq!(
            claimed_tool, tool,
            "the claim returns the exact retained tool bytes"
        );
        assert_eq!(
            claimed_attempt, attempt,
            "the claim returns the exact fenced attempt"
        );
        assert_eq!(
            crate::parse_local_read_claimed_pair(&json!({ "pair": null }))
                .map_err(|error| format!("empty claim must not fail: {error}"))?,
            None,
            "an empty claim polls null and backs off"
        );

        // The owner invocation: one bounded named read per requested field,
        // through the production read owner over the authenticated read client.
        let store = OwnerProjectionStore::new(fence.clone());
        let body = project_state_projection(store, &fence, &envelope, &tool, &attempt)
            .await
            .map_err(|error| format!("the owner must serve the claimed pair: {error}"))?;

        // The result is bound to THIS operation and presented under the CURRENT
        // attempt, exactly as the submit leg requires.
        assert_eq!(body.operation_id, host_request_operation_id(&envelope));
        assert_eq!(body.request_sha256, envelope.envelope_sha256);
        assert_eq!(body.attempt.as_ref(), Some(&attempt));
        body.validate_local_read_submission()
            .map_err(|error| format!("the owner's result must validate for submission: {error}"))?;

        // The owner's receipt is present, binds the exact result bytes, and is the
        // READ class: a bounded read of already-retained owner state, with no
        // semantic receipt.
        assert_owner_receipt_binds_the_read(&body, &envelope);
        check_state_result_receipt(&body).map_err(|error| {
            format!("the owner result must pass the receipt preflight: {error}")
        })?;

        // The ordinary readback: the stored response IS the bounded MCP
        // projection for THIS request, with the exact correlation triple and the
        // closed canonical tool name the bridge serves.
        let response = &body.response;
        assert_eq!(
            response["request_id"],
            envelope.identity.request_id.as_str()
        );
        assert_eq!(
            response["idempotency_key"],
            envelope.identity.idempotency_key
        );
        assert_eq!(response["canonical_tool_name"], STATE_CAPABILITY);
        assert_eq!(response["kind"], "PROJECTION");
        let expected_request_digest = sha256_hex(&canonical_json_bytes(&(
            envelope.envelope_sha256.clone(),
            envelope.identity.request_id.as_str().to_owned(),
            envelope.identity.idempotency_key.clone(),
        ))?);
        assert_eq!(
            response["canonical_request_sha256"], expected_request_digest,
            "the projection echoes the canonical request digest over the admitted triple"
        );
        let projection = &response["content"]["projection"];
        assert_eq!(projection["task"]["operation"], "GetTaskState");
        assert_eq!(
            projection["task"]["payload"]["records"][0]["state"], "active",
            "the task projection is the owner read's answer, not daemon-authored content"
        );
        assert_eq!(
            projection["attention"]["operation"],
            "GetAttentionAndProblems"
        );
        assert_eq!(
            projection["attention"]["payload"]["records"][0]["problem_id"], "problem-alpha",
            "the attention projection is the owner read's answer"
        );
        assert_eq!(projection["scope"]["operation"], "GetScopeRevisionView");

        // Exact replay is byte-stable, so a lost acknowledgement or a restart
        // resubmits the identical receipt-bound body and persists once.
        let once = serde_json::to_value(&body)?;
        let twice = serde_json::to_value(&body)?;
        assert_eq!(
            once, twice,
            "an exact replay carries byte-identical material"
        );
        let replayed: HostRequestResultBody = serde_json::from_value(twice)?;
        replayed
            .validate_local_read_submission()
            .map_err(|error| format!("a replayed owner result must still validate: {error}"))?;
        assert_eq!(replayed.result_digest, body.result_digest);
        Ok(())
    }

    /// Refusal case (#1739 W5): a receiptless state result and a laundered
    /// canonical-write class are both refused before transport and never persist;
    /// a request naming a field with no owner read is refused with that exact
    /// absence named rather than answered with a placeholder.
    #[tokio::test]
    async fn state_result_without_the_owner_receipt_is_refused_and_never_persists() -> TestResult {
        let fence = test_fence(1)?;
        let tool = state_tool(Some(&["task", "scope"]));
        let envelope = test_envelope(&tool)?;
        let attempt = test_attempt(&envelope)?;
        let store = OwnerProjectionStore::new(fence.clone());
        let body = project_state_projection(store, &fence, &envelope, &tool, &attempt).await?;
        assert!(
            check_state_result_receipt(&body).is_ok(),
            "the owner's own result carries its receipt"
        );

        // A receiptless presentation of the owner's exact bytes: no lineage at
        // all. It names no semantic owner, so it can never complete the row.
        let mut receiptless = body.clone();
        receiptless.lineage = None;
        assert!(
            check_state_result_receipt(&receiptless).is_err(),
            "a receiptless state result must be refused before transport"
        );
        // The wire contract refuses it too, so the refusal is not only a
        // daemon-side convention.
        assert!(
            receiptless.validate_local_read_submission().is_err(),
            "a receiptless state result is not a valid submission"
        );

        // A laundered canonical write receipt: a read projection presented as an
        // admitted canonical record.
        let mut laundered = body.clone();
        if let Some(lineage) = laundered.lineage.as_mut() {
            lineage.result_class = HostRequestResultClass::CanonicalWriteReceipt;
            lineage.semantic_receipt_ref = Some("write-receipt-1".to_owned());
        }
        assert!(
            check_state_result_receipt(&laundered).is_err(),
            "a state result claiming the canonical write-receipt class must be refused"
        );
        // Only the owner-receipted presentation may be the submitted answer, so
        // the refusals above can never become the durable row.
        assert_eq!(
            body.lineage
                .as_ref()
                .map(|lineage| lineage.output_digest.clone()),
            Some(body.result_digest.clone()),
            "the retained outcome is the owner-receipted presentation alone"
        );

        // `health` has no activated owner read on this base: the request is
        // refused by name, and no substitute read or placeholder content is
        // served for it.
        let health_tool = state_tool(Some(&["health"]));
        let health_envelope = test_envelope(&health_tool)?;
        let health_attempt = test_attempt(&health_envelope)?;
        let health_store = OwnerProjectionStore::new(fence.clone());
        let refused = project_state_projection(
            health_store,
            &fence,
            &health_envelope,
            &health_tool,
            &health_attempt,
        )
        .await;
        assert!(
            matches!(refused, Err(StateProjectionError::HealthOwnerAbsent)),
            "a health projection must be refused with its absent owner named, got {refused:?}"
        );

        // A token outside the closed field vocabulary is refused rather than
        // dropped, so a projection never silently omits what the caller asked.
        let unknown_tool = state_tool(Some(&["task", "weather"]));
        let unknown_envelope = test_envelope(&unknown_tool)?;
        assert!(matches!(
            state_projection_fields(&unknown_envelope, &unknown_tool),
            Err(StateProjectionError::UnknownProjectionField(field)) if field == "weather",
        ));
        Ok(())
    }
}
