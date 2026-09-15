//! T11.3 `ContextReconstruction` behavior test (slice C: read/daemon/MCP wiring).
//!
//! One task-bound `ContextReconstruction` request returns all seven provider
//! role dispositions plus the activation evidence from one real admitted
//! exact binding with zero graph edges; a second read after source/fence
//! invalidation rebuilds or reports stale (never serving the previous
//! generation as current); one unsupported/missing role is reported
//! distinctly from an authoritative `KnownEmpty`.
//!
//! The store side is a minimal in-test [`CanonicalReadClient`] modelling the
//! part-B-activated handler surface for the six role-source reads with the
//! production rule order: request validation, operation capability, fence
//! equality, scope declaration, closed selector shape, then request-derived
//! payloads. The evidence path additionally runs the real generated catalogue
//! pre-gate (activated at base); the four T11.3 reads skip only that pre-gate
//! because the base manifest does not activate them yet — their facade gate
//! (`QueryMode::ContextReconstruction`), daemon capability, and catalogue
//! admission reporting are proved in their owning packages. Every asserted
//! record is captured through the table's capture methods and every response
//! field derives from the request inputs; nothing is canned and no admission
//! receipt is fabricated or injected.
//!
//! Role-to-read binding follows the T11 acquisition table: task frame from
//! `GetTaskState`, critical attention from `GetAttentionAndProblems`, the
//! activation evidence from `GetCurrentEpistemicPosition`, cue activation and
//! negative memory from one `GetUnderstandingProjectionInputs` read through
//! distinct closed sections, evidence from `GetEvidencePack`, and affordances
//! from `GetCapabilityEvidenceState`. The table stores flat exact-bound
//! records addressed by `(scope, subject)` only: there is no relation-edge
//! index, and any smuggled edge/graph selector fails closed.

#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "T11.3 behavior test: every asserted role, fence, generation, and disposition derives from captured records and request inputs; nothing is canned"
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_read::{QueryIntent, QueryMode, QueryRequest, ReadApi, ReadError, ReadService};
use eliot_store_api::{
    CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, ReadConsistency, RevisionHead, RevisionKey, ScopeId, StoreError,
    generated_operation_manifests,
};
use serde_json::{Value, json};

/// Payload-shape version minted by the in-test reconstruction table below.
/// Local to the test double; load-bearing assertions compare request-derived
/// identity, fence, generation, and disposition fields.
const TEST_RECONSTRUCTION_VERSION: u32 = 1;

/// Drives the read facade without an async runtime (this crate has none):
/// every test future is immediately ready because the in-test client performs
/// no I/O.
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut pinned = Box::pin(future);
    loop {
        match pinned.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let sequence = NonZeroU64::new(sequence).ok_or(StoreError::InvalidField {
        field: "test.sequence",
        reason: "must be non-zero",
    })?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn fence(generation: u64) -> Result<StateFence, Box<dyn std::error::Error>> {
    Ok(StateFence::new(
        test_epoch(1)?,
        ResourceGeneration::new(generation)?,
    ))
}

fn metadata(fence: &StateFence, tag: &str) -> Result<RequestMetadata, Box<dyn std::error::Error>> {
    Ok(RequestMetadata {
        request_id: RequestId::new(format!("request-reconstruction-{tag}"))?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-reconstruction")?,
        source_id: SourceId::new("source-reconstruction")?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
    })
}

fn reconstruction_intent() -> QueryIntent {
    QueryIntent {
        mode: QueryMode::ContextReconstruction,
        time_scope: "task window for reconstruction".to_owned(),
        branch_environment_scope: "test branch and environment".to_owned(),
        freshness_policy: "exact admitted generation only".to_owned(),
        required_assurance: "reconstruction input read".to_owned(),
    }
}

fn reconstruction_query(
    operation: NamedReadOperation,
    scope: Option<&str>,
    parameters: BTreeMap<String, Value>,
) -> Result<QueryRequest, StoreError> {
    let mut dependencies = BTreeMap::new();
    dependencies.insert(RevisionKey::new("scope:scope-task-7")?, 1);
    Ok(QueryRequest {
        intent: reconstruction_intent(),
        operation,
        query: "reconstruct the exact task-bound context".to_owned(),
        exact_resource_uri: None,
        scope_id: scope.map(ScopeId::new).transpose()?,
        consistency: ReadConsistency::ExactFence,
        dependency_revisions: dependencies,
        parameters,
        provenance_handles: Vec::new(),
    })
}

fn evidence_parameters(subject: &str, max_records: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("subject".to_owned(), Value::String(subject.to_owned())),
        (
            "max_records".to_owned(),
            Value::String(max_records.to_owned()),
        ),
    ])
}

fn position_parameters(position: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([("position".to_owned(), Value::String(position.to_owned()))])
}

/// Minimal in-test reconstruction table modelling the part-B-activated store
/// surface for the six role-source reads. Flat exact-bound records addressed
/// by `(scope, subject)` only — no relation-edge index exists, so the
/// reconstruction traverses zero graph edges by construction. The
/// negative-memory provider section is deliberately left unbound (`None`) to
/// prove the missing-role disposition against the authoritative-known-empty
/// attention role.
struct ReconstructionTableClient {
    fence: StateFence,
    tasks: BTreeMap<String, String>,
    problems: BTreeMap<String, Vec<String>>,
    cue_inputs: BTreeMap<String, Vec<String>>,
    negative_memory: BTreeMap<String, Option<Vec<String>>>,
    evidence: Vec<String>,
    positions: BTreeMap<String, String>,
    capabilities: BTreeMap<String, Vec<String>>,
}

impl ReconstructionTableClient {
    fn new(fence: StateFence) -> Self {
        Self {
            fence,
            tasks: BTreeMap::new(),
            problems: BTreeMap::new(),
            cue_inputs: BTreeMap::new(),
            negative_memory: BTreeMap::new(),
            evidence: Vec::new(),
            positions: BTreeMap::new(),
            capabilities: BTreeMap::new(),
        }
    }

    fn capture_task(&mut self, scope: &str, task_id: &str) {
        self.tasks.insert(scope.to_owned(), task_id.to_owned());
    }

    fn capture_cue_input(&mut self, scope: &str, cue: &str) {
        self.cue_inputs
            .entry(scope.to_owned())
            .or_default()
            .push(cue.to_owned());
    }

    fn bind_negative_memory(&mut self, scope: &str, records: Option<Vec<String>>) {
        self.negative_memory.insert(scope.to_owned(), records);
    }

    fn capture_evidence(&mut self, subject: &str) {
        self.evidence.push(subject.to_owned());
    }

    fn capture_position(&mut self, scope: &str, position: &str) {
        self.positions
            .insert(scope.to_owned(), position.to_owned());
    }

    fn capture_capability(&mut self, scope: &str, affordance: &str) {
        self.capabilities
            .entry(scope.to_owned())
            .or_default()
            .push(affordance.to_owned());
    }

    fn scope_key(scope: &ScopeId) -> Result<RevisionKey, StoreError> {
        RevisionKey::new(format!("scope:{scope}"))
    }

    fn scope_head(&self, scope: &ScopeId) -> Result<RevisionHead, StoreError> {
        Ok(RevisionHead {
            key: Self::scope_key(scope)?,
            revision: 1,
            state_fence: self.fence.clone(),
        })
    }

    fn respond(
        &self,
        request: &NamedReadRequest,
        scope: &ScopeId,
        payload: Value,
    ) -> Result<NamedReadResponse, StoreError> {
        let response = NamedReadResponse {
            operation: request.operation,
            state_fence: self.fence.clone(),
            revision_heads: vec![self.scope_head(scope)?],
            payload,
        };
        response.validate()?;
        Ok(response)
    }

    fn task_payload(&self, scope: &ScopeId) -> Result<Value, StoreError> {
        let task_id = self
            .tasks
            .get(scope.as_str())
            .ok_or(StoreError::Empty { field: "task" })?;
        Ok(json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "scope_id": scope.as_str(),
            "task_id": task_id,
            "generation": self.fence.resource_generation.value(),
        }))
    }

    fn attention_payload(&self, scope: &ScopeId) -> Value {
        let problems: &[String] = self
            .problems
            .get(scope.as_str())
            .map_or(&[], Vec::as_slice);
        json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "scope_id": scope.as_str(),
            "problems": problems,
            "complete": true,
            "generation": self.fence.resource_generation.value(),
        })
    }

    fn understanding_payload(&self, scope: &ScopeId) -> Value {
        let cues: &[String] = self
            .cue_inputs
            .get(scope.as_str())
            .map_or(&[], Vec::as_slice);
        let negative = self.negative_memory.get(scope.as_str()).and_then(|bound| {
            bound
                .as_ref()
                .map(|records| Value::Array(records.iter().map(|record| json!(record)).collect()))
        });
        json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "scope_id": scope.as_str(),
            "cue_inputs": cues,
            "negative_memory": negative,
            "complete": true,
            "generation": self.fence.resource_generation.value(),
        })
    }

    fn capability_payload(&self, scope: &ScopeId) -> Value {
        let affordances: &[String] = self
            .capabilities
            .get(scope.as_str())
            .map_or(&[], Vec::as_slice);
        json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "scope_id": scope.as_str(),
            "affordances": affordances,
            "complete": true,
            "generation": self.fence.resource_generation.value(),
        })
    }

    fn evidence_payload(
        &self,
        request: &NamedReadRequest,
        scope: &ScopeId,
    ) -> Result<Value, StoreError> {
        // Same rule order as the production adapters: catalogue gate, scope
        // declaration, selector shape, explicit bound.
        let entries = generated_operation_manifests()?;
        request.validate_against_catalogue(&entries)?;
        let subject = request
            .parameters
            .get("subject")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            })?;
        if subject.trim().is_empty() || subject.chars().any(char::is_control) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "subject must be a non-blank string",
            });
        }
        let bound_raw = request
            .parameters
            .get("max_records")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            })?;
        let max_records: u32 = bound_raw.parse().map_err(|_| StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must be a positive decimal bound",
        })?;
        if max_records == 0 || max_records > EVIDENCE_PACK_MAX_RECORDS {
            return Err(StoreError::PayloadTooLarge);
        }
        let limit = usize::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)?;
        let matched_total = self.evidence.iter().filter(|captured| captured.as_str() == subject).count();
        let records: Vec<Value> = self
            .evidence
            .iter()
            .filter(|captured| captured.as_str() == subject)
            .take(limit)
            .map(|captured| {
                json!({
                    "operation": "CaptureObservation",
                    "subject": captured,
                })
            })
            .collect();
        let returned = records.len();
        Ok(json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "subject": subject,
            "scope_id": scope.as_str(),
            "records": records,
            "provenance": {
                "state_fence": self.fence,
                "matched_total": matched_total,
                "returned": returned,
                "max_records": max_records,
                "truncated": matched_total > returned,
            },
            "generation": self.fence.resource_generation.value(),
        }))
    }

    fn position_payload(
        &self,
        request: &NamedReadRequest,
        scope: &ScopeId,
    ) -> Result<Value, StoreError> {
        let entries = generated_operation_manifests()?;
        request.validate_against_catalogue(&entries)?;
        let position = request
            .parameters
            .get("position")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "position must be a non-blank string",
            })?;
        let admitted = self
            .positions
            .get(scope.as_str())
            .ok_or(StoreError::Empty {
                field: "position",
            })?;
        if admitted.as_str() != position {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "position selector does not match the admitted position",
            });
        }
        Ok(json!({
            "version": TEST_RECONSTRUCTION_VERSION,
            "scope_id": scope.as_str(),
            "position": admitted,
            "generation": self.fence.resource_generation.value(),
        }))
    }
}

impl CanonicalReadClient for ReconstructionTableClient {
    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        keys.into_iter()
            .map(|key| {
                Ok(RevisionHead {
                    key,
                    revision: 1,
                    state_fence: self.fence.clone(),
                })
            })
            .collect()
    }

    async fn execute_named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        request.validate()?;
        // The four T11.3 reads skip only the generated-catalogue pre-gate
        // (the base manifest activates them in a Store-owned slice); every
        // other production rule — capability, fence equality, scope
        // declaration, closed selector shape — applies exactly.
        if !matches!(
            request.operation,
            NamedReadOperation::GetTaskState
                | NamedReadOperation::GetAttentionAndProblems
                | NamedReadOperation::GetUnderstandingProjectionInputs
                | NamedReadOperation::GetCapabilityEvidenceState
                | NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetCurrentEpistemicPosition
        ) {
            return Err(StoreError::UnknownOperation);
        }
        if request.state_fence != self.fence {
            return Err(StoreError::FenceMismatch);
        }
        let scope = request.scope_id.clone().ok_or(StoreError::InvalidField {
            field: "scope_id",
            reason: "reconstruction read requires scope_id",
        })?;
        // Closed selector shape per the catalogue: the four T11.3 reads
        // declare no parameters, so any supplied key (including an edge or
        // graph selector) fails closed here before any record is touched.
        match request.operation {
            NamedReadOperation::GetTaskState
            | NamedReadOperation::GetAttentionAndProblems
            | NamedReadOperation::GetUnderstandingProjectionInputs
            | NamedReadOperation::GetCapabilityEvidenceState => {
                if !request.parameters.is_empty() {
                    return Err(StoreError::InvalidField {
                        field: "operation.parameter",
                        reason: "reconstruction read declares no parameters",
                    });
                }
            }
            NamedReadOperation::GetEvidencePack | NamedReadOperation::GetCurrentEpistemicPosition => {
            }
            _ => return Err(StoreError::UnknownOperation),
        }
        let payload = match request.operation {
            NamedReadOperation::GetTaskState => self.task_payload(&scope)?,
            NamedReadOperation::GetAttentionAndProblems => self.attention_payload(&scope),
            NamedReadOperation::GetUnderstandingProjectionInputs => {
                self.understanding_payload(&scope)
            }
            NamedReadOperation::GetCapabilityEvidenceState => self.capability_payload(&scope),
            NamedReadOperation::GetEvidencePack => self.evidence_payload(&request, &scope)?,
            NamedReadOperation::GetCurrentEpistemicPosition => {
                self.position_payload(&request, &scope)?
            }
            _ => return Err(StoreError::UnknownOperation),
        };
        self.respond(&request, &scope, payload)
    }
}

/// Classifies one role readout the way the owning Governor reconstruction
/// composition must: a completed lookup over bound records that finds nothing
/// is authoritative `KnownEmpty`; an unbound provider section is `Missing`
/// (never silently empty); anything else derived from captured records is
/// `Present`.
fn classify_role(role: &str, payload: &Value) -> &'static str {
    match role {
        "negative_memory" if payload.get("negative_memory").is_none_or(Value::is_null) => {
            "missing"
        }
        "critical_attention"
            if payload
                .get("problems")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
                && payload.get("complete").and_then(Value::as_bool) == Some(true) =>
        {
            "known_empty"
        }
        _ => "present",
    }
}

#[test]
fn task_bound_context_reconstruction_reports_seven_roles_plus_activation_with_zero_edges_and_stale_on_invalidation(
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = "scope-task-7";
    let fence_one = fence(1)?;
    let ctx_one = metadata(&fence_one, "gen-one")?;

    // One real admitted exact binding: every record is captured through the
    // table's capture path under the same scope and fence. No problem is
    // captured (authoritative empty attention) and no negative-memory
    // provider is bound (missing role section).
    let mut table = ReconstructionTableClient::new(fence_one.clone());
    table.capture_task(scope, "task-7");
    table.capture_cue_input(scope, "cue-alpha");
    table.bind_negative_memory(scope, None);
    table.capture_evidence("evidence-alpha");
    table.capture_position(scope, "position-one");
    table.capture_capability(scope, "act:bounded-example");
    let service = ReadService::new(table);

    // The facade gate admits exactly the six role-source reads to the
    // ContextReconstruction intent; a seventh known operation fails the gate
    // distinctly, and a scopeless task read fails the scope rule.
    for operation in [
        NamedReadOperation::GetTaskState,
        NamedReadOperation::GetAttentionAndProblems,
        NamedReadOperation::GetCurrentEpistemicPosition,
        NamedReadOperation::GetUnderstandingProjectionInputs,
        NamedReadOperation::GetEvidencePack,
        NamedReadOperation::GetCapabilityEvidenceState,
    ] {
        let request = reconstruction_query(operation, Some(scope), BTreeMap::new())?;
        request.validate()?;
    }
    let out_of_intent = reconstruction_query(
        NamedReadOperation::GetMailbox,
        Some(scope),
        BTreeMap::new(),
    )?;
    assert!(matches!(
        out_of_intent.validate(),
        Err(ReadError::InvalidIntentOperation { .. })
    ));
    let unscoped = reconstruction_query(NamedReadOperation::GetTaskState, None, BTreeMap::new())?;
    assert!(matches!(
        unscoped.validate(),
        Err(ReadError::ScopeRequired)
    ));

    // All six role-source reads execute through the canonical
    // `ReadService::query` path against the one admitted binding.
    let task = block_on(service.query(
        &ctx_one,
        reconstruction_query(NamedReadOperation::GetTaskState, Some(scope), BTreeMap::new())?,
    ))?;
    let attention = block_on(service.query(
        &ctx_one,
        reconstruction_query(
            NamedReadOperation::GetAttentionAndProblems,
            Some(scope),
            BTreeMap::new(),
        )?,
    ))?;
    let position = block_on(service.query(
        &ctx_one,
        reconstruction_query(
            NamedReadOperation::GetCurrentEpistemicPosition,
            Some(scope),
            position_parameters("position-one"),
        )?,
    ))?;
    let understanding = block_on(service.query(
        &ctx_one,
        reconstruction_query(
            NamedReadOperation::GetUnderstandingProjectionInputs,
            Some(scope),
            BTreeMap::new(),
        )?,
    ))?;
    let evidence = block_on(service.query(
        &ctx_one,
        reconstruction_query(
            NamedReadOperation::GetEvidencePack,
            Some(scope),
            evidence_parameters("evidence-alpha", "8"),
        )?,
    ))?;
    let capability = block_on(service.query(
        &ctx_one,
        reconstruction_query(
            NamedReadOperation::GetCapabilityEvidenceState,
            Some(scope),
            BTreeMap::new(),
        )?,
    ))?;

    // Seven role dispositions plus the activation evidence, all bound to the
    // admitted fence and generation.
    let roles = [
        ("task_frame", classify_role("task_frame", &task.payload)),
        (
            "critical_attention",
            classify_role("critical_attention", &attention.payload),
        ),
        (
            "current_epistemic_position",
            classify_role("current_epistemic_position", &position.payload),
        ),
        (
            "cue_activation",
            classify_role(
                "cue_activation",
                understanding.payload.get("cue_inputs").unwrap_or(&Value::Null),
            ),
        ),
        (
            "negative_memory",
            classify_role("negative_memory", &understanding.payload),
        ),
        ("evidence", classify_role("evidence", &evidence.payload)),
        (
            "affordances",
            classify_role("affordances", &capability.payload),
        ),
    ];
    assert_eq!(
        roles.map(|(role, _)| role),
        [
            "task_frame",
            "critical_attention",
            "current_epistemic_position",
            "cue_activation",
            "negative_memory",
            "evidence",
            "affordances",
        ]
    );
    assert_eq!(
        roles.map(|(_, disposition)| disposition),
        [
            "present",
            "known_empty",
            "present",
            "present",
            "missing",
            "present",
            "present",
        ]
    );
    // The missing negative-memory role is reported distinctly from the
    // authoritative known-empty attention role: never a silent empty.
    assert_ne!(roles[4].1, roles[1].1);
    // Activation evidence: the admitted position readback under the exact
    // admitted fence and generation.
    assert_eq!(position.state_fence, fence_one);
    assert_eq!(
        position.payload.get("position").and_then(Value::as_str),
        Some("position-one")
    );
    assert_eq!(
        position.payload.get("generation").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        task.payload.get("task_id").and_then(Value::as_str),
        Some("task-7")
    );
    // Zero graph edges: the closure admits only exact selectors, so a
    // smuggled edge selector fails closed before any record is touched.
    let mut smuggled = BTreeMap::new();
    smuggled.insert(
        "relation_edges".to_owned(),
        Value::String("edge-1".to_owned()),
    );
    assert!(
        block_on(service.query(
            &ctx_one,
            reconstruction_query(NamedReadOperation::GetTaskState, Some(scope), smuggled)?,
        ))
        .is_err()
    );

    // Source/fence invalidation: the same six reads against the refreshed
    // fence report stale instead of serving the previous generation as
    // current.
    let fence_two = fence(2)?;
    let ctx_two = metadata(&fence_two, "gen-two")?;
    for operation in [
        NamedReadOperation::GetTaskState,
        NamedReadOperation::GetAttentionAndProblems,
        NamedReadOperation::GetCurrentEpistemicPosition,
        NamedReadOperation::GetUnderstandingProjectionInputs,
        NamedReadOperation::GetEvidencePack,
        NamedReadOperation::GetCapabilityEvidenceState,
    ] {
        let parameters = match operation {
            NamedReadOperation::GetEvidencePack => evidence_parameters("evidence-alpha", "8"),
            NamedReadOperation::GetCurrentEpistemicPosition => {
                position_parameters("position-one")
            }
            _ => BTreeMap::new(),
        };
        let stale = block_on(service.query(
            &ctx_two,
            reconstruction_query(operation, Some(scope), parameters)?,
        ));
        assert!(
            stale.is_err(),
            "invalidated read of {operation:?} must not serve generation one as current"
        );
    }

    // Rebuild under the new generation returns the new generation only.
    let mut rebuilt = ReconstructionTableClient::new(fence_two.clone());
    rebuilt.capture_task(scope, "task-7");
    rebuilt.capture_cue_input(scope, "cue-alpha");
    rebuilt.bind_negative_memory(scope, None);
    rebuilt.capture_evidence("evidence-alpha");
    rebuilt.capture_position(scope, "position-one");
    rebuilt.capture_capability(scope, "act:bounded-example");
    let rebuilt_service = ReadService::new(rebuilt);
    let rebuilt_position = block_on(rebuilt_service.query(
        &ctx_two,
        reconstruction_query(
            NamedReadOperation::GetCurrentEpistemicPosition,
            Some(scope),
            position_parameters("position-one"),
        )?,
    ))?;
    assert_eq!(rebuilt_position.state_fence, fence_two);
    assert_eq!(
        rebuilt_position
            .payload
            .get("generation")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_ne!(rebuilt_position.payload, position.payload);
    Ok(())
}
