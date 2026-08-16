//! G-06 Governor read/query contracts and named-read facade.
//!
//! This crate owns the semantic read boundary above the store-neutral named
//! read port. Requests carry explicit intent, scope, consistency and fence
//! dependencies. The facade never accepts raw database query text, writes
//! canonical state, or treats a payload as proof merely because it was read.
//! Store payloads remain opaque; callers receive their exact payload together
//! with revision and provenance disposition so a later layer can apply the
//! appropriate semantic contract.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ContractIdentity, ContractVersion, RequestMetadata, StateFence,
    contract_identity as make_contract_identity,
};
use eliot_store_api::{
    CanonicalStoreClient, NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency,
    RevisionHead, RevisionKey, ScopeId, StoreError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable wire name for the Governor read contract.
pub const CONTRACT_NAME: &str = "eliot.governor.read";
/// Current wire revision for the Governor read contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Closed semantic query modes from the public ELIOT query surface.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    /// Resolve the currently supported position under the supplied fence.
    CurrentPosition,
    /// Reconstruct a bounded historical position; never silently current.
    HistoricalReconstruction,
    /// Follow exact source, evidence and decision lineage.
    Provenance,
    /// Return navigation candidates that are not evidence or proof.
    Navigation,
    /// Read verifier-oriented evidence and run lineage.
    Verification,
    /// Read a bounded change-impact projection.
    ChangeImpact,
    /// Reconstruct a bounded context/input view.
    ContextReconstruction,
}

/// Explicit assurance semantics for a broad query.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIntent {
    /// Semantic query mode.
    pub mode: QueryMode,
    /// Exact time window or named temporal scope.
    pub time_scope: String,
    /// Branch and environment scope.
    pub branch_environment_scope: String,
    /// Required freshness behavior.
    pub freshness_policy: String,
    /// Required assurance/proof behavior.
    pub required_assurance: String,
}

impl QueryIntent {
    /// Validates the explicit intent dimensions.
    pub fn validate(&self) -> Result<(), ReadError> {
        text(&self.time_scope, "query.intent.time_scope")?;
        text(
            &self.branch_environment_scope,
            "query.intent.branch_environment_scope",
        )?;
        text(&self.freshness_policy, "query.intent.freshness_policy")?;
        text(&self.required_assurance, "query.intent.required_assurance")
    }
}

/// Immutable exact resource URI used for expansion reads.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EliotResourceUri(String);

impl EliotResourceUri {
    /// Creates an exact URI without resolving or dereferencing it.
    pub fn new(value: impl Into<String>) -> Result<Self, ReadError> {
        let value = value.into();
        text(&value, "resource_uri")?;
        if value.chars().any(char::is_whitespace) || !value.contains("://") {
            return Err(ReadError::InvalidResourceUri);
        }
        if value.len() > 2048 {
            return Err(ReadError::InvalidField {
                field: "resource_uri",
                reason: "exceeds 2048 bytes",
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact URI string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EliotResourceUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Exact provenance/evidence handle supplied by an owning read model.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProvenanceHandle(String);

impl ProvenanceHandle {
    /// Creates a non-blank immutable handle.
    pub fn new(value: impl Into<String>) -> Result<Self, ReadError> {
        let value = value.into();
        text(&value, "provenance_handle")?;
        if value.len() > 4096 {
            return Err(ReadError::InvalidField {
                field: "provenance_handle",
                reason: "exceeds 4096 bytes",
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProvenanceHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether result lineage is present and how it may be used.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceDisposition {
    /// The caller supplied exact source/evidence handles for this read.
    Declared,
    /// No exact handle was supplied; the payload remains read-only context.
    Unavailable,
}

/// Result lineage attached to every read response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadProvenance {
    /// Exact handles, never display labels or guessed IDs.
    pub handles: Vec<ProvenanceHandle>,
    /// Whether those handles were declared by the read caller.
    pub disposition: ProvenanceDisposition,
}

impl ReadProvenance {
    fn from_handles(handles: &[ProvenanceHandle]) -> Result<Self, ReadError> {
        let mut unique = BTreeSet::new();
        for handle in handles {
            if !unique.insert(handle.clone()) {
                return Err(ReadError::DuplicateField("provenance_handles".to_owned()));
            }
        }
        Ok(Self {
            handles: handles.to_vec(),
            disposition: if handles.is_empty() {
                ProvenanceDisposition::Unavailable
            } else {
                ProvenanceDisposition::Declared
            },
        })
    }
}

/// Request for one bounded current-state named read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRequest {
    /// Closed named operation owned by the canonical read model.
    pub operation: NamedReadOperation,
    /// Optional scope required by the selected operation.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for at-least and stable reads.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Named operation parameters; never a raw query string.
    pub parameters: BTreeMap<String, Value>,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl StateRequest {
    /// Validates state operation, scope and revision dependencies.
    pub fn validate(&self) -> Result<(), ReadError> {
        if !is_state_operation(self.operation) {
            return Err(ReadError::OperationNotAllowed {
                operation: self.operation,
                context: "state".to_owned(),
            });
        }
        validate_dependencies(&self.dependency_revisions)?;
        validate_parameters(&self.parameters)?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        ReadProvenance::from_handles(&self.provenance_handles)?;
        Ok(())
    }
}

/// Request for one explicit-intent query.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    /// Mandatory semantic intent; exact resources may use [`ResourceRequest`].
    pub intent: QueryIntent,
    /// Closed named operation selected by the Governor read model.
    pub operation: NamedReadOperation,
    /// Human/query text or exact selector, treated as data.
    pub query: String,
    /// Optional exact resource selector for a bounded expansion.
    pub exact_resource_uri: Option<EliotResourceUri>,
    /// Optional scope to which the query is bound.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for consistency validation.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Closed named parameters; no physical query syntax is accepted.
    pub parameters: BTreeMap<String, Value>,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl QueryRequest {
    /// Validates intent, operation semantics and bounded selectors.
    pub fn validate(&self) -> Result<(), ReadError> {
        self.intent.validate()?;
        text(&self.query, "query.query")?;
        validate_dependencies(&self.dependency_revisions)?;
        validate_parameters(&self.parameters)?;
        ReadProvenance::from_handles(&self.provenance_handles)?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        if let Some(uri) = &self.exact_resource_uri {
            text(uri.as_str(), "query.exact_resource_uri")?;
        }
        if !operation_matches_intent(self.operation, self.intent.mode) {
            return Err(ReadError::InvalidIntentOperation {
                operation: self.operation,
                mode: self.intent.mode,
            });
        }
        Ok(())
    }
}

/// Request for an exact resource expansion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    /// Immutable resource URI; no broad listing or URI guessing is allowed.
    pub uri: EliotResourceUri,
    /// Named read operation that owns the resource projection.
    pub operation: NamedReadOperation,
    /// Optional scope for the resource.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for consistency validation.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Additional closed parameters for the named operation.
    pub parameters: BTreeMap<String, Value>,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl ResourceRequest {
    /// Validates exact resource ownership and bounded read parameters.
    pub fn validate(&self) -> Result<(), ReadError> {
        validate_dependencies(&self.dependency_revisions)?;
        validate_parameters(&self.parameters)?;
        ReadProvenance::from_handles(&self.provenance_handles)?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        Ok(())
    }
}

/// Current-state response with the store payload kept opaque.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentStateView {
    /// Named operation that produced the payload.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the payload.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque typed payload owned by the active read model.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this result.
    pub consistency: ReadConsistency,
}

/// Query response with explicit intent and opaque payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResult {
    /// Intent used to interpret the result.
    pub intent: QueryIntent,
    /// Named operation that produced the payload.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the payload.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque typed payload owned by the active read model.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this result.
    pub consistency: ReadConsistency,
}

/// Exact resource response; expansion never re-executes an originating tool.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContent {
    /// Exact resource identity requested by the caller.
    pub uri: EliotResourceUri,
    /// Named operation that owns the resource projection.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the resource.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque immutable resource payload.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this resource.
    pub consistency: ReadConsistency,
}

/// Governor read failures. No variant exposes provider secrets or raw SQL.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadError {
    /// A required field is malformed or out of bounds.
    #[error("invalid read field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    /// A required textual field is blank.
    #[error("{0} must not be empty")]
    EmptyField(String),
    /// Duplicate exact handles or dependency keys were supplied.
    #[error("duplicate values in {0}")]
    DuplicateField(String),
    /// An operation is not legal for the requested facade context.
    #[error("named operation {operation:?} is not allowed for {context}")]
    OperationNotAllowed {
        /// Closed named operation.
        operation: NamedReadOperation,
        /// Facade context.
        context: String,
    },
    /// Query mode and named operation disagree.
    #[error("named operation {operation:?} does not support query mode {mode:?}")]
    InvalidIntentOperation {
        /// Closed named operation.
        operation: NamedReadOperation,
        /// Explicit query mode.
        mode: QueryMode,
    },
    /// A broad query omitted its required intent.
    #[error("query intent is required for a broad read")]
    MissingIntent,
    /// A scope-bound operation omitted its scope.
    #[error("read operation requires a scope")]
    ScopeRequired,
    /// URI is not an immutable exact resource URI.
    #[error("invalid exact resource URI")]
    InvalidResourceUri,
    /// Dependency revisions are absent for a consistency mode that needs them.
    #[error("read consistency requires dependency revisions")]
    MissingDependencies,
    /// A dependency revision was zero or otherwise invalid.
    #[error("invalid dependency revision")]
    InvalidDependencyRevision,
    /// Store response changed the requested operation or fence.
    #[error("named read response does not match request fence or operation")]
    ResponseMismatch,
    /// Stable read observed a revision change during assembly.
    #[error("read dependency revisions changed during stable read")]
    RevisionChurn,
    /// A read response is older than the declared minimum revision.
    #[error("read response is behind the declared minimum revision")]
    StaleRevision,
    /// Store boundary rejected the named read.
    #[error("store read: {0}")]
    Store(String),
}

impl From<StoreError> for ReadError {
    fn from(error: StoreError) -> Self {
        Self::Store(error.to_string())
    }
}

/// Read API implemented by the Governor service boundary.
#[allow(async_fn_in_trait)]
pub trait ReadApi {
    /// Returns one bounded current-state view.
    async fn state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<CurrentStateView, ReadError>;
    /// Executes one explicit-intent named query.
    async fn query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<QueryResult, ReadError>;
    /// Expands one exact immutable resource URI.
    async fn resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<ResourceContent, ReadError>;
}

/// Governor read service over a store-neutral canonical client.
pub struct ReadService<C> {
    store: C,
}

impl<C: CanonicalStoreClient> ReadService<C> {
    /// Creates a read service over the caller-owned store client.
    pub const fn new(store: C) -> Self {
        Self { store }
    }

    /// Returns the underlying store client to the owning composition root.
    pub fn into_store(self) -> C {
        self.store
    }

    async fn execute(
        &self,
        ctx: &RequestMetadata,
        operation: NamedReadOperation,
        scope_id: Option<ScopeId>,
        consistency: ReadConsistency,
        dependencies: &BTreeMap<RevisionKey, u64>,
        parameters: &BTreeMap<String, Value>,
        handles: &[ProvenanceHandle],
    ) -> Result<NamedReadResponse, ReadError> {
        ctx.validate().map_err(|error| ReadError::InvalidField {
            field: "request_metadata".to_owned(),
            reason: error.to_string(),
        })?;
        if matches!(
            consistency,
            ReadConsistency::StableScope | ReadConsistency::ExactFence
        ) && dependencies.is_empty()
        {
            return Err(ReadError::MissingDependencies);
        }
        let keys: Vec<RevisionKey> = dependencies.keys().cloned().collect();
        let before = if keys.is_empty() {
            Vec::new()
        } else {
            self.store.revision_heads(keys.clone()).await?
        };
        validate_minimum_revisions(&before, dependencies)?;
        let request = NamedReadRequest {
            operation,
            scope_id,
            consistency,
            state_fence: ctx.state_fence.clone(),
            parameters: parameters.clone(),
        };
        request.validate()?;
        let response = self.store.execute_named(request).await?;
        response.validate()?;
        if response.operation != operation || response.state_fence != ctx.state_fence {
            return Err(ReadError::ResponseMismatch);
        }
        validate_response_heads(&response, &ctx.state_fence)?;
        validate_minimum_revisions(&response.revision_heads, dependencies)?;
        if matches!(
            consistency,
            ReadConsistency::StableScope | ReadConsistency::ExactFence
        ) {
            let after = self.store.revision_heads(keys).await?;
            validate_minimum_revisions(&after, dependencies)?;
            if !same_dependency_heads(&before, &after, dependencies) {
                return Err(ReadError::RevisionChurn);
            }
            if !same_dependency_heads(&before, &response.revision_heads, dependencies) {
                return Err(ReadError::RevisionChurn);
            }
        }
        if consistency == ReadConsistency::ExactFence
            && response
                .revision_heads
                .iter()
                .filter(|head| dependencies.contains_key(&head.key))
                .any(|head| dependencies.get(&head.key) != Some(&head.revision))
        {
            return Err(ReadError::StaleRevision);
        }
        let _ = ReadProvenance::from_handles(handles)?;
        Ok(response)
    }
}

impl<C: CanonicalStoreClient> ReadApi for ReadService<C> {
    async fn state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<CurrentStateView, ReadError> {
        request.validate()?;
        let response = self
            .execute(
                ctx,
                request.operation,
                request.scope_id,
                request.consistency,
                &request.dependency_revisions,
                &request.parameters,
                &request.provenance_handles,
            )
            .await?;
        Ok(CurrentStateView {
            operation: response.operation,
            state_fence: response.state_fence,
            revision_heads: response.revision_heads,
            payload: response.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        })
    }

    async fn query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<QueryResult, ReadError> {
        request.validate()?;
        let parameters = query_parameters(&request)?;
        let response = self
            .execute(
                ctx,
                request.operation,
                request.scope_id,
                request.consistency,
                &request.dependency_revisions,
                &parameters,
                &request.provenance_handles,
            )
            .await?;
        Ok(QueryResult {
            intent: request.intent,
            operation: response.operation,
            state_fence: response.state_fence,
            revision_heads: response.revision_heads,
            payload: response.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        })
    }

    async fn resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<ResourceContent, ReadError> {
        request.validate()?;
        let mut parameters = request.parameters.clone();
        insert_exact_parameter(&mut parameters, "resource_uri", request.uri.as_str())?;
        let response = self
            .execute(
                ctx,
                request.operation,
                request.scope_id,
                request.consistency,
                &request.dependency_revisions,
                &parameters,
                &request.provenance_handles,
            )
            .await?;
        Ok(ResourceContent {
            uri: request.uri,
            operation: response.operation,
            state_fence: response.state_fence,
            revision_heads: response.revision_heads,
            payload: response.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        })
    }
}

/// Returns the stable contract identity for protocol/schema handshakes.
pub fn contract_identity() -> Result<ContractIdentity, eliot_contracts::ContractError> {
    #[derive(Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        raw_query_rule: &'static str,
        stable_read_rule: &'static str,
        provenance_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "governor_named_read_query_and_resource_facade",
            version: CONTRACT_VERSION,
            raw_query_rule: "closed_named_operations_only",
            stable_read_rule: "revision_heads_before_and_after_named_read",
            provenance_rule: "exact_handles_or_read_only_unavailable_disposition",
        },
    )
}

fn is_state_operation(operation: NamedReadOperation) -> bool {
    matches!(
        operation,
        NamedReadOperation::GetRevisionHeads
            | NamedReadOperation::GetScopeRevisionView
            | NamedReadOperation::GetTaskState
            | NamedReadOperation::GetCurrentEpistemicPosition
            | NamedReadOperation::GetAttentionAndProblems
            | NamedReadOperation::GetModuleCatalogState
            | NamedReadOperation::GetCapabilityEvidenceState
            | NamedReadOperation::GetConformanceState
            | NamedReadOperation::GetMailbox
    )
}

fn requires_scope(operation: NamedReadOperation) -> bool {
    matches!(
        operation,
        NamedReadOperation::GetScopeRevisionView
            | NamedReadOperation::GetTaskState
            | NamedReadOperation::GetCurrentEpistemicPosition
            | NamedReadOperation::GetEvidencePack
            | NamedReadOperation::GetUnderstandingProjectionInputs
            | NamedReadOperation::GetAttentionAndProblems
            | NamedReadOperation::GetCapabilityEvidenceState
            | NamedReadOperation::GetConformanceState
            | NamedReadOperation::GetMailbox
            | NamedReadOperation::GetAuditRange
    )
}

fn operation_matches_intent(operation: NamedReadOperation, mode: QueryMode) -> bool {
    match mode {
        QueryMode::CurrentPosition => matches!(
            operation,
            NamedReadOperation::GetCurrentEpistemicPosition
                | NamedReadOperation::GetScopeRevisionView
                | NamedReadOperation::GetRevisionHeads
        ),
        QueryMode::HistoricalReconstruction => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetAuditRange
                | NamedReadOperation::GetTaskState
        ),
        QueryMode::Provenance => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetAuditRange
                | NamedReadOperation::ResolveWriteReceipt
        ),
        QueryMode::Navigation => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetScopeRevisionView
                | NamedReadOperation::GetRevisionHeads
        ),
        QueryMode::Verification => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
                | NamedReadOperation::GetConformanceState
        ),
        QueryMode::ChangeImpact => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
        ),
        QueryMode::ContextReconstruction => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
                | NamedReadOperation::GetCurrentEpistemicPosition
        ),
    }
}

fn query_parameters(request: &QueryRequest) -> Result<BTreeMap<String, Value>, ReadError> {
    let mut parameters = request.parameters.clone();
    insert_exact_parameter(&mut parameters, "query", &request.query)?;
    if let Some(uri) = &request.exact_resource_uri {
        insert_exact_parameter(&mut parameters, "exact_resource_uri", uri.as_str())?;
    }
    Ok(parameters)
}

fn insert_exact_parameter(
    parameters: &mut BTreeMap<String, Value>,
    key: &str,
    value: &str,
) -> Result<(), ReadError> {
    if parameters.contains_key(key) {
        return Err(ReadError::DuplicateField("named_parameters".to_owned()));
    }
    parameters.insert(key.to_owned(), Value::String(value.to_owned()));
    Ok(())
}

fn validate_dependencies(dependencies: &BTreeMap<RevisionKey, u64>) -> Result<(), ReadError> {
    if dependencies.values().any(|revision| *revision == 0) {
        return Err(ReadError::InvalidDependencyRevision);
    }
    Ok(())
}

fn validate_minimum_revisions(
    heads: &[RevisionHead],
    minimums: &BTreeMap<RevisionKey, u64>,
) -> Result<(), ReadError> {
    for (key, minimum) in minimums {
        let head = heads
            .iter()
            .find(|candidate| candidate.key == *key)
            .ok_or(ReadError::StaleRevision)?;
        if head.revision < *minimum {
            return Err(ReadError::StaleRevision);
        }
    }
    Ok(())
}

fn validate_response_heads(
    response: &NamedReadResponse,
    fence: &StateFence,
) -> Result<(), ReadError> {
    if response
        .revision_heads
        .iter()
        .any(|head| head.state_fence != *fence)
    {
        return Err(ReadError::ResponseMismatch);
    }
    Ok(())
}

fn same_dependency_heads(
    left: &[RevisionHead],
    right: &[RevisionHead],
    dependencies: &BTreeMap<RevisionKey, u64>,
) -> bool {
    dependencies.keys().all(|key| {
        let left_revision = left
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        let right_revision = right
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        left_revision == right_revision
    })
}

fn validate_parameters(parameters: &BTreeMap<String, Value>) -> Result<(), ReadError> {
    for (name, value) in parameters {
        text(name, "named_parameter")?;
        if value.is_null() {
            return Err(ReadError::InvalidField {
                field: "named_parameter".to_owned(),
                reason: "null values are not allowed".to_owned(),
            });
        }
    }
    Ok(())
}

fn text(value: &str, field: &'static str) -> Result<(), ReadError> {
    if value.trim().is_empty() {
        return Err(ReadError::EmptyField(field.to_owned()));
    }
    if value.chars().any(char::is_control) {
        return Err(ReadError::InvalidField {
            field: field.to_owned(),
            reason: "control characters are not allowed".to_owned(),
        });
    }
    Ok(())
}
