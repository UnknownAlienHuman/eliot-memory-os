//! Governor seven-role input reconstruction for context composition.
//!
//! T11 section 5, slice T11.3 (part A, Governor): acquire the seven immutable,
//! revision/fence-bound owner projections through the Governor read owner
//! (`eliot_read::ReadApi`) and expose them as input reconstruction. This is
//! never an admitted `ActiveUnderstandingView`: no candidate selection,
//! admission, assembly, or publication runs here (T11.md:163).
//!
//! Role → acquisition mapping (T11.md:65-77):
//!
//! | Candidate provider role | Named read | Facade |
//! |---|---|---|
//! | `TaskFrame` | `GetTaskState` | `ReadApi::state` |
//! | `CriticalAttention`/`Conflict` | `GetAttentionAndProblems` | `ReadApi::state` |
//! | `CurrentEpistemicPosition` | `GetCurrentEpistemicPosition` | `ReadApi::query` with `QueryMode::ContextReconstruction` (reuses the T11.2 readback shape) |
//! | Cue activation | `GetUnderstandingProjectionInputs` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//! | Negative memory | `GetUnderstandingProjectionInputs` (negative-memory interpretation) | same query |
//! | Evidence/source assurance | `GetEvidencePack` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//! | Affordances | `GetCapabilityEvidenceState` | `ReadApi::state` |
//!
//! The query facade only admits `GetEvidencePack`,
//! `GetUnderstandingProjectionInputs`, and `GetCurrentEpistemicPosition` for
//! `QueryMode::ContextReconstruction` (`eliot_read` intent table); the three
//! state-only roles go through `ReadApi::state` under the same fence and
//! dependency closure instead of failing the intent gate. Every read uses
//! `ReadConsistency::ExactFence` with caller-supplied dependency revisions.
//!
//! Closure discipline (T11.md:77): the dependency heads (`ScopeRevisionView`)
//! are captured before acquisition and re-read afterwards; bounded churn
//! fails closed as [`ContextInputsError::SourceHeadsChanged`] rather than
//! exposing a silently mixed snapshot. There is no retry here.
//!
//! Disposition discipline (`eliot_context_candidates::ProjectionState`):
//! `KnownEmpty` requires an authoritative completed lookup (an explicit empty
//! result with an exact truncation/coverage statement). Transport failure,
//! an unactivated (known-but-unsupported) operation, and a bounded partial
//! scan are reported as `Unavailable`/`Unknown`/`Partial` — never as empty.
//! At base only six reads are catalogue-activated (see
//! `eliot_store_api::operation_catalogue`); `GetTaskState`,
//! `GetAttentionAndProblems`, `GetUnderstandingProjectionInputs`, and
//! `GetCapabilityEvidenceState` have no proven handler triple, so those roles
//! report `Unavailable` distinctly from `KnownEmpty` until the Store-owned
//! slice (part B/C) activates them.

use std::collections::BTreeMap;

use eliot_contracts::RequestMetadata;
use eliot_context_candidates::ProjectionState;
use eliot_read::{QueryIntent, QueryMode, QueryRequest, ReadApi, ReadError, StateRequest};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency, RevisionHead, RevisionKey,
    ScopeId, ScopeRevisionView, WriteReceiptStatus,
    epistemic_revision::EpistemicPositionReadback,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Role label for the `TaskFrame` slot.
pub const ROLE_TASK_FRAME: &str = "task_frame";
/// Role label for the `CriticalAttention`/`Conflict` slot.
pub const ROLE_ATTENTION_CONFLICT: &str = "attention_conflict";
/// Role label for the `CurrentEpistemicPosition` slot.
pub const ROLE_EPISTEMIC_POSITION: &str = "epistemic_position";
/// Role label for the cue-activation slot.
pub const ROLE_CUE_ACTIVATION: &str = "cue_activation";
/// Role label for the negative-memory slot.
pub const ROLE_NEGATIVE_MEMORY: &str = "negative_memory";
/// Role label for the evidence/source-assurance slot.
pub const ROLE_EVIDENCE_ASSURANCE: &str = "evidence_assurance";
/// Role label for the affordances slot.
pub const ROLE_AFFORDANCES: &str = "affordances";

/// Fail-closed errors for seven-role input reconstruction.
///
/// A per-role read failure is never raised here: it becomes that role's
/// [`ProjectionState`] disposition inside [`SevenRoleInputs`]. These variants
/// cover only conditions under which no coherent seven-role view can be
/// exposed at all (bad request, missing closure, churn during acquisition).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextInputsError {
    /// The reconstruction request or caller metadata is malformed.
    #[error("context reconstruction request is invalid: {0}")]
    RequestInvalid(String),
    /// Exact-fence reads require at least one dependency revision.
    #[error("context reconstruction requires at least one dependency revision for exact-fence reads")]
    MissingDependencies,
    /// The dependency-head closure could not be established.
    #[error("context reconstruction closure is unavailable: {0}")]
    ClosureUnavailable(String),
    /// Source heads moved between the before/after capture; retry with a
    /// fresh closure instead of serving a mixed snapshot.
    #[error("source heads changed during acquisition; retry with a fresh closure")]
    SourceHeadsChanged,
    /// A role request was rejected for a caller-shape reason (not a provider
    /// outcome); this is a programming error, never a role disposition.
    #[error("context reconstruction role request was rejected: {0}")]
    RequestRejected(String),
}

/// Closed request for one seven-role reconstruction.
///
/// The fence travels only in the caller [`RequestMetadata`]; dependency
/// revisions bind the exact-fence reads. Selectors are the exact closed
/// named-read parameters: `epistemic_position` is the required `position`
/// selector of `GetCurrentEpistemicPosition`, and `evidence_subject` plus
/// `evidence_max_records` are the required `subject`/`max_records` selectors
/// of `GetEvidencePack`. `GetUnderstandingProjectionInputs` declares no
/// parameters, so cue and negative-memory roles share its empty selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextReconstructionRequest {
    /// Scope every role projection must be bound to.
    pub scope_id: ScopeId,
    /// Dependency revisions for the exact-fence reads.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Exact position identity for the epistemic read.
    pub epistemic_position: String,
    /// Exact captured-observation subject for the evidence read.
    pub evidence_subject: String,
    /// Explicit evidence bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub evidence_max_records: u32,
}

impl ContextReconstructionRequest {
    /// Validates the closed request shape without performing any read.
    pub fn validate(&self) -> Result<(), ContextInputsError> {
        if self.dependency_revisions.values().any(|revision| *revision == 0) {
            return Err(ContextInputsError::RequestInvalid(
                "dependency revisions must be non-zero".to_owned(),
            ));
        }
        if self.epistemic_position.trim().is_empty()
            || self.epistemic_position.chars().any(char::is_control)
        {
            return Err(ContextInputsError::RequestInvalid(
                "epistemic_position must be non-blank text".to_owned(),
            ));
        }
        if self.evidence_subject.trim().is_empty()
            || self.evidence_subject.chars().any(char::is_control)
        {
            return Err(ContextInputsError::RequestInvalid(
                "evidence_subject must be non-blank text".to_owned(),
            ));
        }
        if self.evidence_max_records == 0
            || self.evidence_max_records > EVIDENCE_PACK_MAX_RECORDS
        {
            return Err(ContextInputsError::RequestInvalid(format!(
                "evidence_max_records must be within 1..={EVIDENCE_PACK_MAX_RECORDS}"
            )));
        }
        Ok(())
    }
}

/// One acquired role: its disposition, raw payload, and observed heads.
///
/// Payloads stay opaque here; the candidate stage (T11.4) binds them to the
/// seven typed input families. A `None` payload always pairs with a
/// non-`Complete` disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAcquisition {
    /// Closed named operation that produced (or refused) this role.
    pub operation: NamedReadOperation,
    /// Completeness state of this role (`inputs.rs:188-282` vocabulary).
    pub state: ProjectionState,
    /// Opaque payload for a completed role; `None` otherwise.
    pub payload: Option<Value>,
    /// Revision heads observed with this role's read.
    pub revision_heads: Vec<RevisionHead>,
}

/// The reconstructed seven-role input closure.
///
/// All seven roles bind one compatible read closure: the fence plus the
/// before/after dependency heads. `heads_after` equals `heads_before` by
/// construction — any churn fails the whole reconstruction instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SevenRoleInputs {
    /// Scope every role was acquired under.
    pub scope_id: ScopeId,
    /// Fence every role was acquired under.
    pub state_fence: eliot_contracts::StateFence,
    /// Dependency heads captured before acquisition.
    pub heads_before: ScopeRevisionView,
    /// Dependency heads re-read after acquisition (equal to `heads_before`).
    pub heads_after: ScopeRevisionView,
    /// `TaskFrame` role (`GetTaskState`).
    pub task_frame: RoleAcquisition,
    /// `CriticalAttention`/`Conflict` role (`GetAttentionAndProblems`).
    pub attention: RoleAcquisition,
    /// `CurrentEpistemicPosition` role (`GetCurrentEpistemicPosition`).
    pub epistemic: RoleAcquisition,
    /// Decoded T11.2 readback when the epistemic role is `Complete`.
    pub epistemic_readback: Option<EpistemicPositionReadback>,
    /// Cue-activation role (`GetUnderstandingProjectionInputs`).
    pub cue: RoleAcquisition,
    /// Negative-memory role (`GetUnderstandingProjectionInputs`,
    /// negative-memory interpretation of the same closed projection).
    pub negative_memory: RoleAcquisition,
    /// Evidence/source-assurance role (`GetEvidencePack`).
    pub evidence: RoleAcquisition,
    /// Affordances role (`GetCapabilityEvidenceState`).
    pub affordances: RoleAcquisition,
}

impl SevenRoleInputs {
    /// Returns every role label with its disposition, in slot order.
    #[must_use]
    pub fn role_states(&self) -> [(&'static str, &ProjectionState); 7] {
        [
            (ROLE_TASK_FRAME, &self.task_frame.state),
            (ROLE_ATTENTION_CONFLICT, &self.attention.state),
            (ROLE_EPISTEMIC_POSITION, &self.epistemic.state),
            (ROLE_CUE_ACTIVATION, &self.cue.state),
            (ROLE_NEGATIVE_MEMORY, &self.negative_memory.state),
            (ROLE_EVIDENCE_ASSURANCE, &self.evidence.state),
            (ROLE_AFFORDANCES, &self.affordances.state),
        ]
    }

    /// Returns the labels of roles whose source could not be read or
    /// evaluated (`Unavailable`, `Unknown`, `Missing`, `Blocked`).
    ///
    /// These are reported distinctly from authoritative [`ProjectionState::KnownEmpty`]:
    /// an unreadable or unactivated source is never an empty set.
    #[must_use]
    pub fn unsupported_role_names(&self) -> Vec<&'static str> {
        self.role_states()
            .into_iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    ProjectionState::Unavailable { .. }
                        | ProjectionState::Unknown { .. }
                        | ProjectionState::Missing
                        | ProjectionState::Blocked { .. }
                )
            })
            .map(|(name, _)| name)
            .collect()
    }

    /// Returns whether at least one role is unsupported (T11.3 acceptance:
    /// at least one unsupported/missing role reported distinctly from
    /// authoritative `KnownEmpty`).
    #[must_use]
    pub fn has_unsupported_distinct_from_empty(&self) -> bool {
        !self.unsupported_role_names().is_empty()
    }
}

/// Borrow of the read owner; there is no separate context-input state owner.
pub struct GovernorContextInputs<'a, R: ?Sized> {
    reads: &'a R,
}

impl<'a, R: ?Sized> GovernorContextInputs<'a, R> {
    /// Borrows the Governor read owner without touching `composition.rs`.
    #[must_use]
    pub const fn borrow(reads: &'a R) -> Self {
        Self { reads }
    }
}

impl<R: ReadApi + ?Sized> GovernorContextInputs<'_, R> {
    /// Acquires the seven roles over one compatible read closure and exposes
    /// the reconstructed inputs.
    ///
    /// Per-role provider failures become per-role dispositions; only a bad
    /// request, a missing closure, or observed churn fails the whole call.
    pub async fn reconstruct(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<SevenRoleInputs, ContextInputsError> {
        request.validate()?;
        ctx.validate().map_err(|error| {
            ContextInputsError::RequestInvalid(format!("request metadata: {error}"))
        })?;
        if request.dependency_revisions.is_empty() {
            return Err(ContextInputsError::MissingDependencies);
        }
        let heads_before = self.scope_heads(ctx, request).await?;
        let task_frame = self
            .acquire_state(ctx, request, NamedReadOperation::GetTaskState)
            .await?;
        let attention = self
            .acquire_state(ctx, request, NamedReadOperation::GetAttentionAndProblems)
            .await?;
        let (epistemic, epistemic_readback) = self.acquire_epistemic(ctx, request).await?;
        let cue = self.acquire_projection_inputs(ctx, request).await?;
        // Negative memory reads the same closed projection; only the
        // candidate-stage interpretation differs (kept separate so the two
        // slots stay statically identifiable per inputs.rs:1-13).
        let negative_memory = self.acquire_projection_inputs(ctx, request).await?;
        let evidence = self.acquire_evidence(ctx, request).await?;
        let affordances = self
            .acquire_state(
                ctx,
                request,
                NamedReadOperation::GetCapabilityEvidenceState,
            )
            .await?;
        let heads_after = self.scope_heads(ctx, request).await?;
        if heads_after != heads_before {
            return Err(ContextInputsError::SourceHeadsChanged);
        }
        Ok(SevenRoleInputs {
            scope_id: request.scope_id.clone(),
            state_fence: ctx.state_fence.clone(),
            heads_before,
            heads_after,
            task_frame,
            attention,
            epistemic,
            epistemic_readback,
            cue,
            negative_memory,
            evidence,
            affordances,
        })
    }

    async fn scope_heads(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<ScopeRevisionView, ContextInputsError> {
        let response = self
            .reads
            .state(
                ctx,
                StateRequest {
                    operation: NamedReadOperation::GetScopeRevisionView,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    parameters: BTreeMap::new(),
                    provenance_handles: Vec::new(),
                },
            )
            .await
            .map_err(|error| {
                ContextInputsError::ClosureUnavailable(format!("scope heads: {error}"))
            })?;
        let heads: ScopeRevisionView =
            serde_json::from_value(response.payload).map_err(|error| {
                ContextInputsError::ClosureUnavailable(format!(
                    "scope heads payload is not a revision view: {error}"
                ))
            })?;
        heads.validate().map_err(|error| {
            ContextInputsError::ClosureUnavailable(format!("scope heads invalid: {error}"))
        })?;
        if heads.scope_id != request.scope_id || heads.state_fence != ctx.state_fence {
            return Err(ContextInputsError::ClosureUnavailable(
                "scope heads changed scope or fence".to_owned(),
            ));
        }
        Ok(heads)
    }

    async fn acquire_state(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        operation: NamedReadOperation,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        match self
            .reads
            .state(
                ctx,
                StateRequest {
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    parameters: BTreeMap::new(),
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => Ok(RoleAcquisition {
                operation: response.operation,
                state: classify_opaque_payload(&response.payload),
                payload: Some(response.payload),
                revision_heads: response.revision_heads,
            }),
            Err(error) => Ok(RoleAcquisition {
                operation,
                state: classify_read_error(error)?,
                payload: None,
                revision_heads: Vec::new(),
            }),
        }
    }

    async fn acquire_projection_inputs(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let operation = NamedReadOperation::GetUnderstandingProjectionInputs;
        match self
            .reads
            .query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    query: "reconstruct the bounded understanding-projection inputs".to_owned(),
                    exact_resource_uri: None,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    parameters: BTreeMap::new(),
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => Ok(RoleAcquisition {
                operation: response.operation,
                state: classify_opaque_payload(&response.payload),
                payload: Some(response.payload),
                revision_heads: response.revision_heads,
            }),
            Err(error) => Ok(RoleAcquisition {
                operation,
                state: classify_read_error(error)?,
                payload: None,
                revision_heads: Vec::new(),
            }),
        }
    }

    async fn acquire_epistemic(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<(RoleAcquisition, Option<EpistemicPositionReadback>), ContextInputsError> {
        let operation = NamedReadOperation::GetCurrentEpistemicPosition;
        let response = match self
            .reads
            .query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    query: "reconstruct the current epistemic position".to_owned(),
                    exact_resource_uri: None,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    parameters: BTreeMap::from([(
                        "position".to_owned(),
                        Value::String(request.epistemic_position.clone()),
                    )]),
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok((
                    RoleAcquisition {
                        operation,
                        state: classify_read_error(error)?,
                        payload: None,
                        revision_heads: Vec::new(),
                    },
                    None,
                ));
            }
        };
        let (state, readback) = decode_epistemic_payload(&response.payload);
        let payload = Some(response.payload);
        Ok((
            RoleAcquisition {
                operation: response.operation,
                state,
                payload,
                revision_heads: response.revision_heads,
            },
            readback,
        ))
    }

    async fn acquire_evidence(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let operation = NamedReadOperation::GetEvidencePack;
        let response = match self
            .reads
            .query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    query: "reconstruct the bounded evidence pack".to_owned(),
                    exact_resource_uri: None,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    parameters: BTreeMap::from([
                        (
                            "subject".to_owned(),
                            Value::String(request.evidence_subject.clone()),
                        ),
                        (
                            "max_records".to_owned(),
                            Value::String(request.evidence_max_records.to_string()),
                        ),
                    ]),
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(RoleAcquisition {
                    operation,
                    state: classify_read_error(error)?,
                    payload: None,
                    revision_heads: Vec::new(),
                });
            }
        };
        let state =
            classify_evidence_payload(&response.payload, &request.scope_id, &request.evidence_subject);
        Ok(RoleAcquisition {
            operation: response.operation,
            state,
            payload: Some(response.payload),
            revision_heads: response.revision_heads,
        })
    }
}

/// Fixed explicit intent for every `ContextReconstruction` query.
///
/// Free-text dimensions stay data; the closed operation selects the source.
fn reconstruction_intent() -> QueryIntent {
    QueryIntent {
        mode: QueryMode::ContextReconstruction,
        time_scope: "reconstruction closure under the declared fence".to_owned(),
        branch_environment_scope: "request scope and fence only".to_owned(),
        freshness_policy: "exact-fence reads with declared dependency revisions".to_owned(),
        required_assurance: "input reconstruction only; no admission or proof".to_owned(),
    }
}

/// Builds a bounded, control-character-free reason for a disposition.
fn bounded_reason(prefix: &'static str, detail: impl std::fmt::Display) -> String {
    let mut reason = format!("{prefix}: {detail}");
    reason = reason
        .chars()
        .map(|cell| {
            if cell.is_control() {
                ' '
            } else {
                cell
            }
        })
        .collect();
    let trimmed = reason.trim().to_owned();
    let reason = if trimmed.is_empty() {
        prefix.to_owned()
    } else {
        trimmed
    };
    if reason.len() > 240 {
        // Reasons are bounded role metadata; truncation keeps the envelope
        // bounded while the full provider error stays in the read path.
        let mut end = 240;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &reason[..end])
    } else {
        reason
    }
}

/// Maps a read failure to a role disposition.
///
/// Provider failures (`Store`, unsupported operation for this facade,
/// churn/staleness, blocked evaluation) become dispositions — never
/// `KnownEmpty`. Caller-shape rejections are programming errors and abort
/// the whole reconstruction instead of masquerading as a role outcome.
fn classify_read_error(error: ReadError) -> Result<ProjectionState, ContextInputsError> {
    match error {
        ReadError::Store(detail) => Ok(ProjectionState::Unavailable {
            reason: bounded_reason("store read failed", detail),
        }),
        ReadError::OperationNotAllowed { operation, context } => {
            Ok(ProjectionState::Unavailable {
                reason: bounded_reason(
                    "operation not supported for input reconstruction",
                    format!("{operation:?} for {context}"),
                ),
            })
        }
        ReadError::InvalidIntentOperation { operation, mode } => {
            Ok(ProjectionState::Unavailable {
                reason: bounded_reason(
                    "operation does not support this query mode",
                    format!("{operation:?} for {mode:?}"),
                ),
            })
        }
        ReadError::ResponseMismatch => Ok(ProjectionState::Stale {
            reason: "named read response changed operation or fence".to_owned(),
        }),
        ReadError::RevisionChurn => Ok(ProjectionState::Stale {
            reason: "dependency revisions changed during the read".to_owned(),
        }),
        ReadError::StaleRevision => Ok(ProjectionState::Stale {
            reason: "read response is behind the declared minimum revision".to_owned(),
        }),
        ReadError::MissingDependencies => Ok(ProjectionState::Blocked {
            reason: "read consistency requires dependency revisions".to_owned(),
        }),
        ReadError::ScopeRequired => Ok(ProjectionState::Blocked {
            reason: "read operation requires a scope".to_owned(),
        }),
        ReadError::MissingIntent => Ok(ProjectionState::Blocked {
            reason: "broad read omitted its required intent".to_owned(),
        }),
        ReadError::InvalidField { field, reason } => Err(ContextInputsError::RequestRejected(
            bounded_reason("invalid read field", format!("{field}: {reason}")),
        )),
        ReadError::EmptyField(field) => Err(ContextInputsError::RequestRejected(
            bounded_reason("empty read field", field),
        )),
        ReadError::DuplicateField(field) => Err(ContextInputsError::RequestRejected(
            bounded_reason("duplicate read field", field),
        )),
        ReadError::InvalidResourceUri => Err(ContextInputsError::RequestRejected(
            "invalid exact resource URI".to_owned(),
        )),
        ReadError::InvalidDependencyRevision => Err(ContextInputsError::RequestRejected(
            "invalid dependency revision".to_owned(),
        )),
    }
}

/// Classifies an opaque role payload: only an explicit null is an
/// authoritative empty; any present value is complete.
fn classify_opaque_payload(payload: &Value) -> ProjectionState {
    if payload.is_null() {
        ProjectionState::KnownEmpty
    } else {
        ProjectionState::Complete
    }
}

/// Decodes the current-position payload into the T11.2 readback shape.
///
/// `None` from a successful read is an authoritative empty positions view.
/// A non-committed or undecodable payload is `Unavailable`, never empty and
/// never promoted: only an external receipt proves an admitted position.
fn decode_epistemic_payload(payload: &Value) -> (ProjectionState, Option<EpistemicPositionReadback>) {
    let readback: Option<EpistemicPositionReadback> = match serde_json::from_value(payload.clone())
    {
        Ok(value) => value,
        Err(error) => {
            return (
                ProjectionState::Unavailable {
                    reason: bounded_reason("position payload is not a readback", error),
                },
                None,
            );
        }
    };
    match readback {
        None => (ProjectionState::KnownEmpty, None),
        Some(readback) if readback.receipt.status != WriteReceiptStatus::Committed => (
            ProjectionState::Unavailable {
                reason: "position readback carries no committed receipt".to_owned(),
            },
            None,
        ),
        Some(readback) => (ProjectionState::Complete, Some(readback)),
    }
}

/// Classifies an evidence-pack payload against its authoritative provenance.
///
/// `KnownEmpty` requires the exact empty result: zero records with an
/// explicit `truncated: false` and matching totals. A truncated pack is
/// `Partial`; a payload whose provenance does not describe its records is
/// `Unknown`. Transport and catalogue failures never reach this function.
fn classify_evidence_payload(
    payload: &Value,
    scope: &ScopeId,
    subject: &str,
) -> ProjectionState {
    let unavailable = |detail: &str| ProjectionState::Unavailable {
        reason: bounded_reason("evidence payload fails its contract", detail),
    };
    if payload.get("version").and_then(Value::as_u64) != Some(1) {
        return unavailable("unsupported evidence pack version");
    }
    if payload.get("subject").and_then(Value::as_str) != Some(subject) {
        return unavailable("evidence subject mismatch");
    }
    if payload.get("scope_id").and_then(Value::as_str) != Some(scope.as_str()) {
        return unavailable("evidence scope mismatch");
    }
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return unavailable("evidence payload has no records array");
    };
    let provenance = payload.get("provenance");
    let truncated = provenance
        .and_then(|provenance| provenance.get("truncated"))
        .and_then(Value::as_bool);
    let matched = provenance
        .and_then(|provenance| provenance.get("matched_total"))
        .and_then(Value::as_u64);
    let returned = provenance
        .and_then(|provenance| provenance.get("returned"))
        .and_then(Value::as_u64);
    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    match (truncated, matched, returned) {
        (Some(false), Some(0), Some(0)) if records.is_empty() => ProjectionState::KnownEmpty,
        (Some(false), Some(matched), Some(returned))
            if matched == returned && returned == count =>
        {
            ProjectionState::Complete
        }
        (Some(true), _, _) => ProjectionState::Partial {
            reason: "evidence pack truncated at the declared bound".to_owned(),
        },
        _ => ProjectionState::Unknown {
            reason: "evidence provenance does not authoritatively describe the records".to_owned(),
        },
    }
}

#[cfg(test)]
mod reconstruction_tests {
    use super::*;

    type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn request_validation_rejects_blank_selectors_and_over_bound() -> ProofResult {
        let request = valid_request()?;
        request.validate()?;
        let mut blank = request.clone();
        blank.epistemic_position = "   ".to_owned();
        assert!(blank.validate().is_err());
        let mut blank_subject = request.clone();
        blank_subject.evidence_subject = "\t".to_owned();
        assert!(blank_subject.validate().is_err());
        let mut over_bound = request.clone();
        over_bound.evidence_max_records = EVIDENCE_PACK_MAX_RECORDS + 1;
        assert!(over_bound.validate().is_err());
        let mut zero_bound = request.clone();
        zero_bound.evidence_max_records = 0;
        assert!(zero_bound.validate().is_err());
        let mut zero_revision = request;
        zero_revision
            .dependency_revisions
            .insert(RevisionKey::new("scope:scope-a")?, 0);
        assert!(zero_revision.validate().is_err());
        Ok(())
    }

    #[test]
    fn store_and_churn_failures_are_never_empty() -> ProofResult {
        let unavailable =
            classify_read_error(ReadError::Store("unknown operation".to_owned()))?;
        assert!(matches!(
            unavailable,
            ProjectionState::Unavailable { .. }
        ));
        let stale = classify_read_error(ReadError::RevisionChurn)?;
        assert!(matches!(stale, ProjectionState::Stale { .. }));
        let blocked = classify_read_error(ReadError::MissingDependencies)?;
        assert!(matches!(blocked, ProjectionState::Blocked { .. }));
        // Caller-shape rejections abort instead of becoming dispositions.
        assert!(classify_read_error(ReadError::EmptyField("query.query".to_owned())).is_err());
        Ok(())
    }

    #[test]
    fn evidence_classifier_requires_authoritative_emptiness() -> ProofResult {
        let scope = ScopeId::new("scope-a")?;
        let empty = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        assert_eq!(
            classify_evidence_payload(&empty, &scope, "subject-a"),
            ProjectionState::KnownEmpty
        );
        // Same zero records, but the truncation flag is authoritative: a
        // truncated empty page is partial, not empty.
        let truncated_empty = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 4, "returned": 0, "truncated": true},
        });
        assert!(matches!(
            classify_evidence_payload(&truncated_empty, &scope, "subject-a"),
            ProjectionState::Partial { .. }
        ));
        // Records without a describing provenance are unknown, never empty.
        let undescribed = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
        });
        assert!(matches!(
            classify_evidence_payload(&undescribed, &scope, "subject-a"),
            ProjectionState::Unknown { .. }
        ));
        // A substituted subject fails the contract instead of completing.
        let substituted = serde_json::json!({
            "version": 1,
            "subject": "subject-b",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        assert!(matches!(
            classify_evidence_payload(&substituted, &scope, "subject-a"),
            ProjectionState::Unavailable { .. }
        ));
        Ok(())
    }

    #[test]
    fn unsupported_roles_report_distinctly_from_known_empty() -> ProofResult {
        let inputs = SevenRoleInputs {
            scope_id: ScopeId::new("scope-a")?,
            state_fence: test_fence()?,
            heads_before: test_heads("scope-a")?,
            heads_after: test_heads("scope-a")?,
            task_frame: unavailable_role(NamedReadOperation::GetTaskState),
            attention: unavailable_role(NamedReadOperation::GetAttentionAndProblems),
            epistemic: RoleAcquisition {
                operation: NamedReadOperation::GetCurrentEpistemicPosition,
                state: ProjectionState::KnownEmpty,
                payload: Some(Value::Null),
                revision_heads: Vec::new(),
            },
            epistemic_readback: None,
            cue: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            negative_memory: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            evidence: RoleAcquisition {
                operation: NamedReadOperation::GetEvidencePack,
                state: ProjectionState::Complete,
                payload: Some(serde_json::json!({"records": []})),
                revision_heads: Vec::new(),
            },
            affordances: unavailable_role(NamedReadOperation::GetCapabilityEvidenceState),
        };
        let unsupported = inputs.unsupported_role_names();
        assert!(unsupported.contains(&ROLE_TASK_FRAME));
        assert!(unsupported.contains(&ROLE_CUE_ACTIVATION));
        assert!(unsupported.contains(&ROLE_AFFORDANCES));
        assert!(!unsupported.contains(&ROLE_EPISTEMIC_POSITION));
        assert!(!unsupported.contains(&ROLE_EVIDENCE_ASSURANCE));
        assert!(inputs.has_unsupported_distinct_from_empty());
        Ok(())
    }

    fn valid_request() -> ProofResult<ContextReconstructionRequest> {
        let mut dependency_revisions = BTreeMap::new();
        dependency_revisions.insert(RevisionKey::new("scope:scope-a")?, 1);
        Ok(ContextReconstructionRequest {
            scope_id: ScopeId::new("scope-a")?,
            dependency_revisions,
            epistemic_position: "position-a".to_owned(),
            evidence_subject: "subject-a".to_owned(),
            evidence_max_records: 8,
        })
    }

    fn unavailable_role(operation: NamedReadOperation) -> RoleAcquisition {
        RoleAcquisition {
            operation,
            state: ProjectionState::Unavailable {
                reason: "store read failed: unknown operation".to_owned(),
            },
            payload: None,
            revision_heads: Vec::new(),
        }
    }

    fn test_fence() -> ProofResult<eliot_contracts::StateFence> {
        use std::num::NonZeroU64;
        let lineage = eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let epoch = eliot_contracts::EpochId::new(lineage, NonZeroU64::new(1).ok_or(
            eliot_store_api::StoreError::InvalidField {
                field: "test.sequence",
                reason: "must be non-zero",
            },
        )?)?;
        Ok(eliot_contracts::StateFence::new(
            epoch,
            eliot_contracts::ResourceGeneration::genesis(),
        ))
    }

    fn test_heads(scope: &str) -> ProofResult<ScopeRevisionView> {
        let fence = test_fence()?;
        let view = ScopeRevisionView {
            scope_id: ScopeId::new(scope)?,
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new(format!("scope:{scope}"))?,
                revision: 1,
                state_fence: fence.clone(),
            }],
            ordering_heads: Vec::new(),
            state_fence: fence,
        };
        view.validate()?;
        Ok(view)
    }
}
