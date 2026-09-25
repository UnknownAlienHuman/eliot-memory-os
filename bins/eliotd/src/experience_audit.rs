//! Authenticated manual experience-quality dispatch boundary (issue #223).
//!
//! This is the current-daemon caller for the O1 experience lane. It is
//! reached only when the Kernel has claimed and admitted an invocation whose
//! canonical tool name is [`MANUAL_EXPERIENCE_QUALITY_TOOL`]. The request
//! carries owner-issued bank/feedback envelopes, retention material, receipt
//! candidates, memory-projection inputs, and the complete Dreamer revision
//! intake. This module never fills one of those fields with a default, a
//! timestamp, a boolean, a scope, or an authority. The authenticated envelope
//! and the claimed attempt are checked again before any bridge read or
//! canonical commit is attempted.
//!
//! The donor O1 audit is provenance, not a semantic shortcut: its old
//! `Pending` supplier branches are intentionally not ported. The manual
//! request is the missing owner-input read boundary. It runs the real
//! position read, the owner-page consumer driver, the memory projection and
//! selection edge, the admitted Dreamer revision proposal, and the canonical
//! bank/feedback commit path. It is manual/O1: no timer, GitHub event, or
//! automatic trigger is introduced here.

#![forbid(unsafe_code)]
#![allow(
    clippy::large_futures,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_context_contracts::{SafetyProjection, TaskProjection};
use eliot_contracts::{RequestMetadata, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::self_query::{AcceptedSourceProjection, SelfQueryInput};
use eliot_dreamer_memory_revision::{RevisionIntake, SchemaFreezeBinding};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_memory_projection_contracts::{MemoryQueryIntent, MemorySelectionPolicy};
use eliot_memory_projection_provider::ProjectionRequest;
use eliot_observation::bank_admission::{
    BANK_SOURCE_ID, BankStoreSnapshot, ConsumerPagedReadDriver, ExperienceRevisionLedger,
    FEEDBACK_SOURCE_ID, FeedbackStoreSnapshot, bank_records_from_page, feedback_records_from_page,
    parse_experience_range_page,
};
use eliot_observation_contracts::{
    FailureObservation, MemoryRevisionEvidence, ObservationScope, RetentionHold, RetentionSchedule,
};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_VERSION, HostRequestEnvelope,
    HostRequestKind, HostRequestResultBody, LocalReadAttempt, host_request_operation_id,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CanonicalReadClient, MAX_EXPERIENCE_PAGE_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OrderingHeadExpectation, ReadConsistency, RevisionHeadExpectation, ScopeId,
    WriteReceipt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::experience_runtime::{
    self, ExperienceBankEventInputs, ExperienceDriverError, ExperienceFeedbackEventInputs,
    ExperienceQualityEvent,
};
use crate::{DaemonComposition, DaemonKernelClient};

/// Exact capability name for the manual experience-quality dispatch.
pub const MANUAL_EXPERIENCE_QUALITY_TOOL: &str = "eliot.experience.quality.manual";
/// Payload schema identity admitted with the manual dispatch.
pub const MANUAL_EXPERIENCE_PAYLOAD_SCHEMA_ID: &str = "eliot.daemon.experience-quality-request";
/// Wire identity of the owner-input request.
pub const MANUAL_EXPERIENCE_REQUEST_WIRE_ID: &str = "eliot.daemon.experience-quality-request";
/// Current wire version of the owner-input request.
pub const MANUAL_EXPERIENCE_REQUEST_WIRE_VERSION: u16 = 1;

/// Owner action selecting how the retained family state is entered.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManualPagedAction {
    /// Use the family's retained state and the exact owner selector supplied.
    UseCurrent,
    /// Invalidate only this family and restart it from the headless page.
    RestartFromHead,
}

/// Rebuildable paging state retained by the daemon composition.
///
/// The state is a projection/consumer cursor, not durable authority. It is
/// retained across claimed manual requests so a continuation or a
/// family-local restart cannot silently create a fresh generation. The
/// current page token is still issued only by the owner driver.
pub struct ManualExperienceSession {
    /// Current two-family paging state.
    pub driver: ConsumerPagedReadDriver,
    /// Current owner revision ledger bound to the retained paging state.
    pub ledger: ExperienceRevisionLedger,
    /// Exact last live bank owner page, retained while its family is complete.
    pub last_bank_payload: Option<Value>,
    /// Exact last live feedback owner page, retained while its family is complete.
    pub last_feedback_payload: Option<Value>,
}

impl ManualExperienceSession {
    /// Creates an empty first-page session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            driver: ConsumerPagedReadDriver::headless(),
            ledger: ExperienceRevisionLedger::new(),
            last_bank_payload: None,
            last_feedback_payload: None,
        }
    }
}

impl Default for ManualExperienceSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Exact shared memory-projection request carried by a manual event.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualMemoryProjectionInput {
    /// Existing Governor provider request.
    pub request: ProjectionRequest,
    /// Existing shared selection intent.
    pub intent: MemoryQueryIntent,
    /// Existing shared selection policy.
    pub policy: MemorySelectionPolicy,
}

/// Owned wire carrier for the borrowed Dreamer owner intake.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualRevisionInput {
    /// Current owner-supplied schema-freeze identity and readback.
    pub schema_freeze: SchemaFreezeBinding,
    /// Owner-neutral failure observation.
    pub observation: FailureObservation,
    /// Owner-issued revision evidence.
    pub evidence: Vec<MemoryRevisionEvidence>,
    /// Admitted task projection.
    pub task: TaskProjection,
    /// Admitted safety projection.
    pub safety: SafetyProjection,
    /// Frozen self-query input.
    pub query: SelfQueryInput,
    /// Accepted-source projection.
    pub sources: AcceptedSourceProjection,
    /// Exact posed-query digest.
    pub pose_digest: String,
    /// Candidate identity supplied by the owner edge.
    pub candidate_id: eliot_contracts::ArtifactId,
}

/// Authenticated owner inputs for one manual experience-quality event.
///
/// This is an integration wire carrier, not a second experience projection or
/// provider request. Every member is an existing owner type. In particular,
/// `receipts`, retention terms, source revisions, handles, scope, and the
/// revision intake are required rather than synthesized when absent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualExperienceQualityRequest {
    /// Request wire identity.
    pub wire_id: String,
    /// Request wire version.
    pub wire_version: u16,
    /// Exact owner metadata carried by the admitted request.
    pub metadata: RequestMetadata,
    /// Kernel-issued owner admission receipt digest echoed by the manual
    /// request; it must equal the authenticated envelope's receipt digest.
    pub owner_admission_receipt_sha256: String,
    /// Owner-issued assessment correlation identity.
    pub assessment_id: eliot_contracts::ArtifactId,
    /// Owner-issued work scope for the assessment.
    pub assessment_scope: WorkScopeId,
    /// Owner-issued observation scope.
    pub scope: ObservationScope,
    /// Store scope address for the exact owner read.
    pub scope_id: ScopeId,
    /// Exact position subject selector.
    pub position_subject: String,
    /// Bank owner range envelope and its owner read context.
    pub bank: ExperienceBankEventInputs,
    /// Feedback owner range envelope and its owner read context.
    pub feedback: ExperienceFeedbackEventInputs,
    /// Action for the retained bank paging state.
    pub bank_action: ManualPagedAction,
    /// Action for the retained feedback paging state.
    pub feedback_action: ManualPagedAction,
    /// Exact selector used for the bank owner read, if continuing.
    pub bank_selector: Option<String>,
    /// Exact selector used for the feedback owner read, if continuing.
    pub feedback_selector: Option<String>,
    /// Owner-issued retention schedule.
    pub schedule: RetentionSchedule,
    /// Owner-issued retention holds.
    pub holds: BTreeMap<String, RetentionHold>,
    /// Per-attempt receipt candidates. At least one is required.
    pub receipts: Vec<HarnessActivationReceiptCandidate>,
    /// Obligation-profile handles cited by the owner.
    pub obligation_handles: Vec<eliot_contracts::ArtifactId>,
    /// Handles attested by the owner edge.
    pub attested_handles: Vec<eliot_contracts::ArtifactId>,
    /// Required shared memory projection/selection edge inputs.
    pub memory_projection: ManualMemoryProjectionInput,
    /// Required admitted Dreamer revision intake.
    pub revision: ManualRevisionInput,
    /// Exact live revision expectations supplied by the owner read.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Exact live ordering expectations supplied by the owner read.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

/// A typed failure at the authenticated manual boundary.
#[derive(Debug, Error)]
pub enum ExperienceAuditError {
    /// The admitted request or one of its owner inputs was refused.
    #[error("manual experience request refused: {0}")]
    Request(String),
    /// The real experience driver refused the owner event.
    #[error("manual experience driver: {0}")]
    Driver(#[from] ExperienceDriverError),
    /// The result body could not be encoded within the protocol ceiling.
    #[error("manual experience result body: {0}")]
    ResultBody(String),
}

#[derive(Clone, Debug, Serialize)]
struct ReceiptSummary {
    operation_id: String,
    idempotency_key: String,
    canonical_request_hash: String,
    status: String,
}

#[derive(Clone, Debug, Serialize)]
struct ManualExperienceResult {
    status: String,
    assessment_digest: String,
    extinction_candidate_digest: String,
    bank_receipts: Vec<ReceiptSummary>,
    feedback_receipts: Vec<ReceiptSummary>,
    bank_next_cursor: String,
    feedback_next_cursor: String,
    bank_next_selector: Option<String>,
    feedback_next_selector: Option<String>,
    memory_projection_present: bool,
    view_stale: bool,
    health: String,
    ready: bool,
    degraded: bool,
    refresh_error: Option<String>,
    error: Option<String>,
}

impl ManualExperienceResult {
    fn refused(error: String) -> Self {
        Self {
            status: "refused".to_owned(),
            assessment_digest: String::new(),
            extinction_candidate_digest: String::new(),
            bank_receipts: Vec::new(),
            feedback_receipts: Vec::new(),
            bank_next_cursor: "missing".to_owned(),
            feedback_next_cursor: "missing".to_owned(),
            bank_next_selector: None,
            feedback_next_selector: None,
            memory_projection_present: false,
            view_stale: false,
            health: "unknown".to_owned(),
            ready: false,
            degraded: true,
            refresh_error: None,
            error: Some(error),
        }
    }
}

/// Returns true only for the exact manually admitted capability name.
#[must_use]
pub fn is_manual_experience_tool(tool: &Value) -> bool {
    tool.get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| name == MANUAL_EXPERIENCE_QUALITY_TOOL)
}

fn validate_admission(
    request: &ManualExperienceQualityRequest,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<(), ExperienceAuditError> {
    if request.wire_id != MANUAL_EXPERIENCE_REQUEST_WIRE_ID
        || request.wire_version != MANUAL_EXPERIENCE_REQUEST_WIRE_VERSION
    {
        return Err(ExperienceAuditError::Request(
            "unsupported manual experience request wire".to_owned(),
        ));
    }
    request
        .metadata
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    envelope
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    attempt
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    if envelope.kind != HostRequestKind::Invocation
        || envelope.identity.capability != MANUAL_EXPERIENCE_QUALITY_TOOL
        || envelope.identity.payload_schema_id != MANUAL_EXPERIENCE_PAYLOAD_SCHEMA_ID
        || !is_manual_experience_tool(tool)
        || attempt.operation_id != host_request_operation_id(envelope)
        || attempt.facet_method != MANUAL_EXPERIENCE_QUALITY_TOOL
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.session_id != envelope.identity.session_id.clone().unwrap_or_default()
        || attempt.scope_id != request.scope_id.as_str()
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
    {
        return Err(ExperienceAuditError::Request(
            "manual tool, envelope, attempt, or admitted binding disagrees".to_owned(),
        ));
    }
    let tool_bytes = canonical_json_bytes(tool)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    if sha256_hex(&tool_bytes) != envelope.identity.payload_sha256 {
        return Err(ExperienceAuditError::Request(
            "manual tool bytes are not the exact owner-admitted payload".to_owned(),
        ));
    }
    if request.owner_admission_receipt_sha256 != envelope.peer_admission_receipt_sha256
        || request.owner_admission_receipt_sha256.len() != 64
        || request
            .owner_admission_receipt_sha256
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ExperienceAuditError::Request(
            "manual owner admission receipt is not the authenticated Kernel receipt".to_owned(),
        ));
    }
    if request.metadata.request_id != envelope.identity.request_id
        || request.metadata.state_fence != envelope.state_fence
        || request.metadata.session_id.as_ref().map(|id| id.as_str())
            != envelope.identity.session_id.as_deref()
        || request.metadata.task_id.as_ref().map(|id| id.as_str())
            != envelope.identity.task_id.as_deref()
    {
        return Err(ExperienceAuditError::Request(
            "owner metadata is not the exact authenticated envelope binding".to_owned(),
        ));
    }
    if request.scope_id.as_str() != request.scope.work_scope.as_str()
        || request.assessment_scope != request.scope.work_scope
        || request.scope.task_ref.as_deref().is_some_and(|task| {
            Some(task) != request.metadata.task_id.as_ref().map(|id| id.as_str())
        })
    {
        return Err(ExperienceAuditError::Request(
            "manual scope, assessment scope, and owner task binding disagree".to_owned(),
        ));
    }
    if (request.bank_action == ManualPagedAction::RestartFromHead
        && request.bank_selector.is_some())
        || (request.feedback_action == ManualPagedAction::RestartFromHead
            && request.feedback_selector.is_some())
    {
        return Err(ExperienceAuditError::Request(
            "a family restart must use the headless selector".to_owned(),
        ));
    }
    if request.bank.source_id != BANK_SOURCE_ID
        || request.feedback.source_id != FEEDBACK_SOURCE_ID
        || request.bank.projection_id != request.feedback.projection_id
    {
        return Err(ExperienceAuditError::Request(
            "experience source identities or aggregate projection identity are not owner-issued"
                .to_owned(),
        ));
    }
    request
        .schedule
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    if request.schedule.fence != request.metadata.state_fence {
        return Err(ExperienceAuditError::Request(
            "retention schedule is not in force at the authenticated fence".to_owned(),
        ));
    }
    for hold in request.holds.values() {
        hold.validate()
            .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    }
    if request.receipts.is_empty() {
        return Err(ExperienceAuditError::Request(
            "at least one owner-issued activation receipt is required".to_owned(),
        ));
    }
    for receipt in &request.receipts {
        receipt
            .validate()
            .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
        let binding = &receipt.binding;
        if binding.request_id != request.metadata.request_id
            || binding.product_id != request.metadata.product_id
            || binding.task_id.as_str()
                != request
                    .metadata
                    .task_id
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or_default()
            || binding.scope != request.scope.work_scope
            || binding.state_fence != request.metadata.state_fence
        {
            return Err(ExperienceAuditError::Request(
                "activation receipt is not bound to the authenticated owner scope/fence/request"
                    .to_owned(),
            ));
        }
    }
    request
        .revision
        .schema_freeze
        .validate_current()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    for expectation in &request.expected_revision_heads {
        expectation
            .validate()
            .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
        if expectation.state_fence != request.metadata.state_fence {
            return Err(ExperienceAuditError::Request(
                "revision expectation is not bound to the authenticated fence".to_owned(),
            ));
        }
    }
    for expectation in &request.expected_ordering_heads {
        expectation
            .validate()
            .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
        if expectation.state_fence != request.metadata.state_fence {
            return Err(ExperienceAuditError::Request(
                "ordering expectation is not bound to the authenticated fence".to_owned(),
            ));
        }
    }
    Ok(())
}

fn decode_request(tool: &Value) -> Result<ManualExperienceQualityRequest, ExperienceAuditError> {
    let arguments = tool.get("arguments").ok_or_else(|| {
        ExperienceAuditError::Request("manual tool arguments are absent".to_owned())
    })?;
    serde_json::from_value(arguments.clone())
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))
}

fn receipt_summary(receipt: &WriteReceipt) -> Result<ReceiptSummary, ExperienceAuditError> {
    receipt
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    Ok(ReceiptSummary {
        operation_id: receipt.operation_id.to_string(),
        idempotency_key: receipt.idempotency_key.clone(),
        canonical_request_hash: receipt.canonical_request_hash.clone(),
        status: format!("{:?}", receipt.status),
    })
}

async fn read_live_manual_page(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation: NamedReadOperation,
    scope_id: ScopeId,
    fence: &eliot_contracts::StateFence,
    selector: Option<&str>,
    expected_payload: &Value,
    expected_heads: &[RevisionHeadExpectation],
) -> Result<NamedReadResponse, ExperienceAuditError> {
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "max_records".to_owned(),
        Value::String(MAX_EXPERIENCE_PAGE_RECORDS.to_string()),
    );
    if let Some(cursor) = selector {
        parameters.insert("cursor".to_owned(), Value::String(cursor.to_owned()));
    }
    let request = NamedReadRequest {
        operation,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence: fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    let response = client
        .execute_named(request)
        .await
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    response
        .validate()
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    if response.operation != operation || response.state_fence != *fence {
        return Err(ExperienceAuditError::Request(
            "live experience read did not echo the exact operation and fence".to_owned(),
        ));
    }
    if &response.payload != expected_payload {
        return Err(ExperienceAuditError::Request(
            "submitted experience page is not the current live owner page".to_owned(),
        ));
    }
    for head in &response.revision_heads {
        if !expected_heads.iter().any(|expected| {
            expected.key == head.key
                && expected.expected_revision == head.revision
                && expected.state_fence == head.state_fence
        }) {
            return Err(ExperienceAuditError::Request(
                "submitted revision expectation is not present in the live owner read".to_owned(),
            ));
        }
    }
    Ok(response)
}

async fn drive_manual(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    request: ManualExperienceQualityRequest,
    session: &mut ManualExperienceSession,
) -> Result<ManualExperienceResult, ExperienceAuditError> {
    if request.bank_action == ManualPagedAction::RestartFromHead {
        session.driver.restart_bank_from_head(&mut session.ledger);
    }
    if request.feedback_action == ManualPagedAction::RestartFromHead {
        session
            .driver
            .restart_feedback_from_head(&mut session.ledger);
    }
    let bank_needs_live_read = !matches!(
        session.driver.bank_state(),
        eliot_observation::bank_admission::ConsumerPagedFamilyState::Complete
    );
    let feedback_needs_live_read = !matches!(
        session.driver.feedback_state(),
        eliot_observation::bank_admission::ConsumerPagedFamilyState::Complete
    );
    let bank_payload = if bank_needs_live_read {
        request.bank.payload.clone()
    } else {
        session.last_bank_payload.clone().ok_or_else(|| {
            ExperienceAuditError::Request(
                "completed bank family has no retained owner page".to_owned(),
            )
        })?
    };
    let feedback_payload = if feedback_needs_live_read {
        request.feedback.payload.clone()
    } else {
        session.last_feedback_payload.clone().ok_or_else(|| {
            ExperienceAuditError::Request(
                "completed feedback family has no retained owner page".to_owned(),
            )
        })?
    };
    if !bank_needs_live_read && request.bank.payload != bank_payload {
        return Err(ExperienceAuditError::Request(
            "completed bank family payload differs from the retained live owner page".to_owned(),
        ));
    }
    if !feedback_needs_live_read && request.feedback.payload != feedback_payload {
        return Err(ExperienceAuditError::Request(
            "completed feedback family payload differs from the retained live owner page"
                .to_owned(),
        ));
    }
    let bank_page = parse_experience_range_page(&bank_payload)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    let feedback_page = parse_experience_range_page(&feedback_payload)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    let bank_records = bank_records_from_page(&bank_page)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    let feedback_records = feedback_records_from_page(&feedback_page)
        .map_err(|error| ExperienceAuditError::Request(error.to_string()))?;
    if bank_needs_live_read {
        read_live_manual_page(
            composition,
            kernel,
            NamedReadOperation::GetExperienceBankRange,
            request.scope_id.clone(),
            &request.metadata.state_fence,
            request.bank_selector.as_deref(),
            &bank_payload,
            &request.expected_revision_heads,
        )
        .await?;
    }
    if feedback_needs_live_read {
        read_live_manual_page(
            composition,
            kernel,
            NamedReadOperation::GetAgentFeedbackRange,
            request.scope_id.clone(),
            &request.metadata.state_fence,
            request.feedback_selector.as_deref(),
            &feedback_payload,
            &request.expected_revision_heads,
        )
        .await?;
    }
    let page = experience_runtime::assemble_experience_consumer_page(
        &mut session.driver,
        &mut session.ledger,
        request.bank.projection_id.clone(),
        &request.scope,
        &request.metadata.state_fence,
        BankStoreSnapshot {
            records: &bank_records,
            source_revision: request.bank.source_revision.clone(),
            coverage: request.bank.coverage.clone(),
            omissions: request.bank.omissions.clone(),
        },
        FeedbackStoreSnapshot {
            records: &feedback_records,
            source_revision: request.feedback.source_revision.clone(),
            coverage: request.feedback.coverage.clone(),
            omissions: request.feedback.omissions.clone(),
        },
        &request.schedule,
        &request.holds,
        request.bank_selector.as_deref(),
        request.feedback_selector.as_deref(),
        bank_page.next_cursor.clone(),
        feedback_page.next_cursor.clone(),
    )?;
    if bank_needs_live_read {
        session.last_bank_payload = Some(bank_payload);
    }
    if feedback_needs_live_read {
        session.last_feedback_payload = Some(feedback_payload);
    }

    let intake = RevisionIntake {
        schema_freeze: Some(&request.revision.schema_freeze),
        observation: &request.revision.observation,
        evidence: &request.revision.evidence,
        task: &request.revision.task,
        safety: &request.revision.safety,
        query: &request.revision.query,
        sources: &request.revision.sources,
        pose_digest: &request.revision.pose_digest,
        candidate_id: &request.revision.candidate_id,
    };
    let event = ExperienceQualityEvent {
        assessment_id: request.assessment_id.clone(),
        assessment_scope: request.assessment_scope.clone(),
        scope: request.scope.clone(),
        scope_id: request.scope_id.clone(),
        position_subject: request.position_subject.clone(),
        journal: None,
        bank: request.bank.clone(),
        feedback: request.feedback.clone(),
        schedule: &request.schedule,
        holds: &request.holds,
        receipts: &request.receipts,
        obligation_handles: &request.obligation_handles,
        attested_handles: request.attested_handles.clone(),
        memory: None,
        memory_projection: Some((
            &request.memory_projection.request,
            &request.memory_projection.intent,
            &request.memory_projection.policy,
        )),
        revision: None,
        understanding: None,
        common_ground: None,
    };
    let (quality, extinction) =
        experience_runtime::run_experience_quality_event_with_admitted_revision(
            composition,
            kernel,
            &request.metadata,
            &event,
            &intake,
        )
        .await?;
    let commit = experience_runtime::commit_experience_event_records(
        composition,
        &request.metadata,
        &event,
        &session.driver,
        &page,
        &mut session.ledger,
        &bank_records,
        &feedback_records,
        request.expected_revision_heads.clone(),
        request.expected_ordering_heads.clone(),
    )
    .await?;

    let mut bank_receipts = Vec::with_capacity(commit.bank_receipts.len());
    for receipt in &commit.bank_receipts {
        bank_receipts.push(receipt_summary(receipt)?);
    }
    let mut feedback_receipts = Vec::with_capacity(commit.feedback_receipts.len());
    for receipt in &commit.feedback_receipts {
        feedback_receipts.push(receipt_summary(receipt)?);
    }
    let status = if commit.view_stale || commit.refresh_error.is_some() {
        "stale".to_owned()
    } else if commit.degraded || !commit.ready {
        "degraded".to_owned()
    } else {
        "completed".to_owned()
    };
    Ok(ManualExperienceResult {
        status,
        assessment_digest: quality.candidate.digest,
        extinction_candidate_digest: extinction.digest,
        bank_receipts,
        feedback_receipts,
        bank_next_cursor: boundary_wire(&page.bank_next_cursor),
        feedback_next_cursor: boundary_wire(&page.feedback_next_cursor),
        bank_next_selector: session.driver.bank_cursor().map(str::to_owned),
        feedback_next_selector: session.driver.feedback_cursor().map(str::to_owned),
        memory_projection_present: quality.memory_projection.is_some(),
        view_stale: commit.view_stale,
        health: commit.health,
        ready: commit.ready,
        degraded: commit.degraded,
        refresh_error: commit.refresh_error,
        error: None,
    })
}

fn boundary_wire(boundary: &eliot_store_api::PageBoundary) -> String {
    match boundary {
        eliot_store_api::PageBoundary::MissingCursor => "missing".to_owned(),
        eliot_store_api::PageBoundary::ExplicitEnd => "explicit_end".to_owned(),
        eliot_store_api::PageBoundary::Continuation(cursor) => {
            format!("continuation:{cursor}")
        }
    }
}

fn result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    result: &ManualExperienceResult,
) -> Result<HostRequestResultBody, ExperienceAuditError> {
    let response = serde_json::to_value(result)
        .map_err(|error| ExperienceAuditError::ResultBody(error.to_string()))?;
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| ExperienceAuditError::ResultBody(error.to_string()))?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HOST_REQUEST_RESULT_BODY_WIRE_VERSION,
        operation_id: host_request_operation_id(envelope),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&bytes),
        response,
        attempt: Some(attempt.clone()),
    };
    body.validate()
        .map_err(|error| ExperienceAuditError::ResultBody(error.to_string()))?;
    Ok(body)
}

/// Serves one claimed, authenticated manual experience pair.
///
/// The function is called from the daemon's existing local-read poller. A
/// rejected owner request is persisted as a typed refusal body, while a
/// transport/body encoding failure remains a hard poller error. A valid
/// request consumes the quality output and every returned commit receipt; it
/// never reports a stale or degraded dependent view as healthy.
pub async fn serve_manual_experience_pair(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<HostRequestResultBody, ExperienceAuditError> {
    let result = match decode_request(tool).and_then(|request| {
        validate_admission(&request, envelope, tool, attempt)?;
        Ok(request)
    }) {
        Ok(request) => {
            let mut session = composition.take_experience_session();
            let result = drive_manual(composition, kernel, request, &mut session).await;
            composition.restore_experience_session(session);
            result
        }
        Err(error) => Err(error),
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let refused = ManualExperienceResult::refused(error.to_string());
            return result_body(envelope, attempt, &refused);
        }
    };
    result_body(envelope, attempt, &result)
}
