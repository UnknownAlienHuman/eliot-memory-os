use crate::{
    AdapterObservationBridge, AdapterSupervisor, EngineError, WorkState, WriteAdmissionService,
    WriterHandle,
};
use eliot_store::BlobStore;
use eliot_types::{
    AdapterCapability, AdapterContext, AdapterObservation, AdapterRequest, AgentId, AgentSessionId,
    BlackboardItem, BlobRef, CommandContext, ExternalCitationStatus, ExternalClaimStatus,
    ExternalFindingSeverity, ExternalForbiddenAction, ExternalOutputSchemaKind,
    ExternalProposedChange, ExternalProposedChangeKind, ExternalProviderAuthority,
    ExternalProviderKind, ExternalProviderLimits, ExternalProviderProfile,
    ExternalProviderTransport, ExternalReviewBudget, ExternalReviewFinding,
    ExternalReviewGateDecision, ExternalReviewGateDecisionKind, ExternalReviewGateReason,
    ExternalReviewJob, ExternalReviewJobStatus, ExternalReviewNormalizationReceipt,
    ExternalReviewPacket, ExternalReviewRequest, ExternalReviewResult, ExternalReviewResultStatus,
    ExternalReviewRole, ExternalUncertainty, ExternalVerifierSuggestion, LifecycleStatus,
    MailboxMessage, ProjectId, SemanticCommand, StrictJsonError, TaintClass, TaskId,
    ToolObservationRecordCommand, Visibility, WorkLease, WorktreeLease, WriteId, WriteReceiptRef,
    strict_json_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Lexical byte ceiling for one external-review raw provider document.
///
/// `serde_json::Map` is a `BTreeMap` in this workspace, so raw bytes must cross a
/// duplicate-rejecting decode (`eliot_types::strict_json_value`, owned by #2985)
/// before any `Value` exists, and a `Value` handed to
/// [`ExternalReviewNormalizer::normalize`] without that gate can only come from a
/// trusted in-process constructor. Bounding those bytes therefore bounds the
/// largest input that has to be retained, decoded and re-validated.
///
/// The value is deliberately independent of `request.budget.max_output_bytes`,
/// because that budget is per-request provider policy while this is a decoder
/// safety bound. It must nevertheless stay above the largest document the
/// existing mock path can legitimately produce, so that
/// `ExternalReviewJobService::run_mock_job` keeps normalizing every fixture it
/// normalizes today. The widest of those is the `mock-large-output` provider,
/// which appends a padding string of `request.budget.max_output_bytes + 512`; at
/// the default budget (`ExternalProviderLimits::default().max_raw_output_bytes`,
/// 32 KiB, which `ExternalReviewBudget::default` forwards to
/// `max_output_bytes`) that document is 33 280 bytes, leaving roughly 1 MiB of
/// headroom. A request would need a budget above ~1,087 KiB before that fixture
/// newly rejected. Real provider output is a small candidate document, so a
/// bound in the low megabytes keeps `mock-large-output` a size-stress fixture
/// that still normalizes, while a genuinely multi-megabyte document becomes a
/// bounded rejection rather than an unbounded decode.
const MAX_RAW_EXTERNAL_REVIEW_BYTES: usize = 1024 * 1024 + 64 * 1024;

/// One lexically validated external-review raw provider document.
///
/// The exact bytes and the duplicate-clean `Value` decoded from *those same
/// bytes* are bound to one value, so a `Value` cannot reach
/// [`ExternalReviewNormalizer::normalize`] except through one of the two named
/// constructors below. It owns no schema, authority, scoring or persistence:
/// it only records which bytes the normalizer read.
#[derive(Clone, Debug)]
pub struct ValidatedExternalReviewDocument {
    origin: ExternalReviewDocumentOrigin,
    bytes: Vec<u8>,
    value: Value,
}

impl ValidatedExternalReviewDocument {
    /// The exact bytes that were lexically validated.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The duplicate-clean value decoded from exactly [`Self::bytes`].
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Which construction path produced this document.
    #[must_use]
    pub const fn origin(&self) -> ExternalReviewDocumentOrigin {
        self.origin
    }
}

/// How a [`ValidatedExternalReviewDocument`] came into existence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalReviewDocumentOrigin {
    /// The document was decoded once from exact provider bytes through
    /// `eliot_types::strict_json_value`. This is the only construction that is
    /// evidence that the external bytes themselves preserve lexical integrity.
    StrictProviderBytes,
    /// The document was encoded from an already-constructed in-process value.
    ///
    /// No provider bytes ever existed at this call site, so a duplicate member
    /// was already collapsed before this value was built. Such a document can
    /// never be cited as proof that a raw external ingress is closed.
    InternalConstructed,
}

/// Standing of the retained raw evidence behind one normalized result.
///
/// Only a document strictly decoded from exact provider bytes qualifies its
/// retained handle as byte proof of what was normalized. An internally
/// constructed `Value`, a missing handle, or a historical record read back
/// without the live strict-decode binding is explicitly unqualified legacy
/// evidence: it may be revalidated for consistency, but that revalidation can
/// never silently upgrade it to provider-byte proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalReviewEvidenceStanding {
    /// Exact provider bytes were strictly decoded at ingress and those same
    /// bytes are retained: the handle is byte proof of what was normalized.
    StrictProviderBytes,
    /// No exact original bytes are bound to this evidence: an internally
    /// constructed or historical lossy `Value`, never provider-byte proof.
    UnqualifiedLegacy,
}

impl ExternalReviewEvidenceStanding {
    /// Standing of the live document being normalized.
    ///
    /// This is the production reader of
    /// [`ValidatedExternalReviewDocument::origin`]: only
    /// [`ExternalReviewDocumentOrigin::StrictProviderBytes`] qualifies the
    /// retained handle as byte proof.
    #[must_use]
    pub fn of_document(document: &ValidatedExternalReviewDocument) -> Self {
        match document.origin() {
            ExternalReviewDocumentOrigin::StrictProviderBytes => Self::StrictProviderBytes,
            ExternalReviewDocumentOrigin::InternalConstructed => Self::UnqualifiedLegacy,
        }
    }

    /// Historical readback over a retained raw-output handle without the live
    /// strict-decode binding.
    ///
    /// A bare handle never qualifies on its own: without the live binding, a
    /// byte handle cannot prove pre-collapse lexical integrity, so every arm
    /// returns [`Self::UnqualifiedLegacy`] with the reason naming the retained
    /// shape. Revalidation stays permitted for consistency; it is never a
    /// silent upgrade to provider-byte proof.
    #[must_use]
    pub fn read_back_historical(retained: Option<&BlobRef>) -> (Self, &'static str) {
        match retained {
            None => (
                Self::UnqualifiedLegacy,
                "raw evidence unqualified legacy: no retained raw-output handle and no exact original bytes; lossy value evidence stays explicitly unqualified",
            ),
            Some(handle) if handle.algorithm != "blake3" => (
                Self::UnqualifiedLegacy,
                "raw evidence unqualified legacy: retained handle is not content-addressed provider bytes; lossy value evidence stays explicitly unqualified",
            ),
            Some(_) => (
                Self::UnqualifiedLegacy,
                "raw evidence unqualified legacy: byte handle without the live strict-decode binding; revalidation cannot recover pre-collapse lexical proof",
            ),
        }
    }
}

impl ValidatedExternalReviewDocument {
    /// Binds one exact provider byte string to the duplicate-clean value decoded
    /// from those same bytes.
    ///
    /// A duplicate object member at any depth, malformed or trailing input, or a
    /// document above [`MAX_RAW_EXTERNAL_REVIEW_BYTES`] is one bounded, redacted
    /// rejection. No input byte, offset or member value is returned or echoed.
    pub fn strict_from_provider_bytes(bytes: &[u8]) -> Result<Self, StrictJsonError> {
        let value = strict_json_value(bytes, MAX_RAW_EXTERNAL_REVIEW_BYTES)?;
        Ok(Self {
            origin: ExternalReviewDocumentOrigin::StrictProviderBytes,
            bytes: bytes.to_vec(),
            value,
        })
    }

    /// Binds a trusted, already-constructed in-process value to a self-consistent
    /// canonical encoding of that same value.
    ///
    /// This exists for callers that never hold provider JSON bytes (a fixture, or
    /// a value built from truncated redacted provider *text*). The re-decode is a
    /// structural sanity check on a serialization this code just produced; it
    /// cannot recover a duplicate that was already collapsed into `value`, and
    /// the resulting document is [`ExternalReviewDocumentOrigin::InternalConstructed`]
    /// so that no caller or reader can mistake it for raw-byte evidence.
    pub fn internal_constructed(value: &Value) -> Result<Self, EngineError> {
        let bytes = serde_json::to_vec(value)?;
        let strict = strict_json_value(&bytes, MAX_RAW_EXTERNAL_REVIEW_BYTES).map_err(|error| {
            rejected(
                "external-review-document",
                &format!("constructed external review document is not strict JSON: {error}"),
            )
        })?;
        Ok(Self {
            origin: ExternalReviewDocumentOrigin::InternalConstructed,
            bytes,
            value: strict,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalProviderRegistryReport {
    pub component: String,
    pub providers: Vec<ExternalProviderProfile>,
    pub real_providers_disabled_by_default: bool,
    pub mock_provider_enabled: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewGateContext<'a> {
    pub work_lease: Option<&'a WorkLease>,
    pub worktree_lease: Option<&'a WorktreeLease>,
    pub provider_integration_eval_gate_passed: bool,
    pub incident_lockdown: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalReviewNormalizationOutcome {
    pub receipt: ExternalReviewNormalizationReceipt,
    pub result: Option<ExternalReviewResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalReviewBridgeReport {
    pub component: String,
    pub result_id: String,
    pub write_receipt: Option<WriteReceiptRef>,
    pub observation: AdapterObservation,
    pub blackboard_items: Vec<BlackboardItem>,
    pub mailbox_messages: Vec<MailboxMessage>,
    pub candidate_diff_refs: Vec<String>,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalReviewDoctorStatus {
    pub component: String,
    pub providers_total: usize,
    pub mock_providers_enabled: usize,
    pub real_providers_disabled: bool,
    pub governed_mcp_tools_only: bool,
    pub generated_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalProviderRegistryService;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewPacketBuilder;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewGate;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewJobService;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewNormalizer;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewTaintPolicy;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewBridgeService;

#[derive(Clone, Copy, Debug, Default)]
pub struct ExternalReviewReportService;

impl ExternalProviderRegistryService {
    #[must_use]
    pub fn profiles(&self) -> Vec<ExternalProviderProfile> {
        vec![
            mock_profile(
                "mock-auditor",
                "Mock Auditor",
                vec![ExternalReviewRole::Auditor, ExternalReviewRole::Reviewer],
                vec![
                    ExternalOutputSchemaKind::AuditFindings,
                    ExternalOutputSchemaKind::MixedReview,
                ],
                false,
            ),
            mock_profile(
                "mock-malformed",
                "Mock Malformed Output",
                vec![ExternalReviewRole::Auditor],
                vec![ExternalOutputSchemaKind::AuditFindings],
                false,
            ),
            mock_profile(
                "mock-authority-violator",
                "Mock Authority Violator",
                vec![ExternalReviewRole::Auditor],
                vec![ExternalOutputSchemaKind::AuditFindings],
                false,
            ),
            mock_profile(
                "mock-large-output",
                "Mock Large Output",
                vec![ExternalReviewRole::Auditor],
                vec![ExternalOutputSchemaKind::AuditFindings],
                false,
            ),
            mock_profile(
                "mock-proposed-change",
                "Mock Proposed Change",
                vec![ExternalReviewRole::Worker, ExternalReviewRole::Reviewer],
                vec![
                    ExternalOutputSchemaKind::ProposedChanges,
                    ExternalOutputSchemaKind::MixedReview,
                ],
                true,
            ),
            disabled_real_profile(
                "antigravity-cli-disabled",
                "Antigravity CLI Disabled",
                ExternalProviderKind::AntigravityCli,
            ),
            disabled_real_profile(
                "gemini-cli-disabled",
                "Gemini CLI Disabled",
                ExternalProviderKind::GeminiCli,
            ),
            disabled_real_profile(
                "gemini-api-disabled",
                "Gemini API Disabled",
                ExternalProviderKind::GeminiApi,
            ),
        ]
    }

    pub fn inspect(&self, provider_id: &str) -> Result<ExternalProviderProfile, EngineError> {
        self.profiles()
            .into_iter()
            .find(|profile| profile.provider_id == provider_id)
            .ok_or_else(|| rejected("external-review-registry", "unknown external provider"))
    }

    #[must_use]
    pub fn report(&self) -> ExternalProviderRegistryReport {
        let providers = self.profiles();
        let real_providers_disabled_by_default = providers
            .iter()
            .filter(|profile| profile.kind.is_real())
            .all(|profile| {
                !profile.enabled && profile.transport == ExternalProviderTransport::Disabled
            });
        let mock_provider_enabled = providers
            .iter()
            .any(|profile| profile.provider_id == "mock-auditor" && profile.enabled);
        ExternalProviderRegistryReport {
            component: "external_provider_registry".to_owned(),
            providers,
            real_providers_disabled_by_default,
            mock_provider_enabled,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl ExternalReviewPacketBuilder {
    pub fn build(
        &self,
        request: &ExternalReviewRequest,
        context_ref: impl Into<String>,
        payload: Value,
    ) -> Result<ExternalReviewPacket, EngineError> {
        let mut redacted_refs = Vec::new();
        let allowed_paths = redact_list(&request.allowed_paths, &mut redacted_refs);
        let evidence_refs = redact_list(&request.evidence_refs, &mut redacted_refs);
        let payload = redact_sensitive_value(payload);
        let mut packet = ExternalReviewPacket {
            packet_id: new_id("external-review-packet"),
            request_id: request.request_id.clone(),
            project_id: request.project_id,
            task_id: request.task_id,
            provider_id: request.provider_id.clone(),
            question: request.question.clone(),
            context_ref: context_ref.into(),
            allowed_paths,
            evidence_refs,
            redacted_refs,
            forbidden_actions: request.forbidden_actions.clone(),
            max_packet_bytes: request.budget.max_packet_bytes,
            byte_len: 0,
            payload,
            created_at: OffsetDateTime::now_utc(),
        };
        packet.byte_len = serde_json::to_vec(&packet)?.len();
        if packet.byte_len > request.budget.max_packet_bytes {
            return Err(rejected(
                "external-review-packet-builder",
                "external review packet exceeds size limit",
            ));
        }
        Ok(packet)
    }
}

impl ExternalReviewGate {
    #[must_use]
    pub fn decide(
        &self,
        request: &ExternalReviewRequest,
        provider: &ExternalProviderProfile,
        context: ExternalReviewGateContext<'_>,
    ) -> ExternalReviewGateDecision {
        let mut reasons = Vec::new();
        if context.incident_lockdown {
            reasons.push(ExternalReviewGateReason::IncidentLockdown);
        }
        if provider.authority.can_write_truth
            || provider.authority.can_apply_patch
            || provider.authority.can_grant_actions
            || provider.authority.can_finish_tasks
            || provider.authority.can_enter_normal_l3_as_instruction
        {
            reasons.push(ExternalReviewGateReason::AuthorityViolation);
        }
        if provider.kind.is_real() {
            reasons.push(ExternalReviewGateReason::RealProviderExecutionDisabledInG2);
        }
        if !provider.enabled || provider.transport == ExternalProviderTransport::Disabled {
            reasons.push(ExternalReviewGateReason::ProviderDisabled);
        }
        if !provider.roles.contains(&request.role) {
            reasons.push(ExternalReviewGateReason::UnsupportedRole);
        }
        if !provider.output_schemas.contains(&request.output_schema) {
            reasons.push(ExternalReviewGateReason::UnsupportedOutputSchema);
        }
        if !context.provider_integration_eval_gate_passed {
            reasons.push(ExternalReviewGateReason::ProviderIntegrationGateMissing);
        }
        if request.work_lease_id.is_none() || context.work_lease.is_none() {
            reasons.push(ExternalReviewGateReason::MissingWorkLease);
        }
        if request_requires_worktree(request)
            && (request.worktree_lease_id.is_none() || context.worktree_lease.is_none())
        {
            reasons.push(ExternalReviewGateReason::MissingWorktreeLease);
        }

        let decision = if reasons.is_empty() {
            ExternalReviewGateDecisionKind::AllowMockRun
        } else if reasons.contains(&ExternalReviewGateReason::RealProviderExecutionDisabledInG2)
            || reasons.contains(&ExternalReviewGateReason::ProviderDisabled)
            || reasons.contains(&ExternalReviewGateReason::UnsupportedRole)
            || reasons.contains(&ExternalReviewGateReason::UnsupportedOutputSchema)
            || reasons.contains(&ExternalReviewGateReason::AuthorityViolation)
            || reasons.contains(&ExternalReviewGateReason::IncidentLockdown)
        {
            ExternalReviewGateDecisionKind::Deny
        } else if reasons.contains(&ExternalReviewGateReason::ProviderIntegrationGateMissing) {
            ExternalReviewGateDecisionKind::RequireProviderIntegrationEvalGate
        } else if reasons.contains(&ExternalReviewGateReason::MissingWorkLease) {
            ExternalReviewGateDecisionKind::RequireWorkLease
        } else if reasons.contains(&ExternalReviewGateReason::MissingWorktreeLease) {
            ExternalReviewGateDecisionKind::RequireWorktreeLease
        } else {
            ExternalReviewGateDecisionKind::Deny
        };
        ExternalReviewGateDecision {
            request_id: request.request_id.clone(),
            provider_id: provider.provider_id.clone(),
            decision,
            reasons: if reasons.is_empty() {
                vec![ExternalReviewGateReason::AllowedMockProvider]
            } else {
                reasons
            },
            message: match decision {
                ExternalReviewGateDecisionKind::AllowMockRun => {
                    "mock external review may run".to_owned()
                }
                ExternalReviewGateDecisionKind::RequireWorkLease => {
                    "external review requires an active WorkLease".to_owned()
                }
                ExternalReviewGateDecisionKind::RequireWorktreeLease => {
                    "external proposed changes require an active WorktreeLease".to_owned()
                }
                ExternalReviewGateDecisionKind::RequireProviderIntegrationEvalGate => {
                    "provider-integration eval gate must pass before external review".to_owned()
                }
                ExternalReviewGateDecisionKind::Deny => {
                    "external review request denied by the provider gate".to_owned()
                }
            },
            decided_at: OffsetDateTime::now_utc(),
        }
    }
}

impl ExternalReviewJobService {
    #[must_use]
    pub fn create_job(&self, request: &ExternalReviewRequest) -> ExternalReviewJob {
        ExternalReviewJob {
            job_id: new_id("external-review-job"),
            request_id: request.request_id.clone(),
            provider_id: request.provider_id.clone(),
            status: ExternalReviewJobStatus::Queued,
            adapter_request_id: None,
            adapter_result_id: None,
            result_id: None,
            raw_output_blob_ref: None,
            message: "queued mock external review job".to_owned(),
            created_at: OffsetDateTime::now_utc(),
            completed_at: None,
        }
    }

    pub async fn run_mock(
        &self,
        request: &ExternalReviewRequest,
        provider: &ExternalProviderProfile,
        packet: &ExternalReviewPacket,
        supervisor: &AdapterSupervisor,
        blob_store: &BlobStore,
    ) -> Result<(ExternalReviewJob, ValidatedExternalReviewDocument), EngineError> {
        let job = self.create_job(request);
        self.run_mock_job(request, provider, packet, job, supervisor, blob_store)
            .await
    }

    pub async fn run_mock_job(
        &self,
        request: &ExternalReviewRequest,
        provider: &ExternalProviderProfile,
        packet: &ExternalReviewPacket,
        queued_job: ExternalReviewJob,
        supervisor: &AdapterSupervisor,
        blob_store: &BlobStore,
    ) -> Result<(ExternalReviewJob, ValidatedExternalReviewDocument), EngineError> {
        if provider.kind != ExternalProviderKind::Mock {
            return Err(rejected(
                "external-review-job-service",
                "the provider-free external review path can execute only mock providers",
            ));
        }
        if queued_job.request_id != request.request_id
            || queued_job.provider_id != provider.provider_id
        {
            return Err(rejected(
                "external-review-job-service",
                "queued external review job does not match request/provider",
            ));
        }
        if queued_job.status != ExternalReviewJobStatus::Queued {
            return Err(rejected(
                "external-review-job-service",
                "external review job is not queued",
            ));
        }
        let mut adapter_request = AdapterRequest {
            request_id: new_id("adapter-request"),
            adapter_id: "test-echo".to_owned(),
            requested_capability: AdapterCapability::ExecuteTest,
            context: AdapterContext {
                project_id: request.project_id,
                task_id: request.task_id,
                session_id: None,
                trace_id: new_id("external-review-trace"),
                created_at: OffsetDateTime::now_utc(),
                role_lease_id: None,
                role_lease_epoch: None,
                operation_generation: None,
                runtime_contract_sha256: None,
            },
            input: json!({
                "external_provider_id": provider.provider_id,
                "request_id": request.request_id,
                "packet_id": packet.packet_id,
                "candidate_only": true
            }),
        };
        if serde_json::to_vec(&adapter_request.input)?.len() > 16 * 1024 {
            adapter_request.input =
                json!({ "request_id": request.request_id, "packet_id": packet.packet_id });
        }
        let adapter_result = supervisor
            .execute("test-echo", adapter_request.clone(), Some(blob_store))
            .await?;
        // The byte string is the source of truth: serialize first, then decode
        // exactly those bytes through the shared duplicate-rejecting decoder, and
        // retain those same bytes as the raw evidence. Before this inversion the
        // retained evidence was a re-serialization of an already-collapsed
        // `Value`, so a duplicate member could never be observed here.
        let raw_output_bytes = serde_json::to_vec(&mock_raw_output(request, provider, packet))?;
        let raw_output =
            ValidatedExternalReviewDocument::strict_from_provider_bytes(&raw_output_bytes)
                .map_err(|error| {
                    rejected(
                        "external-review-job-service",
                        &format!(
                            "mock external review raw output failed strict JSON decode: {error}"
                        ),
                    )
                })?;
        let raw_output_blob_ref = Some(blob_store.put_bytes(raw_output.bytes())?);
        let job = ExternalReviewJob {
            job_id: queued_job.job_id,
            request_id: request.request_id.clone(),
            provider_id: provider.provider_id.clone(),
            status: ExternalReviewJobStatus::Succeeded,
            adapter_request_id: Some(adapter_request.request_id),
            adapter_result_id: Some(adapter_result.result_id),
            result_id: None,
            raw_output_blob_ref,
            message: "mock external review ran through AdapterSupervisor".to_owned(),
            created_at: queued_job.created_at,
            completed_at: Some(OffsetDateTime::now_utc()),
        };
        Ok((job, raw_output))
    }
}

impl ExternalReviewNormalizer {
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn normalize(
        &self,
        request: &ExternalReviewRequest,
        job: &ExternalReviewJob,
        raw_output: &ValidatedExternalReviewDocument,
    ) -> ExternalReviewNormalizationOutcome {
        let rejected =
            |status: ExternalReviewResultStatus, reason: &str| ExternalReviewNormalizationOutcome {
                receipt: normalization_receipt(
                    request,
                    job,
                    false,
                    status,
                    vec![reason.to_owned()],
                ),
                result: None,
            };
        // Production provenance reader: the standing decides which
        // retained-evidence reference the accepted result may carry and how
        // the receipt qualifies it. Strict provider bytes keep the job's
        // retained handle as byte proof; an internally constructed value has
        // no exact original bytes, so the result carries no byte-proof
        // reference and the retained handle is read back as explicitly
        // unqualified legacy evidence.
        let standing = ExternalReviewEvidenceStanding::of_document(raw_output);
        let (raw_output_blob_ref, standing_reason) = match standing {
            ExternalReviewEvidenceStanding::StrictProviderBytes => (
                job.raw_output_blob_ref.clone(),
                "raw evidence qualified: exact provider bytes strictly decoded and retained",
            ),
            ExternalReviewEvidenceStanding::UnqualifiedLegacy => {
                let (_, reason) = ExternalReviewEvidenceStanding::read_back_historical(
                    job.raw_output_blob_ref.as_ref(),
                );
                (None, reason)
            }
        };
        // The document is bound to the exact bytes it was decoded from, so the
        // value below is duplicate-clean by construction. The four
        // `serde_json::from_value` sites that follow still apply the T07 DTO
        // shape/alias contract to that value; they no longer need to, and cannot,
        // recover a lexical duplicate, because the gate above already did.
        let raw_output = raw_output.value();

        if raw_output.get("candidate_only") == Some(&Value::Bool(false))
            || raw_output.get("forbidden_actions").is_some()
        {
            return rejected(
                ExternalReviewResultStatus::RejectedAuthorityViolation,
                "external result attempted forbidden authority",
            );
        }
        if contains_verified_claim_status(raw_output) {
            return rejected(
                ExternalReviewResultStatus::RejectedVerifiedClaim,
                "external result attempted verified claim status",
            );
        }
        let Some(findings_value) = raw_output.get("findings") else {
            return rejected(
                ExternalReviewResultStatus::RejectedMalformed,
                "external result missing findings array",
            );
        };
        let Ok(findings) =
            serde_json::from_value::<Vec<ExternalReviewFinding>>(findings_value.clone())
        else {
            return rejected(
                ExternalReviewResultStatus::RejectedMalformed,
                "external result findings failed schema validation",
            );
        };
        if findings.is_empty()
            || findings.iter().any(|finding| {
                finding.citations.is_empty()
                    || finding
                        .citations
                        .iter()
                        .any(|citation| citation.status != ExternalCitationStatus::Cited)
                    || finding.claim_status != ExternalClaimStatus::Candidate
            })
        {
            return rejected(
                ExternalReviewResultStatus::RejectedMissingEvidence,
                "external findings require candidate claims with cited evidence",
            );
        }
        let proposed_changes = raw_output
            .get("proposed_changes")
            .cloned()
            .map_or_else(Vec::new, |value| {
                serde_json::from_value::<Vec<ExternalProposedChange>>(value).unwrap_or_default()
            })
            .into_iter()
            .map(force_candidate_diff_only)
            .collect::<Vec<_>>();
        let verifier_suggestions = raw_output
            .get("verifier_suggestions")
            .cloned()
            .map_or_else(Vec::new, |value| {
                serde_json::from_value::<Vec<ExternalVerifierSuggestion>>(value).unwrap_or_default()
            })
            .into_iter()
            .map(|mut suggestion| {
                suggestion.candidate_only = true;
                suggestion
            })
            .collect::<Vec<_>>();
        let uncertainties = raw_output
            .get("uncertainties")
            .cloned()
            .map_or_else(Vec::new, |value| {
                serde_json::from_value::<Vec<ExternalUncertainty>>(value).unwrap_or_default()
            });
        let result = ExternalReviewResult {
            result_id: new_id("external-review-result"),
            request_id: request.request_id.clone(),
            job_id: job.job_id.clone(),
            provider_id: request.provider_id.clone(),
            project_id: request.project_id,
            task_id: request.task_id,
            status: ExternalReviewResultStatus::AcceptedCandidate,
            candidate_only: true,
            taint: TaintClass::ExternalAgent,
            raw_output_blob_ref,
            findings,
            proposed_changes,
            verifier_suggestions,
            uncertainties,
            write_receipt: None,
            blackboard_item_refs: Vec::new(),
            mailbox_message_refs: Vec::new(),
            created_at: OffsetDateTime::now_utc(),
        };
        ExternalReviewNormalizationOutcome {
            receipt: normalization_receipt(
                request,
                job,
                true,
                ExternalReviewResultStatus::AcceptedCandidate,
                vec![
                    "external result accepted as tainted candidate only".to_owned(),
                    standing_reason.to_owned(),
                ],
            ),
            result: Some(result),
        }
    }
}

impl ExternalReviewTaintPolicy {
    pub fn enforce(&self, result: &mut ExternalReviewResult) {
        result.candidate_only = true;
        result.taint = TaintClass::ExternalAgent;
        for suggestion in &mut result.verifier_suggestions {
            suggestion.candidate_only = true;
        }
        for change in &mut result.proposed_changes {
            *change = force_candidate_diff_only(change.clone());
        }
    }

    #[must_use]
    pub const fn included_in_normal_l3(&self, _result: &ExternalReviewResult) -> bool {
        false
    }
}

impl ExternalReviewBridgeService {
    pub async fn write_and_route(
        &self,
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        state: &mut WorkState,
        owner_session_id: AgentSessionId,
        result: &mut ExternalReviewResult,
    ) -> Result<ExternalReviewBridgeReport, EngineError> {
        ExternalReviewTaintPolicy.enforce(result);
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: AgentId::new_v7(),
                session_id: None,
                project_id: result.project_id,
                task_id: Some(result.task_id),
                scope: "external-review-result".to_owned(),
                authority: "eliot-external-review-protocol".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::ExternalAgent,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: "eliot_external_review_result".to_owned(),
            observation: format!(
                "external provider {} produced candidate-only review result",
                result.provider_id
            ),
            payload: serde_json::to_value(&*result)?,
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        let receipt_ref = WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        };
        result.write_receipt = Some(receipt_ref.clone());
        let mut observation = AdapterObservation {
            observation_id: new_id("external-review-observation"),
            adapter_id: format!("external-review:{}", result.provider_id),
            result_id: result.result_id.clone(),
            project_id: result.project_id,
            task_id: result.task_id,
            summary: format!("external review {} is candidate-only", result.result_id),
            payload: serde_json::to_value(&*result)?,
            payload_ref: format!("external_review_result:{}", result.result_id),
            raw_blob_ref: result.raw_output_blob_ref.clone(),
            taint: TaintClass::ExternalAgent,
            write_receipt: Some(receipt_ref),
            blackboard_item_id: None,
            mailbox_message_id: None,
            controller_review_required: true,
            generated_at: OffsetDateTime::now_utc(),
        };
        let blackboard_item = AdapterObservationBridge::to_blackboard_candidate(
            state,
            owner_session_id,
            &mut observation,
        );
        let mailbox_message = AdapterObservationBridge::to_mailbox_notification(
            state,
            owner_session_id,
            &mut observation,
        );
        result
            .blackboard_item_refs
            .push(format!("blackboard:{}", blackboard_item.blackboard_item_id));
        result
            .mailbox_message_refs
            .push(format!("mailbox:{}", mailbox_message.message_id));
        let candidate_diff_refs = result
            .proposed_changes
            .iter()
            .filter_map(|change| change.candidate_diff_ref.clone())
            .collect::<Vec<_>>();
        Ok(ExternalReviewBridgeReport {
            component: "external_review_bridge".to_owned(),
            result_id: result.result_id.clone(),
            write_receipt: result.write_receipt.clone(),
            observation,
            blackboard_items: vec![blackboard_item],
            mailbox_messages: vec![mailbox_message],
            candidate_diff_refs,
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    #[must_use]
    pub fn normalize_adapter_observation(
        &self,
        result: &ExternalReviewResult,
    ) -> AdapterObservation {
        let mut observation = AdapterObservation {
            observation_id: new_id("external-review-observation"),
            adapter_id: format!("external-review:{}", result.provider_id),
            result_id: result.result_id.clone(),
            project_id: result.project_id,
            task_id: result.task_id,
            summary: format!("external review {} is candidate-only", result.result_id),
            payload: serde_json::to_value(result).unwrap_or_else(|_| json!({})),
            payload_ref: format!("external_review_result:{}", result.result_id),
            raw_blob_ref: result.raw_output_blob_ref.clone(),
            taint: TaintClass::ExternalAgent,
            write_receipt: result.write_receipt.clone(),
            blackboard_item_id: None,
            mailbox_message_id: None,
            controller_review_required: true,
            generated_at: OffsetDateTime::now_utc(),
        };
        if observation.write_receipt.is_none() {
            observation.controller_review_required = true;
        }
        observation
    }
}

impl ExternalReviewReportService {
    #[must_use]
    pub fn providers_report(&self) -> ExternalProviderRegistryReport {
        ExternalProviderRegistryService.report()
    }

    #[must_use]
    pub fn jobs_report(&self, jobs: &[ExternalReviewJob]) -> Value {
        json!({
            "component": "external_review_jobs",
            "jobs": jobs,
            "generated_at": OffsetDateTime::now_utc()
        })
    }

    #[must_use]
    pub fn results_report(&self, results: &[ExternalReviewResult]) -> Value {
        let candidate_only = results.iter().all(|result| result.candidate_only);
        let tainted = results
            .iter()
            .all(|result| result.taint == TaintClass::ExternalAgent);
        json!({
            "component": "external_review_results",
            "results": results,
            "candidate_only": candidate_only,
            "tainted": tainted,
            "generated_at": OffsetDateTime::now_utc()
        })
    }

    #[must_use]
    pub fn gates_report(&self, decisions: &[ExternalReviewGateDecision]) -> Value {
        json!({
            "component": "external_review_gates",
            "decisions": decisions,
            "generated_at": OffsetDateTime::now_utc()
        })
    }

    #[must_use]
    pub fn normalization_report(&self, receipts: &[ExternalReviewNormalizationReceipt]) -> Value {
        json!({
            "component": "external_review_normalization",
            "receipts": receipts,
            "generated_at": OffsetDateTime::now_utc()
        })
    }

    #[must_use]
    pub fn doctor_status(&self, governed_mcp_tools_only: bool) -> ExternalReviewDoctorStatus {
        let providers = ExternalProviderRegistryService.profiles();
        ExternalReviewDoctorStatus {
            component: "external_review_doctor_status".to_owned(),
            providers_total: providers.len(),
            mock_providers_enabled: providers
                .iter()
                .filter(|profile| profile.kind == ExternalProviderKind::Mock && profile.enabled)
                .count(),
            real_providers_disabled: providers
                .iter()
                .filter(|profile| profile.kind.is_real())
                .all(|profile| !profile.enabled),
            governed_mcp_tools_only,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

fn mock_profile(
    provider_id: &str,
    display_name: &str,
    roles: Vec<ExternalReviewRole>,
    output_schemas: Vec<ExternalOutputSchemaKind>,
    can_propose_candidate_diff: bool,
) -> ExternalProviderProfile {
    ExternalProviderProfile {
        provider_id: provider_id.to_owned(),
        display_name: display_name.to_owned(),
        kind: ExternalProviderKind::Mock,
        transport: ExternalProviderTransport::InternalMock,
        enabled: true,
        roles,
        output_schemas,
        authority: ExternalProviderAuthority {
            can_propose_candidate_diff,
            ..ExternalProviderAuthority::default()
        },
        limits: ExternalProviderLimits::default(),
        credential_ref: None,
        disabled_reason: None,
    }
}

fn disabled_real_profile(
    provider_id: &str,
    display_name: &str,
    kind: ExternalProviderKind,
) -> ExternalProviderProfile {
    ExternalProviderProfile {
        provider_id: provider_id.to_owned(),
        display_name: display_name.to_owned(),
        kind,
        transport: ExternalProviderTransport::Disabled,
        enabled: false,
        roles: vec![ExternalReviewRole::Auditor, ExternalReviewRole::Reviewer],
        output_schemas: vec![
            ExternalOutputSchemaKind::AuditFindings,
            ExternalOutputSchemaKind::MixedReview,
        ],
        authority: ExternalProviderAuthority::default(),
        limits: ExternalProviderLimits::default(),
        credential_ref: None,
        disabled_reason: Some("real external provider execution is disabled by policy".to_owned()),
    }
}

fn request_requires_worktree(request: &ExternalReviewRequest) -> bool {
    request.role == ExternalReviewRole::Worker
        || request.output_schema == ExternalOutputSchemaKind::ProposedChanges
        || request.provider_id == "mock-proposed-change"
}

fn mock_raw_output(
    request: &ExternalReviewRequest,
    provider: &ExternalProviderProfile,
    packet: &ExternalReviewPacket,
) -> Value {
    match provider.provider_id.as_str() {
        "mock-malformed" => json!({ "malformed": true }),
        "mock-authority-violator" => json!({
            "candidate_only": false,
            "forbidden_actions": ["write_truth"],
            "findings": []
        }),
        "mock-large-output" => {
            let mut output = base_mock_output(request, packet);
            if let Value::Object(map) = &mut output {
                map.insert(
                    "padding".to_owned(),
                    Value::String("x".repeat(request.budget.max_output_bytes + 512)),
                );
            }
            output
        }
        "mock-proposed-change" => {
            let mut output = base_mock_output(request, packet);
            if let Value::Object(map) = &mut output {
                map.insert(
                    "proposed_changes".to_owned(),
                    json!([{
                        "change_id": new_id("external-proposed-change"),
                        "kind": "candidate_diff_only",
                        "summary": "candidate-only diff proposal from mock external reviewer",
                        "files": packet.allowed_paths,
                        "candidate_diff_id": null,
                        "candidate_diff_ref": format!("candidate_diff:external-review:{}", request.request_id)
                    }]),
                );
            }
            output
        }
        _ => base_mock_output(request, packet),
    }
}

fn base_mock_output(request: &ExternalReviewRequest, packet: &ExternalReviewPacket) -> Value {
    let evidence_ref = packet
        .evidence_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "codecortex:latest".to_owned());
    let file = packet
        .allowed_paths
        .first()
        .cloned()
        .unwrap_or_else(|| "crates/eliot-app/src/mcp_stdio.rs".to_owned());
    json!({
        "candidate_only": true,
        "findings": [{
            "finding_id": new_id("external-finding"),
            "title": "mock external review finding",
            "detail": format!("candidate-only answer to {}", request.question),
            "severity": ExternalFindingSeverity::Low,
            "claim_status": ExternalClaimStatus::Candidate,
            "citations": [{
                "citation_id": new_id("external-citation"),
                "evidence_ref": evidence_ref,
                "file": file,
                "line": 1,
                "status": ExternalCitationStatus::Cited
            }]
        }],
        "proposed_changes": [],
        "verifier_suggestions": [{
            "verifier_id": new_id("external-verifier-suggestion"),
            "command": "just verify",
            "reason": "candidate-only verifier suggestion from mock reviewer",
            "candidate_only": true
        }],
        "uncertainties": [{
            "uncertainty_id": new_id("external-uncertainty"),
            "summary": "mock provider cannot verify repository state independently",
            "evidence_needed": ["local verifier output"]
        }]
    })
}

fn normalization_receipt(
    request: &ExternalReviewRequest,
    job: &ExternalReviewJob,
    accepted: bool,
    status: ExternalReviewResultStatus,
    reasons: Vec<String>,
) -> ExternalReviewNormalizationReceipt {
    ExternalReviewNormalizationReceipt {
        receipt_id: new_id("external-review-normalization"),
        request_id: request.request_id.clone(),
        job_id: job.job_id.clone(),
        provider_id: request.provider_id.clone(),
        accepted,
        status,
        reasons,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn contains_verified_claim_status(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            (key == "claim_status" && value.as_str() == Some("verified"))
                || contains_verified_claim_status(value)
        }),
        Value::Array(values) => values.iter().any(contains_verified_claim_status),
        _ => false,
    }
}

fn force_candidate_diff_only(mut change: ExternalProposedChange) -> ExternalProposedChange {
    change.kind = ExternalProposedChangeKind::CandidateDiffOnly;
    if change.candidate_diff_ref.is_none() {
        change.candidate_diff_ref = Some(format!(
            "candidate_diff:external-review:{}",
            change.change_id
        ));
    }
    change
}

fn redact_list(values: &[String], redacted_refs: &mut Vec<String>) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| {
            if is_sensitive(value) {
                redacted_refs.push(format!(
                    "redacted:{}",
                    blake3::hash(value.as_bytes()).to_hex()
                ));
                None
            } else {
                Some(value.clone())
            }
        })
        .collect()
}

fn redact_sensitive_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_sensitive(&key) {
                        (key, Value::String("[redacted]".to_owned()))
                    } else {
                        (key, redact_sensitive_value(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_sensitive_value).collect())
        }
        Value::String(value) if is_sensitive(&value) => Value::String("[redacted]".to_owned()),
        other => other,
    }
}

fn is_sensitive(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "secret",
        "credential",
        "password",
        "token",
        "db_endpoint",
        "endpoint",
        "raw_storage",
        "storage_path",
        "surreal",
        "table_name",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", WriteId::new_v7())
}

fn rejected(service: &str, reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: service.to_owned(),
        reason: reason.to_owned(),
    }
}

#[must_use]
pub fn external_review_request(
    project: impl Into<String>,
    task: impl Into<String>,
    provider_id: impl Into<String>,
    role: ExternalReviewRole,
    question: impl Into<String>,
) -> ExternalReviewRequest {
    let provider_id = provider_id.into();
    let output_schema =
        if role == ExternalReviewRole::Worker || provider_id == "mock-proposed-change" {
            ExternalOutputSchemaKind::ProposedChanges
        } else {
            ExternalOutputSchemaKind::AuditFindings
        };
    ExternalReviewRequest {
        request_id: new_id("external-review-request"),
        project: project.into(),
        project_id: ProjectId::new_v7(),
        task: task.into(),
        task_id: TaskId::new_v7(),
        provider_id,
        role,
        question: question.into(),
        output_schema,
        budget: ExternalReviewBudget::default(),
        work_lease_id: None,
        worktree_lease_id: None,
        allowed_paths: vec!["crates/eliot-app/src/mcp_stdio.rs".to_owned()],
        evidence_refs: vec!["codecortex:latest".to_owned()],
        forbidden_actions: vec![
            ExternalForbiddenAction::WriteTruth,
            ExternalForbiddenAction::ApplyPatch,
            ExternalForbiddenAction::GrantAction,
            ExternalForbiddenAction::FinishTask,
            ExternalForbiddenAction::EnterNormalL3AsInstruction,
            ExternalForbiddenAction::RevealSecret,
            ExternalForbiddenAction::RawExec,
        ],
        created_at: OffsetDateTime::now_utc(),
    }
}
