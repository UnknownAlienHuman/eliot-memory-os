//! I7.24 tool-call intent gate wiring.
//!
//! This module wires the [`eliot_receipts`] tool-exposure intent contract into
//! the Kernel orchestration boundary. It validates a lightweight
//! [`ToolCallIntent`] before dispatch so an expensive, model-backed, swarm,
//! network, broad-search, or effect-capable call is rejected when it carries no
//! intent, while cheap exact reads stay exempt. It also compares each staging
//! candidate against the retained per-route stage so a materially repeated
//! call on unchanged inputs without a new expected delta surfaces a
//! [`LoopSignal`] instead of staging as progress.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_receipts::{
    LoopSignal, ResultDelivery, ToolCallClass, ToolCallIntent, ToolCallRequest, ToolExposureError,
    ToolExposureReceiptV2,
    tool_exposure::{
        AttemptEvidence, DeliveredToolRepresentation, EXPOSURE_HISTORY_VERSION, OwnerStageFact,
        ProducedToolResultIdentity, TokenCountObservation, TokenCountUnavailableReason,
        detect_repeat_without_progress_with_evidence,
    },
};

use super::host_request_route::LocalReadAdmission;
use super::kernel_audit::AuditEventDraft;

/// Route fingerprint for tool calls admitted through the local-read boundary.
///
/// The fingerprint joins the authenticated envelope session, authority epoch,
/// and resource generation with the admitted campaign task identity when the
/// accepted method carries one. A campaign packet re-requested under a new
/// task revision is new work, not a material repeat, while the same packet
/// under the same task revision keeps its repeat identity. The task identity
/// comes from the accepted [`LocalReadAdmission`] — never caller tool text —
/// so the repeat join stays admission-derived exactly like the call class.
fn route_fingerprint(
    envelope: &eliot_protocol::HostRequestEnvelope,
    admission: &LocalReadAdmission,
) -> String {
    let session = envelope
        .identity
        .session_id
        .as_deref()
        .unwrap_or("unknown-session");
    let base = format!(
        "{}:{:?}:{:?}",
        session, envelope.state_fence.authority_epoch, envelope.state_fence.resource_generation
    );
    match admission {
        LocalReadAdmission::CampaignPacket {
            task_id,
            task_revision,
            ..
        } => format!("{base}:packet:{task_id}:{task_revision}"),
        LocalReadAdmission::Query(_) | LocalReadAdmission::Skill => base,
        // #1213 Link 2: the control-board read joins the admitted session, the
        // identity its board view is role-filtered by. Two sessions reading the
        // board are two routes, so a repeat under one session is never compared
        // against — or excused by — another session's read. The value comes
        // from the accepted admission, never caller tool text.
        LocalReadAdmission::ControlBoardRead { session_id } => {
            format!("{base}:control-board:{session_id}")
        }
    }
}

/// Derives the tool call class from the accepted Kernel admission.
///
/// Tool names, descriptions, and shell substrings never define call
/// semantics: the class comes from the admitted method. The bounded evidence
/// query is broad-search, an exact Skill lifecycle tool is expensive, and a
/// task-bound campaign packet is effect-capable. A name outside the admitted
/// set never reaches classification; admission fails closed first.
///
/// #1213 Link 2: the control-board read is `Expensive`, like the Skill arm.
/// `Expensive` and `BroadSearch` are gate-equivalent — both require an intent
/// and neither requires a durable operation identity — so this is the same
/// admission strength as the query and Skill arms, not a weaker class. It is
/// deliberately NOT `EffectCapable`: the board read dispatches no effect, so
/// claiming that class would both overstate the call and demand a durable
/// operation identity no producer has any owner-issued source for.
pub(crate) fn call_class(admission: &LocalReadAdmission) -> ToolCallClass {
    match admission {
        LocalReadAdmission::Query(_) => ToolCallClass::BroadSearch,
        LocalReadAdmission::Skill | LocalReadAdmission::ControlBoardRead { .. } => {
            ToolCallClass::Expensive
        }
        LocalReadAdmission::CampaignPacket { .. } => ToolCallClass::EffectCapable,
    }
}

/// Computes the SHA-256 identity digest over the effective call inputs.
///
/// The caller-declared `intent` block is stripped before canonicalization:
/// it is gate justification, not tool inputs. Folding justification text
/// into the identity would let a reworded `expected_delta` change the
/// digest and evade the evidence-bound repeat comparison as a
/// never-before-seen call, which step 5 forbids — a reworded delta alone
/// is not progress. Retries that advance real inputs still hash
/// differently and stay fresh; retries that change only justification
/// keep the identity and meet the [`LoopSignal::NoProgress`] arm unless
/// owner-observed evidence advanced.
fn inputs_digest(tool: &serde_json::Value) -> Result<String, serde_json::Error> {
    let mut canonical = tool.clone();
    if let Some(object) = canonical.as_object_mut()
        && let Some(arguments) = object
            .get_mut("arguments")
            .and_then(serde_json::Value::as_object_mut)
    {
        arguments.remove("intent");
    }
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(sha256_hex(&bytes))
}

/// Builds a [`ToolCallRequest`] from the admitted envelope, tool, and accepted admission.
///
/// The cost/effect class derives from `admission` — the accepted method —
/// never from the caller-supplied name string. The versioned tool definition
/// identity still names the invoked tool; classification does not. The route
/// fingerprint likewise joins the admitted campaign task identity for packet
/// methods, so a new task revision is new work rather than a material repeat.
/// The inputs digest covers the effective call inputs with the caller-declared
/// `intent` block stripped, so a reworded `expected_delta` keeps the repeat
/// identity and meets the evidence-bound comparison instead of hashing as
/// fresh inputs.
pub(crate) fn build_tool_call_request(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
    admission: &LocalReadAdmission,
) -> Option<ToolCallRequest> {
    let name = tool.as_object()?.get("name")?.as_str()?.to_owned();
    let class = call_class(admission);
    let arguments = tool.as_object()?.get("arguments")?.as_object()?;
    let intent = build_tool_intent(arguments)?;
    let digest = inputs_digest(tool).ok()?;
    Some(ToolCallRequest {
        tool_definition: name,
        route_fingerprint: route_fingerprint(envelope, admission),
        call_class: class,
        inputs_digest: digest,
        intent: Some(intent),
    })
}

/// Extracts a [`ToolCallIntent`] from the tool arguments.
fn build_tool_intent(
    arguments: &serde_json::Map<String, serde_json::Value>,
) -> Option<ToolCallIntent> {
    let intent_obj = arguments.get("intent")?.as_object()?;
    let expected_delta = intent_obj
        .get("expected_delta")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let cheaper_route_insufficient = intent_obj
        .get("cheaper_route_insufficient")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let budget = intent_obj
        .get("budget")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let stop_conditions = intent_obj
        .get("stop_conditions")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let retry_conditions = intent_obj
        .get("retry_conditions")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let operation_identity = intent_obj
        .get("operation_identity")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    ToolCallIntent::new(
        expected_delta,
        cheaper_route_insufficient,
        budget,
        stop_conditions,
        retry_conditions,
        operation_identity,
    )
    .ok()
}

/// Pre-dispatch gate: validates the tool call intent before dispatch.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the intent is missing,
/// malformed, or lacks required operation identity.
pub(crate) fn authorize_pre_dispatch(
    request: &ToolCallRequest,
) -> Result<(), eliot_receipts::ToolExposureError> {
    eliot_receipts::authorize_pre_dispatch(request)
}

/// Records the per-evaluation receipt skeleton for one authorized request.
///
/// This is the production recording call at the orchestration boundary: it
/// runs the real pre-dispatch gate ([`authorize_pre_dispatch`]) and, only on
/// success, stages the [`eliot_receipts::ToolExposureReceiptV2`] admission
/// skeleton from the request's own admission-derived identities (tool
/// definition, route fingerprint). Eligibility and selection hold because the
/// gated request was presented for dispatch and admitted; every unobserved
/// stage stays `None`, delivery stays `MISSING`, and no representation
/// evidence is attached. Measurement owners populate the rest through the
/// `record_*` transitions; nothing is invented here. `receipt_id` must be
/// infrastructure identity (for example the host-request operation id),
/// never caller prose.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the request fails the
/// pre-dispatch gate or an identity is malformed.
pub(crate) fn observe_authorized_admission(
    request: &ToolCallRequest,
    receipt_id: String,
) -> Result<ToolExposureReceiptV2, ToolExposureError> {
    authorize_pre_dispatch(request)?;
    ToolExposureReceiptV2::admission_observed(
        receipt_id,
        request.tool_definition.clone(),
        request.route_fingerprint.clone(),
    )
}

/// Measures the exact delivered representation for one persisted result and
/// advances its evaluated receipt to a complete delivery.
///
/// This is the delivery owner's transition driver: it re-establishes the
/// admission skeleton from the request's own admission-derived identities
/// ([`observe_authorized_admission`]), measures the delivered bytes itself
/// with [`canonical_json_bytes`], and refuses a produced digest that does
/// not bind those exact bytes. Digest and byte count are never copied from
/// caller values; a mismatch fails typed instead of recording.
///
/// Byte-completeness holds by construction on this path: the protocol bounds
/// the response ceiling and rejects an oversize body instead of cutting it,
/// so a persisted digest-bound body is the whole body. Token completeness is
/// explicitly unobserved instead: no route tokenizer exists on this path, so
/// the token observation stays
/// [`TokenCountUnavailableReason::MeasurementUnavailable`] rather than a
/// zero that would read as measured. A token-truncated delivery has no owner
/// signal here and is never inferred; only the future tokenizer owner can
/// drive [`ToolExposureReceiptV2::record_truncated_delivery`].
///
/// # Errors
///
/// Returns [`ToolExposureError`] when the request fails the pre-dispatch
/// gate, the response is not canonicalizable, the produced digest does not
/// bind the exact delivered bytes, or the resulting receipt is inconsistent.
pub(crate) fn observe_persisted_delivery(
    request: &ToolCallRequest,
    receipt_id: String,
    result_digest: &str,
    response: &serde_json::Value,
    representation_source_handle: String,
) -> Result<ToolExposureReceiptV2, ToolExposureError> {
    let skeleton = observe_authorized_admission(request, receipt_id)?;
    let bytes = canonical_json_bytes(response).map_err(|_| ToolExposureError::InvalidField {
        field: "receipt.delivered_representation.representation_digest",
        reason: "delivered response is not canonicalizable",
    })?;
    let measured = sha256_hex(&bytes);
    if measured != result_digest {
        return Err(ToolExposureError::InvalidField {
            field: "receipt.produced_result.result_digest",
            reason: "produced digest does not bind the exact delivered bytes",
        });
    }
    let byte_count = u64::try_from(bytes.len()).map_err(|_| ToolExposureError::InvalidField {
        field: "receipt.delivered_representation.byte_count",
        reason: "delivered byte count exceeds the addressable bound",
    })?;
    skeleton.record_full_delivery(
        ProducedToolResultIdentity {
            result_digest: measured.clone(),
            artifact_ref: None,
            source_handle: Some(representation_source_handle.clone()),
        },
        DeliveredToolRepresentation {
            representation_digest: measured,
            source_handle: representation_source_handle,
            byte_count,
            token_observation: TokenCountObservation::Unavailable {
                reason: TokenCountUnavailableReason::MeasurementUnavailable,
            },
            prior_delivery_receipt_id: None,
        },
    )
}

/// Returns whether the accepted admission requires an intent before dispatch.
///
/// The answer reads off the admission-derived class, so cheap exact reads
/// stay exempt by construction while every currently admitted method —
/// broad-search query, expensive Skill lifecycle tool, effect-capable
/// campaign packet — carries an intent.
pub(crate) fn requires_intent(admission: &LocalReadAdmission) -> bool {
    call_class(admission).requires_intent()
}

/// Returns whether the accepted admission dispatches Material effects and
/// therefore requires live Governor-issued material authority before
/// dispatch.
///
/// The answer reads off the admission-derived class, so cheap exact reads
/// stay exempt by construction while the effect-capable campaign packet —
/// the only currently admitted Material lane — always requires it. The
/// class derives from the accepted admission, never from the tool name, so
/// a hidden effect-capable method invoked by name faces the identical
/// requirement: advertisement is neither a capability grant nor a security
/// boundary.
pub(crate) fn requires_material_authority(admission: &LocalReadAdmission) -> bool {
    matches!(admission, LocalReadAdmission::CampaignPacket { .. })
}

/// Re-joins the live Governor-issued material authority for one accepted
/// effect-capable (Material) admission before it dispatches.
///
/// This is the tool-lane revalidation of the envelope-level material gate:
/// it runs the single production gate behind every Material effect
/// ([`super::KernelComposition::admit_material_authority_for_governor_issued_fence`])
/// against the same live Governor derivation, so a missing derivation or a
/// revocation that landed after envelope admission still fails the
/// effect-capable lane closed. Read-only admissions are exempt by
/// construction ([`requires_material_authority`]); no second catalogue or
/// authorization service is consulted.
///
/// # Errors
///
/// Returns [`super::TransportError::SessionFenced`] when the admission is
/// Material and no current Governor-derived coverage profile admits it.
pub(crate) fn authorize_material_lane(
    composition: &super::KernelComposition,
    admission: &LocalReadAdmission,
    fence: &eliot_contracts::StateFence,
) -> Result<(), super::TransportError> {
    if !requires_material_authority(admission) {
        return Ok(());
    }
    composition
        .admit_material_authority_for_governor_issued_fence(fence)
        .map_err(|_| super::TransportError::SessionFenced)
}

/// Reports a staging-time loop/no-progress signal for a materially repeated call.
///
/// Each retained candidate is rebuilt into a [`ToolCallRequest`] through the
/// existing admission owner
/// ([`super::host_request_route::check_local_read_admission`]), so the
/// cost/effect class derives from the accepted admission exactly as it does
/// for the staging candidate; unreconstructible pairs never match. The
/// retained per-route stage is the existing attempt history — no new loop
/// ledger — and the comparison is the evidence-bound
/// [`detect_repeat_without_progress_with_evidence`] join. The compared
/// inputs digest excludes caller-declared intent text by construction
/// ([`build_tool_call_request`]), so a reworded `expected_delta` keeps the
/// repeat identity and yields [`LoopSignal::NoProgress`], never a fresh
/// staging as progress.
///
/// No owner-observed evidence is joined at this gate: payloads travel by
/// digest only, so the source revision, poll cursor, and prior outcome the
/// issue names are unobserved here rather than invented. An unobserved
/// dimension is never new evidence, so a reworded `expected_delta` alone
/// yields [`LoopSignal::NoProgress`] instead of staging as progress. Only
/// genuinely advanced owner evidence — joined by the evidence owners, never
/// inferred here — counts as potential progress.
///
/// Pure and total: reads only, never stages, never fails. Exact-idempotent
/// replay, required unknown-effect reconciliation, and admitted polling keep
/// their own semantics at their owners; the signal only refuses a materially
/// repeated staging, never permission to execute again.
pub(crate) fn staged_repeat_without_progress<'a>(
    mut retained: impl Iterator<
        Item = (
            &'a eliot_protocol::HostRequestEnvelope,
            &'a serde_json::Value,
        ),
    >,
    current: &ToolCallRequest,
) -> Option<LoopSignal> {
    // Both sides carry no owner-observed evidence at this gate: the staging
    // path holds digest-bound pairs only, and inventing a revision, cursor,
    // or outcome to obtain a valid-looking pass is forbidden.
    let unobserved = AttemptEvidence {
        source_revision: None,
        poll_cursor: None,
        prior_outcome: None,
    };
    retained.find_map(|(envelope, tool)| {
        let admission =
            super::host_request_route::check_local_read_admission(envelope, tool).ok()?;
        let previous = build_tool_call_request(envelope, tool, &admission)?;
        detect_repeat_without_progress_with_evidence(&previous, &unobserved, current, &unobserved)
    })
}

/// Names the admission-owner evidence behind one dispatch-seam eligibility fact.
///
/// The reference names the accepted admission kind (and the admitted campaign
/// task identity for packet methods), never caller tool text. It is the owner
/// source reference the supplied eligible/selected facts bind, so unknown
/// coverage stays `None` elsewhere instead of being inferred from this seam.
fn admission_source(admission: &LocalReadAdmission) -> String {
    match admission {
        LocalReadAdmission::Query(_) => "local-read-admission:query".to_owned(),
        LocalReadAdmission::Skill => "local-read-admission:skill".to_owned(),
        // #1213 Link 2: a distinct reference, never the Skill one. The
        // exposure evidence names the admission it came from, so reusing
        // `skill` here would record a control-board read as a Skill call. The
        // admitted session is named for the same reason the campaign packet
        // names its task identity: this is the identity the read was admitted
        // under, and an unnamed one would make the owner source ambiguous.
        LocalReadAdmission::ControlBoardRead { session_id } => {
            format!("local-read-admission:control-board:{session_id}")
        }
        LocalReadAdmission::CampaignPacket {
            task_id,
            task_revision,
            ..
        } => format!("local-read-admission:campaign-packet:{task_id}:{task_revision}"),
    }
}

/// Populates the dispatch-seam-owned exposure evidence for one freshly
/// staged pair and seals it as the durable observation draft.
///
/// Only the stages this boundary observes are supplied: eligibility and
/// selection hold because the authorized request was presented for dispatch
/// and admitted through the existing admission owner
/// ([`super::host_request_route::check_local_read_admission`]), bound to the
/// admission source reference from [`admission_source`].
/// Every other stage — registration, advertisement, call, transport,
/// delivery, retry, use, terminal outcome — and the turn/run/attempt
/// identities stay explicitly `null`: unresolved unknown owned elsewhere,
/// never `false`, never inferred from a neighbouring stage. The Tool
/// Definition version is unobservable at this seam (the definition owner
/// lives on the publish side), so it stays explicitly `null` rather than
/// minted or guessed; the populated stages conform to
/// [`EXPOSURE_HISTORY_VERSION`].
///
/// The `idempotency_key` joins the existing operation identity with the
/// admitted request digest — the same identity the staging replay join
/// dedupes on — so a repeated staging reconciles the recorded original
/// instead of persisting a second revision. The caller emits this draft
/// only for fresh staging (replays return early at their classifier);
/// persistence itself runs through the existing observation path
/// (`audit_observe`: hash-chained append, spool reconcile on lost
/// acknowledgement, stable terminal on unavailable writeback).
///
/// Reads only, never stages, never executes. Observation never changes the
/// staged admission.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the tool value carries
/// no admitted name or when an owner-supplied reference fails its existing
/// validation.
pub(crate) fn dispatch_exposure_draft(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
    admission: &LocalReadAdmission,
) -> Result<AuditEventDraft, eliot_receipts::ToolExposureError> {
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(serde_json::Value::as_str)
        .ok_or(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.tool_definition",
            reason: "admitted tool carries no definition identity",
        })?;
    let route = route_fingerprint(envelope, admission);
    let owner_source = admission_source(admission);
    let eligible = OwnerStageFact::supplied(true, owner_source.clone())?;
    let selected = OwnerStageFact::supplied(true, owner_source)?;
    let operation_id = eliot_protocol::host_request_operation_id(envelope);
    let body = serde_json::json!({
        "tool_definition": name,
        "definition_version": null,
        "route_fingerprint": route.clone(),
        "surface_ref": route,
        "turn_ref": null,
        "run_ref": null,
        "attempt_ref": null,
        "registered": null,
        "advertised_to_route": null,
        "eligible_under_scope_policy_and_grant": eligible,
        "selected_by_planner_or_model": selected,
        "called": null,
        "transport_completed": null,
        "result_delivery": null,
        "delivery_source_ref": null,
        "expanded_or_retried": null,
        "observably_used_in_decision_action_or_verifier": null,
        "terminal_task_or_product_outcome_ref": null,
        "exposure_history_version": EXPOSURE_HISTORY_VERSION,
        "idempotency_key": format!("{operation_id}:{}", envelope.envelope_sha256),
    });
    Ok(AuditEventDraft::receipt_exposure_recorded(envelope, body))
}

/// Emits one dispatch-owned exposure draft through the existing observation
/// path (issue #1745, R7 persistence tail).
///
/// Best-effort like every observation: a populate failure is terminal-visible
/// but never changes the staged admission. Callers invoke this only for fresh
/// staging; replays reconcile the recorded original upstream.
pub(crate) fn observe_dispatch_exposure(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
    admission: &LocalReadAdmission,
    emit: impl FnOnce(AuditEventDraft),
) {
    match dispatch_exposure_draft(envelope, tool, admission) {
        Ok(draft) => emit(draft),
        Err(_) => crate::kernel_diagnostics::observe_terminal_error(
            crate::kernel_audit::KERNEL_AUDIT_APPEND_TERMINAL_CODE,
        ),
    }
}

/// Populates the completion-seam-owned exposure evidence for one persisted
/// result and seals it as the durable observation draft.
///
/// Only the stages this boundary observes are supplied, each from its own
/// owner evidence carried by the completed receipt:
/// - `called` and `transport_completed` hold because the receipt retains a
///   produced result with digest-bound delivered representation: the queued
///   pair executed and its result persisted through the Kernel transport leg.
///   Both bind the `host-request-persisted-completion` coordinates, never
///   caller prose;
/// - `result_delivery` is `FULL` with the produced digest and the delivery
///   owner's measured source handle. Only digest-bound full delivery is
///   observable here: the protocol rejects oversize bodies instead of cutting
///   them, and token measurement has no owner on this path, so token
///   observations stay absent rather than zero;
/// - observable use holds only on the campaign lane when the completed
///   receipt records it (the lane verifier consumed the verified view),
///   bound to the `campaign-packet-verified-view` evidence. Query and Skill
///   lanes serve bytes without deciding from content, so their use stays
///   explicitly unresolved — never `false`;
/// - the terminal outcome carries the receipt's recorded reference verbatim.
///
/// Registration, advertisement, eligibility, selection, and retry stay
/// explicitly `null`: unresolved unknown owned elsewhere, never `false`,
/// never inferred from a neighbouring stage, and never overwritten — the
/// dispatch seam already recorded its own stages in its own draft under the
/// same idempotency lineage. Turn, run, and attempt identities likewise stay
/// unresolved; the surface identity is the admission-derived route, exactly
/// like the dispatch draft, so both drafts join one revision lineage. The
/// Tool Definition version stays explicitly `null`: the definition owner
/// lives on the publish side and this seam never mints or guesses it.
///
/// The `idempotency_key` repeats the dispatch construction
/// (`operation:envelope-sha256`), so a repeated completion reconciles the
/// recorded original instead of persisting a second revision.
///
/// Reads only, never stages, never executes. Observation never changes the
/// persisted completion.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the receipt is
/// inconsistent, joins a different tool or route than the admitted request,
/// names a different operation than the presenting envelope, records anything
/// but digest-bound full delivery, or carries unbound digests.
pub(crate) fn completion_exposure_draft(
    envelope: &eliot_protocol::HostRequestEnvelope,
    request: &ToolCallRequest,
    receipt: &ToolExposureReceiptV2,
    campaign_lane: bool,
) -> Result<AuditEventDraft, eliot_receipts::ToolExposureError> {
    receipt.validate()?;
    if request.tool_definition != receipt.tool_definition {
        return Err(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.tool_definition",
            reason: "exposure draft joins the wrong evaluated tool",
        });
    }
    if request.route_fingerprint != receipt.route_fingerprint {
        return Err(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.route_fingerprint",
            reason: "exposure draft joins the wrong evaluated route",
        });
    }
    let operation = eliot_protocol::host_request_operation_id(envelope);
    if operation != receipt.receipt_id {
        return Err(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.identities",
            reason: "exposure draft names a different operation than its envelope",
        });
    }
    if !matches!(receipt.result_delivery, ResultDelivery::Full) {
        return Err(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.result_delivery",
            reason: "completion seam observes only digest-bound full delivery",
        });
    }
    let produced = receipt.produced_result.as_ref().ok_or(
        eliot_receipts::ToolExposureError::InvalidField {
            field: "history.result_delivery",
            reason: "completion delivery requires the produced result it evidences",
        },
    )?;
    let delivered = receipt.delivered_representation.as_ref().ok_or(
        eliot_receipts::ToolExposureError::InvalidField {
            field: "history.delivery_source_ref",
            reason: "full delivery requires rendered representation evidence",
        },
    )?;
    if produced.result_digest != delivered.representation_digest {
        return Err(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.delivery_source_ref",
            reason: "produced digest does not bind the delivered representation",
        });
    }
    let coordinates = format!(
        "host-request-persisted-completion:{}:{}",
        receipt.receipt_id, produced.result_digest
    );
    let called = OwnerStageFact::supplied(true, coordinates.clone())?;
    let transport = OwnerStageFact::supplied(true, coordinates)?;
    let used = match (campaign_lane, receipt.is_evidence_used()) {
        (true, true) => Some(OwnerStageFact::supplied(
            true,
            format!(
                "campaign-packet-verified-view:{}:{}",
                receipt.receipt_id, produced.result_digest
            ),
        )?),
        _ => None,
    };
    let delivery = serde_json::to_value(ResultDelivery::Full).map_err(|_| {
        eliot_receipts::ToolExposureError::InvalidField {
            field: "history.result_delivery",
            reason: "full delivery is not serializable",
        }
    })?;
    let body = serde_json::json!({
        "tool_definition": request.tool_definition,
        "definition_version": null,
        "route_fingerprint": request.route_fingerprint,
        "surface_ref": request.route_fingerprint,
        "turn_ref": null,
        "run_ref": null,
        "attempt_ref": null,
        "registered": null,
        "advertised_to_route": null,
        "eligible_under_scope_policy_and_grant": null,
        "selected_by_planner_or_model": null,
        "called": called,
        "transport_completed": transport,
        "result_delivery": delivery,
        "result_digest": produced.result_digest,
        "delivery_source_ref": delivered.source_handle,
        "expanded_or_retried": null,
        "observably_used_in_decision_action_or_verifier": used,
        "terminal_task_or_product_outcome_ref": receipt.terminal_task_or_product_outcome_ref,
        "exposure_history_version": EXPOSURE_HISTORY_VERSION,
        "idempotency_key": format!("{operation}:{}", envelope.envelope_sha256),
    });
    Ok(AuditEventDraft::receipt_exposure_recorded(envelope, body))
}

/// Emits one completion-owned exposure draft through the existing observation
/// path (issue #1745, R7 completion tail).
///
/// Best-effort like every observation: a populate failure is terminal-visible
/// but never changes the persisted completion. Callers invoke this only for a
/// freshly persisted completion alongside the retained receipt; replays
/// reconcile the recorded original upstream.
pub(crate) fn observe_completion_exposure(
    envelope: &eliot_protocol::HostRequestEnvelope,
    request: &ToolCallRequest,
    receipt: &ToolExposureReceiptV2,
    campaign_lane: bool,
    emit: impl FnOnce(AuditEventDraft),
) {
    match completion_exposure_draft(envelope, request, receipt, campaign_lane) {
        Ok(draft) => emit(draft),
        Err(_) => crate::kernel_diagnostics::observe_terminal_error(
            crate::kernel_audit::KERNEL_AUDIT_APPEND_TERMINAL_CODE,
        ),
    }
}
