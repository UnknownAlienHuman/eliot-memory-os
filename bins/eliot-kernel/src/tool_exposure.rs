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

use eliot_contracts::sha256_hex;
use eliot_receipts::{
    LoopSignal, ToolCallClass, ToolCallIntent, ToolCallRequest,
    tool_exposure::{
        AttemptEvidence, ExposureIdentities, ExposureReplaySignal, OwnerStageFact,
        ToolExposureHistoryEntry, ToolExposureReceiptV2, detect_exposure_replay,
        detect_repeat_without_progress_with_evidence, EXPOSURE_HISTORY_VERSION,
    },
};

use super::host_request_route::LocalReadAdmission;

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
    }
}

/// Derives the tool call class from the accepted Kernel admission.
///
/// Tool names, descriptions, and shell substrings never define call
/// semantics: the class comes from the admitted method. The bounded evidence
/// query is broad-search, an exact Skill lifecycle tool is expensive, and a
/// task-bound campaign packet is effect-capable. A name outside the admitted
/// set never reaches classification; admission fails closed first.
pub(crate) fn call_class(admission: &LocalReadAdmission) -> ToolCallClass {
    match admission {
        LocalReadAdmission::Query(_) => ToolCallClass::BroadSearch,
        LocalReadAdmission::Skill => ToolCallClass::Expensive,
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
        LocalReadAdmission::CampaignPacket {
            task_id,
            task_revision,
            ..
        } => format!("local-read-admission:campaign-packet:{task_id}:{task_revision}"),
    }
}

/// Populates the dispatch-seam-owned stages of one orthogonal exposure history.
///
/// Only the stages this boundary observes are supplied: eligibility and
/// selection hold because the authorized request was presented for dispatch
/// and admitted through the existing admission owner
/// ([`super::host_request_route::check_local_read_admission`]). Registration
/// and advertisement stay explicitly unresolved — the Tool Definition and
/// publish seams populate them, and an admitted name never proves
/// registration. Call, transport, delivery, retry, use, and terminal stages
/// stay explicitly unresolved: the execution, transport, bridge/host
/// projection, and verifier owners populate them, never this seam. Unknown
/// coverage is recorded as `None`, never coerced to `false` and never
/// inferred from a neighbouring stage, so every applicable I7.24 field is
/// supplied or explicitly unresolved, never omitted to obtain a
/// valid-looking record.
///
/// The tool definition identity and route fingerprint come from the accepted
/// admission exactly as they do for [`build_tool_call_request`]. The Tool
/// Definition version arrives from its owner through the caller and is
/// validated here, never invented: a seam that never mints a version binds
/// the supplied one. Turn, run, and attempt identities likewise arrive from
/// their owners; the surface identity defaults to the admission-derived
/// route fingerprint when the caller supplies none, so every entry joins a
/// revision lineage.
///
/// Pure and total: reads only, never stages, never executes, never persists.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the tool value carries
/// no admitted name, when an owner-supplied reference is blank or carries
/// control characters, or when the populated entry is inconsistent.
pub(crate) fn admission_exposure_history(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
    admission: &LocalReadAdmission,
    definition_version: &str,
    mut identities: ExposureIdentities,
) -> Result<ToolExposureHistoryEntry, eliot_receipts::ToolExposureError> {
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(serde_json::Value::as_str)
        .ok_or(eliot_receipts::ToolExposureError::InvalidField {
            field: "history.tool_definition",
            reason: "admitted tool carries no versioned definition identity",
        })?;
    let route = route_fingerprint(envelope, admission);
    if identities.surface_ref.is_none() {
        identities.surface_ref = Some(route.clone());
    }
    let owner_source = admission_source(admission);
    let entry = ToolExposureHistoryEntry {
        schema_version: EXPOSURE_HISTORY_VERSION,
        tool_definition: name.to_owned(),
        definition_version: definition_version.to_owned(),
        route_fingerprint: Some(route),
        identities,
        registered: OwnerStageFact::unresolved(),
        advertised_to_route: OwnerStageFact::unresolved(),
        eligible_under_scope_policy_and_grant: OwnerStageFact::supplied(
            true,
            owner_source.clone(),
        )?,
        selected_by_planner_or_model: OwnerStageFact::supplied(true, owner_source)?,
        called: OwnerStageFact::unresolved(),
        transport_completed: OwnerStageFact::unresolved(),
        result_delivery: None,
        delivery_source_ref: None,
        expanded_or_retried: OwnerStageFact::unresolved(),
        observably_used_in_decision_action_or_verifier: OwnerStageFact::unresolved(),
        terminal_task_or_product_outcome_ref: None,
    };
    entry.validate()?;
    Ok(entry)
}

/// What the Kernel dispatch seam does with a repeated exposure revision.
///
/// The classifier evidence is bound, never by existence: a receipt identity
/// proves nothing until its recorded content is compared with this operation.
/// Digests are validated on the recorded original through the existing
/// [`ToolExposureReceiptV2::validate`], never recomputed here.
pub(crate) enum ExposureRevisionDisposition<'a> {
    /// Same receipt identity with identical recorded evidence: a replayed
    /// publication or result redelivery, not new work. The caller reconciles
    /// the recorded original event — executes nothing again and records no
    /// new use — so the replay produces neither duplicate execution nor
    /// false usage evidence.
    ReconcileRecordedOriginal {
        /// The recorded original revision to reconcile, not rewrite.
        recorded: &'a ToolExposureReceiptV2,
    },
    /// New receipt identity linked through the recorded
    /// `prior_delivery_receipt_id` to the recorded prior while retaining the
    /// same produced result digest: a later authorized expansion delivery of
    /// the same result. The linked revision persists through the existing
    /// observation/receipt path alongside the recorded prior; the original
    /// truncation is preserved, never rewritten.
    PersistLinkedRevision {
        /// The linked revision to persist, never a rewrite of the prior.
        revision: &'a ToolExposureReceiptV2,
    },
    /// Not a replay pair; the revision routes to its stage owners.
    NotAReplayPair,
}

/// Disposes a repeated exposure revision against its recorded original.
///
/// Both revisions validate as recorded first through the existing
/// [`detect_exposure_replay`]: the original recorded digest values are
/// checked, never recomputed, and recorded content decides. A conflicting
/// same-identity revision fails with the classifier's typed error so it can
/// never validate as a quiet rewrite; the caller persists a linked revision
/// through the existing observation/receipt path instead.
///
/// Pure and total: classifies only, never stages, never executes, never
/// persists, never records use. Observable use still requires its public
/// action/decision/verifier link at the use owner; hidden reasoning is not
/// requested and a replayed delivery is not use.
///
/// STITCH(host_request_route): the owning seam persists the returned
/// revision — [`ExposureRevisionDisposition::PersistLinkedRevision`] through
/// the existing observation/receipt path (the `eliot.observe` capture seam
/// at `admit_and_queue_observe_submit`, or the bridge/host projection that
/// owns the delivered representation), and reconciles
/// [`ExposureRevisionDisposition::ReconcileRecordedOriginal`] against the
/// recorded original event. This module performs no durable write because no
/// durable V2-receipt owner exists on main at this seam: the reachable
/// durable seams are typed for `HostRequestAttempt`/bridge-event rows and
/// private to `host_request_route`, and this seam mints no receipt
/// identities, opens no second store, and performs no blocking attach. Until
/// the owning seam carries the write, a returned linked revision stays a
/// visible pending obligation — never coerced into executed or used.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when either revision is
/// inconsistent, or when one receipt identity carries conflicting recorded
/// evidence.
pub(crate) fn dispose_exposure_revision<'a>(
    recorded: &'a ToolExposureReceiptV2,
    current: &'a ToolExposureReceiptV2,
) -> Result<ExposureRevisionDisposition<'a>, eliot_receipts::ToolExposureError> {
    match detect_exposure_replay(recorded, current)? {
        Some(ExposureReplaySignal::IdempotentReplay) => {
            Ok(ExposureRevisionDisposition::ReconcileRecordedOriginal { recorded })
        }
        Some(ExposureReplaySignal::LinkedExpansion) => {
            Ok(ExposureRevisionDisposition::PersistLinkedRevision { revision: current })
        }
        None => Ok(ExposureRevisionDisposition::NotAReplayPair),
    }
}
