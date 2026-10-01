//! Governor observe serving adapter (issue #2565).
//!
//! Per-claim decoder over one Kernel-admitted `eliot.observe` pair: proves
//! the closed linkage and fence binding the Kernel already admitted, decodes
//! only the closed shared tool vocabulary (the five I7.6 suboperations), and
//! routes each suboperation through the one explicit owner map below.
//!
//! Caller chain: daemon runtime observe poller -> this decoder ->
//! `DaemonKernelClient::defer_observe_claim_async` (pair retired, durable
//! record `Routed`) or, once the matching owner admission connects,
//! `DaemonKernelClient::submit_observe_result_async` (retained result).
//!
//! Production edges out of this module:
//! [`serve_admitted_observe`] serves one admitted pair as an honest
//! [`ObserveDeferral`] naming its exact owner and resume condition;
//! [`decode_observe_suboperation`] decodes the closed vocabulary;
//! [`observe_suboperation_owner`] is the single suboperation-to-owner map.
//!
//! The `Observation` suboperation now executes: [`capture_admitted_observation`]
//! projects the Kernel-admitted payload into the Governor observation owner's
//! existing capture path (`ObservationJournal::admit` plus
//! `CanonicalAdmissionOwner::commit`, both inside
//! `GovernorObservationReconciliation`). The other four suboperations still
//! defer with their exact owner and resume condition: a deferral is never
//! completion, the pending handle stays live under the daemon owner, the
//! status/resolve/rehydrate entries keep serving the live record, and
//! resubmitting the same logical request once the owner connects re-enqueues
//! the pair for execution without duplicating anything. Missing handler
//! semantics stay with their owners and never justify a second semantic
//! engine here.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_observation::{
    CaptureRoute, CoverageDisposition, CoverageEvidence, Durability, ObservationEventCore,
    ObservationEventIdentity, ObservationKind, ObservationRecordEnvelope, ObservationRecordKind,
    ObservationScope, ObservationSubmission, PrivacyRetentionDisclosure, ProducerTrace,
};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};
use eliot_receipts::WorkScopeId;

/// Admitted capability this adapter serves.
const OBSERVE_CAPABILITY: &str = "eliot.observe";

/// Producer identity recorded on a captured observe observation.
///
/// This is the daemon's own service identity, the same value it presents to
/// the canonical owner on every other daemon-side ingress (`SERVICE_NAME`).
/// It is a producer label for what the daemon recorded, never an assertion of
/// task authority.
const OBSERVE_PRODUCER: &str = "eliotd.observe";

/// Route facet recorded on a captured observe observation.
const OBSERVE_ROUTE_REF: &str = "eliot.observe";

/// Privacy domain of a captured observe observation.
///
/// The observation's privacy domain IS its work scope: the record describes
/// work inside that scope, so a separate global privacy domain would claim a
/// disclosure authority nobody granted.
const OBSERVE_DISCLOSURE_CLASS: &str = "observe-candidate";

/// Retention policy of a captured observe observation.
///
/// A durable-candidate capture retains the same way every other candidate on
/// this path retains. Retention enforcement stays with the retention owner;
/// this is the policy reference the record carries, not an enforcement.
const OBSERVE_RETENTION_POLICY_REF: &str = "governor-retention";

/// Owner-issued provenance/source facts for one admitted observe payload.
///
/// Every field is read from a real owner, never defaulted:
/// - `affected_resources` and `source_handles` are the caller's exact
///   declared sets from the admitted `ObserveInput`. Empty means the caller
///   declared no source handle, which is a real answer and not a substitute
///   for owner data.
/// - `session_id` and `work_scope_id` are the Kernel-admitted identities on
///   the envelope itself.
/// - `envelope_digest`, `payload_digest`, `operation_id`, `attempt_id` and
///   `attempt_generation` are the retained host request's own operation
///   identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveObservationProvenance {
    /// Exact source/evidence handles the caller declared.
    pub source_handles: Vec<String>,
    /// Exact paths/entities the caller declared as affected.
    pub affected_resources: Vec<String>,
    /// Admitted session identity, when the Kernel bound one.
    pub session_id: Option<String>,
    /// Admitted work-scope identity, when the Kernel bound one.
    pub work_scope_id: Option<String>,
    /// Digest of the exact retained host-request envelope.
    pub envelope_digest: String,
    /// Digest of the exact canonical tool bytes this observation came from.
    pub payload_digest: String,
    /// Kernel-derived operation handle of the retained host request.
    pub operation_id: String,
    /// Boot-unique attempt identity the Kernel minted for this claim.
    pub attempt_id: String,
    /// Monotonic fencing generation of that attempt.
    pub attempt_generation: u64,
    /// Task the caller selected, when the observation named one. `None` keeps
    /// the capture cold; it is never substituted with a fabricated task.
    pub task_id: Option<String>,
}

/// A captured `Observation` outcome, projected through the observation owner.
///
/// The receipt is the store's own; a terminal non-committed status is a
/// refusal, never a capture, and the caller must treat it as such.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveObservationCapture {
    /// Record identity the journal admitted.
    pub record_id: String,
    /// Canonical request digest the journal issued.
    pub request_digest: String,
    /// Exact store receipt for the canonical capture commit.
    pub receipt: eliot_store_api::WriteReceipt,
    /// Whether the admitted observation named a task. `false` is a cold
    /// candidate, not a weaker capture.
    pub task_bound: bool,
}

/// The closed five observe suboperations (`eliot.observe`, I7.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveSuboperation {
    /// What was observed, with source/effect metadata.
    Observation,
    /// Chosen path, alternatives and revisit condition.
    Decision,
    /// Failed path, signature, evidence and next discriminator.
    Failure,
    /// Actual artifact/effect/verifier result.
    Outcome,
    /// How a delivered memory item affected the next public decision.
    InfluenceAck,
}

impl ObserveSuboperation {
    /// Stable wire discriminator for this suboperation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Decision => "decision",
            Self::Failure => "failure",
            Self::Outcome => "outcome",
            Self::InfluenceAck => "influence_ack",
        }
    }
}

/// One explicit owner route for an observe suboperation (issue #2565 item
/// 7: one handler/capability map with the exact real caller and the residual
/// owner for everything not yet connected).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveOwnerRoute {
    /// Routed suboperation.
    pub suboperation: ObserveSuboperation,
    /// Missing owner admission that must connect before execution.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics (never this adapter).
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
}

/// Returns the single recorded owner route for one suboperation.
///
/// Exhaustive over [`ObserveSuboperation`]: a new suboperation is a compile
/// error here until its owner, residual program, and resume condition are
/// recorded. The real caller for every row today is the daemon observe
/// poller (`bins/eliotd/src/daemon_runtime.rs`); the residual owner is the
/// Governor semantic program that must connect the matching admission
/// (integration #18).
pub fn observe_suboperation_owner(suboperation: ObserveSuboperation) -> ObserveOwnerRoute {
    match suboperation {
        ObserveSuboperation::Observation => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-admission",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the observation admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Decision => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-decision",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the decision admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Failure => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-failure",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the failure admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Outcome => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-outcome",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the outcome admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::InfluenceAck => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-influence-ack",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the influence-ack admission connects; exact replay re-enqueues the pair",
        },
    }
}

/// Decodes only the closed shared observe vocabulary from linked tool bytes.
///
/// Returns the suboperation discriminator. The tool name must be the
/// admitted capability and `arguments.kind` must name exactly one of the
/// five I7.6 suboperations; anything else fails closed. No semantic field is
/// interpreted here — routing only.
pub fn decode_observe_suboperation(
    tool: &serde_json::Value,
) -> Result<ObserveSuboperation, String> {
    let object = tool
        .as_object()
        .ok_or_else(|| "daemon observe pair tool is not an object".to_owned())?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "daemon observe pair tool omits the canonical tool name".to_owned())?;
    if name != OBSERVE_CAPABILITY {
        return Err("daemon observe pair tool is not the admitted observe capability".to_owned());
    }
    let kind = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .and_then(|arguments| arguments.get("kind"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "daemon observe pair tool omits the suboperation discriminator".to_owned()
        })?;
    match kind {
        "observation" => Ok(ObserveSuboperation::Observation),
        "decision" => Ok(ObserveSuboperation::Decision),
        "failure" => Ok(ObserveSuboperation::Failure),
        "outcome" => Ok(ObserveSuboperation::Outcome),
        "influence_ack" => Ok(ObserveSuboperation::InfluenceAck),
        _ => Err("daemon observe pair tool names an unknown suboperation".to_owned()),
    }
}

/// Honest deferral for one served observe pair.
///
/// Names the exact owner admission that must connect, the residual program
/// that owns it, and the resume condition — never a result, never a receipt.
/// The daemon flight records this through the Kernel defer leg (pair
/// retired, durable record `Routed`) and the waiter keeps the live pending
/// handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveDeferral {
    /// Served suboperation.
    pub suboperation: ObserveSuboperation,
    /// Missing owner admission that must connect before execution.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics.
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
}

/// Serves one admitted observe pair through the closed vocabulary.
///
/// Re-proves the admitted linkage (capability echoes the tool name,
/// canonical tool bytes digest to the admitted payload digest), the admitted
/// envelope shape, and the attempt binding (operation handle plus validated
/// capability admitted for this facet) before any defer touches the pair. Returns the honest
/// deferral with its exact owner and resume condition. Pure: no IO, no
/// semantic interpretation, no invented receipt.
pub fn serve_admitted_observe(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ObserveDeferral, String> {
    envelope
        .validate()
        .map_err(|error| format!("daemon observe pair envelope is not admitted shape: {error}"))?;
    if envelope.identity.capability != OBSERVE_CAPABILITY {
        return Err(
            "daemon observe pair envelope is not the admitted observe capability".to_owned(),
        );
    }
    attempt
        .validate()
        .map_err(|error| format!("daemon observe pair attempt is not bound shape: {error}"))?;
    if attempt.operation_id != host_request_operation_id(envelope) {
        return Err("daemon observe pair attempt does not bind the envelope".to_owned());
    }
    // Issue #1739 W3: the claim joins the Governor dispatch only through
    // the attempt minted for this admitted operation. A capability minted
    // for another facet never dispatches here, even when its shape
    // validates — the defer leg would quarantine it, but the dispatch
    // refuses it before any suboperation decodes.
    if attempt.facet_method != OBSERVE_CAPABILITY {
        return Err(
            "daemon observe pair attempt is not admitted for the observe operation".to_owned(),
        );
    }
    let object = tool
        .as_object()
        .ok_or_else(|| "daemon observe pair tool is not an object".to_owned())?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "daemon observe pair tool omits the canonical tool name".to_owned())?;
    if name != envelope.identity.capability {
        return Err("daemon observe pair tool does not match the admitted capability".to_owned());
    }
    let bytes = canonical_json_bytes(tool)
        .map_err(|error| format!("daemon observe pair tool cannot be canonicalized: {error}"))?;
    if sha256_hex(&bytes) != envelope.identity.payload_sha256 {
        return Err(
            "daemon observe pair payload does not match the admitted payload digest".to_owned(),
        );
    }
    let suboperation = decode_observe_suboperation(tool)?;
    let route = observe_suboperation_owner(suboperation);
    Ok(ObserveDeferral {
        suboperation: route.suboperation,
        owner_capability: route.owner_capability,
        residual_owner: route.residual_owner,
        resume: route.resume,
    })
}

/// Returns whether this suboperation executes through the observation owner
/// today.
///
/// Exactly one row is connected: `Observation` captures through
/// [`capture_admitted_observation`]. The other four still have no connected
/// owner admission and keep deferring, so this predicate is the single place
/// the difference between "executed" and "deferred" is decided.
#[must_use]
pub const fn observe_suboperation_executes(suboperation: ObserveSuboperation) -> bool {
    matches!(suboperation, ObserveSuboperation::Observation)
}

/// The exact owner-read provenance for one admitted observe payload.
///
/// Every value is read off the admitted envelope, the Kernel-minted attempt
/// or the retained tool bytes; nothing here is invented or substituted with a
/// default. `task_id` is the Kernel-admitted task the envelope claims. When
/// that is `None` the capture stays a COLD CANDIDATE: `task_selection` is
/// `None` and the canonical envelope carries no `task_id`. Fabricating a task
/// to reach a positive capture is exactly the failure this path exists to
/// prevent, so an absent task is preserved as absent all the way through.
fn observe_provenance(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ObserveObservationProvenance, String> {
    let arguments = tool
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "daemon observe pair tool omits its admitted arguments".to_owned())?;
    let text_array = |key: &'static str| -> Result<Vec<String>, String> {
        let Some(value) = arguments.get(key) else {
            return Ok(Vec::new());
        };
        let entries = value.as_array().ok_or_else(|| {
            format!("daemon observe pair argument {key} is not an array of declared handles")
        })?;
        let mut seen = BTreeSet::new();
        let mut collected = Vec::with_capacity(entries.len());
        for entry in entries {
            let text = entry.as_str().ok_or_else(|| {
                format!("daemon observe pair argument {key} carries a non-text handle")
            })?;
            if text.trim().is_empty() || text.chars().any(char::is_control) {
                return Err(format!(
                    "daemon observe pair argument {key} carries an unusable handle"
                ));
            }
            if seen.insert(text.to_owned()) {
                collected.push(text.to_owned());
            }
        }
        Ok(collected)
    };
    Ok(ObserveObservationProvenance {
        source_handles: text_array("source_handles")?,
        affected_resources: text_array("affected_resources")?,
        session_id: envelope.identity.session_id.clone(),
        work_scope_id: envelope.identity.work_scope_id.clone(),
        envelope_digest: envelope.envelope_sha256.clone(),
        payload_digest: envelope.identity.payload_sha256.clone(),
        operation_id: host_request_operation_id(envelope),
        attempt_id: attempt.attempt_id.clone(),
        attempt_generation: attempt.fencing_generation,
        task_id: envelope.identity.task_id.clone(),
    })
}

/// The evidence set one admitted observe capture carries.
///
/// This is the retained host request's own identity (its payload and envelope
/// digests) plus the caller's declared source handles, deduplicated and sorted.
/// Nothing else is added: the Kernel-minted attempt is the provenance of this
/// capture, not an execution effect the observation could claim, so it is
/// recorded on the scope as `attempt_ref` rather than asserted as evidence.
fn observe_capture_evidence(provenance: &ObserveObservationProvenance) -> Vec<String> {
    let mut evidence = BTreeSet::new();
    evidence.insert(provenance.payload_digest.clone());
    evidence.insert(provenance.envelope_digest.clone());
    for handle in &provenance.source_handles {
        evidence.insert(handle.clone());
    }
    evidence.into_iter().collect()
}

/// Projects one admitted `Observation` payload into the observation owner's
/// typed submission.
///
/// Provenance and source come from the Kernel-admitted envelope and the
/// retained tool bytes; the work scope is the Kernel-admitted scope when the
/// envelope names one, otherwise the daemon's own governed self scope the
/// observation owner admits captures into. A no-task observation keeps
/// `task_ref: None` and submits no task selection.
fn observe_capture_submission(
    envelope: &HostRequestEnvelope,
    provenance: &ObserveObservationProvenance,
    observed_at_unix_ms: u64,
) -> Result<(eliot_contracts::OperationId, ObserveAdmittedSubmission), String> {
    let work_scope_text = provenance
        .work_scope_id
        .clone()
        .unwrap_or_else(|| crate::SERVICE_NAME.to_owned());
    let work_scope = WorkScopeId::new(work_scope_text.clone())
        .map_err(|error| format!("daemon observe work scope is not a contract value: {error}"))?;
    // The observation's own identity is derived from the retained host
    // request's operation identity, not from retry time and not from a
    // per-call counter, so an identical replay presents the same operation and
    // the store's `(operation_id, canonical_request_hash)` identity reconciles
    // the retry onto the first commit instead of writing a second record.
    let observation_operation = eliot_contracts::OperationId::new(format!(
        "{}/observe-observation",
        provenance.operation_id
    ))
    .map_err(|error| {
        format!("daemon observe capture operation is not a contract value: {error}")
    })?;
    let idempotency_key = format!(
        "{}:observe:observation:{}",
        envelope.identity.idempotency_key, provenance.payload_digest
    );
    let clock = eliot_contracts::ClockReading {
        valid_time_ms: i64::try_from(observed_at_unix_ms).ok(),
        known_time_ms: i64::try_from(observed_at_unix_ms).ok(),
        transaction_sequence: None,
        monotonic_ns: None,
    };
    let evidence = observe_capture_evidence(provenance);
    let record_id = format!("observe:{}", provenance.payload_digest);
    let event_id = format!("observe-event:{}", provenance.payload_digest);
    let core = ObservationEventCore {
        event_id_and_time: ObservationEventIdentity { event_id, clock },
        producer_generation_and_trace: ProducerTrace {
            producer: OBSERVE_PRODUCER.to_owned(),
            generation: envelope.state_fence.resource_generation.value().to_string(),
            trace_ref: Some(provenance.operation_id.clone()),
        },
        kind: ObservationKind::AgentFeedback,
        affected_scope: ObservationScope {
            work_scope,
            // An absent Kernel-admitted task stays absent. The record is a
            // cold candidate, never a fabricated task-bound one.
            task_ref: provenance.task_id.clone(),
            attempt_ref: Some(provenance.attempt_id.clone()),
            module_or_route_ref: Some(OBSERVE_ROUTE_REF.to_owned()),
        },
        observed_delta: format!(
            "observe observation captured under operation {} attempt {} generation {} affecting [{}]",
            provenance.operation_id,
            provenance.attempt_id,
            provenance.attempt_generation,
            provenance.affected_resources.join(", ")
        ),
        expected_baseline: None,
        evidence_and_raw_handles: evidence,
        // One observation is one observation: the denominator is this exact
        // admitted capture, not a rate anyone could have sampled away.
        coverage_and_blind_intervals: CoverageEvidence {
            disposition: CoverageDisposition::Complete,
            denominator_source_ref: format!("eliot.observe:{}", provenance.payload_digest),
            interval: None,
            blind_intervals: Vec::new(),
            observed_count: 1,
        },
        privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
            // The privacy domain is the work scope the record describes. The
            // retention policy reference names the owner's candidate retention;
            // retention enforcement itself stays with the retention owner.
            privacy_domain_ref: work_scope_text,
            retention_policy_ref: OBSERVE_RETENTION_POLICY_REF.to_owned(),
            disclosure_class: OBSERVE_DISCLOSURE_CLASS.to_owned(),
        },
        candidate_importance: 1,
        dedup_key: provenance.payload_digest.clone(),
    };
    let submission = ObservationSubmission {
        operation_id: observation_operation.as_str().to_owned(),
        idempotency_key,
        state_fence: envelope.state_fence.clone(),
        record: ObservationRecordEnvelope {
            record_id: record_id.clone(),
            kind: ObservationRecordKind::Telemetry,
            event: Some(core),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        },
        record_v2: None,
        capture_route: CaptureRoute::CanonicalJournal,
        durability: Durability::Durable,
        plan: None,
        // No task selection is asserted without an owner-selected task. A
        // task-bound observation carries no fabricated acceptance digest.
        task_selection: None,
        evidence: None,
    };
    let request_digest = submission
        .request_digest()
        .map_err(|error| format!("daemon observe capture submission is not admissible: {error}"))?;
    Ok((
        observation_operation,
        ObserveAdmittedSubmission {
            record_id,
            request_digest,
            task_bound: provenance.task_id.is_some(),
            submission,
        },
    ))
}

/// One admitted capture submission plus the journal identities it binds.
pub struct ObserveAdmittedSubmission {
    /// Record identity the submission will be admitted under.
    pub record_id: String,
    /// Canonical request digest the submission resolves to.
    pub request_digest: String,
    /// Whether the admitted observation named a task.
    pub task_bound: bool,
    /// The typed submission handed to the observation owner unchanged.
    pub submission: ObservationSubmission,
}

/// Captures one admitted `Observation` pair through the observation owner.
///
/// This is the production execution of the `Observation` arm. It first
/// re-proves the admitted linkage exactly as [`serve_admitted_observe`] does
/// and refuses anything that is not the `Observation` suboperation, then
/// projects the retained payload into the owner's typed submission from the
/// real admitted identities, then admits that submission through the single
/// Governor observation owner. The store's own receipt is returned unchanged:
/// a terminal non-committed status is a refusal, not a capture, and no
/// receipt, commit or readback is ever fabricated to obtain a positive result.
///
/// No composition lock is held across the owner's IO: the caller supplies a
/// borrow that is taken and dropped around this call, exactly like the
/// maintenance publication path beside it.
pub async fn capture_admitted_observation<P: eliot_governor::KernelTransitionPort + ?Sized>(
    owner: &crate::observation_adapters::ForwardingObservationReconciliation<'_, P>,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ObserveObservationCapture, String> {
    // The same closed linkage proof the defer leg uses, so a pair that could
    // not be served is refused before any owner work begins.
    let deferral = serve_admitted_observe(envelope, tool, attempt)?;
    if !observe_suboperation_executes(deferral.suboperation) {
        return Err(format!(
            "daemon observe pair is the {} suboperation; only the observation suboperation captures",
            deferral.suboperation.as_str()
        ));
    }
    let provenance = observe_provenance(envelope, tool, attempt)?;
    // A currency check before the effect: the live composition fence is read by
    // the caller and compared against the fence this pair was admitted under.
    // The pair is only executed against a still-current fence.
    let live_fence = owner.state_fence();
    if live_fence != envelope.state_fence {
        return Err("daemon observe capture fence is not the live admitted fence".to_owned());
    }
    let observed_at_unix_ms = u64::try_from(crate::unix_ms_i64()).unwrap_or_default();
    let (operation, prepared) =
        observe_capture_submission(envelope, &provenance, observed_at_unix_ms)?;
    let identity = observe_capture_identity(envelope, &prepared.submission.idempotency_key)?;
    let receipt = owner
        .admit_capture_submission(&identity, &operation, &prepared.submission)
        .await
        .map_err(|error| format!("daemon observe capture admission: {error}"))?;
    Ok(ObserveObservationCapture {
        record_id: prepared.record_id,
        request_digest: prepared.request_digest,
        receipt,
        task_bound: prepared.task_bound,
    })
}

/// Derives the admitted capture identity from the retained host request.
///
/// The request binding is the Kernel's own: same fence, same session and task
/// as the admitted envelope, with the daemon's own product/source identity. The
/// operation identity is the observation's derived capture operation, not the
/// host request's, so the capture is a distinct store effect from the read that
/// fed it. The idempotency key is the submission's own derived key, so a
/// replay presents byte-identical canonical bytes and reconciles.
fn observe_capture_identity(
    envelope: &HostRequestEnvelope,
    idempotency_key: &str,
) -> Result<eliot_protocol::RequestIdentity, String> {
    let now = u64::try_from(crate::unix_ms_i64()).unwrap_or_default();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!(
            "{}:observe-capture:{idempotency_key}",
            crate::SERVICE_NAME
        ))
        .map_err(|error| format!("daemon observe capture request id: {error}"))?,
        session_id: envelope
            .identity
            .session_id
            .clone()
            .map(|session| {
                eliot_contracts::SessionId::new(session)
                    .map_err(|error| format!("daemon observe capture session id: {error}"))
            })
            .transpose()?,
        task_id: envelope
            .identity
            .task_id
            .clone()
            .map(|task| {
                eliot_contracts::TaskId::new(task)
                    .map_err(|error| format!("daemon observe capture task id: {error}"))
            })
            .transpose()?,
        product_id: eliot_contracts::ProductId::new(crate::SERVICE_NAME)
            .map_err(|error| format!("daemon observe capture product id: {error}"))?,
        source_id: eliot_contracts::SourceId::new(crate::SERVICE_NAME)
            .map_err(|error| format!("daemon observe capture source id: {error}"))?,
        state_fence: envelope.state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: i64::try_from(now).ok(),
            known_time_ms: i64::try_from(now).ok(),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|error| format!("daemon observe capture request metadata: {error}"))?;
    Ok(eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: envelope.state_fence.clone(),
        },
        idempotency_key: idempotency_key.to_owned(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        cancellation_id: envelope.identity.cancellation_id.clone(),
    })
}
