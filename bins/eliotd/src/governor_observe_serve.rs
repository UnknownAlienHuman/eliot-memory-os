//! Governor observe serving adapter (issue #2565).
//!
//! Per-claim decoder over one Kernel-admitted `eliot.observe` pair: proves
//! the closed linkage and fence binding the Kernel already admitted, decodes
//! only the closed shared tool vocabulary (the five I7.6 suboperations), and
//! routes each suboperation through the one explicit owner map below.
//!
//! Caller chain: daemon runtime observe poller -> this decoder ->
//! [`decode_observation_capture`] for the one connected suboperation, then
//! `DaemonKernelClient::submit_observe_result_async` with the real owner
//! receipt; every other suboperation goes to
//! `DaemonKernelClient::defer_observe_claim_async` (pair retired, durable
//! record `Routed`).
//!
//! Production edges out of this module:
//! [`serve_admitted_observe`] re-proves the admitted linkage and names the
//! served suboperation; [`decode_observe_suboperation`] decodes the closed
//! vocabulary; [`decode_observation_capture`] decodes the one executed
//! suboperation's typed payload into the Governor owner's capture record;
//! [`observe_suboperation_owner`] is the single suboperation-to-owner map.
//!
//! `eliot.observe / observation` has a connected semantic owner: the existing
//! Governor observation entry
//! (`GovernorObservationReconciliation::admit_captured_observation`) prepares
//! the real `CaptureCandidate` transition and the existing canonical
//! admission owner returns the Store's own `WriteReceipt`, which is what the
//! result leg carries back. The other four suboperations — `decision`,
//! `failure`, `outcome` and `influence_ack` — stay on the explicit deferred
//! map with their named residual owners, because their own semantic owners
//! have no connected admission on this path. A deferral is never completion —
//! the pending handle stays live under the daemon owner, the
//! status/resolve/rehydrate entries keep serving the live record, and
//! resubmitting the same logical request once the owner connects re-enqueues
//! the pair for execution without duplicating anything. Missing handler
//! semantics stay with their owners and never justify a second semantic
//! engine here.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::CapturedObservation;
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};

/// Admitted capability this adapter serves.
const OBSERVE_CAPABILITY: &str = "eliot.observe";

/// Work scope recorded for a safe unbound capture that admitted no scope.
///
/// An unbound capture is retained cold under this scope: it is a real scope
/// value the Governor addresses and the store orders under, not a claim that
/// the capture was task-bound. The envelope's own `work_scope_id` is used
/// whenever the admission carried one.
const OBSERVE_UNBOUND_WORK_SCOPE: &str = "governor-mcp-observe-unbound";

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
/// recorded. The real caller for every row is the daemon observe poller
/// (`bins/eliotd/src/daemon_runtime.rs`). [`ObserveSuboperation::Observation`]
/// names the connected Governor capture owner and is executed on that poll
/// step; the other four name the Governor semantic program that must connect
/// their matching admission (integration #18) and stay deferred until it does.
pub fn observe_suboperation_owner(suboperation: ObserveSuboperation) -> ObserveOwnerRoute {
    match suboperation {
        ObserveSuboperation::Observation => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.capture-observation",
            residual_owner: "connected: GovernorObservationReconciliation::admit_captured_observation",
            resume: "executed on the daemon observe flight; the retained Store WriteReceipt is the result",
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

/// Decodes the one executed suboperation's typed payload into the Governor
/// owner's capture record (issue #2565 W4).
///
/// Only [`ObserveSuboperation::Observation`] decodes: the other four remain on
/// the explicit deferred map above with their named residual owners, because
/// their semantic owners have no connected admission yet. Every identity on the
/// returned record comes from the Kernel-admitted envelope and its minted
/// attempt, and the observed content is the exact admitted payload the host
/// submitted — the host's own `candidate_disposition` is carried as a claim
/// for the owner to compare, never as authority.
///
/// Bounded by the same shared text guard the MCP surface applies before
/// admission, so a payload that would not have been admitted cannot decode here
/// either, and no unbounded host text reaches the Governor.
pub fn decode_observation_capture(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<CapturedObservation, String> {
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "daemon observe pair tool omits its arguments object".to_owned())?;
    let content = arguments
        .get("text_or_structured_payload")
        .or_else(|| arguments.get("statement"))
        .ok_or_else(|| "daemon observe pair omits the observed content field".to_owned())?
        .clone();
    if content.is_null() {
        return Err("daemon observe pair observed content is null".to_owned());
    }
    // The Governor's own bound guards on the canonical bytes, so the same
    // admission rule is applied here before the record is built rather than
    // after it is offered to the owner.
    canonical_json_bytes(&content).map_err(|error| {
        format!("daemon observe pair observed content is not canonicalizable: {error}")
    })?;
    let source_handles = match arguments.get("source_handles") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "daemon observe pair source handle is not a string".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err("daemon observe pair source handles are not a list".to_owned());
        }
    };
    let candidate_disposition = match arguments.get("candidate_disposition") {
        None | Some(serde_json::Value::Null) => "unspecified".to_owned(),
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(_) => {
            return Err("daemon observe pair candidate disposition is not a string".to_owned());
        }
    };
    Ok(CapturedObservation {
        operation_id: host_request_operation_id(envelope),
        payload_digest: envelope.identity.payload_sha256.clone(),
        // The minted attempt's session is the Kernel-issued one, never the
        // host's claim: the claim mints it and the submit leg re-proves it.
        session_id: attempt.session_id.clone(),
        work_scope_id: envelope
            .identity
            .work_scope_id
            .clone()
            .unwrap_or_else(|| OBSERVE_UNBOUND_WORK_SCOPE.to_owned()),
        task_id: envelope.identity.task_id.clone(),
        producer: envelope.identity.capability.clone(),
        observed_content: content.to_string(),
        candidate_disposition,
        source_handles,
    })
}

/// The disposition the daemon observe flight actually produced for one
/// admitted pair (issue #2565 W4/W5).
///
/// A canonical commit, an external effect, a durable child job and a host
/// response are different results, and this enum keeps them apart rather than
/// collapsing "the owner answered" into "the host request completed".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserveServeOutcome {
    /// The Governor owner committed the capture and the Store returned its own
    /// `Committed` receipt; that exact receipt is what the result body carries
    /// as its semantic receipt reference.
    Committed {
        /// The exact store operation the receipt was issued for.
        operation_id: String,
        /// The store's own canonical request hash over the committed bytes.
        canonical_request_hash: String,
    },
    /// The owner reached its own terminal, non-committed verdict. The exact
    /// status travels through unchanged; it is never reported as a capture.
    Refused {
        /// The store's own operation identity.
        operation_id: String,
        /// The exact terminal status the store issued.
        status: String,
    },
    /// The canonical commit may have executed but neither a terminal receipt
    /// nor a clean refusal was observed. The pair is not free to be retried
    /// blindly and the original owner receipt stays the reconciliation
    /// reference: this is `PossiblyEffected/Unknown`, never a safe refusal.
    OutcomeUnknown {
        /// The exact store operation whose outcome is unresolved.
        operation_id: String,
    },
}

/// Builds the canonical-write request identity for one served capture.
///
/// The fence is the one the Kernel admitted on this exact envelope and read
/// here from that envelope, never taken from the host or from a cached copy:
/// `validate_capture_identity_fence` requires it to equal the live canonical
/// fence anyway, so a stale transported fence is refused rather than
/// substituted. The request and idempotency identities are derived from the
/// admitted operation and its exact payload digest, so a replay of the same
/// logical request converges on the same identity while a changed payload is a
/// distinct one.
pub fn observation_request_identity(
    envelope: &HostRequestEnvelope,
    capture: &CapturedObservation,
    observed_unix_ms: i64,
) -> Result<eliot_protocol::RequestIdentity, String> {
    let operation_text = format!(
        "{}:mcp-observe:{}",
        crate::SERVICE_NAME,
        capture.operation_id
    );
    let invalid = |field: &'static str| {
        format!("observe capture identity is not a valid contract value: {field}")
    };
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(operation_text.clone())
            .map_err(|_| invalid("observe_capture.request_id"))?,
        // The authenticated session the Kernel minted this attempt under. An
        // unbound session stays `None` rather than being invented; the
        // capture's own `session_id` still carries the attempt's session for
        // the owner's record.
        session_id: envelope
            .identity
            .session_id
            .as_deref()
            .map(eliot_contracts::SessionId::new)
            .transpose()
            .map_err(|_| invalid("observe_capture.session_id"))?,
        task_id: envelope
            .identity
            .task_id
            .as_deref()
            .map(eliot_contracts::TaskId::new)
            .transpose()
            .map_err(|_| invalid("observe_capture.task_id"))?,
        product_id: eliot_contracts::ProductId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("observe_capture.product_id"))?,
        source_id: eliot_contracts::SourceId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("observe_capture.source_id"))?,
        state_fence: envelope.state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(observed_unix_ms),
            known_time_ms: Some(observed_unix_ms),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|_| invalid("observe_capture.request_metadata"))?;
    Ok(eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: envelope.state_fence.clone(),
        },
        idempotency_key: format!("{}:{}", operation_text, capture.payload_digest),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        cancellation_id: envelope.identity.cancellation_id.clone(),
    })
}

/// Builds the base owner operation identity for one served capture.
pub fn observation_base_operation(
    envelope: &HostRequestEnvelope,
) -> Result<eliot_contracts::OperationId, String> {
    eliot_contracts::OperationId::new(format!("{}:mcp-observe", envelope.connection_id))
        .map_err(|error| format!("observe base operation is not a valid contract value: {error}"))
}

/// Projects one owner receipt into the serve outcome, keeping a non-committed
/// terminal status distinguishable from a committed capture.
pub fn observe_serve_outcome(
    receipt: &eliot_store_api::WriteReceipt,
) -> Result<ObserveServeOutcome, String> {
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed {
        return Ok(ObserveServeOutcome::Refused {
            operation_id: receipt.operation_id.as_str().to_owned(),
            status: format!("{:?}", receipt.status),
        });
    }
    let canonical_request_hash = receipt.canonical_request_hash.clone();
    Ok(ObserveServeOutcome::Committed {
        operation_id: receipt.operation_id.as_str().to_owned(),
        canonical_request_hash,
    })
}

/// Builds the result body the observe submit leg carries, bound to the exact
/// admitted attempt and to the owner's actual receipt (issue #2565 W5).
///
/// The lineage class is [`HostRequestResultClass::CanonicalWriteReceipt`] and
/// `semantic_receipt_ref` is the Store's own operation identity for the
/// committed observation, so the Kernel's receipt-comparison gate
/// (`same_observe_owner_receipt`) can tell this retained outcome from a
/// receiptless or foreign presentation. The output digest is the digest of the
/// exact response bytes, as the contract requires. A refused or unknown
/// outcome carries its own class and never claims a semantic receipt.
pub fn observation_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &ObserveServeOutcome,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let response = match outcome {
        ObserveServeOutcome::Committed {
            operation_id,
            canonical_request_hash,
        } => serde_json::json!({
            "status": "observation_candidate_committed",
            "record_kind": "observation_candidate",
            "suboperation": "observation",
            "capability": OBSERVE_CAPABILITY,
            "observation_operation_id": operation_id,
            "canonical_request_hash": canonical_request_hash,
        }),
        ObserveServeOutcome::Refused {
            operation_id,
            status,
        } => serde_json::json!({
            "status": "observation_not_committed",
            "record_kind": "observation_candidate",
            "suboperation": "observation",
            "capability": OBSERVE_CAPABILITY,
            "observation_operation_id": operation_id,
            "owner_status": status,
        }),
        ObserveServeOutcome::OutcomeUnknown { operation_id } => serde_json::json!({
            "status": "observation_outcome_unknown",
            "record_kind": "observation_candidate",
            "suboperation": "observation",
            "capability": OBSERVE_CAPABILITY,
            "observation_operation_id": operation_id,
            "reconciliation_reference": operation_id,
        }),
    };
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| format!("observe result response is not canonicalizable: {error}"))?;
    let result_digest = sha256_hex(&bytes);
    let (result_class, semantic_receipt_ref) = match outcome {
        ObserveServeOutcome::Committed { operation_id, .. } => (
            eliot_protocol::HostRequestResultClass::CanonicalWriteReceipt,
            Some(operation_id.clone()),
        ),
        // A refusal and an unknown outcome are honestly unclassified semantic
        // records: neither is a canonical write, so neither may carry a
        // semantic receipt reference.
        ObserveServeOutcome::Refused { .. } | ObserveServeOutcome::OutcomeUnknown { .. } => {
            (eliot_protocol::HostRequestResultClass::Unclassified, None)
        }
    };
    let body = eliot_protocol::HostRequestResultBody {
        wire_id: eliot_protocol::HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: result_digest.clone(),
        response,
        attempt: Some(attempt.clone()),
        lineage: Some(eliot_protocol::HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: result_digest,
            producer_ref: Some(crate::SERVICE_NAME.to_owned()),
            source_revisions: None,
            source_state_fence: Some(envelope.state_fence.clone()),
            input_refs: Some(vec![envelope.identity.payload_sha256.clone()]),
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: None,
            semantic_receipt_ref,
            result_class,
            proof_ceiling: None,
            influence_state: eliot_security_contracts::InfluenceState::Unknown,
            instruction_taint: None,
        }),
        evidence: None,
    };
    body.validate()
        .map_err(|error| format!("observe result body is not a valid submission: {error}"))?;
    Ok(body)
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
