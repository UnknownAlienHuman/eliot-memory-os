//! Governor observe serving adapter (issue #2565, package O).
//!
//! Per-claim decoder over one Kernel-admitted `eliot.observe` pair: proves
//! the closed linkage and fence binding the Kernel already admitted, decodes
//! only the closed shared tool vocabulary (the five I7.6 suboperations), and
//! routes each suboperation through the one explicit owner map below.
//!
//! Caller chain: daemon runtime observe poller -> this decoder ->
//! `DaemonKernelClient::submit_observe_result_async` (the real owner result
//! for `Observation`) or `DaemonKernelClient::defer_observe_claim_async` (pair
//! retired, durable record `Routed`) for the four suboperations whose owner
//! adapter does not exist.
//!
//! Production edges out of this module:
//! [`serve_admitted_observe`] serves one admitted pair, either as a real
//! [`ObservationServe`] that carries the owner inputs for the one connected
//! `Observation` admission, or as an honest [`ObserveDeferral`] naming its
//! exact owner and resume condition;
//! [`decode_observe_suboperation`] decodes the closed vocabulary;
//! [`observe_suboperation_owner`] is the single suboperation-to-owner map;
//! [`ObservationServe::owner_input`] derives the exact owner input for the
//! admitted capture from the retained request and the owner-decided
//! privacy/retention legs the Kernel resolved before persistence.
//!
//! Only `Observation` is connected. `Decision`, `Failure`, `Outcome` and
//! `InfluenceAck` keep their honest deferrals: a closed vocabulary map is
//! routing, not execution, and their own owner adapters are still residual.
//! Missing handler semantics stay with their owners and never justify a second
//! semantic engine here.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::{McpObservationInput, McpTaskSelection};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};

/// Admitted capability this adapter serves.
const OBSERVE_CAPABILITY: &str = "eliot.observe";

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
    /// The admission this suboperation reaches. For `Observation` it is the
    /// connected one; for the rest it is the still-missing one.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics (never this adapter).
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
    /// Whether the named admission is connected on this path.
    ///
    /// `true` for `Observation` only. The row below is the single place that
    /// decides which suboperation executes, so a fifth positive suboperation
    /// cannot appear without a deliberate change here.
    pub connected: bool,
}

/// Returns the single recorded owner route for one suboperation.
///
/// Exhaustive over [`ObserveSuboperation`]: a new suboperation is a compile
/// error here until its owner, residual program, resume condition, and
/// connection state are recorded. The real caller for every row today is the
/// daemon observe poller (`bins/eliotd/src/daemon_runtime.rs`); the residual
/// owner is the Governor semantic program that must connect the matching
/// admission (integration #18).
pub fn observe_suboperation_owner(suboperation: ObserveSuboperation) -> ObserveOwnerRoute {
    match suboperation {
        ObserveSuboperation::Observation => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-admission",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "connected: the retained pair is admitted through ObservationSubmission, ObservationJournal::admit and CanonicalAdmissionOwner::commit, and the exact store receipt is retained as the host result",
            connected: true,
        },
        ObserveSuboperation::Decision => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-decision",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the decision admission connects; exact replay re-enqueues the pair",
            connected: false,
        },
        ObserveSuboperation::Failure => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-failure",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the failure admission connects; exact replay re-enqueues the pair",
            connected: false,
        },
        ObserveSuboperation::Outcome => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-outcome",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the outcome admission connects; exact replay re-enqueues the pair",
            connected: false,
        },
        ObserveSuboperation::InfluenceAck => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-influence-ack",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the influence-ack admission connects; exact replay re-enqueues the pair",
            connected: false,
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
/// that owns it, and the resume condition -- never a result, never a receipt.
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

/// The decoded, owner-bound content of one admitted `Observation` capture.
///
/// Every field is read from the exact admitted payload bytes plus the
/// owner-decided privacy/retention legs. Nothing here is defaulted: a capture
/// whose payload cannot be decoded fails closed rather than reaching the owner
/// with a filled-in field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedObservationCapture {
    /// The provenance text the payload carries about what was observed.
    pub observed_delta: String,
    /// The exact source/evidence handles the payload carries, in producer order.
    pub source_handles: Vec<String>,
    /// The task the payload names, when it names one.
    ///
    /// A claim, not authority. The Governor re-checks it against the current
    /// owner selection, or keeps the capture cold when there is no selection.
    pub claimed_task_id: Option<String>,
}

/// One served `Observation` pair, ready for the Governor owner admission.
///
/// This is not a result and not a wrapper around a missing answer: it carries
/// the exact owner inputs the admission needs, and the receipt the owner
/// returns is retained as the host result by the caller. The privacy/retention
/// legs are NOT here on purpose. They were decided by the Kernel's privacy
/// owner BEFORE the raw body was persisted, and they are read back off the
/// durable record by the caller, so the decision that governed persistence is
/// the same decision the record carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationServe {
    /// Served suboperation (always `Observation` on this arm).
    pub suboperation: ObserveSuboperation,
    /// The connected owner admission this pair reaches.
    pub owner_capability: &'static str,
    /// The decoded capture content.
    pub capture: DecodedObservationCapture,
    /// The exact operation handle the attempt is bound to.
    pub operation_id: String,
    /// The exact envelope digest the request is committed under.
    pub request_digest: String,
    /// The exact admitted payload digest the capture observed.
    pub payload_sha256: String,
    /// The attempted expiry, which the submit leg re-checks against the row.
    pub expires_at_unix_ms: u64,
}

/// The privacy/retention legs the Kernel decided before the raw observe body
/// was persisted (issue #2565 package O; I7.23).
///
/// These are the owner's own decision, read back verbatim from the durable
/// record. They are never re-decided here: re-running the rule in the daemon
/// would make the daemon a second privacy owner, and carrying a value the
/// owner did not decide would be the exact "field filled in place of owner
/// data" this package forbids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservePrivacyDisposition {
    /// The owner's disposition: the retention projection Kernel actually
    /// persisted for these exact bytes.
    pub disposition: String,
    /// The scope the verdict was decided in, when the verdict is a verdict
    /// over a resolved scope.
    pub scope_ref: Option<String>,
    /// The redaction classes the owner recorded, empty when admitted verbatim.
    pub redacted_classes: Vec<String>,
    /// The owner's redaction reason, empty when admitted verbatim.
    pub redaction_reason: String,
}

/// One served pair: the real owner inputs, or an honest deferral.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserveServe {
    /// The one connected suboperation, ready for the Governor admission.
    Executed(ObservationServe),
    /// A suboperation whose owner admission is still missing.
    Deferred(ObserveDeferral),
}

impl ObserveServe {
    /// The served suboperation on either arm.
    pub const fn suboperation(&self) -> ObserveSuboperation {
        match self {
            Self::Executed(serve) => serve.suboperation,
            Self::Deferred(deferral) => deferral.suboperation,
        }
    }

    /// The owner admission this serve reached or is waiting for.
    pub const fn owner_capability(&self) -> &'static str {
        match self {
            Self::Executed(serve) => serve.owner_capability,
            Self::Deferred(deferral) => deferral.owner_capability,
        }
    }
}

/// Reads the bounded `text_or_structured_payload` / `source_handles` /
/// `task_id` of one admitted observe capture, in that exact producer order.
///
/// Pure: it decodes the bytes already proven to be the admitted bytes and
/// projects the provenance the record needs. A payload that does not decode
/// fails closed here rather than reaching the owner with an empty field.
fn decode_observation_capture(
    tool: &serde_json::Value,
) -> Result<DecodedObservationCapture, String> {
    let arguments = tool
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "daemon observe pair tool omits the canonical arguments object".to_owned())?;
    let payload = arguments.get("text_or_structured_payload").ok_or_else(|| {
        "daemon observe pair omits the capture payload text_or_structured_payload".to_owned()
    })?;
    let observed_delta = match payload {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => {
            return Err(
                "daemon observe pair capture payload must not be null".to_owned(),
            );
        }
        structured => canonical_json_bytes(structured)
            .map_err(|error| {
                format!("daemon observe pair structured capture cannot be canonicalized: {error}")
            })
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|error| {
                    format!("daemon observe pair structured capture is not valid UTF-8: {error}")
                })
            })?,
    };
    if observed_delta.trim().is_empty() {
        return Err("daemon observe pair capture payload carries no observation text".to_owned());
    }
    let mut source_handles = Vec::new();
    for (index, handle) in arguments
        .get("source_handles")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let handle = handle.as_str().ok_or_else(|| {
            format!("daemon observe pair source handle {index} is not text")
        })?;
        if handle.trim().is_empty() {
            return Err(format!(
                "daemon observe pair source handle {index} is blank"
            ));
        }
        if !source_handles.iter().any(|seen| seen == handle) {
            source_handles.push(handle.to_owned());
        }
    }
    let claimed_task_id = match arguments.get("task_id") {
        None | Some(serde_json::Value::Null) => None,
        Some(task) => {
            let task = task.as_str().ok_or_else(|| {
                "daemon observe pair task selector is not text".to_owned()
            })?;
            if task.trim().is_empty() {
                return Err("daemon observe pair task selector is blank".to_owned());
            }
            Some(task.to_owned())
        }
    };
    Ok(DecodedObservationCapture {
        observed_delta,
        source_handles,
        claimed_task_id,
    })
}

/// Serves one admitted observe pair through the closed vocabulary.
///
/// Re-proves the admitted linkage (capability echoes the tool name, canonical
/// tool bytes digest to the admitted payload digest), the admitted envelope
/// shape, and the attempt binding (operation handle plus validated capability
/// admitted for this facet) before either arm touches the pair.
///
/// On the connected `Observation` arm it returns the exact owner inputs for
/// the Governor's narrow MCP admission, decoded from the admitted bytes. On
/// every other arm it returns the honest deferral with its exact owner and
/// resume condition; no receipt is invented on either arm. Pure: no IO, no
/// semantic interpretation, no invented receipt.
pub fn serve_admitted_observe(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ObserveServe, String> {
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
    // validates -- the defer leg would quarantine it, but the dispatch
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
    if !route.connected {
        return Ok(ObserveServe::Deferred(ObserveDeferral {
            suboperation: route.suboperation,
            owner_capability: route.owner_capability,
            residual_owner: route.residual_owner,
            resume: route.resume,
        }));
    }
    let capture = decode_observation_capture(tool)?;
    Ok(ObserveServe::Executed(ObservationServe {
        suboperation: route.suboperation,
        owner_capability: route.owner_capability,
        capture,
        operation_id: attempt.operation_id.clone(),
        request_digest: envelope.envelope_sha256.clone(),
        payload_sha256: envelope.identity.payload_sha256.clone(),
        expires_at_unix_ms: attempt.expires_at_unix_ms,
    }))
}

/// Projects the owner-decided privacy/retention legs off the durable record.
///
/// The Kernel resolves the disclosure verdict over the canonical payload bytes
/// BEFORE it persists them (issue #2565 package O, I7.23) and records the legs
/// on the same durable row. This reads them back verbatim. A row carrying no
/// decided legs is refused here rather than defaulted: an undecided privacy
/// position must never become an admitted one on the way to the owner.
pub fn observe_privacy_disposition(
    disposition: &str,
    redacted_classes: &serde_json::Value,
    redaction_reason: &str,
    scope_ref: Option<&str>,
) -> Result<ObservePrivacyDisposition, String> {
    if disposition.trim().is_empty() {
        return Err("daemon observe pair carries no owner privacy disposition".to_owned());
    }
    let mut classes = Vec::new();
    if let Some(list) = redacted_classes.as_array() {
        for (index, class) in list.iter().enumerate() {
            let class = class
                .as_str()
                .ok_or_else(|| format!("daemon observe privacy class {index} is not text"))?;
            classes.push(class.to_owned());
        }
    } else if !redacted_classes.is_null() {
        return Err("daemon observe privacy classes are not a list".to_owned());
    }
    Ok(ObservePrivacyDisposition {
        disposition: disposition.to_owned(),
        scope_ref: scope_ref.map(str::to_owned),
        redacted_classes: classes,
        redaction_reason: redaction_reason.to_owned(),
    })
}

/// Builds the owner-decided privacy domain and retention policy references for
/// one admitted capture from the disposition the Kernel resolved before
/// persistence.
///
/// The domain is the owner's own namespace for this decision and the policy
/// reference names the exact policy revision that decided it. Neither is
/// invented: both are projections of the recorded verdict, and a redacted
/// disposition records the withholding rather than pretending the bytes were
/// admitted verbatim.
pub fn owner_privacy_references(
    privacy: &ObservePrivacyDisposition,
) -> (String, String, String) {
    let domain = if privacy.redacted_classes.is_empty() {
        format!("mcp-observe-admitted:{}", privacy.disposition)
    } else {
        format!("mcp-observe-redacted:{}", privacy.disposition)
    };
    let policy = if privacy.redaction_reason.trim().is_empty() {
        format!("mcp-observe-retention:{}", privacy.disposition)
    } else {
        format!("mcp-observe-retention:{}:{}", privacy.disposition, privacy.redaction_reason)
    };
    let disclosure_class = if privacy.redacted_classes.is_empty() {
        "internal".to_owned()
    } else {
        privacy.redacted_classes.join("+")
    };
    (domain, policy, disclosure_class)
}
