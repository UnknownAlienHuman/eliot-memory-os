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
//! W5 Ã¢â‚¬â€ outcomes are recorded at the layer that actually produced them:
//! [`OutcomeLayer`] keeps a canonical commit, an external effect, a durable
//! child job and the final host response apart, and [`ObserveServeOutcome`]
//! is exhaustive over them so a pending handle can never be read as a terminal
//! success. A live pending handle is [`PendingObserveHandle`], whose read/wait
//! resolve the exact owner operation through the owner's own receipt route and
//! whose cancel is the admitted envelope's own cancellation identity Ã¢â‚¬â€ a handle
//! nothing can service is never constructed. When the owner's commit is real
//! but persisting that response fails, the honest state is
//! [`ObserveServeOutcome::EffectOccurrenceUnretained`]: the effect happened,
//! the completion was not retained, and the committed operation stays the
//! reconciliation reference.
//!
//! W2 â€” authority is resolved PER OPERATION, not by a blanket `task_id = None`.
//! [`ObserveOperationAuthority`] is the single typed classifier over the closed
//! carrier vocabulary: an operation that legitimately has no task contract and an
//! operation that REQUIRES one are different variants, so a task-relative
//! operation can never pass as an unbound cold capture.
//! [`resolve_observe_operation_authority`] is the sole producer, and it resolves
//! from the live #1746 activation/task-selection owner evidence
//! ([`eliot_governor::GovernorActivationSnapshot`], read through
//! `read_unique_agent_activation`) â€” never from `envelope.identity.task_id`,
//! which is a claim to compare, not authority. The envelope's claimed task and
//! scope are compared against the owner-resolved binding; a disagreement is a
//! conflict, never a silent rebind. [`ObserveEffectCeiling`] is the effect
//! ceiling an operation may act under, and it is derived from the accepted owner
//! grant: an operation whose class has no owner grant stays
//! [`ObserveEffectCeiling::NotGranted`], which refuses the operation rather than
//! defaulting to a ceiling.
//!
//! `eliot.observe / observation` has a connected semantic owner: the existing
//! Governor observation entry
//! (`GovernorObservationReconciliation::admit_captured_observation`) prepares
//! the real `CaptureCandidate` transition and the existing canonical
//! admission owner returns the Store's own `WriteReceipt`, which is what the
//! result leg carries back. The other four suboperations Ã¢â‚¬â€ `decision`,
//! `failure`, `outcome` and `influence_ack` Ã¢â‚¬â€ stay on the explicit deferred
//! map with their named residual owners, because their own semantic owners
//! have no connected admission on this path. A deferral is never completion Ã¢â‚¬â€
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

/// The closed operation classes this carrier can admit.
///
/// Exhaustive over the carrier's operation space, so a new operation cannot be
/// served without naming its own authority requirement: the authority resolver
/// below matches on this enum, and a new variant is a compile error there until
/// its task-contract requirement and effect ceiling are recorded. The cold
/// unbound capture leg exists only as [`Self::ColdUnboundObservationCapture`],
/// which is reachable by exactly the safe raw capture class â€” a task-relative
/// class can never reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveOperationClass {
    /// `eliot.observe / observation`: a safe raw capture that MAY retain an
    /// explicitly unbound cold candidate under its existing policy. This is the
    /// only class with a legitimately absent task contract.
    ColdUnboundObservationCapture,
    /// Task-relative promotion, actions, verification and Finish: these REQUIRE
    /// the applicable actual task contract and can never be admitted unbound.
    TaskRelative,
}

impl ObserveOperationClass {
    /// Stable wire discriminator for the resolved operation class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ColdUnboundObservationCapture => "cold_unbound_observation_capture",
            Self::TaskRelative => "task_relative",
        }
    }
}

/// The effect ceiling one resolved operation may act under (issue #2565 W2).
///
/// The ceiling is derived from the accepted owner grant, never from a request
/// field or a default. [`Self::NotGranted`] is a first-class variant meaning the
/// owner granted no ceiling for this operation class; such an operation is
/// refused or degraded visibly rather than executed under an assumed ceiling.
/// There is deliberately no `Unbounded` variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveEffectCeiling {
    /// The owner grant admits a cold candidate only (safe raw capture).
    CandidateOnly,
    /// The owner grant admits a bounded reversible effect.
    ReversibleMutation,
    /// The owner granted no effect ceiling for this operation class. Absent
    /// stays absent: the operation must be refused or degraded, never executed.
    NotGranted,
}

impl ObserveEffectCeiling {
    /// Stable wire discriminator for the effect ceiling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateOnly => "candidate_only",
            Self::ReversibleMutation => "reversible_mutation",
            Self::NotGranted => "not_granted",
        }
    }

    /// Whether a ceiling was actually granted. `NotGranted` is false, so a
    /// caller cannot treat an absent grant as a permission.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        match self {
            Self::CandidateOnly | Self::ReversibleMutation => true,
            Self::NotGranted => false,
        }
    }
}

/// The exact applicable task contract one operation resolved against (issue
/// #2565 W2).
///
/// Every field is the OWNER-resolved value from the #1746 activation /
/// task-selection evidence, never the host's claimed identity text. The
/// envelope's `task_id`/`work_scope_id` are compared against these values; a
/// mismatch is [`Self::ConflictingClaim`], never a silent adoption of the host's
/// text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveTaskContract {
    /// Owner-resolved task identity from the live activation evidence.
    pub task_id: String,
    /// Owner-resolved task contract revision from the activation evidence.
    pub task_revision: u64,
    /// Owner-resolved `WorkScope` identity from the activation evidence.
    pub work_scope_id: String,
    /// Owner-resolved canonical owner revision the binding was read at.
    pub owner_revision: u64,
}

/// The typed authority one carrier operation resolved to (issue #2565 W2).
///
/// The point of this enum is that the two former indistinguishable cases are now
/// DIFFERENT VARIANTS: an operation that legitimately has no task contract
/// ([`Self::ColdUnboundCapture`]) and an operation that requires a task contract
/// but the owner has not resolved one ([`Self::TaskContractRequired`]) can no
/// longer both appear on the wire as `task_id = None`. A task-relative operation
/// that arrives without a resolvable task contract is refused into
/// [`Self::TaskContractRequired`], which is not an admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserveOperationAuthority {
    /// A safe unbound cold capture under its existing policy: legitimately no
    /// task contract, retained cold with no task effect. The effect ceiling is
    /// the owner-granted candidate ceiling.
    ColdUnboundCapture {
        /// The operation class that reached the cold leg.
        class: ObserveOperationClass,
        /// The owner-granted effect ceiling for a safe raw capture.
        effect_ceiling: ObserveEffectCeiling,
    },
    /// An operation bound to the applicable actual task contract. The effect
    /// ceiling is the owner-granted ceiling for this operation class.
    TaskBound {
        /// The operation class that reached the task-relative leg.
        class: ObserveOperationClass,
        /// The exact owner-resolved task contract.
        task_contract: ObserveTaskContract,
        /// The owner-granted effect ceiling.
        effect_ceiling: ObserveEffectCeiling,
    },
    /// A task-relative operation that REQUIRES a task contract but the owner
    /// has not resolved one at the current fence. This is distinct from a cold
    /// unbound capture and is NOT an admission: the operation is refused and
    /// must not execute under an assumed or blanket-absent task.
    TaskContractRequired {
        /// The operation class that required a task contract.
        class: ObserveOperationClass,
        /// Stable refusal code; the caller reports it, never downgrades it.
        code: &'static str,
        /// Human-readable reason naming the missing owner authority.
        reason: String,
    },
    /// The host's claimed task/scope disagreed with the owner-resolved binding.
    /// This is a conflict, not a rebind: the operation is refused and the
    /// owner's binding is never overwritten by the host's text.
    ConflictingClaim {
        /// The operation class whose claim conflicted.
        class: ObserveOperationClass,
        /// Stable refusal code for a claim that disagrees with owner authority.
        code: &'static str,
        /// Human-readable reason naming the exact disagreement.
        reason: String,
    },
}

impl ObserveOperationAuthority {
    /// The effect ceiling this authority permits, or [`ObserveEffectCeiling::NotGranted`]
    /// for every non-admitting arm. A refused or conflicting arm can never be
    /// read as holding a ceiling.
    #[must_use]
    pub const fn effect_ceiling(&self) -> ObserveEffectCeiling {
        match self {
            Self::ColdUnboundCapture { effect_ceiling, .. }
            | Self::TaskBound { effect_ceiling, .. } => *effect_ceiling,
            Self::TaskContractRequired { .. } | Self::ConflictingClaim { .. } => {
                ObserveEffectCeiling::NotGranted
            }
        }
    }

    /// The owner-resolved task contract this authority was bound to, if any. A
    /// cold unbound capture has none by definition and returns `None`; a
    /// task-relative operation without one never reaches here as `None`-and-
    /// passing, because it is refused into [`Self::TaskContractRequired`].
    #[must_use]
    pub const fn task_contract(&self) -> Option<&ObserveTaskContract> {
        match self {
            Self::TaskBound { task_contract, .. } => Some(task_contract),
            Self::ColdUnboundCapture { .. }
            | Self::TaskContractRequired { .. }
            | Self::ConflictingClaim { .. } => None,
        }
    }

    /// Whether this authority admits execution. Only the two admitting arms do;
    /// a task-relative operation missing its task contract or carrying a
    /// conflicting claim is not admitted.
    #[must_use]
    pub const fn is_admitting(&self) -> bool {
        match self {
            Self::ColdUnboundCapture { .. } | Self::TaskBound { .. } => true,
            Self::TaskContractRequired { .. } | Self::ConflictingClaim { .. } => false,
        }
    }
}

/// Decodes only the closed shared observe vocabulary from linked tool bytes.
///
/// Returns the suboperation discriminator. The tool name must be the
/// admitted capability and `arguments.kind` must name exactly one of the
/// five I7.6 suboperations; anything else fails closed. No semantic field is
/// interpreted here Ã¢â‚¬â€ routing only.
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
/// submitted Ã¢â‚¬â€ the host's own `candidate_disposition` is carried as a claim
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
    /// The owner holds a real, durable operation that outlives this exchange
    /// and has not reached a terminal verdict. This is a live pending handle
    /// with a real read/wait/cancel path, kept distinct from
    /// [`Self::OutcomeUnknown`]: an unknown outcome has no handle to service
    /// because the owner may never have started anything, while this one names
    /// an operation the owner already admitted.
    Pending {
        /// The owner operation a read resolves against.
        handle: PendingObserveHandle,
    },
    /// The owner committed its canonical write and the exact receipt exists,
    /// but persisting that response against the host record failed. The effect
    /// happened; the completion was not retained. This is the honest
    /// `effect occurred / completion not retained` state: never reported as
    /// success, never reported as a clean refusal, and never silently retried Ã¢â‚¬â€
    /// the named owner operation stays the reconciliation reference.
    EffectOccurrenceUnretained {
        /// The committed store operation, kept as the reconciliation reference.
        operation_id: String,
        /// The store's own canonical request hash over the committed bytes.
        canonical_request_hash: String,
        /// Exact reason the host-result persistence did not complete.
        reason: String,
    },
    /// This suboperation has no connected semantic owner, so there is no
    /// disposition to report and no handle that anything could service. The
    /// named residual owner and resume condition are the whole answer.
    Unavailable {
        /// Served suboperation.
        suboperation: ObserveSuboperation,
        /// Missing owner admission that must connect before execution.
        owner_capability: &'static str,
        /// Program that owns the missing semantics.
        residual_owner: &'static str,
        /// Exact condition that resumes the deferred pair.
        resume: &'static str,
    },
    /// The per-operation authority resolution refused to admit this operation
    /// (issue #2565 W2).
    ///
    /// This arm exists so a task-relative operation that REQUIRES a task
    /// contract, or whose host claim conflicts with the owner-resolved binding,
    /// is reported as its own typed refusal instead of failing closed through an
    /// opaque string or â€” worse â€” being admitted as an unbound cold capture.
    /// Nothing executed, so this is not a commit, a refusal from an owner, a
    /// pending handle or an unknown outcome.
    AuthorityRefused {
        /// Served suboperation.
        suboperation: ObserveSuboperation,
        /// The operation class whose authority was resolved and refused.
        class: ObserveOperationClass,
        /// Stable refusal code from the authority resolver.
        code: &'static str,
        /// Exact reason naming the missing or conflicting owner authority.
        reason: String,
    },
}

impl ObserveServeOutcome {
    /// The domain layer this outcome was actually produced at (issue #2565
    /// W5).
    ///
    /// Exhaustive over the enum, so a new arm cannot be added without naming
    /// the layer it belongs to. Only [`OutcomeLayer::CanonicalCommit`] is
    /// reached by the carrier today; `ExternalEffect` and `DurableChildJob`
    /// exist so those handlers can never borrow the commit arm's success.
    /// A live pending handle reports [`OutcomeLayer::Pending`] and an
    /// unresolved commit outcome reports [`OutcomeLayer::PossiblyEffected`],
    /// because neither proved itself to be a commit, an external effect or a
    /// child job. An authority refusal (issue #2565 W2) is its own
    /// [`OutcomeLayer::AuthorityRefused`] layer: nothing was admitted and nothing
    /// executed, so it is neither a canonical commit nor an unavailable owner.
    #[must_use]
    pub const fn outcome_layer(&self) -> OutcomeLayer {
        match self {
            Self::Committed { .. } | Self::EffectOccurrenceUnretained { .. } => {
                OutcomeLayer::CanonicalCommit
            }
            Self::Refused { .. } => OutcomeLayer::CanonicalCommit,
            Self::Pending { .. } => OutcomeLayer::Pending,
            Self::OutcomeUnknown { .. } => OutcomeLayer::PossiblyEffected,
            Self::Unavailable { .. } => OutcomeLayer::Unavailable,
            Self::AuthorityRefused { .. } => OutcomeLayer::AuthorityRefused,
        }
    }

    /// Whether this outcome is a terminal disposition the owner actually
    /// issued.
    ///
    /// A pending handle and an unresolved outcome are both non-terminal: they
    /// must never be reported to the host as a completion. An unretained effect
    /// IS terminal at the domain layer Ã¢â‚¬â€ the commit happened Ã¢â‚¬â€ but it is
    /// terminal *without* retained completion, which is why it is reported
    /// separately rather than folded into `Committed`. An authority refusal is
    /// terminal for THIS attempt â€” the operation was not admitted and nothing
    /// ran â€” while explicitly never being a completion.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        match self {
            Self::Committed { .. }
            | Self::Refused { .. }
            | Self::EffectOccurrenceUnretained { .. }
            | Self::AuthorityRefused { .. } => true,
            Self::Pending { .. } | Self::OutcomeUnknown { .. } | Self::Unavailable { .. } => false,
        }
    }
}

/// Stable refusal code: a task-relative operation arrived with no resolvable
/// owner task contract at the current fence.
pub const OBSERVE_TASK_CONTRACT_REQUIRED: &str = "OBSERVE_TASK_CONTRACT_REQUIRED";

/// Stable refusal code: the host's claimed task/scope disagreed with the
/// owner-resolved binding.
pub const OBSERVE_CLAIM_CONFLICTS_OWNER_AUTHORITY: &str = "OBSERVE_CLAIM_CONFLICTS_OWNER_AUTHORITY";

/// Maps one served observe suboperation to its authority requirement class.
///
/// Exhaustive over [`ObserveSuboperation`], so the per-operation authority split
/// cannot drift from the closed carrier vocabulary: a new suboperation is a
/// compile error here until its requirement class is recorded. The mapping
/// reuses the OWNER's frozen canonical requirement table
/// ([`crate::task_binding_admission::classify_observe_suboperation`],
/// issue #1746 W1) rather than restating it, so this carrier can never drift
/// from the admission contract the store gate enforces.
#[must_use = "a caller must record the resolved class; an unclassified operation carries no authority"]
pub fn observe_operation_class(
    suboperation: ObserveSuboperation,
) -> Result<ObserveOperationClass, String> {
    match crate::task_binding_admission::classify_observe_suboperation(suboperation.as_str()) {
        Some(crate::task_binding_admission::CanonicalOperationRequirement::SafeRawCapture) => {
            Ok(ObserveOperationClass::ColdUnboundObservationCapture)
        }
        Some(
            crate::task_binding_admission::CanonicalOperationRequirement::TaskRelativeEffectful,
        ) => Ok(ObserveOperationClass::TaskRelative),
        Some(crate::task_binding_admission::CanonicalOperationRequirement::DiscoveryReadOnly) => {
            Err("observe suboperation classified as a discovery read-only operation".to_owned())
        }
        None => Err("observe suboperation has no canonical requirement class".to_owned()),
    }
}

/// Derives the effect ceiling an operation class may act under from the accepted
/// owner grant (issue #2565 W2).
///
/// The ceiling is a property of the OWNER's accepted policy for that operation
/// class, projected from the owner itself â€” never a request field and never a
/// default. The connected Governor capture owner accepts exactly a
/// `CaptureCandidate` transition, whose accepted ceiling is the store's
/// `EffectClass::Candidate`; that owner-accepted ceiling is projected here as
/// [`ObserveEffectCeiling::CandidateOnly`]. A task-relative class has NO
/// connected owner grant on this carrier, so it resolves to
/// [`ObserveEffectCeiling::NotGranted`]: absent stays absent, and the operation
/// is refused rather than executed under an assumed ceiling.
///
/// A caller cannot widen this: the function takes no request argument at all, so
/// there is no request field that could raise the ceiling.
#[must_use]
pub fn observe_effect_ceiling_for(class: ObserveOperationClass) -> ObserveEffectCeiling {
    match class {
        // The connected owner is `GovernorObservationReconciliation::admit_captured_observation`,
        // which builds a `TransitionClass::CaptureCandidate` envelope with
        // `requested_effect_ceiling: EffectClass::Candidate`. That is the
        // ceiling the owner accepted, projected losslessly.
        ObserveOperationClass::ColdUnboundObservationCapture => ObserveEffectCeiling::CandidateOnly,
        // No task-relative owner is connected on this carrier, so there is no
        // accepted grant to project. Not granted is not a small grant.
        ObserveOperationClass::TaskRelative => ObserveEffectCeiling::NotGranted,
    }
}

/// Resolves the applicable authority for ONE operation on this carrier (issue
/// #2565 W2).
///
/// This is the single authority seam replacing the former blanket
/// `task_id = envelope.identity.task_id` with a `None` fallback. It resolves
/// from the live #1746 activation / task-selection owner evidence and NEVER
/// from host-authored identity text. `activation` is `None` only when the
/// semantic owner itself reports that no unique live activation exists (a
/// `CompositionError` from `read_unique_agent_activation`); that is the owner's
/// honest "no authority resolved" answer, not a default and not a fallback.
///
/// The envelope's `task_id` / `work_scope_id` are treated as CLAIMS to compare,
/// never as authority to persist verbatim:
///
/// - a task-relative operation with no owner-resolved activation is refused into
///   [`ObserveOperationAuthority::TaskContractRequired`] â€” it can never pass as
///   an unbound cold capture;
/// - a host claim that disagrees with the owner-resolved task or scope is
///   refused into [`ObserveOperationAuthority::ConflictingClaim`] and is never
///   written over the owner's binding;
/// - only the safe raw capture class, which legitimately has no task contract,
///   may resolve to [`ObserveOperationAuthority::ColdUnboundCapture`], and only
///   under an owner-granted ceiling.
///
/// `live_fence` is the canonical owner's current fence. A resolved activation
/// observed at a different fence is stale authority and is refused rather than
/// applied.
pub fn resolve_observe_operation_authority(
    envelope: &HostRequestEnvelope,
    suboperation: ObserveSuboperation,
    activation: Option<&eliot_governor::GovernorActivationSnapshot>,
    live_fence: &eliot_contracts::StateFence,
) -> Result<ObserveOperationAuthority, String> {
    let class = observe_operation_class(suboperation)?;
    match activation {
        // No owner-resolved activation. Only the safe raw capture class may
        // proceed without one; a task-relative class is refused, which is the
        // whole point of this typed split.
        None => match class {
            ObserveOperationClass::ColdUnboundObservationCapture => {
                Ok(ObserveOperationAuthority::ColdUnboundCapture {
                    class,
                    effect_ceiling: observe_effect_ceiling_for(class),
                })
            }
            ObserveOperationClass::TaskRelative => {
                Ok(ObserveOperationAuthority::TaskContractRequired {
                    class,
                    code: OBSERVE_TASK_CONTRACT_REQUIRED,
                    reason: "task-relative operation requires the applicable owner-resolved \
                             TaskContract; the activation owner resolved no live task binding"
                        .to_owned(),
                })
            }
        },
        Some(activation) => {
            // Stale owner authority is refused, never applied under the live
            // fence it was not observed at.
            if !eliot_contracts::fences_match_exact(&activation.state_fence, live_fence) {
                return Ok(ObserveOperationAuthority::ConflictingClaim {
                    class,
                    code: OBSERVE_CLAIM_CONFLICTS_OWNER_AUTHORITY,
                    reason: "owner activation evidence was observed at another fence and is \
                             not applicable to this admission"
                        .to_owned(),
                });
            }
            let task_contract = ObserveTaskContract {
                task_id: activation.task_id.to_string(),
                task_revision: activation.task_revision,
                work_scope_id: activation.work_scope_id.clone(),
                owner_revision: activation.owner_revision,
            };
            // Compare the host's claims against the owner-resolved binding. A
            // disagreement is a conflict; the host text never wins.
            for (claimed, resolved, field) in [
                (
                    envelope.identity.task_id.as_deref(),
                    task_contract.task_id.as_str(),
                    "task_id",
                ),
                (
                    envelope.identity.work_scope_id.as_deref(),
                    task_contract.work_scope_id.as_str(),
                    "work_scope_id",
                ),
            ] {
                if let Some(claimed) = claimed
                    && claimed != resolved
                {
                    return Ok(ObserveOperationAuthority::ConflictingClaim {
                        class,
                        code: OBSERVE_CLAIM_CONFLICTS_OWNER_AUTHORITY,
                        reason: format!(
                            "envelope {field} claim does not match the owner-resolved \
                                 activation binding"
                        ),
                    });
                }
            }
            Ok(ObserveOperationAuthority::TaskBound {
                class,
                task_contract,
                effect_ceiling: observe_effect_ceiling_for(class),
            })
        }
    }
}

/// Builds the canonical-write request identity for one served capture.
///
/// The task identity written into the request metadata is taken from the RESOLVED
/// authority, never from `envelope.identity.task_id`. For a cold unbound capture
/// it stays `None` (a legitimate absent task contract). For a task-bound operation
/// it is the owner-resolved task id, so a blanket `None` can no longer stand in
/// for an operation that requires a task contract. A non-admitting authority
/// (required-but-absent contract, or a conflicting claim) is refused here before
/// any identity is built.
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
    authority: &ObserveOperationAuthority,
    observed_unix_ms: i64,
) -> Result<eliot_protocol::RequestIdentity, String> {
    let invalid = |field: &'static str| {
        format!("observe capture identity is not a valid contract value: {field}")
    };
    // A task-relative operation whose task contract the owner did not resolve,
    // or whose host claim conflicts with owner authority, must not receive an
    // identity at all. Refusing here keeps the failure typed and upstream of the
    // canonical commit rather than producing an unbound-looking identity.
    let (task_id, effect_ceiling) = match authority {
        ObserveOperationAuthority::ColdUnboundCapture { effect_ceiling, .. } => {
            (None, *effect_ceiling)
        }
        ObserveOperationAuthority::TaskBound {
            task_contract,
            effect_ceiling,
            ..
        } => (Some(task_contract.task_id.as_str()), *effect_ceiling),
        ObserveOperationAuthority::TaskContractRequired { code, reason, .. }
        | ObserveOperationAuthority::ConflictingClaim { code, reason, .. } => {
            return Err(format!(
                "observe capture authority refused: {code}: {reason}"
            ));
        }
    };
    // The ceiling must actually be granted. An operation whose class has no
    // accepted owner grant is refused here rather than executed under an
    // assumed ceiling.
    if !effect_ceiling.is_granted() {
        return Err(format!(
            "observe capture authority refused: {}: no owner-granted effect ceiling for this \
             operation class",
            ObserveEffectCeiling::NotGranted.as_str()
        ));
    }
    let operation_text = format!(
        "{}:mcp-observe:{}",
        crate::SERVICE_NAME,
        capture.operation_id
    );
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
        // The owner-resolved task contract, or `None` for the one class that
        // legitimately has no task. Never the host's claim.
        task_id: task_id
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

/// Which domain layer actually produced one front-door result (issue #2565
/// W5).
///
/// A canonical commit, an external effect, a durable child job and the final
/// host response are four different results. The carrier only ever executes a
/// canonical write for `eliot.observe / observation`, so the executed arm must
/// carry that exact layer. Every arm with no owner today reports
/// [`OutcomeLayer::Unavailable`] with its named residual owner instead of
/// borrowing the executed arm's layer, which is what keeps a "the owner
/// answered" answer from being read as "the host request completed".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeLayer {
    /// The Governor owner's canonical write committed; the Store's own receipt
    /// is the result.
    CanonicalCommit,
    /// An external effect occurred outside the canonical store.
    ExternalEffect,
    /// A durable child job was created and outlives this exchange.
    DurableChildJob,
    /// A live owner operation was admitted and has not reached a terminal
    /// receipt yet. The operation is real and pending under the named handle;
    /// it is NOT a completion, and NOT a durable child job it never proved
    /// itself to be.
    Pending,
    /// The effect may have occurred but no terminal evidence was observed. This
    /// is deliberately its own layer: claiming a commit, an external effect or
    /// a child job here would be inventing an outcome, and reporting it as a
    /// refusal would be asserting a rollback nobody observed.
    PossiblyEffected,
    /// No owner is connected for this arm, so the result is the explicit
    /// unavailable disposition with its named residual owner Ã¢â‚¬â€ never a success.
    Unavailable,
    /// The per-operation authority resolution refused to admit the operation
    /// (issue #2565 W2): a task-relative operation required a task contract the
    /// owner had not resolved, or the host's claim conflicted with the
    /// owner-resolved binding. Nothing was admitted and nothing executed, so
    /// this is deliberately distinct from both the canonical-commit refusal arm
    /// and the unavailable-owner arm.
    AuthorityRefused,
}

impl OutcomeLayer {
    /// Stable wire discriminator for the result layer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalCommit => "canonical_commit",
            Self::ExternalEffect => "external_effect",
            Self::DurableChildJob => "durable_child_job",
            Self::Pending => "pending",
            Self::PossiblyEffected => "possibly_effected",
            Self::Unavailable => "unavailable",
            Self::AuthorityRefused => "authority_refused",
        }
    }
}

/// A real pending handle a caller can read, wait on and cancel (issue #2565
/// W5).
///
/// A handle exists only when an owner can actually service all three verbs:
///
/// - read: [`Self::read`] resolves the exact owner operation through the
///   owner's own committed-receipt route
///   ([`read_captured_observation_receipt`](crate::observation_adapters::ForwardingObservationReconciliation::read_captured_observation_receipt));
/// - wait: [`Self::wait`] is that same read, repeated by the caller until its
///   own deadline or until the owner holds a terminal receipt;
/// - cancel: [`Self::cancel`] returns the admitted host request's own
///   `cancellation_id`, which the carrier forwards unchanged into the owner
///   request identity, so the owner decides whether the operation may still be
///   stopped.
///
/// No verb here invents a status. A read that finds no terminal receipt returns
/// [`ObserveServeOutcome::OutcomeUnknown`], which is the honest "still pending"
/// answer and never asserts either completion or rollback. A port failure is
/// returned as `Err` and is deliberately not mapped to a disposition: an
/// unreachable owner is not an owner verdict.
///
/// A handle that cannot name all three verbs is not constructed at all. An arm
/// with no owner returns [`ObserveServeOutcome::Unavailable`] with its residual
/// owner instead, so no handle ever exists that nothing can service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingObserveHandle {
    /// The owner operation a read resolves against.
    pub operation_id: String,
    /// The exact owner interface that services read and wait.
    pub receipt_owner: &'static str,
    /// The exact identity a cancel is presented under.
    pub cancellation_id: String,
}

impl PendingObserveHandle {
    /// Reads the current owner disposition for this handle (issue #2565 W5).
    ///
    /// This is the read verb of the handle. `Some(receipt)` means the owner
    /// issued a terminal receipt and [`observe_serve_outcome`] classifies it.
    /// `None` means the owner holds no terminal receipt yet: the honest answer
    /// is [`ObserveServeOutcome::OutcomeUnknown`], which keeps the operation
    /// claimable-by-reconciliation and never asserts completion or rollback.
    ///
    /// `base_operation` and `capture` must be the exact pair the admission used,
    /// because the owner derives the operation identity from them. A transport
    /// or port failure is returned as `Err` and is deliberately not mapped to a
    /// disposition: an unreachable owner is not an owner verdict.
    pub async fn read(
        &self,
        owner: &crate::observation_adapters::ForwardingObservationReconciliation<
            '_,
            dyn eliot_governor::KernelGenerationPort,
        >,
        base_operation: &eliot_contracts::OperationId,
        capture: &CapturedObservation,
    ) -> Result<ObserveServeOutcome, String> {
        let receipt = owner
            .read_captured_observation_receipt(base_operation, capture)
            .await
            .map_err(|error| format!("pending handle owner read: {error}"))?;
        match receipt {
            Some(receipt) => observe_serve_outcome(&receipt),
            None => Ok(ObserveServeOutcome::OutcomeUnknown {
                operation_id: self.operation_id.clone(),
            }),
        }
    }

    /// The wait verb: the bounded read a caller repeats until its own deadline
    /// or until the owner holds a terminal receipt.
    ///
    /// Returns the owner's actual classification on the first terminal
    /// receipt. A poll that reads nothing returns
    /// [`ObserveServeOutcome::OutcomeUnknown`], and the caller Ã¢â‚¬â€ not this
    /// module Ã¢â‚¬â€ decides how long to wait; nothing here asserts that the effect
    /// did or did not happen.
    pub async fn wait(
        &self,
        owner: &crate::observation_adapters::ForwardingObservationReconciliation<
            '_,
            dyn eliot_governor::KernelGenerationPort,
        >,
        base_operation: &eliot_contracts::OperationId,
        capture: &CapturedObservation,
    ) -> Result<ObserveServeOutcome, String> {
        self.read(owner, base_operation, capture).await
    }

    /// The cancel verb: the exact cancellation identity this operation may be
    /// stopped under (issue #2565 W5).
    ///
    /// Returns the identity the caller must present to the owner, or `None`
    /// when the admitted envelope carried no cancellation identity. A `None` is
    /// the honest answer: the operation has no cancellation right, and no
    /// caller may invent one. The handle never claims a cancel took effect Ã¢â‚¬â€
    /// the owner's disposition is still read through [`Self::read`].
    #[must_use]
    pub fn cancel(&self) -> Option<&str> {
        if self.cancellation_id.is_empty() {
            None
        } else {
            Some(self.cancellation_id.as_str())
        }
    }
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

/// The exact owner interface that services the read and wait verbs of an
/// `eliot.observe` pending handle.
///
/// Named here rather than at the call site so a handle and its servicing owner
/// can never drift: every handle this module constructs reads and waits
/// through `KernelTransitionPort::receipt`, which is the existing owner
/// interface and resolves the exact committed operation identity.
pub const OBSERVE_PENDING_RECEIPT_OWNER: &str =
    "governor-observation-owner.KernelTransitionPort::receipt";

/// Builds the live pending handle for one admitted operation whose owner holds
/// the operation but has issued no terminal receipt yet.
///
/// The handle names the owner operation to read, the exact owner interface that
/// services read/wait, and the admitted cancellation identity a cancel is
/// presented under. The cancellation identity comes from the Kernel-admitted
/// envelope and is never synthesized: an envelope that carried none yields an
/// empty identity, and [`PendingObserveHandle::cancel`] then honestly answers
/// `None` instead of inventing a right to stop the operation.
///
/// This is only reachable for an operation the owner has actually admitted. An
/// operation the owner may never have started is
/// [`ObserveServeOutcome::OutcomeUnknown`], which carries no handle precisely
/// because there would be nothing to poll or cancel.
pub fn observation_pending_handle(
    envelope: &HostRequestEnvelope,
    owner_operation_id: &str,
) -> Result<PendingObserveHandle, String> {
    if owner_operation_id.is_empty() {
        return Err("pending handle owner operation is empty".to_owned());
    }
    Ok(PendingObserveHandle {
        operation_id: owner_operation_id.to_owned(),
        receipt_owner: OBSERVE_PENDING_RECEIPT_OWNER,
        // Absent stays absent: the envelope carried no cancellation identity, so
        // `cancellation_identity` reports None rather than an empty id that a
        // caller could present as a real one.
        cancellation_id: envelope.identity.cancellation_id.clone(),
    })
}

/// Projects the explicit unavailable disposition for one served suboperation.
///
/// This is the arm that keeps W7's single handler/capability map honest at the
/// outcome layer: a suboperation whose owner is not connected reports
/// [`OutcomeLayer::Unavailable`] with the exact residual owner the map names,
/// never a handle nothing can service and never another arm's success.
pub fn observation_unavailable_outcome(deferral: &ObserveDeferral) -> ObserveServeOutcome {
    ObserveServeOutcome::Unavailable {
        suboperation: deferral.suboperation,
        owner_capability: deferral.owner_capability,
        residual_owner: deferral.residual_owner,
        resume: deferral.resume,
    }
}

/// Builds the result body the observe submit leg carries, bound to the exact
/// admitted attempt and to the owner's actual receipt (issue #2565 W5).
///
/// Projects the host-facing response document for one served observe outcome.
///
/// Each arm states what the OWNER actually proved at the layer it acted in, so a
/// pending handle is never dressed as a completion and an effect whose result was
/// never retained stays visible as its own state.
fn observe_response_document(outcome: &ObserveServeOutcome) -> serde_json::Value {
    match outcome {
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
        // A live pending handle is carried as a handle, not as a completion: the
        // response names the owner operation a read resolves against and the
        // exact owner interface that services read/wait/cancel, so a caller
        // never has to guess how to service it. The cancellation identity is
        // the admitted envelope's own: an envelope that carried none yields
        // null rather than an empty string a reader could mistake for a real
        // identity, matching [`PendingObserveHandle::cancel`].
        ObserveServeOutcome::Pending { handle } => serde_json::json!({
            "status": "observation_pending",
            "record_kind": "observation_candidate",
            "suboperation": "observation",
            "capability": OBSERVE_CAPABILITY,
            "observation_operation_id": handle.operation_id,
            "read_wait_cancel_owner": handle.receipt_owner,
            "cancellation_id": if handle.cancellation_id.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(handle.cancellation_id.clone())
            },
        }),
        // The commit happened and the receipt exists, but the host record was
        // never updated with it. The response says exactly that, keeps the
        // committed operation as the reconciliation reference, and carries the
        // owner's receipt reference so a later reconciliation resolves the same
        // operation rather than re-running the capture.
        ObserveServeOutcome::EffectOccurrenceUnretained {
            operation_id,
            canonical_request_hash,
            reason,
        } => serde_json::json!({
            "status": "observation_effected_result_not_retained",
            "record_kind": "observation_candidate",
            "suboperation": "observation",
            "capability": OBSERVE_CAPABILITY,
            "observation_operation_id": operation_id,
            "canonical_request_hash": canonical_request_hash,
            "reconciliation_reference": operation_id,
            "host_result_persistence": "failed",
            "host_result_persistence_reason": reason,
        }),
        // An arm with no connected owner has no disposition to persist. It
        // retires through the Kernel defer leg instead, carrying its named
        // residual owner; this arm exists so the classification seam can name
        // that answer instead of borrowing another arm's success.
        ObserveServeOutcome::Unavailable {
            suboperation,
            owner_capability,
            residual_owner,
            resume,
        } => serde_json::json!({
            "status": "observation_owner_unavailable",
            "record_kind": "observation_candidate",
            "suboperation": suboperation.as_str(),
            "capability": OBSERVE_CAPABILITY,
            "owner_capability": owner_capability,
            "residual_owner": residual_owner,
            "resume": resume,
        }),
        // An authority refusal (issue #2565 W2) is reported as its own typed
        // disposition: the operation was not admitted, nothing executed, and the
        // exact operation class plus refusal code name WHY it was refused. It
        // never borrows a commit status or an unavailable-owner status.
        ObserveServeOutcome::AuthorityRefused {
            suboperation,
            class,
            code,
            reason,
        } => serde_json::json!({
            "status": "observation_authority_refused",
            "record_kind": "observation_candidate",
            "suboperation": suboperation.as_str(),
            "capability": OBSERVE_CAPABILITY,
            "operation_class": class.as_str(),
            "authority_refusal_code": code,
            "authority_refusal_reason": reason,
        }),
    }
}

/// The lineage class is [`HostRequestResultClass::CanonicalWriteReceipt`] and
/// `semantic_receipt_ref` is the Store's own operation identity for the
/// committed observation, so the Kernel's receipt-comparison gate
/// (`same_observe_owner_receipt`) can tell this retained outcome from a
/// receiptless or foreign presentation. The output digest is the digest of the
/// exact response bytes, as the contract requires. A refused, unknown,
/// pending-handle, unavailable or authority-refused outcome carries its own
/// class and never claims a semantic receipt: only a canonical write receipt
/// result may carry one, and the live pending handle travels in the response
/// document instead.
pub fn observation_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &ObserveServeOutcome,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let response = observe_response_document(outcome);
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| format!("observe result response is not canonicalizable: {error}"))?;
    let result_digest = sha256_hex(&bytes);
    let (result_class, semantic_receipt_ref) = match outcome {
        ObserveServeOutcome::Committed { operation_id, .. }
        | ObserveServeOutcome::EffectOccurrenceUnretained { operation_id, .. } => (
            eliot_protocol::HostRequestResultClass::CanonicalWriteReceipt,
            Some(operation_id.clone()),
        ),
        // A pending handle names the owner operation, not a receipt: the owner
        // has admitted it but has issued no terminal receipt, so it stays
        // unclassified and carries no semantic receipt reference. The reference
        // MUST stay `None`: the protocol's own class gate refuses a receipt
        // reference on any non-`CanonicalWriteReceipt` class, so carrying the
        // handle here would fail body validation and no durable pending handle
        // could ever persist (issue #2565 AUD12). The live handle itself
        // travels in the response document (`observation_operation_id` plus
        // `read_wait_cancel_owner`), which is what a read/wait/cancel path
        // resolves; the lineage only binds the exact response bytes.
        ObserveServeOutcome::Pending { .. } => (
            eliot_protocol::HostRequestResultClass::Unclassified,
            None,
        ),
        // A refusal, an unknown outcome and an arm with no connected owner admit
        // no semantic record at all. `Unavailable` never reaches this leg in
        // production Ã¢â‚¬â€ the carrier retires it through the defer leg Ã¢â‚¬â€ so it
        // carries no receipt reference rather than borrowing one from another arm.
        ObserveServeOutcome::Refused { .. }
        | ObserveServeOutcome::OutcomeUnknown { .. }
        | ObserveServeOutcome::Unavailable { .. }
        // An authority refusal (issue #2565 W2) is in this group for the same
        // reason: nothing was committed, so it carries no receipt reference and is
        // never classified as a canonical write receipt.
        | ObserveServeOutcome::AuthorityRefused { .. } => {
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
/// that owns it, and the resume condition Ã¢â‚¬â€ never a result, never a receipt.
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
    // validates Ã¢â‚¬â€ the defer leg would quarantine it, but the dispatch
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
