//! Screened exact-one-handler Curation fan-in (A-31).
//!
//! Pure typed router over an already A-05-validated curation batch, the exact
//! immutable A-19c screen binding, and an injected A-03 handler registry with
//! one live hub-native port per handler family. Every eligible dispatchable
//! item invokes exactly one semantic owner; the returned full result content
//! is sealed and preserved without fallback, retry, sibling calls, or
//! semantic recomputation, and the batch aggregates into a deterministic
//! lineage-preserving candidate set.
//!
//! Cell `smart.dreamer.curation`, order 31. Inputs are immutable and
//! caller-supplied; every identity, receipt, screen, registry, policy, budget,
//! deadline, and digest binding is explicit. The A-05 receipt and the A-19c
//! screen are checked intrinsically through their own validation entry points
//! and are never re-executed here. No screening, grounding, common
//! validation, production registry construction, canonical mutation,
//! authority, effect, Store, Governor, or Finish surface exists in this cell.
//!
//! Runtime boundary: a blocked, malformed, over-budget, past-deadline, or
//! cancelled-before-dispatch item invokes **zero** handlers. Exactly-once
//! applies to dispatched items, not to rejected inputs. Handler error,
//! partial results, and panics are terminal: no alternate handler is tried.
//! There is no wall-clock timeout in this pure cell and no clock is read; the
//! caller injects `observation_time_ms` for an explicit pre-dispatch deadline
//! comparison, and cancellation is an explicit caller flag.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::error::{check_fence, is_hex64_lower, sorted_set_eq};
use eliot_dreamer_contracts::job::{PRIVACY_GOVERNED_EXTERNAL, PRIVACY_LOCAL_ONLY};
use eliot_dreamer_contracts::{
    AtomicityMode, BoundCurationCall, BudgetLimits, BudgetUsage, CURATION_FAMILIES,
    CandidateDisposition, ContractViolation, CurationFamily, CurationHandlerPort,
    CurationHandlerRegistry, CurationKind, CurationRejectionCode, FullCurationResult,
    ProducedCurationContent, Requester, ScreenBinding, ScreenState, TargetDenominator,
    TypedCurationHandlerRequest, ValidatedCurationItem, ValidationReceipt, family_of, parse_family,
    request_digest_of,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum validated items admitted in one batch.
pub const MAX_BATCH_ITEMS: usize = 64;
/// Maximum bytes for any identity or digest-list handle field.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for task, scope, authority, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any free-text note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum predecessor digests admitted in one batch.
pub const MAX_PREDECESSORS: usize = 32;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Exact owner descriptors required: ten families, eleven wire kinds.
pub const EXPECTED_OWNER_DESCRIPTORS: usize = 10;

/// Routing-only proof ceiling carried by every emitted set.
pub const ROUTING_PROOF_NOTE: &str = "a-31 routing-only aggregation: handler envelopes preserved without screening, grounding, common validation, semantic recomputation, canonical mutation, authority, effect, or finish";

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn redact(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_REDACTED_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

fn contract_detail(err: &ContractViolation) -> String {
    redact(&err.to_string())
}

fn check_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), CurationRoutingError> {
    if value.trim().is_empty() {
        return Err(CurationRoutingError::Batch {
            field,
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(CurationRoutingError::Batch {
            field,
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(CurationRoutingError::Batch {
            field,
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

fn check_digest(value: &str, field: &'static str) -> Result<(), CurationRoutingError> {
    if !is_hex64_lower(value) {
        return Err(CurationRoutingError::Digest {
            detail: std::format!("{field} must be 64 lowercase hex sha256"),
        });
    }
    Ok(())
}

fn is_sorted_unique(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        if index > 0 {
            if let (Some(prev), Some(cur)) = (values.get(index - 1), values.get(index)) {
                if prev >= cur {
                    return false;
                }
            } else {
                return false;
            }
        }
        index = index.saturating_add(1);
    }
    true
}

/// Canonical owner package for one handler family.
///
/// The ten spellings are the contract-only routing table: each family is owned
/// by exactly one sibling cell. Merge and Split share the structure-repair
/// owner while remaining distinct wire kinds; Repair is owned by memory
/// repair. No `Other` family exists.
#[must_use]
pub const fn expected_owner_package(family: CurationFamily) -> &'static str {
    match family {
        CurationFamily::Classification => "eliot-dreamer-classification",
        CurationFamily::Relation => "eliot-dreamer-relation",
        CurationFamily::Episode => "eliot-dreamer-episode",
        CurationFamily::Concept => "eliot-dreamer-concept",
        CurationFamily::Procedure => "eliot-dreamer-procedure",
        CurationFamily::Failure => "eliot-dreamer-failure",
        CurationFamily::StructureRepair => "eliot-dreamer-structure-repair",
        CurationFamily::Reconsolidation => "eliot-dreamer-reconsolidation",
        CurationFamily::Accessibility => "eliot-dreamer-accessibility",
        CurationFamily::MemoryRepair => "eliot-dreamer-memory-repair",
    }
}

fn canonical_families() -> Result<Vec<CurationFamily>, CurationRoutingError> {
    let mut families = Vec::with_capacity(CURATION_FAMILIES.len());
    for spelling in CURATION_FAMILIES {
        let family = parse_family(spelling).map_err(|err| CurationRoutingError::Registry {
            detail: contract_detail(&err),
        })?;
        families.push(family);
    }
    Ok(families)
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed or mismatched input only; semantic
// shortfalls of dispatched handlers are preserved member dispositions.
// ---------------------------------------------------------------------------

/// Typed fail-closed routing error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurationRoutingError {
    /// The batch envelope is malformed or out of bounds.
    Batch {
        /// Closed field name.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// The bundled A-05 receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The supplied screen cannot enable dispatch or drifts from the batch.
    Screen {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The injected registry is not exactly the closed ten-owner coverage.
    Registry {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The injected port set is not exactly one live port per owner family.
    Port {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The routing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A target/member denominator is malformed or incomplete.
    Denominator {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A selected handler reported a terminal typed failure.
    Handler {
        /// Handler that reported the failure.
        handler_id: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// A selected handler panicked; terminal with no alternate handler.
    HandlerPanicked {
        /// Handler that panicked.
        handler_id: String,
    },
    /// A returned envelope drifts from the dispatched request binding.
    Envelope {
        /// Handler that returned the drifting envelope.
        handler_id: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// All-or-nothing aggregation met a non-candidate member.
    Atomicity {
        /// Bounded redacted reason naming the offending member.
        detail: String,
    },
    /// A digest shape or replay pin is wrong.
    Digest {
        /// Bounded redacted reason.
        detail: String,
    },
}

impl core::fmt::Display for CurationRoutingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Batch { field, detail } => write!(f, "batch[{field}]: {detail}"),
            Self::Binding { field, detail } => write!(f, "binding[{field}]: {detail}"),
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Screen { detail } => write!(f, "screen: {detail}"),
            Self::Registry { detail } => write!(f, "registry: {detail}"),
            Self::Port { detail } => write!(f, "port: {detail}"),
            Self::Policy { detail } => write!(f, "policy: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
            Self::Handler { handler_id, detail } => write!(f, "handler[{handler_id}]: {detail}"),
            Self::HandlerPanicked { handler_id } => {
                write!(
                    f,
                    "handler[{handler_id}] panicked: terminal, no alternate handler"
                )
            }
            Self::Envelope { handler_id, detail } => write!(f, "envelope[{handler_id}]: {detail}"),
            Self::Atomicity { detail } => write!(f, "atomicity: {detail}"),
            Self::Digest { detail } => write!(f, "digest: {detail}"),
        }
    }
}

impl core::error::Error for CurationRoutingError {}

// ---------------------------------------------------------------------------
// Public vocabulary: policy, batch, ports, dispositions, candidate set.
// ---------------------------------------------------------------------------

/// Routing policy for one fan-in call: all-or-nothing versus explicit partial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    /// Policy identity bound into the input digest.
    pub policy_id: String,
    /// Policy revision; zero is rejected as a defaulted binding.
    pub policy_revision: u32,
    /// False selects all-or-nothing aggregation; true selects explicit partial.
    pub allow_partial: bool,
    /// Maximum items admitted in the routed batch (at least one).
    pub max_items: u32,
}

impl RoutingPolicy {
    /// Validates intrinsic policy bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError::Policy`] on blank identity, defaulted
    /// revision, or an unusable item bound.
    pub fn validate(&self) -> Result<(), CurationRoutingError> {
        check_bounded_text(&self.policy_id, "policy_id", MAX_ID_BYTES).map_err(|_| {
            CurationRoutingError::Policy {
                detail: "policy_id is blank, controlled, or overlong".to_owned(),
            }
        })?;
        if self.policy_revision == 0 {
            return Err(CurationRoutingError::Policy {
                detail: "policy_revision must be explicit, not defaulted".to_owned(),
            });
        }
        if self.max_items == 0 || self.max_items as usize > MAX_BATCH_ITEMS {
            return Err(CurationRoutingError::Policy {
                detail: std::format!("max_items must cover 1..={MAX_BATCH_ITEMS}"),
            });
        }
        Ok(())
    }

    /// Returns the sha256 digest over the canonical policy bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError::Digest`] when canonical serialization fails.
    pub fn digest(&self) -> Result<String, CurationRoutingError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|err| CurationRoutingError::Digest {
                detail: redact(&err.to_string()),
            })
    }
}

/// One pinned owner revision: the exact handler revision the batch was sealed
/// against. Any drift between pin and injected port fails closed as stale.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerRevisionPin {
    /// Owner family this pin binds.
    pub family: CurationFamily,
    /// Pinned owner revision identity.
    pub revision: String,
}

/// Already A-05-validated curation batch proposed for fan-in dispatch.
///
/// The batch records every routing binding wholesale: job, request,
///
/// operation, idempotency, requester, task, attempt, scope, fence, bundle,
/// manifest, grounding, and validation receipt digests; the pinned closed
/// registry digest plus one revision pin per owner family; privacy, authority,
/// effect, and proof postures; atomicity, budgets, deadline, cancellation,
/// predecessor, and invalidation evidence; and the exact input digest sealing
/// the whole preimage. Screens, registries, and policies arrive as separate
/// parameters and are bound here by digest and identity comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedCurationBatch {
    /// Owning job identity.
    pub job_id: String,
    /// Curation request identity; must equal the screen request identity.
    pub request_id: String,
    /// Operation identity carried for lineage.
    pub operation_id: String,
    /// Idempotency identity carried for lineage.
    pub idempotency_key: String,
    /// Authenticated requester; must equal every item requester.
    pub requester: Requester,
    /// Owning task identity; must equal the screen task identity.
    pub task_id: String,
    /// Dispatch attempt number bound into replay identity.
    pub attempt: u32,
    /// Decision scope identity; must equal the screen scope identity.
    pub scope_id: String,
    /// State fence; must equal the screen fence.
    pub state_fence: StateFence,
    /// Digest of the frozen input bundle; must equal the receipt bundle digest.
    pub bundle_digest: String,
    /// Digest of the frozen input manifest; must equal the receipt manifest digest.
    pub manifest_digest: String,
    /// Digest of the grounding the batch accounts for.
    pub grounding_digest: String,
    /// A-05 validator receipt backing every item.
    pub receipt: ValidationReceipt,
    /// Validated items in semantic order; canonical output preserves it.
    pub items: Vec<ValidatedCurationItem>,
    /// Batch target/member denominator; must equal the screened target set.
    pub denominator: TargetDenominator,
    /// Privacy posture: exactly `local_only` or `governed_external`.
    pub privacy_profile: String,
    /// Authority posture reference carried without exercising authority.
    pub authority_ref: String,
    /// Effect posture note; routing exercises no effect.
    pub effect_note: String,
    /// Proof ceiling carried without promotion.
    pub proof_ceiling: String,
    /// Batch atomicity mode applied at aggregation.
    pub atomicity: AtomicityMode,
    /// Independent per-dimension budget limits authorizing dispatch.
    pub budgets: BudgetLimits,
    /// Observed per-dimension consumption that must fit the limits.
    pub usage: BudgetUsage,
    /// Optional wall-clock deadline in Unix milliseconds; compared only
    /// against the injected observation, never against a clock.
    pub deadline_ms: Option<u64>,
    /// Explicit observation time for the deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit caller cancellation; honors an exact unprocessed frontier.
    pub cancelled: bool,
    /// Predecessor input digests invalidated or superseded by this batch.
    pub predecessor_digests: Vec<String>,
    /// Invalidation condition note carried for lineage.
    pub invalidation_note: String,
    /// Pinned closed-registry digest; must equal the injected registry digest.
    pub registry_digest: String,
    /// Exactly one revision pin per owner family, in `CURATION_FAMILIES` canonical order.
    pub owner_pins: Vec<OwnerRevisionPin>,
    /// Sealed input digest over batch, screen, registry digest, and policy.
    pub input_digest: String,
}

impl ValidatedCurationBatch {
    /// Validates intrinsic batch bounds only; call
    /// [`route_validated_curation`] to bind the batch against screen,
    /// registry, and policy.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError`] on any blank, controlled, overlong,
    /// unordered, duplicated, or misshapen field.
    pub fn validate(&self) -> Result<(), CurationRoutingError> {
        check_bounded_text(&self.job_id, "job_id", MAX_ID_BYTES)?;
        check_bounded_text(&self.request_id, "request_id", MAX_ID_BYTES)?;
        check_bounded_text(&self.operation_id, "operation_id", MAX_ID_BYTES)?;
        check_bounded_text(&self.idempotency_key, "idempotency_key", MAX_ID_BYTES)?;
        check_bounded_text(&self.task_id, "task_id", MAX_SCOPE_BYTES)?;
        check_bounded_text(&self.scope_id, "scope_id", MAX_SCOPE_BYTES)?;
        self.requester
            .validate()
            .map_err(|err| CurationRoutingError::Batch {
                field: "requester",
                detail: contract_detail(&err),
            })?;
        check_fence(&self.state_fence).map_err(|err| CurationRoutingError::Batch {
            field: "state_fence",
            detail: contract_detail(&err),
        })?;
        check_digest(&self.bundle_digest, "bundle_digest")?;
        check_digest(&self.manifest_digest, "manifest_digest")?;
        check_digest(&self.grounding_digest, "grounding_digest")?;
        self.receipt
            .validate()
            .map_err(|err| CurationRoutingError::Receipt {
                detail: contract_detail(&err),
            })?;
        if self.receipt.terminal_disposition != "accepted"
            && self.receipt.terminal_disposition != "partial"
        {
            return Err(CurationRoutingError::Receipt {
                detail: "validator receipt is not accepted or partial".to_owned(),
            });
        }
        if self.items.is_empty() || self.items.len() > MAX_BATCH_ITEMS {
            return Err(CurationRoutingError::Batch {
                field: "items",
                detail: std::format!("batch must carry 1..={MAX_BATCH_ITEMS} items"),
            });
        }
        self.denominator
            .validate()
            .map_err(|err| CurationRoutingError::Denominator {
                detail: contract_detail(&err),
            })?;
        if self.privacy_profile != PRIVACY_LOCAL_ONLY
            && self.privacy_profile != PRIVACY_GOVERNED_EXTERNAL
        {
            return Err(CurationRoutingError::Batch {
                field: "privacy_profile",
                detail: "must be local_only or governed_external".to_owned(),
            });
        }
        check_bounded_text(&self.authority_ref, "authority_ref", MAX_SCOPE_BYTES)?;
        check_bounded_text(&self.effect_note, "effect_note", MAX_NOTE_BYTES)?;
        check_bounded_text(&self.proof_ceiling, "proof_ceiling", MAX_SCOPE_BYTES)?;
        check_bounded_text(&self.invalidation_note, "invalidation_note", MAX_NOTE_BYTES)?;
        if self.predecessor_digests.len() > MAX_PREDECESSORS {
            return Err(CurationRoutingError::Batch {
                field: "predecessor_digests",
                detail: std::format!("at most {MAX_PREDECESSORS} predecessor digests"),
            });
        }
        for digest in &self.predecessor_digests {
            check_digest(digest, "predecessor_digests")?;
        }
        if !is_sorted_unique(&self.predecessor_digests) {
            return Err(CurationRoutingError::Batch {
                field: "predecessor_digests",
                detail: "predecessor digests must be sorted and unique".to_owned(),
            });
        }
        check_digest(&self.registry_digest, "registry_digest")?;
        check_digest(&self.input_digest, "input_digest")?;
        if self.owner_pins.len() != EXPECTED_OWNER_DESCRIPTORS {
            return Err(CurationRoutingError::Batch {
                field: "owner_pins",
                detail: std::format!(
                    "batch must pin exactly {EXPECTED_OWNER_DESCRIPTORS} owner revisions"
                ),
            });
        }
        let canonical = canonical_families()?;
        for (index, pin) in self.owner_pins.iter().enumerate() {
            check_bounded_text(&pin.revision, "owner_pins", MAX_ID_BYTES)?;
            let Some(expected) = canonical.get(index) else {
                return Err(CurationRoutingError::Batch {
                    field: "owner_pins",
                    detail: "owner pins must cover each family exactly once in canonical order"
                        .to_owned(),
                });
            };
            if pin.family != *expected {
                return Err(CurationRoutingError::Batch {
                    field: "owner_pins",
                    detail: "owner pins must cover each family exactly once in canonical order"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Full input-identity preimage hashed by [`compute_input_digest`].
///
/// The preimage covers every batch field except the sealing `input_digest`
/// itself, plus the exact screen binding, the closed registry digest, and the
/// routing policy. `budget_note`-style free annotations inside items stay
/// covered through the item bytes; nothing ambient enters the hash.
#[derive(Serialize)]
struct InputDigestPreimage<'a> {
    job_id: &'a str,
    request_id: &'a str,
    operation_id: &'a str,
    idempotency_key: &'a str,
    requester: &'a Requester,
    task_id: &'a str,
    attempt: u32,
    scope_id: &'a str,
    state_fence: &'a StateFence,
    bundle_digest: &'a str,
    manifest_digest: &'a str,
    grounding_digest: &'a str,
    receipt: &'a ValidationReceipt,
    items: &'a [ValidatedCurationItem],
    denominator: &'a TargetDenominator,
    privacy_profile: &'a str,
    authority_ref: &'a str,
    effect_note: &'a str,
    proof_ceiling: &'a str,
    atomicity: AtomicityMode,
    budgets: &'a BudgetLimits,
    usage: &'a BudgetUsage,
    deadline_ms: Option<u64>,
    observation_time_ms: Option<u64>,
    cancelled: bool,
    predecessor_digests: &'a [String],
    invalidation_note: &'a str,
    registry_digest: &'a str,
    owner_pins: &'a [OwnerRevisionPin],
    screen: &'a ScreenBinding,
    policy: &'a RoutingPolicy,
}

/// Computes the sealed input digest over batch, screen, registry, and policy.
///
/// The digest is deterministic: order-only target or evidence permutations
/// inside payloads share one digest only where the shared closed contracts
/// normalize them; every scalar, set, identity, or binding drift stays
/// digest-visible. A changed same-ID input, registry, or policy conflicts
/// with the sealed pin instead of routing silently.
///
/// # Errors
///
/// Returns [`CurationRoutingError::Digest`] when canonical serialization fails.
pub fn compute_input_digest(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    registry_digest: &str,
    policy: &RoutingPolicy,
) -> Result<String, CurationRoutingError> {
    let preimage = InputDigestPreimage {
        job_id: &batch.job_id,
        request_id: &batch.request_id,
        operation_id: &batch.operation_id,
        idempotency_key: &batch.idempotency_key,
        requester: &batch.requester,
        task_id: &batch.task_id,
        attempt: batch.attempt,
        scope_id: &batch.scope_id,
        state_fence: &batch.state_fence,
        bundle_digest: &batch.bundle_digest,
        manifest_digest: &batch.manifest_digest,
        grounding_digest: &batch.grounding_digest,
        receipt: &batch.receipt,
        items: &batch.items,
        denominator: &batch.denominator,
        privacy_profile: &batch.privacy_profile,
        authority_ref: &batch.authority_ref,
        effect_note: &batch.effect_note,
        proof_ceiling: &batch.proof_ceiling,
        atomicity: batch.atomicity,
        budgets: &batch.budgets,
        usage: &batch.usage,
        deadline_ms: batch.deadline_ms,
        observation_time_ms: batch.observation_time_ms,
        cancelled: batch.cancelled,
        predecessor_digests: &batch.predecessor_digests,
        invalidation_note: &batch.invalidation_note,
        registry_digest,
        owner_pins: &batch.owner_pins,
        screen,
        policy,
    };
    canonical_json_bytes(&preimage)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| CurationRoutingError::Digest {
            detail: redact(&err.to_string()),
        })
}

/// Live semantic owner behind one hub-native port.
///
/// H1 follow-up migration (deferred by the hub binding): the A-31 local port
/// trait (`CurationHandler::handle`, typed request in, digest-only result
/// envelope out) is retired in favor of the hub native binding
/// [`NativeCurationHandler::handle`] (frozen [`BoundCurationCall`] in, full
/// [`ProducedCurationContent`] out). Implementors are the ten concrete
/// subtype owners (or faithful test doubles counting real calls). The router
/// calls the selected owner exactly once per dispatchable item, validates the
/// produced content against the bound call, seals a [`FullCurationResult`],
/// and treats any failure as terminal.
///
/// Boundary: the hub `invoke()` acceptance leg (`ValidatedCurationItem::accept`
/// over job, bundle, grounded draft, and screen) stays at the composition
/// layer and is not replayed here. It binds the screen `item_digest` to one
/// per-item digest, while A-31 routes many distinct items under one
/// batch-shared screen; replaying it per item would fail closed on every
/// multi-item batch. A-31 keeps its batch-level acceptance (batch envelope,
/// screen binding, closed registry, owner pins, budgets, sealed input digest,
/// per-item uniformity and denominator gates) and hands the frozen call view
/// to the hub handler contract.
pub use eliot_dreamer_contracts::NativeCurationHandler;

/// One hub-native live port: an A-03 port descriptor bound to its owner
/// package, revision, and live hub-native handler.
///
/// Ports are live injection handles, never serialized: digests pin them
/// instead. No discovery, no default family, no trial decode.
pub struct NativeCurationPort<'a> {
    /// A-03 port identity bound to one owner descriptor.
    pub port: CurationHandlerPort,
    /// Owner package identity; must equal the closed routing table.
    pub owner_package: String,
    /// Owner revision identity; must equal the batch pin for the family.
    pub owner_revision: String,
    /// Live hub-native handler invoked exactly once per dispatched item of
    /// the family, receiving the frozen hub call view.
    pub handler: &'a dyn NativeCurationHandler,
}

/// Exactly one live hub-native port per owner family, validated against the
/// registry.
pub struct NativeCurationPortSet<'a> {
    /// Ten injected hub-native ports, one per canonical family.
    pub ports: Vec<NativeCurationPort<'a>>,
}

impl NativeCurationPortSet<'_> {
    /// Validates the port set against the closed registry and batch pins.
    ///
    /// Requires exactly ten ports covering each canonical family once, with
    /// descriptors byte-equal to the registry descriptors, packages matching
    /// the closed routing table, and revisions matching the batch pins.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError::Port`] on any missing, duplicate,
    /// wrong-owner, mispackaged, or stale port, and
    /// [`CurationRoutingError::Registry`] when the canonical family table
    /// itself cannot be read.
    pub fn validate(
        &self,
        registry: &CurationHandlerRegistry,
        pins: &[OwnerRevisionPin],
    ) -> Result<(), CurationRoutingError> {
        let families = canonical_families()?;
        if self.ports.len() != EXPECTED_OWNER_DESCRIPTORS {
            return Err(CurationRoutingError::Port {
                detail: std::format!(
                    "port set must carry exactly {EXPECTED_OWNER_DESCRIPTORS} live ports"
                ),
            });
        }
        for family in &families {
            let matching: Vec<&NativeCurationPort<'_>> = self
                .ports
                .iter()
                .filter(|port| port.port.descriptor.family == *family)
                .collect();
            let Some(injected) = matching.first() else {
                return Err(CurationRoutingError::Port {
                    detail: std::format!("missing live port for family {}", family.as_str()),
                });
            };
            if matching.len() != 1 {
                return Err(CurationRoutingError::Port {
                    detail: std::format!("duplicate live ports for family {}", family.as_str()),
                });
            }
            injected
                .port
                .validate()
                .map_err(|err| CurationRoutingError::Port {
                    detail: contract_detail(&err),
                })?;
            let Some(declared) = registry.handlers.iter().find(|item| item.family == *family)
            else {
                return Err(CurationRoutingError::Port {
                    detail: std::format!(
                        "registry declares no descriptor for family {}",
                        family.as_str()
                    ),
                });
            };
            if injected.port.descriptor != *declared {
                return Err(CurationRoutingError::Port {
                    detail: std::format!(
                        "live port for family {} is not the registered owner",
                        family.as_str()
                    ),
                });
            }
            if injected.owner_package != expected_owner_package(*family) {
                return Err(CurationRoutingError::Port {
                    detail: std::format!(
                        "live port for family {} carries the wrong owner package",
                        family.as_str()
                    ),
                });
            }
            check_bounded_text(&injected.owner_revision, "owner_revision", MAX_ID_BYTES).map_err(
                |_| CurationRoutingError::Port {
                    detail: std::format!(
                        "live port for family {} carries a malformed owner revision",
                        family.as_str()
                    ),
                },
            )?;
            let Some(pin) = pins.iter().find(|item| item.family == *family) else {
                return Err(CurationRoutingError::Port {
                    detail: std::format!(
                        "batch pins no owner revision for family {}",
                        family.as_str()
                    ),
                });
            };
            if injected.owner_revision != pin.revision {
                return Err(CurationRoutingError::Port {
                    detail: std::format!(
                        "live port for family {} is stale against the batch pin",
                        family.as_str()
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Per-member routing disposition.
///
/// The first eight spellings preserve the selected handler envelope one to
/// one; [`RoutingDisposition::Unprocessed`] marks members never attempted
/// because cancellation or a bound stopped dispatch before any handler call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutingDisposition {
    /// The selected owner returned a live proposal.
    Candidate,
    /// The selected owner reported a repeat proposal.
    Duplicate,
    /// The selected owner reported a conflicting proposal.
    Conflict,
    /// The selected owner offered no proposal.
    Abstention,
    /// The selected owner formed only a partial proposal.
    Partial,
    /// The owner path or the pre-dispatch gate is blocked.
    Blocked,
    /// The requested shape is not supported by the selected owner.
    Unsupported,
    /// The selected owner stopped on an internal defect.
    InternalDefect,
    /// The member was never attempted; see the unprocessed frontier.
    Unprocessed,
}

impl RoutingDisposition {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Abstention => "abstention",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
            Self::Unsupported => "unsupported",
            Self::InternalDefect => "internal_defect",
            Self::Unprocessed => "unprocessed",
        }
    }
}

impl From<CandidateDisposition> for RoutingDisposition {
    fn from(value: CandidateDisposition) -> Self {
        match value {
            CandidateDisposition::Candidate => Self::Candidate,
            CandidateDisposition::Duplicate => Self::Duplicate,
            CandidateDisposition::Conflict => Self::Conflict,
            CandidateDisposition::Abstention => Self::Abstention,
            CandidateDisposition::Partial => Self::Partial,
            CandidateDisposition::Blocked => Self::Blocked,
            CandidateDisposition::Unsupported => Self::Unsupported,
            CandidateDisposition::InternalDefect => Self::InternalDefect,
        }
    }
}

/// Maps one routing disposition to its routing-only rejection hint.
///
/// Accepted candidates carry no hint. The hint is never a hub-external verdict and
/// never authorizes anything; it only classifies preserved outcomes for
/// downstream accounting.
#[must_use]
pub const fn routing_rejection_hint(
    disposition: RoutingDisposition,
) -> Option<CurationRejectionCode> {
    match disposition {
        RoutingDisposition::Candidate => None,
        RoutingDisposition::Duplicate | RoutingDisposition::Conflict => {
            Some(CurationRejectionCode::LineageMismatch)
        }
        RoutingDisposition::Abstention | RoutingDisposition::Unsupported => {
            Some(CurationRejectionCode::UnsupportedJobShape)
        }
        RoutingDisposition::Partial => Some(CurationRejectionCode::UnsupportedPrecision),
        RoutingDisposition::Blocked => Some(CurationRejectionCode::IdentityMismatch),
        RoutingDisposition::InternalDefect => Some(CurationRejectionCode::PreservationFailed),
        RoutingDisposition::Unprocessed => Some(CurationRejectionCode::Cancelled),
    }
}

/// Exactly one routing outcome per batch member, in batch order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationMemberOutcome {
    /// Member identity: sha256 over the canonical item bytes.
    pub member_id: String,
    /// Zero-based batch index the member accounts for.
    pub item_index: u32,
    /// Dispatched wire kind.
    pub kind: CurationKind,
    /// Resolved owner family from the shared closed mapping.
    pub family: CurationFamily,
    /// Resolved owner handler identity, or `unresolved` when the kind itself
    /// could not be established before dispatch.
    pub handler_id: String,
    /// Exactly one disposition for this member.
    pub disposition: RoutingDisposition,
    /// Routing-only rejection hint classifying the disposition.
    pub rejection_hint: Option<CurationRejectionCode>,
    /// Handler calls performed for this member: exactly zero or one.
    pub calls: u32,
    /// Digest of the dispatched request; absent when never dispatched.
    pub request_digest: Option<String>,
    /// Digest carried by the preserved result; absent when never dispatched.
    pub result_digest: Option<String>,
    /// Proposed mutable targets echoed from the item facets.
    pub targets: Vec<String>,
    /// Immutable evidence references echoed from the item facets.
    pub evidence_refs: Vec<String>,
    /// Bounded routing note naming the gate or preserved outcome.
    pub note: String,
}

impl CurationMemberOutcome {
    /// Validates intrinsic outcome shape and dispatch accounting.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError::Batch`] on any blank, misshapen, or
    /// inconsistent field, including a call count other than zero or one and
    /// any digest presence that disagrees with the call count.
    pub fn validate(&self) -> Result<(), CurationRoutingError> {
        let failed = |detail: &str| CurationRoutingError::Batch {
            field: "members",
            detail: detail.to_owned(),
        };
        check_digest(&self.member_id, "member_id")
            .map_err(|_| failed("member_id must be 64 lowercase hex sha256"))?;
        check_bounded_text(&self.handler_id, "handler_id", MAX_ID_BYTES)
            .map_err(|_| failed("handler_id is blank, controlled, or overlong"))?;
        if family_of(self.kind) != self.family {
            return Err(failed(
                "member kind and family disagree on the closed mapping",
            ));
        }
        if self.rejection_hint != routing_rejection_hint(self.disposition) {
            return Err(failed(
                "member rejection hint disagrees with its disposition",
            ));
        }
        if self.calls > 1 {
            return Err(failed("member calls must be exactly zero or one"));
        }
        match (self.calls, &self.request_digest, &self.result_digest) {
            (0, None, None) => {}
            (1, Some(request), Some(result)) => {
                check_digest(request, "request_digest")
                    .map_err(|_| failed("request_digest must be 64 lowercase hex sha256"))?;
                check_digest(result, "result_digest")
                    .map_err(|_| failed("result_digest must be 64 lowercase hex sha256"))?;
            }
            _ => {
                return Err(failed(
                    "dispatched members carry both digests; undispatched members carry neither",
                ));
            }
        }
        if self.disposition == RoutingDisposition::Unprocessed && self.calls != 0 {
            return Err(failed("unprocessed members must carry zero calls"));
        }
        for handle in self.targets.iter().chain(self.evidence_refs.iter()) {
            check_bounded_text(handle, "targets", MAX_ID_BYTES)
                .map_err(|_| failed("target or evidence handle is blank or overlong"))?;
        }
        check_bounded_text(&self.note, "note", MAX_NOTE_BYTES)
            .map_err(|_| failed("member note is blank, controlled, or overlong"))?;
        Ok(())
    }
}

/// Deterministic lineage-preserving candidate set for one routed batch.
///
/// Members appear in batch order with exactly one disposition each. The
/// unprocessed frontier names members never attempted; omitted targets name
/// denominator members no item proposed. Aggregation evidence carries
/// registry, policy, input, screen, kind, family, handler, call-count,
/// target, evidence, member, atomicity, budget, and digest bindings with a
/// routing-only proof note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationCandidateSet {
    /// Owning job identity echoed from the batch.
    pub job_id: String,
    /// Curation request identity echoed from the batch.
    pub request_id: String,
    /// Owning task identity echoed from the batch.
    pub task_id: String,
    /// Decision scope identity echoed from the batch.
    pub scope_id: String,
    /// Dispatch attempt number echoed from the batch.
    pub attempt: u32,
    /// State fence echoed from the batch.
    pub state_fence: StateFence,
    /// Aggregation mode applied.
    pub atomicity: AtomicityMode,
    /// True only under an explicit-partial policy.
    pub allow_partial: bool,
    /// Routing policy identity applied.
    pub policy_id: String,
    /// Routing policy revision applied.
    pub policy_revision: u32,
    /// Closed registry digest the batch was routed against.
    pub registry_digest: String,
    /// Sealed input digest the batch was routed against.
    pub input_digest: String,
    /// Screen result digest echoed from the binding.
    pub screen_result_digest: String,
    /// Screen item digest echoed from the binding.
    pub screen_item_digest: String,
    /// Batch denominator echoed for omission accounting.
    pub denominator: TargetDenominator,
    /// Budget limits echoed from the batch.
    pub budgets: BudgetLimits,
    /// Observed consumption echoed from the batch.
    pub usage: BudgetUsage,
    /// Exactly one outcome per batch member, in batch order.
    pub members: Vec<CurationMemberOutcome>,
    /// Member identities never attempted, in batch order.
    pub unprocessed_frontier: Vec<String>,
    /// Denominator members no item proposed, sorted.
    pub omitted_targets: Vec<String>,
    /// Members with a live candidate disposition.
    pub accepted: u32,
    /// Members with a duplicate, conflict, abstention, or unsupported disposition.
    pub rejected: u32,
    /// Members with a blocked, partial, or internal-defect disposition.
    pub blocked: u32,
    /// Members never attempted.
    pub unprocessed: u32,
    /// Total handler calls performed across all members.
    pub total_handler_calls: u32,
    /// Deterministic set digest over the aggregation evidence.
    pub set_digest: String,
    /// Routing-only proof ceiling.
    pub proof_note: String,
}

impl CurationCandidateSet {
    /// Validates intrinsic set shape, count reconciliation, and digest.
    ///
    /// # Errors
    ///
    /// Returns [`CurationRoutingError`] on any blank or misshapen identity,
    /// any count that disagrees with member dispositions, any call total that
    /// disagrees with per-member counts, any frontier or omission that
    /// disagrees with member state, or any set digest that does not recompute.
    pub fn validate(&self) -> Result<(), CurationRoutingError> {
        self.validate_set_bindings()?;
        self.validate_set_tallies()?;
        self.validate_set_coverage()?;
        Ok(())
    }

    fn validate_set_bindings(&self) -> Result<(), CurationRoutingError> {
        let failed = |detail: &str| CurationRoutingError::Batch {
            field: "candidate_set",
            detail: detail.to_owned(),
        };
        check_bounded_text(&self.job_id, "job_id", MAX_ID_BYTES)
            .map_err(|_| failed("job_id is blank, controlled, or overlong"))?;
        check_bounded_text(&self.request_id, "request_id", MAX_ID_BYTES)
            .map_err(|_| failed("request_id is blank, controlled, or overlong"))?;
        check_bounded_text(&self.task_id, "task_id", MAX_SCOPE_BYTES)
            .map_err(|_| failed("task_id is blank, controlled, or overlong"))?;
        check_bounded_text(&self.scope_id, "scope_id", MAX_SCOPE_BYTES)
            .map_err(|_| failed("scope_id is blank, controlled, or overlong"))?;
        check_bounded_text(&self.policy_id, "policy_id", MAX_ID_BYTES)
            .map_err(|_| failed("policy_id is blank, controlled, or overlong"))?;
        check_fence(&self.state_fence).map_err(|_| failed("state_fence is invalid"))?;
        check_digest(&self.registry_digest, "registry_digest")
            .map_err(|_| failed("registry_digest must be 64 lowercase hex sha256"))?;
        check_digest(&self.input_digest, "input_digest")
            .map_err(|_| failed("input_digest must be 64 lowercase hex sha256"))?;
        check_digest(&self.screen_result_digest, "screen_result_digest")
            .map_err(|_| failed("screen_result_digest must be 64 lowercase hex"))?;
        check_digest(&self.screen_item_digest, "screen_item_digest")
            .map_err(|_| failed("screen_item_digest must be 64 lowercase hex"))?;
        self.denominator
            .validate()
            .map_err(|err| CurationRoutingError::Denominator {
                detail: contract_detail(&err),
            })?;
        self.budgets
            .validate()
            .map_err(|_| failed("echoed budget limits exceed their ceilings"))?;
        self.usage
            .fits(&self.budgets)
            .map_err(|_| failed("echoed budget usage does not fit its limits"))?;
        if self.proof_note != ROUTING_PROOF_NOTE {
            return Err(failed("proof note must be the routing-only ceiling"));
        }
        Ok(())
    }

    fn validate_set_tallies(&self) -> Result<(), CurationRoutingError> {
        let failed = |detail: &str| CurationRoutingError::Batch {
            field: "candidate_set",
            detail: detail.to_owned(),
        };
        let mut seen: Vec<&str> = Vec::with_capacity(self.members.len());
        let mut accepted = 0u32;
        let mut rejected = 0u32;
        let mut blocked = 0u32;
        let mut unprocessed = 0u32;
        let mut total_calls = 0u32;
        for member in &self.members {
            member.validate()?;
            if seen.contains(&member.member_id.as_str()) {
                return Err(failed("member identities must be unique"));
            }
            seen.push(&member.member_id);
            match member.disposition {
                RoutingDisposition::Candidate => {
                    accepted = accepted.saturating_add(1);
                }
                RoutingDisposition::Duplicate
                | RoutingDisposition::Conflict
                | RoutingDisposition::Abstention
                | RoutingDisposition::Unsupported => {
                    rejected = rejected.saturating_add(1);
                }
                RoutingDisposition::Partial
                | RoutingDisposition::Blocked
                | RoutingDisposition::InternalDefect => {
                    blocked = blocked.saturating_add(1);
                }
                RoutingDisposition::Unprocessed => {
                    unprocessed = unprocessed.saturating_add(1);
                }
            }
            total_calls = total_calls.saturating_add(member.calls);
        }
        if self.accepted != accepted
            || self.rejected != rejected
            || self.blocked != blocked
            || self.unprocessed != unprocessed
        {
            return Err(failed(
                "accepted, rejected, blocked, and unprocessed must reconcile",
            ));
        }
        if self.total_handler_calls != total_calls {
            return Err(failed("total handler calls must equal the per-member sum"));
        }
        Ok(())
    }

    fn validate_set_coverage(&self) -> Result<(), CurationRoutingError> {
        let failed = |detail: &str| CurationRoutingError::Batch {
            field: "candidate_set",
            detail: detail.to_owned(),
        };
        let frontier: Vec<&str> = self
            .members
            .iter()
            .filter(|member| member.disposition == RoutingDisposition::Unprocessed)
            .map(|member| member.member_id.as_str())
            .collect();
        let retained: Vec<&str> = self
            .unprocessed_frontier
            .iter()
            .map(String::as_str)
            .collect();
        if frontier != retained {
            return Err(failed(
                "unprocessed frontier must name exactly the unprocessed members in order",
            ));
        }
        let mut covered: Vec<&str> = Vec::new();
        for member in &self.members {
            for target in &member.targets {
                if !covered.contains(&target.as_str()) {
                    covered.push(target);
                }
            }
        }
        let mut omitted: Vec<&str> = self
            .denominator
            .members
            .iter()
            .filter(|handle| !covered.contains(&handle.as_str()))
            .map(String::as_str)
            .collect();
        omitted.sort_unstable();
        let retained_omitted: Vec<&str> = self.omitted_targets.iter().map(String::as_str).collect();
        if omitted != retained_omitted {
            return Err(failed(
                "omitted targets must name exactly the uncovered denominator members",
            ));
        }
        if !is_sorted_unique(&self.omitted_targets) {
            return Err(failed("omitted targets must be sorted and unique"));
        }
        let recomputed = self
            .compute_set_digest()
            .map_err(|_| failed("set digest inputs cannot be canonically serialized"))?;
        if recomputed != self.set_digest {
            return Err(failed("set digest does not recompute"));
        }
        Ok(())
    }

    fn compute_set_digest(&self) -> Result<String, CurationRoutingError> {
        let mut members = Vec::with_capacity(self.members.len());
        for member in &self.members {
            let mut targets: Vec<&str> = member.targets.iter().map(String::as_str).collect();
            targets.sort_unstable();
            let mut evidence_refs: Vec<&str> =
                member.evidence_refs.iter().map(String::as_str).collect();
            evidence_refs.sort_unstable();
            members.push(MemberDigestView {
                member_id: &member.member_id,
                item_index: member.item_index,
                kind: member.kind,
                family: member.family,
                handler_id: &member.handler_id,
                disposition: member.disposition,
                calls: member.calls,
                request_digest: member.request_digest.as_deref(),
                result_digest: member.result_digest.as_deref(),
                targets,
                evidence_refs,
            });
        }
        let view = SetDigestView {
            job_id: &self.job_id,
            request_id: &self.request_id,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            attempt: self.attempt,
            atomicity: self.atomicity,
            allow_partial: self.allow_partial,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            registry_digest: &self.registry_digest,
            input_digest: &self.input_digest,
            screen_result_digest: &self.screen_result_digest,
            screen_item_digest: &self.screen_item_digest,
            denominator: &self.denominator,
            budgets: &self.budgets,
            usage: &self.usage,
            members,
            unprocessed_frontier: &self.unprocessed_frontier,
            omitted_targets: &self.omitted_targets,
            accepted: self.accepted,
            rejected: self.rejected,
            blocked: self.blocked,
            unprocessed: self.unprocessed,
            total_handler_calls: self.total_handler_calls,
        };
        canonical_json_bytes(&view)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|err| CurationRoutingError::Digest {
                detail: redact(&err.to_string()),
            })
    }
}

/// Digest view of one member: targets and evidence sorted so order-only
/// permutations share one digest while scalar or set drift stays visible.
#[derive(Serialize)]
struct MemberDigestView<'a> {
    member_id: &'a str,
    item_index: u32,
    kind: CurationKind,
    family: CurationFamily,
    handler_id: &'a str,
    disposition: RoutingDisposition,
    calls: u32,
    request_digest: Option<&'a str>,
    result_digest: Option<&'a str>,
    targets: Vec<&'a str>,
    evidence_refs: Vec<&'a str>,
}

/// Digest view of one aggregation: every routing evidence field except the
/// sealing `set_digest` itself.
#[derive(Serialize)]
struct SetDigestView<'a> {
    job_id: &'a str,
    request_id: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
    attempt: u32,
    atomicity: AtomicityMode,
    allow_partial: bool,
    policy_id: &'a str,
    policy_revision: u32,
    registry_digest: &'a str,
    input_digest: &'a str,
    screen_result_digest: &'a str,
    screen_item_digest: &'a str,
    denominator: &'a TargetDenominator,
    budgets: &'a BudgetLimits,
    usage: &'a BudgetUsage,
    members: Vec<MemberDigestView<'a>>,
    unprocessed_frontier: &'a [String],
    omitted_targets: &'a [String],
    accepted: u32,
    rejected: u32,
    blocked: u32,
    unprocessed: u32,
    total_handler_calls: u32,
}

// ---------------------------------------------------------------------------
// Canonical entry point.
// ---------------------------------------------------------------------------

/// Routes one already-validated curation batch through the screened
/// exact-one-handler fan-in.
///
/// The call validates, in order, the batch envelope, the routing policy, the
/// screen binding and its batch identities, the closed ten-owner registry and
/// its pinned digest, the injected live port set and owner pins, budgets and
/// the sealed input digest. Cancellation or a breached deadline then returns
/// an orderly set with the exact unprocessed frontier and zero handler calls.
/// Otherwise every item is gated against the exact screened denominator and
/// dispatched to exactly one hub-native owner port, called once with the
/// frozen hub call view, with the produced full content validated and sealed.
/// Aggregation honors the batch atomicity
/// against the routing policy: all-or-nothing fails on any non-candidate
/// member, while an explicit-partial policy retains exact accepted, rejected,
/// blocked, and unprocessed accounting with frontier and omissions.
///
/// A-05 common validation and A-19c screening are never invoked here; only
/// their sealed outputs are checked. No sibling handler is imported: owners
/// arrive exclusively through `ports` as hub-native handlers behind the frozen
/// hub call view.
///
/// # Errors
///
/// Returns [`CurationRoutingError`] on any binding, registry, port, budget,
/// digest, handler, content, sealing, or atomicity failure. Handler errors,
/// content drift, panics, and sealing mismatches are terminal with no retry,
/// no fallback, and no sibling call.
#[allow(clippy::too_many_lines)]
pub fn route_validated_curation(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    registry: &CurationHandlerRegistry,
    policy: &RoutingPolicy,
    ports: &NativeCurationPortSet<'_>,
) -> Result<CurationCandidateSet, CurationRoutingError> {
    batch.validate()?;
    policy.validate()?;
    let batch_partial = batch.atomicity != AtomicityMode::AllOrNothing;
    if batch_partial != policy.allow_partial {
        return Err(CurationRoutingError::Binding {
            field: "atomicity",
            detail: "batch atomicity disagrees with the routing policy mode".to_owned(),
        });
    }
    if batch.items.len() > policy.max_items as usize {
        return Err(CurationRoutingError::Policy {
            detail: "batch carries more items than the routing policy admits".to_owned(),
        });
    }
    validate_screen_binding(screen, batch)?;
    let registry_digest = validate_registry(registry)?;
    if registry_digest != batch.registry_digest {
        return Err(CurationRoutingError::Registry {
            detail: "injected registry digest drifts from the batch pin".to_owned(),
        });
    }
    ports.validate(registry, &batch.owner_pins)?;
    batch
        .budgets
        .validate()
        .map_err(|err| CurationRoutingError::Batch {
            field: "budgets",
            detail: contract_detail(&err),
        })?;
    batch
        .usage
        .fits(&batch.budgets)
        .map_err(|err| CurationRoutingError::Batch {
            field: "budgets",
            detail: contract_detail(&err),
        })?;
    let input_digest = compute_input_digest(batch, screen, &registry_digest, policy)?;
    if input_digest != batch.input_digest {
        return Err(CurationRoutingError::Digest {
            detail: "input digest drifts: changed same-ID input, registry, or policy".to_owned(),
        });
    }
    if batch.cancelled {
        return unprocessed_set(
            batch,
            screen,
            &registry_digest,
            policy,
            "cancelled before dispatch",
        );
    }
    if deadline_hit(batch) {
        return unprocessed_set(
            batch,
            screen,
            &registry_digest,
            policy,
            "deadline reached before dispatch",
        );
    }
    check_item_uniformity(batch)?;
    check_batch_denominator(batch)?;
    let mut members: Vec<CurationMemberOutcome> = Vec::with_capacity(batch.items.len());
    for (index, item) in batch.items.iter().enumerate() {
        let position = u32::try_from(index).map_err(|_| CurationRoutingError::Batch {
            field: "items",
            detail: "batch index exceeds u32".to_owned(),
        })?;
        members.push(dispatch_item(
            batch,
            screen,
            ports,
            &registry_digest,
            position,
            item,
        )?);
    }
    aggregate(batch, screen, &registry_digest, policy, members)
}

fn validate_screen_binding(
    screen: &ScreenBinding,
    batch: &ValidatedCurationBatch,
) -> Result<(), CurationRoutingError> {
    screen
        .validate()
        .map_err(|_| CurationRoutingError::Screen {
            detail: std::format!("screen binding is not eligible: {}", screen.state.reason()),
        })?;
    if screen.state != ScreenState::Eligible {
        return Err(CurationRoutingError::Screen {
            detail: std::format!("screen state is not eligible: {}", screen.state.reason()),
        });
    }
    let mismatch = |field: &'static str| CurationRoutingError::Binding {
        field,
        detail: "screen binding drifts from the batch envelope".to_owned(),
    };
    if screen.request_id.as_str() != batch.request_id {
        return Err(mismatch("request_id"));
    }
    if screen.task_id != batch.task_id {
        return Err(mismatch("task_id"));
    }
    if screen.scope_id != batch.scope_id {
        return Err(mismatch("scope_id"));
    }
    if screen.state_fence != batch.state_fence {
        return Err(mismatch("state_fence"));
    }
    if !sorted_set_eq(&screen.screened_targets, &batch.denominator.members) {
        return Err(CurationRoutingError::Binding {
            field: "denominator",
            detail: "screened targets must equal the exact batch denominator".to_owned(),
        });
    }
    Ok(())
}

fn validate_registry(registry: &CurationHandlerRegistry) -> Result<String, CurationRoutingError> {
    registry
        .validate_closure()
        .map_err(|err| CurationRoutingError::Registry {
            detail: contract_detail(&err),
        })?;
    if registry.handlers.len() != EXPECTED_OWNER_DESCRIPTORS {
        return Err(CurationRoutingError::Registry {
            detail: std::format!(
                "registry must declare exactly {EXPECTED_OWNER_DESCRIPTORS} owner descriptors"
            ),
        });
    }
    for family in canonical_families()? {
        let count = registry
            .handlers
            .iter()
            .filter(|item| item.family == family)
            .count();
        if count != 1 {
            return Err(CurationRoutingError::Registry {
                detail: std::format!(
                    "registry must declare family {} exactly once",
                    family.as_str()
                ),
            });
        }
    }
    registry
        .digest()
        .map_err(|err| CurationRoutingError::Registry {
            detail: contract_detail(&err),
        })
}

fn deadline_hit(batch: &ValidatedCurationBatch) -> bool {
    match (batch.deadline_ms, batch.observation_time_ms) {
        (Some(deadline), Some(observed)) => observed >= deadline,
        _ => false,
    }
}

fn item_content_digest(item: &ValidatedCurationItem) -> Result<String, CurationRoutingError> {
    canonical_json_bytes(item)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|err| CurationRoutingError::Digest {
            detail: redact(&err.to_string()),
        })
}

fn check_item_uniformity(batch: &ValidatedCurationBatch) -> Result<(), CurationRoutingError> {
    if batch.receipt.bundle_digest != batch.bundle_digest {
        return Err(CurationRoutingError::Binding {
            field: "bundle_digest",
            detail: "receipt bundle digest drifts from the batch bundle".to_owned(),
        });
    }
    if batch.receipt.manifest_digest != batch.manifest_digest {
        return Err(CurationRoutingError::Binding {
            field: "manifest_digest",
            detail: "receipt manifest digest drifts from the batch manifest".to_owned(),
        });
    }
    let mut digests: Vec<String> = Vec::with_capacity(batch.items.len());
    for (index, item) in batch.items.iter().enumerate() {
        let position = u32::try_from(index).map_err(|_| CurationRoutingError::Batch {
            field: "items",
            detail: "batch index exceeds u32".to_owned(),
        })?;
        let failed = |field: &'static str, detail: &str| CurationRoutingError::Binding {
            field,
            detail: std::format!("item {position}: {detail}"),
        };
        if item.receipt != batch.receipt {
            return Err(failed(
                "receipt",
                "item receipt drifts from the batch receipt",
            ));
        }
        if item.task_id != batch.task_id {
            return Err(failed("task_id", "item task drifts from the batch task"));
        }
        if item.scope_id != batch.scope_id {
            return Err(failed("scope_id", "item scope drifts from the batch scope"));
        }
        if item.state_fence != batch.state_fence {
            return Err(failed(
                "state_fence",
                "item fence drifts from the batch fence",
            ));
        }
        if item.requester != batch.requester {
            return Err(failed(
                "requester",
                "item requester drifts from the batch requester",
            ));
        }
        let digest = item_content_digest(item)?;
        if digests.contains(&digest) {
            return Err(CurationRoutingError::Binding {
                field: "items",
                detail: std::format!("duplicate item {position} repeats batch content"),
            });
        }
        digests.push(digest);
    }
    Ok(())
}

fn check_batch_denominator(batch: &ValidatedCurationBatch) -> Result<(), CurationRoutingError> {
    if batch.atomicity != AtomicityMode::AllOrNothing {
        return Ok(());
    }
    let mut union: Vec<String> = Vec::new();
    for item in &batch.items {
        for target in &item.payload.facets().targets {
            if !union.contains(target) {
                union.push(target.clone());
            }
        }
    }
    if !sorted_set_eq(&union, &batch.denominator.members) {
        return Err(CurationRoutingError::Denominator {
            detail: "all-or-nothing batch must cover the exact denominator".to_owned(),
        });
    }
    Ok(())
}

fn resolve_port<'port>(
    ports: &'port NativeCurationPortSet<'port>,
    family: CurationFamily,
) -> Result<&'port NativeCurationPort<'port>, CurationRoutingError> {
    let mut found: Option<&'port NativeCurationPort<'port>> = None;
    for port in &ports.ports {
        if port.port.descriptor.family == family {
            if found.is_some() {
                return Err(CurationRoutingError::Port {
                    detail: "port set resolves two ports for one family".to_owned(),
                });
            }
            found = Some(port);
        }
    }
    found.ok_or(CurationRoutingError::Port {
        detail: "port set resolves no port for the item family".to_owned(),
    })
}

fn blocked_member(
    position: u32,
    member_id: &str,
    kind: CurationKind,
    item: &ValidatedCurationItem,
    reason: &str,
) -> CurationMemberOutcome {
    let family = family_of(kind);
    CurationMemberOutcome {
        member_id: member_id.to_owned(),
        item_index: position,
        kind,
        family,
        handler_id: std::format!("family:{}", family.as_str()),
        disposition: RoutingDisposition::Blocked,
        rejection_hint: routing_rejection_hint(RoutingDisposition::Blocked),
        calls: 0,
        request_digest: None,
        result_digest: None,
        targets: item.payload.facets().targets.clone(),
        evidence_refs: item.payload.facets().evidence_refs.clone(),
        note: redact(reason),
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_item(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    ports: &NativeCurationPortSet<'_>,
    registry_digest: &str,
    position: u32,
    item: &ValidatedCurationItem,
) -> Result<CurationMemberOutcome, CurationRoutingError> {
    let member_id = item_content_digest(item)?;
    if let Err(err) = item.validate() {
        return Ok(blocked_member(
            position,
            &member_id,
            item.payload.kind(),
            item,
            &std::format!("validated item rejected before dispatch: {err}"),
        ));
    }
    let kind = item.payload.kind();
    let family = family_of(kind);
    let targets = &item.payload.facets().targets;
    if !targets
        .iter()
        .all(|target| screen.screened_targets.contains(target))
    {
        return Ok(blocked_member(
            position,
            &member_id,
            kind,
            item,
            "item proposes a target outside the exact screened denominator",
        ));
    }
    let port = resolve_port(ports, family)?;
    let request = TypedCurationHandlerRequest {
        request_id: screen.request_id.as_str().to_owned(),
        receipt_id: screen.receipt_id.as_str().to_owned(),
        source_snapshot: screen.source_snapshot.clone(),
        source_revision: screen.source_revision.clone(),
        profile: screen.profile.clone(),
        kind,
        family,
        job_id: batch.job_id.clone(),
        scope_id: batch.scope_id.clone(),
        task_id: batch.task_id.clone(),
        state_fence: batch.state_fence.clone(),
        payload: item.payload.clone(),
        denominator: item.denominator.clone(),
        screen_binding: Some(screen.clone()),
    };
    if let Err(err) = request.validate() {
        return Ok(blocked_member(
            position,
            &member_id,
            kind,
            item,
            &std::format!("typed handler request rejected before call: {err}"),
        ));
    }
    let handler_id = port.port.descriptor.handler_id.clone();
    let call = BoundCurationCall {
        port: port.port.clone(),
        item: item.clone(),
        request: request.clone(),
        registry_digest: registry_digest.to_owned(),
    };
    if let Err(err) = call.validate() {
        return Err(CurationRoutingError::Envelope {
            handler_id: handler_id.clone(),
            detail: redact(&err.to_string()),
        });
    }
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| port.handler.handle(&call)));
    let content: ProducedCurationContent = match outcome {
        Err(_) => {
            return Err(CurationRoutingError::HandlerPanicked {
                handler_id: handler_id.clone(),
            });
        }
        Ok(Err(violation)) => {
            return Err(CurationRoutingError::Handler {
                handler_id: handler_id.clone(),
                detail: redact(&violation.to_string()),
            });
        }
        Ok(Ok(content)) => content,
    };
    content
        .validate_for(&call)
        .map_err(|err| CurationRoutingError::Envelope {
            handler_id: handler_id.clone(),
            detail: redact(&err.to_string()),
        })?;
    let result = seal_full_result(item, &call, content)?;
    let disposition = RoutingDisposition::from(result.content.disposition);
    Ok(CurationMemberOutcome {
        member_id,
        item_index: position,
        kind,
        family,
        handler_id,
        disposition,
        rejection_hint: routing_rejection_hint(disposition),
        calls: 1,
        request_digest: Some(result.request_digest.clone()),
        result_digest: Some(result.result_digest.clone()),
        targets: item.payload.facets().targets.clone(),
        evidence_refs: item.payload.facets().evidence_refs.clone(),
        note: redact("selected owner content sealed and preserved without recomputation"),
    })
}

/// Seals the produced full content into a hub [`FullCurationResult`].
///
/// Identities, fence, and digests are preserved from the frozen bound call;
/// both digests are recomputed over the canonical content, never trusted from
/// the handler. A digest alone is never content: the sealed result carries
/// the complete typed payload, preservation evidence, and role separation.
///
/// # Errors
///
/// Returns [`CurationRoutingError::Digest`] when canonical serialization
/// fails and [`CurationRoutingError::Envelope`] when the sealed result does
/// not validate.
fn seal_full_result(
    item: &ValidatedCurationItem,
    call: &BoundCurationCall,
    content: ProducedCurationContent,
) -> Result<FullCurationResult, CurationRoutingError> {
    let handler_id = call.port.descriptor.handler_id.clone();
    let request_digest =
        request_digest_of(&call.request).map_err(|err| CurationRoutingError::Digest {
            detail: redact(&err.to_string()),
        })?;
    let mut result = FullCurationResult {
        request_id: call.request.request_id.clone(),
        job_id: call.request.job_id.clone(),
        scope_id: call.request.scope_id.clone(),
        task_id: call.request.task_id.clone(),
        kind: call.request.kind,
        family: call.request.family,
        handler_id,
        port_id: call.port.port_id.clone(),
        registry_digest: call.registry_digest.clone(),
        state_fence: item.state_fence.clone(),
        request_digest,
        result_digest: String::new(),
        content,
    };
    result.result_digest =
        result
            .computed_result_digest()
            .map_err(|err| CurationRoutingError::Digest {
                detail: redact(&err.to_string()),
            })?;
    let handler_id = result.handler_id.clone();
    result
        .validate()
        .map_err(|err| CurationRoutingError::Envelope {
            handler_id,
            detail: redact(&err.to_string()),
        })?;
    Ok(result)
}

fn assemble_set(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    registry_digest: &str,
    policy: &RoutingPolicy,
    members: Vec<CurationMemberOutcome>,
) -> Result<CurationCandidateSet, CurationRoutingError> {
    let mut accepted = 0u32;
    let mut rejected = 0u32;
    let mut blocked = 0u32;
    let mut unprocessed = 0u32;
    let mut total_calls = 0u32;
    for member in &members {
        match member.disposition {
            RoutingDisposition::Candidate => {
                accepted = accepted.saturating_add(1);
            }
            RoutingDisposition::Duplicate
            | RoutingDisposition::Conflict
            | RoutingDisposition::Abstention
            | RoutingDisposition::Unsupported => {
                rejected = rejected.saturating_add(1);
            }
            RoutingDisposition::Partial
            | RoutingDisposition::Blocked
            | RoutingDisposition::InternalDefect => {
                blocked = blocked.saturating_add(1);
            }
            RoutingDisposition::Unprocessed => {
                unprocessed = unprocessed.saturating_add(1);
            }
        }
        total_calls = total_calls.saturating_add(member.calls);
    }
    let unprocessed_frontier: Vec<String> = members
        .iter()
        .filter(|member| member.disposition == RoutingDisposition::Unprocessed)
        .map(|member| member.member_id.clone())
        .collect();
    let mut covered: Vec<&str> = Vec::new();
    for member in &members {
        for target in &member.targets {
            if !covered.contains(&target.as_str()) {
                covered.push(target);
            }
        }
    }
    let mut omitted_targets: Vec<String> = batch
        .denominator
        .members
        .iter()
        .filter(|handle| !covered.contains(&handle.as_str()))
        .cloned()
        .collect();
    omitted_targets.sort_unstable();
    let mut set = CurationCandidateSet {
        job_id: batch.job_id.clone(),
        request_id: batch.request_id.clone(),
        task_id: batch.task_id.clone(),
        scope_id: batch.scope_id.clone(),
        attempt: batch.attempt,
        state_fence: batch.state_fence.clone(),
        atomicity: batch.atomicity,
        allow_partial: policy.allow_partial,
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        registry_digest: registry_digest.to_owned(),
        input_digest: batch.input_digest.clone(),
        screen_result_digest: screen.result_digest.clone(),
        screen_item_digest: screen.item_digest.clone(),
        denominator: batch.denominator.clone(),
        budgets: batch.budgets,
        usage: batch.usage,
        members,
        unprocessed_frontier,
        omitted_targets,
        accepted,
        rejected,
        blocked,
        unprocessed,
        total_handler_calls: total_calls,
        set_digest: String::new(),
        proof_note: ROUTING_PROOF_NOTE.to_owned(),
    };
    let digest = set.compute_set_digest()?;
    set.set_digest = digest;
    set.validate()?;
    Ok(set)
}

fn aggregate(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    registry_digest: &str,
    policy: &RoutingPolicy,
    members: Vec<CurationMemberOutcome>,
) -> Result<CurationCandidateSet, CurationRoutingError> {
    if !policy.allow_partial {
        for member in &members {
            if member.disposition != RoutingDisposition::Candidate {
                // No redaction here: the template is fixed and both
                // interpolations are closed vocabularies (64 hex digest plus
                // a closed disposition spelling), so the offender stays exact.
                return Err(CurationRoutingError::Atomicity {
                    detail: std::format!(
                        "all-or-nothing batch meets non-candidate member {} with disposition {}",
                        member.member_id,
                        member.disposition.as_str()
                    ),
                });
            }
        }
    }
    assemble_set(batch, screen, registry_digest, policy, members)
}

fn unprocessed_set(
    batch: &ValidatedCurationBatch,
    screen: &ScreenBinding,
    registry_digest: &str,
    policy: &RoutingPolicy,
    reason: &str,
) -> Result<CurationCandidateSet, CurationRoutingError> {
    let mut members: Vec<CurationMemberOutcome> = Vec::with_capacity(batch.items.len());
    for (index, item) in batch.items.iter().enumerate() {
        let position = u32::try_from(index).map_err(|_| CurationRoutingError::Batch {
            field: "items",
            detail: "batch index exceeds u32".to_owned(),
        })?;
        let member_id = item_content_digest(item)?;
        let kind = item.payload.kind();
        let family = family_of(kind);
        let note = std::format!("{reason}; retained on the exact unprocessed frontier");
        members.push(CurationMemberOutcome {
            member_id,
            item_index: position,
            kind,
            family,
            handler_id: std::format!("family:{}", family.as_str()),
            disposition: RoutingDisposition::Unprocessed,
            rejection_hint: routing_rejection_hint(RoutingDisposition::Unprocessed),
            calls: 0,
            request_digest: None,
            result_digest: None,
            targets: item.payload.facets().targets.clone(),
            evidence_refs: item.payload.facets().evidence_refs.clone(),
            note: redact(&note),
        });
    }
    assemble_set(batch, screen, registry_digest, policy, members)
}

// ---------------------------------------------------------------------------
// Tests: few now (six WORK_UNIT_CASE markers), rest deferred to the manager.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration};
    use eliot_dreamer_contracts::CurationHandlerDescriptor;
    use eliot_dreamer_contracts::curation::{
        AccessibilityPayload, ClassificationPayload, ConceptPayload, EpisodePayload,
        FailurePayload, MergePayload, ProcedurePayload, ReconsolidationPayload, RelationPayload,
        RepairPayload, SplitPayload, TargetEvidence,
    };
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::num::NonZeroU64;

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("canonical test lineage-A"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn test_receipt() -> ValidationReceipt {
        ValidationReceipt {
            schema_version: 1,
            validator_contract: "a05-validator".to_owned(),
            validator_policy: "policy-7".to_owned(),
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            input_digest: "d".repeat(64),
            output_digest: "e".repeat(64),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            state_fence: test_fence(),
            preservation_digest: "f".repeat(64),
            budget_digest: "0".repeat(64),
        }
    }

    fn facets(targets: &[&str]) -> TargetEvidence {
        TargetEvidence {
            targets: targets.iter().map(|item| (*item).to_owned()).collect(),
            evidence_refs: vec!["e-1".to_owned()],
        }
    }

    fn payload_for(
        kind: CurationKind,
        targets: &[&str],
    ) -> eliot_dreamer_contracts::CurationPayload {
        use eliot_dreamer_contracts::CurationPayload as Payload;
        match kind {
            CurationKind::Classification => Payload::Classification(ClassificationPayload {
                label: "memory".to_owned(),
                confidence_bps: 9000,
                target_evidence: facets(targets),
            }),
            CurationKind::Relation => Payload::Relation(RelationPayload {
                from_handle: targets[0].to_owned(),
                to_handle: targets[1].to_owned(),
                relation: "refines".to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Episode => Payload::Episode(EpisodePayload {
                episode: "ep-7".to_owned(),
                observed_at_ms: 1_700_000_000_000,
                target_evidence: facets(targets),
            }),
            CurationKind::Concept => Payload::Concept(ConceptPayload {
                concept: "fence".to_owned(),
                definition: "state dependency".to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Procedure => Payload::Procedure(ProcedurePayload {
                procedure: "rotate".to_owned(),
                steps: 3,
                target_evidence: facets(targets),
            }),
            CurationKind::Failure => Payload::Failure(FailurePayload {
                fingerprint: "fp-1".to_owned(),
                signature: "sig-1".to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Merge => Payload::Merge(MergePayload {
                left: targets[0].to_owned(),
                right: targets[1].to_owned(),
                merged: targets[2].to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Split => Payload::Split(SplitPayload {
                whole: targets[2].to_owned(),
                first: targets[0].to_owned(),
                second: targets[1].to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Reconsolidation => Payload::Reconsolidation(ReconsolidationPayload {
                target: targets[0].to_owned(),
                update: "refresh".to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Accessibility => Payload::Accessibility(AccessibilityPayload {
                handle: targets[0].to_owned(),
                note: "captioned".to_owned(),
                target_evidence: facets(targets),
            }),
            CurationKind::Repair => Payload::Repair(RepairPayload {
                target: targets[0].to_owned(),
                repair: "relink".to_owned(),
                target_evidence: facets(targets),
            }),
        }
    }

    fn test_item(kind: CurationKind, targets: &[&str], denom: &[&str]) -> ValidatedCurationItem {
        ValidatedCurationItem {
            receipt: test_receipt(),
            kind_spelling: kind.as_str().to_owned(),
            family_spelling: eliot_dreamer_contracts::curation::kind_family(kind).to_owned(),
            payload: payload_for(kind, targets),
            denominator: TargetDenominator {
                mode: AtomicityMode::PerMember,
                members: denom.iter().map(|item| (*item).to_owned()).collect(),
                expected_total: u32::try_from(denom.len()).expect("denominator fits u32"),
            },
            source_digest: "1".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            job_digest: "2".repeat(64),
            requester: Requester {
                origin: eliot_dreamer_contracts::job::RequesterOrigin::Human,
                principal: "op-1".to_owned(),
                session: None,
            },
            budget_note: "within budget".to_owned(),
        }
    }

    fn test_screen(targets: &[&str]) -> ScreenBinding {
        ScreenBinding {
            request_id: RequestId::new("req-1").expect("request id"),
            receipt_id: ReceiptId::new("rcpt-1").expect("receipt id"),
            screened_targets: targets.iter().map(|item| (*item).to_owned()).collect(),
            source_snapshot: "snap-1".to_owned(),
            source_revision: "rev-1".to_owned(),
            profile: "default".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            state: ScreenState::Eligible,
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
        }
    }

    fn descriptor_for(family: CurationFamily) -> CurationHandlerDescriptor {
        CurationHandlerDescriptor {
            family,
            handler_id: std::format!("h-{}", family.as_str()),
            accepted_kinds: eliot_dreamer_contracts::registry::family_kinds(family).to_vec(),
        }
    }

    fn full_registry() -> CurationHandlerRegistry {
        let mut registry = CurationHandlerRegistry::new();
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            registry
                .register(descriptor_for(family))
                .expect("fixture descriptor");
        }
        registry
    }

    #[derive(Debug)]
    enum StubBehavior {
        Echo(CandidateDisposition),
        TamperKind,
    }

    struct CountingHandler {
        descriptor: CurationHandlerDescriptor,
        calls: Cell<usize>,
        behavior: StubBehavior,
        counterevidence_refs: Vec<String>,
        seen_call: RefCell<Option<BoundCurationCall>>,
        seen_content: RefCell<Option<ProducedCurationContent>>,
    }

    impl CountingHandler {
        fn echoing(family: CurationFamily, disposition: CandidateDisposition) -> Self {
            Self {
                descriptor: descriptor_for(family),
                calls: Cell::new(0),
                behavior: StubBehavior::Echo(disposition),
                counterevidence_refs: Vec::new(),
                seen_call: RefCell::new(None),
                seen_content: RefCell::new(None),
            }
        }

        fn tampering_kind(family: CurationFamily) -> Self {
            Self {
                descriptor: descriptor_for(family),
                calls: Cell::new(0),
                behavior: StubBehavior::TamperKind,
                counterevidence_refs: Vec::new(),
                seen_call: RefCell::new(None),
                seen_content: RefCell::new(None),
            }
        }

        fn echoing_with_counterevidence(
            family: CurationFamily,
            disposition: CandidateDisposition,
            counterevidence_refs: Vec<String>,
        ) -> Self {
            Self {
                descriptor: descriptor_for(family),
                calls: Cell::new(0),
                behavior: StubBehavior::Echo(disposition),
                counterevidence_refs,
                seen_call: RefCell::new(None),
                seen_content: RefCell::new(None),
            }
        }
    }

    fn passing_report() -> eliot_dreamer_contracts::PreservationReport {
        eliot_dreamer_contracts::PreservationReport {
            verdicts: eliot_dreamer_contracts::PRESERVATION_DIMENSIONS
                .iter()
                .map(
                    |dimension| eliot_dreamer_contracts::candidate::DimensionVerdict {
                        dimension: eliot_dreamer_contracts::PreservationDimension::parse(dimension)
                            .expect("known preservation dimension"),
                        passed: true,
                        known: true,
                        note: std::format!("{dimension} holds"),
                    },
                )
                .collect(),
        }
    }

    impl NativeCurationHandler for CountingHandler {
        fn handle(
            &self,
            call: &BoundCurationCall,
        ) -> Result<ProducedCurationContent, eliot_dreamer_contracts::ContractViolation> {
            self.calls.set(self.calls.get().saturating_add(1));
            if call.port.descriptor != self.descriptor {
                return Err(
                    eliot_dreamer_contracts::ContractViolation::BindingMismatch {
                        field: "handler_descriptor",
                        reason: "double observed an unselected binding".to_owned(),
                    },
                );
            }
            let content = match &self.behavior {
                StubBehavior::Echo(disposition) => ProducedCurationContent {
                    payload: call.request.payload.clone(),
                    disposition: *disposition,
                    preservation: passing_report(),
                    support_note: "supported by source-b".to_owned(),
                    rollback_note: "drop result to roll back".to_owned(),
                    counterevidence_refs: self.counterevidence_refs.clone(),
                },
                StubBehavior::TamperKind => ProducedCurationContent {
                    payload: eliot_dreamer_contracts::CurationPayload::Split(SplitPayload {
                        whole: "ab".to_owned(),
                        first: "a".to_owned(),
                        second: "b".to_owned(),
                        target_evidence: TargetEvidence {
                            targets: vec!["a".to_owned(), "b".to_owned(), "ab".to_owned()],
                            evidence_refs: vec!["e-1".to_owned()],
                        },
                    }),
                    disposition: CandidateDisposition::Candidate,
                    preservation: passing_report(),
                    support_note: "supported by source-b".to_owned(),
                    rollback_note: "drop result to roll back".to_owned(),
                    counterevidence_refs: Vec::new(),
                },
            };
            self.seen_call.replace(Some(call.clone()));
            self.seen_content.replace(Some(content.clone()));
            Ok(content)
        }
    }

    fn test_handlers() -> Vec<CountingHandler> {
        CURATION_FAMILIES
            .iter()
            .map(|spelling| {
                let family = parse_family(spelling).expect("known family");
                CountingHandler::echoing(family, CandidateDisposition::Candidate)
            })
            .collect()
    }

    fn test_ports<'a>(
        handlers: &'a [CountingHandler],
        registry: &CurationHandlerRegistry,
    ) -> NativeCurationPortSet<'a> {
        let ports = handlers
            .iter()
            .map(|handler| {
                let family = handler.descriptor.family;
                let declared = registry
                    .handlers
                    .iter()
                    .find(|item| item.family == family)
                    .expect("registry declares the family");
                NativeCurationPort {
                    port: CurationHandlerPort {
                        port_id: std::format!("port-{}", family.as_str()),
                        descriptor: declared.clone(),
                    },
                    owner_package: expected_owner_package(family).to_owned(),
                    owner_revision: "rev-1".to_owned(),
                    handler,
                }
            })
            .collect();
        NativeCurationPortSet { ports }
    }

    fn test_policy(allow_partial: bool) -> RoutingPolicy {
        RoutingPolicy {
            policy_id: "routing-policy-1".to_owned(),
            policy_revision: 1,
            allow_partial,
            max_items: u32::try_from(MAX_BATCH_ITEMS).expect("batch bound fits u32"),
        }
    }

    fn test_budgets() -> (BudgetLimits, BudgetUsage) {
        (
            BudgetLimits {
                input_bytes: Some(4096),
                output_bytes: Some(4096),
                source_width: Some(16),
                reference_width: Some(16),
                model_calls: Some(8),
                attempts: Some(8),
                candidates: Some(8),
                wall_ms: Some(1000),
                work_fan_out: Some(8),
                report_bytes: Some(4096),
                max_stu: Some(100),
            },
            BudgetUsage::default(),
        )
    }

    fn test_pins() -> Vec<OwnerRevisionPin> {
        CURATION_FAMILIES
            .iter()
            .map(|spelling| OwnerRevisionPin {
                family: parse_family(spelling).expect("known family"),
                revision: "rev-1".to_owned(),
            })
            .collect()
    }

    fn seal_batch(
        items: Vec<ValidatedCurationItem>,
        denom: &[&str],
        atomicity: AtomicityMode,
        screen: &ScreenBinding,
        registry: &CurationHandlerRegistry,
        policy: &RoutingPolicy,
    ) -> ValidatedCurationBatch {
        let (budgets, usage) = test_budgets();
        let mut batch = ValidatedCurationBatch {
            job_id: "job-1".to_owned(),
            request_id: "req-1".to_owned(),
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            requester: Requester {
                origin: eliot_dreamer_contracts::job::RequesterOrigin::Human,
                principal: "op-1".to_owned(),
                session: None,
            },
            task_id: "task-1".to_owned(),
            attempt: 1,
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            grounding_digest: "d".repeat(64),
            receipt: test_receipt(),
            items,
            denominator: TargetDenominator {
                mode: atomicity,
                members: denom.iter().map(|item| (*item).to_owned()).collect(),
                expected_total: u32::try_from(denom.len()).expect("denominator fits u32"),
            },
            privacy_profile: "local_only".to_owned(),
            authority_ref: "epoch-genesis".to_owned(),
            effect_note: "routing exercises no effect".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            atomicity,
            budgets,
            usage,
            deadline_ms: None,
            observation_time_ms: None,
            cancelled: false,
            predecessor_digests: Vec::new(),
            invalidation_note: "no invalidation".to_owned(),
            registry_digest: registry.digest().expect("closed registry"),
            owner_pins: test_pins(),
            input_digest: "0".repeat(64),
        };
        let digest = compute_input_digest(&batch, screen, &batch.registry_digest, policy)
            .expect("sealed input digest");
        batch.input_digest = digest;
        batch
    }

    fn calls_for(handlers: &[CountingHandler], family: CurationFamily) -> usize {
        handlers
            .iter()
            .find(|item| item.descriptor.family == family)
            .expect("handler exists")
            .calls
            .get()
    }

    fn drift_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
                .expect("canonical test lineage-B"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    // H1-ORDER: the hub-native binding invokes the selected owner exactly
    // once and seals its full result content.
    #[test]
    fn h1_native_binding_invokes_selected_owner_once_with_full_content() {
        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![test_item(CurationKind::Classification, &["a"], &["a"])],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("eligible classification routes through the hub binding");
        assert_eq!(set.members.len(), 1);
        let member = &set.members[0];
        assert_eq!(member.disposition, RoutingDisposition::Candidate);
        assert_eq!(member.calls, 1);
        assert_eq!(set.accepted, 1);
        assert_eq!(set.total_handler_calls, 1);
        let owner = handlers
            .iter()
            .find(|item| item.descriptor.family == CurationFamily::Classification)
            .expect("classification double exists");
        assert_eq!(owner.calls.get(), 1);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            if family != CurationFamily::Classification {
                assert_eq!(calls_for(&handlers, family), 0);
            }
        }
        // The double observed the frozen hub call view bound to the registry.
        let call = owner.seen_call.borrow();
        let call = call
            .as_ref()
            .expect("selected owner observed one bound call");
        assert_eq!(call.port.port_id, "port-classification");
        assert_eq!(call.port.descriptor, owner.descriptor);
        assert_eq!(call.item, batch.items[0]);
        assert_eq!(call.request.kind, CurationKind::Classification);
        assert_eq!(call.request.family, CurationFamily::Classification);
        assert_eq!(call.request.payload, batch.items[0].payload);
        assert_eq!(
            call.registry_digest,
            registry.digest().expect("closed registry digests")
        );
        // The double produced full typed content, not a digest alone.
        let content = owner.seen_content.borrow();
        let content = content
            .as_ref()
            .expect("selected owner produced full content");
        assert_eq!(content.payload, batch.items[0].payload);
        assert_eq!(content.disposition, CandidateDisposition::Candidate);
        assert!(content.preservation.overall().is_ok());
        assert!(content.counterevidence_refs.is_empty());
        // Member digests bind the exact frozen call and the sealed content.
        assert_eq!(
            member.request_digest.as_deref(),
            Some(
                request_digest_of(&call.request)
                    .expect("request digests")
                    .as_str()
            )
        );
        let mut expected = FullCurationResult {
            request_id: call.request.request_id.clone(),
            job_id: call.request.job_id.clone(),
            scope_id: call.request.scope_id.clone(),
            task_id: call.request.task_id.clone(),
            kind: call.request.kind,
            family: call.request.family,
            handler_id: call.port.descriptor.handler_id.clone(),
            port_id: call.port.port_id.clone(),
            registry_digest: call.registry_digest.clone(),
            state_fence: batch.items[0].state_fence.clone(),
            request_digest: request_digest_of(&call.request).expect("request digests"),
            result_digest: String::new(),
            content: content.clone(),
        };
        expected.result_digest = expected
            .computed_result_digest()
            .expect("sealed digest recomputes");
        expected.validate().expect("rebuilt seal validates");
        assert_eq!(
            member.result_digest.as_deref(),
            Some(expected.result_digest.as_str())
        );
        set.validate().expect("emitted set validates");
    }

    // H1-ORDER: altered item, fence, and binding drift fail closed with zero
    // or exactly-once handler calls proving the check order.
    #[test]
    fn h1_altered_item_fence_and_binding_fail_closed() {
        // Altered item identity fails intrinsic validation before dispatch:
        // the member is blocked with zero handler calls.
        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let mut altered = test_item(CurationKind::Classification, &["a"], &["a"]);
        altered.kind_spelling = "merge".to_owned();
        let batch = seal_batch(
            vec![altered],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("altered item routes to a blocked member");
        assert_eq!(set.members.len(), 1);
        assert_eq!(set.members[0].disposition, RoutingDisposition::Blocked);
        assert_eq!(set.members[0].calls, 0);
        assert_eq!(set.total_handler_calls, 0);
        for handler in &handlers {
            assert_eq!(handler.calls.get(), 0, "no handler runs for a blocked item");
        }

        // Fence drift between the item and the batch fails the batch closed
        // before any handler call.
        let mut drifted = test_item(CurationKind::Classification, &["a"], &["a"]);
        drifted.state_fence = drift_fence();
        let batch = seal_batch(
            vec![drifted],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let err = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect_err("fence drift must fail");
        assert!(
            matches!(
                err,
                CurationRoutingError::Binding {
                    field: "state_fence",
                    ..
                }
            ),
            "expected a state_fence binding failure, got {err:?}"
        );
        for handler in &handlers {
            assert_eq!(handler.calls.get(), 0, "no handler runs on fence drift");
        }

        // A live port carrying a valid but unregistered descriptor fails the
        // port binding with zero handler calls.
        let batch = seal_batch(
            vec![test_item(CurationKind::Classification, &["a"], &["a"])],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let mut rogue_ports = test_ports(&handlers, &registry);
        rogue_ports.ports[0].port.descriptor.handler_id = "rogue-owner".to_owned();
        let err = route_validated_curation(&batch, &screen, &registry, &policy, &rogue_ports)
            .expect_err("unregistered descriptor must fail");
        assert!(
            matches!(err, CurationRoutingError::Port { .. }),
            "expected a port failure, got {err:?}"
        );
        for handler in &handlers {
            assert_eq!(handler.calls.get(), 0, "no handler runs on port drift");
        }
    }

    // H1-ORDER: mutable-target versus immutable-evidence roles are rejected
    // before dispatch, and counterevidence naming a mutable target is
    // rejected after exactly one handler call.
    #[test]
    fn h1_evidence_target_roles_rejected_pre_and_post_call() {
        // An immutable evidence handle promoted to a mutable target never
        // dispatches: blocked with zero handler calls.
        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let mut promoted = test_item(CurationKind::Classification, &["a"], &["a"]);
        if let eliot_dreamer_contracts::CurationPayload::Classification(inner) =
            &mut promoted.payload
        {
            inner.target_evidence.targets.push("e-1".to_owned());
        } else {
            panic!("classification fixture carries a classification payload");
        }
        let batch = seal_batch(
            vec![promoted],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("evidence-as-target routes to a blocked member");
        assert_eq!(set.members.len(), 1);
        assert_eq!(set.members[0].disposition, RoutingDisposition::Blocked);
        assert_eq!(set.members[0].calls, 0);
        assert_eq!(
            set.members[0].rejection_hint,
            routing_rejection_hint(RoutingDisposition::Blocked)
        );
        for handler in &handlers {
            assert_eq!(
                handler.calls.get(),
                0,
                "no handler runs for evidence-as-target"
            );
        }

        // Counterevidence naming a mutable target runs the selected handler
        // once; the hub content check then rejects its output terminally with
        // no sibling call.
        let counter_handlers: Vec<CountingHandler> = CURATION_FAMILIES
            .iter()
            .map(|spelling| {
                let family = parse_family(spelling).expect("known family");
                if family == CurationFamily::StructureRepair {
                    CountingHandler::echoing_with_counterevidence(
                        family,
                        CandidateDisposition::Candidate,
                        vec!["a".to_owned()],
                    )
                } else {
                    CountingHandler::echoing(family, CandidateDisposition::Candidate)
                }
            })
            .collect();
        let counter_ports = test_ports(&counter_handlers, &registry);
        let batch = seal_batch(
            vec![test_item(
                CurationKind::Merge,
                &["a", "b", "ab"],
                &["a", "b", "ab"],
            )],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let err = route_validated_curation(&batch, &screen, &registry, &policy, &counter_ports)
            .expect_err("counterevidence-as-target must fail");
        assert!(
            matches!(err, CurationRoutingError::Envelope { .. }),
            "expected a terminal envelope failure, got {err:?}"
        );
        assert_eq!(
            calls_for(&counter_handlers, CurationFamily::StructureRepair),
            1,
            "the selected port is called once before its content fails"
        );
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            if family != CurationFamily::StructureRepair {
                assert_eq!(
                    calls_for(&counter_handlers, family),
                    0,
                    "no sibling handler runs after a content rejection"
                );
            }
        }
    }

    // WORK_UNIT_CASE: 684/1
    #[test]
    fn work_unit_684_1_classification_routes_to_classification_owner() {
        use eliot_dreamer_contracts::CURATION_WIRE_KINDS;
        assert_eq!(CURATION_WIRE_KINDS.len(), 11);
        assert_eq!(CURATION_FAMILIES.len(), 10);
        assert_eq!(
            family_of(CurationKind::Classification),
            CurationFamily::Classification
        );
        assert_eq!(
            family_of(CurationKind::Merge),
            family_of(CurationKind::Split)
        );
        assert_eq!(
            family_of(CurationKind::Merge),
            CurationFamily::StructureRepair
        );
        assert_eq!(
            family_of(CurationKind::Repair),
            CurationFamily::MemoryRepair
        );

        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![test_item(CurationKind::Classification, &["a"], &["a"])],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("eligible classification routes");
        assert_eq!(set.members.len(), 1);
        let member = &set.members[0];
        assert_eq!(member.kind, CurationKind::Classification);
        assert_eq!(member.family, CurationFamily::Classification);
        assert_eq!(member.handler_id, "h-classification");
        assert_eq!(member.disposition, RoutingDisposition::Candidate);
        assert_eq!(member.calls, 1);
        assert_eq!(set.accepted, 1);
        assert_eq!(set.total_handler_calls, 1);
        assert_eq!(calls_for(&handlers, CurationFamily::Classification), 1);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            if family != CurationFamily::Classification {
                assert_eq!(calls_for(&handlers, family), 0);
            }
        }
        set.validate().expect("emitted set validates");
    }

    // WORK_UNIT_CASE: 684/7
    #[test]
    fn work_unit_684_7_merge_and_split_share_structure_repair_owner_distinct() {
        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![
                test_item(CurationKind::Merge, &["a", "b", "ab"], &["a", "b", "ab"]),
                test_item(CurationKind::Split, &["a", "b", "ab"], &["a", "b", "ab"]),
            ],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("merge and split route");
        assert_eq!(set.members.len(), 2);
        assert_eq!(set.members[0].kind, CurationKind::Merge);
        assert_eq!(set.members[1].kind, CurationKind::Split);
        assert_ne!(set.members[0].member_id, set.members[1].member_id);
        for member in &set.members {
            assert_eq!(member.family, CurationFamily::StructureRepair);
            assert_eq!(member.handler_id, "h-structure_repair");
            assert_eq!(member.disposition, RoutingDisposition::Candidate);
            assert_eq!(member.calls, 1);
        }
        assert_eq!(calls_for(&handlers, CurationFamily::StructureRepair), 2);
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            if family != CurationFamily::StructureRepair {
                assert_eq!(calls_for(&handlers, family), 0);
            }
        }
        assert_eq!(set.accepted, 2);
        assert_eq!(set.total_handler_calls, 2);
        set.validate().expect("emitted set validates");
    }

    // WORK_UNIT_CASE: 684/15
    #[test]
    fn work_unit_684_15_complete_ten_owner_registry_closes() {
        let registry = full_registry();
        assert_eq!(registry.handlers.len(), EXPECTED_OWNER_DESCRIPTORS);
        registry.validate_closure().expect("ten owners close");
        let mut reversed = CurationHandlerRegistry::new();
        for handler in registry.handlers.iter().rev().cloned() {
            reversed.register(handler).expect("fixture descriptor");
        }
        assert_eq!(
            registry.digest().expect("digest"),
            reversed.digest().expect("permutation-stable digest")
        );

        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);

        let mut partial = CurationHandlerRegistry::new();
        for handler in registry.handlers.iter().take(9).cloned() {
            partial.register(handler).expect("fixture descriptor");
        }
        let batch = seal_batch(
            vec![test_item(CurationKind::Classification, &["a"], &["a"])],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let missing = route_validated_curation(&batch, &screen, &partial, &policy, &ports);
        assert!(
            matches!(missing, Err(CurationRoutingError::Registry { .. })),
            "missing kind coverage fails closed"
        );

        let mut overlapping = full_registry();
        overlapping
            .handlers
            .push(descriptor_for(CurationFamily::Relation));
        let overlap = route_validated_curation(&batch, &screen, &overlapping, &policy, &ports);
        assert!(
            matches!(overlap, Err(CurationRoutingError::Registry { .. })),
            "overlapping coverage fails closed"
        );
        for handler in &handlers {
            assert_eq!(
                handler.calls.get(),
                0,
                "no handler runs on registry failure"
            );
        }
    }

    // WORK_UNIT_CASE: 684/22
    #[test]
    fn work_unit_684_22_protected_target_invokes_zero_handlers() {
        let registry = full_registry();
        let handlers = test_handlers();
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![
                test_item(CurationKind::Classification, &["a"], &["a"]),
                test_item(CurationKind::Repair, &["zz"], &["zz"]),
            ],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &policy, &ports)
            .expect("partial route preserves the eligible member");
        assert_eq!(set.members.len(), 2);
        assert_eq!(set.members[0].disposition, RoutingDisposition::Candidate);
        assert_eq!(set.members[0].calls, 1);
        assert_eq!(set.members[1].disposition, RoutingDisposition::Blocked);
        assert_eq!(set.members[1].calls, 0);
        assert_eq!(set.members[1].handler_id, "family:memory_repair");
        assert_eq!(set.accepted, 1);
        assert_eq!(set.blocked, 1);
        assert_eq!(set.total_handler_calls, 1);
        assert_eq!(calls_for(&handlers, CurationFamily::Classification), 1);
        assert_eq!(calls_for(&handlers, CurationFamily::MemoryRepair), 0);
        set.validate().expect("emitted set validates");
    }

    // WORK_UNIT_CASE: 684/44
    #[test]
    fn work_unit_684_44_returned_kind_family_mismatch_is_terminal() {
        let registry = full_registry();
        let mut handlers = test_handlers();
        for handler in &mut handlers {
            if handler.descriptor.family == CurationFamily::StructureRepair {
                *handler = CountingHandler::tampering_kind(CurationFamily::StructureRepair);
            }
        }
        let ports = test_ports(&handlers, &registry);
        let policy = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![test_item(
                CurationKind::Merge,
                &["a", "b", "ab"],
                &["a", "b", "ab"],
            )],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        );
        let failed = route_validated_curation(&batch, &screen, &registry, &policy, &ports);
        assert!(
            matches!(failed, Err(CurationRoutingError::Envelope { .. })),
            "returned kind and family drift is a terminal envelope defect"
        );
        assert_eq!(
            calls_for(&handlers, CurationFamily::StructureRepair),
            1,
            "the selected port is called once before its envelope fails"
        );
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).expect("known family");
            if family != CurationFamily::StructureRepair {
                assert_eq!(
                    calls_for(&handlers, family),
                    0,
                    "no sibling handler runs after an envelope mismatch"
                );
            }
        }
    }

    // WORK_UNIT_CASE: 684/52
    #[test]
    fn work_unit_684_52_explicit_partial_counts_frontier_and_determinism() {
        let registry = full_registry();
        let mut handlers = test_handlers();
        for handler in &mut handlers {
            if handler.descriptor.family == CurationFamily::Accessibility {
                *handler = CountingHandler::echoing(
                    CurationFamily::Accessibility,
                    CandidateDisposition::Unsupported,
                );
            }
        }
        let ports = test_ports(&handlers, &registry);
        let partial = test_policy(true);
        let screen = test_screen(&["a", "b", "ab"]);
        let batch = seal_batch(
            vec![
                test_item(CurationKind::Classification, &["a"], &["a"]),
                test_item(CurationKind::Accessibility, &["a"], &["a"]),
                test_item(CurationKind::Repair, &["zz"], &["zz"]),
            ],
            &["a", "b", "ab"],
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &partial,
        );
        let set = route_validated_curation(&batch, &screen, &registry, &partial, &ports)
            .expect("explicit partial retains every member");
        assert_eq!(set.members.len(), 3);
        assert_eq!(set.members[0].disposition, RoutingDisposition::Candidate);
        assert_eq!(set.members[1].disposition, RoutingDisposition::Unsupported);
        assert_eq!(set.members[2].disposition, RoutingDisposition::Blocked);
        assert_eq!(
            (set.accepted, set.rejected, set.blocked, set.unprocessed),
            (1, 1, 1, 0)
        );
        assert!(set.unprocessed_frontier.is_empty());
        assert_eq!(set.omitted_targets, vec!["ab".to_owned(), "b".to_owned()]);
        assert_eq!(set.total_handler_calls, 2);
        let mut ids: Vec<&str> = set
            .members
            .iter()
            .map(|member| member.member_id.as_str())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3, "every member carries one disposition");
        set.validate().expect("emitted set validates");

        let again = route_validated_curation(&batch, &screen, &registry, &partial, &ports)
            .expect("replay routes");
        assert_eq!(set.set_digest, again.set_digest, "replay is deterministic");

        let strict = test_policy(false);
        let strict_screen = test_screen(&["a", "b"]);
        let strict_batch = seal_batch(
            vec![
                test_item(CurationKind::Classification, &["a"], &["a"]),
                test_item(CurationKind::Accessibility, &["b"], &["b"]),
            ],
            &["a", "b"],
            AtomicityMode::AllOrNothing,
            &strict_screen,
            &registry,
            &strict,
        );
        let strict_ports = test_ports(&handlers, &registry);
        let refused = route_validated_curation(
            &strict_batch,
            &strict_screen,
            &registry,
            &strict,
            &strict_ports,
        );
        assert!(
            matches!(refused, Err(CurationRoutingError::Atomicity { .. })),
            "all-or-nothing reports no applied-looking subset"
        );
    }
}
