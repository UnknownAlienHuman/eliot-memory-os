//! Canonical problem-owner-state wire contract (issue #1759 I2, I13.9/I13.7).
//!
//! This module owns the serialization-only wire boundary for the named
//! owner transitions `create`, `update`, `assign`, `unassign`, `escalate`,
//! `resolve`, `waive`, `supersede`, `reopen` and `quarantine`. It contains no problem
//! domain model and no transition logic: the pure state machines
//! (`eliot_problem::Problem`) own the typed record and its fail-closed
//! candidate-copy transitions, the Governor prepares the one
//! `PreparedTransition`, and the store bridge executes exactly that plan.
//! Wire shapes stay serialization-only and never become a second semantic
//! model.
//!
//! The verbs are *named* on the wire, not spelled as one generic
//! mutation: a caller that can write `REOPEN` cannot write the same change as
//! `UPDATE`, because the discriminator is part of the canonical request hash and
//! the recorded record must satisfy the identity, predecessor revision and
//! source-Signal bindings that verb implies.
//!
//! Wire identity: [`PROBLEM_OWNER_STATE_SCHEMA_V1`]
//! (`eliot.problem.owner-state.v1`). Mutation operation:
//! [`PROBLEM_OWNER_STATE_MUTATION_NAME`] (`ApplyProblemOwnerState`). Read
//! operation: `GetAttentionAndProblems`, the existing committed-only
//! attention/problem projection. Transition class: `RecoverySchema` with a
//! `ReversibleMutation` ceiling.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{NamedMutationOperation, NamedMutationRequest, StoreError};

/// Versioned wire/schema identity for canonical problem owner state.
pub const PROBLEM_OWNER_STATE_SCHEMA_V1: &str = "eliot.problem.owner-state.v1";
/// Closed mutation operation name for the named owner transitions.
///
/// The wire spelling of [`NamedMutationOperation::ApplyProblemOwnerState`],
/// named here so the contract, the catalogue row and the closed name table all
/// have one stated spelling to agree on.
pub const PROBLEM_OWNER_STATE_MUTATION_NAME: &str = "ApplyProblemOwnerState";

/// Named transition discriminator. Part of the canonical request hash, so one
/// change can never be replayed under another verb.
pub const PROBLEM_PARAM_TRANSITION: &str = "transition";
/// Problem record identity, and the revision-head key suffix.
pub const PROBLEM_PARAM_PROBLEM_ID: &str = "problem_id";
/// The record revision the transition expects to replace, as its decimal
/// string. This is the compare-and-swap value the store checks against the live
/// revision head; it is never an assertion the bridge takes on trust.
pub const PROBLEM_PARAM_EXPECTED_REVISION: &str = "expected_problem_revision";
/// Identity of the Signal this transition is bound to.
pub const PROBLEM_PARAM_SOURCE_SIGNAL_ID: &str = "source_signal_id";
/// Lowercase SHA-256 over the re-proved current authorization.
pub const PROBLEM_PARAM_AUTHORIZATION_DIGEST: &str = "authorization_digest";
/// Lowercase SHA-256 over the canonical candidate record bytes.
pub const PROBLEM_PARAM_RECORD_DIGEST: &str = "record_digest";
/// The complete canonical candidate Problem record.
pub const PROBLEM_PARAM_RECORD_JSON: &str = "record_json";
/// The retained closure record a `WAIVE`, `SUPERSEDE` or `QUARANTINE`
/// transition commits.
///
/// `Problem` carries no waiver, supersession or source-restriction record, so
/// the committed transition is where all three closures are durable. It is
/// present for exactly those three verbs and absent for every other one, so a
/// retained record can never be attached to a transition that did not produce
/// one.
pub const PROBLEM_PARAM_CLOSURE_JSON: &str = "closure_json";

/// The retained closure record a `QUARANTINE` transition commits.
///
/// `Problem` carries no source-restriction record, so the committed transition
/// is where an admitted quarantine is durable. It is present for exactly the
/// three closing verbs and absent for every other one, so a retained
/// restriction can never be attached to a transition that did not produce one.
pub const PROBLEM_CLOSURE_QUARANTINED_FOR_REBUILD: &str = "SOURCE_QUARANTINE";

/// `closure_json.kind` for an accepted risk.
pub const PROBLEM_CLOSURE_WAIVED: &str = "WAIVED";
/// `closure_json.kind` for a supersession.
pub const PROBLEM_CLOSURE_SUPERSEDED_BY: &str = "SUPERSEDED_BY";

/// Wire value of the `create` transition.
pub const PROBLEM_TRANSITION_CREATE: &str = "CREATE";
/// Wire value of the `update` transition.
pub const PROBLEM_TRANSITION_UPDATE: &str = "UPDATE";
/// Wire value of the `assign` transition.
pub const PROBLEM_TRANSITION_ASSIGN: &str = "ASSIGN";
/// Wire value of the `unassign` transition.
pub const PROBLEM_TRANSITION_UNASSIGN: &str = "UNASSIGN";
/// Wire value of the `escalate` transition.
pub const PROBLEM_TRANSITION_ESCALATE: &str = "ESCALATE";
/// Wire value of the `resolve` transition.
pub const PROBLEM_TRANSITION_RESOLVE: &str = "RESOLVE";
/// Wire value of the `waive` transition.
pub const PROBLEM_TRANSITION_WAIVE: &str = "WAIVE";
/// Wire value of the `supersede` transition.
pub const PROBLEM_TRANSITION_SUPERSEDE: &str = "SUPERSEDE";
/// Wire value of the `reopen` transition.
pub const PROBLEM_TRANSITION_REOPEN: &str = "REOPEN";
/// Wire value of the `quarantine` transition.
///
/// A tenth named verb, added with issue #1760 item 5: an external-source
/// restriction is admitted as its own transition rather than as an ordinary
/// advance, because it is committed with a retained restriction record and
/// under a deterministic-rule-or-authorized-decision authority that no other
/// verb can name.
pub const PROBLEM_TRANSITION_QUARANTINE: &str = "QUARANTINE";

/// `ProblemState::Quarantined` as the wire spelling the candidate record uses.
///
/// Declared here so the verb check compares against a named spelling rather
/// than an inline literal that could drift from the state machine's own
/// `snake_case` serialization.
pub const PROBLEM_STATE_QUARANTINED: &str = "quarantined";

/// The closed I13.9 owner-transition verb set.
///
/// Ten variants, one per named transition. The set is closed: an eleventh verb
/// would be a further contract change, and an existing verb cannot be reused for
/// another verb's state change because the candidate record is checked against
/// the bindings that verb carries. The tenth verb, `quarantine`, is the
/// owner-bound admission of an external-source restriction; it is named rather
/// than folded into `update` because it commits a retained restriction record
/// and is authorized by a deterministic rule or an authorized decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemOwnerTransition {
    /// Open a new Problem at revision 1 from an admitting Signal.
    Create,
    /// Advance the declared non-terminal lifecycle of a Problem.
    Update,
    /// Assign an eligible successor under a newly issued ownership lease.
    Assign,
    /// Record a fenced owner loss and leave the obligation visible.
    Unassign,
    /// Escalate the outstanding reassignment/escalation obligation.
    Escalate,
    /// Resolve against the independently expected observable set.
    Resolve,
    /// Accept risk under an authorized, scoped, expiring waiver.
    Waive,
    /// Reach `superseded` under an accepted replacement obligation.
    Supersede,
    /// Reopen a terminal Problem against actual recurrence evidence.
    Reopen,
    /// Quarantine the bounded affected scope of an admitted source
    /// restriction, under a deterministic rule or an authorized decision.
    Quarantine,
}

impl ProblemOwnerTransition {
    /// The closed wire name of this transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => PROBLEM_TRANSITION_CREATE,
            Self::Update => PROBLEM_TRANSITION_UPDATE,
            Self::Assign => PROBLEM_TRANSITION_ASSIGN,
            Self::Unassign => PROBLEM_TRANSITION_UNASSIGN,
            Self::Escalate => PROBLEM_TRANSITION_ESCALATE,
            Self::Resolve => PROBLEM_TRANSITION_RESOLVE,
            Self::Waive => PROBLEM_TRANSITION_WAIVE,
            Self::Supersede => PROBLEM_TRANSITION_SUPERSEDE,
            Self::Reopen => PROBLEM_TRANSITION_REOPEN,
            Self::Quarantine => PROBLEM_TRANSITION_QUARANTINE,
        }
    }

    /// Resolves a wire name to its transition, or refuses an unknown verb.
    ///
    /// Closed: the names below are the whole set, so another verb is a
    /// contract change here and never a value that happens to decode.
    #[must_use]
    pub const fn by_name(name: &str) -> Option<Self> {
        match name.as_bytes() {
            b"CREATE" => Some(Self::Create),
            b"UPDATE" => Some(Self::Update),
            b"ASSIGN" => Some(Self::Assign),
            b"UNASSIGN" => Some(Self::Unassign),
            b"ESCALATE" => Some(Self::Escalate),
            b"RESOLVE" => Some(Self::Resolve),
            b"WAIVE" => Some(Self::Waive),
            b"SUPERSEDE" => Some(Self::Supersede),
            b"REOPEN" => Some(Self::Reopen),
            b"QUARANTINE" => Some(Self::Quarantine),
            _ => None,
        }
    }
}

/// The closed decoded owner-state mutation: one named transition plus the four
/// bindings every transition carries.
///
/// The bindings are decoded, not merely transported: [`decode_problem_owner_state_mutation`]
/// compares the candidate record's own identity, predecessor revision and
/// source-Signal list against the presented bindings, so a record that names a
/// different Problem, claims a revision other than the one it replaces, or is
/// bound to a different Signal is refused at the bridge before any write.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedProblemOwnerState {
    /// The named transition this leg commits.
    pub transition: ProblemOwnerTransition,
    /// Problem record identity.
    pub problem_id: String,
    /// The record revision this transition expects to replace.
    pub expected_revision: u64,
    /// Identity of the Signal this transition is bound to.
    pub source_signal_id: String,
    /// Lowercase SHA-256 over the re-proved current authorization.
    pub authorization_digest: String,
    /// Lowercase SHA-256 over the canonical candidate record bytes.
    pub record_digest: String,
    /// The complete canonical candidate Problem record.
    pub record_json: Value,
    /// The retained closure record, present for exactly `WAIVE`, `SUPERSEDE`
    /// and `QUARANTINE`.
    pub closure_json: Option<Value>,
}

impl DecodedProblemOwnerState {
    /// The revision the candidate record must carry for this transition.
    ///
    /// Every transition except `CREATE` replaces exactly one committed revision,
    /// so its candidate must be the checked successor — this is the local half
    /// of the compare-and-swap, and the store half is the revision-head
    /// expectation the same value is carried on. `CREATE` replaces no
    /// predecessor, so its candidate must be the genesis revision and its
    /// expectation is the absent-or-genesis head the store's own CAS already
    /// treats as revision one. A successor that would overflow is refused rather
    /// than wrapped, so a transition can never reuse a revision.
    #[must_use]
    pub const fn required_record_revision(&self) -> Option<u64> {
        match self.transition {
            ProblemOwnerTransition::Create => Some(1),
            ProblemOwnerTransition::Update
            | ProblemOwnerTransition::Assign
            | ProblemOwnerTransition::Unassign
            | ProblemOwnerTransition::Escalate
            | ProblemOwnerTransition::Resolve
            | ProblemOwnerTransition::Waive
            | ProblemOwnerTransition::Supersede
            | ProblemOwnerTransition::Reopen
            | ProblemOwnerTransition::Quarantine => match self.expected_revision.checked_add(1) {
                Some(revision) => Some(revision),
                None => None,
            },
        }
    }

    /// Whether the candidate record satisfies every binding this transition
    /// carries.
    ///
    /// The record is the lossless statement of what the transition produced, so
    /// the bridge compares the record against the presented bindings rather than
    /// recording both and trusting that they agree.
    pub fn record_satisfies_bindings(&self) -> Result<(), StoreError> {
        let Some(required) = self.required_record_revision() else {
            return Err(StoreError::InvalidField {
                field: "expected_problem_revision",
                reason: "record revision overflow: refusing to reuse a revision",
            });
        };
        let record = &self.record_json;
        if record.get("problem_id").and_then(Value::as_str) != Some(self.problem_id.as_str()) {
            return Err(StoreError::InvalidField {
                field: "record_json.problem_id",
                reason: "candidate record does not carry the presented problem identity",
            });
        }
        match record.get("revision").and_then(Value::as_u64) {
            Some(revision) if revision == required => {}
            _ => {
                return Err(StoreError::InvalidField {
                    field: "record_json.revision",
                    reason: "candidate record is not the checked successor of the expected revision",
                });
            }
        }
        let bound = record.get("signal_refs").and_then(Value::as_array).ok_or(
            StoreError::InvalidField {
                field: "record_json.signal_refs",
                reason: "candidate record must retain its source Signal identities",
            },
        )?;
        if !bound
            .iter()
            .any(|value| value.as_str() == Some(self.source_signal_id.as_str()))
        {
            return Err(StoreError::InvalidField {
                field: "record_json.signal_refs",
                reason: "candidate record is not bound to the presented source Signal",
            });
        }
        // A quarantine verb whose candidate is not quarantined would commit a
        // restriction record against a record the store can read as anything
        // else, so the verb and the state it means are compared here rather
        // than trusted from the producer.
        if self.transition == ProblemOwnerTransition::Quarantine
            && record.get("state").and_then(Value::as_str) != Some(PROBLEM_STATE_QUARANTINED)
        {
            return Err(StoreError::InvalidField {
                field: "record_json.state",
                reason: "a quarantine transition must commit a quarantined candidate record",
            });
        }
        Ok(())
    }
}

/// Builds the closed `ApplyProblemOwnerState` mutation request.
#[must_use]
pub fn problem_owner_state_mutation_request(
    params: BTreeMap<String, Value>,
) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyProblemOwnerState,
        parameters: params,
    }
}

/// The revision-head key namespace the compare-and-swap is arbitrated under.
///
/// The existing `ReconcileRecovery` problem leg already binds
/// `problem:{problem_id}` this way; the named owner transitions share the one
/// namespace so a doctor's verified repair and a reassignment cannot both
/// believe they replaced the same predecessor revision.
pub fn problem_revision_key(problem_id: &str) -> Result<crate::RevisionKey, StoreError> {
    crate::RevisionKey::new(format!("problem:{problem_id}"))
}

fn required_text<'a>(
    parameters: &'a BTreeMap<String, Value>,
    name: &'static str,
) -> Result<&'a str, StoreError> {
    match parameters.get(name).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() && !value.chars().any(char::is_control) => {
            Ok(value)
        }
        _ => Err(StoreError::InvalidField {
            field: name,
            reason: "problem owner transition parameter must be non-blank text",
        }),
    }
}

fn required_digest(
    parameters: &BTreeMap<String, Value>,
    name: &'static str,
) -> Result<String, StoreError> {
    let value = required_text(parameters, name)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field: name,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(value.to_owned())
}

/// The exact member set of one `closure_json` kind.
fn closure_members(kind: &str) -> &'static [&'static str] {
    match kind.as_bytes() {
        b"WAIVED" => &[
            "authority",
            "decision_ref",
            "evidence",
            "expires_at_ms",
            "kind",
            "limits",
            "residual_risk",
        ],
        b"SOURCE_QUARANTINE" => &[
            "assessed_source",
            "authority",
            "dependency_closure",
            "expected_problem_revision",
            "impacted_scopes",
            "kind",
            "owner",
            "permitted_effects",
            "problem_id",
            "rebuild_condition",
            "release_condition",
            "retained_frontier",
        ],
        _ => &[
            "evidence",
            "kind",
            "replacement_holder",
            "replacement_obligation_ref",
        ],
    }
}

/// Whether this transition commits a retained closure record.
fn transition_closes(transition: ProblemOwnerTransition) -> bool {
    matches!(
        transition,
        ProblemOwnerTransition::Waive
            | ProblemOwnerTransition::Supersede
            | ProblemOwnerTransition::Quarantine
    )
}

/// Validates one collection of unique non-blank strings.
fn validate_unique_strings(
    value: Option<&Value>,
    reason: &'static str,
    allow_empty: bool,
) -> Result<(), StoreError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason,
        });
    };
    if !allow_empty && items.is_empty() {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason,
            });
        };
        if text.trim().is_empty() || !seen.insert(text) {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason,
            });
        }
    }
    Ok(())
}

/// Whether a value is a lowercase SHA-256 digest.
fn is_lowercase_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates the closed admitting-authority spelling of a retained source
/// restriction.
///
/// The two member names are I13.10's closed pair, restated at this boundary so
/// a record carrying any other authority shape — including one that tried to
/// name a model recommendation — refuses here instead of being stored as an
/// admitted restriction.
fn validate_quarantine_authority(value: Option<&Value>) -> Result<(), StoreError> {
    const REASON: &str = "retained source restriction must name a deterministic rule or an authorized decision";
    let Some(Value::Object(object)) = value else {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: REASON,
        });
    };
    let mut members = object.keys();
    let name = members.next().ok_or(StoreError::InvalidField {
        field: PROBLEM_PARAM_CLOSURE_JSON,
        reason: REASON,
    })?;
    if members.next().is_some() {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: REASON,
        });
    }
    let reference = match name.as_str() {
        "deterministic_policy" => "rule_id",
        "authorized_human" => "decision_ref",
        _ => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: REASON,
            });
        }
    };
    let inner = object.get(name).and_then(Value::as_object).ok_or(
        StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: REASON,
        },
    )?;
    if inner.len() != 1
        || !inner
            .get(reference)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: REASON,
        });
    }
    Ok(())
}

/// Validates the nested identities of a retained source restriction: the exact
/// affected source revision with its digest, the admitting authority and the
/// accountable owner.
fn validate_source_quarantine_identities(
    object: &serde_json::Map<String, Value>,
) -> Result<(), StoreError> {
    let members = || StoreError::InvalidField {
        field: PROBLEM_PARAM_CLOSURE_JSON,
        reason: "retained source restriction does not carry exactly its admitted members",
    };
    let Some(source) = object.get("assessed_source").and_then(Value::as_object) else {
        return Err(members());
    };
    for name in ["source_ref", "revision"] {
        if !source
            .get(name)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(members());
        }
    }
    if !source
        .get("digest")
        .and_then(Value::as_str)
        .is_some_and(is_lowercase_digest)
    {
        return Err(members());
    }
    validate_quarantine_authority(object.get("authority"))?;
    let Some(owner) = object.get("owner").and_then(Value::as_object) else {
        return Err(members());
    };
    for name in ["principal", "generation"] {
        if !owner
            .get(name)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(members());
        }
    }
    Ok(())
}

/// Validates the retained source restriction one `QUARANTINE` verb commits.
///
/// The record is the lossless statement of what was admitted, so this compares
/// it with the presented bindings instead of recording both: the retained
/// Problem identity and expected revision must equal the ones the transition
/// itself carries, and every named collection must be non-blank and
/// duplicate-free. Nothing here is held to a digest the store cannot itself
/// recompute; the affected closure travels as the exact member list the
/// Governor re-derived from the traversal's own qualified edges, inside the same
/// canonical request hash that carries the rest of this record.
fn validate_source_quarantine_json(
    object: &serde_json::Map<String, Value>,
    problem_id: &str,
    expected_revision: &str,
) -> Result<(), StoreError> {
    if object.get("problem_id").and_then(Value::as_str) != Some(problem_id) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: "retained source restriction does not name the presented Problem",
        });
    }
    if object.get("expected_problem_revision").and_then(Value::as_str) != Some(expected_revision) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: "retained source restriction does not name the presented expected revision",
        });
    }
    for name in ["release_condition", "rebuild_condition"] {
        if !object
            .get(name)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "retained source restriction must state its release/rebuild condition",
            });
        }
    }
    validate_unique_strings(
        object.get("dependency_closure"),
        "retained source restriction must carry the exact affected dependency closure",
        false,
    )?;
    validate_unique_strings(
        object.get("impacted_scopes"),
        "retained source restriction must carry the bounded quarantined scope",
        false,
    )?;
    validate_unique_strings(
        object.get("permitted_effects"),
        "retained source restriction must carry the bounded permitted effect",
        false,
    )?;
    validate_unique_strings(
        object.get("retained_frontier"),
        "retained source restriction must carry its retained frontier",
        true,
    )?;
    validate_source_quarantine_identities(object)
}

/// Validates the retained closure record for one verb.
///
/// Exact membership per `kind`, so a waiver cannot carry a supersession's
/// members, a supersession cannot carry a waiver's, neither can hide a
/// member the admitted decision did not have, and a retained source restriction
/// cannot be attached to a verb that did not admit one. This is what makes the
/// closure durable *as admitted* rather than as a restatement.
fn validate_closure_json(
    transition: ProblemOwnerTransition,
    value: &Value,
    problem_id: &str,
    expected_revision: &str,
) -> Result<(), StoreError> {
    let Value::Object(object) = value else {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: "retained closure record must be a JSON object",
        });
    };
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "closure_json.kind",
            reason: "retained closure record must name its kind",
        })?;
    let expected_kind = match transition {
        ProblemOwnerTransition::Waive => PROBLEM_CLOSURE_WAIVED,
        ProblemOwnerTransition::Supersede => PROBLEM_CLOSURE_SUPERSEDED_BY,
        ProblemOwnerTransition::Quarantine => PROBLEM_CLOSURE_QUARANTINED_FOR_REBUILD,
        _ => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "only a waive, supersede or quarantine transition commits a closure record",
            });
        }
    };
    if kind != expected_kind {
        return Err(StoreError::InvalidField {
            field: "closure_json.kind",
            reason: "retained closure kind does not match the named transition",
        });
    }
    let members = closure_members(kind);
    if object.len() != members.len() || object.keys().any(|name| !members.contains(&name.as_str()))
    {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_CLOSURE_JSON,
            reason: "retained closure record does not carry exactly its admitted members",
        });
    }
    if kind == PROBLEM_CLOSURE_QUARANTINED_FOR_REBUILD {
        return validate_source_quarantine_json(object, problem_id, expected_revision);
    }
    if kind == PROBLEM_CLOSURE_WAIVED
        && !matches!(object.get("expires_at_ms").and_then(Value::as_u64), Some(expiry) if expiry > 0)
    {
        return Err(StoreError::InvalidField {
            field: "closure_json.expires_at_ms",
            reason: "an accepted-risk closure must retain a positive expiry",
        });
    }
    for name in ["authority", "replacement_holder"] {
        if let Some(holder) = object.get(name)
            && !matches!(holder, Value::Object(_))
        {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "retained closure holder must be a JSON object",
            });
        }
    }
    Ok(())
}

/// Validates the closed `ApplyProblemOwnerState` parameter map.
///
/// The declaration table in `operation_parameters` owns exact membership and
/// per-value shape; this enforces the closed verb set, the non-zero expected
/// revision, the digest shapes, the presence of the candidate record, and the
/// verb-gated retained closure. It grants no authority: the bindings it checks
/// are still compared against live state by the store bridge.
pub fn validate_problem_owner_state_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let verb = required_text(parameters, PROBLEM_PARAM_TRANSITION)?;
    let Some(transition) = ProblemOwnerTransition::by_name(verb) else {
        return Err(StoreError::UnknownOperation);
    };
    let problem_id = required_text(parameters, PROBLEM_PARAM_PROBLEM_ID)?;
    required_text(parameters, PROBLEM_PARAM_SOURCE_SIGNAL_ID)?;
    let expected = required_text(parameters, PROBLEM_PARAM_EXPECTED_REVISION)?;
    match expected.parse::<u64>() {
        Ok(revision) if revision > 0 => {}
        _ => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_REVISION,
                reason: "must be a non-zero decimal record revision",
            });
        }
    }
    required_digest(parameters, PROBLEM_PARAM_AUTHORIZATION_DIGEST)?;
    required_digest(parameters, PROBLEM_PARAM_RECORD_DIGEST)?;
    if !matches!(
        parameters.get(PROBLEM_PARAM_RECORD_JSON),
        Some(Value::Object(_))
    ) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_RECORD_JSON,
            reason: "problem owner transition must carry its candidate record object",
        });
    }
    match parameters.get(PROBLEM_PARAM_CLOSURE_JSON) {
        Some(value) => validate_closure_json(transition, value, problem_id, expected)?,
        None if transition_closes(transition) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "a waive, supersede or quarantine transition must retain its closure record",
            });
        }
        None => {}
    }
    Ok(())
}

/// Decodes one validated parameter map into its named transition and bindings,
/// and proves the candidate record satisfies them.
pub fn decode_problem_owner_state_mutation(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedProblemOwnerState, StoreError> {
    validate_problem_owner_state_params(parameters)?;
    let transition =
        ProblemOwnerTransition::by_name(required_text(parameters, PROBLEM_PARAM_TRANSITION)?)
            .ok_or(StoreError::UnknownOperation)?;
    let expected_revision = required_text(parameters, PROBLEM_PARAM_EXPECTED_REVISION)?
        .parse::<u64>()
        .map_err(|_error| StoreError::InvalidField {
            field: PROBLEM_PARAM_EXPECTED_REVISION,
            reason: "must be a non-zero decimal record revision",
        })?;
    let decoded = DecodedProblemOwnerState {
        transition,
        problem_id: required_text(parameters, PROBLEM_PARAM_PROBLEM_ID)?.to_owned(),
        expected_revision,
        source_signal_id: required_text(parameters, PROBLEM_PARAM_SOURCE_SIGNAL_ID)?.to_owned(),
        authorization_digest: required_digest(parameters, PROBLEM_PARAM_AUTHORIZATION_DIGEST)?,
        record_digest: required_digest(parameters, PROBLEM_PARAM_RECORD_DIGEST)?,
        record_json: parameters.get(PROBLEM_PARAM_RECORD_JSON).cloned().ok_or(
            StoreError::InvalidField {
                field: PROBLEM_PARAM_RECORD_JSON,
                reason: "problem owner transition must carry its candidate record object",
            },
        )?,
        closure_json: parameters.get(PROBLEM_PARAM_CLOSURE_JSON).cloned(),
    };
    decoded.record_satisfies_bindings()?;
    Ok(decoded)
}
