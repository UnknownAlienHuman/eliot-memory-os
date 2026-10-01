//! Canonical problem-owner-state wire contract (issue #1759 I2, I13.9/I13.7).
//!
//! This module owns the serialization-only wire boundary for the nine named
//! owner transitions `create`, `update`, `assign`, `unassign`, `escalate`,
//! `resolve`, `waive`, `supersede` and `reopen`. It contains no problem
//! domain model and no transition logic: the pure state machines
//! (`eliot_problem::Problem`) own the typed record and its fail-closed
//! candidate-copy transitions, the Governor prepares the one
//! `PreparedTransition`, and the store bridge executes exactly that plan.
//! Wire shapes stay serialization-only and never become a second semantic
//! model.
//!
//! The nine verbs are *named* on the wire, not spelled as one generic
//! mutation: a caller that can write `REOPEN` cannot write the same change as
//! `UPDATE`, because the discriminator is part of the canonical request hash and
//! the recorded record must satisfy the identity, predecessor revision and
//! source-Signal bindings that verb implies.
//!
//! Every binding is **compared** here, never merely transported:
//!
//! - `record_digest` is re-derived from the candidate record's own canonical
//!   bytes and compared, so a digest cannot describe one record while a
//!   different record travels beside it;
//! - `authorization_digest` is re-derived from the ownership-lease identity the
//!   candidate record itself retains — plus that record's own `state_fence` —
//!   and compared, so the authorization a transition claims is provably the
//!   authorization its record was written under rather than a value the caller
//!   restated;
//! - the expected record revision is compared against the record's own revision
//!   (its checked successor) here, and separately against the live revision head
//!   by the store that arbitrates it, so a stale revision fails at use time;
//! - the source Signal is compared against the record's own retained
//!   `signal_refs`.
//!
//! [`PROBLEM_AUTHORIZATION_DOMAIN`] is the one stated domain separator for that
//! re-derivation. The Governor prepares the digest through the same constant, so
//! the two sides derive one value rather than two that can drift.
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
/// The retained closure record a `WAIVE` or `SUPERSEDE` transition commits.
///
/// `Problem` carries no waiver or supersession field, so the committed
/// transition is where both closures are durable. It is present for exactly
/// those two verbs and absent for every other one, so a closure can never be
/// attached to a transition that did not produce one.
pub const PROBLEM_PARAM_CLOSURE_JSON: &str = "closure_json";
/// The complete issuer grant used for this transition, retained in the same
/// canonical receipt as the resulting Problem record.
pub const PROBLEM_PARAM_OWNER_LEASE_GRANT: &str = "owner_lease_grant";
/// Issuer-observed revocation, present only when this transition records the
/// loss of the exact grant it also carries.
pub const PROBLEM_PARAM_OWNER_LEASE_REVOCATION: &str = "owner_lease_revocation";
/// Digest of the exact currently committed predecessor Problem record. The
/// Store compares this to its owner row inside the transaction.
pub const PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST: &str =
    "expected_current_record_digest";
/// Whether the exact current predecessor retained a revoked/lost lease.
pub const PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_REVOKED: &str =
    "expected_current_owner_revoked";
/// Exact current predecessor's retained lease identity, compared to the
/// Store-owned owner row inside the transaction.
pub const PROBLEM_PARAM_EXPECTED_CURRENT_LEASE_IDENTITY: &str =
    "expected_current_lease_identity";
/// Full grant retained by the current predecessor, compared inside the Store
/// transaction independently from the grant carried by the candidate head.
pub const PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_LEASE_GRANT: &str =
    "expected_current_owner_lease_grant";

/// `closure_json.kind` for an accepted risk.
pub const PROBLEM_CLOSURE_WAIVED: &str = "WAIVED";
/// `closure_json.kind` for a supersession.
pub const PROBLEM_CLOSURE_SUPERSEDED_BY: &str = "SUPERSEDED_BY";

/// Domain separator for the current-authorization digest of a named owner
/// transition.
///
/// The digest is over the exact ownership-lease identity the committed record
/// retains — lease id, the lease owner's own commitment and the ownership epoch
/// — together with that record's own `state_fence`. It lives here, beside the
/// wire names the digest travels under, so the Governor that prepares it and the
/// store that rechecks it derive it from one stated constant instead of two
/// literals that can drift.
pub const PROBLEM_AUTHORIZATION_DOMAIN: &str = "eliot.problem.owner-transition-authorization.v1";

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

/// The closed I13.9 owner-transition verb set.
///
/// Nine variants, one per named transition. The set is closed: a tenth verb is a
/// contract change, and an existing verb cannot be reused for another verb's
/// state change because the candidate record is checked against the bindings
/// that verb carries.
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
        }
    }

    /// Resolves a wire name to its transition, or refuses an unknown verb.
    ///
    /// Closed: the nine names below are the whole set, so a tenth verb is a
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
    /// Complete lease grant presented by the lease owner, retained for an
    /// exact future issuer readback.
    pub owner_lease_grant: Value,
    /// Exact issuer-observed revocation, required only for `UNASSIGN`.
    pub owner_lease_revocation: Option<Value>,
    /// Digest of the current committed Problem, absent only for `CREATE`.
    pub expected_current_record_digest: Option<String>,
    /// Current predecessor's assignment/revocation state, absent only for
    /// `CREATE`.
    pub expected_current_owner_revoked: Option<bool>,
    /// Current predecessor's exact lease identity, absent only for `CREATE`.
    pub expected_current_lease_identity: Option<Value>,
    /// Exact prior grant held by the owner row; absent only for `CREATE`.
    pub expected_current_owner_lease_grant: Option<Value>,
    /// The retained closure record, present for exactly `WAIVE` and
    /// `SUPERSEDE`.
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
            | ProblemOwnerTransition::Reopen => match self.expected_revision.checked_add(1) {
                Some(revision) => Some(revision),
                None => None,
            },
        }
    }

    /// The ownership-lease identity this transition's authorization is over,
    /// read from the candidate record's own `ownership`.
    ///
    /// Read from the record rather than from a presented value, so the digest
    /// compared against it describes the authorization the record was actually
    /// written under. An assigned record carries its live lease; an unassigned
    /// record carries the exact lost lease the loss observed, which is the
    /// identity an owner-loss or escalation transition is authorized by. A
    /// record that retains neither is refused: there is nothing to bind the
    /// authorization to.
    fn retained_lease_identity(&self) -> Result<(String, String, u64), StoreError> {
        let ownership = self
            .record_json
            .get("ownership")
            .and_then(Value::as_object)
            .ok_or(StoreError::InvalidField {
                field: "record_json.ownership",
                reason: "candidate record must retain its ownership",
            })?;
        // `Ownership` is an externally tagged enum with SCREAMING_SNAKE_CASE
        // variants, so exactly one of these two members is present.
        let lease = if let Some(assigned) = ownership.get("ASSIGNED") {
            assigned.get("lease")
        } else if let Some(unassigned) = ownership.get("UNASSIGNED") {
            unassigned.get("lost_lease")
        } else {
            return Err(StoreError::InvalidField {
                field: "record_json.ownership",
                reason: "candidate record must retain an assigned lease or an observed lost lease",
            });
        };
        let lease = lease
            .and_then(Value::as_object)
            .ok_or(StoreError::InvalidField {
                field: "record_json.ownership.lease",
                reason: "candidate record must retain the exact ownership-lease identity",
            })?;
        let text = |name: &'static str| {
            lease
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .ok_or(StoreError::InvalidField {
                    field: "record_json.ownership.lease",
                    reason: "retained ownership lease must name its identity members",
                })
        };
        let ownership_epoch = lease
            .get("ownership_epoch")
            .and_then(Value::as_u64)
            .filter(|epoch| *epoch > 0)
            .ok_or(StoreError::InvalidField {
                field: "record_json.ownership.lease.ownership_epoch",
                reason: "retained ownership lease must carry a non-zero ownership epoch",
            })?;
        Ok((text("lease_id")?, text("commitment")?, ownership_epoch))
    }

    /// The authorization digest the candidate record's own retained ownership
    /// implies, re-derived here over the ORIGINAL recorded values.
    ///
    /// Nothing presented by the caller takes part: the lease id, the lease
    /// owner's own commitment and the ownership epoch are read out of the
    /// committed record, together with that record's own `state_fence`, and the
    /// digest is taken over exactly those. A transition therefore cannot claim an
    /// authorization belonging to a different lease, epoch or fence than the one
    /// its record retains.
    fn rederived_authorization_digest(&self) -> Result<String, StoreError> {
        let (lease_id, commitment, ownership_epoch) = self.retained_lease_identity()?;
        let state_fence =
            self.record_json
                .get("state_fence")
                .cloned()
                .ok_or(StoreError::InvalidField {
                    field: "record_json.state_fence",
                    reason: "candidate record must retain the state fence it was admitted under",
                })?;
        let bytes = crate::canonical_json_bytes(&(
            PROBLEM_AUTHORIZATION_DOMAIN,
            &commitment,
            &lease_id,
            ownership_epoch,
            &state_fence,
        ))
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(crate::sha256_hex(&bytes))
    }

    /// Whether the candidate record satisfies every binding this transition
    /// carries.
    ///
    /// The record is the lossless statement of what the transition produced, so
    /// the bridge compares the record against the presented bindings rather than
    /// recording both and trusting that they agree. Each of the four bindings is
    /// a comparison: the record's own bytes against the presented
    /// `record_digest`, the record's own retained lease and fence against the
    /// presented `authorization_digest`, the record's own revision against the
    /// checked successor of the presented expected revision, and the record's
    /// own `signal_refs` against the presented source Signal.
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
        // The record digest is re-derived from the record's own canonical bytes
        // and compared, so it describes THIS record rather than travelling
        // beside it.
        let record_bytes = crate::canonical_json_bytes(record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if crate::sha256_hex(&record_bytes) != self.record_digest {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_RECORD_DIGEST,
                reason: "record digest does not describe the presented candidate record",
            });
        }
        // The authorization digest is re-derived from the record's own retained
        // lease identity and fence and compared, so the authorization is bound
        // to the record this transition commits.
        if self.rederived_authorization_digest()? != self.authorization_digest {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_AUTHORIZATION_DIGEST,
                reason: "authorization digest does not describe the lease the record retains",
            });
        }
        validate_problem_owner_lease_evidence(
            self.transition,
            record,
            &self.owner_lease_grant,
            self.owner_lease_revocation.as_ref(),
        )?;
        Ok(())
    }
}

/// Holds the complete grant and optional revocation to the candidate record's
/// own lease identity. This is a consistency check; the grant becomes
/// authoritative only after it is written in a Store-owned transaction and
/// read back from that committed receipt.
fn validate_problem_owner_lease_evidence(
    transition: ProblemOwnerTransition,
    record: &Value,
    grant: &Value,
    revocation: Option<&Value>,
) -> Result<(), StoreError> {
    let ownership = record
        .get("ownership")
        .and_then(Value::as_object)
        .ok_or(StoreError::InvalidField {
            field: "record_json.ownership",
            reason: "candidate record must retain its ownership",
        })?;
    let (owner, identity) = if let Some(assigned) = ownership.get("ASSIGNED") {
        (
            assigned.get("holder"),
            assigned.get("lease"),
        )
    } else if let Some(unassigned) = ownership.get("UNASSIGNED") {
        (
            unassigned.get("last_holder"),
            unassigned.get("lost_lease"),
        )
    } else {
        return Err(StoreError::InvalidField {
            field: "record_json.ownership",
            reason: "candidate record must be assigned or retain an observed lost lease",
        });
    };
    let identity = identity.and_then(Value::as_object).ok_or(StoreError::InvalidField {
        field: "record_json.ownership.lease",
        reason: "candidate record must retain the original lease identity",
    })?;
    let grant_obj = grant.as_object().ok_or(StoreError::InvalidField {
        field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
        reason: "must carry the exact lease grant object",
    })?;
    let field_text = |object: &serde_json::Map<String, Value>, field: &'static str| {
        object.get(field).and_then(Value::as_str).ok_or(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant is missing a required text field",
        })
    };
    let grant_epoch = grant_obj
        .get("ownership_epoch")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant ownership epoch must be non-zero",
        })?;
    if field_text(grant_obj, "lease_id")? != identity.get("lease_id").and_then(Value::as_str).unwrap_or("")
        || grant_epoch != identity.get("ownership_epoch").and_then(Value::as_u64).unwrap_or(0)
    {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant identity differs from the candidate's original owner lease",
        });
    }
    if grant_obj.get("holder") != owner {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant holder differs from the candidate's original owner",
        });
    }
    let state_fence = record.get("state_fence").ok_or(StoreError::InvalidField {
        field: "record_json.state_fence",
        reason: "candidate record must retain its current full state fence",
    })?;
    if grant_obj.get("state_fence") != Some(state_fence) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant is not bound to the candidate's exact current state fence",
        });
    }
    let authority_epoch = grant_obj.get("authority_epoch").ok_or(StoreError::InvalidField {
        field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
        reason: "grant must retain its authority epoch",
    })?;
    let issued_at_ms = grant_obj.get("issued_at_ms").and_then(Value::as_u64).ok_or(
        StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant issue time must be a non-negative integer",
        },
    )?;
    let expires_at_ms = grant_obj.get("expires_at_ms").and_then(Value::as_u64).ok_or(
        StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant expiry must be a non-negative integer",
        },
    )?;
    if expires_at_ms <= issued_at_ms
        || authority_epoch != state_fence.get("authority_epoch").unwrap_or(&Value::Null)
    {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant validity window or authority epoch differs from the current fence",
        });
    }
    let grant_bytes = crate::canonical_json_bytes(&(
        "eliot.problem.owner-lease.v1",
        field_text(grant_obj, "lease_id")?,
        grant_obj.get("holder").ok_or(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant must retain its exact holder",
        })?,
        authority_epoch,
        state_fence,
        grant_epoch,
        issued_at_ms,
        expires_at_ms,
    ))
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if crate::sha256_hex(&grant_bytes)
        != identity.get("commitment").and_then(Value::as_str).unwrap_or("")
    {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "grant commitment differs from the candidate's original lease identity",
        });
    }
    if revocation.is_some() != matches!(transition, ProblemOwnerTransition::Unassign) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_REVOCATION,
            reason: "issuer revocation is required exactly for UNASSIGN",
        });
    }
    if let Some(revocation) = revocation {
        let unassigned = ownership.get("UNASSIGNED").and_then(Value::as_object);
        if revocation.as_object().is_none()
            || unassigned.is_none_or(|unassigned| {
                revocation.get("reason") != unassigned.get("reason")
                    || revocation.get("evidence") != unassigned.get("loss_evidence")
            })
        {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_OWNER_LEASE_REVOCATION,
                reason: "must equal the revocation retained by the candidate owner-loss record",
            });
        }
    }
    Ok(())
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
        ProblemOwnerTransition::Waive | ProblemOwnerTransition::Supersede
    )
}

/// Validates the retained closure record for one verb.
///
/// Exact membership per `kind`, so a waiver cannot carry a supersession's
/// members, a supersession cannot carry a waiver's, and neither can hide a
/// member the admitted decision did not have. This is what makes the closure
/// durable *as admitted* rather than as a restatement.
fn validate_closure_json(
    transition: ProblemOwnerTransition,
    value: &Value,
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
        _ => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "only a waive or supersede transition commits a closure record",
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
    required_text(parameters, PROBLEM_PARAM_PROBLEM_ID)?;
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
    match (
        transition,
        parameters.get(PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST),
    ) {
        (ProblemOwnerTransition::Create, None) => {}
        (ProblemOwnerTransition::Create, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST,
                reason: "CREATE has no predecessor record",
            });
        }
        (_, Some(value)) => {
            let digest = value.as_str().ok_or(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST,
                reason: "must be a SHA-256 digest",
            })?;
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(StoreError::InvalidField {
                    field: PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST,
                    reason: "must be a SHA-256 digest",
                });
            }
        }
        (_, None) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST,
                reason: "non-CREATE transition must bind its exact predecessor record",
            });
        }
    }
    match (
        transition,
        parameters.get(PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_REVOKED),
    ) {
        (ProblemOwnerTransition::Create, None) => {}
        (ProblemOwnerTransition::Create, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_REVOKED,
                reason: "CREATE has no predecessor owner state",
            });
        }
        (_, Some(Value::Bool(_))) => {}
        (_, _) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_REVOKED,
                reason: "non-CREATE transition must bind the predecessor owner state",
            });
        }
    }
    match (
        transition,
        parameters.get(PROBLEM_PARAM_EXPECTED_CURRENT_LEASE_IDENTITY),
    ) {
        (ProblemOwnerTransition::Create, None) => {}
        (ProblemOwnerTransition::Create, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_LEASE_IDENTITY,
                reason: "CREATE has no predecessor lease identity",
            });
        }
        (_, Some(Value::Object(identity)))
            if identity.get("lease_id").and_then(Value::as_str).is_some()
                && identity.get("commitment").and_then(Value::as_str).is_some()
                && identity.get("ownership_epoch").and_then(Value::as_u64).is_some() => {}
        (_, _) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_LEASE_IDENTITY,
                reason: "non-CREATE transition must bind the exact predecessor lease identity",
            });
        }
    }
    match (
        transition,
        parameters.get(PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_LEASE_GRANT),
    ) {
        (ProblemOwnerTransition::Create, None) => {}
        (ProblemOwnerTransition::Create, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_LEASE_GRANT,
                reason: "CREATE has no predecessor grant",
            });
        }
        (_, Some(Value::Object(_))) => {}
        (_, _) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_LEASE_GRANT,
                reason: "non-CREATE transition must bind the exact predecessor grant",
            });
        }
    }
    if !matches!(
        parameters.get(PROBLEM_PARAM_RECORD_JSON),
        Some(Value::Object(_))
    ) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_RECORD_JSON,
            reason: "problem owner transition must carry its candidate record object",
        });
    }
    if !matches!(parameters.get(PROBLEM_PARAM_OWNER_LEASE_GRANT), Some(Value::Object(_))) {
        return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
            reason: "must carry the complete issuer grant",
        });
    }
    match parameters.get(PROBLEM_PARAM_OWNER_LEASE_REVOCATION) {
        Some(value) if matches!(transition, ProblemOwnerTransition::Unassign) && value.is_object() => {}
        None if !matches!(transition, ProblemOwnerTransition::Unassign) => {}
        _ => return Err(StoreError::InvalidField {
            field: PROBLEM_PARAM_OWNER_LEASE_REVOCATION,
            reason: "issuer revocation is present exactly for UNASSIGN",
        }),
    }
    match parameters.get(PROBLEM_PARAM_CLOSURE_JSON) {
        Some(value) => validate_closure_json(transition, value)?,
        None if transition_closes(transition) => {
            return Err(StoreError::InvalidField {
                field: PROBLEM_PARAM_CLOSURE_JSON,
                reason: "a waive or supersede transition must retain its closure record",
            });
        }
        None => {}
    }
    if let Some(value) = parameters.get("sequence_disposition") {
        let evidence: crate::SequenceDispositionEvidence = serde_json::from_value(value.clone())
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        evidence.validate()?;
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
        owner_lease_grant: parameters.get(PROBLEM_PARAM_OWNER_LEASE_GRANT).cloned().ok_or(
            StoreError::InvalidField {
                field: PROBLEM_PARAM_OWNER_LEASE_GRANT,
                reason: "must carry the complete issuer grant",
            },
        )?,
        owner_lease_revocation: parameters.get(PROBLEM_PARAM_OWNER_LEASE_REVOCATION).cloned(),
        expected_current_record_digest: parameters
            .get(PROBLEM_PARAM_EXPECTED_CURRENT_RECORD_DIGEST)
            .and_then(Value::as_str)
            .map(str::to_owned),
        expected_current_owner_revoked: parameters
            .get(PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_REVOKED)
            .and_then(Value::as_bool),
        expected_current_lease_identity: parameters
            .get(PROBLEM_PARAM_EXPECTED_CURRENT_LEASE_IDENTITY)
            .cloned(),
        expected_current_owner_lease_grant: parameters
            .get(PROBLEM_PARAM_EXPECTED_CURRENT_OWNER_LEASE_GRANT)
            .cloned(),
        closure_json: parameters.get(PROBLEM_PARAM_CLOSURE_JSON).cloned(),
    };
    decoded.record_satisfies_bindings()?;
    Ok(decoded)
}
