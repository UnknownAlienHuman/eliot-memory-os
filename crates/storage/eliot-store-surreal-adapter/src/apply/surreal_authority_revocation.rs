//! Durable Surreal transaction leg for the owner-issued
//! `RecordAuthorityRevocation` revocation record (issue #686).
//!
//! Transitive influence revocation is decided by the authority owner
//! (`eliot-authority`) and recorded by the Governor, which emits the closed
//! seven-field `RecordAuthorityRevocation` command through
//! `authority_revocation_envelope`
//! (`crates/governor/eliot-governor/src/authority_revocation.rs:173`). This leg
//! persists exactly that record and nothing else: the create-only row, its
//! payload bytes and the canonical receipt commit in the same prepared
//! transaction as every other owner row, so a reader can never observe a durable
//! revocation the receipt does not describe.
//!
//! It adds NO table. The row lives in its own namespace of the existing
//! `recovery_owner` table — the same mechanism the blackboard item record
//! (issue #1822) and the capability-evidence record (issue #1773) use — and is
//! addressed through `super::surreal_blackboard::recovery_owner_id`, so there is
//! no second durable identity scheme and no second revocation vocabulary.
//!
//! # Why the row is keyed by the closure identity
//!
//! The key is derived from `(closure_id, closure_revision)` alone, because that
//! is the property this leg actually decides and owns: reading one recorded
//! revocation back is a point lookup at ONE exact durable closure revision, not a
//! scan for "whatever is current", so a record can only ever be found at the
//! durable revision it was recorded at. The durable history revision is part of
//! the identity on purpose: two records of the same closure at different durable
//! revisions are two different historical facts — the influence-revocation
//! contract requires preserving historical decisions and retaining forensic
//! history (`docs/architecture/I12-20-influence-revocation.md`) — and collapsing
//! them would let a later revision silently answer for an earlier one. Nothing
//! else feeds the key, so a caller cannot move the record by changing an
//! unrelated parameter. No named read is promised here: the paired
//! `GetAuthorityRevocationHistory` read is served by the Kernel from the
//! retained P-07 ORS and never reaches this row, so it neither justifies nor
//! constrains this key.
//!
//! The row is create-only. A second commit for the same `(closure_id,
//! closure_revision)` is refused rather than overwritten, so the owner cannot
//! narrow or widen a recorded revocation after it is durable. Issuing a
//! different recorded revocation means a new closure revision, which is the
//! same precondition the durable owner already committed and fenced.
//!
//! # The fence binding is proved here, never stored unchecked
//!
//! `fence_digest` is declared to bind the record to its state fence
//! (`eliot-store-api/src/operation_parameters.rs:568-604`). Storing the
//! caller's string unchecked would be "evidence bound to nothing", so this leg
//! reproduces the producer's EXACT derivation and compares it: the Governor
//! computes `fence_digest` as `sha256_hex(canonical_json_bytes(&state_fence))`
//! over the durable closure's `StateFence`
//! (`authority_revocation.rs:446` and `:489`, via `canonical_digest` at `:136`),
//! after refusing to emit an envelope unless that fence EQUALS the request
//! metadata fence (`:548`, and again at `:482` for the second-phase
//! coordinates). The envelope carries `request: identity.request.metadata`
//! (`:232`), so the value the transition records under `state_fence` is
//! byte-identical to the fence that was digested. This leg recomputes the same
//! digest from `transition.state_fence` through the same
//! `canonical_json_bytes` + `sha256_hex` helpers and refuses with
//! [`StoreError::FenceMismatch`] on any disagreement, so a row can only ever be
//! durable at a fence the transition itself proves. The fence CAS runs earlier
//! in that same transaction against the store's durable `canonical_fence`
//! (`atomic_write.rs:779`, before this leg's statements are appended at
//! `atomic_write.rs:984`), so the fence proven here is the store's LIVE fence.
//!
//! What that proves is the FENCE, and only the fence. `fence_digest` is the
//! digest of a `StateFence` alone — `authority_epoch`, `resource_generation`,
//! `task_revision`, `policy_revision` and `integration_revision`
//! (`eliot-contracts/src/lib.rs:888-899`) — so `origin_ref`, `closure_id`,
//! `affected_digest`, `affected_count` and `invalidation_reason` are NOT inputs
//! to it. Those five are the authority owner's own recorded values, carried
//! verbatim from the envelope into the payload; this leg derives nothing from
//! them and admits them only in the owner's canonical spelling (see the next
//! section for the two counters and `declared_text` for the five strings). At
//! the store they remain the PRODUCER's assertion. Six of the seven recorded
//! fields ARE deep-bound to a committed `GrantClosureReceipt` upstream in the
//! Governor, not re-derived here: `require_recorded_fields_bind_closure`
//! (`authority_revocation.rs:410-453`) compares `origin_ref`, `closure_id`,
//! `closure_revision`, `affected_digest`, `affected_count` and `fence_digest`
//! against the durable closure, and `bind_durable_closure_coordinates` calls it
//! (`:455-459`) before the envelope is admitted. The seventh,
//! `invalidation_reason`, is NOT among them: it is carried as the producer's own
//! recorded value and is never re-derived or compared against the closure
//! anywhere, in the Governor or in this leg.
//!
//! # The two numeric fields are parsed, never defaulted
//!
//! `closure_revision` and `affected_count` are declared as decimal STRINGS
//! (`operation_parameters.rs:568-604`) and the producer emits
//! `u64::to_string()` of each (`:222`, `:224`). The owner refuses a blank field
//! (`:193-205`) and refuses a zero revision or a zero affected count
//! (`:206-216`) before it emits anything. A leg that accepted what the owner
//! refused would reintroduce exactly the defect class this record exists to
//! close, so both fields are parsed here and refused when absent, non-string,
//! blank, not ASCII decimal digits, carrying a non-canonical leading zero,
//! overflowing `u64`, or zero.
//!
//! The revision carries one bound the affected count deliberately does not.
//! `closure_revision` becomes the durable row's `revision`, and that column is
//! declared as `int` in the base DDL and again, identically, in both the `v2` and
//! `v3` migrations (`schema.rs:249`, `:498`, `:568`); `SurrealDB` `int` is `i64`, so a
//! revision in `[i64::MAX + 1, u64::MAX]` is not representable in the column it
//! is written to, and is refused at the parse site as a typed `StoreError`
//! through the exact comparison and reason the sibling owner rows bind their
//! own revision with (`eliot-store-api/src/blackboard.rs:78`). Refusing it here
//! rather than letting the provider see it matters: an unrepresentable value
//! reaches the database as an unrecognised provider error, which this crate
//! keeps as an UNKNOWN outcome requiring receipt reconciliation — materially
//! weaker than this leg's other refusals. `affected_count` is NOT written to
//! the `revision` column; it travels only as a decimal string inside the
//! `payload` BYTES (`schema.rs:251`), where every `u64` spelling is
//! representable, so bounding it would refuse a record the column can hold.
//! Nothing is `unwrap`ped, defaulted, or coerced, and `null` is refused like
//! any other non-string value.
//!
//! # The payload records data, never a capability
//!
//! The stored payload is exactly the seven owner-approved values, canonicalised.
//! It is NOT a `RecordedRevocation` / `RevocationHistoryPayload` v2 value
//! (`eliot-store-api/src/revocation_history.rs`): that wire shape additionally
//! requires `owner_namespace`, `bounds`, `disposition`, `omissions`,
//! `current_influence` and `canonical_request_digest`, and this mutation carries
//! none of them. Minting them here would be adapter-side semantic defaulting,
//! which `crates/storage/AGENTS.md` forbids, so the read half remains
//! responsible for joining this row with the producer coordinates its own
//! evidence carries.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, RecoveryRecord, RecoveryRecordKey, StateFence,
    StoreError, canonical_json_bytes, sha256_hex,
};
use serde_json::{Map, Value, json};

use crate::error::AdapterError;
use crate::schema;

/// Provider marker proving the create-only revocation row already exists for
/// this exact closure identity. Classified as a typed semantic/currentness
/// conflict by `SEMANTIC_CONFLICT_MARKERS` in `apply/atomic_write.rs`, exactly
/// like the acceptance-set and blackboard create-only siblings.
///
/// `pub(crate)` SO THAT this crate's own `SEMANTIC_CONFLICT_MARKERS` table, and
/// its test, can reference THIS SINGLE DEFINITION instead of restating the
/// literal. Nothing in production consumes the visibility: the marker is
/// rendered into the statement text by `record_write` below, and the classifier
/// in `apply/atomic_write.rs` still matches it as a sentinel token. The visibility
/// exists so a rename or spelling change cannot leave the two halves silently
/// disagreeing — which would downgrade a deterministic create-only collision
/// from `ProviderConflict` to an UNKNOWN outcome requiring receipt
/// reconciliation. It is not a rename and does not change the marker text.
pub(crate) const RECORD_CONFLICT: &str = "authority_revocation_record_conflict";

/// Versioned `recovery_owner` namespace holding the authority-revocation rows.
///
/// A peer of the existing store-owned record namespaces
/// (`capability-evidence-v1`, `task-contract-acceptance-v1`,
/// `blackboard-item-v1`), not a new table. Defined here rather than in
/// `eliot-store-api` because this leg introduces the durable row.
///
/// `pub(crate)` SO THAT a future read half, IF AND WHEN ONE IS WRITTEN, reuses
/// THIS exact constant rather than re-declaring a second literal. No such read
/// half is planned in this slice and no module is named here as its owner, so
/// this is a constraint on a future writer, not a statement about where that
/// code will live. The read boundary's EXISTING reuse of
/// `eliot_store_api::TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE`
/// (`read_boundary.rs:506`, `:521`) is the pattern such a writer would follow.
/// Nothing reads either constant today: the paired named read
/// `GetAuthorityRevocationHistory` is deliberately and truthfully unactivated,
/// because the Kernel intercepts it and serves it from
/// the retained P-07 ORS before the store bridge sees it
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs:10343`, handler
/// `crates/kernel/eliot-kernel-service/src/owner_history.rs:235`). The reuse is
/// therefore a forward obligation, not an observed fact. The sibling constants of
/// the other two owner records live in `eliot-store-api` only because that crate
/// owned their rows first; visibility here is crate-internal in the same way
/// `surreal_blackboard::recovery_owner_id` (`apply/surreal_blackboard.rs:164`)
/// is `pub(crate)` for this crate's own read half.
pub(crate) const AUTHORITY_REVOCATION_RECORD_NAMESPACE: &str = "authority-revocation-v1";

/// Schema identifier of the persisted revocation record.
///
/// Distinct from the neutral read payload version
/// (`REVOCATION_HISTORY_PAYLOAD_VERSION`), which names what the history read
/// serves: this one names the durable row the authority owner writes.
///
/// `pub(crate)` for the same reason as
/// [`AUTHORITY_REVOCATION_RECORD_NAMESPACE`]: if and when a read half is
/// written, it must reuse this exact identifier so the read can never validate a
/// row under a schema string the write half did not write. No such read half is
/// planned in this slice and no module is named as its owner, so this is the
/// obligation the visibility is held for, not a reuse that has already happened.
pub(crate) const AUTHORITY_REVOCATION_RECORD_SCHEMA_V1: &str =
    "eliot.authority.revocation-record.v1";

/// One owner-recorded revocation, exactly as the seven owner-approved
/// parameters carry it.
///
/// Every field is the owner's own recorded value. Nothing is derived here
/// except the two numeric fields, which are the parsed form of the owner's own
/// decimal strings, and the row's `state_fence`, which is the transition's.
#[derive(Debug, Eq, PartialEq)]
struct AuthorityRevocationRecord {
    origin_ref: String,
    closure_id: String,
    closure_revision: u64,
    affected_digest: String,
    affected_count: u64,
    invalidation_reason: String,
    fence_digest: String,
}

/// Renders one admitted owner revocation record into the caller's canonical
/// transaction.
///
/// Returns an empty fragment when the transition names no such operation, so a
/// transition for another owner writes exactly the rows it declared.
pub(crate) fn authority_revocation_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut matching = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::RecordAuthorityRevocation);
    let Some(command) = matching.next() else {
        return Ok((String::new(), Map::new()));
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "authority_revocation.named_operations",
        }));
    }
    // The allowed class is read from the operation's own catalogue row rather
    // than restated here (`RecordAuthorityRevocation` declares
    // `TransitionClass::RecoverySchema`), so this leg cannot drift from the
    // owner declaration; a transition presenting this command under any other
    // class never reaches the provider.
    if transition.transition_class != command.operation.transition_class() {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let record = decode_record(&command.parameters).map_err(AdapterError::Store)?;
    // Defence in depth beside the catalogue gate: the durable row and the
    // receipt must describe one revocation at one live fence. The supplied
    // digest is only kept when it reproduces the transition's own fence digest
    // exactly, so the row's FENCE is bound to something this transition proves
    // rather than to a string the caller asserted — and since the fence CAS
    // already ran earlier in this transaction, that fence is the store's live
    // canonical fence. The comparison covers the fence only: `fence_digest`
    // digests the `StateFence` alone, so the closure fields are carried here as
    // the authority owner's recorded values, not derived here. Upstream,
    // `require_recorded_fields_bind_closure`
    // (`authority_revocation.rs:410-453`) deep-binds six of the seven recorded
    // fields to a committed `GrantClosureReceipt`: `origin_ref`, `closure_id`,
    // `closure_revision`, `affected_digest`, `affected_count` and
    // `fence_digest`. `invalidation_reason` is the seventh and is NOT among
    // them: it is the producer's own recorded value, never re-derived or
    // compared against the closure in the Governor or here.
    let fence_digest =
        fence_digest_hex(&transition.state_fence).map_err(AdapterError::Serialization)?;
    if record.fence_digest != fence_digest {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    record_write(&record, &transition.state_fence)
}

/// Recomputes the exact `fence_digest` the producer emits for one State Fence.
///
/// This is the producer's own derivation
/// (`authority_revocation.rs:446`, `:489`, `canonical_digest` at `:136`):
/// `sha256_hex(canonical_json_bytes(&state_fence))`. The Governor refuses to
/// emit unless the closure's fence equals the request metadata fence (`:548`),
/// and the envelope carries that metadata verbatim as its request (`:232`), so
/// the transition's `state_fence` is the very value that was digested.
fn fence_digest_hex(state_fence: &StateFence) -> Result<String, String> {
    let bytes = canonical_json_bytes(state_fence).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// Decodes the closed seven-field owner record out of the operation's
/// parameter map, by the owner's exact parameter names.
///
/// The owner declares these seven names, all required and all
/// `ParameterShape::Subject`, in `RECORD_AUTHORITY_REVOCATION_PARAMETERS`
/// (`eliot-store-api/src/operation_parameters.rs:568-604`). That table is
/// private, but `declared_mutation_parameters` is itself public and re-exported
/// from `eliot-store-api`; what does NOT exist is a `decode_authority_revocation_record`
/// for this operation, which is why the names are read through the parameter map
/// here rather than through a typed owner record.
/// Each read is fail-closed: absent, non-string, blank, and
/// control-character-bearing values refuse, and the two declared decimal
/// counters additionally refuse a non-digit, non-canonical, overflowing, or
/// zero value. `closure_revision` additionally goes through
/// [`declared_closure_revision`], which closes the i64 representability bound
/// the `recovery_owner.revision` column imposes on it.
fn decode_record(
    parameters: &BTreeMap<String, Value>,
) -> Result<AuthorityRevocationRecord, StoreError> {
    Ok(AuthorityRevocationRecord {
        origin_ref: declared_text(parameters, "origin_ref")?.to_owned(),
        closure_id: declared_text(parameters, "closure_id")?.to_owned(),
        closure_revision: declared_closure_revision(parameters)?,
        affected_digest: declared_text(parameters, "affected_digest")?.to_owned(),
        affected_count: declared_counter(parameters, "affected_count")?,
        invalidation_reason: declared_text(parameters, "invalidation_reason")?.to_owned(),
        fence_digest: declared_text(parameters, "fence_digest")?.to_owned(),
    })
}

/// Reads one required owner-approved string parameter.
///
/// Refuses an absent parameter, a value that is not a JSON string (so `null`, a
/// number, an object and an array are all refused rather than coerced), a blank
/// string, and any string carrying control characters — the same refusals the
/// producer applies before it emits (`authority_revocation.rs:193-205`).
fn declared_text<'a>(
    parameters: &'a BTreeMap<String, Value>,
    name: &'static str,
) -> Result<&'a str, StoreError> {
    let value = parameters
        .get(name)
        .ok_or(StoreError::InvalidField {
            field: name,
            reason: "is a required owner-approved revocation field",
        })?
        .as_str()
        .ok_or(StoreError::InvalidField {
            field: name,
            reason: "must be a string, not a null or an untyped value",
        })?;
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: name,
            reason: "must be a non-blank string without control characters",
        });
    }
    Ok(value)
}

/// Reads one required owner-approved counter parameter, which the owner
/// declares and emits as its decimal string.
///
/// The producer refuses a zero durable revision and a zero affected count before
/// emitting anything (`authority_revocation.rs:206-216`) because the origin
/// itself is always affected; a leg that admitted either would store a record
/// asserting a closure that never happened. The canonical decimal spelling is
/// required too: the producer emits `u64::to_string()`, so a leading zero, a
/// sign, a decimal point or surrounding whitespace is a malformed spelling that
/// this leg refuses rather than normalising into a stored value.
///
/// The bound here is exactly the `u64` the DECIMAL SPELLING denotes: it refuses
/// an absent, non-string, blank, non-canonical, overflowing-u64 or zero value,
/// and nothing else. Any further bound belongs to the field that actually lands
/// in a bounded column, not here: `closure_revision` additionally goes through
/// [`declared_closure_revision`], while `affected_count` — which travels only
/// as a string inside the `payload` BYTES — does not, so this parser is never
/// widened into an over-refusal of a representable count.
fn declared_counter(
    parameters: &BTreeMap<String, Value>,
    name: &'static str,
) -> Result<u64, StoreError> {
    let text = declared_text(parameters, name)?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(StoreError::InvalidField {
            field: name,
            reason: "must be the canonical decimal string of an unsigned counter",
        });
    }
    let value = text.parse::<u64>().map_err(|_| StoreError::InvalidField {
        field: name,
        reason: "must be a decimal counter that fits an unsigned 64-bit integer",
    })?;
    if value == 0 {
        return Err(StoreError::InvalidField {
            field: name,
            reason: "must be non-zero: a zero revision or affected count records no closure",
        });
    }
    Ok(value)
}

/// Reads the declared durable closure revision, which the row binds into the
/// store's `int` `revision` column.
///
/// This is [`declared_counter`] plus the one bound the COLUMN requires and the
/// counter itself does not: `DEFINE FIELD revision ON recovery_owner TYPE int`
/// (`schema.rs:249`, and identically in the `v2` and `v3` migrations at `:498` and
/// `:568`), and `SurrealDB` `int` is `i64`, so a revision above `i64::MAX` has no
/// representation in the field it is written to even though the owner's
/// decimal spelling is a well-formed `u64`. The comparison and the reason are
/// the sibling convention verbatim — `revision == 0 || revision > i64::MAX as
/// u64`, refusing with "must fit a positive Surreal integer"
/// (`eliot-store-api/src/blackboard.rs:78`, and the same form in
/// `swarm_owner_revisions.rs:251` and `mailbox.rs:108`), so every owner row
/// that writes an `int` revision bounds it identically at write. The zero half
/// of that sibling comparison is already refused, with its own more specific
/// reason, by [`declared_counter`] above, so only the `> i64::MAX as u64` half
/// is added here.
///
/// Refused as a typed `StoreError` at the parse site, before any statement is
/// rendered: the alternative is an unrecognised provider error at commit, which
/// this crate keeps as an UNKNOWN outcome requiring receipt reconciliation and
/// would therefore let a value that never happened reach the database.
fn declared_closure_revision(parameters: &BTreeMap<String, Value>) -> Result<u64, StoreError> {
    let value = declared_counter(parameters, "closure_revision")?;
    if value > i64::MAX as u64 {
        return Err(StoreError::InvalidField {
            field: "closure_revision",
            reason: "must fit a positive Surreal integer",
        });
    }
    Ok(value)
}

/// Derives the deterministic `recovery_owner` address of one recorded
/// revocation.
///
/// Keyed by `(closure_id, closure_revision)` alone, so the paired read is a
/// point lookup at one exact durable closure revision, and two revisions of one
/// closure are two rows rather than one overwritten answer.
fn revocation_record_key(
    closure_id: &str,
    closure_revision: u64,
) -> Result<RecoveryRecordKey, AdapterError> {
    let identity = canonical_json_bytes(&(closure_id, closure_revision))
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    RecoveryRecordKey::new(
        AUTHORITY_REVOCATION_RECORD_NAMESPACE,
        format!("revocation_{}", sha256_hex(&identity)),
    )
    .map_err(AdapterError::Store)
}

/// Renders the create-only row for one decoded record.
fn record_write(
    record: &AuthorityRevocationRecord,
    state_fence: &StateFence,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let key = revocation_record_key(&record.closure_id, record.closure_revision)?;
    let record_id = super::surreal_blackboard::recovery_owner_id(&key)?;
    let record_json = canonical_json_bytes(&json!({
        "origin_ref": record.origin_ref,
        "closure_id": record.closure_id,
        "closure_revision": record.closure_revision.to_string(),
        "affected_digest": record.affected_digest,
        "affected_count": record.affected_count.to_string(),
        "invalidation_reason": record.invalidation_reason,
        "fence_digest": record.fence_digest,
    }))
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let row = RecoveryRecord {
        namespace: AUTHORITY_REVOCATION_RECORD_NAMESPACE.to_owned(),
        key: key.key.clone(),
        state_fence: state_fence.clone(),
        // The durable row revision IS the durable history revision the owner
        // recorded the closure at. It is not a store sequence: the read asks for
        // one exact closure revision, so the row must answer at that revision or
        // not at all. It is bounded to i64 by `declared_closure_revision`
        // because that is what the `int` column this is written to can hold.
        revision: record.closure_revision,
        schema: AUTHORITY_REVOCATION_RECORD_SCHEMA_V1.to_owned(),
        value_digest: sha256_hex(&record_json),
        payload: record_json,
    };

    let mut sql = String::new();
    write!(
        sql,
        "LET $revocation_record_current = (SELECT VALUE {{ namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest }} FROM ONLY type::record($revocation_table, $revocation_record_id)); IF type::is_object($revocation_record_current) {{ THROW '{RECORD_CONFLICT}'; }} ELSE {{ CREATE type::record($revocation_table, $revocation_record_id) CONTENT {{ namespace: $revocation_record.namespace, key: $revocation_record.key, state_fence: $revocation_record.state_fence, revision: $revocation_record.revision, schema: $revocation_record.schema, payload: <bytes>$revocation_record.payload, value_digest: $revocation_record.value_digest }}; }};"
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;

    // Every caller-derived byte travels as a binding; only this leg's own table
    // name and row identifier are named in the statement text, and neither is
    // caller-derived.
    let bindings = Map::from_iter([
        (
            "revocation_table".to_owned(),
            json!(schema::table::RECOVERY_OWNER),
        ),
        ("revocation_record_id".to_owned(), json!(record_id)),
        ("revocation_record".to_owned(), json!(row)),
    ]);
    Ok((sql, bindings))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::{
        CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext,
        TransitionClass, bind_issue18_digests,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("canonical test lineage-A"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn transition(fence: &StateFence, parameters: BTreeMap<String, Value>) -> PreparedTransition {
        let mut transition = PreparedTransition {
            contract_version: CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new("op-revoke-686").expect("op"),
                idempotency_key: "idem-revoke-686".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("governor").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope:governor").expect("ordering")],
            transition_class: TransitionClass::RecoverySchema,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("c".repeat(64))
                .expect("manifest digest"),
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::RecordAuthorityRevocation,
                parameters,
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn admitted_parameters(fence: &StateFence) -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("origin_ref".to_owned(), json!("root:alpha")),
            ("closure_id".to_owned(), json!("revocation-686-01")),
            ("closure_revision".to_owned(), json!("9")),
            ("affected_digest".to_owned(), json!("d".repeat(64))),
            ("affected_count".to_owned(), json!("3")),
            (
                "invalidation_reason".to_owned(),
                json!("KERNEL_REVOCATION_COMMITTED"),
            ),
            (
                "fence_digest".to_owned(),
                json!(fence_digest_hex(fence).expect("fence digest")),
            ),
        ])
    }

    #[test]
    fn admitted_revocation_renders_a_create_only_row_for_its_closure_key() {
        let fence = test_fence();
        let transition = transition(&fence, admitted_parameters(&fence));
        let (sql, bindings) =
            authority_revocation_statements(&transition).expect("admitted revocation renders");
        assert!(sql.contains("CREATE type::record($revocation_table"));
        assert!(sql.contains(RECORD_CONFLICT));
        assert_eq!(
            bindings.get("revocation_table"),
            Some(&json!(schema::table::RECOVERY_OWNER))
        );
        // Every caller-derived byte travels as a binding, never in the statement.
        assert!(!sql.contains("root:alpha"));
        assert!(!sql.contains("revocation-686-01"));
        let row: RecoveryRecord = bindings
            .get("revocation_record")
            .and_then(|value| serde_json::from_value(value.clone()).expect("row binding decodes"))
            .expect("row binding");
        assert_eq!(row.namespace, AUTHORITY_REVOCATION_RECORD_NAMESPACE);
        assert_eq!(row.revision, 9);
        assert_eq!(row.state_fence, fence);
        assert_eq!(sha256_hex(&row.payload), row.value_digest);
        // The key is the closure identity alone, so it is stable and does not
        // move with any other parameter.
        let key = revocation_record_key("revocation-686-01", 9).expect("key");
        assert_eq!(
            bindings.get("revocation_record_id"),
            Some(&json!(
                super::super::surreal_blackboard::recovery_owner_id(&key).expect("row id")
            ))
        );
    }

    #[test]
    fn fence_digest_reproduces_the_producer_derivation_over_the_whole_state_fence() {
        let fence = test_fence();
        // WHAT is hashed is pinned here from the PUBLIC building blocks the
        // producer itself uses, never from the helper under test.
        //
        // The Governor derives `fence_digest` as
        // `canonical_digest(&closure.authority.state_fence)` — `authority_revocation.rs:452`
        // in `require_recorded_fields_bind_closure` and again `:495` in
        // `bind_durable_closure_coordinates` (and `:561` on the entry path) —
        // through `canonical_digest` at `:142`, whose body is exactly
        // `sha256_hex(canonical_json_bytes(value))` (`:143` and `:146`) over the
        // `eliot_contracts::{canonical_json_bytes, sha256_hex}` import at `:98`.
        // `eliot_store_api` re-exports those EXACT two functions rather than
        // wrapping them (`eliot-store-api/src/lib.rs:16-19`:
        // `pub use eliot_contracts::{... canonical_json_bytes, sha256_hex}`), so
        // the producer's two calls and the two calls below are the same
        // functions on the same canonical bytes; the Governor only maps their
        // error into `CompositionError::Owner`.
        //
        // The expected digest below is WRITTEN from those public functions
        // rather than obtained from `fence_digest_hex`, which is what makes the
        // helper's BODY a discriminating variable. Every other test in this
        // module builds its `fence_digest` fixture value THROUGH
        // `fence_digest_hex`, and the production comparison compares the caller's
        // string against the same helper, so before this test an implementation
        // that hashed only `state_fence.authority_epoch` — silently breaking the
        // binding to the Governor's `canonical_digest(&closure.authority
        // .state_fence)` — would have left the entire module green.
        let expected =
            sha256_hex(&canonical_json_bytes(&fence).expect("canonical StateFence bytes"));
        assert_eq!(
            fence_digest_hex(&fence).expect("fence digest"),
            expected,
            "the leg must reproduce the producer's derivation over the WHOLE StateFence"
        );
        // The same discriminating statement, named: the authority epoch ALONE is
        // not the producer's derivation. `StateFence` carries five keys
        // (`eliot-contracts/src/lib.rs:888-899`), and dropping the other four
        // would let a row be fenced to one epoch while the producer proved the
        // full `resource_generation` / `task_revision` / `policy_revision` /
        // `integration_revision` set.
        let epoch_only = sha256_hex(
            &canonical_json_bytes(&fence.authority_epoch).expect("canonical authority-epoch bytes"),
        );
        assert_ne!(
            epoch_only, expected,
            "the digest must not degenerate to the authority epoch alone"
        );
    }

    #[test]
    fn the_row_is_addressed_by_the_closure_identity_alone_and_stores_the_seven_supplied_values() {
        let fence = test_fence();
        // A local closure, not a module helper: the two renders below differ ONLY
        // in the two parameters the module doc forbids from feeding the key, and
        // nothing else in this module needs a bare `parameters -> bindings` step.
        let rendered = |parameters: BTreeMap<String, Value>| {
            let transition = transition(&fence, parameters);
            authority_revocation_statements(&transition)
                .expect("admitted revocation renders")
                .1
        };
        let row_of = |bindings: &Map<String, Value>| -> RecoveryRecord {
            bindings
                .get("revocation_record")
                .and_then(|value| {
                    serde_json::from_value(value.clone()).expect("row binding decodes")
                })
                .expect("row binding")
        };

        let bindings = rendered(admitted_parameters(&fence));
        let row = row_of(&bindings);

        // (i) The ADDRESS is pinned. `row.schema` and `row.namespace` are
        // compared against the declared constants (neither was compared at all
        // before), and `row.key` is compared against a key derived HERE from the
        // public building blocks over the closure identity ALONE —
        // `sha256_hex(canonical_json_bytes(&(closure_id, closure_revision)))`
        // under this leg's own namespace — rather than against the production
        // `revocation_record_key`, so the HASHED INPUT SET of the key is now a
        // discriminating variable and folding any other recorded field into it
        // fails.
        assert_eq!(row.namespace, AUTHORITY_REVOCATION_RECORD_NAMESPACE);
        assert_eq!(row.schema, AUTHORITY_REVOCATION_RECORD_SCHEMA_V1);
        let identity = canonical_json_bytes(&("revocation-686-01", 9u64))
            .expect("canonical closure identity bytes");
        let expected_key = RecoveryRecordKey::new(
            AUTHORITY_REVOCATION_RECORD_NAMESPACE,
            format!("revocation_{}", sha256_hex(&identity)),
        )
        .expect("expected recovery record key");
        assert_eq!(row.key, expected_key.key);

        // The forbidden inputs really are outside the key: a record that differs
        // ONLY in `origin_ref` and `invalidation_reason` lands on the SAME
        // address and the same durable revision. This is the module doc's "a
        // caller cannot move the record by changing an unrelated parameter",
        // stated as an observation over two renders rather than as a claim.
        let mut moved = admitted_parameters(&fence);
        moved.insert("origin_ref".to_owned(), json!("root:beta"));
        moved.insert(
            "invalidation_reason".to_owned(),
            json!("SOME_OTHER_TERMINAL_REASON"),
        );
        let moved_row = row_of(&rendered(moved));
        assert_eq!(moved_row.key, row.key);
        assert_eq!(moved_row.revision, row.revision);
        assert_eq!(
            bindings.get("revocation_record_id"),
            Some(&json!(
                super::super::surreal_blackboard::recovery_owner_id(&expected_key).expect("row id")
            ))
        );

        // (ii) The CONTENT is pinned. `row.payload` is DECODED and every one of
        // the seven owner-approved fields is asserted BY NAME against the value
        // that was supplied. The existing positive test only recomputed
        // `value_digest` from whatever bytes the renderer produced, so a swapped
        // `origin_ref`/`closure_id`, a dropped `invalidation_reason`, or a
        // `closure_revision` written as a JSON NUMBER instead of the owner's
        // decimal STRING all re-digested consistently and passed. No production
        // helper computes the expectations below: the `fence_digest` expectation
        // is derived from the same public `canonical_json_bytes` + `sha256_hex`
        // pair the Governor derives it from, and the payload itself is never
        // regenerated — the STORED BYTES are read.
        let payload: Value = serde_json::from_slice(&row.payload).expect("payload bytes decode");
        assert_eq!(payload.get("origin_ref"), Some(&json!("root:alpha")));
        assert_eq!(payload.get("closure_id"), Some(&json!("revocation-686-01")));
        assert_eq!(
            payload.get("closure_revision"),
            Some(&json!("9")),
            "closure_revision travels as the owner's canonical decimal STRING"
        );
        assert_eq!(payload.get("affected_digest"), Some(&json!("d".repeat(64))));
        assert_eq!(
            payload.get("affected_count"),
            Some(&json!("3")),
            "affected_count travels as the owner's canonical decimal STRING"
        );
        assert_eq!(
            payload.get("invalidation_reason"),
            Some(&json!("KERNEL_REVOCATION_COMMITTED")),
            "the seventh field is the producer's own recorded value and must not be dropped"
        );
        assert_eq!(
            payload.get("fence_digest"),
            Some(&json!(sha256_hex(
                &canonical_json_bytes(&fence).expect("canonical StateFence bytes")
            )))
        );
        // The two counters are strings, not numbers: a numeric spelling would be a
        // different wire shape than the owner's `u64::to_string()` and would not
        // compare equal to `json!("9")` / `json!("3")` above, so it is asserted
        // by type as well to name the property rather than leave it implied.
        assert!(payload["closure_revision"].is_string());
        assert!(payload["affected_count"].is_string());
        // `origin_ref` and `closure_id` hold the values that were SUPPLIED and are
        // not each other's: swapping them renders a record that binds the wrong
        // origin to the wrong closure and deep-binds against the durable closure
        // for a different operation than the one recorded.
        assert_ne!(payload["origin_ref"], payload["closure_id"]);
        assert_ne!(payload["origin_ref"], json!("revocation-686-01"));
        assert_ne!(payload["closure_id"], json!("root:alpha"));
        // Exactly the seven fields: an eighth minted coordinate (for example a
        // `RecordedRevocation` shape field) would be adapter-side semantic
        // defaulting, which `crates/storage/AGENTS.md` forbids.
        assert_eq!(payload.as_object().map(serde_json::Map::len), Some(7));
    }

    #[test]
    fn unproven_fence_digest_refuses_before_any_statement_is_rendered() {
        let fence = test_fence();
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("fence_digest".to_owned(), json!("e".repeat(64)));
        let foreign_fence = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&foreign_fence),
            Err(AdapterError::Store(StoreError::FenceMismatch))
        );

        // A zero counter is refused too: the owner refuses it before emitting, so
        // the leg must not admit what the owner refused.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("affected_count".to_owned(), json!("0"));
        let second = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&second),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "affected_count",
                reason: "must be non-zero: a zero revision or affected count records no closure",
            }))
        );

        // A revision above i64::MAX is refused here too, even though it is a
        // well-formed non-zero u64 decimal: it is written to the `int`
        // `recovery_owner.revision` column, which cannot hold it, so admitting
        // it would defer the failure to an unrecognised provider error.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert(
            "closure_revision".to_owned(),
            json!((i64::MAX as u64 + 1).to_string()),
        );
        let third = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&third),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "closure_revision",
                reason: "must fit a positive Surreal integer",
            }))
        );

        // The same over-i64 spelling of the COUNT is admitted, because it never
        // reaches the `revision` column: it travels as a string inside the
        // `payload` bytes. The bound must not over-refuse.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert(
            "affected_count".to_owned(),
            json!((i64::MAX as u64 + 1).to_string()),
        );
        let fourth = transition(&fence, parameters);
        assert!(
            authority_revocation_statements(&fourth).is_ok(),
            "a count above i64::MAX is representable in the payload bytes"
        );
    }

    #[test]
    fn a_second_revocation_command_in_one_transition_is_refused() {
        let fence = test_fence();
        let parameters = admitted_parameters(&fence);
        let mut transition = transition(&fence, parameters.clone());
        // The closed record is admitted once per transition; a second copy of the
        // same command is ambiguous about which one owns the row, so it is
        // refused before any decoding or statement rendering happens.
        transition.named_operations.push(NamedMutationRequest {
            operation: NamedMutationOperation::RecordAuthorityRevocation,
            parameters,
        });
        assert_eq!(
            authority_revocation_statements(&transition),
            Err(AdapterError::Store(StoreError::Duplicate {
                field: "authority_revocation.named_operations",
            }))
        );
    }

    #[test]
    fn a_revocation_presented_under_another_transition_class_is_refused() {
        let fence = test_fence();
        let parameters = admitted_parameters(&fence);
        let mut transition = transition(&fence, parameters);
        // `RecordAuthorityRevocation` declares `TransitionClass::RecoverySchema`
        // in the owner catalogue row, which `transition()` already presents. Any
        // other ceiling is refused: the class is read from the operation's own
        // declaration, so this leg cannot drift from the owner and a command
        // smuggled under an unrelated family never reaches the provider.
        transition.transition_class = TransitionClass::CaptureCandidate;
        assert_ne!(
            transition.transition_class,
            NamedMutationOperation::RecordAuthorityRevocation.transition_class()
        );
        assert_eq!(
            authority_revocation_statements(&transition),
            Err(AdapterError::Store(StoreError::TransitionClassExceeded))
        );
    }

    #[test]
    fn a_non_string_revocation_parameter_is_refused() {
        let fence = test_fence();
        // `null` is the load-bearing case: it substantiates the module
        // doc's "never coerced, never defaulted" claim. A missing value would be
        // indistinguishable from a defaulted one, so it is refused rather than
        // substituted.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("invalidation_reason".to_owned(), Value::Null);
        let null_value = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&null_value),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "invalidation_reason",
                reason: "must be a string, not a null or an untyped value",
            }))
        );

        // A number is refused for the same reason and never coerced to text.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("invalidation_reason".to_owned(), json!(3));
        let number_value = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&number_value),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "invalidation_reason",
                reason: "must be a string, not a null or an untyped value",
            }))
        );
    }

    #[test]
    fn a_blank_or_control_character_revocation_parameter_is_refused() {
        let fence = test_fence();
        // Whitespace-only is blank in the owner's sense and never stored as an
        // empty owner-recorded value.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("origin_ref".to_owned(), json!("   "));
        let blank = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&blank),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "origin_ref",
                reason: "must be a non-blank string without control characters",
            }))
        );

        // A non-blank string carrying a control character is refused for the
        // same reason, so no record ever claims a value the producer refused.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("closure_id".to_owned(), json!("revocation-686\u{7}01"));
        let control = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&control),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "closure_id",
                reason: "must be a non-blank string without control characters",
            }))
        );
    }

    #[test]
    fn a_non_canonical_counter_spelling_is_refused() {
        let fence = test_fence();
        // A leading zero is a malformed spelling of a value the producer emits as
        // `u64::to_string()`; it is refused rather than normalised into a stored
        // revision, so the row can never say "9" in one spelling and "09" in
        // another.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("closure_revision".to_owned(), json!("09"));
        let leading_zero = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&leading_zero),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "closure_revision",
                reason: "must be the canonical decimal string of an unsigned counter",
            }))
        );

        // A sign is the same malformed spelling, not a negative number.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert("closure_revision".to_owned(), json!("-1"));
        let signed = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&signed),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "closure_revision",
                reason: "must be the canonical decimal string of an unsigned counter",
            }))
        );

        // A canonically spelled value beyond `u64` is a different refusal with
        // its own reason: the digits are well formed, so it must not be reported
        // as a malformed spelling.
        let mut parameters = admitted_parameters(&fence);
        parameters.insert(
            "affected_count".to_owned(),
            json!(u64::MAX.to_string() + "0"),
        );
        let overflowing = transition(&fence, parameters);
        assert_eq!(
            authority_revocation_statements(&overflowing),
            Err(AdapterError::Store(StoreError::InvalidField {
                field: "affected_count",
                reason: "must be a decimal counter that fits an unsigned 64-bit integer",
            }))
        );
    }

    #[test]
    fn the_create_only_refusal_is_pinned_as_a_structure_not_as_a_fragment() {
        let fence = test_fence();
        let transition = transition(&fence, admitted_parameters(&fence));
        let (sql, _) =
            authority_revocation_statements(&transition).expect("admitted revocation renders");

        // The positive test above asserts only that the SQL CONTAINS
        // `CREATE type::record($revocation_table` and CONTAINS the conflict token. Both
        // substrings survive the two mutations that kill the create-only refusal outright
        // — `type::is_object($x)` becoming `type::is_string($x)`, and `FROM ONLY` becoming
        // `FROM` — with every test in this module green. So the GUARD is asserted here as
        // one contiguous structure: the existence test, the refusal, the `ELSE`, and the
        // create it guards, in that order and with that exact spelling.
        let guard = format!(
            "IF type::is_object($revocation_record_current) {{ THROW '{RECORD_CONFLICT}'; }} \
             ELSE {{ CREATE type::record($revocation_table, $revocation_record_id) CONTENT {{ \
             namespace: $revocation_record.namespace, key: $revocation_record.key, \
             state_fence: $revocation_record.state_fence, revision: $revocation_record.revision, \
             schema: $revocation_record.schema, payload: <bytes>$revocation_record.payload, \
             value_digest: $revocation_record.value_digest }};"
        );
        assert!(
            sql.contains(&guard),
            "the refusal and the row it guards must be rendered as one structure"
        );
        // The probe itself: a SINGLE-record point lookup at the exact closure identity.
        // `ONLY` is load-bearing here — without it the probe answers for whichever record
        // the scan matched, which is a different question than "does this one durable
        // closure revision already exist", and it would also be satisfied by a second
        // record at some other address.
        assert!(
            sql.contains(concat!(
                "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, ",
                "revision: revision, schema: schema, payload: payload, value_digest: value_digest }",
                " FROM ONLY type::record($revocation_table, $revocation_record_id)"
            )),
            "the guard must probe the exact record, at ONE durable closure revision"
        );
        // The guard PRECEDES the create it guards, named on its own so a rendering that
        // tests for the conflict after the write cannot satisfy the contiguous assertion
        // above by accident of ordering.
        let guard_at = sql
            .find("IF type::is_object(")
            .expect("the guard is rendered");
        let create_at = sql
            .find("CREATE type::record(")
            .expect("the create is rendered");
        assert!(
            guard_at < create_at,
            "the create-only refusal must be tested before the create, not after it"
        );
    }

    #[test]
    fn an_absent_required_revocation_parameter_is_refused() {
        let fence = test_fence();
        // Every other test in this module OVERWRITES a key; none removes one. The
        // absent-key branch of `declared_text` — the one that refuses with "is a required
        // owner-approved revocation field" — could therefore be deleted, replaced by a
        // default, or swapped for the non-string branch with all of them green. Two
        // fields are removed here, one read early and one read late, so the branch is
        // shown to be the per-field absence refusal and not an artefact of decode order.
        let removals: [(&'static str, Value); 2] = [
            ("closure_id", json!("revocation-686-01")),
            ("invalidation_reason", json!("KERNEL_REVOCATION_COMMITTED")),
        ];
        for (field, value) in removals {
            let mut parameters = admitted_parameters(&fence);
            assert_eq!(
                parameters.remove(field),
                Some(value),
                "the admitted fixture supplies {field}, so the map really is missing it"
            );
            let missing = transition(&fence, parameters);
            assert_eq!(
                authority_revocation_statements(&missing),
                Err(AdapterError::Store(StoreError::InvalidField {
                    field,
                    reason: "is a required owner-approved revocation field",
                })),
                "a required owner-approved field that is ABSENT must be refused, not defaulted"
            );
        }
    }

    #[test]
    fn the_class_gate_admits_exactly_the_class_the_operation_declares() {
        let fence = test_fence();
        let parameters = admitted_parameters(&fence);
        // The class the leg compares against is read from the operation's own declaration.
        // The expectation below is therefore DERIVED from that declaration and never
        // restated, and every variant of the ceiling enum is presented, so a gate that
        // hardcoded any single literal other than the declared one — the drift the class
        // check's own doc forbids — is refused here for a variant it should have admitted,
        // while the declared class alone still renders.
        let declared = NamedMutationOperation::RecordAuthorityRevocation.transition_class();
        let every_class = [
            TransitionClass::CaptureCandidate,
            TransitionClass::Epistemic,
            TransitionClass::TaskControl,
            TransitionClass::LifecyclePolicy,
            TransitionClass::RecoverySchema,
            TransitionClass::Erasure,
            TransitionClass::NotificationState,
            TransitionClass::ReactiveState,
            TransitionClass::UserAutomation,
            TransitionClass::InstrumentRegistry,
        ];
        for class in every_class {
            let mut transition = transition(&fence, parameters.clone());
            transition.transition_class = class;
            if class == declared {
                assert!(
                    authority_revocation_statements(&transition).is_ok(),
                    "{class:?} is the class the operation declares, so it must render"
                );
            } else {
                assert_eq!(
                    authority_revocation_statements(&transition),
                    Err(AdapterError::Store(StoreError::TransitionClassExceeded)),
                    "{class:?} is not the class the operation declares, so it must be refused"
                );
            }
        }
        // The declaration the leg reads is named, so a move of this operation to another
        // family in the owner catalogue cannot pass unnoticed here either.
        assert_eq!(
            declared,
            TransitionClass::RecoverySchema,
            "the leg reads the operation's declaration; this pins what it currently is"
        );
    }

    #[test]
    fn the_persisted_schema_identifier_is_the_exact_versioned_literal() {
        // Both existing schema assertions compare the constant against ITSELF, so
        // changing its VALUE broke nothing: a future read half validates durable rows
        // under exactly this string, so the literal is asserted against the constant here.
        assert_eq!(
            AUTHORITY_REVOCATION_RECORD_SCHEMA_V1, "eliot.authority.revocation-record.v1",
            "the durable row's schema identifier is pinned by value, not only by reference"
        );
    }
}
