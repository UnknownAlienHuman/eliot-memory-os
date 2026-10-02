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
//! The key is derived from `(closure_id, closure_revision)` alone. That pair is
//! what makes the paired `GetAuthorityRevocationHistory` read (and any later
//! point read of one recorded revocation) a lookup at ONE exact closure
//! revision rather than a scan for "whatever is current". The durable history
//! revision is part of the identity on purpose: two records of the same closure
//! at different durable revisions are two different historical facts, and
//! collapsing them would let a later revision silently answer for an earlier
//! one. Nothing else feeds the key, so a caller cannot move the record by
//! changing an unrelated parameter.
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
const RECORD_CONFLICT: &str = "authority_revocation_record_conflict";

/// Versioned `recovery_owner` namespace holding the authority-revocation rows.
///
/// A peer of the existing store-owned record namespaces
/// (`capability-evidence-v1`, `task-contract-acceptance-v1`,
/// `blackboard-item-v1`), not a new table. Defined here rather than in
/// `eliot-store-api` because this leg introduces the durable row.
///
/// `pub(crate)` SO THAT a future read half reuses THIS constant rather than
/// re-declaring a second literal: a read half in `apply/read_boundary.rs` will
/// reach it as
/// `super::surreal_authority_revocation::AUTHORITY_REVOCATION_RECORD_NAMESPACE`,
/// the same reuse `read_boundary.rs:506,521` performs for
/// `eliot_store_api::TASK_CONTRACT_ACCEPTANCE_RECORD_NAMESPACE` (verified at
/// `read_boundary.rs:506` and `:521`). That read half does not exist yet: the
/// paired named read `GetAuthorityRevocationHistory` is deliberately and
/// truthfully unactivated, because the Kernel intercepts it and serves it from
/// the retained P-07 ORS before the store bridge sees it
/// (`bins/eliot-kernel/src/daemon_request_dispatch.rs:10343`, handler
/// `crates/kernel/eliot-kernel-service/src/owner_history.rs:235`), and nothing
/// outside this module reads either constant today. The reuse is therefore a
/// forward obligation, not an observed fact. The sibling constants of the other
/// two owner records live in `eliot-store-api` only because that crate owned
/// their rows first; visibility here is crate-internal in the same way
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
/// [`AUTHORITY_REVOCATION_RECORD_NAMESPACE`]: a future read half in
/// `apply/read_boundary.rs` must reuse this exact identifier so the read can
/// never validate a row under a schema string the write half did not write.
/// That read half does not exist yet, so this is the obligation the visibility
/// is held for, not a reuse that has already happened.
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
}
