//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Source-backed atomic event/projection/revision/receipt binding: single Surreal
//! transaction couples envelope, projected events, relations, revision/ordering
//! heads, receipt and outbox via one `TX_BEGIN`/`TX_COMMIT`.
//! Implementation: I1.8, I5.1, I5.4, I5.9, I2.2, I2.23 — named already-prepared transition only; bridge alone owns SDK/credentials; event/projection/relation/revision/receipt/outbox commit in one DB transaction; unknown outcome resolves exact `WriteReceipt` before replay.
//! Ownership: bounded atomic transaction writer only; no read/head-validation/
//! uniqueness/schema/receipt/named-read/DDL/tests/Dreamer.

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::surreal_automation::{AutomationWrites, automation_write_statements};
use super::surreal_experience::{ExperienceWrites, experience_write_statements};
use super::surreal_learning::{LearningWrites, learning_write_statements};
use super::surreal_reactive::{ReactiveWrites, reactive_write_statements};
use crate::client;
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::plan::{ApplyPlan, EvidenceRecord, OrderingChainTips, PayloadAuthorityRecord};
use crate::schema;
use eliot_store_api::epistemic_revision::EpistemicCommit;
use eliot_store_api::{
    ORDERING_LINK_GENESIS_HASH, OrderingHead, OrderingHeadExpectation, RevisionHead,
    RevisionHeadExpectation, ScopeId, StateFence, StoreError, WriteReceipt,
};

// Read and compare in the same transaction as the fence CAS and receipt.
// The fence CAS serializes racing writers even when the position is absent.
const EPISTEMIC_CAS: &str = r"
LET $position_before = (SELECT epistemic_position_revision, epistemic_candidate_digest FROM write_receipt
    WHERE epistemic_position_key = $epistemic_position_key
    ORDER BY epistemic_position_revision DESC LIMIT 1);
IF ($position_before[0].epistemic_position_revision ?? 0) != $expected_position_revision
    OR ($position_before[0].epistemic_candidate_digest ?? '') != $expected_predecessor_digest {
    THROW 'epistemic_position_cas_conflict';
};
";

// 688-B erasure intent-before-dispatch statements. These closed templates live
// in this apply-owned writer (a sibling of `schema`, inside the admitted
// apply/schema SurrealQL contour): the intent upsert opens the same atomic
// transaction as the destructive statements; one scrub `UPDATE` pair per
// store-owned surface removes only the selected subject's erasable entries
// admitted under the exact recorded scope while the receipt row itself —
// operation/idempotency identity, immutable `body`, sibling captures —
// survives for exact replay and resolution; the outcome seal persists the
// exact per-surface outcomes for idempotent same-operation replay.

// Issue #1712 admits the named erasure dispatch: `apply.rs` routes an
// admitted `ApplyErasure` transition through `record_surreal_erasure_intent`
// and the in-transaction bundle below, so the intent-before-dispatch body is
// live inside the canonical transaction. The pure template/binding helpers
// remain exercised by the wired erasure unit tests in `apply.rs`.
/// Upsert of one durable erasure-intent row: creates the row when absent,
/// refuses with `erasure_intent_conflict` when the same `operation_id`
/// already names a different intent. First statement of the erasure atomic
/// transaction — before any destructive statement.
const TX_ERASURE_INTENT: &str = "LET $erasure_existing = (SELECT VALUE { operation_id: operation_id, subject: subject, payload_ref: payload_ref, encryption_key_ref: encryption_key_ref, deadline_unix_ms: deadline_unix_ms, scope_id: scope_id, surfaces: surfaces, state_fence: state_fence, operation_count: operation_count } FROM ONLY type::record($erasure_table, $erasure_operation_id)); IF type::is_object($erasure_existing) { IF $erasure_existing != $erasure_intent_expected { THROW 'erasure_intent_conflict'; }; } ELSE { CREATE type::record($erasure_table, $erasure_operation_id) CONTENT $erasure_intent_record; };";

/// Scrubs exactly the selected subject's payload-authority entries admitted
/// under the exact recorded scope. `{i}` selects the binding index. The row
/// survives: only authority entries whose `operation_index` belongs to the
/// target's own evidence entries are removed (one named operation carries at
/// most one capture subject, so sibling entries never share the index).
/// Runs before [`TX_ERASURE_SCRUB_EVIDENCE`] in the same transaction so this
/// filter still observes the complete evidence array. The scope predicate
/// compares the single request parameter against the durable row's stored
/// admitted scope (`body.envelope.core.work_scope.scope_id`, rendered verbatim
/// from the admitted transition's `ScopeId` at issuance) — row-versus-request,
/// never parameter-versus-identical-parameter. Exact subject match only —
/// never substring, never a default scope. Rows without a stored envelope
/// scope never match (fail closed).
const TX_ERASURE_SCRUB_AUTHORITY: &str = "UPDATE write_receipt SET payload_authority = payload_authority.filter(|$erasure_authority{i}| array::len(evidence_records.filter(|$erasure_evidence{i}| $erasure_evidence{i}.subject = $erasure_subject{i} AND $erasure_evidence{i}.operation_index = $erasure_authority{i}.operation_index)) = 0) WHERE $erasure_subject{i} IN evidence_records.subject AND $erasure_scope_expected{i} = body.envelope.core.work_scope.scope_id;";

/// Scrubs exactly the selected subject's capture-evidence entries admitted
/// under the exact recorded scope. `{i}` selects the binding index. Runs after
/// [`TX_ERASURE_SCRUB_AUTHORITY`], which has already removed the target's
/// payload-authority entries, so the subject predicate still matches the row
/// here. The row itself — operation/idempotency identity, immutable `body`,
/// sibling captures, unrelated authority entries — is preserved for exact
/// replay and resolution; only the target's erasable entries leave the row.
/// Same stored-scope predicate as [`TX_ERASURE_SCRUB_AUTHORITY`].
const TX_ERASURE_SCRUB_EVIDENCE: &str = "UPDATE write_receipt SET evidence_records = evidence_records.filter(|$erasure_entry{i}| $erasure_entry{i}.subject != $erasure_subject{i}) WHERE $erasure_subject{i} IN evidence_records.subject AND $erasure_scope_expected{i} = body.envelope.core.work_scope.scope_id;";

/// Seals one completed operation with its exact per-surface outcomes. Last
/// statement before commit; same-operation replay reads this row and returns
/// the stored outcomes without duplicate destructive work (the single
/// completion marker for the intent row above — never a second ledger).
const TX_ERASURE_OUTCOME: &str = "LET $erasure_outcome_existing = (SELECT VALUE { operation_id: operation_id, outcomes: outcomes } FROM ONLY type::record($erasure_outcome_table, $erasure_outcome_id)); IF type::is_object($erasure_outcome_existing) { IF $erasure_outcome_existing.outcomes != $erasure_outcomes { THROW 'erasure_intent_conflict'; }; } ELSE { CREATE type::record($erasure_outcome_table, $erasure_outcome_id) CONTENT $erasure_outcome_record; };";

/// Reads one sealed erasure-outcome row by exact operation id.
const READ_ERASURE_OUTCOME: &str = "SELECT VALUE { operation_id: operation_id, outcomes: outcomes } FROM ONLY type::record($erasure_outcome_table, $erasure_outcome_id);";

/// Session lane carrying one canonical transaction (S-CONC-TX, issue #989).
///
/// Production canonical writes use the pre-pool facade session. The explicit
/// test/private seam routes through the admitted #987 pooled normal-write
/// lane so concurrent tasks execute on real separate sessions; no other lane
/// may carry a canonical transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TxLane {
    Facade,
    PooledWrite,
}

/// Provider markers proving the shared fence/sequence allocation moved while
/// the transaction carried no semantic conflict marker.
///
/// Closed to the canonical fence CAS alone (S-CONC-TX, issue #989, audit
/// `5919482812`): only the fence compare-and-set arbitrates the global
/// commit/outbox cursors. Every owner-row/revision/snapshot marker lives in
/// [`SEMANTIC_CONFLICT_MARKERS`]: such a marker proves an owner row read
/// before the transaction changed before the transaction CAS, i.e.
/// semantic/currentness drift for the named leg, never bare allocation
/// movement. Matching is exact sentinel-token equality (see
/// [`has_marker_token`]), never a substring search over provider prose.
const ALLOCATION_CONFLICT_MARKERS: &[&str] = &[
    "canonical_fence_cas_conflict",
    "canonical_fence_create_conflict",
];

/// Provider markers proving a deterministic semantic conflict: a stale
/// epistemic position, revision head, ordering head, or owner-row
/// predecessor (notification, reactive, automation, experience, learning,
/// finish/canonical/module-registry/capability-evidence owners, swarm,
/// blackboard, task-contract acceptance).
///
/// Each of these proves the admitted operation's semantic input moved under
/// it. The apply loop never retries them as allocation contention and never
/// recomputes the named leg under the old operation identity: they surface
/// as the exact typed semantic/currentness conflict (or demand a separately
/// specified re-admission whose refreshed revisions are bound into identity).
const SEMANTIC_CONFLICT_MARKERS: &[&str] = &[
    "epistemic_position_cas_conflict",
    "revision_head_cas_conflict",
    "revision_head_create_conflict",
    "ordering_head_cas_conflict",
    "ordering_head_create_conflict",
    "finish_owner_cas_conflict",
    "finish_owner_create_conflict",
    "canonical_owner_cas_conflict",
    "canonical_owner_create_conflict",
    "module_registry_owner_cas_conflict",
    "capability_evidence_cas_conflict",
    "capability_evidence_create_conflict",
    "swarm_owner_revision_conflict",
    "blackboard_item_revision_conflict",
    "task_contract_acceptance_revision_conflict",
    "notification_revision_conflict",
    "reactive_session_conflict",
    "reactive_snapshot_conflict",
    "automation_revision_conflict",
    "automation_current_conflict",
    "automation_invocation_conflict",
    "automation_failure_conflict",
    "automation_continuation_guard_conflict",
    "automation_continuation_parent_conflict",
    "experience_bank_conflict",
    "experience_feedback_conflict",
    "learning_record_conflict",
];

/// Reports whether a provider statement error carries the exact closed
/// sentinel token (S-CONC-TX, issue #989, audit `5919482812`).
///
/// The provider contour on this path offers no numeric statement codes: the
/// transport decodes only per-statement `status` plus a free-form `result`
/// string. The closed protocol is therefore exact token equality against the
/// sentinel vocabulary our own `THROW` templates emit. The error is split on
/// every character outside `[0-9A-Za-z_]` and one token must equal the marker
/// exactly, so `THROW 'canonical_fence_cas_conflict'`, `An error occurred:
/// canonical_fence_cas_conflict`, and a bare echoed marker all match, while a
/// longer identifier merely containing the marker
/// (`not_canonical_fence_cas_conflict`, `canonical_fence_cas_confliction`),
/// a translation without the token, or surrounding narration can never match.
/// Retry authority comes from this typed token plus the validated
/// statement-result denominator (see [`write_canonical_transaction`]), never
/// from prose.
fn has_marker_token(error: &str, marker: &str) -> bool {
    error
        .split(|cell: char| !(cell.is_ascii_alphanumeric() || cell == '_'))
        .any(|token| token == marker)
}

/// Reports whether a provider statement error proves shared-allocation
/// movement (fence/sequence CAS).
fn is_allocation_conflict(error: &str) -> bool {
    ALLOCATION_CONFLICT_MARKERS
        .iter()
        .any(|marker| has_marker_token(error, marker))
}

/// Reports whether a provider statement error proves a deterministic
/// semantic conflict (epistemic/revision/ordering/owner-row CAS).
fn is_semantic_conflict(error: &str) -> bool {
    SEMANTIC_CONFLICT_MARKERS
        .iter()
        .any(|marker| has_marker_token(error, marker))
}

/// Provider narration of an aborted transaction's cascade, never an
/// independent statement outcome.
///
/// Observed on a real fence race (S-CONC-TX, issue #989): the fence `THROW`
/// aborts the transaction, and the provider reports one allocation marker
/// plus this deterministic fallout for every unexecuted statement. Those
/// lines assert non-execution, so they carry no outcome evidence of their
/// own. Membership is CLOSED EXACT matching (see [`is_abort_fallout`]): any
/// rewording, localization, or additional observation fails closed to
/// [`AdapterError::UnknownOutcome`] for same-operation reconciliation — a
/// safe direction, never a blind retry. A genuine transport ambiguity
/// (`"connection reset during COMMIT"`, timeouts, duplicate creates) never
/// equals these strings and still resolves unknown.
const TRANSACTION_ABORT_FALLOUT_MARKERS: &[&str] = &[
    "The query was not executed due to a failed transaction",
    "The query was not executed due to a cancelled transaction",
    "Cannot COMMIT: the transaction was aborted due to a prior error",
];

/// Reports whether a provider statement error is aborted-transaction
/// cascade narration rather than an executed statement's outcome.
///
/// Closed exact match only: one layer of JSON string quoting (the transport
/// pushes `result.to_string()`) and one optional `An error occurred: ` wrap
/// are stripped, then the remainder must EQUAL a member of
/// [`TRANSACTION_ABORT_FALLOUT_MARKERS`]. No substring search, no prose
/// inference: an error carrying any sentinel token is evidence regardless of
/// narration, and any other deviation is unknown.
fn is_abort_fallout(error: &str) -> bool {
    let unquoted = strip_json_string_quotes(error.trim());
    let bare = unquoted
        .strip_prefix("An error occurred: ")
        .unwrap_or(unquoted);
    TRANSACTION_ABORT_FALLOUT_MARKERS.contains(&bare)
}

/// Strips one layer of JSON string quoting from a transported provider
/// error: `result.to_string()` renders a `Value::String` with surrounding
/// double quotes, which carry no outcome meaning.
fn strip_json_string_quotes(error: &str) -> &str {
    if error.len() >= 2 && error.starts_with('"') && error.ends_with('"') {
        &error[1..error.len() - 1]
    } else {
        error
    }
}

/// Classifies one canonical-transaction statement-error set without wildcard
/// collapse (S-CONC-TX, issue #989, audit `5919482812`).
///
/// Closed typed protocol over the transaction's own sentinel vocabulary:
///
/// - a deterministic semantic token anywhere in the set wins: the head or
///   owner row it names is stale regardless of fence movement, so the
///   outcome is [`AdapterError::ProviderConflict`] and the apply loop never
///   retries it as contention and never recomputes the named leg under the
///   old operation identity;
/// - otherwise, pure fence/sequence movement is transient allocation
///   contention on proved-not-committed ground (the fence CAS precedes the
///   receipt create in statement order, so its abort commits nothing) — but
///   ONLY when the set carries at least one exact fence token and every
///   other member is either an exact fence token or exact aborted-transaction
///   cascade narration, which asserts non-execution and is non-evidence;
/// - anything else (mixed allocation-plus-unknown, bare cascade, transport
///   ambiguity, duplicate creates, malformed rows) is
///   [`AdapterError::UnknownOutcome`] resolved by exact same-operation
///   receipt reconciliation, never retried blindly and never reported as a
///   semantic conflict.
///
/// No trustworthy code is inferred from arbitrary prose: sentinels match by
/// exact token equality ([`has_marker_token`]), cascade by exact full-string
/// equality ([`is_abort_fallout`]). [`AdapterError::AllocationContention`] is
/// the only outcome that re-enters the transaction loop, and it requires
/// positive fence evidence.
fn classify_transaction_errors(errors: &[String], operation_id: &str) -> AdapterError {
    debug_assert!(
        !errors.is_empty(),
        "classification runs only on a non-empty statement-error set"
    );
    if errors
        .iter()
        .any(|error| has_marker_token(error, "automation_normalization_identity_conflict"))
    {
        return AdapterError::Store(StoreError::IdentityConflict);
    }
    if errors.iter().any(|error| is_semantic_conflict(error)) {
        return AdapterError::ProviderConflict;
    }
    let has_allocation = errors.iter().any(|error| is_allocation_conflict(error));
    if has_allocation
        && errors
            .iter()
            .all(|error| is_allocation_conflict(error) || is_abort_fallout(error))
    {
        return AdapterError::AllocationContention {
            operation_id: operation_id.to_owned(),
        };
    }

    AdapterError::UnknownOutcome {
        operation_id: operation_id.to_owned(),
    }
}

/// Typed terminal allocation proof returned by the canonical transaction
/// itself (S-CONC-TX, issue #989, audit `5919482812`).
///
/// Decoded from the [`schema::TX_ALLOC_PROOF`] result slot — the
/// second-to-last statement result, immediately before `COMMIT` — on every
/// error-free RPC. The writer requires exact operation binding plus exact
/// allocation equality against the attempted plan; a missing, duplicate,
/// malformed, or mismatched slot is a possible-commit outcome for
/// same-operation reconciliation, never a local success. Unknown provider
/// fields are tolerated on read (no `deny_unknown_fields`); every
/// load-bearing value is compared exactly after decode.
#[derive(serde::Deserialize)]
struct AllocationProof {
    operation_id: String,
    commit_sequence: u64,
    next_commit_sequence: u64,
    next_outbox_sequence: u64,
}

/// Counts the top-level statements of one assembled canonical transaction.
///
/// The provider returns exactly one result slot per executed statement, so
/// this count is the closed expected result denominator the writer validates
/// against (`values_len` equality is proven through indexed `take`s, the only
/// result accessor this contour owns). Quote- and brace-aware: `;` inside
/// single/double-quoted literals (every `THROW` sentinel) or inside `{...}`
/// blocks (every `IF` body) never counts. Covers only the closed templates
/// this writer assembles — never caller-supplied query text.
fn count_transaction_statements(sql: &str) -> usize {
    let mut count = 0_usize;
    let mut depth = 0_usize;
    let mut quote: Option<char> = None;
    for cell in sql.chars() {
        if let Some(open) = quote {
            if cell == open {
                quote = None;
            }
            continue;
        }
        match cell {
            '\'' | '"' => quote = Some(cell),
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
#[cfg(test)]
pub(super) async fn write_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
    current_revisions: &[RevisionHead],
    current_orderings: &[OrderingHead],
    lane: TxLane,
    notifications: &[super::surreal_notification::SurrealNotificationWrite],
    reactive: &ReactiveWrites,
    automation: &AutomationWrites,
    experience: &ExperienceWrites,
    learning: &LearningWrites,
) -> Result<(), AdapterError> {
    write_canonical_transaction(
        db,
        config,
        transition,
        plan,
        receipt,
        initial_state,
        expected_commit_sequence,
        expected_outbox_sequence,
        current_revisions,
        current_orderings,
        lane,
        notifications,
        reactive,
        automation,
        experience,
        learning,
        None,
    )
    .await
}

/// Sends one assembled canonical transaction and validates its complete
/// provider result (S-CONC-TX, issue #989, audit `5919482812`).
///
/// Closed success protocol, in order:
///
/// 1. the transport sends the single `BEGIN`/`COMMIT` transaction (transport
///    loss maps to [`AdapterError::UnknownOutcome`], never to a retry);
/// 2. a non-empty statement-error set classifies through
///    [`classify_transaction_errors`] (exact sentinel tokens only);
/// 3. an error-free RPC must still prove its commit: the exact statement
///    count ([`count_transaction_statements`]) must decode slot-for-slot —
///    the terminal [`AllocationProof`] at the proof index must carry the
///    attempted operation identity and allocation, and no trailing slot may
///    exist past `COMMIT`.
///
/// Every failure at step 3 is a possible-commit outcome for same-operation
/// receipt reconciliation — an error-free RPC is never treated as a
/// committed exact receipt on its own. The caller additionally compares the
/// durable receipt/fence/event/outbox readback before returning success (see
/// `apply.rs::verify_durable_commit_bundle`).
///
/// `erasure` carries an admitted erasure intent's in-transaction fragment
/// (intent upsert, scrub pairs, outcome seal) spliced before the receipt
/// create when the transition class is `Erasure`; `None` assembles the
/// receipt-only boundary. Either way the whole bundle commits in this one
/// transaction — a destructive effect never commits ahead of it.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
#[cfg(test)]
pub(super) async fn write_canonical_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
    current_revisions: &[RevisionHead],
    current_orderings: &[OrderingHead],
    lane: TxLane,
    notifications: &[super::surreal_notification::SurrealNotificationWrite],
    reactive: &ReactiveWrites,
    automation: &AutomationWrites,
    experience: &ExperienceWrites,
    learning: &LearningWrites,
    erasure: Option<ErasureInTx>,
) -> Result<(), AdapterError> {
    write_canonical_transaction_with_expected_heads(
        db,
        config,
        transition,
        plan,
        receipt,
        initial_state,
        expected_commit_sequence,
        expected_outbox_sequence,
        current_revisions,
        current_orderings,
        &[],
        &[],
        &OrderingChainTips::new(),
        lane,
        notifications,
        reactive,
        automation,
        experience,
        learning,
        erasure,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
pub(super) async fn write_canonical_transaction_with_expected_heads(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
    current_revisions: &[RevisionHead],
    current_orderings: &[OrderingHead],
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
    current_chain_tips: &OrderingChainTips,
    lane: TxLane,
    notifications: &[super::surreal_notification::SurrealNotificationWrite],
    reactive: &ReactiveWrites,
    automation: &AutomationWrites,
    experience: &ExperienceWrites,
    learning: &LearningWrites,
    erasure: Option<ErasureInTx>,
) -> Result<(), AdapterError> {
    let operation_id = transition.identity.operation_id.to_string();
    let (mut sql, mut bindings) = build_apply_statements(
        transition,
        plan,
        receipt,
        initial_state,
        expected_commit_sequence,
        expected_outbox_sequence,
        current_revisions,
        current_orderings,
        notifications,
        reactive,
        automation,
        experience,
        learning,
    )?;
    let (head_checks, head_bindings) = expected_head_predicates(
        expected_revision_heads,
        expected_ordering_heads,
        &transition.state_fence,
        current_chain_tips,
    )?;
    sql.insert_str(schema::TX_BEGIN.len(), &head_checks);
    for (name, value) in head_bindings {
        if bindings.insert(name, value).is_some() {
            return Err(AdapterError::Serialization(
                "expected head binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    if let Some(erasure) = erasure {
        // The erasure bundle joins the canonical atomic unit ahead of the
        // receipt create (intent before destructive scrubs, seal before the
        // linearization point), inside this same `BEGIN`/`COMMIT`.
        let receipt_at = sql.rfind(schema::TX_CREATE_RECEIPT).ok_or_else(|| {
            AdapterError::Serialization(
                "canonical transaction is missing its receipt create".to_owned(),
            )
        })?;
        sql.insert_str(receipt_at, &erasure.sql_fragment);
        for (name, value) in erasure.bindings {
            if bindings.insert(name.clone(), value).is_some() {
                return Err(AdapterError::Serialization(
                    "erasure binding collided with a canonical binding".to_owned(),
                ));
            }
        }
    }
    // 688-B classifies provider replies after the atomic RPC: deterministic
    // fence/head markers are conflicts, while an unavailable or unclassified
    // reply remains an unknown outcome for identity-based reconciliation.
    let unknown = || AdapterError::UnknownOutcome {
        operation_id: operation_id.clone(),
    };
    let mut response = match send_transaction(db, config, &sql, bindings, lane).await {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => return Err(unknown()),
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(classify_transaction_errors(&errors, &operation_id));
    }
    let expected_statements = count_transaction_statements(&sql);
    if expected_statements < 2 {
        return Err(unknown());
    }
    let proof: AllocationProof = response
        .take(expected_statements - 2)
        .map_err(|_| unknown())?;
    if proof.operation_id != operation_id
        || proof.commit_sequence != plan.commit_sequence
        || proof.next_commit_sequence != plan.next_commit_sequence
        || proof.next_outbox_sequence != plan.next_outbox_sequence
    {
        return Err(unknown());
    }
    if response.take::<Value>(expected_statements).is_ok() {
        return Err(unknown());
    }
    Ok(())
}

/// Builds transaction-local predicates for every independently declared
/// expected head. The ordering chain hash is the exact pre-plan observation
/// that produced the planned next link; the transaction compares that same
/// stored sibling field before any canonical mutation.
fn expected_head_predicates(
    revisions: &[RevisionHeadExpectation],
    orderings: &[OrderingHeadExpectation],
    state_fence: &StateFence,
    chain_tips: &OrderingChainTips,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, expected) in revisions.iter().enumerate() {
        expected.validate()?;
        if expected.state_fence != *state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
        let suffix = index.to_string();
        sql.push_str(&schema::indexed(schema::TX_VERIFY_EXPECTED_REVISION, index));
        bindings.insert(
            format!("expected_revision_table{suffix}"),
            json!(schema::table::REVISION_HEAD),
        );
        bindings.insert(
            format!("expected_revision_key{suffix}"),
            json!(expected.key.to_string()),
        );
        bindings.insert(
            format!("expected_revision_value{suffix}"),
            json!(expected.expected_revision),
        );
        bindings.insert(
            format!("expected_revision_fence{suffix}"),
            json!(expected.state_fence),
        );
    }
    for (index, expected) in orderings.iter().enumerate() {
        expected.validate()?;
        if expected.state_fence != *state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
        let suffix = index.to_string();
        let scope = expected.scope.to_string();
        let expected_hash = chain_tips
            .get(&scope)
            .map_or(ORDERING_LINK_GENESIS_HASH, String::as_str);
        sql.push_str(&schema::indexed(schema::TX_VERIFY_EXPECTED_ORDERING, index));
        bindings.insert(
            format!("expected_ordering_table{suffix}"),
            json!(schema::table::ORDERING_HEAD),
        );
        bindings.insert(format!("expected_ordering_scope{suffix}"), json!(scope));
        bindings.insert(
            format!("expected_ordering_sequence{suffix}"),
            json!(expected.expected_sequence),
        );
        bindings.insert(
            format!("expected_ordering_fence{suffix}"),
            json!(expected.state_fence),
        );
        bindings.insert(
            format!("expected_ordering_hash{suffix}"),
            json!(expected_hash),
        );
        bindings.insert(
            format!("ordering_genesis_hash{suffix}"),
            json!(ORDERING_LINK_GENESIS_HASH),
        );
    }
    Ok((sql, bindings))
}

/// Sends one assembled canonical transaction on the selected lane.
///
/// Both lanes use the identical parameterized `query` RPC and binding codec;
/// only the session differs (facade vs pooled normal-write).
async fn send_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    sql: &str,
    bindings: Map<String, Value>,
    lane: TxLane,
) -> Result<client::RpcResults, AdapterError> {
    match lane {
        TxLane::Facade => client::query(db, config, "transaction.apply", sql, bindings).await,
        TxLane::PooledWrite => db.query_write("transaction.apply", sql, bindings).await,
    }
}

/// Assembles one canonical apply transaction (pure SQL + bindings).
///
/// Statement order is the commit boundary: epistemic CAS, fence CAS/create,
/// revision CAS/create, ordering CAS/create(s), event/projection/relation/
/// outbox creates, receipt create, terminal allocation proof — all inside one
/// `BEGIN`/`COMMIT`. Every declared expected revision head, ordering head,
/// and the fence allocation is verified inside this transaction immediately
/// before applying changes; shared allocation contention never waives those
/// checks. An admitted erasure bundle is spliced ahead of the receipt create
/// by [`write_canonical_transaction`], never in a side transaction.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
fn build_apply_statements(
    transition: &eliot_store_api::PreparedTransition,
    plan: &ApplyPlan,
    receipt: &WriteReceipt,
    initial_state: bool,
    expected_commit_sequence: u64,
    expected_outbox_sequence: u64,
    current_revisions: &[RevisionHead],
    current_orderings: &[OrderingHead],
    notifications: &[super::surreal_notification::SurrealNotificationWrite],
    reactive: &ReactiveWrites,
    automation: &AutomationWrites,
    experience: &ExperienceWrites,
    learning: &LearningWrites,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let operation_id = transition.identity.operation_id.to_string();
    let revision = plan.next_revision_heads.first().ok_or_else(|| {
        AdapterError::Serialization(
            "prepared transition plan is missing its required revision head".to_owned(),
        )
    })?;
    let mut sql = String::from(schema::TX_BEGIN);
    let mut bindings = Map::new();
    let context = &receipt
        .require_reconciliation_envelope()?
        .core
        .request
        .metadata;
    let epistemic = EpistemicCommit::from_prepared(context, transition)?;
    if let Some(commit) = &epistemic {
        commit.readback(receipt)?;
        sql.push_str(EPISTEMIC_CAS);
        bindings.insert(
            "expected_predecessor_digest".to_owned(),
            json!(
                commit
                    .payload
                    .candidate
                    .predecessor
                    .as_ref()
                    .map_or("", |id| id.as_str())
            ),
        );
        bindings.insert(
            "epistemic_position_key".to_owned(),
            json!(commit.payload.position_key()?),
        );
        bindings.insert(
            "expected_position_revision".to_owned(),
            json!(commit.payload.expected_position_revision.map_or(
                0,
                eliot_store_api::epistemic_revision::PositionRevision::value
            )),
        );
    }

    sql.push_str(if initial_state {
        schema::TX_CREATE_FENCE
    } else {
        schema::TX_UPSERT_FENCE
    });
    bindings.insert(
        "fence_table".to_owned(),
        json!(schema::table::CANONICAL_FENCE),
    );
    bindings.insert("fence_key".to_owned(), json!(schema::FENCE_KEY));
    bindings.insert(
        "fence".to_owned(),
        json!({
            "state_fence": transition.state_fence,
            "next_commit_sequence": plan.next_commit_sequence,
            "next_outbox_sequence": plan.next_outbox_sequence,
        }),
    );
    bindings.insert(
        "expected_state_fence".to_owned(),
        json!(transition.state_fence),
    );
    bindings.insert(
        "expected_commit_sequence".to_owned(),
        json!(expected_commit_sequence),
    );
    bindings.insert(
        "expected_outbox_sequence".to_owned(),
        json!(expected_outbox_sequence),
    );

    let revision_exists = current_revisions
        .iter()
        .any(|head| head.key == revision.key);
    sql.push_str(revision_write_template(initial_state, revision_exists));
    bindings.insert(
        "revision_table".to_owned(),
        json!(schema::table::REVISION_HEAD),
    );
    bindings.insert("revision_key".to_owned(), json!(revision.key.to_string()));
    bindings.insert(
        "revision_record".to_owned(),
        json!({
            "revision_key": revision.key.to_string(),
            "body": to_value(revision)?,
        }),
    );
    bindings.insert(
        "expected_revision".to_owned(),
        json!(
            plan.revision_before_after
                .first()
                .map_or(1, |delta| delta.before)
        ),
    );

    for (index, head) in plan.next_ordering_heads.iter().enumerate() {
        let ordering_exists = current_orderings
            .iter()
            .any(|current| current.scope == head.scope);
        let template = ordering_write_template(initial_state, ordering_exists);
        sql.push_str(&schema::indexed(template, index));
        let suffix = index.to_string();
        // Issue #1931: the per-scope chain tip rides the same CAS-guarded
        // `CREATE`/`UPDATE ... CONTENT` as the neutral `OrderingHead` body, so
        // the head and its chain tip advance atomically or not at all. The
        // shipped `OrderingHead` serde boundary is unchanged: both hashes are
        // sibling fields on the schemaless record, invisible to every
        // `SELECT VALUE body` reader.
        let link = chain_link_for_scope(plan, head)?;
        bindings.insert(
            format!("ordering_table{suffix}"),
            json!(schema::table::ORDERING_HEAD),
        );
        bindings.insert(
            format!("ordering_scope{suffix}"),
            json!(head.scope.to_string()),
        );
        bindings.insert(
            format!("ordering_record{suffix}"),
            json!({
                "ordering_scope": head.scope.to_string(),
                "body": to_value(head)?,
                "previous_event_hash": link.previous_event_hash,
                "event_hash": link.event_hash,
            }),
        );
        bindings.insert(
            format!("expected_ordering_sequence{suffix}"),
            json!(head.sequence.saturating_sub(1)),
        );
    }

    for (index, event_id) in plan.event_ids.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_EVENT, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("event_table{suffix}"),
            json!(schema::table::CANONICAL_EVENT),
        );
        bindings.insert(format!("event_id{suffix}"), json!(event_id.to_string()));
        // Issue #1931: the durable event row now carries the whole canonical
        // event — one identity, the payload digest, the monotonic ordinal, the
        // fence, and one hash-chain link per declared Ordering Scope — plus the
        // transition's audit-chain digest, in the same statement and therefore
        // the same transaction as the receipt and outbox rows below.
        bindings.insert(
            format!("event{suffix}"),
            json!({
                "event_id": event_id.to_string(),
                "operation_id": operation_id,
                "body": to_value(&plan.canonical_event)?,
                "audit_chain_digest": plan.audit_chain_digest,
            }),
        );
    }

    for (index, projection) in plan.projection_records.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_PROJECTION, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("projection_table{suffix}"),
            json!(schema::table::PROJECTION_RECORD),
        );
        bindings.insert(
            format!("publication_id{suffix}"),
            json!(projection.publication_id.to_string()),
        );
        bindings.insert(
            format!("projection{suffix}"),
            json!({
                "publication_id": projection.publication_id.to_string(),
                "body": to_value(projection)?,
            }),
        );
    }

    for (index, relation_kind) in transition
        .event_projection_relation_intents
        .relation_kinds
        .iter()
        .enumerate()
    {
        sql.push_str(&schema::indexed(schema::TX_CREATE_RELATION, index));
        let suffix = index.to_string();
        let relation_id = format!("relation-{operation_id}-{index}");
        bindings.insert(
            format!("relation_table{suffix}"),
            json!(schema::table::RELATION_RECORD),
        );
        bindings.insert(format!("relation_id{suffix}"), json!(&relation_id));
        bindings.insert(
            format!("relation{suffix}"),
            json!({
                "relation_id": relation_id,
                "relation_kind": relation_kind,
                "operation_id": operation_id,
                "state_fence": transition.state_fence,
            }),
        );
    }

    for (index, outbox) in plan.outbox_records.iter().enumerate() {
        sql.push_str(&schema::indexed(schema::TX_CREATE_OUTBOX, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("outbox_table{suffix}"),
            json!(schema::table::OUTBOX_EVENT),
        );
        bindings.insert(
            format!("outbox_id{suffix}"),
            json!(outbox.outbox_id.to_string()),
        );
        bindings.insert(
            format!("outbox{suffix}"),
            json!({
                "outbox_id": outbox.outbox_id.to_string(),
                "operation_id": operation_id,
                "sequence": outbox.sequence,
                "body": to_value(outbox)?,
            }),
        );
    }

    append_notification_statements(&mut sql, &mut bindings, notifications)?;

    append_reactive_statements(&mut sql, &mut bindings, reactive)?;

    append_automation_statements(&mut sql, &mut bindings, automation)?;

    // #223 experience writes and #325 finish owner snapshots commit atomically
    // with the canonical receipt.
    append_experience_statements(&mut sql, &mut bindings, experience)?;
    append_swarm_owner_revision_statements(&mut sql, &mut bindings, transition)?;
    append_blackboard_item_statements(&mut sql, &mut bindings, transition)?;
    append_task_contract_acceptance_statements(&mut sql, &mut bindings, transition)?;
    // #1868 learning-record writes commit atomically beside the experience
    // rows under the same create-or-converge contract.
    append_learning_statements(&mut sql, &mut bindings, learning)?;
    // #1773 capability-evidence rows commit atomically beside the learning
    // rows under the same fenced compare-and-set contract.
    append_capability_evidence_owner_statements(&mut sql, &mut bindings, transition)?;
    append_module_registry_owner_statement(&mut sql, &mut bindings, transition)?;
    append_finish_evidence_owner_statement(&mut sql, &mut bindings, transition)?;
    append_finish_owner_statement(&mut sql, &mut bindings, transition)?;

    sql.push_str(schema::TX_CREATE_RECEIPT);
    bindings.insert(
        "receipt_table".to_owned(),
        json!(schema::table::WRITE_RECEIPT),
    );
    bindings.insert("receipt_operation_id".to_owned(), json!(operation_id));
    bindings.insert(
        "receipt".to_owned(),
        json!({
            "operation_id": receipt.operation_id.to_string(),
            "idempotency_key": receipt.idempotency_key,
            "body": to_value(receipt)?,
            // Opaque payload authorities (issue #10): exact versioned,
            // digest-bound bytes persisted alongside — never inside —
            // the queryable `body` projections above. An empty array means
            // the transition claimed no authority; receipt `body` readback
            // selects `body` only, so this field changes no read path.
            "payload_authority": payload_authority_binding(&plan.payload_authority)?,
            // Recoverable capture evidence (T11.1, #19): full subject +
            // exact bytes + provenance per `CaptureObservation`, persisted
            // atomically with the receipt so the closed evidence SELECT can
            // serve `GetEvidencePack` with memory parity. Empty when the
            // transition carries no capture; pre-change receipts lack this
            // field and read as absent (never as an error).
            "evidence_records": evidence_binding(&plan.evidence_records)?,
            "commit_sequence": plan.commit_sequence,
            "named_operation_count": transition.named_operations.len(),
            "epistemic_position_key": epistemic.as_ref().map(|commit| commit.payload.position_key()).transpose()?,
            "epistemic_position_revision": epistemic.as_ref().map(|commit| commit.payload.next_revision().map(eliot_store_api::epistemic_revision::PositionRevision::value)).transpose()?,
            "epistemic_candidate_digest": epistemic.as_ref().map(|commit| &commit.payload.candidate.digest),
            "epistemic_payload": epistemic.as_ref().map(serde_json::to_string).transpose()
                .map_err(|error| AdapterError::Serialization(error.to_string()))?,
        }),
    );

    sql.push_str(schema::TX_ALLOC_PROOF);
    bindings.insert("alloc_operation_id".to_owned(), json!(operation_id));
    bindings.insert(
        "alloc_commit_sequence".to_owned(),
        json!(plan.commit_sequence),
    );
    bindings.insert(
        "alloc_next_commit_sequence".to_owned(),
        json!(plan.next_commit_sequence),
    );
    bindings.insert(
        "alloc_next_outbox_sequence".to_owned(),
        json!(plan.next_outbox_sequence),
    );

    sql.push_str(schema::TX_COMMIT);
    Ok((sql, bindings))
}

/// Binds one ordering head to the canonical event's link for the same scope.
///
/// The event is issued from the same `next_ordering_heads`, so every head has
/// exactly one link; a missing link means the plan and the event disagree and
/// the transaction is refused before it is sent rather than advancing a head
/// with no chain link.
fn chain_link_for_scope<'plan>(
    plan: &'plan ApplyPlan,
    head: &OrderingHead,
) -> Result<&'plan eliot_store_api::OrderingLink, AdapterError> {
    plan.canonical_event
        .ordering_links
        .iter()
        .find(|link| link.ordering_scope == head.scope)
        .ok_or_else(|| {
            AdapterError::Serialization(
                "prepared transition plan has an ordering head without a canonical event link"
                    .to_owned(),
            )
        })
}

/// Appends the Governor-produced current Module Catalog owner image.
///
/// The adapter keeps the snapshot opaque and only performs the fixed
/// `owner/module_registry` fenced revision CAS. Governor derives the admitted
/// generation from its desired manifest and must read the exact committed
/// image back before publishing a Kernel execution manifest.
fn append_module_registry_owner_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let Some(command) = transition.named_operations.iter().find(|command| {
        command.operation == eliot_store_api::NamedMutationOperation::RecordModuleCatalogSnapshot
    }) else {
        return Ok(());
    };
    if transition.transition_class != eliot_store_api::TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let expected_revision = text_param("expected_module_registry_revision")?
        .parse::<u64>()
        .map_err(|_| {
            AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "expected_module_registry_revision must be a decimal revision",
            })
        })?;
    if expected_revision == 0 {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "module_registry.owner_revision",
            reason: "the genesis owner record must already exist",
        }));
    }
    let snapshot_json = text_param("snapshot_json")?;
    if snapshot_json.is_empty() {
        return Err(AdapterError::Store(StoreError::Empty {
            field: "module_registry.snapshot_json",
        }));
    }
    if snapshot_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }

    let key = eliot_store_api::RecoveryRecordKey::new("owner", "module_registry")
        .map_err(AdapterError::Store)?;
    let owner_id = recovery_owner_id(&key)?;
    let payload = snapshot_json.as_bytes();
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(key.namespace));
    record.insert("key".to_owned(), json!(key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert(
        "revision".to_owned(),
        json!(expected_revision.checked_add(1).ok_or({
            AdapterError::Store(StoreError::InvalidField {
                field: "module_registry.owner_revision",
                reason: "revision overflow",
            })
        })?),
    );
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::OWNER_SNAPSHOT_SCHEMA),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );

    sql.push_str(schema::TX_MODULE_REGISTRY_OWNER);
    bindings.insert(
        "module_registry_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("module_registry_owner_id".to_owned(), json!(owner_id));
    bindings.insert(
        "module_registry_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "module_registry_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "module_registry_owner_record".to_owned(),
        Value::Object(record),
    );
    Ok(())
}

/// Appends the Governor-produced canonical finish-evidence owner image.
///
/// The adapter keeps the snapshot opaque and only performs the fixed
/// `owner/canonical` fenced revision CAS. Governor has already validated and
/// derived the evidence from its task, observation, coordination, and plan
/// owners before this statement is assembled.
fn append_finish_evidence_owner_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let Some(command) = transition.named_operations.iter().find(|command| {
        command.operation == eliot_store_api::NamedMutationOperation::RecordFinishEvidence
    }) else {
        return Ok(());
    };
    if transition.transition_class != eliot_store_api::TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let expected_revision = text_param("expected_canonical_revision")?
        .parse::<u64>()
        .map_err(|_| {
            AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "expected_canonical_revision must be a decimal revision",
            })
        })?;
    let snapshot_json = text_param("snapshot_json")?;
    if snapshot_json.is_empty() {
        return Err(AdapterError::Store(StoreError::Empty {
            field: "canonical.finish_evidence_snapshot_json",
        }));
    }
    if snapshot_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }

    let canonical_key = eliot_store_api::RecoveryRecordKey::new("owner", "canonical")
        .map_err(AdapterError::Store)?;
    let owner_id = recovery_owner_id(&canonical_key)?;
    let payload = snapshot_json.as_bytes();
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(canonical_key.namespace));
    record.insert("key".to_owned(), json!(canonical_key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert(
        "revision".to_owned(),
        json!(expected_revision.checked_add(1).ok_or_else(|| {
            AdapterError::Store(StoreError::InvalidField {
                field: "canonical.owner_revision",
                reason: "revision overflow",
            })
        })?),
    );
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::OWNER_SNAPSHOT_SCHEMA),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );

    sql.push_str(schema::TX_CANONICAL_OWNER);
    bindings.insert(
        "canonical_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("canonical_owner_id".to_owned(), json!(owner_id));
    bindings.insert(
        "canonical_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "canonical_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert("canonical_owner_record".to_owned(), Value::Object(record));
    Ok(())
}

/// Appends the single Governor-owned finish persistence leg, when present.
///
/// The adapter does not decode or derive a finish decision.  It binds the
/// admitted receipt bytes verbatim to the fixed `owner/finish` recovery row
/// and lets the provider arbitrate the exact fence and outer revision inside
/// the same canonical transaction as the receipt.  The Governor remains the
/// owner of all finish semantics and evidence.
fn append_finish_owner_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let Some(command) = transition.named_operations.iter().find(|command| {
        command.operation == eliot_store_api::NamedMutationOperation::RecordFinishDecision
    }) else {
        return Ok(());
    };
    if transition.transition_class != eliot_store_api::TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let text_param = |name: &'static str| {
        command
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            }))
    };
    let attempt_id = text_param("attempt_id")?;
    let expected_revision = text_param("expected_finish_revision")?
        .parse::<u64>()
        .map_err(|_| {
            AdapterError::Store(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "expected_finish_revision must be a decimal revision",
            })
        })?;
    let receipt_json = text_param("receipt_json")?;
    if receipt_json.is_empty() {
        return Err(AdapterError::Store(StoreError::Empty {
            field: "finish.receipt_json",
        }));
    }
    if receipt_json.len() > eliot_store_api::MAX_RECOVERY_RECORD_BYTES {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }

    let finish_key =
        eliot_store_api::RecoveryRecordKey::new("owner", "finish").map_err(AdapterError::Store)?;
    let owner_id = recovery_owner_id(&finish_key)?;
    let payload = receipt_json.as_bytes();
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(finish_key.namespace));
    record.insert("key".to_owned(), json!(finish_key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert(
        "revision".to_owned(),
        json!(expected_revision.checked_add(1).ok_or_else(|| {
            AdapterError::Store(StoreError::InvalidField {
                field: "finish.owner_revision",
                reason: "revision overflow",
            })
        })?),
    );
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::OWNER_SNAPSHOT_SCHEMA),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );

    sql.push_str(schema::TX_FINISH_OWNER);
    bindings.insert(
        "finish_owner_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("finish_owner_id".to_owned(), json!(owner_id));
    bindings.insert(
        "finish_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "finish_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert("finish_owner_record".to_owned(), Value::Object(record));
    // Keep the attempt identity bound in the assembled transaction even
    // though the storage layer treats the receipt payload as opaque.  This
    // prevents a future caller from silently dropping the required parameter
    // while preserving Governor ownership of its interpretation.
    bindings.insert("finish_attempt_id".to_owned(), json!(attempt_id));
    Ok(())
}

fn recovery_owner_id(key: &eliot_store_api::RecoveryRecordKey) -> Result<String, AdapterError> {
    let bytes = eliot_store_api::canonical_json_bytes(key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(eliot_store_api::sha256_hex(&bytes))
}

/// Appends the admitted Governor capability-evidence row writes (issue #1773,
/// I3.4).
///
/// One fenced compare-and-set per admitted command, against the
/// `capability-evidence-v1` namespace in the canonical `recovery_owner` table
/// — the same durable owner-row contour the finish-evidence owner image and the
/// blackboard revisions already use, so no new table and no migration chain
/// change is introduced. The evidence document travels as opaque bytes and the
/// adapter arbitrates only the row address, the fence, and the outer revision;
/// it never derives status, source, scope fingerprint, limitations, or
/// requalification semantics from the document.
///
/// The issued `revision` is `expected + 1`, and that value is the owner-issued
/// immutable revision the Governor registry orders same-key evidence by and
/// receives back verbatim from
/// `GetCapabilityEvidenceRecordRange`. A delayed writer holding a stale
/// predecessor trips `capability_evidence_cas_conflict` inside the canonical
/// transaction, so it never commits a row and never reaches the registry.
fn append_capability_evidence_owner_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let mut matching = transition.named_operations.iter().filter(|command| {
        command.operation == eliot_store_api::NamedMutationOperation::RecordCapabilityEvidenceRecord
    });
    let Some(command) = matching.next() else {
        return Ok(());
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "capability_evidence.named_operations",
        }));
    }
    if transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let decoded = eliot_store_api::decode_capability_evidence_mutation(
        command.operation,
        &command.parameters,
    )
    .map_err(AdapterError::Store)?;
    let row_key =
        eliot_store_api::capability_evidence_row_key(&decoded.skill_id, &decoded.scope_key);
    let owner_id = recovery_owner_id(&row_key)?;
    let payload = decoded.record_json.as_bytes();
    let expected_revision = decoded.expected_canonical_revision;
    let revision =
        expected_revision
            .checked_add(1)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "capability_evidence.revision",
                reason: "capability evidence revision overflow",
            }))?;
    let mut record = Map::new();
    record.insert("namespace".to_owned(), json!(row_key.namespace));
    record.insert("key".to_owned(), json!(row_key.key));
    record.insert("state_fence".to_owned(), json!(&transition.state_fence));
    record.insert("revision".to_owned(), json!(revision));
    record.insert(
        "schema".to_owned(),
        json!(eliot_store_api::CAPABILITY_EVIDENCE_STORE_SCHEMA_V1),
    );
    record.insert("payload".to_owned(), json!(payload));
    record.insert(
        "value_digest".to_owned(),
        json!(eliot_store_api::sha256_hex(payload)),
    );
    // The owner-declared identity parts travel as row fields so a read can
    // project them without parsing the opaque document. They are the exact
    // parts the deterministic row address was derived from.
    record.insert("skill_id".to_owned(), json!(decoded.skill_id));
    record.insert("scope_key".to_owned(), json!(decoded.scope_key));
    record.insert("record_digest".to_owned(), json!(decoded.record_digest));
    record.insert(
        "scope_id".to_owned(),
        json!(transition.scope_id.to_string()),
    );

    sql.push_str(schema::TX_CAPABILITY_EVIDENCE_OWNER);
    bindings.insert(
        "capability_evidence_table".to_owned(),
        json!(schema::table::RECOVERY_OWNER),
    );
    bindings.insert("capability_evidence_id".to_owned(), json!(owner_id));
    bindings.insert(
        "capability_evidence_expected_state_fence".to_owned(),
        json!(&transition.state_fence),
    );
    bindings.insert(
        "capability_evidence_expected_revision".to_owned(),
        json!(expected_revision),
    );
    bindings.insert(
        "capability_evidence_record".to_owned(),
        Value::Object(record),
    );
    Ok(())
}

/// Appends canonical notification record writes (issue #1780).
///
/// One compare-and-set per computed write, assembled from the pre-transaction
/// model computation: creates refuse when a row already exists, updates
/// refuse on missing rows or revision drift. Drift surfaces the
/// `notification_revision_conflict` marker, which the classifier reports as
/// the exact typed semantic/currentness conflict: the apply loop never
/// retries it as allocation contention and never recomputes the leg under
/// the old operation identity. Record rows commit in the same transaction
/// as the receipt and outbox rows below, so record, receipt, and outbox
/// stay atomic.
fn append_notification_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    notifications: &[super::surreal_notification::SurrealNotificationWrite],
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) =
        super::surreal_notification::notification_write_statements(notifications);
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "notification binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends canonical automation row writes (issue #1779).
///
/// Same atomicity contract as the sibling fragments: revision
/// create-or-converge, pointer compare-and-set, and invocation
/// create-or-converge rows commit in the same transaction as the receipt
/// and outbox rows. Binding collisions fail closed instead of silently
/// overwriting a canonical binding.
fn append_automation_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    automation: &AutomationWrites,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) = automation_write_statements(automation);
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "automation binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends canonical experience bank/feedback row writes (issue #223).
///
/// Same atomicity contract as the automation fragment: create-or-converge
/// rows commit in the same transaction as the receipt and outbox rows.
/// Binding collisions fail closed instead of silently overwriting a
/// canonical binding.
fn append_experience_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    experience: &ExperienceWrites,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) = experience_write_statements(experience);
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "experience binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends the owner-separated swarm record and revision head when the named
/// operation is present in the transition (#1702).
///
/// Immutable record bytes, owner-head CAS and the canonical receipt commit in
/// this one transaction. The operation is activated by the catalogue and its
/// owner-specific authorization is verified by `PreparedTransition::validate`
/// before this writer is reached, so these statements only ever persist the row
/// an already-authorized transition names.
fn append_swarm_owner_revision_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) =
        super::surreal_swarm::swarm_owner_revision_statements(transition)?;
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "swarm binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends the named candidate revision and item-head CAS to this canonical
/// transition, preserving immutable prior revisions and candidate-only scope.
fn append_blackboard_item_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) =
        super::surreal_blackboard::blackboard_item_statements(transition)?;
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "blackboard binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends the create-only owner acceptance-set row when the named operation is
/// present in the transition (#325 P1, I7.9).
///
/// The durable owner record and the canonical receipt commit in this one
/// transaction, so a reader can never observe an acceptance set that the
/// receipt does not describe. Nothing here derives acceptance semantics: the
/// row is the contract owner's own enumeration, carried verbatim.
fn append_task_contract_acceptance_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) =
        super::surreal_task_acceptance::task_contract_acceptance_statements(transition)?;
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "task contract acceptance binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Appends canonical learning-record row writes (issue #1868).
///
/// Same atomicity contract as the experience fragment: create-or-converge
/// rows commit in the same transaction as the receipt and outbox rows.
/// Binding collisions fail closed instead of silently overwriting a
/// canonical binding.
fn append_learning_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    learning: &LearningWrites,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) = learning_write_statements(learning);
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "learning binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}
/// Appends canonical reactive row writes (issue #1941 C4).
///
/// Same atomicity contract as the notification fragment above: session
/// compare-and-set plus snapshot create-or-converge rows commit in the
/// same transaction as the receipt and outbox rows. Binding collisions
/// fail closed instead of silently overwriting a canonical binding.
fn append_reactive_statements(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    reactive: &ReactiveWrites,
) -> Result<(), AdapterError> {
    let (fragment, fragment_bindings) = reactive_write_statements(reactive);
    sql.push_str(&fragment);
    for (name, value) in fragment_bindings {
        if bindings.insert(name.clone(), value).is_some() {
            return Err(AdapterError::Serialization(
                "reactive binding collided with a canonical binding".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn to_value<T: Serialize>(value: &T) -> Result<Value, AdapterError> {
    serde_json::to_value(value).map_err(|error| AdapterError::Serialization(error.to_string()))
}

/// Renders the opaque payload-authority array for the receipt record
/// binding (issue #10, Wave C).
///
/// Each entry carries the authority identity (operation index, version,
/// encoding, digest, length) plus the exact UTF-8 bytes as one opaque
/// string scalar. Bytes that are not valid UTF-8 JSON fail closed here
/// instead of being lossily coerced into the binding.
fn payload_authority_binding(records: &[PayloadAuthorityRecord]) -> Result<Value, AdapterError> {
    records
        .iter()
        .map(|record| {
            let bytes_utf8 = String::from_utf8(record.bytes.clone()).map_err(|_| {
                AdapterError::Serialization(
                    "payload authority bytes are not valid UTF-8 JSON".to_owned(),
                )
            })?;
            Ok(json!({
                "operation_index": record.operation_index,
                "version": record.version,
                "encoding": record.encoding,
                "digest_hex": record.digest_hex,
                "byte_len": record.byte_len,
                "bytes_utf8": bytes_utf8,
            }))
        })
        .collect::<Result<Vec<_>, AdapterError>>()
        .map(Value::Array)
}

/// Renders the recoverable capture-evidence array for the receipt record
/// binding (T11.1, #19).
///
/// Each entry carries the full recoverable record — subject selector,
/// complete admitted parameters, and exact bytes with version/encoding/
/// digest/length provenance — plus the durable capture order
/// (`commit_sequence`, `operation_index`) and the transition's total
/// operation count. Bytes that are not valid UTF-8 JSON fail closed here
/// instead of being lossily coerced into the binding.
fn evidence_binding(records: &[EvidenceRecord]) -> Result<Value, AdapterError> {
    records
        .iter()
        .map(|record| {
            let bytes_utf8 = String::from_utf8(record.bytes.clone()).map_err(|_| {
                AdapterError::Serialization(
                    "evidence record bytes are not valid UTF-8 JSON".to_owned(),
                )
            })?;
            Ok(json!({
                "operation_index": record.operation_index,
                "subject": record.subject,
                "parameters": record.parameters,
                "version": record.version,
                "encoding": record.encoding,
                "digest_hex": record.digest_hex,
                "byte_len": record.byte_len,
                "bytes_utf8": bytes_utf8,
                "commit_sequence": record.commit_sequence,
                "named_operation_count": record.named_operation_count,
            }))
        })
        .collect::<Result<Vec<_>, AdapterError>>()
        .map(Value::Array)
}

pub(super) fn revision_write_template(initial_state: bool, exists: bool) -> &'static str {
    if initial_state || !exists {
        schema::TX_CREATE_REVISION
    } else {
        schema::TX_UPSERT_REVISION
    }
}

pub(super) fn ordering_write_template(initial_state: bool, exists: bool) -> &'static str {
    if initial_state || !exists {
        schema::TX_CREATE_ORDERING
    } else {
        schema::TX_UPSERT_ORDERING
    }
}

/// 688-B local intent/outcome model for the Surreal apply path.
///
/// Local model only: depends solely on existing `eliot-store-api` types plus
/// this module (the neutral purge port is defined in a parallel subtask and
/// is not yet on this base; the canonical erasure path lives in
/// `eliot-store-api` `erasure_admission` and `ErasureIntentRecord`, not in a
/// separate crate). All `SurrealQL` stays in `apply`/`schema` modules; the
/// public boundary carries store-api types only.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurrealErasureSurface {
    CanonicalPayload,
    Projection,
    Index,
    Blob,
    OperationalRecovery,
    ProviderCopy,
    BackupRestorePath,
    RouteContinuation,
}

impl SurrealErasureSurface {
    /// Resolves one admitted handler-surface name (issue #1712).
    ///
    /// Closed vocabulary: the same eight store surfaces the memory reference
    /// handler accepts. Unknown names fail closed; the bridge never invents
    /// a surface.
    pub(crate) fn by_name(name: &str) -> Result<Self, StoreError> {
        match name {
            "CanonicalPayload" => Ok(Self::CanonicalPayload),
            "Projection" => Ok(Self::Projection),
            "Index" => Ok(Self::Index),
            "Blob" => Ok(Self::Blob),
            "OperationalRecovery" => Ok(Self::OperationalRecovery),
            "ProviderCopy" => Ok(Self::ProviderCopy),
            "BackupRestorePath" => Ok(Self::BackupRestorePath),
            "RouteContinuation" => Ok(Self::RouteContinuation),
            _ => Err(StoreError::InvalidField {
                field: "erasure.surfaces",
                reason: "unknown erasure surface",
            }),
        }
    }

    /// Surfaces whose evidence lives in the store-owned receipt rows below.
    ///
    /// Every other surface is out of store scope: the adapter marks it
    /// `Incomplete` (never `Purged`) instead of claiming foreign removal.
    #[must_use]
    pub const fn is_store_owned(self) -> bool {
        match self {
            Self::CanonicalPayload | Self::Projection | Self::Index => true,
            Self::Blob
            | Self::OperationalRecovery
            | Self::ProviderCopy
            | Self::BackupRestorePath
            | Self::RouteContinuation => false,
        }
    }
}

/// Per-surface erasure outcome for one operation.
///
/// `NotAttempted` is the registry state after intent recording, before
/// dispatch. `Unknown` preserves an ambiguous effect (e.g. lost provider
/// response) for same-operation reconciliation: it is stored and replayed,
/// never retried blindly and never promoted into suppression.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurrealSurfaceOutcome {
    NotAttempted { surface: SurrealErasureSurface },
    Purged { surface: SurrealErasureSurface },
    Incomplete { surface: SurrealErasureSurface },
    Unknown { surface: SurrealErasureSurface },
}

impl SurrealSurfaceOutcome {
    /// Returns the surface this outcome reports on.
    #[must_use]
    pub const fn surface(self) -> SurrealErasureSurface {
        match self {
            Self::NotAttempted { surface }
            | Self::Purged { surface }
            | Self::Incomplete { surface }
            | Self::Unknown { surface } => surface,
        }
    }
}

/// Durable erasure intent recorded BEFORE any destructive dispatch.
///
/// `operation_id` is the caller-supplied stable identity (never regenerated
/// on retry); `subject` + `scope_id` name the exact admitted pair;
/// `payload_ref` and `encryption_key_ref` name the exact payload/blob and
/// key identities the deletion touches; `deadline_unix_ms` is the exact
/// deadline identity; `surfaces` is the exact admitted denominator;
/// `state_fence` pins the fence the destructive calls execute under.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealErasureIntent {
    pub operation_id: String,
    pub subject: String,
    pub payload_ref: String,
    pub encryption_key_ref: String,
    pub deadline_unix_ms: u64,
    pub scope_id: ScopeId,
    pub surfaces: Vec<SurrealErasureSurface>,
    pub state_fence: StateFence,
}

impl SurrealErasureIntent {
    /// Fail-closed validation of the frozen intent.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_erasure_text(&self.operation_id, "erasure.operation_id")?;
        validate_erasure_text(&self.subject, "erasure.subject")?;
        validate_erasure_text(&self.payload_ref, "erasure.payload_ref")?;
        validate_erasure_text(&self.encryption_key_ref, "erasure.encryption_key_ref")?;
        if self.deadline_unix_ms == 0 {
            return Err(StoreError::InvalidField {
                field: "erasure.deadline_unix_ms",
                reason: "must be greater than zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.surfaces.is_empty() {
            return Err(StoreError::Empty {
                field: "erasure.surfaces",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for surface in &self.surfaces {
            if !seen.insert(*surface) {
                return Err(StoreError::Duplicate {
                    field: "erasure.surfaces",
                });
            }
        }
        Ok(())
    }
}

fn validate_erasure_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

/// Address of one durable erasure-intent row: (`erasure_intent`,
/// `erasure-intent-<operation_id>`). One row per operation; no second ledger.
#[must_use]
pub(crate) fn erasure_intent_record_id(operation_id: &str) -> String {
    format!("erasure-intent-{operation_id}")
}

/// Address of one sealed erasure-outcome row: (`erasure_outcome`,
/// `erasure-outcome-<operation_id>`). The single completion marker for the
/// intent row above — never a second ledger.
#[must_use]
pub(crate) fn erasure_outcome_record_id(operation_id: &str) -> String {
    format!("erasure-outcome-{operation_id}")
}

/// Intent-before-dispatch body shared by the standalone template below and
/// the canonical in-transaction bundle (S-CONC-TX, issue #989): (1) the
/// intent upsert that creates the durable intent row when absent and refuses
/// when the same id already names different bytes; (2) one scrub `UPDATE`
/// pair per store-owned surface admitted under the exact recorded scope; (3)
/// the outcome seal. No `BEGIN`/`COMMIT` delimiters: the caller supplies the
/// transaction boundary.
fn erasure_body_template(store_owned_surface_count: usize) -> String {
    let mut sql = String::new();
    sql.push_str(TX_ERASURE_INTENT);
    for index in 0..store_owned_surface_count {
        sql.push_str(&schema::indexed(TX_ERASURE_SCRUB_AUTHORITY, index));
        sql.push_str(&schema::indexed(TX_ERASURE_SCRUB_EVIDENCE, index));
    }
    sql.push_str(TX_ERASURE_OUTCOME);
    sql
}

/// Intent-before-dispatch transaction template (688-B, pure).
///
/// Statement order inside one `BEGIN`/`COMMIT` pair: the intent upsert, one
/// scrub `UPDATE` pair per store-owned surface (authority entries first,
/// then evidence entries), and the outcome seal that persists the exact
/// per-surface outcomes for idempotent replay. Renders over
/// [`erasure_body_template`], the same body the canonical in-transaction
/// bundle splices, so the standalone ordering assertion and the live bundle
/// cannot drift.
///
/// All `SurrealQL` stays inside the local `TX_ERASURE_*` templates above:
/// this builder composes closed statement constants owned by this apply
/// writer (inside the admitted apply/schema contour), never caller-supplied
/// query text. `Unknown`-outcome surfaces are preserved for
/// reconciliation: they appear in the sealed outcomes but emit no scrub
/// statement. Fail-closed: with no recorded intent this template is never
/// built (the caller refuses with `ReceiptNotFound` before any provider I/O);
/// a lost commit response is `UnknownOutcome` for same-operation
/// reconciliation, never a blind retry.
#[must_use]
pub(crate) fn erasure_transaction_template(store_owned_surface_count: usize) -> String {
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(&erasure_body_template(store_owned_surface_count));
    sql.push_str(schema::TX_COMMIT);
    sql
}

/// Builds the intent-row bindings for [`erasure_transaction_template`].
///
/// Returns the bindings map plus the sealed per-surface outcomes:
/// store-owned surfaces report `Purged`, every other surface reports
/// `Incomplete` (foreign removal is never claimed). A surface that already
/// carries a terminal non-`NotAttempted` outcome keeps it verbatim
/// (partial-resume identity; `Unknown` is preserved, never cleared).
/// A preserved terminal outcome replays verbatim AND emits no scrub
/// statement for that surface: the transaction template is rendered from the
/// count of `erasure_subject{i}` bindings below, so a replayed-`Unknown`
/// (or any replayed terminal) surface contributes zero scrub `UPDATE`s.
pub(crate) fn erasure_transaction_bindings(
    intent: &SurrealErasureIntent,
    prior_outcomes: &[SurrealSurfaceOutcome],
) -> Result<(Map<String, Value>, Vec<SurrealSurfaceOutcome>), AdapterError> {
    intent.validate().map_err(AdapterError::Store)?;
    let mut bindings = Map::new();
    let surfaces: Vec<String> = intent
        .surfaces
        .iter()
        .map(|surface| format!("{surface:?}"))
        .collect();
    let intent_value = json!({
        "operation_id": intent.operation_id,
        "subject": intent.subject,
        "payload_ref": intent.payload_ref,
        "encryption_key_ref": intent.encryption_key_ref,
        "deadline_unix_ms": intent.deadline_unix_ms,
        "scope_id": intent.scope_id.to_string(),
        "surfaces": surfaces,
        "state_fence": intent.state_fence,
        "operation_count": intent.surfaces.len(),
    });
    bindings.insert(
        "erasure_table".to_owned(),
        json!(schema::table::ERASURE_INTENT),
    );
    bindings.insert(
        "erasure_operation_id".to_owned(),
        json!(erasure_intent_record_id(&intent.operation_id)),
    );
    bindings.insert("erasure_intent_expected".to_owned(), intent_value.clone());
    bindings.insert("erasure_intent_record".to_owned(), intent_value);
    let mut outcomes = Vec::with_capacity(intent.surfaces.len());
    let mut store_owned_index = 0_usize;
    for surface in &intent.surfaces {
        let preserved = prior_outcomes.iter().find(|outcome| {
            outcome.surface() == *surface
                && !matches!(outcome, SurrealSurfaceOutcome::NotAttempted { .. })
        });
        if let Some(outcome) = preserved {
            // Terminal replay: keep the stored outcome verbatim and emit no
            // scrub statement for this surface (no `erasure_subject{i}`
            // bindings, so the rendered template carries no scrub `UPDATE`
            // for it).
            outcomes.push(*outcome);
            continue;
        }
        if surface.is_store_owned() {
            outcomes.push(SurrealSurfaceOutcome::Purged { surface: *surface });
            erasure_delete_bindings(
                &mut bindings,
                store_owned_index,
                &intent.subject,
                &intent.scope_id,
            );
            store_owned_index += 1;
        } else {
            outcomes.push(SurrealSurfaceOutcome::Incomplete { surface: *surface });
        }
    }
    let outcome_strings: Vec<String> = outcomes
        .iter()
        .map(|outcome| match *outcome {
            SurrealSurfaceOutcome::NotAttempted { surface } => {
                format!("NOT_ATTEMPTED:{surface:?}")
            }
            SurrealSurfaceOutcome::Purged { surface } => format!("PURGED:{surface:?}"),
            SurrealSurfaceOutcome::Incomplete { surface } => {
                format!("INCOMPLETE:{surface:?}")
            }
            SurrealSurfaceOutcome::Unknown { surface } => format!("UNKNOWN:{surface:?}"),
        })
        .collect();
    let outcome_value = json!({
        "operation_id": intent.operation_id,
        "outcomes": outcome_strings,
    });
    bindings.insert(
        "erasure_outcome_table".to_owned(),
        json!(schema::table::ERASURE_OUTCOME),
    );
    bindings.insert(
        "erasure_outcome_id".to_owned(),
        json!(erasure_outcome_record_id(&intent.operation_id)),
    );
    bindings.insert("erasure_outcomes".to_owned(), json!(outcome_strings));
    bindings.insert("erasure_outcome_record".to_owned(), outcome_value);
    Ok((bindings, outcomes))
}

/// Binds one scrub index: the exact admitted subject plus the single admitted
/// scope. The scope travels in exactly one binding
/// (`erasure_scope_expected{suffix}`); the scrub statements compare it against
/// the durable row's stored admitted scope, never against a second copy of
/// itself.
fn erasure_delete_bindings(
    bindings: &mut Map<String, Value>,
    index: usize,
    subject: &str,
    scope_id: &ScopeId,
) {
    let suffix = index.to_string();
    bindings.insert(format!("erasure_subject{suffix}"), json!(subject));
    bindings.insert(
        format!("erasure_scope_expected{suffix}"),
        json!(scope_id.to_string()),
    );
}

/// Executes one recorded erasure intent inside the canonical atomic
/// transaction (S-CONC-TX, issue #989, audit `5919482812`).
///
/// In-transaction bundle for one admitted erasure intent: the intent upsert
/// opens the fragment before any destructive statement, then the exact
/// subject/scope scrub `UPDATE` pairs, then the outcome seal. The caller
/// splices this fragment into the canonical `BEGIN`/`COMMIT` ahead of the
/// receipt create, so intent, destructive effects, canonical event, heads,
/// outbox, and receipt commit atomically or not at all: a fence-contention
/// abort, a semantic head conflict, retry exhaustion, or an unknown outcome
/// can never leave a separately committed destructive effect behind the
/// canonical receipt. Same-operation replay converges without duplicate
/// destructive work: the intent upsert refuses a same-identity intent naming
/// different bytes (`erasure_intent_conflict`), and the scrub filters are
/// idempotent over the already-scrubbed rows.
///
/// Constructed only after the caller proves the outcome is not already
/// sealed (see [`read_sealed_erasure_outcomes`]); a sealed row replays
/// verbatim with no fragment and no duplicate destructive work.
pub(super) struct ErasureInTx {
    pub(super) sql_fragment: String,
    pub(super) bindings: Map<String, Value>,
}

/// Builds the in-transaction erasure bundle for one recorded intent.
///
/// Pure over the frozen intent: bindings and sealed outcomes follow
/// [`erasure_transaction_bindings`] exactly (store-owned surfaces report
/// `Purged`, foreign surfaces `Incomplete`, preserved terminal outcomes
/// replay verbatim with zero scrub statements), and the fragment renders
/// from the emitted `erasure_subject{i}` bindings so a replayed terminal
/// outcome contributes no scrub `UPDATE`.
pub(super) fn erasure_in_tx_parts(
    intent: &SurrealErasureIntent,
) -> Result<ErasureInTx, AdapterError> {
    intent.validate().map_err(AdapterError::Store)?;
    let prior: Vec<SurrealSurfaceOutcome> = Vec::new();
    let (bindings, _) = erasure_transaction_bindings(intent, &prior)?;
    let store_owned = bindings
        .keys()
        .filter(|key| {
            key.starts_with("erasure_subject")
                && key["erasure_subject".len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
        })
        .count();
    Ok(ErasureInTx {
        sql_fragment: erasure_body_template(store_owned),
        bindings,
    })
}

/// Reads one sealed erasure-outcome row by exact operation id.
///
/// `Some` means a prior attempt sealed the exact per-surface outcomes: the
/// caller replays them verbatim with no duplicate destructive work. `None`
/// means no sealed row exists, so the caller builds the full in-transaction
/// bundle. A lost commit response surfaces as
/// [`AdapterError::UnknownOutcome`] for same-operation reconciliation (no
/// blind retry); a guard conflict surfaces as `IdentityConflict`.
pub(super) async fn read_sealed_erasure_outcomes(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &eliot_store_api::OperationId,
) -> Result<Option<Vec<SurrealSurfaceOutcome>>, AdapterError> {
    read_erasure_outcome(db, config, &operation_id.to_string()).await
}

async fn read_erasure_outcome(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &str,
) -> Result<Option<Vec<SurrealSurfaceOutcome>>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "erasure_outcome_table".to_owned(),
        json!(schema::table::ERASURE_OUTCOME),
    );
    bindings.insert(
        "erasure_outcome_id".to_owned(),
        json!(erasure_outcome_record_id(operation_id)),
    );
    let mut response = client::query(
        db,
        config,
        "read.erasure_outcome",
        READ_ERASURE_OUTCOME,
        bindings,
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<ErasureOutcomeRow> = response.take(0)?;
    row.map(|row| parse_erasure_outcomes(&row.outcomes))
        .transpose()
}

#[derive(serde::Deserialize)]
struct ErasureOutcomeRow {
    outcomes: Vec<String>,
}

fn parse_erasure_outcomes(outcomes: &[String]) -> Result<Vec<SurrealSurfaceOutcome>, AdapterError> {
    outcomes
        .iter()
        .map(|outcome| {
            let (state, surface) = outcome.split_once(':').ok_or_else(|| {
                AdapterError::Serialization("erasure outcome row is malformed".to_owned())
            })?;
            let surface = match surface {
                "CanonicalPayload" => SurrealErasureSurface::CanonicalPayload,
                "Projection" => SurrealErasureSurface::Projection,
                "Index" => SurrealErasureSurface::Index,
                "Blob" => SurrealErasureSurface::Blob,
                "OperationalRecovery" => SurrealErasureSurface::OperationalRecovery,
                "ProviderCopy" => SurrealErasureSurface::ProviderCopy,
                "BackupRestorePath" => SurrealErasureSurface::BackupRestorePath,
                "RouteContinuation" => SurrealErasureSurface::RouteContinuation,
                _ => {
                    return Err(AdapterError::Serialization(
                        "erasure outcome surface is unknown".to_owned(),
                    ));
                }
            };
            match state {
                "NOT_ATTEMPTED" => Ok(SurrealSurfaceOutcome::NotAttempted { surface }),
                "PURGED" => Ok(SurrealSurfaceOutcome::Purged { surface }),
                "INCOMPLETE" => Ok(SurrealSurfaceOutcome::Incomplete { surface }),
                "UNKNOWN" => Ok(SurrealSurfaceOutcome::Unknown { surface }),
                _ => Err(AdapterError::Serialization(
                    "erasure outcome state is unknown".to_owned(),
                )),
            }
        })
        .collect()
}

#[cfg(test)]
mod authority_binding_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use eliot_store_api::{ExactJsonBytes, PayloadSource};

    fn authority_record(raw: &[u8]) -> PayloadAuthorityRecord {
        let authority = ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw)
            .expect("authority parses");
        PayloadAuthorityRecord {
            operation_index: 0,
            version: authority.version,
            encoding: authority.encoding.mnemonic().to_owned(),
            digest_hex: authority.digest_hex(),
            byte_len: authority.byte_len(),
            bytes: authority.bytes.clone(),
        }
    }

    #[test]
    fn binding_persists_opaque_bytes_beside_queryable_bodies() {
        let raw = br#"{"subject":"observation-1"}"#;
        let bound = payload_authority_binding(&[authority_record(raw)]).expect("binding renders");
        let entries = bound.as_array().expect("binding is an array");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("bytes_utf8").and_then(Value::as_str),
            Some(std::str::from_utf8(raw).expect("test raw is UTF-8")),
            "opaque bytes round-trip exactly for readback"
        );
        assert_eq!(
            entries[0].get("operation_index"),
            Some(&Value::from(0)),
            "operation index is preserved"
        );
        assert!(
            entries[0]
                .get("digest_hex")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.len() == 64),
            "digest identity travels with the opaque bytes"
        );
        assert_eq!(
            payload_authority_binding(&[]).expect("empty binding renders"),
            Value::Array(Vec::new()),
            "legacy transitions persist an empty authority array"
        );
    }

    #[test]
    fn non_utf8_authority_bytes_fail_closed() {
        let record = PayloadAuthorityRecord {
            operation_index: 0,
            version: 1,
            encoding: "utf8_json".to_owned(),
            digest_hex: "0".repeat(64),
            byte_len: 1,
            bytes: vec![0xff],
        };
        assert!(
            payload_authority_binding(&[record]).is_err(),
            "non-UTF-8 bytes never coerce into the binding"
        );
    }

    #[test]
    fn evidence_binding_persists_full_recoverable_record() {
        use crate::plan::{plan_apply, select_apply_plan};
        use eliot_store_api::{
            EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
            NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId,
            ScopeId, SecurityContext, TransitionClass,
        };
        use serde_json::json;
        use std::collections::BTreeMap;

        fn transition() -> eliot_store_api::PreparedTransition {
            use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
            use std::num::NonZeroU64;
            let lineage =
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
            let epoch =
                EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
            let mut transition = eliot_store_api::PreparedTransition {
                contract_version: eliot_store_api::CONTRACT_VERSION,
                identity: OperationIdentity {
                    operation_id: eliot_store_api::OperationId::new("op-evidence-bind")
                        .expect("operation"),
                    idempotency_key: "idem-evidence-bind".to_owned(),
                    canonical_request_hash: "a".repeat(64),
                },
                state_fence: eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis()),
                scope_id: ScopeId::new("scope-1").expect("scope"),
                task_id: None,
                ordering_scopes: vec![OrderingScopeId::new("scope-1").expect("ordering")],
                transition_class: TransitionClass::CaptureCandidate,
                requested_effect_ceiling: EffectClass::Candidate,
                admission_contract_set_digest: "b".repeat(64),
                operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                    .expect("manifest"),
                // Issue-#18 digests are derived, never defaulted; no semantic
                // source is bound here (`[]`).
                admission_digest: String::new(),
                mutation_plan_digest: String::new(),
                semantic_source_revisions: Vec::new(),
                named_operations: vec![NamedMutationRequest {
                    operation: NamedMutationOperation::CaptureObservation,
                    parameters: BTreeMap::from([("subject".to_owned(), json!("evidence-alpha"))]),
                }],
                event_projection_relation_intents: EventProjectionRelationIntents {
                    event_ids: Vec::new(),
                    projection_kinds: Vec::new(),
                    relation_kinds: Vec::new(),
                },
                security: SecurityContext::default(),
                required_proof_and_approval_refs: Vec::new(),
            };
            eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
            transition
        }

        // Real planner output — never a canned row — binds subject, full
        // parameters, exact bytes, and provenance together.
        let transition = transition();
        let plan = plan_apply(&transition, &[], &[], 7, 1).expect("plan applies");
        let bound = evidence_binding(&plan.evidence_records).expect("binding renders");
        let entries = bound.as_array().expect("binding is an array");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        assert_eq!(
            entries[0]
                .get("parameters")
                .and_then(|parameters| parameters.get("subject"))
                .and_then(Value::as_str),
            Some("evidence-alpha"),
            "full parameters travel, never a subject-only projection"
        );
        let bytes_utf8 = entries[0]
            .get("bytes_utf8")
            .and_then(Value::as_str)
            .expect("bytes travel as one opaque string");
        let decoded: BTreeMap<String, Value> =
            serde_json::from_str(bytes_utf8).expect("bytes parse");
        assert_eq!(
            decoded, plan.evidence_records[0].parameters,
            "persisted bytes recover the exact parameters"
        );
        assert_eq!(
            entries[0].get("commit_sequence").and_then(Value::as_u64),
            Some(7)
        );
        // Authority path keeps the original raw bytes verbatim.
        let raw = br#"{"subject":"evidence-alpha"}"#;
        let authority =
            ExactJsonBytes::parse(PayloadSource::NamedOperationParameter, raw).expect("parses");
        let bound_plan = select_apply_plan(&transition, &[Some(authority)], &[], &[], 7, 1)
            .expect("bound applies");
        let bound_rendered =
            evidence_binding(&bound_plan.evidence_records).expect("bound binding renders");
        assert_eq!(
            bound_rendered.as_array().expect("array")[0]
                .get("bytes_utf8")
                .and_then(Value::as_str),
            Some(std::str::from_utf8(raw).expect("UTF-8")),
            "original authority bytes are preserved, never re-serialized"
        );
        assert_eq!(
            evidence_binding(&[]).expect("empty renders"),
            Value::Array(Vec::new()),
            "non-capture transitions persist an empty evidence array"
        );
    }
}

#[cfg(test)]
mod allocation_classification_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::plan::{build_receipt, plan_apply};
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext,
        TransitionClass,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new(TEST_LINEAGE).expect("lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn transition(operation: &str) -> eliot_store_api::PreparedTransition {
        use serde_json::json;
        use std::collections::BTreeMap;
        let mut transition = eliot_store_api::PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: eliot_store_api::OperationId::new(operation).expect("operation"),
                idempotency_key: format!("idem-{operation}"),
                canonical_request_hash: "a".repeat(64),
            },
            state_fence: fence(),
            scope_id: ScopeId::new("scope-alloc").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope-alloc").expect("ordering")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "b".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1")
                .expect("manifest"),
            // Issue-#18 digests are derived, never defaulted; no semantic
            // source is bound here (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([("subject".to_owned(), json!(operation))]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn context() -> eliot_store_api::RequestMeta {
        use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
        eliot_store_api::RequestMeta {
            request_id: RequestId::new("request-alloc").expect("request"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-alloc").expect("product"),
            source_id: SourceId::new("source-alloc").expect("source"),
            state_fence: fence(),
            clock: ClockReading::default(),
        }
    }

    #[test]
    fn fence_only_errors_are_allocation_contention() {
        for marker in [
            "THROW 'canonical_fence_cas_conflict'",
            "THROW 'canonical_fence_create_conflict'",
        ] {
            match classify_transaction_errors(&[format!("statement failed: {marker}")], "op-alloc")
            {
                AdapterError::AllocationContention { operation_id } => {
                    assert_eq!(operation_id, "op-alloc");
                }
                unexpected => panic!("fence marker must contend, got {unexpected:?}"),
            }
        }
    }

    #[test]
    fn semantic_markers_win_over_fence_markers() {
        for marker in [
            "epistemic_position_cas_conflict",
            "revision_head_cas_conflict",
            "revision_head_create_conflict",
            "ordering_head_cas_conflict",
            "ordering_head_create_conflict",
        ] {
            // A semantic marker anywhere in the set is deterministic, even
            // beside a fence marker: stale heads never retry as contention.
            let errors = vec![
                "THROW 'canonical_fence_cas_conflict'".to_owned(),
                format!("THROW '{marker}'"),
            ];
            assert_eq!(
                classify_transaction_errors(&errors, "op-semantic"),
                AdapterError::ProviderConflict,
                "semantic marker {marker} must win"
            );
            assert_eq!(
                classify_transaction_errors(&[format!("THROW '{marker}'")], "op-semantic"),
                AdapterError::ProviderConflict,
                "lone semantic marker {marker} is deterministic"
            );
        }
    }

    #[test]
    fn unrecognized_errors_stay_unknown_never_conflict() {
        for error in [
            "connection reset during COMMIT".to_owned(),
            "THROW 'erasure_intent_conflict'".to_owned(),
            "Database index `wr_operation` already contains op-alloc".to_owned(),
            String::new(),
        ] {
            match classify_transaction_errors(std::slice::from_ref(&error), "op-unknown") {
                AdapterError::UnknownOutcome { operation_id } => {
                    assert_eq!(operation_id, "op-unknown");
                }
                unexpected => panic!("unrecognized error must stay unknown, got {unexpected:?}"),
            }
        }
    }

    #[test]
    fn mixed_fence_plus_unknown_stays_unknown_never_retries() {
        // S-CONC-TX rework (issue #989): retry eligibility is exclusive.
        // An error set pairing a recognized allocation marker with any
        // unrecognized observation is an unknown outcome — the provider
        // result is no longer proved-not-committed, so it must reconcile
        // by receipt identity instead of retrying as contention.
        for marker in [
            "THROW 'canonical_fence_cas_conflict'",
            "THROW 'canonical_fence_create_conflict'",
        ] {
            for unknown in ["connection reset during COMMIT".to_owned(), String::new()] {
                let errors = vec![marker.to_owned(), unknown];
                match classify_transaction_errors(&errors, "op-mixed") {
                    AdapterError::UnknownOutcome { operation_id } => {
                        assert_eq!(operation_id, "op-mixed");
                    }
                    unexpected => {
                        panic!("mixed fence-plus-unknown set must stay unknown, got {unexpected:?}")
                    }
                }
            }
        }
    }

    #[test]
    fn fence_race_with_abort_cascade_stays_contention() {
        // S-CONC-TX rework (issue #989): the exact provider shape of a
        // genuine fence race. The fence `THROW` aborts the transaction and
        // every unexecuted statement reports deterministic cascade
        // narration; that narration asserts non-execution, so the set
        // still proves allocation movement on proved-not-committed ground
        // and the bounded retry may absorb it.
        let errors = vec![
            "\"The query was not executed due to a failed transaction\"".to_owned(),
            "\"An error occurred: canonical_fence_cas_conflict\"".to_owned(),
            "\"The query was not executed due to a cancelled transaction\"".to_owned(),
            "\"Cannot COMMIT: the transaction was aborted due to a prior error\"".to_owned(),
        ];
        match classify_transaction_errors(&errors, "op-race") {
            AdapterError::AllocationContention { operation_id } => {
                assert_eq!(operation_id, "op-race");
            }
            unexpected => panic!("fence race with cascade must contend, got {unexpected:?}"),
        }
    }

    #[test]
    fn bare_abort_cascade_without_executed_error_stays_unknown() {
        // Cascade narration alone proves no fence movement: contention
        // requires a positive allocation marker, so this resolves unknown.
        let errors = vec![
            "\"The query was not executed due to a cancelled transaction\"".to_owned(),
            "\"Cannot COMMIT: the transaction was aborted due to a prior error\"".to_owned(),
        ];
        match classify_transaction_errors(&errors, "op-cascade") {
            AdapterError::UnknownOutcome { operation_id } => {
                assert_eq!(operation_id, "op-cascade");
            }
            unexpected => panic!("bare cascade must stay unknown, got {unexpected:?}"),
        }
    }

    #[test]
    fn semantic_marker_wins_through_abort_cascade() {
        // A semantic trigger behind the same cascade is deterministic, not
        // contention: stale heads never retry.
        let errors = vec![
            "\"An error occurred: revision_head_cas_conflict\"".to_owned(),
            "\"The query was not executed due to a cancelled transaction\"".to_owned(),
            "\"Cannot COMMIT: the transaction was aborted due to a prior error\"".to_owned(),
        ];
        assert_eq!(
            classify_transaction_errors(&errors, "op-semantic-cascade"),
            AdapterError::ProviderConflict,
            "semantic marker wins through the cascade"
        );
    }

    #[test]
    fn assembled_transaction_verifies_fence_revision_ordering_before_receipt() {
        use eliot_store_api::{OrderingHead, RevisionHead};
        let ctx = context();
        let transition = transition("op-assemble");
        let plan = plan_apply(&transition, &[], &[], 1, 1).expect("plan applies");
        let receipt = build_receipt(&ctx, &transition, &plan).expect("receipt builds");
        // Existing heads select the CAS-update path, mirroring a live
        // steady-state commit: every declared expectation is verified inside
        // the transaction immediately before effects.
        let current_revisions: Vec<RevisionHead> = plan
            .revision_before_after
            .iter()
            .map(|delta| RevisionHead {
                key: delta.key.clone(),
                revision: delta.before,
                state_fence: fence(),
            })
            .collect();
        let current_orderings: Vec<OrderingHead> = plan
            .next_ordering_heads
            .iter()
            .map(|head| OrderingHead {
                scope: head.scope.clone(),
                sequence: head.sequence.saturating_sub(1),
                state_fence: fence(),
            })
            .collect();
        let (sql, bindings) = build_apply_statements(
            &transition,
            &plan,
            &receipt,
            false,
            1,
            1,
            &current_revisions,
            &current_orderings,
            &[],
            &ReactiveWrites::default(),
            &AutomationWrites::default(),
            &ExperienceWrites::default(),
            &LearningWrites::default(),
        )
        .expect("statements assemble");
        assert!(sql.starts_with(schema::TX_BEGIN), "one transaction opens");
        assert!(sql.ends_with(schema::TX_COMMIT), "one transaction closes");
        let fence = sql
            .find("canonical_fence_cas_conflict")
            .expect("fence CAS guards allocation");
        let revision = sql
            .find("revision_head_cas_conflict")
            .expect("revision CAS guards heads");
        let ordering = sql
            .find("ordering_head_cas_conflict")
            .expect("ordering CAS guards heads");
        let receipt_create = sql
            .find("CREATE type::record($receipt_table")
            .expect("receipt create closes the boundary");
        assert!(
            fence < revision && revision < ordering && ordering < receipt_create,
            "checks precede effects: fence, revision, ordering, receipt"
        );
        assert_eq!(
            bindings.get("expected_commit_sequence"),
            Some(&json!(1)),
            "allocation expectation travels"
        );
        assert_eq!(
            bindings.get("expected_outbox_sequence"),
            Some(&json!(1)),
            "outbox allocation expectation travels"
        );
        assert!(
            bindings.contains_key("expected_state_fence"),
            "fence expectation travels"
        );
        // Absent heads select the create path instead of the CAS-update
        // path; the fence singleton still CAS-guards the steady state.
        let (create_sql, _) = build_apply_statements(
            &transition,
            &plan,
            &receipt,
            false,
            1,
            1,
            &[],
            &[],
            &[],
            &ReactiveWrites::default(),
            &AutomationWrites::default(),
            &ExperienceWrites::default(),
            &LearningWrites::default(),
        )
        .expect("create path assembles");
        assert!(
            create_sql.contains("revision_head_create_conflict"),
            "absent revision head is created guarded"
        );
        assert!(
            create_sql.contains("ordering_head_create_conflict"),
            "absent ordering head is created guarded"
        );
        assert!(
            create_sql.contains("canonical_fence_cas_conflict"),
            "steady-state fence still CAS-guards allocation"
        );
        let (genesis_sql, _) = build_apply_statements(
            &transition,
            &plan,
            &receipt,
            true,
            1,
            1,
            &[],
            &[],
            &[],
            &ReactiveWrites::default(),
            &AutomationWrites::default(),
            &ExperienceWrites::default(),
            &LearningWrites::default(),
        )
        .expect("genesis assembles");
        assert!(
            genesis_sql.contains("canonical_fence_create_conflict"),
            "initial state creates the fence singleton"
        );
        assert!(
            !genesis_sql.contains("canonical_fence_cas_conflict"),
            "initial state never CAS-updates an absent fence"
        );
    }

    #[test]
    fn assembled_transaction_preserves_plan_contents() {
        let ctx = context();
        let transition = transition("op-contents");
        let plan = plan_apply(&transition, &[], &[], 3, 7).expect("plan applies");
        let receipt = build_receipt(&ctx, &transition, &plan).expect("receipt builds");
        let (sql, bindings) = build_apply_statements(
            &transition,
            &plan,
            &receipt,
            false,
            3,
            7,
            &[],
            &[],
            &[],
            &ReactiveWrites::default(),
            &AutomationWrites::default(),
            &ExperienceWrites::default(),
            &LearningWrites::default(),
        )
        .expect("statements assemble");
        assert_eq!(
            sql.matches("CREATE type::record($event_table0").count(),
            1,
            "exactly the planned event is created"
        );
        assert_eq!(
            sql.matches("CREATE type::record($outbox_table0").count(),
            1,
            "exactly the planned outbox row is created"
        );
        assert_eq!(
            bindings.get("receipt_operation_id"),
            Some(&json!("op-contents")),
            "receipt binds the admitted operation"
        );
        assert_eq!(
            bindings
                .get("receipt")
                .and_then(|receipt| receipt.get("commit_sequence")),
            Some(&json!(3)),
            "receipt binds the allocated commit sequence"
        );
    }
}
