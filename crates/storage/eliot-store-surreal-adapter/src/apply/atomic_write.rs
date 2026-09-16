//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01.
//! Source-backed atomic event/projection/revision/receipt binding: single Surreal
//! transaction couples envelope, projected events, relations, revision/ordering
//! heads, receipt and outbox via one `TX_BEGIN`/`TX_COMMIT`.
//! Implementation: I1.8, I5.1, I5.4, I5.9, I2.2, I2.23 — named already-prepared transition only; bridge alone owns SDK/credentials; event/projection/relation/revision/receipt/outbox commit in one DB transaction; unknown outcome resolves exact `WriteReceipt` before replay.
//! Ownership: bounded atomic transaction writer only; no read/head-validation/
//! uniqueness/schema/receipt/named-read/DDL/tests/Dreamer.

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::client;
use crate::config::SurrealAdapterConfig;
use crate::error::AdapterError;
use crate::plan::{ApplyPlan, EvidenceRecord, PayloadAuthorityRecord};
use crate::schema;
use eliot_store_api::epistemic_revision::EpistemicCommit;
use eliot_store_api::{OrderingHead, RevisionHead, ScopeId, StateFence, StoreError, WriteReceipt};

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
// transaction as the destructive statements; one `DELETE` per store-owned
// surface removes only the selected subject's capture rows admitted under the
// exact recorded scope; the outcome seal persists the exact per-surface
// outcomes for idempotent same-operation replay.

// 688-FIX: the erasure items below form the intent-before-dispatch live path
// owned by the real-Surreal round-trip integration slice. No admitted erasure
// dispatch exists on this base (the neutral purge port lives in a parallel
// subtask and is not yet on this base), so wiring a caller here would widen
// scope; each item carries `allow(dead_code)` until that slice wires it. The
// pure template/binding helpers are additionally exercised by the wired
// erasure unit test in `apply.rs`.
/// Upsert of one durable erasure-intent row: creates the row when absent,
/// refuses with `erasure_intent_conflict` when the same `operation_id`
/// already names a different intent. First statement of the erasure atomic
/// transaction — before any destructive statement.
#[allow(dead_code)]
const TX_ERASURE_INTENT: &str = "LET $erasure_existing = (SELECT VALUE { operation_id: operation_id, subject: subject, scope_id: scope_id, surfaces: surfaces, state_fence: state_fence, operation_count: operation_count } FROM ONLY type::record($erasure_table, $erasure_operation_id)); IF type::is_object($erasure_existing) { IF $erasure_existing != $erasure_intent_expected { THROW 'erasure_intent_conflict'; }; } ELSE { CREATE type::record($erasure_table, $erasure_operation_id) CONTENT $erasure_intent_record; };";

/// Deletes exactly the selected subject's capture rows admitted under the
/// exact recorded scope. `{i}` selects the binding index. Exact subject/scope
/// match only — never substring, never a default scope.
#[allow(dead_code)]
const TX_ERASURE_DELETE_EVIDENCE: &str = "DELETE write_receipt WHERE $erasure_subject{i} IN evidence_records.subject AND $erasure_scope{i} = $erasure_scope_expected{i};";

/// Seals one completed operation with its exact per-surface outcomes. Last
/// statement before commit; same-operation replay reads this row and returns
/// the stored outcomes without duplicate destructive work (the single
/// completion marker for the intent row above — never a second ledger).
#[allow(dead_code)]
const TX_ERASURE_OUTCOME: &str = "LET $erasure_outcome_existing = (SELECT VALUE { operation_id: operation_id, outcomes: outcomes } FROM ONLY type::record($erasure_outcome_table, $erasure_outcome_id)); IF type::is_object($erasure_outcome_existing) { IF $erasure_outcome_existing.outcomes != $erasure_outcomes { THROW 'erasure_intent_conflict'; }; } ELSE { CREATE type::record($erasure_outcome_table, $erasure_outcome_id) CONTENT $erasure_outcome_record; };";

/// Reads one sealed erasure-outcome row by exact operation id.
#[allow(dead_code)]
const READ_ERASURE_OUTCOME: &str = "SELECT VALUE { operation_id: operation_id, outcomes: outcomes } FROM ONLY type::record($erasure_outcome_table, $erasure_outcome_id);";

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the transaction writer preserves the closed named-operation order and atomic SQL assembly"
)]
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
) -> Result<(), AdapterError> {
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
        bindings.insert(
            format!("event{suffix}"),
            json!({
                "event_id": event_id.to_string(),
                "operation_id": operation_id,
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

    sql.push_str(schema::TX_COMMIT);

    let mut response = match client::query(db, config, "transaction.apply", &sql, bindings).await {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => {
            return Err(AdapterError::UnknownOutcome { operation_id });
        }
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().any(|error| is_transaction_conflict(error)) {
            return Err(AdapterError::ProviderConflict);
        }
        return Err(AdapterError::UnknownOutcome { operation_id });
    }
    Ok(())
}

fn is_transaction_conflict(error: &str) -> bool {
    [
        "epistemic_position_cas_conflict",
        "canonical_fence_cas_conflict",
        "canonical_fence_create_conflict",
        "revision_head_cas_conflict",
        "revision_head_create_conflict",
        "ordering_head_cas_conflict",
        "ordering_head_create_conflict",
    ]
    .iter()
    .any(|marker| error.contains(marker))
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
/// is not yet on this base; the adapter never imports `eliot-erasure`). All
/// `SurrealQL` stays in `apply`/`schema` modules; the public boundary carries
/// store-api types only.
#[allow(dead_code)]
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
    /// Surfaces whose evidence lives in the store-owned receipt rows below.
    ///
    /// Every other surface is out of store scope: the adapter marks it
    /// `Incomplete` (never `Purged`) instead of claiming foreign removal.
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
/// `surfaces` is the exact admitted denominator; `state_fence` pins the
/// fence the destructive calls execute under.
#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealErasureIntent {
    pub operation_id: String,
    pub subject: String,
    pub scope_id: ScopeId,
    pub surfaces: Vec<SurrealErasureSurface>,
    pub state_fence: StateFence,
}

impl SurrealErasureIntent {
    /// Fail-closed validation of the frozen intent.
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_erasure_text(&self.operation_id, "erasure.operation_id")?;
        validate_erasure_text(&self.subject, "erasure.subject")?;
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

#[allow(dead_code)]
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
#[allow(dead_code)]
#[must_use]
pub(crate) fn erasure_intent_record_id(operation_id: &str) -> String {
    format!("erasure-intent-{operation_id}")
}

/// Address of one sealed erasure-outcome row: (`erasure_outcome`,
/// `erasure-outcome-<operation_id>`). The single completion marker for the
/// intent row above — never a second ledger.
#[allow(dead_code)]
#[must_use]
pub(crate) fn erasure_outcome_record_id(operation_id: &str) -> String {
    format!("erasure-outcome-{operation_id}")
}

/// Intent-before-dispatch transaction template (688-B, pure).
///
/// Statement order inside one `BEGIN`/`COMMIT` pair: (1) the intent upsert
/// that creates the durable intent row when absent and refuses when the same
/// id already names different bytes; (2) one destructive `DELETE` per
/// store-owned surface, each deleting only the selected subject's capture
/// rows admitted under the exact recorded scope; (3) the outcome seal that
/// persists the exact per-surface outcomes for idempotent replay.
///
/// All `SurrealQL` stays inside the local `TX_ERASURE_*` templates above:
/// this builder composes closed statement constants owned by this apply
/// writer (inside the admitted apply/schema contour), never caller-supplied
/// query text. `Unknown`-outcome surfaces are preserved for
/// reconciliation: they appear in the sealed outcomes but emit no destructive
/// statement. Fail-closed: with no recorded intent this template is never
/// built (the caller refuses with `ReceiptNotFound` before any provider I/O);
/// a lost commit response is `UnknownOutcome` for same-operation
/// reconciliation, never a blind retry.
#[allow(dead_code)]
#[must_use]
pub(crate) fn erasure_transaction_template(store_owned_surface_count: usize) -> String {
    let mut sql = String::from(schema::TX_BEGIN);
    sql.push_str(TX_ERASURE_INTENT);
    for index in 0..store_owned_surface_count {
        sql.push_str(&schema::indexed(TX_ERASURE_DELETE_EVIDENCE, index));
    }
    sql.push_str(TX_ERASURE_OUTCOME);
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
/// A preserved terminal outcome replays verbatim AND emits no destructive
/// statement for that surface: the transaction template is rendered from the
/// count of `erasure_subject{i}` bindings below, so a replayed-`Unknown`
/// (or any replayed terminal) surface contributes zero `DELETE`s.
#[allow(dead_code)]
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
            // destructive statement for this surface (no `erasure_subject{i}`
            // bindings, so the rendered template carries no `DELETE` for it).
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

#[allow(dead_code)]
fn erasure_delete_bindings(
    bindings: &mut Map<String, Value>,
    index: usize,
    subject: &str,
    scope_id: &ScopeId,
) {
    let suffix = index.to_string();
    bindings.insert(format!("erasure_subject{suffix}"), json!(subject));
    bindings.insert(
        format!("erasure_scope{suffix}"),
        json!(scope_id.to_string()),
    );
    bindings.insert(
        format!("erasure_scope_expected{suffix}"),
        json!(scope_id.to_string()),
    );
}

/// Executes one recorded erasure intent atomically (688-B, live path).
///
/// Order: replay check (sealed outcome rows replay verbatim, no duplicate
/// destructive work) → intent-before-dispatch transaction (intent row first,
/// then exact-scope/scope deletes, then outcome seal) → sealed outcomes. A
/// lost commit response surfaces as
/// [`AdapterError::UnknownOutcome`] for same-operation reconciliation (no
/// blind retry); a guard conflict surfaces as `IdentityConflict`.
///
/// Callers invoke this only after the apply-path intent gate below has
/// recorded the durable intent: without that gate this function is never
/// reached (fail-closed, zero destructive effects without recorded intent).
#[allow(dead_code)]
pub(super) async fn write_erasure_transaction(
    db: &client::RpcTransport,
    config: &SurrealAdapterConfig,
    intent: &SurrealErasureIntent,
) -> Result<Vec<SurrealSurfaceOutcome>, AdapterError> {
    intent.validate().map_err(AdapterError::Store)?;
    // Single sealed-outcome read: a sealed row replays verbatim with no
    // duplicate destructive work; the unsealed case (`None`) binds against an
    // empty prior so the transaction emits the full store-owned `DELETE` set.
    let sealed = read_erasure_outcome(db, config, &intent.operation_id).await?;
    if let Some(sealed) = sealed {
        return Ok(sealed);
    }
    let prior: Vec<SurrealSurfaceOutcome> = Vec::new();
    let (bindings, outcomes) = erasure_transaction_bindings(intent, &prior)?;
    // 688-FIX: render the template from the emitted `erasure_subject{i}`
    // bindings (not from the intent denominator), so a replayed terminal
    // outcome — preserved verbatim above with no bindings — contributes zero
    // `DELETE`s. On the fresh path every store-owned surface emits bindings,
    // so this equals the intent's store-owned count.
    let store_owned = bindings
        .keys()
        .filter(|key| {
            key.starts_with("erasure_subject")
                && key["erasure_subject".len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
        })
        .count();
    let sql = erasure_transaction_template(store_owned);
    let mut response = match client::query(db, config, "transaction.erasure", &sql, bindings).await
    {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => {
            return Err(AdapterError::UnknownOutcome {
                operation_id: intent.operation_id.clone(),
            });
        }
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors
            .iter()
            .any(|error| error.contains("erasure_intent_conflict"))
        {
            return Err(AdapterError::Store(StoreError::IdentityConflict));
        }
        return Err(AdapterError::UnknownOutcome {
            operation_id: intent.operation_id.clone(),
        });
    }
    Ok(outcomes)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ErasureOutcomeRow {
    outcomes: Vec<String>,
}

#[allow(dead_code)]
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
            eliot_store_api::PreparedTransition {
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
            }
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
