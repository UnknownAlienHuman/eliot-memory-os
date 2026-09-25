//! Canonical experience-bank/feedback execution for the `SurrealDB` bridge
//! (issue #223).
//!
//! Mirrors the reference contour's closed legs through the store-api wire
//! contract, persisted in two tables: `experience_bank` holds one
//! immutable row per `(handle, revision)` carrying the verbatim
//! Governor-admitted bank-record document; `experience_feedback` holds
//! one immutable row per `(handle, revision)` carrying the verbatim
//! admitted feedback-record document. Documents stay opaque: lineage,
//! sequencing, and digest re-proof are Governor-owned, and this module
//! arbitrates keys and immutability only. Concurrent writers arbitrate
//! through the in-transaction compare-and-set inside the canonical
//! transaction; retries recompute from fresh rows, never from stale
//! reads. Rows commit inside the canonical transaction beside the receipt
//! and outbox rows, so rows, receipt, and outbox stay atomic.
//!
//! Rows are addressed by a joined record id
//! (`handle` + `\x1f` + zero-padded decimal revision). The join is
//! collision-free by construction: the wire contract rejects control
//! characters in the handle and the revision is fixed-width digits, so
//! the unit separator can never occur inside either half and key order
//! matches revision order. The halves also travel as separate row
//! fields, so no reader ever parses the address.

use eliot_store_api::{
    DecodedExperienceMutation, NamedMutationOperation, StateFence, StoreError, TransitionClass,
    decode_experience_mutation,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// Joins one experience row address. Collision-free: the handle may not
/// contain control characters per the wire contract and the revision is
/// fixed-width decimal.
fn experience_row_key(handle: &str, revision: u64) -> String {
    format!("{handle}\x1f{revision:020}")
}

/// One computed bank-row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExperienceBankWrite {
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Owner revision of the record.
    pub revision: u64,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the admitted record bytes.
    pub record_digest: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// One computed feedback-row write for the canonical transaction. Same
/// field rule as the bank write.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExperienceFeedbackWrite {
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Owner revision of the record.
    pub revision: u64,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the admitted record bytes.
    pub record_digest: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// Computed experience row writes for one admitted transition.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ExperienceWrites {
    /// Bank-row creates in admitted command order.
    pub bank: Vec<ExperienceBankWrite>,
    /// Feedback-row creates in admitted command order.
    pub feedback: Vec<ExperienceFeedbackWrite>,
}

/// Stored bank row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredExperienceBank {
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Owner revision of the record.
    pub revision: u64,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the admitted record bytes.
    pub record_digest: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Stored feedback row shape as projected by reads. Same field rule.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredExperienceFeedback {
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Owner revision of the record.
    pub revision: u64,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the admitted record bytes.
    pub record_digest: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Ensures the experience tables exist (idempotent).
///
/// Schemaless tables auto-create on write, but reads and the
/// in-transaction compare-and-set fail closed on missing tables. This
/// one-shot definition keeps first use on a fresh database exact; it
/// changes no migration chain and carries no data.
async fn ensure_experience_tables(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::EXPERIENCE_BANK,
        crate::schema::table::EXPERIENCE_FEEDBACK
    );
    let mut response =
        client::query(db, config, "experience.ensure_tables", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes experience row writes for one admitted transition.
///
/// Reads no rows: bank/feedback rows are create-or-converge keyed by
/// joined handle and revision, so the in-transaction compare-and-set
/// arbitrates concurrent writers without pre-transaction reads.
/// Transitions without experience operations yield no writes. The tables
/// are ensured (idempotent) so first use on a fresh database is exact.
pub(crate) async fn prepare_experience_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<ExperienceWrites, AdapterError> {
    let mut commanded = false;
    for command in &transition.named_operations {
        if command.operation == NamedMutationOperation::CommitExperienceBank
            || command.operation == NamedMutationOperation::CommitAgentFeedback
        {
            commanded = true;
        }
    }
    if !commanded {
        return Ok(ExperienceWrites::default());
    }
    if transition.transition_class != TransitionClass::CaptureCandidate {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    ensure_experience_tables(db, config).await?;
    let mut writes = ExperienceWrites::default();
    for command in &transition.named_operations {
        let decoded = match command.operation {
            NamedMutationOperation::CommitExperienceBank
            | NamedMutationOperation::CommitAgentFeedback => {
                decode_experience_mutation(command.operation, &command.parameters)
                    .map_err(AdapterError::Store)?
            }
            _ => continue,
        };
        match decoded {
            DecodedExperienceMutation::Bank {
                handle,
                revision,
                record_json,
                record_digest,
                ..
            } => writes.bank.push(ExperienceBankWrite {
                handle,
                revision,
                record_json,
                record_digest,
                state_fence: transition.state_fence.clone(),
                scope_id: transition.scope_id.to_string(),
                task_id: transition.task_id.clone(),
            }),
            DecodedExperienceMutation::Feedback {
                handle,
                revision,
                record_json,
                record_digest,
                ..
            } => writes.feedback.push(ExperienceFeedbackWrite {
                handle,
                revision,
                record_json,
                record_digest,
                state_fence: transition.state_fence.clone(),
                scope_id: transition.scope_id.to_string(),
                task_id: transition.task_id.clone(),
            }),
        }
    }
    Ok(writes)
}

/// Builds the canonical-transaction fragment persisting experience rows.
///
/// Row writes are create-or-converge: missing rows create, identical rows
/// pass silently, divergent rows abort the transaction. Drift surfaces
/// the `experience_bank_conflict` / `experience_feedback_conflict`
/// markers so the apply loop retries with fresh rows. Rows commit in the
/// same transaction as the receipt and outbox rows, so rows, receipt,
/// and outbox stay atomic.
pub(crate) fn experience_write_statements(
    writes: &ExperienceWrites,
) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.bank.iter().enumerate() {
        append_bank_statement(&mut sql, &mut bindings, index, write);
    }
    for (index, write) in writes.feedback.iter().enumerate() {
        append_feedback_statement(&mut sql, &mut bindings, index, write);
    }
    (sql, bindings)
}

/// Appends one bank-row create-or-converge fragment.
fn append_bank_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &ExperienceBankWrite,
) {
    let suffix = format!("bank_{index}");
    sql.push_str(
            "LET $experience_current_{s} = (SELECT record_json FROM ONLY type::record($experience_table_{s}, $experience_key_{s})); IF type::is_object($experience_current_{s}) { IF $experience_current_{s}.record_json != $experience_expected_{s} { THROW 'experience_bank_conflict'; }; } ELSE { CREATE type::record($experience_table_{s}, $experience_key_{s}) CONTENT $experience_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("experience_table_{suffix}"),
        json!(schema::table::EXPERIENCE_BANK),
    );
    bindings.insert(
        format!("experience_key_{suffix}"),
        json!(experience_row_key(&write.handle, write.revision)),
    );
    bindings.insert(
        format!("experience_expected_{suffix}"),
        json!(&write.record_json),
    );
    bindings.insert(
        format!("experience_record_{suffix}"),
        json!({
            "handle": write.handle,
            "revision": write.revision,
            "record_json": write.record_json,
            "record_digest": write.record_digest,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Appends one feedback-row create-or-converge fragment. Same
/// create-or-converge rule as the bank fragment.
fn append_feedback_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &ExperienceFeedbackWrite,
) {
    let suffix = format!("feedback_{index}");
    sql.push_str(
            "LET $experience_current_{s} = (SELECT record_json FROM ONLY type::record($experience_table_{s}, $experience_key_{s})); IF type::is_object($experience_current_{s}) { IF $experience_current_{s}.record_json != $experience_expected_{s} { THROW 'experience_feedback_conflict'; }; } ELSE { CREATE type::record($experience_table_{s}, $experience_key_{s}) CONTENT $experience_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("experience_table_{suffix}"),
        json!(schema::table::EXPERIENCE_FEEDBACK),
    );
    bindings.insert(
        format!("experience_key_{suffix}"),
        json!(experience_row_key(&write.handle, write.revision)),
    );
    bindings.insert(
        format!("experience_expected_{suffix}"),
        json!(&write.record_json),
    );
    bindings.insert(
        format!("experience_record_{suffix}"),
        json!({
            "handle": write.handle,
            "revision": write.revision,
            "record_json": write.record_json,
            "record_digest": write.record_digest,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Reports whether a provider statement error observes a missing
/// experience table. Missing tables read as empty, never as failure:
/// every error must narrate a nonexistent table naming one of the two
/// experience tables.
pub(crate) fn missing_experience_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist")
                && (error.contains(schema::table::EXPERIENCE_BANK)
                    || error.contains(schema::table::EXPERIENCE_FEEDBACK))
        })
}

fn text_row_field(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, AdapterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field,
            reason: "experience row field must be present text",
        }))
}

fn revision_row_field(object: &serde_json::Map<String, Value>) -> Result<u64, AdapterError> {
    object
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "revision",
            reason: "experience row revision must be a count",
        }))
}

fn fence_row_field(object: &serde_json::Map<String, Value>) -> Result<StateFence, AdapterError> {
    serde_json::from_value(
        object
            .get("state_fence")
            .cloned()
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "state_fence",
                reason: "experience row field must be present",
            }))?,
    )
    .map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "state_fence",
            reason: "experience row fence must decode",
        })
    })
}

fn decode_bank_row(
    object: serde_json::Map<String, Value>,
) -> Result<StoredExperienceBank, AdapterError> {
    Ok(StoredExperienceBank {
        handle: text_row_field(&object, "handle")?,
        revision: revision_row_field(&object)?,
        record_json: text_row_field(&object, "record_json")?,
        record_digest: text_row_field(&object, "record_digest")?,
        state_fence: fence_row_field(&object)?,
    })
}

fn decode_feedback_row(
    object: serde_json::Map<String, Value>,
) -> Result<StoredExperienceFeedback, AdapterError> {
    Ok(StoredExperienceFeedback {
        handle: text_row_field(&object, "handle")?,
        revision: revision_row_field(&object)?,
        record_json: text_row_field(&object, "record_json")?,
        record_digest: text_row_field(&object, "record_digest")?,
        state_fence: fence_row_field(&object)?,
    })
}

/// Reads bank rows for the current query in key order.
pub(crate) async fn read_bank_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    limit: usize,
) -> Result<Vec<StoredExperienceBank>, AdapterError> {
    let sql = format!(
        "SELECT * FROM {} WHERE scope_id = $experience_scope ORDER BY handle, revision LIMIT {limit};",
        schema::table::EXPERIENCE_BANK
    );
    let mut bindings = Map::new();
    bindings.insert("experience_scope".to_owned(), json!(scope_id));
    let mut response = client::query(db, config, "experience.read_bank", &sql, bindings).await?;
    let errors = response.take_errors();
    if missing_experience_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "experience bank snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.into_iter()
        .map(|row| {
            row.as_object()
                .cloned()
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "experience.row",
                    reason: "experience bank row must be an object",
                }))
                .and_then(decode_bank_row)
        })
        .collect()
}

/// Reads feedback rows for the current query in key order. Same
/// scope-gated rule as the bank read.
pub(crate) async fn read_feedback_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    scope_id: &str,
    limit: usize,
) -> Result<Vec<StoredExperienceFeedback>, AdapterError> {
    let sql = format!(
        "SELECT * FROM {} WHERE scope_id = $experience_scope ORDER BY handle, revision LIMIT {limit};",
        schema::table::EXPERIENCE_FEEDBACK
    );
    let mut bindings = Map::new();
    bindings.insert("experience_scope".to_owned(), json!(scope_id));
    let mut response =
        client::query(db, config, "experience.read_feedback", &sql, bindings).await?;
    let errors = response.take_errors();
    if missing_experience_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "experience feedback snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.into_iter()
        .map(|row| {
            row.as_object()
                .cloned()
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "experience.row",
                    reason: "experience feedback row must be an object",
                }))
                .and_then(decode_feedback_row)
        })
        .collect()
}
