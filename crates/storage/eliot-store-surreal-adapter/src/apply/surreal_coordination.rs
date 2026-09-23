//! Canonical restore-coordination execution for the `SurrealDB` bridge
//! (issues #959/#960/#962/#975; #954 caller control).
//!
//! Persists Governor-admitted restore coordination decision rows in the
//! `restore_coordination` table: one row per `coordination_operation_id`
//! carrying the six admitted coordination bindings, the admission fence, and
//! the Governor-issued proof refs bound into the row as audit evidence.
//! Same-operation replay converges when every binding is byte-exact and
//! refuses with `IdentityConflict` on any divergence (F6); the in-transaction
//! compare-and-set arbitrates concurrent writers, and drift retries through
//! allocation contention, never as a semantic conflict. Record rows commit
//! inside the canonical transaction beside the receipt and outbox rows, so
//! decision row, receipt, and outbox stay atomic.
//!
//! Caller authentication (#954): coordination legs execute only on
//! transitions carrying non-empty Governor-issued proof/approval refs (the
//! store-api plan gate refuses earlier); the leg re-checks at the execution
//! boundary and binds the refs into the persisted row. No caller-supplied
//! bytes are treated as issuance: the bridge independently re-fetches the
//! coordination receipt keyed by the restore identity before any restore
//! effect (consumer-side verification lives with the restore caller).

use eliot_store_api::{
    NamedMutationOperation, StateFence, StoreError, TransitionClass,
    validate_coordination_mutation_params,
};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// One computed coordination row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SurrealCoordinationWrite {
    /// Restore operation identity keying the decision row.
    pub operation_id: String,
    /// Admitted destination binding.
    pub destination: String,
    /// Admitted payload digest (coordination transition request hash).
    pub payload_digest: String,
    /// Admitted fence digest.
    pub fence_digest: String,
    /// Coordination decision digest.
    pub decision_digest: String,
    /// Governor admission digest the decision was built from.
    pub admission_digest: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Governor-issued proof refs bound into the row as audit evidence.
    pub proof_refs: Vec<String>,
}

/// Stored coordination row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredCoordinationRow {
    /// Restore operation identity keying the decision row.
    pub operation_id: String,
    /// Admitted destination binding.
    pub destination: String,
    /// Admitted payload digest.
    pub payload_digest: String,
    /// Admitted fence digest.
    pub fence_digest: String,
    /// Coordination decision digest.
    pub decision_digest: String,
    /// Governor admission digest.
    pub admission_digest: String,
    /// Admission fence of the committing transition.
    pub state_fence: StateFence,
    /// Governor-issued proof refs bound at commit time.
    pub proof_refs: Vec<String>,
}

/// Ensures the restore coordination table exists (idempotent).
///
/// Schemaless tables auto-create on write, but reads and the
/// in-transaction compare-and-set fail closed on a missing table. This
/// one-shot definition keeps first use on a fresh database exact without a
/// schema-migration bump.
async fn ensure_coordination_table(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::RESTORE_COORDINATION
    );
    let mut response =
        client::query(db, config, "coordination.ensure_table", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes coordination row writes for one admitted transition.
///
/// Filters `RecordRestoreCoordination` commands, enforces the RecoverySchema
/// class and the Governor proof-refs gate at the execution boundary,
/// validates the closed six-parameter vocabulary, and converges
/// same-operation replay: a stored row with byte-exact bindings yields no
/// write, while any divergence refuses with `IdentityConflict` before any
/// statement is built. Transitions without coordination operations yield no
/// writes. Pure reads plus pure compute: rows are written only by the
/// canonical transaction.
pub(crate) async fn prepare_coordination_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<Vec<SurrealCoordinationWrite>, AdapterError> {
    let mut commands = Vec::new();
    for command in &transition.named_operations {
        if command.operation == NamedMutationOperation::RecordRestoreCoordination {
            commands.push(command);
        }
    }
    if commands.is_empty() {
        return Ok(Vec::new());
    }
    if transition.transition_class != TransitionClass::RecoverySchema {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    // #954 caller control at the execution boundary: coordination legs run
    // only with Governor-issued proof refs on the transition. The plan gate
    // refuses earlier; this re-check closes any path that bypasses it.
    if transition.required_proof_and_approval_refs.is_empty() {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "proof_or_approval_ref",
            reason: "restore coordination requires Governor-issued proof refs",
        }));
    }
    ensure_coordination_table(db, config).await?;
    let mut writes = Vec::with_capacity(commands.len());
    for command in commands {
        validate_coordination_mutation_params(&command.parameters)
            .map_err(AdapterError::Store)?;
        let write = write_for(
            &command.parameters,
            &transition.state_fence,
            &transition.required_proof_and_approval_refs,
        )?;
        // Same-operation replay convergence (F6): a stored row with
        // byte-exact bindings is already the committed decision — no new
        // write. Any divergence is a rotated admission under a reused
        // identity and refuses here, before any statement is built.
        if let Some(stored) = read_coordination_row(db, config, &write.operation_id).await? {
            if stored_matches(&stored, &write) {
                continue;
            }
            return Err(AdapterError::Store(StoreError::IdentityConflict));
        }
        writes.push(write);
    }
    Ok(writes)
}

/// Builds one coordination write from validated closed parameters.
fn write_for(
    parameters: &std::collections::BTreeMap<String, Value>,
    state_fence: &StateFence,
    proof_refs: &[String],
) -> Result<SurrealCoordinationWrite, AdapterError> {
    let text = |key: &str| -> Result<String, AdapterError> {
        parameters
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "coordination.parameter",
                reason: "coordination parameter must be a present string",
            }))
    };
    Ok(SurrealCoordinationWrite {
        operation_id: text(eliot_store_api::COORDINATION_PARAM_OPERATION_ID)?,
        destination: text(eliot_store_api::COORDINATION_PARAM_DESTINATION)?,
        payload_digest: text(eliot_store_api::COORDINATION_PARAM_PAYLOAD_DIGEST)?,
        fence_digest: text(eliot_store_api::COORDINATION_PARAM_FENCE_DIGEST)?,
        decision_digest: text(eliot_store_api::COORDINATION_PARAM_DECISION_DIGEST)?,
        admission_digest: text(eliot_store_api::COORDINATION_PARAM_ADMISSION_DIGEST)?,
        state_fence: state_fence.clone(),
        proof_refs: proof_refs.to_vec(),
    })
}

/// Reports whether the stored row carries byte-exactly the computed bindings,
/// admission fence, and proof refs — the same whole-row equality the memory
/// contour enforces, so fence-rotated replay converges on both contours or
/// on neither.
fn stored_matches(stored: &StoredCoordinationRow, write: &SurrealCoordinationWrite) -> bool {
    stored.operation_id == write.operation_id
        && stored.destination == write.destination
        && stored.payload_digest == write.payload_digest
        && stored.fence_digest == write.fence_digest
        && stored.decision_digest == write.decision_digest
        && stored.admission_digest == write.admission_digest
        && stored.state_fence == write.state_fence
        && stored.proof_refs == write.proof_refs
}

/// Reads one stored coordination row by exact operation identity.
async fn read_coordination_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    operation_id: &str,
) -> Result<Option<StoredCoordinationRow>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "coord_table".to_owned(),
        json!(crate::schema::table::RESTORE_COORDINATION),
    );
    bindings.insert("coord_key".to_owned(), json!(operation_id));
    let statement = "SELECT * FROM ONLY type::record($coord_table, $coord_key);";
    let mut response =
        client::query(db, config, "coordination.read_row", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_coordination_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_coordination_row).transpose()
}

/// Reports whether provider errors prove only that the coordination table
/// has no rows yet (fresh database, no migration): a missing table carries
/// no rows, so empty is exact truth here rather than an inference. Any
/// other error stays a partial outcome.
fn missing_coordination_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors
            .iter()
            .all(|error| error.contains("restore_coordination") && error.contains("does not exist"))
}

fn decode_coordination_row(value: &Value) -> Result<StoredCoordinationRow, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "coordination.row",
            reason: "coordination row must be an object",
        }))?;
    let text_field = |name: &str| -> Result<String, AdapterError> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "coordination.row",
                reason: "coordination row is missing a text field",
            }))
    };
    let proof_refs = object
        .get("proof_refs")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_owned).ok_or(AdapterError::Store(
                        StoreError::InvalidField {
                            field: "coordination.row",
                            reason: "coordination proof ref must be a string",
                        },
                    ))
                })
                .collect::<Result<Vec<String>, AdapterError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let state_fence: StateFence =
        serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
            .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    Ok(StoredCoordinationRow {
        operation_id: text_field("operation_id")?,
        destination: text_field("destination")?,
        payload_digest: text_field("payload_digest")?,
        fence_digest: text_field("fence_digest")?,
        decision_digest: text_field("decision_digest")?,
        admission_digest: text_field("admission_digest")?,
        state_fence,
        proof_refs,
    })
}

/// Builds the canonical-transaction fragment persisting coordination rows.
///
/// One sealed compare-and-set per write, mirroring the erasure-outcome row:
/// a present row with divergent bindings throws
/// `coordination_identity_conflict` (unlisted marker → unknown outcome for
/// identity-based reconciliation, never blind retry); an absent row is
/// created. Same-operation byte-exact replay never reaches this fragment
/// (converged pre-transaction); the in-transaction guard covers commit races
/// only.
pub(crate) fn coordination_write_statements(
    writes: &[SurrealCoordinationWrite],
) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.iter().enumerate() {
        let suffix = index.to_string();
        // Full-row compare: all six coordination bindings plus the admission
        // fence and the bound proof refs, matching the memory contour's
        // whole-row equality. A fence-rotated replay converges only when the
        // stored row is byte-exact; any divergence throws for identity-based
        // reconciliation.
        sql.push_str(
            "LET $coord_current_{s} = (SELECT operation_id, destination, payload_digest, fence_digest, decision_digest, admission_digest, state_fence, proof_refs FROM ONLY type::record($coord_table_{s}, $coord_key_{s})); IF type::is_object($coord_current_{s}) { IF $coord_current_{s}.operation_id != $coord_operation_{s} OR $coord_current_{s}.destination != $coord_destination_{s} OR $coord_current_{s}.payload_digest != $coord_payload_{s} OR $coord_current_{s}.fence_digest != $coord_fence_{s} OR $coord_current_{s}.decision_digest != $coord_decision_{s} OR $coord_current_{s}.admission_digest != $coord_admission_{s} OR $coord_current_{s}.state_fence != $coord_state_fence_{s} OR $coord_current_{s}.proof_refs != $coord_proof_refs_{s} { THROW 'coordination_identity_conflict'; }; } ELSE { CREATE type::record($coord_table_{s}, $coord_key_{s}) CONTENT $coord_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
        bindings.insert(
            format!("coord_table_{suffix}"),
            json!(schema::table::RESTORE_COORDINATION),
        );
        bindings.insert(format!("coord_key_{suffix}"), json!(&write.operation_id));
        bindings.insert(
            format!("coord_operation_{suffix}"),
            json!(&write.operation_id),
        );
        bindings.insert(
            format!("coord_destination_{suffix}"),
            json!(&write.destination),
        );
        bindings.insert(
            format!("coord_payload_{suffix}"),
            json!(&write.payload_digest),
        );
        bindings.insert(format!("coord_fence_{suffix}"), json!(&write.fence_digest));
        bindings.insert(
            format!("coord_decision_{suffix}"),
            json!(&write.decision_digest),
        );
        bindings.insert(
            format!("coord_admission_{suffix}"),
            json!(&write.admission_digest),
        );
        bindings.insert(
            format!("coord_state_fence_{suffix}"),
            json!(&write.state_fence),
        );
        bindings.insert(
            format!("coord_proof_refs_{suffix}"),
            json!(&write.proof_refs),
        );
        bindings.insert(
            format!("coord_record_{suffix}"),
            json!({
                "operation_id": write.operation_id,
                "destination": write.destination,
                "payload_digest": write.payload_digest,
                "fence_digest": write.fence_digest,
                "decision_digest": write.decision_digest,
                "admission_digest": write.admission_digest,
                "state_fence": write.state_fence,
                "proof_refs": write.proof_refs,
            }),
        );
    }
    (sql, bindings)
}
