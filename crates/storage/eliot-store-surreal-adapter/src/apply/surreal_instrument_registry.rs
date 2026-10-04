//! Canonical instrument-registry execution for the `SurrealDB` bridge
//! (issue #1814 W1.2).
//!
//! Mirrors `surreal_reactive.rs`: one singleton head row
//! per fence carrying the verbatim opaque snapshot bytes with a store-issued
//! revision. Applies replace the head verbatim with a bumped revision under
//! the same fence+revision compare-and-set contract; cross-fence writes fail
//! closed and the bytes stay opaque here (the adapter never interprets
//! instrument admission).

use eliot_store_api::{
    NamedMutationOperation, PreparedTransition, StateFence, StoreError, TransitionClass,
    decode_instrument_registry_mutation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;
use crate::schema::table::INSTRUMENT_REGISTRY;

const INSTRUMENT_REGISTRY_HEAD_KEY: &str = "head";

/// One durable instrument-registry head row.
///
/// Row shape mirrors the writer (verbatim `snapshot_json`, `revision`,
/// `state_fence`). The row is the singleton snapshot head; every apply
/// replaces it verbatim with a bumped revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredInstrumentRegistryHead {
    pub(crate) snapshot_json: String,
    pub(crate) revision: u64,
    pub(crate) state_fence: StateFence,
}

/// One computed instrument-registry head write: the verbatim snapshot bytes
/// with the store-issued revision and admission fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InstrumentRegistryHeadWrite {
    pub(super) snapshot_json: String,
    pub(super) revision: u64,
    pub(super) state_fence: StateFence,
    pub(super) scope_id: String,
    pub(super) task_id: Option<String>,
    pub(super) expected_revision: u64,
}

/// Pre-transaction instrument-registry writes for one attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InstrumentRegistryWrites {
    pub(super) heads: Vec<InstrumentRegistryHeadWrite>,
}

/// Creates the instrument-registry head table if the provider has not.
///
/// The statement text is the owner's published
/// [`crate::schema::INSTRUMENT_REGISTRY_TABLES_DDL`] constant, issued verbatim:
/// the bytes this operation executes are exactly the bytes
/// `crate::schema_inventory::EMBEDDED_SCHEMA_BODIES` publishes, so the body's
/// recorded digest describes the DDL that reaches the provider instead of a
/// second, informal copy of it (issue #1221 acceptance A1).
async fn ensure_instrument_registry_table(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    client::query(
        db,
        config,
        "schema.ensure",
        schema::INSTRUMENT_REGISTRY_TABLES_DDL,
        Map::new(),
    )
    .await
    .map(|_| ())
}

/// Pre-computes instrument-registry head writes (issue #1814 W1.2).
///
/// Same contract as `prepare_reactive_writes`: the decoded snapshot is
/// accepted only under the `InstrumentRegistry` transition class, at most
/// one instrument leg per transition (a second leg is a duplicate that
/// fails closed instead of silently winning), and the pre-read of the
/// current head supplies the expected revision for the in-transaction
/// compare-and-set plus the Rust-side fence check.
pub(super) async fn prepare_instrument_registry_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &PreparedTransition,
) -> Result<InstrumentRegistryWrites, AdapterError> {
    ensure_instrument_registry_table(db, config).await?;
    let mut matching = transition.named_operations.iter().filter(|command| {
        command.operation == NamedMutationOperation::ApplyInstrumentRegistryState
    });
    let Some(command) = matching.next() else {
        return Ok(InstrumentRegistryWrites::default());
    };
    if matching.next().is_some() {
        return Err(AdapterError::Store(StoreError::Duplicate {
            field: "instrument_registry.named_operations",
        }));
    }
    if transition.transition_class != TransitionClass::InstrumentRegistry {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    let snapshot_json =
        decode_instrument_registry_mutation(&command.parameters).map_err(AdapterError::Store)?;
    let current = read_instrument_registry_row(db, config).await?;
    let expected_revision = current.as_ref().map_or(0, |row| row.revision);
    if current
        .as_ref()
        .is_some_and(|row| row.state_fence != transition.state_fence)
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let revision =
        expected_revision
            .checked_add(1)
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "instrument_registry.revision",
                reason: "owner revision overflow",
            }))?;
    Ok(InstrumentRegistryWrites {
        heads: vec![InstrumentRegistryHeadWrite {
            snapshot_json,
            revision,
            state_fence: transition.state_fence.clone(),
            scope_id: transition.scope_id.to_string(),
            task_id: transition.task_id.clone(),
            expected_revision,
        }],
    })
}

async fn read_instrument_registry_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<StoredInstrumentRegistryHead>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "instrument_registry_table".to_owned(),
        json!(crate::schema::table::INSTRUMENT_REGISTRY),
    );
    bindings.insert(
        "instrument_registry_key".to_owned(),
        json!(INSTRUMENT_REGISTRY_HEAD_KEY),
    );
    let statement =
        "SELECT * FROM ONLY type::record($instrument_registry_table, $instrument_registry_key);";
    let mut response = client::query(
        db,
        config,
        "instrument_registry.read_row",
        statement,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if missing_instrument_registry_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_instrument_registry_row).transpose()
}

pub(crate) fn missing_instrument_registry_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist") && error.contains(schema::table::INSTRUMENT_REGISTRY)
        })
}

fn text_row_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, AdapterError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "instrument_registry.row",
            reason: "instrument registry row field must be a string",
        }))
}

fn decode_instrument_registry_row(
    value: &Value,
) -> Result<StoredInstrumentRegistryHead, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "instrument_registry.row",
            reason: "instrument registry row must be an object",
        }))?;
    let snapshot_json = text_row_field(object, "snapshot_json")?;
    let revision = object.get("revision").and_then(Value::as_u64).unwrap_or(0);
    let state_fence: StateFence =
        serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
            .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    Ok(StoredInstrumentRegistryHead {
        snapshot_json,
        revision,
        state_fence,
    })
}

/// Renders canonical instrument-registry head writes (issue #1814 W1.2).
///
/// Same compare-and-set contract as the reactive-session fragment: an
/// existing head updates only under the same fence and expected revision
/// (fence drift and revision drift surface deterministic conflict
/// markers so the apply loop retries with fresh rows), while a missing
/// head creates exactly when nothing is expected.
pub(super) fn instrument_registry_write_statements(
    writes: &InstrumentRegistryWrites,
) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    bindings.insert(
        "instrument_registry_table".to_owned(),
        json!(INSTRUMENT_REGISTRY),
    );
    for (index, write) in writes.heads.iter().enumerate() {
        let suffix = format!("_{index}");
        sql.push_str(
            "LET $instrument_registry_existing{s} = (SELECT VALUE { state_fence: state_fence, revision: revision } FROM ONLY type::record($instrument_registry_table, $instrument_registry_key{s})); IF type::is_object($instrument_registry_existing{s}) { IF $instrument_registry_existing{s}.state_fence == $instrument_registry_expected_fence{s} { UPDATE type::record($instrument_registry_table, $instrument_registry_key{s}) CONTENT $instrument_registry_record{s} WHERE revision = $instrument_registry_expected_revision{s}; } ELSE { THROW 'instrument_registry_fence_conflict'; }; } ELSE { IF $instrument_registry_expected_revision{s} != 0 { THROW 'instrument_registry_create_conflict'; }; CREATE type::record($instrument_registry_table, $instrument_registry_key{s}) CONTENT $instrument_registry_record{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
        bindings.insert(
            format!("instrument_registry_key{suffix}"),
            json!(INSTRUMENT_REGISTRY_HEAD_KEY),
        );
        bindings.insert(
            format!("instrument_registry_expected_fence{suffix}"),
            json!(&write.state_fence),
        );
        bindings.insert(
            format!("instrument_registry_expected_revision{suffix}"),
            json!(write.expected_revision),
        );
        bindings.insert(
            format!("instrument_registry_record{suffix}"),
            json!({
                "snapshot_json": write.snapshot_json,
                "revision": write.revision,
                "state_fence": write.state_fence,
                "scope_id": write.scope_id,
                "task_id": write.task_id,
            }),
        );
    }
    (sql, bindings)
}

/// Reads the instrument-registry head row for the read path.
pub(crate) async fn read_head_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<Option<StoredInstrumentRegistryHead>, AdapterError> {
    read_instrument_registry_row(db, config).await
}
