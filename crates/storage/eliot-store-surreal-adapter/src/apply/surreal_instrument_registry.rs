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
    CanonicalRequestView, NamedMutationOperation, OrderingHeadExpectation, PreparedTransition,
    RequestMeta, RevisionHeadExpectation, StateFence, StoreError, TransitionClass,
    decode_instrument_registry_authority_ledger, decode_instrument_registry_expected_revision,
    decode_instrument_registry_mutation, verify_canonical_request_hash,
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
/// Row shape mirrors the writer (verbatim `snapshot_json`, store-local
/// `revision`, `state_fence`, original transition/request identity, and the
/// byte-preserved request view used to verify its canonical hash). The row is
/// the singleton snapshot head; every apply replaces it verbatim with a bumped
/// revision. Historical rows may lack new identity fields; those remain
/// explicit `None` so only a real re-registration can fill them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredInstrumentRegistryHead {
    pub(crate) snapshot_json: String,
    pub(crate) revision: u64,
    pub(crate) state_fence: StateFence,
    pub(crate) scope_id: String,
    pub(crate) task_id: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) canonical_request_hash: Option<String>,
    /// Governor-owned, closed registration authority ledger. `None` is kept
    /// explicit for historical rows so callers can refuse migration rather
    /// than fabricate a fresh use budget.
    pub(crate) registration_authority_json: Option<String>,
    /// Exact serialized original apply request used to admit this registration.
    /// Historical rows remain `None`; the adapter never manufactures proof.
    pub(crate) registration_request_json: Option<String>,
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
    pub(super) operation_id: String,
    pub(super) canonical_request_hash: String,
    pub(super) registration_authority_json: String,
    pub(super) registration_request_json: String,
    pub(super) expected_revision: u64,
}

/// Pre-transaction instrument-registry writes for one attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InstrumentRegistryWrites {
    pub(super) heads: Vec<InstrumentRegistryHeadWrite>,
}

async fn ensure_instrument_registry_table(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let ddl = format!(
        "DEFINE TABLE IF NOT EXISTS {INSTRUMENT_REGISTRY} SCHEMAFULL; \
         DEFINE FIELD IF NOT EXISTS snapshot_json ON {INSTRUMENT_REGISTRY} TYPE string; \
         DEFINE FIELD IF NOT EXISTS revision ON {INSTRUMENT_REGISTRY} TYPE int; \
         DEFINE FIELD IF NOT EXISTS state_fence ON {INSTRUMENT_REGISTRY} TYPE object; \
         DEFINE FIELD IF NOT EXISTS scope_id ON {INSTRUMENT_REGISTRY} TYPE string; \
         DEFINE FIELD IF NOT EXISTS task_id ON {INSTRUMENT_REGISTRY} TYPE option<string>; \
         DEFINE FIELD IF NOT EXISTS operation_id ON {INSTRUMENT_REGISTRY} TYPE option<string>; \
         DEFINE FIELD IF NOT EXISTS canonical_request_hash ON {INSTRUMENT_REGISTRY} TYPE option<string>; \
         DEFINE FIELD IF NOT EXISTS registration_authority_json ON {INSTRUMENT_REGISTRY} TYPE option<string>; \
         DEFINE FIELD IF NOT EXISTS registration_request_json ON {INSTRUMENT_REGISTRY} TYPE option<string>;"
    );
    client::query(db, config, "schema.ensure", &ddl, Map::new())
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
    context: &RequestMeta,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
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
    let original_request = CanonicalRequestView::from_apply(
        context,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(
        &original_request,
        &transition.identity.canonical_request_hash,
    )
    .map_err(AdapterError::Store)?;
    let registration_request_json = serde_json::to_string(&original_request)
        .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))?;
    let snapshot_json =
        decode_instrument_registry_mutation(&command.parameters).map_err(AdapterError::Store)?;
    let registration_authority_json =
        decode_instrument_registry_authority_ledger(&command.parameters)
            .map_err(AdapterError::Store)?;
    let expected_revision = decode_instrument_registry_expected_revision(&command.parameters)
        .map_err(AdapterError::Store)?;
    let current = read_instrument_registry_row(db, config).await?;
    let revision_matches = match current.as_ref() {
        None => expected_revision == 0,
        Some(row) => row.revision > 0 && row.revision == expected_revision,
    };
    if !revision_matches {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    }
    if let Some(previous) = current.as_ref() {
        if previous.registration_authority_json.is_none() {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "instrument_registry.registration_authority_json",
                reason: "stored authority ledger is missing; explicit migration is required",
            }));
        }
        let previous_ledger =
            previous
                .registration_authority_json
                .as_ref()
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "instrument_registry.registration_authority_json",
                    reason: "stored authority ledger is missing; explicit migration is required",
                }))?;
        decode_instrument_registry_authority_ledger(&std::collections::BTreeMap::from([(
            "registration_authority_json".to_owned(),
            serde_json::Value::String(previous_ledger.clone()),
        )]))
        .map_err(AdapterError::Store)?;
    }
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
            operation_id: transition.identity.operation_id.as_str().to_owned(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            registration_authority_json,
            registration_request_json,
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
    let scope_id = text_row_field(object, "scope_id")?;
    let task_id = optional_text_row_field(object, "task_id")?;
    let operation_id = optional_text_row_field(object, "operation_id")?;
    let canonical_request_hash = optional_text_row_field(object, "canonical_request_hash")?;
    let registration_authority_json =
        optional_text_row_field(object, "registration_authority_json")?;
    let registration_request_json = optional_text_row_field(object, "registration_request_json")?;
    Ok(StoredInstrumentRegistryHead {
        snapshot_json,
        revision,
        state_fence,
        scope_id,
        task_id,
        operation_id,
        canonical_request_hash,
        registration_authority_json,
        registration_request_json,
    })
}

fn optional_text_row_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, AdapterError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(AdapterError::Store(StoreError::InvalidField {
            field: "instrument_registry.row",
            reason: "optional instrument registry row field must be a string",
        })),
    }
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
                "operation_id": write.operation_id,
                "canonical_request_hash": write.canonical_request_hash,
                "registration_authority_json": write.registration_authority_json,
                "registration_request_json": write.registration_request_json,
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
