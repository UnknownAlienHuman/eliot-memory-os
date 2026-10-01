//! Canonical persistence and exact named reads for the three Orientation
//! owner-source records. The bridge validates closed identities and CAS
//! state; it does not interpret Governor decisions or source semantics.

use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignOwnerRecordId, CampaignOwnerRevision,
    CampaignSourceHead, CampaignSourcePublication, CampaignSourcePublicationState,
    CampaignSourceReadStatus, CampaignSourceRecord, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, CampaignSourceRole, NamedMutationOperation,
    NamedReadRequest, PreparedTransition, StateFence, StoreError, canonical_json_bytes,
    decode_orientation_owner_sources,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// One admitted source row write retains both the original owner publication
/// and its exact immutable row serialization.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OrientationOwnerSourceWrite {
    source_key: String,
    revision_key: String,
    record_json: String,
    publication_json: String,
    next_head_json: String,
    expected_head_json: Option<String>,
    current_reference: bool,
    record: CampaignSourceRecord,
}

/// Source writes in original operation order.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct OrientationOwnerSourceWrites {
    pub rows: Vec<OrientationOwnerSourceWrite>,
}

#[derive(Serialize)]
struct SourceIdentity<'a> {
    role: CampaignSourceRole,
    owner_id: &'a str,
    record_id: &'a CampaignOwnerRecordId,
}

#[derive(Serialize)]
struct SourceRevisionIdentity<'a> {
    source_key: &'a str,
    revision: &'a CampaignOwnerRevision,
}

/// Prepare exact campaign source rows for the canonical transaction. The
/// typed StoreAPI decoder enforces the exact three-role set; this edge binds
/// the publications to the prepared task, WorkScope, and full state fence.
pub(crate) async fn prepare_orientation_owner_source_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &PreparedTransition,
) -> Result<(), AdapterError> {
    let writes = orientation_owner_source_writes(transition)?;
    if !writes.rows.is_empty() {
        ensure_orientation_source_table(db, config).await?;
    }
    Ok(())
}

fn orientation_owner_source_writes(
    transition: &PreparedTransition,
) -> Result<OrientationOwnerSourceWrites, AdapterError> {
    let mut commands = transition
        .named_operations
        .iter()
        .filter(|command| command.operation == NamedMutationOperation::RecordOrientationOwnerSources);
    let Some(command) = commands.next() else {
        return Ok(OrientationOwnerSourceWrites::default());
    };
    if commands.next().is_some()
        || transition.named_operations.len() != 1
        || transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate
    {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }

    let (task_id, publications) =
        decode_orientation_owner_sources(&command.parameters).map_err(AdapterError::Store)?;
    if transition.task_id.as_deref() != Some(task_id.as_str()) {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "orientation_owner_sources.task_id",
            reason: "must equal the prepared transition task",
        }));
    }
    let task_revision = transition.state_fence.task_revision.as_ref().ok_or(
        AdapterError::Store(StoreError::InvalidField {
            field: "orientation_owner_sources.state_fence.task_revision",
            reason: "Orientation owner sources require the original task revision",
        }),
    )?;
    let mut rows = Vec::with_capacity(publications.len());
    for publication in publications {
        publication.validate().map_err(AdapterError::Store)?;
        validate_publication_binding(
            &publication,
            &task_id,
            transition,
            task_revision,
        )?;
        rows.push(prepare_source_write(publication)?);
    }
    Ok(OrientationOwnerSourceWrites { rows })
}

/// Append source rows and exact predecessor-head compare-and-set operations
/// inside the single canonical transaction.
pub(crate) fn orientation_owner_source_write_statements(
    transition: &PreparedTransition,
) -> Result<(String, Map<String, Value>), AdapterError> {
    let writes = orientation_owner_source_writes(transition)?;
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.rows.iter().enumerate() {
        let suffix = index.to_string();
        let template = if write.current_reference {
            "LET $orientation_source_head_{s} = (SELECT * FROM ONLY type::record($orientation_source_table_{s}, $orientation_source_head_id_{s})); LET $orientation_source_record_{s} = (SELECT * FROM ONLY type::record($orientation_source_table_{s}, $orientation_source_revision_id_{s})); IF !type::is_object($orientation_source_head_{s}) OR $orientation_source_head_{s}.row_kind != 'head' OR $orientation_source_head_{s}.head_json != $orientation_source_expected_head_{s} OR !type::is_object($orientation_source_record_{s}) OR $orientation_source_record_{s}.row_kind != 'revision' OR $orientation_source_record_{s}.record_json != $orientation_source_expected_record_{s} { THROW 'orientation_owner_source_conflict'; };"
        } else {
            "LET $orientation_source_head_{s} = (SELECT * FROM ONLY type::record($orientation_source_table_{s}, $orientation_source_head_id_{s})); IF type::is_object($orientation_source_head_{s}) { IF !$orientation_source_expected_head_present_{s} OR $orientation_source_head_{s}.row_kind != 'head' OR $orientation_source_head_{s}.head_json != $orientation_source_expected_head_{s} { THROW 'orientation_owner_source_conflict'; }; } ELSE { IF $orientation_source_expected_head_present_{s} { THROW 'orientation_owner_source_conflict'; }; }; LET $orientation_source_record_{s} = (SELECT * FROM ONLY type::record($orientation_source_table_{s}, $orientation_source_revision_id_{s})); IF type::is_object($orientation_source_record_{s}) { IF $orientation_source_record_{s}.row_kind != 'revision' OR $orientation_source_record_{s}.record_json != $orientation_source_expected_record_{s} OR $orientation_source_record_{s}.publication_json != $orientation_source_publication_{s} { THROW 'orientation_owner_source_conflict'; }; } ELSE { CREATE type::record($orientation_source_table_{s}, $orientation_source_revision_id_{s}) CONTENT $orientation_source_record_value_{s}; }; IF type::is_object($orientation_source_head_{s}) { UPDATE type::record($orientation_source_table_{s}, $orientation_source_head_id_{s}) CONTENT $orientation_source_head_value_{s}; } ELSE { CREATE type::record($orientation_source_table_{s}, $orientation_source_head_id_{s}) CONTENT $orientation_source_head_value_{s}; };"
        };
        sql.push_str(&template.replace("{s}", &suffix));
        insert_binding(
            &mut bindings,
            format!("orientation_source_table_{suffix}"),
            json!(schema::table::CAMPAIGN_SOURCE),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_head_id_{suffix}"),
            json!(format!("head:{}", write.source_key)),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_revision_id_{suffix}"),
            json!(format!("revision:{}", write.revision_key)),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_expected_record_{suffix}"),
            json!(write.record_json),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_expected_head_present_{suffix}"),
            json!(write.expected_head_json.is_some()),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_expected_head_{suffix}"),
            json!(write.expected_head_json.as_deref().unwrap_or("")),
        );
        if write.current_reference {
            continue;
        }
        insert_binding(
            &mut bindings,
            format!("orientation_source_publication_{suffix}"),
            json!(write.publication_json),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_record_value_{suffix}"),
            json!({
                "row_kind": "revision",
                "source_key": write.source_key,
                "revision_key": write.revision_key,
                "role": write.record.role,
                "owner_id": write.record.owner_id,
                "record_id": write.record.record_id,
                "revision": write.record.revision,
                "content_digest": write.record.content_digest,
                "recorded_state_fence": write.record.recorded_state_fence,
                "record_json": write.record_json,
                "publication_json": write.publication_json,
            }),
        );
        insert_binding(
            &mut bindings,
            format!("orientation_source_head_value_{suffix}"),
            json!({
                "row_kind": "head",
                "source_key": write.source_key,
                "head_json": write.next_head_json,
            }),
        );
    }
    Ok((sql, bindings))
}

/// Execute `GetCampaignSourceRevision` for one exact typed source key.
pub(crate) async fn read_campaign_source_revision(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    query: &NamedReadRequest,
) -> Result<CampaignSourceRevisionRead, AdapterError> {
    let lookup: CampaignSourceRevisionLookup = serde_json::from_value(
        query
            .parameters
            .get("lookup")
            .cloned()
            .ok_or(AdapterError::Store(StoreError::InvalidField {
                field: "campaign_source_lookup",
                reason: "lookup is required",
            }))?,
    )
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    lookup.validate().map_err(AdapterError::Store)?;

    let source_key = source_key(&lookup.role, lookup.owner_id.as_str(), &lookup.record_id)?;
    let Some(current_head) = read_current_head(db, config, &source_key).await? else {
        return empty_read(CampaignSourceReadStatus::Missing, query.state_fence.clone());
    };
    validate_head_for_lookup(&current_head, &lookup)?;

    let (source, status) = match (&lookup.expected_revision, &lookup.expected_content_digest) {
        (None, None) => {
            let source = read_source_record(
                db,
                config,
                &source_key,
                &lookup,
                &current_head.revision,
            )
            .await?
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "campaign_source_revision",
                    reason: "current owner head has no immutable source row",
                }))?;
            (source, CampaignSourceReadStatus::Current)
        }
        (Some(revision), Some(digest)) => {
            let source = read_source_record(db, config, &source_key, &lookup, revision).await?;
            if revision == &current_head.revision
                && digest == &current_head.content_digest
                && source.is_none()
            {
                return Err(AdapterError::Store(StoreError::InvalidField {
                    field: "campaign_source_revision",
                    reason: "current owner head has no immutable source row",
                }));
            }
            let current = revision == &current_head.revision
                && digest == &current_head.content_digest
                && source.as_ref().is_some_and(|record| record.content_digest == *digest);
            (
                source,
                if current {
                    CampaignSourceReadStatus::Current
                } else {
                    CampaignSourceReadStatus::Stale
                },
            )
        }
        _ => {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "campaign_source_lookup.expected_reference",
                reason: "expected revision and content digest must be supplied together",
            }));
        }
    };

    if status == CampaignSourceReadStatus::Current
        && source.as_ref().is_none_or(|record| !record_matches_head(record, &current_head))
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source_revision",
            reason: "current owner row does not match its exact head",
        }));
    }
    let read_receipt = source
        .as_ref()
        .map(|record| {
            eliot_store_api::CampaignOwnerReadReceipt::from_record(record, &query.state_fence)
                .map_err(AdapterError::Store)
        })
        .transpose()?;
    let read = CampaignSourceRevisionRead {
        status,
        source,
        current_head: Some(current_head),
        read_receipt,
        read_state_fence: query.state_fence.clone(),
    };
    read.validate().map_err(AdapterError::Store)?;
    Ok(read)
}

fn prepare_source_write(
    publication: CampaignSourcePublication,
) -> Result<OrientationOwnerSourceWrite, AdapterError> {
    let record_json = canonical_text(&publication.record)?;
    let publication_json = canonical_text(&publication)?;
    let next_head = publication.next_head();
    let next_head_json = canonical_text(&next_head)?;
    let (expected_head_json, current_reference) = match &publication.state {
        CampaignSourcePublicationState::NewRevision { expected_head } => (
            expected_head.as_ref().map(canonical_text).transpose()?,
            false,
        ),
        CampaignSourcePublicationState::CurrentReference { current_head } => {
            (Some(canonical_text(current_head)?), true)
        }
    };
    let source_key = source_key(
        &publication.record.role,
        publication.record.owner_id.as_str(),
        &publication.record.record_id,
    )?;
    let revision_key = revision_key(&publication.record)?;
    Ok(OrientationOwnerSourceWrite {
        source_key,
        revision_key,
        record_json,
        publication_json,
        next_head_json,
        expected_head_json,
        current_reference,
        record: publication.record,
    })
}

fn validate_publication_binding(
    publication: &CampaignSourcePublication,
    task_id: &str,
    transition: &PreparedTransition,
    task_revision: &eliot_contracts::TaskRevision,
) -> Result<(), AdapterError> {
    let record = &publication.record;
    if publication.read_receipt.read_state_fence != transition.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if matches!(
        &publication.state,
        CampaignSourcePublicationState::NewRevision { .. }
    ) && record.recorded_state_fence != transition.state_fence
    {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let body: CampaignOwnerProjectionBody = serde_json::from_value(record.document.body.clone())
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    if body.state_fence != record.recorded_state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    match record.role {
        CampaignSourceRole::OrientationAdmission | CampaignSourceRole::OrientationCueBindings => {
            let source_task = body
                .projection
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "orientation_owner_sources.task_id",
                    reason: "owner source must retain its original task identity",
                }))?;
            let source_scope = body
                .projection
                .get("scope_id")
                .and_then(Value::as_str)
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "orientation_owner_sources.scope_id",
                    reason: "owner source must retain its original WorkScope identity",
                }))?;
            let source_fence: StateFence = serde_json::from_value(
                body.projection
                    .get("state_fence")
                    .cloned()
                    .ok_or(AdapterError::Store(StoreError::InvalidField {
                        field: "orientation_owner_sources.state_fence",
                        reason: "owner source must retain its original full state fence",
                    }))?,
            )
            .map_err(|error| AdapterError::Serialization(error.to_string()))?;
            let row_task = match &record.record_id {
                CampaignOwnerRecordId::Task(task) => task.as_str(),
                _ => "",
            };
            let row_revision = match &record.revision {
                CampaignOwnerRevision::Task(revision) => revision,
                _ => return Err(AdapterError::Store(StoreError::FenceMismatch)),
            };
            if source_task != task_id
                || source_scope != transition.scope_id.as_str()
                || source_fence != record.recorded_state_fence
                || row_task != task_id
                || row_revision != task_revision
            {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
        }
        CampaignSourceRole::OrientationClassification => {
            let target = body
                .projection
                .get("target")
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "orientation_owner_sources.classification.target",
                    reason: "classification source must retain its original target binding",
                }))?;
            let target_id = target
                .get("target_id")
                .and_then(Value::as_str)
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "orientation_owner_sources.classification.target_id",
                    reason: "profile target id must be retained",
                }))?;
            let target_revision = target
                .get("target_revision")
                .and_then(Value::as_str)
                .ok_or(AdapterError::Store(StoreError::InvalidField {
                    field: "orientation_owner_sources.classification.target_revision",
                    reason: "profile target revision must be retained",
                }))?;
            if !matches!(
                (&record.record_id, &record.revision),
                (CampaignOwnerRecordId::Artifact(id), CampaignOwnerRevision::ResourceSnapshot(revision))
                    if id.as_str() == target_id && revision == target_revision
            ) {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
        }
        _ => {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "orientation_owner_sources.role",
                reason: "only the exact three Orientation owner roles are accepted",
            }));
        }
    }
    Ok(())
}

async fn ensure_orientation_source_table(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let mut response = client::query(
        db,
        config,
        "orientation_source.ensure_table",
        schema::ORIENTATION_OWNER_SOURCE_TABLES_DDL,
        Map::new(),
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

async fn read_current_head(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    source_key: &str,
) -> Result<Option<CampaignSourceHead>, AdapterError> {
    let Some(row) = read_row(
        db,
        config,
        &format!("head:{source_key}"),
        "orientation_source.read_head",
    )
    .await?
    else {
        return Ok(None);
    };
    if row.get("row_kind").and_then(Value::as_str) != Some("head") {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.head",
            reason: "stored source head row has an invalid discriminator",
        }));
    }
    let head_json = row
        .get("head_json")
        .and_then(Value::as_str)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.head_json",
            reason: "stored source head bytes are missing",
        }))?;
    let head: CampaignSourceHead = serde_json::from_str(head_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    head.validate().map_err(AdapterError::Store)?;
    if row.get("source_key").and_then(Value::as_str) != Some(source_key)
        || canonical_text(&head)? != head_json
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.head.identity",
            reason: "stored source head is not the exact canonical row under its source key",
        }));
    }
    Ok(Some(head))
}

async fn read_source_record(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    source_key: &str,
    lookup: &CampaignSourceRevisionLookup,
    revision: &CampaignOwnerRevision,
) -> Result<Option<CampaignSourceRecord>, AdapterError> {
    let revision_key = revision_key_for(source_key, revision)?;
    let Some(row) = read_row(
        db,
        config,
        &format!("revision:{revision_key}"),
        "orientation_source.read_record",
    )
    .await?
    else {
        return Ok(None);
    };
    if row.get("row_kind").and_then(Value::as_str) != Some("revision") {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.revision",
            reason: "stored source revision row has an invalid discriminator",
        }));
    }
    let record_json = row
        .get("record_json")
        .and_then(Value::as_str)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.record_json",
            reason: "stored source record bytes are missing",
        }))?;
    let record: CampaignSourceRecord = serde_json::from_str(record_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    record.validate().map_err(AdapterError::Store)?;
    let publication_json = row
        .get("publication_json")
        .and_then(Value::as_str)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.publication_json",
            reason: "stored source publication bytes are missing",
        }))?;
    let publication: CampaignSourcePublication = serde_json::from_str(publication_json)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    publication.validate().map_err(AdapterError::Store)?;
    if canonical_text(&record)? != record_json
        || canonical_text(&publication)? != publication_json
        || publication.record != record
        || row.get("content_digest").and_then(Value::as_str)
            != Some(record.content_digest.as_str())
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.revision.publication",
            reason: "stored source row does not preserve the exact canonical owner publication",
        }));
    }
    if row.get("source_key").and_then(Value::as_str) != Some(source_key)
        || row.get("revision_key").and_then(Value::as_str) != Some(revision_key.as_str())
        || record.role != lookup.role
        || record.owner_id != lookup.owner_id
        || record.record_id != lookup.record_id
        || &record.revision != revision
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.revision.identity",
            reason: "stored immutable row does not match the exact requested owner key and revision",
        }));
    }
    Ok(Some(record))
}

async fn read_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    key: &str,
    operation: &'static str,
) -> Result<Option<Value>, AdapterError> {
    let statement = "SELECT * FROM ONLY type::record($campaign_source_table, $campaign_source_key);";
    let mut bindings = Map::new();
    bindings.insert(
        "campaign_source_table".to_owned(),
        json!(schema::table::CAMPAIGN_SOURCE),
    );
    bindings.insert("campaign_source_key".to_owned(), json!(key));
    let mut response = client::query(db, config, operation, statement, bindings).await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        if errors.iter().all(|error| {
            error.contains("does not exist") && error.contains(schema::table::CAMPAIGN_SOURCE)
        }) {
            return Ok(None);
        }
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    Ok(row)
}

fn validate_head_for_lookup(
    head: &CampaignSourceHead,
    lookup: &CampaignSourceRevisionLookup,
) -> Result<(), AdapterError> {
    if head.role != lookup.role
        || head.owner_id != lookup.owner_id
        || head.record_id != lookup.record_id
    {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "campaign_source.head.identity",
            reason: "source head does not match the exact typed lookup",
        }));
    }
    Ok(())
}

fn record_matches_head(record: &CampaignSourceRecord, head: &CampaignSourceHead) -> bool {
    record.role == head.role
        && record.owner_id == head.owner_id
        && record.record_id == head.record_id
        && record.revision == head.revision
        && record.content_digest == head.content_digest
        && record.recorded_state_fence == head.recorded_state_fence
        && record.slot_projection_digests == head.slot_projection_digests
}

fn empty_read(
    status: CampaignSourceReadStatus,
    read_state_fence: StateFence,
) -> Result<CampaignSourceRevisionRead, AdapterError> {
    let read = CampaignSourceRevisionRead {
        status,
        source: None,
        current_head: None,
        read_receipt: None,
        read_state_fence,
    };
    read.validate().map_err(AdapterError::Store)?;
    Ok(read)
}

fn source_key(
    role: &CampaignSourceRole,
    owner_id: &str,
    record_id: &CampaignOwnerRecordId,
) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(&SourceIdentity {
        role: *role,
        owner_id,
        record_id,
    })
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| AdapterError::Serialization(error.to_string()))
}

fn revision_key(record: &CampaignSourceRecord) -> Result<String, AdapterError> {
    revision_key_for(
        &source_key(&record.role, record.owner_id.as_str(), &record.record_id)?,
        &record.revision,
    )
}

fn revision_key_for(
    source_key: &str,
    revision: &CampaignOwnerRevision,
) -> Result<String, AdapterError> {
    let bytes = canonical_json_bytes(&SourceRevisionIdentity {
        source_key,
        revision,
    })
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| AdapterError::Serialization(error.to_string()))
}

fn canonical_text<T: Serialize>(value: &T) -> Result<String, AdapterError> {
    String::from_utf8(canonical_json_bytes(value).map_err(|error| {
        AdapterError::Serialization(error.to_string())
    })?)
    .map_err(|error| AdapterError::Serialization(error.to_string()))
}

fn insert_binding(bindings: &mut Map<String, Value>, name: String, value: Value) {
    bindings.insert(name, value);
}
