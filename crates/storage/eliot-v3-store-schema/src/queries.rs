use crate::{QueryBounds, QueryClass, QueryId, QuerySpec};

const QUERY_STORE_PROBE: &str = r#"RETURN { probe: "eliot-v3-store", ok: true };
"#;

const QUERY_STREAM_LOOKUP: &str = r"SELECT stream_id, project, source_kind, source_native_id, workspace_id, last_ingest_seq, created_at_ms, updated_at_ms
FROM stream
WHERE stream_unique_key = $stream_unique_key
LIMIT 1;
";

const QUERY_STREAM_INSERT: &str = r"CREATE ONLY stream CONTENT {
  stream_id: $stream_id,
  project: $project,
  source_kind: $source_kind,
  source_native_id: $source_native_id,
  workspace_id: $workspace_id,
  stream_unique_key: $stream_unique_key,
  last_ingest_seq: 0,
  created_at_ms: $now_ms,
  updated_at_ms: $now_ms
}
RETURN stream_id, project, source_kind, source_native_id, workspace_id, last_ingest_seq, created_at_ms, updated_at_ms;
";

const QUERY_STREAM_LOCK: &str = r"SELECT stream_id, last_ingest_seq
FROM stream
WHERE stream_id = $stream_id
LIMIT 1
FOR UPDATE;
";

const QUERY_STREAM_ADVANCE: &str = r"UPDATE ONLY stream
SET last_ingest_seq = $next_ingest_seq, updated_at_ms = $now_ms
WHERE stream_id = $stream_id AND last_ingest_seq = $expected_ingest_seq
RETURN stream_id, last_ingest_seq, updated_at_ms;
";

const QUERY_CAPTURE_IDENTITY: &str = r"SELECT observation_id, project, stream_id, event_key, command_id, body_length, body_sha256, binding_json
FROM observation
WHERE project = $project
  AND ((command_id != NONE AND command_id = $command_id) OR (stream_id = $stream_id AND event_key = $event_key))
ORDER BY observation_id ASC
LIMIT 2;
";

const QUERY_OBSERVATION_INSERT: &str = r"CREATE ONLY observation CONTENT {
  observation_id: $observation_id,
  project: $project,
  stream_id: $stream_id,
  event_key: $event_key,
  command_id: $command_id,
  native_event_key: $native_event_key,
  ingest_seq: $ingest_seq,
  occurrence_time_ms: $occurrence_time_ms,
  occurrence_precision: $occurrence_precision,
  receipt_time_ms: $receipt_time_ms,
  kind: $kind,
  body_storage: $body_storage,
  body_inline: $body_inline,
  blob_ref: $blob_ref,
  body_length: $body_length,
  body_sha256: $body_sha256,
  search_excerpt: $search_excerpt,
  disclosure: $disclosure,
  workspace_id: $workspace_id,
  task_id: $task_id,
  actor_id: $actor_id,
  session_id: $session_id,
  call_id: $call_id,
  parent_observation_id: $parent_observation_id,
  resource_id: $resource_id,
  resource_version: $resource_version,
  locator_json: $locator_json,
  binding_json: $binding_json,
  relations_json: $relations_json,
  capture_limit_json: $capture_limit_json,
  created_at_ms: $created_at_ms
}
RETURN observation_id, project, stream_id, event_key, command_id, ingest_seq, body_length, body_sha256, binding_json;
";

const QUERY_CONTINUATION_TASK: &str = r"SELECT observation_id, stream_id, ingest_seq, receipt_time_ms, kind, search_excerpt, resource_id, resource_version
FROM observation
WHERE project = $project
  AND workspace_id = $workspace_id
  AND task_id = $task_id
  AND (receipt_time_ms > $after_receipt_time_ms OR (receipt_time_ms = $after_receipt_time_ms AND observation_id > $after_observation_id))
ORDER BY receipt_time_ms ASC, observation_id ASC
LIMIT $hard_limit;
";

const QUERY_CONTINUATION_SESSION: &str = r"SELECT observation_id, stream_id, ingest_seq, receipt_time_ms, kind, search_excerpt, resource_id, resource_version
FROM observation
WHERE project = $project
  AND workspace_id = $workspace_id
  AND actor_id = $actor_id
  AND session_id = $session_id
  AND (receipt_time_ms > $after_receipt_time_ms OR (receipt_time_ms = $after_receipt_time_ms AND observation_id > $after_observation_id))
ORDER BY receipt_time_ms ASC, observation_id ASC
LIMIT $hard_limit;
";

const QUERY_OPEN_MEMORY_CURRENT: &str = r"SELECT memory_id, origin_project, reuse_scope, revision, kind, content, disclosure, conditions_json, exceptions_json, valid_from_ms, valid_until_ms, support_state, exposure_state, influence_state, created_at_ms, updated_at_ms
FROM memory
WHERE memory_id = $memory_id
LIMIT 1;
";

const QUERY_OPEN_MEMORY_HISTORY: &str = r"SELECT history_id, memory_id, revision, snapshot_json, replaced_at_ms
FROM memory_history
WHERE memory_id = $memory_id AND revision = $revision
LIMIT 1;
";

const QUERY_OPEN_OBSERVATION: &str = r"SELECT observation_id, project, stream_id, event_key, command_id, ingest_seq, occurrence_time_ms, occurrence_precision, receipt_time_ms, kind, body_storage, body_inline, blob_ref, body_length, body_sha256, disclosure, locator_json, capture_limit_json
FROM observation
WHERE observation_id = $observation_id
LIMIT 1;
";

const QUERY_LINKS_FORWARD: &str = r"SELECT link_id, source_kind, source_id, source_revision, target_kind, target_id, target_revision, relation_kind, grounds_group, locator_json, qualification_json, created_at_ms
FROM link
WHERE source_kind = $source_kind
  AND source_id = $source_id
  AND source_revision = $source_revision
  AND (relation_kind > $after_relation_kind OR (relation_kind = $after_relation_kind AND link_id > $after_link_id))
ORDER BY relation_kind ASC, link_id ASC
LIMIT $hard_limit;
";

const QUERY_LINKS_REVERSE: &str = r"SELECT link_id, source_kind, source_id, source_revision, target_kind, target_id, target_revision, relation_kind, grounds_group, locator_json, qualification_json, created_at_ms
FROM link
WHERE target_kind = $target_kind
  AND target_id = $target_id
  AND target_revision = $target_revision
  AND (relation_kind > $after_relation_kind OR (relation_kind = $after_relation_kind AND link_id > $after_link_id))
ORDER BY relation_kind ASC, link_id ASC
LIMIT $hard_limit;
";

const QUERY_LEXICAL_OBSERVATION: &str = r"SELECT observation_id, search::score(0) AS score, search_excerpt
FROM observation
WHERE project = $project
  AND search_excerpt @0@ $query
ORDER BY score DESC, observation_id ASC
LIMIT $hard_limit;
";

const QUERY_LEXICAL_MEMORY: &str = r"SELECT memory_id, revision, kind, search::score(0) AS score, search_text
FROM memory
WHERE origin_project = $project
  AND search_text @0@ $query
ORDER BY score DESC, memory_id ASC
LIMIT $hard_limit;
";

const QUERY_DUE_JOBS: &str = r#"SELECT job_id, project, purpose, target_key, state, due_at_ms, first_queued_at_ms, attempt, disclosure, profile_name
FROM job
WHERE state = "pending"
  AND (due_at_ms = NONE OR due_at_ms <= $now_ms)
ORDER BY due_at_ms ASC, first_queued_at_ms ASC, job_id ASC
LIMIT $hard_limit;
"#;

const QUERY_CLAIM_JOB: &str = r#"UPDATE ONLY job
SET state = "claimed",
    slot_key = $active_slot_key,
    claim_owner = $claim_owner,
    claim_until_ms = $claim_until_ms,
    attempt = attempt + 1,
    updated_at_ms = $now_ms
WHERE job_id = $job_id AND state = "pending" AND slot_key = $pending_slot_key
RETURN job_id, project, purpose, target_key, state, slot_key, attempt, claim_owner, claim_until_ms, frozen_input_json, method_id, method_revision, limits_json, disclosure, profile_name;
"#;

const QUERY_BACKUP_STREAM: &str = r"SELECT stream_id, project, source_kind, source_native_id, workspace_id, stream_unique_key, last_ingest_seq, created_at_ms, updated_at_ms
FROM stream
WHERE stream_id > $after_id
ORDER BY stream_id ASC
LIMIT $hard_limit;
";

const QUERY_BACKUP_OBSERVATION: &str = r"SELECT observation_id, project, stream_id, event_key, command_id, native_event_key, ingest_seq, occurrence_time_ms, occurrence_precision, receipt_time_ms, kind, body_storage, body_inline, blob_ref, body_length, body_sha256, search_excerpt, disclosure, workspace_id, task_id, actor_id, session_id, call_id, parent_observation_id, resource_id, resource_version, locator_json, binding_json, relations_json, capture_limit_json, created_at_ms
FROM observation
WHERE observation_id > $after_id
ORDER BY observation_id ASC
LIMIT $hard_limit;
";

const QUERY_BACKUP_MEMORY: &str = r"SELECT memory_id, origin_project, reuse_scope, revision, kind, address_kind, address_key, address_unique_key, content, search_text, exact_cues, disclosure, subject, aspect, perspective, conditions_json, exceptions_json, valid_from_ms, valid_until_ms, support_state, exposure_state, influence_state, commitment_state, method_role, processing_purpose, created_at_ms, updated_at_ms
FROM memory
WHERE memory_id > $after_id
ORDER BY memory_id ASC
LIMIT $hard_limit;
";

const QUERY_BACKUP_MEMORY_HISTORY: &str = r"SELECT history_id, memory_id, revision, snapshot_json, replaced_at_ms
FROM memory_history
WHERE history_id > $after_id
ORDER BY history_id ASC
LIMIT $hard_limit;
";

const QUERY_BACKUP_LINK: &str = r"SELECT link_id, source_kind, source_id, source_revision, target_kind, target_id, target_revision, relation_kind, grounds_group, locator_json, qualification_json, created_at_ms
FROM link
WHERE link_id > $after_id
ORDER BY link_id ASC
LIMIT $hard_limit;
";

const QUERY_BACKUP_JOB: &str = r"SELECT job_id, project, purpose, target_key, state, slot_key, origin, cause_id, first_queued_at_ms, due_at_ms, attempt, waiting_reason, claim_owner, claim_until_ms, frozen_input_json, method_id, method_revision, limits_json, disclosure, profile_name, request_blob_ref, request_length, request_sha256, result_json, coverage_json, cleanup_json, created_at_ms, updated_at_ms
FROM job
WHERE job_id > $after_id
ORDER BY job_id ASC
LIMIT $hard_limit;
";

const QUERY_INFO_DATABASE: &str = r"INFO FOR DB;
";
const QUERY_INFO_STREAM: &str = r"INFO FOR TABLE stream;
";
const QUERY_INFO_OBSERVATION: &str = r"INFO FOR TABLE observation;
";
const QUERY_INFO_MEMORY: &str = r"INFO FOR TABLE memory;
";
const QUERY_INFO_MEMORY_HISTORY: &str = r"INFO FOR TABLE memory_history;
";
const QUERY_INFO_LINK: &str = r"INFO FOR TABLE link;
";
const QUERY_INFO_JOB: &str = r"INFO FOR TABLE job;
";

macro_rules! query {
    ($id:ident, $name:literal, $class:ident, $sql:ident, $bounds:expr) => {
        QuerySpec {
            id: QueryId::$id,
            name: $name,
            class: QueryClass::$class,
            sql: $sql,
            bounds: $bounds,
        }
    };
}

pub const QUERIES: &[QuerySpec] = &[
    query!(StoreProbe, "store_probe", Read, QUERY_STORE_PROBE, SMALL_READ),
    query!(StreamLookup, "stream_lookup", Read, QUERY_STREAM_LOOKUP, SMALL_READ),
    query!(StreamInsert, "stream_insert", Mutation, QUERY_STREAM_INSERT, SMALL_READ),
    query!(StreamLock, "stream_lock", Mutation, QUERY_STREAM_LOCK, SMALL_READ),
    query!(StreamAdvance, "stream_advance", Mutation, QUERY_STREAM_ADVANCE, SMALL_READ),
    query!(CaptureIdentity, "capture_identity", Read, QUERY_CAPTURE_IDENTITY, SMALL_READ),
    query!(ObservationInsert, "observation_insert", Mutation, QUERY_OBSERVATION_INSERT, SMALL_READ),
    query!(ContinuationTask, "continuation_task", Read, QUERY_CONTINUATION_TASK, PAGE_READ),
    query!(ContinuationSession, "continuation_session", Read, QUERY_CONTINUATION_SESSION, PAGE_READ),
    query!(OpenMemoryCurrent, "open_memory_current", Read, QUERY_OPEN_MEMORY_CURRENT, SMALL_READ),
    query!(OpenMemoryHistory, "open_memory_history", Read, QUERY_OPEN_MEMORY_HISTORY, SMALL_READ),
    query!(OpenObservation, "open_observation", Read, QUERY_OPEN_OBSERVATION, SMALL_READ),
    query!(LinksForward, "links_forward", Read, QUERY_LINKS_FORWARD, PAGE_READ),
    query!(LinksReverse, "links_reverse", Read, QUERY_LINKS_REVERSE, PAGE_READ),
    query!(LexicalObservation, "lexical_observation", Read, QUERY_LEXICAL_OBSERVATION, PAGE_READ),
    query!(LexicalMemory, "lexical_memory", Read, QUERY_LEXICAL_MEMORY, PAGE_READ),
    query!(DueJobs, "due_jobs", Read, QUERY_DUE_JOBS, PAGE_READ),
    query!(ClaimJob, "claim_job", Mutation, QUERY_CLAIM_JOB, SMALL_READ),
    query!(BackupStream, "backup_stream", Read, QUERY_BACKUP_STREAM, BACKUP_PAGE),
    query!(BackupObservation, "backup_observation", Read, QUERY_BACKUP_OBSERVATION, BACKUP_PAGE),
    query!(BackupMemory, "backup_memory", Read, QUERY_BACKUP_MEMORY, BACKUP_PAGE),
    query!(BackupMemoryHistory, "backup_memory_history", Read, QUERY_BACKUP_MEMORY_HISTORY, BACKUP_PAGE),
    query!(BackupLink, "backup_link", Read, QUERY_BACKUP_LINK, BACKUP_PAGE),
    query!(BackupJob, "backup_job", Read, QUERY_BACKUP_JOB, BACKUP_PAGE),
    query!(InfoDatabase, "info_database", SchemaRead, QUERY_INFO_DATABASE, SCHEMA_READ),
    query!(InfoStream, "info_stream", SchemaRead, QUERY_INFO_STREAM, SCHEMA_READ),
    query!(InfoObservation, "info_observation", SchemaRead, QUERY_INFO_OBSERVATION, SCHEMA_READ),
    query!(InfoMemory, "info_memory", SchemaRead, QUERY_INFO_MEMORY, SCHEMA_READ),
    query!(InfoMemoryHistory, "info_memory_history", SchemaRead, QUERY_INFO_MEMORY_HISTORY, SCHEMA_READ),
    query!(InfoLink, "info_link", SchemaRead, QUERY_INFO_LINK, SCHEMA_READ),
    query!(InfoJob, "info_job", SchemaRead, QUERY_INFO_JOB, SCHEMA_READ),
];

pub fn query(id: QueryId) -> &'static QuerySpec {
    match id {
        QueryId::StoreProbe => &QUERIES[0],
        QueryId::StreamLookup => &QUERIES[1],
        QueryId::StreamInsert => &QUERIES[2],
        QueryId::StreamLock => &QUERIES[3],
        QueryId::StreamAdvance => &QUERIES[4],
        QueryId::CaptureIdentity => &QUERIES[5],
        QueryId::ObservationInsert => &QUERIES[6],
        QueryId::ContinuationTask => &QUERIES[7],
        QueryId::ContinuationSession => &QUERIES[8],
        QueryId::OpenMemoryCurrent => &QUERIES[9],
        QueryId::OpenMemoryHistory => &QUERIES[10],
        QueryId::OpenObservation => &QUERIES[11],
        QueryId::LinksForward => &QUERIES[12],
        QueryId::LinksReverse => &QUERIES[13],
        QueryId::LexicalObservation => &QUERIES[14],
        QueryId::LexicalMemory => &QUERIES[15],
        QueryId::DueJobs => &QUERIES[16],
        QueryId::ClaimJob => &QUERIES[17],
        QueryId::BackupStream => &QUERIES[18],
        QueryId::BackupObservation => &QUERIES[19],
        QueryId::BackupMemory => &QUERIES[20],
        QueryId::BackupMemoryHistory => &QUERIES[21],
        QueryId::BackupLink => &QUERIES[22],
        QueryId::BackupJob => &QUERIES[23],
        QueryId::InfoDatabase => &QUERIES[24],
        QueryId::InfoStream => &QUERIES[25],
        QueryId::InfoObservation => &QUERIES[26],
        QueryId::InfoMemory => &QUERIES[27],
        QueryId::InfoMemoryHistory => &QUERIES[28],
        QueryId::InfoLink => &QUERIES[29],
        QueryId::InfoJob => &QUERIES[30],
    }
}

pub fn query_by_name(name: &str) -> Option<&'static QuerySpec> {
    QUERIES.iter().find(|specification| specification.name == name)
}
