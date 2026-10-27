-- Eliot Memory OS V3 / Slice 0 candidate
-- SurrealDB target: v3.3.4
-- DESIGN ONLY: exact bytes have not yet passed the production Windows/RocksDB runner.
-- The runner selects namespace/database, binds the three metadata variables below,
-- checks every statement result, and performs exact catalog readback.

BEGIN TRANSACTION;

DEFINE TABLE stream TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE TABLE observation TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE TABLE memory TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE TABLE memory_history TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE TABLE link TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;
DEFINE TABLE job TYPE NORMAL SCHEMAFULL PERMISSIONS NONE;

-- -----------------------------------------------------------------------------
-- stream
-- -----------------------------------------------------------------------------

DEFINE FIELD stream_id ON TABLE stream
  TYPE string
  READONLY
  ASSERT $value = /^s_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;

DEFINE FIELD project ON TABLE stream
  TYPE string
  READONLY
  PERMISSIONS NONE;

DEFINE FIELD source_kind ON TABLE stream
  TYPE string
  READONLY
  PERMISSIONS NONE;

DEFINE FIELD source_native_id ON TABLE stream
  TYPE string
  READONLY
  PERMISSIONS NONE;

DEFINE FIELD workspace_id ON TABLE stream
  TYPE option<string>
  READONLY
  PERMISSIONS NONE;

DEFINE FIELD stream_unique_key ON TABLE stream
  TYPE string
  READONLY
  ASSERT $value = /^[0-9a-f]{64}$/
  PERMISSIONS NONE;

DEFINE FIELD last_ingest_seq ON TABLE stream
  TYPE int
  ASSERT $value >= 0
  PERMISSIONS NONE;

DEFINE FIELD created_at_ms ON TABLE stream
  TYPE int
  READONLY
  ASSERT $value >= 0
  PERMISSIONS NONE;

DEFINE FIELD updated_at_ms ON TABLE stream
  TYPE int
  ASSERT $value >= 0
  PERMISSIONS NONE;

-- -----------------------------------------------------------------------------
-- observation
-- -----------------------------------------------------------------------------

DEFINE FIELD observation_id ON TABLE observation
  TYPE string
  READONLY
  ASSERT $value = /^o_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;

DEFINE FIELD project ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD stream_id ON TABLE observation TYPE string READONLY ASSERT $value = /^s_[0-7][0-9A-HJKMNP-TV-Z]{25}$/ PERMISSIONS NONE;
DEFINE FIELD event_key ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD command_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD native_event_key ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD ingest_seq ON TABLE observation TYPE int READONLY ASSERT $value > 0 PERMISSIONS NONE;
DEFINE FIELD occurrence_time_ms ON TABLE observation TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD occurrence_precision ON TABLE observation
  TYPE string
  READONLY
  ASSERT $value IN ["unknown", "date", "second", "millisecond", "native"]
  PERMISSIONS NONE;
DEFINE FIELD receipt_time_ms ON TABLE observation TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD kind ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD body_storage ON TABLE observation
  TYPE string
  READONLY
  ASSERT $value IN ["inline", "blob"]
  PERMISSIONS NONE;
DEFINE FIELD body_inline ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD blob_ref ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD body_length ON TABLE observation TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD body_sha256 ON TABLE observation TYPE string READONLY ASSERT $value = /^[0-9a-f]{64}$/ PERMISSIONS NONE;
DEFINE FIELD search_excerpt ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD disclosure ON TABLE observation
  TYPE string
  READONLY
  ASSERT $value IN ["local_only", "external_allowed"]
  PERMISSIONS NONE;
DEFINE FIELD workspace_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD task_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD actor_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD session_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD call_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD parent_observation_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD resource_id ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD resource_version ON TABLE observation TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD locator_json ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD binding_json ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD relations_json ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD capture_limit_json ON TABLE observation TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD created_at_ms ON TABLE observation TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;

-- Cross-field body XOR and byte/digest agreement remain fixed-writer invariants
-- until the exact row-local ASSERT expression passes Slice 0.

-- -----------------------------------------------------------------------------
-- memory
-- -----------------------------------------------------------------------------

DEFINE FIELD memory_id ON TABLE memory
  TYPE string
  READONLY
  ASSERT $value = /^m_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;
DEFINE FIELD origin_project ON TABLE memory TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD reuse_scope ON TABLE memory TYPE string ASSERT $value IN ["origin", "selected", "owner_local"] PERMISSIONS NONE;
DEFINE FIELD revision ON TABLE memory TYPE int ASSERT $value > 0 PERMISSIONS NONE;
DEFINE FIELD kind ON TABLE memory TYPE string PERMISSIONS NONE;
DEFINE FIELD address_kind ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD address_key ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD address_unique_key ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD content ON TABLE memory TYPE string PERMISSIONS NONE;
DEFINE FIELD search_text ON TABLE memory TYPE string PERMISSIONS NONE;
DEFINE FIELD exact_cues ON TABLE memory TYPE array<string> PERMISSIONS NONE;
DEFINE FIELD disclosure ON TABLE memory TYPE string ASSERT $value IN ["local_only", "external_allowed"] PERMISSIONS NONE;
DEFINE FIELD subject ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD aspect ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD perspective ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD conditions_json ON TABLE memory TYPE string PERMISSIONS NONE;
DEFINE FIELD exceptions_json ON TABLE memory TYPE string PERMISSIONS NONE;
DEFINE FIELD valid_from_ms ON TABLE memory TYPE option<int> PERMISSIONS NONE;
DEFINE FIELD valid_until_ms ON TABLE memory TYPE option<int> PERMISSIONS NONE;
DEFINE FIELD support_state ON TABLE memory TYPE string ASSERT $value IN ["unknown", "supported", "disputed", "refuted"] PERMISSIONS NONE;
DEFINE FIELD exposure_state ON TABLE memory TYPE string ASSERT $value IN ["normal", "reduced", "hidden"] PERMISSIONS NONE;
DEFINE FIELD influence_state ON TABLE memory TYPE string ASSERT $value IN ["active", "conditional", "withdrawn"] PERMISSIONS NONE;
DEFINE FIELD commitment_state ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD method_role ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD processing_purpose ON TABLE memory TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD created_at_ms ON TABLE memory TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD updated_at_ms ON TABLE memory TYPE int ASSERT $value >= 0 PERMISSIONS NONE;

-- Complete-address/digest agreement and validity ordering remain fixed-writer
-- invariants until exact row-local assertions pass Slice 0.

-- -----------------------------------------------------------------------------
-- memory_history: immutable exact previous semantic projection
-- -----------------------------------------------------------------------------

DEFINE FIELD history_id ON TABLE memory_history
  TYPE string
  READONLY
  ASSERT $value = /^h_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;
DEFINE FIELD memory_id ON TABLE memory_history TYPE string READONLY ASSERT $value = /^m_[0-7][0-9A-HJKMNP-TV-Z]{25}$/ PERMISSIONS NONE;
DEFINE FIELD revision ON TABLE memory_history TYPE int READONLY ASSERT $value > 0 PERMISSIONS NONE;
DEFINE FIELD origin_project ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD reuse_scope ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD kind ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD address_kind ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD address_key ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD address_unique_key ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD content ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD search_text ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD exact_cues ON TABLE memory_history TYPE array<string> READONLY PERMISSIONS NONE;
DEFINE FIELD disclosure ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD subject ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD aspect ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD perspective ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD conditions_json ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD exceptions_json ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD valid_from_ms ON TABLE memory_history TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD valid_until_ms ON TABLE memory_history TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD support_state ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD exposure_state ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD influence_state ON TABLE memory_history TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD commitment_state ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD method_role ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD processing_purpose ON TABLE memory_history TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD created_at_ms ON TABLE memory_history TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD updated_at_ms ON TABLE memory_history TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD replaced_at_ms ON TABLE memory_history TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;

-- -----------------------------------------------------------------------------
-- link
-- -----------------------------------------------------------------------------

DEFINE FIELD link_id ON TABLE link
  TYPE string
  READONLY
  ASSERT $value = /^l_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;
DEFINE FIELD source_kind ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD source_id ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD source_revision ON TABLE link TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD target_kind ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD target_id ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD target_revision ON TABLE link TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD relation_kind ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD grounds_group ON TABLE link TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD locator_json ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD qualification_json ON TABLE link TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD created_at_ms ON TABLE link TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;

-- -----------------------------------------------------------------------------
-- job
-- -----------------------------------------------------------------------------

DEFINE FIELD job_id ON TABLE job
  TYPE string
  READONLY
  ASSERT $value = /^j_[0-7][0-9A-HJKMNP-TV-Z]{25}$/
  PERMISSIONS NONE;
DEFINE FIELD project ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD purpose ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD target_key ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD state ON TABLE job
  TYPE string
  ASSERT $value IN ["pending", "claimed", "running", "waiting", "succeeded", "failed", "cancelled", "unknown", "reconcile_required"]
  PERMISSIONS NONE;
DEFINE FIELD slot_key ON TABLE job TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD origin ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD cause_id ON TABLE job TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD first_queued_at_ms ON TABLE job TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD due_at_ms ON TABLE job TYPE option<int> PERMISSIONS NONE;
DEFINE FIELD attempt ON TABLE job TYPE int ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD waiting_reason ON TABLE job TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD claim_owner ON TABLE job TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD claim_until_ms ON TABLE job TYPE option<int> PERMISSIONS NONE;
DEFINE FIELD frozen_input_json ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD method_id ON TABLE job TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD method_revision ON TABLE job TYPE option<int> READONLY PERMISSIONS NONE;
DEFINE FIELD limits_json ON TABLE job TYPE string READONLY PERMISSIONS NONE;
DEFINE FIELD disclosure ON TABLE job TYPE string READONLY ASSERT $value IN ["local_only", "external_allowed"] PERMISSIONS NONE;
DEFINE FIELD profile_name ON TABLE job TYPE option<string> READONLY PERMISSIONS NONE;
DEFINE FIELD request_blob_ref ON TABLE job TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD request_length ON TABLE job TYPE option<int> PERMISSIONS NONE;
DEFINE FIELD request_sha256 ON TABLE job TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD result_json ON TABLE job TYPE string PERMISSIONS NONE;
DEFINE FIELD coverage_json ON TABLE job TYPE string PERMISSIONS NONE;
DEFINE FIELD cleanup_json ON TABLE job TYPE string PERMISSIONS NONE;
DEFINE FIELD created_at_ms ON TABLE job TYPE int READONLY ASSERT $value >= 0 PERMISSIONS NONE;
DEFINE FIELD updated_at_ms ON TABLE job TYPE int ASSERT $value >= 0 PERMISSIONS NONE;

-- Claim/request/slot tuple agreement remains fixed-writer and Slice 0 negative-test
-- territory until an exact row-local expression is qualified.

-- -----------------------------------------------------------------------------
-- Exact and conditional unique indexes
-- -----------------------------------------------------------------------------

DEFINE INDEX stream_id_unique ON TABLE stream FIELDS stream_id UNIQUE;
DEFINE INDEX stream_identity_unique ON TABLE stream FIELDS stream_unique_key UNIQUE;

DEFINE INDEX observation_id_unique ON TABLE observation FIELDS observation_id UNIQUE;
DEFINE INDEX observation_event_unique ON TABLE observation FIELDS project, stream_id, event_key UNIQUE;
DEFINE INDEX observation_command_unique ON TABLE observation FIELDS project, command_id UNIQUE;

DEFINE INDEX memory_id_unique ON TABLE memory FIELDS memory_id UNIQUE;
DEFINE INDEX memory_address_unique ON TABLE memory FIELDS address_unique_key UNIQUE;

DEFINE INDEX memory_history_id_unique ON TABLE memory_history FIELDS history_id UNIQUE;
DEFINE INDEX memory_history_revision_unique ON TABLE memory_history FIELDS memory_id, revision UNIQUE;

DEFINE INDEX link_id_unique ON TABLE link FIELDS link_id UNIQUE;

DEFINE INDEX job_id_unique ON TABLE job FIELDS job_id UNIQUE;
DEFINE INDEX job_slot_unique ON TABLE job FIELDS slot_key UNIQUE;

-- -----------------------------------------------------------------------------
-- Reader-backed ordinary indexes
-- -----------------------------------------------------------------------------

DEFINE INDEX observation_stream_sequence ON TABLE observation FIELDS stream_id, ingest_seq, observation_id;
DEFINE INDEX observation_task_continuation ON TABLE observation FIELDS project, workspace_id, task_id, receipt_time_ms, observation_id;
DEFINE INDEX observation_session_continuation ON TABLE observation FIELDS project, workspace_id, actor_id, session_id, receipt_time_ms, observation_id;

DEFINE INDEX memory_project_kind ON TABLE memory FIELDS origin_project, kind, memory_id;

DEFINE INDEX link_forward ON TABLE link FIELDS source_kind, source_id, source_revision, relation_kind, link_id;
DEFINE INDEX link_reverse ON TABLE link FIELDS target_kind, target_id, target_revision, relation_kind, link_id;

DEFINE INDEX job_due ON TABLE job FIELDS state, due_at_ms, first_queued_at_ms, job_id;
DEFINE INDEX job_target ON TABLE job FIELDS project, purpose, target_key, state, job_id;

-- -----------------------------------------------------------------------------
-- Base full-text indexes
-- -----------------------------------------------------------------------------

DEFINE ANALYZER eliot_base_text TOKENIZERS blank,class FILTERS lowercase;
DEFINE INDEX observation_search_fulltext ON TABLE observation FIELDS search_excerpt FULLTEXT ANALYZER eliot_base_text BM25;
DEFINE INDEX memory_search_fulltext ON TABLE memory FIELDS search_text FULLTEXT ANALYZER eliot_base_text BM25;

-- -----------------------------------------------------------------------------
-- Runner-bound schema identity. Exact bound-variable execution remains a Slice 0
-- qualification item; these statements are intentionally inside the same candidate
-- transaction as the owned catalog.
-- -----------------------------------------------------------------------------

DEFINE PARAM OVERWRITE $eliot_schema_bundle_format VALUE $bound_schema_bundle_format;
DEFINE PARAM OVERWRITE $eliot_schema_generation VALUE $bound_schema_generation;
DEFINE PARAM OVERWRITE $eliot_schema_bundle_sha256 VALUE $bound_schema_bundle_sha256;

COMMIT TRANSACTION;
