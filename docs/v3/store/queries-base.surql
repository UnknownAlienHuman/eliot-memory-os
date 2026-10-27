-- Eliot Memory OS V3 / Slice 0 fixed-query review corpus
-- SurrealDB target: v3.3.4
-- DESIGN ONLY: the production client embeds selected named blocks separately.
-- This whole file is never exposed as one executable query surface.

-- =============================================================================
-- QUERY: store_probe_create_read_delete
-- Purpose: prove the production Editor path can write, read and delete through the
-- same fixed-query transport used by Base. The caller supplies one precommitted
-- probe stream ID and derived unique key.
-- =============================================================================

BEGIN TRANSACTION;
CREATE stream CONTENT {
  stream_id: $probe_stream_id,
  project: $probe_project,
  source_kind: "eliot_store_probe",
  source_native_id: $probe_native_id,
  workspace_id: NONE,
  stream_unique_key: $probe_stream_unique_key,
  last_ingest_seq: 0,
  created_at_ms: $now_ms,
  updated_at_ms: $now_ms
};
SELECT stream_id, project, source_kind, source_native_id, stream_unique_key, last_ingest_seq
FROM stream
WHERE stream_id = $probe_stream_id
LIMIT 1;
DELETE stream WHERE stream_id = $probe_stream_id;
COMMIT TRANSACTION;

-- =============================================================================
-- QUERY: stream_by_identity_for_update
-- Purpose: exact stream resolution and sequence-owner lock.
-- =============================================================================

SELECT stream_id,
       project,
       source_kind,
       source_native_id,
       workspace_id,
       stream_unique_key,
       last_ingest_seq,
       created_at_ms,
       updated_at_ms
FROM stream
WHERE stream_unique_key = $stream_unique_key
LIMIT 1
FOR UPDATE;

-- =============================================================================
-- QUERY: capture_existing_by_command
-- Purpose: lost-reply/replay identity readback. command_id is required by this
-- operation; an event without a native command ID uses the relay command ID.
-- =============================================================================

SELECT observation_id,
       project,
       stream_id,
       event_key,
       command_id,
       body_storage,
       body_length,
       body_sha256,
       workspace_id,
       task_id,
       actor_id,
       session_id,
       resource_id,
       resource_version
FROM observation
WHERE project = $project
  AND command_id = $command_id
LIMIT 1;

-- =============================================================================
-- QUERY: capture_existing_by_event
-- Purpose: native event-key collision/readback inside the owning stream.
-- =============================================================================

SELECT observation_id,
       project,
       stream_id,
       event_key,
       command_id,
       body_storage,
       body_length,
       body_sha256,
       workspace_id,
       task_id,
       actor_id,
       session_id,
       resource_id,
       resource_version
FROM observation
WHERE project = $project
  AND stream_id = $stream_id
  AND event_key = $event_key
LIMIT 1;

-- =============================================================================
-- QUERY: observation_by_id
-- Purpose: exact source/open read. Large body bytes remain in immutable blobs.
-- =============================================================================

SELECT observation_id,
       project,
       stream_id,
       event_key,
       command_id,
       native_event_key,
       ingest_seq,
       occurrence_time_ms,
       occurrence_precision,
       receipt_time_ms,
       kind,
       body_storage,
       body_inline,
       blob_ref,
       body_length,
       body_sha256,
       search_excerpt,
       disclosure,
       workspace_id,
       task_id,
       actor_id,
       session_id,
       call_id,
       parent_observation_id,
       resource_id,
       resource_version,
       locator_json,
       binding_json,
       relations_json,
       capture_limit_json,
       created_at_ms
FROM observation
WHERE observation_id = $observation_id
LIMIT 1;

-- =============================================================================
-- QUERY: continuation_by_task
-- Stable cursor: (receipt_time_ms, observation_id). The cursor is valid only for
-- the same query version, project, workspace and task.
-- =============================================================================

SELECT observation_id,
       stream_id,
       ingest_seq,
       receipt_time_ms,
       kind,
       search_excerpt,
       body_storage,
       body_length,
       body_sha256,
       disclosure,
       call_id,
       parent_observation_id,
       resource_id,
       resource_version,
       locator_json,
       capture_limit_json
FROM observation
WHERE project = $project
  AND workspace_id = $workspace_id
  AND task_id = $task_id
  AND (
    receipt_time_ms > $after_receipt_time_ms
    OR (receipt_time_ms = $after_receipt_time_ms AND observation_id > $after_observation_id)
  )
ORDER BY receipt_time_ms ASC, observation_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: continuation_by_actor_session
-- Stable cursor: (receipt_time_ms, observation_id).
-- =============================================================================

SELECT observation_id,
       stream_id,
       ingest_seq,
       receipt_time_ms,
       kind,
       search_excerpt,
       body_storage,
       body_length,
       body_sha256,
       disclosure,
       task_id,
       call_id,
       parent_observation_id,
       resource_id,
       resource_version,
       locator_json,
       capture_limit_json
FROM observation
WHERE project = $project
  AND workspace_id = $workspace_id
  AND actor_id = $actor_id
  AND session_id = $session_id
  AND (
    receipt_time_ms > $after_receipt_time_ms
    OR (receipt_time_ms = $after_receipt_time_ms AND observation_id > $after_observation_id)
  )
ORDER BY receipt_time_ms ASC, observation_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: memory_current_by_id
-- =============================================================================

SELECT memory_id,
       origin_project,
       reuse_scope,
       revision,
       kind,
       address_kind,
       address_key,
       address_unique_key,
       content,
       search_text,
       exact_cues,
       disclosure,
       subject,
       aspect,
       perspective,
       conditions_json,
       exceptions_json,
       valid_from_ms,
       valid_until_ms,
       support_state,
       exposure_state,
       influence_state,
       commitment_state,
       method_role,
       processing_purpose,
       created_at_ms,
       updated_at_ms
FROM memory
WHERE memory_id = $memory_id
LIMIT 1;

-- =============================================================================
-- QUERY: memory_current_by_address
-- =============================================================================

SELECT memory_id,
       origin_project,
       reuse_scope,
       revision,
       kind,
       address_kind,
       address_key,
       content,
       search_text,
       exact_cues,
       disclosure,
       conditions_json,
       exceptions_json,
       support_state,
       exposure_state,
       influence_state,
       updated_at_ms
FROM memory
WHERE address_unique_key = $address_unique_key
LIMIT 1;

-- =============================================================================
-- QUERY: memory_history_exact
-- Exact historical revision; no fall-forward.
-- =============================================================================

SELECT history_id,
       memory_id,
       revision,
       origin_project,
       reuse_scope,
       kind,
       address_kind,
       address_key,
       address_unique_key,
       content,
       search_text,
       exact_cues,
       disclosure,
       subject,
       aspect,
       perspective,
       conditions_json,
       exceptions_json,
       valid_from_ms,
       valid_until_ms,
       support_state,
       exposure_state,
       influence_state,
       commitment_state,
       method_role,
       processing_purpose,
       created_at_ms,
       updated_at_ms,
       replaced_at_ms
FROM memory_history
WHERE memory_id = $memory_id
  AND revision = $revision
LIMIT 1;

-- =============================================================================
-- QUERY: relation_page_forward
-- Stable cursor: link_id within the exact source/revision/relation scope.
-- =============================================================================

SELECT link_id,
       source_kind,
       source_id,
       source_revision,
       target_kind,
       target_id,
       target_revision,
       relation_kind,
       grounds_group,
       locator_json,
       qualification_json,
       created_at_ms
FROM link
WHERE source_kind = $source_kind
  AND source_id = $source_id
  AND source_revision = $source_revision
  AND relation_kind = $relation_kind
  AND link_id > $after_link_id
ORDER BY link_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: relation_page_reverse
-- =============================================================================

SELECT link_id,
       source_kind,
       source_id,
       source_revision,
       target_kind,
       target_id,
       target_revision,
       relation_kind,
       grounds_group,
       locator_json,
       qualification_json,
       created_at_ms
FROM link
WHERE target_kind = $target_kind
  AND target_id = $target_id
  AND target_revision = $target_revision
  AND relation_kind = $relation_kind
  AND link_id > $after_link_id
ORDER BY link_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: lexical_observation_top_k
-- One statement snapshot. score=0 is still a match. No cross-call page cursor.
-- =============================================================================

SELECT observation_id,
       project,
       stream_id,
       receipt_time_ms,
       kind,
       search_excerpt,
       disclosure,
       locator_json,
       search::score(0) AS score
FROM observation
WHERE project = $project
  AND search_excerpt @0@ $query
ORDER BY score DESC, observation_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: lexical_memory_top_k
-- =============================================================================

SELECT memory_id,
       origin_project,
       reuse_scope,
       revision,
       kind,
       content,
       disclosure,
       conditions_json,
       exceptions_json,
       support_state,
       exposure_state,
       influence_state,
       search::score(0) AS score
FROM memory
WHERE origin_project = $origin_project
  AND search_text @0@ $query
ORDER BY score DESC, memory_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY: due_job_candidate_for_update
-- Fixed claim transaction must recheck state/slot/claim tuple before mutation.
-- =============================================================================

SELECT job_id,
       project,
       purpose,
       target_key,
       state,
       slot_key,
       first_queued_at_ms,
       due_at_ms,
       attempt,
       waiting_reason,
       claim_owner,
       claim_until_ms,
       frozen_input_json,
       method_id,
       method_revision,
       limits_json,
       disclosure,
       profile_name,
       request_blob_ref,
       request_length,
       request_sha256
FROM job
WHERE state = "pending"
  AND (due_at_ms = NONE OR due_at_ms <= $now_ms)
ORDER BY due_at_ms ASC, first_queued_at_ms ASC, job_id ASC
LIMIT 1
FOR UPDATE;

-- =============================================================================
-- QUERY: jobs_by_target
-- =============================================================================

SELECT job_id,
       project,
       purpose,
       target_key,
       state,
       slot_key,
       first_queued_at_ms,
       due_at_ms,
       attempt,
       waiting_reason,
       updated_at_ms
FROM job
WHERE project = $project
  AND purpose = $purpose
  AND target_key = $target_key
  AND job_id > $after_job_id
ORDER BY job_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY FAMILY: backup pages
-- The runtime embeds one statement per table with the same stable-ID pattern.
-- =============================================================================

SELECT stream_id, project, source_kind, source_native_id, workspace_id,
       stream_unique_key, last_ingest_seq, created_at_ms, updated_at_ms
FROM stream
WHERE stream_id > $after_id
ORDER BY stream_id ASC
LIMIT $hard_limit;

SELECT observation_id, project, stream_id, event_key, command_id,
       native_event_key, ingest_seq, occurrence_time_ms, occurrence_precision,
       receipt_time_ms, kind, body_storage, body_inline, blob_ref, body_length,
       body_sha256, search_excerpt, disclosure, workspace_id, task_id, actor_id,
       session_id, call_id, parent_observation_id, resource_id, resource_version,
       locator_json, binding_json, relations_json, capture_limit_json, created_at_ms
FROM observation
WHERE observation_id > $after_id
ORDER BY observation_id ASC
LIMIT $hard_limit;

SELECT memory_id, origin_project, reuse_scope, revision, kind, address_kind,
       address_key, address_unique_key, content, search_text, exact_cues,
       disclosure, subject, aspect, perspective, conditions_json,
       exceptions_json, valid_from_ms, valid_until_ms, support_state,
       exposure_state, influence_state, commitment_state, method_role,
       processing_purpose, created_at_ms, updated_at_ms
FROM memory
WHERE memory_id > $after_id
ORDER BY memory_id ASC
LIMIT $hard_limit;

SELECT history_id, memory_id, revision, origin_project, reuse_scope, kind,
       address_kind, address_key, address_unique_key, content, search_text,
       exact_cues, disclosure, subject, aspect, perspective, conditions_json,
       exceptions_json, valid_from_ms, valid_until_ms, support_state,
       exposure_state, influence_state, commitment_state, method_role,
       processing_purpose, created_at_ms, updated_at_ms, replaced_at_ms
FROM memory_history
WHERE history_id > $after_id
ORDER BY history_id ASC
LIMIT $hard_limit;

SELECT link_id, source_kind, source_id, source_revision, target_kind, target_id,
       target_revision, relation_kind, grounds_group, locator_json,
       qualification_json, created_at_ms
FROM link
WHERE link_id > $after_id
ORDER BY link_id ASC
LIMIT $hard_limit;

SELECT job_id, project, purpose, target_key, state, slot_key, origin, cause_id,
       first_queued_at_ms, due_at_ms, attempt, waiting_reason, claim_owner,
       claim_until_ms, frozen_input_json, method_id, method_revision,
       limits_json, disclosure, profile_name, request_blob_ref, request_length,
       request_sha256, result_json, coverage_json, cleanup_json,
       created_at_ms, updated_at_ms
FROM job
WHERE job_id > $after_id
ORDER BY job_id ASC
LIMIT $hard_limit;

-- =============================================================================
-- QUERY FAMILY: schema admission
-- The client decodes maps, selects owned names, sorts keys and compares exact
-- pinned-version canonical DEFINE strings. STRUCTURE is intentionally absent.
-- =============================================================================

INFO FOR DB;
INFO FOR TABLE stream;
INFO FOR TABLE observation;
INFO FOR TABLE memory;
INFO FOR TABLE memory_history;
INFO FOR TABLE link;
INFO FOR TABLE job;

-- =============================================================================
-- MUTATION SCRIPTS NOT YET CLAIMED QUALIFIED
-- =============================================================================
-- Capture insert/replay branching, stream sequence allocation, memory revision
-- publication, job claim/settle and row-local cross-field guards require one exact
-- transaction/control-flow script each. Implementation defines their ownership and
-- invariants, but this design pack intentionally does not guess unrun IF/THROW or
-- cross-field ASSERT forms. Slice 0 must add and execute those exact assets before
-- R-006/R-150/R-160 can advance beyond design-only status.
