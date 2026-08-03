DEFINE TABLE IF NOT EXISTS memory_search_projection SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_search_state SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_search_outbox SCHEMALESS;
DEFINE TABLE IF NOT EXISTS cognitive_projection_state SCHEMALESS;
DEFINE TABLE IF NOT EXISTS cognitive_projection_cutover SCHEMALESS;

DEFINE INDEX OVERWRITE idx_memory_search_projection_handle
  ON TABLE memory_search_projection FIELDS project_id, handle;
DEFINE INDEX OVERWRITE idx_memory_search_projection_parent_segment
  ON TABLE memory_search_projection
  FIELDS project_id, parent_handle, source_segment_ordinal, fts_segment_ordinal;
DEFINE INDEX OVERWRITE idx_memory_search_projection_lifecycle_kind_revision
  ON TABLE memory_search_projection FIELDS project_id, lifecycle, record_kind, updated_revision;
DEFINE INDEX OVERWRITE idx_memory_search_outbox_write
  ON TABLE memory_search_outbox FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_memory_search_outbox_project_status_revision
  ON TABLE memory_search_outbox FIELDS project_id, status, updated_revision;
DEFINE INDEX IF NOT EXISTS idx_cognitive_projection_outbox_claim_v1
  ON TABLE memory_search_outbox FIELDS status, next_attempt_at, created_at;
DEFINE INDEX IF NOT EXISTS idx_cognitive_projection_state_project_family_v1
  ON TABLE cognitive_projection_state FIELDS project_id, family UNIQUE;

RETURN {
  projection_table: 'memory_search_projection',
  state_table: 'memory_search_state',
  outbox_table: 'memory_search_outbox',
  family_state_table: 'cognitive_projection_state',
};
