DEFINE TABLE IF NOT EXISTS memory_search_projection SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_search_token SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_search_state SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_search_outbox SCHEMALESS;

DEFINE INDEX OVERWRITE idx_memory_search_projection_handle
  ON TABLE memory_search_projection FIELDS project_id, handle UNIQUE;
DEFINE INDEX OVERWRITE idx_memory_search_projection_lifecycle_kind_revision
  ON TABLE memory_search_projection FIELDS project_id, lifecycle, record_kind, updated_revision;
DEFINE INDEX OVERWRITE idx_memory_search_token_posting
  ON TABLE memory_search_token FIELDS project_id, token, handle;
DEFINE INDEX OVERWRITE idx_memory_search_token_handle
  ON TABLE memory_search_token FIELDS project_id, handle;
DEFINE INDEX OVERWRITE idx_memory_search_outbox_write
  ON TABLE memory_search_outbox FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_memory_search_outbox_project_status_revision
  ON TABLE memory_search_outbox FIELDS project_id, status, updated_revision;

RETURN {
  projection_table: 'memory_search_projection',
  token_table: 'memory_search_token',
  state_table: 'memory_search_state',
  outbox_table: 'memory_search_outbox',
};
