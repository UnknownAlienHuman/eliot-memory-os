DEFINE TABLE IF NOT EXISTS ul_dep_reverse_index SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_dep_reverse
  ON TABLE ul_dep_reverse_index
  FIELDS project_id, dependency_kind, dependency_key;

DEFINE INDEX OVERWRITE idx_ul_dep_target
  ON TABLE ul_dep_reverse_index
  FIELDS project_id, target_kind, target_id, build_id;

DEFINE TABLE IF NOT EXISTS ul_artifact_dirty SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_dirty_target
  ON TABLE ul_artifact_dirty
  FIELDS project_id, target_kind, target_id UNIQUE;

DEFINE INDEX OVERWRITE idx_ul_dirty_state
  ON TABLE ul_artifact_dirty
  FIELDS project_id, dirty, updated_at;

DEFINE INDEX OVERWRITE idx_ul_activation_scope
  ON TABLE activation_trace
  FIELDS project_id, task_id, session_id, created_at;
