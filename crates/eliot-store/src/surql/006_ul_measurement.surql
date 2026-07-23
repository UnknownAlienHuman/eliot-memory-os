DEFINE TABLE IF NOT EXISTS ul_task_ledger SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_task_ledger_project_task
  ON TABLE ul_task_ledger FIELDS project_id, task_id UNIQUE;
DEFINE INDEX OVERWRITE idx_ul_prediction_scope
  ON TABLE prediction_record FIELDS project_id, task_id, created_at;
DEFINE INDEX OVERWRITE idx_ul_prediction_verifier
  ON TABLE prediction_record FIELDS project_id, task_id, payload.verifier, created_at;

RETURN {
  migrated: true,
  schema: 'ul_measurement'
};
