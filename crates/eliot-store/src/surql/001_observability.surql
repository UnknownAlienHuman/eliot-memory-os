DEFINE TABLE IF NOT EXISTS observability_receipt SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_influence_trace SCHEMALESS;
DEFINE TABLE IF NOT EXISTS injection_receipt SCHEMALESS;
DEFINE TABLE IF NOT EXISTS activation_trace SCHEMALESS;
DEFINE TABLE IF NOT EXISTS prediction_record SCHEMALESS;
DEFINE TABLE IF NOT EXISTS exam_record SCHEMALESS;

DEFINE INDEX OVERWRITE idx_observability_receipt_write
  ON TABLE observability_receipt FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_observability_receipt_kind
  ON TABLE observability_receipt FIELDS project_id, kind, created_at;
DEFINE INDEX OVERWRITE idx_influence_write
  ON TABLE memory_influence_trace FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_influence_task
  ON TABLE memory_influence_trace FIELDS project_id, task_id, created_at;
DEFINE INDEX OVERWRITE idx_injection_write
  ON TABLE injection_receipt FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_prediction_write
  ON TABLE prediction_record FIELDS write_id UNIQUE;
