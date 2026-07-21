RETURN SELECT
  record_id,
  receipt_kind,
  project_id,
  task_id,
  subject_ref,
  receipt_body,
  receipt_body_json_b64,
  canonical_receipt,
  memory_revision,
  project_sequence
FROM canonical_record
WHERE project_id = $project_id
  AND ($task_id = NONE OR $task_id = NULL OR task_id = $task_id)
  AND receipt_kind IN $receipt_kinds
  AND write_id = $write_id
ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
LIMIT 2;
