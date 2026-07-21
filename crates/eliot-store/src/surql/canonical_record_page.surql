LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 100 {
  100
} ELSE {
  $limit
};

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
ORDER BY memory_revision ASC, project_sequence ASC, record_id ASC
START $start
LIMIT $bounded_limit;
