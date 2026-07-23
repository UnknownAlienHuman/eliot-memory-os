LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 128 {
  128
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
  AND receipt_kind IN $receipt_kinds
ORDER BY receipt_kind ASC, subject_ref ASC, memory_revision DESC, project_sequence DESC
LIMIT $bounded_limit;
