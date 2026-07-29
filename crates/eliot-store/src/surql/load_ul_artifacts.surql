LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 256 {
  256
} ELSE {
  $limit
};

LET $bounded_start = IF $start < 0 {
  0
} ELSE {
  $start
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
  AND record_id = array::first(
    SELECT VALUE record_id
    FROM canonical_record
    WHERE project_id = $parent.project_id
      AND receipt_kind = $parent.receipt_kind
      AND subject_ref = $parent.subject_ref
    ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
    LIMIT 1
  )
ORDER BY receipt_kind ASC, subject_ref ASC, memory_revision DESC, project_sequence DESC, record_id DESC
START $bounded_start
LIMIT $bounded_limit;
