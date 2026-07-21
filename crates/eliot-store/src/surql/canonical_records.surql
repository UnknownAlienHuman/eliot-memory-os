LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 128 {
  128
} ELSE {
  $limit
};
LET $subject_ref_filter = IF $has_subject_ref {
  <string> array::join(
    $subject_ref_fragments.map(|$fragment| <string> $fragment),
    ''
  )
} ELSE {
  NONE
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
  AND ($subject_ref_filter = NONE OR subject_ref = <string> $subject_ref_filter)
ORDER BY memory_revision ASC, project_sequence ASC, record_id ASC
LIMIT $bounded_limit;
