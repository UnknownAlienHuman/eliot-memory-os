LET $trace_ref = <string> array::join(
  $trace_ref_fragments.map(|$fragment| <string> $fragment),
  ''
);

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
  AND task_id = $task_id
  AND receipt_kind = 'trace_completeness_contract'
  AND (
    trace_ref = <string> $trace_ref
    OR (
      (trace_ref = NONE OR trace_ref = NULL OR trace_ref = '')
      AND <string> receipt_body.trace_ref = <string> $trace_ref
    )
  )
ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
LIMIT 2;
