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
      -- Explicit missing-field predicate. On the pinned SurrealDB 3.1.4 route
      -- `type::is_none(x)` is true only for an absent/UNSET field (and an
      -- explicitly stored NONE, which the provider itself removes on write),
      -- and false for '', NULL, and any present value. `x IS NONE` is the
      -- equivalent grammar form and behaves identically here. Unlike
      -- `(x ?? '') = ''`, this keeps an explicit empty string, NULL, and a
      -- non-empty value distinct from an unmaterialized identity, so the
      -- receipt-body fallback below applies only to a genuinely missing field.
      type::is_none(trace_ref)
      AND <string> receipt_body.trace_ref = <string> $trace_ref
    )
  )
ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
LIMIT 2;
