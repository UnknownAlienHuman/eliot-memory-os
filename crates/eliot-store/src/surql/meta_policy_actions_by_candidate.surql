LET $candidate_id = <string> array::join(
  $candidate_id_fragments.map(|$fragment| <string> $fragment),
  ''
);
LET $action = <string> array::join(
  $action_fragments.map(|$fragment| <string> $fragment),
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
  AND receipt_kind IN ['meta_policy_promotion', 'meta_policy_rollback']
  AND (
    candidate_id = <string> $candidate_id
    OR (
      -- Same explicit missing-field predicate as canonical_trace_by_trace_ref
      -- and the 000_schema.surql repair, so candidate/action lookup and trace
      -- lookup share one confirmed semantic. See that file for the pinned
      -- SurrealDB 3.1.4 evidence: `type::is_none(x)` is true only for an
      -- absent/UNSET field and false for '', NULL, and any present value.
      type::is_none(candidate_id)
      AND <string> receipt_body.candidate_id = <string> $candidate_id
    )
  )
  AND (
    canonical_action = <string> $action
    OR (
      type::is_none(canonical_action)
      AND <string> receipt_body.action = <string> $action
    )
  )
ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
LIMIT 2;
