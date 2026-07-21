LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 128 {
  128
} ELSE {
  $limit
};
LET $candidate_rows = SELECT
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
  AND receipt_kind IN [
    'sleep_consolidation_bundle',
    'sleep_consolidation_run',
    'procedure_candidate',
    'forgetting_candidate',
    'test_candidate',
    'replay_case_candidate',
    'dream_candidate'
  ]
ORDER BY memory_revision ASC, project_sequence ASC, record_id ASC
LIMIT $bounded_limit + 1;
LET $truncated = array::len($candidate_rows) > $bounded_limit;
LET $candidates = array::slice($candidate_rows, 0, $bounded_limit);

RETURN {
  op: 'sleep_candidates',
  project_id: $project_id,
  task_id: $task_id,
  candidates: $candidates,
  truncation: {
    truncated: $truncated,
    limit: $bounded_limit,
    returned: array::len($candidates)
  }
};
