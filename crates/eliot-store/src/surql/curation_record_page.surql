LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 100 {
  100
} ELSE {
  $limit
};

RETURN SELECT VALUE {
  record_id: <string> claim_id,
  receipt_kind: 'claim_card',
  project_id: <string> project_id,
  task_id: <string> task_id,
  subject_ref: string::concat('claim:', <string> claim_id),
  receipt_body: {
    claim_id: <string> claim_id,
    statement: statement,
    status: status,
    lifecycle_status: IF lifecycle_status_revision = NONE
      OR lifecycle_status_revision = NULL
      OR lifecycle_status_revision <= $at_revision {
      lifecycle_status
    } ELSE {
      'active'
    },
    lifecycle_transitions: SELECT VALUE receipt_body.to_state
      FROM canonical_record
      WHERE <string> project_id = <string> $parent.project_id
        AND <string> task_id = <string> $parent.task_id
        AND receipt_kind = 'state_transition'
        AND subject_ref = string::concat('claim:', <string> $parent.claim_id)
        AND memory_revision <= $at_revision
      ORDER BY memory_revision DESC, project_sequence DESC
      LIMIT 1,
    payload: payload
  },
  canonical_receipt: {
    receipt_id: <string> write_id,
    write_id: <string> write_id
  },
  memory_revision: memory_revision,
  project_sequence: project_sequence
}
FROM claim_card
WHERE <string> project_id = <string> $project_id
  AND <string> task_id = <string> $task_id
  AND memory_revision <= $at_revision
ORDER BY memory_revision ASC, project_sequence ASC, claim_id ASC
START $start
LIMIT $bounded_limit;
