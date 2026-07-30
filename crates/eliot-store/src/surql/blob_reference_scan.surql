LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 512 {
  512
} ELSE {
  $limit
};
LET $fetch_limit = $bounded_limit + 1;

LET $records = SELECT *, <string> id AS gc_record_ref
FROM task_contract, source_snapshot, evidence_atom, tool_observation, claim_card,
  verification_run, failure_fingerprint, write_receipt, memory_transition,
  canonical_record, trace_span, context_packet_receipt, supports, verified_by,
  contradicts, supersedes, mentions, belongs_to, produces, invalidated_by
ORDER BY gc_record_ref ASC
LIMIT $fetch_limit;

LET $scope_heads = SELECT *, <string> id AS gc_record_ref
FROM scope_head
ORDER BY gc_record_ref ASC
LIMIT $fetch_limit;

RETURN {
  bounded_limit: $bounded_limit,
  records: $records,
  scope_heads: $scope_heads
};
