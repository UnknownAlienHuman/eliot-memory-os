LET $head = SELECT * FROM ONLY type::record('scope_head', $request.project_id);
LET $revision = IF $head == NONE { 0 } ELSE { $head.memory_revision };
LET $sequence = IF $head == NONE { 0 } ELSE { $head.project_sequence };
LET $failed_claim_ids = SELECT VALUE <string> claim_id FROM verification_run
  WHERE project_id = $request.project_id AND result = 'failed' AND claim_id != NONE;
LET $claims = SELECT claim_id, statement, status, lifecycle_status, visibility, memory_revision, project_sequence
  FROM claim_card
  WHERE project_id = $request.project_id
  ORDER BY memory_revision DESC, project_sequence DESC, claim_id ASC
  LIMIT 251;
LET $resolved = $claims.map(|$claim| {
  LET $target_refs = [
    <string> $claim.claim_id,
    string::concat('claim:', <string> $claim.claim_id)
  ];
  LET $transitions = SELECT VALUE receipt_body.to_state
    FROM canonical_record
    WHERE project_id = $request.project_id
      AND receipt_kind = 'state_transition'
      AND subject_ref IN $target_refs
    ORDER BY memory_revision DESC, project_sequence DESC
    LIMIT 1;
  LET $lifecycle_state = IF array::len($transitions) > 0 {
    $transitions[0]
  } ELSE IF $claim.lifecycle_status != NONE {
    $claim.lifecycle_status
  } ELSE {
    'active'
  };
  RETURN {
    claim_id: $claim.claim_id,
    statement: $claim.statement,
    status: $claim.status,
    memory_revision: $claim.memory_revision,
    visibility: $claim.visibility,
    lifecycle_state: $lifecycle_state,
    failed_verification: <string> $claim.claim_id IN $failed_claim_ids,
  };
});
LET $verified = $resolved[WHERE status = 'verified'
  AND failed_verification = false
  AND lifecycle_state IN ['active', 'restored']];
LET $supported = $resolved[WHERE status = 'supported'
  AND failed_verification = false
  AND lifecycle_state IN ['active', 'restored']];
LET $weak = $resolved[WHERE status = 'candidate'
  AND failed_verification = false
  AND lifecycle_state IN ['active', 'restored']];
LET $contested = $resolved[WHERE (failed_verification = true OR status = 'contested')
  AND lifecycle_state IN ['active', 'restored']];
LET $forbidden = $resolved[WHERE status IN ['rejected', 'stale', 'superseded']
  OR lifecycle_state IN ['stale', 'superseded', 'deleted']
  OR visibility = 'private'];
LET $verified_page = array::slice($verified, 0, 50);
LET $supported_page = array::slice($supported, 0, 50);
LET $weak_page = array::slice($weak, 0, 50);
LET $contested_page = array::slice($contested, 0, 50);
LET $forbidden_page = array::slice($forbidden, 0, 50);
LET $returned = array::len($verified_page)
  + array::len($supported_page)
  + array::len($weak_page)
  + array::len($contested_page)
  + array::len($forbidden_page);

RETURN {
  project_id: $request.project_id,
  memory_revision: $revision,
  project_sequence: $sequence,
  verified_now: $verified_page,
  supported_now: $supported_page,
  weak_or_candidate: $weak_page,
  contested_now: $contested_page,
  do_not_use: $forbidden_page,
  recent_failures: SELECT fingerprint, summary FROM failure_fingerprint WHERE project_id = $request.project_id LIMIT 20,
  truncation: {
    truncated: array::len($claims) > 250
      OR array::len($verified) > 50
      OR array::len($supported) > 50
      OR array::len($weak) > 50
      OR array::len($contested) > 50
      OR array::len($forbidden) > 50,
    limit: 50,
    returned: $returned
  }
};
