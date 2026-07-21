LET $head = SELECT * FROM ONLY type::record('scope_head', $request.project_id);
LET $supports = SELECT relation_type, from, to FROM supports WHERE project_id = $request.project_id LIMIT 50;
LET $verified_by = SELECT relation_type, from, to FROM verified_by WHERE project_id = $request.project_id LIMIT 50;
LET $contradicts = SELECT relation_type, from, to FROM contradicts WHERE project_id = $request.project_id LIMIT 50;
LET $supersedes = SELECT relation_type, from, to FROM supersedes WHERE project_id = $request.project_id LIMIT 50;
LET $mentions = SELECT relation_type, from, to FROM mentions WHERE project_id = $request.project_id LIMIT 50;
LET $belongs_to = SELECT relation_type, from, to FROM belongs_to WHERE project_id = $request.project_id LIMIT 50;
LET $produced_by = SELECT relation_type, from, to FROM produced_by WHERE project_id = $request.project_id LIMIT 50;
LET $invalidated_by = SELECT relation_type, from, to FROM invalidated_by WHERE project_id = $request.project_id LIMIT 50;

RETURN {
  project_id: $request.project_id,
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  evidence_atoms: SELECT evidence_id, summary, payload FROM evidence_atom WHERE project_id = $request.project_id LIMIT 50,
  claims: SELECT claim_id, statement, status, payload FROM claim_card WHERE project_id = $request.project_id LIMIT 50,
  verification_runs: SELECT verification_id, result, summary, payload FROM verification_run WHERE project_id = $request.project_id LIMIT 50,
  tool_observations: SELECT observation_id, tool_name, observation, payload FROM tool_observation WHERE project_id = $request.project_id LIMIT 50,
  failure_fingerprints: SELECT fingerprint, summary, payload FROM failure_fingerprint WHERE project_id = $request.project_id LIMIT 50,
  relations: array::concat($supports, $verified_by, $contradicts, $supersedes, $mentions, $belongs_to, $produced_by, $invalidated_by),
  requested_handles: [],
  returned_handles: [],
  missing_handles: [],
  forbidden_handles: [],
  continuation: NONE,
  truncation: {
    truncated: false,
    limit: 50,
    returned: 0,
  },
};
