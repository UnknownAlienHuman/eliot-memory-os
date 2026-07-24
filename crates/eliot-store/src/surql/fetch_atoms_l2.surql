LET $head = SELECT * FROM ONLY type::record('scope_head', $request.project_id);
LET $claim_ids = $exact.claims.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $evidence_ids = $exact.evidence.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $verification_ids = $exact.verifications.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $observation_ids = $exact.observations.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $failure_ids = $exact.failures.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $relation_ids = $exact.relations.map(|$fragments| {
  RETURN <string> array::join($fragments.map(|$fragment| <string> $fragment), '');
});
LET $supports_raw = SELECT relation_type, from, to FROM supports
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $verified_by_raw = SELECT relation_type, from, to FROM verified_by
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $contradicts_raw = SELECT relation_type, from, to FROM contradicts
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $supersedes_raw = SELECT relation_type, from, to FROM supersedes
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $mentions_raw = SELECT relation_type, from, to FROM mentions
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $belongs_to_raw = SELECT relation_type, from, to FROM belongs_to
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $produced_by_raw = SELECT relation_type, from, to FROM produced_by
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $invalidated_by_raw = SELECT relation_type, from, to FROM invalidated_by
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $co_change_raw = SELECT relation_type, from, to FROM co_change
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $concept_implemented_by_raw = SELECT relation_type, from, to FROM concept_implemented_by
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $concept_depends_on_raw = SELECT relation_type, from, to FROM concept_depends_on
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $capsule_covers_raw = SELECT relation_type, from, to FROM capsule_covers
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $card_covers_raw = SELECT relation_type, from, to FROM card_covers
  WHERE project_id = $request.project_id
    AND (<string> from IN $relation_ids OR <string> to IN $relation_ids)
  ORDER BY from ASC, to ASC LIMIT 65;
LET $relation_truncated = array::len($supports_raw) > 64
  OR array::len($verified_by_raw) > 64
  OR array::len($contradicts_raw) > 64
  OR array::len($supersedes_raw) > 64
  OR array::len($mentions_raw) > 64
  OR array::len($belongs_to_raw) > 64
  OR array::len($produced_by_raw) > 64
  OR array::len($invalidated_by_raw) > 64
  OR array::len($co_change_raw) > 64
  OR array::len($concept_implemented_by_raw) > 64
  OR array::len($concept_depends_on_raw) > 64
  OR array::len($capsule_covers_raw) > 64
  OR array::len($card_covers_raw) > 64;
LET $supports = array::slice($supports_raw, 0, 64);
LET $verified_by = array::slice($verified_by_raw, 0, 64);
LET $contradicts = array::slice($contradicts_raw, 0, 64);
LET $supersedes = array::slice($supersedes_raw, 0, 64);
LET $mentions = array::slice($mentions_raw, 0, 64);
LET $belongs_to = array::slice($belongs_to_raw, 0, 64);
LET $produced_by = array::slice($produced_by_raw, 0, 64);
LET $invalidated_by = array::slice($invalidated_by_raw, 0, 64);
LET $co_change = array::slice($co_change_raw, 0, 64);
LET $concept_implemented_by = array::slice($concept_implemented_by_raw, 0, 64);
LET $concept_depends_on = array::slice($concept_depends_on_raw, 0, 64);
LET $capsule_covers = array::slice($capsule_covers_raw, 0, 64);
LET $card_covers = array::slice($card_covers_raw, 0, 64);
LET $relations = array::concat(
  $supports,
  $verified_by,
  $contradicts,
  $supersedes,
  $mentions,
  $belongs_to,
  $produced_by,
  $invalidated_by,
  $co_change,
  $concept_implemented_by,
  $concept_depends_on,
  $capsule_covers,
  $card_covers
);
LET $relation_neighbors = array::concat(
  $relations.map(|$relation| <string> $relation.from),
  $relations.map(|$relation| <string> $relation.to)
);
LET $forbidden_claims = SELECT VALUE string::concat('claim:', <string> claim_id)
  FROM claim_card WHERE project_id != $request.project_id AND <string> claim_id IN $claim_ids;
LET $forbidden_evidence = SELECT VALUE string::concat('evidence:', <string> evidence_id)
  FROM evidence_atom WHERE project_id != $request.project_id AND <string> evidence_id IN $evidence_ids;
LET $forbidden_verifications = SELECT VALUE string::concat('verification:', <string> verification_id)
  FROM verification_run WHERE project_id != $request.project_id AND <string> verification_id IN $verification_ids;
LET $forbidden_observations = SELECT VALUE string::concat('observation:', <string> observation_id)
  FROM tool_observation WHERE project_id != $request.project_id AND <string> observation_id IN $observation_ids;
LET $forbidden_failures = SELECT VALUE string::concat('failure:', <string> fingerprint)
  FROM failure_fingerprint WHERE project_id != $request.project_id AND <string> fingerprint IN $failure_ids;

RETURN {
  project_id: $request.project_id,
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  evidence_atoms: SELECT evidence_id, summary, payload FROM evidence_atom
    WHERE project_id = $request.project_id
      AND <string> evidence_id IN array::concat($evidence_ids, $relation_neighbors),
  claims: SELECT claim_id, statement, status, payload FROM claim_card
    WHERE project_id = $request.project_id
      AND <string> claim_id IN array::concat($claim_ids, $relation_neighbors),
  verification_runs: SELECT verification_id, result, summary, payload FROM verification_run
    WHERE project_id = $request.project_id
      AND <string> verification_id IN array::concat($verification_ids, $relation_neighbors),
  tool_observations: SELECT observation_id, tool_name, observation, payload FROM tool_observation
    WHERE project_id = $request.project_id
      AND <string> observation_id IN array::concat($observation_ids, $relation_neighbors),
  failure_fingerprints: SELECT fingerprint, summary, payload FROM failure_fingerprint
    WHERE project_id = $request.project_id
      AND <string> fingerprint IN array::concat($failure_ids, $relation_neighbors),
  relations: $relations,
  requested_handles: [],
  returned_handles: [],
  missing_handles: [],
  forbidden_handles: array::concat($forbidden_claims, $forbidden_evidence, $forbidden_verifications, $forbidden_observations, $forbidden_failures),
  continuation: NONE,
  truncation: {
    truncated: $relation_truncated,
    limit: 64,
    returned: 0,
  },
};
