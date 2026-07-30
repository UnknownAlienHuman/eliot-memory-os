LET $project = <string> $project_id;

LET $claim_scan = SELECT id, claim_id, status, lifecycle_status, visibility, write_id
  FROM claim_card
  WHERE <string> project_id = $project OR project = $project
  LIMIT $scan_fetch_limit;
LET $evidence_scan = SELECT id, evidence_id, write_id
  FROM evidence_atom
  WHERE <string> project_id = $project OR project = $project
  LIMIT $scan_fetch_limit;
LET $verification_scan = SELECT id, verification_id, claim_id, result, write_id
  FROM verification_run
  WHERE <string> project_id = $project OR project = $project
  LIMIT $scan_fetch_limit;

LET $claims = array::slice($claim_scan, 0, $scan_limit);
LET $evidence = array::slice($evidence_scan, 0, $scan_limit);
LET $verifications = array::slice($verification_scan, 0, $scan_limit);
LET $claim_refs = array::concat(
  $claims.map(|$record| <string> $record.id),
  $claims[WHERE claim_id != NONE].map(|$record| <string> $record.claim_id)
);
LET $evidence_refs = array::concat(
  $evidence.map(|$record| <string> $record.id),
  $evidence[WHERE evidence_id != NONE].map(|$record| <string> $record.evidence_id)
);
LET $verification_refs = array::concat(
  $verifications.map(|$record| <string> $record.id),
  $verifications[WHERE verification_id != NONE].map(|$record| <string> $record.verification_id)
);
LET $project_refs = array::concat($claim_refs, $evidence_refs, $verification_refs);

LET $supports_scan = SELECT id, in, out, from, to
  FROM supports
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $verified_by_scan = SELECT id, in, out, from, to
  FROM verified_by
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $contradicts_scan = SELECT id, in, out, from, to
  FROM contradicts
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $supersedes_scan = SELECT id, in, out, from, to
  FROM supersedes
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $mentions_scan = SELECT id, in, out, from, to
  FROM mentions
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $belongs_to_scan = SELECT id, in, out, from, to
  FROM belongs_to
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;
LET $produces_scan = SELECT id, in, out, from, to
  FROM produces
  WHERE <string> project_id = $project
    OR (<string> in) IN $project_refs
    OR (<string> out) IN $project_refs
    OR (<string> from) IN $project_refs
    OR (<string> to) IN $project_refs
  LIMIT $scan_fetch_limit;

LET $supports = array::slice($supports_scan, 0, $scan_limit);
LET $verified_by = array::slice($verified_by_scan, 0, $scan_limit);
LET $contradicts = array::slice($contradicts_scan, 0, $scan_limit);
LET $supersedes = array::slice($supersedes_scan, 0, $scan_limit);
LET $mentions = array::slice($mentions_scan, 0, $scan_limit);
LET $belongs_to = array::slice($belongs_to_scan, 0, $scan_limit);
LET $produces = array::slice($produces_scan, 0, $scan_limit);
LET $supported_claim_refs = array::concat(
  $supports.map(|$relation| <string> $relation.out),
  $supports.map(|$relation| <string> $relation.to)
);
LET $verified_claim_refs = array::concat(
  $verified_by.map(|$relation| <string> $relation.in),
  $verified_by.map(|$relation| <string> $relation.out),
  $verified_by.map(|$relation| <string> $relation.from),
  $verified_by.map(|$relation| <string> $relation.to),
  $verifications[WHERE claim_id != NONE].map(|$verification| <string> $verification.claim_id)
);
LET $failed_claim_refs = $verifications[
  WHERE result = 'failed' AND claim_id != NONE
].map(|$verification| <string> $verification.claim_id);
LET $claims_without_support_rows = $claims[
  WHERE (
    (<string> id) IN $supported_claim_refs
    OR (<string> claim_id) IN $supported_claim_refs
  ) = false
];
LET $claims_without_verification_rows = $claims[
  WHERE (
    (<string> id) IN $verified_claim_refs
    OR (<string> claim_id) IN $verified_claim_refs
  ) = false
];
LET $orphan_verification_rows = $verifications[
  WHERE claim_id != NONE AND ((<string> claim_id) IN $claim_refs) = false
];
LET $supported_evidence_refs = array::concat(
  $supports.map(|$relation| <string> $relation.in),
  $supports.map(|$relation| <string> $relation.from)
);
LET $orphan_evidence_rows = $evidence[
  WHERE (
    (<string> id) IN $supported_evidence_refs
    OR (<string> evidence_id) IN $supported_evidence_refs
  ) = false
];
LET $unsupported_relations = [
  IF $has_invalidated_by { NONE } ELSE { 'invalidated_by' }
][WHERE $this != NONE];
LET $scan_truncated = array::len($claim_scan) > $scan_limit
  OR array::len($evidence_scan) > $scan_limit
  OR array::len($verification_scan) > $scan_limit
  OR array::len($supports_scan) > $scan_limit
  OR array::len($verified_by_scan) > $scan_limit
  OR array::len($contradicts_scan) > $scan_limit
  OR array::len($supersedes_scan) > $scan_limit
  OR array::len($mentions_scan) > $scan_limit
  OR array::len($belongs_to_scan) > $scan_limit
  OR array::len($produces_scan) > $scan_limit;

RETURN {
  project_id: $project_id,
  scan_limit: $scan_limit,
  scan_truncated: $scan_truncated,
  unsupported_relation_families: $unsupported_relations,
  scope_head_supported: $has_scope_head,
  orphan_claims: array::len($claims_without_support_rows),
  claims_without_support: array::len($claims_without_support_rows),
  claims_without_verification: array::len($claims_without_verification_rows),
  verified_claims: array::len($claims[
    WHERE status = 'verified' AND ((<string> claim_id) IN $failed_claim_refs) = false
  ]),
  supported_claims: array::len($claims[
    WHERE status = 'supported' AND ((<string> claim_id) IN $failed_claim_refs) = false
  ]),
  weak_claims: array::len($claims[
    WHERE status = 'candidate' AND ((<string> claim_id) IN $failed_claim_refs) = false
  ]),
  contested_claims: array::len($claims[
    WHERE status = 'contested' OR (<string> claim_id) IN $failed_claim_refs
  ]),
  orphan_evidence: array::len($orphan_evidence_rows),
  orphan_verifications: array::len($orphan_verification_rows),
  duplicate_write_ids: IF $has_write_receipt {
    array::len(
      SELECT VALUE <string> write_id FROM write_receipt
      WHERE <string> project_id = $project OR project = $project
      LIMIT $scan_limit
    ) - array::len(array::distinct(
      SELECT VALUE <string> write_id FROM write_receipt
      WHERE <string> project_id = $project OR project = $project
      LIMIT $scan_limit
    ))
  } ELSE {
    0
  },
  relation_count_by_type: [
    { name: 'supports', count: array::len($supports) },
    { name: 'verified_by', count: array::len($verified_by) },
    { name: 'contradicts', count: array::len($contradicts) },
    { name: 'supersedes', count: array::len($supersedes) },
    { name: 'mentions', count: array::len($mentions) },
    { name: 'belongs_to', count: array::len($belongs_to) },
    { name: 'produces', count: array::len($produces) },
    {
      name: 'invalidated_by',
      count: IF $has_invalidated_by {
        array::len(
          SELECT id FROM invalidated_by
          WHERE <string> project_id = $project
            OR (<string> in) IN $project_refs
            OR (<string> out) IN $project_refs
            OR (<string> from) IN $project_refs
            OR (<string> to) IN $project_refs
          LIMIT $scan_limit
        )
      } ELSE {
        0
      }
    }
  ],
  records_by_lifecycle_status: [
    { name: 'active', count: array::len($claims[WHERE lifecycle_status = 'active']) },
    { name: 'superseded', count: array::len($claims[WHERE lifecycle_status = 'superseded']) },
    { name: 'stale', count: array::len($claims[WHERE lifecycle_status = 'stale']) },
    { name: 'deleted', count: array::len($claims[WHERE lifecycle_status = 'deleted']) }
  ],
  records_by_visibility: [
    { name: 'internal', count: array::len($claims[WHERE visibility = 'internal']) },
    { name: 'project', count: array::len($claims[WHERE visibility = 'project']) },
    { name: 'private', count: array::len($claims[WHERE visibility = 'private']) }
  ],
  latest_memory_revision_by_project: IF $has_scope_head {
    SELECT project_id, memory_revision, project_sequence
    FROM scope_head
    WHERE <string> project_id = $project OR project = $project
    ORDER BY memory_revision DESC
    LIMIT 1
  } ELSE {
    []
  }
};
