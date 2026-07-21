LET $failed_claim_ids = SELECT VALUE <string> claim_id FROM verification_run WHERE result = 'failed' AND claim_id != NONE;

RETURN {
  orphan_claims: 0,
  claims_without_support: array::len(SELECT * FROM claim_card WHERE status = 'candidate'),
  claims_without_verification: array::len(SELECT * FROM claim_card WHERE status IN ['candidate', 'supported']),
  verified_claims: array::len(SELECT * FROM claim_card WHERE status = 'verified' AND <string> claim_id NOT IN $failed_claim_ids),
  supported_claims: array::len(SELECT * FROM claim_card WHERE status = 'supported' AND <string> claim_id NOT IN $failed_claim_ids),
  weak_claims: array::len(SELECT * FROM claim_card WHERE status = 'candidate' AND <string> claim_id NOT IN $failed_claim_ids),
  contested_claims: array::len(SELECT * FROM claim_card WHERE status = 'contested' OR <string> claim_id IN $failed_claim_ids),
  orphan_evidence: 0,
  orphan_verifications: 0,
  duplicate_write_ids: 0,
  relation_count_by_type: [
    { name: 'supports', count: array::len(SELECT * FROM supports) },
    { name: 'verified_by', count: array::len(SELECT * FROM verified_by) },
    { name: 'contradicts', count: array::len(SELECT * FROM contradicts) },
    { name: 'supersedes', count: array::len(SELECT * FROM supersedes) },
    { name: 'mentions', count: array::len(SELECT * FROM mentions) },
    { name: 'belongs_to', count: array::len(SELECT * FROM belongs_to) },
    { name: 'produced_by', count: array::len(SELECT * FROM produced_by) },
    { name: 'invalidated_by', count: array::len(SELECT * FROM invalidated_by) }
  ],
  records_by_lifecycle_status: [
    { name: 'active', count: array::len(SELECT * FROM claim_card WHERE lifecycle_status = 'active') },
    { name: 'superseded', count: array::len(SELECT * FROM claim_card WHERE lifecycle_status = 'superseded') },
    { name: 'stale', count: array::len(SELECT * FROM claim_card WHERE lifecycle_status = 'stale') },
    { name: 'deleted', count: array::len(SELECT * FROM claim_card WHERE lifecycle_status = 'deleted') }
  ],
  records_by_visibility: [
    { name: 'internal', count: array::len(SELECT * FROM claim_card WHERE visibility = 'internal') },
    { name: 'project', count: array::len(SELECT * FROM claim_card WHERE visibility = 'project') },
    { name: 'private', count: array::len(SELECT * FROM claim_card WHERE visibility = 'private') }
  ],
  latest_memory_revision_by_project: SELECT project_id, memory_revision, project_sequence FROM scope_head
    ORDER BY memory_revision DESC
    LIMIT 50
};
