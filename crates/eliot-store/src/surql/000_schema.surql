DEFINE TABLE IF NOT EXISTS scope_head SCHEMALESS;
DEFINE TABLE IF NOT EXISTS task_contract SCHEMALESS;
DEFINE TABLE IF NOT EXISTS source_snapshot SCHEMALESS;
DEFINE TABLE IF NOT EXISTS evidence_atom SCHEMALESS;
DEFINE TABLE IF NOT EXISTS tool_observation SCHEMALESS;
DEFINE TABLE IF NOT EXISTS claim_card SCHEMALESS;
DEFINE TABLE IF NOT EXISTS verification_run SCHEMALESS;
DEFINE TABLE IF NOT EXISTS failure_fingerprint SCHEMALESS;
DEFINE TABLE IF NOT EXISTS write_receipt SCHEMALESS;
DEFINE TABLE IF NOT EXISTS memory_transition SCHEMALESS;
DEFINE TABLE IF NOT EXISTS canonical_record SCHEMALESS;
DEFINE TABLE IF NOT EXISTS trace_span SCHEMALESS;
DEFINE TABLE IF NOT EXISTS context_packet_receipt SCHEMALESS;
DEFINE TABLE IF NOT EXISTS supports SCHEMALESS;
DEFINE TABLE IF NOT EXISTS verified_by SCHEMALESS;
DEFINE TABLE IF NOT EXISTS contradicts SCHEMALESS;
DEFINE TABLE IF NOT EXISTS supersedes SCHEMALESS;
DEFINE TABLE IF NOT EXISTS mentions SCHEMALESS;
DEFINE TABLE IF NOT EXISTS belongs_to SCHEMALESS;
DEFINE TABLE IF NOT EXISTS produced_by SCHEMALESS;
DEFINE TABLE IF NOT EXISTS invalidated_by SCHEMALESS;

DEFINE INDEX OVERWRITE idx_scope_head_project ON TABLE scope_head FIELDS project_id;
DEFINE INDEX OVERWRITE idx_task_contract_project ON TABLE task_contract FIELDS project_id;
DEFINE INDEX OVERWRITE idx_task_contract_status ON TABLE task_contract FIELDS status;
DEFINE INDEX OVERWRITE idx_evidence_project ON TABLE evidence_atom FIELDS project_id;
DEFINE INDEX OVERWRITE idx_evidence_write ON TABLE evidence_atom FIELDS write_id;
DEFINE INDEX OVERWRITE idx_claim_project ON TABLE claim_card FIELDS project_id;
DEFINE INDEX OVERWRITE idx_claim_status ON TABLE claim_card FIELDS status;
DEFINE INDEX OVERWRITE idx_claim_write ON TABLE claim_card FIELDS write_id;
DEFINE INDEX OVERWRITE idx_verification_project ON TABLE verification_run FIELDS project_id;
DEFINE INDEX OVERWRITE idx_verification_result ON TABLE verification_run FIELDS result;
DEFINE INDEX OVERWRITE idx_failure_project ON TABLE failure_fingerprint FIELDS project_id;
DEFINE INDEX OVERWRITE idx_tool_observation_project_task_kind_pattern ON TABLE tool_observation FIELDS project_id, task_id, payload.receipt_kind, payload.receipt_body.pattern_id;
DEFINE INDEX OVERWRITE idx_receipt_write ON TABLE write_receipt FIELDS write_id UNIQUE;
DEFINE INDEX OVERWRITE idx_receipt_project ON TABLE write_receipt FIELDS project_id;
DEFINE INDEX OVERWRITE idx_receipt_sequence ON TABLE write_receipt FIELDS project_sequence;
DEFINE INDEX OVERWRITE idx_transition_project ON TABLE memory_transition FIELDS project_id;
DEFINE INDEX OVERWRITE idx_canonical_project_kind ON TABLE canonical_record FIELDS project_id, receipt_kind;
DEFINE INDEX OVERWRITE idx_canonical_project_task_kind ON TABLE canonical_record FIELDS project_id, task_id, receipt_kind;
DEFINE INDEX OVERWRITE idx_canonical_project_subject ON TABLE canonical_record FIELDS project_id, subject_ref;
DEFINE INDEX OVERWRITE idx_canonical_write ON TABLE canonical_record FIELDS write_id;

-- Pre-exact-lookup releases persisted the canonical body and byte-exact JSON,
-- but did not materialize these indexed identity fields. Repair those rows on
-- every idempotent schema migration so an upgrade cannot hide prior authority.
UPDATE canonical_record SET trace_ref = <string> receipt_body.trace_ref
WHERE receipt_kind = 'trace_completeness_contract'
  AND (trace_ref = NONE OR trace_ref = NULL OR trace_ref = '')
  AND receipt_body.trace_ref != NONE
  AND receipt_body.trace_ref != NULL;
UPDATE canonical_record SET
  candidate_id = <string> receipt_body.candidate_id,
  canonical_action = <string> receipt_body.action
WHERE receipt_kind IN ['meta_policy_promotion', 'meta_policy_rollback']
  AND (
    candidate_id = NONE OR candidate_id = NULL OR candidate_id = ''
    OR canonical_action = NONE OR canonical_action = NULL OR canonical_action = ''
  )
  AND receipt_body.candidate_id != NONE
  AND receipt_body.candidate_id != NULL
  AND receipt_body.action != NONE
  AND receipt_body.action != NULL;

DEFINE INDEX OVERWRITE idx_canonical_project_task_trace ON TABLE canonical_record FIELDS project_id, task_id, trace_ref;
DEFINE INDEX OVERWRITE idx_canonical_project_task_candidate_action ON TABLE canonical_record FIELDS project_id, task_id, candidate_id, canonical_action;

RETURN {
  migrated: true,
  schema: 'phase_b_canonical_memory_core'
};
