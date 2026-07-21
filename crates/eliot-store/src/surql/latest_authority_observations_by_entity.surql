LET $entity_ref = <string> array::join(
  $entity_ref_fragments.map(|$fragment| <string> $fragment),
  ''
);

RETURN SELECT observation_id, project_id, task_id, scope, authority, tool_name, observation,
              payload, memory_revision, project_sequence, write_id
FROM tool_observation
WHERE project_id = $project_id
  AND (
    ($has_task_id = false AND (task_id = NONE OR task_id = NULL))
    OR ($has_task_id = true AND task_id = $task_id)
  )
  AND (
    (<string> $entity_kind = 'agent_session'
      AND <string> payload.agent_session.agent_session_id = $entity_ref)
    OR (<string> $entity_kind = 'task_role_lease'
      AND payload.receipt_kind = 'host_role_lease_authority'
      AND <string> payload.receipt_body.role_lease_id = $entity_ref)
    OR (<string> $entity_kind = 'host_binding'
      AND payload.receipt_kind = 'host_binding_authority'
      AND <string> payload.receipt_body.agent_session_id = $entity_ref)
    OR (<string> $entity_kind = 'work_lease'
      AND (
        <string> payload.work_lease.work_lease_id = $entity_ref
        OR (payload.receipt_kind = 'work_lease'
          AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
      ))
    OR (<string> $entity_kind = 'worktree_lease'
      AND (
        <string> payload.worktree_lease.worktree_lease_id = $entity_ref
        OR (payload.receipt_kind = 'worktree_lease'
          AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
      ))
    OR (<string> $entity_kind = 'candidate_diff'
      AND payload.receipt_kind = 'candidate_diff'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'candidate_review'
      AND payload.receipt_kind = 'candidate_review'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'agent_result'
      AND payload.receipt_kind = 'agent_result'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'agent_result_disposition'
      AND payload.receipt_kind = 'agent_result_disposition'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'controller_lease'
      AND payload.receipt_kind = 'controller_lease'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'operation_job'
      AND payload.receipt_kind = 'operation_job'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'agent_invocation_request'
      AND payload.receipt_kind = 'agent_invocation_request'
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
    OR (<string> $entity_kind = 'managed_finalization'
      AND payload.receipt_kind IN ['managed_finalization_intent', 'managed_finalization_aggregate']
      AND <string> array::join(canonical_subject_ref_fragments.map(|$fragment| <string> $fragment), '') = $entity_ref)
  )
ORDER BY memory_revision DESC, project_sequence DESC, observation_id DESC
LIMIT 2;
