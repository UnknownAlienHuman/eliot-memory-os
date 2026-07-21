RETURN SELECT
  task_id,
  project_id,
  title,
  status,
  acceptance_items,
  action_lease_id,
  understanding_proof_hash,
  action_provenance,
  observation_ids,
  verification_ids,
  verification_scopes,
  completion_write_id,
  memory_revision,
  project_sequence,
  write_id
FROM ONLY type::record('task_contract', $task_id);
