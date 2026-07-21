RETURN SELECT
  verification_id,
  claim_id,
  project_id,
  task_id,
  write_id,
  memory_revision,
  verifier,
  result,
  summary,
  payload
FROM ONLY type::record('verification_run', $verification_id);
