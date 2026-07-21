RETURN SELECT
  claim_id,
  project_id,
  task_id,
  scope,
  status,
  lifecycle_status,
  visibility,
  taint,
  authority,
  statement,
  payload,
  memory_revision,
  project_sequence,
  write_id
FROM type::record('claim_card', $claim_id)
WHERE project_id = $project_id
LIMIT 1;
