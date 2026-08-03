RETURN SELECT
  project_id,
  family,
  target_revision,
  applied_revision,
  status,
  last_error,
  updated_at
FROM cognitive_projection_state
WHERE project_id = $project_id
ORDER BY family ASC
LIMIT 4;
