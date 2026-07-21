RETURN SELECT observation_id, project_id, task_id, scope, authority, tool_name, observation,
              payload, memory_revision, project_sequence, write_id
FROM tool_observation
WHERE project_id = $project_id
  AND task_id = $task_id
  AND payload.receipt_kind = 'experience_pattern'
  AND payload.receipt_body.pattern_id = $pattern_id
ORDER BY memory_revision DESC, project_sequence DESC
LIMIT 2;
