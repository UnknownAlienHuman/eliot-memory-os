RETURN SELECT observation_id, project_id, task_id, scope, authority, tool_name, observation,
              payload, memory_revision, project_sequence, write_id
FROM tool_observation
WHERE write_id = $write_id
ORDER BY memory_revision ASC, project_sequence ASC
LIMIT 2;
