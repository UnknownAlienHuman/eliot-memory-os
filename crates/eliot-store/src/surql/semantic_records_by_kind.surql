RETURN SELECT observation_id, tool_name, observation, payload, write_id, memory_revision, project_sequence
FROM tool_observation
WHERE project_id = $project_id
  AND payload.receipt_kind = $receipt_kind
ORDER BY memory_revision ASC, project_sequence ASC
LIMIT 512;
