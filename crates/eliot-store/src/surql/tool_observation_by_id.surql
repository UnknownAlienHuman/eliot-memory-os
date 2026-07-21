RETURN SELECT
  observation_id,
  tool_name,
  observation,
  payload,
  write_id
FROM ONLY type::record('tool_observation', $observation_id);
