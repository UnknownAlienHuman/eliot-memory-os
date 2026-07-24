LET $rows = SELECT
  row_id,
  project_id,
  cue_kind,
  cue_value_norm,
  match_mode,
  record_ref,
  record_kind,
  strength,
  negative_memory,
  lifecycle,
  token_estimate
FROM cue_index
WHERE <string> project_id = <string> $project_id
ORDER BY row_id ASC
LIMIT 10001;
RETURN {
  rows: array::slice($rows, 0, 10000),
  truncated: array::len($rows) > 10000
};
