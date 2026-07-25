RETURN SELECT
  project_id,
  {
    kind: dependency_kind,
    key: dependency_key
  } AS dependency,
  dependency_kind,
  dependency_key,
  target_kind,
  target_id,
  build_id
FROM ul_dep_reverse_index
WHERE project_id = $project_id
  AND dependency_kind IN $dependency_kinds
  AND dependency_key IN $dependency_keys
ORDER BY target_kind ASC, target_id ASC, dependency_kind ASC, dependency_key ASC
LIMIT 4096;
