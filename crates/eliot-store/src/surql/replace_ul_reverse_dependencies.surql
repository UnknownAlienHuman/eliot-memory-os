BEGIN TRANSACTION;
DELETE ul_dep_reverse_index
WHERE project_id = $project_id
  AND target_kind = $target_kind
  AND target_id = $target_id;
FOR $dependency IN $dependencies {
  CREATE ul_dep_reverse_index CONTENT {
    project_id: $project_id,
    dependency_kind: $dependency.kind,
    dependency_key: $dependency.key,
    target_kind: $target_kind,
    target_id: $target_id,
    build_id: $build_id
  };
};
COMMIT TRANSACTION;
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
  AND target_kind = $target_kind
  AND target_id = $target_id
ORDER BY dependency_kind ASC, dependency_key ASC;
