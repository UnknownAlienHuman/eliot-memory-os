LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 512 {
  512
} ELSE {
  $limit
};

RETURN SELECT
  project_id,
  target_kind,
  target_id,
  build_id,
  dirty,
  reasons,
  first_dirty_at,
  updated_at
FROM ul_artifact_dirty
WHERE project_id = $project_id
  AND dirty = true
ORDER BY first_dirty_at ASC, target_kind ASC, target_id ASC
LIMIT $bounded_limit;
