LET $updated = UPDATE ul_artifact_dirty
SET
  dirty = false,
  reasons = [],
  build_id = $superseding_build_id,
  updated_at = time::now()
WHERE project_id = $project_id
  AND target_kind = $target_kind
  AND target_id = $target_id
RETURN AFTER;
RETURN array::first($updated);
