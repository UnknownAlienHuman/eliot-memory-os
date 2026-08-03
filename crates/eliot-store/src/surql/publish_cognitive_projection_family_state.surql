LET $state_record = type::record('cognitive_projection_state', $state_id);
LET $existing = SELECT * FROM ONLY $state_record;
LET $pending_dependency_dirty_raw = IF $family = 'dependency_dirty' AND $status = 'published' {
  SELECT status, blocked_reason
  FROM memory_search_outbox
  WHERE project_id = $project_id
    AND status != 'applied'
    AND string::starts_with(<string> write_id, 'dependency-dirty:')
  LIMIT 1
} ELSE {
  []
};
LET $pending_dependency_dirty = array::flatten([$pending_dependency_dirty_raw])
  .filter(|$row| $row != NONE);
LET $blocked_dependency_dirty_raw = IF array::len($pending_dependency_dirty) > 0 {
  SELECT blocked_reason
  FROM memory_search_outbox
  WHERE project_id = $project_id
    AND status = 'blocked'
    AND string::starts_with(<string> write_id, 'dependency-dirty:')
  LIMIT 1
} ELSE {
  []
};
LET $blocked_dependency_dirty = array::flatten([$blocked_dependency_dirty_raw])
  .filter(|$row| $row != NONE);
LET $effective_status = IF array::len($blocked_dependency_dirty) > 0 {
  'blocked'
} ELSE IF array::len($pending_dependency_dirty) > 0 {
  'stale'
} ELSE {
  $status
};
LET $effective_error = IF array::len($blocked_dependency_dirty) > 0 {
  $blocked_dependency_dirty[0].blocked_reason
} ELSE {
  $last_error
};
LET $existing_applied = IF $existing = NONE
  OR $existing.applied_revision = NONE {
  0
} ELSE {
  $existing.applied_revision
};
LET $incoming_applied = $applied_revision ?? 0;
LET $may_advance = $existing = NONE
  OR $target_revision > $existing.target_revision
  OR (
    $target_revision = $existing.target_revision
    AND $incoming_applied >= $existing_applied
    AND (
      $existing.status != 'published'
      OR $effective_status = 'published'
      OR ($family = 'dependency_dirty' AND array::len($pending_dependency_dirty) > 0)
    )
  );
IF $may_advance {
  UPSERT $state_record CONTENT {
    project_id: $project_id,
    family: $family,
    target_revision: $target_revision,
    applied_revision: $applied_revision,
    status: $effective_status,
    last_error: $effective_error,
    updated_at: <datetime> $now
  };
};
RETURN SELECT * FROM ONLY type::record('cognitive_projection_state', $state_id);
