BEGIN TRANSACTION;

LET $write_ids = ($write_id_parts ?? []).map(|$parts|
  <string> array::join($parts.map(|$fragment| <string> $fragment), '')
);
LET $owned = SELECT *
FROM memory_search_outbox
WHERE project_id = $project_id
  AND status = 'leased'
  AND lease_id = $lease_id
  AND lease_owner = $lease_owner
  AND lease_expires_at > <datetime> $now;
LET $owned_rows = $owned ?? [];
LET $bound_write_ids = ($write_ids ?? []).map(|$write_id| <string> $write_id);
LET $bound_families = $families ?? [];
LET $matching = $owned_rows.filter(|$row|
  <string> $row.write_id IN $bound_write_ids
  AND $row.updated_revision <= $through_revision
);
LET $matching_rows = $matching ?? [];
LET $owned_revisions = $owned_rows.map(|$row| $row.updated_revision);
LET $owned_families = array::distinct(array::flatten(
  $owned_rows.map(|$row| $row.families ?? [])
));
LET $family_set_matches = array::len($owned_families) = array::len($bound_families)
  AND array::len($owned_families.filter(|$family| !($family IN $bound_families))) = 0
  AND array::len($bound_families.filter(|$family| !($family IN $owned_families))) = 0;
LET $lease_mismatch = IF array::len($owned_rows) != array::len($bound_write_ids) {
  'cognitive_projection_lease_mismatch:owned_count'
} ELSE IF array::len($matching_rows) != array::len($owned_rows) {
  'cognitive_projection_lease_mismatch:row_set'
} ELSE IF math::max($owned_revisions) != $through_revision {
  'cognitive_projection_lease_mismatch:through_revision'
} ELSE IF !$family_set_matches {
  'cognitive_projection_lease_mismatch:family_set'
} ELSE {
  NONE
};
IF $lease_mismatch != NONE {
  THROW $lease_mismatch;
};
LET $updated = UPDATE $matching_rows SET
  status = 'retryable',
  lease_id = NONE,
  lease_owner = NONE,
  lease_expires_at = NONE,
  next_attempt_at = <datetime> $next_attempt_at,
  last_error = $error,
  blocked_reason = NONE,
  updated_at = <datetime> $now
RETURN AFTER;

IF $families CONTAINS 'dependency_dirty' {
  LET $state_id = type::record('cognitive_projection_state', $dependency_state_id);
  LET $state = SELECT * FROM ONLY $state_id;
  UPSERT $state_id CONTENT {
    project_id: $project_id,
    family: 'dependency_dirty',
    target_revision: IF $state = NONE {
      $through_revision
    } ELSE {
      math::max([$state.target_revision, $through_revision])
    },
    applied_revision: IF $state = NONE { NONE } ELSE { $state.applied_revision },
    status: IF $state != NONE AND $state.status = 'blocked' {
      'blocked'
    } ELSE {
      'stale'
    },
    last_error: IF $state != NONE AND $state.status = 'blocked' {
      $state.last_error
    } ELSE {
      $error
    },
    updated_at: <datetime> $now
  };
};

COMMIT TRANSACTION;
RETURN { rows_updated: array::len($updated) };
