BEGIN TRANSACTION;

LET $event_id = <string> array::join(
  $event_id_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $record_id = type::record('memory_search_outbox', $intent_id);
IF $families CONTAINS 'utility' {
  THROW 'utility_projection_is_unavailable_until_phase2';
};
LET $existing = SELECT * FROM ONLY $record_id;
IF $existing = NONE {
  UPSERT $record_id CONTENT {
    write_id: $event_id,
    project_id: $project_id,
    updated_revision: $updated_revision,
    families: $families,
    status: 'pending',
    attempt_count: 0,
    next_attempt_at: <datetime> $now,
    created_at: <datetime> $now,
    updated_at: <datetime> $now
  };
} ELSE IF $existing.project_id != $project_id
  OR $existing.updated_revision != $updated_revision
  OR $existing.families != $families {
  THROW 'cognitive_projection_intent_id_conflict';
} ELSE IF $rearm_applied AND $existing.status = 'applied' {
  UPDATE $record_id SET
    status = 'pending',
    attempt_count = 0,
    lease_id = NONE,
    lease_owner = NONE,
    lease_expires_at = NONE,
    next_attempt_at = <datetime> $now,
    last_error = NONE,
    blocked_reason = NONE,
    applied_at = NONE,
    updated_at = <datetime> $now;
};

LET $result = SELECT * FROM ONLY $record_id;
IF $mark_dependency_dirty_stale
  AND $result.status IN ['pending', 'retryable', 'leased'] {
  LET $state_id = type::record('cognitive_projection_state', $dependency_state_id);
  LET $state = SELECT * FROM ONLY $state_id;
  LET $target_revision = IF $state = NONE {
    $updated_revision
  } ELSE {
    math::max([$state.target_revision, $updated_revision])
  };
  UPSERT $state_id CONTENT {
    project_id: $project_id,
    family: 'dependency_dirty',
    target_revision: $target_revision,
    applied_revision: IF $state = NONE { NONE } ELSE { $state.applied_revision },
    status: IF $state != NONE AND $state.status = 'blocked' {
      'blocked'
    } ELSE {
      'stale'
    },
    last_error: IF $state != NONE AND $state.status = 'blocked' {
      $state.last_error
    } ELSE {
      NONE
    },
    updated_at: <datetime> $now
  };
};
COMMIT TRANSACTION;
RETURN {
  event_id: <string> $result.write_id,
  project_id: $result.project_id,
  updated_revision: $result.updated_revision,
  families: $result.families,
  status: $result.status
};
