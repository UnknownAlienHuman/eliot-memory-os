BEGIN TRANSACTION;

LET $candidate = SELECT *
FROM memory_search_outbox
WHERE (
  (
    status IN ['pending', 'retryable']
    AND (next_attempt_at = NONE OR next_attempt_at <= <datetime> $now)
  ) OR (
    status = 'leased'
    AND lease_expires_at != NONE
    AND lease_expires_at <= <datetime> $now
  )
)
AND array::len((
  SELECT VALUE id
  FROM memory_search_outbox
  WHERE project_id = $parent.project_id
    AND status != 'applied'
    AND (
      updated_revision < $parent.updated_revision
      OR (
        updated_revision = $parent.updated_revision
        AND created_at < $parent.created_at
      )
      OR (
        updated_revision = $parent.updated_revision
        AND created_at = $parent.created_at
        AND <string> write_id < <string> $parent.write_id
      )
    )
  LIMIT 1
)) = 0
AND array::len((
  SELECT VALUE id
  FROM memory_search_outbox
  WHERE project_id = $parent.project_id
    AND status = 'leased'
    AND lease_expires_at > <datetime> $now
  LIMIT 1
)) = 0
ORDER BY created_at ASC, updated_revision ASC, write_id ASC
LIMIT 1;
LET $leased = UPDATE $candidate SET
  status = 'leased',
  lease_id = $lease_id,
  lease_owner = $lease_owner,
  lease_expires_at = <datetime> $lease_expires_at,
  attempt_count = (attempt_count ?? 0) + 1,
  updated_at = <datetime> $now
RETURN AFTER;

COMMIT TRANSACTION;
RETURN {
  rows: $leased.map(|$row| {
    RETURN {
      write_id: <string> $row.write_id,
      project_id: $row.project_id,
      updated_revision: $row.updated_revision,
      families: $row.families ?? ['search'],
      attempt_count: $row.attempt_count ?? 1
    };
  })
};
