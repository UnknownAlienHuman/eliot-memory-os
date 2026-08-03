LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 100 {
  100
} ELSE {
  $limit
};
LET $rows = SELECT
  project_id,
  memory_revision AS head_revision,
  (SELECT VALUE applied_revision
    FROM ONLY type::record('memory_search_state', $parent.project_id)
  ) AS search_applied_revision,
  (SELECT VALUE projection_format
    FROM ONLY type::record('memory_search_state', $parent.project_id)
  ) AS search_projection_format,
  ((SELECT count(id) AS count
    FROM memory_search_outbox
    WHERE project_id = $parent.project_id AND status = 'pending'
    GROUP ALL)[0].count ?? 0) AS pending,
  ((SELECT count(id) AS count
    FROM memory_search_outbox
    WHERE project_id = $parent.project_id AND status = 'leased'
    GROUP ALL)[0].count ?? 0) AS leased,
  ((SELECT count(id) AS count
    FROM memory_search_outbox
    WHERE project_id = $parent.project_id AND status = 'retryable'
    GROUP ALL)[0].count ?? 0) AS retryable,
  ((SELECT count(id) AS count
    FROM memory_search_outbox
    WHERE project_id = $parent.project_id AND status = 'blocked'
    GROUP ALL)[0].count ?? 0) AS blocked,
  ((SELECT VALUE created_at
    FROM memory_search_outbox
    WHERE project_id = $parent.project_id AND status = 'pending'
    ORDER BY created_at ASC
    LIMIT 1)[0] ?? NONE) AS oldest_pending_created_at
FROM scope_head
ORDER BY project_id ASC
START $start
LIMIT $bounded_limit + 1;
LET $truncated = array::len($rows) > $bounded_limit;
LET $projects = array::slice($rows, 0, $bounded_limit);
RETURN {
  projects: $projects,
  truncated: $truncated,
  next_start: IF $truncated {
    $start + array::len($projects)
  } ELSE {
    NONE
  }
};
