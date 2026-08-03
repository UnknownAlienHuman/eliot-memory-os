LET $pending = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status = 'pending'
GROUP ALL;
LET $leased = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status = 'leased'
GROUP ALL;
LET $retryable = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status = 'retryable'
GROUP ALL;
LET $blocked = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status = 'blocked'
GROUP ALL;
LET $oldest = SELECT VALUE created_at
FROM memory_search_outbox
WHERE status != 'applied'
ORDER BY created_at ASC
LIMIT 1;
LET $search = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status != 'applied'
  AND (families = NONE OR families CONTAINS 'search')
GROUP ALL;
LET $cue = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status != 'applied' AND families CONTAINS 'cue'
GROUP ALL;
LET $dependency_dirty = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status != 'applied' AND families CONTAINS 'dependency_dirty'
GROUP ALL;
LET $utility = SELECT count(id) AS count
FROM memory_search_outbox
WHERE status != 'applied' AND families CONTAINS 'utility'
GROUP ALL;

RETURN {
  pending: $pending[0].count ?? 0,
  leased: $leased[0].count ?? 0,
  retryable: $retryable[0].count ?? 0,
  blocked: $blocked[0].count ?? 0,
  oldest_created_at: $oldest[0] ?? NONE,
  family_counts: {
    search: $search[0].count ?? 0,
    cue: $cue[0].count ?? 0,
    dependency_dirty: $dependency_dirty[0].count ?? 0,
    utility: $utility[0].count ?? 0
  }
};
