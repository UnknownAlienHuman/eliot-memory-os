BEGIN TRANSACTION;

LET $heads_plus_one = SELECT project_id, memory_revision
FROM scope_head
ORDER BY project_id ASC
LIMIT 10001;
IF array::len($heads_plus_one) > 10000 {
  THROW 'memory_search_cutover_project_cap_exceeded';
};
FOR $head IN $heads_plus_one {
  LET $state = SELECT *
  FROM ONLY type::record('memory_search_state', $head.project_id);
  IF $state = NONE
    OR $state.projection_format != 'fts_v1'
    OR $state.applied_revision != $head.memory_revision {
    THROW string::concat(
      'memory_search_cutover_not_ready:',
      <string> $head.project_id
    );
  };
};

REMOVE INDEX IF EXISTS idx_memory_search_token_posting ON TABLE memory_search_token;
REMOVE INDEX IF EXISTS idx_memory_search_token_handle ON TABLE memory_search_token;
REMOVE TABLE IF EXISTS memory_search_token;
UPSERT cognitive_projection_cutover:fts_v1 CONTENT {
  cutover: 'memory_search_fts_v1',
  projects_verified: array::len($heads_plus_one),
  completed_at: time::now()
};

COMMIT TRANSACTION;
RETURN {
  cutover: 'memory_search_fts_v1',
  projects_verified: array::len($heads_plus_one),
  legacy_postings_removed: true
};
