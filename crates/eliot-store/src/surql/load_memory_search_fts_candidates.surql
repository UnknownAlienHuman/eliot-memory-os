LET $head = SELECT * FROM ONLY type::record('scope_head', $project_id);
LET $state = SELECT * FROM ONLY type::record('memory_search_state', $project_id);
LET $bounded_candidate_limit = IF $candidate_limit < 1 {
  1
} ELSE IF $candidate_limit > 256 {
  256
} ELSE {
  $candidate_limit
};
LET $candidate_limit_plus_one = $bounded_candidate_limit + 1;
LET $exact_handle = IF $exact_handle_parts != NONE AND $exact_handle_parts != NULL {
  <string> array::join(
    array::flatten([$exact_handle_parts]).map(|$fragment| <string> $fragment),
    ''
  )
} ELSE {
  ''
};
LET $exact_raw = IF $exact_handle != '' {
  SELECT VALUE handle
  FROM memory_search_projection
  WHERE project_id = $project_id AND handle = $exact_handle
  LIMIT 1
} ELSE {
  []
};
LET $exact_handles = array::flatten([$exact_raw])
  .filter(|$handle| $handle != NONE AND $handle != NULL);
LET $fts_raw = IF array::len($exact_handles) > 0
  OR $query_text == NONE
  OR $query_text == NULL
  OR string::trim(<string> $query_text) == '' {
  []
} ELSE {
  SELECT
    handle,
    authority_rank
  FROM memory_search_projection
  WHERE project_id = $project_id AND search_document @OR@ $query_text
  ORDER BY authority_rank DESC, handle ASC
  LIMIT $candidate_limit_plus_one
};
LET $fts_hits = array::flatten([$fts_raw])
  .filter(|$row| $row != NONE AND $row != NULL);
LET $fts_handles = array::flatten([$fts_hits.handle])
  .filter(|$handle| $handle != NONE AND $handle != NULL AND $handle != $exact_handle);
LET $ordered_handles = array::distinct(array::flatten([$exact_handles, $fts_handles]));
LET $capped_handles = array::slice($ordered_handles, 0, $bounded_candidate_limit);
LET $rows_raw = IF array::len($capped_handles) = 0 {
  []
} ELSE {
  SELECT
    record_ref,
    handle,
    record_kind AS record_type,
    preview,
    search_text,
    cue_text,
    scope_text,
    concept_text,
    task_id,
    status,
    lifecycle AS lifecycle_state,
    authority_rank,
    negative_memory,
    memory_revision,
    project_sequence,
    verification_value,
    known_decision_delta,
    prior_beneficial_use,
    contradiction_signal,
    harm_signal,
    repetition_signal,
    distraction_signal
  FROM memory_search_projection
  WHERE project_id = $project_id AND handle IN $capped_handles
  LIMIT $bounded_candidate_limit
};
LET $rows = array::flatten([$rows_raw])
  .filter(|$row| $row != NONE AND $row != NULL);

RETURN {
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  projection_revision: IF $state == NONE { NONE } ELSE { $state.applied_revision },
  projection_format: IF $state == NONE { NONE } ELSE { $state.projection_format },
  ordered_handles: $capped_handles,
  candidates: $rows,
  truncated: array::len($ordered_handles) > $bounded_candidate_limit,
};
