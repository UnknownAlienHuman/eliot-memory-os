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

IF $exact_handle != '' {
  SELECT handle
  FROM memory_search_projection
  WHERE project_id = $project_id AND handle = $exact_handle
  LIMIT 1
  EXPLAIN FULL
} ELSE {
  SELECT
    handle,
    authority_rank
  FROM memory_search_projection
  WHERE project_id = $project_id AND search_document @OR@ $query_text
  ORDER BY authority_rank DESC, handle ASC
  LIMIT $candidate_limit_plus_one
  EXPLAIN FULL
};
