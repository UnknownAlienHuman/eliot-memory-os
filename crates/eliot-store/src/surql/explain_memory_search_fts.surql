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
    math::max(authority_rank) AS authority_rank,
    math::max(search::score(0)) AS relevance_score
  FROM memory_search_projection
  WHERE project_id = $project_id AND search_document @0,OR@ $query_text
  GROUP BY handle
  ORDER BY relevance_score DESC, authority_rank DESC, handle ASC
  LIMIT $candidate_limit_plus_one
  EXPLAIN FULL
};
