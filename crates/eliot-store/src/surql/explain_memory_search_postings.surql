SELECT handle
FROM memory_search_token
WHERE project_id = $project_id AND token IN $tokens
LIMIT $candidate_limit
EXPLAIN FULL;
