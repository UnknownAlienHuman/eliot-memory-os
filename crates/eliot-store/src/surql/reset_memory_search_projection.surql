DELETE memory_search_token WHERE project_id = $project_id;
DELETE memory_search_projection WHERE project_id = $project_id;
DELETE type::record('memory_search_state', $project_id);
RETURN { project_id: $project_id, reset: true };
