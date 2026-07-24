SELECT VALUE payload
FROM type::table($target_table)
WHERE project_id = $project_id
  AND kind = $kind
  AND ($has_task_id = false OR task_id = $task_id)
ORDER BY created_at ASC;
