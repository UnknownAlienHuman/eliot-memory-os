SELECT VALUE payload
FROM prediction_record
WHERE project_id = $project_id
  AND ($has_task_id = false OR task_id = $task_id)
  AND ($has_verifier = false OR payload.verifier = $verifier)
  AND (
    $unresolved_only = false
    OR payload.resolution = NONE
    OR payload.resolution = NULL
  )
  AND ($has_created_before = false OR created_at <= $created_before)
ORDER BY created_at ASC;
