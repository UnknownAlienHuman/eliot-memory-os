BEGIN TRANSACTION;
DELETE ul_artifact_dirty
WHERE project_id = $project_id
RETURN NONE;
COMMIT TRANSACTION;
RETURN { project_id: $project_id, reset: true };
