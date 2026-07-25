RETURN SELECT
  project_id,
  task_id,
  task_class,
  ordinal,
  arm,
  injection_mode,
  config_hash
FROM ONLY type::record('ul_task_experiment', $assignment_key);
