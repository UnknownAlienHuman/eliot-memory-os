DEFINE TABLE IF NOT EXISTS ul_task_experiment SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_experiment_task
  ON TABLE ul_task_experiment FIELDS project_id, task_id UNIQUE;
DEFINE INDEX OVERWRITE idx_ul_experiment_class
  ON TABLE ul_task_experiment FIELDS project_id, task_class_key, ordinal;

DEFINE TABLE IF NOT EXISTS ul_ab_counter SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_ab_counter
  ON TABLE ul_ab_counter FIELDS project_id, task_class_key UNIQUE;

DEFINE TABLE IF NOT EXISTS ul_task_class_policy SCHEMALESS;
DEFINE INDEX OVERWRITE idx_ul_policy_class
  ON TABLE ul_task_class_policy FIELDS project_id, task_class_key UNIQUE;
