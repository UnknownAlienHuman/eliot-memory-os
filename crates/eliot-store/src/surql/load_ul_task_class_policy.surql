RETURN SELECT
  project_id,
  task_class_key,
  injection_mode,
  treatment_tasks,
  control_tasks,
  control_median_exploration_tokens,
  treatment_median_net_delta,
  reason,
  evidence_task_ids
FROM ONLY type::record('ul_task_class_policy', $policy_key);
