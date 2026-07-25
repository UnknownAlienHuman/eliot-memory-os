SELECT VALUE {
  task_id: task_id,
  project_id: project_id,
  task_class_key: task_class_key ?? '',
  arm: arm ?? NONE,
  injection_mode: injection_mode ?? NONE,
  injected_tokens: injected_tokens,
  read_tool_input_bytes: read_tool_input_bytes,
  read_tool_output_bytes: read_tool_output_bytes,
  exploration_tokens: exploration_tokens ?? 0,
  matched_baseline_tokens: matched_baseline_tokens ?? 0,
  net_token_delta: net_token_delta ?? 0,
  expanded_injected_handles: expanded_injected_handles,
  acknowledged_items: acknowledged_items,
  first_mutation_seen: first_mutation_seen
}
FROM ul_task_ledger
WHERE project_id = $project_id AND task_class_key = $task_class_key
ORDER BY task_id ASC;
