SELECT VALUE {
  task_id: task_id,
  project_id: project_id,
  injected_tokens: injected_tokens,
  read_tool_input_bytes: read_tool_input_bytes,
  read_tool_output_bytes: read_tool_output_bytes,
  expanded_injected_handles: expanded_injected_handles,
  acknowledged_items: acknowledged_items,
  first_mutation_seen: first_mutation_seen
}
FROM ul_task_ledger
WHERE project_id = $project_id
ORDER BY task_id ASC;
