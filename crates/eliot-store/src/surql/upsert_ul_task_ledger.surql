BEGIN TRANSACTION;
LET $record_id = type::record('ul_task_ledger', $ledger_key);
LET $existing = SELECT * FROM ONLY $record_id;
LET $ledger = UPSERT ONLY $record_id CONTENT {
  task_id: $task_id,
  project_id: $project_id,
  injected_tokens: (IF $existing = NONE { 0 } ELSE { $existing.injected_tokens })
    + $delta.injected_tokens,
  read_tool_input_bytes: (IF $existing = NONE { 0 } ELSE { $existing.read_tool_input_bytes })
    + $delta.read_tool_input_bytes,
  read_tool_output_bytes: (IF $existing = NONE { 0 } ELSE { $existing.read_tool_output_bytes })
    + $delta.read_tool_output_bytes,
  expanded_injected_handles: (
    IF $existing = NONE { 0 } ELSE { $existing.expanded_injected_handles }
  ) + $delta.expanded_injected_handles,
  acknowledged_items: (IF $existing = NONE { 0 } ELSE { $existing.acknowledged_items })
    + $delta.acknowledged_items,
  first_mutation_seen: $delta.first_mutation_seen
    OR (IF $existing = NONE { false } ELSE { $existing.first_mutation_seen })
};
COMMIT TRANSACTION;
RETURN $ledger;
