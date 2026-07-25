BEGIN TRANSACTION;
LET $record_id = type::record('ul_task_ledger', $ledger_key);
LET $existing = SELECT * FROM ONLY $record_id;
LET $injected_tokens = (IF $existing = NONE { 0 } ELSE { $existing.injected_tokens })
  + $delta.injected_tokens;
LET $read_tool_input_bytes =
  (IF $existing = NONE { 0 } ELSE { $existing.read_tool_input_bytes })
  + $delta.read_tool_input_bytes;
LET $read_tool_output_bytes =
  (IF $existing = NONE { 0 } ELSE { $existing.read_tool_output_bytes })
  + $delta.read_tool_output_bytes;
LET $matched_baseline_tokens = IF $delta.matched_baseline_tokens > 0 {
  $delta.matched_baseline_tokens
} ELSE IF $existing = NONE {
  0
} ELSE {
  $existing.matched_baseline_tokens ?? 0
};
LET $ledger = UPSERT ONLY $record_id CONTENT {
  task_id: $task_id,
  project_id: $project_id,
  task_class_key: IF string::len($delta.task_class_key) > 0 {
    $delta.task_class_key
  } ELSE IF $existing = NONE {
    ''
  } ELSE {
    $existing.task_class_key ?? ''
  },
  arm: IF $delta.arm != NONE {
    $delta.arm
  } ELSE IF $existing = NONE {
    NONE
  } ELSE {
    $existing.arm ?? NONE
  },
  injection_mode: IF $delta.injection_mode != NONE {
    $delta.injection_mode
  } ELSE IF $existing = NONE {
    NONE
  } ELSE {
    $existing.injection_mode ?? NONE
  },
  injected_tokens: $injected_tokens,
  read_tool_input_bytes: $read_tool_input_bytes,
  read_tool_output_bytes: $read_tool_output_bytes,
  exploration_tokens: ($read_tool_input_bytes + $read_tool_output_bytes + 3) / 4,
  matched_baseline_tokens: $matched_baseline_tokens,
  net_token_delta: <int> $injected_tokens - <int> $matched_baseline_tokens,
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
