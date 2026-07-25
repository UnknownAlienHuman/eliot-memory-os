BEGIN TRANSACTION;
LET $assignment_id = type::record('ul_task_experiment', $assignment_key);
LET $counter_id = type::record('ul_ab_counter', $counter_key);
LET $existing = SELECT * FROM ONLY $assignment_id;
LET $counter = SELECT * FROM ONLY $counter_id;
LET $ordinal = IF $existing != NONE {
  $existing.ordinal
} ELSE IF $counter = NONE {
  1
} ELSE {
  $counter.ordinal + 1
};
LET $counter_write = IF $existing = NONE {
  UPSERT ONLY $counter_id CONTENT {
    project_id: $project_id,
    task_class_key: $task_class_key,
    ordinal: $ordinal
  }
} ELSE {
  $counter
};
LET $assignment = IF $existing != NONE {
  $existing
} ELSE {
  UPSERT ONLY $assignment_id CONTENT {
    project_id: $project_id,
    task_id: $task_id,
    task_class: $task_class,
    task_class_key: $task_class_key,
    ordinal: $counter_write.ordinal,
    arm: IF $counter_write.ordinal % 2 = 1 { 'control' } ELSE { 'treatment' },
    injection_mode: 'payload',
    config_hash: $config_hash
  }
};
COMMIT TRANSACTION;
RETURN {
  project_id: $assignment.project_id,
  task_id: $assignment.task_id,
  task_class: $assignment.task_class,
  ordinal: $assignment.ordinal,
  arm: $assignment.arm,
  injection_mode: $assignment.injection_mode,
  config_hash: $assignment.config_hash
};
