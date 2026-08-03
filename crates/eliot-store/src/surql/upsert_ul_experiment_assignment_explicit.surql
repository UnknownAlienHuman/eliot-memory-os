BEGIN TRANSACTION;
LET $assignment_id = type::record('ul_task_experiment', $assignment_key);
LET $existing = SELECT * FROM ONLY $assignment_id;
IF $existing != NONE AND (
  $existing.project_id != $project_id
  OR $existing.task_id != $task_id
  OR $existing.task_class != $task_class
  OR $existing.task_class_key != $task_class_key
  OR $existing.ordinal != 0
  OR $existing.arm != $arm
  OR $existing.injection_mode != $injection_mode
  OR $existing.config_hash != $config_hash
) {
  THROW 'ul_explicit_assignment_conflict';
};
LET $assignment = IF $existing != NONE {
  $existing
} ELSE {
  UPSERT ONLY $assignment_id CONTENT {
    project_id: $project_id,
    task_id: $task_id,
    task_class: $task_class,
    task_class_key: $task_class_key,
    ordinal: 0,
    arm: $arm,
    injection_mode: $injection_mode,
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
