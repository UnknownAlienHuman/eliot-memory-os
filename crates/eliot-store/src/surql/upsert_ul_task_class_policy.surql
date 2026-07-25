LET $record_id = type::record('ul_task_class_policy', $policy_key);
RETURN UPSERT ONLY $record_id CONTENT $policy;
