LET $record_id = type::record('ul_artifact_dirty', $state_key);
RETURN UPSERT ONLY $record_id CONTENT $state;
