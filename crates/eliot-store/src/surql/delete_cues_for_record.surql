LET $record_ref_value = array::join($record_ref_parts, ':');
DELETE cue_index
WHERE <string> project_id = <string> $project_id
  AND record_ref = $record_ref_value;
RETURN true;
