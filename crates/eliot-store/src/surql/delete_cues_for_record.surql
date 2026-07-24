DELETE cue_index
WHERE <string> project_id = <string> $project_id
  AND record_ref_key = $record_ref_key;
RETURN true;
