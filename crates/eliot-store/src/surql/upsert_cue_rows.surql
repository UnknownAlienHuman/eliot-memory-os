BEGIN TRANSACTION;
IF $replace_project {
  DELETE cue_index
  WHERE <string> project_id = <string> $project_id;
} ELSE {
  DELETE cue_index
  WHERE <string> project_id = <string> $project_id
    AND record_ref_key = $record_ref_key;
};
FOR $row IN $rows {
  LET $row_id_value = array::join($row.row_id_parts, ':');
  LET $cue_value = array::join($row.cue_value_parts, ':');
  LET $row_record_ref = array::join($row.record_ref_parts, ':');
  UPSERT type::record('cue_index', $row_id_value) CONTENT {
    row_id: $row_id_value,
    project_id: <string> $row.project_id,
    cue_kind: <string> $row.cue_kind,
    cue_value_norm: $cue_value,
    match_mode: <string> $row.match_mode,
    record_ref: $row_record_ref,
    record_ref_parts: $row.record_ref_parts,
    record_ref_key: <string> $row.record_ref_key,
    record_kind: <string> $row.record_kind,
    strength: <string> $row.strength,
    negative_memory: <bool> $row.negative_memory,
    lifecycle: <string> $row.lifecycle,
    token_estimate: <int> $row.token_estimate
  };
};
COMMIT TRANSACTION;
RETURN true;
