LET $memory_handle = <string> array::join(
  $memory_handle_parts.map(|$fragment| <string> $fragment),
  ''
);
IF $child_kind != 'segment' AND $child_kind != 'cue_page' {
  THROW 'canonical_capacity_unknown_child_kind';
};
LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 1 {
  1
} ELSE {
  $limit
};
LET $limit_plus_one = $bounded_limit + 1;
LET $raw_rows = IF $child_kind = 'segment' {
  SELECT VALUE receipt_body_json_b64
  FROM canonical_record
  WHERE project_id = $project_id
    AND receipt_kind = 'memory_blob_segment'
    AND subject_ref = <string> $memory_handle
  ORDER BY record_id ASC
  START $start
  LIMIT $limit_plus_one
} ELSE {
  SELECT VALUE receipt_body_json_b64
  FROM canonical_record
  WHERE project_id = $project_id
    AND receipt_kind = 'cue_binding_page'
    AND subject_ref = <string> $memory_handle
  ORDER BY record_id ASC
  START $start
  LIMIT $limit_plus_one
};
LET $rows = array::flatten([$raw_rows]);
IF array::len($rows.filter(|$row| $row != NONE AND $row != NULL AND $row != '')) != array::len($rows) {
  THROW 'canonical_capacity_child_body_not_lossless';
};

RETURN {
  bodies_b64: array::slice($rows, 0, $bounded_limit),
  truncated: array::len($rows) > $bounded_limit,
};
