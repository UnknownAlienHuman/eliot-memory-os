LET $requested_handle = <string> array::join(
  $memory_handle_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $requested_segment_record_id = <string> array::join(
  $requested_segment_record_id_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 1 {
  1
} ELSE {
  $limit
};
LET $limit_plus_one = $bounded_limit + 1;
LET $requested_segment_rows = IF $requested_is_segment {
  SELECT VALUE receipt_body_json_b64
  FROM type::record('canonical_record', $requested_segment_record_id)
  WHERE project_id = $project_id
    AND receipt_kind = 'memory_blob_segment'
  LIMIT 1
} ELSE {
  []
};
LET $manifest_rows = IF $requested_is_segment {
  []
} ELSE {
  SELECT VALUE receipt_body_json_b64
  FROM canonical_record
  WHERE project_id = $project_id
    AND receipt_kind = 'memory_blob_manifest'
    AND subject_ref = $requested_handle
  ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
  START $start
  LIMIT $limit_plus_one
};
LET $lossless_segment_rows = array::flatten([$requested_segment_rows]);
LET $lossless_manifest_rows = array::flatten([$manifest_rows]);
IF array::len($lossless_segment_rows.filter(|$row| {
  $row != NONE AND $row != NULL AND $row != ''
})) != array::len($lossless_segment_rows) {
  THROW 'canonical_l2_segment_body_not_lossless';
};
IF array::len($lossless_manifest_rows.filter(|$row| {
  $row != NONE AND $row != NULL AND $row != ''
})) != array::len($lossless_manifest_rows) {
  THROW 'canonical_l2_manifest_body_not_lossless';
};

RETURN {
  requested_segment_body_b64: $lossless_segment_rows[0] ?? NONE,
  manifest_bodies_b64: array::slice($lossless_manifest_rows, 0, $bounded_limit),
  truncated: !$requested_is_segment
    AND array::len($lossless_manifest_rows) > $bounded_limit,
};
