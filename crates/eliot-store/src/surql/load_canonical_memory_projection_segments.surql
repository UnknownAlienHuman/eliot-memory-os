LET $memory_handle = <string> array::join(
  $memory_handle_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $blob_digest_hex = <string> array::join(
  $blob_digest_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $logical_kind = <string> array::join(
  $logical_kind_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $segment_set_hash_blake3 = <string> array::join(
  $segment_set_hash_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $blob_relative_path = <string> array::join(
  $blob_relative_path_parts.map(|$fragment| <string> $fragment),
  ''
);
LET $bounded_limit = IF $limit < 1 {
  1
} ELSE IF $limit > 32 {
  32
} ELSE {
  $limit
};

RETURN SELECT
  record_id,
  receipt_body,
  receipt_body.ordinal AS ordinal
FROM canonical_record
WHERE project_id = $project_id
  AND receipt_kind = 'memory_blob_segment'
  AND subject_ref = $memory_handle
  AND receipt_body.logical_kind = $logical_kind
  AND receipt_body.segment_count = $segment_count
  AND receipt_body.segment_set_hash_blake3 = $segment_set_hash_blake3
  AND receipt_body.blob.algorithm = 'blake3'
  AND receipt_body.blob.digest_hex = $blob_digest_hex
  AND receipt_body.blob.size_bytes = $blob_size_bytes
  AND receipt_body.blob.relative_path = $blob_relative_path
ORDER BY receipt_body.ordinal ASC
START $start
LIMIT $bounded_limit;
