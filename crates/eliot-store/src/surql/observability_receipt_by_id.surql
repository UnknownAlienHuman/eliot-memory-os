-- The deny-closed ObservabilityWriteReceipt contract is exactly these nine stored
-- CONTENT keys, so the readback names them instead of projecting `*`: a schemaless
-- record also carries its synthetic id, and a wildcard projection put that
-- persistence metadata into the public receipt. The Rust decode of this result stays
-- strict, so a missing or mistyped member is refused there, never defaulted.
SELECT
  write_id,
  record_id,
  project_id,
  task_id,
  kind,
  input_hash,
  status,
  rejected_reason,
  created_at
FROM ONLY type::record('observability_receipt', $write_id);
