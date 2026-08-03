BEGIN TRANSACTION;

LET $receipt_id = $batch.write_id;
LET $existing_receipt =
  SELECT * FROM ONLY type::record('observability_receipt', $receipt_id);
LET $result = IF $existing_receipt != NONE {
  IF $existing_receipt.input_hash == $batch.input_hash {
    {
      write_id: $existing_receipt.write_id,
      record_id: $existing_receipt.record_id,
      project_id: $existing_receipt.project_id,
      task_id: $existing_receipt.task_id,
      kind: $existing_receipt.kind,
      input_hash: $existing_receipt.input_hash,
      status: 'idempotent_replay',
      rejected_reason: $existing_receipt.rejected_reason,
      created_at: $existing_receipt.created_at
    }
  } ELSE {
    {
      write_id: $existing_receipt.write_id,
      record_id: $existing_receipt.record_id,
      project_id: $existing_receipt.project_id,
      task_id: $existing_receipt.task_id,
      kind: $existing_receipt.kind,
      input_hash: $batch.input_hash,
      status: 'rejected',
      rejected_reason: 'pending_injection_batch_write_id_conflict',
      created_at: $existing_receipt.created_at
    }
  }
} ELSE {
  DELETE pending_injection
  WHERE <string> project_id = <string> $batch.project_id
    AND <string> session_id = <string> $batch.session_id;
  FOR $row IN $rows {
    UPSERT type::record('pending_injection', $row.record_id) CONTENT {
      record_id: $row.record_id,
      kind: 'pending_injection',
      project_id: $batch.project_id,
      task_id: $batch.task_id,
      session_id: $batch.session_id,
      payload_b64: $row.payload_b64,
      batch_write_id: $batch.write_id,
      input_hash: $row.input_hash,
      created_at: $batch.created_at
    };
  };
  UPSERT type::record('observability_receipt', $receipt_id) CONTENT {
    write_id: $batch.write_id,
    record_id: $batch.write_id,
    project_id: $batch.project_id,
    task_id: $batch.task_id,
    kind: 'pending_injection',
    input_hash: $batch.input_hash,
    status: 'committed',
    rejected_reason: NONE,
    created_at: $batch.created_at
  };
  SELECT * FROM ONLY type::record('observability_receipt', $receipt_id)
};

COMMIT TRANSACTION;
RETURN $result;
