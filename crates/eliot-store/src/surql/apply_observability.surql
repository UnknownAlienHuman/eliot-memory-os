BEGIN TRANSACTION;

LET $receipt_id = $envelope.write_id;
LET $existing_receipt =
  SELECT * FROM ONLY type::record('observability_receipt', $receipt_id);
LET $result = IF $existing_receipt != NONE {
  IF $existing_receipt.input_hash == $envelope.input_hash {
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
      input_hash: $envelope.input_hash,
      status: 'rejected',
      rejected_reason: 'observability_write_id_conflict',
      created_at: $existing_receipt.created_at
    }
  }
} ELSE {
  UPSERT type::record($target_table, $envelope.record_id) CONTENT {
    record_id: $envelope.record_id,
    kind: $envelope.kind,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    session_id: $envelope.session_id,
    payload: $envelope.payload,
    write_id: $envelope.write_id,
    input_hash: $envelope.input_hash,
    created_at: $envelope.created_at
  };
  UPSERT type::record('observability_receipt', $receipt_id) CONTENT {
    write_id: $envelope.write_id,
    record_id: $envelope.record_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    kind: $envelope.kind,
    input_hash: $envelope.input_hash,
    status: 'committed',
    rejected_reason: NONE,
    created_at: $envelope.created_at
  };
  SELECT * FROM ONLY type::record('observability_receipt', $receipt_id)
};

COMMIT TRANSACTION;
RETURN $result;
