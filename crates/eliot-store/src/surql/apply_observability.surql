BEGIN TRANSACTION;

LET $receipt_id = $envelope.write_id;
LET $stored_payload = IF $envelope.kind = 'injection_receipt' {
  {
    injection_id: array::join($injection_payload.injection_id_parts, ':'),
    session_id: array::join($injection_payload.session_id_parts, ':'),
    task_id: IF $injection_payload.task_id_parts = NONE
      OR $injection_payload.task_id_parts = NULL {
      NONE
    } ELSE {
      array::join($injection_payload.task_id_parts, ':')
    },
    surface: array::join($injection_payload.surface_parts, ':'),
    item_ref: array::join($injection_payload.item_ref_parts, ':'),
    render_form: array::join($injection_payload.render_form_parts, ':'),
    fired_cues: $injection_payload.fired_cues.map(|$cue| {
      RETURN {
        kind: <string> $cue.kind,
        value: array::join($cue.value_parts, ':')
      };
    }),
    token_cost: <int> $injection_payload.token_cost,
    source_fingerprint: array::join($injection_payload.source_fingerprint_parts, ':'),
    outcome: array::join($injection_payload.outcome_parts, ':'),
    policy_reason: IF $injection_payload.policy_reason_parts = NONE
      OR $injection_payload.policy_reason_parts = NULL {
      NONE
    } ELSE {
      array::join($injection_payload.policy_reason_parts, ':')
    }
  }
} ELSE IF $envelope.kind = 'memory_influence_trace' {
  {
    task_id: array::join($memory_influence_payload.task_id_parts, ':'),
    session_id: array::join($memory_influence_payload.session_id_parts, ':'),
    memory_handle: array::join($memory_influence_payload.memory_handle_parts, ':'),
    packet_id: array::join($memory_influence_payload.packet_id_parts, ':'),
    admission_decision: <string> $memory_influence_payload.admission_decision,
    inclusion_or_suppression_reason: array::join(
      $memory_influence_payload.inclusion_reason_parts,
      ':'
    ),
    epistemic_status_at_use: array::join(
      $memory_influence_payload.epistemic_status_parts,
      ':'
    ),
    cited_in_understanding_proof: <bool> $memory_influence_payload.cited_in_understanding_proof,
    action_or_probe_changed: <bool> $memory_influence_payload.action_or_probe_changed,
    write_set_changed: <bool> $memory_influence_payload.write_set_changed,
    verifier_changed: <bool> $memory_influence_payload.verifier_changed,
    repeated_failure_prevented: <bool> $memory_influence_payload.repeated_failure_prevented,
    suppressed_as_stale_or_wrong_scope: <bool> $memory_influence_payload.suppressed_as_stale_or_wrong_scope,
    downstream_outcome_ref: IF $memory_influence_payload.downstream_outcome_ref_parts = NONE
      OR $memory_influence_payload.downstream_outcome_ref_parts = NULL {
      NONE
    } ELSE {
      array::join($memory_influence_payload.downstream_outcome_ref_parts, ':')
    },
    influence_class: <string> $memory_influence_payload.influence_class
  }
} ELSE {
  $envelope.payload
};
LET $existing_receipt =
  SELECT * FROM ONLY type::record('observability_receipt', $receipt_id);
LET $existing_immutable_record = IF $envelope.kind = 'memory_grant_offer' {
  SELECT * FROM ONLY type::record($target_table, $envelope.record_id)
} ELSE {
  NONE
};
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
} ELSE IF $existing_immutable_record != NONE {
  {
    write_id: $envelope.write_id,
    record_id: $envelope.record_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    kind: $envelope.kind,
    input_hash: $envelope.input_hash,
    status: 'rejected',
    rejected_reason: 'immutable_observability_record_conflict',
    created_at: $envelope.created_at
  }
} ELSE {
  UPSERT type::record($target_table, $envelope.record_id) CONTENT {
    record_id: $envelope.record_id,
    kind: $envelope.kind,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    session_id: $envelope.session_id,
    payload: $stored_payload,
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
