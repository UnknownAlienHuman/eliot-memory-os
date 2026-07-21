LET $revision = $envelope.project_sequence_hint;
LET $sequence = $envelope.project_sequence_hint;
LET $receipt_id = $envelope.write_id;
LET $canonical_kinds = [
  'state_transition',
  'memory_trajectory_correctness',
  'minority_pressure_record',
  'memory_influence_report',
  'replay_run',
  'replay_audit',
  'trace_completeness_contract',
  'replay_set',
  'replay_case',
  'replay_input_snapshot',
  'sealed_replay_run',
  'harness_experiment',
  'harness_disposition',
  'meta_metric_evidence',
  'meta_isolation_rejection',
  'experimental_policy_candidate',
  'meta_policy_promotion',
  'meta_policy_rollback',
  'sleep_consolidation_bundle',
  'sleep_consolidation_run',
  'procedure_candidate',
  'procedure_skill_candidate',
  'procedure_promotion_disposition',
  'forgetting_candidate',
  'test_candidate',
  'replay_case_candidate',
  'dream_candidate',
  'autonomy_run_contract',
  'autonomy_run_transition',
  'autonomy_budget_ledger',
  'autonomy_work_graph',
  'autonomy_tripwire',
  'autonomy_recovery',
  'autonomy_approval_request',
  'autonomy_approval_decision',
  'autonomy_approval_consumption',
  'candidate_diff',
  'candidate_review',
  'agent_result',
  'agent_result_disposition',
  'worktree_lease',
  'work_lease',
  'controller_lease',
  'operation_job',
  'agent_invocation_request',
  'managed_finalization_intent',
  'managed_finalization_aggregate',
  'operator_control_request',
  'cognitive_run_contract',
  'cognitive_run_attempt',
  'cognitive_tool_observation',
  'cognitive_raw_verifier',
  'cognitive_run_terminal'
];
LET $existing_receipt = SELECT * FROM ONLY type::record('write_receipt', $receipt_id);
LET $idempotency_result = IF $existing_receipt != NONE {
  IF $existing_receipt.input_hash == $envelope.input_hash {
    {
      receipt_id: $existing_receipt.receipt_id,
      write_id: $existing_receipt.write_id,
      input_hash: $existing_receipt.input_hash,
      project_id: $existing_receipt.project_id,
      task_id: $existing_receipt.task_id,
      command_kind: $existing_receipt.command_kind,
      status: 'idempotent_replay',
      memory_revision: $existing_receipt.memory_revision,
      project_sequence: $existing_receipt.project_sequence,
      created_records: $existing_receipt.created_records,
      created_relations: $existing_receipt.created_relations,
      weak_records: $existing_receipt.weak_records,
      rejected_reason: $existing_receipt.rejected_reason,
      db_operation_id: $existing_receipt.db_operation_id,
      created_at: $existing_receipt.created_at
    }
  } ELSE {
    {
      receipt_id: $receipt_id,
      write_id: $envelope.write_id,
      input_hash: $envelope.input_hash,
      project_id: $envelope.project_id,
      task_id: $envelope.task_id,
      command_kind: $envelope.command_kind,
      status: 'rejected',
      memory_revision: $existing_receipt.memory_revision,
      project_sequence: $existing_receipt.project_sequence,
      created_records: [],
      created_relations: [],
      weak_records: [],
      rejected_reason: 'write_id_input_hash_conflict',
      db_operation_id: $envelope.operation_id,
      created_at: time::now()
    }
  }
} ELSE {
  NONE
};

IF $idempotency_result == NONE {
UPSERT type::record('scope_head', $envelope.project_id) CONTENT {
  project_id: $envelope.project_id,
  scope: $envelope.scope,
  memory_revision: $revision,
  project_sequence: $sequence,
  last_write_id: $envelope.write_id,
  updated_at: time::now()
};

FOR $task IN $envelope.task_contracts {
  LET $existing_task = SELECT * FROM ONLY type::record('task_contract', $task.task_id);
  IF $task.expected_revision != NONE AND $task.expected_revision != NULL AND (
    $existing_task == NONE OR $existing_task.memory_revision != $task.expected_revision
  ) {
    THROW string::concat('stale_task_revision:', <string> $task.task_id);
  };
  UPSERT type::record('task_contract', $task.task_id) CONTENT {
    task_id: $task.task_id,
    project_id: $envelope.project_id,
    title: $task.title,
    status: $task.status,
    acceptance_items: $task.acceptance_items,
    action_lease_id: $task.action_lease_id,
    understanding_proof_hash: $task.understanding_proof_hash,
    action_provenance: $task.action_provenance,
    observation_ids: $task.observation_ids,
    verification_ids: $task.verification_ids,
    verification_scopes: $task.verification_scopes,
    completion_write_id: $task.completion_write_id,
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: IF $existing_task == NONE { time::now() } ELSE { $existing_task.created_at },
    updated_at: time::now()
  };
};

FOR $source IN $envelope.source_snapshots {
  UPSERT type::record('source_snapshot', $source.source_id) CONTENT {
    source_id: $source.source_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: 'observed',
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $source.authority,
    uri: $source.uri,
    content_hash: $source.content_hash,
    excerpt: $source.excerpt,
    source_refs: [],
    evidence_refs: [],
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };
};

FOR $evidence IN $envelope.evidence_atoms {
  UPSERT type::record('evidence_atom', $evidence.evidence_id) CONTENT {
    evidence_id: $evidence.evidence_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: 'observed',
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $envelope.authority,
    source_refs: [$evidence.source_id],
    evidence_refs: [],
    summary: $evidence.summary,
    payload: $evidence.payload,
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };
};

FOR $observation IN $envelope.tool_observations {
  LET $canonical_payload = $canonical_payloads.filter(|$payload| {
    <string> $payload.observation_id = <string> $observation.observation_id
  })[0];
  UPSERT type::record('tool_observation', $observation.observation_id) CONTENT {
    observation_id: $observation.observation_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: 'observed',
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $envelope.authority,
    tool_name: $observation.tool_name,
    observation: $observation.observation,
    payload: $observation.payload,
    canonical_subject_ref_fragments: $canonical_payload.subject_ref_fragments,
    source_refs: [],
    evidence_refs: [],
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };

  IF $observation.payload.receipt_kind IN $canonical_kinds
    AND $observation.payload.receipt_body != NONE
    AND $observation.payload.receipt_body != NULL
    AND $canonical_payload != NONE {
    LET $body = $observation.payload.receipt_body;
    LET $subject_ref = <string> array::join(
      $canonical_payload.subject_ref_fragments.map(|$fragment| <string> $fragment),
      ''
    );
    LET $trace_ref = <string> array::join(
      $canonical_payload.trace_ref_fragments.map(|$fragment| <string> $fragment),
      ''
    );
    LET $candidate_id = <string> array::join(
      $canonical_payload.candidate_id_fragments.map(|$fragment| <string> $fragment),
      ''
    );
    LET $canonical_action = <string> array::join(
      $canonical_payload.action_fragments.map(|$fragment| <string> $fragment),
      ''
    );

    UPSERT type::record('canonical_record', $observation.observation_id) CONTENT {
      record_id: $observation.observation_id,
      receipt_kind: $observation.payload.receipt_kind,
      project_id: $envelope.project_id,
      task_id: $envelope.task_id,
      subject_ref: $subject_ref,
      trace_ref: $trace_ref,
      candidate_id: $candidate_id,
      canonical_action: $canonical_action,
      receipt_body: $body,
      receipt_body_json_b64: <string> $canonical_payload.receipt_body_json_b64,
      canonical_receipt: {
        receipt_id: $receipt_id,
        write_id: $envelope.write_id
      },
      memory_revision: $revision,
      project_sequence: $sequence,
      write_id: $envelope.write_id,
      input_hash: $envelope.input_hash,
      created_at: $envelope.created_at,
      updated_at: $envelope.created_at
    };
  };
};

FOR $claim IN $envelope.claims {
  UPSERT type::record('claim_card', $claim.claim_id) CONTENT {
    claim_id: $claim.claim_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: $claim.status,
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $envelope.authority,
    statement: $claim.statement,
    payload: $claim.payload,
    source_refs: [],
    evidence_refs: [],
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };
};

FOR $verification IN $envelope.verification_runs {
  UPSERT type::record('verification_run', $verification.verification_id) CONTENT {
    verification_id: $verification.verification_id,
    claim_id: $verification.claim_id,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: $verification.result,
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $envelope.authority,
    verifier: $verification.verifier,
    result: $verification.result,
    summary: $verification.summary,
    payload: $verification.payload,
    source_refs: [],
    evidence_refs: [],
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };
};

FOR $failure IN $envelope.failures {
  UPSERT type::record('failure_fingerprint', $failure.fingerprint) CONTENT {
    fingerprint: $failure.fingerprint,
    project_id: $envelope.project_id,
    task_id: $envelope.task_id,
    scope: $envelope.scope,
    status: 'observed',
    lifecycle_status: $envelope.lifecycle.status,
    visibility: $envelope.lifecycle.visibility,
    taint: $envelope.lifecycle.taint,
    authority: $envelope.authority,
    summary: $failure.summary,
    payload: $failure.payload,
    source_refs: [],
    evidence_refs: [],
    memory_revision: $revision,
    project_sequence: $sequence,
    write_id: $envelope.write_id,
    created_at: time::now(),
    updated_at: time::now()
  };
};

FOR $relation IN $envelope.relations {
  UPSERT type::record(<string> $relation.relation_type, string::concat($envelope.write_id, '-', $relation.from, '-', $relation.to)) CONTENT {
    relation_type: $relation.relation_type,
    project_id: $envelope.project_id,
    from: $relation.from,
    to: $relation.to,
    write_id: $envelope.write_id,
    memory_revision: $revision,
    project_sequence: $sequence,
    created_at: time::now()
  };
};

UPSERT type::record('memory_transition', $envelope.write_id) CONTENT {
  project_id: $envelope.project_id,
  task_id: $envelope.task_id,
  scope: $envelope.scope,
  write_id: $envelope.write_id,
  operation_id: $envelope.operation_id,
  command_kind: $envelope.command_kind,
  memory_revision: $revision,
  project_sequence: $sequence,
  created_at: time::now()
};

UPSERT type::record('write_receipt', $receipt_id) CONTENT {
  receipt_id: $receipt_id,
  write_id: $envelope.write_id,
  input_hash: $envelope.input_hash,
  project_id: $envelope.project_id,
  task_id: $envelope.task_id,
  command_kind: $envelope.command_kind,
  status: 'committed',
  memory_revision: $revision,
  project_sequence: $sequence,
  created_records: array::concat(
    $envelope.task_contracts.*.task_id,
    $envelope.source_snapshots.*.source_id,
    $envelope.evidence_atoms.*.evidence_id,
    $envelope.tool_observations.*.observation_id,
    $envelope.tool_observations[WHERE payload.receipt_kind IN $canonical_kinds].map(|$observation| {
      string::concat('canonical_record:', <string> $observation.observation_id)
    }),
    $envelope.claims.*.claim_id,
    $envelope.verification_runs.*.verification_id
  ),
  created_relations: $envelope.relations.*.relation_type,
  weak_records: $envelope.claims[WHERE status = 'candidate'].*.claim_id,
  rejected_reason: NONE,
  db_operation_id: $envelope.operation_id,
  created_at: $envelope.created_at
};

};

RETURN IF $idempotency_result != NONE {
  $idempotency_result
} ELSE {
  SELECT * FROM ONLY type::record('write_receipt', $receipt_id)
};
