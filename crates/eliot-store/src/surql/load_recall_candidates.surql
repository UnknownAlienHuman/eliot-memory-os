LET $head = SELECT * FROM ONLY type::record('scope_head', $project_id);
LET $page_limit_plus_one = $limit + 1;

-- Retrieval is paged by kind so no kind can consume a fixed share of a
-- one-shot union. Ranking remains in Rust; this query only projects current
-- logical candidates in stable order and applies project/lifecycle filters.
LET $raw = IF $kind = 'claim' {
  SELECT
    <string> id AS record_ref,
    claim_id,
    string::concat('claim:', <string> claim_id) AS handle,
    'claim_card' AS record_type,
    <string> statement AS preview,
    string::concat(
      <string> statement, ' ', <string> payload.topic, ' ',
      <string> payload.where_applicable, ' ',
      <string> payload.where_not_applicable, ' ',
      <string> payload.negative_constraints, ' ',
      <string> payload.freshness_rule, ' ', <string> payload
    ) AS search_text,
    string::concat(
      <string> payload.path, ' ', <string> payload.symbol, ' ',
      <string> payload.error, ' ', <string> payload.task_class
    ) AS cue_text,
    <string> scope AS scope_text,
    string::concat(
      <string> payload.concept_id, ' ', <string> payload.concept_refs,
      ' ', <string> payload.subsystem
    ) AS concept_text,
    task_id,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    IF status = 'verified' { 80 }
      ELSE IF status = 'supported' { 50 }
      ELSE IF status = 'candidate' { 10 }
      ELSE { 0 } AS authority_rank,
    false AS negative_memory,
    memory_revision,
    project_sequence,
    0 AS verification_value,
    IF payload.changed_outcome = true { 1 } ELSE { 0 } AS known_decision_delta,
    IF payload.beneficial_use_count != NONE {
      <int> payload.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    status IN ['contested', 'rejected'] AS contradiction_signal,
    IF payload.harmful = true { true } ELSE { false } AS harm_signal,
    IF payload.repeated = true { true } ELSE { false } AS repetition_signal,
    IF payload.distraction = true { true } ELSE { false } AS distraction_signal
  FROM claim_card
  WHERE project_id = $project_id
    AND ($lifecycle_audit OR lifecycle_status NOT IN [
      'archived', 'quarantined', 'forgotten', 'hard_deleted'
    ])
  ORDER BY claim_id ASC
  START $start LIMIT $page_limit_plus_one
} ELSE IF $kind = 'evidence' {
  SELECT
    <string> id AS record_ref,
    evidence_id,
    string::concat('evidence:', <string> evidence_id) AS handle,
    'evidence_atom' AS record_type,
    <string> summary AS preview,
    string::concat(<string> summary, ' ', <string> payload, ' ', <string> source_refs)
      AS search_text,
    string::concat(
      <string> payload.path, ' ', <string> payload.symbol, ' ',
      <string> payload.error, ' ', <string> payload.task_class
    ) AS cue_text,
    <string> scope AS scope_text,
    string::concat(<string> payload.concept_id, ' ', <string> payload.concept_refs)
      AS concept_text,
    task_id,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    35 AS authority_rank,
    false AS negative_memory,
    memory_revision,
    project_sequence,
    25 AS verification_value,
    IF payload.changed_outcome = true { 1 } ELSE { 0 } AS known_decision_delta,
    IF payload.beneficial_use_count != NONE {
      <int> payload.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    false AS contradiction_signal,
    IF payload.harmful = true { true } ELSE { false } AS harm_signal,
    IF payload.repeated = true { true } ELSE { false } AS repetition_signal,
    IF payload.distraction = true { true } ELSE { false } AS distraction_signal
  FROM evidence_atom
  WHERE project_id = $project_id
    AND ($lifecycle_audit OR lifecycle_status NOT IN [
      'archived', 'quarantined', 'forgotten', 'hard_deleted'
    ])
  ORDER BY evidence_id ASC
  START $start LIMIT $page_limit_plus_one
} ELSE IF $kind = 'verification' {
  SELECT
    <string> id AS record_ref,
    verification_id,
    string::concat('verification:', <string> verification_id) AS handle,
    'verification_run' AS record_type,
    <string> summary AS preview,
    string::concat(
      <string> summary, ' ', <string> verifier, ' ', <string> result,
      ' ', <string> claim_id, ' ', <string> payload
    ) AS search_text,
    string::concat(
      <string> payload.path, ' ', <string> payload.symbol, ' ',
      <string> payload.error, ' ', <string> payload.task_class
    ) AS cue_text,
    <string> scope AS scope_text,
    string::concat(<string> payload.concept_id, ' ', <string> payload.concept_refs)
      AS concept_text,
    task_id,
    <string> result AS status,
    lifecycle_status AS lifecycle_state,
    IF result = 'passed' { 70 } ELSE IF result = 'failed' { 60 } ELSE { 20 }
      AS authority_rank,
    result = 'failed' AS negative_memory,
    memory_revision,
    project_sequence,
    IF result = 'passed' { 80 } ELSE IF result = 'failed' { 60 } ELSE { 10 }
      AS verification_value,
    IF payload.changed_outcome = true { 1 } ELSE { 0 } AS known_decision_delta,
    IF payload.beneficial_use_count != NONE {
      <int> payload.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    result = 'failed' AS contradiction_signal,
    IF payload.harmful = true { true } ELSE { false } AS harm_signal,
    IF payload.repeated = true { true } ELSE { false } AS repetition_signal,
    IF payload.distraction = true { true } ELSE { false } AS distraction_signal
  FROM verification_run
  WHERE project_id = $project_id
    AND ($lifecycle_audit OR lifecycle_status NOT IN [
      'archived', 'quarantined', 'forgotten', 'hard_deleted'
    ])
  ORDER BY verification_id ASC
  START $start LIMIT $page_limit_plus_one
} ELSE IF $kind = 'observation' {
  SELECT
    <string> id AS record_ref,
    observation_id,
    string::concat('observation:', <string> observation_id) AS handle,
    'tool_observation' AS record_type,
    <string> observation AS preview,
    string::concat(
      <string> observation, ' ', <string> tool_name, ' ', <string> payload
    ) AS search_text,
    string::concat(
      <string> payload.path, ' ', <string> payload.symbol, ' ',
      <string> payload.error, ' ', <string> payload.task_class
    ) AS cue_text,
    <string> scope AS scope_text,
    string::concat(<string> payload.concept_id, ' ', <string> payload.concept_refs)
      AS concept_text,
    task_id,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    20 AS authority_rank,
    false AS negative_memory,
    memory_revision,
    project_sequence,
    10 AS verification_value,
    IF payload.changed_outcome = true { 1 } ELSE { 0 } AS known_decision_delta,
    IF payload.beneficial_use_count != NONE {
      <int> payload.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    false AS contradiction_signal,
    IF payload.harmful = true { true } ELSE { false } AS harm_signal,
    IF payload.repeated = true { true } ELSE { false } AS repetition_signal,
    IF payload.distraction = true { true } ELSE { false } AS distraction_signal
  FROM tool_observation
  WHERE project_id = $project_id
    AND ($lifecycle_audit OR lifecycle_status NOT IN [
      'archived', 'quarantined', 'forgotten', 'hard_deleted'
    ])
  ORDER BY observation_id ASC
  START $start LIMIT $page_limit_plus_one
} ELSE IF $kind = 'failure' {
  SELECT
    <string> id AS record_ref,
    fingerprint,
    string::concat('failure:', <string> fingerprint) AS handle,
    'failure_fingerprint' AS record_type,
    <string> summary AS preview,
    string::concat(<string> summary, ' ', <string> payload) AS search_text,
    string::concat(
      <string> payload.path, ' ', <string> payload.symbol, ' ',
      <string> payload.error, ' ', <string> payload.task_class
    ) AS cue_text,
    <string> scope AS scope_text,
    string::concat(<string> payload.concept_id, ' ', <string> payload.concept_refs)
      AS concept_text,
    task_id,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    50 AS authority_rank,
    true AS negative_memory,
    memory_revision,
    project_sequence,
    35 AS verification_value,
    1 AS known_decision_delta,
    IF payload.beneficial_use_count != NONE {
      <int> payload.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    false AS contradiction_signal,
    IF payload.harmful = true { true } ELSE { false } AS harm_signal,
    IF payload.repeated = true { true } ELSE { false } AS repetition_signal,
    IF payload.distraction = true { true } ELSE { false } AS distraction_signal
  FROM failure_fingerprint
  WHERE project_id = $project_id
    AND ($lifecycle_audit OR lifecycle_status NOT IN [
      'archived', 'quarantined', 'forgotten', 'hard_deleted'
    ])
  ORDER BY fingerprint ASC
  START $start LIMIT $page_limit_plus_one
} ELSE IF $kind = 'artifact' {
  SELECT
    <string> id AS record_ref,
    record_id,
    receipt_kind,
    IF receipt_kind = 'module_card' {
      string::concat('card:', <string> receipt_body.card_id)
    } ELSE IF receipt_kind = 'subsystem_capsule' {
      string::concat('capsule:', <string> receipt_body.capsule_id)
    } ELSE IF receipt_kind = 'project_charter' {
      string::concat('charter:', <string> receipt_body.charter_id)
    } ELSE {
      string::concat('map:', <string> receipt_body.map_id)
    } AS handle,
    <string> receipt_kind AS record_type,
    <string> receipt_body.body_md AS preview,
    string::concat(
      <string> receipt_body.body_md, ' ', <string> receipt_body.path, ' ',
      <string> receipt_body.concept_id, ' ', <string> receipt_body.source_refs,
      ' ', <string> receipt_body.concept_refs, ' ',
      <string> receipt_body.subsystem_concept_refs
    ) AS search_text,
    string::concat(
      <string> receipt_body.path, ' ', <string> receipt_body.symbol,
      ' ', <string> receipt_body.error, ' ', <string> receipt_body.task_class
    ) AS cue_text,
    <string> receipt_body.path AS scope_text,
    string::concat(
      <string> receipt_body.concept_id, ' ', <string> receipt_body.concept_refs,
      ' ', <string> receipt_body.subsystem_concept_refs
    ) AS concept_text,
    task_id,
    IF receipt_body.status != NONE {
      <string> receipt_body.status
    } ELSE { 'supported' } AS status,
    IF receipt_body.lifecycle != NONE {
      receipt_body.lifecycle
    } ELSE { 'active' } AS lifecycle_state,
    IF receipt_body.status = 'verified' { 80 }
      ELSE IF receipt_body.status = 'candidate' { 10 }
      ELSE { 50 } AS authority_rank,
    false AS negative_memory,
    memory_revision,
    project_sequence,
    30 AS verification_value,
    IF receipt_body.changed_outcome = true { 1 } ELSE { 0 } AS known_decision_delta,
    IF receipt_body.beneficial_use_count != NONE {
      <int> receipt_body.beneficial_use_count
    } ELSE { 0 } AS prior_beneficial_use,
    receipt_body.status IN ['contested', 'rejected'] AS contradiction_signal,
    IF receipt_body.harmful = true { true } ELSE { false } AS harm_signal,
    IF receipt_body.repeated = true { true } ELSE { false } AS repetition_signal,
    IF receipt_body.distraction = true { true } ELSE { false } AS distraction_signal
  FROM canonical_record
  WHERE project_id = $project_id
    AND receipt_kind IN [
      'module_card', 'subsystem_capsule', 'project_charter', 'system_map'
    ]
    AND ($lifecycle_audit
      OR receipt_body.lifecycle = NONE
      OR receipt_body.lifecycle NOT IN [
        'archived', 'quarantined', 'forgotten', 'hard_deleted'
      ])
  ORDER BY receipt_kind ASC, record_id ASC, memory_revision DESC, project_sequence DESC
  START $start LIMIT $page_limit_plus_one
} ELSE {
  []
};
LET $rows = array::flatten([$raw]).filter(|$row| $row != NONE AND $row != NULL);

RETURN {
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  candidates: array::slice($rows, 0, $limit),
  truncated: array::len($rows) > $limit,
};
