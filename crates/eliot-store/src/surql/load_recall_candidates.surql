LET $head = SELECT * FROM ONLY type::record('scope_head', $project_id);
LET $claims_raw = SELECT
    claim_id,
    string::concat('claim:', <string> claim_id) AS handle,
    'claim_card' AS record_type,
    <string> statement AS preview,
    string::concat(
      <string> statement,
      ' ',
      <string> payload.topic,
      ' ',
      <string> payload.where_applicable,
      ' ',
      <string> payload.where_not_applicable,
      ' ',
      <string> payload.negative_constraints,
      ' ',
      <string> payload.freshness_rule
    ) AS search_text,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    IF status = 'verified' {
      80
    } ELSE IF status = 'supported' {
      50
    } ELSE IF status = 'candidate' {
      10
    } ELSE {
      0
    } AS authority_rank,
    false AS negative_memory
  FROM claim_card
  WHERE project_id = $project_id
    AND lifecycle_status NOT IN ['archived', 'quarantined', 'forgotten', 'hard_deleted']
  ORDER BY claim_id ASC
  LIMIT 257;
LET $claims = array::slice($claims_raw, 0, 256);
LET $failures_raw = SELECT
    fingerprint,
    string::concat('failure:', <string> fingerprint) AS handle,
    'failure_fingerprint' AS record_type,
    <string> summary AS preview,
    string::concat(<string> summary, ' ', <string> payload) AS search_text,
    <string> status AS status,
    lifecycle_status AS lifecycle_state,
    50 AS authority_rank,
    true AS negative_memory
  FROM failure_fingerprint
  WHERE project_id = $project_id
    AND lifecycle_status NOT IN ['archived', 'quarantined', 'forgotten', 'hard_deleted']
  ORDER BY fingerprint ASC
  LIMIT 129;
LET $failures = array::slice($failures_raw, 0, 128);
LET $artifacts_raw = SELECT
    record_id,
    receipt_kind,
    memory_revision,
    project_sequence,
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
      <string> receipt_body.body_md,
      ' ',
      <string> receipt_body.path,
      ' ',
      <string> receipt_body.concept_id,
      ' ',
      <string> receipt_body.source_refs,
      ' ',
      <string> receipt_body.concept_refs,
      ' ',
      <string> receipt_body.subsystem_concept_refs
    ) AS search_text,
    IF receipt_body.status != NONE {
      <string> receipt_body.status
    } ELSE {
      'supported'
    } AS status,
    IF receipt_body.lifecycle != NONE {
      receipt_body.lifecycle
    } ELSE {
      'active'
    } AS lifecycle_state,
    IF receipt_body.status = 'verified' {
      80
    } ELSE IF receipt_body.status = 'candidate' {
      10
    } ELSE {
      50
    } AS authority_rank,
    false AS negative_memory
  FROM canonical_record
  WHERE project_id = $project_id
    AND receipt_kind IN [
      'module_card',
      'subsystem_capsule',
      'project_charter',
      'system_map'
    ]
  ORDER BY receipt_kind ASC, record_id ASC, memory_revision DESC, project_sequence DESC
  LIMIT 129;
LET $artifacts = array::slice($artifacts_raw, 0, 128);
LET $all_candidates = array::concat($claims, $failures, $artifacts);

RETURN {
  at_revision: IF $head == NONE { 0 } ELSE { $head.memory_revision },
  candidates: array::slice($all_candidates, 0, 512),
  truncated: array::len($claims_raw) > 256
    OR array::len($failures_raw) > 128
    OR array::len($artifacts_raw) > 128
    OR array::len($all_candidates) > 512,
};
