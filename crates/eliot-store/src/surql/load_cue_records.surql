LET $claims = SELECT
  string::concat('claim:', <string> claim_id) AS record_ref,
  'claim' AS record_kind,
  <string> statement AS preview_text,
  payload AS payload,
  payload.cue_bindings AS cue_bindings,
  false AS negative_memory,
  <string> lifecycle_status AS lifecycle
FROM claim_card
WHERE <string> project_id = <string> $project_id
  AND payload.cue_bindings != NONE
LIMIT 10001;

LET $failures = SELECT
  string::concat('failure:', <string> fingerprint) AS record_ref,
  'failure_fingerprint' AS record_kind,
  <string> summary AS preview_text,
  payload AS payload,
  payload.cue_bindings AS cue_bindings,
  true AS negative_memory,
  <string> lifecycle_status AS lifecycle
FROM failure_fingerprint
WHERE <string> project_id = <string> $project_id
  AND payload.cue_bindings != NONE
LIMIT 10001;

LET $observations = SELECT
  IF payload.receipt_kind = 'module_card' {
    string::concat('card:', <string> payload.receipt_body.card_id)
  } ELSE IF payload.receipt_kind = 'concept_node' {
    string::concat('concept:', <string> payload.receipt_body.concept_id)
  } ELSE IF payload.receipt_kind = 'project_charter' {
    string::concat('charter:', <string> payload.receipt_body.charter_id)
  } ELSE IF payload.receipt_kind = 'system_map' {
    string::concat('system-map:', <string> payload.receipt_body.map_id)
  } ELSE IF payload.receipt_kind = 'subsystem_capsule' {
    string::concat('capsule:', <string> payload.receipt_body.capsule_id)
  } ELSE {
    string::concat('tool_observation:', <string> observation_id)
  } AS record_ref,
  <string> payload.receipt_kind AS record_kind,
  IF payload.receipt_body.body_md != NONE {
    <string> payload.receipt_body.body_md
  } ELSE {
    <string> observation
  } AS preview_text,
  payload.receipt_body AS payload,
  payload.receipt_body.cue_bindings AS cue_bindings,
  false AS negative_memory,
  <string> lifecycle_status AS lifecycle
FROM tool_observation
WHERE <string> project_id = <string> $project_id
  AND payload.receipt_body.cue_bindings != NONE
  AND payload.receipt_kind != 'cue_binding_page'
LIMIT 10001;

LET $canonical = SELECT
  IF receipt_kind = 'module_card' {
    string::concat('card:', <string> receipt_body.card_id)
  } ELSE IF receipt_kind = 'concept_node' {
    string::concat('concept:', <string> receipt_body.concept_id)
  } ELSE IF receipt_kind = 'project_charter' {
    string::concat('charter:', <string> receipt_body.charter_id)
  } ELSE IF receipt_kind = 'system_map' {
    string::concat('system-map:', <string> receipt_body.map_id)
  } ELSE IF receipt_kind = 'subsystem_capsule' {
    string::concat('capsule:', <string> receipt_body.capsule_id)
  } ELSE IF receipt_kind = 'cue_binding_page' {
    <string> receipt_body.parent_handle
  } ELSE {
    string::concat('canonical:', <string> record_id)
  } AS record_ref,
  <string> receipt_kind AS record_kind,
  IF cue_preview_text != NONE AND cue_preview_text != '' {
    <string> cue_preview_text
  } ELSE IF receipt_body.preview_text != NONE {
    <string> receipt_body.preview_text
  } ELSE IF receipt_body.statement != NONE {
    <string> receipt_body.statement
  } ELSE IF receipt_body.body_md != NONE {
    <string> receipt_body.body_md
  } ELSE {
    <string> receipt_kind
  } AS preview_text,
  receipt_body AS payload,
  receipt_body.cue_bindings AS cue_bindings,
  false AS negative_memory,
  IF receipt_body.lifecycle != NONE {
    <string> receipt_body.lifecycle
  } ELSE {
    'active'
  } AS lifecycle
FROM canonical_record
WHERE <string> project_id = <string> $project_id
  AND receipt_body.cue_bindings != NONE
  AND (
    receipt_kind != 'cue_binding_page'
    OR (
      receipt_body.blob.digest_hex = array::first(
        SELECT VALUE receipt_body.blob.digest_hex
        FROM canonical_record
        WHERE project_id = $parent.project_id
          AND receipt_kind = 'memory_blob_manifest'
          AND subject_ref = $parent.subject_ref
        ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
        LIMIT 1
      )
      AND receipt_body.page_set_hash_blake3 = array::first(
        SELECT VALUE receipt_body.cue_page_set_hash_blake3
        FROM canonical_record
        WHERE project_id = $parent.project_id
          AND receipt_kind = 'memory_blob_manifest'
          AND subject_ref = $parent.subject_ref
        ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC
        LIMIT 1
      )
    )
  )
LIMIT 10001;

LET $records = array::concat($claims, $failures, $observations, $canonical);
RETURN {
  records: array::slice($records, 0, 10000),
  truncated: array::len($records) > 10000
};
