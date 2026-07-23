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
  string::concat('tool_observation:', <string> observation_id) AS record_ref,
  <string> payload.receipt_kind AS record_kind,
  <string> observation AS preview_text,
  payload.receipt_body AS payload,
  payload.receipt_body.cue_bindings AS cue_bindings,
  false AS negative_memory,
  <string> lifecycle_status AS lifecycle
FROM tool_observation
WHERE <string> project_id = <string> $project_id
  AND payload.receipt_body.cue_bindings != NONE
LIMIT 10001;

LET $canonical = SELECT
  string::concat('canonical:', <string> record_id) AS record_ref,
  <string> receipt_kind AS record_kind,
  IF receipt_body.preview_text != NONE {
    <string> receipt_body.preview_text
  } ELSE IF receipt_body.statement != NONE {
    <string> receipt_body.statement
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
LIMIT 10001;

LET $records = array::concat($claims, $failures, $observations, $canonical);
RETURN {
  records: array::slice($records, 0, 10000),
  truncated: array::len($records) > 10000
};
