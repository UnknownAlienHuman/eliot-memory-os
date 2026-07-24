LET $co_change = SELECT VALUE receipt_body
FROM canonical_record
WHERE project_id = $project_id
  AND receipt_kind = 'co_change_edge'
ORDER BY memory_revision DESC, project_sequence DESC
LIMIT 4096;
LET $card_covers = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM card_covers
WHERE project_id = $project_id
LIMIT 4096;
LET $capsule_covers = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM capsule_covers
WHERE project_id = $project_id
LIMIT 4096;
LET $concept_implemented_by = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM concept_implemented_by
WHERE project_id = $project_id
LIMIT 4096;
LET $concept_depends_on = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM concept_depends_on
WHERE project_id = $project_id
LIMIT 4096;
LET $supports = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM supports
WHERE project_id = $project_id
LIMIT 4096;
LET $verified_by = SELECT
  type::string(from) AS from_ref,
  type::string(to) AS to_ref
FROM verified_by
WHERE project_id = $project_id
LIMIT 4096;
RETURN {
  co_change: $co_change,
  card_covers: $card_covers,
  capsule_covers: $capsule_covers,
  concept_implemented_by: $concept_implemented_by,
  concept_depends_on: $concept_depends_on,
  supports: $supports,
  verified_by: $verified_by
};
