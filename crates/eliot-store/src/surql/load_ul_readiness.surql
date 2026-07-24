RETURN {
  co_change_edges: array::len(
    SELECT VALUE id FROM co_change WHERE project_id = $project_id
  ),
  card_covers_edges: array::len(
    SELECT VALUE id FROM card_covers WHERE project_id = $project_id
  ),
  concept_implemented_by_edges: array::len(
    SELECT VALUE id FROM concept_implemented_by WHERE project_id = $project_id
  ),
  concept_depends_on_edges: array::len(
    SELECT VALUE id FROM concept_depends_on WHERE project_id = $project_id
  ),
  capsule_covers_edges: array::len(
    SELECT VALUE id FROM capsule_covers WHERE project_id = $project_id
  )
};
