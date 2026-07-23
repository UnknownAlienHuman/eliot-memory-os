DEFINE INDEX OVERWRITE idx_ul_concept_name ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.name;
DEFINE INDEX OVERWRITE idx_ul_capsule_concept ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.concept_id;
DEFINE INDEX OVERWRITE idx_ul_build_target ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.target_kind, receipt_body.target_id;

RETURN {
  migrated: true,
  schema: 'ul_pyramid'
};
