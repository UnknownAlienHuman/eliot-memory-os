DEFINE INDEX OVERWRITE idx_ul_mining_identity ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.head_commit, receipt_body.config_hash;
DEFINE INDEX OVERWRITE idx_ul_artifact_path ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.path;

-- cue_index is a derived cache. Rebuild it with opaque record_ref keys so
-- SurrealDB never coerces colon-bearing handles while replacing bindings.
DELETE cue_index;

RETURN {
  migrated: true,
  schema: 'ul_artifacts'
};
