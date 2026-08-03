DEFINE INDEX OVERWRITE idx_ul_mining_identity ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.head_commit, receipt_body.config_hash;
DEFINE INDEX OVERWRITE idx_ul_artifact_path ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.path;
DEFINE INDEX OVERWRITE idx_canonical_memory_parent_segment
  ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.parent_handle, receipt_body.blob.digest_hex, receipt_body.ordinal;
DEFINE INDEX OVERWRITE idx_canonical_memory_manifest
  ON TABLE canonical_record
  FIELDS project_id, receipt_kind, receipt_body.memory_handle, receipt_body.blob.digest_hex;

RETURN {
  migrated: true,
  schema: 'ul_artifacts_and_canonical_capacity'
};
