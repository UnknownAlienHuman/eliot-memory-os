DEFINE TABLE IF NOT EXISTS cue_index SCHEMALESS;
DEFINE INDEX OVERWRITE idx_cue_lookup
  ON TABLE cue_index FIELDS project_id, cue_kind, cue_value_norm;
DEFINE INDEX OVERWRITE idx_cue_record
  ON TABLE cue_index FIELDS project_id, record_ref;
