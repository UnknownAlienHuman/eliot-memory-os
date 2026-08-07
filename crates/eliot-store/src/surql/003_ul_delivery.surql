DEFINE INDEX OVERWRITE idx_injection_session
  ON TABLE injection_receipt FIELDS project_id, session_id, created_at;
