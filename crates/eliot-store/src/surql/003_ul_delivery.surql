DEFINE INDEX OVERWRITE idx_injection_session
  ON TABLE injection_receipt FIELDS project_id, session_id, created_at;
DEFINE INDEX OVERWRITE idx_pending_injection_session
  ON TABLE pending_injection FIELDS project_id, session_id, created_at;
