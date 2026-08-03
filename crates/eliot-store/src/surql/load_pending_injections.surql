LET $pending = SELECT VALUE payload_b64
FROM pending_injection
WHERE <string> project_id = <string> $project_id
  AND <string> session_id = <string> $session_id
ORDER BY created_at ASC, record_id ASC
LIMIT 257;

RETURN {
  pending: array::slice($pending, 0, 256),
  truncated: array::len($pending) > 256
};
