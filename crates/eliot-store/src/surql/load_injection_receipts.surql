LET $receipts = SELECT VALUE payload
FROM injection_receipt
WHERE <string> project_id = <string> $project_id
  AND <string> session_id = <string> $session_id
ORDER BY created_at ASC
LIMIT 10001;

RETURN {
  receipts: array::slice($receipts, 0, 10000),
  truncated: array::len($receipts) > 10000
};
