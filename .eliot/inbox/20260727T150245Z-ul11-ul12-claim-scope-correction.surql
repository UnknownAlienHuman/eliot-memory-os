USE NS eliot DB system;

UPDATE claim_card:eliot_ul_v1_4_complete_20260727
SET scope.branch = "main";

SELECT id, authority, branch_env_scope, scope, status
FROM claim_card:eliot_ul_v1_4_complete_20260727;
