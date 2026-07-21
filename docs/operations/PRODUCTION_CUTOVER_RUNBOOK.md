# Production Cutover Runbook

The repository prepares a cutover; it does not perform administrative mutation without an operator's explicit approval.

1. Build or select the release executable.
2. Run `scripts/plan-eliot-production-cutover.ps1` with the current config, proposed non-synced local data-root, and release executable.
3. Run `eliot-governor --config <candidate-config> doctor operations`. Require every blocking check to pass, then require the cutover manifest status to equal `READY_FOR_OPERATOR_CUTOVER`.
4. Review `exact_changes`, `operator_commands`, and `rollback_commands` line by line.
5. Take and verify a fresh full logical/blob backup, inspect `backup status`, and complete `scripts/test-m5-isolated-operations.ps1` against isolated stores.
6. Obtain operator approval for the exact manifest.
7. Only then perform the service/data-root changes from an elevated terminal.
8. Run authenticated doctor, backup status, IPC, and Operator contract/snapshot smoke checks. Preserve the exact approval and generated receipts with the cutover manifest.

Rollback stops the new service, restores the prior service `ImagePath` and data-root config, and starts the prior service. Do not delete either data-root during the cutover window.
