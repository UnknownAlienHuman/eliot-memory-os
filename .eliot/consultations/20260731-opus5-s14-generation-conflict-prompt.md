# Narrow S14 recovery-fixture decision

You are the escalation reviewer for `ELIOT_RUNTIME_SUPERVISION_01_PROCESS_LEASE_SEAL_RECOVERY_v1_0.md` in `eliot-memory-os`, branch `codex/cognitive-completion-v2`.

Read only these anchors:

- `crates/eliot-app/src/cognitive_field_runner.rs`: `inspect_seal_recovery`, `recover_seal`, and the new test `exact_run006_partial_shape_is_recovered_once_without_provider_evidence`.
- `crates/eliot-engine/src/external_agent/mod.rs`: `validate_external_agent_execution_request`.
- Contract section S14 and the run006 recovery section.

Observed test-fixture failures:

1. Empty `CognitiveFieldProviderCallPlan.executions` caused the request builder to index element 0. Fixed by adding one execution.
2. The next run was rejected because `validate_external_agent_execution_request` requires `launch.operation_generation != 0`, while the real legacy run006 authority recovered by `inspect_seal_recovery` is deliberately `AgentSession`/`TaskRoleLease` generation 0 with no owner or seal attempt.

No provider calls occurred. The real run006 recovery already succeeded and is idempotently `ALREADY_ABANDONED` with zero provider evidence.

Decide the smallest contract-correct fixture repair. Specifically answer:

1. May the immutable execution request use operation generation 1 while the deliberately legacy broker `AgentSession`, `TaskRoleLease`, and matching `OperationJob` remain generation 0, given the inspector's exact legacy predicates?
2. If that is misleading, state the exact alternative fixture construction or narrow product change.
3. Identify the precise assertions needed for S14 and whether this test must call the modern execution-request validator at all.

Return one decisive recommendation, a short rationale, and at most five concrete edits/assertions. Do not edit files, invoke providers, broaden scope, or review unrelated code.
