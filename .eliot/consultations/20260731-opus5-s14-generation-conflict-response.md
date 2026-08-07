# Opus 5 decision: S14 generation asymmetry

- Model: `claude-opus-5`
- Session: `464220ea-4232-4852-9a52-1f1401557ba9`
- Duration: 145.131 seconds
- Cost: USD 1.1495645
- Provider/web/tool side effects: none; read-only `Read`, `Grep`, `Glob`

## Decision

Mint the immutable execution requests with `operation_generation = 1` and keep the deliberately legacy broker `AgentSession`, `TaskRoleLease`, and matching `OperationJob` rows at generation 0. Update the client instance suffix to `g1`.

The asymmetry is the exact defect being recovered: request generation is the seal-attempt generation, while the generation-0 broker rows with no owner/seal binding are authority persisted by the pre-fence path. The recovery inspector intentionally uses request identity/binding fields while requiring generation-0 CAS-ready broker authority.

Do not weaken or bypass `validate_external_agent_execution_request`. Exercise it transitively through `cognitive_external_execution_request`.

## Required assertions

1. Explicitly assert request generation 1 versus broker generation 0, missing broker owners, and missing lease seal attempts.
2. Assert `legacy_authority_cas_ready`, `scoped_authority_exact`, no integrity error, and no non-projection proofs for the fully projected fixture.
3. Apply recovery twice and prove the second pass is byte-identical/idempotent.
4. Assert the quarantine manifest contains exactly eight entries.
