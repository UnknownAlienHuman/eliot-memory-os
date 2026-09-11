# `eliot-dreamer-configuration-plan` implementation contract

Owning issue: [#679 — A-42 snapshot-bound ConfigurationChangeIntent](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/679).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I3.9 — Configuration layers`](../../../docs/architecture/I03-09-configuration-layers.md#i39-configuration-layers)
- [`I3.10 — Immutable configuration and policy snapshots`](../../../docs/architecture/I03-10-immutable-config-and-policy-snapshots.md#i310-immutable-config-and-policy-snapshots)
- [`I3.4 — Capability and route registry`](../../../docs/architecture/I03-04-capability-and-route-registry.md#i34-capability-and-route-registry)
- [`I3.6 — Model route and portfolio policy`](../../../docs/architecture/I03-06-model-route-and-portfolio-policy.md#i36-model-route-and-portfolio-policy)
- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.4 — Dreamer input bundle`](../../../docs/architecture/I09-04-dreamer-input-bundle.md#i94-dreamer-input-bundle)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I12.24 — Meta-learning and improvement delivery`](../../../docs/architecture/I12-24-meta-learning-and-improvement-delivery.md#i1224-meta-learning-and-improvement-delivery)
- [`I14.14 — Module hot replacement`](../../../docs/architecture/I14-14-module-hot-replacement.md#i1414-module-hot-replacement)
- [`I14.20 — Canonical runtime lifecycle vocabulary`](../../../docs/architecture/I14-20-canonical-runtime-lifecycle-vocabulary.md#i1420-canonical-runtime-lifecycle-vocabulary)
- [`I15.4 — Secrets`](../../../docs/architecture/I15-04-secrets.md#i154-secrets)
- [`I0.10 — User outcome and anti-proxy development`](../../../docs/architecture/I00-10-user-outcome-recovery-invariants-and-anti-proxy-development-contract.md#i010-user-outcome-recovery-invariants-and-anti-proxy-development-contract)

## What to implement

Replace the placeholder with the pure candidate-only owner of one typed `ConfigurationChangeIntent`: exact immutable base/schema/layer/owner, closed change set, purely derived candidate snapshot, complete impact evidence, verifier/rollout/rollback and Human boundary.

## How

- Consume only an explicitly grounded structured request and canonical configuration schemas; natural-language text, labels, paths and environment-variable names are evidence, not field identity or a patch.
- Validate exact job/task/scope/fence/bundle/grounding/input receipt, layer/schema/field/owner, immutable base/overlay precedence, capability/environment impact, history, policy and all independent bounds.
- Accept only closed canonical operations such as set/reset/remove-override/inherit/add-remove-member with exact old/proposed presence/value/type/constraints. Reject generic maps, JSON Patch and `Other`.
- Preserve absent, inherited, explicit-empty, value, reset, remove and unknown distinctly; never read ambient current configuration or auto-rebase a stale candidate.
- Derive the full candidate snapshot purely in memory, validate cross-field constraints and prove every unchanged field byte/identity remains unchanged.
- Reject unauthorized widening of authority/capabilities/effects, remote/network/principal scope, privacy/retention/telemetry/training/export, secrets, provider/model/cost/fallback, automatic launch/deployment and Product Objective/oracle.
- Traverse only the supplied bounded impact graph and give every consumer/dependency an exact current/affected/unaffected/stale/blocked/unknown/not-applicable disposition.
- Emit inert application-owner, approval, verifier, rollout/canary, stop, exact-base compare, rollback/forward-repair and expiry requirements; publish or restart nothing.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every complete intent has one primary schema/layer/owner, exact current base, typed closed delta, deterministic full candidate snapshot and complete impact/approval/verifier/rollback evidence.
- Prose, aliases, unknown/removed/read-only fields, stale bases and wrong owners cannot produce a ready intent.
- Raw secrets cannot enter values, diagnostics or serialized output; only exact authorized references survive.
- Forbidden ceiling widening is rejected, not emitted as a ready candidate with a warning.
- Partial/unknown impact cannot become no-impact; concurrent same-base conflicts cannot be heuristically merged.
- No file/environment/registry edit, secret acquisition, service restart/deployment, route/budget acquisition, canonical write, authority, effect or Finish API exists.
- All 55 `WORK_UNIT_CASE: 679/1..55` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #969 performs serialized workspace admission.
