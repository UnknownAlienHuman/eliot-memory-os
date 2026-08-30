## I17.2. Current recovery priority and promotion gate

Historical failure audits are regression donors, not the current migration baseline. The only current baseline is the latest `CurrentSystemEvidenceSnapshot` bound to exact source, build, installed runtime, policy, schema, integrations and live store revision. Until that snapshot exists, `support_observation_state = UNKNOWN`; absent exact source/runtime evidence leaves dependent capabilities `TARGET` / `NOT_EXECUTED`, while any previously stronger but invalidated claim is `STALE`. Historical failures remain active candidate regressions where the affected path has not been re-proved.

Until the affected recovery obligations close, the following are prohibited **only on paths that depend on them**:

```text
production promotion or release claim;
new authority or external effect through the defective path;
compatibility fallback inside an authority surface;
report/file projection used as current control state;
`complete`, `certified` or `architecture-complete` status.
```

The recovery sequence is evidence-driven:

1. **CurrentSystemEvidenceSnapshot** — bind exact source, build, runtime, policy, schema, integrations and store revision.
2. **Known-regression discrimination** — replay the strict-finish, payload round-trip, writer-authority, real-verifier and memory-lifecycle probes that apply to the observed topology; a historical failure that does not reproduce is recorded as refuted/stale for that identity, not repaired ceremonially.
3. **Confirmed Hard Boundary repair** — repair only the gaps actually demonstrated on the current identity, preserving the exact old failing path as a regression.
4. **Real verification and Operational Spine Proof** — the governed ProcessExecutor/Instrument path executes the verifier and the real agent/task/effect/restart route closes without synthetic proof.
5. **Live memory lifecycle and benefit evaluation** — demonstrate current admission/retrieval/use/revision and, when claimed, later task benefit.

Parallel development remains allowed through bounded causal work units:

```text
isolated no-effect prototypes;
independent crates/modules;
read-only audits and research;
contract/discriminator/test work;
shadow generations;
repair tooling.
```

A complete impact graph is not a prerequisite for exploration. When dependency evidence is incomplete, the result cannot be promoted or integrated into the affected production owner; it is not grounds for a global stop. The gate protects product authority, not agent activity metrics.

Before canonical memory is available, D0/D1 development evidence is not discarded. `eliot bootstrap brief` writes content-addressed, append-only `BootstrapFailureDraft` / `BootstrapImprovementDraft` artifacts under the repository/external audit evidence root with exact source identity, owner, discriminator and import disposition. They are evidence only, never current truth or authority. When the canonical write path becomes available, an explicit import/rejection receipt reconciles them; filename presence does not auto-promote them.

