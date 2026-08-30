# Appendix G. Research Gate families

This appendix defines the small family vocabulary used by generated `ResearchGateRecord`s. It is not an always-active question bank. Historical detailed questions and legacy `RG-01…RG-67` aliases are retained in the external cold backlog.

```yaml
ResearchGateRecord:
  gate_id_and_family:
  owner_and_affected_decision:
  status: INACTIVE | ACTIVE | BLOCKING | RESOLVED | REJECTED | STALE
  activation_condition_and_current_gap:
  exact_artifact_experiment_or_reproduction_required:
  discriminator_or_decision_boundary:
  budget_time_expiry_and_stop_condition:
  support_and_invalidation_refs:
  decision_unblocked_narrowed_or_rejected_by_result:
```

Only `ACTIVE` and `BLOCKING` gates are shown to the current agent or may block the dependent promotion. `INACTIVE` backlog material creates no obligation.

| Family | Scope |
|---|---|
| `RGF-STORAGE-MIGRATION` | canonical store, engine choice, export, restore and replacement |
| `RGF-RUNTIME-RESILIENCE` | supervision, process identity, cutover, restart, resources and recovery |
| `RGF-PROTOCOL-TRANSPORT` | EBP/MCP/IPC encoding, ordering, reconnect and compatibility |
| `RGF-CONTEXT-MEMORY` | context recipes, retrieval, memory lifecycle, episodes and causal influence |
| `RGF-AGENT-ROUTES` | Codex/OpenCode/Claude/ACP/local-model/translation route competence |
| `RGF-SWARM-ORCHESTRATION` | decomposition, fan-out, independence, synthesis and coordinator recovery |
| `RGF-INSTRUMENT-TESTING` | ProcessExecutor, testd, verifiers, simulation, selection and proof validity |
| `RGF-CRATE-BUILD` | workspace topology, build/cache economics, context and split/merge evidence |
| `RGF-COMPONENT-SANDBOX` | WASM/native contours, build isolation, promotion and rollback |
| `RGF-SECURITY-AUTHORITY` | disclosure, grants, resources, references, secrets and adversarial tests |
| `RGF-CODE-RESEARCH` | code/build/verifier graphs, external corpora, Researcher and donor pilots |
| `RGF-HUMAN-PRODUCT` | usability, attention, economics, product evaluation and delayed outcomes |
| `RGF-PLATFORM-DISTRIBUTION` | Windows packaging, future Linux/multi-device/distribution boundaries |

A family is not a single giant gate. Activation compiles one narrow question for one decision, owner, budget and expiry. Exact old questions remain evidence lineage, not a permanent roadmap.

