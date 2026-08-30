## I0.2. Current compatibility baseline

| Surface | Current line | Status | Fallback or replacement rule |
|---|---|---|---|
| Architecture source | `ELIOT_ARCHITECTURE.md` 4.5-draft; exact path, version and digest are emitted after freeze in `docs/normative-pair.toml` | priority semantic baseline | a missing/mismatched pair receipt, different digest or mixed revision makes dependent conformance and self-knowledge projections stale/untrusted |
| Rust toolchain | Rust 1.97.1, edition 2024 | source-verified DEFAULT candidate in the external compatibility ledger; local admission still absent | exact patch is pinned in `rust-toolchain.toml`; update after affected suite |
| Windows | Windows 11 x64 | target production platform | Linux is unsupported until separate CI and acceptance exist |
| MCP | final specification 2026-07-28; stateless core | source-verified target line in the external compatibility ledger; local conformance still absent | compatibility adapter for 2025-11-25; ELIOT Session remains application state in both profiles |
| Rust MCP SDK | official `rmcp` 3.1.x line; 3.1.2 candidate | source-verified beta/primary candidate in the external compatibility ledger; local bridge/conformance absent | exact patch is pinned in `Cargo.lock` only after dual-version bridge/conformance tests; SDK remains isolated in `eliot-mcp` and cannot define domain/session semantics |
| Canonical DB | SurrealDB 3.2.x compatibility line; 3.2.3 candidate, not yet admitted | source-verified provisional target in the external compatibility ledger; local workload/crash/restore proof absent | active patch is selected only after current-system audit, workload/crash/restore proof and RGF-STORAGE-MIGRATION; rollback uses the last actually verified generation |
| Host state journal | `redb`, separate Host-owned file | target default | replacement requires torn-write/recovery equivalence and no semantic-state leakage |
| Operational recovery DB | `redb`, Kernel-owned ORS file | target default | replaceable only through ORS export/import proof |
| Internal process protocol | EBP/1 over named pipes; JSON-first encoding | target default | `protobuf-v1` — RGF-PROTOCOL-TRANSPORT profile; Unix domain socket reuse the same messages |
| In-process supervision | plain Tokio behind `eliot-runtime`; `ractor` is an unpinned research candidate | baseline + RGF-RUNTIME-RESILIENCE | exact candidate/version comes only from the current compatibility receipt and lockfile; Kernel/domain never depend on actor-framework semantics and a framework becomes default only after measured simplification without ownership drift |
| WASM component runtime | Wasmtime 47.x compatibility line; 47.0.3 candidate; Component Model + `wasm32-wasip2` | source-verified PROVISIONAL candidate in the external compatibility ledger; local security/Windows conformance absent | exact patch is resolved only from the current compatibility receipt and lockfile after security/Windows conformance; WASI 0.3/`wasm32-wasip3` remains a laboratory lane |
| Build/test execution plane | isolated `eliot-testd` over EBP; same typed Instrument profiles as local/CI | target default / RGF-INSTRUMENT-TESTING | may be co-located only at D0 as an explicit extraction default; compile storms never share Kernel Control Reserve |
| Deterministic simulation | pure ELIOT event simulator first; Loom plus admitted Shuttle/Turmoil/MadSim adapters | staged / RGF-INSTRUMENT-TESTING | no simulator becomes operational truth; seeds, schedules, failpoints and cassettes are immutable artifacts |
| Windows Human UI | WinUI 3 desktop client on the stable Windows App SDK 2.3.1 line; optional Ratatui terminal board | source-verified TARGET; local UI/usability/recovery conformance absent | thin non-authoritative user-session client over the role-filtered ControlBoard/Operator API; CLI remains the mandatory recovery fallback; browser UI is optional, not the primary surface |

`Cargo.lock`, `compatibility.toml`, Module manifests, and service manifest are the exact source of patch versions. This table defines compatible lines; it does not replace the lockfile.

The table is a reviewed compatibility baseline, not an updater or a current-installation claim. `checked_at`, source identities and local admission live in the external `CompatibilityEvidenceRecord`; immutable manifests and lockfiles remain authoritative for the installed generation.

### Compatibility evidence discipline

Every row above has a `CompatibilityEvidenceRecord` outside prose:

```yaml
CompatibilityEvidenceRecord:
  surface:
  claimed_line_or_version:
  primary_source_ref:
  checked_at:
  source_digest_or_release_identity:
  installed_artifact_identity:
  local_probe_refs:
  status: declared | source_verified | locally_probed | admitted | stale | rejected
  invalidation_conditions:
```

Rules:

```text
`current candidate` means source-verified only; it is not an installed or production-admitted generation;
exact production authority comes from the installed manifest, lockfile, artifact hash and local conformance receipts;
a newer release, changed upstream contract, changed account/route or changed local artifact makes the record stale;
research prose, README text or a previous assistant answer cannot update this table without a primary-source check;
unknown or contradictory version evidence remains visible and blocks only the dependent admission.
```

### Agent Execution Fabric route baseline

| Route surface | Implementation status | Production rule |
|---|---|---|
| Codex App Server over stdio/JSONL | **PRIMARY-1 integration candidate; stable schema surface with separately gated experimental operations** | first durable vertical slice; exact executable/schema hash, stable-only schema pin, current-account probes and rollback required; WebSocket and opt-in experimental methods are non-production until separately admitted |
| OpenCode local server over HTTP/SSE | **PRIMARY-2 candidate** | second provider-neutral execution path; use public OpenAPI/session/event surface; independence is credited only from ActualRouteReceipt/IndependenceProfile; internal runtime DB is forensic-only |
| ACP over stdio | **COMPATIBILITY-1** | baseline methods plus operation-level probes for every optional capability; handshake claims alone are insufficient |
| Claude local Agent SDK | **LATER sidecar** | separate Python/TypeScript sidecar bundle; local route is distinct from hosted Managed Agents |
| Claude Managed Agents | **LATER remote beta** | separate adapter, billing, retention and beta profile; explicit user opt-in |
| Antigravity local SDK/CLI | **LATER sidecar** | local route only until an official remote session/resource/event contract is proven |
| Cursor/Copilot/other preview routes | **EXPERIMENTAL** | pinned bundle, short evidence expiry, stronger verification and visible preview status |

A route is identified by the full `RouteFingerprint`, not by a model ID or vendor label. Every line above is `PROVISIONAL` until exact-version conformance and current-account probes produce evidence. The research sources for this baseline are non-normative and are recorded in I0.3; the current primary-source checks and admission status live in the content-addressed compatibility-evidence receipt bound by the normative-pair identity.

### SurrealDB decision

SurrealDB is first because graph, document, temporal, and structured representations are available under one transaction boundary. License risk and vendor dependence are acknowledged in advance. Therefore:

```text
`eliotd` does not import the SurrealDB SDK;
database credentials belong only to the storage bridge;
all operations use a store-neutral semantic API;
full canonical export is mandatory;
shadow migration to another store is a normal scenario.
```

The choice remains an empirical Default, not a reward for using more SurrealDB-specific syntax. After D1, a `StorageValueProfile` is compiled from the actual named-operation registry:

```yaml
StorageValueProfile:
  exact_store_and_workload_identity:
  canonical_operation_families:
  operations_using_atomic_graph_document_or_temporal_features:
  portable_reference_implementation_and_round_trips:
  latency_tail_resource_and_write_amplification:
  schema_migration_backup_restore_and_operator_cost:
  bridge_query_complexity_and_maintenance_burden:
  product_or_recovery_delta:
  keep_simplify_or_migrate_candidate:
  uncertainty_review_and_kill_condition:
```

If the real workload gains little from the hybrid transaction/query model, simplification to a more mature substrate is an admissible result of `RGF-STORAGE-MIGRATION`; replacement is not limited to another multi-model database. No universal operation-count threshold is frozen in prose.

### Current distribution boundary

The first supported topology is one installation with one logical canonical owner on one primary machine. Two installations do not become replicas merely because they share documents, a provider account or exported files. Cross-device canonical replication, offline multi-writer merge and automatic multi-node failover are not current capabilities. Until a future distributed contract is accepted, transfer between installations uses explicit export/import or migration receipts, and each installation remains an independent authority lineage. Optional remote workers may execute bounded jobs but never become another canonical owner.

