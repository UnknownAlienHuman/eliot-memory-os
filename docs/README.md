# Documentation map

## Current work: V3 design

V1/V2 Memory implementations are archived donors. V3 is a fresh implementation target; these documents are design authority, not evidence of runtime support.

| Need | Current V3 source |
|---|---|
| Reading order and proof ceiling | [v3/README.md](v3/README.md) |
| Product purpose, authority and invariants | [v3/ARCHITECTURE.md](v3/ARCHITECTURE.md) — draft.18 |
| Runtime, migration/query contract and implementation order | [v3/IMPLEMENTATION.md](v3/IMPLEMENTATION.md) — draft.39 |
| Reconstruction, retrieval and learning algorithms | [v3/COGNITION.md](v3/COGNITION.md) — draft.22 |
| Memory↔controller V2 boundary | [v3/INFERENCE-CONTRACT.md](v3/INFERENCE-CONTRACT.md) — Contract 0.17 |
| Active decisions, gaps and queue | [v3/ANALYSIS-REGISTRY.md](v3/ANALYSIS-REGISTRY.md) |
| Evidence and donor rationale | [v3/AUDIT.md](v3/AUDIT.md), [v3/AUDIT-MAP.md](v3/AUDIT-MAP.md) |
| Version precedence | [ARCHITECTURE_CONTRACT.md](ARCHITECTURE_CONTRACT.md) |

Read Architecture, Implementation, Cognition and Inference Contract together for a load-bearing boundary. `ANALYSIS-REGISTRY.md` is the only active audit/work ledger.

### Current load-bearing decisions

- daemon owns application state, controller-mutation serialization, backup-set transitions and restore file leases;
- supervisor owns privileged Store lifecycle, candidate process/root and final cutover;
- final backup directory first appears with a durable canonical fence already inside it;
- terminal abort/retire records remain authoritative after content cleanup;
- migration 0001 uses canonical string application IDs, explicit DTO queries, external SHA-256 bundle identity, fixed schema metadata and catalog readback;
- controller issue #200 separates binding allocation, selected pointer and native effect;
- controller issue #199 remains blocked on #200 and V2 L0/L1.

## Retained V2 donor documentation

The remaining `docs/architecture/`, `docs/normative-pair.toml`, source, scripts and workstream records describe V2. Their status words are historical unless a current V3 owner document explicitly adopts a bounded property.

Use the verified-reading protocol for donor fragments. A donor receipt does not certify V3 design or runtime.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact paths and causal property. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not comprehension or runtime proof.
<!-- eliot-doc-routing:end -->

For V3 prose, verify version/status consistency, links, ownership, normal/failure paths, source attribution and `git diff --check`. Raw research, generated bundles/receipts and temporary review notes remain outside source tree.