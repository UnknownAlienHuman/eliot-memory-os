# Documentation map

## Current work: V3 design

V1/V2 Memory implementations are archived donors. V3 is a fresh implementation target; these documents are design authority, not runtime evidence.

| Need | Current V3 source |
|---|---|
| Reading order and proof ceiling | [v3/README.md](v3/README.md) |
| Product purpose, authority and invariants | [v3/ARCHITECTURE.md](v3/ARCHITECTURE.md) — draft.19 |
| Runtime, Store/query contract and implementation order | [v3/IMPLEMENTATION.md](v3/IMPLEMENTATION.md) — draft.40 |
| Reconstruction, retrieval and learning algorithms | [v3/COGNITION.md](v3/COGNITION.md) — draft.23 |
| Memory↔controller V2 boundary | [v3/INFERENCE-CONTRACT.md](v3/INFERENCE-CONTRACT.md) — Contract 0.18 |
| Active decisions, gaps and queue | [v3/ANALYSIS-REGISTRY.md](v3/ANALYSIS-REGISTRY.md) |
| Evidence and donor rationale | [v3/AUDIT.md](v3/AUDIT.md), [v3/AUDIT-MAP.md](v3/AUDIT-MAP.md) |
| Version precedence | [ARCHITECTURE_CONTRACT.md](ARCHITECTURE_CONTRACT.md) |

Read Architecture, Implementation, Cognition and Inference Contract together for a load-bearing boundary. `ANALYSIS-REGISTRY.md` is the only active audit/work ledger.

### Current load-bearing decisions

- daemon owns application state, controller-mutation serialization, backup-set transitions and bounded restore leases;
- supervisor owns privileged Store lifecycle, candidate process/root and final cutover;
- final backup directory first appears with a durable canonical fence already inside;
- terminal abort/retire records remain authoritative after content cleanup;
- restore retains directory/fence/manifest handles and streams one verified part at a time under finite limits;
- migration bundle identity includes runner protocol, wrapper template, DDL and expected catalog;
- schema admission compares plain `INFO` maps, never unstable `STRUCTURE` or raw JSON order;
- scored FTS uses numbered match references and bounded top-K snapshots, not durable lexical cursors;
- controller issue #200 separates allocation, selected pointer and native effect;
- issue #199 remains blocked on #200 and V2 L0/L1.

## Retained V2 donor documentation

The remaining `docs/architecture/`, `docs/normative-pair.toml`, source, scripts and workstream records describe V2. Their status words are historical unless a current V3 owner document explicitly adopts a bounded property.

Use the verified-reading protocol for donor fragments. A donor receipt does not certify V3 design or runtime.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for exact paths and causal property. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not comprehension or runtime proof.
<!-- eliot-doc-routing:end -->

For V3 prose, verify version/status consistency, links, ownership, normal/failure paths, source attribution and `git diff --check`. Raw research, generated bundles/receipts and temporary review notes remain outside source tree.