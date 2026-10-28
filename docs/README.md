# Documentation map

[V3 task routes](v3/README.md#task-routes) select the sections needed for a change.
[Documentation stages](v3/ANALYSIS-REGISTRY.md#documentation-stages) select what
needs correction next. Do not preload all owner documents or the audit.

| Surface | Owns |
|---|---|
| [Architecture authority](ARCHITECTURE_CONTRACT.md) | Version boundary and document precedence |
| [Architecture](v3/ARCHITECTURE.md) | Product purpose and invariants |
| [Implementation](v3/IMPLEMENTATION.md) | Runtime, data, operations and implementation order |
| [Cognition](v3/COGNITION.md) | Reconstruction, retrieval and learning algorithms |
| [Inference contract](v3/INFERENCE-CONTRACT.md) | Proposed Memory/controller boundary; compatibility needs reconciliation |
| [Existing registry](v3/ANALYSIS-REGISTRY.md) | Current findings, evidence limits and next work |
| [Audit](v3/AUDIT.md) / [source map](v3/AUDIT-MAP.md) | Rationale, requirement coverage and donor evidence; consult on demand |
| [Store candidates](v3/store/README.md) | Subordinate design assets, not qualified runtime |

An index links to the owning rule; it does not repeat it. Keep revision metadata
in owner documents and dated external observations in the registry. A conflict
is fixed in the owners, not by appending a new equally authoritative document.

## Retained V2 donor documentation

`architecture/`, `normative-pair.toml`, [PROJECT_MAP](PROJECT_MAP.md),
[code navigation](CODE_NAVIGATION.md) and old workstreams describe the retained
V2 checkout. Their historical status words do not establish V3 support.

The following generated block applies only to explicitly assigned retained V2
edits. V3 prose uses direct task-scoped reading; required CI is not waived.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for exact paths and causal property. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not comprehension or runtime proof.
<!-- eliot-doc-routing:end -->

Work rules and checks live in [AGENTS](../AGENTS.md) and [WORKFLOW](../WORKFLOW.md).
