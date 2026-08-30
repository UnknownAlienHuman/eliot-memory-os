## A0.9. Current Strategic Defaults

ELIOT is a local-first system for mainstream desktop users, primarily on Windows.

Current strategy:

| Default | Rationale |
|---|---|
| Rust for the daemon and control plane | Memory safety, predictable native concurrency, low overhead, and suitability for a long-lived local service |
| Hybrid canonical storage such as SurrealDB | Graph, document, temporal, and structured state should remain under one governed owner rather than diverging stores |
| Windows-first operations | Primary users and agent tools run on Windows; a local-first product must operate as a first-class service there |
| Models, agents, and tools from multiple vendors | Capability contracts reduce lock-in and permit changes in cognitive and failure profile without rewriting ELIOT |

These are Defaults, not permanent Invariants. Replacement is permitted when the Architecture, migration path, and demonstrated operational benefit are preserved. Micro-modularity, isolation, staged promotion, and hot-path discipline are architectural properties; concrete language packages, sandbox or component runtimes, and process technologies are only current Implementation mappings.

---
