# ADR 0008: Surrealist interaction patterns without a second control plane

## Status

Accepted for Phases L10-L12.

## Context

The completed Memory OS needs a productive native inspection surface for memory,
provenance, replay, autonomy, and maintenance. Surrealist demonstrates useful
Explorer, Designer, Query, graph, saved-view, and command-palette interactions,
but its React/Vite/Bun/Tauri implementation and direct database administration
model do not satisfy ELIOT's authority boundary.

## Decision

`Eliot.Operator.exe` remains a Windows-native WinUI 3 projection over the active
Governor runtime:

```text
WinUI Operator
  -> ActiveRuntimeManifest discovery
  -> generation-bound authenticated named pipe
  -> typed Governor read projections and commands
  -> CanonicalStore / WriterActor receipts
```

The following donor patterns are translated, not embedded:

| Donor pattern | Native ELIOT projection |
|---|---|
| Explorer | paged Memory, Evidence, Experience, Task, and Receipt views |
| Designer | read-only canonical object/relation/authority/schema catalogue |
| Query View | saved semantic filters over bounded typed Governor read APIs |
| Graph result | expand-on-demand causal/provenance/supersession/replay slices |
| Command palette | native palette containing only typed Governor commands |
| Context dashboard | project scope, host sessions, evidence, entities, and trace statistics |
| Scoped principals | explicit OperatorSession/AgentSession identity and receipted role leases |
| Credential rotation | existing runtime/auth generation reconnect with stale-auth rejection |

The Operator must not:

- carry SurrealDB credentials or connect to the database;
- accept arbitrary SQL, SurrealQL, shell, or JSON mutation payloads;
- own durable workflow, policy, truth, memory, or cache state;
- expose hidden chain-of-thought;
- introduce WebView2, a browser UI, Tauri, Electron, Node, or a second HTTP
  control server.

All durable mutations are typed commands. The Governor validates scope,
revision, risk, approval, and idempotency, performs the canonical write, and
returns a receipt. The client may retain only transient presentation state such
as the selected page, an unsubmitted filter, or cancellation state.

## Progressive-disclosure limits

Explorer and graph operations require a selected project or task, an explicit
filter, page and payload budgets, and continuation cursors. Graph expansion is
bounded to a selected neighborhood; whole-database graph loading is rejected.
Semantic queries are allow-listed Governor operations and never arbitrary
database text.

These limits preserve UI responsiveness and prevent an inspection request from
becoming an unbounded database or memory export.

## Native dependency decision

No additional graph or UI dependency is required for L10-L12. WinUI controls,
virtualized collections, and native drawing primitives are sufficient. A future
native graph dependency requires a separate maintenance, license, binary-size,
accessibility, and security review before adoption.

## Consequences

- Governor and CanonicalStore remain the only product authority.
- Operator reconnect and stale-auth behavior use the same production IPC path
  as other local clients.
- Surrealist is not a runtime, build, release, or availability dependency.
- An optional admin-only read-only Surrealist diagnostic path remains outside
  normal operation and is not required for product completion.
