## I10.3. Bridge types

```text
MCPBridge      — external MCP server/client;
CliBridge      — supervised subprocess with structured stdout/files;
HttpBridge     — local/remote API;
LspBridge      — language server;
GraphBridge    — code/dependency graph;
ModelBridge    — provider/local model;
StoreBridge    — canonical storage;
AppBridge      — professional software/API;
CloudBridge    — AWS/lab/remote compute;
ResearchBridge — acquisition/indexing corpus.
```

All expose EBP capability contracts to internal system.

### Tool and adapter route selection

Normal exact calls are routed automatically from Capability Registry, WorkScope Profile and current health; the agent is not asked to choose among equivalent tools. A `ToolRouteDecision` is recorded only when the choice is expensive, side-effectful, ambiguous, privacy-sensitive or materially changes proof quality.

Selection considers:

```text
property/capability match and exactness;
truth/evaluation competence;
freshness and health;
State Fence and WorkScope fit;
latency/cost/resource envelope;
side effects and authority;
privacy/source assurance;
known failure profile and overlap with already available evidence;
expected information, decision or verification delta.
```

A call whose expected delta is negligible is skipped or deferred. This is a routing optimization, not a requirement that the Main Agent write an essay before every tool call.

### Execution identity boundary on Windows

Every route profile declares `execution_identity = service | interactive_user | remote`. `interactive_user` routes are launched only through the authorized User Broker of I1.3. A bridge cannot silently switch execution identity to obtain subscriptions, desktop state or credentials.

