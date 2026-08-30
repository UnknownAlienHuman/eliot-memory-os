## I10.6. OpenCode HTTP/SSE profile

**Priority:** PRIMARY-2 route. **Status:** PROVISIONAL until exact installed server, provider account and event semantics pass RGF-AGENT-ROUTES/RGF-AGENT-ROUTES.

```text
local authenticated server;
public OpenAPI HTTP operations;
global/project SSE event streams;
session create/read/fork/abort/diff/reconcile;
provider/model discovery and actual route receipt;
server bind restricted to loopback profile.
```

OpenCode internal SQLite/Drizzle/storage is not a public recovery contract. Normal reconciliation uses ELIOT attempt journal + health/session/event API + worktree/artifact state. Exact-version read-only forensic snapshots may be used only with explicit degraded receipt and never override contradictory public API evidence.

OpenCode native agents/plugins are optional runtime-local optimizations. ELIOT owns task DAG, budgets, authority and finish.

