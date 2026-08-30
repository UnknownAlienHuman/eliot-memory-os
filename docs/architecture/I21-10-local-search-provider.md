## I21.10. Local search provider

The local provider prepares and retrieves local data. For each local namespace it admits, it is the sole authoritative mutable owner of source identity and revisions, safe no-execute reads, materialization, unitization, exact, lexical, structural, and optional semantic projections, publication, and coherent readback. ELIOT stores immutable `SourceRevisionRef` values and governed admission or influence records; it does not mint a competing source revision. The provider is a separate product with its own repository, contracts, and delivery gates.

The ELIOT-facing boundary is fixed here:

```text
ELIOT compiles a typed request and a scoped read grant;
the provider returns candidates, coverage, freshness, provider assurance and reason codes;
the provider never receives canonical credentials, task authority, admission or finish authority;
the provider never returns an ELIOT memory disposition;
provider availability is planning information, not permission.
```

A capability descriptor supplies supported recipes, available profiles, visible-scope readiness, observation freshness and degraded reason codes. Coverage claimed by ELIOT is bounded by what the descriptor actually supports; an unavailable provider produces an explicit gap, never a silent narrowing.

