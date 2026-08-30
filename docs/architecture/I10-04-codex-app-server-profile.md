## I10.4. Codex App Server profile

**Priority:** PRIMARY-1 ELIOT route. **Status:** PROVISIONAL as an ELIOT integration until exact-version, current-account and recovery proof pass. The upstream App Server publishes a stable schema surface and separately gates experimental methods/fields; ELIOT pins the stable-only generated schema by default and admits each experimental operation independently.

Candidate local transport for the P0 pilot:

```text
`codex app-server --listen stdio://`;
JSON-RPC-lite over newline-delimited JSON;
one supervised process or bounded tenancy profile;
exact generated schema pinned to executable hash.
```

It becomes an admitted ELIOT route only after exact-version conformance and recovery tests. The installed generation remains pinned and immediately replaceable because the protocol evolves with the executable; however, ELIOT does not mislabel the stable schema subset as experimental. Any opt-in experimental API stays disabled unless its exact descriptor, capability negotiation, negative tests and rollback path are admitted separately.

WebSocket listener is experimental and not a production dependency. Integration covers thread/turn/item events, approvals, interrupt, result reconciliation and supported native session operations.

Rules:

```text
skills/MCP/config are installed through ELIOT integration lifecycle;
plugin mutation APIs are not a v1 dependency;
native child agents are optional runtime-local accelerators;
child output is candidate evidence, never task completion;
model/effort/service-tier and actual route require receipts/probes;
crash, interrupt, unknown outcome, resume/fork and descendant cleanup are mandatory tests.
```

Codex agent never receives SurrealDB endpoint or canonical write authority.

A ChatGPT-subscription or desktop-profile Codex route declares `execution_identity = interactive_user` and runs through the authorized User Broker. An API-key or otherwise service-safe Codex route may use `execution_identity = service` only when its credentials, retention and network policy are explicitly approved for the service identity. The two are separate `RuntimeRoute` fingerprints and continuity does not transfer silently between them.

