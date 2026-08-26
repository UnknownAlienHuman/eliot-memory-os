# Perplexity mechanisms versus ELIOT

## Scope and authority

This is a donor/mechanism audit, not a change to ELIOT Architecture or Implementation. Per ELIOT Implementation I0.11, external projects and audits are evidence/mechanism donors; they do not become normative authority.

Baseline used:

- canonical `ELIOT_ARCHITECTURE.md` 4.5-draft in `C:\Development\Rust\docs\ELIOT Arhitecture`;
- canonical `ELIOT_IMPLEMENTATION.md` current working document;
- current repository identity at audit start: `C:\Development\Rust\projects\eliot-memory-os`, HEAD `8af3984b9a3059fe1b8950337f432065cc7a85f4`;
- no assumption that a prose schema or source type is `CURRENT_VERIFIED` without exact Product Identity and executed evidence.

## Gap matrix

| # | Perplexity mechanism | Static/official evidence | ELIOT correspondence | Gap / risk | Disposition |
|---:|---|---|---|---|---|
| 1 | Remote advisor returns text only; local orchestrator retains tools/files/action authority | official research article + PII/advisor RPC strings | WorkScope, Authority, Task Controller, provider-neutral routes, no hidden authority | ELIOT has the broader authority model, but a concrete `advice-only` route contract and outbound-context receipt could make the boundary easier to verify | `ADOPT_AS_TYPED_ROUTE`, no architecture change |
| 2 | Tool execution disables itself when sandbox cannot be trusted | official fail-closed claim + `trusted bwrap could not be probed`, seccomp/cgroup/network strings | Hard Boundary fail-closed, Experimental Contour, Instrument/ProcessExecutor policy | Perplexity static audit cannot prove runtime branch; ELIOT must not equate OS sandbox with semantic authority | `ADAPT_AND_VERIFY` with fault injection |
| 3 | Minimal core tools; skills loaded on demand; capability tools appear only after skill load | bundled manifest/README, embedded Rust allowlists | Tool Definition, Active Understanding View, Effective Context Profile, RuleBinding | ELIOT context compilation is richer, but can still over-render schemas/instructions | `ADOPT_MEASURED_CONTEXT_DELTA`; preserve exact rule/provenance bindings |
| 4 | Deterministic orchestrator controls loop; model only proposes actions | official article + Rust orchestrator paths | Governor/application authority, Harness, Task Controller | Strong alignment. Perplexity policy evidence is mostly binary/prose and lacks ELIOT-style receipt/revision binding | `ALREADY_ALIGNED`; use as external validation, not donor code |
| 5 | SQLite automation scheduler with unique claims, states and abandoned-run recovery | exact SQL strings/indexes/state values | Durable Job, checkpoint, owner, State Fence, cancellation, outcome, receipt; Watchdog scheduler | Perplexity schema is concrete and compact; ELIOT requires canonical owner, fencing, receipts and cross-scope ordering beyond a local claim row | `ADAPT_PROTOCOL`, never introduce a second canonical scheduler writer |
| 6 | Electron supervises RPC sidecar with bounded retry and terminal rejection | ASAR lifecycle code, five-failure limit | Host Supervisor, Authority Epoch, fencing, Recovery View | Restart loop has no observed durable generation/epoch fence or recovery receipt; stale child output risk is not visibly addressed at Electron layer | `REJECT_AS_SUFFICIENT`; borrow bounded backoff only |
| 7 | Pinned model/image catalogs, explicit supervised-container label, stale-container cleanup | Rust catalog strings and pinned digest | Module Registry, Product Identity, installed artifact/generation hashes, CurrentSystemEvidenceSnapshot | Good supply-chain granularity, but exact download manifest/signature/license and rollback receipts are unavailable | `ADOPT_MANIFEST_SHAPE`, require provenance/admission before activation |
| 8 | Search/connectors run through broker/compact CLI surfaces; sandbox helper has no direct key/network | template config + `pplx-search` Unix-socket symbols + official connector claims | typed Instrument routes, capability/visibility boundaries, integration receipts | Compact context is useful; broker must not become hidden authority or opaque data egress | `ADOPT_BROKER_PATTERN` with ActualRouteReceipt and privacy policy |
| 9 | Health hooks trigger model self-verification | official research article | Verifier, CompletionGate, truth surfaces, honest finish | Self-verification improves trajectory but is not independent proof and cannot establish `DONE_VERIFIED` | `ADOPT_ONLY_AS_TRIGGER`; never as completion authority |
| 10 | Durable trajectory/event persistence and interrupted-exchange recovery | SQL/event sequences, trajectory encode/decode/persist strings | Canonical Memory, single history/write path, revision, provenance, receipt, Route Continuation State | Perplexity confirms durability but not bitemporal truth, claim/evidence separation, writer ownership or artifact binding | `ADAPT_CAPTURE_MECHANICS`; retain ELIOT canonical semantics |

## Highest-value mechanisms for ELIOT

### 1. Advice-only external cognition route

Implement or tighten a route profile whose output type is guidance only:

```text
local controller selects bounded context
→ privacy classifier and Human policy
→ outbound-context preview/receipt
→ remote advisor returns text
→ local controller may accept/reject
→ only local authority may invoke tools or write canonical state
```

This fits ELIOT’s provider-neutral model and prevents remote-model quality from silently becoming action authority.

Acceptance probes:

- advisor cannot receive tool handles, leases or raw credentials;
- denied context never appears in outbound request;
- advisor output cannot directly satisfy CompletionGate;
- every call has route identity, context digest, policy decision and cost/privacy receipt.

### 2. Trusted-sandbox admission probe

Perplexity’s `bwrap` negotiation suggests separating “binary present” from “trusted sandbox executable under negotiated policy.” ELIOT should admit a sandbox generation only after a trivial contained probe and reject tool execution if the probe cannot establish the required boundary.

Required additions beyond Perplexity evidence:

- exact sandbox binary/artifact hash;
- mount/network/seccomp policy digest;
- host capability snapshot;
- negative tests for symlink, home ancestor, sensitive paths and network;
- generation fence and execution receipt.

### 3. Context-efficient capability loading

Perplexity’s small core tool surface and explicit `load_skill` path are a useful empirical candidate for ELIOT Effective Context Profiles.

Do not copy the “description only” selection as an unverified universal rule. Test per model × harness × task family:

- prompt tokens saved;
- tool-selection accuracy;
- missed capability rate;
- stale skill/rule risk;
- quality after compaction;
- recovery rate after incorrect skill selection.

### 4. Concrete durable-run claim/recovery state machine

The compact states `claimed → running → succeeded|failed` plus recovery index are useful as an implementation discriminator for ELIOT Durable Job, provided they sit behind the one Governor/canonical owner.

ELIOT extensions required:

- `authority_epoch` and fenced owner;
- `state_fence`;
- checkpoint/artifact identity;
- cancellation and supersession;
- immutable outcome/receipt;
- recovery directive when resumption is unsafe.

### 5. Pinned runtime catalog and supervised resource labels

Adopt the principle that model/container/runtime selection resolves to immutable identities before activation. Improve it with:

- signed download manifest;
- expected bytes/hash/license;
- compatible hardware/driver profile;
- declared storage impact;
- rollback/uninstall recipe;
- provenance and admission receipt.

## Negative lessons

### Default telemetry versus local-first claims

Static ASAR shows packaged-build Sentry/Datadog default enablement. ELIOT should keep observability identity, payload classes, retention and network effects explicit in Governance Profile; “local-first” cannot imply “no egress.”

### Binary-only policy is difficult to independently certify

Perplexity has strong-looking sandbox/PII/orchestration design, but core source/license and reproducible build mapping are unavailable. ELIOT should not delegate canonical authority to an opaque component solely on marketing claims or strings. Opaque integrations need a lower Governance Profile, strict effect ceiling and independent black-box probes.

### App-owned automation is not system-owned durable work

Bundled instructions say automations run while the app/local mode is active. ELIOT Durable Jobs require lifecycle ownership that survives UI loss and preserves canonical state; do not copy the desktop-process dependency.

## Recommended bounded experiments

1. `AdvisorAdviceOnlyContract` prototype with fake remote provider and outbound-context receipts.
2. `SandboxAdmissionProbe` corpus covering unavailable/untrusted bwrap, symlink escapes and denied network.
3. Effective Context Profile A/B test: full tool catalog versus on-demand skill/tool expansion.
4. Durable Job recovery capsule using Perplexity-like claim states plus ELIOT epoch/fence/receipt fields.
5. Runtime Artifact Manifest schema for model/container download size, digest, license, hardware and rollback.

Each experiment should remain an isolated no-authority contour until its verifier and Product Identity evidence are admitted.

## Architecture decision

No Architecture or Implementation files were changed. The audit supports five bounded mechanism candidates, but does not justify a new canonical state owner, a second scheduler, a Perplexity dependency or an opaque binary in ELIOT’s authority path.

