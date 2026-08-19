# Domain: Integrations, agents/swarm, surfaces (CLI + Operator UI), human control, module/generation registry, release & promotion, Rust workspace topology

> STATUS: IN PROGRESS — Q1 answered. File is rewritten after each question.

## Scope covered

(to be completed)

---

## Q1. Workspace topology / dependency law

### 1a. The two named docs contain no layering law at all

- `docs/PROJECT_LAYOUT.md` is 21 lines. It is a directory-purpose table only. It states **no** dependency rule, no layer, no direction.
- `docs/DEPENDENCY_POLICY.md` is 130 lines and is **entirely a third-party licensing policy** (`docs/DEPENDENCY_POLICY.md:3` `## Licensing posture`, sections 1–8 + component notes on `sha2`, SurrealDB, `wasmtime`). It contains no intra-workspace dependency direction rule.

So "does the layout obey PROJECT_LAYOUT + DEPENDENCY_POLICY" cannot be answered against those files — **the repository has no written internal dependency law**. The law lives only in the normative pair, `I2.3` (`ELIOT_IMPLEMENTATION.md:2121`):

```
C4 process/surface composition  → C3 adapters/instruments → C2 application services
   → C1 pure domain cores → C0 primitives/contracts
Dependency direction только наружу:  C4 → C3 → C2 → C1 → C0
"Допустима зависимость на более глубокий стабильный contract,
 но не на implementation более высокого слоя."
```
(`ELIOT_IMPLEMENTATION.md:2186-2201`)

`docs/PROJECT_LAYOUT.md` is also **stale against the tree**: it lists `crates/ apps/ config/ migrations/ integrations/ scripts/ tests/ docs/*` and does **not** mention `bins/` (15 packages), `plugin/` (2 packages), or `workspace/tools/` (2 packages) — all of which exist and 17 of which are workspace members (`Cargo.toml:3`, `Cargo.toml:111-125`).

### 1b. Layering violations found by reading manifest edges

Measured from `cargo metadata --no-deps` over all 123 members (all dep kinds: normal/dev/build). Directory family used as the layer proxy (`crates/foundation` = C0, `crates/governor|smart` = C2, `crates/instrument|storage|kernel` = C3, `crates/surfaces` + `bins/` = C4).

| # | Edge | Evidence | Why it violates `I2.3` |
|---|---|---|---|
| V1 | `crates/governor/eliot-skill` → `crates/surfaces/eliot-skills` | `crates/governor/eliot-skill/Cargo.toml:11` `eliot-skills.workspace = true` | **C2 → C4.** A governor application service depends on a *surface* crate. This is the single clearest inversion in the tree: the surface layer is the outermost composition layer and nothing below it may import it. `crates/surfaces/eliot-skills/src/contract.rs` is 3049 lines, so this is not a thin re-export. |
| V2 | `crates/foundation/eliot-protocol` → `crates/agent/eliot-agent-contracts`, `crates/instrument/eliot-instrument-api` | `crates/foundation/eliot-protocol/Cargo.toml:10`, `:13` | **C0 → C3-family.** The protocol contract hub imports from the agent and instrument families. `I2.3` (`ELIOT_IMPLEMENTATION.md:2205-2213`) requires a contract hub to have *minimal* dependencies and to not become a dumping ground. Mitigating: both targets are themselves `-contracts`/`-api` crates, so this may be a *directory placement* error rather than a true layer inversion — but the physical topology encodes the wrong answer either way. |
| V3 | `crates/foundation/eliot-rules` → `eliot-agent-contracts`, `eliot-instrument-api` | `crates/foundation/eliot-rules/Cargo.toml:10`, `:13` | same as V2 |
| V4 | `crates/foundation/eliot-evaluation-contracts` → `eliot-instrument-api` | `crates/foundation/eliot-evaluation-contracts/Cargo.toml:12` | same as V2 |
| V5 | `crates/kernel/eliot-process` → `crates/instrument/eliot-instrument-api` | `crates/kernel/eliot-process/Cargo.toml:11` | Kernel process layer imports an instrument-family contract. Combined with the 9 `instrument → kernel` edges (all `crates/instrument/eliot-instrument-*` → `crates/kernel/eliot-process`), instrument and kernel are **mutually entangled at the family level** — not a Cargo cycle (different crates), but the two families are no longer independently layered. |
| V6 | `crates/storage/eliot-blob-api` → `crates/kernel/eliot-platform` | `crates/storage/eliot-blob-api/Cargo.toml:10` | A storage **API/contract** crate depends on the kernel platform adapter. `eliot-blob` does too (`crates/storage/eliot-blob/Cargo.toml:11`) — that one is defensible; the `-api` one is not. |
| V7 | `crates/governor/eliot-change-monitor` → `crates/agent/eliot-agent-contracts` | `crates/governor/eliot-change-monitor/Cargo.toml:10` | C2 → agent family; contract-only target, lower severity. |

Full cross-family edge census (from → to, count): `bins→kernel 34`, `governor→foundation 32`, `kernel→foundation 25`, `surfaces→foundation 24`, `bins→foundation 23`, `storage→foundation 16`, `instrument→foundation 12`, `smart→foundation 10`, `bins→surfaces 9`, `instrument→kernel 9`, `agent→foundation 7`, `bins→instrument 6`, `modules→foundation 6`, `surfaces→kernel 6`, `bins→storage 5`, `security→foundation 5`, … and the inverted ones above. The dominant direction is correct; the violations are a small, nameable set (7 edges / ~10 dependency declarations).

No Cargo cycle exists (Cargo would refuse to build; `cargo metadata` succeeded).

### 1c. Root manifest vs `I2.3`

- `I2.3` prescribes `members = ["crates/*", "bins/*", "tests/*"]`. Actual `Cargo.toml:2-126` is an **explicit hand-maintained list of 123 paths**, and `tests/` contains **no** Cargo packages at all (`tests/` holds `Eliot.Operator.Tests`, `cognitive`, `harness-security`, `release-security` — no `Cargo.toml` anywhere under it). Divergence, low severity: the explicit list is arguably safer than a glob.
- `resolver = "3"` at `Cargo.toml:135` — matches `I2.3`.
- `default-members` at `Cargo.toml:127-134` = 6 binaries — matches the `I2.3` intent ("daily core packages and primary binaries only").
- `I2.3` "Federated workspaces" prescribes `/workspace/core`, `/workspace/modules`, `/workspace/lab`, `/workspace/tools`. Only `workspace/tools/` exists (`eliot-runtime-compiler`, `eliot-campaign-executor`, `Cargo.toml:124-125`) — and it is a **member of the root workspace**, i.e. not federated at all. This is consistent with the doc's own escape hatch ("До доказанного cache/dependency конфликта допускается один root workspace", `ELIOT_IMPLEMENTATION.md:2158`), so not a violation.

### 1d. Orphans — 60 of 123 crates have zero dependents; 41 are library-only dead weight

Computed from the full workspace reverse-dependency map (all dep kinds).

- **60 / 123** workspace members have **zero** workspace dependents.
- **19** of those legitimately produce a `bin` target (the 15 `bins/*`, plus `crates/eliot-app` → bin `eliot-governor`, `crates/agent/eliot-agent-opencode` → bin `eliot-opencode-bootstrap`, and the 2 `workspace/tools/*`). Those are expected leaves.
- **41 are library-only crates that nothing in the workspace depends on** — they compile, they are clippy-clean, they have tests, and **no binary can reach them**:

```
crates/agent/eliot-agent-acp            crates/agent/eliot-agent-codex
crates/agent/eliot-agent-coordinator    crates/agent/eliot-swarm
crates/surfaces/eliot-mcp               crates/surfaces/eliot-controlboard
crates/governor/eliot-budget            crates/governor/eliot-read
crates/smart/eliot-memory               crates/smart/eliot-memory-curation
crates/smart/eliot-cues                 crates/smart/eliot-epistemic
crates/smart/eliot-understanding        crates/smart/eliot-dreamer-core
crates/smart/eliot-system-experience    crates/meta/eliot-improvement
crates/security/eliot-erasure           crates/security/eliot-influence
crates/storage/eliot-backup             crates/storage/eliot-ecxf
crates/storage/eliot-store-memory       crates/kernel/eliot-host-service
crates/foundation/eliot-test-support
crates/instrument/{eliot-artifact, eliot-build-test-graph, eliot-code-cortex,
  eliot-code-graph, eliot-diagnostic, eliot-empirical-profile, eliot-observability,
  eliot-product-evaluation, eliot-reports, eliot-test-selection, eliot-verifier,
  eliot-instrument-cargo, eliot-instrument-dotnet, eliot-instrument-nextest,
  eliot-instrument-runner, eliot-instrument-rustc, eliot-instrument-rustfmt,
  eliot-instrument-scip}
```

Cross-checked by raw manifest grep: `eliot-mcp`, `eliot-swarm`, `eliot-controlboard`, `eliot-agent-coordinator` appear in **no** `Cargo.toml` other than their own. By contrast `eliot-cli` has 6 dependents (`bins/eliot`, `bins/eliot-agent-bridge`, `bins/eliot-dreamer`, `bins/eliot-native-worker`, `bins/eliot-notify`, `bins/eliot-user-broker`), so the graph computation is sound.

Consequence for the whole audit: **"2258 tests pass" and "clippy clean over 123 crates" cover a large body of code that is not on any production call path.** Per the brief's evidence rule, a crate with no dependent cannot be `IMPLEMENTED` (nothing calls it) — at best `SHELL` at the wiring level, however complete its internals.

---

## Q2. CLI (`bins/eliot` + `crates/surfaces/eliot-cli`)

`bins/eliot/src/main.rs` is 285 lines and exposes only **5 clap subcommands** (`bins/eliot/src/main.rs:26-41`): `catalogue {help|schema|validate}`, `dispatch`, `system snapshot`, `version`, `ui`. Every `Appendix J` command exists instead as a `CommandId` variant in a **command catalogue** (`crates/surfaces/eliot-cli/src/lib.rs:30-56`, revision `"a11-plan-v2"` at `:21`) that is submitted as one JSON `CommandRequest` on stdin via `eliot dispatch` and forwarded to the Kernel over an authenticated named pipe.

**The catalogue self-declares 24 of its 25 commands as not implemented.** Each `CommandSpec` carries `availability: CommandAvailability::{Admitted|PlanGap|Unsupported}` (`crates/surfaces/eliot-cli/src/lib.rs:1004-1017`). Grep result: `CommandAvailability::Admitted` appears exactly **once** in the static table, at `crates/surfaces/eliot-cli/src/lib.rs:1036` (`system-snapshot`). Every other row is `PlanGap`. `Unsupported` is never used in the table at all. `execute()` (`:1493-1501`) refuses to run an `Admitted` command locally, and returns a typed `Unavailable` for everything else.

| # | `Appendix J` command | Exists in catalogue | Real behaviour or stub | Evidence |
|---|---|---|---|---|
| 1 | `eliot system snapshot` | yes, **Admitted** | **REAL.** `bins/eliot/src/main.rs:124-134` calls `eliot_bootstrap::capture::capture_snapshot(&repo_root)` then `write_snapshot_artifact`. Local, does not need the Kernel. | `main.rs:7`, `:128-129`; availability `eliot-cli/src/lib.rs:1036` |
| 2 | `eliot bootstrap brief --work-unit` | yes | STUB — `PlanGap { missing_work_id: "A-06", dependency: "eliot-mcp" }` | `eliot-cli/src/lib.rs:1047-1050` |
| 3 | `eliot recovery status` | yes | STUB — `PlanGap` on `eliot-mcp` | `eliot-cli/src/lib.rs:1061-1064` |
| 4 | `eliot ui` | yes + clap subcommand | **STUB, and the stub is hard-coded.** `KernelClient::ensure_operator_launch()` builds the `OperatorLaunchRequest` into `let _request` and then unconditionally `Err(FrontDoorClosed(...))` — no I/O at all. | `crates/surfaces/eliot-cli/src/lib.rs:514-525` |
| 5 | `eliot dashboard` | yes | STUB — `PlanGap { missing_work_id: "A-08", dependency: "eliot-controlboard" }` | `eliot-cli/src/lib.rs` static table (`Dashboard` row) |
| 6 | `eliot dev impact --changed` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 7 | `eliot dev check --changed` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 8 | `eliot dev test --changed` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 9 | `eliot dev pulse --objective` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 10 | `eliot instrument run --profile` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 11 | `eliot module validate` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 12 | `eliot module test` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 13 | `eliot module contract-test` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 14 | `eliot module edge-test` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 15 | `eliot module build` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 16 | `eliot module stage` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 17 | `eliot module canary` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 18 | `eliot module promote` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 19 | `eliot module rollback` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 20 | `eliot release verify` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 21 | `eliot doctor integration` | yes | STUB — `PlanGap` on `eliot-mcp`. The `bins/eliot-doctor` binary is a **22-line refusal**: `main()` writes `KERNEL_ADMISSION_REQUIRED` to stderr and `exit(78)`. | `bins/eliot-doctor/src/main.rs:13-22` |
| 22 | `eliot backup create` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 23 | `eliot backup verify` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 24 | `eliot backup restore-test` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| 25 | `eliot maintenance run` | yes | STUB — `PlanGap` on `eliot-mcp` | same table |
| — | `eliot catalogue help/schema/validate` | not in `Appendix J` | **REAL** deterministic projection of the static table | `bins/eliot/src/main.rs:265-276`; `eliot-cli/src/lib.rs:1457,1474,1444` |
| — | `eliot dispatch` | not in `Appendix J` | **REAL transport.** Reads one `CommandRequest` from stdin, forwards via `KernelClient::transact_json("eliot.cli.command", …)` over an authenticated Windows named pipe with SID + session-id peer expectation and a `ClientHello`/`ServerHello` handshake bound to generation/authority-epoch/artifact-digest. | `bins/eliot/src/main.rs:161-208`, `:242-263`; `eliot-cli/src/lib.rs:548-600` (`connect`, `NamedPipeTransport::connect_authenticated`, `NamedPipePeerExpectation`) |
| — | `eliot version` | not in `Appendix J` | REAL (prints `CARGO_PKG_VERSION`) | `bins/eliot/src/main.rs:81-84` |

**Score: 1 of 25 `Appendix J` commands does real work. 24 are typed, tested, honest refusals.**

Two observations that matter more than the score:

1. **The refusals are architecturally correct, not fake.** `CommandResponse::validate_for` (`eliot-cli/src/lib.rs:1573-1611`) makes it a hard error for a `PlanGap` command to return a `Forwarded` payload, and the doc comment on `dispatch` (`:1567-1571`) says explicitly the catalogue "must never convert that metadata into local authority or a fake success". `crates/surfaces/eliot-cli/tests/cli_contract.rs:177` (`missing_a06_and_a08_operations_are_typed_unavailable`) and `:317` (`full_request_identity_and_intended_effect_survive_unavailable_results`) pin this. This is the opposite of the usual `todo!()` problem — the CLI is a correct thin client over a Kernel that does not yet advertise the operations.
2. **The two blockers named by the CLI are exactly the two orphan crates from Q1.** 22 rows block on `eliot-mcp`, 2 rows (`ui`, `dashboard`) block on `eliot-controlboard`. Both crates exist, compile, and have **zero workspace dependents** (Q1d). The product's entire command surface is one wiring edge away from existing — and that edge has not been made.
3. **Internal inconsistency:** the catalogue marks `ui` as `PlanGap` on `eliot-controlboard` (an unbuilt UI crate), but `bins/eliot/src/main.rs:91` routes the clap `Ui` subcommand around the catalogue directly into `run_ui()` → `ensure_operator_launch()`, whose blocker is a *different* thing ("Kernel user-broker Operator launch contract with admitted fence/clock snapshot", `eliot-cli/src/lib.rs:523`). Two different stated reasons for the same unavailable command.

---

## Q3. `A10` swarm / delegation — durable coordination

### The decisive structural fact: the repo contains TWO products

Before answering, this must be stated because it determines every status below.

`crates/eliot-app` (103,810 LOC) + `crates/eliot-engine` (64,720 LOC) + `crates/eliot-store` (14,218 LOC) + `crates/eliot-types` + `crates/eliot-windows-ipc` form a **self-contained ~185k-LOC island**. `crates/eliot-app/Cargo.toml:14-30` lists its entire ELIOT dependency set: `eliot-engine`, `eliot-store`, `eliot-types`, `eliot-windows-ipc`. It depends on **none** of the ~110 architecture-shaped crates. It builds `[[bin]] name = "eliot-governor"` (`crates/eliot-app/Cargo.toml:8-10`) — the MCP server.

Only **two** edges cross from the new tree into the island, both trivial: `crates/kernel/eliot-platform-windows/Cargo.toml:10` → `eliot-windows-ipc`, and `crates/instrument/eliot-verifier/Cargo.toml:10` → `eliot-types`.

So: the swarm mechanisms are implemented **twice**, in two disconnected halves.

### Half A — the legacy island: mailbox + blackboard are REAL and shipped

| `I10.18` element | Status | Evidence |
|---|---|---|
| Mailbox: message-id idempotency | IMPLEMENTED | `crates/eliot-engine/src/collective.rs:176-184` — `send()` returns the existing message when `message_id` already present |
| Mailbox: ordered sequence per recipient/task | IMPLEMENTED | `collective.rs:188` `next_sequence(state, project_id, task_id, &recipient)` |
| Mailbox: ack for control messages | IMPLEMENTED | `collective.rs:198-201` `requires_ack: input.requires_ack.unwrap_or_else(|| message_kind_requires_ack(input.kind))`; `acknowledge()` at `:226-237` |
| Mailbox: expiry | IMPLEMENTED | `collective.rs:239-253` `expire_stale()` moves `Pending|Delivered` → `Expired` |
| Mailbox: large payload by handle | IMPLEMENTED | `payload_ref` field, `collective.rs:196` |
| Blackboard typed items | IMPLEMENTED | `BlackboardService` at `collective.rs:55`, with `create_item/list/acknowledge/resolve/reject/supersede/expire_old` at `:73-174` |
| Agent-loss reassignment (`ARCH-SWM-02`) | IMPLEMENTED | `LostAgentRecoveryService::scan` at `collective.rs:259` |
| Agent-facing surface | IMPLEMENTED | MCP tools `eliot_blackboard_add/list/ack` and `eliot_mailbox_send/inbox/ack` registered at `crates/eliot-app/src/mcp_stdio/catalog.rs:2174-2208` |

**But its durability violates the architecture.** `WorkState` — which holds `blackboard_items` and `mailbox_messages` (`crates/eliot-engine/src/work.rs:36,38`) — is persisted as a **plain JSON file**:

- `crates/eliot-app/src/commands/support.rs:785-791` `load_work_state()` = `serde_json::from_reader(File::open(reports/work/state.json))`, defaulting to `WorkState::default()` when absent
- `:793-809` `save_work_state_and_report()` writes the whole blob back
- path: `:811-813` `root/reports/work/state.json`

No canonical store, no transaction, no `StateFence`, no authority epoch, no receipt, no operation identity. It is last-writer-wins read-modify-write on a file under `reports/` — a directory `docs/PROJECT_LAYOUT.md` does not even list. Two concurrent agents lose each other's messages.

### Half B — the architecture tree: correct logic, not wired

**`crates/governor/eliot-coordination`** — package description at `Cargo.toml:7` literally reads `"Durable, idempotent and epoch-fenced multi-actor coordination owner"`, i.e. it claims `ARCH-SWM-02` by name. The logic is genuinely good:

- epoch/fence gate on every entry point: `self.common(req.authority_epoch, &req.state_fence)?` — `src/lib.rs:647`, `:759`, and every other mutator
- idempotent lease re-acquisition: `src/lib.rs:660-675` returns the prior `WorkLeaseDecision` when the same `lease_id` re-claims, else `WorkAlreadyOwned`
- idempotent mailbox send with digest equality check: `src/lib.rs:769-783`
- leases with `expires_at`, `last_heartbeat`, `attempt` counter: `:681-693`, `:712`

Three problems:

1. **It is never driven.** `CoordinationOwner` is `use`d once (`crates/governor/eliot-governor/src/composition.rs:23`), reconstructed from a recovery snapshot (`:1062-1064`), and stored as a struct field (`:988`, `:1146`). A repo-wide grep for callers of `register_session`, `register_work`, `acquire_work`, `heartbeat`, `send_message`, `checkpoint`, `submit_result`, `reassign`, `submit_integration_candidate`, `acquire_integration`, `record_coordination_event` outside `crates/governor/eliot-coordination/` returns **zero** hits on `CoordinationOwner`. It is a state machine with no request handler. Status: **SHELL at the wiring level** despite a fully implemented body.
2. **It is not durable by itself.** `Cargo.toml:9-13` — its only ELIOT dependency is `eliot-contracts`. State is `BTreeMap` in memory. Durability is delegated entirely to Governor snapshot/recovery, which is a legitimate design, but the crate's own description overstates it.
3. **No test file.** `grep -c '#\[test\]' crates/governor/eliot-coordination/src/lib.rs` = **0**, and the crate has no `tests/` directory (`ls crates/governor/eliot-coordination/` → `Cargo.toml`, `src`). 1131 lines of fencing/idempotency logic with zero tests.

**`crates/agent/eliot-swarm`** (2546 LOC lib + 1406 LOC `repair_tests.rs`) — implements the negotiated-partition pipeline as pure admission functions: `admit_plan` (`src/lib.rs:807`), `begin_execution` (`:1159`), `admit_wave` (`:1296`), `apply_terminal_updates` (`:1402`), `accept_cross_review` (`:1517`), `selectively_replan` (`:1677`), `accept_blind_audit` (`:1806`), `accept_synthesis_contribution` (`:1971`), `synthesize` (`:2132`), `admit_concilium` (`:2218`), `checkpoint_controller` (`:2412`), `restore_controller` (`:2511`). No `todo!`/`unimplemented!`. `RECIPE = "NegotiatedInterdependentInvestigation"` at `:28`.

Durability and routing are delegated to three injected traits (`src/lib.rs:298`, `:306`, `:312`): `AgentRouteProvider`, `ReceiptVerificationPort`, `SwarmCheckpointProvider`. **The only implementations in the entire repository are test doubles**: `impl AgentRouteProvider for A02` at `crates/agent/eliot-swarm/src/repair_tests.rs:222` and `impl SwarmCheckpointProvider for M04` at `repair_tests.rs:1211`. And the crate has **zero workspace dependents** (Q1d). Status: **SHELL** — pure core is real, nothing composes it, no production provider exists. The crate even encodes this itself: `SwarmError::PlanGap(RequiredProvider)` at `src/lib.rs:112`.

**`crates/agent/eliot-agent-coordinator`** (1767 + 696 + 1090 LOC) — implements the `I10.18` live-peer delivery state machine for real: `LivePeerMessageState::Draft → Queued → Delivered` at `src/core.rs:1131`, `:1150`, `:1358-1368`, with `peer_message_payloads: BTreeMap<MessageId, LivePeerMessage>` at `:118` and `mailbox_route_handle` assignment at `:1108`. Zero workspace dependents. Status: **SHELL**.

**`crates/agent/eliot-agent-contracts`** — `AnchoredReviewItem` (`src/lib.rs:803-815`) with `ReviewLifecycle`, `validate()` (`:817-841`), `validate_resolution()` (`:843-857`) and `transition_to()`. This is a validated type, and it *is* reachable (via `eliot-protocol` → `bins/eliot`). But there is **no owner, no store, no delivery, no `ReviewBatch` envelope** — grep for `AnchoredReview` across `crates` and `bins` returns hits only inside `eliot-agent-contracts/src/lib.rs` and its own inline tests (`:1202`, `:1215`, `:1251`, `:1371`). Status: **SHELL**.

**Blackboard in the architecture tree: ABSENT.** `grep -rn -i 'blackboard'` over `crates/agent crates/governor crates/surfaces crates/foundation crates/kernel bins` returns **zero** hits. The only blackboard in the repo is the legacy one.

### Answer

**Types-plus-real-pure-logic, but not a durable multi-agent system.**

- `ARCH-SWM-02` (durable, idempotent, epoch-fenced) — the *logic* exists and is correct in `eliot-coordination`, but is `SHELL`: never invoked, never tested. The only coordination that actually runs (legacy) is idempotent and ordered but has **no epoch fence and no durable store** — a JSON file.
- Mailbox — `IMPLEMENTED` in the legacy island, `SHELL` in the architecture tree.
- Blackboard — `IMPLEMENTED` in the legacy island, `ABSENT` in the architecture tree.
- Negotiated partition — `SHELL` (`eliot-swarm`, 0 dependents, providers are test doubles only).
- Anchored review — `SHELL` (validated type, no owner).
- Live peer delivery — `SHELL` (`eliot-agent-coordinator`, 0 dependents).

---

## Q4. Integrations — which of EBP / MCP / Codex / Claude / OpenCode / ACP have real transport code

| Integration | Real transport? | Where | Status |
|---|---|---|---|
| **EBP/1** | **YES** | Contracts: `crates/foundation/eliot-protocol/src/lib.rs` (`EBP_MAJOR=1` `:32`, `Frame` `:387`, `FrameKind` `:255`, `ClientHello` `:728`, `ServerHello` `:797`). Wire transport: `crates/kernel/eliot-ipc/src/lib.rs:1195` `NamedPipeTransport`, `:1271` `NamedPipeServer` over real `tokio::net::windows::named_pipe` (`:1272`, `:1299`, `:1445`), `connect_authenticated` at `:1382` with `NamedPipePeerExpectation` (SID + session id). Reachable from `bins/eliot`, `bins/eliot-kernel`, `bins/eliot-host`, `bins/eliot-store-surreal`, `bins/eliotd`. | **IMPLEMENTED** |
| **MCP — legacy island** | **YES** | `crates/eliot-app/src/mcp_stdio*` = **40,338 LOC**. Entry `mcp_stdio::run()` at `crates/eliot-app/src/mcp_stdio.rs:704`, dispatched from clap at `crates/eliot-app/src/main.rs:2390-2404` (`Command::Mcp { McpCommand::Stdio }`). Host-aware: accepts `codex \| antigravity \| opencode \| claude \| claude-desktop` (`mcp_stdio.rs:718-724`). Access-profile scoping (`:729-751`), inherited-DB-credential rejection (`:711-714`), named-pipe IPC to a daemon (`:717`, `:753-762`). Shipped as `bin/eliot-governor.exe mcp stdio --profile codex_controller` per `plugin/eliot-governor/.mcp.json`. | **IMPLEMENTED** |
| **MCP — architecture tree** | **NO** | `crates/surfaces/eliot-mcp` (1894 LOC) is contracts + `McpCore::execute` over an injected `KernelGovernorPort` trait (`src/core.rs:244`, `:434`). Repo-wide, the **only** implementations are `impl KernelGovernorPort for NoProviderPort` at `src/core.rs:573` (fail-closed) and 6 test doubles in `crates/surfaces/eliot-mcp/tests/contract.rs:158,207,548,669,771,796`. No stdio/pipe/socket code. Zero workspace dependents. | **SHELL** |
| **OpenCode** | **YES — the best-built integration in the new tree** | `crates/agent/eliot-agent-opencode` = 5808 LOC. Hand-written HTTP/1.1 client over `tokio::net::TcpStream` (`src/http.rs:11`, `send()` at `:394-413` with connect/IO timeouts), chunked transfer decoding (`:865-868`), SSE stream reader (`src/sse.rs`, 690 LOC), loopback-only endpoint type (`src/endpoint.rs`, 311 LOC), typed API surface (`src/types.rs`, 1428 LOC), client (`src/client.rs`, 1823 LOC). Runnable binary `eliot-opencode-bootstrap`: reads `OPENCODE_SERVER_PASSWORD`/`OPENCODE_SERVER_USERNAME`, parses a `LoopbackEndpoint`, builds `BasicAuth`, `ReadOnlyRunRequest`, `OpenCodeRunPolicy`, `OpenCodeClient::new(...)` — `src/bin/eliot-opencode-bootstrap.rs:169-209`. Note it uses **zero ELIOT dependencies** (`Cargo.toml:8-16` — only base64/secrecy/serde/serde_json/sha2/thiserror/tokio), so it is not bound to authority, fence, or receipts. | **IMPLEMENTED (transport) / not integrated** |
| **Codex** | **PARTIAL** | `crates/agent/eliot-agent-codex/src/lib.rs` (1164 LOC) implements the App Server wire layer for real: `CodexWireMessage::parse_line` (`:411`), `initialize` (`:439`), `thread_start` (`:454`), `turn_start` (`:458`), `turn_interrupt` (`:466`), `correlate_response` (`:476`), `translate_host_event` (`:536`), `translate_result` (`:598`), `wire_schema` (`:678`), plus route fingerprinting (`codex_route` `:77`), session binding (`:121-144`) and attach receipts with `invocation_digest`/`permit_digest`/`source_digest` (`:193-201`). **It never spawns anything itself** — process launch is delegated to `eliot_process::ProcessExecutor` (`Cargo.toml` dep `eliot-process`; `CodexAdapter<E>` at `:268`). Zero workspace dependents: nothing composes `CodexAdapter` with an executor. | **SHELL (unwired) over a real codec** |
| **ACP** | **PARTIAL** | `crates/agent/eliot-agent-acp/src/lib.rs` (1724 LOC): `AcpFrameCodec` with bounded header/frame limits (`:122-215`), JSON-RPC request/notification/response types (`:319-385`), capability negotiation with explicit probe-not-advertisement rule (`AcpCapabilitySet::probe` `:509`, `negotiate` `:549`), `AcpVersionLine` v1/v2 gating (`:567`), session registry (`:715-755`), typed `AcpUnavailableReason`/`AcpUnknownOutcome` (`:67`, `:88`). The doc comment at `:120` states it plainly: *"this codec accepts arbitrary chunks and never reads stdin itself."* Grep for `TcpStream`/`Command::new`/`stdin` in the crate returns nothing but that comment. Zero workspace dependents. | **SHELL (codec only)** |
| **Claude** | **ABSENT in code** | `grep -ril 'claude'` over `crates/agent crates/surfaces crates/foundation bins` returns **zero files**. No Agent SDK sidecar, no NDJSON bridge, no Managed Agents adapter — nothing `I10.5` describes. What exists is **packaging only**: `integrations/claude/eliot/.mcp.json`, `.claude-plugin/plugin.json`, `hooks/hooks.json`, `integrations/claude/claude-desktop/mcpb/manifest.json`, `integrations/claude/canonical/connector.json`. Claude reaches ELIOT only as an MCP *client* of the legacy `eliot-governor` server. | **ABSENT** (route) / IMPLEMENTED (packaging) |
| Antigravity | packaging only | `plugin/eliot-antigravity-official/plugin.json` + rules markdown; `integrations/antigravity/integration.json`; CLI surface `AntigravityMcpCommand::{ConfigStatus, Register}` at `crates/eliot-app/src/main.rs:2874-2878` | partial |

### The process substrate is real, but nothing above it is plugged in

`crates/instrument/eliot-process-executor/src/lib.rs:402` `impl ProcessExecutor for WindowsProcessExecutor` is a genuine implementation: SHA-256 verification of the executable against `ProcessRequest.executable_sha256` before launch (`:434-438`), refusal of unadmitted secret env refs (`:429-433`), `SuspendedLaunchSpec` (`:446`), `JobObjectLimits` with CPU/memory/descendant caps (`:459-465`), stdout/stderr byte caps (`:466-467`), wall timeout (`:470`). It is consumed by `bins/eliot-kernel`, `bins/eliot-testd`, `bins/eliot-user-broker`.

So the pattern across the whole integration layer is consistent: **the bottom (EBP + named pipes + hardened process launch) is real, the top (Codex/ACP codecs) is real, and the middle — the composition that joins them — does not exist.** `bins/eliot-agent-bridge/src/main.rs:80-84` makes this literal: it constructs `BridgeRunner::new(config.profile, ProviderReadiness::unprobed(), …)`, and `ProviderReadiness::unprobed()` (`crates/surfaces/eliot-agent-bridge-core/src/lib.rs:162-169`) sets **every** provider to `false` by construction, with the doc comment "Readiness is an observation, not a construction default." The binary therefore runs a real NDJSON stdin loop (`main.rs:92-100`) that can only ever emit `BridgeError::PlanGap` and exit `PROVIDER_PORT_EXIT`.

---

(Q5–Q6 pending)
