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

(Q3–Q6 pending)
