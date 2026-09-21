# 361 provider-binding delivery — Codex turn/thread → AgentAttempt attribution

SID: fresh Line B3 #361 worker (Muse Spark 1.3, `ses_f3abd4233ffeAG0O77g5lBccOP`).
Worktree root: `C:/Development/Rust/projects/eliot-swarm/B-361-provider-binding-20260921`
(repo root serves as the owned branch checkout; the named
`codex361-provider-attempt-binding` subdirectory did not exist, so no new
branch or directory was created — work is on the exact owned branch below).
Branch: `codex/361-provider-attempt-binding` (local commits only, never pushed).
HEAD base: `9f4c7315dbc1a3ee57c0969149e7c2b7a7838bf4` (clean tree at start).
Scope: agent API/contracts/coordinator/Codex adapter only. No edits to
Kernel/Store/Host/native-worker/process-executor/Governor/Skill central files.
Changed file: `crates/agent/eliot-agent-codex/src/lib.rs` only.

## 1. A01 owner boundary resolution (before adapter migration)

Issue #361 forbids adapter-local attempt-binding invention until the A-01 /
Coordinator owners freeze the public boundary. Verified at HEAD that the
freeze already exists in source and matches the canonical docs:

- Field/shape owner: `eliot-agent-api::execution_binding`
  (`crates/agent/eliot-agent-api/src/execution_binding.rs`), freeze
  `A01_PROVIDER_EXECUTION_BINDING_V1`: exactly one execution unit per agent
  attempt; a Codex execution unit is the exact turn ID; a new turn (including
  resume/fork) is a new agent attempt with continuity lineage; a same-turn
  steer keeps the same binding; a thread-level event is session observation
  only and never carries attempt authority. Canonical identities are imported,
  never redefined (`eliot-agent-contracts::AgentAttemptId`,
  `eliot-contracts::{StateFence, ResourceGeneration}`).
- Lifecycle owner: `eliot-agent-coordinator::bind_provider_execution`
  (`crates/agent/eliot-agent-coordinator/src/core.rs:733`, submission at
  `model.rs:521`). No `bind_provider_execution` exists in the API crate.
- Codex turn rule (S3, this cell): `eliot-agent-codex` records the exact turn
  ID under namespace `"codex"` (`CODEX_EXECUTION_UNIT_NAMESPACE`) and
  attributes only on exact turn equality.

Doc conformance: `docs/architecture/I10-15` ("durable execution unit is an
`AgentAttempt`; a route/session is an ephemeral executor attached to one
attempt"; "Process liveness, logical turn, event cursor and task completion
are independent fields"; "native resume is only an optimization inside one
compatible fingerprint"); `docs/architecture/A10-01` (execute through the
Harness, record observations); `docs/architecture/I10-17` (adapter manifests
declare input/output schemas and evidence rules; adapters never write
canonical state). No code/document disagreement was found on this boundary.

## 2. Residual defect fixed in this cell (source facts before guessing)

Prior state: `wire_turn_id` read turn identity only from `params.turn.id`.
Upstream source facts (openai/codex app-server-protocol schema, fetched live
2026-09-21, consistent with prior `control/recovery-1437-binding.json`
webfetch evidence):

- `TurnStartedNotification = { threadId, turn: Turn }`;
- `TurnCompletedNotification = { threadId, turn: Turn }`,
  `Turn.id: string` (UUIDv7), `TurnStatus = completed|interrupted|failed|inProgress`;
- `AgentMessageDeltaNotification = { threadId, turnId, itemId, delta }` —
  turn identity is a TOP-LEVEL `turnId`, with no `turn` object.

Consequence: a real upstream item delta carrying the exact bound turn in
top-level `turnId` failed closed as `BindingMismatch` (false quarantine of
exact evidence), because no `params.turn.id` exists on that shape.

Fix: `wire_turn_id` now accepts exact nonblank string evidence from both
upstream positions (`params.turn.id`, top-level `params.turnId`).

- Both present and equal → that turn.
- Both present and different → conflicting evidence → no turn (caller fails
  closed; nothing is chosen).
- Non-string / blank / absent → missing evidence, never guessed.
- `terminal_status_from` (`params.turn.status`, only exact
  `completed`/`failed` terminal) is unchanged and now confirmed against the
  upstream `TurnStatus` union.
- Consumed `turnId` was added to the retained (non-omitted) key lists in the
  turn-started / turn-completed / non-terminal-quarantine branches so the loss
  manifest stays honest.

Out of scope, unchanged: the adapter's frozen wire method vocabulary and
`wire_schema()` (upstream method names such as `item/reasoning/textDelta`
are not adopted here; no wire-schema change, no new provider execution).

## 3. Actual call chain (turn/thread → AgentAttempt)

```text
normalize_codex_event(CodexHostEventInput { message, lineage, event_id, cursor,
  sequence, previous_sequence, raw_source_bytes, observed_at, admission })
→ lineage must be ProviderObservationLineage::ExecutionUnitObservation
  (SessionObservation carries no attempt authority)
→ admission.validate() + observation.validate()
→ validate_binding_for_codex: binding shape + exact Codex route +
  execution_unit.namespace == "codex"
→ observation.sequence/cursor/event_id must equal the recorded owner position
→ validate_wire_session_against_binding: wire threadId/thread_id must equal
  the bound native locator; admitted session_id agreement only where admitted
→ wire_turn_id(params) must exactly equal
  binding.execution_unit.unit_id, else Contract(BindingMismatch)
  (missing/foreign/conflicting turn quarantines; never attributes turn B to
  attempt A)
→ classify_codex_payload(method, params, bound_turn, sequence, bound_unit)
→ envelope sealed + validate_for_lineage(binding, admission)
→ translate_result accepts only a terminal observation whose
  attributable_binding == binding (validate_terminal_observation),
  disposition capped at Partial/CancelledObserved/UnknownOutcome (never
  VerifiedComplete)
```

## 4. Focused proof (causal positive/negative tests)

New test `top_level_turn_id_is_exact_turn_evidence` in
`crates/agent/eliot-agent-codex/src/lib.rs` (existing tests untouched,
none weakened):

- positive: upstream delta shape `{threadId, turnId: turn-1, itemId, delta}`
  attributes to the bound attempt (`AssistantDelta`, `delta_chars == 5`,
  `attributable_binding == binding`);
- negative cross-turn: same thread, `turnId: turn-2` → `BindingMismatch`;
- negative loss: delta with no turn identity → `BindingMismatch`;
- negative conflict: `turn.id: turn-1` + `turnId: turn-2` → `BindingMismatch`;
- agreement: both positions equal → attributes (`ExecutionStarted`);
- robustness: non-string `turnId: 42` + exact `turn.id` → attributes
  (real JSON parser only, never a guessed turn).

Pre-existing coverage retained: `missing_and_foreign_turns_quarantine_without_advancing`,
`same_thread_different_turn_quarantines_with_typed_envelope`,
`foreign_or_nonterminal_observations_never_become_results`,
`event_from_wrong_session_is_rejected`,
`session_only_lineage_carries_no_attempt_authority`.

## 5. Gate (isolated target, offline)

`CARGO_TARGET_DIR=C:/Development/Rust/projects/eliot-swarm/control-20260921/cargo-target-361`.
No workspace builds, no `verify.ps1`.

- `cargo test --offline -p eliot-agent-codex --lib` (pre-change baseline):
  ok, 44 passed / 0 failed.
- `cargo test --offline -p eliot-agent-codex --lib` (post-change):
  ok, 45 passed / 0 failed (44 existing + 1 new).
- `cargo fmt -p eliot-agent-codex -- --check`: clean.
- `cargo clippy --offline -p eliot-agent-codex --lib`: 13 warnings after =
  13 warnings at base on the same surface (one transient `match_same_arms`
  introduced mid-work was removed; remaining warnings are pre-existing
  pedantic lints in untouched code: `unnested_or_patterns`, `map_unwrap_or`,
  `filter_map_next`, `too_many_lines` on classify/normalize/translate_result).
- `cargo test --no-run --offline -p eliot-native-worker` (sole reverse
  dependent of `eliot-agent-codex`): compiles, exit 0.

## 6. Docs receipt / handle / path / SHA table

`docs_read.py read` receipt `sha256:3f61dfa2884d247333229a96f952c422b4f603c043007c16267e1edd2e5e20c6`,
route `sha256:fbd972a5fde58fc5f4369084509a92c8b20c09ed308bc13c1b90f5143fc1e8ee`,
pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
bundle SHA `001a8a6c84f6ba7d0f31c0c97076249eccb1c6346383505fb750185d177d02cc`,
matched routes `generic-source, agent-swarm`, required items 49. Bundle and
receipt retained untracked at `.eliot/docs-read-bundle-361.md` /
`.eliot/docs-read-receipt-361.json` (never committed). Key items actually read:

| handle | path | sha256 (12) | bytes | satisfies |
|---|---|---|---|---|
| A10.1 | docs/architecture/A10-01-agent-interaction-loop.md | `ea2935044adb` | 1318 | yes: Harness-mediated execution/observation |
| A10.2 | docs/architecture/A10-02-impact-and-authority.md | `a484150769f1` | 807 | yes: no adapter authority invention |
| A2.3 | docs/architecture/A02-03-modular-architecture.md | `6f7d0566576d` | 6133 | yes: one owner per contract |
| I2.17 | docs/architecture/I02-17-parallel-agent-development-contract.md | `6c333908b112` | 1834 | yes: one writer per file, owned cell |
| I10.15 | docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md | `b54487a50922` | 25823 | yes: attempt durable unit, turn independent field |
| I10.17 | docs/architecture/I10-17-adapter-subsystem.md | `d1f782cb7726` | 4719 | yes: adapter evidence rules, no canonical writes |
| — | crates/agent/eliot-agent-api/AGENTS.md | `a2d544bed77b` | 17318 | yes: S4/S5/S6 landed, contract rules |
| — | crates/agent/eliot-agent-coordinator/AGENTS.md | `6430375ac0f9` | 19045 | yes: coordinator consumer boundary |

Required bundle items read in full: issue #361 body (contract challenge,
representation gap, stop condition); issues #366 (closed), #368 (closed),
#369/#370/#371 bodies (R2→R3→R4 order; #369 blocked by #368+#361; #370
blocked by #369; #371 blocked by #370); `control/recovery-1437-binding.json`
(upstream schema webfetch: delta `{threadId, turnId, itemId, delta}`,
`TurnStartedNotification {threadId, turn}`); live upstream fetches
`Turn.ts`, `TurnCompletedNotification.ts`, `TurnStatus.ts` confirming the
`Turn` object, terminal statuses, and nonterminal quarantine rule.

Reading attestation: every required item above was opened and read before
mutation; no legacy `ELIOT_*` map was used as a receipt.

## 7. Residuals / next queue (not started)

- 369 → 370 → 371 sequential contract migration remains the next queue after
  361 freezes and root integrates; not started (per order constraints in the
  issue bodies: R2 needs #368+#361 integrated; R3 needs #369; R4 needs #370).
- Adapter wire method vocabulary still differs textually from upstream
  app-server-protocol method names (e.g. reasoning deltas); adopting upstream
  names would change the frozen `wire_schema()` and is explicitly out of
  scope here.
- Clippy pedantic warnings pre-existing in the crate (13) are not introduced
  by this change and were left untouched (fixing them would exceed this cell).
- No provider execution, network, credentials, or live model calls were made;
  proof ceiling is adapter attribution unit proof only.
