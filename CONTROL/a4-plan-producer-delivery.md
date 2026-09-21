# A4 plan-producer delivery — settled-plan runtime feed (issue #1941)

Owner: A4 Smart plan lane (`smart.context.reactive_delivery_plan`, source
layer C1). Worktree `A-1941-plan-producer-20260921`, branch
`codex/1941-plan-producer` over base main
`f0635f9e7672b189672564b9fdcc21cb5ea144df` (clean at start).

## Problem closed

`plan_pending_context_injection`
(`crates/smart/eliot-reactive-context-plan/src/plan.rs:32`) had zero
production callers. This lane now owns the production producer/feed caller.

## Prerequisite join (read-only, preserved)

Merged A1 freeze `c2fe33ad8d7e4287f65cb62ff80d9211f72fca02` locally with
`git merge --no-ff` — clean, no conflicts, main semantics untouched. Merge
commit `ca8b37491d99f1a4e97193282604635c4e09591b`. The join brought A1's
`settled_plan_transport.rs` (+ `governor_assess` over the real
`assess_reactive_risk`) and A3's `reactive_admission.rs` plus the C1
`bridge_admission.rs` producer as read-only context. Originals preserved;
nothing in A1/A2/A3 paths modified by this lane.

## Change (dedicated Smart plan runtime/domain files only)

- `crates/smart/eliot-reactive-context-plan/src/settled_plan_feed.rs` (new):
  `produce_settled_plan_feed(SettledPlanFeedInputs) -> Result<SettledPlanFeedOutcome, SettledPlanFeedError>`
  — the first production caller of `plan_pending_context_injection`, running
  projections → plan → `plan_bridge_admissions` in one causal call.
  Stateless (input struct is `Copy` borrowed refs); no ledger, no queue, no
  second state machine. Outcome vocabulary: `Ready { plan, batch }` (same
  `result_digest`, cannot diverge), `NoSettledPlan(disposition)` (full
  accounting, zero emissions), `Err(Planning | Producer)` (fail-closed,
  never downgraded). No `From`/`Into` bridges; explicit `map_err` only.
- `crates/smart/eliot-reactive-context-plan/src/lib.rs`: `mod
  settled_plan_feed` + re-exports. No other production file touched.
- `crates/smart/eliot-reactive-context-plan/tests/settled_plan_feed.rs`
  (new): focused positive/negative causal proof through the production path.
- `CONTROL/a4-feed-join-contract.md` (new): exact output/feed shape for A1.

Real owned-state source: the six owner-issued projections
(A15 `ContextPlanningView`, A10 `ReactiveCueActivation` pair, session
snapshot, attention projection, coverage profile, self-verifying delivery
policy). Authenticated-cue path: cues enter only via
`request.seeds[].observed.context` bound to the view binding + fence
(enforced by `validate_against` inside the planner); target bindings must
join owner atoms with matching revision/digest; policy digest must equal its
canonical digest. The feed accepts no plan/cue/digest text and no
hand-shaped plan — unrepresentable in its signature.

## Actual call chain (production path)

`produce_settled_plan_feed` (`settled_plan_feed.rs`)
→ `plan_pending_context_injection` (`plan.rs:32`)
→ `plan_bridge_admissions` (`bridge_admission.rs:185`)
→ A1 `SettledPlanAdmission::admit_settled_plan` / `admit_batch`
(`bins/eliot-agent-bridge/src/settled_plan_transport.rs:276/294`, A1-owned)
→ per-item `governor_assess` (`:198`, A1-owned) over the live
`GovernorCoverageDerivation` → `assess_reactive_risk` (A3-owned)
→ `BridgeRunner::admit_reactive_injection`. Critical bit: A1 derives it
from owner stickiness (`severity == Critical`); the feed's severity already
encodes that bit 1:1 (see join contract).

## Proof (scoped gate, isolated target `target-a4/`, offline)

- `cargo test --offline -p eliot-reactive-context-plan`: **64 passed, 0
  failed** (2 producer + 6 delivery + 52 work-unit-612 pre-existing + **4
  new feed**: exact-batch positive with planner-equivalence, forged cue
  digest negative → `BindingMismatch`, forged policy digest negative →
  planning error, delivered-session → `NoSettledPlan` with zero
  instructions). No weakened/ignored/deleted tests.
- `cargo clippy --offline -p eliot-reactive-context-plan --lib`: **zero
  findings** (one pedantic `needless_pass_by_value` found and fixed via
  `Copy` inputs; main baseline on the same surface is also zero).
  `--all-targets` shows only the pre-existing shared-support `dead_code`
  class (same class as the merged `bridge_admission_producer` binary;
  `support/reactive_plan.rs` unmodified).
- Dependent edge: `cargo test --no-run --offline -p eliot-agent-bridge`:
  **compiles, test executables linked** (A1 transport unaffected by the
  lib.rs export addition).
- `rustfmt --edition 2024 --check` on all touched files: **clean**.
- Existing A1/A2/A3 paths keep theirs: no file outside
  `crates/smart/eliot-reactive-context-plan/{src,tests}` + `CONTROL/`
  modified (verify: `git status --short`).

## Docs conformance

Bundle route `generic-source` read in full (23/23 items, attested by the
authoring worker, model `muse-spark-1.3-contributor`):

- Route receipt `sha256:b6a99c76c80a34b72ee34bfe278c5aa8ec168c89fff50edcefe6632f3c28fd1e`,
  read receipt `sha256:220d70e9be4c93848bc56fe23390acfc1a78bd6a9f5f3cbdae3d4ac68b62bbea`,
  bundle `sha256:9231d3b156570cb9f006ce12915361a8409ce048ffab5e3920be14b782d7635a`.

| Handle | Path | SHA-256 |
|---|---|---|
| file | AGENTS.md | e2508482aa659aae51df2e0dc0e7bbfa2b827dc8a8a854e7a1c4a7d06a334332 |
| file | WORKFLOW.md | ba1119920d47f33b99ee51332d8951b009fc04ebe8512fb64966c6afbd9ff070 |
| file | crates/AGENTS.md | 91459415c207f25802e4c4182b7b0525ff644c3cc913c7be02032540a325e03f |
| file | docs/ARCHITECTURE_CONTRACT.md | d1e4c393cd7c953d8e41725eae404882236b13493ace74e4513c4cd894a9e846 |
| file | docs/DEPENDENCY_POLICY.md | a69844d656e7cdac0b92fb4d1e6fbcd5d3e923c30ee706ec598acd3c3868933a |
| file | docs/architecture/READING_PROTOCOL.md | fc2ac357ecec293f7246a5ebc5c1e46f5407bb3574ffe39b6224e4d5aa6a3e25 |
| file | workstreams/ACTIVE.toml | 2bf61c09315add08bb0ec8fd2148f2f295b6abbf5e2e1e11b283204cada5b69b |
| A0.1 | docs/architecture/A00-01-purpose-of-the-architecture.md | ee540ede56579ec388e26da2b290759e78ad3bb8a70ba57d56364800a1692750 |
| A0.2 | docs/architecture/A00-02-hierarchy-of-architectural-decisions.md | 342c67f670714c83bb4c68693447fd7597bc4a662b87d4fa6bae09df3cbaf6e5 |
| A0.3 | docs/architecture/A00-03-hard-boundaries.md | 695fe5e156e0dde052556e23c34b008009348742d4fc4a1146393b8b13a48bc0 |
| A0.4 | docs/architecture/A00-04-conflict-resolution.md | 732d3b9a63973398e07e48691ba56f6538d9168f3102e0702a5ca2e08910f556 |
| A0.6 | docs/architecture/A00-06-changing-the-architecture.md | c086ee01cc243b7d7dee465bc0ddfca0c36cc3a344b3b3e803a5eb94ff6f68a8 |
| A2.3 | docs/architecture/A02-03-modular-architecture.md | 6f7d0566576ddfcb88bae531421b58082b44e3ba6cd2b974f55a46990e26fd52 |
| A10.4 | docs/architecture/A10-04-delegation.md | fd9c93b5e66ea93a0a2bb171706449ca8d07d2d48caeb99d1acdc57360014cd9 |
| A14.8 | docs/architecture/A14-08-development-doctrine.md | c7da919cd6112e97780407b7a7ae9806185994c2de6a275ed2449cb1b9ca78bb |
| I0.3 | docs/architecture/I00-03-decision-sources.md | c5d7586399d8640484edaa3cb949495bc99a82b50dabddac029b2d08c2d716e8 |
| I0.4 | docs/architecture/I00-04-change-classes.md | 3c1fc91d692bee9494327b7f5375fbe45cddc00c27d5a0bf0dc3b40300a2ae45 |
| I0.5 | docs/architecture/I00-05-conformance-support-and-evidence-status.md | bfb599eb462ebfb904ec97ba199a8447371bce91ab73b7bad9e71f150cb837f9 |
| I0.13 | docs/architecture/I00-13-current-support-conformance-and-product-status.md | 2d691986e973b4c9191cf5718f32b5035a8470b8355c5d82489df48c18651d2e |
| I0.14 | docs/architecture/I00-14-documentation-and-evidence-build-integrity.md | e645a72c291c89a4bc3e2eae99527aa2476dcfab0280e429df80405dbebe3fd9 |
| I2.17 | docs/architecture/I02-17-parallel-agent-development-contract.md | 6c333908b112859dbffe00c04a9e942b38c5d369a85d89d78788ab576a1d7cb1 |
| I2.20 | docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md | 8a5d8276f2e1357eb58dd06acc7e5ac4017a4515048a5049c84e33849c381ef5 |
| I18 | docs/architecture/I18-testing-and-instrumental-grounding-strategy.md | facd29dfe4a6fdb98a70f5a5decb7d960f8ca95419924828a44596c57940fb10 |

Satisfaction: A0.3 — forged inputs fail closed (`BindingMismatch`, never a
batch); A2.3/ARCH-MOD-03 — same stateless cell (`module.toml`:
`state_class = "stateless"`, `owned_mutable_state = []`), one causal
responsibility, independent proof surface (`settled_plan_feed` test
binary); A10.4 — single-writer scope, no cross-owner mutation; A14.8 —
Module Proof with old-behavior discriminator (zero production callers →
first caller) and no oracle weakening; I2.17 — isolated worktree, only
owned paths; I2.20 — no new crate/cell (feed lives in the existing
`smart.context.reactive_delivery_plan` cell); I18 — minimal focused proof
(4 tests, production path only). CONTROL contracts read read-only as
owning context (not bundle items, disclosed): `1941-1942-join-c1-transport.md`,
`1942-governor-reactive-handoff.md`,
`1941-1942-runtime-owner-contracts.md`, `ROOT-OWNERS-LIVE.md`. No
Perplexity, no audits, no test loops. Canonical `docs/architecture/` is
authority; no code/document disagreement found in this scope.

## Honest residuals (not done / blocked)

1. **Daemon central-export wiring (B2 Skill owns):** the feed needs a live
   in-process caller supplying the six owner projections plus the live
   `GovernorCoverageDerivation` into A1's `admit_settled_plan`/`admit_batch`
   + `governor_assess`. Request the minimal daemon central export via B2;
   those files were not written here per scope.
2. **First integration proof** (settled plan → live derivation → admit →
   hook drain → receipts, per the C1 transport contract §A4.5) needs the
   residual-1 wiring + A1's driver; staged, not claimed.
3. Governor risk internals (A3), Store durability (A2), agent
   API/coordinator (B3) untouched by design.
4. Crate remains a nonmember prototype (`module.toml`: `PROTOTYPE`,
   `workspace_admission` forbidden until proof + integration-owner review);
   this delivery does not claim admission or runtime authority.

Provenance: actual Muse Spark 1.3 work only (`muse-spark-1.3-contributor`).
No secrets committed. `.eliot/` bundle/receipts and `target-a4/` build
output stay untracked, never committed.
