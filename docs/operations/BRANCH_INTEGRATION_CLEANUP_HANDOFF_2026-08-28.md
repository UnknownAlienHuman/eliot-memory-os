# ELIOT branch integration and cleanup handoff (2026-08-28)

## Executive state

- Repository: `UnknownAlienHuman/eliot-memory-os`.
- Product-source cutoff integrated and pushed to `main`: `fadf6a7876c4c21a3c2f9f0c53a3c521e1a0cafc`.
- Persistent CodeGraph refresh commit: `ac9d5500bac4eb99d993b8238457604ea7c3ad8c`.
- Integration worktree: `C:\Development\Rust\worktrees\root-main-integration-4`.
- Integration branch: `codex/root-main-integration-4`.
- Provider census at finalization: zero active Muse, Luna Max, AGY worker, or GLM audit providers. OpenCode Desktop processes are not counted as agent proof.
- Exact post-cleanup inventory before this handoff commit: 9 registered worktrees and 11 local branches.
- This cleanup/integration run is complete. The broader source-extraction goal is **PARTIAL_PROGRESS**, not `DONE_VERIFIED`, because five unique rerolls and one provenance decision remain, and the code phase intentionally ran zero tests.

## 1. Current Goal

Continue the architecture-preserving decomposition of large Rust modules into narrowly owned private cells, while keeping `origin/main` as the only canonical product line. A candidate is acceptable only when it:

1. preserves behavior, public API, serialization, visibility, error order, callers, and authority boundaries;
2. is portable to the current `origin/main`, not merely its old parent;
3. passes the five code gates described below;
4. has a process-clean implementation/review receipt;
5. is integrated by Root, pushed to `main`, and followed by removal of its obsolete branch/worktree.

The next chat should finish the five retained rerolls, decide the Issue 12 source package provenance, run the deferred test phase, refresh CodeGraph again, and remove the resulting obsolete worktrees.

## 2. Canonical work completed

The final integration tranche from `0cc8ddf1d87ee8bc1d4663a9c5b5e4e42c6b9ba4` through `fadf6a7` contains 20 commits:

| Commit | Integrated change |
|---|---|
| `818ddc4` | Directory publication models |
| `294735f` | Host console protocol envelope |
| `f567d63` | Surreal adapter atomic transaction writer |
| `0e89ef2` | ORS recovery projection |
| `8d4b6f7` | `eliotd` daemon runtime entrypoint |
| `4ac9de9` | Host journal termination evidence tests |
| `17e00b9` | Watchdog registry fixture support |
| `3b92e76` | Installer-root contract models |
| `5f19350` | Host watchdog start timing cell |
| `e0d7341` | Watchdog admission adapter cell |
| `02bd060` | Watchdog service-status publication cell |
| `052bf18` | ORS store persistence models |
| `7915b3a` | Named-pipe peer authentication |
| `dc5213b` | Watchdog Host-identity observation |
| `79528b4` | Authenticode module |
| `f74b60c` | Platform port contracts |
| `3eb81a6` | Platform test module split |
| `43461d5` | `eliotd` Kernel-port adapters |
| `0bec310` | User-owned lease module |
| `fadf6a7` | Process-authority handoff protocol |

Every product candidate above had current-parent source/merge verification and the smallest relevant Cargo gates before integration. No candidate branch was pushed directly; Root cherry-picked or rerolled onto the integration line and pushed `HEAD:main`.

## 3. Work organization and agent launch methods

### Root ownership

Root owns the Goal, current-base selection, architecture and authority decisions, final acceptance, integration, cleanup, CodeGraph refresh, and GitHub push. Worker or reviewer verdicts are evidence, not integration authority.

Root should work from one dedicated clean worktree. Do not switch or clean the primary checkout, because it contains W1 evidence:

```powershell
git fetch origin main --prune
git worktree add C:\Development\Rust\worktrees\root-main-integration-5 `
  -b codex/root-main-integration-5 origin/main
```

### Native Codex subagents

Use `spawn_agent` for bounded parallel discovery or implementation. Give each worker exact file ownership and state that other workers share the repository. Prefer:

- `explorer` for read-only codebase questions and branch classification;
- `worker` for a current-parent reroll with exact owned paths;
- no full-history fork unless the subtask genuinely needs the whole conversation.

A packet must name the exact base SHA, worktree, owned files, excluded adjacent authority, allowed gates, and required terminal receipt.

### Luna Max reviewers and reroll workers

The verified external reviewer/worker runtime was OpenCode 1.18.23 with `openai/gpt-5.6-luna`, variant `max`. Launch from the exact worktree rather than passing an inferred project root:

```powershell
Set-Location C:\Development\Rust\worktrees\<exact-worktree>
& "$env:LOCALAPPDATA\OpenCode\OpenCode.exe" run `
  --model openai/gpt-5.6-luna `
  --variant max `
  --agent build `
  "<bounded packet>"
```

Do not treat process creation as provider proof. Record the OpenCode session, OS PID, and an emitted stream event whose `providerID`, `modelID`, and variant match the requested provider.

### Muse contributors

Muse was used for narrow mechanical source extraction:

```powershell
Set-Location C:\Development\Rust\worktrees\<exact-worktree>
& "$env:LOCALAPPDATA\OpenCode\OpenCode.exe" run `
  --model opencode-go/muse-spark-1.2-contributor `
  --agent build `
  "<bounded packet>"
```

Muse source output still requires an independent reviewer and Root current-parent parity. A clean tree alone is not acceptance.

### AGY and GLM

- AGY is read-only second-opinion evidence. Use the `eliot-agy-auditor` skill with a bounded diff; do not allow repository mutation or tests.
- GLM remained `HOLD`: repeated timeouts/rate limits produced no dependable responding audit provider. Do not count a server-like process as an audit lane.

### Packet and process contract

During the code phase, the five allowed gates were:

1. locked/no-deps Cargo metadata;
2. focused all-target/all-feature Cargo check;
3. strict no-deps Clippy with `-D warnings`;
4. focused format check;
5. diff check.

Tests, test listing, `nextest`, and broad `just quick` were deliberately forbidden in the extraction phase. The packet also forbade Python/Node helpers, temporary/log files, shell file writes, self-census, `git switch`/rebase/reset, destructive Git, and unrequested pushes. A process violation produces `PROCESS_REJECT` even if the source is correct.

The reviewer returns exactly one source disposition:

- `INTEGRATE`: current-parent portable and accepted;
- `REROLL`: unique value, but stale/conflicting or narrowly defective;
- `DELETE`: integrated duplicate, obsolete, or regressive;
- `HOLD`: provenance or authority decision required.

## 4. Remaining work and exact branches

### Source rerolls

| Priority | Branch / worktree | Exact state | Required next action |
|---|---|---|---|
| 1 | `codex/stage-raw-status-fix` / `stage-raw-status-fix` | `ae58b95e8d8ba99ac3dd2a4355d83890f985d3dc`; clean | Fresh-current reroll of the unique raw Win32 protected-open status fix. The old candidate conflicts in installation, platform facade, and package staging. |
| 2 | `codex/platform-service-control-adapter-reroll-8d4b6f7` / `platform-service-control-adapter-reroll-8d4b6f7` | `87440475c06ec7b1a71fa3263a3736dac36ae7ef`; clean | Fresh-current reroll preserving all newer platform facade modules. Do not cherry-pick this SHA: current `lib.rs` merge conflicts. The older `e06188c` worktree was removed as superseded by this improved candidate. |
| 3 | `codex/luna-watchdog-kernel-sensor-v1` / `luna-watchdog-kernel-sensor-v1` | `6814c696c0ad3f4a6185a8f9c59b10b68c8b44cf`; clean | Fresh-current reroll of the unique pure Kernel sensor adapter; old watchdog `lib.rs` conflicts with current splits. |
| 4 | `codex/luna-platform-named-pipe-peer-models-06bba20` / `luna-platform-named-pipe-peer-models-06bba20` | `35b86b3bd9649ce79497a18f5e2fb7b5d3c371b5`; clean | Reroll on current and keep `NamedPipePeerProfile.expectation` at `pub(super)`; the old extraction widens it to `pub(crate)`. |
| 5 | `codex/maintenance-neutral-lifecycle-intents` / `maintenance-neutral-lifecycle-intents` | `1ac82b71e73b45a53676802a40b6e0fd65ffea6c`; clean | Complete the API/caller closure. The candidate removes `MaintenanceStateStore`, but current governor composition still imports and implements it. |

For each reroll: create a new worktree from the then-current `origin/main`, copy only the accepted semantic closure, run the five gates, perform independent review, integrate through Root, then remove both old and reroll worktrees.

### User/provenance holds

| Branch / worktree | State | Rule |
|---|---|---|
| `fix/issue-12-normative-cutover` / `eliot-memory-os-issue12` | `cb2b123e7e44c63d85bd5f3c52aa466db54b2e1f`; clean; three unique commits and a 133-path normative/source package | `HOLD_USER_PROVENANCE`. Do not integrate or delete until the user decides whether the uploaded research, generated maps, scripts, and normative sources belong in canonical history. |
| `docs/related-repositories` | `bd910db309f63e75a5954e29af6855e695403932`; no worktree; local and remote documentation branch | Preserve. It is user-authored and has an explicit remote, even though its commit is already an ancestor of current `main`. |
| `work/w1-clean-eol-refresh` / `w1-clean-eol-refresh` | `ed3538a44b33e3692fb576a850f2f7a771330447`; 17 dirty W1 evidence/docs paths | Preserve; do not clean or force-remove. |
| `work/w1-index-refresh-dd10c` / primary checkout | `c2d74b3c256802e87f176e3e4a589b69ca90b80d`; untracked `swarm/results/W1-04-OWNER-RULE.json` | Preserve the primary checkout and evidence artifact. |

The clean `codex/root-main-integration-4` worktree is intentionally retained as the canonical handoff checkout. Local `main` should be fast-forwarded to the final remote SHA after this report is pushed; do not switch the dirty primary checkout.

## 5. Cleanup performed

The final root pass reduced the live inventory from 17 registered worktrees / 20 local branches to 9 worktrees / 11 branches. It removed:

- integrated ancestors or patch-equivalent duplicates: `luna-eliotd-kernel-protocol-v1`, `luna-runtime-store-inspection-v1`, `luna-surql-templates-v1`, `luna-surreal-credential-split-v3`, and the unregistered `luna-eliotd-config-binding-cell-v1` branch;
- stale integration checkout `root-main-integration-3`;
- superseded legacy service-control candidate `platform-service-control-adapter-v2`;
- two explicitly agent-created dirty monolith attempts already represented by current modular code: `platform-windows-watchdog-task-v3` and `runtime-status-live-observers`.

The three dirty removals discarded only obsolete uncommitted generated/extraction artifacts. They are not recoverable as working-tree edits; the final CodeGraph replaces the stale graph artifacts, and current `main` contains the superseding watchdog/runtime implementations.

Earlier controller-owned cleanup waves also removed dozens of integrated, rejected, and superseded worktrees after exact path, HEAD, cleanliness, process-liveness, and ancestry/patch-equivalence checks. No broad filesystem deletion was used.

## 6. CodeGraph and source truth

The full persistent graph was refreshed from product-source commit `fadf6a7`:

- project: `eliot-memory-os-fadf6a7-live`;
- mode: `full` with persistence;
- nodes: 61,133;
- edges: 292,972;
- files: 1,192 total, including 770 Rust files;
- original graph size: 117,178,368 bytes;
- compressed artifact: `.codebase-memory/graph.db.zst`, 19,121,048 bytes;
- manifest: `.codebase-memory/artifact.json`;
- graph commit: `ac9d5500bac4eb99d993b8238457604ea7c3ad8c`.
- `docs/conformance.toml` is rebound to the same project, source SHA, counts, sizes, and SHA-256 digests in this handoff commit.

Useful entrypoints for the next chat:

1. select project `eliot-memory-os-fadf6a7-live` in `codebase-memory-mcp`;
2. call architecture overview before raw exploration;
3. scope graph questions to the candidate crate/path;
4. confirm all conclusions against current source and Cargo before editing.

The graph is a routing/evidence layer. Current source, `Cargo.toml`, `Cargo.lock`, Cargo metadata, diagnostics, and tests remain authoritative. There is no `just index` recipe in this checkout; the persistent refresh was performed through `codebase-memory-mcp`.

## 7. Verification state and known limitations

- Each integrated source candidate passed its focused metadata/check/strict no-deps Clippy/fmt/diff gates before integration.
- The final graph refresh returned `indexed` with `expected_nodes == nodes` and `expected_edges == edges`.
- The extraction phase intentionally ran **ZERO tests**. No workspace-wide test completion claim is made.
- Workspace-wide `cargo fmt --all -- --check` can hit Windows error 206 because of the generated command-line length; focused package formatting was used where that baseline occurred.
- Recurrent out-of-scope baselines observed during branch gates included:
  - `eliot-engine/tests/work_lease.rs` `expect_used`;
  - `eliot-host` `journal_tests.rs` `too_many_lines`;
  - authority `grants.rs` `doc_markdown`;
  - platform test/dependency-only unused or dead helpers.
- Final product integrations did not claim live Windows SCM, installation, provider, or runtime-canary proof.

## 8. Exact restart sequence for the new chat

1. Read this handoff and fetch `origin/main`; verify local and remote SHA before any mutation.
2. Verify zero live agent providers and inventory the 9 retained worktrees. Do not touch the primary W1 checkout.
3. Query CodeGraph project `eliot-memory-os-fadf6a7-live`, then confirm the selected reroll against current source/Cargo.
4. Reroll the five source candidates in the priority order above. Do not reuse their stale parents.
5. After every accepted integration, push `HEAD:main`, fetch, compare local/remote SHA, and delete the old and reroll worktrees only after exact liveness/path/HEAD/status checks.
6. Ask the user for the Issue 12 provenance decision before touching that branch.
7. When all code rerolls are complete, leave code phase and run the smallest truthful test matrix, followed by the repository's final verification command if available. Report every skipped or baseline failure.
8. Refresh CodeGraph from the final source SHA, commit `.codebase-memory/artifact.json` and `graph.db.zst`, push, and perform a final branch/worktree census.

## Completion proof

- Result: `PARTIAL_PROGRESS` for the broad refactor program; `COMPLETE` for this integration/cleanup/handoff request after the report push is read back.
- Canonical product source: `fadf6a7876c4c21a3c2f9f0c53a3c521e1a0cafc`.
- Persistent graph: `eliot-memory-os-fadf6a7-live`, commit `ac9d5500bac4eb99d993b8238457604ea7c3ad8c`.
- Remaining acceptance blockers: five current-parent rerolls, Issue 12 provenance, and the deferred test phase.
- Provider state: zero actual Muse/Luna/AGY/GLM audit workers at finalization.
