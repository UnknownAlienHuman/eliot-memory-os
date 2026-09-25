# 2250 integrated delivery — Skill catalogue (issue #1882) — FROZEN CANDIDATE

## Candidate (frozen, no defects found in integration check)

- Branch: `work/1882-catalogue-verify`, frozen SHA `b68d5732e0593892322ade61635a1a0b1ac84bbe`
- Ancestry: base `56f00a52` (original PR #2250 head: `catalogue.rs` + lib exports, +1069/−0) → `0ea1b20b` (verify repairs: stale-receipt binding, canonical receipt order + 2 proofs; PRESERVED as ancestor, verified via `merge-base --is-ancestor`) → `b68d5732` (root merge of published `59861b8d` "Enforce canonical configuration precedence and delegation boundaries"; `eliot-skill/lib.rs` merged automatically, no conflicts).
- Scope in this branch for #1882: `crates/governor/eliot-skill/src/catalogue.rs`, `crates/governor/eliot-skill/src/lib.rs` (3 re-export lines). Everything else in the merge is main-side and untouched by this worker.
- Target-isolated build dir preserved untracked as ordered.

## Integrated check (once, smallest)

- `cargo test --offline -p eliot-skill` post-merge: **13 passed, 0 failed** (7 catalogue tests incl. the 2 verify proofs + 6 main-side `eliot-skill` lib tests). Compatibility of the merged `lib.rs` with the catalogue module established. No unrelated suites repeated.

## Live #1882 remainder — exact caller gap (no caller exists)

Exhaustive workspace grep for `SkillCatalogue`, `HotsetDeliveryReceipt`, `activation_display(`, `note_dependency_change(`, `catalogue::` outside `crates/governor/eliot-skill` returns ZERO hits (remaining hits are unrelated namesakes: `CommandCatalogue`, `CodexCatalogue`, provider/store catalogues, other `promote` fns). Consequences for acceptance:

- "Actual runtime display": no runtime path calls `activation_display` — the display renders, but nothing displays it.
- "Stale dependency blocking": `note_dependency_change` blocks inside the catalogue, but no installation/activation flow feeds observed dependency sets into it.
- "Hotset acknowledgement": `HotsetDeliveryReceipt::issue` mints injector-side records; no Hotset injection flow calls it, and no runtime acknowledgement flows back.

The live Skill lifecycle runs elsewhere and does not touch the catalogue:
- `crates/governor/eliot-governor/src/skill_lifecycle.rs` (`promote` flow with scratch/gate/domain receipts),
- `bins/eliotd/src/skill_lifecycle_adapters.rs` (async `promote` adapters),
- `bins/eliotd/src/skill_surface_adapters.rs` (surface `promote`/propose path, likely under the frozen 2252 surfaces lane).

## Concrete proposal (continuation, authorization required)

New clean continuation worktree (e.g. `B-fx2250c`, branch `work/1882-catalogue-caller`) implementing ONE caller seam, e.g.: `skill_lifecycle_adapters` consults `SkillCatalogue::is_usable` before Material promotion and issues a `HotsetDeliveryReceipt` on Hotset injection, with `note_dependency_change` fed from observed tool/contract versions. Exact hunks require authorization because `skill_surface_adapters.rs` sits in the frozen 2252 surfaces lane and `eliot-governor/skill_lifecycle.rs` is shared Governor code — this worker claims NO shared file unilaterally. Needed: root/manager-B authorization naming the exact shared hunks and their owners, plus docs_read for the new mutable families before any mutation. No fabricated tool registry, no observer-ack invention (both explicitly out).

## Docs / fences

- 2250 verification receipts stand (route `1f58e86b…`, read `1a7626e8…`, bundle `2f6cfdc0…`, 24 fragments read + I7.12/I7.13 direct). No new mutable family touched this turn, so no new docs_read.
- CBM: `codebase-memory-mcp-0.9.0` binary runs (`--help` OK with `CBM_CACHE_DIR` set) but its `cli` tool inventory is undiscoverable (`list-tools`/`search`/`--help` all rejected as unknown tool) — disclosed unusable-for-search; grep fallback used throughout.
- No push/merge/main mutation performed (root FF-pushes original PR #2250). No audits, no Perplexity, no trailers.
