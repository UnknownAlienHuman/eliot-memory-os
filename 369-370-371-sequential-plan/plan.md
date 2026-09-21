# 369 → 370 → 371 sequential staged plan (root integration pending — NO MUTATION)

Session: `ses_f3abd4233ffeAG0O77g5lBccOP` (same B3 worker, continued).
Worktree: `C:/Development/Rust/projects/eliot-swarm/B-361-provider-binding-20260921`.
Branch: `codex/361-provider-attempt-binding` (local only, never pushed, never rebased).
Freeze commit (preserved, unamended): `ee1bec90a3950c086a23f282b4637d2337babc2a`.
Base: `9f4c7315dbc1a3ee57c0969149e7c2b7a7838bf4`. Current main (given):
`f475cdd87bacfebd4a964df27afc9a8acd24b6fc` — does not contain `ee1bec90`.

## Freeze confirmation

- `git status` clean; `361-provider-binding-delivery/body.md` present (11,145 bytes).
- `wire_turn_id` dual-position evidence + conflict fail-closed intact
  (test `top_level_turn_id_is_exact_turn_evidence` at
  `crates/agent/eliot-agent-codex/src/lib.rs:2867`).
- Re-run `cargo test --offline -p eliot-agent-codex --lib`
  (isolated target `control-20260921/cargo-target-361`): ok, 45/45.
- #366/#368 are CLOSED and are not reopened by anything below.

## Why this is a staged plan, not implementation (STOP rules fire)

- #369 STOP-1: "#368 or #361 is not integrated and independently accepted on
  the supplied authority" → STOP. #361 (`ee1bec90`) is branch-local and
  unpushed; root integration (PR2246 + `ee1bec90`) is pending. No supplied
  post-#368+#361 published authority SHA exists in this worktree.
- #370 STOP-1 needs #369 integrated → STOP. #371 STOP-1 needs #370
  integrated → STOP.
- Per #369 pre-gate-2 / #370 pre-gate-2, the future writers must start clean
  issue-numbered branches from the published post-blocker authority and must
  NOT reuse the #361 branch. So no 369/370/371 code is staged here — only
  owner boundaries, current-source readback, and first-hunk contours.

## Owner boundaries resolved per docs (before any future migration)

- #369 R2 (route receipts, requested-vs-observed): field owner is
  `eliot-agent-api::route_receipts` — `RouteSelectionCandidate` (candidate
  only), `AdmittedRouteReceipt` (admitted logical decision),
  `PhysicalRouteObservationReceipt` (observed physical evidence) with
  `RouteObservationState::{Matched, Diverged, Unobserved, UnknownOutcome}`.
  Coordinator consumes (no second `RoutingReceipt` — verified absent from
  `model.rs`). Foundation digest/time/fence owners (`sha256_hex`,
  `ClockReading`, `StateFence`) are read-only. Matches I10-15 (admission vs
  execution separation) and agent-api AGENTS.md S4.
- #370 R3 (candidate-only result): field owner is
  `eliot-agent-api::{AgentResult, ResultDisposition}` — `CandidateSucceeded`
  et al, no `VerifiedComplete` variant (verified: only negative-test
  mentions). Coordinator admission → `CandidateResultReceipt` capped at
  `ProofCeiling::CandidateArtifact`. `eliot-canonical` / `eliot-finish`
  (FinishDecision, FinishService) are read-only boundaries. Matches A10-08
  (verification-and-finish) and AGENTS.md S5.
- #371 R4 (typed host events): field owner is
  `eliot-agent-api::host_event::NormalizedHostEventEnvelope` (closed v7
  payload family, normalization receipt, loss/privacy manifest); legacy
  `HostEventEnvelope` (lib.rs:754) is the quarantined legacy boundary.
  Adapter normalizers (ACP/Codex S7 inputs) convert; `eliot-protocol`,
  bridge transport, native-worker transport are read-only. Matches I10-17
  (adapter evidence rules) and AGENTS.md S6.

## Current-source readback at base+ee1bec90 (what a future writer inherits)

- R2 triple + Diverged/Unobserved landed (`route_receipts.rs:217/419/517/488`);
  four legacy route types absent from the API surface; coordinator has no
  second `RoutingReceipt`. Residual to prove post-integration: coordinator
  `AdmittedLaneReceipt.routing_receipt_digest` recompute-vs-copy;
  OpenCode/ACP physical-observation conversion totals; placeholder-digest and
  raw-string-time fixtures confined to negative/legacy tests.
- R3 enum landed (`ResultDisposition::CandidateSucceeded`, lib.rs:962-963);
  legacy `VERIFIED_COMPLETE` wires rejected by negative fixtures (lib.rs
  ~1905-2040, ~2418). Codex maps provider success to `Partial`. Residual:
  coordinator submission binding negatives (wrong execution unit / admitted
  receipt / replay conflict); `DescendantTerminalState` / `ParentFinishCeiling`
  rename-if-ambiguous; host/coordination result-named type dispositions.
- R4 envelope landed (`host_event.rs:719`); Codex S7 normalizer enforces
  execution-unit lineage + #369 admission (`normalize_codex_event`,
  `validate_terminal_observation`); `ee1bec90` adds top-level `turnId`
  evidence (371 acceptance item 32 partial). Residual: wrong-turn-parent
  lineage negative; `eliot-types::host::HostEventEnvelope`
  RETAIN_DISTINCT-vs-MIGRATE disposition; legacy generic-payload quarantine
  fixtures per old wire.

## First-hunk contours (one step at a time, after root supplies authority)

1. 369 first: re-run six-row disposition table against post-blocker source
   (expected: triple RETAIN_AS_SINGLE_OWNER, four legacy REMOVE-confirmed);
   add coordinator-selection divergence preservation negative (both
   fingerprints survive, ceiling lowered, no `RouteMismatch` erasure) and
   stale-fence/wrong-execution-unit physical-observation rejects; migrate
   direct producers, then reverse consumers in issue-body order.
2. 370 second: freeze candidate schema version bump from the actual
   post-#369 value; add submission-binding negatives (wrong attempt / fence /
   lease / execution unit / admitted+physical receipt / replay conflict as
   quarantine); add Finish-edge negatives (candidate success + nonempty refs
   still cannot derive `VerifiedComplete`); keep canonical/finish read-only.
3. 371 third: add Codex wrong-turn-parent + non-string-turnId delta negatives
   under exact #361 lineage; freeze `eliot-types::host` disposition with
   schema negatives; add legacy-wire reject/quarantine fixtures; keep
   transport owners read-only with conversion-only changes.

Mismatch/loss rule for every hunk: divergence/loss/missing identity is typed
evidence or quarantine, never silent substitution, default equality, or
ambient attribution. Source facts (upstream schema positions, real JSON
parser) before any pattern/regex extraction — the `ee1bec90` precedent.

## Per-step minimal gates (isolated target, offline; substitute exact SHAs)

- 369: `cargo test --offline -p eliot-agent-api -p eliot-agent-coordinator -p eliot-agent-acp -p eliot-agent-codex -p eliot-agent-opencode`; `cargo test --no-run --offline` on changed reverse consumers (bridge-core, bootstrap, native-worker-core, swarm, eliot); `cargo fmt --check` on touched packages; `cargo clippy --offline -p <touched> --lib` compared with the post-blocker base surface.
- 370: above + `-p eliot-agent-contracts -p eliot-canonical -p eliot-finish` tests (boundary oracles, read-only production); `cargo check --offline -p eliot`.
- 371: `-p eliot-agent-api -p eliot-agent-acp -p eliot-agent-codex -p eliot-agent-bridge-core` tests + `-p eliot-protocol -p eliot-native-worker-core` transport tests; strict clippy on touched packages.
- Never: workspace builds, `verify.ps1`, fetches, pushes, rebases of this branch.

## Docs receipt (this turn)

`docs_read.py` receipt `sha256:d28c27afaa64f0d1078e6b35f56cb200f141c7db3e326915b690d43998872622`,
route `sha256:9b204f53efff76fbab77d071de7973538d3fed43fe0390644698874ee19b22fd`,
bundle `f167d86e0f6ba1b32ada898fe35c2d4782b2b57c3079524919aa0eaff88564b9`,
required 90, retained untracked at `.eliot/docs-read-bundle-369-371.json/md`
(never committed). Full issue bodies #369/#370/#371 read (STOP rules,
acceptance matrices, gate lists); #366/#368 closure states confirmed;
upstream `Turn`/`TurnCompletedNotification`/`TurnStatus` shapes from prior
turn's official-source fetch reused (no new fetches, no Perplexity).

## Residuals

- Root integration dependency: #361 (`ee1bec90`) + #368 accepted on a
  published authority before any 369 writer starts; then 369 → 370 → 371
  strictly sequentially (370 needs 369; 371 needs 370).
- No 369/370/371 code, branch, or worktree created here; this plan commits
  only the contour.
- Independent verifier still required per each issue body before closure.

## Join request

361-READY-FOR-ROOT: `ee1bec90` frozen, gated (45/45 lib, fmt clean, clippy
13=13 base, dependent no-run compiles), delivery doc present — ready for root
integration via PR2246 flow. 369-NEXT: request published post-#368+#361
authority SHA + clean 369 worktree when root integration lands; this branch
will not be reused for 369.
