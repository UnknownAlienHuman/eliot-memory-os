# REPORT — issue #204 (W1, session 20260924-075254)

Branch: `issue/204-W1-2`. Base: `origin/main = 7f3ec0c2823ecfd685d61643a946e6ae88494168`.
Claim: `W1` (control dir `CLAIM`, session 20260924-075254) — not deleted.

## What changed (10 files)

P2 repair: actual candidate/recovery/failure handles plus retry dependency/time
now flow through Kernel response → activation port → `BridgeError` → host
response instead of collapsing to static strings.

1. `crates/foundation/eliot-protocol/src/lib.rs`
   - `AgentBridgeActivationDisposition::Denied` gains
     `detail: Option<AgentActivationResolutionDisposition>` (`:2101`); wire
     version `AGENT_BRIDGE_ACTIVATION_RESPONSE_WIRE_VERSION` 1→2 (`:137`).
   - `denied()` takes the detail (`:2186`) and fail-closed-validates the pair:
     `None` only with `SemanticResolutionUnavailable`; `Some` never `Resolved`
     and never with the no-result code.
   - Wire codes documented as transport vocabulary; agent-facing catalogue
     projection lives at the bridge alias (`agent_reason_for_denial`).
2. `crates/foundation/eliot-protocol/src/activation_resolution.rs`
   - `AgentActivationResolutionDisposition::validate` → `pub(crate)` (`:268`)
     so the wire denial validates its carried detail.
3. `bins/eliot-kernel/src/agent_bridge.rs`
   - Both typed projection sites pass `Some(result.disposition.clone())`
     (`:1456`, `:1542`); `denied_result_response_frame` carries it (`:1710`);
     result-less expiry (`:1945`) and pre-ticket denial (`:2055`) pass `None`.
   - `activation_denial_code_for_disposition` (`:1376`) unchanged (kernel
     tests pin it).
4. `crates/surfaces/eliot-agent-bridge-core/src/lib.rs`
   - New `ActivationDenialReport` (`:536`): catalogue reason + disposition +
     directive + operation correlation + exact owner-issued detail, with
     `agent_detail()` rendering that keeps distinct candidate sets, retry
     bounds, and failure handles distinct (candidates as JSON, never
     comma-joined).
   - `ActivationPortOutcome::Denied(ActivationDenialReport)` replaces
     `Denied`/`DeniedDetailed` (`:684`); new distinct
     `DeadlineExceeded`/`UnknownOutcome` outcomes.
   - `BridgeError::ActivationDenied(ActivationDenialReport)` (`:2158`) plus
     `ActivationDeadlineExceeded` (`:2162`) / `ActivationUnknownOutcome`
     (`:2169`); `attach()` maps all three without minting Session/authority
     (`:1131`).
   - Removed dead `ActivationDenialDetails` (had no producer/consumer).
   - The 8 disposition/directive consts are now actually used (bridge
     projection + host code mapping).
5. `bins/eliot-agent-bridge/src/kernel_activation_client.rs`
   - New bridge-alias projection `agent_reason_for_denial` (`:82`): every wire
     code → verbatim I7.20 catalogue reason (`TASK_SELECTION_REQUIRED`,
     `TASK_SCOPE_INCOMPATIBLE`, `AMBIGUOUS_RESULT`, `DEFERRED_CAPACITY`,
     `STALE_STATE_FENCE`, `RUNTIME_FAILED`, `UNKNOWN_OUTCOME`).
   - New `denial_report_for` (`:134`): coherence-checked report builder;
     mismatch fails closed as transport rejection.
   - `SemanticResolutionUnavailable` directive corrected to
     `retry-requires-new-ticket` (no capsule exists for the no-result refusal).
   - Removed `denial_reason_code` (duplicated protocol `as_str()`).
   - `activate_inner` (`:417`): transport failure → distinct
     `observe_no_result_outcome` (`:172`, clock vs ticket deadline);
     one-shot guard now consumes on decoded response (`:461`), so a failed
     transport attempt leaves one exact retry; guard check stays before send.
6. `bins/eliot-agent-bridge/src/main.rs`
   - `bridge_error` (`:1460`) renders denials as `ACTIVATION_*` per-disposition
     codes with the full detail string; new `ACTIVATION_DEADLINE_EXCEEDED` /
     `ACTIVATION_UNKNOWN_OUTCOME` codes.
7. Tests updated to the new shapes (same or stronger assertions, none
   weakened/deleted/ignored):
   - `bins/eliot-agent-bridge/src/lib.rs`: `denied()` gains per-code typed
     details; `typed_denial_codes_surface_distinctly` now round-trips detail
     presence per code.
   - `crates/surfaces/eliot-agent-bridge-core/tests/bridge_contract.rs`:
     denial report construction asserted field-by-field.
   - `bins/eliot-kernel/src/tests.rs` + `crates/instrument/eliot-r13-harness`:
     e2e denial stdout updated to the exact new rendering
     (`ACTIVATION_FAILED` + disposition/reason/directive/operation/detail).

No placeholder facades, no unfinished markers, no prose parsing
(typed exhaustive matches only), no new authority minted on any denial path.

## Docs receipts (read before editing)

- Route receipt `sha256:e8367c1153ad2f35e9d3cb4d0ee5512e652335097dba355fbd8cde6eb0179341`,
  read receipt `sha256:87955697e8164830c6939c42dce7e37edfb09e3d96e1ddc486c89b69d09d7318`,
  bundle SHA-256 `cae1f7d27287f9309b0bacd9b1162e370bda32fd956dcc3721bf21478aaa1a15`.
- Matched routes: `generic-source`, `host-kernel`, `agent-swarm`,
  `human-surfaces`. Topic: `activation negatives`.
- Required handles read: A0.1–A0.6, A2.2–A2.3, A10.1–A10.8, A11, A12.2, A13.2,
  A14.8, I0.3–I0.5, I0.13–I0.14, I1.1–I1.8, I2.17, I2.20, I3, I5.5, I7.1–I7.9,
  I10.15–I10.18, I11, I13, I14.14, I14, I16.17, I18.16–I18.17, I18.
- Normative authority: `docs/architecture/I07-20-agent-facing-error-contract.md`
  (read in full, 68 lines). Relied sentences: two-layer
  disposition+reason control (I7.20:3-12); every non-success carries
  disposition + exact reason + directive + operation identity, bridges switch
  on disposition and MAY specialize reasons, legacy names only via
  bridge-alias mapping, never host-specific enums; silence/generic prose not
  control (I7.20:67); catalogue groups request/identity (`TASK_SELECTION_REQUIRED`,
  `TASK_SCOPE_INCOMPATIBLE`), state/conflict (`STALE_STATE_FENCE`,
  `AMBIGUOUS_RESULT`), capacity/availability (`DEFERRED_CAPACITY`,
  `DEADLINE_EXCEEDED`), security/recovery (`UNKNOWN_OUTCOME`),
  route/integration (`RUNTIME_FAILED`) (I7.20:16-65).
- Crate instructions read: root `AGENTS.md`, `bins/AGENTS.md`,
  `crates/AGENTS.md`, `crates/surfaces/AGENTS.md`, `WORKFLOW.md`.
- Attestation: I read every required bundle item listed above plus the I7.20
  fragment before mutation. No `ELIOT_*` compatibility map used.

## Gate (`$env:CARGO_TARGET_DIR='C:\Development\Rust\projects\eliot-swarm\targets\W1'`, no `cargo test` per owner order)

- `cargo fmt -p eliot-protocol -p eliot-agent-bridge-core -p eliot-agent-bridge -p eliot-kernel -p eliot-r13-harness` → exit 0
  (6 unrelated files reformatted by the tool were reverted; diff holds only
  the 10 listed files). `rustfmt --edition 2024 --check` on all 10 files → 0.
  (`cargo fmt --check` workspace-wide fails with Windows os error 206 —
  command line too long — environment limitation, unrelated to this diff.)
- `cargo check --locked --offline -p <crate> --all-targets` → exit 0 for
  `eliot-protocol`, `eliot-agent-bridge-core`, `eliot-agent-bridge`,
  `eliot-kernel`, `eliot-r13-harness`.
- `cargo clippy --locked --offline -p <crate> --lib/--bins --no-deps -- -D warnings`,
  branch vs `origin/main` (7f3ec0c2, same flags, stash-compared):
  - `eliot-protocol --lib`: 0 = 0 (clean both).
  - `eliot-agent-bridge-core --lib`: 72 = 72, identical lint multiset
    (only line shifts; 3 interim new findings fixed during work).
  - `eliot-agent-bridge --lib --bins`: 41 = 41 (only ±1 line shifts).
  - `eliot-kernel --lib --bins`: 18 = 18 (one +16 line shift, same finding).
  - `eliot-r13-harness --lib`: 0 = 0 (clean both).
  - Zero NEW findings on every surface.
- `cargo check --locked --offline --workspace --all-targets --keep-going` →
  exit 101 both sides with the same single pre-existing broken target
  `eliot-platform-windows (lib test)` (E0382, untouched crate). Zero new
  broken targets.

## Checklist summary

`CHECKLIST.json`: 36 items (all prev ids kept). MET 21: S1, S2, S6, M1–M7,
R1–R4, R6, R7, R9–R11, A2, A4. TEST-PHASE 15 (code wired, executed/runtime
proof pending): S3–S5, R5, R8, F1–F6, C1, A1, A3, A5.

## Cross-check refutations disposed (REMAINING.md)

- M1/M3/M5/R3/R11/A1 (dropped handles/retry/failure): fixed — full typed
  detail through Kernel response → port → `BridgeError` → host response.
- M2/M4 (SCOPE_AMBIGUOUS/STALE_FENCE): fixed — agent face emits catalogue
  `AMBIGUOUS_RESULT` / `STALE_STATE_FENCE` via the alias projection.
- M6/R11 (deadline/unknown collapse): fixed — distinct port outcomes,
  errors, and host codes.
- M7/A3/A4 (ownership/enum): fixed in code — agent face uses only I7.20
  dispositions + catalogue alias reasons, no prose parsing, no host-invented
  semantics; wire enum kept as shared transport vocabulary with documented
  alias. Generated `docs/generated/reason-codes.md` artifact stays TEST-PHASE
  (S3/A3).
- R2/R10/F3 (blank/wrong anchors): fixed — checklist now cites the real
  projection/validation lines.
- F4 (one-shot guard): narrowed — guard consumes on decoded response, not on
  attempt; replacement connections ride a new admission; reconnect execution
  proof stays TEST-PHASE.
- R5: carry landed; kernel same-ticket conflict + NotReady supersede gate
  pre-exist; cross-ticket revision/time admission enforcement stays
  TEST-PHASE (no new protocol linkage invented here).
- S4/F5 (pulse), F1/F2 (suite/edge runs), C1/A5 (closure): TEST-PHASE, owner
  test phase.

## BLOCKED-BY

- `BLOCKED-BY #204-eliotd-cleanup`: final removal of
  `ActivationDecisionDisposition` (`bins/eliot-kernel/src/lib.rs:632`, used
  `bins/eliot-kernel/src/agent_bridge.rs:1286-1350`) plus protocol wire
  type/consts still imported by eliotd production code. Deleting them here
  breaks the eliotd build; needs the eliotd dead-producer migration first.
  (Carried over from the previous attempt; unchanged by this slice.)
- No other blockers. Runtime/executed proofs (real EBP edge run,
  per-disposition authority matrix, D0/D1 pulse, compat-suite run) are
  TEST-PHASE, not blocked: `cargo test`/live runs deferred by owner order.

## Notes / deviations

- Branch name `issue/204-W1-2` was assigned by the manager brief; it does not
  match the `work|fix|.../<n>-<slug>` convention. Kept as instructed; flagging
  for root at integration.
- `docs/generated/reason-codes.md` was not created: per WORKFLOW.md generated
  projections land only with an active consumer plus regeneration check; the
  code-side alias projection (`agent_reason_for_denial`) is the consumer-ready
  half.
