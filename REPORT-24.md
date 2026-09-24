# REPORT-24 — governed research provider bridge repair

## Candidate identity

- Worktree: `C:\Development\Rust\projects\eliot-swarm\W2-24`
- Branch: `work/24-w2-2`
- Base/authority at start: `7f3ec0c2823ecfd685d61643a946e6ae88494168` (`origin/main`), with Slice B commit `04d6e9ec` in the base history.
- Candidate commit: recorded in the final delivery response after this artifact is staged.
- Issue: #24, `[research/daemon] Replace ambient research-process launch with a governed provider bridge`.
- Scope: source/contract repair only; no unrelated issue worktree, no push.

## Documentation read receipt

The final route/read after the artifact update was:

- route receipt: `sha256:21690c281e1ff33f6fb7980a74d5fc5f1fc9b425ae18d4e59dcc0db74b0fa6c9`
- read receipt: `sha256:976d276c92c7b3d20736582512641736508e20d50947210be117db34a6d19443`
- verified bundle SHA-256: `5a48ca53f84476b5b050969bd0690d9e65008b2db128d1f9b8e38eded3883198`
- required items: 44; every rendered item was opened/read from `.eliot/docs-read-bundle-24-final4.md` before this receipt refresh.
- matched route handles, required fragment paths, and SHA-256 values are recorded in `.eliot/docs-read-receipt-24-final4.json`.
- no legacy `ELIOT_*` map was used as evidence.

Reading attestation: the issue body/comments, assignment, `COMMON-RULES.md`, nearest `AGENTS.md` files, `WORKFLOW.md`, active workstreams, architecture contract, and linked I21/process/security fragments were read before mutation. The final bundle was re-read after the source scope settled; the artifact update is followed by one final route/read refresh.

## Implementation and exact handles

- `bins/eliot-mod-research/src/admission.rs:268` — closed `BridgeContract`; `:347` validates artifact/config/protocol/registry, route/privacy/data, owner/credential, process generation, epoch/full State Fence, budget/deadline, and cancellation; `:203`/`:217` resolve one unambiguous active `ProviderRegistry` generation; `:434`/`:587` bind the exact operation and request.
- `bins/eliot-mod-research/src/protocol.rs:63` — versioned wire v2 carries operation, request digest, provider/route/bridge, full-fence digest, privacy/data, owner/credential, budget/deadline/cancellation, registry, and process identities; `:272`/`:344` strictly decode correlated ack/result frames and reject ambiguous/malformed claims.
- `bins/eliot-mod-research/src/execution.rs:71` — `ResearchRequestPort` receives the encoded envelope and exact bytes; `:191` is the shared `WindowsProcessExecutor` runner; `:304` builds wire before minting; `:375` enforces the admitted deadline; `:396`/`:541` retain terminal, crash, timeout, cancellation, unknown, cleanup, and reconciliation evidence; `:867` rechecks artifact, process generation, full process fence, environment, working directory, resource bounds, exact argv, and wire bytes before start.
- `bins/eliot-mod-research/src/evidence.rs:86` — raw stdout/stderr/exit evidence with explicit omission handles; `:238` pre-start `ProviderIntentRecord`; `:279` complete `ProviderAttemptReceipt` with start/process outcome/error, route/provider/credential/privacy/budget/usage/deadline/cancellation, raw evidence, cleanup, reconciliation, and source/provenance/coverage metadata.
- `bins/eliot-mod-research/src/runtime.rs:135` — fixed material reader; `:200` durable, synced pre-start intent spool; `:216` ephemeral one-shot dispatch validation/permit composition; `:373` production request port; `:437` production `compose_admitted` caller using the real `WindowsProcessExecutor`. The material must be Kernel-presented beside the executable; no stdin, argv, environment lookup, caller-selected executable, or direct process constructor is used.
- `bins/eliot-mod-research/src/lib.rs:126` — typed provider-failure projection; `:427` same-operation reconciliation; `:593` records only operations that reached provider effect for replay gating; `:618` production admitted composition.
- `crates/research/eliot-research-exchange-api/src/lib.rs:149`/`:163` — typed coverage gaps and `ResearchProviderFailure`.
- `crates/research/eliot-research-exchange/src/lib.rs:58`/`:73`/`:91`/`:191` — `ExchangeError::Provider`, typed gap/failure accessors, candidate extraction, and replayable degraded jobs; provider failure no longer collapses to `InvalidTransition`.
- `bins/eliot-mod-research/src/main.rs:11`/`:20` — production one-shot entry; absence of Kernel material is a typed admission-required result, while a present admitted arm drives execution and projects candidate/failure evidence.
- `bins/eliot-mod-research/Cargo.toml`/`Cargo.lock` — existing workspace dependencies `eliot-platform` and `uuid` are recorded for the governed clock and ephemeral one-shot dispatch key.

No Dreamer/synthesis, canonical write, policy/task/Finish ownership, hidden fallback, credential secret, or provider authority was added. `synthesis_is_candidate` remains true and all provider material stays candidate/evidence custody.

## Verification observed

All commands used `CARGO_TARGET_DIR=C:\Users\kleym\AppData\Local\Temp\opencode\w2-24-target` unless noted. No `cargo test` command was run.

| Check | Result |
|---|---|
| `cargo fmt -p eliot-mod-research` | PASS |
| `rustfmt --edition 2024 --check` on all changed `elmod-research/src/*.rs` files | PASS |
| `rustfmt --edition 2024 --check crates/research/eliot-research-exchange/src/lib.rs` | PASS |
| `rustfmt --edition 2024 --check crates/research/eliot-research-exchange-api/src/lib.rs` | PASS |
| `cargo check -p eliot-mod-research --all-targets` once without `--locked` after adding the existing `uuid` workspace dependency | PASS; lockfile updated |
| `cargo check --locked -p eliot-research-exchange-api -p eliot-research-exchange -p eliot-researcher -p eliot-mod-research --all-targets` | PASS |
| `cargo clippy --locked -p eliot-research-exchange-api -p eliot-research-exchange -p eliot-researcher -p eliot-mod-research --all-targets --no-deps -- -D warnings` | PASS |
| `cargo check --locked --workspace` | PASS; only pre-existing warnings in unrelated workspace targets |
| `git diff --check` | PASS |
| forbidden launch/ambient source audit | PASS; no `std::process::Command`, `Command::new`, `ELIOT_RESEARCH_BRIDGE`, `std::env::var`, `std::env::args`, or `from_environment` in the production crate source |
| `cargo fmt --all -- --check` | BLOCKED by Windows wrapper `os error 206` (filename/extension too long); scoped rustfmt checks above pass |
| exchange package `cargo fmt --manifest-path ... -- --check` | reports three pre-existing formatting-only diffs in `tests/evidence_exchange.rs`; changed library source passes direct rustfmt check and the unrelated test file was restored |

`cargo check --all-targets` compiles test targets but does not execute tests, consistent with the no-`cargo test` lane rule.

## Proof ceiling and remaining blocker

- Module/source proof is green for the scoped candidate and workspace compilation.
- Live Product/Edge proof is **NOT EXECUTED**: this environment has no authenticated Kernel-delivered `AdmittedResearchMaterial` or approved Windows provider executable. The production root therefore fails closed as `KERNEL_ADMISSION_REQUIRED` when material is absent; it does not use a fallback or fabricate readiness.
- The exact live continuation is issue #11 / the Kernel dispatch route plus one approved provider, unavailable-provider degradation, cancellation, timeout, stderr, descendant cleanup, and same-operation reconciliation. This is an external live prerequisite, not a remaining Rust compile blocker.
- No push was performed. The local commit is the only delivery action remaining after the final artifact receipt refresh.
