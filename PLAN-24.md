# PLAN-24 — governed research provider bridge repair

- Worktree: `C:\Development\Rust\projects\eliot-swarm\W2-24`
- Branch/base: `work/24-w2-2` at `7f3ec0c2823ecfd685d61643a946e6ae88494168` (`origin/main`), with Slice B `04d6e9ec` in the base history.
- Issue: #24, `[research/daemon] Replace ambient research-process launch with a governed provider bridge`.
- Scope: `bins/eliot-mod-research`, the typed research exchange contracts, and issue work-unit artifacts. No Dreamer, canonical, authority, policy, task, or Finish owner is added.

## Reading attestation

Before mutation I read the issue body and all comments, `workstreams/core-daemons/assignments/024-research-provider-runtime.toml`, `COMMON-RULES.md` from `control-20260923-impl`, nearest `AGENTS.md` files, `WORKFLOW.md`, `workstreams/ACTIVE.toml`, the architecture contract, and the linked I21/process/security fragments.

Final route/read after the artifact update:

- route `sha256:21690c281e1ff33f6fb7980a74d5fc5f1fc9b425ae18d4e59dcc0db74b0fa6c9`
- read `sha256:976d276c92c7b3d20736582512641736508e20d50947210be117db34a6d19443`
- bundle `5a48ca53f84476b5b050969bd0690d9e65008b2db128d1f9b8e38eded3883198`
- required handles/paths and SHA-256 values: `.eliot/docs-read-receipt-24-final4.json`
- all 44 rendered required items were opened/read from `.eliot/docs-read-bundle-24-final4.md`; no legacy compatibility map was used.

## Work mapping

1. **W1 — admitted manifest and registry resolution.** `admission.rs::BridgeContract`, `ModuleGenerationEvidence`, `ProviderRegistry::resolve`, `ProviderAdmission::from_contract`, and `validate_request` require exact artifact/config/protocol/registry digests, module/generation, provider/route, owner/credential, privacy/data, full State Fence, Authority Epoch, process generation, budget/deadline, and cancellation identity.
2. **W2 — shared process launch and wire delivery.** `execution.rs::ResearchRequestPort::bind` receives the encoded envelope and exact bytes before minting; `ProviderBridge::bind_operation` and `check_minted_request` recheck the complete process binding, environment, working directory, resources, argv, and wire bytes.
3. **W3 — receipts, evidence, and terminal outcomes.** `ProviderIntentRecord` is durably appended before launch; `RawProviderEvidence` retains stdout/stderr/exit/lineage or omission handles; `ProviderAttemptReceipt` retains start/process outcome/error, route/provider/credential/privacy/budget/usage/deadline/cancellation, cleanup, and reconciliation.
4. **W4 — timeout/cancel/crash/unknown.** `ProviderOutcome`, `await_terminal`, `finish_terminal`, `finish_unobserved_with_reconciliation`, and `AdmittedResearchBridge::{submit,cancel,reconcile}` keep timeout/unknown distinct, retain cancellation, and prevent blind resubmission.
5. **W5 — protocol/candidate result.** Versioned `SubmitEnvelope`, `SubmitAck`, and `ResultFrame` correlate canonical operation/request/provider/route identities; candidate material remains source/provenance/coverage-limited and never becomes truth.
6. **W6 — exchange degradation.** `ResearchProviderFailure`, `CoverageGap`, `ExchangeError::Provider`, candidate extraction, and replayable degraded jobs replace generic `InvalidTransition` collapse for provider failures.
7. **W7 — production composition caller.** `runtime.rs::run_once` reads only fixed Kernel-presented material, records a synced pre-start intent, composes the real `WindowsProcessExecutor` through `compose_admitted`, and projects typed admission/failure outcomes. `ResearchDispatchAuthority` is an ephemeral one-shot P-03 validation/permit composition, not semantic or provider authority.
8. **W8 — delivery evidence.** `REPORT-24.md` and `CHECKLIST-24.md` carry exact implementation/caller lines, final docs receipts, command outcomes, no-test statement, and live-edge residual.

## Acceptance mapping

- No environment/caller path or direct `Command`: W1/W2/W7 and source audit.
- Identity proven before start/cancel: W1/W2/W4.
- Deadline/cancel/cleanup/raw evidence/route/privacy/usage/reconciliation receipted: W2/W3/W4.
- Unknown and unconfirmed cancel cannot retry blindly: W4/W6.
- Provider failure narrows only acquisition coverage: W5/W6.
- Candidate-only provenance/coverage: W5/W6.
- Unavailable provider returns `RESEARCH_SOURCE_UNAVAILABLE`/coverage gap: W6/W7.
- Exact replay/idempotency remains owned by the exchange: W6.

## Planned gates (no `cargo test`)

`cargo fmt -p eliot-mod-research`; direct rustfmt checks for changed source files; focused locked check and clippy for the four research packages; workspace locked check; `git diff --check`; source/direct-process audit. The Windows `cargo fmt --all -- --check` wrapper limitation and the unrelated exchange test formatting baseline are recorded in `REPORT-24.md`.
