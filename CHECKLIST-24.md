# CHECKLIST-24 — issue #24 acceptance and proof ledger

Status vocabulary: **MET** = source/controlled proof observed; **TEST-PHASE** = implementation is wired but live Kernel/Windows provider proof was not executed in this lane; **BLOCKED** = exact external prerequisite is absent.

| ID | Work / acceptance item | Status | Evidence / exact source location |
|---|---|---|---|
| W1 | Admitted `BridgeContract`, Module generation, artifact/config/protocol/registry resolution | MET | `admission.rs:268`, `:347`, `ProviderRegistry::resolve:217`, `ProviderAdmission::from_contract:434` |
| W2 | Exact process generation, Authority Epoch, full State Fence, route/privacy/data, owner/credential, budget/deadline/cancel identity | MET (source) | `admission.rs:347`, `admission.rs:587`; wire fields `protocol.rs:63`; minted checks `execution.rs:867` |
| W3 | Shared governed Windows `ProcessExecutor` and no direct process launch | MET | `ProviderBridge:execution.rs:191`; production composition `runtime.rs:437`; source audit found no forbidden launch symbols |
| W4 | Typed versioned wire delivered before start | MET | `ResearchRequestPort:execution.rs:71`; `bind_operation:304`; runtime exact argv/wire check `runtime.rs:379` and `execution.rs:867` |
| W5 | Raw stdout/stderr/exit/lineage evidence and omission handles | MET (source) | `RawProviderEvidence:evidence.rs:86`, handle method `:177`, `ProviderAttemptReceipt:279`, synced intent `runtime.rs:200` |
| W6 | Provider result correlation and candidate-only source/provenance/coverage result | MET (source) | `ResultFrame:protocol.rs:272`, scan `:344`; candidate builder `execution.rs:776`; receipt source/provenance/coverage fields; `synthesis_is_candidate=true` |
| W7 | Explicit crash/cancel/timeout/unknown and stable-operation reconciliation | MET (source) / TEST-PHASE (live) | `ProviderOutcome`, `finish_unobserved_with_reconciliation:execution.rs:541`, `AdmittedResearchBridge::reconcile:lib.rs:427`; live edge not run |
| W8 | Cancel receipt retained; post-start errors not clean `Refused` | MET (source) | `AdmittedResearchBridge::cancel:lib.rs:528`; `ProviderAttemptReceipt.process_error/cancellation`; post-start errors enter unknown/process receipt path |
| A1 | No environment/caller-selected executable path | MET | fixed material filename `runtime.rs:39`; absolute registered artifact validation `lib.rs:224`; forbidden-source audit PASS |
| A2 | Identity proven before start/cancel/kill/adopt/credential | MET (source) / TEST-PHASE (live) | `check_minted_request:execution.rs:867`, shared suspended validation, `ResearchDispatchAuthority:runtime.rs:216`; live identity observation not run |
| A3 | Deadline, route, privacy, usage, cancel, cleanup, reconciliation receipted | MET (source) / TEST-PHASE (populated live receipt) | `ProviderAttemptReceipt:evidence.rs:279`; `ProviderCleanupReceipt`; `DurableEvidenceSink` |
| A4 | Unknown/cancel-unconfirmed cannot retry blindly | MET | replayable operation identity `exchange:lib.rs:214`; `AdmittedResearchBridge` phase/reconcile gates |
| A5 | Provider failure degrades only acquisition coverage | MET | `ExchangeError::Provider`, `ResearchProviderFailure`, `CoverageGap`; no Kernel/Governor failure path |
| A6 | Candidate-only provenance/coverage | MET (source) | candidate bundle `execution.rs:776`; exact handles/denominator/gaps retained in receipt; no canonical write |
| A7 | Unavailable provider returns `RESEARCH_SOURCE_UNAVAILABLE` / coverage gap | MET (source) | `BridgeError::provider_failure:lib.rs:126`; `ExchangeError::Provider`; `main.rs:20` typed projection |
| P1 | Approved/unapproved artifact and environment injection negatives | TEST-PHASE | binding/negative fixtures compile; no live approved/unapproved Windows provider material run |
| P2 | Crash/timeout/cancel/pipe pressure/descendant cleanup/stderr | TEST-PHASE | shared executor and evidence paths wired; live edge not run per no-test/no-live brief |
| P3 | Route/privacy/budget/fence mismatch | MET (source) | admission/request/process validators; exact owner/credential and full-fence comparisons |
| P4 | Duplicate/unknown job identity reconciliation | MET (source) / TEST-PHASE (live) | operation identity is canonical; provider job ID is subordinate; same-operation reconciliation is wired |
| P5 | Workspace check / focused clippy / fmt / diff | MET with one environment limitation | commands and exact results in `REPORT-24.md`; workspace/all-target check and focused clippy pass; workspace-wide fmt wrapper hits Windows OS error 206 |

## Hard-boundary attestations

- No Dreamer implementation, synthesis, canonical-store write, authority issuance for semantic effects, policy mutation, task scheduling, or Finish ownership was added.
- No `ELIOT_RESEARCH_BRIDGE`, environment lookup, caller-selected command/path, generic shell, or direct `Command` launch was added.
- No `cargo test` command was run.

## Remaining live prerequisite

A real Kernel-delivered `AdmittedResearchMaterial` file and approved Windows provider executable are not present in this worktree/environment. This lane therefore does not claim live Product/Edge proof; the exact continuation is #11 plus the Kernel dispatch route, not a guessed fallback.
