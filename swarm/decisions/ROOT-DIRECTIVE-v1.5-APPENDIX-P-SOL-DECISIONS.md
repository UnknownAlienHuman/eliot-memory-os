# ROOT-DIRECTIVE v1.5 — Sol decision ledger for Appendix P1–P6

## Authority and scope

This is the explicit Sol decision record required by the Appendix of
`ROOT-DIRECTIVE-v1.5.md`. It records consequences; it does not create a new
WorkItem, result schema, product capability, or proof authority.

## Non-reopening invariants

- This ledger does not reopen W0 or W1.
- Option A remains the selected temporary operational donor.
- `BOOTSTRAP-PLAN-ADMISSION` remains ratified; no admitted JSON is fabricated.
- No hosted execution, provider activation, product mutation, or
  `schema_version` is introduced here.
- These are Markdown decision statuses, not serialized result-schema values.

## Decision matrix

| ID | Status | Authoritative consequence | Proof ceiling | Trigger / rollback | Related carriers |
|---|---|---|---|---|---|
| P1 | `ACCEPTED_PERMANENT_LOCAL_CEILING` | W0 remains closed only at its accepted local ceiling. The W0-09 rollback is no longer represented as a presently recoverable route. Downstream local gates use `CLEAN_CLONE_ATTESTED`; W0 and W1 are not reopened. | No hosted, release, Product Proof, or terminal authority follows. | A hosted ceiling can return only through a new Sol decision after quota recovery and a newly admitted hosted receipt. | `swarm/gates/W0.md`; `swarm/results/W0-09.json`; v1.5 §6 and Appendix P1. |
| P2 | `DECLINED_WITH_REASON` | The unavailable audit named by the program is not imported as authority and creates no new work. Its reference is treated as withdrawn until a content-bound in-tree copy exists. | Only current in-tree directives, program text, gates, source, and content-bound artifacts support claims. | Reconsider only after import with exact path and digest; otherwise the missing audit remains non-authoritative. | `docs/tasks/RECOVERY_PROGRAM_v1.md:1-7`; v1.5 Appendix P2. |
| P3 | `DEFERRED_WITH_TRIGGER` | The current file-based swarm artifacts are not claimed as `eliot-swarm` dogfood. Existing envelopes remain evidence-only and no new schema version is created. Typed semantic migration belongs to W7. | Content-bound static evidence only; no ELIOT-owned swarm authority is claimed. | Trigger: an admitted W7 consumer with a Rust-owned typed path. Rollback preserves the existing evidence-only artifacts and removes only the failed migration. | `docs/tasks/RECOVERY_PROGRAM_v1.md:91-102,585-590`; `swarm/gates/W1.md`; v1.5 Appendix P3. |
| P4 | `RATIFIED_PROVIDER_FIRST` | `ARCH-DEV-01` is applied as provider-first ordering: the real Kernel agent-bridge provider precedes broad hardening. W0/W3 artifacts are not called a vertical spine, and no new split is authorized. | The current `KernelAdmissionRequired` refusal is static evidence of the missing provider, not a runtime spine. | Revisit after admitted `eliot.agent-bridge.activate` plus an end-to-end loop; until then the provider-first order remains mandatory. | `docs/architecture/ELIOT_ARCHITECTURE.md:277-308`; `bins/eliot-agent-bridge/src/lib.rs`; v1.5 §2, §8, Appendix P4. |
| P5 | `EXECUTED_STATIC_NAVIGATION_ONLY` | The §2.1 code-derived owner↔symbol join exists and provides bidirectional navigation. It does not turn `support = UNKNOWN` or empty invalidation lists into live A6.7 conformance. | Current map ceiling is generated, content-bound navigation with 4 code bindings and 54 unknown owners; live conformance remains unproved. | If generator/verifier parity or mutation checks fail, remove the affected projection atomically and return its owner to `UNKNOWN`; do not infer owners from Appendix H. | `docs/conformance.toml`; `swarm/challenges/W1-04-ANCHOR-SYMBOL-INDEX.md`; `scripts/gen-conformance.ps1`; `scripts/verify-conformance.ps1`; v1.5 §2.1 and Appendix P5. |
| P6 | `EXECUTED` | Workspace count drift is corrected to 126 in CI and `PROJECT_MAP`; the correction is committed in `892688d` and does not open a new WorkItem. | Static topology alignment only; hosted execution is not claimed. | Any later workspace topology change must update both carriers in the same change; mismatch marks the map stale and blocks that topology gate. | `.github/workflows/ci.yml`; `docs/PROJECT_MAP.md`; commit `892688d`; v1.5 §6 and Appendix P6. |

## Anchor index

- P1: `ROOT-DIRECTIVE-v1.5.md` §6 and Appendix P1.
- P2: `ROOT-DIRECTIVE-v1.5.md` Appendix P2 and
  `docs/tasks/RECOVERY_PROGRAM_v1.md:1-7`.
- P3: `ROOT-DIRECTIVE-v1.5.md` Appendix P3 and
  `docs/tasks/RECOVERY_PROGRAM_v1.md:91-102,585-590`.
- P4: `ROOT-DIRECTIVE-v1.5.md` §2, §8, §9 and Appendix P4.
- P5: `ROOT-DIRECTIVE-v1.5.md` §2.1 and Appendix P5.
- P6: `ROOT-DIRECTIVE-v1.5.md` §6 and Appendix P6.

## Current-tree caveats

- P5 records navigation, not live conformance or Product Proof.
- P6 is durable at commit `892688d`; later topology drift still requires same-change carrier updates.
- Provider #1 and every later authority seam remain separate Sol-owned work.
