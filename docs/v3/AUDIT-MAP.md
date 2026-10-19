# V3 audit map

Updated 2026-10-19. This is the working map requested by the owner, not a runtime registry, approval gate or a second specification. Findings and donor decisions belong in [AUDIT.md](AUDIT.md); implementation changes belong in the existing implementation chapters. Update a row after actual reading or a saved change. Never turn a bibliography entry or search hit into a completed audit.

## Source baseline and unfinished publication

- Active documentation before this pass: `c28359fc2716f3b498ea512ca24a57801d18014c`, PR #5325.
- V2 donor: `5aac094834fb5635921b550c821cb933a1196105`; V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`.
- The attached 0.5 ZIP contains a prepared three-file patch and section 18. It was not in the branch at the start of this pass. Publish its substance with the next reconciled documentation revision; do not claim it was already committed or re-run its old probes merely by importing their report.
- GitHub write tools and `permissions.push` were checked in this pass. A successful unattached blob write disproves an ongoing write-access blocker. Local VM network failure is not a GitHub API permission failure.
- The supplied Claude audit, edition 4, is a source of proposals and historical measurements; its reported decisions, source claims and forecasts must remain distinct.
- New donor: `google-research/harness2@1cfe254e8d25b15f37048c3730134686abe60335` (commit 2026-10-14), paper `2610.14224v1` (2026-10-09).

## Coverage and next concrete action

“Prior” means reported in earlier audit sections, not personally re-read in this pass. “Source” means the named code was inspected, not that its runtime behavior was reproduced. No percentage of the entire codebase is claimed.

| Track | Coverage now | Read next / finish | Expected decision |
|---|---|---|---|
| A01 Original product requirements | Prior V1 reconstruction; existing 34-requirement and 29-scenario maps | Re-read V1 learning, cognitive autonomy and original minimal topology; compare precise V3 constraints | Preserve behavior, discard obsolete physical machinery |
| A02 V2 write path | Source: I5.6 and `bins/eliotd/src/notification_plan_admission.rs` through its function body; `request_hash.rs` lines 1–175 | Trace notification identity and both actual callers; inspect Store transaction rather than stopping at types | Replace repeated plan/catalogue/digest checks with one domain write and stable retry identity |
| A03 Process/generation infrastructure | Prior topology findings; not a complete fresh runtime read | I1.2/I1.8, daemon readiness, Kernel generation, custody and restart ownership | Separate necessary child-process handling from hot-swap/epoch infrastructure |
| A04 Storage and recovery | Prior source findings and 0.2–0.4 contracts | ORS tables by responsibility; real primary capture/backup/purge callers; SDK dependency cost at implementation time | One primary Store, minimal deferred input, no ORS clone |
| A05 Useful V2 algorithms | Source: cue normalizer public entry points | `normalize.rs`, case/separator rules and examples; then context packing, failure matching, attempt deltas | Retain source spelling/comparison semantics and real edge cases, not envelope/manifest topology |
| A06 Agent delivery and false completion | Prior delivery-guide and Dreamer findings | Full remaining delivery guide; normal Dreamer caller vs curation; native-worker registration vs execution | Find missing useful consumers, not more proof scaffolding |
| A07 Development bureaucracy | Source: I2.20 mandatory contract/capsule triad; current AGENTS; Phase A ADR0001 | Read receipt gate and actual latest CI log; task-catalogue scope and root instructions | Draft development should not depend on a model certificate or historical donor approvals |
| A08 Own V3 excess | Current Implementation first half inspected; prior recursive-lineage/restore contracts | Re-read remainder and Architecture; remove legacy SDK veto, universal per-record controls and duplicated administrative text without losing actual requirements | Small local-user boundary; hashes only for actual bytes; automatic local learning; no repeated qualification platform |
| A09 Hy coding memory | Prior §§6,16,17 with pinned source and isolated probes | Reconcile only changes relevant to new contract; do not repeat every earlier test | Raw preservation, atomic revisions, independent lexical retrieval, no implicit resurrection |
| A10 Hy cross-domain learning | Prepared 0.5 §18 and Cognition read; previous probes not re-run | Publish preserved findings; integrate finite candidate sets, no-change, conditions and alternatives | Similarity suggests; it does not prove equivalence or independent support |
| A11 Harness2 recursion | Source: README, complete task recursion functions and library; paper methods | Selection, reflection/prompts, schedule, ledger, experiments; account for calls and unchanged baseline | Adopt Propose–Probe–Compose plus reusable improvement lessons; keep execution in Controller |
| A12 Archive audits/donor lists | Prior 43 D / 27 P / 187 S inventory; Claude donor map available | Revisit shortlist and transfer decisions by user path; mark inherited vs fresh reads individually | Donor list is not 257 mandatory integrations; no-current-use is a valid reason not to import |
| A13 External interfaces | Prior Claude/SurrealDB/Windows; harness2 current source checked | Exact selected host/controller and DB capabilities only when that contract is changed | No guessed RPCs, no full upstream qualification inferred from docs |
| A14 Publication and consistency | Live PR/head and write permission checked; 0.5 local files present | Commit reconciled documents, read back branch, review changed links; report actual CI separately | No lost local-only result, no false main/CI/reviewer claim |

## Recommended order of subsequent passes

1. Finish A08 and A11 together: remove own unnecessary restrictions and define the two recursive learning loops in existing modules. Publish 0.5 material rather than leaving another local handoff.
2. Finish connected A02/A05/A06 paths: one simple notification write, cue normalization, capture and its real consuming context path. Record take/remove decisions on exact source functions.
3. Complete A03/A04 by ownership rather than file size: process lifecycle, primary storage, minimal recovery and independent observation. Do not treat every ORS table as the same queue problem.
4. Revisit A01/A12 for uncovered cognitive functions and donors, especially revision-aware understanding, negative experience, transfer and meta-learning. A named donor is a candidate, not mandatory software.
5. Reconcile the whole V3 reading path and exact integration decisions. Runtime and broad test work start only in the later owner-authorized implementation stage.

## Rules for this map

One row can refer to several related files; no file-per-finding factory. Record a finding as source location → failure or unnecessary cost → smaller mechanism → document changed. Mark contradictions and uncertain scope explicitly. A scan may legitimately conclude “do not take”. There is no receipt, signature, hash-attestation, mandatory reviewer matrix or numerical code budget attached to a status here.

Ordinary IDs, input equality, transaction boundaries and permission checks at real external boundaries are not automatically bureaucracy. Their absence can lose data or duplicate an external effect. The target is repeated infrastructure without a relevant failure case, not deleting correctness by vocabulary.

This pass has no independently spawned reviewer. Never label a second self-review as GPT Luna or as independent integration. Existing required repository checks are not silently disabled by this map.
