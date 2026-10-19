# V3 audit map

**Updated 2026-10-19, revision 0.6.** This is the owner's requested coverage/next-action map, not a runtime registry, permission system or second specification. [AUDIT.md](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) own the resulting mechanisms. Update a row after actual reading or a saved change, not after a search hit.

## Sources and publication

- Starting documentation head: `c28359fc2716f3b498ea512ca24a57801d18014c`, PR #5325, branch `docs/5324-v3-documentation-audit`.
- This map was first published in `6ef12c1aa796200337dc0590156f0fe7a636dc8d` during this pass. The combined 0.6 change includes the earlier prepared 0.5 work; exact final commit/readback and CI are recorded in the PR, not guessed here.
- V2 donor: `5aac094834fb5635921b550c821cb933a1196105`; V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`.
- Attached Claude audit, edition 4: proposals, historical measurements and reported owner choices, not an infallible specification.
- Attached 0.5 ZIP: Cognition/README previews, patch and §18. Its previous synthetic probes were not re-run in this pass. Its substance is incorporated into the maintained documents, not committed as another patch artefact.
- New donor `google-research/harness2@1cfe254e8d25b15f37048c3730134686abe60335`, commit 2026-10-14; paper `2610.14224v1`, 2026-10-09.
- Full GitHub write catalogue, `permissions.push` and a successful unattached blob write were checked. Local network/materialization failure is not lack of connector write access.

## Coverage and next connected reading

“Prior” means a finding from earlier passes, not a fresh re-read. “Source” means the named code was inspected, not a live deployment reproduced. No percentage of the whole repository is claimed.

| Track | Actually covered | Next reading / unresolved portion | Take/remove decision |
|---|---|---|---|
| A01 Original requirements | Prior 34/29 maps; fresh V1 Production Architecture §0–1 (lines 1–155) | Canonical Master learning and UL Part C in detail; verify remaining autonomy/understanding requirements | Small instrumental topology is useful; V1 already contains WAL/lease/proof overhead and is not an ideal whole runtime |
| A02 Canonical write and notifications | Source: I5.6; notification_plan_admission.rs lines 1–380; request_hash.rs 1–175 | notification_state_emit / notification_acknowledge_emit identities, actual callers and Store transaction | One domain write and actual retry identity, not repeated plan/catalogue/digest verification |
| A03 Process/generation architecture | Prior findings plus fresh I1.2 | I1.8/readiness, Kernel generations, custody and restart callers; no installed Windows run | Keep necessary independent observation/owned child handling; discard hot-swap/epoch infrastructure |
| A04 Storage/recovery | Prior backup/ORS findings; fresh Phase A ADR0001 and current V3 contracts | ORS table responsibilities, primary capture/backup/purge callers, concrete SDK features/versions | Native SurrealDB and small deferred input; old no-SDK decision is not a V3 veto |
| A05 Useful V2 algorithms | Cue lib.rs entrypoints and normalize.rs lines 1–510 | policy.rs/bounds.rs and source adapters; then context packing, failure matching and attempt deltas | Same capture/query normalization; preserve source spelling and actual path/case semantics; no digest envelope around the pure helper |
| A06 Delivery/false completion | Prior Dreamer normal-vs-curation and registration findings | Remaining AGENT_DELIVERY_GUIDE; real capture-to-context consumer; native-worker pointers vs execution | Find missing useful paths, not another proof registry |
| A07 Development bureaucracy | Source: I2.20 mandatory triad, AGENTS and old Phase A ADR; prior gate defects | Current reading-evidence implementation and actual latest CI logs; catalogue binding and remaining entrypoints | Keep reading/diff/integration honesty; no generated certificate of comprehension |
| A08 Own V3 excess | Architecture and substantive Implementation re-read and revised; Cognitive transfer consolidated | Recheck actual schema/job implementation when it exists; ensure remaining normalizer/lineage checks stay small | Remove donor veto, universal promotion gate, optional generic operation ledger and duplicate supervision; local scope/config instead of enterprise policy |
| A09 Hy coding memory | Prior §§6,16,17, named source and isolated SQL/helper probes | Only revisit changed code or a concrete uncovered path; no fresh full Hy run | Raw preservation, atomic revisions, independent lexical candidates and no implicit resurrection |
| A10 Hy cross-domain learning | Prepared 0.5 report/Cognition read and integrated; six prior synthetic branch cases retained as historical | Real upstream execution/quality only in later donor verification; no claim based on synthetic vectors | Finite input and pairs, no-change reuse, preserve conditions and alternatives; no mandatory behavioral embedding for every event |
| A11 Harness2 recursion | README; recursion.py; selection.py including reflection; library.py; ledger.py; schedule.py 390–560; EXPERIMENTS; paper methods | Remaining context/proposer/prompts/tree adapters and reset/isolation behavior; full benchmark not run | D44: two improvement loops; preserve baseline/no-change, record actual cost; no benchmark engine/library DB/extra swarm |
| A12 Audits/donor lists | Prior D43/P27/S187 inventory; supplied Claude §§10,12,14; release metadata refreshed | Re-read actual release shortlist/transfer rows when archive access works; source-check unreviewed donors by useful path | Named donor is not imported or qualified automatically; no-current-consumer is a valid refusal |
| A13 External interfaces | Prior Claude/SurrealDB/Windows contracts; new Harness2 sources | Exact host/controller methods, DB query plans and installed versions when the relevant boundary is implemented | No invented RPCs or complete-upstream qualification from one document |
| A14 Publication/consistency | Map commit confirmed; complete new documents staged through GitHub API | Final commit/ref readback, changed links and actual workflow status | No local-only handoff called publication; no false main/CI/independent-review claim |

## Next passes, in order

1. Complete A02/A05/A06 as connected source paths: notification identity → caller → stored state; capture cue → indexed memory → delivered context. Record one take/remove decision per coherent mechanism.
2. Complete A03/A04 by state ownership, not file size: process lifetime, primary Store, deferred input, external readback and restore. Do not pretend all ORS tables are one queue.
3. Revisit A01/A12 for still-uncovered cognition and donors: original autonomous understanding, transferable negative/successful experience, reconstruction and meta-learning. Read the actual donor implementation where a decision depends on it.
4. Finish A11's context/proposer/adapter edges before copying any Harness2 code. The two-loop mechanism is documented now; default unrestricted executor settings and published results are not product guarantees.
5. Reconcile remaining V3 interface/version choices and entrypoint bureaucracy. Only after the documentation stage begin the owner-authorized product implementation.

## Rules for the map

A finding records source location → concrete failure or unnecessary cost → smaller mechanism → document changed. A row may cover several related files. No file-per-finding factory, signatures, read receipts, confidence certificates or compulsory percentage scores.

A stable ID, transaction, revision check or real permission boundary is not automatically bureaucracy: it can prevent lost data or duplicated external effects. Remove unsupported layers, not correctness by vocabulary. Tests and live product claims follow their actual execution, not the number of reading rows.

This pass is solo. No independently spawned GPT Luna reviewer is claimed. Existing required checks and independent integration are not silently bypassed by changing this map. Main, CI, runtime, user data and the old ACTIVE registry are not changed by this documentation pass.
