# V3 audit map

**Updated 2026-10-19, revision 0.7.** This is the owner's requested coverage/next-action map, not a runtime registry, permission system or second specification. [AUDIT.md](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) own mechanisms. A search hit, source inspection and live execution remain different levels of coverage.

## Sources and publication

- Starting documentation head for this pass: `73c34dcb906637f782e667a4ca4c347227806aa5` (0.6), PR #5325, branch `docs/5324-v3-documentation-audit`.
- V2 donor: `5aac094834fb5635921b550c821cb933a1196105`; V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`.
- This map was originally created in `6ef12c1aa796200337dc0590156f0fe7a636dc8d`; the published 0.6 integrated the formerly local 0.5 findings. Do not leave the publication gap recorded as still current.
- Current pass: connected control/notification and retained MCP/cue/context source paths. New findings are [audit §22](AUDIT.md#22-connected-control-and-context-audit-07). Earlier audit sections retain their original scope; no fresh qualification of all donors is implied.
- GitHub full write catalogue and repository push permission were checked. Source can be read and changes published through its API; local raw-download/DNS failures do not imply a read-only repository. Actual final commit/readback and CI are recorded in the PR.

## Coverage and next connected reading

“Prior” below is inherited research, not a fresh re-read. “Source” identifies code actually inspected, not behavior reproduced in Windows or a deployed application. There is no overall percentage of the repository audited.

| Track | Actually covered | Next reading / unresolved portion | Take/remove decision |
|---|---|---|---|
| A01 Original requirements | Prior 34/29 maps; V1 Production Architecture §0–1 from 0.6; V2 I11.12 UserAutomation read in 0.7 | Canonical Master learning/UL Part C in detail; remaining autonomy and original cold-start requirements | Preserve user behavior; old proof/lease/WAL forms are not requirements of V3 |
| A02 Canonical write and notifications | Prior I5.6/notification admission; 0.7 notification_state_emit through its identity/check/write path, acknowledgement emitter 1–320; NotificationStore 1–330 and 380–660; surreal_notification 1–610; broker dispatch 455–880, control gate 2250–2520 and notify methods 1750–1995 | Remaining Kernel notification intake/fanout and actual toast result reporting; full alternative recurrence routes not qualified | Direct operation-specific control; no universal unavailable Critical approval; problem key differs from episode; current-row CAS and append history, not full-history replay per write |
| A03 Process/generation architecture | Prior topology and I1.2; selected broker process/lease checks seen while following control | I1.8/readiness, Kernel generations, actual custody/restart owner; installed Windows behavior untested | Retain real independent observation and owned-child handling; discard redundant epochs/manifests/hot-swap choreography |
| A04 Storage/recovery | Prior backup/ORS/SDK findings; new exact NotificationState persistence and its revision CAS/history rewrite | ORS tables by responsibility; primary capture/backup/purge callers; concrete SDK/server/query choices | One primary Store and minimal deferred input; recovery replay is not the normal update path |
| A05 Useful V2 cue algorithms | Prior A-11 normalize 1–510; 0.7 old CueIndexService full selected file, eliot-types ul/normalize 1–270, cue.rs 1–290 and load_cue_records.surql | New A-11 legacy_adapter integration and producer base-path binding; wrapper handling of truncated source loads; index publication/rebuild races | Preserve source identity, language/filesystem comparison and segment-prefix behavior; do not keep the old lossy matcher as the real consumer beside an unused replacement |
| A06 Delivery/false completion | 0.7 actual retained MCP call_tool 350–790 and outer response path; InjectionPlanner 1–590; prepare→receipt→attach order and receipt hydration | Transport write/flush, session incarnation and touched-state lifetime; activation expansion and per-ID source loading | Optional advice/measurement cannot rewrite a primary success; prepared is not received; no permanent suppression from a pre-send receipt |
| A07 Development bureaucracy | Prior I2.20/AGENTS/ADR; current AGENTS and WORKFLOW first 105 lines; real broker gate with no successful branch | Latest CI failure detail and old catalogue/reading-gate scope; remaining development entrypoints | A no-success approval gate is a missing useful path, not completed safety; no manufactured reading/reviewer certificates |
| A08 Own V3 excess | 0.6 simplifications preserved; 0.7 refines Implementation §§2.5,3.5,3.6,4.1,9.4 and S27–S32 | Verify these simple boundaries in the future implementation; avoid a new delivery or attention platform | Preserve known result plus accounting gap; exact keys separate from aliases; bounded handoff cache; acknowledgement tied to seen episode/revision |
| A09 Hy coding memory | Prior §§6,16,17 and isolated SQL/helper probes, not re-run in 0.7 | Revisit only changed or uncovered donor paths | Raw preservation, atomic revisions, independent lexical retrieval and no implicit resurrection |
| A10 Hy cross-domain learning | Prior 0.5/0.6 report and finite membership/conditions/no-change integration | Real upstream runtime/quality if needed later; synthetic vectors are not model quality evidence | Similarity suggests candidates, not forced unification or independent support |
| A11 Harness2 recursion | Prior README, recursion, selection/reflection, library, ledger, schedule 390–560, experiments and paper methods | Context/proposer/prompts/tree/executor reset and isolation edges; full benchmark not run | D44 mechanism remains: two loops in existing jobs/controller, baseline/no-change eligible, all real costs counted |
| A12 Audits/donor lists | Prior D43/P27/S187 inventory, supplied Claude and release metadata; D44 added in 0.6 | Actual archived shortlist/transfer rows and unreviewed donor mechanisms by user path; no new archive read in 0.7 | Named donor is not imported or qualified automatically; no-current-consumer is a valid refusal |
| A13 External interfaces | Prior Claude/SurrealDB/Windows; official Windows path and Rust identifier references consulted for 0.7 | Installed host/controller methods, database plan and actual platform behavior | Source syntax/base/case matter; documentation is not an OS run or universal path equality |
| A14 Publication/consistency | 0.6 branch verified; 0.7 text/source review plus four local ASCII helper pairs and history-work arithmetic | Commit selected docs, inspect actual diff/ref and CI; no full V2 checkout/Clippy claim | No local-only result called publication; no inherited PASS or independent review attached to new bytes |

## Next passes, in order

1. Finish the remaining A05/A06 edges: `CanonicalStore::load_cue_records` truncation behavior, per-ID alternatives, source-producer path bases, touched/delivery cache and the actual transport handoff. Inspect activation and projection publication only where they affect this consumer; do not restart at the normalizer definition.
2. Complete A03/A04 by state ownership: ORS responsibilities, daemon readiness, process generations versus simple restart, primary capture and restore. Keep recovery cases while removing roles no longer needed by V3.
3. Revisit A01/A12 for original cognition/autonomy and unreviewed donor shortlist mechanisms. Preserve successful experience and reconstruction, not only prohibitions and safety checks.
4. Finish Harness2's context/proposer/executor edges before copying any code. Its documented recursion is not a reason to re-run an entire benchmark per memory update.
5. Resolve actual V3 interface/version choices and remaining development-gate scope explicitly. Runtime work remains after the documentation stage under the owner's selected code/minimum-Clippy/tests-later order.

## Scope discipline

One finding records source → actual failure or needless work → smaller mechanism → changed document. No signature, proof-of-reading, compulsory percentage or new file per finding. A stable ID, expected revision and real permission boundary can prevent a concrete error without requiring V2's surrounding proof infrastructure.

Preserve discarded hypotheses too: valid DirPath inputs already require Prefix, and NotificationState SQL already checks expected revision. Do not report those as newly found bugs merely because a lower-level function looked suspicious in isolation.

This pass is solo; no GPT Luna/independent review is fabricated. Four ASCII helper examples are a local Python port of selected pure transformations, not a Rust/V2/Windows test. History-loop counts are arithmetic, not measured latency. Product code, schema, CI, validators, main, ACTIVE registry and user data are unchanged by this documentation pass.
