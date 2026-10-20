# V3 audit map

**Revision 0.15 · 2026-10-20.** Reading coverage and next useful action. [AUDIT.md](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) own mechanisms. This map is not runtime state or an approval gate.

Base: `841c807659727cd7fb5730331190ee27cd50f47d`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. This pass studies D42 MAGMA and current D17 Letta Code in [Audit §29](AUDIT.md#29-magma-and-letta-relations-and-continuation-015). Detailed earlier coverage remains in the [0.14 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT-MAP.md), not a fresh re-read of all donors.

| Track | Covered | Still missing / next connected read | Decision |
|---|---|---|---|
| A01 Purpose/learning | Original 34/29 maps, selected V1/UL/I12, experience/skill consumers; new continuation/learning distinction | Original autonomy details and real Eliot capture scheduling | Useful provisional knowledge, not a promotion ladder |
| A02 Control/notification | Broker no-success gate, acknowledgement gap, history/CAS and recurrence | Alternative intake and actual delivery feedback | Direct domain operations |
| A03 Process ownership | I1.2 and selected lifetime paths | Startup/readiness, generations and recovery callers | One actual observer |
| A04 Store/recovery | Native Store/SDK/restore/queues and selected donor writes | ORS duties, primary/purge/backup code; full Letta replay/storage behavior | Useful data independent of whole-system readiness |
| A05 Retrieval | Earlier V2, D01/D08/D09/D03/D19/D43 reads; new MAGMA query→adaptive traversal→neighbors→packing | Broader MAGMA callers, Graphiti temporal input filters and Eliot rendered result | Indexed directed relations when useful; do not discard a necessary bridge merely for different vocabulary |
| A06 Producers/consumers | V2 packet/observe/skill; MemMachine background ingestion, Hindsight hook; Letta real local compaction caller and reflection command routing | Eliot outcome→interpretation trigger and full automatic/server Letta reflection | A prompt/receipt is not execution; compaction not another independent observation |
| A07 Development overhead | Old entrypoint/receipt/CI findings and current instructions | Actual current CI diagnosis when integration is addressed | No fabricated read certificate/reviewer or test-shaped production stub |
| A08 Own V3 design | Direct native paths; new Cognition §§5.5–5.6 | Implement under existing ownership after documentation | No second graph/context manager, selection-agent requirement or ontology runtime |
| A09 Hy coding | Prior writer/reconciliation/history/lexical findings | Relevant uncovered source paths | Source preservation and useful independent search |
| A10 Hy transfer | Prior finite inputs/no-change/compaction findings | Quality comparison only for a concrete later implementation | Similarity is candidate discovery |
| A11 Harness2 D44 | Two loops, selection/reflection/library/ledger/schedule/context/proposer | Remaining pool/mission and benchmark adapters/reset | Reuse existing jobs/controller |
| A12 Donors/archive | D42/D17 fresh; D01/D03/D08/D09/D16/D19/D43 earlier; registry D01–D44 retained | D10/D11 real anticipation/context construction; D18 archive remains separate; full archive not re-read | A source is a mechanism candidate, not an imported dependency |
| A13 Interfaces | Host/DB/OS references and donor source contracts | Installed host/controller routes/platform observations during implementation | Availability in source is not deployment qualification |
| A14 Publication | Existing branch/base inspected; four documentation blobs prepared | Actual compare/ref/readback and workflow status in PR | Publication is not main merge; no inherited PASS |

## Fresh source coverage

| Donor/version returned by source | Actually read | Limits |
|---|---|---|
| D42 MAGMA `467cb70b67ac337b22fdb42194d37c04ad701b62` | README, paper v1 methods; `memory/query_engine.py` 1–280,260–470,450–710,700–1020,1010–1290, including actual query/adaptive/neighbor/packing path | Not all ingestion/trg/formatter callers, no full experiment or encoder cost measurement. Hardcoded session helper exists; its influence on every path is not established. The inspected query does not call the neighboring probabilistic helper |
| D17 Letta Code ref `e8073d4e475ab7f56e76f9aaeea81a7618a92575` | Official memory/sleeptime docs; `compaction.ts` 1–260,350–640,640–930; actual `local-backend.ts` 680–1210; selected `local-store.ts` 800–1110,1150–1420,1500–1830; reflection-v2 prompt, `reflection-runs.ts`, `reflection-transcript.ts` 1–250 | Whole server reflection, automatic selector caller and application of all local-store replay events not qualified. Current Code is distinct from D18 archived server. Ref is recorded as returned, not expanded with invented characters |

MAGMA findings follow concrete caller relationships: scan runs despite other hits; multi-type preferences enter an exclusive temporal branch; intermediate nodes need query-word matches; unchanged content is re-encoded; Q&A additions can be clipped after top-k. The expansion has actual bounds, so it is not described as unbounded or as 400 paid requests.

Letta compaction calls a summarizer before updating the local conversation. The inspected reflection command distinguishes local Code ownership and cloud cutover; a cloud-only API message does not establish absence of every local path. Reflection helper types and prompts alone do not prove automatic execution. Their source IDs/replay distinction inform ordinary Eliot job inputs without importing another agent scheduler.

## Failed approaches recorded once

Several guessed reflection paths and blob references failed. They are not evidence of absent code. Code search then supplied actual `reflection-runs.ts` and `cli/helpers/reflection-transcript.ts`, which were read. Large/empty/truncated responses do not count as complete files. Local network/download attempts did not produce the current repository bytes, so no local full checkout, byte-identical reconstruction or local `git diff --check` is claimed. GitHub API publication remains available.

## Next connected reads

1. Follow actual Eliot capture→interpretation scheduling, using saved tool/check outcomes rather than another ready-made episode DTO. This gap remains open despite a real ordinary packet consumer.
2. Investigate D10/D11 EverOS/EverMemOS for concrete context/anticipation mechanisms: identify the correct current versus historical repository first, then read the actual producer and consumer. Do not import a prediction as an instruction or create a separate scheduling product.
3. Finish D08 temporal candidate filtering/add_episode and D09 top-level retain/commit-to-consolidation when obtainable. Existing conditional findings must not be broadened without that source.
4. Complete Letta automatic reflection and local-store replay only if the design depends on their stronger behavior. Current direct compaction and command reads already provide the selected narrow mechanism.
5. Return to remaining original autonomy/understanding and ORS/process ownership where they affect a useful user path. Unread donors are not implementation permission gates.

## Preservation and verification boundary

The audit is editorially consolidated in 0.15 with immutable 0.14 detail links; it is not claimed byte-identical. It retains 34 requirements, 29 A15 identities, D01–D44 and the prior finding families. Cognition retains its 36 existing walkthroughs and adds two mechanism sections, not another test matrix. Architecture and Implementation 0.11 are unchanged.

This pass is source reading and design review, not model/DB/donor execution, synthetic behavior testing, benchmark, Rust/Clippy run or independent subagent review. No local whole-repository/URL scan is claimed. GitHub compare/ref/readback establish the actual published paths and ancestry. Runtime, schema, dependencies, CI, validators, ACTIVE registry, main and user data are untouched. Product work still follows the owner's code/minimum-Clippy/tests-later sequence.
