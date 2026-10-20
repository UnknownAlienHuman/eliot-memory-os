# V3 audit map

**Revision 0.16 · 2026-10-20.** Reading coverage and next useful action. [AUDIT.md](AUDIT.md) holds findings; [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) own mechanisms. This map is not runtime state or an approval gate.

Base: `48a622457c826eed3f539d9a870e3521da644527`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. This pass studies current D10 EverOS and distinguishes the historical D11 EverMemOS paper in [Audit §30](AUDIT.md#30-everos-and-evermemos-anticipation-and-evidence-coverage-016). Earlier coverage remains in the [0.15 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/48a622457c826eed3f539d9a870e3521da644527/docs/v3/AUDIT-MAP.md) and [0.14 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT-MAP.md); those are not fresh re-reads of all donors.

| Track | Covered | Still missing / next connected read | Decision |
|---|---|---|---|
| A01 Purpose/learning | Original 34/29 maps, selected V1/UL/I12, experience/skill consumers; continuation/learning and conditional anticipation | Original autonomy details and real Eliot capture scheduling | Useful provisional knowledge, not a promotion ladder |
| A02 Control/notification | Broker no-success gate, acknowledgement gap, history/CAS and recurrence; forecast expiry versus completion in V3 | Alternative intake and actual delivery feedback | Direct domain operations; expiry does not resolve a commitment |
| A03 Process ownership | I1.2 and selected lifetime paths | Startup/readiness, generations and recovery callers | One actual observer |
| A04 Store/recovery | Native Store/SDK/restore/queues and selected donor writes | ORS duties, primary/purge/backup code; full Letta replay/storage and EverOS intake/recovery | Useful data independent of whole-system readiness |
| A05 Retrieval | Earlier V2, D01/D08/D09/D03/D19/D43 and MAGMA paths; current EverOS mode dispatch, AGENTIC hydration and multi-round finalizer | Broader MAGMA callers, Graphiti temporal filters, imported everalgo internals and Eliot rendered result | Indexed selected-group fetch; preserve material question coverage at final packing |
| A06 Producers/consumers | V2 packet/observe/skill; MemMachine background ingestion, Hindsight hook; Letta compaction/command; current EverOS default-off foresight and HTTP→service→manager | Eliot outcome→interpretation trigger and full automatic/server Letta reflection; no claim about every custom EverOS reader | Actual delivered content, not a prompt, write-only output or receipt |
| A07 Development overhead | Old entrypoint/receipt/CI findings and current instructions | Actual failure diagnosis when integration is addressed | No fabricated read certificate/reviewer or test-shaped production stub |
| A08 Own V3 design | Direct native paths; Cognition §§5.1,5.3,5.7,7 refined | Implement within existing ownership after documentation | No foresight store, mandatory query verifier, expiry daemon or second provider scheduler |
| A09 Hy coding | Prior writer/reconciliation/history/lexical findings | Relevant uncovered source paths | Source preservation and useful independent search |
| A10 Hy transfer | Prior finite inputs/no-change/compaction findings | Quality comparison only for a concrete later implementation | Similarity is candidate discovery |
| A11 Harness2 D44 | Two loops, selection/reflection/library/ledger/schedule/context/proposer | Remaining pool/mission and benchmark adapters/reset | Reuse existing jobs/controller |
| A12 Donors/archive | D10 fresh source, D11 historical paper distinguished; D42/D17 and other earlier coverage retained | Historical D11 implementation not qualified; D18 archive remains separate; full archive not re-read | Versioned mechanisms, not imported product topology or benchmark guarantees |
| A13 Interfaces | Host/DB/OS references; current EverOS embedding provider/factory and actual query caller | Installed controller foreground scheduling and aggregate provider limits during implementation | Reserve interactive capacity through the existing owner |
| A14 Publication | Existing branch/base and push permission checked; prior run 39431478163 completed with failure | New commit compare/ref/readback and actual workflow outcome in PR | Publication is not main merge; no inherited PASS or assumed failure cause |

## Fresh source coverage

| Donor/version | Actually read | Limits |
|---|---|---|
| D10 EverOS `c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18` | README 1–250,280–440; docs/architecture.md 1–230; docs/how-memory-works.md 1–230; extract_foresight.py; API routes/search.py; service/search.py; search/manager.py 1–260,330–570; search/agentic.py 1–290; recall/episode.py; llm_multiround.py 1–190,620–1070; embedding/openai_provider.py and factory.py | Not all OME jobs, persistence or recovery; imported everalgo extraction/ranking internals not read; parser/decider internals between inspected multi-round ranges not qualified. No deployment, provider calls, benchmark or latency/RAM measurement |
| D11 historical EverMemOS | Paper `2601.02163v1`, 2026-01-05, HTML methods §§3.2–3.5 and evaluation-mode/limitations passages | Paper mechanism is not current main. Foresight is illustrated qualitatively; not measured coding-failure prevention. Historical implementation not established/read by a matching commit in this pass |

Current foresight extraction is explicitly default-off. Its standard search consumer was checked through HTTP/service/manager, rather than inferred from a comment alone. This does not prove the absence of every custom reader. Existing MemCell/Foresight names in current source do not make the historical runtime identical.

The actual AGENTIC branch fetches all episodes allowed by `where` before cluster selection; KEYWORD/VECTOR/HYBRID have distinct paths. Multi-round retrieval carries separate sub-query evidence, but final core truncation and remaining-slot guarantees bound what is really delivered. Two embedding semaphores separate local waiting; their combined endpoint demand still needs one aggregate budget. Eliot choices are ordinary context/group queries and existing controller scheduling.

## Previous connected reads retained

| Donor | Previously read, not reread in 0.16 | Remaining boundary |
|---|---|---|
| D42 MAGMA `467cb70b67ac337b22fdb42194d37c04ad701b62` | README, paper v1 methods; query_engine.py 1–280,260–470,450–710,700–1020,1010–1290; actual query/adaptive/neighbor/packing | Not all ingestion/trg/formatter callers or encoder cost. The neighboring probabilistic helper is not the inspected query's caller |
| D17 Letta Code ref `e8073d4e475ab7f56e76f9aaeea81a7618a92575` | Official memory/sleeptime docs; compaction.ts 1–260,350–930; local-backend.ts 680–1210; local-store.ts 800–1110,1150–1420,1500–1830; reflection-v2 prompt, reflection-runs.ts, reflection-transcript.ts 1–250 | Whole server reflection, automatic selector caller and all replay semantics not qualified; current Code distinct from D18 archive |

Other prior coverage is preserved by the linked maps and maintained audit. A new donor finding does not convert earlier partial coverage into completed review.

## Failed approaches recorded once

Prior guessed Letta paths were resolved through code search; failed paths did not prove missing code. In 0.16 an uppercase architecture path and unsupported tag navigation failed; actual directory/release reads identified current docs instead. A historical-date commit query returned no entry, not a historical runtime qualification. Current release naming alone cannot identify the paper's implementation.

Local raw download failed because of unavailable networking; a downloader also rejected an unviewed URL and the web fetch returned a cache miss. These did not produce a current checkout. Use the working GitHub API instead of repeatedly retrying the same download. No local full checkout, local git diff --check or whole-repository scan is claimed. Large/truncated results were expanded for the document portions needed; a partial donor range remains partial.

## Next connected reads

1. Follow actual Eliot capture→saved observation→interpretation scheduling, including worker registration and inputs reaching the model. Start from the real taskless observe path, not another ready-made episode DTO. A working ordinary packet consumer does not close this producer gap.
2. Finish D08 temporal candidate filtering/add_episode and D09 top-level retain/commit-to-consolidation where those stronger guarantees are needed. Existing helper findings remain conditional.
3. Return to original autonomy/understanding and ORS/process ownership where they affect a useful user path. Avoid another donor merely to enlarge the registry.
4. Complete Letta automatic reflection/local-store replay or historical EverMemOS/everalgo internals only when a proposed Eliot mechanism depends on the stronger claim. The selected narrow mechanisms do not require importing those runtimes.

## Preservation and verification boundary

The editorial consolidation occurred in 0.15, with immutable 0.14 detail links. Revision 0.16 adds §30 and targeted source/registry updates rather than consolidating those old findings again. The 34 requirements, 29 A15 identities, D01–D44 and 36 existing cognitive walkthroughs remain. Cognition adds one focused retrieval section and short amendments to existing mechanisms. Architecture 0.6 and Implementation 0.11 are unchanged.

This pass is source reading and design review, not model/DB/donor execution, synthetic behavior testing, benchmark, Rust/Clippy run or independent subagent review. GitHub compare/ref/readback establish published paths and ancestry. Runtime, schema, dependencies, CI, validators, ACTIVE registry, main and user data are untouched. Product work still follows the owner's code/minimum-Clippy/tests-later sequence.
