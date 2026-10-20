# V3 audit map — coverage and remaining design work

**Revision 0.19 · 2026-10-20.** Reading coverage, not runtime state or an approval gate. [AUDIT.md](AUDIT.md) holds findings; [Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) hold the product design. This pass adds source review of two donors missing from the old numbered inventory; it does not declare the whole design or research complete.

Base: `815f51e5a6839263ce6e310a42392c7810eb8218`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [0.18 census](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/815f51e5a6839263ce6e310a42392c7810eb8218/docs/v3/AUDIT-MAP.md) and [0.17 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/4a0616ccb087a4edb8018f1ae07c348d4b1e2dc6/docs/v3/AUDIT-MAP.md) retain previous exact reading and limits. New material is in [Audit §32](AUDIT.md#32-host-capture-and-non-destructive-continuation-019).

## 1. What can honestly be claimed

**Requested subagents were not launched.** The available tool catalog, agent-plugin search and local executor availability did not expose a usable GPT Luna/Codex/subagent invocation. The current pass is solo, not four independent reviews. The initial four work areas remain a division of the task, not agent assignments or completed reports.

**All donors studied: no.** Of the original D01–D44, thirteen have identifiable function-level findings, three documentation/paper treatment, and twenty-eight inherited or insufficiently reconciled coverage. This pass adds D45 claude-mem and D46 OpenHands Software Agent SDK with selected function/caller reading. Thus the numbered table now has fifteen source-excerpt entries, three docs/paper entries and twenty-eight unreconciled entries. These are reading categories, not percentages of product understanding or whole-repository audit claims.

**All audits checked: no.** The supplied Claude report and earlier owner reports informed the design, but there is no complete finding-by-finding reconciliation of the full archive. The six remaining design questions in §5 are still open; two useful donors do not resolve the exact external controller API, all original requirements or the physical Store schema.

The 34 requirement groups, 29 A15 cases and Claude's 63 anchors/eight hard boundaries are different denominators. Preserving them is not proof that all source requirements have been independently reconciled or implemented.

## 2. D01–D44: conservative coverage census

The heading retains its existing link; new D45–D46 are appended without renumbering. **Source excerpts** means concrete functions/callers read, not the entire project. **Unreconciled** means comparable review is not established in the maintained V3 record, not that nobody ever read the donor. A mature external tool need not have its entire source re-audited merely to use it.

| D | Donor surface | Recorded level | Useful next question / retained limit |
|---|---|---|---|
| 01 | MemMachine | Source excerpts, §§26–27 | Actual configured backend and remaining segmenter/ingestion details |
| 02 | MemPalace | Unreconciled | Source identities and repeated export handling |
| 03 | Subcog | Source excerpts, §28 | Selected fusion/lifecycle functions, not full runtime quality |
| 04 | MemOS local plugin | Source excerpts, §9 | L2/gain attribution, not complete learning pipeline |
| 05 | Claude Code memory/tool search | Docs/paper | Installed timing and actual integration, not host source audit |
| 06 | ClawVM | Unreconciled | What compression preserves and what the reader receives |
| 07 | Pichay / demand paging | Unreconciled | Repeated expansion cost and reconstruction behavior |
| 08 | Graphiti | Source excerpts, §26 | Temporal filters and add_episode caller before broadening helper findings |
| 09 | Hindsight | Source excerpts, §§26–27 | Remaining retain/consolidation commits and broader retrieval |
| 10 | Current EverOS | Source excerpts, §30 | Imported everalgo internals and unreviewed intake/recovery |
| 11 | Historical EverMemOS | Docs/paper, §30 | Historical implementation matching the paper not established |
| 12 | Cloudflare managed Agent Memory | Unreconciled | Actual service boundary and useful update mechanism |
| 13 | Cloudflare Agents SDK Sessions | Unreconciled | Session/branch/compaction semantics for source intake |
| 14 | SurrealFS | Unreconciled | Source/indexer identity and incremental indexing |
| 15 | MentisDB | Unreconciled | Versioned procedure lookup/update and actual consumers |
| 16 | LangMem | Source excerpts, §§23–24 | Selected executor/prompt path, not every backend |
| 17 | Current Letta Code | Source excerpts, §29 | Full automatic/server reflection and replay remain partial |
| 18 | Archived Letta V1 | Unreconciled | Historical source distinct from D17 |
| 19 | Nocturne Memory | Source excerpts, §28 | Read/alias/version mechanisms, not persona/boot doctrine |
| 20 | Mem0 OSS | Source excerpts, §31 | Synchronous extraction/formatter; async and hosted platform not qualified |
| 21 | Historical OpenMemory MCP | Unreconciled | Exact historical product and consumer |
| 22 | OpenMemory session CLI | Unreconciled | Real session/import/export rather than roadmap |
| 23 | Cavira LongMemory | Unreconciled | Supersession/decay/checkpoint and product identity |
| 24 | ripgrep | Unreconciled | Concrete source-span use; whole-tool audit unnecessary |
| 25 | ast-grep | Unreconciled | Specific structural queries and coordinates |
| 26 | SCIP | Unreconciled | Actual producer/version/encoding and definition-reference use |
| 27 | GitHub Copilot Memory | Unreconciled | Publicly supportable citation/reuse behavior |
| 28 | Docling | Unreconciled | Relevant document ingestion before parser selection |
| 29 | Docling Core | Unreconciled | Hierarchy/provenance for that document path |
| 30 | DocETL | Unreconciled | Useful transform/error handling, not its whole runtime |
| 31 | Vector / VRL | Unreconciled | Concrete preservation mechanism; no DSL by default |
| 32 | Kreuzberg v4 LTS | Unreconciled | Exact branch and needed native extraction |
| 33 | Current Kreuzberg | Unreconciled | Do not inherit D32 properties by name |
| 34 | Cedar | Unreconciled | No baseline policy-engine need; omission is not review |
| 35 | OPA | Unreconciled | No second policy owner merely to use a donor |
| 36 | redb | Unreconciled | Historical recovery ideas; one-DB choice unchanged |
| 37 | duroxide | Unreconciled | Activity identity may help; workflow runtime not selected |
| 38 | Flawless | Unreconciled | Unknown external outcome/retry distinctions |
| 39 | FoundationDB testing | Unreconciled | Not an implementation prerequisite or new test platform |
| 40 | Wasmtime | Unreconciled | Only a real extension/isolation need justifies it |
| 41 | SurrealDB Agent Memory / Spectron | Docs/paper | Application-tier descriptions, not code/runtime qualification |
| 42 | MAGMA | Source excerpts, §29 | Actual query path; broader ingestion remains partial |
| 43 | A-MEM | Source excerpts, §28 | Library, research code and paper remain distinct |
| 44 | Harness2 | Source excerpts, §§19,25 | Pool/mission/benchmark adapters still partial; no reproduced experiment |
| 45 | claude-mem | Source excerpts, §32, new in 0.19 | Hook observation/spool, generator entry and context registration; full providers, low-level durability and source-to-derived persistence not reviewed |
| 46 | OpenHands Software Agent SDK | Source excerpts, §32, new in 0.19 | Condenser/view/tool-call boundaries and actual message preparation; not every agent/provider/storage path |

Hy-Memory and V1/V2 remain outside this external numbering and were not read completely. The inherited 43 D + 27 P + 187 S inventory describes 257 historical rows, not 257 software projects or verified experiments. New entries do not make the full union of named owner sources complete.

## 3. Additional named sources

The supplied Claude revision 4 §10.2 includes sources outside the old D table. Two omissions are now represented as D45–D46, not silently counted under Claude Code or generic harness research.

| Additional material | Status / relevance |
|---|---|
| claude-mem | Now D45. Concrete capture/context functions reviewed at `9e4f313a89236f7fb593a639a77ee02e21e94469`. The old audit's fixed hook counts and per-tool cost claims do not replace this source scope. |
| OpenHands / software-agent-sdk | Now D46. Condenser and call/result boundaries reviewed at `0996c33916c2a977ea9fe38deee660ff0e1389f2`; this does not qualify the older version cited by Claude. |
| mcp-memory-service | Natural memory triggers proposed in the supplied audit; actual current producer/consumer still unreconciled |
| basic-memory | Contrasting Markdown-source design, not selected as Eliot's storage; code review still open |
| codebase-memory-mcp | Candidate structural source; one concrete integration choice needed, not another embedded graph |
| Codex hooks and OpenCode plugins | Additional real host surfaces; Claude event names do not qualify them |
| Surrealist | Existing inspection UI candidate, not a reason to build another operator application |
| Cloudflare OS, Switchyard, Unsloth, cognee, Perplexity Portable Computer | The supplied audit itself leaves identity/relevance for clarification; not accepted dependencies |

Research families additionally include MemGPT/HiAgent, Retrieve then Solve, LightMem/MemDelta, STALE/ATMS, Memp/ACON, GraphRAG/CodexGraph/RepoGraph/HippoRAG 2, MemLineage/Selection Integrity/TOKI/MemTX and Meta-Harness. Some overlap old P/S rows. The deduplicated union is not established; reading a bibliography is not verifying each result or implementing every framework.

## 4. Audit-of-audits: status retained

These are the owner's source filenames, not new repository reports. Multiple revisions/copies are not independent corroboration. The status from 0.18 remains unless a new read is explicitly noted.

| Audit family | Examined / status | Remaining reconciliation |
|---|---|---|
| Claude documentation audit, revision 4, 2026-10-18 | Used throughout V3; 0.18 reread donor §10.2 and implementation/original-purpose §§15–17 | Remaining recommendations and actual code; 63-anchor closure, fixed counts and line budgets are proposals |
| `ELIOT_AUDIT_2026-10-08_v9(1).md`, v8 also located | Historical `04eec326...`; scope, issue changes, corrections and block-map interpretation read | T01–T31 and later fixes not fully reconciled. Existing retractions of “tests are the established cause” and new registries must not be revived |
| `ELIOT-Swarm-AUDIT-2026-10-06(2).md` | Historical controller `40591a2`; introduction and G1/initial G2 read | Separate controller/swarm responsibilities from Memory OS and historical defects from current interfaces |
| `Аудит репозитория eliot-memory-os относительно /docs/architecture` | `15d6b40d...`, 2026-08-31; scope/findings/recommendations reread | Reconsider its praise of proof/routing machinery under the lightweight rewrite, not automatic adoption |
| `Eliot Memory OS: почему проект остаётся незавершённым` | Summary retrieved, not full current-source reconciliation | Undated current-main/manual-CI claims must not become present facts |
| `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | Referenced by Claude; another exact-title search in 0.19 did not obtain its text | Retrieve the actual report. A different controller donor report found by search was not substituted |
| Release `audit-2026-10-16-incomplete` | Metadata/assets named; full ZIP not successfully transferred/read in this pass | Audit findings, source-transfer decisions and research entries need actual reconciliation; manifest/ledger is not that work |
| `audit-2026-09-14.md` | Its opening establishes adjacent Research/Cloudflare/D1 scope | Not a completed Memory OS audit or evidence about SurrealDB |

The archive's named MANIFEST, execution/intake coverage, blockers, publication and research-join assets establish available names, not complete/correct contents. Failed transfer is not absence of an asset. No new archive-wide count or semantic completeness percentage is claimed.

## 5. What remains for an implementable V3 model

Six connected design tasks remain. These are not six new subsystems or permission gates.

| Work | Chosen direction | Remaining concrete result |
|---|---|---|
| Original-purpose reconciliation | Local-first greenfield memory, history/cognition/transfer and original scenarios retained | Complete source comparison for autonomous understanding, non-code sources, disagreement and self-improvement; name genuine departures |
| Actual host/controller boundary | Native events and one controller for models/embeddings | Real selected event→capture, text request/result and embedding request/result, not only names/types. D45/D46 inform the input but do not provide Eliot's reverse API |
| Concrete storage/read operations | One SurrealDB, native indexes/relations/transactions | Minimal physical layout and capture/work/retrieve/revise/open queries with a compatible SDK/server choice |
| Autonomous useful work | Finite episode interpretation, provisional advice, no-change and subsequent outcomes | What makes work due, which actual source range it consumes, what it changes and how normal next context uses it. No worker per cognitive noun |
| Grounded project understanding | Small purpose/area views linked to real source | Choose an existing structural source and connect actual changed resources/consumers to affected views |
| Practical lifecycle and consistency | Demand start, degraded useful reads, one observer, simple recovery/control | Concrete process/file/DB choices and first-use setup; reconcile all three design documents without invented intermediary layers |

No blanket completion of all research is required for a decided independent component after the documentation stage. Conversely, source findings cannot replace these product decisions. Quality/performance and a promised fifty-fold reduction require implementation, not a new test campaign compensating for missing code.

### Current controller boundary rechecked

The last specific read remains controller `main@eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8`: [README](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8/README.md) and [integration document](https://github.com/UnknownAlienHuman/eliot-swarm-controller/blob/eeea3558d66a1525c9f5c2d9f3b4f75c62714bf8/docs/eliot-memory-os-integration.md) describe requested/unimplemented runtime integration and preparation-only scope. The documented context request is controller→memory, not the reverse text/embedding API. A limited search is not proof that no suitable interface exists elsewhere. That actual method/caller decision stays open; no new controller read or runtime call is claimed in 0.19.

## 6. Fresh source reads and useful next action

| Source | Read in 0.19 | Still outside this pass |
|---|---|---|
| D45 `9e4f313a89236f7fb593a639a77ee02e21e94469` | Architecture overview; hooks.json; observation handler; spool-hook-event; should-skip-agent-observation; context.ts1–260; GeneratorRunner1–260; cache-related head commit and LICENSE opening | Full provider request/response, low-level HookSpool durability, all server/local differences, derived writes and measured cache impact |
| D46 `0996c33916c2a977ea9fe38deee660ff0e1389f2` | README; condenser README/utils/LLMSummarizingCondenser; Condensation event/apply; tool_call_matching/tool_loop_atomicity; base70–300; actual prepare/aprepare_llm_messages in agent/utils430–end | Full agent runtime, other view properties/provider constraints, original event-store durability and live model behavior |

Actual useful findings are recorded in Audit §32: persist before interpretation; coalesce expensive work rather than discard independent child input; preserve stable context while allowing relevant corrections; choose cuts by call/result association; distinguish original sources from model views; do not treat an empty/non-text model answer as a useful summary. Source observations and Eliot design choices are separated.

Next, finish the real controller text/embedding method and concrete first-host event-to-record mapping, then the native Store operations. Use the remaining structural-source donor to settle project views. In parallel task terms, original-purpose and audit reconciliation remain separate unresolved reading; they were not completed by imaginary reviewers. Do not repeatedly broaden donor review instead of resolving these product choices.

The A01–A14 subjects still cover requirements, control, process ownership, storage/recovery, retrieval, producers/consumers, development overhead, own design, Hy coding/transfer, Harness2, donor/archive, interfaces and publication. Graphiti temporal input, Hindsight complete commits, Letta automatic reflection, historical EverMemOS and ORS ownership remain partial.

## 7. Verification and publication boundary

No subagent executor was available, so none ran. No product/donor/model/database execution, synthetic test, Rust/Clippy or performance measurement took place. Current raw-file/asset transfer did not yield a full local checkout; use the actual GitHub diff/ref/readback for publication checks, not a claimed local full-repository scan.

Changes belong to the existing consolidated Audit, this map and navigation. Architecture 0.6, Implementation 0.11 and Cognition 0.16 already define the owners; they are not rewritten merely to repeat them. The original 34 requirements, 29 scenarios and 36 cognitive examples remain. Runtime, schema, dependencies, CI, validators, ACTIVE registry, main and user data are unchanged. The owner's product-code/minimum-Clippy/tests-later sequence still follows the documentation stage.
