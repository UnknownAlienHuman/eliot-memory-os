# V3 audit map — coverage and remaining design work

**Revision 0.23 · 2026-10-21.** Reading coverage, not runtime state or an approval gate. [AUDIT.md](AUDIT.md) holds findings; [Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) hold the product design. This pass prepares source-grounded disagreement, research and self-revision material for Architecture and Implementation. It does not complete the whole requirements or archive audit.

Base: `d7a9de88b87020585a02194c4b51189063f97d96`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [0.18 census](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/815f51e5a6839263ce6e310a42392c7810eb8218/docs/v3/AUDIT-MAP.md) and [0.22 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/d7a9de88b87020585a02194c4b51189063f97d96/docs/v3/AUDIT-MAP.md) retain earlier reading limits. New findings are in [Audit §36](AUDIT.md#36-disagreement-research-and-self-revision-023); implementation changes are §§7.5,8.6–8.7.

## 1. What can honestly be claimed

**No independent subagent review.** Earlier discovery did not expose a usable GPT Luna/Codex/subagent invocation; this pass is also solo. Source reading and a second self-review are not several independent reviewers.

**All donors studied: no.** The numbered table has sixteen source-excerpt entries, three docs/paper entries and twenty-eight unreconciled entries. No new external donor number is added in 0.23. The separate Eliot Research repository is an integration source, not another independently audited donor. These categories do not measure whole-product understanding or imply complete repository audits.

**All audits checked: no.** The supplied Claude report and other historical audits have not been fully reconciled finding by finding. This pass reads selected original cognitive requirements, their V2 implementation and the current Research refactoring plan. It is not the entire Canonical Master, UL document or archive.

The 34 requirement groups, 29 A15 cases and Claude's 63 anchors/eight hard boundaries are different denominators. Preservation is not proof that every original statement has been independently checked or implemented. The small connected implementation is still a design, not deployed V3.

## 2. D01–D44: conservative coverage census

The existing heading/link is retained; later donors are appended without renumbering. **Source excerpts** means named functions/callers read, not the entire product. **Unreconciled** means comparable review is not established in the maintained record, not that nobody ever read it. A mature tool does not require a whole-code audit simply to use its existing interface.

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
| 25 | ast-grep | Unreconciled | Specific structural queries and coordinates; incidental reference lookup is not a comparable donor review |
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
| 36 | redb | Unreconciled | Historical recovery ideas; one semantic DB choice unchanged |
| 37 | duroxide | Unreconciled | Activity identity may help; workflow runtime not selected |
| 38 | Flawless | Unreconciled | Unknown external outcome/retry distinctions |
| 39 | FoundationDB testing | Unreconciled | Not an implementation prerequisite or new test platform |
| 40 | Wasmtime | Unreconciled | Only a real extension/isolation need justifies it |
| 41 | SurrealDB Agent Memory / Spectron | Docs/paper | Application-tier descriptions, not code/runtime qualification |
| 42 | MAGMA | Source excerpts, §29 | Actual query path; broader ingestion remains partial |
| 43 | A-MEM | Source excerpts, §28 | Library, research code and paper remain distinct |
| 44 | Harness2 | Source excerpts, §§19,25 | Pool/mission/benchmark adapters still partial; no reproduced experiment |
| 45 | claude-mem | Source excerpts, §32 | Hook/spool/generator/context, not all providers, low-level durability and source-to-derived persistence |
| 46 | OpenHands Software Agent SDK | Source excerpts, §32 | Condenser/view/tool-call boundaries, not every agent/provider/storage path |
| 47 | DeusData/codebase-memory-mcp | Source excerpts, §35, new in 0.22 | Compact architecture, coverage/trace evidence and actual dispatcher; not every parser, indexer, language, daemon or deployment |

Hy-Memory and V1/V2 remain outside this external numbering and were not read completely. The inherited 43 D + 27 P + 187 S inventory describes 257 historical rows, not 257 software projects or verified experiments. New entries do not establish the complete deduplicated union of the owner's sources.

## 3. Additional named sources

The supplied Claude revision 4 §10.2 names sources outside the old D table. Three omissions now appear as D45–D47 rather than being silently counted under a similar product.

| Additional material | Status / relevance |
|---|---|
| claude-mem | D45, specific paths at `9e4f313a89236f7fb593a639a77ee02e21e94469`; old fixed hook/cost claims do not replace that scope |
| OpenHands / software-agent-sdk | D46, selected SDK paths at `0996c33916c2a977ea9fe38deee660ff0e1389f2`; not qualification of every older version cited by Claude |
| codebase-memory-mcp | D47, `DeusData` source `3457b21b0a3d75960c07ed3ec666a9e684985ef9`; selected as the first configured structural tool, not embedded parser/runtime |
| mcp-memory-service | Natural memory triggers proposed by the supplied audit; actual current producer/consumer still unreconciled |
| basic-memory | Contrasting Markdown-source design; not selected as Eliot storage; code review remains open |
| Codex hooks and OpenCode plugins | Distinct host surfaces; Claude event names do not qualify them |
| Surrealist | Existing inspection UI candidate, not a reason to build another operator application |
| Cloudflare OS, Switchyard, Unsloth, cognee, Perplexity Portable Computer | Identity/relevance remain unresolved in the supplied audit; not accepted dependencies |

Research families additionally include MemGPT/HiAgent, Retrieve then Solve, LightMem/MemDelta, STALE/ATMS, Memp/ACON, GraphRAG/CodexGraph/RepoGraph/HippoRAG 2, MemLineage/Selection Integrity/TOKI/MemTX and Meta-Harness. Some overlap P/S rows. The complete union and each result are not established by a bibliography.

## 4. Audit-of-audits: status retained

These are the owner's source filenames, not new repository reports. Copies and revisions are not independent corroboration. Status remains from earlier passes except the expressly listed fresh reading.

| Audit family | Examined / status | Remaining reconciliation |
|---|---|---|
| Claude documentation audit, revision 4, 2026-10-18 | Used throughout; 0.18 reread donor §10.2 and implementation/original-purpose §§15–17; 0.23 retrieved relevant function-preservation/Concilium/Research proposals | Remaining recommendations and actual code; 63-anchor closure, fixed counts, line budgets and deferred functions remain proposals, not accepted owner requirements |
| `ELIOT_AUDIT_2026-10-08_v9(1).md`, v8 also located | Historical `04eec326...`; scope, issue changes, corrections and block-map interpretation read | T01–T31 and later fixes not fully reconciled. Retractions of “tests are the established cause” and new registries must not be revived |
| `ELIOT-Swarm-AUDIT-2026-10-06(2).md` | Historical controller `40591a2`; introduction and G1/initial G2 read | Separate controller/swarm responsibilities and historical defects from current interfaces |
| `Аудит репозитория eliot-memory-os относительно /docs/architecture` | `15d6b40d...`, 2026-08-31; scope/findings/recommendations reread | Reconsider its praise of proof/routing machinery rather than importing it automatically |
| `Eliot Memory OS: почему проект остаётся незавершённым` | Summary retrieved, not complete source reconciliation | Undated main/manual-CI claims must not become current facts |
| `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | Referenced by Claude; exact-title searches have not obtained its full text | Retrieve the actual report, not a different controller donor report |
| Release `audit-2026-10-16-incomplete` | Metadata/assets named; full ZIP not successfully transferred/read | Findings, transfers and research entries still need reconciliation; manifest/ledger is not that work |
| `audit-2026-09-14.md` | Opening establishes adjacent Research/Cloudflare/D1 scope | Not a completed Memory OS audit or evidence about SurrealDB |

Failed transfer is not absence of an asset. Original normative text can contain both useful goals and flawed compulsory mechanisms. Reading one does not qualify every implementation or justify silently dropping the goal.

## 5. What remains for an implementable V3 model

These subjects are connected design decisions, not new subsystems or permission gates.

| Work | Chosen direction | Remaining concrete result |
|---|---|---|
| Original-purpose reconciliation | UL autonomy in §35; disagreement, research and self-revision in §36 now have Architecture/Implementation choices | Finish unreviewed Canonical Master/UL and historical findings; no blanket requirements-completeness claim |
| Actual host/controller boundary | Native events; synthesis Task→dispatch→result mapping in §6 | Real wiring and missing controller batch-vector operation, without copying controller state |
| Concrete storage/read operations | Six initial primary tables; current/history; five operations in §§2.6–2.9 | Actual DDL/bindings/queries/plans on selected build; sketches are not executed code |
| Autonomous useful work | Existing finite jobs for material changes, useful questions and feedback; targeted self-diagnosis in §7.5 | Implement configured scheduling and meaningful input selection, not a model call on every event or global health gate |
| Grounded project understanding | Configured CBM plus actual source/docs, affected ordinary views and next-context consumer | Connect tool and actual coverage/change behavior; no live parser-quality qualification |
| Concilium and research | Existing claims/links and discriminating observations; external acquisition stays with Research; §§8.6–8.7 | Actual Research request/result mapping, selected route and source opening; its current refactoring plan is not a verified endpoint |
| Practical lifecycle and consistency | Demand start, one observer, usable primary memory and ordinary recovery/control | Concrete first-use/setup/process ownership and remaining interface choices; preserve useful operation without an installation/admission platform |

A decided independent capability need not wait for completion of all research once implementation is authorized. Conversely, reading sources does not implement it. Performance and a fifty-fold reduction require a functioning comparable product, not another mock or certificate programme.

### Controller, Store and structural choices retained

Controller `912df90f`: open is preparation; the chosen first Claude query requires task.dispatch. Input admission is not completed inference; later send and a dispatch-only result reader do not automatically form a pair. The missing vector operation remains controller work. [Audit §33](AUDIT.md#33-controller-execution-and-embedding-boundary-020) retains the scope; no new live qualification here.

`stream`/`observation`, `memory`/`memory_history`, `link` and `job` remain the initial Store layout. Capture/pending work commit together; running input is finite; primary reads need no mirrored publisher. [§34](AUDIT.md#34-native-store-operations-without-mirrored-state-021) retains the source/API basis. No schema was deployed.

D47 supplies a compact structural summary and selected actual source; explanation and relevant knowledge stay in Eliot's ordinary views. Its parser/daemon/index are not copied. First useful orientation does not require a complete pyramid, and a placeholder is not understanding. The [0.22 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/d7a9de88b87020585a02194c4b51189063f97d96/docs/v3/AUDIT-MAP.md) retains the precise UL/CBM/Git reads and counterchecks.

### New choices for Architecture and Implementation

Architecture §§6–8 preserves disagreement, self-correction and autonomous inquiry as product functions, without adding owners. Implementation §7.5 identifies the actual failed step before changing a lesson. §8.6 uses scoped claims, evidence, dissent and the cheapest useful discriminating observation; no compulsory agent panel. §8.7 uses a real configured external research route and existing memory jobs, not V2's complete federation machinery.

Failed repair prevents unsupported repetition of that repair, not new diagnosis. Partial overall monitoring cannot establish global health, but does not hide a known local error. Mixed Pass/Fail in a broad dimension is not automatically a contradiction. Useful provisional memory remains available while a question is unresolved. The application's own source/job/result records support these distinctions without a SelfQualityStore or ResearchRegistry.

## 6. Fresh source reads and useful next action

| Source | Read in 0.23 | Remaining boundary |
|---|---|---|
| V1 Canonical Master `b5c84d4e` | Opening 1–240 and beginning principles through §3.6, including self-improvement gating | Not the full Master; universal gate differs from preserved goal of avoiding self-justified improvement |
| V2 cognitive requirements `5aac0948` | Short A0.5, A9.3, A10.5, I13.4; I14.22, I16.23 and I21.11 | Not all Concilium/research implementation or every old normative cross-reference |
| V2 self-quality | `lib.rs`, `diagnose.rs`1–280; contract250–650,680–1010,1060–1380 | Findings about pure algorithm and valid input; production caller/history selection and live behavior not established |
| V2 Research | Researcher facade1–240; module composition1–300 | Interface/delegation and surrounding shapes, not the complete actual provider execution or retained-data path |
| Current Eliot Research `7c034569b908d3b03a8b821b7c537477a24b10f7` | README, Implementation navigation, backend-entrypoints1–210 | Current simplification plan, not completed ordinary/deep/federation implementation; actual Memory adapter still to choose |
| Attached Claude revision4 | Relevant function-preservation/Concilium/Research excerpts and exact-title report search | Not full report reconciliation or retrieval of the missing work-system report |
| Current V3 | Instructions, Architecture baseline and relevant current Cognition; full maintained audit and Implementation baseline/changed sections | No independent review, full checkout or whole-repository link verification |

Counterchecks: original Concilium explicitly rejects voting and allows one agent; original conflict rules are local. Self-quality requirements already reject a global intelligence score. The pure diagnosis function declares inert handoffs, not an executed repair. A failed narrow name search does not prove absence of all Research routes. Current Research README expressly says refactoring is in progress.

**Next:** concrete first-use/process ownership and configuration of actual routes, then the missing callable Research integration and remaining original/audit reconciliation. Keep the main input→memory→interpretation→next-context path coherent; do not reopen primary reads or add a permission platform to compensate for an unconnected method. The remaining twenty-eight donor rows and full archive are still unfinished.

A01–A14 continue to cover requirements, control, processes, Store, retrieval, producers/consumers, development overhead, own design, Hy coding/transfer, Harness2, donor/archive, interfaces and publication. Graphiti temporal filtering, complete Hindsight commits, Letta automatic reflection, historical EverMemOS and ORS responsibility tracing remain partial.

## 7. Verification and publication boundary

This pass is source/document reading and design review. No product/donor/model/database run, synthetic behavioral test, Rust/Clippy, benchmark or independent subagent review. Local network transfer did not provide a current checkout; actual GitHub commit/compare/ref/readback checks are reported rather than a local full-repository verification.

Changes are confined to Architecture, Implementation §§7.5,8.6–8.7 and associated navigation, Audit §36, this map and README. Cognition0.16 is unchanged. The 34 requirement groups, 29 A15 cases, D01–D47, S1–S32 and 36 cognitive examples remain. Runtime, deployed schema, dependency files, permissions, CI, validators, ACTIVE registry, main and user data are untouched. Product implementation remains after documentation, using the owner's code/minimum-Clippy/tests-later order.
