# V3 audit map — coverage and remaining design work

**Revision 0.22 · 2026-10-21.** Reading coverage, not runtime state or an approval gate. [AUDIT.md](AUDIT.md) holds findings; [Architecture](ARCHITECTURE.md), [Implementation](IMPLEMENTATION.md) and [Cognition](COGNITION.md) hold the product design. This pass revisits original Understanding Layer autonomy and selects a concrete first structural-source adapter. It does not complete the entire requirements or archive audit.

Base: `691556b456c0ede4c33838df9bc3396ac3f1087e`, PR #5325. V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [0.18 census](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/815f51e5a6839263ce6e310a42392c7810eb8218/docs/v3/AUDIT-MAP.md) and [0.21 map](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/691556b456c0ede4c33838df9bc3396ac3f1087e/docs/v3/AUDIT-MAP.md) retain earlier reading limits. New findings are in [Audit §35](AUDIT.md#35-autonomous-understanding-without-a-compulsory-pyramid-022); concrete choices are in [Implementation §8](IMPLEMENTATION.md#8-project-understanding-causality-and-research).

## 1. What can honestly be claimed

**No independent subagent review.** Earlier discovery did not expose a usable GPT Luna/Codex/subagent invocation; this pass is also solo. Source reading and a second self-review are not several independent reviewers.

**All donors studied: no.** The numbered table now has sixteen source-excerpt entries, three docs/paper entries and twenty-eight unreconciled entries. D47 was previously a named source outside the table and is now reviewed in specific code paths. These categories do not measure whole-product understanding or imply complete repository audits.

**All audits checked: no.** The supplied Claude report and other historical audits have not been fully reconciled finding by finding. This pass reads substantial additional UL material, including superseding instructions, not the entire Canonical Master, UL document or archive.

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
| codebase-memory-mcp | Now D47, `DeusData` source `3457b21b0a3d75960c07ed3ec666a9e684985ef9`; selected as the first configured structural tool, not embedded parser/runtime |
| mcp-memory-service | Natural memory triggers proposed by the supplied audit; actual current producer/consumer still unreconciled |
| basic-memory | Contrasting Markdown-source design; not selected as Eliot storage; code review remains open |
| Codex hooks and OpenCode plugins | Distinct host surfaces; Claude event names do not qualify them |
| Surrealist | Existing inspection UI candidate, not a reason to build another operator application |
| Cloudflare OS, Switchyard, Unsloth, cognee, Perplexity Portable Computer | Identity/relevance remain unresolved in the supplied audit; not accepted dependencies |

Research families additionally include MemGPT/HiAgent, Retrieve then Solve, LightMem/MemDelta, STALE/ATMS, Memp/ACON, GraphRAG/CodexGraph/RepoGraph/HippoRAG 2, MemLineage/Selection Integrity/TOKI/MemTX and Meta-Harness. Some overlap P/S rows. The complete union and each result are not established by a bibliography.

## 4. Audit-of-audits: status retained

These are the owner's source filenames, not new repository reports. Copies and revisions are not independent corroboration. Status remains from earlier passes except the expressly listed new UL reading below.

| Audit family | Examined / status | Remaining reconciliation |
|---|---|---|
| Claude documentation audit, revision 4, 2026-10-18 | Used throughout; 0.18 reread donor §10.2 and implementation/original-purpose §§15–17 | Remaining recommendations and actual code; 63-anchor closure, fixed counts and line budgets are proposals |
| `ELIOT_AUDIT_2026-10-08_v9(1).md`, v8 also located | Historical `04eec326...`; scope, issue changes, corrections and block-map interpretation read | T01–T31 and later fixes not fully reconciled. Retractions of “tests are the established cause” and new registries must not be revived |
| `ELIOT-Swarm-AUDIT-2026-10-06(2).md` | Historical controller `40591a2`; introduction and G1/initial G2 read | Separate controller/swarm responsibilities and historical defects from current interfaces |
| `Аудит репозитория eliot-memory-os относительно /docs/architecture` | `15d6b40d...`, 2026-08-31; scope/findings/recommendations reread | Reconsider its praise of proof/routing machinery rather than importing it automatically |
| `Eliot Memory OS: почему проект остаётся незавершённым` | Summary retrieved, not complete source reconciliation | Undated main/manual-CI claims must not become current facts |
| `ELIOT-WORK-SYSTEM-REPORT-2026-10-14.md` | Referenced by Claude; exact-title searches did not obtain its text | Retrieve the actual report, not a different controller donor report |
| Release `audit-2026-10-16-incomplete` | Metadata/assets named; full ZIP not successfully transferred/read | Findings, transfers and research entries still need reconciliation; manifest/ledger is not that work |
| `audit-2026-09-14.md` | Opening establishes adjacent Research/Cloudflare/D1 scope | Not a completed Memory OS audit or evidence about SurrealDB |

Failed transfer is not absence of an asset. This pass does not turn those audit families into completed reviews. Original UL normative text was additionally read directly: preserving its mission does not accept every mandatory implementation choice or every later fixture as proof of understanding.

## 5. What remains for an implementable V3 model

These subjects are connected design decisions, not new subsystems or permission gates.

| Work | Chosen direction | Remaining concrete result |
|---|---|---|
| Original-purpose reconciliation | Autonomous useful orientation, history/cognition/transfer, non-code sources and original scenarios; selected UL Parts A/C/D/E reconciled in §35 | Finish the unreviewed Canonical Master/UL and older audit requirements, especially disagreement, autonomous research and self-revision. No blanket requirement-completeness claim |
| Actual host/controller boundary | Native events; synthesis Task→dispatch→result mapping in §6 | Real wiring and the missing controller batch-vector capability, without copied controller state |
| Concrete storage/read operations | Six initial primary tables; current/history; five operations in §§2.6–2.9 | Actual DDL/bindings/queries/plans on the selected build; sketches are not executed code |
| Autonomous useful work | First attach, material changes/corrections and useful open questions make finite work due; target coalescing and next-context consumer in §8 | Implement actual scheduling/configured capacity and input selection. No fixed concept count, per-event model call or self-exam gate |
| Grounded project understanding | Configured CBM structural queries plus real source/doc reading; ordinary view, not whole graph mirror | Connect the chosen tool in the host, handle its actual scope/index limits and changes. No live CBM run or parser-quality claim |
| Practical lifecycle and consistency | Demand start, one observer, available primary reads and simple recovery/control | Concrete first-use setup and remaining process/file choices; reconcile remaining document boundaries before rewrite |

A decided independent capability need not wait for completion of all research once implementation is authorized. Conversely, reading sources does not implement it. Performance and a fifty-fold reduction require a functioning comparable product, not another mock or certificate programme.

### Controller and Store choices retained

Controller source `912df90f`: open is preparation; the chosen first Claude query requires task.dispatch. Input admission is not completed inference; later send and a dispatch-only result reader do not automatically form a pair. The separate missing vector operation remains controller work. [Audit §33](AUDIT.md#33-controller-execution-and-embedding-boundary-020) retains exact scope; no new live qualification here.

`stream`/`observation`, `memory`/`memory_history`, `link` and `job` remain the selected initial Store layout. Capture and pending work commit together; running input is finite; native primary reads do not wait for a mirrored search publisher. Editorial revision is not unique current truth. [§34](AUDIT.md#34-native-store-operations-without-mirrored-state-021) retains its source/API basis. No tables or dependencies were deployed in this pass.

### Autonomous understanding decision in 0.22

Read a compact structural summary and selected actual source/docs, then interpret purpose and useful relations. Save existing ordinary views; refresh those affected by real edits and changed selection membership; deliver available relevant material at the next planning boundary. First useful output does not wait for full onboarding. A source index, directory partition, generated skeleton or `(pending)` purpose is not semantic completion.

The external CBM index remains a derived source owned by its configured tool. Eliot does not copy its parser/daemon/graph or auto-install profiles. Without it, scoped file/manifest/text reads remain useful with their limits. Native Git status covers worktree changes rather than pretending HEAD equals current files. These are implementation decisions in §8, not a new CodeGraph framework.

## 6. Fresh source reads and useful next action

| Source | Read in 0.22 | Remaining boundary |
|---|---|---|
| V1 UL v1.4 at `b5c84d4e` | 1–260,500–820,1380–1650,1650–1940,1940–2220; exact 1865–1965 reread for metric and superseding decay rule | Not the entire UL/Canonical Master or all legacy implementations. Source-prescribed problems do not prove every author's intent or historical cause |
| D47 `3457b21b` | README1–240; mcp_internal.h; dispatcher excerpts; get_architecture8059–8290; coverage6800–7020 and trace evidence around9000–9120; neighboring navigation chunks | Not all mcp.c, parsers/indexer, detect_changes internals, all languages, daemon lifecycle or full app |
| Official Git status documentation | Porcelain-v1/NUL output, tracked/untracked/staged/unstaged and rename semantics | No repository scan executed; content and source-scope handling still implementation work |
| Current V3 | AGENTS, Architecture, relevant Cognition, full Audit and Implementation baseline/changed sections | No new independent reviewer or exhaustive external-link check |

Counterchecks: Part C already removes synchronous human approval; Part E already improves auto-boot. D7 explicitly repairs the seed-adjacent decay arithmetic, so the early WP3 formula is not reported as an unresolved v1.4 defect. The cost proposal includes a control arm, but its actual downgrade formula still does not measure saved total work. CBM's own coverage output warns that it is not completeness proof. No failed guessed-path fetch is evidence that a capability is missing.

**Next:** finish the original-purpose comparison outside code-oriented UL, particularly disagreement/Concilium, autonomous research and self-revision. Then address concrete first-use/process ownership and the remaining host/controller/source integrations. Do not reopen the already resolved primary-read design or build another policy platform to compensate for a missing connection. The remaining 28 donor entries and full archive stay explicitly unfinished.

A01–A14 continue to cover requirements, control, processes, Store, retrieval, producers/consumers, development overhead, own design, Hy coding/transfer, Harness2, donor/archive, interfaces and publication. Graphiti temporal filtering, complete Hindsight commits, Letta automatic reflection, historical EverMemOS and ORS responsibility tracing remain partial.

## 7. Verification and publication boundary

This pass is source/document reading and design review. No product/donor/model/database run, synthetic behavioral test, Rust/Clippy, benchmark or independent subagent review. Local network transfer did not provide a current checkout; GitHub diff/ref/readback checks are reported as such rather than a local full-repository verification.

The change is confined to Audit, Implementation §8, this map and navigation. Architecture0.6 and Cognition0.16, the 34 requirement groups, 29 A15 cases, S1–S32 and 36 cognitive examples retain their content. D47 is added without renumbering. Runtime, deployed schema, dependency files, permissions, CI, validators, ACTIVE registry, main and user data are unchanged. Product implementation remains after documentation, using the owner's code/minimum-Clippy/tests-later order.
