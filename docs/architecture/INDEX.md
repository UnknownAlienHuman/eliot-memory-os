# ELIOT: предметный индекс

> **Роль:** канонический навигационный слой для агентов; не третья нормативная книга.
>
> **Формат:** Markdown — основной и единственный поддерживаемый индекс. JSON не хранится вручную; он нужен только как генерируемая проекция для конкретного программного потребителя.

Нормативная пара: [Architecture](./ELIOT_ARCHITECTURE.md) `4.5-draft` + [Implementation](./ELIOT_IMPLEMENTATION.md) `0.29-draft`. Быстрый вход: [README](./README.md).

English final edition (2026-08-28):
[Architecture](./ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md),
[Implementation](./ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md).
Edition SHA-256 and authority boundaries are recorded in
[`README.md`](./README.md) and
[`../ARCHITECTURE_CONTRACT.md`](../ARCHITECTURE_CONTRACT.md).

## Как пользоваться

- `E:` — сущность или owner; `F:` — сквозной flow; `T:` — предметный вопрос.
- Сначала найдите один ключ в этом файле, затем откройте только указанные handles.
- В записи `start → expand` сначала читайте `start`; `expand` нужен только для незакрытого вопроса или прямой зависимости.
- Architecture задаёт смысл и Hard Boundaries; Implementation — целевой контракт.
- Утверждение о текущем коде, runtime или store требует отдельного exact evidence.
- Line numbers не являются ключами. Стабильный ключ — номер секции.

```powershell
rg -n -i 'canonical-write|receipt' INDEX.md
rg -n -g 'ELIOT_*.md' '^#{1,2} (A12\.3|I5\.19)\.' .
```

## English edition 2026-08-28: structural delta

Ниже перечислены edition-specific маршруты. Остальные записи этого индекса
используют стабильные `A*` / `I*` handles общей пары; если маршрут включает
вынесенный appendix detail, English Implementation указывает соответствующую
publication projection прямо в верхнем уровне приложения.

| Вопрос | Architecture English final | Implementation English final |
|---|---|---|
| Confirmatory/exploratory inquiry, evidence freeze, coverage denominator | `A5.7` | `I21.2–I21.9` |
| Researcher plane и provider boundaries | `A5.7`, `A10`, `A12` | `I21.1–I21.13` |
| Portable skill package | `A7.10`, `A12.7` | `I7.29` |
| Messaging bridge | `A10.1–A10.3`, `A12.6` | `I10.23` |
| User automation | `A11`, `A12.2` | `I11.12` |
| Rust topology и crate-fleet economics | `A2.3`, `A14.8` | start `I2.1`, `I2.3–I2.8`, `I2.10–I2.23`, `I2.25` → expand `I18.33` |

## Статус и authority

| Вопрос | Читать |
|---|---|
| Каноническая location и роль индекса | [README](./README.md) |
| Иерархия intent и конфликт смысла | `A0.2`, `A0.4` |
| Роли Architecture, Implementation и evidence | headers книг; `I0.3` |
| Contract maturity, implementation support, execution status | `I0.5` |
| Current source/runtime/store evidence | `I0.5` → `CurrentSystemEvidenceSnapshot` |
| Product acceptance | `I0.13`, `Document status` |

## Сущности и owners

| Ключ / aliases | Architecture | Implementation |
|---|---|---|
| `E:authority` — authority, owner, grant, lease, epoch | `A0.2`, `A2.2`, `A10.2`, `A12.2` | `I1.8`, `I6.10`, `I11.3` |
| `E:workscope` — scope, repository, workspace, Terrain | `A3` | `I4.1`, `I4.3` |
| `E:kernel-host` — Governor, Kernel, Host, supervision | `A2.2`, `A13.2–A13.3` | `I1.2`, `I1.5`, `I1.8`, `I1.10–I1.13`, `B.0`, `P.2–P.3` |
| `E:module-generation` — Module, generation, replacement, artifact | `A2.3`, `A13.3` | `I2.1`, `I2.23`, `I6.4`, `I7.4`, `I14.14`, `Appendix A` |
| `E:registry` — Module, Generation, Capability, Route Registry | `A2.3`, `A11.3` | `I1.9`, `I3.4`, `I3.14`, `I6.15` |
| `E:canonical-store` — storage classes, SurrealDB, read model | `A4.5`, `A12.3` | `I5.1–I5.3`, `I5.9–I5.11`, `I5.20`, `P.6` |
| `E:canonical-write` — transition, envelope, receipt, operation identity | `A12.3` | `I5.4–I5.8`, `I5.19`, `I5.27` |
| `E:blob-store` — immutable payload, reachability, GC | `A4.5`, `A13.7` | `I5.12`, `B.3`, `P.5` |
| `E:memory` — cognitive inheritance, records, cues, lifecycle | `A4.1–A4.7`, `A14.2–A14.4` | start `I12.1–I12.5`, `I12.26` → expand `I12.6–I12.8`, `I12.19–I12.25` |
| `E:evidence` — observation, verifier, receipt, execution status | `A4.5`, `A5.1`, `A5.5` | `I0.5`, `I5.19`, `I7.27`, `I16.1`, `I18.1` |
| `E:state-fence` — time, revision, attempt/effect identity | `A5.4` | `I5.27`, `I9.5`, `I13.5` |
| `E:epistemic-position` — status, theories, fitness, unknown | `A5.2–A5.3`, `A5.6` | `I12.5`, `I12.12`, `I12.22` |
| `E:understanding` — layers, graph, causality, competence, change provenance | `A6.1–A6.7` | `I6.12`, `I6.16`, `I10.21`, `I12.9–I12.11`, `I12.28`, `I12.31`, `I12.33–I12.34` |
| `E:context-compiler` — Active View, packet, compaction, economy | `A7.1`, `A7.4`, `A7.6`, `A7.9` | `I7.11`, `I7.19`, `I7.26`, `I12.13–I12.17`, `I12.32` |
| `E:skills` — skill, guard, challenge, tool exposure | `A7.10`, `A12.7` | `I7.12–I7.13`, `I7.24–I7.25` |
| `E:watchdog` — supervision, liveness, bypass detection | `A8` | start `I8.1`, `I8.3`, `I8.6`, `I8.14` → expand `I8.7–I8.8`, `I8.11`, `I8.13`, `I8.15`, `I8.18`; `B.5`, `P.11` |
| `E:problem-incident` — Signal, Problem, Incident, Failure Capsule | `A8.3`, `A13.4` | `I13.9`, `I14.5`, `I16.18` |
| `E:doctor-recovery` — repair, recovery state, escalation | `A8.6`, `A13.3–A13.6`, `A13.12` | `I14.5`, `I14.21`, `I14.26`, `I14.29`, `P.4`, `P.11` |
| `E:dreamer` — curation, orientation, research synthesis | `A9` | `I9.1`, `I9.5`, `I9.9`, `I9.16–I9.17`, `B.6`, `P.11` |
| `E:agents-swarm` — delegation, durable swarm, negotiated partition, mailbox, blackboard, live peer delivery | `A10` | start `I10.15`, `I10.18` → expand `I7.8–I7.9`, `I9.9`, `I14.20`, `I17.15`, `I18.11` |
| `E:instrument-plane` — ProcessExecutor, InstrumentRunner, CodeCortex, LSP | `A5.5`, `A10.8`, `A14.6` | `I10.8–I10.10`, `I16.17`, `I18.6`, `I18.19`, `P.12` |
| `E:review-provenance` — anchored review, ChangeMonitor, evolving anchor, ChangeProvenanceView | `A5.5`, `A10.8`, `A14.6` | start `I10.18`, `I10.21`, `I12.10`, `I12.31` → expand `I11.2`, `I14.20`, `I18.18`, `I18.43` |
| `E:integrations` — EBP, MCP, Codex, Claude, OpenCode, ACP | `A10.1`, `A12.6` | `I7.1–I7.7`, `I10.1–I10.7`, `I10.11–I10.14` |
| `E:human-control` — installation, board, approval, notification | `A11` | `I11.2`, `I11.3`, `I11.10`, `B.8` |
| `E:security` — principal, provenance, injection, bypass, secrets | `A12.1–A12.7` | `I8.6–I8.8`, `I15.1`, `I15.5`, `I15.18` |
| `E:privacy` — influence, disclosure, retention, erasure | `A4.7`, `A12.5`, `A12.8` | `I5.14`, `I15.14`, `I15.18` |
| `E:observability` — logs, metrics, audit, reports, diagnostics | `A13.10` | `I16.1`, `I16.3`, `I16.17`, `I16.18`, `I16.23` |

## Сквозные flows

| Ключ / flow | Architecture | Implementation |
|---|---|---|
| `F:bootstrap` — install → scope → deterministic scan | `A3`, `A11.2` | `I3.2`, `I4.1`, `I4.3` |
| `F:session` — handshake → session → continuation/transfer | `A10.1`, `A12.2` | `I7.3`, `I7.14–I7.15` |
| `F:orientation` — cue → epistemic position → bounded context | `A5.2`, `A7.1–A7.4` | `I12.6–I12.17` |
| `F:read` — scope → named read → consistency/cache | `A4.5`, `A7.3` | `I1.8`, `I5.20`, `I7.18` |
| `F:canonical-write` — admission → transition → projections → receipt | `A12.3` | `I1.8`, `I5.4–I5.8`, `I5.19`, `I5.27` |
| `F:external-effect` — authority → action → effect identity → reconciliation | `A10.2–A10.3`, `A12.2` | `I1.8`, `I6.10`, `I14.28` |
| `F:strict-finish` — acceptance → verifier → canonical outcome | `A5.5`, `A10.8` | `I7.9`, `I18.1`, `I18.9` |
| `F:promotion` — artifact → candidate → canary → cutover/rollback | `A2.3`, `A13.3`, `A14.8` | `I7.4`, `I14.14`, `I18.42`, `Appendix A` |
| `F:evidence` — instrument → raw evidence → receipt → verifier | `A5.5`, `A14.6` | `I10.8`, `I16.17`, `I18.6–I18.9` |
| `F:compaction-resume` — task frame → omission handles → continuation | `A7.6` | `I7.15`, `I7.26`, `I12.17`, `I12.32` |
| `F:recovery` — signal/problem → directive → repair → verified disposition | `A8.6`, `A13.4`, `A13.6`, `A13.12` | `I13.9`, `I14.5`, `I14.21`, `I14.26`, `I14.29` |
| `F:agent-execution` — goal → route → bounded attempt → reconcile | `A10.1–A10.8` | `I7.8–I7.9`, `I10.15–I10.18`, `I17.15` |
| `F:peer-coordination` — independent mapping → frozen partition → admitted delta → revalidation/cross-review → synthesis | `A10.1–A10.8` | start `I10.15`, `I10.18` → expand `I14.20`, `I18.11` |
| `F:change-provenance` — public decision/review → operation/diff → historical/current anchor → verifier/outcome | `A5.5`, `A10.8`, `A14.6` | `I10.18`, `I10.21`, `I12.10`, `I12.31`, `I18.18` |
| `F:migration` — forensic baseline → ordered transition → cutover | `A0.6`, `A13.7` | `I19.1`, `I19.5`, `I19.10`, `I19.15–I19.16` |

## Предметные вопросы

| Ключ / вопрос | Architecture | Implementation |
|---|---|---|
| `T:interpretation` — какое правило выше, как разрешить конфликт | `A0.1–A0.6` | `I0.3–I0.6` |
| `T:vocabulary` — определения основных объектов и состояний | `A0.7` | `I5.15–I5.18`, `I6` |
| `T:mission` — зачем ELIOT и почему это не RAG | `A1` | `Краткое решение` |
| `T:conformance` — maturity, support, execution status | `A0.8`, `A16.1` | `I0.5`, `I0.9`, `I0.13`, `Appendices F/H` |
| `T:current-vs-target` — что существует сейчас, что только planned | `A0.9`, `A5.1` | `I0.2`, `I0.5`, `I0.13`, `I20.2`, `Document status` |
| `T:concilium` — disagreement, rival models, decision framing | `A0.5`, `A9.3`, `A10.5` | `I13.4` |
| `T:coordination-review-provenance` — negotiated partition, live peer delivery, anchored review, evolving anchors, ChangeProvenanceView | `A10`, `A13.10` | start `I10.15`, `I10.18`, `I10.21`, `I12.10` → expand `I12.31`, `I14.20`, `I18.11`, `I18.18`, `I18.43` |
| `T:memory-lifecycle` — capture, classify, revise, consolidate, forget | `A4.2–A4.7`, `A14.2–A14.4` | `I5.14`, `I12.2–I12.5`, `I12.19–I12.26` |
| `T:causality-grounding` — graph, artifacts, causal proof, reconstruction | `A6.4–A6.6` | `I12.9–I12.10`, `I12.28`, `I12.34` |
| `T:context-economy` — bounded context, hot path, omission, resume | `A7.6–A7.9` | `I7.24–I7.26`, `I12.14`, `I12.17`, `I12.32` |
| `T:runtime-topology` — processes, ownership, health, Kernel unavailable | `A2.3`, `A13.2` | start `I1.4`, `I1.8`, `I1.10`, `I1.13` → expand `I1.1–I1.7` |
| `T:rust-topology` — workspace, crates, dependency law, agent workset | `A2.3`, `A14.8` | start `I2.1–I2.3`, `I2.20` → expand `I2.15–I2.24` |
| `T:installation` — setup, capability discovery, credentials, update | `A11.2–A11.3`, `A12.6` | `I3.2`, `I3.4`, `I3.12`, `I3.15`, `Appendix C` |
| `T:storage` — semantic API, writes, reads, SurrealDB, backup, schema | `A4`, `A13.7` | start `I5.1–I5.4`, `I5.19–I5.20` → expand `I5.9–I5.14`, `I5.22–I5.27`, `Appendix N` |
| `T:protocols` — EBP, IPC, MCP, service profiles, Rust boundaries | `A10.1–A10.3` | `I7.1–I7.7`, `Appendices B/P` |
| `T:queues-degradation` — backpressure, outage, memory pressure, resource limits | `A13.5`, `A13.11` | `I14.2`, `I14.4`, `I14.11–I14.12`, `I14.28` |
| `T:security-threats` — injection, bypass, supply chain, remote routes | `A12` | start `I15.1`, `I15.5`, `I15.18` → expand `I15.2–I15.4`, `I15.13–I15.17`, `I18.44` |
| `T:observability-diagnostics` — telemetry, wait graph, Failure Capsule | `A13.10` | `I16.1`, `I16.18`, `I16.23` |
| `T:learning-meta` — consolidation, calibration, evaluation, improvement | `A13.12`, `A14.1–A14.7` | `I12.18–I12.24`, `I16.23` |
| `T:human-control-recovery` — board, approval, recovery view, stuck work | `A11`, `A13.6` | `I11`, `I14.21`, `I14.26`, `I14.29` |
| `T:development` — vertical spine, delivery depths, agent work units | `A14.8–A14.9` | start `I17.2`, `I17.6`, `I17.15` → expand `I17.7–I17.14` |
| `T:testing` — tiers, discriminators, product proof, release gate | `A5.5`, `A10.8`, `A14.6` | start `I18.1`, `I18.6`, `I18.9`, `I18.13` → expand по проверяемому property |
| `T:migration-future` — repair order, cutover, replacement, distributed future | `A0.6`, `A13.7`, `A16` | start `I19.1`, `I19.5`, `I19.10`, `I20.2`, `I20.9` → expand `I19.15–I19.16` |
| `T:professional-multimodal` — professional apps, objects, workflow continuity | `A3`, `A6` | `I10.13`, `I10.20–I10.22`, `I12.35`, `I18.47` |
| `T:config-defaults` — runtime configuration | `A0.9`, `A12.2` | `Appendix C` |
| `T:reason-codes` — reason codes, directives, dispositions | `A8.3`, `A13.4` | `Appendix D` |
| `T:conformance-map` — Architecture obligations → implementation owners | `A16.1` | `Appendices F/H` |
| `T:research-gates` — unknowns, experiments, adoption gates | `A5.6`, `A14.6` | `Appendix G` |
| `T:dependencies` — library choice and containment | `A2.3`, `A14.8` | `Appendix I` |
| `T:developer-commands` — CLI and Instrument command surface | `A10.3`, `A14.8` | `Appendix J` |
| `T:legacy-evidence` — donor/legacy/compatibility pointers | `A0.6`, `A13.7` | `Appendices K–M` |
| `T:physical-schema` — SurrealDB tables, indexes, named queries | `A4.5`, `A12.3` | `Appendix N` |
| `T:empirical-profiles` — candidate performance/resource defaults | `A14.6–A14.7` | `Appendix O` |
| `T:rust-interfaces` — public Rust boundaries | `A2.3`, `A10.3` | `Appendix P` |

## Evidence guardrails

- `ContractMaturity`, `ImplementationSupport` и `EvidenceExecutionStatus` — независимые измерения (`I0.5`).
- `TARGET`, `EXPERIMENTAL` и `DEFERRED` не доказывают текущую поддержку.
- `CURRENT_VERIFIED` требует executed, current, scoped evidence для exact Product Identity.
- Prose, report, test count, trait presence или manual status edit не повышают support.
- `NOT_EXECUTED` и `SIMULATED` не доказывают реальный effect.
- Invalidated dependency переводит зависимый support в `STALE`.
- Неизвестное остаётся `UNKNOWN`; индекс не заполняет пробел догадкой.

## Поддержка индекса

Обновляйте `INDEX.md` при изменении canonical files, section handles, source hierarchy или status policy. Не добавляйте line ranges, contracts, schemas, audit chronology и runtime claims. JSON создавайте только автоматически из этого файла для уже существующего consumer; refs в нём должны быть namespaced как `arch:A0.2`, `impl:I5.19`, `impl:appendix:P.12`.
