# ELIOT: индекс документации

> **Статус:** каноническая точка входа; только навигация, не третья нормативная книга.
>
> **Канонический каталог:** `C:\Development\Rust\docs\ELIOT Arhitecture`. Копии внутри проекта или на GitHub не являются источником документации.

Читайте этот файл первым. Для точного поиска по сущностям, потокам и предметам используйте [INDEX.md](./INDEX.md). Не загружайте обе книги целиком.

## Нормативная пара и границы утверждений

| Вопрос | Источник |
|---|---|
| Intent, Theory, Invariants, Hard Boundaries, смысл решений | [ELIOT Architecture](./ELIOT_ARCHITECTURE.md), `4.5-draft` |
| Целевые owners, contracts, defaults, failure behavior, migration | [ELIOT Implementation](./ELIOT_IMPLEMENTATION.md), `0.29-draft` |
| Что реально существует и работает сейчас | точные source/build/runtime/store evidence, не проза |

При смысловом конфликте Architecture выше Implementation. Каноничность каталога не меняет статусы ревизий: Architecture — кандидат на принятие; Implementation — `TARGET`; code/runtime/data conformance неизвестно; product — `NOT_ACCEPTED / UNVERIFIED`.

## Минимальный вход

- Общее понимание: введение Architecture, `A1`, `A16.3`.
- Конфликт или толкование правила: `A0`.
- Реализация: `Краткое решение`, `Как читать эту книгу`, `I0`, затем только маршрут задачи ниже.
- Любое утверждение о текущей системе: документ + отдельное актуальное evidence.

## Протокол экономного чтения

1. Выберите один маршрут ниже.
2. Найдите заголовок, не сканируя сначала весь текст:

   ```powershell
   rg -n -i -g 'ELIOT_*.md' '^#{1,3} .*PATTERN' .
   ```

3. Прочитайте минимальный numbered section и только его прямые ссылки.
4. Если заголовка недостаточно, ограничьте поиск первых совпадений:

   ```powershell
   rg -n -i -m 20 -g 'ELIOT_*.md' 'PATTERN' .
   ```

5. Расширяйте контекст только при незакрытой зависимости, конфликте или failure boundary.

## Маршруты

| Задача | Минимальный маршрут |
|---|---|
| Смысл, authority, конфликт решений | `A0`, нужный `A*`, `A16`; `I0.3–I0.5` |
| Текущая поддержка и статус продукта | `I0.2`, `I0.5`, `I0.13`, `Document status`; затем exact evidence |
| Первый vertical spine | `I0`, `I1.1–I1.8`, `I2.1–I2.5`, `I5.1–I5.7`, `I7`, `I14`, `I17–I18` |
| Kernel и recovery | `A8`, `A12–A13`; `I1`, `I2.3–I2.5`, `I5.5–I5.23`, `I14–I16`, Appendices `A–D/P` |
| Process Module или bridge | `A2`, `A13`; `I2.1–I2.25`, `I6.4–I6.5`, `I7.1–I7.5`, `I10`, `I14.14`, `I18` |
| Instrument, verifier, code understanding | `A5–A6`, `A10.8`, `A14.6`; `I2.9–I2.25`, `I10.8–I10.10`, `I12.9–I12.10`, `I16.17`, `I17–I18`, Appendices `J/P` |
| Agent/runtime/swarm integration | `A7`, `A10`, `A12`; `I3`, `I7`, `I10.15–I10.18`, `I10.21`, `I13–I14`, `I16`, `I18.11`, `I18.16–I18.18`, `I18.43` |
| Negotiated decomposition, live peer delivery и anchored review | `A10`; `I10.15`, `I10.18`, `I10.21`, `I12.10`, `I12.31`, `I14.20`, `I18.11`, `I18.18`, `I18.43` |
| Memory, Understanding, Dreamer | `A4–A7`, `A9`, `A14`; `I9`, `I12–I13`, `I16` |
| Security и provenance | `A12`; `I5`, `I10.21`, `I12.10`, `I15`, `I18.18`, применимые proof-разделы `I18` |
| Professional/multimodal workflow | `I4`, `I10.13`, `I10.20–I10.22`, `I12.35`, `I18.47` |
| Migration, release, future boundaries | `I0.8–I0.9`, `I18–I20`, Appendices `G–P` |

## Карта верхнего уровня

- Architecture `A0–A3`: толкование; миссия; роли/authority/modules; WorkScope.
- Architecture `A4–A7`: memory; reality/evidence; understanding; context/skills.
- Architecture `A8–A11`: Watchdog; Dreamer; Harness/agents/swarm; Human control.
- Architecture `A12–A16`: security; resilience; learning/Meta; scenarios; decision anchors.
- Implementation `I0–I4`: status/change; processes; Rust/workspace; installation; WorkScope/bootstrap.
- Implementation `I5–I9`: storage; contracts; agent interaction; Watchdog; Dreamer.
- Implementation `I10–I14`: integrations; Human plane; understanding/memory; conflict/attention; queues/degradation.
- Implementation `I15–I20`: security; observability; development order; testing/grounding; migration; future replacements.
- Appendices `A–P`: lifecycle/protocols, config/reason codes, backlog/conformance, research gates, dependencies/commands, legacy evidence pointers, storage profile, empirical profiles и Rust interfaces. Открывать только по точной необходимости.

## Правило поддержки индекса

Обновляйте этот файл только при изменении canonical location, имён/версий книг, top-level `A*`/`I*`, статуса или рабочих маршрутов. Не копируйте сюда contracts, schemas, audit history и текущие runtime claims.
