# Исправление замечаний независимого аудита (Claude Opus 5 и GPT 5.6 Sol) по PR #1999 (коммит 645bc1e6)

## Статус аудита: DUAL REJECT на коммите 645bc1e6
Оба аудитора (Claude Opus 5 и GPT 5.6 Sol) подтвердили корректность разделения потока (A-20 -> carrier check -> A-31, пропуская model, grounding и A-05 validation для Curation), но заблокировали слияние по критическому дефекту B1:

### Блокирующее замечание B1: Production Curation success remains impossible
В `AuthenticatedKernelJobPort::submit`:
```rust
run_admitted_pipeline(admission, job, None)
```
В продакшн-коде `AuthenticatedKernelJobPort::submit` жестко зашит `None` в качестве носителя исполнения (`carrier`). В результате любая реальная задача Curation, прошедшая валидацию Kernel/Governor, на этапе `submit` гарантированно падает с отказом, а успешное прохождение A-31 возможно исключительно через тестовый фикстурный вызов `run_admitted_pipeline(..., Some(carrier))`!

Согласно требованиям #702 и #1136:
1. `AuthenticatedKernelJobPort` (или его среда исполнения/Governor-провайдер) должен иметь реальный механизм получения/инъекции `CurationExecutionCarrier` (с валидированным батчем и набором портов обработчиков).
2. `AuthenticatedKernelJobPort::submit` должен передавать полученный/сконфигурированный carrier в `run_admitted_pipeline`, связывая его с admission, A-20 screen, батчем и зарегистрированными портами обработчиков.
3. Если carrier не предоставлен или невалиден — сохраняется fail-closed поведение с `InvalidAdmission`.
4. Но если валидный carrier предоставлен в `AuthenticatedKernelJobPort::submit`, Curation должна успешно проходить A-20 -> carrier check -> A-31 -> генерацию typed `DreamResult::Curation`.
5. Публичный E2E тест должен проверять именно публичный путь `AuthenticatedKernelJobPort::submit` (а не только приватную функцию `run_admitted_pipeline`), демонстрируя:
   - screen (A-20) выполняется первым;
   - generic model/grounding/A-05 не вызываются для Curation;
   - A-31 вызывается ровно 1 раз;
   - типизированный Curation результат корректно возвращается.

## План действий для OpenCode Manager:
1. Изучить структуру `AuthenticatedKernelJobPort` в `bins/eliot-dreamer/src/` (например, конструктор, поля порта, способ инъекции или получения Governor-носителя/провайдера).
2. Добавить в `AuthenticatedKernelJobPort` поддержку инъекции/резолва `CurationExecutionCarrier` (например, через фабрику/провайдер носителя или поле в конструкторе/builder порта), чтобы продакшн-порт не был ограничен жестким `None`.
3. В `AuthenticatedKernelJobPort::submit` передавать carrier в `run_admitted_pipeline`.
4. Реализовать интеграционный тест через публичный метод `AuthenticatedKernelJobPort::submit`:
   - тест с валидным носителем Curation завершается успехом (A-31 -> `DreamResult::Curation`);
   - тест без носителя Curation падает с fail-closed ошибкой `DreamerError::InvalidAdmission`.
5. Запустить верификацию:
   `cargo test --locked -p eliot-dreamer --all-targets`
   `cargo clippy --locked -p eliot-dreamer --all-targets`
6. Зафиксировать изменения коммитом в ветке `work/702-pipeline-slice-3`.
