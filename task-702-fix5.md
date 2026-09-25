# Исправление замечаний аудитора Claude Opus 5 по коммиту 1f67c91a

## Аудит коммита 1f67c91a:
Аудитор признал успешными пункты:
- B1.1 (Carrier source boundary): PASS (`with_curation_source`, `CurationCarrierSource`, `CurationExecutionCarrier`).
- B1.2 (Curation branch threading): PASS (выделенная ветка Curation в `submit`: screen -> carrier -> A-31 -> finish_with_result).
- B1.3 (Fail-closed ordering): PASS (при отсутствии носителя возвращается typed `InvalidAdmission`).

## Единственное блокирующее замечание: B1.4 — Публичный тест успеха submit:
В тесте `submit_curation_with_source_runs_a31_then_fails_closed_at_transport` использовался `ClosedTestTransport`, метод `transact` которого всегда возвращает ошибку, из-за чего `submit` возвращает `DreamerError::KernelAdmissionRequired(_)`.
Аудитор требует добавить тест, доказывающий **успешное** возвращение результата через публичный контракт `<AuthenticatedKernelJobPort as KernelJobPort>::submit`:
`submit(...) -> Ok(JobView)` с `view.result == Some(DreamResult::Curation(...))`!

## Задачи:
1. В `bins/eliot-dreamer/src/pipeline_e2e.rs` (или вспомогательном тестовом модуле):
   - Реализовать `SuccessClaimTransport` (или настроить mock-транспорт), который на вызов `transact` / `status_once` возвращает валидный claim-bound `JobState` (например `JobState::Dispatched` или `JobState::Executing`, с корректным epoch/generation/fence).
2. Написать публичный интеграционный тест `submit_curation_with_source_succeeds_with_curation_result_view`:
   - Сконструировать `AuthenticatedKernelJobPort` с `SuccessClaimTransport` и `TestCarrierSource`;
   - Вызвать публичный `<AuthenticatedKernelJobPort as KernelJobPort>::submit`;
   - Проверить `assert!(res.is_ok())`;
   - Извлечь `view = res.unwrap()`;
   - Проверить `view.result` — это `Some(DreamResult::Curation(c))` с ожидаемыми признаками;
   - Проверить, что счетчик вызовов обработчика равен ровно 1;
   - Сохранить существующий тест отказа при отсутствии источника.
3. Прогнать проверки:
   `cargo test --locked -p eliot-dreamer --all-targets`
   `cargo clippy --locked -p eliot-dreamer --all-targets`
4. Закоммитить изменения в ветку `work/702-pipeline-slice-3`.
