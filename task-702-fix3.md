# Исправление замечаний аудитора Claude Opus 5 по коммиту f5acbdad

Аудитор выявил конкретные дефекты архитектуры конвейера Curation:

1. **Отдельная ветка пайплайна для Curation без лишнего grounding:**
   Curation владеет собственным носителем A-31 и не потребляет общий grounded draft A-14b и не проходит общую валидацию A-05.
   В `run_admitted_pipeline`:
   - Для Curation: выполнить screen (A-20), проверить наличие носителя исполнения Curation (батч и `NativeCurationPortSet`). Если носитель отсутствует — вернуть явную типизированную ошибку/отказ `DreamerError::InvalidAdmission("admitted Curation requires Governor-injected execution carrier and handler ports")` **ДО** запуска generic model/grounding! А если носитель предоставлен — вызвать A-31.
   - Для non-Curation (Orientation, ResearchSynthesis, Maintenance): выполнить screen (pass-through) -> model -> grounding -> validation -> dispatch.

2. **Проверка портов Curation до ресурсоёмких стадий:**
   Curation не должна проходить через фиктивный generic grounding с пустым манифестом, чтобы в самом конце упасть на пустом `NativeCurationPortSet`. Проверка носителя исполнения должна останавливать задачу до ненужных фаз.

3. **Интеграционные E2E тесты:**
   - Добавить тест с инжектированными тестовыми портами Curation (или mock-носителем), доказывающий успешное прохождение через A-20 screen к A-31;
   - Добавить тест, подтверждающий, что при отсутствии портов Curation останавливается сразу на фазе проверки портов с чистым `InvalidAdmission`, не выполняя лишний generic grounding.
   - Убрать устаревшие комментарии в `validation_stage.rs` и других файлах, где говорится, что Curation отклоняется на входе в `submit`.

4. Прогнать `cargo test --locked -p eliot-dreamer --lib`, `cargo clippy --locked -p eliot-dreamer --lib`, сделать коммит в ветку `work/702-pipeline-slice-3`.
