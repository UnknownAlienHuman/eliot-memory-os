# Статический аудит Perplexity Portable Computer

Дата среза: 2026-08-26  
Статус: `STATIC_AUDIT_COMPLETE_WITH_OPEN_UNKNOWNS`  
Целевой пакет: `perplexity_26.8.4+build50522_arm64.deb`

## Краткий результат

Исследован актуальный официальный Linux/Arm64 пакет Perplexity Portable Computer без установки и без запуска содержимого пакета. Криптографическая цепочка `InRelease/Release → Packages.gz → .deb` корректна. Независимого публичного закрепления fingerprint репозиторного ключа не найдено, поэтому подпись классифицирована как `SIGNATURE_VALID_WITH_UNPINNED_KEY`, а не как независимо подтверждённая identity.

Пакет не является ни пустым downloader, ни полностью автономным стеком. Это **полноценный desktop/control-plane пакет плюс runtime bootstrapper**:

- Electron/Chromium UI и Electron main process;
- большой Rust sidecar `perplexity-rpc-server` с harness, orchestration, sandbox, PII gate, durable state, automations и local-engine control;
- broker client `pplx-search`;
- `uv`, `libaic.so`, локальный skill/template catalog;
- нет model weights, OCI layers, готового Python venv или полной inference-среды;
- Python-зависимости, модели и часть engine/container payloads устанавливаются после запуска local mode.

Сырые данные находятся только вне Git:

`C:\Users\kleym\Downloads\perplexity-portable-computer-audit`

В `.git/info/exclude` дополнительно поставлен локальный guard на возможные `raw/`, `downloads/` и `rootfs/` под report tree. В репозитории находятся только текстовые отчёты и четыре небольших воспроизводимых audit-скрипта. Коммит и push не выполнялись.

## Идентичность пакета

| Поле | Значение |
|---|---|
| Repository | `https://packages.perplexity.ai/deb` |
| Suite / component | `stable / main` |
| Debian package/version | `perplexity / 26.8.4` |
| Build number | `50522` из filename и ASAR manifest |
| Architecture | `arm64` |
| Filename | `pool/main/p/perplexity/perplexity_26.8.4+build50522_arm64.deb` |
| Size | `161,635,712` bytes |
| SHA-256 | `5ac7b5f597e03a888f92a3aaa643138f6cc78a50fd891bc7afabfe86e1e2b994` |
| APT key fingerprint | `5CE6 FE16 BD53 3152 E64E FD93 C751 F9CA C952 A583` |
| Package metadata license | `unknown` |

`+` в object URL пришлось RFC-кодировать как `%2B`; literal `+` возвращал S3 `403 AccessDenied`. Финальный официальный URL:

`https://packages.perplexity.ai/deb/pool/main/p/perplexity/perplexity_26.8.4%2Bbuild50522_arm64.deb`

## Что подтверждено статически

`CONFIRMED_STATIC`:

- 2,080 файлов в rootfs, 598,811,297 байт распакованного содержимого;
- Electron main запускает packaged Rust RPC sidecar через приватный Unix socket/named pipe и JSON-RPC 2.0 framing;
- renderer ограничен явным RPC allowlist; чтение выбранных attachments вынесено в отдельный preload-only channel;
- local harness использует Bubblewrap, seccomp, cgroup и network policy; присутствуют проверки trusted `bwrap` и sensitive paths;
- scheduler/automations используют SQLite, unique run claims и recovery состояний `claimed/running`;
- interrupted trajectories и event sequences сохраняются;
- local inference поддерживает llama.cpp и vLLM/Docker, с pinned image/model identifiers;
- cloud/advisor, connectors и search пересекают локальную границу через отдельные broker/RPC paths и consent/PII механизмы;
- packaged build содержит Sentry и Datadog, включённые по умолчанию для packaged app; фактические runtime payloads не измерялись;
- Linux app updater внутри Electron возвращает snapshot/no-op для check/install; фактический update transport статически не установлен;
- maintainer scripts не скачивают модели, не создают service/user и не запускают application code.

`NOT_FOUND_IN_PACKAGE`:

- model weights;
- OCI image layers или Docker tar archives;
- systemd service/socket/timer;
- публичный Debian source package index;
- лицензия или source offer для core Perplexity harness/RPC/search binaries.

`UNKNOWN_WITHOUT_RUNTIME`:

- точный default model selected для конкретного аккаунта/устройства;
- фактические URLs, размеры и hashes всех post-launch downloads;
- точный local search index backend и schema;
- полный telemetry payload и opt-out UX;
- динамическая эффективность sandbox/PII fail-closed branches;
- uninstall очистка пользовательских моделей, containers, SQLite и `~/.pplx`.

## Карта отчётов

| Отчёт | Назначение |
|---|---|
| `OFFICIAL_SOURCES.md` | первичные официальные источники, даты и public mirror checks |
| `PACKAGE_PROVENANCE.md` | signature/hash provenance chain и package identity |
| `INSTALLATION_BEHAVIOR.md` | maintainer scripts, system mutations, runtime bootstrap и rollback |
| `ARCHITECTURE_RECONSTRUCTION.md` | реконструкция process/data/security architecture |
| `OPEN_SOURCE_STATUS.md` | component-level license/source classification |
| `ELIOT_MECHANISM_GAP_MATRIX.md` | полезные механизмы и расхождения с ELIOT |
| `UNKNOWNS_AND_NEXT_PROBES.md` | остающиеся unknowns и безопасные следующие probes |
| `artifact-map.json` | machine-readable карта evidence и deliverables |
| `scripts/` | download, extraction, inventory и printable-string helpers |

## Evidence policy

Используются четыре класса:

- `CONFIRMED_STATIC` — непосредственно наблюдалось в подписанном metadata, архиве, text/source-visible artifact или binary strings/symbols;
- `CONFIRMED_OFFICIAL_CLAIM` — заявлено первичным источником Perplexity/NVIDIA, но не всегда доказано package bytes;
- `STRONG_INFERENCE` — наиболее простая архитектурная интерпретация нескольких независимых static anchors;
- `UNKNOWN` — static audit не позволяет честно определить behavior.

Наличие string, symbol или source path доказывает присутствие кода/ветки, но не доказывает, что ветка активна в production. Отсутствие public search result не доказывает, что private source не существует.

## Safety record

Не выполнялись:

- `apt install`, `dpkg -i`, package manager installation;
- `postinst`, `postrm` или любые файлы из rootfs;
- Electron binary, Rust sidecar, `pplx-search`, `uv`, `libaic.so`;
- containers, model engines, model downloads или model inference;
- system service registration;
- commit или push.

Архивы распакованы `7-Zip 26.02`. Перед extraction были просмотрены `7z l -slt` listings и проверены пути, links и special-file modes. Windows extraction не сохраняет всю Unix ownership/mode/link семантику, поэтому raw listings являются authority для этих свойств.

## Code understanding proof

- RepoRoot подтверждён как `C:\Development\Rust\projects\eliot-memory-os`, branch `main`, исходный HEAD `8af3984b9a3059fe1b8950337f432065cc7a85f4`.
- Существующие пользовательские изменения в product code не изменялись и не откатывались.
- Codebase-memory index оказался stale/wrong-scope для nested checkout, поэтому использованы current Git identity, canonical Architecture/Implementation и exact source/evidence handles.
- Нормативная база сравнения: внешняя canonical pair в `C:\Development\Rust\docs\ELIOT Arhitecture`; audit reports не меняют Architecture или Implementation authority.

## Completion proof

- официальный package metadata и обе архитектуры прочитаны;
- arm64 package скачан и hash/size совпали с signed `Packages`;
- package распакован 7-Zip без выполнения кода;
- 2,080 rootfs files проинвентаризированы и захешированы;
- ELF/ASAR/static strings исследованы;
- public source/model/mirror status проверен по состоянию на 2026-08-26;
- все предусмотренные отчёты и воспроизводимые скрипты созданы;
- raw data находится в Downloads вне Git;
- ограниченный process/service probe: `0` процессов и `0` Windows services с executable path из raw-каталога.
