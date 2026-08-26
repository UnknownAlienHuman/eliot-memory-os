# Official sources and public discovery

Дата проверки: 2026-08-26.

## 1. Официальный APT repository

| Surface | URL | Наблюдение |
|---|---|---|
| Repository key | `https://packages.perplexity.ai/perplexity.gpg` | RSA4096, fingerprint `5CE6FE16BD533152E64EFD93C751F9CAC952A583` |
| InRelease | `https://packages.perplexity.ai/deb/dists/stable/InRelease` | clearsigned, signature time 2026-08-25 13:53:44 UTC |
| Release | `https://packages.perplexity.ai/deb/dists/stable/Release` | `stable/main`, `amd64 arm64`, Acquire-By-Hash |
| Release.gpg | `https://packages.perplexity.ai/deb/dists/stable/Release.gpg` | detached signature, same signer |
| arm64 Packages.gz | `https://packages.perplexity.ai/deb/dists/stable/main/binary-arm64/Packages.gz` | signed Release hash/size matched |
| amd64 Packages.gz | `https://packages.perplexity.ai/deb/dists/stable/main/binary-amd64/Packages.gz` | signed Release hash/size matched |
| arm64 package | `https://packages.perplexity.ai/deb/pool/main/p/perplexity/perplexity_26.8.4%2Bbuild50522_arm64.deb` | 161,635,712 bytes, package stanza hash matched |

`Release` не содержит `Valid-Until` и не перечисляет `main/source/Sources*`. Стандартные source-index paths не следует считать signed repository content, если они не перечислены в `Release`.

Ограничение identity: repository key скачан с того же официального HTTPS origin. `gpgv` доказал внутреннюю криптографическую цепочку, но независимый Perplexity/NVIDIA fingerprint pin не найден. Статус: `SIGNATURE_VALID_WITH_UNPINNED_KEY`.

## 2. Официальный product announcement

[Perplexity: Introducing Portable Computer for local-first AI](https://www.perplexity.ai/ml/hub/blog/introducing-portable-computer-for-local-first-ai), опубликован 2026-08-25.

Источник заявляет:

- первый релиз — Linux на NVIDIA DGX Spark; Windows и RTX support — позже;
- Qwen 3.8 27B и PPLX 27B; Nemotron 3.5 Lightning — future picker option;
- orchestrator, planner, tool router, scheduler, durable task queue и local search index работают on-device;
- cloud escalation, browser, apps и frontier models требуют user authorization;
- connectors: Google Drive, Gmail, Slack и GitHub;
- code/tool execution выполняется в isolated sandbox;
- GB10: 20-core Arm CPU и 128 GB unified memory.

Класс: `CONFIRMED_OFFICIAL_CLAIM`. Часть заявлений получила независимые static anchors в package, часть остаётся runtime-only.

## 3. Официальная техническая статья

[Perplexity: A Local-First Agent for Private and Cost-Effective Knowledge Work](https://www.perplexity.ai/ml/hub/blog/a-local-first-agent-for-private-and-cost-effective-knowledge-work), опубликована 2026-08-25.

Ключевые design claims:

- model, harness, conversation и trajectory локальны by default;
- skills загружаются on demand, context compaction сокращает stale context;
- common MCP connectors превращены в compact CLI tools;
- sandbox ограничивает processes, filesystem paths и network;
- если sandbox unavailable, harness отключается до tool call вместо unsandboxed fallback;
- orchestrator — deterministic code, не LLM;
- local model предлагает действия, orchestrator сохраняет tool authority;
- advisor получает только approved context, возвращает text guidance и не имеет прямого доступа к files/tools/conversations;
- PII classifier показывает пользователю outbound context до escalation;
- PPLX 27B — post-trained Qwen 3.8 27B;
- Docker используется в synthetic training environments; это не утверждение, что user runtime всегда containerized;
- technical report по training и открытый benchmark обещаны позже.

Особенно важно: официальный текст подтверждает intended fail-closed semantics, а package strings подтверждают Bubblewrap probe/errors. Runtime audit всё ещё нужен, чтобы доказать фактическое поведение установленной версии.

## 4. NVIDIA confirmation

[NVIDIA Local AI blog: Perplexity Launches Portable Computer Agent Optimized for NVIDIA DGX Spark](https://blogs.nvidia.com/blog/local-ai-open-source-models-agents-nemotron/), entry от 2026-08-25.

NVIDIA подтверждает:

- DGX Spark/GB10 как первичную платформу;
- specially post-trained Qwen 3.8 27B;
- local/cloud model switching;
- long-running always-on workflows;
- future RTX, Windows и DGX Station support.

Hardware baseline подтверждается [DGX Spark User Guide](https://docs.nvidia.com/dgx/dgx-spark/hardware.html): 20-core Arm processor, 128 GB unified memory.

## 5. Model repositories and licenses

### Qwen base

[Qwen/Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B): public model repository, `License: apache-2.0`, model weights/configuration present. Классификация: `OPEN_MODEL_CONFIRMED` для base model, но не автоматически для Perplexity post-training или optimized checkpoint.

### Perplexity optimized checkpoint

[perplexity-ai/pplx-qwen-3-8-27b-dflash2-20260819](https://huggingface.co/perplexity-ai/pplx-qwen-3-8-27b-dflash2-20260819): public model card/repository surface; `License: other`; README описывает auth/private-repo download flow и patched vLLM Dockerfiles. Обычный core `LICENSE` не подтверждён.

Классификация: `WEIGHTS_OR_REPO_SURFACE_AVAILABLE_LICENSE_UNKNOWN_OR_RESTRICTED`, не OSI-open по имеющимся данным.

Package binary catalog содержит более свежий identifier `perplexity-ai/pplx-computer-qwen-3-8-27b-dflash2-20260824`. Его public availability и license отдельно не подтверждены.

### NVIDIA future model

[NVIDIA Nemotron 3.5 Lightning](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16): OpenMDW-1.1/open weights. Это future Portable Computer option по announcement, не содержимое текущего `.deb`.

## 6. Official GitHub and exact-anchor mirror search

Организация [github.com/perplexityai](https://github.com/perplexityai) содержит публичные соседние проекты (`pplx-garden`, `pplx-kernels`, `pplx-rs`, `numbat`, `electron-sdk`), но они не являются source tree обнаруженного local harness.

2026-08-26 GitHub code search, public scope, вернул `[]` для:

- `"perplexity-rpc-server"`;
- `"pplx/rust/libs/localharness"`;
- SHA-256 `1182958abb025d4eb4e01ca0dd29f8143a2ec609e3d417b0c51add1364992ad7`;
- `"perplexity_26.8.4+build50522_arm64.deb"`.

Статус: `NO_PUBLIC_EXACT_MIRROR_FOUND`. Это не доказательство отсутствия private/internal source или неиндексируемого mirror.

## 7. Source discovery conclusion

- signed APT Release не публикует source index;
- package stanza имеет `License: unknown` и не имеет `Source`, `Vcs-Git` или source offer;
- core Rust build paths указывают на internal Bazel workspace, а не на public repository URL;
- public exact-anchor search результатов не дал;
- bundled JavaScript, templates и skills source-visible, но не имеют обнаруженной отдельной core license grant.

Итог: `NO_PUBLIC_CORE_SOURCE_FOUND`, component-level classification приведена в `OPEN_SOURCE_STATUS.md`.

