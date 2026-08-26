# Architecture reconstruction

Scope: static reconstruction of package `perplexity 26.8.4`, build `50522`, Arm64. No package code was executed.

## Confidence legend

- `CONFIRMED_STATIC`: exact file, code-visible JavaScript, symbol, SQL or string anchor;
- `CONFIRMED_OFFICIAL_CLAIM`: primary Perplexity/NVIDIA statement;
- `STRONG_INFERENCE`: multiple static anchors imply the relation;
- `UNKNOWN`: not resolvable without source/runtime evidence.

## High-level topology

```text
Electron/Chromium desktop process
  ├─ renderer windows (sandboxed, nodeIntegration=false)
  ├─ preload boundary and explicit IPC/RPC allowlist
  ├─ Sentry/Datadog observability
  └─ private socket/pipe, JSON-RPC 2.0
       ↓ supervises
Rust perplexity-rpc-server
  ├─ deterministic local harness/orchestrator
  ├─ session/history/trajectory/event persistence
  ├─ SQLite automation scheduler and recovery
  ├─ skills, tool policy and bounded subagents
  ├─ PII consent and advisor/cloud gates
  ├─ Bubblewrap/seccomp/cgroup sandbox
  ├─ local model/engine controller
  │    ├─ llama.cpp
  │    └─ vLLM in supervised Docker container
  └─ per-thread broker socket
       └─ pplx-search (no direct network/key in sandbox)

External, optional/user-gated boundaries
  ├─ Perplexity Search / research
  ├─ advisor/frontier model
  ├─ connected apps
  ├─ Hugging Face/model payloads
  └─ engine/container payloads
```

The `.deb` contains the first two control-plane layers and helpers, but not model weights or container layers.

## 1. Electron shell and renderer boundary

`CONFIRMED_STATIC`:

- ASAR manifest: app name `perplexity`, version `26.8.4`, build number `50522`;
- BrowserWindow uses `nodeIntegration: false`, `sandbox: true`;
- Electron calls `app.enableSandbox()`;
- packaged production build disables dev endpoint/resource overrides;
- `no-sandbox` is only added when running as root, or in non-packaged CI; normal non-root packaged launch retains Chromium sandbox;
- renderer can invoke only commands listed in `XPLAT_NATIVE_RPC_COMMANDS`.

The attachment acquisition path is deliberately excluded from the generic renderer RPC allowlist because it accepts absolute paths. Only preload may mint those paths from user-selected `File` objects. A comment names arbitrary file read as the avoided failure mode.

Interpretation: Electron main is a security mediator, not merely a thin window wrapper.

## 2. RPC sidecar lifecycle

`CONFIRMED_STATIC` from extracted ASAR:

- protocol: JSON-RPC `2.0` with `Content-Length` framing;
- maximum frame: 128 MiB;
- request timeout: 120 seconds;
- one private Unix socket or Windows named pipe per launch;
- Unix socket mode set to `0600`;
- packaged `perplexity-rpc-server` spawned with `--rpc-socket <path>`;
- at most five consecutive relaunch failures, exponential delay capped at five seconds;
- after limit, pending requests are rejected with `perplexity-rpc-server is not running`.

This is process supervision, but no generation/epoch fencing or durable restart receipt was observed at the Electron layer.

## 3. Rust sidecar composition

ELF strings expose non-stripped Rust build paths and symbols for:

- `localharness/orchestrator`, including compaction;
- `localharness/sandbox` and `sandbox-os/src/bwrap.rs`;
- `localharness/pii-gate`;
- `localharness/skills` and tools;
- local-mode service, automations, history, trajectory export, web search, advisor and connectors;
- local-engine Docker/vLLM, llama.cpp and PII serving;
- local-model and preference-store modules;
- local-subagent execution.

These paths strongly map the internal module graph but do not provide source license or prove every module is active.

## 4. Harness, context and delegation

`CONFIRMED_STATIC` bundled template:

- built-in agent prompts and role allowlists are embedded in Rust;
- skills are described by YAML/Markdown and loaded explicitly with `load_skill`;
- no keyword router or extra LLM router selects skills;
- `pulls_tools` exposes optional tools only after a skill is loaded;
- orchestrator core tools: `shell`, `read`, `apply_patch`, `load_skill`, `advisor`; delegation is optional/skill-driven;
- subagent tools omit `advisor` and `spawn_agent`;
- default `max_depth = 1` gives runtime-enforced leaf agents;
- root aggregates structured sources/model usage; child output does not directly append root sections.

`CONFIRMED_OFFICIAL_CLAIM`: deterministic harness code controls the loop; model proposes actions. The official research article also describes context compaction and health hooks that request self-verification.

Interpretation: the product reduces local-model context pressure through a small core tool surface, on-demand skill bodies, compact connector CLIs and shallow delegation.

## 5. Tool sandbox

`CONFIRMED_STATIC` anchors in `perplexity-rpc-server`:

- Bubblewrap probe and negotiated argv;
- `trusted bwrap could not be probed` availability error;
- seccomp and cgroup modules;
- `NetworkPolicy`, direct-network signature and dynamic grants;
- read-only workspace enforcement;
- rejection of writable-root symlinks, home ancestors and sensitive paths;
- errors for user files outside the allowed workspace.

`CONFIRMED_OFFICIAL_CLAIM`: harness disables itself before tool calls when sandbox is unavailable, instead of falling back to unsandboxed execution.

Static package evidence supports intended fail-closed design, but the complete runtime state transition was not executed. Therefore actual `fail_closed` behavior for this exact installed artifact is `CURRENT_UNVERIFIED`.

Two distinct sandboxes must not be conflated:

1. Chromium renderer sandbox/AppArmor userns enabling;
2. Rust harness tool sandbox using Bubblewrap/seccomp/cgroup/network policy.

## 6. Durable state and automations

`CONFIRMED_STATIC`:

- local SQLite initialization and absolute base-directory validation;
- event table queries keyed by session/run with monotonically selected sequence;
- serialization/deserialization of LLM trajectories;
- `persist_interrupted_trajectory` and errors for interrupted exchange persistence;
- `workspaces`, `broker.sock` and durable preference mutation guards;
- automations and `automation_runs` tables;
- due/run indexes, unique `(automation_id, scheduled_for)` constraint;
- claim states `claimed`, `running`, `succeeded`, `failed`;
- recovery query for abandoned `claimed/running` work;
- bundled policy says missed occurrences coalesce and each occurrence appends to its source thread.

This is substantive durable scheduler/recovery logic, not only a UI label.

Unknown: full transaction isolation, crash consistency, schema migrations, retention, backup, multi-process writer ownership and receipt semantics.

## 7. Local inference engines and models

`CONFIRMED_STATIC` providers:

- llama.cpp discovery/catalog;
- vLLM Docker catalog/provider;
- Docker readiness/inspect/load/run paths;
- supervised container labels and stale-container removal;
- loopback heartbeat path;
- chat and PII model/name environment separation;
- pinned vLLM image digest and Perplexity image/model identifiers.

Notable catalog evidence includes:

- `vllm/vllm-openai@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf5`;
- `perplexity-ai/pplx-computer-vllm-dflash`;
- `perplexity-ai/pplx-computer-qwen-3-8-27b-dflash2-20260824`;
- Qwen 3.6 and Qwen 3.8 variants;
- future Nemotron 3.5 Lightning catalog entry;
- `HF_TOKEN` requirement in private llama.cpp binary branch.

No corresponding weights/layers are in the package. `STRONG_INFERENCE`: app downloads or imports these after explicit local-engine/model provisioning.

## 8. Search architecture

Bundled `pplx-search` is a small Rust binary compared with the RPC sidecar.

`CONFIRMED_STATIC`:

- connects to a broker Unix socket;
- serializes localharness broker requests/results;
- template states the sandboxed helper has no key and no direct network;
- app performs authenticated Perplexity search through the signed-in user session;
- no page-fetch tool in local mode.

The template explicitly calls an air-gapped local index backend a future option. This conflicts with the broader launch phrase “local search index” unless “index” refers to another internal file/document subsystem. Exact local-index implementation/schema remains `UNKNOWN`, not absent.

## 9. Connectors

Package contains built-in overlay instructions for Gmail+Calendar and Outlook; runtime generates connector skills from connected services. Official launch additionally names Google Drive, Gmail, Slack and GitHub.

Architecture:

- connector schemas are compacted into CLI-like tool surfaces rather than exposing full MCP catalogs;
- connector availability is filtered by consent, binaries and runtime capability;
- outbound calls cross Electron/Rust/app broker boundaries;
- actual service auth remains app-owned.

Static package alone cannot enumerate account-specific connector catalog, OAuth scopes or data retention.

## 10. PII gate and advisor escalation

`CONFIRMED_STATIC` RPC/types/settings:

- `pii_check_will_run`, consent resolution/cancellation, PII grants;
- decisions include local processing, cancel, allowed, unscreened and kept;
- PII types include person/email/phone/address/private URL/account number/secret;
- separate settings for advisor, external calls, connectors and PII masking;
- unanswered consent cards are refused/cancelled;
- advisor backend does not accept attachments in at least one branch.

`CONFIRMED_OFFICIAL_CLAIM`:

- orchestrator selects relevant advisor context;
- PII classifier flags sensitive material and user sees what leaves device;
- advisor receives only approved context;
- advisor returns text guidance and has no direct file/tool/conversation access;
- local orchestrator retains action authority.

This is a strong “remote cognition, local authority” boundary. Default policy and all UI branches remain runtime-unverified.

## 11. Privileged host setup

Electron code says only a containerized DGX Spark engine currently has fixable privileged preconditions. Renderer triggers setup, but Rust returns the command plan. Electron only permits `pkexec` or `sudo` as runners.

Security value: a compromised renderer cannot directly supply an arbitrary root command. Unknown: exact command plan, package dependencies and rollback on partial failure.

## 12. Telemetry

`CONFIRMED_STATIC`:

- hard-coded Sentry DSN/minidump endpoint;
- Datadog Electron SDK client identifiers;
- packaged builds default-enable Sentry and Datadog initialization;
- Datadog has an environment override; the observed `shouldEnableSentry` logic does not expose an equivalent packaged-build disable branch;
- Rust sidecar stderr telemetry, installation ID seed and lifecycle analytics are forwarded to observability objects.

This does not prove every event is sent, nor reveal exact payload after filters. Nevertheless “entire stack local” must be interpreted as model/harness/data-path intent, not as proof of zero background network telemetry.

## 13. Updates

`CONFIRMED_STATIC`:

- RPC methods `app_update_snapshot`, `app_update_check`, `app_update_install` exist;
- Linux Electron handling broadcasts current snapshot and returns `null` for check/install;
- code reads `apt-cache policy perplexity` to classify official stable package origin;
- official APT repository is operational.

`STRONG_INFERENCE`: Linux application updates are expected to be external/APT-managed. Direct updater→APT invocation was not found, so exact update transport is `UNKNOWN`.

## 14. Binary inventory

| Artifact | Bytes | SHA-256 | Role |
|---|---:|---|---|
| `opt/Perplexity/perplexity` | 203,754,784 | `2d79aad389ca71798b2ea5ba9a6eaabeacdf024e866c66a2df6c436bf34cb5e4` | Electron/Chromium executable |
| `resources/native/bin/perplexity-rpc-server` | 169,370,488 | `1182958abb025d4eb4e01ca0dd29f8143a2ec609e3d417b0c51add1364992ad7` | Rust control plane/harness |
| `resources/native/bin/uv` | 47,411,656 | `07bf07c670d88b099773a43dd0b11ffc42c780d56d7c95fef3087efaf98f8c32` | Python environment bootstrap |
| `resources/app.asar` | 10,692,643 | `0bf618d999b45c4582a18dbbabe4cce678bd7e8d29ae8d68df96148e70758ef1` | Electron main/preload JS |
| `resources/native/lib/Perplexity/libaic.so` | 3,937,216 | `a6183a36efb6d0c9fd51ec6279ccd58135d00968d32e18af2594ef63c13410e2` | multimodal/native library |
| `resources/native/bin/pplx-search` | 1,536,656 | `82ec7803ccb99b3a6c28ac092f176fe1751744521e797875f74018f0dac5ab10` | broker search helper |

All primary native binaries are AArch64 ELF. `perplexity-rpc-server`, `pplx-search` and `uv` expose Rust provenance; the Electron binary is stripped Chromium/Electron.

## Overall architecture finding

Portable Computer is a hybrid local-first agent platform with a clear local authority center:

- Electron mediates UI and native boundaries;
- a Rust sidecar owns orchestration, state, sandbox, model lifecycle and external-call gates;
- local models propose, deterministic code executes;
- networked capabilities are separated into consented broker/advisor/connector paths;
- runtime payloads are provisioned separately from the signed desktop package.

The strongest engineering properties are the narrow renderer RPC surface, fail-closed sandbox intent, shallow capability-limited subagents, durable automation claims and advisor-without-tools pattern. The largest audit gaps are licensing/source availability, runtime payload provenance, telemetry policy, local-index implementation, update mechanism and cleanup semantics.

