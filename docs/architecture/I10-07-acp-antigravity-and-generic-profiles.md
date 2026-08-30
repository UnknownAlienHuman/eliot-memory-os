## I10.7. ACP, Antigravity and generic profiles

### ACP compatibility profile

**Priority:** COMPATIBILITY-1 route. Baseline protocol/session operations are admitted only after provider-free contract tests.

Version rule:

```text
ACP v1 stable line
  production compatibility baseline;
  session load/resume/close and every extension follow negotiated capability markers
  plus an exact adapter/runtime probe;

ACP v2 draft line
  experimental adapter profile only;
  never becomes the default merely because an agent advertises a v2 draft version;
  each operation is feature-gated, version-pinned and rollbackable;
  production promotion requires the specification and SDK line to be declared stable
  and the same ELIOT conformance suite to pass.
```

Every operation that affects continuity, workspace roots, model/mode, MCP, files or reasoning events is challenged by a direct probe on the exact adapter/runtime fingerprint; advertisement alone is not production evidence. ACP agent task/session state remains external runtime state. ELIOT preserves its own attempt, task and evidence lifecycle independently.

### Antigravity local profile

**Priority:** P1 after live probes. Use only documented local SDK/CLI/MCP surfaces through a supervised sidecar or structured process adapter. Do not assume a general remote managed-session API until an official resource/session/event contract is verified.

```text
SDK preferred over PTY/CLI when it exposes structured lifecycle;
PTY/TUI scraping is degraded fallback only;
hooks are observation/defence-in-depth, not root enforcement;
native subagents default-disabled for write/MCP work until inheritance,
cancellation, usage and output contracts pass exact-version probes.
```

### Generic minimum

```text
structured MCP/ACP/HTTP/sidecar/CLI transport;
authenticated attach and exact runtime identity;
working root/scope and route fingerprint;
tool/action observation or explicit observe calls;
cancellation and reconciliation;
finish/checkpoint call;
visible limitations and capability evidence.
```

Tool-only integration supports basic value but cannot claim full enforcement.


