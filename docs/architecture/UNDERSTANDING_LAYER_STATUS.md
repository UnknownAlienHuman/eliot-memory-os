# Understanding Layer status

Version: **ELIOT Understanding Layer v1.4**  
Status: **certified**

## Certified scope

| Capability | Status | Acceptance evidence |
|---|---|---|
| Cue binding, indexing, and firing | PASS | UL E-surface and MVP integration suites |
| Dependency dirty maintenance | PASS | canonical maintenance and workspace verification |
| Deterministic activation | PASS | control/treatment and activation contracts |
| Part-E surface | PASS | exact seven-tool surface on admitted worker profiles |
| Canonical skills | PASS | byte-identical `eliot-work`, `eliot-remember`, `eliot-recover`, and `eliot-finish` packages |
| Native host packages | PASS | Codex plugin, Claude Code plugin, and Antigravity official skills/MCP package |
| Unicode multi-kind Librarian | PASS | Unicode recall and L2 expansion regressions |
| Token policy and memory-free control | PASS | bounded packet and clean-control contracts |
| Metacognition and invariant gate | PASS | UL pyramid, invariant, and finish checks |
| Prediction, calibration, exam, refinement | PASS | UL behavior and cognition suites |
| Reciprocal memory transfer | PASS | sanitized eight-call run `ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486` |
| Writer/revision/anti-falsification boundary | PASS | provider-owned candidate/influence receipts and unchanged observability revision |

## Reciprocal certification

The certified run made exactly eight logical provider calls:

```text
A0 Antigravity control
A1 Claude writer
A2 fresh Antigravity treatment
A3 Antigravity memory-free control
B0 Claude control
B1 Antigravity writer
B2 fresh Claude treatment
B3 Claude memory-free control
```

Both directions passed every canonical check. A2 and B2 each had:

- an exact project/task/session injection receipt;
- the canonical candidate handle;
- exact applicability and first action;
- a model-owned `seen_but_not_used` influence trace;
- a same-session `retrieval:*` context derived from exact `fetch_l2`;
- a committed observability receipt that did not change truth revision.

The controller did not submit candidates, retrieve on behalf of readers, or
write positive influence. Private markers remained outside reader inputs and
the sanitized report.

## Host-package clarification

Codex has a native ELIOT plugin with one MCP server, four canonical skills, and
bounded lifecycle hooks. The obsolete statement that Codex has no native ELIOT
plugin is false.

Antigravity uses its default agent with the official ELIOT skills and governed
MCP registration. A custom `eliot-agent` and `--agent eliot-agent` are not
readiness requirements and do not grant authority.

## Non-blocking performance debt

The full test graph is correct but expensive for a fast local workstation.
Daemon-backed test binaries repeatedly start isolated SurrealDB/Governor
fixtures; the slowest required suite was about 77–80 seconds. Optimized linking
also took about 122 seconds in two consecutive incremental builds. A separate
profiling task should investigate fixture reuse and linker/codegen costs without
weakening isolation or acceptance coverage.
