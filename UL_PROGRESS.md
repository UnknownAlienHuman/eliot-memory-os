# Historical Understanding Layer v1.4 progress

> Historical campaign evidence only, bound to the source identities recorded
> below. It is not the current ELIOT product status and does not transfer PASS or
> CERTIFIED to current bytes. Current status requires exact source/build/runtime
> evidence under the Architecture 4.5 / Implementation 0.29 authority model.

Historical campaign status: **IMPLEMENTATION COMPLETE — UL-11 AND UL-12 CERTIFIED**

Start SHA: `f26985de335f0c6d1970eb3bc8663fce09d9f2cf`

| Phase | Result | Evidence |
|---|---|---|
| UL-11R0 | PASS | `c1d8575` preserves the accepted provider repairs and removes failed experimental routes. |
| UL-11R1 | PASS | `1bf6829` completes the Part-E surface, four canonical skills, and native host packages. |
| UL-11R2 | PASS | `af9e7b3` repairs Unicode multi-kind recall and L2 expansion. |
| UL-11R3 | PASS | `bab9e82` repairs authenticated provider MCP adoption; the default Antigravity agent consumes the official skills/MCP package without a required custom agent. |
| UL-11 | PASS | Blind reciprocal run `ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486`: 8/8 provider calls, both directions PASS, zero unknown outcomes. |
| UL-12 | PASS | Focused suites, workspace format/check/clippy, `just verify`, and `cargo test --workspace` are green. |

## UL-11 canonical evidence

- Claude and Antigravity each made their own candidate-only write.
- Fresh reciprocal readers recovered the exact marker and canonical handle.
- A2 and B2 each produced a provider-session-owned influence trace bound to the
  exact handle and a deterministic `retrieval:*` context.
- Both memory-free controls had no treatment memory.
- Contamination and cross-scope leakage checks passed.
- Truth revision changed only for the two semantic candidate writes.
- No score, authority, blindness, marker-generation, or anti-falsification rule
  was weakened.
- No provider credential was read, copied, embedded, or migrated.

## UL-12 release verification

All required focused suites passed:

- `ul_e_surface`: 3 tests.
- `ul_cross_agent_contract`: 8 tests.
- `plugin_hooks`: 19 tests.
- `multi_agent_access`: 4 passed, 4 ignored by contract.
- `memory_retrieval`: 5 tests.
- `host_integration`: 12 tests.
- `antigravity_contract`: 58 tests.
- `ul_mvp_done`: 12 tests.

Final gates:

- `cargo fmt --all -- --check`: PASS.
- `cargo check --workspace --all-targets`: PASS.
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS.
- `just verify`: PASS in 367.242 seconds.
- `cargo test --workspace`: PASS, 131 result groups and zero failed groups, in
  293.013 seconds.
- `git diff --check`: PASS.

## Performance follow-up

On an AMD Ryzen 9 9950X with fast RAM, pure unit/contract bodies remain fast.
The principal local cost is process-level isolation: `ul_mvp_done` runs twelve
separate SurrealDB/Governor fixtures and takes about 77–80 seconds. Two
incremental optimized builds each took about 122 seconds. Those harness startup
and release link costs merit a separate profile; they do not block UL v1.4.

## Final declaration

```text
UL v1.4 IMPLEMENTATION COMPLETE
NATIVE CODEX/CLAUDE/ANTIGRAVITY ELIOT PACKAGES COMPLETE
CLAUDE <-> ANTIGRAVITY BLIND MEMORY TRANSFER CERTIFIED
```
