<!-- generated: eliot-doc-routes-v1 -->
# Task and path documentation routes

This is a human-readable projection of [`route-rules.toml`](route-rules.toml).
The executable source is the TOML file plus [`scripts/docs_router.py`](../../scripts/docs_router.py).

Run:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Every result includes the global Decision Safety Floor and all matching specialized routes.
A path may intentionally match more than one route.

## Global required baseline

- Handles: `A0.1`, `A0.2`, `A0.3`, `A0.4`, `A0.6`, `I0.3`, `I0.4`, `I0.5`, `I0.13`, `I0.14`
- Files: `AGENTS.md`, `WORKFLOW.md`, `workstreams/ACTIVE.toml`, `docs/ARCHITECTURE_CONTRACT.md`, `docs/DEPENDENCY_POLICY.md`, `docs/architecture/READING_PROTOCOL.md`
- Default maximum required payload: `393216` bytes

## Route matrix

| Route | Purpose | Path patterns | Topic keywords | Required selectors | Optional selectors |
|---|---|---|---|---|---|
| `generic-source` | Common causal-cell, ownership, edge-proof, and completion rules for any source mutation. | `bins/**`<br>`crates/**`<br>`apps/**`<br>`integrations/**`<br>`plugin/**` | `source code`<br>`implementation`<br>`crate`<br>`module`<br>`binary`<br>`refactor` | `A2.3`<br>`A10.4`<br>`A14.8`<br>`I2.17`<br>`I2.20`<br>`I18` | `I2.*`<br>`I17` |
| `host-kernel` | Host, Kernel, authority epoch, fencing, ORS, supervision, startup, and recovery ownership. | `bins/eliot-host/**`<br>`bins/eliot-kernel/**`<br>`crates/kernel/**` | `host`<br>`kernel`<br>`authority epoch`<br>`fencing`<br>`ors`<br>`supervision`<br>`startup` | `A2.2`<br>`A2.3`<br>`A12.2`<br>`A13.2`<br>`I1.1..I1.8`<br>`I5.5`<br>`I14.14`<br>`I16.17` | `I1.9..I1.13`<br>`I5.6..I5.23`<br>`I14.*`<br>`I16.*`<br>`APPENDIX-A..APPENDIX-D`<br>`APPENDIX-P` |
| `watchdog` | Independent Watchdog observation, protected spool, liveness, and bounded recovery interaction. | `bins/eliot-watchdog/**` | `watchdog`<br>`liveness observation`<br>`protected spool` | `A8.1`<br>`A13.2`<br>`A13.8`<br>`I8.1`<br>`I8.2`<br>`I2.16`<br>`I2.23` | `A8.*`<br>`I8.*`<br>`I14.*`<br>`I16.*` |
| `canonical-storage` | Canonical store, BlobStore, one-write-path, transitions, backup, restore, and migration. | `bins/eliot-store-surreal/**`<br>`migrations/**`<br>`crates/**/*store*/**`<br>`crates/**/*blob*/**` | `surrealdb`<br>`canonical store`<br>`blobstore`<br>`transaction`<br>`migration`<br>`backup`<br>`restore` | `A4`<br>`A12.3`<br>`A13.6..A13.9`<br>`I5.1..I5.7`<br>`I5.19`<br>`I5.27` | `A4.*`<br>`I5.8..I5.18`<br>`I5.20..I5.26`<br>`I19`<br>`I20` |
| `module-runtime` | Replaceable process/WASM/native generations, capability boundaries, promotion, and rollback. | `bins/eliot-native-worker/**`<br>`bins/eliot-wasm-host/**`<br>`bins/eliot-mod-*/**`<br>`crates/modules/**` | `wasm`<br>`native worker`<br>`process generation`<br>`hot replacement`<br>`module promotion`<br>`module rollback` | `A2.3`<br>`A13.3`<br>`A14.8`<br>`I2.1..I2.5`<br>`I2.10`<br>`I6.4..I6.5`<br>`I7.1..I7.5`<br>`I14.14`<br>`I18` | `I2.*`<br>`I6.*`<br>`I14.*`<br>`I17`<br>`APPENDIX-P` |
| `agent-swarm` | Agent runtimes, provider routes, delegation, durable tasks, Concilium, swarm, and strict finish. | `bins/eliot-agent-bridge/**`<br>`crates/**/*agent*/**`<br>`integrations/**` | `agent`<br>`swarm`<br>`codex`<br>`claude`<br>`opencode`<br>`antigravity`<br>`provider route`<br>`concilium`<br>`delegation` | `A10.1`<br>`A10.2`<br>`A10.4..A10.8`<br>`I3`<br>`I7.1..I7.9`<br>`I10.15..I10.18`<br>`I13`<br>`I14`<br>`I18.16..I18.17` | `A10.*`<br>`I7.*`<br>`I10.*`<br>`I13.*`<br>`I14.*`<br>`I16.*`<br>`I18.*` |
| `instrument-verification` | Instrument Plane, test execution, evidence envelopes, code understanding, proof breadth, and completion evidence. | `bins/eliot-testd/**`<br>`scripts/audit-*.py`<br>`scripts/verify-*.py`<br>`tests/**`<br>`crates/**/*instrument*/**`<br>`crates/**/*verification*/**` | `instrument`<br>`verification`<br>`verifier`<br>`evidence envelope`<br>`proof`<br>`test harness`<br>`code cortex` | `A5.5`<br>`A10.8`<br>`A14.6..A14.8`<br>`I2.17`<br>`I2.20..I2.23`<br>`I10.8..I10.10`<br>`I16.17`<br>`I17`<br>`I18`<br>`APPENDIX-J`<br>`APPENDIX-P` | `I10.*`<br>`I17.*`<br>`I18.*` |
| `memory-context` | Memory, read reconstruction, Understanding State, graphs, Context Compiler, cues, and cognitive inheritance. | `crates/eliot-engine/src/context/**`<br>`crates/eliot-engine/src/read/**`<br>`crates/eliot-engine/src/project_understanding/**`<br>`crates/**/*memory*/**`<br>`crates/**/*context*/**` | `memory`<br>`context compiler`<br>`active view`<br>`understanding`<br>`causal graph`<br>`code graph`<br>`cognitive inheritance`<br>`cue` | `A4`<br>`A5`<br>`A6`<br>`A7`<br>`A14.1..A14.4`<br>`I12.9..I12.10`<br>`I13`<br>`I16` | `A4.*`<br>`A5.*`<br>`A6.*`<br>`A7.*`<br>`I9.*`<br>`I12.*`<br>`I13.*`<br>`I16.*` |
| `dreamer` | Dreamer orientation, reflection, hypotheses, sleep-like processing, and bounded cognitive improvement. | `bins/eliot-dreamer/**`<br>`crates/**/*dream*/**` | `dreamer`<br>`dreaming`<br>`reflection cycle`<br>`offline cognition` | `A9`<br>`I9` | `A9.*`<br>`I9.*`<br>`I12.*`<br>`I13.*`<br>`I16.*` |
| `human-surfaces` | CLI, operator UI, user broker, notifications, human control, and configuration surfaces. | `apps/**`<br>`crates/surfaces/**`<br>`bins/eliot-user-broker/**`<br>`bins/eliot-ui/**`<br>`bins/eliot-notify/**` | `operator ui`<br>`dashboard`<br>`cli`<br>`user broker`<br>`notification`<br>`human control` | `A11`<br>`I3`<br>`I7.3..I7.8`<br>`I11` | `A11.*`<br>`I3.*`<br>`I7.*`<br>`I11.*` |
| `security-privacy` | Authority, credentials, provenance, influence, privacy, secret residency, and external effects. | `config/**/*security*`<br>`config/**/*privacy*`<br>`crates/**/*auth*/**`<br>`crates/**/*secret*/**`<br>`crates/**/*policy*/**` | `security`<br>`privacy`<br>`secret`<br>`credential`<br>`provenance`<br>`authority`<br>`external effect`<br>`influence` | `A0.3`<br>`A12`<br>`I5.26`<br>`I6.15`<br>`I15` | `A12.*`<br>`I15.*` |
| `doctor-operations` | Doctor diagnostics, bounded repair, recovery recipes, operational status, and maintenance. | `bins/eliot-doctor/**`<br>`docs/operations/**` | `doctor`<br>`repair`<br>`recovery recipe`<br>`maintenance`<br>`operational status` | `A13.3..A13.12`<br>`I14`<br>`I15`<br>`I16` | `A8.*`<br>`A13.*`<br>`I14.*`<br>`I15.*`<br>`I16.*` |
| `release-migration` | Release gates, source identity, packaging, promotion, rollback, backup/restore, and cutover. | `docs/release/**`<br>`.github/workflows/**`<br>`scripts/verify*.ps1`<br>`scripts/**/*release*`<br>`scripts/**/*package*` | `release`<br>`migration`<br>`cutover`<br>`deployment`<br>`packaging`<br>`rollback` | `A13.3`<br>`A13.7..A13.8`<br>`A14.8`<br>`I0.8..I0.9`<br>`I18`<br>`I19`<br>`I20` | `I18.*`<br>`I19.*`<br>`I20.*`<br>`APPENDIX-G..APPENDIX-P` |
| `professional-workflow` | Professional or multimodal WorkScope onboarding, domain contracts, tools, and outcome verification. | `crates/**/*professional*/**`<br>`crates/**/*multimodal*/**` | `professional workflow`<br>`multimodal`<br>`media`<br>`workscope onboarding` | `A3`<br>`A7`<br>`A10.1`<br>`I4`<br>`I10.13`<br>`I10.20..I10.22`<br>`I12.35`<br>`I18.47` | `A3`<br>`A7.*`<br>`I4.*`<br>`I10.*`<br>`I12.*`<br>`I18.*` |
| `documentation-authority` | Normative pair, architecture/implementation semantics, indexes, routes, agent instructions, and documentation integrity. | `docs/**`<br>`AGENTS.md`<br>`**/AGENTS.md`<br>`WORKFLOW.md`<br>`.github/ISSUE_TEMPLATE/**`<br>`.github/pull_request_template.md` | `documentation`<br>`normative`<br>`architecture`<br>`implementation contract`<br>`index`<br>`navigation`<br>`route` | `A0.1..A0.6`<br>`A16.3`<br>`I0.14`<br>`I2.17`<br>`I18` | `A10.4`<br>`A14.8`<br>`I2.20..I2.23` |
| `workspace-governance` | Workspace build graph, repository policy, tests, scripts, active workstreams, and configuration changes. | `Cargo.toml`<br>`Cargo.lock`<br>`rust-toolchain.toml`<br>`deny.toml`<br>`.typos.toml`<br>`Justfile`<br>`tool-versions.json`<br>`mcpls.toml`<br>`.github/**`<br>`scripts/**`<br>`tests/**`<br>`config/**`<br>`workspace/**`<br>`workstreams/**` | `workspace`<br>`cargo`<br>`repository policy`<br>`workstream`<br>`build graph`<br>`configuration` | `A10.4`<br>`A14.8`<br>`I2.17`<br>`I2.20..I2.23`<br>`I17`<br>`I18` | `I2.*`<br>`I17.*`<br>`I18.*` |
| `repository-root` | Root-level repository identity, licensing, tool pins, and contributor entry surfaces. | `.gitattributes`<br>`.gitignore`<br>`LICENSE`<br>`README.md`<br>`WORKFLOW.md`<br>`.typos.toml`<br>`Cargo.toml`<br>`Cargo.lock`<br>`Justfile`<br>`deny.toml`<br>`mcpls.toml`<br>`rust-toolchain.toml`<br>`tool-versions.json` | `repository root`<br>`license`<br>`toolchain pin` | `A0.4`<br>`A14.8`<br>`I0.14`<br>`I2.17`<br>`I18` | `I20` |

## Enforcement

`python scripts/docs_router.py check --root .` validates selectors, files,
representative route examples, tracked-path coverage, route-size ceilings, and
this generated projection. Unknown material paths fail closed.
