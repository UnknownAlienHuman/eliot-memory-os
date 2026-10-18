# Eliot Memory OS

> **V3: documentation and architecture design.** V1 and V2 are archived donors. V3 will be written from scratch after the documentation is refined. No V3 runtime is implemented by this documentation revision.

Eliot is a memory, understanding, and learning system for people and AI agents. It should preserve experience, build useful context before the next decision, understand project relationships, learn procedures from outcomes, and revise its own mistaken memory.

## Start with V3

| Read | Purpose |
|---|---|
| [V3 documentation](docs/v3/README.md) | Current stage, reading order, decisions, and open questions |
| [Architecture](docs/v3/ARCHITECTURE.md) | Preserved requirements and proposed compact product boundaries |
| [Implementation](docs/v3/IMPLEMENTATION.md) | Concrete proposed memory, context, Dreamer, learning, and recovery paths |
| [Consolidated audit](docs/v3/AUDIT.md) | Russian audit of requirements, V2, Claude's proposals, Hy-Memory, donors, and design tradeoffs |

The owner selected a fresh V3 design. Revision 0.1 is a reviewable draft, not acceptance of every proposed mechanism. The current task is [documentation issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324). Source presence, a specification, and a green build do not establish a working capability.

## Version boundary

The existing Rust workspace, old architecture shards, scripts, and workstream records describe **V2**. They remain available for selective reuse and investigation; their checklists do not authorize continuing V2 implementation or importing its physical architecture into V3.

- [V2 source snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105).
- [V2 unfinished audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).
- [V1 donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7).

This is a documentation-stage donor freeze. The repository stays available, old source bytes remain in place, and old issues are not declared completed. Data import, runtime replacement, and removal of old code are later, separately scoped work.

The V2 `ACTIVE.toml` registry and its validators remain unchanged and still encode the old programmes as active. This revision does not claim a machine-enforced registry transition; the owner's documentation scope governs agent work.

[Architecture authority](docs/ARCHITECTURE_CONTRACT.md) records this precedence. English Architecture/Implementation hold the V3 proposal; the Russian audit explains evidence and alternatives without making every idea a mandatory component.

## Repository work

Follow [AGENTS.md](AGENTS.md), [START.md](START.md), and [WORKFLOW.md](WORKFLOW.md). Work from current `main`, preserve unrelated changes, use one writer per scope, and obtain independent review before integration. A documentation edit calls for documentation checks; runtime proof must match actual runtime work and the owner's selected development order.

The [documentation map](docs/README.md) distinguishes V3 from V2 donor references. [PROJECT_MAP](docs/PROJECT_MAP.md), [scripts](scripts/README.md), [workstream records](workstreams/ACTIVE.toml), and the pinned Rust toolchain describe the retained V2 tree, not V3 deployment requirements.

## Related boundaries

| Repository | Proposed relationship to V3 |
|---|---|
| [eliot-swarm-controller](https://github.com/UnknownAlienHuman/eliot-swarm-controller) | External model/embedding routing and task/harness execution; the Memory ModelJob integration still needs a real contract |
| [eliot-search](https://github.com/UnknownAlienHuman/eliot-search) | Candidate external source preparation/retrieval adapter where a concrete path needs it |
| [eliot-research](https://github.com/UnknownAlienHuman/eliot-research) | Candidate external research/acquisition adapter where a concrete path needs it |

Eliot owns durable memory, context, provenance, and outcome-linked learning. External hosts own their goals, actions, and task execution. A provider result does not grant memory authority or demonstrate task completion.

## V2 donor reading tools

The generated block below routes the retained V2 documentation. Use it when inspecting or changing donor surfaces; it does not certify V3 or replace the four V3 documents above.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](docs/architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## License

Eliot is licensed under the MIT License — see [LICENSE](LICENSE). Third-party code and runtimes retain their own licenses; verify the exact revision before reuse. The existing [dependency policy](docs/DEPENDENCY_POLICY.md) remains a V2 reference until a V3 dependency decision explicitly adopts or revises it.
