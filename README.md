# Eliot Memory OS

> **The V3 documentation baseline is on `main`; it is not a released runtime.**
> [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325) is merged.
> Continue from current `main`, not the retired documentation branch.
> V1/V2 Memory source is retained as donor material.

Eliot preserves experience, reconstructs current work and supplies applicable
context for the next decision. It learns from observed outcomes and corrects
memory while retaining source history. Hosts/controllers own task execution,
permissions and acceptance; Memory is not another agent orchestrator.

## Work starts here

| Need | Read |
|---|---|
| Agent instructions | [AGENTS.md](AGENTS.md) |
| Find the relevant contract section | [V3 task map](docs/v3/README.md#task-routes) |
| Continue the documentation update | [Existing stages and findings](docs/v3/ANALYSIS-REGISTRY.md#documentation-stages) |
| Version and document ownership | [Architecture authority](docs/ARCHITECTURE_CONTRACT.md) |
| Branches, worktrees, checks and integration | [WORKFLOW.md](WORKFLOW.md) |

The first useful path is host event → durable capture or spool → replay/restart →
current-work context or retrieval → exact source open. Optional model-assisted
learning must later change an actual Memory revision consumed by that same path.
Base does not depend on controller inference.

Read only the task's owning sections. The audit explains evidence and rejected
mechanisms; it is not required context for every edit. Current findings and
external dependency observations belong in the registry, not copied status lists
in every README. Documentation, source presence and a green build are not runtime
qualification.

## Donors and related projects

[V2 snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105)
and [V1 snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7)
are historical references. Existing Cargo packages and V2 workstream `active`
values do not establish V3 support. The [documentation map](docs/README.md)
separates current design from donor navigation.

[Eliot Search](https://github.com/UnknownAlienHuman/eliot-search),
[Eliot Research](https://github.com/UnknownAlienHuman/eliot-research) and the
[swarm controller](https://github.com/UnknownAlienHuman/eliot-swarm-controller)
own their implementations and roadmaps. Do not mirror them here.

## Retained V2 reading only

The generated block below is for explicitly assigned retained V2 edits. V3 work
uses the task-scoped instructions above; existing merge checks still apply.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](docs/architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for exact paths and causal property. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. Stable `ELIOT_*` files are V2 compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## License

[MIT](LICENSE). Third-party code and runtimes retain their own licenses.
