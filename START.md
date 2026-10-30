# Start here

Read [AGENTS.md](AGENTS.md), then choose one
[V3 task route](docs/v3/README.md#task-routes). Read the owning sections, not every
book or the complete audit.

| Your task | Next step |
|---|---|
| Continue documentation | Pick the existing [stage/finding](docs/v3/ANALYSIS-REGISTRY.md#documentation-stages); correct its owner and direct consumers. |
| Implement an assigned capability | Use the [source map and bounded task](docs/v3/DEVELOPMENT.md#one-bounded-task), then the owning section and actual caller/reader. |
| Check or update a change | Use the [commands](docs/v3/DEVELOPMENT.md#checks) and [companion-update map](docs/v3/DEVELOPMENT.md#change-propagation). |
| Verify the integrated baseline | Resolve the [remaining verification work](docs/v3/ANALYSIS-REGISTRY.md#integration-blockers); do not reopen the merged documentation branch. |

PR #5325 is merged. Start new work from current `main`; the former documentation
branch is retired. Check live state before editing. [WORKFLOW](WORKFLOW.md) owns
branch/worktree and integration rules. V1/V2 source and workstreams are retained
donors, not permission to resume old programmes.

One task connects a caller, owning operation, result/unknown and consumer.
A schema, written contract or passing compile alone is not implemented behavior.
