<!-- generated: eliot-doc-shards-v1 -->
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Resolve current repository authority through `AGENTS.md`, `WORKFLOW.md`, and
   `workstreams/ACTIVE.toml`.
2. Run `python scripts/docs_router.py route --path <path> --topic "<intent>"`.
3. Read every **required** fragment exactly as emitted.
4. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
5. Record the router receipt ID, matched routes, handles, fragment paths, and
   fragment SHA-256 values in the work unit or pull request.
6. Re-run the route when the changed path, causal property, authority boundary,
   or evidence scope expands.

Current normative pair: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.

## Fail-closed cases

Do not mutate the repository when:

- no non-baseline route matches a material path;
- a required handle cannot be resolved;
- a fragment hash differs from the route receipt;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the routed causal property without a new route.

## Context discipline

The router returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, and assembled books are navigation or
audit surfaces. They are prohibited as default agent context.

To inspect all changed paths at once:

```text
python scripts/docs_router.py route --changed-from origin/main --topic "<intent>"
```

To verify the documentation graph:

```text
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
```
