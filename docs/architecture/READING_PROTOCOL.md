<!-- generated: eliot-doc-shards-v1 -->
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Resolve current repository authority through `AGENTS.md`, `WORKFLOW.md`, and
   `workstreams/ACTIVE.toml`.
2. Run the verified reader from the repository root:

   ```text
   python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

   Repeat `--path` for every mutable path family, or use `--changed-from
   origin/main` for the complete branch delta, including deletions.
3. Open the verified bundle and read every required file/fragment before
   mutation. A route alone is navigation, not reading evidence.
4. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
5. Record the route/read receipt IDs, matched routes, required handles, fragment
   paths and SHA-256 values, verified bundle SHA-256, and explicit reading
   attestation in the work unit or pull request.
6. Re-run the reader when the changed path, causal property, authority boundary,
   or evidence scope expands.

Current normative pair: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.

## Fail-closed cases

Do not mutate the repository when:

- no non-baseline route matches a material path;
- a required handle cannot be resolved;
- a routed file/fragment hash or byte count differs from the read receipt;
- the verified bundle cannot be materialized;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the read receipt without a new reader invocation.

## Context discipline

The reader returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, and assembled books are navigation or
audit surfaces. They are prohibited as default agent context.

To inspect all changed paths at once:

```text
python scripts/docs_read.py read --changed-from origin/main --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

The generated bundle and receipts are local evidence and must not be committed.

To verify the documentation graph and reader implementation:

```text
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
```
