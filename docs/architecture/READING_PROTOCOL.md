<!-- generated: eliot-doc-shards-v1 -->
# Verified documentation reading

V3 owners are selected through the [task map](../v3/README.md). Retained V2
fragments apply only to V2/shared paths. This protocol verifies selected bytes;
it does not make the V2 workstream an active V3 assignment.

## Required sequence

1. Resolve the task through `AGENTS.md`, `WORKFLOW.md` and
   [`ARCHITECTURE_CONTRACT.md`](../ARCHITECTURE_CONTRACT.md). The V3 registry tracks
   V3 work; `workstreams/ACTIVE.toml` is retained V2 evidence, not its task queue.
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

Route configuration v3 uses the exact architecture-authority page as its common
identity (wire field `pair_key`). Pure V3 reading does not load V2 metadata or shards;
V2/mixed reading preserves their requirements. Final-candidate metadata is scoped by
the complete changed-path set; see the [recipe](../v3/DEVELOPMENT.md#routing-metadata).

Retained V2 pair: `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`.

## Fail-closed cases

Do not mutate the repository when:

- no non-baseline route matches a material path;
- a required handle cannot be resolved;
- a routed file/fragment hash or byte count differs from the read receipt;
- the verified bundle cannot be materialized;
- a selected V2 shard manifest cannot reconstruct its retained source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the read receipt without a new reader invocation.

## Context discipline

The reader returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, Decision Anchor index, and assembled
books are navigation or audit surfaces. They are prohibited as default agent
context.

To inspect all changed paths at once:

```text
python scripts/docs_read.py read --changed-from origin/main --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

The generated bundle and receipts are local evidence and must not be committed.

For shared routing changes, check the complete configured corpus and reader:

```text
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
```

For prose links use the existing [link-only recipe](../v3/DEVELOPMENT.md#documentation-and-navigation).
The retained V2 shard/pair verifier is a separate legacy check, not a V3 readiness
verdict or a prerequisite for reading a V3 owner file.
