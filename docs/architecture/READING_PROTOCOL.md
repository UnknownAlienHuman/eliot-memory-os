<!-- generated: eliot-doc-shards-v1 -->
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Establish the current repository/base identity and follow applicable
   `AGENTS.md` instructions. `WORKFLOW.md` and `workstreams/ACTIVE.toml` are
   authority/navigation references, not additional default reading. If the
   decision crosses their workflow/workstream boundary, declare the needed
   content in the Issue's `## Read` and rerun the verified reader.
2. The owning Issue lists what to read in a `## Read` (or `## Читать`)
   section: one handle selector (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`)
   or one repository file per list item, optionally followed by a comment.
   Draft it from the path routes and keep only what the change needs:

   ```text
   python scripts/docs_router.py route --path <repository/path> --format issue
   ```

3. Run the verified reader from the repository root:

   ```text
   python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

   With `--issue` (or `--issue-body <file>` offline), the required reading is
   the Decision Safety Floor, the items the Issue declares and the nearest
   `AGENTS.md` files; path routes become optional pointers. Without an Issue,
   repeat `--path` for every mutable path family with a `--topic`, or use
   `--changed-from origin/main` for the complete branch delta, including
   deletions.
   An Issue-only read with no paths is declaration-only navigation; before
   editing, supply the actual mutable paths. An offline body capture preserves
   exact bytes but does not establish current Issue authority.
4. Open the verified bundle and read every required file/fragment before
   mutation. A route alone is navigation, not reading evidence.
5. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
6. Record the route/read receipt IDs, declared reading or matched routes,
   required handles, fragment paths and SHA-256 values, verified bundle SHA-256,
   and explicit reading attestation in the work unit or pull request.
7. Re-run the reader when the Issue reading, changed path, causal property,
   authority boundary, or evidence scope changes.

Current normative pair: `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`.

## Fail-closed cases

Do not mutate the repository when:

- the Issue has no `## Read` section or a declared item does not resolve;
- no non-baseline route matches a material path read without an Issue;
- a required handle cannot be resolved;
- a routed file/fragment hash or byte count differs from the read receipt;
- the verified bundle cannot be materialized;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the read receipt without a new reader invocation.

## Context discipline

The reader returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, Decision Anchor index, and assembled
books are navigation or audit surfaces. They are prohibited as default agent
context.

Human routes summarize optional pointers by default. Use `--full-pointers` or
`--format json` only when inspecting an optional boundary; the reader bundle
contains required content only.

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
