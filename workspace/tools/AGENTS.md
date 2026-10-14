# Workspace tool package instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation reading

Follow the [verified reading protocol](../../docs/architecture/READING_PROTOCOL.md). From the repository
root, read the owning Issue's `## Read` with the actual mutable paths:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Open the verified bundle and read every required item before editing. Record its
route/read identities, hashes and reading attestation. Reroute when scope changes;
without an owning Issue, use the protocol's path/topic mode. Reading references
do not grant write scope. Do not substitute a legacy compatibility map for a read.
<!-- eliot-doc-routing:end -->

## Package documentation index

Every admitted Cargo package below `workspace/tools/` is listed in the generated
[workspace package ↔ documentation index](../../docs/code-navigation/PACKAGE_DOCS_INDEX.md).
The index binds the exact root `Cargo.toml` denominator to the workspace-governance
block and canonical documentation handles. Regenerate it with
`python scripts/code_navigation.py sync-index --root .`; never edit it by hand.

These packages are repository/build tools. Their package names do not grant
runtime, semantic, canonical-state, or Product authority.
