# Workspace tool package instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. Open the
verified bundle and read every required item before mutation. A route alone is
navigation, not reading evidence.

Record the route receipt ID, read receipt ID, matched routes, required handles,
fragment paths and SHA-256 values, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale or missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Package documentation index

Every admitted Cargo package below `workspace/tools/` is listed in the generated
[workspace package ↔ documentation index](../../docs/code-navigation/PACKAGE_DOCS_INDEX.md).
The index binds the exact root `Cargo.toml` denominator to the workspace-governance
block and canonical documentation handles. Regenerate it with
`python scripts/code_navigation.py sync-index --root .`; never edit it by hand.

These packages are repository/build tools. Their package names do not grant
runtime, semantic, canonical-state, or Product authority.
