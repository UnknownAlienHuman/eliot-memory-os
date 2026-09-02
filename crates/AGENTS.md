# Workspace crate instructions

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
permission. See [`../docs/architecture/READING_PROTOCOL.md`](../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Cargo-package documentation indexes

Every Cargo package below `crates/` is covered by one generated index:

- admitted workspace crates:
  [`PACKAGE_DOCS_INDEX.md`](../docs/code-navigation/PACKAGE_DOCS_INDEX.md);
- nonmember prototypes:
  [`PROTOTYPE_DOCS_INDEX.md`](../docs/code-navigation/PROTOTYPE_DOCS_INDEX.md).

The indexes bind discovered manifests to inherited instructions, logical
responsibility blocks, and canonical documentation handles. Regenerate both
with `python scripts/code_navigation.py sync-index --root .`; never edit either
projection by hand.

A deeper `AGENTS.md` narrows the package-specific owner, boundary, proof, and
stop conditions. It does not replace this verified documentation-routing
contract. Prototype presence does not grant workspace admission or runtime
authority.
