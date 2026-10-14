# Workspace crate instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation reading

Follow the [verified reading protocol](../docs/architecture/READING_PROTOCOL.md). From the repository
root, read the owning Issue's `## Read` with the actual mutable paths:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Open the verified bundle and read every required item before editing. Record its
route/read identities, hashes and reading attestation. Reroute when scope changes;
without an owning Issue, use the protocol's path/topic mode. Reading references
do not grant write scope. Do not substitute a legacy compatibility map for a read.
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
