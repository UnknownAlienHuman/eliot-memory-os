# Workspace crate instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Every implementation Issue lists what to read in a `## Read` section: handle
selectors (`I5.19`, `I1.1..I1.8`, `A4.*`, `APPENDIX-L`) and repository files,
one per list item. Draft it with `python scripts/docs_router.py route --path
<repository/path> --format issue` and keep only what the change needs.

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

With `--issue`, the required reading is the Decision Safety Floor, the items the
Issue declares and the nearest `AGENTS.md` files; path routes become optional
pointers. Without an Issue, use `--path <repository/path> --topic "<causal
property>"` for every mutable path family, or `--changed-from origin/main` for
the complete branch delta. Open the verified bundle and read every required
item before mutation. A route alone is navigation, not reading evidence.

Record the route receipt ID, read receipt ID, declared reading or matched
routes, required handles, fragment paths and SHA-256 values, verified bundle
SHA-256, and explicit reading attestation in the work unit or pull request.
Optional fragments are loaded only when the current decision crosses their
stated boundary. A legacy `ELIOT_*` compatibility map is never an acceptable
read receipt.

If the Issue has no `## Read` section, a declared item does not resolve, no
non-baseline route matches a path read without an Issue, a required item is
stale or missing, or scope expands beyond the receipt, stop and repair the Issue
or the route; silence is not permission. See [`../docs/architecture/READING_PROTOCOL.md`](../docs/architecture/READING_PROTOCOL.md).
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
