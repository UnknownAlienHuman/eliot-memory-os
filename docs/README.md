# Documentation map

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->


`main` contains the current documentation. This directory has no historical
audit archive and no alternate Architecture edition.

## Start here

| Need | Source |
|---|---|
| Mandatory verified reading and local receipt | [`architecture/READING_PROTOCOL.md`](architecture/READING_PROTOCOL.md) |
| Architecture authority and precedence | [`ARCHITECTURE_CONTRACT.md`](ARCHITECTURE_CONTRACT.md) |
| Exact accepted pair identity | [`normative-pair.toml`](normative-pair.toml) |
| Architecture / Implementation fragments and indexes | [`architecture/`](architecture/) |
| Admitted workspace package ↔ documentation index | [`code-navigation/PACKAGE_DOCS_INDEX.md`](code-navigation/PACKAGE_DOCS_INDEX.md) |
| Nonmember prototype package ↔ documentation index | [`code-navigation/PROTOTYPE_DOCS_INDEX.md`](code-navigation/PROTOTYPE_DOCS_INDEX.md) |
| Current repository planes and exact Cargo composition roots | [`PROJECT_MAP.md`](PROJECT_MAP.md) |
| Crates, Rust modules, logical responsibility blocks, and Code Graph workflow | [`CODE_NAVIGATION.md`](CODE_NAVIGATION.md) |
| Documentation/source path and inventory conformance | [`../scripts/README.md`](../scripts/README.md#repository-verification-and-documentation-pipeline) |
| Dependency admission/removal policy | [`DEPENDENCY_POLICY.md`](DEPENDENCY_POLICY.md) |
| Stable operational guidance | [`operations/`](operations/) |
| Release packaging and immutable dependency pins | [`release/`](release/) |
| Current host integration documentation | [`integrations/`](integrations/) |
| Accepted load-bearing implementation decisions | [`ADR/`](ADR/) |

`PROJECT_MAP.md` is a navigation projection, not independent authority. Its exact
`bins/*` composition-root inventory is checked against the root `Cargo.toml` by
the repository conformance gate. Source/build presence still does not establish
installation, runtime health, authority correctness, Product acceptance, or
release support.

`CODE_NAVIGATION.md`, `code-navigation/PACKAGE_DOCS_INDEX.md`,
`code-navigation/PROTOTYPE_DOCS_INDEX.md`, and `scripts/code_navigation.py`
derive package/path, documentation-handle, and one-hop dependency navigation
from the exact checkout. The workspace index is bound to the root `Cargo.toml`;
the prototype index is bound to every discovered nonmember Cargo manifest and
requires explicit `prototype = true` plus `workspace_admission`. Both fail
verification when they differ from the current checkout or inherited routing
contracts. Filesystem module locators and external Code Graph results remain
derived evidence; exact source, compiler/build checks, and owning verifiers
retain authority.

Repository work rules live at the root in `AGENTS.md`, `WORKFLOW.md`, and
`workstreams/ACTIVE.toml`.

## Local verification

For path/inventory work, run the narrow checks before broader Cargo proof:

```powershell
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
python scripts/verify-doc-code-conformance.py --self-test
python scripts/verify-doc-code-conformance.py --root .
python scripts/code_navigation.py self-test
python scripts/code_navigation.py check --root .
```

Generated bundles, receipts, JSON findings, and Code Graph databases are
local/issue evidence and are not committed as documentation authority. The two
Cargo-package indexes are committed navigation projections and are accepted
only when the generator reproduces both byte-for-byte.

## What does not belong here

Do not add dated audits, progress journals, donor dossiers, swarm transcripts,
model reports, generated certification packages, or branch handoffs. Put current
findings in the owning issue/PR and generated evidence in CI artifacts. Git
history remains the archaeology surface.

Documentation expresses intent, contracts, and current operator/developer
interfaces. It does not prove that source exists, a service is installed, a
runtime is healthy, or a Product Pulse passed.
