# Documentation map

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. Running `scripts/docs_router.py route` alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
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
| Current repository planes and exact Cargo composition roots | [`PROJECT_MAP.md`](PROJECT_MAP.md) |
| Documentation/source path and inventory conformance | [`../scripts/README.md`](../scripts/README.md#documentation-graph-and-exact-path-verification) |
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
```

Generated bundles, receipts, and JSON findings are local/issue evidence and are
not committed as documentation authority.

## What does not belong here

Do not add dated audits, progress journals, donor dossiers, swarm transcripts,
model reports, generated certification packages, or branch handoffs. Put current
findings in the owning issue/PR and generated evidence in CI artifacts. Git
history remains the archaeology surface.

Documentation expresses intent, contracts, and current operator/developer
interfaces. It does not prove that source exists, a service is installed, a
runtime is healthy, or a Product Pulse passed.
