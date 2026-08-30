# Documentation map

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory reading protocol](architecture/READING_PROTOCOL.md), then use the generated route for the exact files and causal property being changed. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->


`main` contains the current documentation. This directory has no historical
audit archive and no alternate Architecture edition.

## Start here

| Need | Source |
|---|---|
| Architecture authority and precedence | [`ARCHITECTURE_CONTRACT.md`](ARCHITECTURE_CONTRACT.md) |
| Exact accepted pair identity | [`normative-pair.toml`](normative-pair.toml) |
| Architecture / Implementation | [`architecture/`](architecture/) |
| Crates, Rust modules, logical blocks, and CodeBase Memory MCP workflow | [`CODE_NAVIGATION.md`](CODE_NAVIGATION.md) |
| Current repository and runtime-owner map | [`PROJECT_MAP.md`](PROJECT_MAP.md) |
| Dependency admission/removal policy | [`DEPENDENCY_POLICY.md`](DEPENDENCY_POLICY.md) |
| Stable operational guidance | [`operations/`](operations/) |
| Release packaging and immutable dependency pins | [`release/`](release/) |
| Current host integration documentation | [`integrations/`](integrations/) |
| Accepted load-bearing implementation decisions | [`ADR/`](ADR/) |

Repository work rules live at the root in `AGENTS.md`, `WORKFLOW.md`, and
`workstreams/ACTIVE.toml`.

## What does not belong here

Do not add dated audits, progress journals, donor dossiers, swarm transcripts,
model reports, generated certification packages, or branch handoffs. Put current
findings in the owning issue/PR and generated evidence in CI artifacts. Git
history remains the archaeology surface.

Documentation expresses intent, contracts, and current operator/developer
interfaces. It does not prove that source exists, a service is installed, a
runtime is healthy, or a Product Pulse passed.
