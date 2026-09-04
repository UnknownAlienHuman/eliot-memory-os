# Assignment reservation

Owning issue: #840
Implementation PR: #841
Branch: `fix/840-cli-mcp-contract-test`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive mutable scope: remove only the stale duplicated MCP version assertion from `provider_identity_comes_from_actual_contract_shapes` in `crates/surfaces/eliot-cli/src/lib.rs`, then remove this reservation marker.

Issue #840 is the complete ten-case execution contract. It explicitly forbids changing the production constant or provider catalogue and forbids inventing an MCP `ProviderContract` row.

Remove this reservation file when the source edit begins and before ready-for-review.
