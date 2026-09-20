# 1860 repair impact graph

Owner: `bins/eliotd` migration coordination. Nodes are migration facts with
owners, not support claims; edges are blocking/ordering relations. The
machine-readable graph lives in `.eliot/migration-inventory-1860.json`
(`impact_graph`); the tool fails closed on dangling edges.

## Nodes

| ID | Meaning | Owner / evidence path |
|---|---|---|
| `HB1-canonical-finish` | Strict canonical finish only (I19.5 B) | #18 eliotd semantic ownership |
| `HB2-lossless-payload` | Lossless generic payload authority (I19.5 B) | #18 eliotd semantic ownership |
| `HB3-one-writer` | Canonical control records and one online writer composition (I19.5 B) | #18 with Store owner #19 |
| `LEGACY-RETIREMENT` | `eliot-app` / `eliot-engine` / `eliot-store` / `eliot-types` aggregate facades | retirement #1189 (T7-S9); extraction #18/#19 |
| `KERNEL-STORE-V1-DECODE-REMOVAL` | Removal of the Kernel–Store v1 compatibility decoders | Store owner #19; Governor owner #18 |
| `RELEASE-SURFACE` | `docs/release/WINDOWS_X64_RELEASE.md` + `scripts/build-eliot-windows-x64-release.ps1` gate (incl. `Test-ExcludedDispositions`) | release owner via #1811 gate |
| `WINDOWS-PRODUCT-PROOF` | Installed D0/D1 pulse with `ProductPulseReceipt` | #11 (see `1860-product-proof-plan.md`) |
| `STORE-PATH` | Admitted named Store operations | #19 (`bins/eliot-store-surreal`) |
| `GOVERNOR-PATH` | `eliotd` semantic Governor application | #18 (`bins/eliotd`) |

## Edges

- `HB1-canonical-finish` -> `GOVERNOR-PATH`: finish semantics must land in eliotd before facade extraction
- `HB2-lossless-payload` -> `GOVERNOR-PATH`: payload authority must precede agent-path cutover
- `HB3-one-writer` -> `STORE-PATH`: one-writer composition must precede Store bridge migration
- `GOVERNOR-PATH` -> `LEGACY-RETIREMENT`: facade consumers migrate to eliotd before RETIRE
- `STORE-PATH` -> `LEGACY-RETIREMENT`: Store readers migrate to named operations before RETIRE
- `STORE-PATH` -> `KERNEL-STORE-V1-DECODE-REMOVAL`: v1 compat decoders removable only after v2-only production
- `GOVERNOR-PATH` -> `KERNEL-STORE-V1-DECODE-REMOVAL`: eliotd v1-compat projection removable only after v2-only resolution
- `LEGACY-RETIREMENT` -> `RELEASE-SURFACE`: release gate must reject retired crates as inputs
- `KERNEL-STORE-V1-DECODE-REMOVAL` -> `RELEASE-SURFACE`: release bundle must carry no legacy decode path
- `RELEASE-SURFACE` -> `WINDOWS-PRODUCT-PROOF`: installed proof runs from the gated release bundle
- `HB1-canonical-finish` -> `WINDOWS-PRODUCT-PROOF`: pulse asserts strict finish
- `HB2-lossless-payload` -> `WINDOWS-PRODUCT-PROOF`: pulse asserts lossless payload round-trip
- `HB3-one-writer` -> `WINDOWS-PRODUCT-PROOF`: pulse asserts single-writer composition

## Shape

```text
HB1 ──► GOVERNOR-PATH ──┬──► LEGACY-RETIREMENT ──► RELEASE-SURFACE ──► WINDOWS-PRODUCT-PROOF
HB2 ──► GOVERNOR-PATH ──┘         ▲                          ▲                  ▲
HB3 ──► STORE-PATH ───────────────┘                          │                  │
        STORE-PATH ──► KERNEL-STORE-V1-DECODE-REMOVAL ────────┘                  │
        GOVERNOR-PATH ─► KERNEL-STORE-V1-DECODE-REMOVAL ──────┘                  │
        HB1 / HB2 / HB3 ─────────────────────────────────────────────────────────┘
```

## Kernel–Store v1 decode removal (current decoder sites)

- `crates/kernel/eliot-kernel-service/src/store_exchange.rs` — sole versioned
  compatibility decoder for legacy v1 string failure.
- `crates/storage/eliot-store-api/src/wire.rs` — `decode_legacy_store_failure_v1`
  (legacy v1 string failure retained for a bounded compatibility window).
- `bins/eliotd/src/activation_projection.rs` / `bins/eliotd/src/lib.rs` — v1
  compatibility projection (must never consume v2 typed-result data).
- Boundary rule (from #451 allocation family): confine legacy decoding to the
  explicit v1 compatibility boundary; current producer code and the current v2
  session must not use it. Removal requires v2-only production on both paths,
  then the release gate asserts no legacy decode path ships.

## How to read impact for a row

From any ledger row in `1860-dispositions.md`, walk the edges above: a RETIRE
row (`LEGACY-RETIREMENT`) is blocked by `GOVERNOR-PATH` + `STORE-PATH`
consumer migration and blocks `RELEASE-SURFACE`; a Store/Governor change walks
forward into `KERNEL-STORE-V1-DECODE-REMOVAL` and then into
`WINDOWS-PRODUCT-PROOF`. No edge may be severed without the owning issue's
reviewed unit (I19.5: each repair is a separate reviewed unit with an
adversarial discriminator before code).
