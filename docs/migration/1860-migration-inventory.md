# 1860 migration inventory — component / owner / path

Owner: `bins/eliotd` migration coordination.
Issue: [#1860](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/1860) —
publish the required migration inventory and impact graph (I19.2 required output:
component/owner/path inventory).

## Reading attestation

Documentation routing was run from the repository root before any mutation:

- Route receipt: `sha256:4c9eb46dec6e156fdb79347c9da94f9db4571387905b09d809d88589a24c9911`
- Read receipt: `sha256:843fe89f61717696b83b5127ba55ee7304c796c8ef4603b8901a564492b821fa`
- Matched routes: `canonical-storage`, `release-migration`,
  `documentation-authority`, `workspace-governance`
- Verified bundle SHA-256: `b6a227bc93defbc1448676e44cc9a3ca8071529ff7be9c3c784de887f759c03c`
- Normative pair: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`
- Required fragments read in full: I19.1, I19.2, I19.3, I19.13, I19.16, I0.8,
  I19.5, I19.10, I19.11, plus the #11 installed-pulse allocation and
  `bins/AGENTS.md` composition rules.

## Source identity (inventory denominator)

- `git_head`: `95bd6b2ccb3898182ffda745f7b7b094e95debbf`
- Tracked tree clean at scan time: yes (`git status --porcelain --untracked-files=no` empty)
- `Cargo.lock` SHA-256: `f931d991aa3f51466cf034d08d91016b8fe5d8bf71a2f20a5cd9b16f7c07eb45`
- `cargo 1.97.1`, `rustc 1.97.1`
- Workspace members: **174** · `bins/` roots: **15** · bins-reachable: **101** ·
  bins-unreachable: **73** · standalone packages: **11** · root `exclude`: empty
- Machine output (evidence, not authority):
  `.eliot/migration-inventory-1860.json`,
  aggregate `sha256:9aab21cf9d341abe56ad14f3205e6eed3c7f5256ce4c3752a73c5e9fac321ebc`
  (regenerate with `python scripts/migration_inventory_1860.py --emit --output
  .eliot/migration-inventory-1860.json --overwrite`; verify with `--check`).

## Premise reconciliation

The issue's audit premise named 43 unreachable workspace packages (of 158) and
13 excluded packages. At this head the workspace holds 174 members with 73
bins-unreachable packages, and the standalone denominator holds 11 package
crates (reconciled in `workstreams/security/standalone-crate-dispositions.toml`
as 11 packages + 3 non-production `[workspace]` roots: `mcpls.toml` config and
two `scripts/testdata/` fixture workspaces). The ledger in
`1860-dispositions.md` dispositions **all 73** currently-unreachable packages —
a superset covering the audit-time 43 — and **all 11** standalone rows
(verbatim #1811 verbs), which together with the checked-in reconciliation cover
the 13-wide excluded scope. Reachability alone never retires anything (I19.2
refresh rule); six rows are explicit `UNKNOWN` pending owner experiment.

## Reviewer lookup guide

Start from any binary, package, excluded path, or generated artifact and follow
exactly one hop:

| Start point | Where the answer lives |
|---|---|
| Any `bins/*` binary | `packages[]` row for its manifest dir: owner, bins-reachability, impact edges via its dependency closure |
| Any `crates/*` / `workspace/tools/*` package | `packages[]` row by `path`: owner, `disposition` + `rationale`, `active_reference.status` + `hit_classes`, crate metadata |
| Any excluded/standalone path | `excluded_scope[]` row by `path`: verbatim #1811 disposition + owner + active-reference status |
| Generated artifact (`target/`, build output, `wit/`, release bundle) | `surfaces[]` class row (`binary`, `script`, `schema`, `install`, `generated-schema`), then the owning binary/package row above |
| Schema / Skill / prompt / config / CI / install manifest | `surfaces[]` class row, then the referencing package rows via `active_reference.hits_by_class` |
| Installed integration / live state | `active_reference.unscanned_surfaces`: explicitly `UNKNOWN` — live store, installed artifacts, and runtime integration state are not scanned by this tool and must be rechecked per the I19.2 refresh rule |

## Tracked surface denominator (from the tool)

| Class | Files | Meaning |
|---|---|---|
| `source` | 1029 | production Rust sources |
| `docs` | 731 | documentation payload |
| `test` | 447 | tests and fixtures |
| `binary` | 287 | files under `bins/` (composition roots) |
| `script` | 288 | `scripts/` automation |
| `manifest` | 169 | Cargo manifests/locks outside `bins/` |
| `schema` | 86 | `.surql` / migration bytes |
| `workstream` | 80 | work allocations and ledgers |
| `integration` | 46 | `integrations/` bridges |
| `skill` | 23 | Skill payloads |
| `app` | 13 | `apps/` operator surfaces |
| `tool` | 13 | `workspace/tools/` developer tools |
| `ci` | 10 | `.github/` workflows |
| `plugin` | 10 | `plugin/` payloads |
| `config` | 6 | `config/` policy |
| `other` | 131 | remaining tracked files |

Full per-file lists live in the JSON `surfaces[]` rows (truncated at 40 paths
per class in the projection; the scan itself is complete).

## Companion documents

- `1860-dispositions.md` — the 73 + 11 disposition ledger with owners, rationales,
  and active-reference status.
- `1860-impact-graph.md` — the repair impact graph (three hard-boundary repairs,
  legacy-crate retirement, Kernel–Store v1 decode removal, release surface,
  Windows Product Proof, Store/Governor paths).
- `1860-product-proof-plan.md` — the first Product Proof plan; its
  installed-route receipt is `ProductPulseReceipt`.
- Tool: `scripts/migration_inventory_1860.py`; minimal proof:
  `scripts/tests/test_migration_inventory_1860.py`.

## Proof ceiling

`MIGRATION_INVENTORY_EVIDENCE_ONLY`. This inventory establishes
source/reachability/ownership evidence only and cannot prove runtime or Product
support. Product status remains `NOT_ACCEPTED / UNVERIFIED` until the exact
Product Proof in `1860-product-proof-plan.md` executes.
