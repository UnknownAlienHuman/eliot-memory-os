# Dependency policy

Dependencies implement bounded mechanics behind ELIOT-owned contracts. They do
not own Architecture, task semantics, authority, canonical memory, finish, or
recovery policy.

## Admission

A new or upgraded dependency requires:

- a real current consumer and owner;
- exact version/source identity in `Cargo.lock` or the applicable immutable
  runtime manifest;
- feature, MSRV, license, advisory, Windows-support, and build-cost review;
- a narrow facade/process/protocol boundary with no vendor types in public ELIOT
  contracts;
- failure, removal, migration, and rollback behavior;
- focused proof on the affected package/edge and broader proof only for a
  matching blast radius.

Prefer, in order:

1. use an upstream project unchanged behind a facade;
2. wrap an executable/service through a typed ELIOT protocol;
3. contribute upstream;
4. fork with explicit divergence ownership;
5. implement from scratch only for a genuinely unique ELIOT contract.

## Runtime and authority boundaries

- Optional third-party runtimes are separately obtained/licensed components.
- Credentials are confined to the owning adapter/process boundary.
- Availability or installation never grants semantic authority.
- Provider fallback never expands privacy, effects, or cost silently.
- A framework may implement local mechanics but cannot define ELIOT ownership,
  authority, task lifecycle, or proof semantics.
- Every dependency has an export/removal path appropriate to the state it can
  affect.

## Evidence

README claims, audit prose, donor research, and version names are not admission.
Current authority comes from exact lockfile/manifest identity plus applicable
executed evidence. Advisory and license exceptions are explicit and scoped; a
report is never committed merely to make a gate look complete.

Dependency decisions that change a load-bearing default, hard dependency,
canonical format/protocol, authority boundary, or production contour receive an
ADR. Ordinary implementation and routine patch updates do not.

## Repository hygiene

Downloaded packages, vendor source snapshots, research dossiers, reverse-
engineering output, and generated dependency reports do not live in the active
checkout. Findings belong in the owning issue/PR; generated SBOM/license/
advisory artifacts belong in CI or release artifacts. Git tracks only source,
accepted policy/ADR, and exact manifests/lockfiles required to reproduce the
current product candidate.

## Executable verification profiles

Dependency policy execution operates under two distinct profiles with separate
proof ceilings:

1. **`offline-source`**: A bounded, offline gate for local and PR validation. It
   verifies `deny.toml` policy conformance, scanner pinning, lockfile integrity
   across all ecosystems (`Cargo.lock`, `packages.lock.json`,
   `requirements-verification.txt`), full direct-dependency inventory
   accounting in `config/dependency-policy.toml`, and executes `cargo deny check
   bans licenses sources`. It checks cached offline data and does not claim
   current vulnerability coverage. Proof ceiling: `OFFLINE_SOURCE_EVIDENCE_ONLY`.
2. **`current-advisories`**: A manual source/release workflow profile. In
   addition to offline checks, it validates the current advisory snapshot from
   the authoritative RustSec advisory database, executes `cargo deny check
   advisories bans licenses sources`, binds advisory freshness, and generates a
   content-addressed canonical receipt. Proof ceiling:
   `DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE`.

## Multi-ecosystem denominator and inventory

All third-party inputs admitted into ELIOT are accounted for in a single
canonical manifest at `config/dependency-policy.toml`:

- **Rust**: Workspace member and standalone crates, locked via `Cargo.lock`,
  governed by `deny.toml`.
- **NuGet**: Operator desktop dependencies, locked via
  `apps/Eliot.Operator/packages.lock.json` with
  `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`.
- **Python**: Repository verification dependencies, hash-locked with SHA-256
  digests in `scripts/requirements-verification.txt`.
- **Node / MCPB**: Bridge contracts and manifests under `integrations/`.
- **External executables**: Shipped or runtime services such as SurrealDB,
  inventoried with version, digest, license, trust model, and removal boundary.

Every direct third-party dependency must record a current consumer, capability
owner, justification, enabled features, public-contract exposure boundary, and
removal/rollback plan.

## Pinned scanner identity and canonical receipts

Scanner execution is pinned to an exact toolchain identity (`cargo-deny 0.20.2`
with executable digest). Policy execution produces a canonical receipt
(`.eliot/dependency-policy-receipt.json` or release artifact) that binds:

- Git source commit SHA;
- input manifest and lockfile SHA-256 digests;
- policy digest (`deny.toml` and `config/dependency-policy.toml`);
- scanner executable identity and version;
- advisory database snapshot timestamp and source;
- evaluated targets and feature profiles;
- structured exceptions and verification findings.

