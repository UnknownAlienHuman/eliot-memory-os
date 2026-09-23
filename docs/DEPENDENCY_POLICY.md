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

The Review profile's final cargo-deny gate delegates to this verifier profile.
It uses the configured version-and-digest-pinned Windows executable through
the verifier's private-copy runner. The verifier may locate a candidate via
PATH, but PATH resolution alone is never trusted: it validates the configured
version, executable SHA-256 and Windows PE identity, then executes only the
digest-matched bytes through a verified private copy. The summary takes scanner
identity only from that profile's source/profile-bound receipt.

For a Windows release selecting the project-local SurrealDB candidate, the
provisioner keeps the installed-version OSV evidence separate and fetches a
fresh query/result for the exact selected candidate version. After the Windows
build, the release builder consumes a selected-release receipt that binds the
candidate artifact bytes, policy manifest, release catalogue, provisioning
receipt, exact OSV query/response digests and retrieval time. It stages the
receipt and the query/response bytes, then verifies those bindings again with
the release bundle. The receipt reports `release_admission: INCOMPLETE` while
applicability of crate advisories to the distributed Windows binary remains
unestablished; it does not turn the installed `3.1.4` findings into a clean
result or claim a complete dependency-policy PASS.
This release-only refresh does not make the `offline-source` profile depend on
network access or current candidate advisories; that profile does not assess
the selected candidate's advisory response.

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

The verifier constructs the receipt denominator from observed source inputs and
lock data, then reconciles direct roots against the policy inventory in both
directions. Rust receipts enumerate every Cargo.lock package identity, source,
checksum when present, and locked dependency edges. They also retain each
observed Cargo manifest edge with its consumer package, declaration kind,
target condition, alias, requested version/features, optionality, and whether
the target is an internal workspace package. Explicit internal-edge
dispositions bind the owner, reason, feature profile, exposure boundary, and
removal plan for selected production edges; they remain separate from the
third-party inventory. Receipt input digests include every Cargo.toml scanned
for these edges, so the manifest declarations that produce the denominator are
bound alongside Cargo.lock. Unused workspace dependency definitions do not
become direct roots by themselves.

Each observed Rust edge also carries resolver-binding status. A manifest
outside the root workspace is not attributed a lock identity merely because
the root Cargo.lock contains a package with the same name. Until resolver
metadata binds that manifest's alias, dependency kind, target condition and
requested version to an exact locked package, the edge remains
`source_only_incomplete` and the Rust denominator remains incomplete. The
current verifier does not yet produce a resolver-backed identity for any
non-member workspace edge; it counts every observed non-member edge as
incomplete, including an edge with a missing or malformed identity record. The
current ten non-member manifests each declare an independent `[workspace]` and
have no adjacent checked-in `Cargo.lock`, so the root lock cannot provide the
missing resolver binding. Any standalone lockfile later observed for such a
workspace is included in the receipt's input digests, but its presence alone
is not treated as a resolved edge. The remaining resolver boundary is to join
each declaration's manifest, alias, dependency kind, target condition and
requested version to an exact locked package identity from resolver metadata
before clearing that incomplete state.

The current-main #2393 source adds three governed production edges from
`eliot-governor` to `eliot-kernel-core`, `eliot-ors`, and `eliot-platform`.
Their explicit dispositions describe the owner-closure provider and its public
type exposure. The two `eliot-wasm-host` edges to `eliot-contracts` and
`eliot-platform` are also present in current source and have explicit
dispositions; those rows do not establish that the separate WASM invocation
path is complete. Other observed internal edges remain in the source-derived
receipt denominator even when they do not have a selected-edge disposition.
The current-main #2395 merge also adds the observed internal edges
`eliot-host` → `eliot-notify` and the `eliot` CLI → `eliot-host`. The verifier
records both in the source-derived denominator; their presence does not make
them selected disposition rows. The disposition ledger remains selective by
contract and covers only explicitly selected production edges.

NuGet receipts enumerate
each target-specific package instance with its resolved version and SHA-512
content hash, and bind direct project PackageReference entries to the configured
lock target and inventory versions. Python receipts enumerate every exact
package pin and its SHA-256 hashes, identify direct roots from the lock's -r
provenance, and reconcile those roots and versions with the inventory.

The Node denominator follows the production surface named by the bridge
contract, resolves and digests its local import graph, and records observed
external module imports. An empty package set is complete only when that graph
has no external imports and the configured integration package root contains no
package-manager manifest or lock. An unbound external import or newly present
package-manager file yields incomplete evidence until it is explicitly locked
and supported by policy.

## Pinned scanner identity and canonical receipts

Scanner execution is trusted only at the configured toolchain identity
(cargo-deny 0.20.2 plus executable digest). When `--receipt-out` is supplied,
the verifier writes a canonical receipt to the caller-selected path, for
example `.eliot/dependency-policy-receipt.json` or a release artifact.
The Review configuration requires exactly one each of `advisories`, `bans`,
`licenses` and `sources`; missing, duplicate or additional check names are
rejected before scanner execution.
The Review wrapper
uses a GUID-named temporary receipt only to pass scanner identity to its
summary and deletes that file before exit; it is not retained as a canonical
artifact. A failed cleanup is reported as a harness failure. The receipt binds:

- Git source commit SHA;
- input manifest and lockfile SHA-256 digests;
- policy digest (`deny.toml` and `config/dependency-policy.toml`);
- scanner executable identity and version;
- advisory database snapshot timestamp and source;
- evaluated targets and feature profiles;
- structured exceptions and verification findings.
