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
