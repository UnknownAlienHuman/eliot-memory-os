# Build success claim boundary (release/status reporting owner)

This document binds successful compilation to its exact claim. It does not
create installed-runtime, verifier, acceptance, or release-eligibility evidence.

## Claim types (distinct)

| Claim | Presentation label | Meaning |
|---|---|---|
| `build` | `BUILD_PASS` | Exact source-built executables only. |
| `assembly` | `ASSEMBLY_COMPLETE` | Exact staged bundle inventory only. |
| `installed-runtime` | `INSTALLED_RUNTIME_OBSERVED` or `INSTALLED_RUNTIME_UNKNOWN` | Live installed Windows observation only. |
| `verifier` | `VERIFIER_PASS` or `VERIFIER_NOT_EXECUTED` | Executed verifier on the exact artifact/environment only. |
| `acceptance` | `ACCEPTED` or `NOT_ACCEPTED` | Canonical acceptance coverage only. |
| `release-eligibility` | `RELEASE_ELIGIBLE` or `RELEASE_NOT_ELIGIBLE_TARGET` | Full release gate only. |

## Nine-binary build scope

A successful nine-binary build is exactly these source-built roles, bound to
the pinned source commit and `cargo metadata --locked --offline` identities:

`eliot`, `eliot-host`, `eliot-watchdog`, `eliot-kernel`,
`eliot-store-surreal`, `eliotd`, `eliot-doctor`, `eliot-testd`,
`eliot-native-worker`.

Such a build emits `BUILD_PASS` and `ASSEMBLY_COMPLETE` only.

## Downstream statuses from compilation alone

Compilation alone leaves every downstream claim at its non-claiming value:

| Downstream | Status from compilation alone |
|---|---|
| installed-runtime observation | `UNKNOWN` (no identity-bound installed Windows spine proof) |
| verifier success | `NOT_EXECUTED` |
| task acceptance | `TARGET` (product remains `NOT_ACCEPTED / UNVERIFIED`) |
| release eligibility | `TARGET` (never `release-ready`) |
| invalidated prior stronger claim | `STALE` |

No `release-ready`, `complete`, `certified`, or `architecture-complete` status
is derivable from compilation. The same status surface that shows
`BUILD_PASS / ASSEMBLY_COMPLETE` visibly retains
`NOT_ACCEPTED / UNVERIFIED` for the product until an identity-bound installed
Windows spine proof (I17.6 operational spine on the exact product identity)
exists.

## Mechanism Review trigger (I17.5)

A build pass while the declared product outcome remains unchanged is the
I17.5 trigger `local PASS with unchanged product outcome`. The build claim
surface raises `MECHANISM_REVIEW_REQUIRED` instead of promoting the product
claim. Review output names the actual owner/path, why the discriminator was
insufficient, the common causal mechanism, and the smallest closing seam.

## Machine enforcement

`scripts/verify-release-claim-boundary.py` is the executable projection of
this boundary. Its `--self-test` is the minimal acceptance proof; its
`--root` check binds this document, the nine-binary build definitions in
`scripts/build-eliot-windows-x64-release.ps1`, and the emitted claim shape.
