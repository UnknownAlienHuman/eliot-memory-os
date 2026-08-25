# Architecture authority

This file is a navigation contract, not a third normative architecture book.

ELIOT has one normative pair. Its canonical location is outside the checkout so
that source cutovers and generated host packages cannot silently replace it:

`C:\Development\Rust\docs\ELIOT Arhitecture`

| Authority | Canonical file | Revision | SHA-256 |
|---|---|---|---|
| Intent, theory, invariants, and hard boundaries | `ELIOT_ARCHITECTURE.md` | `4.5-draft` | `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8` |
| Target owners, contracts, defaults, failure behavior, and migration | `ELIOT_IMPLEMENTATION.md` | `0.29-draft` | `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B` |

Read the canonical `README.md` and `INDEX.md` in that directory for bounded
routing into the pair. Architecture prevails over Implementation when their
meaning conflicts. Neither document proves that a target mechanism exists or is
running.

## Current-system truth

Current source files, Cargo manifests and lockfile, generated metadata, compiler
diagnostics, tests, installed artifact hashes, and live runtime observations are
the evidence for the current product identity. Databases, reports, code graphs,
agent memory, and prose are evidence layers and may be stale.

The normative pair remains draft/target. Until an exact, scoped Product Proof is
accepted, the honest product status is `NOT_ACCEPTED / UNVERIFIED`. A green
workspace build does not promote D0 or D1 by itself.

## Repository documents

Files under `docs/architecture/`, milestone worklogs, `UL_PROGRESS.md`, and old
completion reports are historical or bounded evidence tied to their recorded
source identities. They are not competing current authorities and their PASS or
CERTIFIED labels must not be transferred to current bytes.

Copies of the normative books inside this repository or a generated host package
are non-canonical. Any projection must retain the canonical revisions and hashes
above and must be regenerated when the pair changes.
