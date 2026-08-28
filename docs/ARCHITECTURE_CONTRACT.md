# Architecture authority

This file is the repository authority and navigation contract. It is not a
third normative book.

## Accepted normative pair

On 2026-08-28 the Architecture Owner adopted the exact 2026-08-28 English pair
as ELIOT's sole current normative pair.

| Authority | Canonical repository file | Revision | Edition | SHA-256 |
|---|---|---|---|---|
| Intent, theory, invariants, and Hard Boundaries | [`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) | `4.5-draft` | `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Target owners, contracts, defaults, failure behavior, and migration | [`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) | `0.29-draft` | `2026-08-28` | `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063` |

The machine-bindable adoption receipt is
[`docs/normative-pair.toml`](normative-pair.toml). Its pair key is
`sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.
Only the two document digests form the normative pair; the receipt, indexes,
catalogues, audits, and generated projections are evidence or navigation and
cannot become a third normative source.

Architecture prevails over Implementation when their meaning conflicts.
Adoption does not promote target mechanisms to current implementation support.
The frozen Architecture bytes retain their pre-adoption header wording
`candidate for canonical adoption`; the external receipt above is the adoption
decision. Implementation remains a target contract, and product status remains
`NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.

## Byte-identical publication aliases

The dated files below are byte-identical aliases of the canonical files, not
separate editions with independent authority:

- [`ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md`](architecture/ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md)
- [`ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md`](architecture/ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md)

Use [`docs/architecture/README.md`](architecture/README.md) and
[`docs/architecture/INDEX.md`](architecture/INDEX.md) for bounded routing.

## Superseded predecessor pair

The predecessor pair is superseded for current work:

- Architecture SHA-256 `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8`;
- Implementation SHA-256 `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B`.

`docs/normative/`, frozen recovery-program results, old conformance output, and
other artifacts bound to those predecessor digests remain historical evidence.
They must not be rewritten to look current. Any active compiler, Rule Catalogue,
conformance map, agent brief, or runtime handshake still bound to the predecessor
pair is `STALE` until regenerated and verified against
`docs/normative-pair.toml`. Sections from the predecessor and current pairs may
not be combined as one current contract.

## Current-system truth

Current source files, Cargo manifests and lockfile, generated metadata, compiler
diagnostics, tests, installed artifact hashes, store identity, and live runtime
observations are the evidence for current product support. Prose, reports,
graphs, and successful builds cannot by themselves establish D0/D1 acceptance,
runtime health, or `CURRENT_VERIFIED`.
