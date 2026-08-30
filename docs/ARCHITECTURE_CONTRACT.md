# Architecture authority

This file is the repository authority and navigation contract. It is not a
third normative book.

## Accepted sharded normative pair

The 2026-08-28 adopted semantic byte streams are unchanged. Only their
repository layout changed: each stream is reconstructed deterministically
from ordered fragments and verified against the original SHA-256.

| Authority | Canonical manifest and entry | Revision | Edition | Reconstructed SHA-256 |
|---|---|---|---|---|
| Intent, theory, invariants, and Hard Boundaries | [`docs/architecture/architecture/manifest.json`](architecture/architecture/manifest.json) · [bounded index](architecture/architecture/README.md) | `4.5-draft` | `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Target owners, contracts, defaults, failure behavior, and migration | [`docs/architecture/implementation/manifest.json`](architecture/implementation/manifest.json) · [bounded index](architecture/implementation/README.md) | `0.29-draft` | `2026-08-28` | `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063` |

The machine-bindable adoption receipt is [`docs/normative-pair.toml`](normative-pair.toml). Its pair key remains `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b` because the reconstructed canonical bytes are unchanged.

The historical paths [`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) and [`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) are compact compatibility maps. They preserve incoming file and heading links,
but agents must not load them as the documentation payload.

Use [`docs/architecture/READING_PROTOCOL.md`](architecture/READING_PROTOCOL.md),
[`docs/architecture/ROUTES.md`](architecture/ROUTES.md), and
[`docs/architecture/HANDLE_INDEX.md`](architecture/HANDLE_INDEX.md) for bounded routing.

Architecture still prevails over Implementation on semantic conflict. A layout
migration does not promote target behavior to current support; product status
remains `NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.

## Preserved pre-sharding authority contract

> The following text is retained as migration evidence. Where it calls the
> two former monolith paths canonical files, the sharded authority section
> above supersedes only that repository-layout statement.

# Architecture authority

This file is the repository authority and navigation contract. It is not a
third normative book.

## Accepted normative pair

On 2026-08-28 the Architecture Owner adopted the exact English pair below as
ELIOT's sole current normative pair.

| Authority | Canonical repository file | Revision | Edition | SHA-256 |
|---|---|---|---|---|
| Intent, theory, invariants, and Hard Boundaries | [`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) | `4.5-draft` | `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Target owners, contracts, defaults, failure behavior, and migration | [`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) | `0.29-draft` | `2026-08-28` | `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063` |

The machine-bindable adoption receipt is
[`docs/normative-pair.toml`](normative-pair.toml). Its pair key is
`sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.
Only the two document digests form the normative pair. The receipt, indexes,
registries, issues, tests, audits, and generated projections are evidence or
navigation and cannot become a third normative source.

Architecture prevails over Implementation on semantic conflict. Adoption does
not promote a target mechanism to current implementation support. Product status
remains `NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.

## Repository location and branch authority

The canonical files above live on `main`. A copy in another branch, worktree,
package, report, prompt, or agent memory has no current authority. Agents must
resolve current work through `AGENTS.md`, `WORKFLOW.md`, and
`workstreams/ACTIVE.toml` before using documentation.

There are no checked-in dated aliases or predecessor books. The superseded pair
had these digests:

- Architecture: `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8`;
- Implementation: `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B`.

Those bytes and their historical audits remain available through Git history
and issue/PR records only. They must not be restored into the active checkout or
combined with current sections as one contract. Any compiler, Rule Catalogue,
conformance map, brief, or runtime handshake still bound to the predecessor is
`STALE` until regenerated and verified against `docs/normative-pair.toml`.

Use [`docs/architecture/README.md`](architecture/README.md) and
[`docs/architecture/INDEX.md`](architecture/INDEX.md) for bounded routing.

## Current-system truth

Current source files, Cargo manifests and lockfile, generated metadata, compiler
diagnostics, tests, installed artifact hashes, store identity, and live runtime
observations are evidence for current support. Prose, reports, graphs, branch
names, successful builds, and test counts cannot by themselves establish
runtime health, D0/D1 acceptance, or `CURRENT_VERIFIED`.
