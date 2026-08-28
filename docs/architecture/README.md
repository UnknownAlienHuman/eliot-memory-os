# ELIOT normative documentation

> Canonical navigation entrypoint. This file is not a third normative book.

ELIOT has one accepted normative pair on `main`:

| Role | Canonical file | Revision / edition | SHA-256 |
|---|---|---|---|
| Intent, theory, invariants, Hard Boundaries | [ELIOT Architecture](./ELIOT_ARCHITECTURE.md) | `4.5-draft` / `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Owners, contracts, defaults, failure behavior, migration | [ELIOT Implementation](./ELIOT_IMPLEMENTATION.md) | `0.29-draft` / `2026-08-28` | `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063` |

Machine identity and adoption status are in
[`../normative-pair.toml`](../normative-pair.toml); authority and branch rules
are in [`../ARCHITECTURE_CONTRACT.md`](../ARCHITECTURE_CONTRACT.md). There are
no alternate dated copies or predecessor books in the active checkout.

Use [INDEX.md](./INDEX.md) to route by entity, flow, or question. Do not load
both books in full for ordinary work.

## Minimal reading routes

- Mission and first orientation: Architecture introduction, `A1`, `A16.3`.
- Interpretation or rule conflict: `A0`.
- Core/Kernel/recovery: applicable `A2`, `A12–A13`; Implementation `I1`, `I2`,
  `I5`, `I14–I16`.
- Module or agent work: one `FunctionalCapabilityCell`, its exact contract and
  evidence handles, then the affected Edge Proof and Product Pulse.
- Current support claims: Implementation `I0.5` plus exact current
  source/build/runtime/store evidence.

Architecture outranks Implementation on semantic conflict. Canonical
Documentation does not prove that code exists, is installed, running, or
accepted. The honest product status remains `NOT_ACCEPTED / UNVERIFIED`.
