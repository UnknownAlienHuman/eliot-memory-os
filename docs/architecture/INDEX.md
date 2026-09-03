<!-- generated: eliot-doc-shards-v1 -->
# ELIOT canonical topic index

For executable routing, use [`ROUTES.md`](ROUTES.md). For an exact section
handle, use [`HANDLE_INDEX.md`](HANDLE_INDEX.md). The table below preserves the
pre-sharding topic map; each handle now resolves to a bounded fragment.

## Preserved topic map

This file is a navigation projection over the accepted pair. It is not a third
normative book. Stable references are section handles, not line numbers.

Normative pair:

- [Architecture](./ELIOT_ARCHITECTURE.md) `4.5-draft`;
- [Implementation](./ELIOT_IMPLEMENTATION.md) `0.29-draft`.

Before implementation work, also read the repository workflow and active
workstream registry at the repository root.

## Status and interpretation

| Question | Read |
|---|---|
| Purpose, decision hierarchy, Hard Boundaries | `A0`, `A1` |
| Architecture change and conflict resolution | `A0.4`, `A0.6` |
| Current vs target support and evidence dimensions | `I0.3–I0.5`, `I0.13` |
| Documentation and pair identity | `I0.14`; `../ARCHITECTURE_CONTRACT.md` |
| Work-unit decomposition and development proof | `A10.4`, `A14.8`; `I2.17`, `I2.20–I2.23` |

## Core entities and owners

| Topic | Architecture | Implementation |
|---|---|---|
| Authority, principals, leases, epochs | `A2`, `A10.2`, `A12.2` | `I1.8`, `I6.10`, `I6.15` |
| Host and Kernel | `A2.2–A2.3`, `A13.2` | `I1.1–I1.13`, `I14–I16` |
| Governor and `eliotd` | `A2.2`, `A10`, `A12.3` | `I1.2`, `I1.8`, `I5.4–I5.7` |
| FunctionalCapabilityCell and crate topology | `A2.3`, `A14.8` | `I2.1–I2.25` |
| Canonical store and one write path | `A4`, `A12.3`, `A13.6–A13.9` | `I5.1–I5.27` |
| BlobStore | `A4.5`, `A12.8`, `A13.7` | `I5.2`, `I5.12–I5.14` |
| Tasks, sessions, durable work, swarm | `A10` | `I7`, `I10`, `I13–I14` |
| Evidence, instruments, verification, finish | `A5.5`, `A10.8`, `A14.6–A14.8` | `I7.9`, `I7.27`, `I10`, `I17–I18` |
| WorkScope and onboarding | `A3` | `I4` |
| Memory and cognitive inheritance | `A4`, `A14.1–A14.4` | `I12` |
| Understanding, causality, graphs | `A5–A6` | `I6.16`, `I10`, `I12` |
| Context Compiler, cues, attention, Skills | `A7` | `I7.11–I7.29`, `I12` |
| Watchdog | `A8`, `A13` | `I1`, `I8`, `I14`, `I16` |
| Dreamer | `A9` | `I9` |
| Doctor and recovery | `A13.3–A13.12` | `I14–I16` |
| Human control and configuration | `A11` | `I3`, `I11` |
| Security, provenance, influence, privacy | `A12` | `I5.26`, `I6.15`, `I15` |
| Learning and Meta | `A14` | applicable `I12–I18` contracts |

## End-to-end flows

| Flow | Architecture | Implementation |
|---|---|---|
| Install/start/attach | `A11`, `A13` | `I1`, `I3`, `I7.3–I7.8` |
| Scope/task onboarding | `A3`, `A7`, `A10.1` | `I4`, `I7.8`, `I7.17` |
| Capture and canonical write | `A4`, `A12.3` | `I5.4–I5.8`, `I5.19`, `I5.27` |
| Read and Active View | `A5–A7` | `I5.20`, `I7.11`, `I12` |
| External effect | `A10.2–A10.3`, `A12` | `I1.8`, `I6.6`, `I6.10`, `I14` |
| Verification and strict finish | `A5.5`, `A10.8` | `I7.9`, `I17–I18` |
| Agent delegation/swarm | `A10.4–A10.7` | `I2.17`, `I7`, `I10`, `I13–I14` |
| Module generation promotion | `A2.3`, `A13.3`, `A14.8` | `I2.10`, `I14.14`, `I18` |
| Failure/recovery | `A8`, `A13` | `I1`, `I14–I16` |
| Learning and improvement | `A14` | `I2.25`, `I7.25`, applicable Meta contracts |
| Backup/restore/migration | `A12.8`, `A13.7–A13.8` | `I5.10–I5.14`, `I19–I20` |

## Working rule

Open only the sections required for the current causal property and one-hop
edges. A branch, report, audit, donor document, or generated projection cannot
change the meaning of the pair. Claims about current code/runtime/store require
exact current evidence in addition to these documents.
