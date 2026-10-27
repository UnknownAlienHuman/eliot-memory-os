# V3 Store candidate assets

**Status: design-only Slice 0 input. Not runtime code, not a second Store contract, and not proof that SurrealDB 3.3.4 accepts the complete bundle.**

The normative owner remains [Implementation](../IMPLEMENTATION.md), especially §§4–6 and §12. The [analysis registry](../ANALYSIS-REGISTRY.md) records the exact proof ceiling. These files make the selected schema and read/query shapes reviewable before production code exists.

## Files

- [`0001-base.surql`](0001-base.surql) — candidate first migration body for the six Base tables, fields, analyzers and indexes.
- [`queries-base.surql`](queries-base.surql) — named fixed-query shapes for exact readers, lexical retrieval, backup paging and schema readback.

The runtime must not load this directory dynamically. Production code will embed or include exact checked assets, compute their digests, bind only closed DTO variables and compare the live catalog against an expected catalog generated from the **same qualified asset bytes**.

## Exact target

```text
SurrealDB tag/commit: v3.3.4 / 1ac2b1dba7cd177621a4cf5d507caebeb2414395
transport:            authenticated query-only JSON WebSocket
storage candidate:    external RocksDB with sync=every
schema:                STRICT database, six SCHEMAFULL tables
```

Exact-tag source/tests already support the selected `DEFINE TABLE`, `DEFINE FIELD`, `READONLY`, type, analyzer, FULLTEXT, UNIQUE, plain `INFO`, numbered match and score forms. They also establish that a unique tuple containing `NONE` or `NULL` is skipped, that `READONLY` allows initial and same-value writes, and that persisted `DEFINE PARAM` plus index overwrite participate in tested transaction cancellation cases.

They do **not** prove the complete Eliot wrapper over every DDL statement, bound metadata value, query DTO, conflict path or Windows/RocksDB failure. Slice 0 must execute the exact bytes and retain the result.

## Runner-owned wrapper

`0001-base.surql` is one candidate transaction body. The runner:

1. selects the configured namespace and STRICT database through the authenticated Store connection;
2. binds exactly:
   - `$bound_schema_bundle_format`;
   - `$bound_schema_generation`;
   - `$bound_schema_bundle_sha256`;
3. executes the file as one query call;
4. checks every returned statement status;
5. on success, reads the three params plus plain `INFO FOR DB` and `INFO FOR TABLE` for every owned table;
6. sorts owned map keys and compares exact server-canonical `DEFINE` strings for the pinned version;
7. classifies a lost reply only through exact metadata and catalog readback.

The schema-bundle digest preimage is defined by Implementation and includes runner protocol, wrapper template, ordered UTF-8/LF asset bytes and expected-catalog template. Bound metadata values are outside the preimage.

## Deliberate qualification gaps

The candidate migration uses only per-field assertions whose exact language form is already supported by the pinned parser/runtime evidence. The following invariants remain owned by fixed writers and must be exercised in Slice 0 before any server-side cross-field assertion is promoted into the migration:

- observation inline/blob XOR and exact byte length/digest;
- memory validity interval ordering;
- complete-address tuple and derived digest agreement;
- job claim-owner/expiry pair;
- job request blob/length/digest tuple;
- job state/slot-key agreement;
- stream sequence and revision allocation;
- replay identity, set cardinality and concurrency.

This is intentional. A guessed `$before`/`$after` expression inside a checked-in migration is worse than an explicit open qualification item.

`queries-base.surql` is a review corpus of named statements. The production client must split and embed the selected blocks; it must never expose the whole file, arbitrary SurrealQL, dynamic grammar or a generic CRUD surface.

## Slice 0 acceptance

The pack becomes production-qualified only after the exact Windows binary/profile demonstrates:

- parse and execution of every DDL asset in the exact runner order;
- bound metadata variables inside the three `DEFINE PARAM` statements;
- rollback after injected failure at each table/field/analyzer/index boundary;
- exact catalog strings and metadata readback after commit and lost reply;
- positive/negative immutable-field and closed-state writes;
- concurrent unique-key and `FOR UPDATE` behavior;
- exact query DTO decoding and stable-key continuation;
- representative `EXPLAIN` for every required reader;
- bounded lexical top-K behavior, including score `0`;
- crash/restart admission with RocksDB `sync=every`.

Until then, these files remain `DECIDED / NOT QUALIFIED` design inputs.