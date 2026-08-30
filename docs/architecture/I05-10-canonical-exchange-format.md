## I5.10. Canonical Exchange Format

`ECXF/1` enables database replacement.

```text
manifest.json
schema/
events/*.ndjson.zst
projections/*.ndjson.zst
blobs/<residency-key-digest>/<content-digest>.blob
receipts/*.ndjson.zst
integrity.json
privacy-purge-ledger.json
```

The manifest contains:

```text
format version;
source store adapter/version;
Architecture source digest plus externally sealed NormativePairIdentity receipt;
scope/revision ranges;
checksums;
opaque blob residency identities plus retention/erasure domains;
encryption/compression;
missing/unsupported features;
purge state;
export receipt.
```

Export is independent of SurrealQL.

### Consistent export boundary

An ECXF export is tied to an `ExportFence` containing schema/store generation, scope revisions, Ordering Heads, event range and blob residency/reachability manifest. The bridge uses a database-supported consistent snapshot/transaction when available. Otherwise it records a base fence, exports immutable history/projections, tails canonical events to a final fence and briefly quiesces affected writes for final reconciliation. If neither route can prove a coherent boundary, the export fails; mixing unrelated table moments into one “backup” is forbidden.

