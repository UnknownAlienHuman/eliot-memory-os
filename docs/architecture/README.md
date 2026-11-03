<!-- generated: eliot-doc-shards-v1 -->
# Retained V2 documentation and shared routing

Current V3 work starts at the [V3 task map](../v3/README.md). The fragments below
preserve V2 source evidence and still serve explicit V2/shared tooling tasks; they
are not the V3 specification or its default context. Pure V3 reading is independent
of their handle index and pair receipt. Do not open the former monoliths as task context.

1. Read [`READING_PROTOCOL.md`](READING_PROTOCOL.md).
2. Run the verified reader for the exact path and causal property:

   ```text
   python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

3. Open the verified bundle and read every required item before mutation.
4. Record the route/read receipt IDs, verified bundle SHA-256, matched routes,
   required handles, and explicit reading attestation.

A route alone is navigation, not reading evidence. The local
`.eliot/docs-read-bundle.md` and read receipt are not committed.

## Navigation

- [Mandatory verified-reading protocol](READING_PROTOCOL.md)
- [Task/path route matrix](ROUTES.md)
- [Exact numeric-handle index](HANDLE_INDEX.md)
- [Decision Anchor index](DECISION_ANCHOR_INDEX.md)
- [Architecture bounded index](architecture/README.md)
- [Implementation bounded index](implementation/README.md)
- [Architecture authority](../ARCHITECTURE_CONTRACT.md)
- [Dependency policy](../DEPENDENCY_POLICY.md)
- [Pre-sharding navigation snapshots](navigation-history/)

Retained V2 pair: `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`.

`ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` remain only to preserve
incoming file and heading links. Their canonical content has moved to fragments.
