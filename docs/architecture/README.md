<!-- generated: eliot-doc-shards-v1 -->
# ELIOT documentation router

Do not open the former monoliths as task context.

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
- [Exact handle index](HANDLE_INDEX.md)
- [Architecture bounded index](architecture/README.md)
- [Implementation bounded index](implementation/README.md)
- [Architecture authority](../ARCHITECTURE_CONTRACT.md)
- [Dependency policy](../DEPENDENCY_POLICY.md)
- [Pre-sharding navigation snapshots](navigation-history/)

Normative pair: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.

`ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` remain only to preserve
incoming file and heading links. Their canonical content has moved to fragments.
