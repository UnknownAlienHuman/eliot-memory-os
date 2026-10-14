<!-- generated: eliot-doc-shards-v1 -->
# ELIOT documentation router

Do not open the former monoliths as task context.

1. Check the owning Issue's `## Read` declaration and applicable `AGENTS.md`.
2. Run the verified reader for the owning Issue and exact mutable path:

   ```text
   python scripts/docs_read.py read --issue <number> --path <repository/path> --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

3. Open the verified bundle and read every required item before mutation.
4. Record the route/read receipt IDs, verified bundle SHA-256, matched routes,
   required handles, and explicit reading attestation.

A route alone is navigation, not reading evidence. The local
`.eliot/docs-read-bundle.md` and read receipt are not committed.

The Issue's `## Read` list, the Decision Safety Floor and applicable `AGENTS.md`
files form the required bundle. Path routes are optional pointers. Without an
owning Issue, use `--path <repository/path> --topic "<causal property>"` to resolve
required reading from the paths. [`READING_PROTOCOL.md`](READING_PROTOCOL.md)
explains this command; navigation links do not add required reading. Declare
additional content in the Issue before rerunning the verified reader.

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

Normative pair: `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`.

`ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` remain only to preserve
incoming file and heading links. Their canonical content has moved to fragments.
