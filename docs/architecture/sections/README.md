# Generated semantic documentation sections

This directory defines the generated-section surface; it does not contain a
second normative edition.

The accepted books remain at:

- [`../ELIOT_ARCHITECTURE.md`](../ELIOT_ARCHITECTURE.md);
- [`../ELIOT_IMPLEMENTATION.md`](../ELIOT_IMPLEMENTATION.md).

Create a complete physical split locally with:

```powershell
python scripts/docs_router.py materialize --all --output .eliot-docs/all
```

The output contains:

```text
.eliot-docs/all/
├─ architecture/
│  ├─ 00-PREAMBLE.md
│  ├─ 01-A0.md
│  └─ ...
├─ implementation/
│  ├─ 00-PREAMBLE.md
│  ├─ 01-I0.md
│  └─ ...
└─ manifest.json
```

Every generated file is an exact byte range from one canonical source. The
manifest records source identity, order, line range, byte count, and SHA-256.
Materialization reconstructs both original files and fails on any gap,
overlap, reordering, or changed byte.

For normal agent work, do not materialize the whole corpus. Follow
[`../AGENT_READING.md`](../AGENT_READING.md) and materialize only the route for
the current changed paths and task.
