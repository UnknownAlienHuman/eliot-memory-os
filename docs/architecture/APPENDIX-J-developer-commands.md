# Appendix J. Developer commands

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_TARGET`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. The detailed candidate catalogue is `docs/generated/developer-commands.md`, assembled from the exact pre-extraction snapshot plus a post-integration support note. It is not compiled help and cannot make a command supported.

Owners: I10.8 and the owning capability contract of each command. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_J.md`.

Rules that remain normative here:

```text
one admitted command catalogue defines supported CLI surfaces;
a command uses the same Kernel/Governor/Instrument contracts as every other front door;
help/schema output and execution receipts identify the exact supported revision;
expiring migration shims cannot define different semantics or authority;
missing command support returns a typed unsupported state rather than a prose promise;
no later-wave capability receives a CLI command merely because the capability is documented.
```

---

