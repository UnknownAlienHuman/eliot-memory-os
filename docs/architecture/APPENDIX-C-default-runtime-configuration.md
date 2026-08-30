# Appendix C. Default runtime configuration

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_CANDIDATE`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `FORBIDDEN`. The detailed profile is `docs/generated/default-runtime-configuration.md`; the machine candidate is `config/defaults.generated.toml`. Both are deterministically retained planning projections. The TOML contains a mandatory rejection guard and is not an admitted runtime config.

Owners: I2.16, I14.28 and Human policy surfaces. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_C.md`.

Rules that remain normative here:

```text
configuration schema and defaults remain replaceable projections, not Architecture invariants;
effective configuration is immutable, versioned and visible through its snapshot/receipt;
defaults never silently widen authority, privacy, cost, disclosure or external access;
unknown or invalid load-bearing configuration fails to a typed degraded/blocked state;
configuration changes run affected contract, recovery and Product Pulse checks;
measured profiles replace candidate values rather than accumulating prose overrides;
absence of a post-integration feature default means disabled, unqualified or unsupported—not permissive implicit behavior.
```

---

