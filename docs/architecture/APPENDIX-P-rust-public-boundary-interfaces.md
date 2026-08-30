# Appendix P. Rust public boundary interfaces

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_CANDIDATE_MAPPING`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. `docs/generated/rust-boundary-interfaces.md` preserves the detailed pre-extraction candidate mappings, including stable section P.12, plus a post-integration coverage-gap supplement. Candidate Rust syntax is not a normative signature, generated source or implementation proof.

Owners: the I-section owning each boundary and a future admitted `eliot-contracts` catalogue for normalized serialization. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_P.md`.

Rules that remain normative here:

```text
public types carry explicit contract/schema versions and validated newtype identities;
major incompatibility fails before effects; additive minor compatibility is declared explicitly;
authority, scope, effect, privacy, ordering and receipt fields are never silently defaulted;
closed control variants fail when unknown; additive reason/telemetry values preserve Unknown(raw);
canonical hashes use normalized versioned serialization;
public signatures do not leak vendor/upstream types;
in-process and process-boundary implementations must produce equivalent receipts and failures;
no boundary may read implicit global mutable current principal, scope or task state;
later-wave interfaces remain uncovered TARGET gaps until generated from an admitted catalogue and proven against source.
```

---

