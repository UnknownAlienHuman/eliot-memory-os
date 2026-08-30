# Appendix D. Reason codes and directive dispositions

> **Projection lifecycle label (artifact-local):** `CURRENT_DOCUMENTATION_PROJECTION`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`. `docs/generated/reason-codes.md` is generated from the exact current I7.20 registry and includes bridge-only migration aliases. The projection proves documentation-set equality, not runtime implementation.

Owner: I7.20. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Historical source: `_REVIEW/baseline_sections/Appendix_D.md`.

Rules that remain normative here:

```text
codes are additive and versioned;
a code is never reused with different meaning;
unknown codes preserve their raw identity and degrade through the stable AgentResponseDisposition;
an unresolved unknown code opens a Problem rather than inventing a lifecycle state;
a directive names the code, preserved state and next admissible action;
legacy aliases are translated only at a bridge boundary and never become canonical names.
```

---

