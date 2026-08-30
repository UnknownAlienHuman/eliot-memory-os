## I18.19. Specialized instrument profiles

Profiles are enabled progressively:

```text
Baseline D1:
  compiler, test and rustfmt observation;

D2:
  dependency, snapshot and Windows runtime where required;

D3:
  architecture via Cargo + rust-analyzer/SCIP;

Targeted escalation:
  test-strength, concurrency, unsafe/FFI and performance.
```

Each profile has independent fixtures, parsers, resource policy, coverage semantics and context projection. Adding a profile does not widen every change's test plan.

