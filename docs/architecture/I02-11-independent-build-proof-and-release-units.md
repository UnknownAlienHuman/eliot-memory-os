## I2.11. Independent build, proof and release units

Every first-party crate must have an independently selectable proof surface that matches its actual proof ceiling:

```text
`cargo check -p <crate>` or equivalent shape or build proof;
behavioral unit, property, or model tests only where the crate actually owns behavior;
a contract, facade, or data-only crate may use compile, schema, or consumer-contract proof instead of artificial unit tests;
public contract selector when applicable;
source/context/build metrics and clear reverse-dependency impact;
explicit declaration of behavior that cannot be proved package-locally.
```

Absence of a meaningless package-local test is not a defect when the proof ceiling and mandatory consumer or edge profile are stated. But absence of any independently invocable proof makes the capability `CURRENT_UNVERIFIED` or `TARGET`, not supported.

A release unit may contain several crates:

```text
eliotd bundle;
Kernel bundle;
Watchdog bundle;
store bridge bundle;
agent bridge bundle;
optional Module bundle.
```

Runtime bundle manifest records the exact crate and artifact graph, protocol range, SBOM, symbols, license report, and rollback compatibility.

### When a separate workspace or lockfile is required

```text
a heavy dependency island causes measured cache invalidation;
a different toolchain, target, or profile is required;
an upstream project must remain in delivered form;
a Module is released independently;
license or MSRV requires containment;
core-workspace feature unification becomes unstable.
```

A separate workspace receives no ELIOT authority of its own. Compatibility is checked through protocol, schema, and artifact digests and integration proofs.

