## I2.12. Third-party Rust adoption rule

Before implementing a subsystem, maintainers search for a suitable upstream project. Adoption requires:

```text
compatible licensing;
acceptable maintenance and frozen-project risk;
Windows support for the required path;
bounded dependency/security footprint;
clear failure semantics;
thin facade/process bridge;
export/removal path;
no upstream types in public ELIOT contracts.
```

Order of preference:

```text
use upstream unchanged behind a facade;
wrap an executable or service behind EBP;
contribute upstream;
fork only with explicit divergence ownership;
write from scratch only for genuinely unique ELIOT contract.
```

An upstream project does not dictate ELIOT crate topology. Its source may live in a separate workspace or bundle.

