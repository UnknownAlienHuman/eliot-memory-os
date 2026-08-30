## I18.21. Local and CI parity

CI builds the ELIOT verifier/runner bootstrap and then calls the same versioned profiles used locally. Justfile/scripts are aliases only.

```text
local profile revision == CI profile revision;
executable/tool identities are pinned or recorded;
external binaries require digest/provenance receipt;
results share one schema and evidence model;
CI-specific environment differences are explicit profile dependencies;
no CI-only hidden verifier command list.
```

The minimal bootstrap build is the only unavoidable pre-run exception.

