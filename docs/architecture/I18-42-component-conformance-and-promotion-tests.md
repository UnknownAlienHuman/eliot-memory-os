## I18.42. Component conformance and promotion tests

Every multi-contour component shares one conformance corpus across pure core, WASM and native process backends.

Required classes:

```text
contract/WIT schema and interface digest;
unknown-field/version compatibility;
property and differential behavior;
capability denial;
memory/table/stack/output/host-call limits;
epoch/fuel cancellation and trap containment;
deterministic replay;
state export/import and incompatible migration;
shadow divergence;
canary rollback and old-epoch rejection;
AOT/cache compatibility with exact Wasmtime engine.
```

Production promotion consumes a `ComponentPromotionReceipt` that references all required evidence; it cannot infer success from a build or one test suite.

