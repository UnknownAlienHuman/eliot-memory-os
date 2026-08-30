## I5.1. Storage boundary

The domain system sees the `CanonicalStoreService` interface, not SurrealDB.

```text
writes:
  eliotd builds PreparedTransition
  → Kernel stages/orders/authorizes
  → store bridge executes named transaction;

reads:
  eliotd uses Kernel-issued read capability
  → bounded named read or hot mirror
  → store bridge/current storage implementation.
```

Storage bridge process:

```text
owns credentials;
owns vendor SDK;
validates protocol and schema generation;
executes named operations;
returns receipts and exact errors;
has no model/agent surface;
cannot invent semantic transitions.
```

