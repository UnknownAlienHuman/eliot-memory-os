## I1.12. Compatibility and rollback boundary

Every process handshake exchanges:

```text
protocol range;
contract-set digest;
canonical format range;
Architecture source digest plus externally sealed NormativePairIdentity receipt;
module generation and Authority Epoch;
required/optional capabilities;
state migration class.
```

Rollback is allowed only to an artifact compatible with current durable formats and epoch lineage. “Last known good” means **verified compatible with current state**, not merely “previously launched”.

