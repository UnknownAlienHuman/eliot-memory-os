## I5.23. Recovery/import inbox

Offline producers and legacy migration may submit signed/hashed `CanonicalWriteEnvelope` files to a recovery inbox:

```text
write temp;
flush/fsync;
atomic rename;
Kernel imports into ORS;
normal admission and receipt path applies;
file moves to applied/rejected/dead-letter with receipt sidecar.
```

Arbitrary `.surql` or vendor script is admin maintenance input and cannot enter the normal hot path.

---

