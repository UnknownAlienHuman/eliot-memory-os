## I10.1. Bridge doctrine

Third-party project remains upstream-shaped. ELIOT integration adds:

```text
one process/container boundary when practical;
one thin protocol adapter;
one capability manifest;
one health/failure translation;
one update/removal path.
```

Do not fork or copy internal code unless upstream cannot be used safely and replacement benefit is demonstrated.

