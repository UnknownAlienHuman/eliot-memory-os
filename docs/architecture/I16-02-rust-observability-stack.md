## I16.2. Rust observability stack

DEFAULT:

```text
tracing + tracing-subscriber;
non-blocking rolling file appender;
OpenMetrics endpoint via lightweight Rust metrics exporter;
optional OTLP bridge module, disabled by default;
Windows Event Log for Host/Kernel critical startup/recovery in `system_service` profile;
protected rolling-file/event-spool fallback in `user_mode` and portable profiles;
structured crash report + symbol artifact.
```

