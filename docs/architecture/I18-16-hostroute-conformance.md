## I18.16. Host/route conformance

Provider-free protocol tests and bounded live probes are mandatory for exact `RouteFingerprint`. First route acceptance includes crash/cancel/restart, actual-route receipt, bounded artifacts/effects, no orphan descendants and correct interaction with InstrumentRunner/verifier callbacks.

Native resume/fork/replay/rehydration are tested separately. A route cannot claim independent audit credit when actual provider/model or lineage is unknown.

Translation/route conformance also covers mixed reasoning-visible deltas, malformed/partial streams, reconnect and cancellation after partial output, preservation invalidation, helper APIs that might drop diagnostics, header/error redaction, policy-branch reachability and session-revision races. A buffered restream or provider-specific request mutation must produce an explicit `TranslationReceipt` and RouteFingerprint delta.

