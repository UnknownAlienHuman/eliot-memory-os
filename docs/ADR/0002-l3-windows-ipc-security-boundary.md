# ADR 0002: L3 Windows IPC security boundary

Known facts:
- Tokio 1.52.3 creates named pipes with a null `SECURITY_ATTRIBUTES` pointer by default.
- Phase L3 requires a current-user pipe DACL, while the existing workspace forbids unsafe code.
- `windows-sys 0.61.2` is already present in `Cargo.lock` through Tokio and `windows-service`.

Causal mechanism:
- A per-start bearer token authenticates the relay, but it does not prevent unrelated local users from opening the pipe and consuming connection capacity.
- Passing an explicit Win32 security descriptor to Tokio requires one unsafe FFI call whose pointer lifetime must be audited.
- Keeping that call in a tiny internal crate prevents unsafe code from spreading into the daemon, engine, store, or types crates.

Conclusion:
- Add `eliot-windows-ipc` as the sole unsafe Win32 descriptor boundary.
- Grant pipe access only to the resolved current-user SID and LocalSystem.
- Keep token rotation, handshake validation, replay defense, deadlines, and action authority in safe Rust above this transport helper.
- This adds no service, process, runtime, network path, or new third-party version to the hot path.
