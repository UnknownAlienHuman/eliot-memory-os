# Dependency policy

## `sha2` 0.10.9

Cross-process host evidence defines executable, argument, environment,
working-directory, bundle, prompt, process, stdout, and stderr identities as
SHA-256 values. `sha2` is a pure Rust MIT/Apache-2.0 implementation, supports the
workspace MSRV, adds no service or runtime process, and is used only for bounded
in-process hashing. BLAKE3 remains the internal deterministic-ID and
content-addressing primitive elsewhere.
