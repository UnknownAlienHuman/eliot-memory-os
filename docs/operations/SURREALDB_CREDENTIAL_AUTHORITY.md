# SurrealDB credential authority

## Authority

For the installed per-user `default` instance, the only production credential
authority is the current Windows user's Credential Manager entry with logical
ID `surreal-runtime/default`. Governor resolves the value inside the native
Windows credential boundary and supplies it to the SurrealDB child process
without placing it in TOML, command-line arguments, logs, reports, canonical
memory, or publication artifacts.

`credential_provider = "windows_credential_manager"` selects that authority.
The `password_file` field is retained only as a migration locator required by
the typed configuration. It is ignored while the Windows provider is selected,
must not exist in a steady-state installation, and must never be treated as a
fallback. A legacy password file is permitted only for an explicitly gated,
isolated migration or test.

The portable development template uses the separate logical ID
`surreal-runtime/local-dev`; an installed instance must use its own configured
logical ID and must not share plaintext credentials with another instance.

## Read-only verification

Run these commands with the installed Governor and its active configuration:

```powershell
eliot-governor --config $env:LOCALAPPDATA\Eliot\config\governor.toml credentials validate
eliot-governor --config $env:LOCALAPPDATA\Eliot\config\governor.toml daemon health --instance default
eliot-governor --config $env:LOCALAPPDATA\Eliot\config\governor.toml security scan-canonical
```

Acceptance requires a present Windows credential reference, no credential value
in TOML or argv, daemon health `ready`, and a complete canonical scan. These
commands emit metadata or fingerprints only; they must never print the secret.

## Migration and rollback

If a legacy credential still authenticates, provision a distinct Windows
credential first and use `security rotate-legacy-credential`. Verify
authentication and a full daemon restart before removing any plaintext copy.
Do not restore a plaintext file as rollback. Rollback is an operator-controlled
credential rotation through the same Windows authority, followed by a bounded
restart and the read-only checks above.
