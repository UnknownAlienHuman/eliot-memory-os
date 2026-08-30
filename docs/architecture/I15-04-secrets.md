## I15.4. Secrets

The first Windows line uses Windows Credential Manager/DPAPI-protected `SecretRef` values behind the ELIOT secret-provider facade.

Rules:

```text
secret values never in TOML, CLI args, model packet, logs, canonical memory or blobs;
child receives only needed secret via protected handle/pipe;
secret access has audit receipt without value;
rotation invalidates dependent Sessions/modules;
compromise opens Incident and revokes route.
```

For the Host-managed `surreal.exe` dependency, the immutable process manifest contains only secret references. Host materializes a fresh child-only environment block or another upstream-supported protected one-shot channel immediately before process creation; secret values are never placed in argv, HostStateJournal, Module Catalog, crash command text or reusable environment snapshots. If an upstream version can receive a required secret only through a command-line argument or another observable unsafe channel, that version is not admitted.

The store bridge receives a separate least-privilege database client credential through the same secret-provider boundary. Server bootstrap/admin and normal application credentials are distinct, independently rotatable references. Startup diagnostics may record which reference/version was used, never the value. Sibling processes inherit neither credential.

Future Linux uses secret-service/keyring adapter.

### Data at rest

ELIOT does not invent a database-encryption scheme inside domain code.

```text
installation paths use explicit ACLs and a dedicated service/user identity;
System Survey records whether the containing Windows volume is protected by BitLocker/device encryption;
sensitive WorkScope policy may require an encrypted volume before capture;
portable backups/ECXF exports are encrypted by default with a versioned envelope key protected by the installation/user secret provider;
ORS/blob/export encryption is implemented behind `eliot-crypto`, using audited primitives/libraries and a replaceable format version;
loss of the key is a recovery failure, never a reason to write plaintext silently.
```

The ControlBoard shows the actual at-rest profile. Linux support later maps the same contract to platform volume/key services; it does not change canonical semantics.

