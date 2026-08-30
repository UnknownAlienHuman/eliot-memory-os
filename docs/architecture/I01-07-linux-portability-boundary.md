## I1.7. Linux portability boundary

Linux is not a supported first-line target, but the following properties must not be coupled to Windows:

```text
module protocol messages;
module lifecycle;
store API;
canonical formats;
authority/fencing semantics;
job/checkpoint model;
agent interaction contracts.
```

The platform layer isolates:

| Windows | Future Linux |
|---|---|
| SCM demand-start | systemd socket activation |
| Task Scheduler | systemd timers |
| named pipes | Unix domain sockets |
| Job Objects | cgroups / process groups |
| DPAPI / Credential Manager | keyring / secret service |
| Windows notifications | desktop notification adapter |

Linux support begins only after CI, packaging, and fault tests on a real Linux installation.

---

