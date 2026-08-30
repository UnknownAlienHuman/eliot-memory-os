## I8.13. Watchdog failure

```text
SCM recovery policy and, when available, Host supervision observe process exit;
SCM/installer starts the last approved compatible generation;
Kernel/Governor lower Supervision axis;
Material work may continue only per policy and visible degradation;
Critical work pauses unless independent supervision is restored or Human explicitly accepts risk;
failed Watchdog does not repair itself;
repeated failure escalates through fallback notification.
```

If Host/OS/machine and fallback notification all fail, internal notification is impossible; this is platform/manual recovery boundary.

The fallback path is defined in I11.6 and remains independent of normal Kernel/UI delivery. `Host alive but unresponsive` is a distinct failure from Host exit: Watchdog uses the challenge/SCM path of I8.3, bounded restart intensity and then a persistent manual-recovery notification. Process survival never counts as responsiveness.

