## I11.6. Windows notifications

`eliot-notify.exe` is a per-user one-shot notification adapter. Normal delivery is launched through the authorized User Broker. A separately registered signed Task Scheduler fallback may launch it without Kernel/User Broker only to read a minimal signed envelope produced by Watchdog.

```text
normal:
  canonical notification → User Broker → native toast → authenticated local UI;

control-loss fallback:
  Watchdog spool + Windows Event Log → signed minimal envelope
  → Task Scheduler / next `eliot` launch → `eliot-notify` or recovery banner;

no interactive user session:
  no immediate desktop toast is promised; Event Log/spool persist the obligation.
```

The fallback envelope contains only incident class, installation identity, timestamp, evidence digest and `eliot recovery status` instruction. It contains no secrets, project content or large evidence and grants no repair authority. Loss of notification delivery never resolves the underlying Problem/Critical Attention.

The Host/Kernel service does not attempt to display desktop toasts directly. Notification adapter loss degrades delivery only; canonical notification state or Watchdog control-loss evidence remains durable in its owning store.

