## I14.3. Control Reserve

Capacity reserved independently at every applicable bottleneck:

```text
Kernel control channel and runnable task slots;
ORS write budget and durable queue bytes;
store connection/transaction slot and pending-write memory;
process launch/termination path;
notification/inbox transition;
CPU task slot and protected memory reserve;
pipe/message bytes, file descriptors/handles and disk-queue capacity.
```

Used for:

```text
cancellation;
fencing;
health;
Critical Attention/Problem/Incident transition;
critical telemetry;
safe shutdown;
recovery.
```

Normal workload cannot consume it.

Reserve accounting is multidimensional. Admission checks the exact bottleneck vector rather than one scalar percentage; exhaustion of CPU, memory, pipe bytes, ORS writes, disk queue or handles may independently close normal/background admission while preserving the applicable recovery/control lane. Each disposition names the exhausted resource and the work shed, deferred or quarantined.

`Last-resort Control Slot` is preallocated outside normal accounting for reserve-exhaustion/gap record. If unavailable, system enters platform/manual recovery boundary.

