## I8.2. Independent observation routes

At least one route for process/integration health must not depend on `eliotd` self-report.

Windows sensors:

```text
SCM service state;
process handle and exit code;
Job Object membership/resource counters;
named-pipe availability and handshake;
filesystem change journal / watched paths, including persisted USN cursor replay on wake for registered Windows WorkScopes;
module artifact and config hashes;
Host-managed SurrealDB process health from an independent read-only probe;
Kernel heartbeat;
agent hook/bridge event cadence;
network/listener inventory for registered services;
security audit signals from OS and bridges.
```

Independent observation proves event existence, not principal attribution. Attribution requires correlation identity; otherwise origin remains `unknown`.

Observation coverage is explicit:

```text
CONTINUOUS       — sensor observed the interval live;
JOURNAL_REPLAYED — OS/application journal covered the interval after wake;
PARTIAL          — some sources or sequence ranges are missing;
BLIND            — no competent source covered the interval;
UNKNOWN          — coverage cannot be established.
```

A persisted USN/host-event cursor lives in HostStateJournal/Watchdog spool, not canonical memory. Replay is bounded, records journal wrap/gaps, and emits an `ObservationCoverageManifest`; it cannot reconstruct hidden tool intent or principal attribution from file changes alone. Push claims are limited to the observed/replayed channels.

