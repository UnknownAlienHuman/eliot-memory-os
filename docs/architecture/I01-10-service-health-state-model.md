## I1.10. Service health state model

The shared `ServiceProcessState` vocabulary is defined once in I14.20. This section defines its health dimensions and readiness interpretation; it does not create another lifecycle enum.

Health is a vector, not one boolean:

```text
liveness;
readiness;
freshness;
compatibility;
integrity;
capacity;
supervision coverage.
```

A component is `READY` only for the capabilities whose required dimensions pass. A stale graph can be alive and compatible but not fresh; it must not advertise current impact analysis.

`ServiceProcessState` describes one running process. `ModuleGenerationState` describes discovery, staging, activation, drain and retirement of a replaceable capability artifact. A process may be alive/READY while its generation is only STAGED or DEGRADED; the two state spaces are never merged into one enum, and route switching belongs to the separate `GenerationCutover` machine.

