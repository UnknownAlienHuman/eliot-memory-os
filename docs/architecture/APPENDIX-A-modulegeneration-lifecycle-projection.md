# Appendix A. ModuleGeneration lifecycle projection

The normative `ServiceProcessState`, `ModuleGenerationState` and `GenerationCutover` vocabularies live in I14.20. This appendix is a compact rendering/health profile and cannot introduce alternative states.

`ModuleGenerationState` is separate from `ServiceProcessState`: process health answers whether one process is running; generation state answers whether a capability artifact is discovered, staged, active, draining or retired.

## A.1. States

The only normative `ModuleGenerationState` transition set is I14.20. This appendix renders current state and health dimensions; it does not repeat or redefine the machine.

Upgrade is not a `SWITCHING` generation state. It is two generation records plus the separate I14.20 `GenerationCutover` machine and receipt; this prevents process health, artifact lifecycle and route authority from collapsing into one status.

## A.2. Health dimensions

```text
liveness — process responds;
readiness — can accept new work;
freshness — derived state current enough;
compatibility — protocol/contracts match;
integrity — artifact/config/state valid;
capacity — resource budget available.
```

Green “healthy” is not used when one dimension is unknown/degraded.

## A.3. Restart child classes

The canonical restart classes, group strategies, intensity budgets and quarantine rules are defined in I14.10. A Module manifest selects one of those contracts; Appendix A does not create additional restart semantics.

---
