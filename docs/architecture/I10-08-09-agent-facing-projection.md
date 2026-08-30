### I10.8.9. Agent-facing projection

Instrument Plane does not add dozens of hot tools. The existing `eliot.query`/`eliot.verify` surface exposes four semantic intents:

```text
verify(profile, scope);
inspect(definition|references|implementations|impact|tests|architecture, target);
assist(compiler|test-strength|concurrency|windows-runtime|dependency|performance, target);
evidence(handle, bounded slice).
```

The result contains compact facts, primary failures, conflicts, unknowns, exact reruns and unexpanded raw handles. Backend names are hidden unless the agent diagnoses disagreement or asks for provenance.

An agent may run a direct shell command for exploratory feedback when its host policy allows it. Such output is captured as an observation with the actual Governance Profile; it does not satisfy a registered verifier or finish obligation merely because the command exited successfully. Canonical proof requires either re-execution through the applicable InstrumentProfile or exact ProcessEvidence imported through the same profile contract. Watchdog treats an attempt to present an ungoverned shell result as canonical proof as a protocol-discipline signal, not as an automatic security Incident.

