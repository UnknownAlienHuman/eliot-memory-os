## I5.17. Semantic command families and activation

Implementation defines a small set of semantic command **families**; exact variants are generated from the active contract catalogue. A permanent prose list of every anticipated future command is forbidden because it becomes a feature checklist and a second schema registry.

```text
Capture and source observation;
Task/WorkScope/plan state;
Epistemic revision and conflict/attention;
Canonical transition and receipt;
Instrument, verification and finish;
Authority, lease, capability and external effect;
Session, agent attempt, coordination and integration;
Module/config/lifecycle and recovery;
Audit/telemetry evidence.
```

The D0/D1 surface activates only variants required by the operational spine. A Module adds a command only when its owning section, catalogue entry, consumer and affected proof exist. Unknown variants remain unsupported; they are not silently mapped to generic upsert/status behavior.

Batch forms are bounded envelopes for one source/attempt/WorkScope and shared provenance. Full schema, visibility, authority, privacy, scope and fence validation occurs before staging. A boundary violation rejects the atomic envelope. Semantic type/relation/cue ambiguity instead preserves the item as `ObservationCandidate` when safe capture is allowed.

The command profile fixes item/byte limits. Oversized input is rejected before sequence reservation with a split directive; the server never silently splits one causal envelope into several commits.

Ownership is derived from the owning I-section and active catalogue:

```text
definition/plan intent requires the current Task Controller authority;
Governor owns admission and canonical semantic transitions;
Kernel owns mechanical generation/epoch/ORS lifecycle, never semantic intent;
Instrument evidence requires the admitted InstrumentRunner identity and executed status;
model/worker/Dreamer outputs remain candidate-only;
external effects require proposal → authority → executor → outcome reconciliation;
derived index/session/episode inputs remain coverage-bounded observations;
Module process generation is never mutated by a semantic command.
```

There is no `RawRecordUpsert`, raw storage query or generic `set status`. Detailed historical candidate vocabulary is retained in the non-normative cold backlog; reactivation requires a real owner, consumer, migration and falsifier.

