## I18.6. Canonical InstrumentRunner, test discovery and `dev-fast`

All verification profiles execute through I10.8. The first canonical coding profile is:

```text
0. resolve Product/WorkScope/base/candidate/worktree identity;
1. protected-path and allowed-change preflight;
2. Cargo lock/metadata/toolchain/config preflight;
3. discover current tests from nextest JSON;
4. select affected packages/binaries/tests from Impact Graph;
5. run governed Clippy/rustc JSON for affected scope;
6. run selected nextest with JUnit and per-test policy;
7. run rustfmt check as a separately reported low-cost stage;
8. normalize recurrence/progress, facts, unknowns and exact reruns;
9. commit InstrumentRuns and VerificationProfileRun through ELIOT evidence path.
```

A separate governed `cargo check` stage is not part of `dev-fast` when Clippy performs the same compilation. Direct `cargo check` remains available as an exploratory noncanonical instrument.

Test inventory is discovered, not hand-maintained:

```text
cargo nextest list --message-format json
→ parse stable package/binary/test identities
→ join ELIOT metadata overlay.
```

Overlay stores only non-discoverable policy:

```text
risk/criticality;
state/resource class;
required Windows/service fixture;
serial group;
acceptance relation;
coverage/mutation obligation;
known quarantine/flake disposition.
```

Missing overlay target is stale metadata. A discovered critical test lacking required classification produces policy-incomplete status, not a fabricated classification.

Target layout is explicit and worktree-safe:

```text
%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-class>
```

Initial build classes:

```text
interactive;
clippy;
nextest;
rust-analyzer;
coverage;
mutation.
```

ELIOT-owned instruments do not use repository `target/`. Classes may merge only after measured lock/cache/memory evidence.

Every run stores a `TestSelectionReceipt`:

```text
candidate/profile revision;
discovered inventory snapshot;
selected and omitted tests/stages with reasons;
impact evidence and unknown coverage;
expected/executed counts;
resource groups and cache/target identity.
```

The receipt makes false-negative selection auditable and allows replay after an escaped regression.

