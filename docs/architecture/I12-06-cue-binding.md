## I12.6. Cue binding

Reusable record has at least one activation route:

```text
file/path/symbol;
error signature;
command/tool;
service/process;
dependency/API;
task class;
concept/subsystem;
commitment/deadline;
problem/incident;
Architecture/module ID.
```

Bindings are generated from observed touched-set first. Agent may add expected reuse. Unbound record remains cold and available to Dreamer/pull; it is not discarded.

`CUE_BINDING_REQUIRED` applies only to an attempted promotion into reusable hot memory when auto-binding cannot produce an admissible route. The underlying safe observation is retained as a cold `ObservationCandidate` and the response returns suggested bindings; it is not a failed capture.

Normalization is a single shared pure contract used by capture and firing:

```text
path        → canonical WorkScope-relative identity preserving case and Git spelling; a separate comparison key follows the actual directory case-sensitivity policy and never destructively lowercases the canonical path;
symbol      → adapter-resolved stable container/name identity where available;
error       → stable signature over tool/rule/message class/path class, excluding commit/config noise;
command     → executable + stable subcommand tokens, volatile arguments removed;
task class  → deterministic profile over task/artifact/subsystem fields;
service/API → registered capability identity and version range.
```

Write-side and read-side normalization cannot be separate implementations. Property/fuzz tests exercise roundtrip symmetry and cross-scope isolation.

