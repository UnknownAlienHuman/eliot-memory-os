# Assignment reservation

Owning issue: #704
Implementation PR: #720
Branch: `fix/704-context-measurement`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/smart/eliot-context-measurement/**`, package-local tests/fixtures, and this temporary marker. A-15 #584 owns shared `SerializedContextMeasurement` schemas; this package owns only exact serialized-byte measurement, normative unvalidated STU, immutable tokenizer-observation validation, unit-compatible capacity/headroom arithmetic, both estimator error directions and deterministic result construction.

Consumer migrations are exclusively #783/#784 (`eliot-app`) and #785/#786 (`eliot-engine`). Repository ownership enforcement is exclusively #787/#788. Forbidden: any consumer file, source-wide oracle, admission/assembly/delivery, provider/tokenizer I/O, root workspace/lock/index, workflows, Justfile, verification scripts or docs. Remove this marker before ready.
