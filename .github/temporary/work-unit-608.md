# Assignment reservation

Owning issue: #608
Implementation PR: #609
Branch: `work/608-context-admission`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/smart/eliot-context-admission/**` and this temporary marker. A-17a is the sole membership owner: it consumes A-15 candidate/recipe/measurement contracts, applies exactly one Include/HandleOnly/Revalidate/Suppress/Quarantine disposition per candidate, enforces the complete Decision Safety Floor, and emits AdmittedContextSet, exact omissions, economy/selection evidence or first-class DecisionContextIncomplete.

A-16a is a runtime producer/Edge predecessor, not a compile dependency. No A-16a/A-18/F-STU/provider/Store/runtime algorithm linkage, rendering, delivery or measurement implementation. Package-local manifest/router correction is allowed. Issue #608 plus its producer/compile correction and #816 are normative. Remove this marker before ready.
