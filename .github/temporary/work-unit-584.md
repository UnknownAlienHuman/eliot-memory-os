# Assignment reservation

Owning issue: #584
Implementation PR: #585
Branch: `work/584-context-contracts`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/smart/eliot-context-contracts/**` and this temporary marker. A-15 owns the complete shared Context schema vocabulary and intrinsic invariants: whole atoms, four loss policies, provider/candidate denominators, Decision Safety Floor, admission/incomplete/omission/economy, twelve quality dimensions, selection integrity, ActiveUnderstandingView, PendingContextInjectionPlan, and provider-neutral serialized-measurement port/result/receipt contracts.

It owns no candidate construction, admission algorithm, rendering, measurement implementation, delivery, provider/model/Store/state/effect/finish path. F-STU-0 #704 implements measurement behind A-15 contracts; A-16a/A-17a/A-18/A-19r are independent consumers. Issue #584 plus its topology clarification and A-COGNITIVE-TOPOLOGY #816 are normative. Remove this marker before ready.
