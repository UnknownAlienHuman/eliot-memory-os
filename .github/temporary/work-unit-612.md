# Assignment reservation

Owning issue: #612
Implementation PR: #613
Branch: `work/612-reactive-context-plan`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/smart/eliot-reactive-context-plan/**` and this temporary marker. A-19r plans one bounded Context injection from exact A-15 ActiveUnderstandingView, A-10 CueActivationResult and immutable session/Critical-Attention/integration projections. It emits one PendingContextInjectionPlan, per-item dispositions and an inert downstream DeliveryReceipt request.

A-14a/A-18 are runtime value producers only. Compile against owner-neutral contracts; no A-14a/A-16a/A-17a/A-18/Host/delivery implementation linkage, provider refresh, readmission/reassembly, session mutation, actual delivery, receipt issuance or use/outcome inference. B-RCTX-C0 #796 is the next contract owner. Issue #612 plus its contract-only correction and #816 are normative. Remove this marker before ready.
