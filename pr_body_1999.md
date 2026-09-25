### #702 Slices 3–8 + #1136 Slice B: pipeline stages in eliot-dreamer binary

Part of #702 and #1136.

#### Revisions and authority
- Base: `origin/main@3b831849d41294ef48cdd162e0891662b0cb9ce1`
- Candidate: `work/702-pipeline-slice-3@392b4352d0d8861e707e6b6c30a223a6d55cc54a`
- Remote: `UnknownAlienHuman/eliot-memory-os`

#### Causal change
Scope bounded strictly to `bins/eliot-dreamer/src/**`:
- `curation_screen_stage.rs`: Slice 3 (A-20 / #588) pre-model curation screen seam. Non-curation classes pass through; curation routes to Governor screen binding.
- `model_stage.rs`: Slice 4 (T12-07 / #702) model adapter seam with route and budget validation.
- `grounding_stage.rs`: Slice 5 (A-14b / #602) grounding seam with frozen evidence binding.
- `validation_stage.rs`: Slice 6 (A-05 / #595) pre-handler validation gate + Slice B (#1136) native `OrientationPacketCandidate` consumption with adaptations G1–G5.
- `dispatch_stage.rs`: Slice 7 native owner dispatch with exhaustive 9-arm matching; A-31 is the sole Curation fan-in owner.
- `result_stage.rs`: Slice 8 result projection and validation, stdout JSONL emission, stderr logs.
- `lib.rs` / `kernel_port.rs`: Dedicated Curation pipeline routing (Screen -> carrier check -> A-31) bypassing generic model/grounding/A-05 stages. Introduced `CurationCarrierSource` injection boundary on `AuthenticatedKernelJobPort`.
- `pipeline_e2e.rs`: End-to-end chain and public submit tests covering both fail-closed missing carrier refusal and public submit success path with `SuccessClaimTransport` and attached `DreamResult::Curation`.

#### Production boundary & adapter contract
- In the production binary (`connect()`), `curation_source` initializes to `None`, maintaining a strict fail-closed refusal (`DreamerError::InvalidAdmission("admitted Curation requires Governor-injected execution carrier and handler ports")`) until Governor host daemon composition injects runtime handler ports.
- The public `submit` adapter contract and A-31 routing are proven via `with_curation_source` and `SuccessClaimTransport`, confirming that an injected carrier produces a valid `JobView` with attached `DreamResult::Curation` and exactly one A-31 invocation.

#### Verification
- `cargo test --locked -p eliot-dreamer --all-targets`: **107 passed (98 lib, 9 bin), 0 failed, 0 ignored**.
- `cargo clippy --locked -p eliot-dreamer --all-targets`: **0 warnings/diagnostics** in `bins/eliot-dreamer`.
- `git diff --check`: clean.

#### Independent Audit
- Claude Opus 5: **APPROVE for squash-merge** on commit `392b4352d0d8861e707e6b6c30a223a6d55cc54a`.
- GPT 5.6 Sol: Verified B1.4 resolution; production boundary framed as fail-closed preparatory seam with adapter-contract verification.
