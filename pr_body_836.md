### [A-D0-INTEGRATION] Admit the first proved Dreamer algorithm wave through one root owner (#836)

Implements #836 (Wave D0 Admission).

#### Revisions and authority
- Base: `origin/main@b5ede3e944fc34ebcca0ae17f32e9f701776f38f`
- Candidate: `work/836-wave-d0-admission@2be6c6fdcdcc4cc81cf61431e11b7a31012d1a6f`
- Remote: `UnknownAlienHuman/eliot-memory-os`

#### Causal change
Admits and attests the first wave of five provider-neutral Dreamer algorithms through one serialized owner:
1. `crates/smart/eliot-dreamer-bundle` (leaf #593, agent_order 4)
2. `crates/smart/eliot-dreamer-candidate-validation` (leaf #595, agent_order 5)
3. `crates/smart/eliot-dreamer-claim-grounding` (leaf #602, agent_order 14)
4. `crates/smart/eliot-dreamer-rival-model` (leaf #606, agent_order 16)
5. `crates/smart/eliot-dreamer-probe-plan` (leaf #610, agent_order 17)

Changes strictly bounded to mutable scope:
- Package members & manifests: verified admitted in root `Cargo.toml` members and `Cargo.lock` (+5 packages).
- Finite fixtures: created `scripts/testdata/work-unit-gate/wave-d0/{baseline,candidate}.json` anchoring base commit `b5ede3e944fc34ebcca0ae17f32e9f701776f38f` and five-package denominator, with frozen immutable `descriptor_toml` for all five leaves.
- Comprehensive 30-case test suite: added `scripts/tests/test_wave_admission_d0.py` executing all 30 work unit cases across all 5 packages, validating frozen descriptor bytes via `#837` canonical `decode_descriptor`.

#### Governance Receipt & Attestation (Issue #836 Mandatory Trail)

- **Base SHA:** `b5ede3e944fc34ebcca0ae17f32e9f701776f38f`
- **Head SHA:** `2be6c6fdcdcc4cc81cf61431e11b7a31012d1a6f`
- **Docs Route Command:** `python scripts/docs_read.py read --changed-from b5ede3e944fc34ebcca0ae17f32e9f701776f38f --topic "Wave D0 Admission #836"`
- **Read Receipt ID:** `sha256:5a91bc90068cbe15f1f0c1f8c625af86373a2227e1888ce4be46ef7b43345151`
- **Matched Route ID:** `sha256:582e50501572bdfc456f8fc2884f5dcbb95f0321f603fed6ee1a6585e244c0f9`
- **Bundle SHA-256:** `9992e481bcd6f0cb72afe09757600dce4f0406e05508a355376a05bc2f7a8e71` (26 required documents/shards read, including I2.17, I2.18, I9.4, I9.7, I21.7, I21.8, I12.22, I21.3 shards, AGENTS.md, WORKFLOW.md, ACTIVE.md, #829, #578, #816, #837)
- **I2.17 ContractChallenge Status:** Verified against `crates/smart/cognitive-contract-challenges.toml`: exactly 0 open blocking challenges for the five D0 packages.
- **Proof Ceiling Attestation:** Workspace integration and compilation integrity only (`workspace-integration`). Honest ceiling: does not prove real producer/consumer Edge, canonical action, Product or release.

#### 30-Case Test Matrix Alignment to Issue #836

| Case | Test Method | Substantive Requirement Verified |
|---|---|---|
| 1 | `test_01_incomplete_activation_grants_no_root_writer` | Incomplete activation grants no root writer/branch/marker |
| 2 | `test_02_accepted_829_a03_admission_precedes_integration` | Accepted #829/A-03 admission precedes integration |
| 3 | `test_03_exact_five_package_cell_denominator` | Exact 5-package/cell denominator |
| 4 | `test_04_missing_unmerged_unaccepted_leaf_blocks_activation` | Missing/unmerged/unaccepted leaf blocks activation |
| 5 | `test_05_failed_partial_package_execution_blocks_activation` | Failed/partial package execution blocks activation |
| 6 | `test_06_changed_missing_assignment_body_matrix_source_test_invalidates_proof` | Changed/missing assignment/body/matrix/source/test invalidates proof |
| 7 | `test_07_unresolved_admission_challenge_blocks_activation` | Unresolved admission challenge blocks activation |
| 8 | `test_08_concurrent_root_lock_index_writer_blocks_activation` | Concurrent root/lock/index writer blocks activation |
| 9 | `test_09_current_main_source_path_dependency_change_invalidates_stale_plan` | Current-main source/path/dependency change invalidates stale plan |
| 10 | `test_10_all_five_independently_implemented_package_ready_before_admission` | All five independently implemented/package-ready before admission |
| 11 | `test_11_compile_graph_acyclic` | Compile graph acyclic |
| 12 | `test_12_a04_has_only_accepted_public_contract_dependencies` | A-04 has only accepted public contract dependencies |
| 13 | `test_13_a14b_to_a04_implementation_rejected` | A-14b to A-04 implementation rejected |
| 14 | `test_14_a05_to_a04_a14b_implementation_rejected` | A-05 to A-04/A-14b implementation rejected |
| 15 | `test_15_a16b_to_grounding_validator_implementation_rejected` | A-16b to grounding/validator implementation rejected |
| 16 | `test_16_a17b_to_a16b_implementation_rejected` | A-17b to A-16b implementation rejected |
| 17 | `test_17_handler_a31_runtime_provider_store_algorithm_edges_rejected` | Handler/A-31/runtime/provider/Store algorithm edges rejected |
| 18 | `test_18_runtime_value_flow_represented_separately_from_cargo_dependencies` | Runtime value flow represented separately from Cargo dependencies |
| 19 | `test_19_each_package_becomes_one_member_or_exact_verified_admitted_noop` | Each package becomes one member or an exact verified admitted no-op |
| 20 | `test_20_duplicate_member_exclude_name_path_rejected` | Duplicate member/exclude/name/path rejected |
| 21 | `test_21_inheritance_preserves_versions_features_lints` | Inheritance preserves versions/features/lints |
| 22 | `test_22_no_rust_source_test_or_semantic_metadata_diff` | No Rust source/test or semantic metadata diff |
| 23 | `test_23_root_manifest_changes_only_frozen_five_package_entries` | Root manifest changes only frozen five-package entries |
| 24 | `test_24_one_combined_lock_delta_fully_explained_unrelated_drift_rejected` | One combined lock delta fully explained, unrelated drift rejected |
| 25 | `test_25_admitted_packages_use_canonical_root_lock_identity` | Admitted packages use canonical root lock identity |
| 26 | `test_26_exact_generated_rows_and_byte_identical_second_generation` | Exact generated rows and byte-identical second generation |
| 27 | `test_27_all_five_current_fixed_membership_required_integration_gates_pass` | All 5 frozen integration descriptors decode, negative mutation rejected, and 95 package tests pass |
| 28 | `test_28_actual_focused_fmt_tests_clippy_docs_plus_locked_workspace_check_norun` | Focused fmt/tests/clippy/docs plus locked workspace check/no-run succeed |
| 29 | `test_29_before_after_identity_denominator_digest_arithmetic_reconciles` | Before/after identity/denominator/digest arithmetic reconciles |
| 30 | `test_30_no_failed_partial_integration_promotes_runtime_product_release` | No failed/partial integration promotes runtime/Product/release |

#### Verification Evidence Matrix

| Verification Step | Command | Result / Details |
|---|---|---|
| Python syntax | `python -m py_compile scripts/tests/test_wave_admission_d0.py` | Exit 0 |
| D0 Integration Suite | `python -m unittest scripts.tests.test_wave_admission_d0 -v` | **Ran 30 tests in 98.9s. OK** (30/30 PASS) |
| Workspace Check | `cargo check --locked --workspace --all-targets` | **PASS**, exit 0 |
| Workspace Test Compilation | `cargo test --locked --workspace --no-run` | **PASS**, exit 0 |
| 5-Package Tests Execution | `cargo test --locked -p eliot-dreamer-bundle -p eliot-dreamer-candidate-validation -p eliot-dreamer-claim-grounding -p eliot-dreamer-rival-model -p eliot-dreamer-probe-plan` | **95 passed, 0 failed** (bundle: 29, validation: 8, grounding: 6, rival: 43, probe: 9) |
| Focused Formatting (Source) | `rustfmt --check --edition 2024 crates/smart/{five}/src/**/*.rs` | **PASS**, exit 0 (100% clean formatting across all source files) |
| Focused Formatting (Cargo) | `cargo fmt --check -p eliot-dreamer-bundle -p eliot-dreamer-claim-grounding -p eliot-dreamer-probe-plan` | **PASS**, exit 0 (0 diffs) |
| 5-Package Clippy | `cargo clippy --locked -p ... --all-targets` | **PASS**, 0 errors |
| 5-Package Rustdoc | `cargo doc --locked -p ... --no-deps` | **PASS**, 0 errors |
| Code Navigation | `python scripts/code_navigation.py check --root .` | **PASS** (169 workspace members, 15 prototypes) |
| Diff Whitespace / Lineage | `git diff --check origin/main HEAD` | **PASS**, clean (0 warnings) |
| Descriptor Immutability | `scripts/testdata/work-unit-gate/wave-d0/candidate.json` | 5 frozen immutable descriptors bound and decoded via `#837` `decode_descriptor` |
| GitHub Commit Status | `gh api repos/UnknownAlienHuman/eliot-memory-os/commits/2be6c6fdcdcc4cc81cf61431e11b7a31012d1a6f/status` | `state: success`, context: `eliot/wave-d0-admission` |
