# Task: Implement Wave D0 Admission for 5 Dreamer Algorithm Crates (Issue #836)

## 1. Goal & Context
Implement Issue #836: Admit five independently proved provider-neutral Dreamer algorithms into workspace `members` through one serialized root/lock/index owner:
1. `crates/smart/eliot-dreamer-bundle` (leaf #593, agent_order 4)
2. `crates/smart/eliot-dreamer-candidate-validation` (leaf #595, agent_order 5)
3. `crates/smart/eliot-dreamer-claim-grounding` (leaf #602, agent_order 14)
4. `crates/smart/eliot-dreamer-rival-model` (leaf #606, agent_order 16)
5. `crates/smart/eliot-dreamer-probe-plan` (leaf #610, agent_order 17)

Base commit: `b5ede3e944fc34ebcca0ae17f32e9f701776f38f` (post-PR #2000).

## 2. Exclusive Mutable Scope
- root `Cargo.toml`: exactly the five member/exclude entries (move from `exclude` to `members`).
- root `Cargo.lock`: deterministic additive resolution of this wave only (+5 package entries).
- `Cargo.toml` and `module.toml` beneath the five package paths: mechanical standalone/inheritance/admission transitions only.
  - In `Cargo.toml`: inherit package version, edition, rust-version, license, and workspace lints. Remove standalone `[workspace]`. Under `[package.metadata.eliot]`, set `prototype = false` and `workspace_admission = "admitted via #836 (T8-A4) root workspace membership"`.
  - In `module.toml`: set `status = "ADMITTED"` and update `agent_task.workspace_admission`.
  - Remove any local `Cargo.lock` files under the 5 crate directories.
- `docs/code-navigation/PACKAGE_DOCS_INDEX.md` and `docs/code-navigation/PROTOTYPE_DOCS_INDEX.md`: canonical regeneration via `python scripts/code_navigation.py sync-index --root .` twice (169 -> 174 members, 15 -> 10 prototypes).
- New fixtures under `scripts/testdata/work-unit-gate/wave-d0/`:
  - `baseline.json`: anchored to `b5ede3e944fc34ebcca0ae17f32e9f701776f38f`.
  - `candidate.json`: includes the 5 leaves, their test counts, SHA-256 digests, and frozen immutable `descriptor_toml` for each leaf.
- New test suite `scripts/tests/test_wave_admission_d0.py`: exactly 30 substantive test methods covering cases 1..30 with `# WORK_UNIT_CASE: 836/<case>` markers.

## 3. Required 30-Case Test Matrix (1..30)
1. `test_01_incomplete_activation_grants_no_root_writer`
2. `test_02_accepted_829_a03_admission_precedes_integration`
3. `test_03_exact_five_package_cell_denominator`
4. `test_04_missing_unmerged_unaccepted_leaf_blocks_activation`
5. `test_05_failed_partial_package_execution_blocks_activation`
6. `test_06_changed_missing_assignment_body_matrix_source_test_invalidates_proof`
7. `test_07_unresolved_admission_challenge_blocks_activation`
8. `test_08_concurrent_root_lock_index_writer_blocks_activation`
9. `test_09_current_main_source_path_dependency_change_invalidates_stale_plan`
10. `test_10_all_five_independently_implemented_package_ready_before_admission`
11. `test_11_compile_graph_acyclic`
12. `test_12_a04_has_only_accepted_public_contract_dependencies`
13. `test_13_a14b_to_a04_implementation_rejected`
14. `test_14_a05_to_a04_a14b_implementation_rejected`
15. `test_15_a16b_to_grounding_validator_implementation_rejected`
16. `test_16_a17b_to_a16b_implementation_rejected`
17. `test_17_handler_a31_runtime_provider_store_algorithm_edges_rejected`
18. `test_18_runtime_value_flow_represented_separately_from_cargo_dependencies`
19. `test_19_each_package_becomes_one_member_or_exact_verified_admitted_noop`
20. `test_20_duplicate_member_exclude_name_path_rejected`
21. `test_21_inheritance_preserves_versions_features_lints`
22. `test_22_no_rust_source_test_or_semantic_metadata_diff`
23. `test_23_root_manifest_changes_only_frozen_five_package_entries`
24. `test_24_one_combined_lock_delta_fully_explained_unrelated_drift_rejected`
25. `test_25_admitted_packages_use_canonical_root_lock_identity`
26. `test_26_exact_generated_rows_and_byte_identical_second_generation`
27. `test_27_all_five_current_fixed_membership_required_integration_gates_pass` (frozen descriptors via `#837` `decode_descriptor`, negative mutation test, and per-package test execution)
28. `test_28_actual_focused_tests_clippy_docs_plus_locked_workspace_check_norun`
29. `test_29_before_after_identity_denominator_digest_arithmetic_reconciles`
30. `test_30_no_failed_partial_integration_promotes_runtime_product_release`

## 4. Verification Execution
Run and verify:
- `python -m py_compile scripts/tests/test_wave_admission_d0.py`
- `python -m unittest scripts.tests.test_wave_admission_d0 -v` (30/30 pass)
- `cargo check --locked --workspace --all-targets`
- `cargo test --locked --workspace --no-run`
- `python scripts/code_navigation.py check --root .`
- `git diff --check`
- `python scripts/docs_read.py read --changed-from b5ede3e944fc34ebcca0ae17f32e9f701776f38f --topic "Wave D0 Admission #836"`
