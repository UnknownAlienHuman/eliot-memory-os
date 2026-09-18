# 837 integration fixtures — frozen paths for D-WU-FINAL matrix layer.
#
# Frozen list (17 files, no more without issue revision):
# - README.md (this file)
# - descriptors/selected-python.toml        (837/D-WU-FINAL python-unittest, 2 cases)
# - descriptors/selected-rust.toml          (850/D-WU-RUNNERS rust-package, 2 cases)
# - descriptors/selected-metadata.toml      (849/A-1 metadata-python, 2 cases)
# - descriptors/standalone-local.toml       (837/D-WU-FINAL python-unittest, standalone)
# - descriptors/membership-required.toml    (837/D-WU-FINAL rust-package, member-required)
# - descriptors/planned-future.toml         (999/D-WU-FUTURE python-unittest, future path)
# - repos/python-tiny/sample.py
# - repos/python-tiny/test_sample.py
# - repos/python-tiny/test_markers.py
# - repos/rust-tiny/Cargo.toml
# - repos/rust-tiny/src/lib.rs
# - repos/metadata-tiny/module.toml
# - repos/metadata-tiny/check.py
# - captures/offline-capture.json
# - vectors/redaction-canaries.txt
# - vectors/ordering-vectors.json
#
# Proof kinds (SPECIFIED contract, integrator binds CLI to these labels):
# - catalogue-only: validate frozen catalogue, run no tests, exit 0 with
#   ceiling `catalogue-integrity-only`, never an execution claim.
# - selected-package / selected-verification: execute exactly the selected
#   descriptors via accepted #850 runners, exit 0 with ceiling
#   `selected-verification-only` only when every selected case passes.
# - integrated/workspace-integration: membership-required plan needs actual
#   workspace membership + fresh integrated evidence, ceiling
#   `selected-verification-only` scoped to the integrated selection, never
#   `full-project-complete` unless scope is full-project.
#
# Exits (per #857): 0 requested proof satisfied; 1 contract/incomplete;
# 2 usage/configuration/internal. Skipped/ignored/filtered/cfg-disabled/
# unavailable/zero-selected never pass.
#
# No live model/Product dependency. Real tiny repos are bounded (wall_ms,
# output_bytes) and offline. Fake child ports in the matrix tests assert
# failure paths deterministically, never canned pass.
