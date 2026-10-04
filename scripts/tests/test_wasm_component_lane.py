"""Lane-gate regressions for #764; no fake proves live component execution.

The declared denominator is 21 cases (1..21), one substantive executable test per `# WORK_UNIT_CASE: 764/<case>` marker; 19 markers are present (1..15 and 17..20) and drive the lane helper's public APIs with the private run seam faked. Markers 16 and 21 are deliberately absent: both need `.github/workflows/wasm-modules.yml`, outside the card's EDIT scope by accepted owner decision, and 21 also needs one owner-authorized manual Actions dispatch, so the issue stays open until they land with real component execution. That real-execution proof is separate and still blocked: on main the guest closure does not compile for wasm32-wasip2 (error[E0392] in crates/smart/eliot-context-admission/src/lib.rs:91, whose `LearningGovernance<'a>` uses `'a` only inside a `#[cfg(not(target_arch = "wasm32"))]` variant), so `cargo build` never emits the component artifact; and `cargo test --target wasm32-wasip2` has no configured runner for a wasip2 harness. Both just commands therefore stay non-green by observation, not by a mocked tool status.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/wasm_component_lane.py"
spec = importlib.util.spec_from_file_location("eliot_wasm_component_lane", SCRIPT)
assert spec and spec.loader
lane = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lane
spec.loader.exec_module(lane)
FIXTURE = json.loads((ROOT / "scripts/testdata/wasm-component-lane/registry.json").read_bytes())["modules"]


class WasmComponentLaneTests(unittest.TestCase):
    def test_registry_fixture_binds_accepted_identities(self):
        entry = FIXTURE["eliot-context-compiler-wasm"]
        self.assertEqual(entry["package_id"], "eliot:current@0.1.0")
        self.assertEqual(entry["abi_revision"], 1)
        self.assertEqual(entry["capsule"]["operation"], entry["domain_operation"])

    # WORK_UNIT_CASE: 764/1
    def test_build_resolves_every_registered_module_to_exact_manifest_world(self):
        self.assertTrue(FIXTURE)
        digests = set()
        for module in sorted(FIXTURE):
            entry = lane.resolve_module(FIXTURE, module)
            self.assertIs(entry, FIXTURE[module])
            self.assertEqual(lane.check_module_name(module), module)
            frozen = lane.freeze_module(ROOT, module, entry)
            self.assertEqual(frozen.module, module)
            self.assertEqual(frozen.manifest_relpath, entry["manifest"])
            self.assertEqual(frozen.world, entry["world"])
            self.assertEqual(frozen.package_id, entry["package_id"])
            self.assertEqual(frozen.abi_revision, entry["abi_revision"])
            self.assertEqual(frozen.package_id, lane.TYPED_PACKAGE_ID)
            self.assertIn(frozen.world, lane.FROZEN_WORLDS)
            manifest = (ROOT / entry["manifest"]).read_bytes()
            self.assertEqual(frozen.manifest_bytes, len(manifest))
            self.assertEqual(frozen.manifest_sha256, hashlib.sha256(manifest).hexdigest())
            self.assertIn(f'name = "{module}"', manifest.decode("utf-8"))
            digests.add(frozen.digest)
        self.assertEqual(len(digests), len(FIXTURE))

    # WORK_UNIT_CASE: 764/2
    def test_test_invokes_only_its_declared_capsule(self):
        module = "eliot-context-compiler-wasm"
        entry = lane.resolve_module(FIXTURE, module)
        frozen = lane.freeze_module(ROOT, module, entry)
        self.assertEqual(frozen.capsule_stage, entry["capsule"]["stage"])
        self.assertIn(frozen.capsule_stage, lane.FROZEN_STAGES)
        # The declared capsule test identity is frozen from the registry
        # entry, and the stage label is never the thing cargo filters on:
        # a ProofStage such as INVOCATION matches no libtest name, so a zero
        # exit from it proved no capsule execution at all.
        declared = entry["capsule"]["execution"]
        self.assertEqual(frozen.capsule_test_target, declared["package_test_target"])
        self.assertEqual(frozen.capsule_test_name, declared["test_name"])
        with tempfile.TemporaryDirectory() as scratch:
            target_root = Path(scratch) / "lane-target"
            argv = lane.test_argv(frozen, target_root)
            root_text = str(target_root)
        self.assertEqual(
            argv,
            [
                "cargo", "test", "-p", module,
                "--target", lane.GUEST_TARGET,
                "--target-dir", root_text,
                "--test", frozen.capsule_test_target,
                "--", "--exact", frozen.capsule_test_name,
            ],
        )
        separator = argv.index("--")
        self.assertEqual(argv.count("--"), 1)
        self.assertEqual(
            argv[separator + 1:], ["--exact", frozen.capsule_test_name])
        self.assertNotIn(frozen.capsule_stage, argv)
        self.assertEqual(argv.count("-p"), 1)
        self.assertEqual(
            [argv[index + 1] for index, part in enumerate(argv) if part == "-p"],
            [module],
        )
        self.assertNotIn("--workspace", argv)
        self.assertNotIn("--all", argv)
        for other in sorted(FIXTURE):
            if other != module:
                self.assertNotIn(other, argv)
        lane._assert_exact_manifest_argv(argv, module)
        for forbidden in ("--workspace", "--all", "--exclude"):
            with self.subTest(argv=forbidden):
                with self.assertRaises(lane.LaneError) as failure:
                    lane._assert_exact_manifest_argv(
                        ["cargo", "test", "-p", module, forbidden, frozen.capsule_test_name],
                        module,
                    )
                self.assertEqual(str(failure.exception), "WORKSPACE_LANE_DENIED")

        # An undeclared or malformed execution identity fails closed while
        # freezing, before any command exists: the lane may never fall back
        # to some other test of the owning package.
        import copy

        for mutation, expected in (
            ({"execution": None}, "CAPSULE_EXECUTION_UNDECLARED"),
            ({"execution": {}}, "CAPSULE_EXECUTION_UNDECLARED"),
            ({"execution": {"test_name": declared["test_name"]}}, "CAPSULE_EXECUTION_UNDECLARED"),
            ({"execution": dict(declared, package_test_target="../proof")},
             "CAPSULE_TEST_TARGET_INVALID"),
            ({"execution": dict(declared, package_test_target="Proof/Proof")},
             "CAPSULE_TEST_TARGET_INVALID"),
            ({"execution": dict(declared, test_name="--nocapture")},
             "CAPSULE_TEST_NAME_INVALID"),
            ({"execution": dict(declared, test_name="")}, "INVALID_CAPSULE_TEST_NAME"),
            ({"execution": dict(declared, extra="x")}, "CAPSULE_EXECUTION_UNDECLARED"),
        ):
            with self.subTest(mutation=sorted(mutation)):
                broken = copy.deepcopy(entry)
                broken["capsule"].pop("execution", None)
                broken["capsule"].update(mutation)
                with self.assertRaises(lane.LaneError) as failure:
                    lane.freeze_module(ROOT, module, broken)
                self.assertEqual(str(failure.exception), expected)

    # WORK_UNIT_CASE: 764/5
    def test_one_component_execution_never_invokes_workspace_or_normal_verification(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        with tempfile.TemporaryDirectory() as scratch:
            target_root = Path(scratch) / "lane-target"
            build = lane.build_argv(frozen, target_root)
            test = lane.test_argv(frozen, target_root)
            root_text = str(target_root)
        self.assertEqual(
            build,
            [
                "cargo", "build", "-p", module,
                "--target", lane.GUEST_TARGET,
                "--target-dir", root_text,
            ],
        )
        self.assertEqual(build[:3], ["cargo", "build", "-p"])
        self.assertEqual(test[:3], ["cargo", "test", "-p"])
        for argv in (build, test):
            joined = "\0".join(argv)
            for forbidden in ("--workspace", "--all", "--exclude", "--manifest-path="):
                self.assertNotIn(forbidden, joined)
            self.assertEqual(argv.count("-p"), 1)
            self.assertEqual(
                [argv[index + 1] for index, part in enumerate(argv) if part == "-p"],
                [module],
            )
            for other in sorted(FIXTURE):
                if other != module:
                    self.assertNotIn(other, argv)
        self.assertEqual(build.count("-p"), 1)
        self.assertEqual(build[build.index("-p") + 1], module)
        for forbidden in ("--workspace", "--all", "--exclude"):
            with self.subTest(argv=forbidden):
                with self.assertRaises(lane.LaneError) as failure:
                    lane._assert_exact_manifest_argv(["cargo", "build", "-p", module, forbidden], module)
                self.assertEqual(str(failure.exception), "WORKSPACE_LANE_DENIED")

    # WORK_UNIT_CASE: 764/6
    def test_component_target_directory_distinct_from_workspace_and_incompatible_lanes(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        other_contract = dataclasses.replace(frozen, native_contract="eliot-context-other")
        other_revision = dataclasses.replace(frozen, native_revision="0.2.0")
        identity = {
            "abi_revision": frozen.abi_revision,
            "wit_digest": "b" * 64,
            "native_contract": frozen.native_contract,
            "native_revision": frozen.native_revision,
            "profile": frozen.profile,
            "features_digest": "c" * 64,
            "source_digest": "d" * 64,
        }
        variants = {
            "wit_digest": {"wit_digest": "e" * 64},
            "source_digest": {"source_digest": "f" * 64},
            "profile": {"profile": "release"},
            "features_digest": {"features_digest": "1" * 64},
            "native_contract": {"native_contract": other_contract.native_contract},
            "native_revision": {"native_revision": other_revision.native_revision},
        }
        workspace_target = ROOT / "target"
        with tempfile.TemporaryDirectory() as scratch:
            controller_root = Path(scratch) / "controller"
            lane_root = lane.lane_target_root(controller_root, ROOT, **identity)
            self.assertEqual(lane_root, lane.lane_target_root(controller_root, ROOT, **identity))
            self.assertEqual(lane_root.parent, controller_root)
            self.assertNotEqual(lane_root, workspace_target)
            self.assertNotIn(workspace_target, lane_root.parents)
            self.assertTrue(
                lane_root.name.startswith(f"{lane.TOOLCHAIN_CHANNEL}+{lane.GUEST_TARGET}__wit-")
            )
            self.assertIn(f"abi{lane.TYPED_ABI_REVISION}", lane_root.name)
            leaves = set()
            for label, overrides in variants.items():
                with self.subTest(variant=label):
                    variant_root = lane.lane_target_root(
                        controller_root, ROOT, **{**identity, **overrides}
                    )
                    self.assertEqual(variant_root.parent, controller_root)
                    self.assertNotEqual(variant_root, lane_root)
                    self.assertNotIn(workspace_target, variant_root.parents)
                    leaves.add(variant_root.name)
            self.assertEqual(len(leaves), len(variants))
            self.assertNotIn(lane_root.name, leaves)
            for field, value in (("toolchain", "stable"), ("target", "wasm32-unknown-unknown")):
                with self.subTest(pin=field):
                    with self.assertRaises(lane.LaneError) as failure:
                        lane.lane_target_root(controller_root, ROOT, **{**identity, field: value})
                    self.assertEqual(str(failure.exception), "LANE_IDENTITY_NOT_PINNED")
            with self.assertRaises(lane.LaneError) as failure:
                lane.lane_target_root(ROOT, ROOT, **identity)
            self.assertEqual(str(failure.exception), "WORKSPACE_TARGET_REUSE_DENIED")

    # WORK_UNIT_CASE: 764/7
    def test_toolchain_change_invalidates_cache_identity(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        closure = {
            "wit_digest": "a" * 64,
            "dependency_digest": "b" * 64,
            "source_digest": "c" * 64,
        }
        identity = lane.cache_identity(frozen, **closure)
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        self.assertEqual(identity, lane.cache_identity(frozen, **closure))
        self.assertEqual(
            identity, lane.cache_identity(frozen, toolchain=lane.TOOLCHAIN_CHANNEL, **closure)
        )
        channels = (
            "stable",
            "1.97.0",
            "1.97.1-nightly",
            "1.97",
            "",
            "1.97.1 ",
            lane.TOOLCHAIN_CHANNEL + "1",
        )
        for channel in channels:
            with self.subTest(toolchain=channel or "<empty>"):
                with self.assertRaises(lane.LaneError) as failure:
                    lane.cache_identity(frozen, toolchain=channel, **closure)
                self.assertEqual(str(failure.exception), "TOOLCHAIN_NOT_PINNED")
        self.assertEqual(identity, lane.cache_identity(frozen, **closure))

    # WORK_UNIT_CASE: 764/8
    def test_target_change_invalidates_cache_identity(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        closure = {
            "wit_digest": "a" * 64,
            "dependency_digest": "b" * 64,
            "source_digest": "c" * 64,
        }
        identity = lane.cache_identity(frozen, target=lane.GUEST_TARGET, **closure)
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        self.assertEqual(identity, lane.cache_identity(frozen, **closure))
        with tempfile.TemporaryDirectory() as scratch:
            argv = lane.build_argv(frozen, Path(scratch) / "lane-target")
        self.assertEqual(argv[argv.index("--target") + 1], lane.GUEST_TARGET)
        targets = (
            "wasm32-unknown-unknown",
            "wasm32-wasip1",
            "x86_64-pc-windows-msvc",
            "",
            lane.GUEST_TARGET + " ",
        )
        for target in targets:
            with self.subTest(target=target or "<empty>"):
                with self.assertRaises(lane.LaneError) as failure:
                    lane.cache_identity(frozen, target=target, **closure)
                self.assertEqual(str(failure.exception), "TARGET_NOT_PINNED")
        self.assertEqual(identity, lane.cache_identity(frozen, target=lane.GUEST_TARGET, **closure))

    # WORK_UNIT_CASE: 764/3
    def test_unknown_module_fails_before_commands(self):
        calls = []

        def never(argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            calls.append(list(argv))
            self.fail("unknown module must not construct or execute a command")

        with self.assertRaises(lane.LaneError) as failure:
            lane.resolve_module(FIXTURE, "eliot-not-registered-wasm")
        self.assertEqual(str(failure.exception), "UNKNOWN_MODULE")
        self.assertEqual(calls, [])

    # WORK_UNIT_CASE: 764/9
    def test_wit_world_version_and_abi_change_invalidate_cache_identity(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        self.assertEqual(frozen.package_id, lane.TYPED_PACKAGE_ID)
        self.assertEqual(frozen.abi_revision, lane.TYPED_ABI_REVISION)
        self.assertIn(frozen.world, lane.FROZEN_WORLDS)
        closure = {
            "wit_digest": "ab" * 32,
            "dependency_digest": "cd" * 32,
            "source_digest": "ef" * 32,
        }
        baseline = lane.cache_identity(frozen, **closure)
        self.assertRegex(baseline, r"^[0-9a-f]{64}$")
        other_world = sorted(lane.FROZEN_WORLDS - {frozen.world})[0]
        self.assertIn(other_world, lane.FROZEN_WORLDS)
        self.assertNotEqual(other_world, frozen.world)
        bindings = {
            "world": dataclasses.replace(frozen, world=other_world),
            "package_version": dataclasses.replace(frozen, package_id="eliot:current@0.2.0"),
            "abi_revision": dataclasses.replace(
                frozen, abi_revision=frozen.abi_revision + 1),
        }
        identities = {}
        for label, binding in bindings.items():
            with self.subTest(invalidating_input=label):
                identity = lane.cache_identity(binding, **closure)
                self.assertNotEqual(identity, baseline)
                self.assertRegex(identity, r"^[0-9a-f]{64}$")
                identities[label] = identity
        with self.subTest(invalidating_input="wit_digest"):
            changed_wit = lane.cache_identity(frozen, **dict(closure, wit_digest="12" * 32))
            self.assertNotEqual(changed_wit, baseline)
            self.assertRegex(changed_wit, r"^[0-9a-f]{64}$")
            identities["wit_digest"] = changed_wit
        self.assertEqual(sorted(identities), ["abi_revision", "package_version", "wit_digest", "world"])
        self.assertEqual(len(set(identities.values())), len(identities))
        self.assertEqual(lane.cache_identity(frozen, **closure), baseline)
        for malformed in ("", "ab" * 31, "AB" * 32, "zz" * 32, 12):
            with self.subTest(wit_digest=str(malformed)):
                with self.assertRaises(lane.LaneError) as failure:
                    lane.cache_identity(frozen, **dict(closure, wit_digest=malformed))
                self.assertEqual(str(failure.exception), "INVALID_WIT_DIGEST")

    # WORK_UNIT_CASE: 764/10
    def test_native_contract_dependency_feature_profile_change_invalidates_cache_identity(self):
        module = "eliot-context-compiler-wasm"
        entry = lane.resolve_module(FIXTURE, module)
        frozen = lane.freeze_module(ROOT, module, entry)
        closure = {
            "wit_digest": "ab" * 32,
            "dependency_digest": "cd" * 32,
            "source_digest": "ef" * 32,
        }
        baseline = lane.cache_identity(frozen, **closure)
        self.assertRegex(baseline, r"^[0-9a-f]{64}$")
        variants = {
            "native_contract": (dataclasses.replace(frozen, native_contract="eliot-context-assembly"), "cd" * 32),
            "native_revision": (dataclasses.replace(frozen, native_revision="0.2.0"), "cd" * 32),
            "profile": (dataclasses.replace(frozen, profile="release"), "cd" * 32),
            "features": (dataclasses.replace(frozen, features=("admission-capsule",)), "cd" * 32),
            "dependency_digest": (frozen, "34" * 32),
        }
        self.assertEqual(
            sorted(variants),
            ["dependency_digest", "features", "native_contract", "native_revision", "profile"],
        )
        identities = {}
        for label, (binding, dependency_digest) in variants.items():
            with self.subTest(invalidating_input=label):
                identity = lane.cache_identity(
                    binding, **dict(closure, dependency_digest=dependency_digest))
                self.assertNotEqual(identity, baseline)
                self.assertRegex(identity, r"^[0-9a-f]{64}$")
                identities[label] = identity
        self.assertEqual(len(set(identities.values())), len(identities))
        self.assertEqual(lane.cache_identity(frozen, **closure), baseline)

        absent = object()

        def accepted(**overrides):
            candidate = dict(FIXTURE[module])
            for key, value in overrides.items():
                if value is absent:
                    candidate.pop(key, None)
                else:
                    candidate[key] = value
            return lane.freeze_module(ROOT, module, candidate)

        def rejected(**overrides):
            candidate = dict(FIXTURE[module])
            for key, value in overrides.items():
                if value is absent:
                    candidate.pop(key, None)
                else:
                    candidate[key] = value
            with self.assertRaises(lane.LaneError) as failure:
                lane.freeze_module(ROOT, module, candidate)
            return str(failure.exception)

        self.assertEqual(accepted(profile=absent).profile, "dev")
        self.assertEqual(accepted(features=absent).features, ())
        self.assertEqual(accepted(features=["beta-capsule"]).features, ("beta-capsule",))
        self.assertEqual(
            rejected(native_contract=absent), "INVALID_NATIVE_CONTRACT")
        self.assertEqual(
            rejected(native_contract=None), "INVALID_NATIVE_CONTRACT")
        self.assertEqual(
            rejected(native_contract=""), "INVALID_NATIVE_CONTRACT")
        self.assertEqual(
            rejected(native_contract="e" * (lane.MAX_TEXT_FIELD + 1)), "INVALID_NATIVE_CONTRACT")
        self.assertEqual(
            rejected(native_contract="eliot context\tadmission"), "INVALID_NATIVE_CONTRACT")
        self.assertEqual(
            rejected(native_revision=absent), "INVALID_NATIVE_REVISION")
        self.assertEqual(rejected(native_revision=""), "INVALID_NATIVE_REVISION")
        self.assertEqual(rejected(native_revision=1), "INVALID_NATIVE_REVISION")
        self.assertEqual(rejected(profile=""), "INVALID_PROFILE")
        self.assertEqual(rejected(profile=None), "INVALID_PROFILE")
        self.assertEqual(rejected(profile="rel\tlease"), "INVALID_PROFILE")
        self.assertEqual(rejected(profile="release profile\t"), "INVALID_PROFILE")
        self.assertEqual(
            rejected(features=["admission", "admission"]), "DUPLICATE_FEATURES")
        self.assertEqual(
            rejected(features=[f"feature-{index}" for index in range(33)]), "INVALID_FEATURES")
        self.assertEqual(rejected(features="admission"), "INVALID_FEATURES")
        self.assertEqual(rejected(features=[None]), "INVALID_FEATURE")
        self.assertEqual(rejected(features=[""]), "INVALID_FEATURE")
        self.assertEqual(rejected(features=["admission\tcapsule"]), "INVALID_FEATURE")
        self.assertEqual(accepted().digest, frozen.digest)

    # WORK_UNIT_CASE: 764/11
    def test_receipt_binds_artifact_hash_world_source_toolchain_target_and_actual_result(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        cache_id = lane.cache_identity(
            frozen,
            wit_digest="ab" * 32,
            dependency_digest="cd" * 32,
            source_digest="ef" * 32,
        )
        base_sha = "11" * 20
        head_sha = "22" * 20
        argv_digest = "56" * 32
        artifact = {
            "path": "lane-target-root/wasm32-wasip2/debug/eliot-context-compiler-wasm.wasm",
            "sha256": "34" * 32,
            "bytes": 4096,
        }
        capsule_report = {"operation": frozen.capsule_operation, "tool_status": "OK"}
        receipt = lane.make_receipt(
            frozen=frozen,
            base_sha=base_sha,
            head_sha=head_sha,
            artifact=artifact,
            capsule_report=capsule_report,
            disposition="BUILD_PASS",
            cache_id=cache_id,
            cache_hit=False,
            argv_digest=argv_digest,
        )
        self.assertEqual(receipt["schema"], lane.RECEIPT_SCHEMA)
        self.assertEqual(receipt["module"], module)
        self.assertEqual(receipt["manifest_sha256"], frozen.manifest_sha256)
        self.assertEqual(receipt["manifest_bytes"], frozen.manifest_bytes)
        self.assertRegex(receipt["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(receipt["world"], frozen.world)
        self.assertEqual(receipt["package_id"], lane.TYPED_PACKAGE_ID)
        self.assertEqual(receipt["abi_revision"], lane.TYPED_ABI_REVISION)
        self.assertEqual(receipt["interface"], frozen.interface)
        self.assertEqual(receipt["native_contract"], frozen.native_contract)
        self.assertEqual(receipt["native_revision"], frozen.native_revision)
        self.assertEqual(receipt["toolchain"], lane.TOOLCHAIN_CHANNEL)
        self.assertEqual(receipt["target"], lane.GUEST_TARGET)
        self.assertEqual(receipt["profile"], frozen.profile)
        self.assertEqual(receipt["features"], list(frozen.features))
        self.assertEqual(receipt["engine"], {
            "implementation_id": frozen.engine_implementation,
            "exact_version": frozen.engine_version,
        })
        self.assertEqual(receipt["source"], {"base": base_sha, "head": head_sha})
        self.assertEqual(receipt["artifact"], artifact)
        self.assertEqual(receipt["capsule"]["operation"], frozen.capsule_operation)
        self.assertEqual(receipt["capsule"]["stage"], frozen.capsule_stage)
        self.assertEqual(receipt["capsule"]["oracle"], frozen.capsule_oracle)
        self.assertEqual(receipt["capsule"]["report"], capsule_report)
        self.assertEqual(receipt["execution"], {
            "argv_sha256": argv_digest,
            "disposition": "BUILD_PASS",
            "cache_identity": cache_id,
            "cache_hit": False,
            "cache_skipped_verification": False,
        })
        self.assertEqual(
            receipt["timing"],
            {"cold_s": "UNAVAILABLE", "warm_s": "UNAVAILABLE", "baseline_s": "UNAVAILABLE"},
        )
        self.assertEqual(receipt["proof_ceiling"], "ISOLATED_COMPONENT_EVIDENCE_ONLY")
        self.assertNotIn("release", receipt)
        self.assertNotIn("product", receipt)

        dispositions = (
            "BUILD_PASS", "TEST_PASS", "NO_WORK", "SKIPPED",
            "UNAVAILABLE", "CANCELLED", "FAILED",
        )
        self.assertEqual(len(dispositions), 7)
        bound = set()
        for disposition in dispositions:
            with self.subTest(disposition=disposition):
                candidate = lane.make_receipt(
                    frozen=frozen,
                    base_sha=base_sha,
                    head_sha=head_sha,
                    artifact=artifact,
                    capsule_report=capsule_report,
                    disposition=disposition,
                    cache_id=cache_id,
                    cache_hit=True,
                    argv_digest=argv_digest,
                )
                self.assertEqual(candidate["schema"], lane.RECEIPT_SCHEMA)
                self.assertEqual(candidate["execution"]["disposition"], disposition)
                self.assertIs(candidate["execution"]["cache_hit"], True)
                self.assertIs(candidate["execution"]["cache_skipped_verification"], False)
                bound.add(json.dumps(candidate, sort_keys=True))
        self.assertEqual(len(bound), len(dispositions))

        def rejected(**overrides):
            call = {
                "frozen": frozen,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "artifact": artifact,
                "capsule_report": capsule_report,
                "disposition": "BUILD_PASS",
                "cache_id": cache_id,
                "cache_hit": False,
                "argv_digest": argv_digest,
            }
            call.update(overrides)
            with self.assertRaises(lane.LaneError) as failure:
                lane.make_receipt(**call)
            return str(failure.exception)

        for attempt in ("PASS", "OK", "build_pass", "BUILD_PASS ", "", "PASSED", "SUCCESS", None):
            with self.subTest(disposition=str(attempt)):
                self.assertEqual(rejected(disposition=attempt), "INVALID_DISPOSITION")
        self.assertEqual(rejected(base_sha="abc"), "INVALID_BASE_SHA")
        self.assertEqual(rejected(base_sha="11" * 19), "INVALID_BASE_SHA")
        self.assertEqual(rejected(base_sha="AA" * 20), "INVALID_BASE_SHA")
        self.assertEqual(rejected(base_sha=None), "INVALID_BASE_SHA")
        self.assertEqual(rejected(head_sha="22" * 21), "INVALID_HEAD_SHA")
        self.assertEqual(rejected(head_sha="zz" * 20), "INVALID_HEAD_SHA")
        self.assertEqual(rejected(head_sha=2222), "INVALID_HEAD_SHA")
        self.assertEqual(rejected(cache_id="ab" * 31), "INVALID_CACHE_IDENTITY")
        self.assertEqual(rejected(cache_id="AB" * 32), "INVALID_CACHE_IDENTITY")
        self.assertEqual(rejected(cache_id=None), "INVALID_CACHE_IDENTITY")
        self.assertEqual(rejected(argv_digest="56" * 33), "INVALID_ARGV_DIGEST")
        self.assertEqual(rejected(argv_digest="gg" * 32), "INVALID_ARGV_DIGEST")
        self.assertEqual(rejected(argv_digest=5656), "INVALID_ARGV_DIGEST")
        empty = lane.make_receipt(
            frozen=frozen,
            base_sha=base_sha,
            head_sha=head_sha,
            artifact=None,
            capsule_report=None,
            disposition="SKIPPED",
            cache_id=cache_id,
            cache_hit=False,
            argv_digest=argv_digest,
        )
        self.assertIsNone(empty["artifact"])
        self.assertIsNone(empty["capsule"]["report"])
        self.assertEqual(empty["execution"]["disposition"], "SKIPPED")
        self.assertIs(empty["execution"]["cache_skipped_verification"], False)

        # A real `--test` run binds the artifact read back off disk and the
        # capsule execution actually observed in the harness output, never
        # the declared stage/oracle echoed back as if it were a result.
        registry_path = ROOT / "scripts/testdata/wasm-component-lane/registry.json"
        test_name = frozen.capsule_test_name
        harness_ok = (
            "\n     Running tests/proof.rs (target/wasm32-wasip2/debug/deps/proof-abc)\n"
            f"test {test_name} ... ok\n"
            "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "0 filtered out; finished in 0.01s\n"
        ).encode("utf-8")
        executed_argv: list[list[str]] = []

        def fake_capsule_gate(tool_argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            executed_argv.append(list(tool_argv))
            target_dir = Path(tool_argv[tool_argv.index("--target-dir") + 1])
            artifact_path = lane.component_artifact_path(frozen, target_dir)
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_bytes(b"\x00asm\x01\x00\x00\x00" + module.encode("ascii"))
            return lane.CommandResult("OK", harness_ok)

        with tempfile.TemporaryDirectory() as scratch_text:
            scratch = Path(scratch_text)
            previous_tempdir = tempfile.tempdir
            tempfile.tempdir = str(scratch)
            try:
                receipt_path = scratch / "receipt-test.json"
                with mock.patch.object(lane, "_run", fake_capsule_gate):
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = lane.main([
                            "--test", module,
                            "--registry", str(registry_path),
                            "--receipt-out", str(receipt_path),
                            "--base-sha", base_sha,
                            "--head-sha", head_sha,
                        ])
                observed = json.loads(receipt_path.read_text(encoding="utf-8"))
                observed_digest = lane.sha256_file(Path(observed["artifact"]["path"]))[0]
            finally:
                tempfile.tempdir = previous_tempdir
        self.assertEqual(exit_code, 0)
        self.assertEqual(observed["status"], "PASS")
        self.assertEqual(observed["execution"]["disposition"], "TEST_PASS")
        self.assertEqual(len(executed_argv), 1)
        produced = executed_argv[0]
        self.assertEqual(produced[:3], ["cargo", "test", "-p"])
        self.assertNotIn(frozen.capsule_stage, produced)
        self.assertEqual(
            produced[produced.index("--") + 1:], ["--exact", test_name])
        # The bound artifact is the file the fake gate really wrote, hashed
        # by the helper: its identity cannot be a declared constant.
        self.assertIsNotNone(observed["artifact"])
        self.assertEqual(
            observed["artifact"]["bytes"], len(b"\x00asm\x01\x00\x00\x00" + module.encode("ascii")))
        self.assertRegex(observed["artifact"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(observed["artifact"]["sha256"], observed_digest)
        report = observed["capsule"]["report"]
        self.assertEqual(report["executed_test"], test_name)
        self.assertEqual(report["executed_test_target"], frozen.capsule_test_target)
        self.assertEqual(report["tool_status"], "OK")
        self.assertEqual(report["passed"], 1)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["artifact_sha256"], observed["artifact"]["sha256"])

    # WORK_UNIT_CASE: 764/12
    def test_one_guest_change_selects_only_justified_dependents(self):
        registry = {
            "guest-a-wasm": {
                "owned_paths": ["crates/modules/guest-a-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
            "guest-b-wasm": {
                "owned_paths": ["crates/modules/guest-b-wasm"],
                "native_contract": "eliot:context-assembly@1",
            },
            "guest-c-wasm": {
                "owned_paths": ["crates/modules/guest-c-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
        }
        dependents = {"guest-a-wasm": ["guest-c-wasm"]}
        native_prefixes = {
            "eliot:context-admission@1": ["crates/native/context-admission"],
            "eliot:context-assembly@1": ["crates/native/context-assembly"],
        }
        changed = ["crates/modules/guest-a-wasm/src/lib.rs"]
        selection = lane.select_affected(
            registry,
            changed,
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents=dependents,
        )
        self.assertEqual(selection.selected, ("guest-a-wasm", "guest-c-wasm"))
        self.assertEqual(selection.disposition, "SELECTED")
        self.assertEqual(selection.reason, "AFFECTED_WITH_DEPENDENTS")
        self.assertNotIn("guest-b-wasm", selection.selected)
        nested = lane.select_affected(
            registry,
            ["crates/modules/guest-a-wasm/src/host/runtime.rs"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents=dependents,
        )
        self.assertEqual(nested.selected, selection.selected)
        descriptor = lane.select_affected(
            registry,
            ["crates/modules/guest-a-wasm/module.toml"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents=dependents,
        )
        self.assertEqual(descriptor.selected, selection.selected)
        leaf = lane.select_affected(
            registry,
            ["crates/modules/guest-b-wasm/src/lib.rs"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents=dependents,
        )
        self.assertEqual(leaf.selected, ("guest-b-wasm",))
        self.assertNotIn("guest-a-wasm", leaf.selected)
        self.assertNotIn("guest-c-wasm", leaf.selected)
        self.assertEqual(leaf.reason, "AFFECTED_WITH_DEPENDENTS")
        mixed = lane.select_affected(
            registry,
            ["crates/modules/guest-a-wasm/src/lib.rs", "crates/modules/guest-b-wasm/src/lib.rs"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents=dependents,
        )
        self.assertEqual(mixed.selected, ("guest-a-wasm", "guest-b-wasm", "guest-c-wasm"))

    # WORK_UNIT_CASE: 764/13
    def test_native_owner_change_selects_its_guest_dependents(self):
        registry = {
            "guest-a-wasm": {
                "owned_paths": ["crates/modules/guest-a-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
            "guest-b-wasm": {
                "owned_paths": ["crates/modules/guest-b-wasm"],
                "native_contract": "eliot:context-assembly@1",
            },
            "guest-c-wasm": {
                "owned_paths": ["crates/modules/guest-c-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
        }
        native_prefixes = {
            "eliot:context-admission@1": ["crates/native/context-admission"],
            "eliot:context-assembly@1": ["crates/native/context-assembly"],
        }
        everyone = tuple(sorted(registry))
        admission = lane.select_affected(
            registry,
            ["crates/native/context-admission/src/lib.rs"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents={"guest-a-wasm": ["guest-c-wasm"]},
        )
        self.assertEqual(admission.selected, ("guest-a-wasm", "guest-c-wasm"))
        self.assertEqual(admission.disposition, "SELECTED")
        self.assertNotIn("guest-b-wasm", admission.selected)
        assembly = lane.select_affected(
            registry,
            ["crates/native/context-assembly/Cargo.toml"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents={"guest-a-wasm": ["guest-c-wasm"]},
        )
        self.assertEqual(assembly.selected, ("guest-b-wasm",))
        self.assertNotIn("guest-a-wasm", assembly.selected)
        unknown_contract = lane.select_affected(
            registry,
            ["crates/native/context-admission/nested/deep/revision.txt"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents={},
        )
        self.assertEqual(unknown_contract.selected, ("guest-a-wasm", "guest-c-wasm"))
        self.assertEqual(unknown_contract.reason, "AFFECTED_WITH_DEPENDENTS")
        unrelated_contract = lane.select_affected(
            registry,
            ["crates/native/context-dreamer/src/lib.rs"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=["README.md"],
            dependents={"guest-a-wasm": ["guest-c-wasm"]},
        )
        self.assertEqual(unrelated_contract.selected, everyone)
        self.assertEqual(unrelated_contract.disposition, "SELECTED")
        self.assertEqual(unrelated_contract.reason, "UNKNOWN_PATH_CLOSED_TO_ALL")

    # WORK_UNIT_CASE: 764/14
    def test_shared_wit_host_runtime_change_selects_all_registered_transitive_dependents(self):
        registry = {
            "guest-a-wasm": {
                "owned_paths": ["crates/modules/guest-a-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
            "guest-b-wasm": {
                "owned_paths": ["crates/modules/guest-b-wasm"],
                "native_contract": "eliot:context-assembly@1",
            },
            "guest-c-wasm": {
                "owned_paths": ["crates/modules/guest-c-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
        }
        everyone = tuple(sorted(registry))
        self.assertEqual(everyone, ("guest-a-wasm", "guest-b-wasm", "guest-c-wasm"))
        shared_paths = (
            "crates/runtime/wit/typed/context-admission.wit",
            "crates/modules/eliot-wasm-runtime/src/component_contract.rs",
            "bins/eliot-wasm-host/wit/typed/context-admission.wit",
        )
        for changed in shared_paths:
            with self.subTest(changed_path=changed):
                selection = lane.select_affected(
                    registry,
                    [changed],
                    shared_prefixes=["crates/runtime", "crates/modules/eliot-wasm-runtime", "bins/eliot-wasm-host"],
                    native_contract_prefixes={
                        "eliot:context-admission@1": ["crates/native/context-admission"],
                    },
                    unrelated_prefixes=["README.md"],
                    dependents={"guest-a-wasm": ["guest-c-wasm"]},
                )
                self.assertEqual(selection.selected, everyone)
                self.assertEqual(selection.disposition, "SELECTED")
                self.assertEqual(selection.reason, "SHARED_WIT_HOST_RUNTIME_SELECTS_ALL")
                self.assertEqual(len(selection.selected), len(registry))
        transitive = lane.select_affected(
            registry,
            ["crates/runtime/wit/typed/context-admission.wit", "docs/unrelated.md"],
            shared_prefixes=["crates/runtime"],
            native_contract_prefixes={},
            unrelated_prefixes=["README.md", "docs"],
            dependents=None,
        )
        self.assertEqual(transitive.selected, everyone)
        self.assertEqual(transitive.reason, "SHARED_WIT_HOST_RUNTIME_SELECTS_ALL")

    # WORK_UNIT_CASE: 764/15
    def test_unrelated_change_is_explicit_no_work_and_incomplete_graph_cannot_hide_a_dependent(self):
        registry = {
            "guest-a-wasm": {
                "owned_paths": ["crates/modules/guest-a-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
            "guest-b-wasm": {
                "owned_paths": ["crates/modules/guest-b-wasm"],
                "native_contract": "eliot:context-assembly@1",
            },
            "guest-c-wasm": {
                "owned_paths": ["crates/modules/guest-c-wasm"],
                "native_contract": "eliot:context-admission@1",
            },
        }
        everyone = tuple(sorted(registry))
        native_prefixes = {
            "eliot:context-admission@1": ["crates/native/context-admission"],
            "eliot:context-assembly@1": ["crates/native/context-assembly"],
        }
        shared = ["crates/runtime"]
        unrelated = ["README.md", "docs"]
        for changed in ("README.md", "docs/architecture/I14-19-wasm-components.md"):
            with self.subTest(unrelated_path=changed):
                no_work = lane.select_affected(
                    registry,
                    [changed],
                    shared_prefixes=shared,
                    native_contract_prefixes=native_prefixes,
                    unrelated_prefixes=unrelated,
                    dependents={"guest-a-wasm": ["guest-c-wasm"]},
                )
                self.assertEqual(no_work.selected, ())
                self.assertEqual(no_work.disposition, "NO_WORK")
                self.assertEqual(no_work.reason, "UNRELATED_CHANGE_NO_WORK")
        unknown = lane.select_affected(
            registry,
            ["vendor/zlib/zlib.c"],
            shared_prefixes=shared,
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=unrelated,
            dependents={"guest-a-wasm": ["guest-c-wasm"]},
        )
        self.assertEqual(unknown.selected, everyone)
        self.assertEqual(unknown.disposition, "SELECTED")
        self.assertEqual(unknown.reason, "UNKNOWN_PATH_CLOSED_TO_ALL")
        incomplete = lane.select_affected(
            registry,
            ["crates/modules/guest-a-wasm/src/lib.rs"],
            shared_prefixes=shared,
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=unrelated,
            dependents=None,
        )
        self.assertEqual(incomplete.selected, everyone)
        self.assertEqual(incomplete.disposition, "SELECTED")
        self.assertEqual(incomplete.reason, "INCOMPLETE_GRAPH_CLOSED_TO_ALL")
        self.assertIn("guest-c-wasm", incomplete.selected)
        self.assertGreater(len(incomplete.selected), 1)
        complete = lane.select_affected(
            registry,
            [
                "crates/modules/guest-a-wasm/src/lib.rs",
                "crates/modules/guest-b-wasm/src/lib.rs",
                "crates/modules/guest-c-wasm/src/lib.rs",
            ],
            shared_prefixes=shared,
            native_contract_prefixes=native_prefixes,
            unrelated_prefixes=unrelated,
            dependents=None,
        )
        self.assertEqual(complete.selected, everyone)
        self.assertEqual(complete.reason, "DIRECT_SELECTION")
        for attempt in ([], ["../escape"], ["/absolute"], ["windows\\path"]):
            with self.subTest(changed_path=str(attempt)):
                with self.assertRaises(lane.LaneError) as failure:
                    lane.select_affected(
                        registry,
                        attempt,
                        shared_prefixes=shared,
                        native_contract_prefixes=native_prefixes,
                        unrelated_prefixes=unrelated,
                        dependents={"guest-a-wasm": ["guest-c-wasm"]},
                    )
                self.assertIn(
                    str(failure.exception), ("EMPTY_CHANGESET", "MALFORMED_CHANGED_PATH"))

    # Source-shape guard, not a runtime capability proof: it reads the lane
    # source text only and observes no live provider, credential or network.
    # WORK_UNIT_CASE: 764/17
    def test_no_provider_credential_secret_or_undeclared_network_capability(self):
        source = SCRIPT.read_text(encoding="utf-8")
        forbidden = (
            "ANTHROPIC_",
            "OPENAI_",
            "GOOGLE_API",
            "API_KEY",
            "APIKEY",
            "API_TOKEN",
            "ACCESS_TOKEN",
            "AUTH_TOKEN",
            "BEARER_TOKEN",
            "TOKEN_URL",
            "Bearer",
            "Authorization",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "HF_TOKEN",
            "PRIVATE_KEY",
            "netrc",
            "id_rsa",
            "gh auth",
            "requests",
            "urllib",
            "http.client",
            "socket.socket",
            "ftplib",
            "smtplib",
            "ssh",
            "shell=True",
        )
        for token in forbidden:
            with self.subTest(forbidden_token=token):
                self.assertNotIn(token, source)
        imports = re.findall(r"^import ([A-Za-z_][\w]*)", source, re.MULTILINE)
        self.assertEqual(
            sorted(set(imports) & {"requests", "urllib", "socket", "http", "ftplib", "smtplib", "ssl"}),
            [],
        )
        secret_reads = re.findall(
            r"os\.environ(?:\.get)?\(\s*[\"']([^\"']+)[\"']", source)
        self.assertEqual(
            [name for name in secret_reads
             if re.search(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH", name, re.IGNORECASE)],
            [],
        )
        self.assertEqual(source.count("subprocess.Popen("), 1)
        popen = re.search(r"subprocess\.Popen\((?:[^()]|\([^()]*\))*\)", source, re.DOTALL)
        self.assertIsNotNone(popen)
        self.assertNotIn("shell", popen.group(0))
        self.assertIn("stdin=subprocess.DEVNULL", popen.group(0))
        self.assertIn("stderr=subprocess.STDOUT", popen.group(0))
        self.assertNotIn("os.system", source)
        self.assertNotIn("os.popen", source)
        self.assertNotIn("subprocess.call", source)
        self.assertNotIn("subprocess.check_output", source)
        self.assertIn("RUSTUP_AUTO_INSTALL", source)
        self.assertNotIn("rustup target add", source)
        self.assertNotIn("target add", source)

    # WORK_UNIT_CASE: 764/18
    def test_timing_observations_are_measured_comparable_or_explicitly_unavailable(self):
        module = "eliot-context-compiler-wasm"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        cache_id = lane.cache_identity(
            frozen,
            wit_digest="ab" * 32,
            dependency_digest="cd" * 32,
            source_digest="ef" * 32,
        )
        provenance = "D-CI-750 workspace gate 8fb0a426f measured on the same toolchain"

        def fresh():
            return lane.make_receipt(
                frozen=frozen,
                base_sha="11" * 20,
                head_sha="22" * 20,
                artifact=None,
                capsule_report=None,
                disposition="BUILD_PASS",
                cache_id=cache_id,
                cache_hit=False,
                argv_digest="56" * 32,
            )

        measured = lane.bind_observations(fresh(), cold_s=12.5, warm_s=6.25)
        self.assertIs(measured["timing"]["cold_s"], 12.5)
        self.assertEqual(measured["timing"]["cold_s"], 12.5)
        self.assertEqual(measured["timing"]["warm_s"], 6.25)
        self.assertEqual(measured["timing"]["baseline_s"], "UNAVAILABLE")
        self.assertNotIn("speedup", measured["timing"])
        self.assertNotIn("baseline_provenance", measured["timing"])

        unavailable = lane.bind_observations(fresh(), cold_s=None, warm_s=None)
        self.assertEqual(unavailable["timing"]["cold_s"], "UNAVAILABLE")
        self.assertEqual(unavailable["timing"]["warm_s"], "UNAVAILABLE")
        self.assertEqual(unavailable["timing"]["baseline_s"], "UNAVAILABLE")
        self.assertNotIn("speedup", unavailable["timing"])

        half = lane.bind_observations(fresh(), cold_s=None, warm_s=6.25)
        self.assertEqual(half["timing"]["cold_s"], "UNAVAILABLE")
        self.assertEqual(half["timing"]["warm_s"], 6.25)
        self.assertNotIn("speedup", half["timing"])

        compared = lane.bind_observations(
            fresh(), cold_s=12.5, warm_s=2.5,
            baseline_s=10.0, baseline_provenance=provenance)
        self.assertEqual(compared["timing"]["baseline_s"], 10.0)
        self.assertEqual(compared["timing"]["baseline_provenance"], provenance)
        self.assertEqual(compared["timing"]["speedup"], 4.0)

        zero_warm = lane.bind_observations(
            fresh(), cold_s=12.5, warm_s=0.0,
            baseline_s=10.0, baseline_provenance=provenance)
        self.assertEqual(zero_warm["timing"]["warm_s"], 0.0)
        self.assertEqual(zero_warm["timing"]["speedup"], "UNAVAILABLE")

        for baseline_s, baseline_provenance, label in (
            (None, provenance, "baseline missing"),
            (10.0, None, "provenance missing"),
        ):
            with self.subTest(baseline=label):
                unbound = lane.bind_observations(
                    fresh(), cold_s=12.5, warm_s=2.5,
                    baseline_s=baseline_s, baseline_provenance=baseline_provenance)
                self.assertEqual(unbound["timing"]["baseline_s"], "UNAVAILABLE")
                self.assertNotIn("speedup", unbound["timing"])
                self.assertNotIn("baseline_provenance", unbound["timing"])

        def rejected(**kwargs):
            with self.assertRaises(lane.LaneError) as failure:
                lane.bind_observations(fresh(), **kwargs)
            return str(failure.exception)

        self.assertEqual(rejected(cold_s=-0.5, warm_s=2.5), "INVALID_TIMING")
        self.assertEqual(rejected(cold_s=1_000_000, warm_s=2.5), "INVALID_TIMING")
        self.assertEqual(rejected(cold_s=1_000_001, warm_s=2.5), "INVALID_TIMING")
        self.assertEqual(rejected(cold_s="12", warm_s=2.5), "INVALID_TIMING")
        self.assertEqual(rejected(cold_s=12.5, warm_s=-1.0), "INVALID_TIMING")
        self.assertEqual(
            rejected(cold_s=12.5, warm_s=None, baseline_s=10.0, baseline_provenance=provenance),
            "INVALID_BASELINE",
        )
        self.assertEqual(
            rejected(cold_s=12.5, warm_s=2.5, baseline_s=0.0, baseline_provenance=provenance),
            "INVALID_BASELINE",
        )
        self.assertEqual(
            rejected(cold_s=12.5, warm_s=2.5, baseline_s=-10.0, baseline_provenance=provenance),
            "INVALID_BASELINE",
        )
        self.assertEqual(
            rejected(cold_s=12.5, warm_s=2.5, baseline_s=10.0, baseline_provenance=""),
            "INVALID_BASELINE",
        )
        self.assertEqual(
            rejected(cold_s=12.5, warm_s=2.5, baseline_s=10.0, baseline_provenance="g" * 513),
            "INVALID_BASELINE",
        )
        broken = fresh()
        broken["timing"] = None
        with self.assertRaises(lane.LaneError) as failure:
            lane.bind_observations(broken, cold_s=1.0, warm_s=1.0)
        self.assertEqual(str(failure.exception), "INVALID_RECEIPT")

    # WORK_UNIT_CASE: 764/19
    def test_cache_hit_and_miss_both_execute_the_required_gate(self):
        module = "eliot-context-compiler-wasm"
        registry_path = ROOT / "scripts/testdata/wasm-component-lane/registry.json"
        frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
        base_sha = "11" * 20
        head_sha = "22" * 20
        calls = []
        artifact_paths = []

        def fake_gate(tool_argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            calls.append(list(tool_argv))
            target_dir = Path(tool_argv[tool_argv.index("--target-dir") + 1])
            artifact = lane.component_artifact_path(frozen, target_dir)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b"\x00asm\x01\x00\x00\x00" + module.encode("ascii"))
            artifact_paths.append(artifact)
            return lane.CommandResult("OK", b"")

        with tempfile.TemporaryDirectory() as scratch_text:
            scratch = Path(scratch_text)
            previous_tempdir = tempfile.tempdir
            tempfile.tempdir = str(scratch)
            try:
                self.assertEqual(Path(lane.tempfile.gettempdir()), scratch)
                receipts = []
                for index in (1, 2):
                    out = scratch / f"receipt-{index}.json"
                    buffer = io.StringIO()
                    invocation = [
                        "--build", module,
                        "--registry", str(registry_path),
                        "--base-sha", base_sha,
                        "--head-sha", head_sha,
                    ]
                    if index == 1:
                        invocation.extend(("--receipt-out", str(out)))
                    # The cache-hit invocation below keeps the default CLI
                    # options, matching the Justfile's text-mode call.
                    with mock.patch.object(lane, "_run", fake_gate):
                        with contextlib.redirect_stdout(buffer):
                            exit_code = lane.main(invocation)
                    lines = buffer.getvalue().splitlines()
                    self.assertEqual(len(lines), 2)
                    self.assertTrue(lines[0].startswith("WASM_COMPONENT_LANE: PASS "))
                    receipt = json.loads(lines[1])
                    self.assertEqual(receipt["schema"], lane.RECEIPT_SCHEMA)
                    self.assertEqual(
                        lines[1], json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                    if index == 1:
                        self.assertEqual(
                            json.loads(out.read_text(encoding="utf-8")), receipt)
                    receipts.append((exit_code, receipt))
            finally:
                tempfile.tempdir = previous_tempdir
            self.assertEqual(Path(tempfile.tempdir), Path(previous_tempdir))
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0], calls[1])
            executed = calls[1]
            self.assertEqual(executed[:3], ["cargo", "build", "-p"])
            self.assertEqual(executed[3], module)
            self.assertEqual(executed[executed.index("--target") + 1], lane.GUEST_TARGET)
            self.assertEqual(executed.count("-p"), 1)
            for forbidden in ("--workspace", "--all", "--exclude", "--manifest-path="):
                self.assertNotIn(forbidden, executed)
            target_root = Path(executed[executed.index("--target-dir") + 1])
            self.assertIn(scratch, target_root.parents)
            self.assertNotIn(ROOT / "target", target_root.parents)
            self.assertEqual(len(artifact_paths), 2)
            self.assertEqual(artifact_paths[0], artifact_paths[1])
            self.assertEqual(artifact_paths[0], lane.component_artifact_path(frozen, target_root))
            self.assertIn(scratch, artifact_paths[0].parents)
            digest, size = lane.sha256_file(artifact_paths[0])
            (first_code, first), (second_code, second) = receipts
            for exit_code, receipt in receipts:
                self.assertEqual(exit_code, 0)
                self.assertEqual(receipt["schema"], lane.RECEIPT_SCHEMA)
                self.assertEqual(receipt["status"], "PASS")
                self.assertEqual(receipt["module"], module)
                self.assertEqual(receipt["source"], {"base": base_sha, "head": head_sha})
                self.assertEqual(receipt["world"], frozen.world)
                self.assertEqual(receipt["package_id"], lane.TYPED_PACKAGE_ID)
                self.assertEqual(receipt["abi_revision"], lane.TYPED_ABI_REVISION)
                self.assertEqual(receipt["target"], lane.GUEST_TARGET)
                self.assertEqual(receipt["toolchain"], lane.TOOLCHAIN_CHANNEL)
                self.assertEqual(receipt["execution"]["disposition"], "BUILD_PASS")
                self.assertIs(receipt["execution"]["cache_skipped_verification"], False)
                self.assertEqual(
                    receipt["artifact"],
                    {"path": str(artifact_paths[0]), "sha256": digest, "bytes": size},
                )
                self.assertEqual(receipt["timing"]["baseline_s"], "UNAVAILABLE")
                self.assertNotIn("speedup", receipt["timing"])
                self.assertEqual(receipt["proof_ceiling"], "ISOLATED_COMPONENT_EVIDENCE_ONLY")
            self.assertEqual(len({receipt["execution"]["argv_sha256"] for _, receipt in receipts}), 1)
            self.assertEqual(first["execution"]["argv_sha256"], hashlib.sha256(
                json.dumps(executed, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest())
            self.assertEqual(first["execution"]["cache_identity"], second["execution"]["cache_identity"])
            self.assertRegex(first["execution"]["cache_identity"], r"^[0-9a-f]{64}$")
            self.assertIs(first["execution"]["cache_hit"], False)
            self.assertIs(second["execution"]["cache_hit"], True)
            self.assertEqual(first_code, second_code)
            self.assertEqual(type(first["timing"]["cold_s"]), float)
            self.assertGreaterEqual(first["timing"]["cold_s"], 0.0)
            self.assertEqual(first["timing"]["warm_s"], "UNAVAILABLE")
            self.assertEqual(second["timing"]["cold_s"], "UNAVAILABLE")
            self.assertEqual(type(second["timing"]["warm_s"]), float)
            self.assertGreaterEqual(second["timing"]["warm_s"], 0.0)
            miss_only = json.loads(json.dumps(first))
            hit_only = json.loads(json.dumps(second))
            hit_only["execution"]["cache_hit"] = False
            miss_only["timing"] = dict(
                miss_only["timing"], cold_s="UNAVAILABLE", warm_s="UNAVAILABLE")
            hit_only["timing"] = dict(
                hit_only["timing"], cold_s="UNAVAILABLE", warm_s="UNAVAILABLE")
            self.assertEqual(
                json.dumps(miss_only, sort_keys=True), json.dumps(hit_only, sort_keys=True))
            controller_root = scratch / "eliot-wasm-lane"
            cache_id = first["execution"]["cache_identity"]
            store_root = lane.cache_store_root(controller_root, cache_id)
            self.assertEqual(store_root.parent, controller_root)
            self.assertIn(cache_id, store_root.name)
            self.assertIn(scratch, store_root.parents)
            self.assertTrue(store_root.is_dir())
            hit_record = lane.read_cache_record(controller_root, cache_id)
            self.assertIsNotNone(hit_record)
            self.assertEqual(hit_record["schema"], lane.CACHE_RECORD_SCHEMA)
            self.assertEqual(hit_record["cache_identity"], cache_id)
            self.assertEqual(hit_record["module"], module)
            self.assertEqual(hit_record["artifact"], {
                "path": str(artifact_paths[0]), "sha256": digest, "bytes": size})
            self.assertIsNone(lane.read_cache_record(controller_root, "12" * 32))
            with self.assertRaises(lane.LaneError) as failure:
                lane.read_cache_record(controller_root, "not-a-cache-id")
            self.assertEqual(str(failure.exception), "INVALID_CACHE_IDENTITY")
            with self.assertRaises(lane.LaneError) as failure:
                lane.cache_store_root(scratch / "target" / "lane", cache_id)
            self.assertEqual(str(failure.exception), "WORKSPACE_TARGET_REUSE_DENIED")
            with self.assertRaises(lane.LaneError) as failure:
                lane.write_cache_record(
                    controller_root, cache_id, dict(hit_record, cache_identity="34" * 32))
            self.assertEqual(str(failure.exception), "CACHE_IDENTITY_MISMATCH")
            artifact_paths[0].write_bytes(b"\x00asm\x01\x00\x00\x00tampered-gate-bytes")
            self.assertNotEqual(lane.sha256_file(artifact_paths[0])[0], digest)
            self.assertIsNone(lane.read_cache_record(controller_root, cache_id))
            artifact_paths[0].write_bytes(b"\x00asm\x01\x00\x00\x00" + module.encode("ascii"))
            self.assertEqual(lane.read_cache_record(controller_root, cache_id), hit_record)

    # WORK_UNIT_CASE: 764/20
    def test_failure_unknown_and_cancellation_cannot_promote_native_release_state(self):
        module = "eliot-context-compiler-wasm"
        registry_path = ROOT / "scripts/testdata/wasm-component-lane/registry.json"
        forbidden_state_keys = {
            "product", "product_state", "release", "release_state", "pulse", "ci_green",
        }
        ceiling = "ISOLATED_COMPONENT_EVIDENCE_ONLY"

        def state_keys(value):
            if isinstance(value, dict):
                keys = set(value)
                for nested in value.values():
                    keys |= state_keys(nested)
                return keys
            if isinstance(value, list):
                keys = set()
                for nested in value:
                    keys |= state_keys(nested)
                return keys
            return set()

        def fake_tool(tool_status):
            def fake(tool_argv, cwd, timeout=lane.COMMAND_TIMEOUT):
                fake.calls.append(list(tool_argv))
                return lane.CommandResult(tool_status, b"")
            fake.calls = []
            return fake

        scenarios = (
            ("missing_registry", ["--select"], "OK",
             {"reason": "REGISTRY_REQUIRED", "expect_no_command": True}),
            ("unknown_module", ["--build", "eliot-not-registered-wasm", "--registry", None],
             "OK", {"reason": "UNKNOWN_MODULE", "expect_no_command": True}),
            ("no_work_select", ["--select", "--registry", None, "--changed", "CHANGED"], "OK",
             {"status": "FAIL", "reason": "UNRELATED_CHANGE_NO_WORK",
              "disposition": "NO_WORK", "selected": [],
              "expect_no_command": True}),
            (
                "selected_select",
                ["--select", "--registry", None, "--changed", "SELECTED_CHANGED"],
                "OK",
                {
                    "status": "FAIL",
                    "reason": "AFFECTED_WITH_DEPENDENTS",
                    "disposition": "SELECTED",
                    "selected": [module],
                    "expect_no_command": True,
                },
            ),
            ("failed_build", ["--build", module, "--registry", None], "TOOL_FAILED",
             {"execution_disposition": "FAILED"}),
            ("cancelled_test", ["--test", module, "--registry", None], "TOOL_CANCELLED",
             {"execution_disposition": "CANCELLED"}),
            ("unavailable_build", ["--build", module, "--registry", None], "TOOL_UNAVAILABLE",
             {"execution_disposition": "UNAVAILABLE"}),
            ("fake_gate_without_artifact", ["--build", module, "--registry", None], "OK",
             {"execution_disposition_not": ("BUILD_PASS", "TEST_PASS")}),
        )
        with tempfile.TemporaryDirectory() as scratch_text:
            scratch = Path(scratch_text)
            previous_tempdir = tempfile.tempdir
            tempfile.tempdir = str(scratch)
            try:
                changed_path = scratch / "changed.json"
                changed_path.write_text(json.dumps({
                    "paths": ["README.md"],
                    "shared_prefixes": [],
                    "native_contract_prefixes": {},
                    "unrelated_prefixes": ["README.md"],
                    "dependents": {},
                }), encoding="utf-8")
                selected_changed_path = scratch / "selected-changed.json"
                selected_changed_path.write_text(json.dumps({
                    "paths": ["crates/smart/eliot-context-compiler-wasm/src/lib.rs"],
                    "shared_prefixes": [],
                    "native_contract_prefixes": {},
                    "unrelated_prefixes": [],
                    "dependents": {},
                }), encoding="utf-8")
                payloads = []
                stdout_by_scenario = {}
                for index, (label, argv, tool_status, expected) in enumerate(scenarios):
                    with self.subTest(scenario=label):
                        invocation = [
                            str(changed_path) if part == "CHANGED" else
                            str(selected_changed_path) if part == "SELECTED_CHANGED" else part
                            for part in argv
                        ]
                        invocation = [
                            str(registry_path) if part is None else part for part in invocation
                        ]
                        receipt_path = scratch / f"receipt-{index}-{label}.json"
                        fake = fake_tool(tool_status)
                        buffer = io.StringIO()
                        with mock.patch.object(lane, "_run", fake):
                            with contextlib.redirect_stdout(buffer):
                                exit_code = lane.main(invocation + [
                                    "--receipt-out", str(receipt_path),
                                    "--base-sha", "11" * 20,
                                    "--head-sha", "22" * 20,
                                ])
                        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
                        payloads.append(payload)
                        stdout_by_scenario[label] = buffer.getvalue()
                        self.assertNotEqual(exit_code, 0)
                        self.assertNotEqual(payload.get("status"), "PASS")
                        self.assertEqual(payload.get("proof_ceiling"), ceiling)
                        self.assertEqual(state_keys(payload) & forbidden_state_keys, set())
                        if "reason" in expected:
                            self.assertEqual(payload.get("reason"), expected["reason"])
                        if "status" in expected:
                            self.assertEqual(payload.get("status"), expected["status"])
                        if "disposition" in expected:
                            self.assertEqual(payload.get("disposition"), expected["disposition"])
                        if "selected" in expected:
                            self.assertEqual(payload.get("selected"), expected["selected"])
                        if "execution_disposition" in expected:
                            self.assertEqual(
                                payload["execution"]["disposition"],
                                expected["execution_disposition"],
                            )
                        if "execution_disposition_not" in expected:
                            self.assertNotIn(
                                payload["execution"]["disposition"],
                                expected["execution_disposition_not"],
                            )
                        if "execution" in payload:
                            self.assertIs(payload["execution"]["cache_skipped_verification"], False)
                        if expected.get("expect_no_command"):
                            self.assertEqual(fake.calls, [])
                        else:
                            self.assertEqual(len(fake.calls), 1)
                            for call in fake.calls:
                                self.assertIn(call[0], ("cargo", "rustc"))
                                self.assertIn(module, call)
                                self.assertNotIn("--workspace", call)
            finally:
                tempfile.tempdir = previous_tempdir
            self.assertEqual(len(payloads), len(scenarios))
            for payload in payloads:
                if payload.get("status") == "PASS":
                    self.assertEqual(payload["proof_ceiling"], ceiling)
            self.assertEqual(
                {payload["proof_ceiling"] for payload in payloads}, {ceiling})
            self.assertEqual(
                [payload for payload in payloads if payload.get("status") == "PASS"], [])
            for label in ("no_work_select", "selected_select"):
                with self.subTest(selection_text_output=label):
                    lines = stdout_by_scenario[label].splitlines()
                    self.assertEqual(len(lines), 1)
                    self.assertTrue(lines[0].startswith("WASM_COMPONENT_LANE: FAIL "))

            # A zero exit from a filtered harness is not execution evidence.
            # Each of these tools "succeeds" yet must stay non-green, because
            # the declared capsule test did not demonstrably run and pass.
            frozen = lane.freeze_module(ROOT, module, lane.resolve_module(FIXTURE, module))
            declared_test = frozen.capsule_test_name
            artifact_bytes = b"\x00asm\x01\x00\x00\x00" + module.encode("ascii")
            zero_selected = (
                "\n     Running tests/proof.rs (target/debug/deps/proof-abc)\n"
                "running 0 tests\n"
                "\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; "
                "1 filtered out; finished in 0.00s\n"
            ).encode("utf-8")
            wrong_test_passed = (
                "\n     Running tests/proof.rs (target/debug/deps/proof-abc)\n"
                "test some_other_proof_test ... ok\n"
                "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.01s\n"
            ).encode("utf-8")
            failed_summary = (
                f"test {declared_test} ... ok\n"
                "\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.01s\n"
            ).encode("utf-8")
            capsule_scenarios = (
                ("zero_selected_capsule", zero_selected, True,
                 "FAILED", "CAPSULE_TEST_NOT_EXECUTED"),
                ("wrong_test_passed", wrong_test_passed, True,
                 "FAILED", "CAPSULE_TEST_NOT_EXECUTED"),
                ("no_harness_summary", b"Compiling eliot v0.1.0\n", True,
                 "UNAVAILABLE", "CAPSULE_RESULT_UNAVAILABLE"),
                ("failed_capsule_summary", failed_summary, True,
                 "FAILED", "CAPSULE_TEST_FAILED"),
                ("capsule_without_artifact",
                 f"test {declared_test} ... ok\n"
                 "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                 "0 filtered out; finished in 0.01s\n".encode("utf-8"),
                 False, "UNAVAILABLE", "ARTIFACT_UNAVAILABLE"),
            )
            for label, output, writes_artifact, expected_disposition, expected_reason in (
                capsule_scenarios
            ):
                with self.subTest(capsule_scenario=label):
                    # Each scenario gets its own controller root: a lane
                    # target root is a deterministic function of the frozen
                    # digests, so a shared root would let one scenario's
                    # artifact satisfy a later scenario that must not have
                    # one.
                    with tempfile.TemporaryDirectory() as capsule_scratch_text:
                        capsule_scratch = Path(capsule_scratch_text)
                        capsule_tempdir = tempfile.tempdir
                        tempfile.tempdir = str(capsule_scratch)
                        try:

                            def fake_capsule(tool_argv, cwd, timeout=lane.COMMAND_TIMEOUT,
                                             _out=output, _writes=writes_artifact):
                                if _writes:
                                    target_dir = Path(tool_argv[tool_argv.index("--target-dir") + 1])
                                    artifact_path = lane.component_artifact_path(frozen, target_dir)
                                    artifact_path.parent.mkdir(parents=True, exist_ok=True)
                                    artifact_path.write_bytes(artifact_bytes)
                                return lane.CommandResult("OK", _out)

                            capsule_receipt = capsule_scratch / "receipt.json"
                            with mock.patch.object(lane, "_run", fake_capsule):
                                with contextlib.redirect_stdout(io.StringIO()):
                                    capsule_code = lane.main([
                                        "--test", module,
                                        "--registry", str(registry_path),
                                        "--receipt-out", str(capsule_receipt),
                                        "--base-sha", "11" * 20,
                                        "--head-sha", "22" * 20,
                                    ])
                            capsule_payload = json.loads(
                                capsule_receipt.read_text(encoding="utf-8"))
                        finally:
                            tempfile.tempdir = capsule_tempdir
                    self.assertNotEqual(capsule_code, 0)
                    self.assertEqual(capsule_payload.get("status"), "FAIL")
                    self.assertEqual(capsule_payload.get("reason"), expected_reason)
                    self.assertEqual(
                        capsule_payload["execution"]["disposition"], expected_disposition)
                    self.assertIsNone(capsule_payload["capsule"]["report"])
                    if not writes_artifact:
                        self.assertIsNone(capsule_payload["artifact"])
                    self.assertEqual(capsule_payload["proof_ceiling"], ceiling)
                    self.assertEqual(
                        state_keys(capsule_payload) & forbidden_state_keys, set())

    # WORK_UNIT_CASE: 764/4
    def test_traversal_absolute_separator_shell_injection_fail_before_commands(self):
        calls = []

        def never(argv, cwd, timeout=lane.COMMAND_TIMEOUT):
            calls.append(list(argv))
            self.fail("injection must not construct or execute a command")

        battery = [
            "../eliot-context-compiler-wasm",
            "..\\eliot-context-compiler-wasm",
            "/etc/passwd",
            "C:\\Windows\\Temp\\x",
            "crates/smart/eliot-context-compiler-wasm",
            "eliot-context-compiler-wasm;rm -rf /",
            "eliot-context-compiler-wasm|cat",
            "eliot-context-compiler-wasm&cargo build --workspace",
            "$(cargo build --workspace)",
            "`cargo build --workspace`",
            "eliot-context-compiler-wasm\ncargo build --workspace",
            "${CARGO_HOME}",
            "eliot-context-compiler-wasm*",
            "",
            "x" * 65,
        ]
        for attempt in battery:
            with self.subTest(attempt=attempt[:24]):
                with self.assertRaises(lane.LaneError):
                    lane.resolve_module(FIXTURE, attempt)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
