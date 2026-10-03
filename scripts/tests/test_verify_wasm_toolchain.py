"""#870 declared test matrix for scripts/verify-wasm-toolchain.py.

One substantive, independently executable test per declared case 870/1..870/16,
each carrying its `# WORK_UNIT_CASE: 870/<n>` marker immediately above the
method. Every case exercises the real checker: declaration parsing over fixed
fixtures, the documented offline CLI invocation, and the private command seam
(`_run`, `shutil.which`) for the diagnostic and probe paths.

No network, no install, no ambient rustup repair and no simulated green compile.
The probe case asserts the live recorded probe argv; a fake tool never proves
live Rust, so the clean-environment bootstrap artifact stays deferred as
separate clean-runner execution evidence (cards/870.md DEFER).
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-wasm-toolchain.py"
TESTDATA = ROOT / "scripts/testdata/wasm-toolchain"
FIXTURE_VALID = TESTDATA / "valid.toml"
FIXTURE_MISSING_GUEST = TESTDATA / "missing-guest-target.toml"
FIXTURE_DUPLICATE_TARGET = TESTDATA / "duplicate-target.toml"
FIXTURE_UNSUPPORTED_GUEST = TESTDATA / "unsupported-guest-target.toml"
FIXTURE_UNOWNED_EXTRA = TESTDATA / "unowned-extra-target.toml"
FIXTURE_REORDERED = TESTDATA / "reordered-targets.toml"
FIXTURE_CHANNEL_CHANGED = TESTDATA / "channel-changed.toml"
FIXTURE_GUEST_CHANGED = TESTDATA / "guest-target-changed.toml"
PINNED_CHANNEL = "1.97.1"
PINNED_COMPONENTS = b'["clippy", "rustfmt", "rust-analyzer", "rust-src"]'
# cards/870.md declares exactly seven fixture files, so these two documents stay
# inline bytes literals rather than becoming new fixtures.
MOVING_STABLE = (
    b'[toolchain]\nchannel = "stable"\nprofile = "default"\n'
    b'components = ' + PINNED_COMPONENTS + b"\n"
    b'targets = ["x86_64-pc-windows-msvc", "wasm32-wasip2"]\n'
)
HOST_MISSING = (
    b'[toolchain]\nchannel = "' + PINNED_CHANNEL.encode() + b'"\nprofile = "default"\n'
    b'components = ' + PINNED_COMPONENTS + b"\n"
    b'targets = ["wasm32-wasip2"]\n'
)
spec = importlib.util.spec_from_file_location("eliot_wasm_toolchain_check", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = check
spec.loader.exec_module(check)


class ToolchainTests(unittest.TestCase):
    # WORK_UNIT_CASE: 870/1
    def test_exact_current_toolchain_declaration_parses(self) -> None:
        """The repository's own declaration is accepted and is the pinned one."""
        declared = check.read_declaration(ROOT)
        self.assertEqual(declared.channel, PINNED_CHANNEL)
        self.assertEqual(declared.profile, "default")
        self.assertEqual(set(declared.components), set(check.COMPONENTS))
        self.assertEqual(len(declared.targets), 2)
        self.assertEqual(declared, check.parse_declaration(FIXTURE_VALID.read_bytes()))

    # WORK_UNIT_CASE: 870/2
    def test_channel_remains_pinned_not_moving_stable(self) -> None:
        """The channel stays a pin; a moving `stable` document is refused."""
        declared = check.read_declaration(ROOT)
        self.assertEqual(declared.channel, PINNED_CHANNEL)
        self.assertIn(b'channel = "stable"', MOVING_STABLE)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(MOVING_STABLE)
        self.assertEqual(str(caught.exception), "CHANNEL_NOT_PINNED")

    # WORK_UNIT_CASE: 870/3
    def test_required_host_target_retained(self) -> None:
        """The host triple stays declared; a guest-only document is refused."""
        self.assertIn(check.HOST_TARGET, check.read_declaration(ROOT).targets)
        self.assertIn(b'targets = ["wasm32-wasip2"]', HOST_MISSING)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(HOST_MISSING)
        self.assertEqual(str(caught.exception), "HOST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/4
    def test_pinned_guest_target_declared_once(self) -> None:
        """Exactly one accepted guest target, declared once beside the host."""
        self.assertEqual(check.GUEST_TARGET, "wasm32-wasip2")
        self.assertEqual(check.HOST_TARGET, "x86_64-pc-windows-msvc")
        targets = check.read_declaration(ROOT).targets
        self.assertEqual(targets.count(check.GUEST_TARGET), 1)
        self.assertEqual(set(targets), {check.HOST_TARGET, check.GUEST_TARGET})

    # WORK_UNIT_CASE: 870/5
    def test_missing_guest_target_gives_stable_prerequisite_failure(self) -> None:
        """A guest-less declaration fails closed on the prerequisite, not semantics."""
        raw = FIXTURE_MISSING_GUEST.read_bytes()
        self.assertNotIn(b"wasm32-wasip2", raw)
        self.assertIn(b'targets = ["x86_64-pc-windows-msvc"]', raw)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(raw)
        self.assertEqual(str(caught.exception), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/6
    def test_duplicate_guest_target_rejected(self) -> None:
        """The guest target is declared at most once, exactly as it is here."""
        raw = FIXTURE_DUPLICATE_TARGET.read_bytes()
        self.assertEqual(raw.count(b"wasm32-wasip2"), 2)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(raw)
        self.assertEqual(str(caught.exception), "DUPLICATE_TARGETS")

    # WORK_UNIT_CASE: 870/7
    def test_unsupported_guest_target_rejected(self) -> None:
        """No fallback target exists: another wasm triple is not the guest target.

        docs/architecture/I14-19-wasm-components.md line 17: "`wasm32-unknown-unknown`
        may be used for a completely self-contained library experiment, but it is
        not the standard capability-oriented component target." The checker has no
        UNSUPPORTED_TARGET reason code and must not gain one, so the closed reason
        here is GUEST_TARGET_MISSING with the substituted triple declared.
        """
        raw = FIXTURE_UNSUPPORTED_GUEST.read_bytes()
        self.assertIn(b"wasm32-unknown-unknown", raw)
        self.assertNotIn(b"wasm32-wasip2", raw)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(raw)
        self.assertEqual(str(caught.exception), "GUEST_TARGET_MISSING")

    # WORK_UNIT_CASE: 870/8
    def test_additional_unowned_wasm_target_rejected(self) -> None:
        """The declared set is exactly host plus the accepted guest, never more."""
        raw = FIXTURE_UNOWNED_EXTRA.read_bytes()
        self.assertIn(b"wasm32-wasip1", raw)
        self.assertIn(b"wasm32-wasip2", raw)
        with self.assertRaises(check.ToolchainError) as caught:
            check.parse_declaration(raw)
        self.assertEqual(str(caught.exception), "UNOWNED_TARGET")

    # WORK_UNIT_CASE: 870/9
    def test_reordered_equivalent_targets_follow_canonical_order(self) -> None:
        """File order is not declaration order, and the identity is unaffected.

        `_unique_strings` normalises every list to `tuple(sorted(value))`
        (scripts/verify-wasm-toolchain.py:70), which is the only canonical-order
        policy in force here; no further ordering rule is claimed.
        """
        text = FIXTURE_REORDERED.read_text(encoding="utf-8")
        self.assertLess(text.index("wasm32-wasip2"), text.index("x86_64-pc-windows-msvc"))
        reordered = check.parse_declaration(FIXTURE_REORDERED.read_bytes())
        baseline = check.parse_declaration(FIXTURE_VALID.read_bytes())
        self.assertEqual(reordered, baseline)
        self.assertEqual(reordered.digest, baseline.digest)
        self.assertEqual(reordered.targets, tuple(sorted(reordered.targets)))

    # WORK_UNIT_CASE: 870/10
    def test_changed_channel_invalidates_semantic_toolchain_identity(self) -> None:
        """The declaration digest covers the channel, so a re-pin moves it."""
        changed = check.parse_declaration(FIXTURE_CHANNEL_CHANGED.read_bytes())
        baseline = check.parse_declaration(FIXTURE_VALID.read_bytes())
        self.assertEqual(changed.channel, "1.98.0")
        self.assertEqual(baseline.channel, PINNED_CHANNEL)
        self.assertEqual(changed.targets, baseline.targets)
        self.assertNotEqual(changed.digest, baseline.digest)

    # WORK_UNIT_CASE: 870/11
    def test_changed_guest_target_invalidates_toolchain_identity(self) -> None:
        """A substituted guest target is refused, and no digest branch exists.

        `parse_declaration` raises at scripts/verify-wasm-toolchain.py:100, which
        is before the Declaration is constructed at :103, so a refused document
        has no digest and a digest comparison is impossible here. Identity is
        invalidated by the gate order instead: the substituted document raises
        GUEST_TARGET_MISSING at :100, while host+guest+an extra wasm target raises
        UNOWNED_TARGET at :102. Two distinct reason codes from the same parser
        prove the guest gate and the ownership gate are separate decisions.
        """
        substituted = FIXTURE_GUEST_CHANGED.read_bytes()
        self.assertIn(b"wasm32-wasip1", substituted)
        self.assertNotIn(b"wasm32-wasip2", substituted)
        with self.assertRaises(check.ToolchainError) as guest_gate:
            check.parse_declaration(substituted)
        with self.assertRaises(check.ToolchainError) as ownership_gate:
            check.parse_declaration(FIXTURE_UNOWNED_EXTRA.read_bytes())
        self.assertEqual(str(guest_gate.exception), "GUEST_TARGET_MISSING")
        self.assertEqual(str(ownership_gate.exception), "UNOWNED_TARGET")
        self.assertNotEqual(str(guest_gate.exception), str(ownership_gate.exception))

    # WORK_UNIT_CASE: 870/12
    def test_normal_checker_has_no_network_install_or_mutation_path(self) -> None:
        """The documented invocation launches nothing, installs nothing, mutates nothing.

        `_run` is a tripwire here, not a CommandResult source: the normal path must
        never reach a tool at all, so any argv recorded is itself the failure. Two
        roots, two jobs: the real repository root proves the documented invocation
        returns 0 on the real declaration, and a temporary root seeded with the real
        `rust-toolchain.toml` bytes proves the listing is unchanged afterwards. The
        repository root is never listed as a directory: it legitimately holds far
        more entries than the single declaration file.
        """
        launched: list[list[str]] = []

        def tripwire(argv, cwd, timeout):
            launched.append(list(argv))
            raise AssertionError(f"the normal path launched a tool: {list(argv)!r}")

        captured = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            (temp_root / "rust-toolchain.toml").write_bytes(
                (ROOT / "rust-toolchain.toml").read_bytes()
            )
            before = sorted(p.name for p in temp_root.iterdir())
            self.assertEqual(before, ["rust-toolchain.toml"])
            with mock.patch.object(check.shutil, "which", lambda name: "rustup"):
                with mock.patch.object(check, "_run", tripwire):
                    with contextlib.redirect_stdout(captured):
                        code = check.main(["--root", str(ROOT), "--format", "json"])
                        temp_code = check.main(
                            ["--root", str(temp_root), "--format", "json"]
                        )
            after = sorted(p.name for p in temp_root.iterdir())
        self.assertEqual(launched, [])
        self.assertEqual(after, before)
        self.assertEqual(code, 0)
        self.assertEqual(temp_code, 0)
        lines = captured.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 2)
        for document in (json.loads(lines[0]), json.loads(lines[1])):
            self.assertEqual(document["status"], "PASS")
            self.assertEqual(document["installed"], "NOT_CHECKED")
            self.assertEqual(document["compilable"], "NOT_RUN")
            self.assertEqual(document["proof_ceiling"], "DECLARATION_ONLY")
            self.assertEqual(document["reason"], "DECLARED_NOT_EXECUTED")
            self.assertIs(document["clean_bootstrap_qualified"], False)

    # WORK_UNIT_CASE: 870/13
    def test_ambient_installed_target_without_declaration_still_fails(self) -> None:
        """An ambient rustup cannot substitute for the missing declaration.

        `which` records every call and answers "rustup" - that is the whole fiction
        of an ambient install - and `_run` is a tripwire, so the recorded call list
        also proves the declaration gate is decided before any installation
        question is asked. The FAIL branch at :400-401 never sets the installation
        fields, so an ambient toolchain can never be reported from here.
        """
        asked: list[str] = []

        def fake_which(name):
            asked.append(name)
            return "rustup"

        def tripwire(argv, cwd, timeout):
            raise AssertionError(f"no tool may run: {list(argv)!r}")

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_bytes(FIXTURE_MISSING_GUEST.read_bytes())
            with mock.patch.object(check.shutil, "which", fake_which):
                with mock.patch.object(check, "_run", tripwire):
                    with contextlib.redirect_stdout(buffer):
                        code = check.main(["--root", str(root), "--format", "json"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["reason"], "GUEST_TARGET_MISSING")
        self.assertIsNone(payload.get("installed"))
        self.assertEqual(asked, [])

    # WORK_UNIT_CASE: 870/14
    def test_fixed_diagnostic_distinguishes_declaration_installation_compilation(self) -> None:
        """`--diagnostic` observes installation and never claims compilation.

        `shutil.which` is patched alongside `_run`: without it `diagnose`
        short-circuits with RUSTUP_UNAVAILABLE on any machine that happens to have
        rustup, and the case would silently become machine-dependent. The injected
        failures are reported as their own bounded reason codes, never as a pass.
        """
        declaration = check.read_declaration(ROOT)
        listing = f"{declaration.channel}-x86_64-pc-windows-msvc (default)\n".encode()
        version = b"release: " + declaration.channel.encode() + b"\ncommit-hash: " + b"a" * 40 + b"\n"
        installed = (check.HOST_TARGET + "\n" + check.GUEST_TARGET + "\n").encode()

        def observation(toolchain_result, version_result):
            def fake_run(argv, cwd, timeout):
                self.assertEqual(argv[0], "rustup")
                if argv[1:3] == ["toolchain", "list"]:
                    if toolchain_result is not None:
                        return toolchain_result
                    return check.CommandResult("OK", listing)
                if argv[1:4] == ["run", declaration.channel, "rustc"]:
                    if version_result is not None:
                        return version_result
                    return check.CommandResult("OK", version)
                if argv[1:3] == ["target", "list"]:
                    return check.CommandResult("OK", installed)
                raise AssertionError(f"unexpected diagnostic command: {list(argv)!r}")
            return fake_run

        with mock.patch.object(check.shutil, "which", lambda name: "rustup"):
            with mock.patch.object(check, "_run", observation(None, None)):
                healthy = check.diagnose(declaration)
            with mock.patch.object(check, "_run", observation(check.CommandResult("TOOL_FAILED"), None)):
                failed = check.diagnose(declaration)
            with mock.patch.object(check, "_run", observation(check.CommandResult("TOOL_UNAVAILABLE"), None)):
                unavailable = check.diagnose(declaration)
        self.assertEqual(healthy["status"], "PASS")
        self.assertEqual(healthy["reason"], "INSTALLED_NOT_COMPILED")
        self.assertEqual(healthy["proof_ceiling"], "INSTALLED_TOOLCHAIN_ONLY")
        self.assertEqual(healthy["compilable"], "NOT_RUN")
        self.assertIs(healthy["installed"], True)
        self.assertNotEqual(failed["status"], "PASS")
        self.assertEqual(failed["reason"], "TOOL_FAILED")
        self.assertNotEqual(unavailable["status"], "PASS")
        self.assertEqual(unavailable["reason"], "TOOL_UNAVAILABLE")

    # WORK_UNIT_CASE: 870/15
    def test_probe_argv_pins_wasip2_without_manual_target_add(self) -> None:
        """The probe itself compiles for wasip2; no target-add step precedes it.

        This case asserts the live recorded probe argv, never a simulated green
        compile. `RUSTUP_AUTO_INSTALL = "0"` (scripts/verify-wasm-toolchain.py:141)
        plus the `RUSTUP_*`/`RUSTC_*` environment scrub at :142-144 are the
        existing static evidence that the checker never repairs the environment,
        and `clean_bootstrap_qualified` is initialised False at :222 and never
        assigned True, so the checker cannot self-certify a clean bootstrap. The
        real clean-environment artifact is separate clean-runner execution evidence
        and is deferred by cards/870.md; a fake tool may not replace it.
        """
        listing = f"{PINNED_CHANNEL}-x86_64-pc-windows-msvc (default)\n".encode()
        version = b"release: " + PINNED_CHANNEL.encode() + b"\ncommit-hash: " + b"a" * 40 + b"\n"
        installed = (check.HOST_TARGET + "\n" + check.GUEST_TARGET + "\n").encode()
        recorded: list[list[str]] = []

        def recording_run(argv, cwd, timeout):
            recorded.append(list(argv))
            if "--edition=2021" in argv or "--target" in argv:
                raise AssertionError(f"no simulated compile: {list(argv)!r}")
            if argv[1:3] == ["toolchain", "list"]:
                return check.CommandResult("OK", listing)
            if argv[1:4] == ["run", PINNED_CHANNEL, "rustc"]:
                return check.CommandResult("OK", version)
            if argv[1:3] == ["target", "list"]:
                return check.CommandResult("OK", installed)
            raise AssertionError(f"unexpected probe command: {list(argv)!r}")

        with mock.patch.object(check.shutil, "which", lambda name: "rustup"):
            with mock.patch.object(check, "_run", recording_run):
                with self.assertRaises(AssertionError):
                    check.diagnose(check.read_declaration(ROOT), probe=True)
        self.assertEqual(len(recorded), 4)
        self.assertEqual(recorded[0][1:3], ["toolchain", "list"])
        self.assertEqual(recorded[2][1:3], ["target", "list"])
        probes = [argv for argv in recorded if "--target" in argv]
        self.assertEqual(len(probes), 1)
        probe = probes[0]
        self.assertEqual(probe[0], "rustup")
        self.assertEqual(probe[1:4], ["run", PINNED_CHANNEL, "rustc"])
        self.assertEqual(probe[probe.index("--target") + 1], "wasm32-wasip2")
        self.assertIn("--edition=2021", probe)
        self.assertIn("--crate-type=bin", probe)
        self.assertNotIn("target add", SCRIPT.read_text(encoding="utf-8"))

    # WORK_UNIT_CASE: 870/16
    def test_missing_target_probe_is_toolchain_prerequisite_failure(self) -> None:
        """`--probe` on a guest-less root fails at the declaration, not the guest.

        A missing target is a toolchain prerequisite, so the run fails closed with
        GUEST_TARGET_MISSING and exit 1 and never produces a `diagnose` result: the
        installation and compilation fields stay unset and no tool is launched.
        That keeps a prerequisite failure distinguishable from a guest/WIT semantic
        verdict, which this checker never renders.
        """
        launched: list[list[str]] = []

        def tripwire(argv, cwd, timeout):
            launched.append(list(argv))
            raise AssertionError(f"--probe must not run a tool: {list(argv)!r}")

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_bytes(FIXTURE_MISSING_GUEST.read_bytes())
            with mock.patch.object(check.shutil, "which", lambda name: "rustup"):
                with mock.patch.object(check, "_run", tripwire):
                    with contextlib.redirect_stdout(buffer):
                        code = check.main(
                            ["--root", str(root), "--format", "json", "--probe"]
                        )
            listing = sorted(p.name for p in root.iterdir())
        payload = json.loads(buffer.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["reason"], "GUEST_TARGET_MISSING")
        self.assertIsNone(payload.get("installed"))
        self.assertIsNone(payload.get("compilable"))
        self.assertEqual(launched, [])
        self.assertEqual(listing, ["rust-toolchain.toml"])


if __name__ == "__main__":
    unittest.main()