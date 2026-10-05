"""Issue #1719 W3 disposition-aware front-door wiring lock: scripts/build-eliot-windows-x64-release.ps1 under the full release gate norm docs/architecture/I18-13-full-release-gate.md and docs/release/WINDOWS_X64_RELEASE.md:16 (disposition-derived selection)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "scripts" / "build-eliot-windows-x64-release.ps1"
RELEASE_DOC = ROOT / "docs" / "release" / "WINDOWS_X64_RELEASE.md"

DISPOSITION_RESOLVE = "$governorDisposition = Resolve-GovernorDisposition"
FRONT_DOOR_SELECTION = "$frontDoorSelection = if ($legacyGovernorPresent)"
FRONT_DOOR_BRIDGE_PLAN = "$frontDoorBridgePlan = Get-FrontDoorBridgePlan"
W3_COMMENT = re.compile(r"computed AFTER the\s*(?:#\s*)?disposition resolves")
PLAN_DEFINITION = "function Get-FrontDoorBridgePlan"
PLAN_INVOCATION = re.compile(
    r"^.*Get-FrontDoorBridgePlan \$cargoMetadata \$frontDoorSelection.*$",
    re.MULTILINE,
)
DIRECT_SELECTION_CALL = re.compile(r"Get-FrontDoorBridgePlan .*\$ClaudeCodeFrontDoor")
RETIRED_LEGACY_ABORT = (
    "explicit -ClaudeCodeFrontDoor legacy contradicts the resolved Retired governor disposition"
)
SELECTION_EMITTER = "selection = $frontDoorSelection"
LEGACY_SELECTION_EMITTER = "selection = $ClaudeCodeFrontDoor"
PLAN_HASH_SITE = "legacy_available"
STAGE_VERIFY_SITE = "bridge_provisioned"
DISPOSITION_DERIVED_SELECTION = "disposition-derived selection"
RETIRED_ALWAYS_PROVISIONS = "Retired always provisions"


class TestReleaseFrontDoorSelection1719(unittest.TestCase):
    def test_disposition_resolves_before_front_door_plan(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn(DISPOSITION_RESOLVE, text)
        self.assertIn(FRONT_DOOR_SELECTION, text)
        self.assertIn(FRONT_DOOR_BRIDGE_PLAN, text)
        disposition_offset = text.find(DISPOSITION_RESOLVE)
        selection_offset = text.find(FRONT_DOOR_SELECTION)
        bridge_plan_offset = text.find(FRONT_DOOR_BRIDGE_PLAN)
        self.assertLess(disposition_offset, selection_offset)
        self.assertLess(selection_offset, bridge_plan_offset)
        self.assertIsNotNone(
            W3_COMMENT.search(text),
            "the W3 comment block above the plan call says it is computed AFTER the disposition resolves",
        )

    def test_single_plan_call_uses_selection_var(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        invocations = PLAN_INVOCATION.findall(text)
        self.assertEqual(
            len(invocations),
            1,
            "exactly one Get-FrontDoorBridgePlan invocation passes $frontDoorSelection",
        )
        call_lines = [
            line
            for line in text.splitlines()
            if "Get-FrontDoorBridgePlan" in line and PLAN_DEFINITION not in line
        ]
        self.assertEqual(
            call_lines,
            invocations,
            "the only non-definition Get-FrontDoorBridgePlan line is the selection-variable call",
        )
        self.assertIsNone(
            DIRECT_SELECTION_CALL.search(text),
            "no Get-FrontDoorBridgePlan call passes $ClaudeCodeFrontDoor directly",
        )

    def test_explicit_legacy_against_retired_aborts(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertIn(RETIRED_LEGACY_ABORT, text)

    def test_both_emitters_record_selection_var(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        self.assertGreaterEqual(
            text.count(SELECTION_EMITTER),
            2,
            "the plan hash site and the stage/verify site both record the selection variable",
        )
        self.assertEqual(
            text.count(LEGACY_SELECTION_EMITTER),
            0,
            "no emitter records the raw operator flag as the selection",
        )
        self.assertIn(PLAN_HASH_SITE, text)
        self.assertIn(STAGE_VERIFY_SITE, text)

    def test_release_doc_records_disposition_derived_selection(self) -> None:
        doc = RELEASE_DOC.read_text(encoding="utf-8")
        self.assertIn(DISPOSITION_DERIVED_SELECTION, doc)
        self.assertIn(RETIRED_ALWAYS_PROVISIONS, doc)


if __name__ == "__main__":
    unittest.main()
