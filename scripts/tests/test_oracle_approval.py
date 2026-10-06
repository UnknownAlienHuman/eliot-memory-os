"""Unit tests for GitHub-attested oracle approval authority (issue #1225 AUD2/AUD3)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

# Load scripts/work_unit_gate/doc_read_evidence.py dynamically
_script_path = Path(__file__).resolve().parents[1] / "work_unit_gate" / "doc_read_evidence.py"
_spec = importlib.util.spec_from_file_location("work_unit_gate_doc_read_evidence", _script_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_script_path}")
dre = importlib.util.module_from_spec(_spec)
sys.modules["work_unit_gate_doc_read_evidence"] = dre
_spec.loader.exec_module(dre)

HEAD = "b" * 40
OLD_HEAD = "a" * 40


def _review(login: str, state: str = "APPROVED", commit: str = HEAD,
            association: str = "MEMBER") -> dict:
    return {
        "id": 1,
        "user": {"login": login},
        "state": state,
        "commit_id": commit,
        "author_association": association,
        "submitted_at": "2026-10-05T00:00:00Z",
    }


class TestOracleApproval(unittest.TestCase):
    def test_valid_approval_accepted(self) -> None:
        accepted = dre._require_oracle_approval([_review("blind-reviewer")], "pr-author", HEAD)
        self.assertEqual(accepted["user"]["login"], "blind-reviewer")

    def test_missing_snapshot_refused(self) -> None:
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval(None, "pr-author", HEAD)

    def test_fictional_reviewer_refused(self) -> None:
        # A made-up reviewer login with no APPROVED review behind it counts
        # for nothing: only a GitHub-attested review authorizes.
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval([_review("someone-else", state="COMMENTED")], "pr-author", HEAD)

    def test_real_login_without_approval_refused(self) -> None:
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval([_review("maintainer", state="CHANGES_REQUESTED")], "pr-author", HEAD)

    def test_self_approval_refused(self) -> None:
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval([_review("PR-Author")], "pr-author", HEAD)

    def test_stale_head_approval_refused(self) -> None:
        # An APPROVED review on an older head dies with the re-push.
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval([_review("blind-reviewer", commit=OLD_HEAD)], "pr-author", HEAD)

    def test_unadmitted_association_refused(self) -> None:
        with self.assertRaises(dre.EvidenceError):
            dre._require_oracle_approval(
                [_review("blind-reviewer", association="NONE")], "pr-author", HEAD
            )


if __name__ == "__main__":
    unittest.main()
