"""Regression probe for scripts/verify-branch-protection.py (issue #3004 W10).

This is the proof that makes the rest of the readback trustworthy. It constructs
the PERFECT rule shape and every DEFECTIVE shape the W10 clause names, runs the
real ``compare()`` over each, and asserts the verdict. It performs no network
call and never touches branch protection: every observation is a constructed
payload handed straight to the comparison, so the probe cannot itself change the
live state it measures.

The eight required shapes, and what each must yield:

    perfect                            -> MATCH (no findings)
    bare context, any app              -> BP-APP-UNBOUND
    wrong app                          -> BP-APP-MISMATCH
    renamed emitter job                -> BP-RULE-UNBOUND
    wrong default branch               -> BP-DEFAULT-BRANCH
    non-strict                         -> BP-NOT-STRICT
    enforce_admins false               -> BP-BYPASS-ALLOWED
    undeclared bypass actor            -> BP-BYPASS-ALLOWED
    missing context                    -> BP-CONTEXT-MISSING

plus the additional fail-closed shapes this lane demonstrated: an app-level
push exemption, an active ruleset bypass actor, a declared-but-absent
break-glass actor, and the three retained-rule-weakening shapes.

Exit code 0 only when every assertion holds. A single accepted defective shape
makes the suite fail, which is the whole point: a readback that cannot be shown
to reject the wrong rule is not a readback.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-branch-protection.py"
EXPECTED_RULE = ROOT / "config/merge-compile-enforcement.json"
EMITTED = ROOT / ".github/workflows/ci.yml"

_spec = importlib.util.spec_from_file_location("verify_branch_protection", SCRIPT)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Cannot load {_spec and SCRIPT}")
vbp = importlib.util.module_from_spec(_spec)
sys.modules["verify_branch_protection"] = vbp
_spec.loader.exec_module(vbp)


def retained_rule() -> dict:
    """The checked-in retained expected rule, exactly as the readback loads it."""
    return json.loads(EXPECTED_RULE.read_text(encoding="utf-8"))


def live_protection(**overrides) -> dict:
    """A perfect observed protection rule, with named fields overridable.

    The payload is shaped by ``read_protection`` ITSELF through a stubbed
    ``gh_api``, not by a copy of its logic. A probe that reimplemented the
    shaping would keep passing after the reader stopped reading a surface -- the
    mutation run caught exactly that -- so the reader is the only thing under
    test here.
    """
    raw = {
        "required_status_checks": {
            "strict": True,
            "contexts": [],
            "checks": [{"context": "merge-compile", "app_id": 15368}],
        },
        "enforce_admins": {"enabled": True},
        "restrictions": {"users": [], "teams": [], "apps": []},
    }
    for key, value in overrides.items():
        if value is _ABSENT:
            raw.pop(key, None)
        else:
            raw[key] = value
    return shape_protection(raw)


def shape_protection(raw: dict) -> dict:
    """Run a raw GitHub protection payload through the real ``read_protection``."""
    original = vbp.gh_api
    vbp.gh_api = lambda path: (0, json.dumps(raw))
    try:
        return vbp.read_protection("owner/repo", "main")
    finally:
        vbp.gh_api = original


class _Absent:
    """Sentinel: remove a key rather than set it to None."""

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return "<ABSENT>"


_ABSENT = _Absent()


def active_ruleset(**overrides) -> dict:
    """An active ruleset that carries the retained context and no bypass actor."""
    ruleset = {
        "id": 1,
        "name": "main merge gate",
        "enforcement": "active",
        "bypass_actors": [],
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {"context": "merge-compile", "integration_id": 15368}
                    ]
                },
            }
        ],
    }
    ruleset.update(overrides)
    return ruleset


def codes(expected: dict, protection: dict, rulesets=(), emitted=None,
          default_branch: str = "main") -> list[str]:
    return [
        finding["code"]
        for finding in vbp.compare(
            expected, protection, list(rulesets), emitted, default_branch
        )
    ]


class RetainedRuleShapeTests(unittest.TestCase):
    """The checked-in retained rule must be the exact, discriminating rule."""

    def test_retained_rule_is_the_discriminating_shape(self):
        rule = retained_rule()
        self.assertEqual(rule["branch"], "main")
        self.assertTrue(rule["required_contexts"], "the rule must require a context")
        self.assertIsNotNone(
            rule["required_check_app_id"],
            "the rule must pin the app identity, or any app can satisfy the context",
        )
        self.assertIs(rule["strict"], True, "W10 requires strict semantics")
        self.assertIs(rule["enforce_admins"], True, "W10 requires admins/agents too")
        self.assertIn("allowed_bypass_actors", rule, "bypass actors must be declared")

    def test_retained_context_is_emitted_by_the_checked_in_workflow(self):
        emitted = vbp.emitted_check_names(EMITTED)
        for context in retained_rule()["required_contexts"]:
            self.assertIn(context, emitted, f"ci.yml no longer emits {context!r}")


class VerdictShapeTests(unittest.TestCase):
    """One test per required rule shape: perfect -> MATCH, each defect refused."""

    def setUp(self):
        self.rule = retained_rule()

    def test_1_perfect_rule_is_a_match(self):
        self.assertEqual(codes(self.rule, live_protection(), [active_ruleset()]), [])

    def test_2_bare_context_any_app_is_refused(self):
        # A context-only requirement is satisfiable by ANY app posting the name.
        live = live_protection(
            required_status_checks={
                "strict": True,
                "contexts": ["merge-compile"],
                "checks": [],
            }
        )
        self.assertIn("BP-APP-UNBOUND", codes(self.rule, live, [active_ruleset()]))

    def test_3_wrong_app_binding_is_refused(self):
        live = live_protection(
            required_status_checks={
                "strict": True,
                "contexts": [],
                "checks": [{"context": "merge-compile", "app_id": 4}],
            }
        )
        self.assertIn("BP-APP-MISMATCH", codes(self.rule, live, [active_ruleset()]))

    def test_4_renamed_emitter_job_is_refused(self):
        self.assertIn(
            "BP-RULE-UNBOUND",
            codes(self.rule, live_protection(), [active_ruleset()],
                  emitted={"compile-only-merge"}),
        )

    def test_5_wrong_default_branch_is_refused(self):
        # The live rule is perfect, but the repository default branch is elsewhere:
        # a rule that is not on the merge path must never satisfy MATCH.
        self.assertIn(
            "BP-DEFAULT-BRANCH",
            codes(self.rule, live_protection(), [active_ruleset()],
                  default_branch="release/1.x"),
        )

    def test_6_non_strict_is_refused(self):
        live = live_protection(
            required_status_checks={
                "strict": False,
                "contexts": [],
                "checks": [{"context": "merge-compile", "app_id": 15368}],
            }
        )
        self.assertIn("BP-NOT-STRICT", codes(self.rule, live, [active_ruleset()]))

    def test_7_enforce_admins_false_is_refused(self):
        live = live_protection(enforce_admins={"enabled": False})
        self.assertIn("BP-BYPASS-ALLOWED", codes(self.rule, live, [active_ruleset()]))

    def test_8_undeclared_bypass_actor_is_refused(self):
        for actor in (
            {"users": [{"login": "uncleared-operator"}]},
            {"teams": [{"slug": "release-team"}]},
            {"apps": [{"slug": "deployment-bot", "id": 999}]},
        ):
            with self.subTest(actor=actor):
                live = live_protection(
                    restrictions={
                        "users": actor.get("users", []),
                        "teams": actor.get("teams", []),
                        "apps": actor.get("apps", []),
                    }
                )
                self.assertIn(
                    "BP-BYPASS-ALLOWED", codes(self.rule, live, [active_ruleset()])
                )

    def test_9_missing_context_is_refused(self):
        live = live_protection(
            required_status_checks={"strict": True, "contexts": [], "checks": []}
        )
        self.assertIn("BP-CONTEXT-MISSING", codes(self.rule, live, [active_ruleset()]))

    def test_10_unprotected_branch_is_refused(self):
        live = live_protection()
        live["protected"] = False
        self.assertIn("BP-UNPROTECTED", codes(self.rule, live, [active_ruleset()]))


class BypassSurfaceTests(unittest.TestCase):
    """Every bypass surface the readback can see must fail closed."""

    def setUp(self):
        self.rule = retained_rule()

    def test_active_ruleset_bypass_actor_is_refused(self):
        # A ruleset bypass actor skips the ruleset independently of branch
        # protection. Every actor_type and bypass_mode is a bypass path.
        for actor in (
            {"actor_id": 7, "actor_type": "Integration", "bypass_mode": "always"},
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"},
            {"actor_id": 4, "actor_type": "OrganizationAdmin", "bypass_mode": "always"},
            {"actor_id": 9, "actor_type": "PullRequest", "bypass_mode": "pull_request"},
            {"actor_id": 11, "actor_type": "Team", "bypass_mode": "always"},
            {"actor_id": 12},
        ):
            with self.subTest(actor=actor):
                ruleset = active_ruleset(bypass_actors=[actor])
                self.assertIn(
                    "BP-BYPASS-ALLOWED", codes(self.rule, live_protection(), [ruleset])
                )

    def test_non_active_ruleset_bypass_actor_cannot_excuse_a_bypass(self):
        # A disabled ruleset enforces nothing, so its actors cannot make a live
        # bypass acceptable: the branch rule's own actor list is still compared.
        ruleset = active_ruleset(
            enforcement="disabled",
            bypass_actors=[
                {"actor_id": 7, "actor_type": "Integration", "bypass_mode": "always"}
            ],
        )
        live = live_protection(
            restrictions={"users": [{"login": "uncleared"}], "teams": [], "apps": []}
        )
        self.assertIn("BP-BYPASS-ALLOWED", codes(self.rule, live, [ruleset]))

    def test_declared_but_absent_break_glass_actor_is_refused(self):
        # Set equality in BOTH directions: a declared break-glass owner that is
        # gone is drift, and reporting it as a clean match would hide the fact
        # that the governed path no longer exists.
        rule = {**self.rule, "allowed_bypass_actors": ["recovery-principal"]}
        self.assertIn("BP-BYPASS-DRIFTED", codes(rule, live_protection(), [active_ruleset()]))

    def test_declared_and_present_break_glass_actor_is_accepted(self):
        rule = {**self.rule, "allowed_bypass_actors": ["recovery-principal"]}
        live = live_protection(
            restrictions={
                "users": [{"login": "recovery-principal"}],
                "teams": [],
                "apps": [],
            }
        )
        self.assertEqual(codes(rule, live, [active_ruleset()]), [])

    def test_allowed_bypass_actor_plus_one_undeclared_is_still_refused(self):
        rule = {**self.rule, "allowed_bypass_actors": ["recovery-principal"]}
        live = live_protection(
            restrictions={
                "users": [
                    {"login": "recovery-principal"},
                    {"login": "quiet-extra-operator"},
                ],
                "teams": [],
                "apps": [],
            }
        )
        self.assertIn("BP-BYPASS-ALLOWED", codes(rule, live, [active_ruleset()]))


class RetainedRuleWeakeningTests(unittest.TestCase):
    """A weakened retained rule must not compare equal to everything (#943 class)."""

    def test_retained_rule_requiring_nothing_is_refused(self):
        rule = {**retained_rule(), "required_contexts": []}
        self.assertIn(
            "BP-RETENED-RULE-EMPTY",
            codes(rule, live_protection(), [active_ruleset()]),
        )

    def test_retained_rule_without_app_identity_is_refused(self):
        rule = {**retained_rule(), "required_check_app_id": None}
        self.assertIn(
            "BP-RETAINED-RULE-UNBOUND",
            codes(rule, live_protection(), [active_ruleset()]),
        )

    def test_retained_rule_without_strict_is_refused(self):
        rule = {**retained_rule(), "strict": False}
        self.assertIn(
            "BP-RETENED-RULE-WEAK", codes(rule, live_protection(), [active_ruleset()])
        )

    def test_retained_rule_without_enforce_admins_is_refused(self):
        rule = {**retained_rule(), "enforce_admins": False}
        self.assertIn(
            "BP-RETENED-RULE-WEAK", codes(rule, live_protection(), [active_ruleset()])
        )


class WeakenedRulesetSurfaceTests(unittest.TestCase):
    """An active ruleset is a second enforcement surface over the same branch."""

    def setUp(self):
        self.rule = retained_rule()

    def test_active_ruleset_without_the_context_is_refused(self):
        ruleset = active_ruleset(rules=[])
        self.assertIn(
            "BP-RULESET-DIVERGED", codes(self.rule, live_protection(), [ruleset])
        )

    def test_active_ruleset_requiring_a_different_context_is_refused(self):
        ruleset = active_ruleset(
            rules=[
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{"context": "some-other-check"}]
                    },
                }
            ]
        )
        self.assertIn(
            "BP-RULESET-DIVERGED", codes(self.rule, live_protection(), [ruleset])
        )


class ReadbackIsReadOnlyTests(unittest.TestCase):
    """The readback must never be able to configure protection."""

    def test_module_exposes_no_protection_writing_call(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for verb in ("--method", "-X PUT", "-X PATCH", "-X DELETE", "-X POST"):
            self.assertNotIn(
                verb, source, f"the readback must not apply changes ({verb} present)"
            )

    def test_bypass_actor_names_reads_unreadable_actors_as_present(self):
        # An actor shape the readback cannot parse is not an absent actor.
        self.assertTrue(vbp.bypass_actor_names({"bypass_actors": ["oops"]}))

    def test_reader_surfaces_every_restriction_actor_class(self):
        # The reader is what turns the raw payload into compared values, so a
        # surface it stops surfacing is a surface no later comparison can see.
        shaped = shape_protection(
            {
                "required_status_checks": {
                    "strict": True,
                    "contexts": [],
                    "checks": [{"context": "merge-compile", "app_id": 15368}],
                },
                "enforce_admins": {"enabled": True},
                "restrictions": {
                    "users": [{"login": "an-operator"}],
                    "teams": [{"slug": "a-team"}],
                    "apps": [{"slug": "an-app", "id": 42}],
                },
            }
        )
        self.assertEqual(shaped["bypass_users"], ["an-operator"])
        self.assertEqual(shaped["bypass_teams"], ["a-team"])
        self.assertEqual(shaped["bypass_apps"], ["an-app"])

    def test_reader_does_not_invent_a_restrictions_entry(self):
        # An absent restrictions object is an empty actor set, not an error and
        # not a populated one.
        shaped = shape_protection(
            {
                "required_status_checks": {
                    "strict": True,
                    "contexts": [],
                    "checks": [{"context": "merge-compile", "app_id": 15368}],
                },
                "enforce_admins": {"enabled": True},
            }
        )
        self.assertEqual(shaped["bypass_users"], [])
        self.assertEqual(shaped["bypass_teams"], [])
        self.assertEqual(shaped["bypass_apps"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)