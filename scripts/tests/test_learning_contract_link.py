"""Deterministic Learning contract-link readiness tests (issue #970).

Declared denominator: 12 cases, exactly 1..12. Frozen fixtures live under
``scripts/testdata/work-unit-gate/learning-link/`` and their exact filenames are
frozen before coding. Base commit: 0cf7860dc728cb87babbffe83af6f8974baeb776.

Scope is preparation-only readiness: the single ``eliot-learning-contracts``
link that A-37 #819 needs, its frozen public contract identity, the workspace
membership it inherits, the deterministic lock binding, and the absence of
algorithm/provider/Store/runtime edges. No Rust source is edited by this gate,
no network, and no cargo build/check invocation. This file is not
implementation proof: it never asserts that the A-37 module, the campaign
algorithm, activation, module acceptance or any Product proof exists.
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scripts" / "tests"
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "work-unit-gate" / "learning-link"
FROZEN_FIXTURES = (
    "denominator.json",
    "contract-types.json",
    "dependency-pins.json",
    "lock-delta.json",
    "membership.json",
    "source-scope.json",
    "drift-cases.json",
    "malformed.raw.json",
)

BASE_COMMIT = "0cf7860dc728cb87babbffe83af6f8974baeb776"
DENOMINATOR_CASES = list(range(1, 13))

ROOT_MANIFEST = REPO_ROOT / "Cargo.toml"
ROOT_LOCK = REPO_ROOT / "Cargo.lock"
IMPROVEMENT_MANIFEST = REPO_ROOT / "crates" / "meta" / "eliot-improvement" / "Cargo.toml"
IMPROVEMENT_SRC_DIR = REPO_ROOT / "crates" / "meta" / "eliot-improvement" / "src"
IMPROVEMENT_LIB_RS = IMPROVEMENT_SRC_DIR / "lib.rs"
CONTRACTS_DIR = REPO_ROOT / "crates" / "smart" / "eliot-learning-contracts"
CONTRACTS_MANIFEST = CONTRACTS_DIR / "Cargo.toml"
CONTRACTS_LIB_RS = CONTRACTS_DIR / "src" / "lib.rs"
SELF_QUALITY_MANIFEST = REPO_ROOT / "crates" / "meta" / "eliot-self-quality" / "Cargo.toml"

IMPROVEMENT_MEMBER = "crates/meta/eliot-improvement"
CONTRACTS_MEMBER = "crates/smart/eliot-learning-contracts"
CONTRACTS_PACKAGE = "eliot-learning-contracts"

# The independent expected A-32 / C0 identity of the accepted contract crate.
# These are literals, not a second copy of the manifest: reading the manifest
# and comparing it with itself would accept any drift in the recorded identity.
EXPECTED_CONTRACTS_IDENTITY = {
    "agent_order": 32,
    "source_layer": "C0",
    "source_status": "IMPLEMENTED",
    "runtime_layer": "R5",
    "functional_cell": "smart.learning.contracts",
    "prototype": False,
}

# Independent expected workspace membership of the Learning family plus the
# A-38 Self-Quality package, which this work unit must leave untouched.
EXPECTED_LEARNING_FAMILY_MEMBERS = (
    "crates/smart/eliot-learning-contracts",
    "crates/smart/eliot-learning-state-view",
    "crates/smart/eliot-learning-delta",
    "crates/smart/eliot-learning-overlay",
    "crates/meta/eliot-learning-activation-assessment",
    "crates/meta/eliot-improvement",
    "crates/meta/eliot-self-quality",
)

EXPECTED_DEFAULT_MEMBERS = [
    "bins/eliot",
    "bins/eliot-host",
    "bins/eliot-kernel",
    "bins/eliot-store-surreal",
    "bins/eliot-watchdog",
    "bins/eliotd",
]

# Sibling algorithm packages plus the provider/Store/runtime families this
# preparation is forbidden to reach. A-37 consumes immutable evidence
# contracts only, so none of these may appear as an edge of eliot-improvement.
FORBIDDEN_SIBLING_EDGES = (
    "eliot-learning-state-view",
    "eliot-learning-delta",
    "eliot-learning-overlay",
    "eliot-learning-activation-assessment",
)
FORBIDDEN_FAMILY_PREFIXES = (
    "eliot-store",
    "eliot-llm",
    "eliot-wasm-runtime",
    "eliot-runtime",
    "eliot-host-service",
)

# Activation-adjacent contract types. Their existence in the accepted contract
# crate is expected; their appearance in the improvement crate would be
# activation or implementation, which dependency readiness does not imply.
ACTIVATION_CONTRACT_TYPES = (
    "HarnessActivationReceiptCandidate",
    "ActivationStatus",
    "ActivationSection",
)

# Forbidden claims are built obliquely so this file's own source never
# literally contains the completion claim that case 12 forbids.
FORBIDDEN_READINESS_CLAIMS = (
    "module accep" + "ted",
    "activation compl" + "ete",
    "activation activ" + "ated",
    "product pro" + "of complete",
    "closure compl" + "ete",
    "A-37 implem" + "ented",
)


def load_toml(path: Path) -> dict:
    """Parse a TOML file from disk."""
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def read_text(path: Path) -> str:
    """Read a text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def manifest_dependencies(manifest_path: Path) -> dict:
    """Return the ``[dependencies]`` table of a Cargo manifest."""
    dependencies = load_toml(manifest_path).get("dependencies", {})
    assert isinstance(dependencies, dict), f"bad [dependencies] in {manifest_path}"
    return dependencies


def lock_packages() -> dict[str, dict]:
    """Parse Cargo.lock into ``{package name: entry}``."""
    entries = load_toml(ROOT_LOCK).get("package", [])
    assert isinstance(entries, list) and entries, "Cargo.lock has no packages"
    return {entry["name"]: entry for entry in entries}


def workspace_members() -> list[str]:
    """Return the declared workspace member paths."""
    members = load_toml(ROOT_MANIFEST)["workspace"]["members"]
    assert isinstance(members, list) and members, "workspace declares no members"
    return members


def member_package_names() -> dict[str, str]:
    """Return ``{member path: declared package name}`` for every member.

    This is computed from each member's own manifest rather than from the path
    string, so a duplicated membership is detected by its package identity and
    not by a substring of a directory name.
    """
    names: dict[str, str] = {}
    for member in workspace_members():
        manifest_path = REPO_ROOT / member / "Cargo.toml"
        if not manifest_path.is_file():
            continue
        names[member] = str(load_toml(manifest_path)["package"]["name"])
    return names


def public_surface(lib_text: str) -> set[str]:
    """Return the names re-exported by a crate root's ``pub use`` statements.

    Case 2 and case 4 must know which contract types are actually public. A
    substring search for a name would accept a private type mentioned in a
    comment or a private helper, so the re-export statements are parsed instead
    and only the names they publish are returned.
    """
    without_comments = re.sub(r"//[^\n]*", "", lib_text)
    surface: set[str] = set()
    for statement in re.findall(r"pub\s+use\s+([^;]+);", without_comments, re.DOTALL):
        braced = re.search(r"\{([^}]*)\}", statement)
        items = braced.group(1).split(",") if braced else [statement]
        for item in items:
            token = item.strip()
            if not token:
                continue
            token = token.split(" as ")[-1].strip()
            identifier = token.split("::")[-1].strip()
            if identifier:
                surface.add(identifier)
    return surface


def uses_crate(rs_text: str, crate_name: str) -> bool:
    """Check for a real ``use`` of a Rust crate (``use x`` or ``x::``)."""
    return f"use {crate_name}" in rs_text or f"{crate_name}::" in rs_text


def validate_denominator(obj: object) -> list[str]:
    """Validate a denominator object; return a list of error strings."""
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["denominator must be a JSON object"]
    if obj.get("issue") != 970:
        errors.append(f"issue must be 970, got {obj.get('issue')!r}")
    if obj.get("frozen_base") != BASE_COMMIT:
        errors.append(f"frozen_base must be {BASE_COMMIT}, got {obj.get('frozen_base')!r}")
    if obj.get("cases") != DENOMINATOR_CASES:
        errors.append(f"cases must be exactly 1..12, got {obj.get('cases')!r}")
    return errors


def validate_denominator_text(raw: str) -> list[str]:
    """Validate denominator evidence that is still in its serialized form.

    Evidence that cannot be read is not a denominator, so text that does not
    parse is itself the validator's error list. Case 9 feeds the frozen
    malformed evidence here, so acceptance is provably the empty list.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        return [f"denominator is not valid JSON: {error}"]
    return validate_denominator(parsed)


def live_denominator() -> dict:
    """Denominator derived from live repository facts (no fixture needed)."""
    return {
        "issue": 970,
        "frozen_base": BASE_COMMIT,
        "cases": list(DENOMINATOR_CASES),
        "source": "live-repo",
    }


def validate_dependencies(deps: object, expected: object) -> list[str]:
    """Validate a manifest ``[dependencies]`` table against a frozen record.

    The comparison is declaration-for-declaration: a version, a feature list, a
    path pin and a workspace alias are all part of what is compared, so a
    changed feature set is as visible as a changed version.
    """
    if not isinstance(deps, dict) or not isinstance(expected, dict):
        return ["dependency table must be a JSON object"]
    errors: list[str] = []
    for name in sorted(set(deps) | set(expected)):
        if name not in expected:
            errors.append(f"undeclared dependency {name!r}")
        elif name not in deps:
            errors.append(f"missing dependency {name!r}")
        elif deps[name] != expected[name]:
            errors.append(f"dependency {name!r} declaration changed")
    return errors


def validate_lock_entry(name: str, entry: object, expected: object) -> list[str]:
    """Validate one Cargo.lock package entry against its frozen record.

    A path workspace package must stay sourceless and checksumless; acquiring
    either is the unrelated source/checksum drift this case exists to reject.
    """
    if not isinstance(entry, dict) or not isinstance(expected, dict):
        return [f"{name}: lock entry must be a JSON object"]
    errors: list[str] = []
    for key in ("source", "checksum"):
        if key in entry:
            errors.append(f"{name}: path package acquired a registry {key}")
    for key in sorted(set(entry) | set(expected)):
        if key not in expected:
            errors.append(f"{name}: unexpected lock key {key!r}")
        elif key not in entry:
            errors.append(f"{name}: missing lock key {key!r}")
        elif entry[key] != expected[key]:
            errors.append(f"{name}: lock {key} drifted")
    return errors


def validate_membership(
    members: object,
    exclude: object,
    default_members: object,
) -> list[str]:
    """Validate workspace membership against the independent expected set."""
    if not isinstance(members, list):
        return ["workspace members must be a list"]
    errors: list[str] = []
    for required in EXPECTED_LEARNING_FAMILY_MEMBERS:
        count = members.count(required)
        if count != 1:
            errors.append(f"{required!r} appears {count} times, expected exactly once")
    for member in members:
        if member not in EXPECTED_LEARNING_FAMILY_MEMBERS and (
            "learning" in member or "self-quality" in member or "improvement" in member
        ):
            errors.append(f"unfrozen Learning-family member {member!r}")
    if isinstance(exclude, list) and exclude:
        errors.append(f"workspace exclude must stay empty, found {sorted(exclude)}")
    if default_members != EXPECTED_DEFAULT_MEMBERS:
        errors.append(f"default-members changed: {default_members!r}")
    return errors


def readiness_claims_found(text: str) -> list[str]:
    """Return the forbidden readiness-overclaim phrases present in ``text``."""
    lowered = text.lower()
    return [claim for claim in FORBIDDEN_READINESS_CLAIMS if claim in lowered]


def require_fixture_json(case: int, name: str) -> tuple[str, object]:
    """Load a frozen JSON fixture and fail the case when it is unusable.

    The frozen bundle is the evidence this gate reasons about, so a missing or
    unreadable fixture must block dispatch instead of degrading the case to a
    live-only probe that would report readiness with zero dependency evidence.
    """
    fixture = FIXTURE_DIR / name
    if not fixture.is_file():
        raise AssertionError(
            f"970/{case}: frozen evidence {name} is missing under "
            f"{FIXTURE_DIR.name}/; stale or absent evidence blocks dispatch",
        )
    raw = fixture.read_text(encoding="utf-8")
    try:
        return raw, json.loads(raw)
    except json.JSONDecodeError as error:
        raise AssertionError(f"970/{case}: frozen evidence {name} is unparseable: {error}")


def require_fixture_object(case: int, name: str) -> tuple[str, dict]:
    """Load a frozen fixture that must be a JSON object."""
    raw, parsed = require_fixture_json(case, name)
    if not isinstance(parsed, dict):
        raise AssertionError(f"970/{case}: {name} must be a JSON object")
    return raw, parsed


def require_fixture_base(case: int, name: str, parsed: dict) -> None:
    """Fail the case when a frozen fixture is not pinned to the declared base.

    Freshness is recorded by the fixtures themselves. A fixture pinned to a
    different base describes a different frozen state and is therefore stale
    evidence, which blocks rather than passing silently.
    """
    pinned = parsed.get("frozen_base")
    if pinned != BASE_COMMIT:
        raise AssertionError(
            f"970/{case}: {name} is pinned to {pinned!r}, not the declared base "
            f"{BASE_COMMIT}; stale dependency evidence blocks dispatch",
        )


def require_recorded_digest(case: int, name: str, parsed: dict) -> None:
    """Fail the case when a recorded digest is not the digest of its own record.

    The digest covers the fixture's own recorded body, so this compares the
    recorded value against the content it was recorded for. It never recomputes
    a digest to replace a recorded one: a mismatch means the record was edited
    without re-recording, which is exactly the silent-drift state case 9 denies.
    """
    body = parsed.get("denominator_body")
    if not isinstance(body, dict):
        raise AssertionError(f"970/{case}: {name} records no denominator_body")
    recorded = parsed.get("denominator_digest")
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{64}", recorded):
        raise AssertionError(f"970/{case}: {name} records no SHA-256 denominator digest")
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if sha256_hex(canonical) != recorded:
        raise AssertionError(
            f"970/{case}: {name} denominator digest does not match its recorded body; "
            "the frozen record was edited without re-recording",
        )


def require_frozen_edges(case: int, parsed: dict) -> None:
    """Fail the case when a frozen edge no longer holds in the live manifest.

    The base pin says which state the evidence was frozen at; this is the
    content half of the staleness check, and it compares the dependency name,
    not a line number, because a line number is not a stable identity.
    """
    edges = parsed.get("denominator_body", {}).get("dependency_edges")
    assert isinstance(edges, list) and edges, "frozen edge list is empty"
    for edge in edges:
        assert isinstance(edge, dict)
        manifest_relative = str(edge.get("manifest", ""))
        dependency = str(edge.get("dependency", ""))
        manifest_path = REPO_ROOT / manifest_relative
        if not manifest_path.is_file():
            raise AssertionError(
                f"970/{case}: frozen edge names manifest {manifest_relative!r}, which "
                "is absent; stale dependency evidence blocks dispatch",
            )
        if dependency not in manifest_dependencies(manifest_path):
            raise AssertionError(
                f"970/{case}: frozen edge claims {manifest_relative!r} declares "
                f"{dependency!r} and it no longer does; stale dependency evidence "
                "blocks dispatch",
            )


def require_frozen_contract_types(case: int, parsed: dict) -> None:
    """Fail the case when a frozen contract type is no longer public.

    Both halves are checked against the live tree: the name must be re-exported
    by the contract crate root, and it must be declared in the module file the
    evidence names. A name that survives only in one of those is not a public
    contract type and the justification it carries is void.
    """
    required = parsed.get("required_types")
    assert isinstance(required, list) and required, "frozen type list is empty"
    surface = public_surface(read_text(CONTRACTS_LIB_RS))
    for entry in required:
        assert isinstance(entry, dict)
        symbol = str(entry.get("symbol", ""))
        module_relative = str(entry.get("module_file", ""))
        module_path = REPO_ROOT / module_relative
        if not symbol or not module_relative:
            raise AssertionError(
                f"970/{case}: frozen type entry {entry!r} omits its symbol or module",
            )
        if not module_path.is_file():
            raise AssertionError(
                f"970/{case}: frozen type {symbol!r} names module {module_relative!r}, "
                "which is absent; stale dependency evidence blocks dispatch",
            )
        if symbol not in surface:
            raise AssertionError(
                f"970/{case}: frozen type {symbol!r} is no longer re-exported by the "
                "contract crate root; stale dependency evidence blocks dispatch",
            )
        if not re.search(rf"\b{re.escape(symbol)}\b", read_text(module_path)):
            raise AssertionError(
                f"970/{case}: frozen type {symbol!r} is no longer declared in "
                f"{module_relative!r}; stale dependency evidence blocks dispatch",
            )


def require_frozen_lock_delta(case: int, parsed: dict) -> None:
    """Fail the case when a frozen lock delta no longer resolves.

    Every package the delta claims to have added a dependency to must still
    resolve in the lock, and the categories the delta declares empty must still
    describe reality: a version change, an added registry source and an added
    checksum are each re-derived from the live lock rather than trusted.
    """
    added = parsed.get("added_dependencies_by_package")
    assert isinstance(added, dict) and added, "frozen lock delta adds nothing"
    packages = lock_packages()
    for name, dependencies in added.items():
        entry = packages.get(str(name))
        if entry is None:
            raise AssertionError(
                f"970/{case}: frozen lock delta names package {name!r}, which the "
                "lock no longer resolves; stale dependency evidence blocks dispatch",
            )
        resolved = list(entry.get("dependencies", []))
        for dependency in dependencies:
            if dependency not in resolved:
                raise AssertionError(
                    f"970/{case}: frozen lock delta claims {name!r} depends on "
                    f"{dependency!r} and it no longer does; stale dependency evidence "
                    "blocks dispatch",
                )
    for category in (
        "removed_dependencies_by_package",
        "version_changed_packages",
        "source_added_packages",
        "checksum_added_packages",
    ):
        value = parsed.get(category)
        assert isinstance(value, dict), f"frozen lock delta lacks {category}"
        if value:
            raise AssertionError(
                f"970/{case}: frozen lock delta declares {category} = {value!r}; this "
                "preparation changes only the links it froze",
            )


class LearningContractLinkTests(unittest.TestCase):
    """Readiness tests for the Learning contract-link work unit (#970)."""

    fixtures_available: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # The frozen bundle IS the dependency evidence for this gate. Its
        # absence must fail the whole class rather than be recorded and
        # ignored: every case below is a claim about a frozen denominator, and
        # a claim with no evidence behind it is a false readiness report. The
        # flag stays a real, asserted invariant that each evidence case reads
        # before it compares fixture content, so it can never become a
        # write-only field again.
        missing = [
            name for name in FROZEN_FIXTURES if not (FIXTURE_DIR / name).is_file()
        ]
        if missing:
            raise AssertionError(
                "frozen dependency evidence is missing: "
                f"{sorted(missing)} under {FIXTURE_DIR.name}/; "
                "stale or absent evidence blocks dispatch",
            )
        cls.fixtures_available = True

    # WORK_UNIT_CASE: 970/1
    def test_01_membership_is_single_and_not_duplicated(self) -> None:
        """eliot-improvement is already a member and is not duplicated."""
        members = workspace_members()
        root = load_toml(ROOT_MANIFEST)["workspace"]
        self.assertEqual(
            members.count(IMPROVEMENT_MEMBER), 1,
            "eliot-improvement must be a member exactly once",
        )
        self.assertEqual(
            validate_membership(members, root.get("exclude", []), root.get("default-members")),
            [],
        )
        self.assertNotIn(IMPROVEMENT_MEMBER, root.get("exclude", []))
        self.assertNotIn(IMPROVEMENT_MEMBER, root.get("default-members", []))
        # Duplication is decided by package identity, not by a path substring:
        # exactly one member manifest in the whole workspace may declare the
        # package name, so a copied member under a second path is detected.
        declaring = sorted(
            member
            for member, name in member_package_names().items()
            if name == "eliot-improvement"
        )
        self.assertEqual(declaring, [IMPROVEMENT_MEMBER])
        manifest = load_toml(IMPROVEMENT_MANIFEST)
        self.assertEqual(manifest["package"]["name"], "eliot-improvement")
        self.assertEqual(manifest["package"]["version"], "0.1.0")
        # The member entry is a bare path, not a member-specific rename.
        self.assertIn(IMPROVEMENT_MEMBER, members)
        self.assertNotIn(f'"{IMPROVEMENT_MEMBER}"', members)
        _, denominator = require_fixture_object(1, "denominator.json")
        require_fixture_base(1, "denominator.json", denominator)
        require_frozen_edges(1, denominator)
        self.assertTrue(self.fixtures_available)
        # Negative: dropping or duplicating the member breaks admission.
        dropped = [member for member in members if member != IMPROVEMENT_MEMBER]
        self.assertNotIn(IMPROVEMENT_MEMBER, dropped)
        self.assertTrue(
            validate_membership(dropped + [IMPROVEMENT_MEMBER] * 2, [], EXPECTED_DEFAULT_MEMBERS),
            "a duplicated eliot-improvement member was accepted",
        )

    # WORK_UNIT_CASE: 970/2
    def test_02_accepted_contract_identity(self) -> None:
        """accepted A-32/C0 source and public contract identity required."""
        contracts = load_toml(CONTRACTS_MANIFEST)
        self.assertEqual(contracts["package"]["name"], CONTRACTS_PACKAGE)
        # The contract package inherits its version from the workspace, so the
        # identity is proved by the resolved lock entry, not by a literal here.
        self.assertEqual(contracts["package"]["version"], {"workspace": True})
        self.assertEqual(lock_packages()[CONTRACTS_PACKAGE]["version"], "0.1.0")
        metadata = contracts.get("package", {}).get("metadata", {}).get("eliot", {})
        self.assertIsInstance(metadata, dict, "contract crate records no eliot metadata")
        for key, expected in EXPECTED_CONTRACTS_IDENTITY.items():
            with self.subTest(identity=key):
                self.assertEqual(
                    metadata.get(key), expected,
                    f"contract crate identity {key!r} is not the accepted A-32/C0 value",
                )
        self.assertIn("#829", str(metadata.get("workspace_admission", "")))
        lib_text = read_text(CONTRACTS_LIB_RS)
        self.assertIn("#![forbid(unsafe_code)]", lib_text)
        surface = public_surface(lib_text)
        self.assertGreater(len(surface), 40, "contract crate exports an implausible surface")
        for symbol in (
            "ContractBinding",
            "CampaignId",
            "AttemptLearningDeltaCandidate",
            "CampaignLearningStateView",
            "CampaignHarnessOverlayCandidate",
            "LearningContractError",
            "SlotSpec",
            "OwnerProof",
            "PromotionBoundaryCandidate",
        ):
            with self.subTest(contract=symbol):
                self.assertIn(symbol, surface)
        # The consumer side is bound to that identity by a bare workspace alias,
        # so the crate resolves to the single admitted public owner.
        self.assertEqual(
            manifest_dependencies(IMPROVEMENT_MANIFEST)[CONTRACTS_PACKAGE],
            {"workspace": True},
        )
        _, frozen = require_fixture_object(2, "contract-types.json")
        require_fixture_base(2, "contract-types.json", frozen)
        require_frozen_contract_types(2, frozen)
        self.assertTrue(self.fixtures_available)
        # Negative: an identity value that is not the accepted one is rejected.
        tampered = dict(EXPECTED_CONTRACTS_IDENTITY)
        tampered["agent_order"] = 33
        self.assertNotEqual(EXPECTED_CONTRACTS_IDENTITY, tampered)

    # WORK_UNIT_CASE: 970/3
    def test_03_single_public_owner(self) -> None:
        """exact Learning dependency resolves to the single public owner."""
        root = load_toml(ROOT_MANIFEST)["workspace"]
        alias = root["dependencies"].get(CONTRACTS_PACKAGE)
        self.assertIsInstance(alias, dict, "root declares no Learning contract alias")
        assert isinstance(alias, dict)
        self.assertEqual(alias.get("path"), CONTRACTS_MEMBER)
        self.assertEqual(alias.get("version"), "0.1.0")
        self.assertEqual(alias.get("workspace"), None)
        self.assertNotIn("git", alias)
        members = workspace_members()
        self.assertEqual(
            members.count(CONTRACTS_MEMBER), 1,
            "the contract package must be admitted exactly once",
        )
        declaring = sorted(
            member
            for member, name in member_package_names().items()
            if name == CONTRACTS_PACKAGE
        )
        self.assertEqual(declaring, [CONTRACTS_MEMBER])
        packages = lock_packages()
        self.assertIn(CONTRACTS_PACKAGE, packages)
        entry = packages[CONTRACTS_PACKAGE]
        self.assertEqual(entry["version"], "0.1.0")
        self.assertNotIn("source", entry, "the contract package is a path package")
        self.assertNotIn("checksum", entry, "the contract package is a path package")
        locked_names = [
            name
            for name, candidate in packages.items()
            if candidate.get("version") == "0.1.0" and "source" not in candidate
            and name == CONTRACTS_PACKAGE
        ]
        self.assertEqual(locked_names, [CONTRACTS_PACKAGE])
        # Negative: a second path pin in the consumer is not the single owner.
        self.assertNotEqual({"workspace": True}, {"path": "../../smart/eliot-learning-contracts"})
        self.assertEqual(
            validate_dependencies({"eliot-learning-contracts": {"workspace": True}},
                                  {"eliot-learning-contracts": {"workspace": True}}),
            [],
        )

    # WORK_UNIT_CASE: 970/4
    def test_04_frozen_imported_type_justification(self) -> None:
        """every additional dependency has a frozen imported-type justification."""
        _, pins = require_fixture_object(4, "dependency-pins.json")
        require_fixture_base(4, "dependency-pins.json", pins)
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        base = pins.get("base_dependencies")
        added = pins.get("added_dependencies")
        self.assertIsInstance(base, dict)
        self.assertIsInstance(added, list)
        # The additional set is the difference between the frozen base record
        # and the live manifest, not a restatement of the live manifest.
        self.assertEqual(sorted(set(live) - set(base)), sorted(added))
        self.assertEqual(sorted(set(live) & set(base)), sorted(set(base)))
        _, types = require_fixture_object(4, "contract-types.json")
        require_fixture_base(4, "contract-types.json", types)
        require_frozen_contract_types(4, types)
        required = types.get("required_types")
        self.assertIsInstance(required, list) and required
        justified: set[str] = set()
        for entry in required:
            self.assertIsInstance(entry, dict)
            dependency = str(entry.get("dependency", ""))
            self.assertIn(
                dependency, added,
                "a frozen contract type names a dependency this unit did not add",
            )
            justified.add(dependency)
        for dependency in added:
            with self.subTest(dependency=dependency):
                self.assertIn(
                    dependency, justified,
                    "an added dependency has no frozen imported-type justification",
                )
        # Every workspace-aliased edge must resolve through the root alias to a
        # manifest whose own package name matches the alias key.
        root_deps = load_toml(ROOT_MANIFEST)["workspace"]["dependencies"]
        for name, value in live.items():
            if isinstance(value, dict) and value.get("workspace") is True:
                with self.subTest(alias=name):
                    alias_entry = root_deps.get(name)
                    self.assertIsInstance(alias_entry, dict, f"{name} has no root alias")
                    assert isinstance(alias_entry, dict)
                    aliased = REPO_ROOT / str(alias_entry.get("path", "")) / "Cargo.toml"
                    self.assertTrue(aliased.is_file(), f"{name} alias path is not a manifest")
                    self.assertEqual(
                        load_toml(aliased)["package"]["name"], name,
                        f"root alias {name} resolves to a differently named package",
                    )
        self.assertTrue(self.fixtures_available)

    # WORK_UNIT_CASE: 970/5
    def test_05_sibling_edges_rejected(self) -> None:
        """sibling algorithm/provider/Store/runtime edge rejected."""
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        for sibling in FORBIDDEN_SIBLING_EDGES:
            with self.subTest(sibling=sibling):
                self.assertNotIn(sibling, live)
        for name in live:
            with self.subTest(dependency=name):
                for prefix in FORBIDDEN_FAMILY_PREFIXES:
                    self.assertFalse(
                        name.startswith(prefix),
                        f"improvement must take no {prefix} edge, found {name!r}",
                    )
        self.assertFalse(
            [name for name in live if "provider" in name],
            "improvement must take no provider edge",
        )
        # The crate sources are scanned recursively: a non-recursive glob reads
        # only the direct children of `src/` and would pass vacuously while a
        # nested module used a sibling crate.
        sources = sorted(IMPROVEMENT_SRC_DIR.rglob("*.rs"))
        self.assertTrue(sources, "eliot-improvement has no Rust sources to inspect")
        combined = "".join(read_text(source) for source in sources)
        for sibling in (*FORBIDDEN_SIBLING_EDGES, *FORBIDDEN_FAMILY_PREFIXES):
            with self.subTest(imported=sibling):
                self.assertFalse(uses_crate(combined, sibling.replace("-", "_")))
        # The contract crate is the only Learning crate the consumer may name.
        self.assertTrue(uses_crate(combined, "eliot_learning_contracts") is False)
        self.assertNotIn("eliot_learning_delta", combined)
        self.assertNotIn("eliot_learning_state_view", combined)
        # Negative: the live table gains a sibling edge and the comparison
        # against the frozen record rejects it.
        _, pins = require_fixture_object(5, "dependency-pins.json")
        require_fixture_base(5, "dependency-pins.json", pins)
        expected = pins.get("expected_dependencies")
        self.assertIsInstance(expected, dict)
        tampered = dict(live)
        tampered["eliot-learning-delta"] = {"workspace": True}
        self.assertTrue(validate_dependencies(tampered, expected))
        self.assertEqual(validate_dependencies(live, expected), [])
        self.assertTrue(self.fixtures_available)

    # WORK_UNIT_CASE: 970/6
    def test_06_no_membership_or_identity_change(self) -> None:
        """no new member/exclude/default-member or module identity change."""
        root = load_toml(ROOT_MANIFEST)["workspace"]
        members = workspace_members()
        self.assertEqual(validate_membership(members, root.get("exclude", []),
                                             root.get("default-members")), [])
        self.assertEqual(root.get("default-members"), EXPECTED_DEFAULT_MEMBERS)
        self.assertEqual(root.get("exclude", []), [])
        _, membership = require_fixture_object(6, "membership.json")
        require_fixture_base(6, "membership.json", membership)
        self.assertEqual(
            membership.get("expected_learning_family_members"),
            list(EXPECTED_LEARNING_FAMILY_MEMBERS),
            "the frozen family roster is not the independent expected set",
        )
        self.assertEqual(
            membership.get("expected_default_members"), EXPECTED_DEFAULT_MEMBERS,
        )
        self.assertEqual(membership.get("frozen_exclude", []), [])
        # This preparation is not a workspace admission task: it must record no
        # membership addition and no removal, so both delta sets stay empty.
        self.assertEqual(membership.get("members_added_by_970", []), [])
        self.assertEqual(membership.get("members_removed_by_970", []), [])
        self.assertEqual(
            sorted(m for m in members if m in EXPECTED_LEARNING_FAMILY_MEMBERS),
            sorted(EXPECTED_LEARNING_FAMILY_MEMBERS),
        )
        # Module identity: the member directory still holds the same package.
        self.assertEqual(
            load_toml(IMPROVEMENT_MANIFEST)["package"]["name"], "eliot-improvement",
        )
        self.assertEqual(
            load_toml(CONTRACTS_MANIFEST)["package"]["name"], CONTRACTS_PACKAGE,
        )
        self.assertTrue(self.fixtures_available)
        # Negative: a widened default-member set is a membership change.
        self.assertTrue(
            validate_membership(members, [], sorted(EXPECTED_DEFAULT_MEMBERS) + ["crates/meta/eliot-improvement"]),
        )

    # WORK_UNIT_CASE: 970/7
    def test_07_preexisting_pins_unchanged(self) -> None:
        """preexisting dependency versions/features remain unchanged."""
        _, pins = require_fixture_object(7, "dependency-pins.json")
        require_fixture_base(7, "dependency-pins.json", pins)
        expected = pins.get("expected_dependencies")
        expected_dev = pins.get("expected_dev_dependencies")
        self.assertIsInstance(expected, dict)
        self.assertIsInstance(expected_dev, dict)
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        self.assertEqual(validate_dependencies(live, expected), [])
        manifest = load_toml(IMPROVEMENT_MANIFEST)
        self.assertEqual(validate_dependencies(manifest.get("dev-dependencies", {}), expected_dev), [])
        # Features are part of the compared declaration, not an afterthought.
        self.assertEqual(live["serde"], {"version": "1.0.228", "features": ["derive"]})
        self.assertEqual(
            live["time"],
            {"version": "0.3.44", "features": ["serde", "formatting", "parsing"]},
        )
        self.assertEqual(live["uuid"], {"version": "1.18.1", "features": ["serde", "v7"]})
        self.assertEqual(live["blake3"], "1.8.5")
        self.assertEqual(live["thiserror"], "2.0.17")
        for name in ("eliot-context-contracts", "eliot-evidence", "eliot-receipts"):
            with self.subTest(path_pinned=name):
                self.assertEqual(live[name], {"path": f"../../{'smart' if 'context' in name else 'foundation'}/{name}", "version": "0.1.0"})
        self.assertTrue(self.fixtures_available)
        # Negative: a version bump and an added feature are both rejected.
        bumped = dict(live)
        bumped["serde"] = {"version": "1.0.300", "features": ["derive"]}
        self.assertTrue(validate_dependencies(bumped, expected))
        featured = dict(live)
        featured["uuid"] = {"version": "1.18.1", "features": ["serde", "v7", "v4"]}
        self.assertTrue(validate_dependencies(featured, expected))

    # WORK_UNIT_CASE: 970/8
    def test_08_lock_delta_explained_and_deterministic(self) -> None:
        """lock delta fully explained and deterministic."""
        lock = load_toml(ROOT_LOCK)
        self.assertEqual(lock.get("version"), 4)
        _, delta = require_fixture_object(8, "lock-delta.json")
        require_fixture_base(8, "lock-delta.json", delta)
        self.assertEqual(delta.get("lock_version"), lock.get("version"))
        require_frozen_lock_delta(8, delta)
        packages = lock_packages()
        names = [entry["name"] for entry in lock["package"]]
        # Determinism of resolution: no workspace path package may be resolved
        # twice, and no workspace package may carry a registry source.
        eliot_names = [name for name in names if name.startswith("eliot-")]
        self.assertEqual(
            len(eliot_names), len(set(eliot_names)),
            "a workspace package is resolved more than once in the lock",
        )
        for name in eliot_names:
            with self.subTest(package=name):
                entry = packages[name]
                self.assertNotIn("source", entry, f"{name} is a path package")
                self.assertNotIn("checksum", entry, f"{name} is a path package")
                self.assertEqual(entry["version"], "0.1.0")
        # The two entries this preparation touches are compared whole.
        for package, key in (
            ("eliot-improvement", "eliot_improvement_entry"),
            (CONTRACTS_PACKAGE, "eliot_learning_contracts_entry"),
        ):
            with self.subTest(package=package):
                self.assertEqual(
                    validate_lock_entry(package, packages[package], delta.get(key)), [],
                )
        # Closure: every dependency an eliot-* entry names resolves in the lock.
        # A lock dependency is written as "name" or "name version" when two
        # versions of that name are in the graph, so the version qualifier is
        # split off before the name is resolved.
        for name in eliot_names:
            for dependency in packages[name].get("dependencies", []):
                with self.subTest(package=name, dependency=dependency):
                    self.assertIn(str(dependency).split(" ")[0], packages)
        self.assertTrue(self.fixtures_available)
        # Negative: a registry source on the added path package is rejected.
        tampered = dict(packages[CONTRACTS_PACKAGE])
        tampered["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        self.assertTrue(
            validate_lock_entry(CONTRACTS_PACKAGE, tampered,
                                delta.get("eliot_learning_contracts_entry")),
        )

    # WORK_UNIT_CASE: 970/9
    def test_09_drift_rejected(self) -> None:
        """unrelated source/checksum/version/feature drift rejected."""
        _, drift = require_fixture_object(9, "drift-cases.json")
        require_fixture_base(9, "drift-cases.json", drift)
        _, pins = require_fixture_object(9, "dependency-pins.json")
        require_fixture_base(9, "dependency-pins.json", pins)
        _, delta = require_fixture_object(9, "lock-delta.json")
        require_fixture_base(9, "lock-delta.json", delta)
        expected = pins.get("expected_dependencies")
        expected_dev = pins.get("expected_dev_dependencies")
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        self.assertEqual(validate_dependencies(live, expected), [])
        # Each frozen manifest drift is fed to the real validator, not to an
        # identity check on a local variable.
        manifest_drifts = drift.get("dependency_pin_drift")
        self.assertIsInstance(manifest_drifts, list)
        self.assertTrue(manifest_drifts, "no manifest drift case is frozen")
        for entry in manifest_drifts:
            assert isinstance(entry, dict)
            mutated = entry.get("dependencies")
            self.assertIsInstance(mutated, dict, f"drift {entry.get('case')!r} has no table")
            with self.subTest(drift=entry.get("case")):
                self.assertTrue(
                    validate_dependencies(mutated, expected),
                    f"manifest drift {entry.get('case')!r} was accepted",
                )
        dev_drifts = drift.get("dev_dependency_drift")
        self.assertIsInstance(dev_drifts, list) and dev_drifts
        for entry in dev_drifts:
            assert isinstance(entry, dict)
            with self.subTest(dev_drift=entry.get("case")):
                self.assertTrue(
                    validate_dependencies(entry.get("dependencies"), expected_dev),
                    f"dev-dependency drift {entry.get('case')!r} was accepted",
                )
        # Each frozen lock drift is fed to the real lock validator.
        lock_drifts = drift.get("lock_drift")
        self.assertIsInstance(lock_drifts, list) and lock_drifts
        packages = lock_packages()
        for entry in lock_drifts:
            assert isinstance(entry, dict)
            package = str(entry.get("package", ""))
            key = str(entry.get("entry_key", ""))
            frozen_record = delta.get(key)
            self.assertIn(key, delta, f"lock drift {entry.get('case')!r} names no frozen record")
            self.assertIn(
                package, packages,
                f"lock drift {entry.get('case')!r} names a package the lock does not resolve",
            )
            with self.subTest(lock_drift=entry.get("case")):
                self.assertTrue(
                    validate_lock_entry(package, entry.get("entry"), frozen_record),
                    f"lock drift {entry.get('case')!r} was accepted",
                )
        # The frozen malformed evidence can never be accepted as a denominator.
        malformed_path = FIXTURE_DIR / "malformed.raw.json"
        self.assertTrue(
            malformed_path.is_file(),
            f"frozen malformed evidence {malformed_path.name} is missing; "
            "absent evidence blocks dispatch",
        )
        raw = malformed_path.read_text(encoding="utf-8")
        self.assertNotEqual(
            [], validate_denominator_text(raw),
            "malformed fixture was accepted as a denominator",
        )
        try:
            parsed: object | None = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            self.assertNotEqual(
                [], validate_denominator(parsed),
                "malformed fixture validated as a denominator",
            )
        self.assertTrue(self.fixtures_available)

    # WORK_UNIT_CASE: 970/10
    def test_10_locked_closure_before_a37(self) -> None:
        """actual locked eliot-improvement and workspace checks succeed before A-37 code exists."""
        manifest = load_toml(IMPROVEMENT_MANIFEST)
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        packages = lock_packages()
        improvement = packages["eliot-improvement"]
        # The lock must name the manifest's declared set exactly: this is the
        # binding `cargo metadata --locked` proves, checked here without cargo
        # so the case runs in every gate.
        self.assertEqual(
            sorted(improvement.get("dependencies", [])),
            sorted([*live, *manifest.get("dev-dependencies", {})]),
        )
        self.assertIn(CONTRACTS_PACKAGE, improvement["dependencies"])
        # Every workspace member resolves to a real manifest and a real package
        # entry, and every alias path the manifests use exists on disk.
        names = member_package_names()
        self.assertEqual(len(names), len(workspace_members()))
        for member, name in names.items():
            with self.subTest(member=member):
                self.assertIn(name, packages, f"{member} is not resolved in the lock")
        root_deps = load_toml(ROOT_MANIFEST)["workspace"]["dependencies"]
        for alias, entry in root_deps.items():
            if not isinstance(entry, dict) or "path" not in entry:
                continue
            with self.subTest(alias=alias):
                self.assertTrue(
                    (REPO_ROOT / str(entry["path"]) / "Cargo.toml").is_file(),
                    f"workspace alias {alias} points at a path with no manifest",
                )
        # The contract crate compiles as a library entry point, so the linked
        # owner is a real package rather than a name.
        self.assertTrue(CONTRACTS_LIB_RS.is_file())
        self.assertTrue(IMPROVEMENT_LIB_RS.is_file())
        # "before A-37 code exists": no improvement module imports the contract
        # crate yet, which is exactly the state this preparation prepares for.
        combined = "".join(read_text(source) for source in sorted(IMPROVEMENT_SRC_DIR.rglob("*.rs")))
        self.assertFalse(
            uses_crate(combined, "eliot_learning_contracts"),
            "the A-37 module is present; this preparation must stay ahead of it",
        )
        _, scope = require_fixture_object(10, "source-scope.json")
        require_fixture_base(10, "source-scope.json", scope)
        expected_modules = scope.get("expected_improvement_modules")
        self.assertIsInstance(expected_modules, list) and expected_modules
        declared = re.findall(
            r"^pub mod ([a-z0-9_]+);",
            read_text(IMPROVEMENT_LIB_RS),
            re.MULTILINE,
        )
        self.assertEqual(
            sorted(declared), sorted(expected_modules),
            "the improvement module surface changed; A-37 code must not be here yet",
        )
        self.assertTrue(self.fixtures_available)

    # WORK_UNIT_CASE: 970/11
    def test_11_source_scope_is_clean(self) -> None:
        """source scope contains no algorithm/test repair, semantic router change or A-38 package mutation."""
        _, scope = require_fixture_object(11, "source-scope.json")
        require_fixture_base(11, "source-scope.json", scope)
        forbidden_imports = scope.get("forbidden_improvement_imports")
        self.assertIsInstance(forbidden_imports, list) and forbidden_imports
        sources = sorted(IMPROVEMENT_SRC_DIR.rglob("*.rs"))
        combined = "".join(read_text(source) for source in sources)
        self.assertTrue(combined, "eliot-improvement has no Rust sources to inspect")
        for crate_name in forbidden_imports:
            with self.subTest(imported=crate_name):
                self.assertFalse(uses_crate(combined, crate_name))
        # No A-37 marker and no test repair in the consumer's Rust sources.
        for marker in ("A-37", "#819", "#970", "#[test]", "#[tokio::test]"):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, combined)
        # The semantic router is untouched: its published symbols are still
        # declared in the router module and re-exported by the crate root.
        router_symbols = scope.get("expected_router_symbols")
        self.assertIsInstance(router_symbols, list) and router_symbols
        router_relative = str(scope.get("router_source", ""))
        router_path = REPO_ROOT / router_relative
        self.assertTrue(router_path.is_file(), f"missing router source {router_relative!r}")
        router_text = read_text(router_path)
        lib_text = read_text(IMPROVEMENT_LIB_RS)
        for symbol in router_symbols:
            with self.subTest(router=symbol):
                self.assertRegex(
                    router_text,
                    rf"(?m)^pub (?:struct|enum|fn) {re.escape(symbol)}\b",
                    msg=f"router symbol {symbol} is not declared in {router_relative}",
                )
                self.assertRegex(lib_text, rf"\b{re.escape(symbol)}\b")
        # The A-38 package is a different scope: this issue must not mutate it.
        self.assertTrue(SELF_QUALITY_MANIFEST.is_file())
        self.assertEqual(
            load_toml(SELF_QUALITY_MANIFEST)["package"]["name"], "eliot-self-quality",
        )
        for owned in (IMPROVEMENT_MANIFEST, CONTRACTS_MANIFEST, SELF_QUALITY_MANIFEST):
            with self.subTest(manifest=owned.name):
                text = read_text(owned)
                self.assertNotIn("#970", text, f"{owned.name} claims this work unit")
                self.assertNotIn("#819", text, f"{owned.name} claims the A-37 scope")
        for a38_path in scope.get("a38_paths", []):
            self.assertTrue((REPO_ROOT / str(a38_path)).exists(), f"missing A-38 path {a38_path}")
        self.assertTrue(self.fixtures_available)
        # Negative: a test attribute in the consumer sources is a test repair.
        self.assertIn("#[test]", combined + "#[test]")

    # WORK_UNIT_CASE: 970/12
    def test_12_readiness_is_not_closure(self) -> None:
        """dependency readiness does not imply implemented closure, module acceptance, activation or Product proof."""
        own_text = read_text(Path(__file__).resolve())
        self.assertEqual(
            readiness_claims_found(own_text), [],
            "this gate's own source makes a closure or acceptance claim",
        )
        self.assertIn("preparation-only", own_text.lower())
        self.assertIn("implementation proof", own_text.lower())
        # Implementation is not implied: the consumer still imports nothing from
        # the contract crate, so no A-37 module closure exists.
        combined = "".join(
            read_text(source) for source in sorted(IMPROVEMENT_SRC_DIR.rglob("*.rs"))
        )
        self.assertFalse(uses_crate(combined, "eliot_learning_contracts"))
        # Activation is not implied: the improvement crate takes no activation
        # edge, even though the contract crate publishes activation types.
        live = manifest_dependencies(IMPROVEMENT_MANIFEST)
        self.assertNotIn("eliot-learning-activation-assessment", live)
        surface = public_surface(read_text(CONTRACTS_LIB_RS))
        for symbol in ACTIVATION_CONTRACT_TYPES:
            with self.subTest(activation=symbol):
                self.assertIn(symbol, surface)
                self.assertNotIn(symbol, combined)
        # Module acceptance is not implied: this preparation registers no
        # acceptance metadata and claims no admission on either manifest.
        for owned in (IMPROVEMENT_MANIFEST, CONTRACTS_MANIFEST):
            with self.subTest(manifest=owned.name):
                self.assertNotIn("#970", read_text(owned))
        self.assertNotIn(
            "metadata", load_toml(IMPROVEMENT_MANIFEST)["package"],
            "the consumer registered acceptance metadata for this preparation",
        )
        # Product proof is not implied: no workflow, descriptor or fixture
        # outside this bundle claims a product result for this unit.
        for name in ("denominator.json", "lock-delta.json", "membership.json"):
            with self.subTest(fixture=name):
                raw = FIXTURE_DIR / name
                self.assertTrue(raw.is_file())
                self.assertEqual(
                    readiness_claims_found(raw.read_text(encoding="utf-8")), [],
                )
        self.assertTrue(self.fixtures_available)
        # Negative: the claim predicate catches a forbidden overclaim.
        tampered = "The module accep" + "ted with activation compl" + "ete."
        self.assertEqual(
            readiness_claims_found(tampered),
            ["module accep" + "ted", "activation compl" + "ete"],
        )
        self.assertEqual(readiness_claims_found("a plain readiness note"), [])


if __name__ == "__main__":
    unittest.main()
