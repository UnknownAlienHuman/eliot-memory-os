"""Language-aware case-marker and execution-reconciliation oracle for #851.

Sole ownership for D-WU-BINDINGS and D-CASE-COVERAGE. Every numbered assignment
case 1..N must have exactly one source-bound qualified test, one matching
discovery receipt and one actual executed-pass result under the current v4 contracts.

Rust source parsing uses bounded lexical states (code, attributes, comments,
strings, raw strings, byte strings, chars). Python parsing uses tokenize and AST.
No subprocess, network, filesystem mutation, or test execution occurs in this module.
"""
from __future__ import annotations

import ast
import dataclasses
from dataclasses import dataclass
from enum import Enum
import io
import re
import tokenize
from typing import Sequence

from . import contracts as c

SCHEMA_REVISION = "eliot-work-unit-case-binding-v1"
MAX_SOURCE_BYTES = 8_388_608
MAX_LINE_BYTES = 65_536
MAX_LEXICAL_DEPTH = 128
MAX_TESTS = 100_000
MAX_CASES = 1_000

_RUST_MARKER_RE = re.compile(r"^\s*//\s*WORK_UNIT_CASE:\s*(\d+)/(\d+)\s*$")
_PY_MARKER_RE = re.compile(r"^#\s*WORK_UNIT_CASE:\s*(\d+)/(\d+)\s*$")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class CaseBindingProblem(str, Enum):
    # Lexical / parsing
    UNCLOSED_LEXICAL_STATE = "UNCLOSED_LEXICAL_STATE"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    DETACHED_MARKER = "DETACHED_MARKER"
    AMBIGUOUS_MARKER = "AMBIGUOUS_MARKER"
    MARKER_BEFORE_NON_TEST = "MARKER_BEFORE_NON_TEST"
    IGNORED_TEST = "IGNORED_TEST"
    CFG_DISABLED = "CFG_DISABLED"
    SKIPPED_DECORATOR = "SKIPPED_DECORATOR"
    DYNAMIC_IDENTITY = "DYNAMIC_IDENTITY"
    DUPLICATE_TEST_IDENTITY = "DUPLICATE_TEST_IDENTITY"
    FOREIGN_TEST_PATH = "FOREIGN_TEST_PATH"

    # Reconciliation
    MISSING_CASE = "MISSING_CASE"
    DUPLICATE_CASE = "DUPLICATE_CASE"
    CASE_NUMBER_OUT_OF_BOUNDS = "CASE_NUMBER_OUT_OF_BOUNDS"
    FOREIGN_ISSUE = "FOREIGN_ISSUE"
    FUNCTION_MULTIPLE_CASES = "FUNCTION_MULTIPLE_CASES"
    TEST_NOT_DISCOVERED = "TEST_NOT_DISCOVERED"
    TEST_NOT_EXECUTED = "TEST_NOT_EXECUTED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    NON_PASSING_DISPOSITION = "NON_PASSING_DISPOSITION"
    DUPLICATE_DISCOVERY = "DUPLICATE_DISCOVERY"
    DUPLICATE_EXECUTION = "DUPLICATE_EXECUTION"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"

    # Adequacy floor / placeholders
    EMPTY_TEST_BODY = "EMPTY_TEST_BODY"
    UNCONDITIONAL_TRUE = "UNCONDITIONAL_TRUE"
    TRIVIAL_SELF_EQUALITY = "TRIVIAL_SELF_EQUALITY"
    NO_CHECK_CONSTANT = "NO_CHECK_CONSTANT"

    # Resource bounds
    FILE_SIZE_LIMIT = "FILE_SIZE_LIMIT"
    LINE_LENGTH_LIMIT = "LINE_LENGTH_LIMIT"
    LEXICAL_DEPTH_LIMIT = "LEXICAL_DEPTH_LIMIT"
    TEST_COUNT_LIMIT = "TEST_COUNT_LIMIT"
    CASE_COUNT_LIMIT = "CASE_COUNT_LIMIT"


class CaseBindingError(ValueError):
    """Fail-closed error with stable error problem code."""

    def __init__(self, problem: CaseBindingProblem, detail: str = ""):
        self.problem = problem
        self.detail = detail
        msg = f"{problem.value}: {detail}" if detail else problem.value
        super().__init__(msg)


@dataclass(frozen=True)
class BindingLimits:
    max_source_bytes: int = MAX_SOURCE_BYTES
    max_line_bytes: int = MAX_LINE_BYTES
    max_lexical_depth: int = MAX_LEXICAL_DEPTH
    max_tests: int = MAX_TESTS
    max_cases: int = MAX_CASES


@dataclass(frozen=True)
class ParsedMarker:
    case_issue: int
    case_number: int
    test_name: str
    qualified_name: str
    file_path: str
    line: int
    column: int
    has_skip: bool = False
    has_ignore: bool = False
    has_cfg: bool = False
    is_async: bool = False
    adequacy_problem: CaseBindingProblem | None = None
    adequacy_detail: str | None = None
    proof_ceiling_downgrade: bool = False


def _check_source_bounds(source_bytes: bytes, limits: BindingLimits) -> str:
    if len(source_bytes) > limits.max_source_bytes:
        raise CaseBindingError(CaseBindingProblem.FILE_SIZE_LIMIT,
                               f"source size {len(source_bytes)} exceeds bound {limits.max_source_bytes}")
    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CaseBindingError(CaseBindingProblem.SYNTAX_ERROR, f"source is not valid UTF-8: {exc}") from exc

    for line_idx, line in enumerate(source_text.splitlines(keepends=True), 1):
        if len(line.encode("utf-8")) > limits.max_line_bytes:
            raise CaseBindingError(CaseBindingProblem.LINE_LENGTH_LIMIT,
                                   f"line {line_idx} length {len(line.encode('utf-8'))} exceeds bound {limits.max_line_bytes}")
    return source_text


def parse_rust_markers(
    source: str | bytes,
    file_path: str,
    *,
    expected_issue: int | None = None,
    limits: BindingLimits | None = None,
) -> list[ParsedMarker]:
    """Parse Rust source with bounded lexical scanning for WORK_UNIT_CASE comments."""
    limits = limits or BindingLimits()
    source_bytes = source.encode("utf-8") if isinstance(source, str) else source
    source_text = _check_source_bounds(source_bytes, limits)

    lines = source_text.splitlines(keepends=True)
    if len(lines) > limits.max_tests:
        raise CaseBindingError(CaseBindingProblem.TEST_COUNT_LIMIT, "line count exceeds test bound")

    # Lexical scan over entire text
    i = 0
    n = len(source_text)
    depth = 0
    candidate_markers: list[tuple[int, int, int, int]] = []  # (issue, case, line_num, col_num)
    line_num = 1
    col_num = 1

    while i < n:
        # Track line/col
        char = source_text[i]

        if depth > 0:
            # Inside block comment
            if source_text[i:i+2] == "/*":
                depth += 1
                if depth > limits.max_lexical_depth:
                    raise CaseBindingError(CaseBindingProblem.LEXICAL_DEPTH_LIMIT,
                                           f"block comment depth {depth} exceeds bound {limits.max_lexical_depth}")
                i += 2
                col_num += 2
                continue
            elif source_text[i:i+2] == "*/":
                depth -= 1
                i += 2
                col_num += 2
                continue
            elif char == "\n":
                line_num += 1
                col_num = 1
                i += 1
                continue
            else:
                col_num += 1
                i += 1
                continue

        # Normal code state
        if source_text[i:i+2] == "/*":
            depth = 1
            i += 2
            col_num += 2
            continue

        if source_text[i:i+3] in ("///", "//!"):
            # Doc comment: marker is ignored in doc comments
            end_line = source_text.find("\n", i)
            if end_line == -1:
                break
            line_num += 1
            col_num = 1
            i = end_line + 1
            continue

        if source_text[i:i+2] == "//":
            # Ordinary line comment: check for WORK_UNIT_CASE
            end_line = source_text.find("\n", i)
            comment_line = source_text[i:end_line] if end_line != -1 else source_text[i:]
            match = _RUST_MARKER_RE.match(comment_line)
            if match:
                c_issue = int(match.group(1))
                c_case = int(match.group(2))
                candidate_markers.append((c_issue, c_case, line_num, col_num))
            if end_line == -1:
                break
            line_num += 1
            col_num = 1
            i = end_line + 1
            continue

        # Raw string literals: r"...", r#"..."#, r##"..."##
        # Raw byte strings: br"...", br#"..."#
        is_raw = False
        hash_count = 0
        raw_start = i
        if source_text[i:i+2] == 'r"' or source_text[i:i+3] == 'br"':
            is_raw = True
            hash_count = 0
            i = i + 2 if source_text[i] == 'r' else i + 3
        elif source_text[i:i+2] == "r#" or source_text[i:i+3] == "br#":
            is_raw = True
            j = i + 1 if source_text[i] == 'r' else i + 2
            while j < n and source_text[j] == '#':
                j += 1
            if j < n and source_text[j] == '"':
                hash_count = j - (i + 1 if source_text[i] == 'r' else i + 2)
                i = j + 1
            else:
                is_raw = False

        if is_raw:
            closing = '"' + ('#' * hash_count)
            close_idx = source_text.find(closing, i)
            if close_idx == -1:
                raise CaseBindingError(CaseBindingProblem.UNCLOSED_LEXICAL_STATE, "unclosed raw string literal")
            # Advance line_num and col_num
            segment = source_text[raw_start:close_idx + len(closing)]
            nl_count = segment.count("\n")
            if nl_count > 0:
                line_num += nl_count
                last_nl = segment.rfind("\n")
                col_num = len(segment) - last_nl
            else:
                col_num += len(segment)
            i = close_idx + len(closing)
            continue

        # Normal string literal: "..." or b"..."
        if char == '"' or source_text[i:i+2] == 'b"':
            str_start = i
            i = i + 1 if char == '"' else i + 2
            escaped = False
            closed = False
            while i < n:
                c_char = source_text[i]
                if escaped:
                    escaped = False
                elif c_char == '\\':
                    escaped = True
                elif c_char == '"':
                    closed = True
                    i += 1
                    break
                elif c_char == '\n':
                    line_num += 1
                    col_num = 1
                    i += 1
                    continue
                i += 1
            if not closed:
                raise CaseBindingError(CaseBindingProblem.UNCLOSED_LEXICAL_STATE, "unclosed string literal")
            col_num += (i - str_start)
            continue

        # Char literal: '...' or b'...'
        if char == "'" or source_text[i:i+2] == "b'":
            char_start = i
            i = i + 1 if char == "'" else i + 2
            if i < n and source_text[i] == '\\':
                # Escaped char
                if i + 2 < n and source_text[i+2] == "'":
                    i += 3
                    col_num += (i - char_start)
                    continue
                elif i + 3 < n and source_text[i+3] == "'":
                    i += 4
                    col_num += (i - char_start)
                    continue
            elif i + 1 < n and source_text[i+1] == "'":
                i += 2
                col_num += (i - char_start)
                continue
            # Lifetime e.g. 'a, 'static
            # Fall through as normal identifier

        if char == "\n":
            line_num += 1
            col_num = 1
        else:
            col_num += 1
        i += 1

    if depth > 0:
        raise CaseBindingError(CaseBindingProblem.UNCLOSED_LEXICAL_STATE, f"unclosed block comment (depth {depth})")

    # Now attribute each candidate marker to the immediately following test function
    parsed_markers: list[ParsedMarker] = []
    seen_test_names: set[str] = set()

    for issue_num, case_num, m_line, m_col in candidate_markers:
        # Check lines following m_line
        idx = m_line  # 1-based index in lines (m_line is lines[m_line - 1])
        has_test_attr = False
        has_tokio_attr = False
        has_ignore_attr = False
        has_cfg_attr = False
        is_async_fn = False
        fn_name: str | None = None
        fn_line: int | None = None

        while idx < len(lines):
            raw_line = lines[idx]
            stripped = raw_line.strip()

            if not stripped:
                # Blank line immediately detaches marker
                raise CaseBindingError(CaseBindingProblem.DETACHED_MARKER,
                                       f"marker on line {m_line} detached by blank line {idx + 1}")

            if stripped.startswith("//") or stripped.startswith("/*"):
                # Intervening comment detaches marker
                raise CaseBindingError(CaseBindingProblem.DETACHED_MARKER,
                                       f"marker on line {m_line} detached by intervening comment on line {idx + 1}")

            if stripped.startswith("#["):
                # Attribute
                attr_text = stripped
                # Check for test attributes
                if "#[test]" in attr_text:
                    has_test_attr = True
                if "#[tokio::test]" in attr_text:
                    has_tokio_attr = True
                if "ignore" in attr_text:
                    has_ignore_attr = True
                if "cfg(" in attr_text:
                    has_cfg_attr = True
                idx += 1
                continue

            # Check for function declaration
            fn_match = re.search(r"\b(?:async\s+)?fn\s+([A-Za-z0-9_]+)", stripped)
            if fn_match:
                fn_name = fn_match.group(1)
                fn_line = idx + 1
                if "async fn" in stripped:
                    is_async_fn = True
                break
            else:
                # Not an attribute and not a fn declaration
                raise CaseBindingError(CaseBindingProblem.MARKER_BEFORE_NON_TEST,
                                       f"marker on line {m_line} precedes non-function item: {stripped}")

        if not fn_name:
            raise CaseBindingError(CaseBindingProblem.DETACHED_MARKER,
                                   f"marker on line {m_line} does not precede any function")

        if not (has_test_attr or has_tokio_attr):
            raise CaseBindingError(CaseBindingProblem.MARKER_BEFORE_NON_TEST,
                                   f"marker on line {m_line} precedes function '{fn_name}' without test attribute")

        if has_ignore_attr:
            raise CaseBindingError(CaseBindingProblem.IGNORED_TEST,
                                   f"Rust test '{fn_name}' has #[ignore] attribute")

        if fn_name in seen_test_names:
            raise CaseBindingError(CaseBindingProblem.DUPLICATE_TEST_IDENTITY,
                                   f"duplicate Rust test identity '{fn_name}'")
        seen_test_names.add(fn_name)

        # Inspect Rust function body for obvious placeholders
        body_text = ""
        brace_count = 0
        inside_body = False
        for b_idx in range(idx, len(lines)):
            l = lines[b_idx]
            if "{" in l:
                brace_count += l.count("{")
                inside_body = True
            if "}" in l:
                brace_count -= l.count("}")
            if inside_body:
                body_text += l
                if brace_count == 0:
                    break

        adequacy_prob: CaseBindingProblem | None = None
        adequacy_detail: str | None = None

        # Clean body statements
        inner_body = body_text.strip()
        if inner_body.startswith("{"):
            inner_body = inner_body[1:]
        if inner_body.endswith("}"):
            inner_body = inner_body[:-1]
        inner_stripped = inner_body.strip()

        if not inner_stripped or inner_stripped == "return;" or inner_stripped == "return":
            adequacy_prob = CaseBindingProblem.EMPTY_TEST_BODY
            adequacy_detail = "empty or return-only Rust test body"
        elif re.fullmatch(r"assert!\s*\(\s*true\s*\)\s*;", inner_stripped):
            adequacy_prob = CaseBindingProblem.UNCONDITIONAL_TRUE
            adequacy_detail = "unconditional true assert!(true) in Rust test"
        elif re.search(r"assert_eq!\s*\(\s*([A-Za-z0-9_]+)\s*,\s*\1\s*\)\s*;", inner_stripped):
            adequacy_prob = CaseBindingProblem.TRIVIAL_SELF_EQUALITY
            adequacy_detail = "trivial self-equality in Rust test"
        elif not any(k in inner_stripped for k in ("assert", "panic", "check", "verify", "should_panic")):
            adequacy_prob = CaseBindingProblem.NO_CHECK_CONSTANT
            adequacy_detail = "constant construction without checked result in Rust test"

        parsed_markers.append(ParsedMarker(
            case_issue=issue_num,
            case_number=case_num,
            test_name=fn_name,
            qualified_name=fn_name,
            file_path=file_path,
            line=fn_line or m_line,
            column=m_col,
            has_ignore=has_ignore_attr,
            has_cfg=has_cfg_attr,
            is_async=is_async_fn or has_tokio_attr,
            adequacy_problem=adequacy_prob,
            adequacy_detail=adequacy_detail,
        ))

    return parsed_markers


def check_python_function_adequacy(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[CaseBindingProblem | None, str | None, bool]:
    """Check Python test function body against the anti-placeholder floor."""
    body = node.body
    # Strip docstrings
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]

    if not body:
        return CaseBindingProblem.EMPTY_TEST_BODY, "empty test body", False
    if all(isinstance(stmt, ast.Pass) for stmt in body):
        return CaseBindingProblem.EMPTY_TEST_BODY, "test body contains only pass", False
    if len(body) == 1 and isinstance(body[0], ast.Return) and (body[0].value is None or (isinstance(body[0].value, ast.Constant) and body[0].value.value is None)):
        return CaseBindingProblem.EMPTY_TEST_BODY, "test body contains only return", False

    assertions = []
    has_with_raises = False
    has_call = False

    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Assert):
            assertions.append(stmt)
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                if isinstance(item.context_expr, ast.Call):
                    func = item.context_expr.func
                    if (isinstance(func, ast.Attribute) and func.attr == 'assertRaises') or \
                       (isinstance(func, ast.Name) and func.id == 'assertRaises'):
                        has_with_raises = True
        elif isinstance(stmt, ast.Call):
            has_call = True
            func = stmt.func
            if isinstance(func, ast.Attribute) and (func.attr.startswith(('assert', 'check', 'verify')) or func.attr == 'fail'):
                assertions.append(stmt)
            elif isinstance(func, ast.Name) and (func.id.startswith(('assert', 'check', 'verify')) or func.id == 'fail'):
                assertions.append(stmt)

    if not assertions and not has_with_raises:
        return CaseBindingProblem.NO_CHECK_CONSTANT, "constant construction or execution without a checked result", False

    # Unconditional true check
    def is_true_assert(a):
        if isinstance(a, ast.Assert):
            if isinstance(a.test, ast.Constant) and a.test.value is True:
                return True
            if isinstance(a.test, ast.UnaryOp) and isinstance(a.test.op, ast.Not) and isinstance(a.test.operand, ast.Constant) and a.test.operand.value is False:
                return True
        elif isinstance(a, ast.Call):
            func = a.func
            if isinstance(func, ast.Attribute) and func.attr in ('assertTrue',):
                if a.args and isinstance(a.args[0], ast.Constant) and a.args[0].value is True:
                    return True
            elif isinstance(func, ast.Attribute) and func.attr in ('assertFalse',):
                if a.args and isinstance(a.args[0], ast.Constant) and a.args[0].value is False:
                    return True
        return False

    if assertions and all(is_true_assert(a) for a in assertions):
        return CaseBindingProblem.UNCONDITIONAL_TRUE, "unconditional true assertion", False

    # Trivial self-equality check
    def is_self_equality(a):
        if isinstance(a, ast.Assert):
            if isinstance(a.test, ast.Compare) and len(a.test.ops) == 1 and isinstance(a.test.ops[0], (ast.Eq, ast.Is)):
                left = a.test.left
                right = a.test.comparators[0]
                if ast.dump(left) == ast.dump(right):
                    return True
        elif isinstance(a, ast.Call):
            func = a.func
            if isinstance(func, ast.Attribute) and func.attr in ('assertEqual', 'assertIs', 'assertIsEqual'):
                if len(a.args) >= 2:
                    left, right = a.args[0], a.args[1]
                    if ast.dump(left) == ast.dump(right):
                        return True
        return False

    if assertions and all(is_self_equality(a) for a in assertions):
        return CaseBindingProblem.TRIVIAL_SELF_EQUALITY, "trivial self-equality assertion", False

    # Check for unknown complex assertion shape retaining lower proof ceiling
    proof_ceiling_downgrade = False
    for a in assertions:
        if isinstance(a, ast.Call):
            func = a.func
            if isinstance(func, ast.Attribute) and func.attr.startswith(('check_', 'verify_custom_')):
                proof_ceiling_downgrade = True

    return None, None, proof_ceiling_downgrade


def parse_python_markers(
    source: str | bytes,
    file_path: str,
    *,
    module_name: str | None = None,
    mode: c.RunnerMode = c.RunnerMode.PYTHON_UNITTEST,
    expected_issue: int | None = None,
    limits: BindingLimits | None = None,
) -> list[ParsedMarker]:
    """Parse Python source using tokenize and AST for WORK_UNIT_CASE comments."""
    limits = limits or BindingLimits()
    source_bytes = source.encode("utf-8") if isinstance(source, str) else source
    source_text = _check_source_bounds(source_bytes, limits)

    # Tokenize to extract real comments (ignoring strings and docstrings)
    candidate_markers: list[tuple[int, int, int, int]] = []
    try:
        token_gen = tokenize.tokenize(io.BytesIO(source_bytes).readline)
        for tok in token_gen:
            if tok.type == tokenize.COMMENT:
                match = _PY_MARKER_RE.match(tok.string)
                if match:
                    c_issue = int(match.group(1))
                    c_case = int(match.group(2))
                    start_line, start_col = tok.start
                    candidate_markers.append((c_issue, c_case, start_line, start_col))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        raise CaseBindingError(CaseBindingProblem.SYNTAX_ERROR, f"tokenization failure: {exc}") from exc

    # Parse AST
    try:
        tree = ast.parse(source_text, filename=file_path)
    except SyntaxError as exc:
        raise CaseBindingError(CaseBindingProblem.SYNTAX_ERROR, f"syntax error in {file_path}: {exc}") from exc

    source_lines = source_text.splitlines(keepends=True)

    # Class-level markers check
    class_nodes: list[ast.ClassDef] = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    for c_node in class_nodes:
        c_start = c_node.decorator_list[0].lineno if c_node.decorator_list else c_node.lineno
        for issue_num, case_num, m_line, m_col in candidate_markers:
            if m_line == c_start - 1:
                raise CaseBindingError(CaseBindingProblem.AMBIGUOUS_MARKER,
                                       f"marker on line {m_line} is attached to class '{c_node.name}'")

    # Map functions and methods
    parsed_markers: list[ParsedMarker] = []
    seen_identities: set[str] = set()

    # Collect all functions/methods with their class context
    functions_with_ctx: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, ast.ClassDef | None]] = []

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions_with_ctx.append((node, None))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions_with_ctx.append((item, node))

    for issue_num, case_num, m_line, m_col in candidate_markers:
        # Find matching function
        matched_fn: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        matched_class: ast.ClassDef | None = None

        for fn_node, cls_node in functions_with_ctx:
            fn_start = fn_node.decorator_list[0].lineno if fn_node.decorator_list else fn_node.lineno
            if m_line == fn_start - 1:
                matched_fn = fn_node
                matched_class = cls_node
                break
            elif fn_start > m_line + 1 and fn_node.lineno >= m_line + 1:
                # Check lines between marker and fn_start
                intervening = source_lines[m_line:fn_start - 1]
                if all(not l.strip() or l.strip().startswith("#") for l in intervening):
                    raise CaseBindingError(CaseBindingProblem.DETACHED_MARKER,
                                           f"marker on line {m_line} detached from '{fn_node.name}' by intervening lines")

        if not matched_fn:
            raise CaseBindingError(CaseBindingProblem.DETACHED_MARKER,
                                   f"marker on line {m_line} does not precede any test function")

        # Check for skipped decorators
        for dec in matched_fn.decorator_list:
            dec_id = ""
            if isinstance(dec, ast.Name):
                dec_id = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_id = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_id = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_id = dec.func.attr
            if "skip" in dec_id.lower():
                raise CaseBindingError(CaseBindingProblem.SKIPPED_DECORATOR,
                                       f"test function '{matched_fn.name}' has skip decorator '{dec_id}'")

        # Dynamic name check
        if not matched_fn.name.isidentifier() or matched_fn.name.startswith("<"):
            raise CaseBindingError(CaseBindingProblem.DYNAMIC_IDENTITY,
                                   f"function name '{matched_fn.name}' is dynamic or invalid")

        # Check TestCase requirement for RunnerMode.PYTHON_UNITTEST
        if mode is c.RunnerMode.PYTHON_UNITTEST and not matched_class:
            raise CaseBindingError(CaseBindingProblem.MARKER_BEFORE_NON_TEST,
                                   f"function '{matched_fn.name}' is not inside a TestCase class")

        # Construct qualified name
        mod_prefix = module_name + "." if module_name else ""
        if matched_class:
            qualified = f"{mod_prefix}{matched_class.name}.{matched_fn.name}"
        else:
            qualified = f"{mod_prefix}{matched_fn.name}"

        if qualified in seen_identities:
            raise CaseBindingError(CaseBindingProblem.DUPLICATE_TEST_IDENTITY,
                                   f"duplicate Python test identity '{qualified}'")
        seen_identities.add(qualified)

        adequacy_prob, adequacy_detail, downgrade = check_python_function_adequacy(matched_fn)

        parsed_markers.append(ParsedMarker(
            case_issue=issue_num,
            case_number=case_num,
            test_name=matched_fn.name,
            qualified_name=qualified,
            file_path=file_path,
            line=matched_fn.lineno,
            column=m_col,
            is_async=isinstance(matched_fn, ast.AsyncFunctionDef),
            adequacy_problem=adequacy_prob,
            adequacy_detail=adequacy_detail,
            proof_ceiling_downgrade=downgrade,
        ))

    return parsed_markers


def parse_source_markers(
    source: str | bytes,
    file_path: str,
    mode: c.RunnerMode,
    *,
    module_name: str | None = None,
    expected_issue: int | None = None,
    limits: BindingLimits | None = None,
) -> list[ParsedMarker]:
    """Dispatch to Rust or Python marker parser based on runner mode or file extension."""
    if mode is c.RunnerMode.RUST_PACKAGE or file_path.endswith(".rs"):
        return parse_rust_markers(source, file_path, expected_issue=expected_issue, limits=limits)
    elif mode in (c.RunnerMode.PYTHON_UNITTEST, c.RunnerMode.METADATA_PYTHON) or file_path.endswith(".py"):
        return parse_python_markers(source, file_path, module_name=module_name, mode=mode,
                                    expected_issue=expected_issue, limits=limits)
    else:
        raise CaseBindingError(CaseBindingProblem.FOREIGN_TEST_PATH, f"unsupported source mode or extension: {file_path}")


def reconcile_case_bindings(
    assignment: c.AssignmentSourceReceipt,
    descriptor: c.WorkUnitDescriptor,
    markers: Sequence[ParsedMarker],
    discoveries: Sequence[c.DiscoveredTestReceipt],
    executions: Sequence[c.TestExecutionRecord],
    *,
    findings: tuple[c.Finding, ...] = (),
) -> c.CaseAccountingReceipt:
    """Reconcile 1..N case markers with discovery and execution receipts into CaseAccountingReceipt."""
    # Verify intrinsic descriptor and assignment binding
    c._binding(assignment, descriptor)

    # Check test roots boundary
    for marker in markers:
        path = marker.file_path.replace("\\", "/")
        is_within = any(path == root.value or path.startswith(root.value + "/") for root in descriptor.test_roots)
        if not is_within:
            raise CaseBindingError(CaseBindingProblem.FOREIGN_TEST_PATH,
                                   f"marker path '{path}' is outside test roots")

    # Check adequacy floor on all markers
    for marker in markers:
        if marker.adequacy_problem is not None:
            raise CaseBindingError(marker.adequacy_problem, marker.adequacy_detail or "")

    n_cases = descriptor.matrix_cases

    # Case bounds and foreign issue checks
    for marker in markers:
        if marker.case_issue != descriptor.issue.number:
            raise CaseBindingError(CaseBindingProblem.FOREIGN_ISSUE,
                                   f"marker issue {marker.case_issue} does not match descriptor issue {descriptor.issue.number}")
        if marker.case_number < 1 or marker.case_number > n_cases:
            raise CaseBindingError(CaseBindingProblem.CASE_NUMBER_OUT_OF_BOUNDS,
                                   f"case {marker.case_number} out of bounds (1..{n_cases})")

    # Duplicate case check
    seen_cases: dict[int, ParsedMarker] = {}
    for marker in markers:
        if marker.case_number in seen_cases:
            raise CaseBindingError(CaseBindingProblem.DUPLICATE_CASE,
                                   f"case {marker.case_number} claimed by multiple tests")
        seen_cases[marker.case_number] = marker

    # One function claiming two cases check
    seen_fns: dict[tuple[str, str], int] = {}
    for marker in markers:
        fn_key = (marker.file_path, marker.qualified_name)
        if fn_key in seen_fns:
            raise CaseBindingError(CaseBindingProblem.FUNCTION_MULTIPLE_CASES,
                                   f"function '{marker.qualified_name}' claims both case {seen_fns[fn_key]} and case {marker.case_number}")
        seen_fns[fn_key] = marker.case_number

    # Missing case check: must have exactly 1..N
    for num in range(1, n_cases + 1):
        if num not in seen_cases:
            raise CaseBindingError(CaseBindingProblem.MISSING_CASE, f"missing case {num}")

    # Discovery indexing and duplicate discovery check
    disc_by_name: dict[str, c.DiscoveredTestReceipt] = {}
    for d in discoveries:
        name = d.test.qualified_name
        if name in disc_by_name:
            raise CaseBindingError(CaseBindingProblem.DUPLICATE_DISCOVERY,
                                   f"duplicate discovery receipt for test '{name}'")
        disc_by_name[name] = d

    # Execution indexing and duplicate execution check
    exec_by_name: dict[str, c.TestExecutionRecord] = {}
    for e in executions:
        name = e.test.qualified_name
        if name in exec_by_name:
            raise CaseBindingError(CaseBindingProblem.DUPLICATE_EXECUTION,
                                   f"duplicate execution record for test '{name}'")
        exec_by_name[name] = e

    # Build members in deterministic sorted order 1..N
    members: list[c.CaseAccountingMember] = []
    proof_ceiling = descriptor.proof_ceiling

    for num in range(1, n_cases + 1):
        marker = seen_cases[num]

        # Match to discovery
        matched_disc = disc_by_name.get(marker.qualified_name) or disc_by_name.get(marker.test_name)
        if not matched_disc:
            raise CaseBindingError(CaseBindingProblem.TEST_NOT_DISCOVERED,
                                   f"source-bound test '{marker.qualified_name}' (case {num}) absent from discovery")

        # Match to execution
        matched_exec = exec_by_name.get(matched_disc.test.qualified_name) or exec_by_name.get(marker.qualified_name)
        if not matched_exec:
            raise CaseBindingError(CaseBindingProblem.TEST_NOT_EXECUTED,
                                   f"discovered test '{matched_disc.test.qualified_name}' (case {num}) absent from execution")

        # Verify disposition
        disp = matched_exec.disposition
        if disp is c.ExecutionDisposition.EXECUTED_FAIL:
            raise CaseBindingError(CaseBindingProblem.EXECUTION_FAILED,
                                   f"test '{matched_exec.test.qualified_name}' execution failed")
        if disp in (c.ExecutionDisposition.TIMED_OUT, c.ExecutionDisposition.SKIPPED,
                    c.ExecutionDisposition.IGNORED, c.ExecutionDisposition.CFG_DISABLED,
                    c.ExecutionDisposition.UNAVAILABLE):
            raise CaseBindingError(CaseBindingProblem.NON_PASSING_DISPOSITION,
                                   f"test '{matched_exec.test.qualified_name}' disposition is {disp.value}")
        if disp is not c.ExecutionDisposition.EXECUTED_PASS:
            raise CaseBindingError(CaseBindingProblem.NON_PASSING_DISPOSITION,
                                   f"test '{matched_exec.test.qualified_name}' disposition is not EXECUTED_PASS: {disp.value}")

        if marker.proof_ceiling_downgrade:
            # Complex unknown assertion retains lower proof ceiling
            proof_ceiling = c.ProofCeiling("assignment-source-only")

        case_id = c.CaseIdentity(descriptor.issue, num)
        case_marker = c.CaseMarker(case_id, matched_disc.test, matched_disc.location)
        member = c.CaseAccountingMember(case_id, case_marker, matched_exec)
        members.append(member)

    # Emit deterministic sorted receipt
    sorted_members = tuple(sorted(members, key=lambda m: m.case.number))
    return c.CaseAccountingReceipt(
        assignment=assignment,
        descriptor=descriptor,
        members=sorted_members,
        result=c.OverallResult.PASS,
        proof_ceiling=proof_ceiling,
        findings=findings,
    )
