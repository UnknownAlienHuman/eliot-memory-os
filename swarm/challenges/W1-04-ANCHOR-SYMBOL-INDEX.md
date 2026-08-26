# W1-04 anchor-to-symbol index challenge and Root disposition

Status: `ROOT_SCOPE_AMENDMENT_ACCEPTED`; this remains the single §2.1 work unit.

## Challenge

The four inputs named by `ROOT-DIRECTIVE-v1.5` cannot, by themselves, derive
code-side owners for the 58 Architecture anchors:

- the current Rust source contains one literal `ARCH-*` value, and that value
  is test data rather than a production owner binding;
- the code graph has no Architecture-anchor node property or edge;
- `swarm/inventory/modules.json` owns package and fan-out facts, not symbols;
- `swarm/inventory/refusals.csv` currently carries `UNKNOWN` in every
  `normative_anchor` field;
- Appendix H names implementation sections and several prose owners, but §2.1
  explicitly forbids using those prose owners as code-side ownership.

Any owner inferred from a similar symbol name, directory, graph rank, or prose
would therefore be fabricated evidence. Leaving the generator unchanged would
also make the directive's `UNKNOWN < 55` discriminator impossible.

## Root disposition

Admit one strict, site-local code binding as part of §2.1:

```text
/// ELIOT_ARCH_OWNER: ARCH-XXX-NN
pub <item-kind> <Symbol> ...
```

The marker is navigation metadata, not proof that the requirement is
implemented or operational. The generated `support` field therefore remains
`UNKNOWN`. The owner is the Cargo package that defines the bound production
symbol; the reverse index records the exact source path, symbol, and anchor.

The admitted grammar is deliberately narrower than Rust. For configuration
gates, the only admitted atom is bare `test`; the only admitted operators are
`all(...)`, `any(...)`, and unary `not(...)` over that atom. Every other atom,
including `feature = "..."`, target, and platform atoms such as `target_os = "windows"`,
`target_os = "linux"`, `unix`, and `windows` are outside the grammar even
when they occur inside a larger expression. An unsupported atom on a marked
target or crate-root source fails closed with `UNKNOWN`; an unmarked source
does not become ownership evidence. This avoids treating independent SAT
variables as proof for Rust cfg domains whose correlations the generator does
not model. The marker and its target must be at lexical delimiter depth zero
(`()[]{}`) in a production source file reached from a non-test Cargo target
through direct targets or plain, attribute-free top-level `mod name;`
declarations. The marker is a genuine outer `///` rustdoc line, followed only
by contiguous outer rustdoc lines and complete outer attributes, then one
public defining item. Restricted visibility, re-exports, macro-generated
items, nested/inline-module items, attributed or `#[path]` module edges,
test-only configurations, and unsupported source shapes fail closed and remain
`UNKNOWN` until moved to the admitted grammar. This conservative subset is the
proof boundary; the scripts do not claim to parse all Rust source semantics.

The initial seed is intentionally minimal and unambiguous:

| Anchor | Production symbol | Code owner |
|---|---|---|
| `ARCH-AUTH-01` | `GrantGraph` | `eliot-authority` |
| `ARCH-SCOPE-01` | `ScopeBindingGuard` | `eliot-workscope` |
| `ARCH-SWM-02` | `CoordinationOwner` | `eliot-coordination` |
| `ARCH-FIN-01` | `FinishDecisionOutcome` | `eliot-canonical` |

This yields four code-derived owners and 54 honest `UNKNOWN` owners. No other
anchor is inferred. All four real seed sites are deliberately ungated; no
`cfg`/`cfg_attr` condition is part of their admission. Future lanes that materially touch a bound site must keep
or revise its marker in the same change; a lane may add another marker only
when it can name the exact production owner symbol.

## Generator and verifier contract

- retain the canonical 58-anchor order from Architecture A16.1;
- reject non-top-level, test-only, unknown, duplicate, ambiguous, or missing
  marker targets and every source shape outside the admitted grammar;
- derive package ownership from the current module manifest, never Appendix H;
- join exact refusal sites only when their `normative_anchor` names the anchor;
- bind the persisted code-graph artifact and module/refusal inputs by digest;
- record digest and semantic evidence assuming writer quiescence; this is not
  an atomic snapshot proof and does not claim TOCTOU is fixed;
- emit a symmetric symbol-to-anchor reverse index;
- preserve `UNKNOWN` for every unmapped anchor and for all support claims;
- fail on stale bytes, reverse asymmetry, source-path/symbol drift, or
  `UNKNOWN >= 55`.

Rollback is the atomic revert of the four markers, the generator/verifier
revision, and their generated projections. Review is mandatory when a bound
symbol moves, is renamed, becomes test-only, changes Cargo owner, or when an
affected lane cannot preserve the exact anchor.
