// Frozen fixture for #787 case 7: a `use` ALIAS bound to a differently-named
// estimator. This is a PINNED LIMITATION, asserted rather than expected to pass.
//
//     use crate::budgets::plan_units as tokens;
//     fn plan_hint(body: &str) -> usize {
//         tokens(body)
//     }
//
// #866's accepted rule set contains NO alias-binding grammar. Its trigger arms
// are fixed-shape regexes over estimator IDENTIFIERS -- ESTIMATOR_HELPER_RE,
// ESTIMATOR_CALL_RE, CHAR_RATIO, BYTE_RATIO -- and neither the `use` line nor
// the aliased call matches any of them. The estimator is therefore enumerated
// by NO rule at all and produces NO candidate and NO finding.
//
// Case 7 asserts this observed behaviour so the gap cannot be mistaken for
// coverage. Closing it needs a new `use ... as` resolution arm inside #866,
// which issue #787 is forbidden from writing; it is reported as a
// ContractChallenge instead.
use crate::budgets::plan_units as tokens;

fn plan_hint(body: &str) -> usize {
    tokens(body)
}
