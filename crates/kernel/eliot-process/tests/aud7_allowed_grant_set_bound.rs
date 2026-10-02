//! AUD7 / I1.6: the explicit allowed environment set bounds the GRANT half
//! by the SAME ceiling it bounds the inherited-name half (issue #1888).
//!
//! `docs/architecture/I01-06-windows-isolation.md:14` states, verbatim:
//! "models and third-party Modules do not inherit secrets by default". The one
//! door AUD7 allows inheritance through is `EnvironmentAllowSet`, and its grant
//! half is the only place a launch can name secret material to inherit. This
//! file proves that half is an explicit, BOUNDED set sharing the name half's
//! ceiling: at the ceiling a grant is admitted, and one grant past it the
//! constructor refuses with the typed `ContractError::LimitExceeded` naming
//! `inherited_environment_grants`.
//!
//! The ceiling is discovered by probing the already-bounded name half rather
//! than restating a private constant, so this asserts the CLAIM (one shared
//! ceiling) instead of a duplicated number.
//!
//! No OS probe, process launch, build, or test run happened here; these are
//! value assertions on the contract type only.

use eliot_process::{
    ContractError, EnvironmentAllowSet, EnvironmentInheritance, EnvironmentProjection,
    SecretGrantRef, SecretRef,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Names that are neither secret-like nor malformed, so the name half refuses
/// only on its own size ceiling.
fn probe_names(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("ELIOT_NAME_{index}"))
        .collect()
}

/// One distinct grant per index. A grant is a provider/key pair and never a
/// value, so no entry here is secret material.
fn probe_grants(count: usize) -> Result<Vec<SecretGrantRef>, Box<dyn std::error::Error>> {
    let mut grants = Vec::with_capacity(count);
    for index in 0..count {
        grants.push(SecretGrantRef::new(SecretRef::new(
            "credential_manager",
            format!("provider/key-{index}"),
        )?)?);
    }
    Ok(grants)
}

/// Returns the largest name count the name half admits, by binary search over
/// a ceiling that must exist and must be finite.
fn name_half_ceiling() -> Result<usize, Box<dyn std::error::Error>> {
    let admitted = |count: usize| EnvironmentAllowSet::new(probe_names(count), Vec::new()).is_ok();
    if !admitted(1) {
        return Err("the name half must admit at least one name".into());
    }
    let mut low = 1_usize;
    let mut high = 2_usize;
    while admitted(high) {
        low = high;
        high = high.saturating_mul(2);
    }
    // `low` is admitted, `high` is refused: narrow to the exact boundary.
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if admitted(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

/// Positive case: a grant set exactly at the shared ceiling is admitted, and it
/// admits precisely the references it names and no other.
///
/// This is the positive half of the boundary: at the ceiling the set is still
/// constructible, so the refusal below is the ceiling itself and not some
/// smaller accidental limit on grants.
#[test]
fn granted_allow_set_at_the_ceiling_is_admitted_and_names_exactly_its_references() -> TestResult {
    let ceiling = name_half_ceiling()?;
    let admitted = EnvironmentAllowSet::new(Vec::new(), probe_grants(ceiling)?)?;
    assert_eq!(admitted.grants().len(), ceiling);
    assert!(!admitted.is_empty());

    // The set admits the reference it names and nothing beside it: an unnamed
    // provider/key pair is absent because it was never named, not because it
    // was subtracted after the set existed.
    let named = SecretRef::new("credential_manager", "provider/key-0")?;
    let unnamed = SecretRef::new("credential_manager", "provider/never-named")?;
    assert!(admitted.permits_reference(&named));
    assert!(!admitted.permits_reference(&unnamed));

    // A projection carrying a granted set is no longer ungranted, and only
    // because the caller stated that exact set.
    let projection = EnvironmentProjection::with_allowed(
        std::collections::BTreeMap::new(),
        Vec::new(),
        EnvironmentInheritance::Allowlisted,
        admitted,
    )?;
    assert!(!projection.is_ungranted());
    assert_eq!(projection.allowed().grants().len(), ceiling);
    Ok(())
}

/// Refusal case: one grant past the shared ceiling is refused, typed, and names
/// the GRANT half at that exact ceiling.
///
/// The `field` string is the load-bearing assertion, not the variant:
/// `LimitExceeded` is shared with the inherited-name half, so a variant-only
/// test would still pass if the grant half had no bound at all, and a
/// name-half refusal cannot satisfy this.
#[test]
fn grant_half_past_the_ceiling_is_refused_and_names_its_own_half() -> TestResult {
    let ceiling = name_half_ceiling()?;
    let past = EnvironmentAllowSet::new(Vec::new(), probe_grants(ceiling + 1)?);
    let refused = match past {
        Ok(set) => {
            return Err(format!(
                "a grant set of {} past the ceiling {ceiling} must be refused, but it was \
                 admitted with {} grants",
                ceiling + 1,
                set.grants().len()
            )
            .into());
        }
        Err(error) => error,
    };
    assert_eq!(
        refused,
        ContractError::LimitExceeded {
            field: "inherited_environment_grants",
            limit: ceiling,
        },
        "the refusal must be the grant-half LimitExceeded at exactly the shared ceiling, so a \
         name-half refusal or a variant-only match cannot satisfy it"
    );

    // A secret-like NAME stays refused even inside the ceiling, so the bound
    // is not the only thing the set checks: the allow-set admits no secret
    // material by name at any size.
    let secret_named = EnvironmentAllowSet::new(["API_TOKEN".to_owned()], Vec::new());
    assert!(
        matches!(secret_named, Err(ContractError::SecretBoundary { .. })),
        "a secret-like name must stay refused on the secret boundary, not become \
         admissible because it sits under the ceiling"
    );
    Ok(())
}
