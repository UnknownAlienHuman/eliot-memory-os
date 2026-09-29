use std::{env, error::Error, fmt::Write as _, fs, io, path::PathBuf};

use eliot_contracts::{
    FacetCompensationClass, FacetConcurrencyClass, FacetDisclosureRule, FacetEffectClass,
    FacetIdempotencyClass, FacetObservationClass, FacetReplayClass, FacetSimulationClass,
    FacetTimeoutClass, ResourceFacetContract, ResourceFacetField, ResourceFacetMethod,
    ResourceFacetValueKind, native_worker_resource_facet_v1,
};

const GENERATOR_VERSION: &str = "eliot-native-resource-facet-stubgen/1";

// Controlled regeneration: set ELIOT_REGENERATE_NATIVE_WORKER_FACETS=1 for a
// one-off cargo check -p eliot-native-worker-core; ordinary builds never
// write the tracked projection and fail if it is stale.

fn main() {
    if let Err(error) = generate_projection() {
        panic!("native worker facet projection failed: {error}");
    }
}

fn generate_projection() -> Result<(), Box<dyn Error>> {
    let manifest = native_worker_resource_facet_v1()?;
    manifest.validate()?;
    let canonical_ref = manifest.canonical_ref()?;
    let method = manifest.method("execute").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "shared resource facet has no Execute method",
        )
    })?;
    verify_native_input(method)?;

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/generated/native_worker_facets_v1.rs.in");
    println!("cargo:rerun-if-changed=src/generated/native_worker_facets_v1.rs");
    println!(
        "cargo:rerun-if-changed=../../foundation/eliot-contracts/src/facet_manifest.rs"
    );
    println!("cargo:rerun-if-changed=../../foundation/eliot-contracts/src/lib.rs");
    println!("cargo:rerun-if-env-changed=ELIOT_REGENERATE_NATIVE_WORKER_FACETS");
    println!("cargo:rustc-env=ELIOT_NATIVE_WORKER_RESOURCE_FACET_REF={canonical_ref}");

    let generated = render_projection(&manifest, method)?;
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "manifest dir")
        })?,
    );
    let checked_in_path = manifest_dir.join("src/generated/native_worker_facets_v1.rs");
    if matches!(
        env::var("ELIOT_REGENERATE_NATIVE_WORKER_FACETS").as_deref(),
        Ok("1")
    ) {
        fs::write(&checked_in_path, &generated)?;
    } else {
        let checked_in = fs::read_to_string(&checked_in_path)?;
        if checked_in != generated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is stale; regenerate with ELIOT_REGENERATE_NATIVE_WORKER_FACETS=1",
                    checked_in_path.display()
                ),
            )
            .into());
        }
    }

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "build output directory")
        })?,
    );
    fs::write(out_dir.join("native_worker_facets_v1.rs"), generated)?;
    Ok(())
}

fn verify_native_input(method: &ResourceFacetMethod) -> Result<(), Box<dyn Error>> {
    let expected = [
        ("attempt_id", "AttemptIdentity", true),
        ("capability", "CapabilityName", true),
        ("payload", "TextProperties", true),
        ("proposed_effect", "OptionalProposedEffect", false),
    ];
    if method.method_id != "execute" || method.input.fields.len() != expected.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native Execute projection schema changed without a generator revision",
        )
        .into());
    }
    for (field, (name, kind, required)) in method.input.fields.iter().zip(expected) {
        if field.name != name
            || value_kind_name(&field.value_kind) != kind
            || field.required != required
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native Execute projection schema changed without a generator revision",
            )
            .into());
        }
    }
    Ok(())
}

fn render_projection(
    manifest: &ResourceFacetContract,
    method: &ResourceFacetMethod,
) -> Result<String, Box<dyn Error>> {
    let mut input_fields = String::new();
    let mut validation = String::new();
    for field in &method.input.fields {
        let ty = rust_type(field)?;
        writeln!(
            input_fields,
            "    pub {}: {},",
            field.name,
            ty
        )?;
        write_validation(field, &mut validation)?;
    }

    let input_metadata = render_fields(&method.input.fields)?;
    let output_metadata = render_fields(&method.output.fields)?;
    let mut reserved_methods = String::new();
    for name in &manifest.shape.reserved_method_names {
        writeln!(reserved_methods, "    {},", rust_string(name))?;
    }
    let mut reserved_fields = String::new();
    for name in &manifest.shape.reserved_field_names {
        writeln!(reserved_fields, "    {},", rust_string(name))?;
    }
    let mut projections = String::new();
    for projection in &manifest.shape.contours {
        writeln!(
            projections,
            "    ({}, {}, {}),",
            rust_string(&projection.contour),
            projection.current_projection,
            rust_string(&projection.status)
        )?;
    }

    let method_identity = method.schema_identity(manifest.identity.name.as_str())?;
    let facet_version = manifest.identity.version;
    let compatible_min = manifest.shape.compatible_implementation_minimum;
    let compatible_max = manifest.shape.compatible_implementation_maximum;
    let profile = &method.profile;
    let template = include_str!("src/generated/native_worker_facets_v1.rs.in");
    let replacements = [
        ("@@GENERATOR_VERSION@@", rust_string(GENERATOR_VERSION)),
        ("@@FACET_ID@@", rust_string(manifest.identity.name.as_str())),
        ("@@FACET_VERSION_MAJOR@@", facet_version.major.to_string()),
        ("@@FACET_VERSION_MINOR@@", facet_version.minor.to_string()),
        ("@@FACET_VERSION_PATCH@@", facet_version.patch.to_string()),
        ("@@METHOD_ID@@", rust_string(&method.method_id)),
        ("@@METHOD_SCHEMA_NAME@@", rust_string(method_identity.name.as_str())),
        ("@@INPUT_FIELDS@@", input_fields),
        ("@@INPUT_VALIDATION@@", validation),
        ("@@INPUT_METADATA@@", input_metadata),
        ("@@OUTPUT_METADATA@@", output_metadata),
        ("@@MAX_REQUEST_BYTES@@", profile.resources.maximum_request_bytes.to_string()),
        ("@@MAX_RESPONSE_BYTES@@", profile.resources.maximum_response_bytes.to_string()),
        ("@@TIMEOUT_CLASS@@", rust_string(timeout_class(profile.resources.timeout))),
        ("@@CONCURRENCY_CLASS@@", rust_string(concurrency_class(profile.resources.concurrency))),
        ("@@AUTHORITY_CLASS@@", rust_string(authority_class(profile.authority))),
        ("@@EFFECT_CLASS@@", rust_string(effect_class(profile.effect))),
        ("@@OBSERVATION_CLASS@@", rust_string(observation_class(profile.observation))),
        ("@@DISCLOSURE_RULE@@", rust_string(disclosure_rule(profile.disclosure))),
        ("@@IDEMPOTENCY_CLASS@@", rust_string(idempotency_class(profile.idempotency))),
        ("@@SIMULATION_CLASS@@", rust_string(simulation_class(profile.simulation))),
        ("@@COMPENSATION_CLASS@@", rust_string(compensation_class(profile.compensation))),
        ("@@REPLAY_CLASS@@", rust_string(replay_class(profile.replay))),
        ("@@COLLISION_POLICY@@", rust_string(collision_policy(manifest))),
        ("@@REMOVAL_BOUNDARY@@", rust_string(removal_boundary(manifest))),
        ("@@COMPATIBLE_MIN_MAJOR@@", compatible_min.major.to_string()),
        ("@@COMPATIBLE_MIN_MINOR@@", compatible_min.minor.to_string()),
        ("@@COMPATIBLE_MIN_PATCH@@", compatible_min.patch.to_string()),
        ("@@COMPATIBLE_MAX_MAJOR@@", compatible_max.major.to_string()),
        ("@@COMPATIBLE_MAX_MINOR@@", compatible_max.minor.to_string()),
        ("@@COMPATIBLE_MAX_PATCH@@", compatible_max.patch.to_string()),
        ("@@RESERVED_METHODS@@", reserved_methods),
        ("@@RESERVED_FIELDS@@", reserved_fields),
        ("@@CONTOUR_PROJECTIONS@@", projections),
    ];
    let mut generated = template.to_owned();
    for (marker, value) in replacements {
        generated = generated.replace(marker, &value);
    }
    if generated.contains("@@") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native worker facet template contains an unresolved marker",
        )
        .into());
    }
    Ok(generated)
}

fn rust_type(field: &ResourceFacetField) -> Result<&'static str, Box<dyn Error>> {
    match &field.value_kind {
        ResourceFacetValueKind::AttemptIdentity => Ok("AttemptId"),
        ResourceFacetValueKind::CapabilityName => Ok("String"),
        ResourceFacetValueKind::TextProperties { .. } => Ok("BTreeMap<String, String>"),
        ResourceFacetValueKind::OptionalProposedEffect => Ok("Option<ProposedEffect>"),
        ResourceFacetValueKind::Boolean | ResourceFacetValueKind::ResourceReference { .. } => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("output-only schema kind used as Execute input: {}", field.name),
            )
            .into())
        }
    }
}

fn write_validation(
    field: &ResourceFacetField,
    validation: &mut String,
) -> Result<(), Box<dyn Error>> {
    match &field.value_kind {
        ResourceFacetValueKind::AttemptIdentity => Ok(()),
        ResourceFacetValueKind::CapabilityName => {
            writeln!(
                validation,
                "        if self.{}.trim().is_empty() {{ return Err(\"{}\"); }}",
                field.name, field.name
            )?;
            Ok(())
        }
        ResourceFacetValueKind::TextProperties { maximum_entries } => {
            writeln!(
                validation,
                "        if self.{}.len() > {maximum_entries} {{ return Err(\"{}\"); }}",
                field.name, field.name
            )?;
            Ok(())
        }
        ResourceFacetValueKind::OptionalProposedEffect => {
            writeln!(
                validation,
                "        if self.{}.as_ref().is_some_and(|effect| effect.attempt_id != self.attempt_id) {{ return Err(\"effect_attempt\"); }}",
                field.name
            )?;
            Ok(())
        }
        ResourceFacetValueKind::Boolean | ResourceFacetValueKind::ResourceReference { .. } => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("output-only validator used for input: {}", field.name),
            )
            .into())
        }
    }
}

fn render_fields(fields: &[ResourceFacetField]) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    for field in fields {
        writeln!(
            output,
            "    GeneratedFacetFieldV1 {{ name: {}, value_kind: {}, required: {} }},",
            rust_string(&field.name),
            rust_string(value_kind_name(&field.value_kind)),
            field.required
        )?;
    }
    Ok(output)
}

fn value_kind_name(kind: &ResourceFacetValueKind) -> &'static str {
    match kind {
        ResourceFacetValueKind::AttemptIdentity => "AttemptIdentity",
        ResourceFacetValueKind::CapabilityName => "CapabilityName",
        ResourceFacetValueKind::TextProperties { .. } => "TextProperties",
        ResourceFacetValueKind::OptionalProposedEffect => "OptionalProposedEffect",
        ResourceFacetValueKind::Boolean => "Boolean",
        ResourceFacetValueKind::ResourceReference { .. } => "ResourceReference",
    }
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn timeout_class(class: FacetTimeoutClass) -> &'static str {
    match class {
        FacetTimeoutClass::RequestDeadlineAndBindingExpiry => "request_deadline_and_binding_expiry",
    }
}

fn concurrency_class(class: FacetConcurrencyClass) -> &'static str {
    match class {
        FacetConcurrencyClass::TransportAdmissionBounded => "transport_admission_bounded",
    }
}

fn authority_class(class: eliot_contracts::FacetAuthorityClass) -> &'static str {
    match class {
        eliot_contracts::FacetAuthorityClass::IntroducedResourceAndMethod => {
            "introduced_resource_and_method"
        }
    }
}

fn effect_class(class: FacetEffectClass) -> &'static str {
    match class {
        FacetEffectClass::CandidateOnlyAfterAdmission => "candidate_only_after_admission",
    }
}

fn observation_class(class: FacetObservationClass) -> &'static str {
    match class {
        FacetObservationClass::DurableObservation => "durable_observation",
    }
}

fn disclosure_rule(class: FacetDisclosureRule) -> &'static str {
    match class {
        FacetDisclosureRule::NoWiderThanIntroducedResource => {
            "no_wider_than_introduced_resource"
        }
    }
}

fn idempotency_class(class: FacetIdempotencyClass) -> &'static str {
    match class {
        FacetIdempotencyClass::RequestAndAttempt => "request_and_attempt",
    }
}

fn simulation_class(class: FacetSimulationClass) -> &'static str {
    match class {
        FacetSimulationClass::ObserveWithoutExternalEffects => {
            "observe_without_external_effects"
        }
    }
}

fn compensation_class(class: FacetCompensationClass) -> &'static str {
    match class {
        FacetCompensationClass::CandidateDiscardBeforeCommit => {
            "candidate_discard_before_commit"
        }
    }
}

fn replay_class(class: FacetReplayClass) -> &'static str {
    match class {
        FacetReplayClass::ExactRequestAndSchema => "exact_request_and_schema",
    }
}

fn collision_policy(manifest: &ResourceFacetContract) -> &'static str {
    match manifest.shape.collision_policy {
        eliot_contracts::FacetCollisionPolicy::RejectDuplicateReservedAndCaseFolded => {
            "reject_duplicate_reserved_and_case_folded"
        }
    }
}

fn removal_boundary(manifest: &ResourceFacetContract) -> &'static str {
    match manifest.shape.removal_boundary {
        eliot_contracts::FacetRemovalBoundary::NewVersionAndOwnerMigration => {
            "new_version_and_owner_migration"
        }
    }
}
