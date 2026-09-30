use std::{env, error::Error, fmt::Write as _, fs, io, path::PathBuf};

use eliot_contracts::{
    ResourceFacetContract, ResourceFacetField, ResourceFacetMethod, ResourceFacetValueKind,
    native_worker_resource_facet_v1,
};

const GENERATOR_VERSION: &str = "eliot-native-resource-facet-stubgen/2";

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
    println!("cargo:rerun-if-changed=../../foundation/eliot-contracts/src/facet_manifest.rs");
    println!("cargo:rerun-if-changed=../../foundation/eliot-contracts/src/lib.rs");
    println!("cargo:rerun-if-changed=../../foundation/eliot-protocol/src/lib.rs");
    println!("cargo:rerun-if-env-changed=ELIOT_REGENERATE_NATIVE_WORKER_FACETS");
    println!("cargo:rustc-env=ELIOT_NATIVE_WORKER_RESOURCE_FACET_REF={canonical_ref}");

    // The checked-in template may use CRLF on Windows, while inserted fields
    // use LF. Keep the generated source stable across checkout conventions.
    let generated = render_projection(&manifest, method)?.replace("\r\n", "\n");
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest dir"))?,
    );
    let checked_in_path = manifest_dir.join("src/generated/native_worker_facets_v1.rs");
    if matches!(
        env::var("ELIOT_REGENERATE_NATIVE_WORKER_FACETS").as_deref(),
        Ok("1")
    ) {
        fs::write(&checked_in_path, &generated)?;
    } else {
        let checked_in = fs::read_to_string(&checked_in_path)?;
        // Git may check out tracked Rust source with CRLF on Windows. Compare
        // the source text, not its checkout line-ending convention.
        if checked_in.replace("\r\n", "\n") != generated {
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
        env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "build output directory"))?,
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
        writeln!(input_fields, "    pub {}: {},", field.name, ty)?;
        write_validation(field, &mut validation)?;
    }

    let method_identity = method.schema_identity(manifest.identity.name.as_str())?;
    let facet_version = manifest.identity.version;
    let template = include_str!("src/generated/native_worker_facets_v1.rs.in");
    let replacements = [
        ("@@GENERATOR_VERSION@@", rust_string(GENERATOR_VERSION)),
        ("@@FACET_ID@@", rust_string(manifest.identity.name.as_str())),
        ("@@FACET_VERSION_MAJOR@@", facet_version.major.to_string()),
        ("@@FACET_VERSION_MINOR@@", facet_version.minor.to_string()),
        ("@@FACET_VERSION_PATCH@@", facet_version.patch.to_string()),
        ("@@METHOD_ID@@", rust_string(&method.method_id)),
        (
            "@@METHOD_SCHEMA_NAME@@",
            rust_string(method_identity.name.as_str()),
        ),
        ("@@INPUT_FIELDS@@", input_fields),
        ("@@INPUT_VALIDATION@@", validation),
        (
            "@@MAX_REQUEST_BYTES@@",
            rust_integer_literal(method.profile.resources.maximum_request_bytes),
        ),
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

fn rust_integer_literal(value: usize) -> String {
    let digits = value.to_string();
    let mut literal = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            literal.push('_');
        }
        literal.push(digit);
    }
    literal
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
                format!(
                    "output-only schema kind used as Execute input: {}",
                    field.name
                ),
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
