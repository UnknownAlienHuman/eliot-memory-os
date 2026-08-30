$ErrorActionPreference = 'Stop'

$path = 'crates/agent/eliot-agent-opencode/src/catalogue.rs'
$source = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")

$source = $source.Replace('"context": 200000', '"context": 200_000')
$source = $source.Replace('"output": 32000', '"output": 32_000')

$modelFixturePattern = '(?s)    fn metadata\(value: Value\) -> UnknownFields \{.*?^    \}\n\n    fn model\(id: &str, metadata_value: Value\) -> ProviderModel \{.*?^    \}\n'
$modelFixtureReplacement = @'
    fn model(id: &str, metadata_value: Value) -> ProviderModel {
        let extra = match metadata_value {
            Value::Object(object) => object.into_iter().collect(),
            _ => BTreeMap::new(),
        };
        ProviderModel {
            id: Some(id.to_owned()),
            name: Some(id.to_owned()),
            context_limit: None,
            output_limit: None,
            extra,
        }
    }
'@.Replace("`r`n", "`n")
$updated = [Text.RegularExpressions.Regex]::Replace(
    $source,
    $modelFixturePattern,
    $modelFixtureReplacement,
    [Text.RegularExpressions.RegexOptions]::Multiline
)
if ($updated -eq $source) {
    throw 'SOURCE_PATCH_FAILED: model fixture'
}
$source = $updated

$compilePattern = '(?s)pub fn compile_opencode_model_catalogue\(.*?^\}\n\n(?=impl OpenCodeClient)'
$compileReplacement = @'
enum ModelCompilation {
    Entry(ModelCatalogueEntry),
    Omitted(OpenCodeCatalogueOmissionReason),
}

fn ordered_models(
    models: &BTreeMap<String, ProviderModel>,
) -> Vec<(&String, &ProviderModel)> {
    let mut ordered = models.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    ordered
}

fn provider_omissions(
    provider_id: &str,
    models: &BTreeMap<String, ProviderModel>,
    reason: OpenCodeCatalogueOmissionReason,
) -> Vec<OpenCodeCatalogueOmission> {
    ordered_models(models)
        .into_iter()
        .map(|(model_key, _)| OpenCodeCatalogueOmission {
            provider_id: provider_id.to_owned(),
            model_key: model_key.clone(),
            reason,
        })
        .collect()
}

fn compile_model_entry(
    health: &HealthResponse,
    context: &OpenCodeCatalogueContext,
    provider_id: &str,
    model_key: &str,
    model: &ProviderModel,
    policy: &OpenCodeProviderRoutePolicy,
) -> Result<ModelCompilation, OpenCodeCatalogueError> {
    let Some(model_id) = resolved_model_id(model_key, model) else {
        return Ok(ModelCompilation::Omitted(
            OpenCodeCatalogueOmissionReason::ConflictingModelIdentity,
        ));
    };
    let Ok(metadata) = routing_metadata(model) else {
        return Ok(ModelCompilation::Omitted(
            OpenCodeCatalogueOmissionReason::InvalidModelMetadata,
        ));
    };
    let context_window = metadata
        .limit
        .as_ref()
        .and_then(|limit| limit.context)
        .or(model.context_limit)
        .filter(|value| *value > 0);
    let Some(context_window) = context_window else {
        return Ok(ModelCompilation::Omitted(
            OpenCodeCatalogueOmissionReason::MissingContextWindow,
        ));
    };
    let observed_health = route_health(health, policy.route_health);
    let billing = BillingEvidence {
        class: billing_class(policy.billing_mode(&model_id), &metadata),
        source: policy.billing_source.clone(),
        receipt_ref: policy.billing_receipt_ref.clone(),
        observed_at_unix_ms: context.observed_at_unix_ms,
        expires_at_unix_ms: context.expires_at_unix_ms,
    };
    let capabilities = BTreeMap::from([
        (
            "attachment".to_owned(),
            capability(metadata.attachment, &context.catalogue_receipt_ref),
        ),
        (
            "reasoning".to_owned(),
            capability(metadata.reasoning, &context.catalogue_receipt_ref),
        ),
        (
            "structured_output".to_owned(),
            capability(metadata.structured_output, &context.catalogue_receipt_ref),
        ),
        (
            "tool_call".to_owned(),
            capability(metadata.tool_call, &context.catalogue_receipt_ref),
        ),
    ]);
    let evidence_refs = evidence_refs(vec![
        context.evidence_refs.clone(),
        policy.evidence_refs.clone(),
        vec![
            context.health_receipt_ref.clone(),
            context.catalogue_receipt_ref.clone(),
            policy.billing_receipt_ref.clone(),
            policy.quota.receipt_ref.clone(),
        ],
    ])?;
    let family = metadata
        .family
        .filter(|family| !family.trim().is_empty())
        .unwrap_or_else(|| model_id.clone());
    Ok(ModelCompilation::Entry(ModelCatalogueEntry {
        entry_id: format!("opencode:{provider_id}:{model_id}"),
        account_scope: context.account_scope.clone(),
        host_family: OPENCODE_HOST_FAMILY.to_owned(),
        provider_id: provider_id.to_owned(),
        model_id: model_id.clone(),
        model_family: family,
        route: policy.route.route(provider_id, &model_id),
        route_admission: policy.route_admission,
        route_health: observed_health,
        availability: availability(observed_health),
        billing,
        quota: policy.quota.clone(),
        context_window,
        cost_class: policy.cost_class,
        latency_class: policy.latency_class,
        capabilities,
        role_eligibility: policy.role_eligibility.clone(),
        evidence_refs,
    }))
}

fn compile_provider_entries(
    health: &HealthResponse,
    context: &OpenCodeCatalogueContext,
    provider_id: &str,
    models: &BTreeMap<String, ProviderModel>,
    policy: &OpenCodeProviderRoutePolicy,
) -> Result<
    (Vec<ModelCatalogueEntry>, Vec<OpenCodeCatalogueOmission>),
    OpenCodeCatalogueError,
> {
    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    for (model_key, model) in ordered_models(models) {
        match compile_model_entry(health, context, provider_id, model_key, model, policy)? {
            ModelCompilation::Entry(entry) => entries.push(entry),
            ModelCompilation::Omitted(reason) => omissions.push(OpenCodeCatalogueOmission {
                provider_id: provider_id.to_owned(),
                model_key: model_key.clone(),
                reason,
            }),
        }
    }
    Ok((entries, omissions))
}

fn sort_collection(
    entries: &mut [ModelCatalogueEntry],
    omissions: &mut [OpenCodeCatalogueOmission],
) {
    entries.sort_by(|left, right| {
        (
            left.provider_id.as_str(),
            left.model_id.as_str(),
            left.entry_id.as_str(),
        )
            .cmp(&(
                right.provider_id.as_str(),
                right.model_id.as_str(),
                right.entry_id.as_str(),
            ))
    });
    omissions.sort_by(|left, right| {
        (
            left.provider_id.as_str(),
            left.model_key.as_str(),
            left.reason,
        )
            .cmp(&(
                right.provider_id.as_str(),
                right.model_key.as_str(),
                right.reason,
            ))
    });
}

pub fn compile_opencode_model_catalogue(
    health: &HealthResponse,
    providers: &ProviderCatalog,
    context: &OpenCodeCatalogueContext,
) -> Result<OpenCodeCatalogueCollection, OpenCodeCatalogueError> {
    context.validate()?;
    text(&health.version, "health.version")?;
    let connected = providers
        .connected
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    let mut ordered_providers = providers.all.iter().collect::<Vec<_>>();
    ordered_providers.sort_by(|left, right| left.id.cmp(&right.id));

    for provider in ordered_providers {
        text(&provider.id, "provider.id")?;
        let is_connected = connected.contains(provider.id.as_str())
            || provider.connected.is_some_and(|value| value);
        if !is_connected {
            omissions.extend(provider_omissions(
                &provider.id,
                &provider.models,
                OpenCodeCatalogueOmissionReason::ProviderDisconnected,
            ));
            continue;
        }
        let Some(policy) = context.provider_policies.get(&provider.id) else {
            omissions.extend(provider_omissions(
                &provider.id,
                &provider.models,
                OpenCodeCatalogueOmissionReason::MissingProviderPolicy,
            ));
            continue;
        };
        let (provider_entries, provider_omissions) = compile_provider_entries(
            health,
            context,
            &provider.id,
            &provider.models,
            policy,
        )?;
        entries.extend(provider_entries);
        omissions.extend(provider_omissions);
    }

    sort_collection(&mut entries, &mut omissions);
    let snapshot = ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: context.snapshot_id.clone(),
        account_scope: context.account_scope.clone(),
        collector_identity: context.collector_identity.clone(),
        observed_at_unix_ms: context.observed_at_unix_ms,
        expires_at_unix_ms: context.expires_at_unix_ms,
        entries,
    };
    snapshot.validate()?;
    Ok(OpenCodeCatalogueCollection {
        schema_version: OPENCODE_CATALOGUE_COLLECTION_VERSION.to_owned(),
        snapshot,
        omissions,
        execution: ZeroModelExecutionCounters::zero(),
    })
}

'@.Replace("`r`n", "`n")
$updated = [Text.RegularExpressions.Regex]::Replace(
    $source,
    $compilePattern,
    $compileReplacement,
    [Text.RegularExpressions.RegexOptions]::Multiline
)
if ($updated -eq $source) {
    throw 'SOURCE_PATCH_FAILED: collector refactor'
}

[IO.File]::WriteAllText($path, $updated, [Text.UTF8Encoding]::new($false))
