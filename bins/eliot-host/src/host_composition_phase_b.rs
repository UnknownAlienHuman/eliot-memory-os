use super::*;

impl HostComposition {
    /// Materializes the Host-owned Phase-B authority, Store bootstrap, and
    /// dynamic launch descriptors for one already-approved generation.
    ///
    /// Phase A contributes only immutable templates. This method requires the
    /// live Host epoch opened by [`Self::open`], accepts authority bytes from
    /// the external ORS handoff producer, publishes each destination through
    /// the protected atomic path, and classifies every unknown publication by
    /// exact readback. No authority bytes or OS destination identity are
    /// synthesized or added to the immutable candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate, live Host epoch, external ORS
    /// handoff, protected destinations, or exact post-publication readback do
    /// not match the approved contour.
    ///
    /// `durable_prior_binding` is required for an `ActiveVerified` rebind.  Any
    /// destination marker is treated only as physical continuity evidence and
    /// is accepted there after exact comparison with the committed registry
    /// binding; it never establishes prior ownership.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "Phase-B materialization keeps the ordered authority/config/bootstrap publication and receipt binding auditable"
    )]
    #[cfg(windows)]
    pub fn materialize_phase_b(
        &mut self,
        manifest: &CandidateManifest,
        input: &HostPhaseBInput,
        durable_prior_binding: Option<&PhaseBLiveBinding>,
    ) -> Result<HostPhaseBMaterialization, HostError> {
        self.ensure_admission_open()?;
        manifest
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        if !self
            .registry
            .generations()
            .iter()
            .any(|generation| generation.manifest == *manifest)
        {
            return Err(HostError::RecoveryRequired(
                "Phase-B materialization target is not the exact approved registry manifest"
                    .to_owned(),
            ));
        }
        Self::validate_launch_options_for_manifest(&self.launch_options, manifest)?;
        let launch_template = &manifest.runtime_launch;
        let provisioned_supervision_authority =
            if let Some(pending) = self.registry.pending_activation() {
                pending
                    .phase_b_intent
                    .as_ref()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "pending Phase-B activation has no supervision authority receipt"
                                .to_owned(),
                        )
                    })?
                    .provisioned_supervision_authority
                    .clone()
            } else {
                durable_prior_binding
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "active Phase-B rebind requires the committed supervision authority"
                                .to_owned(),
                        )
                    })?
                    .provisioned_supervision_authority
                    .clone()
            };
        provisioned_supervision_authority
            .validate()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if provisioned_supervision_authority.candidate_generation != manifest.generation.as_str()
            || provisioned_supervision_authority.authority_generation
                != launch_template.authority_generation
            || provisioned_supervision_authority
                .trust_anchor
                .installation_id
                != launch_template.installation_epoch.installation.as_str()
            || provisioned_supervision_authority.supervision_lease_scope_id
                != launch_template.supervision_lease_scope_id()
        {
            return Err(HostError::RecoveryRequired(
                "supervision authority is foreign to the approved Phase-A launch".to_owned(),
            ));
        }
        let portable_root = if launch_template.profile == InstallationProfile::PortableDev {
            Some(
                UserOwnedRootLease::open_existing(Path::new(
                    launch_template
                        .portable_root
                        .as_ref()
                        .ok_or_else(|| {
                            HostError::RecoveryRequired(
                                "Phase-B portable root binding is missing".to_owned(),
                            )
                        })?
                        .as_str(),
                ))
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
            )
        } else {
            None
        };
        let profile = launch_template.profile;
        let authority_path = approved_phase_b_destination_locator(
            Path::new(launch_template.authority_descriptor_path.as_str()),
            &launch_template.authority_descriptor_path,
            profile,
            portable_root.as_ref(),
        )?;
        let observed_previous_binding = phase_b_observe_previous_binding(
            manifest,
            &self.host,
            &self.activation_generation.current,
            portable_root.as_ref(),
            &authority_path,
        )?;
        let durable_manifest_digest = phase_b_manifest_digest(manifest)?;
        let previous_binding = if let Some(durable) = durable_prior_binding {
            if durable.manifest_digest != durable_manifest_digest {
                return Err(HostError::RecoveryRequired(
                    "durable committed Phase-B binding is not bound to the exact manifest"
                        .to_owned(),
                ));
            }
            match observed_previous_binding {
                Some(observed) => {
                    phase_b_validate_durable_previous_binding(&observed, durable)?;
                    Some(observed)
                }
                None => None,
            }
        } else {
            observed_previous_binding
        };
        let allow_expired_exact_replay = match std::fs::symlink_metadata(&authority_path) {
            Ok(_) => {
                let lease =
                    phase_b_open_existing(profile, portable_root.as_ref(), &authority_path)?;
                lease.verify().map_err(HostError::RecoveryRequired)?;
                phase_b_lease_bytes(&lease)? == input.authority_descriptor_bytes
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B authority destination cannot be observed: {error}"
                )));
            }
        };
        let (authority, manifest_digest, authority_descriptor_digest) = phase_b_validate_authority(
            manifest,
            &self.host,
            &self.activation_generation.current,
            &input.authority_descriptor_bytes,
            allow_expired_exact_replay,
        )?;
        let previous_authority_digests = previous_binding
            .as_ref()
            .map(|binding| vec![&binding.authority_digest])
            .unwrap_or_default();
        let authority_physical_digest = phase_b_bytes_digest(&input.authority_descriptor_bytes)?;
        if authority_physical_digest != authority_descriptor_digest {
            return Err(HostError::RecoveryRequired(
                "Phase-B authority descriptor digest changed before publication".to_owned(),
            ));
        }

        let config_path = approved_locator(
            Path::new(manifest.config_path.as_str()),
            &manifest.config_path,
            profile,
        )?;
        let config_template_bytes = phase_b_template_bytes(
            profile,
            portable_root.as_ref(),
            &config_path,
            &manifest.config_digest,
            "Store config",
        )?;
        let mut config = serde_json::from_slice::<serde_json::Value>(&config_template_bytes)
            .map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Phase-B Store config template is not valid JSON: {error}"
                ))
            })?;
        let template_launch_value = config.get("runtime_launch").cloned().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Phase-B Store config template has no runtime_launch".to_owned(),
            )
        })?;
        let template_launch: RuntimeLaunchDescriptor =
            serde_json::from_value(template_launch_value).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Phase-B Store config runtime_launch is invalid: {error}"
                ))
            })?;
        if template_launch != *launch_template {
            return Err(HostError::RecoveryRequired(
                "Phase-B Store config template is not the exact approved launch descriptor"
                    .to_owned(),
            ));
        }
        let eliotd_descriptor_path = approved_locator(
            Path::new(launch_template.eliotd_descriptor_path.as_str()),
            &launch_template.eliotd_descriptor_path,
            profile,
        )?;
        let eliotd_template_bytes = phase_b_template_bytes(
            profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
            &launch_template.eliotd_descriptor_digest,
            "eliotd descriptor",
        )?;
        validate_eliotd_launch_descriptor_bytes(
            &eliotd_template_bytes,
            &launch_template.eliotd_descriptor_digest,
            launch_template,
        )?;
        let mut eliotd_descriptor: EliotdLaunchDescriptor =
            serde_json::from_slice(&eliotd_template_bytes).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Phase-B eliotd descriptor is not parseable: {error}"
                ))
            })?;
        let live_launch_template = phase_b_live_launch(
            launch_template,
            &self.host,
            &authority,
            &authority_descriptor_digest,
            &launch_template.eliotd_descriptor_digest,
            &provisioned_supervision_authority,
        )?;
        eliotd_descriptor.authority_epoch =
            live_launch_template.authority_state_fence.authority_epoch;
        eliotd_descriptor.generation = live_launch_template.authority_generation;
        let eliotd_live_bytes = serde_json::to_vec(
            &eliotd_descriptor
                .with_computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        )
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let previous_eliotd_digest = phase_b_previous_eliotd_digest(
            profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
            &eliotd_live_bytes,
            &launch_template.eliotd_descriptor_digest,
            &eliotd_template_bytes,
            previous_binding.as_ref(),
        )?;
        if let Some(durable) = durable_prior_binding
            && previous_eliotd_digest
                .as_ref()
                .is_some_and(|observed| observed != &durable.eliotd_descriptor_digest)
        {
            return Err(HostError::RecoveryRequired(
                "prior eliotd digest does not match the durable committed Phase-B binding"
                    .to_owned(),
            ));
        }
        let mut eliotd_allowed_digests = vec![&launch_template.eliotd_descriptor_digest];
        if let Some(digest) = previous_eliotd_digest.as_ref() {
            eliotd_allowed_digests.push(digest);
        }
        let eliotd_descriptor_digest = phase_b_bytes_digest(&eliotd_live_bytes)?;
        let live_launch_template = phase_b_live_launch(
            launch_template,
            &self.host,
            &authority,
            &authority_descriptor_digest,
            &eliotd_descriptor_digest,
            &provisioned_supervision_authority,
        )?;

        {
            let config_object = config.as_object_mut().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B Store config root must be an object".to_owned(),
                )
            })?;
            config_object.insert(
                "launch_nonce".to_owned(),
                serde_json::Value::String(
                    self.host
                        .host_process_nonce()
                        .as_handle()
                        .as_str()
                        .to_owned(),
                ),
            );
            config_object.insert(
                "runtime_launch".to_owned(),
                serde_json::to_value(&live_launch_template)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            );
            config_object.insert(
                "approved_config_hash".to_owned(),
                serde_json::Value::String(STORE_SEMANTIC_CONFIG_HASH_PENDING.to_owned()),
            );
        }
        let config_without_semantic_hash = serde_json::to_vec(&config)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let semantic_config_hash =
            semantic_store_config_hash_from_json(&config_without_semantic_hash)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        {
            let config_object = config.as_object_mut().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B Store config root must be an object".to_owned(),
                )
            })?;
            config_object.insert(
                "approved_config_hash".to_owned(),
                serde_json::Value::String(semantic_config_hash.as_str().to_owned()),
            );
        }
        let config_live_bytes = serde_json::to_vec(&config)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let previous_config_digest = phase_b_previous_config_digest(
            profile,
            portable_root.as_ref(),
            &config_path,
            &config_live_bytes,
            &manifest.config_digest,
            &config_template_bytes,
            launch_template,
            previous_binding.as_ref(),
            previous_eliotd_digest.as_ref(),
            &provisioned_supervision_authority,
        )?;
        if let Some(durable) = durable_prior_binding
            && previous_config_digest
                .as_ref()
                .is_some_and(|observed| observed != &durable.config_file_digest)
        {
            return Err(HostError::RecoveryRequired(
                "prior Store config digest does not match the durable committed Phase-B binding"
                    .to_owned(),
            ));
        }
        let mut config_allowed_digests = vec![&manifest.config_digest];
        if let Some(digest) = previous_config_digest.as_ref() {
            config_allowed_digests.push(digest);
        }
        let config_file_digest = phase_b_bytes_digest(&config_live_bytes)?;
        if config_file_digest == semantic_config_hash {
            return Err(HostError::RecoveryRequired(
                "physical Store config digest unexpectedly equals semantic digest".to_owned(),
            ));
        }

        let store_pipe = phase_b_json_string(&config, "store_pipe")?;
        let expected_peer_sid = phase_b_json_string(&config, "expected_client_sid")?;
        let instance_id = phase_b_json_string(&config, "instance_id")?;
        let connect_timeout_ms = phase_b_json_u64(&config, "connect_timeout_ms")?;
        let expected_client_session_id = config
            .get("expected_client_session_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Store config field expected_client_session_id is missing".to_owned(),
                )
            })?;
        let expected_client_session_id =
            u32::try_from(expected_client_session_id).map_err(|_| {
                HostError::RecoveryRequired(
                    "Store config expected_client_session_id is out of range".to_owned(),
                )
            })?;
        let launch_nonce = self.host.host_process_nonce().as_handle().clone();
        let connection_id = PlatformHandle::new(format!(
            "kernel-store:{}:{}",
            instance_id,
            launch_nonce.as_str()
        ))
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let requirement = HostStoreBootstrapRequirement {
            route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)
                .map_err(|error| HostError::Platform(error.to_string()))?,
            canonical_pipe_identity: PlatformHandle::new(store_pipe)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            store_generation: live_launch_template.authority_generation,
            state_fence: live_launch_template.authority_state_fence.clone(),
            launch_nonce,
            connection_id,
            expected_peer_sid: PlatformHandle::new(expected_peer_sid)
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            expected_peer_session_id: expected_client_session_id,
            approved_artifact_hash: live_launch_template.store_bridge_artifact_digest.clone(),
            approved_config_hash: semantic_config_hash.clone(),
            timeout_ms: connect_timeout_ms,
        };
        requirement
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let bootstrap_bytes = serde_json::to_vec(&requirement)
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let bootstrap_path = approved_phase_b_destination_locator(
            Path::new(launch_template.store_bootstrap_descriptor_path.as_str()),
            &launch_template.store_bootstrap_descriptor_path,
            profile,
            portable_root.as_ref(),
        )?;
        let previous_config_value = previous_binding
            .as_ref()
            .map(|previous| {
                phase_b_previous_config_value(
                    &config_template_bytes,
                    launch_template,
                    previous,
                    previous_eliotd_digest.as_ref(),
                    &provisioned_supervision_authority,
                )
            })
            .transpose()?;
        let previous_live_launch = previous_binding
            .as_ref()
            .map(|previous| {
                phase_b_previous_live_launch(
                    launch_template,
                    previous,
                    previous_eliotd_digest.as_ref(),
                    &provisioned_supervision_authority,
                )
            })
            .transpose()?;
        let previous_launch_nonce = previous_binding.as_ref().map_or_else(
            || self.host.host_process_nonce().as_handle().clone(),
            |previous| previous.host.nonce.clone(),
        );
        let previous_bootstrap_digest = phase_b_previous_bootstrap_digest(
            profile,
            portable_root.as_ref(),
            &bootstrap_path,
            &bootstrap_bytes,
            previous_config_value.as_ref().unwrap_or(&config),
            previous_live_launch
                .as_ref()
                .unwrap_or(&live_launch_template),
            &previous_launch_nonce,
            previous_binding.as_ref(),
        )?;
        if let Some(durable) = durable_prior_binding
            && previous_bootstrap_digest
                .as_ref()
                .is_some_and(|observed| observed != &durable.store_bootstrap_descriptor_digest)
        {
            return Err(HostError::RecoveryRequired(
                "prior Store bootstrap digest does not match the durable committed Phase-B binding"
                    .to_owned(),
            ));
        }
        let mut bootstrap_allowed_digests = Vec::new();
        if let Some(digest) = previous_bootstrap_digest.as_ref() {
            bootstrap_allowed_digests.push(digest);
        }
        let store_bootstrap_descriptor_digest = phase_b_bytes_digest(&bootstrap_bytes)?;
        let launch = live_launch_template
            .with_phase_b_materialization(
                authority.generation,
                authority.state_fence.clone(),
                authority_descriptor_digest.clone(),
                store_bootstrap_descriptor_digest.clone(),
                eliotd_descriptor_digest.clone(),
            )
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let pending = self.registry.pending_activation().cloned();
        let active_rebind = self.registry.active_phase_b_rebind().cloned();
        let prepared = if let Some(pending) = pending.as_ref() {
            let intent = pending.phase_b_intent.as_ref().ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B publication requires the durable transaction intent".to_owned(),
                )
            })?;
            if pending.manifest_digest != manifest_digest {
                return Err(HostError::RecoveryRequired(
                    "Phase-B preparation manifest is not the exact pending manifest".to_owned(),
                ));
            }
            let mut prepared = HostPhaseBPreparedMaterialization {
                wire: PlatformHandle::new(HostPhaseBPreparedMaterialization::WIRE)
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                transaction_id: intent.transaction_id.clone(),
                effect_id: intent.effect_id.clone(),
                credential_effect_id: intent.credential_effect_id.clone(),
                manifest_digest: manifest_digest.clone(),
                request_digest: intent.request_digest.clone(),
                credential_receipt_digest: intent.credential_receipt_digest.clone(),
                host_owner_epoch: host_owner_epoch_digest(&self.host)?,
                host_process_identity: host_process_identity_digest_for_host(&self.host)?,
                host_process_nonce_digest: phase_b_bytes_digest(
                    self.host
                        .host_process_nonce()
                        .as_handle()
                        .as_str()
                        .as_bytes(),
                )?,
                host_epoch_lineage: self.host.epoch.current.lineage.clone(),
                host_epoch_sequence: self.host.epoch.current.sequence,
                activation_generation_lineage: self.activation_generation.current.lineage.clone(),
                activation_generation_sequence: self.activation_generation.current.sequence,
                authority_descriptor_digest: authority_descriptor_digest.clone(),
                config_file_digest: config_file_digest.clone(),
                store_bootstrap_descriptor_digest: store_bootstrap_descriptor_digest.clone(),
                eliotd_descriptor_digest: eliotd_descriptor_digest.clone(),
                semantic_config_hash: semantic_config_hash.clone(),
                launch: launch.clone(),
                prepared_digest: PlatformHandle::new("pending")
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            };
            prepared.prepared_digest = prepared
                .computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            prepared.validate().map_err(HostError::Installation)?;
            let host_capability = self.owner_lease.activation_capability();
            self.persist_pending_phase_b_prepared(pending, &prepared, &host_capability)?;
            Some(prepared)
        } else if let Some(rebind) = active_rebind.as_ref() {
            if rebind.intent.manifest_digest != manifest_digest {
                return Err(HostError::RecoveryRequired(
                    "Active Phase-B rebind preparation is not bound to the exact manifest"
                        .to_owned(),
                ));
            }
            let mut prepared = HostPhaseBPreparedMaterialization {
                wire: PlatformHandle::new(HostPhaseBPreparedMaterialization::WIRE)
                    .map_err(|error| HostError::Platform(error.to_string()))?,
                transaction_id: rebind.intent.transaction_id.clone(),
                effect_id: rebind.intent.effect_id.clone(),
                // Rebind does not mutate the credential.  This stable
                // operation-scoped marker keeps the existing prepared wire
                // explicit without making the old credential operation owner.
                credential_effect_id: rebind.intent.effect_id.clone(),
                manifest_digest: manifest_digest.clone(),
                request_digest: rebind.intent.request_digest.clone(),
                credential_receipt_digest: rebind.intent.prior_phase_b_receipt_digest.clone(),
                host_owner_epoch: host_owner_epoch_digest(&self.host)?,
                host_process_identity: host_process_identity_digest_for_host(&self.host)?,
                host_process_nonce_digest: phase_b_bytes_digest(
                    self.host
                        .host_process_nonce()
                        .as_handle()
                        .as_str()
                        .as_bytes(),
                )?,
                host_epoch_lineage: self.host.epoch.current.lineage.clone(),
                host_epoch_sequence: self.host.epoch.current.sequence,
                activation_generation_lineage: self.activation_generation.current.lineage.clone(),
                activation_generation_sequence: self.activation_generation.current.sequence,
                authority_descriptor_digest: authority_descriptor_digest.clone(),
                config_file_digest: config_file_digest.clone(),
                store_bootstrap_descriptor_digest: store_bootstrap_descriptor_digest.clone(),
                eliotd_descriptor_digest: eliotd_descriptor_digest.clone(),
                semantic_config_hash: semantic_config_hash.clone(),
                launch: launch.clone(),
                prepared_digest: PlatformHandle::new("pending")
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            };
            prepared.prepared_digest = prepared
                .computed_digest()
                .map_err(|error| HostError::ProcessContour(error.to_string()))?;
            prepared.validate().map_err(HostError::Installation)?;
            let host_capability = self.owner_lease.activation_capability();
            self.persist_active_phase_b_rebind_prepared(&prepared, &host_capability)?;
            Some(prepared)
        } else {
            None
        };
        if prepared.is_none() {
            return Err(HostError::RecoveryRequired(
                "Phase-B four-file publication requires a durable prepared capability".to_owned(),
            ));
        }
        let (authority_readback_digest, authority_identity) =
            phase_b_materialize_file_with_rollback(
                profile,
                portable_root.as_ref(),
                &authority_path,
                &input.authority_descriptor_bytes,
                &previous_authority_digests,
                "authority descriptor",
            )?;
        if authority_readback_digest != authority_descriptor_digest {
            return Err(HostError::RecoveryRequired(
                "Phase-B authority descriptor digest changed during materialization".to_owned(),
            ));
        }
        let (eliotd_readback_digest, eliotd_identity) = phase_b_materialize_file_with_rollback(
            profile,
            portable_root.as_ref(),
            &eliotd_descriptor_path,
            &eliotd_live_bytes,
            &eliotd_allowed_digests,
            "eliotd descriptor",
        )?;
        if eliotd_readback_digest != eliotd_descriptor_digest {
            return Err(HostError::RecoveryRequired(
                "Phase-B eliotd descriptor digest changed during materialization".to_owned(),
            ));
        }
        let (config_readback_digest, config_identity) = phase_b_materialize_file_with_rollback(
            profile,
            portable_root.as_ref(),
            &config_path,
            &config_live_bytes,
            &config_allowed_digests,
            "Store config",
        )?;
        if config_readback_digest != config_file_digest
            || config_readback_digest == semantic_config_hash
        {
            return Err(HostError::RecoveryRequired(
                "physical Store config digest unexpectedly equals semantic digest".to_owned(),
            ));
        }
        let (bootstrap_readback_digest, bootstrap_identity) =
            phase_b_materialize_file_with_rollback(
                profile,
                portable_root.as_ref(),
                &bootstrap_path,
                &bootstrap_bytes,
                &bootstrap_allowed_digests,
                "Store bootstrap descriptor",
            )?;
        if bootstrap_readback_digest != store_bootstrap_descriptor_digest {
            return Err(HostError::RecoveryRequired(
                "Phase-B Store bootstrap digest changed during materialization".to_owned(),
            ));
        }
        if let Some(prepared) = prepared.as_ref()
            && (prepared.authority_descriptor_digest != authority_readback_digest
                || prepared.eliotd_descriptor_digest != eliotd_readback_digest
                || prepared.config_file_digest != config_readback_digest
                || prepared.store_bootstrap_descriptor_digest != bootstrap_readback_digest)
        {
            return Err(HostError::RecoveryRequired(
                "Phase-B destination readback differs from the durable preparation".to_owned(),
            ));
        }
        let receipt = HostPhaseBMaterialization {
            transaction_id: None,
            effect_id: None,
            credential_receipt_digest: None,
            host_owner_epoch: None,
            host_process_identity: None,
            manifest_digest,
            host_epoch: self.host.epoch.current.clone(),
            host_process_nonce: self.host.host_process_nonce().as_handle().clone(),
            activation_generation: self.activation_generation.current.clone(),
            authority_descriptor_digest,
            store_bootstrap_descriptor_digest: bootstrap_readback_digest,
            config_file_digest: config_readback_digest,
            semantic_config_hash,
            eliotd_descriptor_digest: eliotd_readback_digest,
            request_digest: None,
            public_receipt_digest: None,
            file_identities: [
                authority_identity,
                config_identity,
                bootstrap_identity,
                eliotd_identity,
            ],
            launch,
        };
        self.phase_b = Some(receipt.clone());
        Ok(receipt)
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "ActiveVerified Phase-B rebind keeps source-fence validation, durable lifecycle, four-file publication and exact receipt binding together"
    )]
    pub(super) fn rebind_active_phase_b(
        &mut self,
        active: &eliot_installation::ApprovedGeneration,
        recovery_kind: ActivePhaseBRebindRecoveryKind,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let manifest = &active.manifest;
        let manifest_digest = phase_b_manifest_digest(manifest)?;
        if active
            .manifest
            .runtime_launch
            .installation_epoch
            .installation
            != self.host.installation
        {
            return Err(HostError::RecoveryRequired(
                "ActiveVerified rebind candidate belongs to a different installation".to_owned(),
            ));
        }
        let committed = self
            .registry_store
            .read_committed_activation_receipt(
                active.approval.transaction_id(),
                active.approval.installer_plan_digest(),
                &manifest.generation,
            )
            .map_err(HostError::Installation)?;
        let prior_binding = committed
            .commit_fence()
            .phase_b_live_binding
            .clone()
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "ActiveVerified source fence has no committed Phase-B binding".to_owned(),
                )
            })?;
        if prior_binding.manifest_digest != manifest_digest {
            return Err(HostError::RecoveryRequired(
                "ActiveVerified source fence belongs to a different manifest".to_owned(),
            ));
        }
        let host_owner_epoch = host_owner_epoch_digest(&self.host)?;
        let host_process_identity = host_process_identity_digest_for_host(&self.host)?;
        let host_process_nonce_digest = phase_b_bytes_digest(
            self.host
                .host_process_nonce()
                .as_handle()
                .as_str()
                .as_bytes(),
        )?;
        let host_capability = self.owner_lease.activation_capability();
        let completed_rebind = match recovery_kind {
            ActivePhaseBRebindRecoveryKind::CompletedReceipt => {
                let current = self
                    .registry
                    .active_phase_b_rebind()
                    .cloned()
                    .ok_or_else(|| {
                        HostError::RecoveryRequired(
                            "completed Active Phase-B receipt disappeared before recovery CAS"
                                .to_owned(),
                        )
                    })?;
                // The committed activation binding remains source evidence for
                // the new intent. The completed receipt is the only durable
                // proof of the bytes currently present after the crashed
                // attempt, so carry that exact binding into physical
                // continuity validation; destination bytes never authorize
                // themselves.
                let materialization_prior_binding = Self::active_phase_b_rebind_binding(&current)?;
                Some((current, materialization_prior_binding))
            }
            ActivePhaseBRebindRecoveryKind::Prepared => {
                return Err(HostError::RecoveryRequired(
                    "unresolved Active Phase-B preparation is fail-closed; its original owner must complete or roll back it"
                        .to_owned(),
                ));
            }
            ActivePhaseBRebindRecoveryKind::None | ActivePhaseBRebindRecoveryKind::IntentOnly => {
                None
            }
        };
        let effect_id = PlatformHandle::new(format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "eliot.host.phase-b-rebind.v2\0{}\0{}\0{}",
                    committed.terminal_digest(),
                    active.approval.transaction_id(),
                    manifest_digest,
                )
                .as_bytes(),
            )
        ))
        .map_err(|error| HostError::Platform(error.to_string()))?;
        let static_template =
            phase_b_static_template_for_candidate(manifest).map_err(HostError::Installation)?;
        let intent = ActivePhaseBRebindIntent::new(
            active.approval.transaction_id().clone(),
            active.approval.installer_plan_digest().clone(),
            effect_id,
            manifest_digest.clone(),
            committed.terminal_digest().clone(),
            &prior_binding,
            host_owner_epoch,
            host_process_identity,
            host_process_nonce_digest,
            self.host.epoch.current.lineage.clone(),
            self.host.epoch.current.sequence,
            self.activation_generation.current.lineage.clone(),
            self.activation_generation.current.sequence,
            static_template,
        )
        .map_err(HostError::Installation)?;
        let completed_rebind_binding = if let Some((current, binding)) = completed_rebind {
            let recovery = ActivePhaseBRebindRecovery::new(
                &current,
                intent.host_owner_epoch.clone(),
                intent.host_process_identity.clone(),
                intent.host_process_nonce_digest.clone(),
                intent.host_epoch_lineage.clone(),
                intent.host_epoch_sequence,
            )
            .map_err(HostError::Installation)?;
            self.persist_active_phase_b_rebind_recovery_and_intent(
                &recovery,
                &intent,
                &host_capability,
            )?;
            Some(binding)
        } else {
            self.persist_active_phase_b_rebind_intent(&intent, &host_capability)?;
            None
        };

        if let Some(rebind) = self.registry.active_phase_b_rebind().cloned()
            && let (Some(prepared), Some(receipt)) = (rebind.prepared, rebind.receipt)
        {
            let mut materialization = self.rehydrate_phase_b_from_prepared(manifest, &prepared)?;
            receipt
                .validate_against(&intent, &prepared)
                .map_err(HostError::Installation)?;
            materialization.transaction_id = Some(intent.transaction_id.clone());
            materialization.effect_id = Some(intent.effect_id.clone());
            materialization.credential_receipt_digest =
                Some(intent.prior_phase_b_receipt_digest.clone());
            materialization.host_owner_epoch = Some(receipt.host_owner_epoch.clone());
            materialization.host_process_identity = Some(receipt.host_process_identity.clone());
            materialization.request_digest = Some(intent.request_digest.clone());
            materialization.public_receipt_digest = Some(receipt.receipt_digest.clone());
            self.phase_b = Some(materialization);
            return Ok(());
        }

        let authority_descriptor_bytes = phase_b_build_authority_descriptor_for_rebind(
            manifest,
            &self.host,
            &self.activation_generation.current,
            &intent,
            prior_binding.provisioned_supervision_authority(),
        )?;
        let mut materialization = self.materialize_phase_b(
            manifest,
            &HostPhaseBInput {
                authority_descriptor_bytes,
            },
            Some(completed_rebind_binding.as_ref().unwrap_or(&prior_binding)),
        )?;
        materialization.transaction_id = Some(intent.transaction_id.clone());
        materialization.effect_id = Some(intent.effect_id.clone());
        materialization.credential_receipt_digest =
            Some(intent.prior_phase_b_receipt_digest.clone());
        materialization.request_digest = Some(intent.request_digest.clone());
        let rebind = self
            .registry
            .active_phase_b_rebind()
            .cloned()
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Active Phase-B rebind preparation disappeared after publication".to_owned(),
                )
            })?;
        let prepared = rebind.prepared.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Active Phase-B publication completed without durable preparation".to_owned(),
            )
        })?;
        if materialization.manifest_digest != manifest_digest
            || materialization.authority_descriptor_digest != prepared.authority_descriptor_digest
            || materialization.config_file_digest != prepared.config_file_digest
            || materialization.store_bootstrap_descriptor_digest
                != prepared.store_bootstrap_descriptor_digest
            || materialization.eliotd_descriptor_digest != prepared.eliotd_descriptor_digest
            || materialization.launch != prepared.launch
        {
            return Err(HostError::RecoveryRequired(
                "Active Phase-B publication differs from durable preparation".to_owned(),
            ));
        }
        let receipt = ActivePhaseBRebindReceipt::from_prepared(&intent, prepared)
            .map_err(HostError::Installation)?;
        self.persist_active_phase_b_rebind_receipt(&receipt, &host_capability)?;
        materialization.host_owner_epoch = Some(receipt.host_owner_epoch.clone());
        materialization.host_process_identity = Some(receipt.host_process_identity.clone());
        materialization.public_receipt_digest = Some(receipt.receipt_digest.clone());
        self.phase_b = Some(materialization);
        Ok(())
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "prepared Phase-B rehydration keeps exact four-path readback and dynamic binding checks together"
    )]
    pub(super) fn rehydrate_phase_b_from_prepared(
        &self,
        manifest: &CandidateManifest,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<HostPhaseBMaterialization, HostError> {
        prepared.validate().map_err(HostError::Installation)?;
        let manifest_digest = phase_b_manifest_digest(manifest)?;
        if prepared.manifest_digest != manifest_digest
            || prepared.launch.generation != manifest.generation
            || prepared.launch.store_config_path != manifest.config_path
        {
            return Err(HostError::RecoveryRequired(
                "Phase-B prepared record is not bound to the exact candidate manifest".to_owned(),
            ));
        }
        let nonce_digest = phase_b_bytes_digest(
            self.host
                .host_process_nonce()
                .as_handle()
                .as_str()
                .as_bytes(),
        )?;
        if prepared.host_process_nonce_digest != nonce_digest
            || prepared.host_epoch_lineage != self.host.epoch.current.lineage
            || prepared.host_epoch_sequence != self.host.epoch.current.sequence
        {
            return Err(HostError::RecoveryRequired(
                "Phase-B prepared record belongs to a different Host epoch/process contour"
                    .to_owned(),
            ));
        }
        let profile = manifest.runtime_launch.profile;
        let portable_root = if profile == InstallationProfile::PortableDev {
            Some(
                UserOwnedRootLease::open_existing(Path::new(
                    manifest
                        .runtime_launch
                        .portable_root
                        .as_ref()
                        .ok_or_else(|| {
                            HostError::RecoveryRequired(
                                "Phase-B prepared portable root binding is missing".to_owned(),
                            )
                        })?
                        .as_str(),
                ))
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
            )
        } else {
            None
        };
        let readback = |path: &Path,
                        expected: &PlatformHandle,
                        label: &str|
         -> Result<FileIdentity, HostError> {
            let lease = phase_b_open_existing(profile, portable_root.as_ref(), path)?;
            lease.verify().map_err(HostError::RecoveryRequired)?;
            let bytes = phase_b_lease_bytes(&lease)?;
            let actual = phase_b_bytes_digest(&bytes)?;
            if actual != *expected {
                return Err(HostError::RecoveryRequired(format!(
                    "Phase-B prepared {label} readback digest is not exact"
                )));
            }
            Ok(phase_b_lease_identity(&lease))
        };
        let authority_path = approved_locator(
            Path::new(manifest.runtime_launch.authority_descriptor_path.as_str()),
            &manifest.runtime_launch.authority_descriptor_path,
            profile,
        )?;
        let config_path = approved_locator(
            Path::new(manifest.config_path.as_str()),
            &manifest.config_path,
            profile,
        )?;
        let bootstrap_path = approved_locator(
            Path::new(
                manifest
                    .runtime_launch
                    .store_bootstrap_descriptor_path
                    .as_str(),
            ),
            &manifest.runtime_launch.store_bootstrap_descriptor_path,
            profile,
        )?;
        let eliotd_path = approved_locator(
            Path::new(manifest.runtime_launch.eliotd_descriptor_path.as_str()),
            &manifest.runtime_launch.eliotd_descriptor_path,
            profile,
        )?;
        let authority_identity = readback(
            &authority_path,
            &prepared.authority_descriptor_digest,
            "authority descriptor",
        )?;
        let config_identity = readback(&config_path, &prepared.config_file_digest, "Store config")?;
        let bootstrap_identity = readback(
            &bootstrap_path,
            &prepared.store_bootstrap_descriptor_digest,
            "Store bootstrap descriptor",
        )?;
        let eliotd_identity = readback(
            &eliotd_path,
            &prepared.eliotd_descriptor_digest,
            "eliotd descriptor",
        )?;
        Ok(HostPhaseBMaterialization {
            transaction_id: Some(prepared.transaction_id.clone()),
            effect_id: Some(prepared.effect_id.clone()),
            credential_receipt_digest: Some(prepared.credential_receipt_digest.clone()),
            host_owner_epoch: Some(prepared.host_owner_epoch.clone()),
            host_process_identity: Some(prepared.host_process_identity.clone()),
            manifest_digest,
            host_epoch: self.host.epoch.current.clone(),
            host_process_nonce: self.host.host_process_nonce().as_handle().clone(),
            activation_generation: self.activation_generation.current.clone(),
            authority_descriptor_digest: prepared.authority_descriptor_digest.clone(),
            store_bootstrap_descriptor_digest: prepared.store_bootstrap_descriptor_digest.clone(),
            config_file_digest: prepared.config_file_digest.clone(),
            semantic_config_hash: prepared.semantic_config_hash.clone(),
            eliotd_descriptor_digest: prepared.eliotd_descriptor_digest.clone(),
            request_digest: Some(prepared.request_digest.clone()),
            public_receipt_digest: None,
            file_identities: [
                authority_identity,
                config_identity,
                bootstrap_identity,
                eliotd_identity,
            ],
            launch: prepared.launch.clone(),
        })
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "uncommitted Phase-B rollback keeps all four destination restores and CAS cleanup together"
    )]
    pub(super) fn rollback_uncommitted_phase_b(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<(), HostError> {
        if pending.prior_active_generation.is_some() {
            return Err(HostError::RecoveryRequired(
                "interrupted Phase-B upgrade requires an explicit prior-generation recovery proof"
                    .to_owned(),
            ));
        }
        let profile = pending.manifest.runtime_launch.profile;
        let portable_root = if profile == InstallationProfile::PortableDev {
            Some(
                UserOwnedRootLease::open_existing(Path::new(
                    pending
                        .manifest
                        .runtime_launch
                        .portable_root
                        .as_ref()
                        .ok_or_else(|| {
                            HostError::RecoveryRequired(
                                "Phase-B rollback portable root binding is missing".to_owned(),
                            )
                        })?
                        .as_str(),
                ))
                .map_err(|error| HostError::RecoveryRequired(error.to_string()))?,
            )
        } else {
            None
        };
        let authority_path = approved_locator(
            Path::new(
                pending
                    .manifest
                    .runtime_launch
                    .authority_descriptor_path
                    .as_str(),
            ),
            &pending.manifest.runtime_launch.authority_descriptor_path,
            profile,
        )?;
        let config_path = approved_locator(
            Path::new(pending.manifest.config_path.as_str()),
            &pending.manifest.config_path,
            profile,
        )?;
        let bootstrap_path = approved_locator(
            Path::new(
                pending
                    .manifest
                    .runtime_launch
                    .store_bootstrap_descriptor_path
                    .as_str(),
            ),
            &pending
                .manifest
                .runtime_launch
                .store_bootstrap_descriptor_path,
            profile,
        )?;
        let eliotd_path = approved_locator(
            Path::new(
                pending
                    .manifest
                    .runtime_launch
                    .eliotd_descriptor_path
                    .as_str(),
            ),
            &pending.manifest.runtime_launch.eliotd_descriptor_path,
            profile,
        )?;
        phase_b_restore_or_remove(
            profile,
            portable_root.as_ref(),
            &authority_path,
            "authority descriptor",
            None,
        )?;
        phase_b_restore_or_remove(
            profile,
            portable_root.as_ref(),
            &config_path,
            "Store config",
            Some(&pending.manifest.config_digest),
        )?;
        phase_b_restore_or_remove(
            profile,
            portable_root.as_ref(),
            &bootstrap_path,
            "Store bootstrap descriptor",
            Some(
                &pending
                    .manifest
                    .runtime_launch
                    .store_bootstrap_descriptor_digest,
            ),
        )?;
        phase_b_restore_or_remove(
            profile,
            portable_root.as_ref(),
            &eliotd_path,
            "eliotd descriptor",
            Some(&pending.manifest.runtime_launch.eliotd_descriptor_digest),
        )?;
        let intent = pending.phase_b_intent.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "Phase-B rollback preparation has no matching intent".to_owned(),
            )
        })?;
        let host_capability = self.owner_lease.activation_capability();
        let expected_revision = self.registry.revision();
        self.registry_store
            .clear_pending_phase_b_prepared(
                &host_capability,
                expected_revision,
                &pending.approval,
                prepared,
            )
            .map_err(HostError::Installation)?;
        self.registry = self.registry_store.load().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "Phase-B rollback preparation clear readback failed: {error}"
            ))
        })?;
        let expected_revision = self.registry.revision();
        self.registry_store
            .clear_pending_phase_b_intent(
                &host_capability,
                expected_revision,
                &pending.approval,
                intent,
            )
            .map_err(HostError::Installation)?;
        self.registry = self.registry_store.load().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "Phase-B rollback intent clear readback failed: {error}"
            ))
        })?;
        phase_b_remove_rollback_backup(&authority_path, "authority descriptor")?;
        phase_b_remove_rollback_backup(&config_path, "Store config")?;
        phase_b_remove_rollback_backup(&bootstrap_path, "Store bootstrap descriptor")?;
        phase_b_remove_rollback_backup(&eliotd_path, "eliotd descriptor")?;
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn reconcile_phase_b_for_manifest(
        _manifest: &CandidateManifest,
    ) -> Result<HostPhaseBMaterialization, HostError> {
        Err(HostError::RecoveryRequired(
            "Phase-B recovery requires a transaction-bound Host receipt; destination bytes are never an input"
                .to_owned(),
        ))
    }
}
