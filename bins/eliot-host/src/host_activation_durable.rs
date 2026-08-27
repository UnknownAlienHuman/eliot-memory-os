use super::*;

impl HostComposition {
    #[cfg(windows)]
    pub(super) fn reconcile_pending_activation(
        &mut self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<(), HostError> {
        self.ensure_admission_open()?;
        let host_capability = self.owner_lease.activation_capability();
        let pending = self.claim_pending_durable(pending, &host_capability)?;
        if pending
            .manifest
            .runtime_launch
            .installation_epoch
            .installation
            != self.host.installation
        {
            let reason = "pending activation installation epoch is stale";
            persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                &host_capability,
                &pending,
                reason,
            )?;
            return Err(HostError::RecoveryRequired(reason.to_owned()));
        }
        if let Err(error) = start_approved_manifest_contour(
            self,
            &pending.manifest,
            HostStartupBranch::Pending,
            Some(&pending),
        ) {
            if pending.prior_active_generation.is_none() {
                self.abort_pending_durable(&pending, &host_capability)?;
            } else {
                let reason = error.to_string();
                persist_pending_recovery(
                    &self.registry_store,
                    &mut self.registry,
                    &host_capability,
                    &pending,
                    &reason,
                )?;
            }
            return Err(error);
        }
        self.commit_pending_durable(&pending, &host_capability)?;
        Ok(())
    }

    #[cfg(windows)]
    fn claim_pending_durable(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<eliot_installation::PendingActivation, HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current.approval == pending.approval
                && matches!(&current.state, PendingActivationState::Pending)
        }) {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "pending activation claim registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self.registry_store.claim_pending_activation(
            host_capability,
            expected_revision,
            &pending.approval,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "pending activation claim outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_pending = durable.pending_activation().filter(|current| {
            current.transaction_id == pending.transaction_id
                && current.plan_digest == pending.plan_digest
                && current.approval == pending.approval
                && matches!(&current.state, PendingActivationState::Pending)
        });
        let exact_readback =
            durable.revision() == expected_post_revision && exact_pending.is_some();
        let recovered = exact_pending.cloned();
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && Some(&returned) == recovered.as_ref() => Ok(returned),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "pending activation claim returned a value different from exact registry readback"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "pending activation claim succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => recovered.ok_or_else(|| {
                HostError::RecoveryRequired(
                    "pending activation claim readback lost the exact pending record".to_owned(),
                )
            }),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "pending activation claim failed and exact readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_pending_phase_b_intent(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        intent: &HostPhaseBMaterializationIntent,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current
                .phase_b_intent
                .as_ref()
                .is_some_and(|existing| existing == intent)
        }) {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired("Phase-B intent registry revision overflow".to_owned())
            })?
        };
        let outcome = self.registry_store.record_pending_phase_b_intent(
            host_capability,
            expected_revision,
            &pending.approval,
            intent,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Phase-B intent outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.approval == pending.approval
                    && current.phase_b_intent.as_ref() == Some(intent)
                    && current.phase_b_receipt.is_none()
            });
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *intent => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Phase-B intent succeeded but exact registry readback differed".to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Phase-B intent succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Phase-B intent failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_pending_phase_b_prepared(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        prepared: &HostPhaseBPreparedMaterialization,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current
                .phase_b_prepared
                .as_ref()
                .is_some_and(|existing| existing == prepared)
        }) {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Phase-B preparation registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self.registry_store.record_pending_phase_b_prepared(
            host_capability,
            expected_revision,
            &pending.approval,
            prepared,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Phase-B preparation outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.approval == pending.approval
                    && current.phase_b_prepared.as_ref() == Some(prepared)
                    && current.phase_b_receipt.is_none()
            });
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *prepared => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Phase-B preparation succeeded but exact registry readback differed".to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Phase-B preparation succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Phase-B preparation failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_pending_phase_b_agent_bridge_stage_prepared(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        stage: &AgentBridgeStagePrepared,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current.phase_b_agent_bridge_stage_prepared.as_ref() == Some(stage)
        }) {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Agent Bridge stage-prepared registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self
            .registry_store
            .record_pending_phase_b_agent_bridge_stage_prepared(
                host_capability,
                expected_revision,
                &pending.approval,
                stage,
            );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Agent Bridge stage-prepared outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.approval == pending.approval
                    && current.phase_b_agent_bridge_stage_prepared.as_ref() == Some(stage)
                    && current.phase_b_prepared.is_none()
                    && current.phase_b_receipt.is_none()
            });
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *stage => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Agent Bridge stage-prepared succeeded but exact registry readback differed"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Agent Bridge stage-prepared succeeded but exact registry readback failed"
                    .to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Agent Bridge stage-prepared failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn clear_pending_phase_b_agent_bridge_stage_prepared(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        stage: &AgentBridgeStagePrepared,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current.phase_b_agent_bridge_stage_prepared.as_ref() == Some(stage)
        }) {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Agent Bridge stage-clear registry revision overflow".to_owned(),
                )
            })?
        } else {
            expected_revision
        };
        let outcome = self
            .registry_store
            .clear_pending_phase_b_agent_bridge_stage_prepared(
                host_capability,
                expected_revision,
                &pending.approval,
                stage,
            );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Agent Bridge stage-clear outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.approval == pending.approval
                    && current.phase_b_agent_bridge_stage_prepared.is_none()
                    && current.phase_b_prepared.is_none()
                    && current.phase_b_receipt.is_none()
            });
        self.registry = durable;
        match outcome {
            Ok(()) if exact_readback => Ok(()),
            Ok(()) => Err(HostError::RecoveryRequired(
                "Agent Bridge stage-clear succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Agent Bridge stage-clear failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_pending_phase_b_receipt(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        receipt: &HostPhaseBMaterializationReceipt,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some_and(|current| {
            current
                .phase_b_receipt
                .as_ref()
                .is_some_and(|existing| existing == receipt)
        }) {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired("Phase-B receipt registry revision overflow".to_owned())
            })?
        };
        let outcome = self.registry_store.record_pending_phase_b_receipt(
            host_capability,
            expected_revision,
            &pending.approval,
            receipt,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Phase-B receipt outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.approval == pending.approval
                    && current.phase_b_receipt.as_ref() == Some(receipt)
            });
        self.registry = durable;
        let result = match outcome {
            Ok(returned) if exact_readback && returned == *receipt => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Phase-B receipt succeeded but exact registry readback differed".to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Phase-B receipt succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Phase-B receipt failed and exact registry readback did not confirm it: {error}"
            ))),
        };
        if result.is_ok()
            && let Some(binding) = receipt.agent_bridge.as_ref()
        {
            // Pair rollback backups are retained across the publication and
            // receipt crash window.  They become disposable only after the
            // receipt CAS has exact durable readback.
            phase_b_remove_rollback_backup(
                std::path::Path::new(binding.profile_path.as_str()),
                "Agent Bridge admission profile",
            )?;
            phase_b_remove_rollback_backup(
                std::path::Path::new(binding.declaration_path.as_str()),
                "Agent Bridge client declaration",
            )?;
        }
        result
    }

    #[cfg(windows)]
    pub(super) fn persist_pending_phase_b_prepared_receipt(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        receipt: &eliot_installation::HostPhaseBPreparedReceipt,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self
            .registry
            .pending_activation()
            .is_some_and(|current| current.phase_b_prepared_receipt.as_ref() == Some(receipt))
        {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired("Phase-B prepared receipt revision overflow".to_owned())
            })?
        };
        let outcome = self.registry_store.record_pending_phase_b_prepared_receipt(
            host_capability,
            expected_revision,
            &pending.approval,
            receipt,
        );
        let durable = self.registry_store.load().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "prepared receipt outcome is unknown and registry readback failed: {error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_some_and(|current| {
                current.transaction_id == pending.transaction_id
                    && current.plan_digest == pending.plan_digest
                    && current.phase_b_prepared_receipt.as_ref() == Some(receipt)
                    && current.phase_b_receipt.is_none()
            });
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *receipt => Ok(()),
            Err(_) if exact_readback => Ok(()),
            Ok(_) => Err(HostError::RecoveryRequired(
                "prepared receipt succeeded but exact readback differed".to_owned(),
            )),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "prepared receipt failed and exact readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_active_phase_b_rebind_intent(
        &mut self,
        intent: &ActivePhaseBRebindIntent,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self
            .registry
            .active_phase_b_rebind()
            .is_some_and(|current| current.intent == *intent)
        {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Active Phase-B rebind intent registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self.registry_store.record_active_phase_b_rebind_intent(
            host_capability,
            expected_revision,
            intent,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Active Phase-B rebind intent outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable
                .active_phase_b_rebind()
                .is_some_and(|current| current.intent == *intent);
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *intent => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind intent succeeded but exact registry readback differed"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind intent succeeded but exact registry readback failed"
                    .to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Active Phase-B rebind intent failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_active_phase_b_rebind_recovery_and_intent(
        &mut self,
        recovery: &ActivePhaseBRebindRecovery,
        intent: &ActivePhaseBRebindIntent,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision =
            if self
                .registry
                .active_phase_b_rebind()
                .is_some_and(|current| {
                    current.intent == *intent
                        && current
                            .recovery_history
                            .last()
                            .is_some_and(|existing| existing == recovery)
                })
            {
                expected_revision
            } else {
                expected_revision.checked_add(1).ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Active Phase-B recovery registry revision overflow".to_owned(),
                    )
                })?
            };
        let outcome = self
            .registry_store
            .record_active_phase_b_rebind_recovery_and_intent(
                host_capability,
                expected_revision,
                recovery,
                intent,
            );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Active Phase-B recovery/intent outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.active_phase_b_rebind().is_some_and(|current| {
                current.intent == *intent
                    && current
                        .recovery_history
                        .last()
                        .is_some_and(|existing| existing == recovery)
            });
        self.registry = durable;
        match outcome {
            Ok(returned)
                if exact_readback
                    && returned.intent == *intent
                    && returned
                        .recovery_history
                        .last()
                        .is_some_and(|existing| existing == recovery) =>
            {
                Ok(())
            }
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Active Phase-B recovery/intent succeeded but exact registry readback differed"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Active Phase-B recovery/intent succeeded but exact registry readback failed"
                    .to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Active Phase-B recovery/intent failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_active_phase_b_rebind_prepared(
        &mut self,
        prepared: &HostPhaseBPreparedMaterialization,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self
            .registry
            .active_phase_b_rebind()
            .is_some_and(|current| current.prepared.as_ref() == Some(prepared))
        {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Active Phase-B rebind preparation registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self.registry_store.record_active_phase_b_rebind_prepared(
            host_capability,
            expected_revision,
            prepared,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Active Phase-B rebind preparation outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable
                .active_phase_b_rebind()
                .is_some_and(|current| current.prepared.as_ref() == Some(prepared));
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *prepared => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind preparation succeeded but exact registry readback differed"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind preparation succeeded but exact registry readback failed"
                    .to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Active Phase-B rebind preparation failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    pub(super) fn persist_active_phase_b_rebind_receipt(
        &mut self,
        receipt: &ActivePhaseBRebindReceipt,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self
            .registry
            .active_phase_b_rebind()
            .is_some_and(|current| current.receipt.as_ref() == Some(receipt))
        {
            expected_revision
        } else {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "Active Phase-B rebind receipt registry revision overflow".to_owned(),
                )
            })?
        };
        let outcome = self.registry_store.record_active_phase_b_rebind_receipt(
            host_capability,
            expected_revision,
            receipt,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "Active Phase-B rebind receipt outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable
                .active_phase_b_rebind()
                .is_some_and(|current| current.receipt.as_ref() == Some(receipt));
        self.registry = durable;
        match outcome {
            Ok(returned) if exact_readback && returned == *receipt => Ok(()),
            Ok(_) if exact_readback => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind receipt succeeded but exact registry readback differed"
                    .to_owned(),
            )),
            Ok(_) => Err(HostError::RecoveryRequired(
                "Active Phase-B rebind receipt succeeded but exact registry readback failed"
                    .to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "Active Phase-B rebind receipt failed and exact registry readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    fn abort_pending_durable(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some() {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "pending activation abort registry revision overflow".to_owned(),
                )
            })?
        } else {
            expected_revision
        };
        let outcome = self.registry_store.abort_pending_activation(
            host_capability,
            expected_revision,
            &pending.approval,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "pending activation abort outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_none()
            && durable.active().is_none()
            && !durable
                .generations()
                .iter()
                .any(|generation| generation.manifest.generation == pending.manifest.generation);
        self.registry = durable;
        match outcome {
            Ok(()) if exact_readback => Ok(()),
            Ok(()) => Err(HostError::RecoveryRequired(
                "pending activation abort succeeded but exact registry readback failed".to_owned(),
            )),
            Err(_error) if exact_readback => Ok(()),
            Err(error) => Err(HostError::RecoveryRequired(format!(
                "pending activation abort failed and exact readback did not confirm it: {error}"
            ))),
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "fresh commit fence construction keeps the final journal/readiness/Phase-B CAS proof together"
    )]
    fn fresh_pending_commit_fence(
        &mut self,
        pending: &eliot_installation::PendingActivation,
    ) -> Result<ActivationCommitFence, HostError> {
        self.ensure_admission_open()?;
        let durable = self.registry_store.load().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "activation commit readiness fence registry readback failed: {error}"
            ))
        })?;
        let exact_pending = durable.pending_activation().is_some_and(|current| {
            current == pending && matches!(current.state, PendingActivationState::Pending)
        });
        if !exact_pending {
            return Err(HostError::RecoveryRequired(
                "activation commit readiness fence found a stale, substituted, or recovery-required pending registry record"
                    .to_owned(),
            ));
        }
        self.registry = durable;

        // Bypass HostReadinessGate's cached Instant lease: the final CAS must
        // receive a newly Kernel-authored ProbeReady receipt and Store proof.
        self.persist_process_observations(&pending.manifest.generation)?;

        let (kernel_artifact, store_artifact) = pending
            .manifest
            .host_child_artifact_digests()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let pending_manifest_digest = phase_b_manifest_digest(&pending.manifest)?;
        let phase_b = self
            .phase_b
            .as_ref()
            .filter(|receipt| receipt.manifest_digest == pending_manifest_digest)
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "activation commit has no exact Phase-B materialization receipt".to_owned(),
                )
            })?;
        if phase_b.host_epoch != self.host.epoch.current
            || phase_b.host_process_nonce != self.host.nonce
        {
            return Err(HostError::RecoveryRequired(
                "activation commit Phase-B receipt is not bound to the current Host epoch/nonce"
                    .to_owned(),
            ));
        }
        phase_b
            .launch
            .require_phase_b_live()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let contour = self.current_readiness_contour(
            &pending.manifest.generation,
            kernel_artifact,
            store_artifact,
            &phase_b.config_file_digest,
        )?;
        let store_proof_fence = contour.store_proof_fence.clone().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit readiness fence is missing the Store proof fence".to_owned(),
            )
        })?;
        let state = self.journal.snapshot()?;
        let active = state.kernel.as_ref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit readiness fence has no durable Kernel record".to_owned(),
            )
        })?;
        let observation = state.readiness_observations.last().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit readiness fence has no durable Kernel readiness observation"
                    .to_owned(),
            )
        })?;
        let observation_checksum =
            record_checksum(&HostStateRecord::ReadinessObservation(observation.clone()))?;
        let last_checksum = state.last_checksum.as_deref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit readiness fence has no durable journal checksum".to_owned(),
            )
        })?;
        if state.sequence == 0 || last_checksum != observation_checksum {
            return Err(HostError::RecoveryRequired(
                "activation commit readiness observation is not the final fresh journal frame"
                    .to_owned(),
            ));
        }
        let active_checksum = record_checksum(&HostStateRecord::Kernel(active.clone()))?;
        let expected_authority = phase_b.launch.authority_state_fence.authority_epoch.value();
        if observation.active_kernel_record_checksum.as_str() != active_checksum
            || observation.fence != active.fence
            || observation.config_digest != phase_b.config_file_digest
            || observation.store_fence != store_proof_fence
            || observation.authority_epoch != expected_authority
        {
            return Err(HostError::RecoveryRequired(
                "activation commit readiness fence is stale or substituted".to_owned(),
            ));
        }
        let agent_bridge = match (phase_b.agent_bridge(), phase_b.final_agent_bridge()) {
            (Some(_prepared), Some(final_binding)) => Some(final_binding.clone()),
            (Some(_prepared), None) => {
                return Err(HostError::RecoveryRequired(
                    "Phase-B activation has only a prepared Agent Bridge proof; final provider receipt is required"
                        .to_owned(),
                ));
            }
            (None, Some(final_binding)) => Some(final_binding.clone()),
            (None, None) => None,
        };
        let fence = ActivationCommitFence {
            generation: pending.manifest.generation.clone(),
            config_digest: pending.manifest.config_digest.clone(),
            materialized_config_digest: phase_b.config_file_digest.clone(),
            phase_b_live_binding: Some(PhaseBLiveBinding {
                manifest_digest: phase_b.manifest_digest.clone(),
                authority_descriptor_digest: phase_b.authority_descriptor_digest.clone(),
                store_bootstrap_descriptor_digest: phase_b
                    .store_bootstrap_descriptor_digest
                    .clone(),
                config_file_digest: phase_b.config_file_digest.clone(),
                eliotd_descriptor_digest: phase_b.eliotd_descriptor_digest.clone(),
                semantic_config_hash: phase_b.semantic_config_hash.clone(),
                host_epoch_lineage: phase_b.host_epoch.lineage.clone(),
                host_epoch_sequence: phase_b.host_epoch.sequence,
                host_process_nonce_digest: PlatformHandle::new(format!(
                    "{:x}",
                    Sha256::digest(phase_b.host_process_nonce.as_str().as_bytes())
                ))
                .map_err(|error| HostError::Platform(error.to_string()))?,
                receipt_digest: phase_b_receipt_digest(phase_b)?,
                effect_id: phase_b.effect_id.clone().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B commit is missing its materialization effect identity".to_owned(),
                    )
                })?,
                credential_receipt_digest: phase_b.credential_receipt_digest.clone().ok_or_else(
                    || {
                        HostError::RecoveryRequired(
                            "Phase-B commit is missing its credential receipt digest".to_owned(),
                        )
                    },
                )?,
                request_digest: phase_b.request_digest.clone().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B commit is missing its request digest".to_owned(),
                    )
                })?,
                host_owner_epoch: phase_b.host_owner_epoch.clone().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B commit is missing its Host owner epoch receipt".to_owned(),
                    )
                })?,
                host_process_identity: phase_b.host_process_identity.clone().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B commit is missing its Host process receipt".to_owned(),
                    )
                })?,
                public_receipt_digest: phase_b.public_receipt_digest.clone().ok_or_else(|| {
                    HostError::RecoveryRequired(
                        "Phase-B commit is missing its public receipt digest".to_owned(),
                    )
                })?,
                provisioned_supervision_authority: phase_b
                    .launch
                    .provisioned_supervision_authority()
                    .map_err(HostError::Installation)?
                    .clone(),
                agent_bridge,
            }),
            authority_generation: phase_b.launch.authority_generation,
            authority_state_fence: phase_b.launch.authority_state_fence.clone(),
            active_kernel_record_checksum: observation.active_kernel_record_checksum.clone(),
            probe_request_digest: observation.probe_request_digest.clone(),
            ready_receipt_digest: observation.ready_receipt_digest.clone(),
            store_proof_fence: observation.store_fence.clone(),
            candidate_binding_digest: contour.candidate_binding_digest,
            store_requirement_digest: contour.store_requirement_digest,
            readiness_sequence: state.sequence,
            readiness_journal_checksum: PlatformHandle::new(last_checksum.to_owned())
                .map_err(|error| HostError::Platform(error.to_string()))?,
        };
        fence.validate().map_err(HostError::Installation)?;
        Ok(fence)
    }

    #[cfg(windows)]
    fn verify_pending_commit_journal_fence(
        &self,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), HostError> {
        // The registry readback itself is not a liveness barrier. Re-snapshot
        // the journal after that read and immediately before the CAS so an
        // intervening degraded/recovery append cannot reuse the earlier fence.
        let state = self.journal.snapshot().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "activation commit journal readback failed before CAS: {error}"
            ))
        })?;
        let observation = state.readiness_observations.last().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit readiness observation disappeared before CAS".to_owned(),
            )
        })?;
        let observation_checksum = record_checksum(&HostStateRecord::ReadinessObservation(
            observation.clone(),
        ))
        .map_err(|error| {
            HostError::RecoveryRequired(format!(
                "activation commit readiness checksum failed before CAS: {error}"
            ))
        })?;
        let journal_checksum = state.last_checksum.as_deref().ok_or_else(|| {
            HostError::RecoveryRequired(
                "activation commit journal checksum disappeared before CAS".to_owned(),
            )
        })?;
        if state.sequence != commit_fence.readiness_sequence
            || journal_checksum != commit_fence.readiness_journal_checksum.as_str()
            || observation_checksum != commit_fence.readiness_journal_checksum.as_str()
        {
            return Err(HostError::RecoveryRequired(
                "activation commit readiness fence changed before registry CAS".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn commit_pending_durable(
        &mut self,
        pending: &eliot_installation::PendingActivation,
        host_capability: &eliot_platform_windows::HostOwnerEpochCapability,
    ) -> Result<(), HostError> {
        let commit_fence = self.fresh_pending_commit_fence(pending)?;
        let durable_before_commit = self.registry_store.load().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "activation commit registry readback failed after readiness proof: {error}"
            ))
        })?;
        let exact_pending = durable_before_commit
            .pending_activation()
            .is_some_and(|current| {
                current == pending && matches!(current.state, PendingActivationState::Pending)
            });
        if !exact_pending {
            return Err(HostError::RecoveryRequired(
                "activation commit registry changed after readiness proof".to_owned(),
            ));
        }
        self.registry = durable_before_commit;
        self.verify_pending_commit_journal_fence(&commit_fence)?;
        let expected_revision = self.registry.revision();
        let expected_post_revision = if self.registry.pending_activation().is_some() {
            expected_revision.checked_add(1).ok_or_else(|| {
                HostError::RecoveryRequired(
                    "pending activation commit registry revision overflow".to_owned(),
                )
            })?
        } else {
            expected_revision
        };
        let outcome = self.registry_store.commit_pending_activation(
            host_capability,
            expected_revision,
            &pending.approval,
            &commit_fence,
        );
        let durable = self.registry_store.load().map_err(|readback_error| {
            HostError::RecoveryRequired(format!(
                "activation commit outcome is unknown and registry readback failed: {readback_error}"
            ))
        })?;
        let exact_readback = durable.revision() == expected_post_revision
            && durable.pending_activation().is_none()
            && durable.active().is_some_and(|active| {
                active.manifest.generation == pending.manifest.generation
                    && active.approval == pending.approval
                    && durable.last_committed_activation_fence() == Some(&commit_fence)
            });
        self.registry = durable;
        let result = match outcome {
            Ok(()) if exact_readback => return Ok(()),
            Ok(()) => HostError::RecoveryRequired(
                "activation commit succeeded but exact registry readback failed".to_owned(),
            ),
            Err(_error) if exact_readback => return Ok(()),
            Err(error) => HostError::RecoveryRequired(format!(
                "activation commit failed and exact readback did not confirm it: {error}"
            )),
        };
        if self.registry.pending_activation().is_some_and(|current| {
            current.transaction_id == pending.transaction_id
                && current.plan_digest == pending.plan_digest
                && current.approval == pending.approval
        }) {
            persist_pending_recovery(
                &self.registry_store,
                &mut self.registry,
                host_capability,
                pending,
                "activation commit outcome is unknown",
            )
            .map_err(|recovery_error| {
                HostError::RecoveryRequired(format!(
                    "{result}; durable recovery disposition failed: {recovery_error}"
                ))
            })?;
        }
        Err(result)
    }
}
