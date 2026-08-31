#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn binding() -> TestResult<ProcessExecutionBinding> {
        Ok(serde_json::from_value(serde_json::json!({
            "operation_id": "operation-1",
            "process_tree_id": "tree-1",
            "job_id": "job-1",
            "image_id": "image-1",
            "session_id": "session-1",
            "generation": 3,
            "action_lease_ref": "lease-1",
            "authority_id": "authority-1",
            "authority_epoch": 7,
            "state_fence": {
                "authority_epoch": 7,
                "generation": 3,
                "nonce": "fence-1"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 2
        }))?)
    }

    fn policy() -> Result<ProcessStreamPolicyBinding, ProcessStreamEvidenceError> {
        ProcessStreamPolicyBinding::new(
            "policy:1",
            "privacy:project",
            "visibility:owner",
            "retention:task",
            "redaction:exact-v1",
        )
    }

    fn exact_source(
        bytes: &[u8],
    ) -> Result<DurableProcessStreamSource, ProcessStreamEvidenceError> {
        let digest = sha256_hex(bytes);
        DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{digest}"),
            format!("receipt:blob-ready:{digest}"),
            digest,
            usize_to_u64("test.source.byte_length", bytes.len())?,
        )
    }

    fn exact_source_identity(
        sha256: impl Into<String>,
        byte_length: u64,
    ) -> Result<DurableProcessStreamSource, ProcessStreamEvidenceError> {
        let sha256 = sha256.into();
        DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{sha256}"),
            format!("receipt:blob-ready:{sha256}"),
            sha256,
            byte_length,
        )
    }

    fn prefix_identity(
        bytes: &[u8],
    ) -> Result<ProcessStreamTransportPrefixIdentity, ProcessStreamEvidenceError> {
        ProcessStreamTransportPrefixIdentity::new(
            sha256_hex(bytes),
            usize_to_u64("test.prefix.byte_length", bytes.len())?,
        )
    }

    fn transformation(
        input: &[u8],
        output: &[u8],
    ) -> Result<ProcessStreamTransformationBinding, ProcessStreamEvidenceError> {
        ProcessStreamTransformationBinding::new(
            "receipt:transformation:1",
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            sha256_hex(output),
            usize_to_u64("test.output_length", output.len())?,
            "policy:1",
            "redaction:exact-v1",
        )
    }

    fn transformed_source(
        input: &[u8],
        output: &[u8],
    ) -> Result<DurableProcessStreamSource, ProcessStreamEvidenceError> {
        let output_sha256 = sha256_hex(output);
        DurableProcessStreamSource::policy_transformed(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{output_sha256}"),
            format!("receipt:blob-ready:{output_sha256}"),
            output_sha256,
            usize_to_u64("test.output_length", output.len())?,
            transformation(input, output)?,
        )
    }

    fn assert_unknown_field_rejected<T>(value: &T) -> TestResult
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut wire = serde_json::to_value(value)?;
        wire.as_object_mut()
            .ok_or("expected object wire")?
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<T>(wire).is_err());
        Ok(())
    }

    #[test]
    fn truncated_transport_preview_and_complete_source_keep_separate_identities() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abcdef"),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 6)?,
            Some(exact_source(b"abcdef")?),
            Vec::new(),
        )?;
        assert!(evidence.preview().is_truncated());
        assert_ne!(
            evidence.preview().sha256(),
            evidence.source().ok_or("missing source")?.sha256()
        );
        assert_eq!(evidence.source().ok_or("missing source")?.byte_length(), 6);
        assert!(evidence.transport_prefix_identity().is_none());
        assert!(
            serde_json::to_value(&evidence)?
                .get("transport_prefix_identity")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn zero_byte_complete_stream_is_valid() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stderr,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(&[]),
            0,
            ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
            Some(exact_source(&[])?),
            Vec::new(),
        )?;
        assert_eq!(evidence.observed_bytes(), 0);
        assert_eq!(evidence.source().ok_or("missing source")?.byte_length(), 0);
        Ok(())
    }

    #[test]
    fn complete_source_requires_durable_locator() -> TestResult {
        let result = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            None,
            Vec::new(),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn locator_scheme_grammar_and_forbidden_schemes_fail_closed() {
        for locator in [
            "raw:p04-stream:sha256:abc",
            "RAW:p04-stream:sha256:abc",
            "memory:operation-1",
            "MeMoRy:operation-1",
            "process-memory:operation-1",
            "process_memory:operation-1",
            " raw:p04-stream:sha256:abc",
            "memory:operation-1 ",
            ":raw",
            "1memory:operation-1",
            "bad scheme:value",
            "bad_scheme:value",
            "scheme:",
        ] {
            let result = DurableProcessStreamSource::exact_transport(
                DurableStreamLocatorKind::ImmutableArtifact,
                locator,
                "receipt:ready",
                "a".repeat(64),
                3,
            );
            assert!(
                result.is_err(),
                "locator unexpectedly accepted: {locator:?}"
            );
        }

        for locator in ["eliot://blob/abc", "artifact+cas:v1", "A.b-c+1:value"] {
            let result = DurableProcessStreamSource::exact_transport(
                DurableStreamLocatorKind::ImmutableArtifact,
                locator,
                "receipt:ready",
                "a".repeat(64),
                3,
            );
            assert!(result.is_ok(), "canonical locator rejected: {locator:?}");
        }
    }

    #[test]
    fn read_failure_with_all_observed_bytes_remains_partial() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            Some(exact_source(b"abc")?),
            vec![StreamEvidenceGap::TransportReadFailed],
        )?;
        assert_eq!(
            evidence.persistence(),
            StreamPersistenceStatus::PartialSource
        );
        assert!(evidence.transport_prefix_identity().is_none());
        Ok(())
    }

    #[test]
    fn full_length_partial_source_rejects_mismatched_digest() -> TestResult {
        let source = DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            "eliot://blob/wrong",
            "receipt:blob-ready:wrong",
            "d".repeat(64),
            3,
        )?;
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            Some(source),
            vec![StreamEvidenceGap::TransportReadFailed],
        );
        assert!(evidence.is_err());
        Ok(())
    }

    #[test]
    fn shorter_partial_source_uses_exact_transport_prefix_identity() -> TestResult {
        let observed = b"abcdef";
        let evidence = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(b"ab".to_vec(), 6)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"abc")?),
            vec![StreamEvidenceGap::PersistenceFailed],
        )?;
        assert_eq!(evidence.source().ok_or("missing source")?.byte_length(), 3);
        assert_eq!(
            evidence
                .transport_prefix_identity()
                .ok_or("missing prefix identity")?
                .sha256(),
            sha256_hex(b"abc")
        );
        Ok(())
    }

    #[test]
    fn shorter_partial_source_rejects_mismatched_prefix_identity() -> TestResult {
        let observed = b"abcdef";
        let evidence = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(observed.to_vec(), 6)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"xyz")?),
            vec![StreamEvidenceGap::PersistenceFailed],
        );
        assert!(evidence.is_err());
        Ok(())
    }

    #[test]
    fn deserialization_rejects_tampered_transport_preview_at_durable_prefix_length() -> TestResult {
        let evidence = shorter_partial_source_uses_exact_transport_prefix_identity_fixture()?;
        let mut wire = serde_json::to_value(evidence)?;
        wire["preview"]["bytes"] = serde_json::json!([120, 121, 122]);
        wire["preview"]["sha256"] = serde_json::json!(sha256_hex(b"xyz"));
        wire["preview"]["retained_bytes"] = serde_json::json!(3);
        wire["preview"]["omitted_ranges"] = serde_json::json!([{
            "start": 3,
            "end_exclusive": 6
        }]);
        assert!(serde_json::from_value::<ProcessStreamEvidence>(wire).is_err());
        Ok(())
    }

    fn shorter_partial_source_uses_exact_transport_prefix_identity_fixture(
    ) -> TestResult<ProcessStreamEvidence> {
        let observed = b"abcdef";
        Ok(ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(b"ab".to_vec(), 6)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"abc")?),
            vec![StreamEvidenceGap::PersistenceFailed],
        )?)
    }

    #[test]
    fn shorter_partial_source_requires_identity_and_persistence_gap() -> TestResult {
        let observed = b"abcdef";
        let missing_identity = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(observed.to_vec(), 6)?,
            Some(exact_source(b"abc")?),
            vec![StreamEvidenceGap::PersistenceFailed],
        );
        assert!(missing_identity.is_err());

        let no_persistence_gap = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(observed.to_vec(), 6)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"abc")?),
            vec![StreamEvidenceGap::TransportReadFailed],
        );
        assert!(no_persistence_gap.is_err());
        Ok(())
    }

    #[test]
    fn large_partial_source_is_independent_of_preview_limit() -> TestResult {
        let source_length = u64::try_from(MAX_PREVIEW_BYTES)? + 1;
        let observed_bytes = source_length + 1;
        let source_sha256 = "d".repeat(64);
        let source = exact_source_identity(source_sha256.clone(), source_length)?;
        let prefix = ProcessStreamTransportPrefixIdentity::new(source_sha256, source_length)?;
        let evidence = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            "e".repeat(64),
            observed_bytes,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), observed_bytes)?,
            Some(source),
            Some(prefix),
            vec![StreamEvidenceGap::PersistenceBackpressure],
        )?;
        assert!(evidence.preview().retained_bytes() < source_length);
        assert_eq!(
            evidence
                .transport_prefix_identity()
                .ok_or("missing prefix identity")?
                .byte_length(),
            source_length
        );
        Ok(())
    }

    #[test]
    fn prefix_identity_rejected_for_complete_or_full_observed_source() -> TestResult {
        let complete = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"abc")?),
            Vec::new(),
        );
        assert!(complete.is_err());

        let full_partial = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            Some(exact_source(b"abc")?),
            Some(prefix_identity(b"abc")?),
            vec![StreamEvidenceGap::TransportReadFailed],
        );
        assert!(full_partial.is_err());
        Ok(())
    }

    #[test]
    fn prefix_identity_rejected_for_transformed_or_unavailable_source() -> TestResult {
        let input = b"secret=42";
        let output = b"secret=[redacted]";
        let transformed = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::ReadFailed,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_source_prefix(
                Vec::new(),
                usize_to_u64("test.output_length", output.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Some(prefix_identity(input)?),
            vec![StreamEvidenceGap::TransportReadFailed],
        );
        assert!(transformed.is_err());

        let unavailable = ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            None,
            Some(prefix_identity(b"abc")?),
            vec![StreamEvidenceGap::PersistenceUnavailable],
        );
        assert!(unavailable.is_err());
        Ok(())
    }

    #[test]
    fn policy_transformed_complete_preview_is_bound_to_source() -> TestResult {
        let input = b"secret=42";
        let output = b"secret=[redacted]";
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_source_prefix(
                output.to_vec(),
                usize_to_u64("test.output_length", output.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Vec::new(),
        )?;
        assert_eq!(
            evidence.preview().representation(),
            StreamPreviewRepresentation::DurableSourceBytes
        );
        assert_ne!(
            evidence.observed_sha256(),
            evidence.source().ok_or("missing source")?.sha256()
        );
        Ok(())
    }

    #[test]
    fn policy_transformed_allows_zero_byte_preview() -> TestResult {
        let input = b"secret=42";
        let output = b"secret=[redacted]";
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_source_prefix(
                Vec::new(),
                usize_to_u64("test.output_length", output.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Vec::new(),
        )?;
        assert!(evidence.preview().bytes().is_empty());
        assert!(evidence.preview().is_truncated());
        Ok(())
    }

    #[test]
    fn policy_transformed_rejects_nonempty_truncated_or_raw_preview() -> TestResult {
        let input = b"secret=42";
        let output = b"secret=[redacted]";
        let truncated = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_source_prefix(
                output[..6].to_vec(),
                usize_to_u64("test.output_length", output.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Vec::new(),
        );
        assert!(truncated.is_err());

        let raw_mislabeled = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_source_prefix(
                input.to_vec(),
                usize_to_u64("test.output_length", output.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Vec::new(),
        );
        assert!(raw_mislabeled.is_err());

        let raw_coordinates = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(input),
            usize_to_u64("test.input_length", input.len())?,
            ProcessStreamPrefixPreview::from_transport_prefix(
                input.to_vec(),
                usize_to_u64("test.input_length", input.len())?,
            )?,
            Some(transformed_source(input, output)?),
            Vec::new(),
        );
        assert!(raw_coordinates.is_err());
        Ok(())
    }

    #[test]
    fn policy_prohibited_and_redaction_failed_withhold_inline_bytes() -> TestResult {
        let input = b"secret=42";
        for gap in [
            StreamEvidenceGap::PolicyProhibited,
            StreamEvidenceGap::RedactionFailed,
        ] {
            let raw_preview = ProcessStreamEvidence::new_raw(
                binding()?,
                ProcessStreamKind::Stdout,
                policy()?,
                StreamTransportStatus::Complete,
                StreamPersistenceStatus::SourceUnavailable,
                sha256_hex(input),
                usize_to_u64("test.input_length", input.len())?,
                ProcessStreamPrefixPreview::from_transport_prefix(
                    input.to_vec(),
                    usize_to_u64("test.input_length", input.len())?,
                )?,
                None,
                vec![gap],
            );
            assert!(raw_preview.is_err());

            let withheld = ProcessStreamEvidence::new_raw(
                binding()?,
                ProcessStreamKind::Stdout,
                policy()?,
                StreamTransportStatus::Complete,
                StreamPersistenceStatus::SourceUnavailable,
                sha256_hex(input),
                usize_to_u64("test.input_length", input.len())?,
                ProcessStreamPrefixPreview::withheld_by_policy(),
                None,
                vec![gap],
            )?;
            assert!(withheld.preview().bytes().is_empty());
        }
        Ok(())
    }

    #[test]
    fn every_transport_status_rejects_contradictory_transport_gaps() -> TestResult {
        let statuses = [
            StreamTransportStatus::Complete,
            StreamTransportStatus::ReadFailed,
            StreamTransportStatus::CancelledBeforeEof,
            StreamTransportStatus::CaptureUnavailable,
            StreamTransportStatus::UnknownOutcome,
        ];
        for status in statuses {
            let expected = expected_transport_gap(status);
            let observed = if status == StreamTransportStatus::CaptureUnavailable {
                Vec::new()
            } else {
                b"abc".to_vec()
            };
            let observed_len = usize_to_u64("test.observed_length", observed.len())?;
            let preview =
                ProcessStreamPrefixPreview::from_transport_prefix(observed.clone(), observed_len)?;

            if let Some(expected_gap) = expected {
                let mut valid_gaps = vec![expected_gap];
                if status != StreamTransportStatus::CaptureUnavailable {
                    valid_gaps.push(StreamEvidenceGap::PersistenceUnavailable);
                }
                let valid = ProcessStreamEvidence::new_raw(
                    binding()?,
                    ProcessStreamKind::Stdout,
                    policy()?,
                    status,
                    StreamPersistenceStatus::SourceUnavailable,
                    sha256_hex(&observed),
                    observed_len,
                    preview.clone(),
                    None,
                    valid_gaps,
                );
                assert!(
                    valid.is_ok(),
                    "expected transport gap rejected for {status:?}"
                );
            }

            for wrong_gap in TRANSPORT_GAPS {
                if Some(wrong_gap) == expected {
                    continue;
                }
                let mut gaps = vec![wrong_gap];
                if let Some(expected_gap) = expected {
                    gaps.push(expected_gap);
                }
                let invalid = ProcessStreamEvidence::new_raw(
                    binding()?,
                    ProcessStreamKind::Stdout,
                    policy()?,
                    status,
                    StreamPersistenceStatus::SourceUnavailable,
                    sha256_hex(&observed),
                    observed_len,
                    preview.clone(),
                    None,
                    gaps,
                );
                assert!(
                    invalid.is_err(),
                    "contradictory gap accepted for {status:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn unavailable_source_requires_reason_and_no_locator() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?;
        let no_gap = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            3,
            preview.clone(),
            None,
            Vec::new(),
        );
        assert!(no_gap.is_err());

        let with_locator = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            3,
            preview.clone(),
            Some(exact_source(b"abc")?),
            vec![StreamEvidenceGap::PersistenceUnavailable],
        );
        assert!(with_locator.is_err());

        let unavailable = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            sha256_hex(b"abc"),
            3,
            preview,
            None,
            vec![StreamEvidenceGap::PersistenceUnavailable],
        )?;
        assert!(unavailable.source().is_none());
        Ok(())
    }

    #[test]
    fn stdout_and_stderr_have_distinct_typed_identities() -> TestResult {
        let preview = ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?;
        let stdout = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            3,
            preview.clone(),
            Some(exact_source(b"abc")?),
            Vec::new(),
        )?;
        let stderr = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stderr,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            3,
            preview,
            Some(exact_source(b"abc")?),
            Vec::new(),
        )?;
        assert_ne!(stdout.identity_sha256()?, stderr.identity_sha256()?);
        Ok(())
    }

    #[test]
    fn public_custom_deserializers_reject_unknown_fields() -> TestResult {
        let range = StreamByteRange::new(0, 1)?;
        let policy = policy()?;
        let preview = ProcessStreamPrefixPreview::from_transport_prefix(b"a".to_vec(), 1)?;
        let transformation = transformation(b"a", b"b")?;
        let source = exact_source(b"a")?;
        let prefix = prefix_identity(b"a")?;
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy.clone(),
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"a"),
            1,
            preview.clone(),
            Some(source.clone()),
            Vec::new(),
        )?;

        assert_unknown_field_rejected(&range)?;
        assert_unknown_field_rejected(&policy)?;
        assert_unknown_field_rejected(&preview)?;
        assert_unknown_field_rejected(&transformation)?;
        assert_unknown_field_rejected(&source)?;
        assert_unknown_field_rejected(&prefix)?;
        assert_unknown_field_rejected(&evidence)?;
        Ok(())
    }

    #[test]
    fn deserialization_rejects_invalid_binding_or_authority_promotion() -> TestResult {
        let evidence = ProcessStreamEvidence::new_raw(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            sha256_hex(b"abc"),
            3,
            ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
            Some(exact_source(b"abc")?),
            Vec::new(),
        )?;

        let mut invalid_binding = serde_json::to_value(&evidence)?;
        invalid_binding["binding"]["authority_epoch"] = serde_json::json!(8);
        assert!(serde_json::from_value::<ProcessStreamEvidence>(invalid_binding).is_err());

        let mut promoted = serde_json::to_value(evidence)?;
        promoted["parsing"] = serde_json::json!("PARSED");
        promoted["evaluation"] = serde_json::json!("PASS");
        assert!(serde_json::from_value::<ProcessStreamEvidence>(promoted).is_err());
        Ok(())
    }
}
