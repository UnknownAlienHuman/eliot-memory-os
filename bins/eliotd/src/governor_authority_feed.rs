//! Daemon publisher for the live Governor-derived authority projection
//! (issue #1935 AUD1, I7.16).
//!
//! Architecture traceability: I7.16 keeps the Governor the sole deriver of
//! the revision-bearing `GovernanceProfile` from runtime coverage, Watchdog
//! supervision evidence, and trace freshness, and revokes authority that
//! depended on a lost guarantee; I1.8 keeps the daemon/Kernel call path
//! behind the authenticated transport; A13.2 keeps daemon/Kernel failure
//! domains explicit.
//!
//! This module owns the daemon side of that path: it feeds the single live
//! Governor-owned derivation instance held by the daemon composition root
//! ([`DaemonComposition`](super::DaemonComposition)) from the authenticated
//! Kernel readback of retained source observations and projects the result
//! across the `publish_governor_authority` boundary. The Kernel maps the exact
//! revision, exact active fingerprint, and exact authorization axes to its
//! existing three-axis profile under its strictly-advancing revision rule,
//! so a newer degraded projection revokes everything issued under the old
//! one. Until the first publish records, every Material/Critical gate
//! refuses closed.
//!
//! Forbidden boundary: this daemon adapter never classifies event payloads or
//! fabricates coverage, Watchdog, or trace facts. It forwards the exact
//! authenticated Kernel readback to the Governor's source-observation builder,
//! never creates a second derivation instance or profile vocabulary, and
//! claims publication only after the Kernel acknowledges the exact revision.

use std::sync::Arc;

use eliot_governor::CompositionError;
pub use eliot_integration_coverage::GovernorAuthorityObservation;
use eliot_integration_coverage::{AdapterAdmissionIdentity, EvidenceAvailability, SourceReadback};

use super::daemon_kernel_client::DaemonKernelClient;
use super::{DaemonComposition, DaemonError, kind_value};

/// Daemon->Kernel front-door governor-authority publish operation: names the
/// exact arm the Kernel dispatcher serves. The transport injects this name
/// into the payload object, so it is not duplicated there.
const PUBLISH_GOVERNOR_AUTHORITY_OPERATION: &str = "publish_governor_authority";
/// Authenticated Kernel readback operation for original admitted bridge rows.
const READ_GOVERNOR_AUTHORITY_OBSERVATION_OPERATION: &str = "read_governor_authority_observation";
/// Typed receipt kind answered by the publish arm.
const GOVERNOR_AUTHORITY_RECEIPT_KIND: &str = "governor_authority_receipt";
/// Typed observation kind answered by the authenticated owner read.
const GOVERNOR_AUTHORITY_OBSERVATION_KIND: &str = "governor_authority_observation";
/// Bounded owner/event page size sent on every observation read.
const GOVERNOR_AUTHORITY_OBSERVATION_PAGE_LIMIT: u32 = 128;
/// Only an acknowledged `recorded` receipt counts as published.
const GOVERNOR_AUTHORITY_RECORDED_STATUS: &str = "recorded";

/// Wire shape answered by the Kernel `publish_governor_authority` arm: the
/// recorded revision plus the acknowledged status. Anything but `recorded`
/// at the projected revision is a refusal, never a partial publish.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernorAuthorityReceiptWire {
    revision: u64,
    status: String,
}

/// Exact Kernel request accepted by the owner-scoped observation read. These
/// cursors are continuation only: principal, producer, stream, and active
/// adapter identity are always resolved by Kernel from authenticated owner
/// state.
#[derive(serde::Serialize)]
struct GovernorAuthorityObservationRequestWire {
    after_owner_sequence: u64,
    after_event_sequence: u64,
    page_limit: u32,
}

/// Strict outer response envelope returned by the Kernel owner read. Nested
/// original rows are decoded by the Governor observation DTO, which rejects
/// unknown fields in each retained owner/page/record structure.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernorAuthorityObservationResponseWire {
    schema_version: u16,
    admission: Option<AdapterAdmissionIdentity>,
    source_status: String,
    source_snapshot: Option<serde_json::Value>,
    source_reason: Option<String>,
    watchdog: serde_json::Value,
    trace: serde_json::Value,
}

/// Derives and publishes from the authenticated Kernel readback of original
/// admitted bridge observations. The Governor owns classification and
/// degradation: this daemon adapter only binds the closed Kernel response to
/// the source DTO and forwards it to the one live derivation owner.
///
/// `Ok(None)` means there is no active admitted profile and no prior Governor
/// baseline to degrade. An unavailable source with a prior profile is still
/// passed through `refresh_observation`, so it advances a degraded revision
/// instead of leaving stale authority in place.
pub async fn maintain_governor_authority_observation(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    observation: &GovernorAuthorityObservation,
) -> Result<Option<u64>, CompositionError> {
    Ok(
        maintain_governor_authority_observation_inner(composition, kernel, observation, None)
            .await?
            .map(|(revision, _, _)| revision),
    )
}

async fn maintain_governor_authority_observation_inner(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    observation: &GovernorAuthorityObservation,
    last_acknowledged: Option<&AcknowledgedProjection>,
) -> Result<Option<(u64, bool, String)>, CompositionError> {
    let authority = composition
        .governor_authority_mut()
        .map_err(|error| match error {
            DaemonError::Composition(error) => error,
            error => CompositionError::Recovery(error.to_string()),
        })?;
    let projection = authority
        .refresh_observation(observation)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let Some(projection) = projection else {
        return Ok(None);
    };
    let revision = projection.revision();
    let fingerprint = projection.fingerprint().to_owned();
    if last_acknowledged.is_some_and(|acknowledged| {
        acknowledged.revision == revision && acknowledged.fingerprint == fingerprint
    }) {
        return Ok(Some((revision, false, fingerprint)));
    }
    let source_selectors = match &observation.source {
        SourceReadback::Available { selectors, .. } => Some(serde_json::json!({
            "after_owner_sequence": selectors.after_owner_sequence,
            "after_event_sequence": selectors.after_event_sequence,
            "page_limit": u32::from(selectors.page_limit),
        })),
        SourceReadback::Unavailable { .. } => None,
    };
    let revision = publish_projection(kernel, &projection, source_selectors).await?;
    Ok(Some((revision, true, fingerprint)))
}

/// Reads one owner-scoped page using only bounded continuation fields and
/// decodes the exact original source DTO. Any transport or decoding failure
/// becomes a typed unavailable observation; it cannot create or restore an
/// adapter identity, and the Governor can use it only to degrade its retained
/// profile.
async fn read_governor_authority_observation(
    kernel: &Arc<DaemonKernelClient>,
    after_owner_sequence: u64,
    after_event_sequence: u64,
) -> GovernorAuthorityObservation {
    let request = GovernorAuthorityObservationRequestWire {
        after_owner_sequence,
        after_event_sequence,
        page_limit: GOVERNOR_AUTHORITY_OBSERVATION_PAGE_LIMIT,
    };
    let unavailable =
        |adapter: Option<AdapterAdmissionIdentity>, reason: &str| GovernorAuthorityObservation {
            adapter,
            source: SourceReadback::Unavailable {
                reason: reason.to_owned(),
            },
            watchdog: EvidenceAvailability::Unavailable {
                reason: reason.to_owned(),
            },
            trace: EvidenceAvailability::Unavailable {
                reason: reason.to_owned(),
            },
        };
    let Ok(response) = kernel
        .transact_async(
            READ_GOVERNOR_AUTHORITY_OBSERVATION_OPERATION,
            serde_json::json!({
                "after_owner_sequence": request.after_owner_sequence,
                "after_event_sequence": request.after_event_sequence,
                "page_limit": request.page_limit,
            }),
        )
        .await
    else {
        return unavailable(None, "authenticated Kernel observation read failed");
    };
    let Ok(value) = kind_value(&response, GOVERNOR_AUTHORITY_OBSERVATION_KIND) else {
        return unavailable(None, "Kernel observation response kind was invalid");
    };
    let wire: GovernorAuthorityObservationResponseWire =
        match serde_json::from_value::<GovernorAuthorityObservationResponseWire>(value) {
            Ok(wire) if wire.schema_version == 1 => wire,
            _ => return unavailable(None, "Kernel observation response schema was invalid"),
        };
    let reason = wire
        .source_reason
        .clone()
        .unwrap_or_else(|| "Kernel source observation unavailable".to_owned());
    let source = match (
        wire.source_status.as_str(),
        wire.source_snapshot,
        wire.source_reason.as_deref(),
    ) {
        ("available", Some(snapshot), None) => match snapshot.as_object() {
            Some(snapshot) if !snapshot.contains_key("status") => {
                let mut source = snapshot.clone();
                source.insert(
                    "status".to_owned(),
                    serde_json::Value::String("available".to_owned()),
                );
                serde_json::Value::Object(source)
            }
            Some(_) | None => {
                return unavailable(
                    wire.admission.clone(),
                    "Kernel observation source page carried an unexpected shape",
                );
            }
        },
        ("unavailable", None, Some(_)) => serde_json::json!({
            "status": "unavailable",
            "reason": reason,
        }),
        _ => {
            return unavailable(
                wire.admission.clone(),
                "Kernel observation status and source page disagreed",
            );
        }
    };
    let observation = serde_json::json!({
        "adapter": wire.admission.clone(),
        "source": source,
        "watchdog": wire.watchdog,
        "trace": wire.trace,
    });
    match serde_json::from_value::<GovernorAuthorityObservation>(observation) {
        Ok(observation) => match &observation.source {
            SourceReadback::Available { selectors, .. }
                if selectors.after_owner_sequence == after_owner_sequence
                    && selectors.after_event_sequence == after_event_sequence
                    && u32::from(selectors.page_limit)
                        == GOVERNOR_AUTHORITY_OBSERVATION_PAGE_LIMIT =>
            {
                observation
            }
            SourceReadback::Available { .. } => unavailable(
                observation.adapter.clone(),
                "Kernel observation selectors did not match the request",
            ),
            SourceReadback::Unavailable { .. } => observation,
        },
        Err(_) => unavailable(wire.admission, "Kernel observation source DTO was invalid"),
    }
}

/// Typed outcome of one daemon-side Governor authority drive pass (issue
/// #1935 AUD1).
///
/// A pass either records the Governor's source-derived revision or skips when
/// neither an active admitted descriptor nor a prior baseline exists.
/// Unavailable or incomplete source pages still reach the Governor and can
/// publish a narrower revision that revokes prior authority.
pub enum GovernorAuthorityDriveOutcome {
    /// The feed derived and the Kernel recorded `revision`.
    FeedPublished { revision: u64 },
    /// The source page derived the already acknowledged exact projection, so
    /// strict Kernel revision ordering requires no duplicate publish.
    FeedUnchanged { revision: u64 },
    /// No owner-issued observation exists, so nothing was published.
    SkippedNoObservation,
}

/// Daemon-side driver for the single live Governor-owned derivation instance
/// (issue #1935 AUD1, I7.16).
///
/// Retains only bounded source continuation cursors. The current profile,
/// original owner rows, and every derivation input remain in their owners.
/// Constructed once per daemon run loop and travels with its drive flight.
#[derive(Default)]
pub struct GovernorAuthorityDriver {
    after_owner_sequence: u64,
    after_event_sequence: u64,
    last_adapter_descriptor: Option<String>,
    last_acknowledged: Option<AcknowledgedProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcknowledgedProjection {
    revision: u64,
    fingerprint: String,
}

impl GovernorAuthorityDriver {
    /// Starts at the first bounded owner/event page.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetches one authenticated Kernel source page and drives the Governor
    /// from that owner-issued DTO. Continuations are retained only as bounded
    /// sequence cursors; owner identities, source rows, and evidence are never
    /// cached or reconstructed in the daemon.
    pub async fn drive_kernel_observation(
        &mut self,
        composition: &mut DaemonComposition,
        kernel: &Arc<DaemonKernelClient>,
    ) -> Result<GovernorAuthorityDriveOutcome, CompositionError> {
        let mut observation = read_governor_authority_observation(
            kernel,
            self.after_owner_sequence,
            self.after_event_sequence,
        )
        .await;
        let adapter_descriptor = observation
            .adapter
            .as_ref()
            .map(|adapter| adapter.descriptor_sha256.clone());
        let adapter_changed = adapter_descriptor.as_ref().is_some_and(|descriptor| {
            self.last_adapter_descriptor
                .as_ref()
                .is_some_and(|previous| previous != descriptor)
        });
        if adapter_changed {
            self.after_owner_sequence = 0;
            self.after_event_sequence = 0;
            observation = read_governor_authority_observation(kernel, 0, 0).await;
        }
        let adapter_descriptor = observation
            .adapter
            .as_ref()
            .map(|adapter| adapter.descriptor_sha256.clone());
        if let Some(descriptor) = adapter_descriptor {
            self.last_adapter_descriptor = Some(descriptor);
        }
        let (next_owner_sequence, next_event_sequence) = match &observation.source {
            SourceReadback::Available { next, .. } => next.as_ref().map_or((0, 0), |next| {
                (next.after_owner_sequence, next.after_event_sequence)
            }),
            SourceReadback::Unavailable { .. } => (0, 0),
        };
        let result = maintain_governor_authority_observation_inner(
            composition,
            kernel,
            &observation,
            self.last_acknowledged.as_ref(),
        )
        .await;
        let Some((revision, published, fingerprint)) = (match result {
            Ok(result) => result,
            Err(error) => {
                self.after_owner_sequence = 0;
                self.after_event_sequence = 0;
                return Err(error);
            }
        }) else {
            self.after_owner_sequence = 0;
            self.after_event_sequence = 0;
            return Ok(GovernorAuthorityDriveOutcome::SkippedNoObservation);
        };
        self.after_owner_sequence = next_owner_sequence;
        self.after_event_sequence = next_event_sequence;
        if published {
            self.last_acknowledged = Some(AcknowledgedProjection {
                revision,
                fingerprint,
            });
            Ok(GovernorAuthorityDriveOutcome::FeedPublished { revision })
        } else {
            Ok(GovernorAuthorityDriveOutcome::FeedUnchanged { revision })
        }
    }
}

/// Publishes one projected revision and verifies the Kernel receipt proves
/// that exact revision.
async fn publish_projection(
    kernel: &Arc<DaemonKernelClient>,
    projection: &eliot_governor::GovernorAuthorityProjection,
    source_selectors: Option<serde_json::Value>,
) -> Result<u64, CompositionError> {
    let payload = serde_json::json!({
        "revision": projection.revision(),
        "fingerprint": projection.fingerprint(),
        "verified": projection.verified(),
        "authorizes_enforcement": projection.authorizes_enforcement(),
        "authorizes_complete_coverage_ops": projection.authorizes_complete_coverage_ops(),
        "source_selectors": source_selectors,
    });
    let value = kernel
        .transact_async(PUBLISH_GOVERNOR_AUTHORITY_OPERATION, payload)
        .await
        .map_err(|error| {
            CompositionError::Recovery(format!("governor authority publish transport: {error}"))
        })?;
    let value = kind_value(&value, GOVERNOR_AUTHORITY_RECEIPT_KIND).map_err(|error| {
        CompositionError::Owner(format!("governor authority receipt kind: {error}"))
    })?;
    let receipt: GovernorAuthorityReceiptWire = serde_json::from_value(value).map_err(|error| {
        CompositionError::Owner(format!(
            "governor authority receipt does not decode: {error}"
        ))
    })?;
    if receipt.status != GOVERNOR_AUTHORITY_RECORDED_STATUS
        || receipt.revision != projection.revision()
    {
        return Err(CompositionError::Recovery(
            "governor authority receipt disagrees with the projected revision".to_owned(),
        ));
    }
    Ok(receipt.revision)
}
