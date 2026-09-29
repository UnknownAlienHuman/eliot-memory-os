//! Windows composition of the Broker's selected-resource owner port.
//!
//! Paths remain private in `UserSelectedResourceLease`. Only handle-derived
//! identity and measurement digests cross into the provider-neutral broker
//! core; retained handles stay alive until the one process-start call returns.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_platform_windows::{
    UserSelectedResourceError, UserSelectedResourceKind, UserSelectedResourceLease,
    UserSelectedResourceMeasurement,
};
use eliot_security_contracts::{
    NativeResourceDevicePolicy, NativeResourceKind, NativeResourceNetworkPolicy,
    NativeResourceReparsePolicy, NativeResourceSelectionCandidate,
};
use eliot_user_broker_core::{
    NativeResourceObjectMeasurement, NativeResourceResolutionError, NativeResourceResolverPort,
    OperatorNativeResourceSelectionInput,
};
use serde::Serialize;

const MAX_RETAINED_SELECTIONS: usize = 64;

/// Production per-user owner for no-follow selected-root/object measurements.
pub(super) struct WindowsNativeResourceResolver {
    selections: BTreeMap<String, UserSelectedResourceLease>,
}

impl WindowsNativeResourceResolver {
    pub(super) fn new() -> Self {
        Self {
            selections: BTreeMap::new(),
        }
    }
}

impl NativeResourceResolverPort for WindowsNativeResourceResolver {
    fn owner_now_unix_ms(&mut self) -> Result<u64, NativeResourceResolutionError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .filter(|time| *time != 0)
            .ok_or(NativeResourceResolutionError::Unknown)
    }

    fn premeasure(
        &mut self,
        input: &OperatorNativeResourceSelectionInput,
        not_before: u64,
    ) -> Result<NativeResourceObjectMeasurement, NativeResourceResolutionError> {
        if self.selections.len() >= MAX_RETAINED_SELECTIONS {
            return Err(NativeResourceResolutionError::Unavailable);
        }
        let (lease, physical) = UserSelectedResourceLease::open(
            Path::new(&input.selected_root_path),
            Path::new(&input.selected_object_path),
        )
        .map_err(map_selected_resource_error)?;
        let candidate_ref = uuid::Uuid::new_v4().simple().to_string();
        let measured = project_measurement(candidate_ref.clone(), &physical)?;
        let measured_at = measured
            .measured_at_unix_ms
            .ok_or(NativeResourceResolutionError::Unknown)?;
        if measured_at < not_before {
            return Err(NativeResourceResolutionError::Unknown);
        }
        self.selections.insert(candidate_ref, lease);
        Ok(measured)
    }

    fn remeasure_for_use(
        &mut self,
        candidate: &NativeResourceSelectionCandidate,
        not_before: u64,
    ) -> Result<NativeResourceObjectMeasurement, NativeResourceResolutionError> {
        let lease = self
            .selections
            .get_mut(&candidate.candidate_ref)
            .ok_or(NativeResourceResolutionError::NotFound)?;
        let physical = lease
            .remeasure_for_use()
            .map_err(map_selected_resource_error)?;
        let measured = project_measurement(candidate.candidate_ref.clone(), &physical)?;
        if measured
            .measured_at_unix_ms
            .is_none_or(|measured_at| measured_at < not_before)
        {
            return Err(NativeResourceResolutionError::Unknown);
        }
        Ok(measured)
    }

    fn complete_use(&mut self, candidate_ref: &str) {
        self.selections.remove(candidate_ref);
    }

    fn discard_candidate(&mut self, candidate_ref: &str) {
        self.selections.remove(candidate_ref);
    }
}

fn project_measurement(
    candidate_ref: String,
    physical: &UserSelectedResourceMeasurement,
) -> Result<NativeResourceObjectMeasurement, NativeResourceResolutionError> {
    let measured_at_unix_ms = physical.measured_at_unix_ms;
    if !physical.reparse_free || physical.network || physical.device {
        return Err(NativeResourceResolutionError::Invalid(
            "selected object violates the local no-reparse policy".to_owned(),
        ));
    }
    if physical.root_contour_index >= physical.ancestor_contour.len()
        || physical.ancestor_contour[physical.root_contour_index].identity != physical.root_identity
        || physical.ancestor_contour.last().map(|node| node.identity)
            != Some(physical.object_identity)
    {
        return Err(NativeResourceResolutionError::Unknown);
    }
    if physical.metadata_change_time_filetime_100ns.is_none() {
        return Err(NativeResourceResolutionError::Unknown);
    }
    match physical.object_kind {
        UserSelectedResourceKind::File
            if physical.file_size_bytes.is_some()
                && physical.last_write_filetime_100ns.is_some()
                && physical.directory_generation.is_none() => {}
        UserSelectedResourceKind::Directory
            if physical.file_size_bytes.is_none()
                && physical.last_write_filetime_100ns.is_none() => {}
        _ => return Err(NativeResourceResolutionError::Unknown),
    }

    let contour = physical
        .ancestor_contour
        .iter()
        .map(|node| {
            (
                node.identity,
                match node.kind {
                    UserSelectedResourceKind::File => "file",
                    UserSelectedResourceKind::Directory => "directory",
                },
            )
        })
        .collect::<Vec<_>>();
    let object_kind_name = match physical.object_kind {
        UserSelectedResourceKind::File => "file",
        UserSelectedResourceKind::Directory => "directory",
    };
    let root_identity_digest = digest(&(
        "eliot.user-broker.selected-resource-root-identity.v1",
        physical.root_identity,
        physical.root_contour_index,
        &contour[..=physical.root_contour_index],
    ))?;
    let resource_identity_digest = digest(&(
        "eliot.user-broker.selected-resource-object-identity.v1",
        root_identity_digest.as_str(),
        physical.object_identity,
        object_kind_name,
        &contour,
    ))?;
    let measurement_digest = digest(&(
        "eliot.user-broker.selected-resource-measurement.v1",
        root_identity_digest.as_str(),
        resource_identity_digest.as_str(),
        &contour,
        physical.file_size_bytes,
        physical.last_write_filetime_100ns,
        physical.metadata_change_time_filetime_100ns,
        physical.directory_generation,
        physical.network,
        physical.device,
        physical.reparse_free,
    ))?;
    Ok(NativeResourceObjectMeasurement {
        candidate_ref,
        canonical_root_identity_digest: root_identity_digest,
        canonical_resource_identity_digest: resource_identity_digest,
        measurement_digest,
        resource_kind: match physical.object_kind {
            UserSelectedResourceKind::File => NativeResourceKind::File,
            UserSelectedResourceKind::Directory => NativeResourceKind::Directory,
        },
        reparse_policy: NativeResourceReparsePolicy::Reject,
        network_policy: NativeResourceNetworkPolicy::LocalOnly,
        device_policy: NativeResourceDevicePolicy::Reject,
        measured_at_unix_ms,
    })
}

fn digest<T: Serialize>(value: &T) -> Result<String, NativeResourceResolutionError> {
    let bytes = canonical_json_bytes(value).map_err(|_| NativeResourceResolutionError::Unknown)?;
    Ok(sha256_hex(&bytes))
}

fn map_selected_resource_error(error: UserSelectedResourceError) -> NativeResourceResolutionError {
    match error {
        UserSelectedResourceError::InvalidPath
        | UserSelectedResourceError::NetworkPath
        | UserSelectedResourceError::DevicePath
        | UserSelectedResourceError::ReparsePoint => NativeResourceResolutionError::Invalid(
            "selected object violates the admitted local object policy".to_owned(),
        ),
        UserSelectedResourceError::IdentityMismatch => NativeResourceResolutionError::Substituted,
        UserSelectedResourceError::Io | UserSelectedResourceError::AlreadyRemeasured => {
            NativeResourceResolutionError::Unknown
        }
        UserSelectedResourceError::UnsupportedPlatform => {
            NativeResourceResolutionError::Unavailable
        }
    }
}
