//! Bounded OpenCode model-catalogue collection for owner-authored admission.
//!
//! This module consumes the current route/billing/quota context supplied by
//! its owner and makes one bounded read through OpenCode's authenticated
//! `/global/health` and `/provider` surfaces. The resulting model snapshot is
//! source observation only; it does not mint an owner reference, currentness
//! receipt, account record, staffing plan, or dispatch authority. OpenCode's
//! provider-catalogue API exposes no provider-account metadata, so the account
//! axis remains an explicit typed `Unavailable` observation.

use eliot_agent_coordinator::{ModelCatalogueSnapshot, ModelControlError, ZeroModelExecutionCounters};
use eliot_agent_opencode::{
    OpenCodeCatalogueCollection, OpenCodeCatalogueContext, OpenCodeCatalogueError,
    OpenCodeClient, OPENCODE_CATALOGUE_COLLECTION_VERSION,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const OPENCODE_MODEL_ACCOUNT_OBSERVATION_SCHEMA_V1: &str =
    "eliot.opencode-model-account-catalogue-observation.v1";
pub const PROVIDER_ACCOUNT_OBSERVATION_SCHEMA_V1: &str =
    "eliot.provider-account-catalogue.observation.v1";
pub const OPENCODE_PROVIDER_CATALOGUE_SOURCE_V1: &str = "opencode-provider-catalogue/v1";
pub const PROVIDER_ACCOUNT_METADATA_UNAVAILABLE_REASON: &str =
    "source_exposes_no_account_metadata";

#[derive(Debug, Error)]
pub enum OpenCodeModelCatalogueObservationError {
    #[error(transparent)]
    Collection(#[from] OpenCodeCatalogueError),
    #[error(transparent)]
    ModelCatalogue(#[from] ModelControlError),
    #[error("OpenCode catalogue collection is not the bounded observation contract")]
    InvalidCollection,
    #[error("OpenCode account-unavailable observation does not bind the model snapshot")]
    InvalidAccountObservation,
    #[error("OpenCode model catalogue canonical JSON is not UTF-8")]
    InvalidUtf8,
    #[error("OpenCode model catalogue canonical serialization failed: {0}")]
    Serialization(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAccountCatalogueObservationKindV1 {
    Unavailable,
}

/// Honest account-axis result from the OpenCode provider catalogue surface.
/// No account id, billing state, quota, credential state, or source-contract
/// reference is manufactured when the endpoint does not return those facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeProviderAccountCatalogueUnavailableV1 {
    pub kind: ProviderAccountCatalogueObservationKindV1,
    pub schema: String,
    pub source: String,
    pub reason: String,
    pub model_catalogue_snapshot_id: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Source-produced catalogue data plus the explicit account-data gap.
///
/// `snapshot_sha256` covers the exact canonical UTF-8 bytes in
/// `snapshot_json`. `snapshot` is retained for typed consumers and is checked
/// against those same bytes by `validate`, so the two projections cannot
/// silently diverge. An owning Governor may wrap this observation in its
/// independently retained, fenced readback; this value alone is not one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeModelCatalogueObservationV1 {
    pub schema: String,
    pub collection: OpenCodeCatalogueCollection,
    pub snapshot_json: String,
    pub snapshot_sha256: String,
    pub provider_accounts: OpenCodeProviderAccountCatalogueUnavailableV1,
}

impl OpenCodeModelCatalogueObservationV1 {
    fn from_collection(
        collection: OpenCodeCatalogueCollection,
    ) -> Result<Self, OpenCodeModelCatalogueObservationError> {
        let snapshot = &collection.snapshot;
        let account_observation = OpenCodeProviderAccountCatalogueUnavailableV1 {
            kind: ProviderAccountCatalogueObservationKindV1::Unavailable,
            schema: PROVIDER_ACCOUNT_OBSERVATION_SCHEMA_V1.to_owned(),
            source: OPENCODE_PROVIDER_CATALOGUE_SOURCE_V1.to_owned(),
            reason: PROVIDER_ACCOUNT_METADATA_UNAVAILABLE_REASON.to_owned(),
            model_catalogue_snapshot_id: snapshot.snapshot_id.clone(),
            observed_at_unix_ms: snapshot.observed_at_unix_ms,
            expires_at_unix_ms: snapshot.expires_at_unix_ms,
        };
        let snapshot_bytes = canonical_json_bytes(snapshot)
            .map_err(|error| OpenCodeModelCatalogueObservationError::Serialization(error.to_string()))?;
        let snapshot_json = String::from_utf8(snapshot_bytes.clone())
            .map_err(|_| OpenCodeModelCatalogueObservationError::InvalidUtf8)?;
        let observation = Self {
            schema: OPENCODE_MODEL_ACCOUNT_OBSERVATION_SCHEMA_V1.to_owned(),
            collection,
            snapshot_json,
            snapshot_sha256: sha256_hex(&snapshot_bytes),
            provider_accounts: account_observation,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), OpenCodeModelCatalogueObservationError> {
        if self.schema != OPENCODE_MODEL_ACCOUNT_OBSERVATION_SCHEMA_V1
            || self.collection.schema_version != OPENCODE_CATALOGUE_COLLECTION_VERSION
            || self.collection.execution != ZeroModelExecutionCounters::zero()
        {
            return Err(OpenCodeModelCatalogueObservationError::InvalidCollection);
        }
        self.collection.snapshot.validate()?;
        let snapshot_bytes = canonical_json_bytes(&self.collection.snapshot)
            .map_err(|error| OpenCodeModelCatalogueObservationError::Serialization(error.to_string()))?;
        let canonical_json = String::from_utf8(snapshot_bytes.clone())
            .map_err(|_| OpenCodeModelCatalogueObservationError::InvalidUtf8)?;
        if self.snapshot_json != canonical_json || self.snapshot_sha256 != sha256_hex(&snapshot_bytes)
        {
            return Err(OpenCodeModelCatalogueObservationError::InvalidCollection);
        }
        let snapshot = &self.collection.snapshot;
        if self.provider_accounts.kind != ProviderAccountCatalogueObservationKindV1::Unavailable
            || self.provider_accounts.schema != PROVIDER_ACCOUNT_OBSERVATION_SCHEMA_V1
            || self.provider_accounts.source != OPENCODE_PROVIDER_CATALOGUE_SOURCE_V1
            || self.provider_accounts.reason != PROVIDER_ACCOUNT_METADATA_UNAVAILABLE_REASON
            || self.provider_accounts.model_catalogue_snapshot_id != snapshot.snapshot_id
            || self.provider_accounts.observed_at_unix_ms != snapshot.observed_at_unix_ms
            || self.provider_accounts.expires_at_unix_ms != snapshot.expires_at_unix_ms
        {
            return Err(OpenCodeModelCatalogueObservationError::InvalidAccountObservation);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> &ModelCatalogueSnapshot {
        &self.collection.snapshot
    }
}

/// Reads live OpenCode catalogue data under a caller-supplied owner context.
/// The client owns bounded transport timeouts and authentication; this module
/// neither loads credentials nor creates route/account policy.
pub async fn collect_opencode_model_catalogue_observation(
    client: &OpenCodeClient,
    context: &OpenCodeCatalogueContext,
) -> Result<OpenCodeModelCatalogueObservationV1, OpenCodeModelCatalogueObservationError> {
    context.validate()?;
    let collection = client.model_catalogue(context).await?;
    let observation = OpenCodeModelCatalogueObservationV1::from_collection(collection)?;
    if observation.snapshot().snapshot_id != context.snapshot_id
        || observation.snapshot().account_scope != context.account_scope
        || observation.snapshot().observed_at_unix_ms != context.observed_at_unix_ms
        || observation.snapshot().expires_at_unix_ms != context.expires_at_unix_ms
    {
        return Err(OpenCodeModelCatalogueObservationError::InvalidCollection);
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_agent_coordinator::MODEL_CATALOGUE_SCHEMA_VERSION;

    fn collection() -> OpenCodeCatalogueCollection {
        OpenCodeCatalogueCollection {
            schema_version: OPENCODE_CATALOGUE_COLLECTION_VERSION.to_owned(),
            snapshot: ModelCatalogueSnapshot {
                schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
                snapshot_id: "owner-snapshot-1".to_owned(),
                account_scope: "owner-account-scope".to_owned(),
                collector_identity: "opencode-provider-catalogue/v1".to_owned(),
                observed_at_unix_ms: 10_000,
                expires_at_unix_ms: 20_000,
                entries: Vec::new(),
            },
            omissions: Vec::new(),
            execution: ZeroModelExecutionCounters::zero(),
        }
    }

    #[test]
    fn observed_catalogue_keeps_account_metadata_explicitly_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = OpenCodeModelCatalogueObservationV1::from_collection(collection())?;
        observation.validate()?;
        assert_eq!(observation.snapshot().snapshot_id, "owner-snapshot-1");
        assert_eq!(
            observation.provider_accounts.kind,
            ProviderAccountCatalogueObservationKindV1::Unavailable
        );
        assert_eq!(
            observation.provider_accounts.reason,
            PROVIDER_ACCOUNT_METADATA_UNAVAILABLE_REASON
        );
        assert_eq!(
            observation.snapshot_sha256,
            sha256_hex(observation.snapshot_json.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn catalogue_with_model_execution_counters_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collection = collection();
        collection.execution.model_calls = 1;
        assert!(matches!(
            OpenCodeModelCatalogueObservationV1::from_collection(collection),
            Err(OpenCodeModelCatalogueObservationError::InvalidCollection)
        ));
        Ok(())
    }
}
