use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

/// Bounded refusal for a startup health report schema version this build does
/// not own.
///
/// The doctor report is read back as this build's liveness, readiness and
/// freshness verdict, so a report written under an incompatible schema must fail
/// closed at the decoder instead of being read as a current `overall`. The
/// message is fixed and never echoes the received version back onto an operator
/// surface.
fn unsupported_schema_version<E>(expected: &str) -> E
where
    E: de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

/// Refuse a report whose `schema_version` is not the one this build owns.
///
/// The accepted spelling is unchanged: the report's only producer writes
/// [`crate::SCHEMA_VERSION`], so exactly the value that has always decoded still
/// decodes. No legacy migration is introduced and no version value is invented —
/// the bound is the constant the writer already emits.
fn deserialize_startup_health_schema_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == crate::SCHEMA_VERSION {
        Ok(value)
    } else {
        Err(unsupported_schema_version(crate::SCHEMA_VERSION))
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Starting,
    Ready,
    Degraded,
    NotReady,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentHealth {
    pub component: String,
    pub status: HealthStatus,
    pub message: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupHealthReport {
    #[serde(deserialize_with = "deserialize_startup_health_schema_version")]
    pub schema_version: String,
    pub service_name: String,
    pub instance_id: String,
    pub components: Vec<ComponentHealth>,
    pub overall: HealthStatus,
}

impl StartupHealthReport {
    pub fn new(
        schema_version: impl Into<String>,
        service_name: impl Into<String>,
        instance_id: impl Into<String>,
        components: Vec<ComponentHealth>,
    ) -> Self {
        let overall = if components
            .iter()
            .any(|component| component.status == HealthStatus::NotReady)
        {
            HealthStatus::NotReady
        } else if components
            .iter()
            .any(|component| component.status == HealthStatus::Degraded)
        {
            HealthStatus::Degraded
        } else if components
            .iter()
            .any(|component| component.status == HealthStatus::Starting)
        {
            HealthStatus::Starting
        } else {
            HealthStatus::Ready
        };

        Self {
            schema_version: schema_version.into(),
            service_name: service_name.into(),
            instance_id: instance_id.into(),
            components,
            overall,
        }
    }
}
