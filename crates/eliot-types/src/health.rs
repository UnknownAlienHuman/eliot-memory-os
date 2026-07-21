use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Starting,
    Ready,
    Degraded,
    NotReady,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub component: String,
    pub status: HealthStatus,
    pub message: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct StartupHealthReport {
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
