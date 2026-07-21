use eliot_types::{HealthStatus, StartupHealthReport};

pub const fn classify_startup(report: &StartupHealthReport) -> HealthStatus {
    report.overall
}
