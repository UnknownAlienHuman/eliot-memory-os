//! Provider-neutral Windows service receipt and validation facade.
//!
//! Architecture anchors: `A2.3` (named module ownership), `A13.2` (Kernel and
//! failure domains), and `A13.3` (module supervision). Implementation anchors:
//! `I1.1` (process/service distinction), `I1.4` (SCM supervision topology), and
//! `I1.8` (exact ownership and call paths).
//!
//! This child owns only `WindowsServiceManager` configuration validation and
//! inert install, control, and status receipts. It does not mutate SCM, launch
//! processes, select artifacts, or own installation, Host, or Kernel authority.

use std::path::Path;

use eliot_types::{
    ServiceAccountRef, ServiceInstallAction, ServiceInstallReceipt, ServiceInstallStatus,
    ServiceRestartPolicy, ServiceStartType, ServiceStatusReport, WindowsServiceConfig,
};
use time::OffsetDateTime;

pub struct WindowsServiceManager {
    config: WindowsServiceConfig,
}

impl WindowsServiceManager {
    #[must_use]
    pub fn new(config: WindowsServiceConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn default_config(data_root: &Path, executable_path: &Path) -> WindowsServiceConfig {
        WindowsServiceConfig {
            service_name: "EliotGovernor".to_owned(),
            display_name: "ELIOT Governor".to_owned(),
            description: "Local ELIOT Governor production runtime service".to_owned(),
            executable_path: executable_path.display().to_string(),
            arguments: vec!["service".to_owned(), "run".to_owned()],
            account: ServiceAccountRef::CurrentUser,
            start_type: ServiceStartType::Manual,
            restart_policy: ServiceRestartPolicy::default(),
            data_root: data_root.display().to_string(),
            log_root: data_root.join("logs").display().to_string(),
            ipc: super::default_ipc_config(data_root),
        }
    }

    #[must_use]
    pub fn config(&self) -> &WindowsServiceConfig {
        &self.config
    }

    #[must_use]
    pub fn validate(&self) -> ServiceInstallReceipt {
        let (warnings, errors) = super::validate_service_config(&self.config);
        let status = if errors.is_empty() {
            ServiceInstallStatus::Succeeded
        } else {
            ServiceInstallStatus::Failed
        };
        self.receipt(ServiceInstallAction::Validate, status, warnings, errors)
    }

    #[must_use]
    pub fn install(&self, dry_run: bool) -> ServiceInstallReceipt {
        let (mut warnings, errors) = super::validate_service_config(&self.config);
        if !errors.is_empty() {
            return self.receipt(
                ServiceInstallAction::Install,
                ServiceInstallStatus::Failed,
                warnings,
                errors,
            );
        }
        if dry_run {
            return self.receipt(
                ServiceInstallAction::Install,
                ServiceInstallStatus::DryRun,
                warnings,
                errors,
            );
        }

        warnings.push(
            "H1 engine does not mutate Windows SCM; use admin service runner for real install"
                .to_owned(),
        );
        self.receipt(
            ServiceInstallAction::Install,
            ServiceInstallStatus::SucceededWithWarnings,
            warnings,
            errors,
        )
    }

    #[must_use]
    pub fn uninstall(&self, dry_run: bool) -> ServiceInstallReceipt {
        let status = if dry_run {
            ServiceInstallStatus::DryRun
        } else {
            ServiceInstallStatus::SucceededWithWarnings
        };
        let warnings = if dry_run {
            Vec::new()
        } else {
            vec![
                "H1 engine reports uninstall intent only; SCM mutation is admin CLI only"
                    .to_owned(),
            ]
        };
        self.receipt(
            ServiceInstallAction::Uninstall,
            status,
            warnings,
            Vec::new(),
        )
    }

    #[must_use]
    pub fn control(&self, action: ServiceInstallAction) -> ServiceInstallReceipt {
        let warnings = vec![
            "H1 does not start/stop SCM from ordinary process; admin CLI boundary is preserved"
                .to_owned(),
        ];
        self.receipt(
            action,
            ServiceInstallStatus::SucceededWithWarnings,
            warnings,
            Vec::new(),
        )
    }

    #[must_use]
    pub fn status(&self) -> ServiceStatusReport {
        let receipt = self.receipt(
            ServiceInstallAction::Status,
            ServiceInstallStatus::SucceededWithWarnings,
            vec!["SCM query is bounded to local status report in H1 tests".to_owned()],
            Vec::new(),
        );
        ServiceStatusReport {
            component: "service_status".to_owned(),
            config: self.config.clone(),
            installed: false,
            running: false,
            install_receipt: receipt,
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    fn receipt(
        &self,
        action: ServiceInstallAction,
        status: ServiceInstallStatus,
        warnings: Vec<String>,
        errors: Vec<String>,
    ) -> ServiceInstallReceipt {
        let created_at = OffsetDateTime::now_utc();
        ServiceInstallReceipt {
            receipt_id: super::id("service-receipt", created_at),
            service_name: self.config.service_name.clone(),
            action,
            status,
            config_ref: super::config_ref(&self.config),
            warnings,
            errors,
            created_at,
        }
    }
}
