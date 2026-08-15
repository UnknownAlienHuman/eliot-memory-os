use anyhow::{Context, Result};
use eliot_engine::{LifecycleService, ServiceSupervisor, shutdown_deadline_after};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

pub struct GovernorComposition {
    data_root: PathBuf,
    instance_id: String,
    lifecycle: LifecycleService,
    supervisor: ServiceSupervisor,
    lock: Option<eliot_engine::RuntimeLock>,
}

impl GovernorComposition {
    pub fn new(data_root: impl Into<PathBuf>, instance_id: impl Into<String>) -> Self {
        let data_root = data_root.into();
        Self {
            lifecycle: LifecycleService::new(&data_root),
            data_root,
            instance_id: instance_id.into(),
            supervisor: ServiceSupervisor::new(eliot_engine::default_runtime_services()),
            lock: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let lock = self
            .lifecycle
            .acquire_single_instance()
            .context("acquire the Governor single-instance lock")?;
        if let Err(error) = self.supervisor.start_all(&self.instance_id).await {
            drop(lock);
            return Err(error).context("start the Governor service supervisor");
        }
        self.lock = Some(lock);
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.lock.is_none() {
            return Ok(());
        }
        self.supervisor
            .shutdown_all(shutdown_deadline_after(SHUTDOWN_GRACE))
            .await
            .context("shut down the Governor service supervisor")?;
        if let Some(lock) = self.lock.take() {
            lock.mark_clean_shutdown()
                .context("record the Governor clean shutdown")?;
        }
        Ok(())
    }

    pub async fn run_until_interrupt(mut self) -> Result<()> {
        self.start().await?;
        let interrupted = tokio::signal::ctrl_c().await;
        let shutdown = self.shutdown().await;
        interrupted.context("wait for Governor shutdown signal")?;
        shutdown
    }

    pub fn status(&self) -> Result<Value> {
        let lifecycle = self
            .lifecycle
            .status()
            .context("read Governor lifecycle status")?;
        Ok(json!({
            "schema_version": "eliot-governor-status-v1",
            "instance_id": self.instance_id,
            "data_root": self.data_root,
            "lifecycle": lifecycle,
            "services": self.supervisor.service_statuses(),
        }))
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }
}
