use super::supervised_process::SupervisedWindowsProcessRunner;
use anyhow::Result;
use eliot_engine::{OperationRuntimeHandle, ProviderProcessRunner};
use std::path::Path;
use std::sync::Arc;

/// Composition owner for every provider process route. Callers may select a
/// policy and build a process spec, but they cannot construct a production
/// runner independently.
#[derive(Clone)]
pub(crate) struct ProviderRuntime {
    runner: Arc<dyn ProviderProcessRunner>,
    operation_runtime: OperationRuntimeHandle,
}

impl ProviderRuntime {
    pub(crate) fn production(config_path: &Path) -> Result<Self> {
        let operation_runtime =
            super::supervised_process::daemon_operation_runtime_handle(config_path)?;
        Ok(Self::from_runtime_store(operation_runtime))
    }

    pub(crate) fn from_runtime_store(operation_runtime: OperationRuntimeHandle) -> Self {
        let runner: Arc<dyn ProviderProcessRunner> = Arc::new(
            SupervisedWindowsProcessRunner::from_runtime_store(operation_runtime.clone()),
        );
        Self {
            runner,
            operation_runtime,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted(runner: Arc<dyn ProviderProcessRunner>) -> Self {
        Self {
            runner,
            operation_runtime: OperationRuntimeHandle::disabled(),
        }
    }

    pub(crate) fn runner(&self) -> Arc<dyn ProviderProcessRunner> {
        Arc::clone(&self.runner)
    }

    pub(crate) fn operation_runtime(&self) -> OperationRuntimeHandle {
        self.operation_runtime.clone()
    }
}
