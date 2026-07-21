use crate::EngineError;
use eliot_types::ComponentHealth;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

pub type BoxServiceFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceContext {
    pub service_name: String,
    pub instance_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceHandle {
    pub service_name: String,
    pub started_at: Instant,
}

pub trait ServiceLifecycle: Send + Sync {
    fn service_name(&self) -> &'static str;

    fn start(
        &self,
        ctx: ServiceContext,
    ) -> BoxServiceFuture<'_, Result<ServiceHandle, EngineError>>;

    fn shutdown(&self, deadline: Instant) -> BoxServiceFuture<'_, Result<(), EngineError>>;

    fn health(&self) -> ComponentHealth;
}
