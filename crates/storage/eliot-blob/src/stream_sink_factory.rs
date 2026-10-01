//! Bounded session factory for one shared Blob stream-sink owner.
//!
//! `BlobStoreStreamSink` intentionally owns one process-stream session. This
//! module routes each checked session identity to one such adapter while every
//! adapter shares clones of the same `BlobStoreService`. Per-session Blob
//! receipts, policy, residency and root lease come only from the injected
//! authenticated binding provider; this factory mints none of them.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};

use eliot_blob_api::BlobStoreClient;
use eliot_process::{
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkTerminal, ProcessStreamSinkUnknownOutcome,
};

use crate::stream_sink::{BlobStreamSinkStoreBinding, BlobStoreStreamSink};

/// Provides the exact owner-issued Blob bindings for one admitted stream.
/// Implementations must resolve the request against current authenticated
/// operation context and fail closed when any source is absent or stale.
pub trait BlobStreamSinkBindingProvider: Send + Sync {
    /// Binds the stream session to its root lease, stage/read contexts,
    /// policy, and residency identity.
    fn bind(
        &self,
        request: &ProcessStreamSinkOpenRequest,
    ) -> Result<BlobStreamSinkStoreBinding, ProcessStreamSinkError>;
}

/// Routes process stream sessions to adapters backed by one shared Blob
/// service. The map has a hard capacity; it never evicts an open or
/// unresolved session to make room for a new one.
pub struct BlobStreamSinkFactory<C> {
    store: C,
    bindings: Arc<dyn BlobStreamSinkBindingProvider>,
    max_sessions: NonZeroUsize,
    sessions: Mutex<BTreeMap<String, Arc<BlobStoreStreamSink<C>>>>,
}

impl<C> BlobStreamSinkFactory<C>
where
    C: BlobStoreClient + Clone + Send + Sync + 'static,
{
    /// Shares an existing Blob service handle and binds a hard session bound.
    pub fn new(
        store: C,
        bindings: Arc<dyn BlobStreamSinkBindingProvider>,
        max_sessions: NonZeroUsize,
    ) -> Self {
        Self {
            store,
            bindings,
            max_sessions,
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<BlobStoreStreamSink<C>>>> {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn adapter(
        &self,
        session: &ProcessStreamSinkSession,
    ) -> Result<Arc<BlobStoreStreamSink<C>>, ProcessStreamSinkError> {
        self.lock()
            .get(session.session_id().as_str())
            .cloned()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)
    }

    fn remove_if_same(&self, key: &str, adapter: &Arc<BlobStoreStreamSink<C>>) {
        let mut sessions = self.lock();
        if sessions
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, adapter))
        {
            sessions.remove(key);
        }
    }

    /// Retires a session only after the adapter reports a durable terminal.
    /// Callers use this after persisting the terminal evidence with its job;
    /// open and unknown outcomes remain retained for reconciliation.
    pub async fn retire_terminal_session(
        &self,
        session: &ProcessStreamSinkSession,
    ) -> Result<bool, ProcessStreamSinkError> {
        let adapter = self.adapter(session)?;
        let readback = adapter.readback(session.clone()).await?;
        if !matches!(readback, ProcessStreamSinkReadback::Terminal { .. }) {
            return Ok(false);
        }
        self.remove_if_same(session.session_id().as_str(), &adapter);
        Ok(true)
    }
}

impl<C> ProcessStreamSinkClient for BlobStreamSinkFactory<C>
where
    C: BlobStoreClient + Clone + Send + Sync + 'static,
{
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        if let Err(error) = request.validate() {
            return Box::pin(async move { Err(error) });
        }
        let key = request.session_id().as_str().to_owned();
        let adapter = {
            let mut sessions = self.lock();
            if let Some(adapter) = sessions.get(&key) {
                Arc::clone(adapter)
            } else {
                if sessions.len() >= self.max_sessions.get() {
                    return Box::pin(async { Err(ProcessStreamSinkError::ProviderUnavailable) });
                }
                let binding = match self.bindings.bind(&request) {
                    Ok(binding) => binding,
                    Err(error) => return Box::pin(async move { Err(error) }),
                };
                let adapter = Arc::new(BlobStoreStreamSink::new(self.store.clone(), binding));
                sessions.insert(key.clone(), Arc::clone(&adapter));
                adapter
            }
        };
        Box::pin(async move { adapter.open(request).await })
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let adapter = match self.adapter(&session) {
            Ok(adapter) => adapter,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move { adapter.append(session, request).await })
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let adapter = match self.adapter(&session) {
            Ok(adapter) => adapter,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move { adapter.finalize(session, request).await })
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let adapter = match self.adapter(&session) {
            Ok(adapter) => adapter,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move { adapter.abort(session, request).await })
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let adapter = match self.adapter(&session) {
            Ok(adapter) => adapter,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move { adapter.readback(session).await })
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let adapter = match self.adapter(&session) {
            Ok(adapter) => adapter,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move { adapter.reconcile(session, outcome).await })
    }
}
