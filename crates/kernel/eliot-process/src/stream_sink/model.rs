use std::sync::{Arc, Mutex};

use eliot_contracts::sha256_hex;

use super::{
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionView, ProcessStreamSinkState,
    ProcessStreamSinkTerminal, ProcessStreamSinkUnknownOutcome,
};

#[derive(Default)]
struct ModelState {
    session: Option<ProcessStreamSinkSession>,
    terminal: Option<ProcessStreamSinkTerminal>,
    unknown: Option<ProcessStreamSinkUnknownOutcome>,
}

/// A provider-neutral, stateful sink model for the session/terminal boundary.
///
/// The model stores an externally supplied, validated terminal result and never
/// manufactures evidence. Provider adapters remain responsible for physical
/// stream capture and durable-result authenticity.
#[derive(Clone, Default)]
pub struct ProcessStreamSinkModel {
    state: Arc<Mutex<ModelState>>,
}

impl ProcessStreamSinkModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an uncertain provider result under the already-open session.
    pub fn record_unknown_outcome(
        &self,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> Result<(), ProcessStreamSinkError> {
        let mut state = self.lock();
        let session = state
            .session
            .as_ref()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
        outcome.validate_against_session(session)?;
        if state.terminal.is_some() {
            return Err(ProcessStreamSinkError::Terminal);
        }
        if let Some(existing) = &state.unknown {
            if existing != &outcome {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            return Ok(());
        }
        state.unknown = Some(outcome);
        Ok(())
    }

    /// Records a provider-produced terminal after validating its session fence.
    pub fn record_terminal(
        &self,
        session: &ProcessStreamSinkSession,
        terminal: ProcessStreamSinkTerminal,
    ) -> Result<(), ProcessStreamSinkError> {
        let mut state = self.lock();
        Self::ensure_session(&state, session)?;
        terminal.validate()?;
        if terminal.session_id() != session.session_id()
            || terminal.source_id() != session.source_id()
            || terminal.terminal_id() != session.terminal_id()
            || terminal.open_request_sha256() != session.open_request_sha256()
        {
            return Err(ProcessStreamSinkError::SessionMismatch);
        }
        if state.unknown.is_some() {
            return Err(ProcessStreamSinkError::ProviderUnavailable);
        }
        if let Some(existing) = &state.terminal {
            return if existing == &terminal {
                Ok(())
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        state.terminal = Some(terminal);
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ModelState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn ready<T: Send + 'static>(
        result: Result<T, ProcessStreamSinkError>,
    ) -> ProcessStreamSinkFuture<'static, T> {
        Box::pin(async move { result })
    }

    fn ensure_session(
        state: &ModelState,
        session: &ProcessStreamSinkSession,
    ) -> Result<(), ProcessStreamSinkError> {
        let existing = state
            .session
            .as_ref()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
        if existing != session {
            return Err(ProcessStreamSinkError::SessionMismatch);
        }
        Ok(())
    }
}

impl ProcessStreamSinkClient for ProcessStreamSinkModel {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let mut state = self.lock();
        let result = match state.session.as_ref() {
            Some(existing) if existing.open_request_sha256() == request.open_request_sha256() => {
                Ok(existing.clone())
            }
            Some(_) => Err(ProcessStreamSinkError::OpenDigestMismatch),
            None => ProcessStreamSinkSession::from_open_request(request).inspect(|session| {
                state.session = Some(session.clone());
            }),
        };
        Self::ready(result)
    }

    fn append(
        &self,
        _session: ProcessStreamSinkSession,
        _request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        Self::ready(Err(ProcessStreamSinkError::ProviderUnavailable))
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let state = self.lock();
        let result = Self::ensure_session(&state, &session).and_then(|()| {
            if state.unknown.is_some() {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            if let Some(terminal) = &state.terminal {
                return terminal
                    .validate_against_finalize(&request)
                    .map(|()| terminal.clone());
            }
            Err(ProcessStreamSinkError::ProviderUnavailable)
        });
        Self::ready(result)
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let state = self.lock();
        let result = Self::ensure_session(&state, &session).and_then(|()| {
            if state.unknown.is_some() {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            if let Some(terminal) = &state.terminal {
                return terminal
                    .validate_against_abort(&request)
                    .map(|()| terminal.clone());
            }
            Err(ProcessStreamSinkError::ProviderUnavailable)
        });
        Self::ready(result)
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        let result = Self::ensure_session(&state, &session).and_then(|()| {
            if let Some(unknown) = &state.unknown {
                return Ok(ProcessStreamSinkReadback::UnknownOutcome {
                    outcome: unknown.clone(),
                });
            }
            if let Some(terminal) = &state.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            Ok(ProcessStreamSinkReadback::Session {
                view: ProcessStreamSinkSessionView::new(
                    session.session_id().clone(),
                    session.source_id().clone(),
                    session.terminal_id().clone(),
                    ProcessStreamSinkState::Open,
                    0,
                    0,
                    0,
                    0,
                    sha256_hex(&[]),
                    session.open_request_sha256().to_owned(),
                    None,
                )?,
            })
        });
        Self::ready(result)
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        let result = Self::ensure_session(&state, &session).and_then(|()| {
            outcome.validate_against_session(&session)?;
            if let Some(terminal) = &state.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            if state.unknown.as_ref() != Some(&outcome) {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            Ok(ProcessStreamSinkReadback::UnknownOutcome { outcome })
        });
        Self::ready(result)
    }
}
