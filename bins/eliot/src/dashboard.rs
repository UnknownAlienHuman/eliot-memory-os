//! `eliot dashboard` — state-free terminal renderer of the served
//! `ControlBoard` projection (issue #1783, I11.1, I11.2, I11.8).
//!
//! This module is the optional lightweight terminal surface I11.1 permits. It
//! is a **reader**: it owns no board handle, no cache, no store, no provider,
//! and no action path. Every row it draws comes from one authenticated
//! `controlboard.status` answer that
//! [`controlboard_status::decode_status_response`](crate::controlboard_status::decode_status_response)
//! already decoded with the owner's own message type and contract constants,
//! over the same
//! [`transact_controlboard_status`](crate::AuthenticatedKernelPort::transact_controlboard_status)
//! front door the JSON `controlboard status` command uses. The dashboard
//! therefore shows the same permitted row identities, dispositions, source /
//! view / fence / revision bindings and authority limitations as any other
//! client of that view.
//!
//! What the renderer deliberately does **not** do:
//!
//! * It does not filter, re-scope, or widen the projection. Role/privacy
//!   admission happens in `ControlBoard::view` upstream; there is no CLI role
//!   flag, hidden widget, or local filter that could grant access.
//! * It does not derive health, readiness, support, authority, or product
//!   state from colour, counts, or process presence. Dispositions render as
//!   their typed `label()` text, in one plain style, with no colour at all.
//! * It does not merge sections across view revisions. Exactly one served
//!   snapshot is in scope at a time and a replacement is atomic, so no
//!   partial-coverage merge across mismatched revisions is possible.
//! * It does not create persistent domain state. Section selection, scroll
//!   offset and refresh are local UI state, discarded on exit.
//!
//! Truthfulness of the sections: the served `RenderedControlBoard` carries one
//! un-sectioned, denominator-reconciled row projection and the typed canonical
//! notification inbox. Notifications are rendered from that inbox, including
//! its board-derived metrics and owner-reported lifecycle/delivery state. Every
//! other I11.2 section is an explicit `UNAVAILABLE` marker with its owner
//! limitation — never an empty list that could read as healthy — and the
//! served rows are shown in their own clearly separate section. Section rows
//! stay their owning producer's work (#1213 and the semantic owners); this
//! layout cannot manufacture them.
//!
//! Terminal ownership: raw mode and the alternate screen are entered only
//! after a board is already in hand and are released by a scoped guard on
//! normal exit, on a handled error, and on an unwinding panic. A restore
//! failure is reported separately from the primary transport/rendering error
//! so it can never hide the real cause. Under redirected or noninteractive
//! output the command never enters raw mode and returns a non-success usage
//! response pointing at the existing JSON status command.

use std::io::{self, IsTerminal, Write};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::Print;
use crossterm::{cursor, execute, queue, terminal};
use eliot_cli::kernel_client::KernelClientError;
use eliot_cli::{CommandCatalogue, CommandId, CommandPortError};
use eliot_runtime_status::RenderedControlBoard;

use super::controlboard_status;

/// Non-success code for redirected/noninteractive output, where the terminal
/// surface cannot be entered at all.
const NON_TERMINAL_CODE: &str = "DASHBOARD_REQUIRES_INTERACTIVE_TERMINAL";
/// Non-success code when the terminal cannot be switched into the bounded
/// surface mode. Recovery is the caller's; nothing is installed or repaired.
const TERMINAL_SETUP_REFUSED: &str = "DASHBOARD_TERMINAL_SETUP_REFUSED";
/// Non-success code when the terminal could not be put back the way it was
/// found. Reported separately so it never masks the primary failure.
const TERMINAL_RESTORE_FAILED: &str = "DASHBOARD_TERMINAL_RESTORE_FAILED";
/// Longest untrusted payload field rendered on one screen line.
const MAX_DISPLAY_CHARS: usize = 160;
/// How long one loop turn waits for a key before redrawing. Bounded so an
/// outstanding refresh is reaped and the terminal stays responsive.
const INPUT_POLL: Duration = Duration::from_millis(100);
/// Finite deadline for one outstanding refresh. A late answer is dropped, not
/// admitted, so a redraw can never renew evidence.
const REFRESH_DEADLINE: Duration = Duration::from_secs(10);
/// Reason recorded when a refresh answer arrives past its deadline.
const REFRESH_DEADLINE_EXCEEDED: &str = "refresh answer arrived after the finite deadline and was not admitted; the snapshot below is stale";
/// Reason recorded when the refresh worker died without an answer.
const REFRESH_WORKER_PANICKED: &str = "the refresh read did not return an answer";
/// Key line shown on the last screen row.
const KEYS_LINE: &str = "keys: Left/Right section, Up/Down scroll, r refresh, q/Esc/Ctrl-C quit";

/// One navigable I11.2 section plus the exact reason the currently served
/// `controlboard.status` projection cannot supply it, when unavailable.
struct Section {
    /// I11.2 section name, reproduced from the normative section list.
    name: &'static str,
    /// Owner limitation shown while this section is displayed. It names the
    /// residual owner; it never claims the section is empty or healthy.
    limitation: &'static str,
}

/// Name of the one section the current transport really serves.
///
/// Its rows are the reconciled, role-filtered `controlboard.status` rows. The
/// transport carries no section discriminator, so they are shown under this
/// name and attributed to no I11.2 section.
const SERVED_ROWS_SECTION_NAME: &str = "Board rows";

/// The I11.2 named sections, in the normative order.
///
/// Notifications are carried as a typed canonical inbox. Review and
/// change-lineage data are not sectioned by the served projection, and no
/// accepted producer exists for the remaining sections. The residual section
/// projection is named per section; the semantic data stays with its owner.
const SECTIONS: &[Section] = &[
    Section {
        name: "Product",
        limitation: "no accepted producer publishes Product Objective, Identity, delta, Proof or boundary-gap rows; that semantic owner has no section projection",
    },
    Section {
        name: "System",
        limitation: "no accepted producer publishes Host/Kernel/DB/module/queue/backup rows; that semantic owner has no section projection",
    },
    Section {
        name: "Integrations",
        limitation: "no accepted producer publishes agent/hook/tool/model or Governance Profile rows; that semantic owner has no section projection",
    },
    Section {
        name: "Tasks",
        limitation: "no accepted producer publishes goal, plan, causal property, progress or finish-readiness rows; that semantic owner has no section projection",
    },
    Section {
        name: "Development",
        limitation: "no accepted producer publishes repeat-repair, activity ratio, zero-test or Mechanism Review rows; that semantic owner has no section projection",
    },
    Section {
        name: "Agents/Swarm",
        limitation: "no accepted producer publishes session, partition, budget or delivery-gap rows; that semantic owner has no section projection",
    },
    Section {
        name: "Review",
        limitation: "eliot-controlboard ControlBoardView.reviews exists, but the controlboard.status consumer merges items and reviews into one un-sectioned row set, so review items are not separable here; the section projection is residual work of #1213",
    },
    Section {
        name: "Change lineage",
        limitation: "eliot-controlboard ControlBoardView.provenance exists, but the controlboard.status transport carries no provenance section; the section projection is residual work of #1213",
    },
    Section {
        name: "Attention",
        limitation: "no accepted producer publishes blocking-obligation or conflict rows; that semantic owner has no section projection",
    },
    Section {
        name: "Problems/Incidents",
        limitation: "no accepted producer publishes owner, evidence, repair or next-action rows; that semantic owner has no section projection",
    },
    Section {
        name: "Memory",
        limitation: "no accepted producer publishes candidate, conflict, stale/poisoned influence or curation rows; that semantic owner has no section projection",
    },
    Section {
        name: "Architecture / Implementation",
        limitation: "no accepted producer publishes accepted revision, conformance gap, default, Research Gate or deviation rows; that semantic owner has no section projection",
    },
    Section {
        name: "Costs",
        limitation: "no accepted producer publishes model/cloud usage or remaining-authority rows; that semantic owner has no section projection",
    },
    Section {
        name: "Notifications",
        limitation: "the served board includes the canonical notification inbox and its locally derived metrics",
    },
];

/// Why the displayed snapshot is not a current observation.
enum SnapshotState {
    /// The last read answered inside its deadline and this is that answer.
    Current,
    /// A read is outstanding; the displayed snapshot is unchanged.
    Refreshing,
    /// The read did not answer inside its finite deadline.
    DeadlineExceeded,
    /// The displayed snapshot is the last successful answer and is **stale**.
    /// A redraw never clears this and never extends its observation time.
    Stale(String),
}

/// One served board plus the view-fence text reproduced from the same message.
struct Snapshot {
    /// The reconciled board exactly as the owner's decode returned it.
    board: RenderedControlBoard,
    /// The same view fence the JSON command emits, serialized once per read.
    view_fence: String,
}

impl Snapshot {
    /// Wraps one decoded board, serializing its view fence verbatim.
    fn new(board: RenderedControlBoard) -> Result<Self> {
        let view_fence = serde_json::to_string(&board.view_fence)
            .context("encode the served controlboard view fence")?;
        Ok(Self { board, view_fence })
    }

    /// The served row observation time, taken from the served rows and
    /// reported only as the value the owner stamped on them.
    fn served_observed_at(&self) -> Option<String> {
        self.board
            .rows
            .first()
            .map(|row| row.observed_at.get().to_string())
    }
}

/// Typed non-success the dashboard reports instead of a board.
///
/// Each code and exit class is the one the existing `controlboard status` JSON
/// command emits for the same condition, so a terminal caller and a JSON
/// caller observe one failure identity. Absence of the backend is reported
/// here; nothing is installed, launched, or repaired.
struct TypedFailure {
    /// Stable machine-readable code.
    code: &'static str,
    /// Diagnostic detail; never persisted, never re-read as authority.
    detail: String,
    /// Process exit class.
    exit_code: i32,
}

impl std::fmt::Display for TypedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

/// Maps a front-door load failure onto the shared typed code and exit class.
fn port_failure(error: CommandPortError) -> TypedFailure {
    match error {
        CommandPortError::FrontDoorClosed { contract } => TypedFailure {
            code: "KERNEL_APPLICATION_PORT_CLOSED",
            detail: contract.to_owned(),
            exit_code: super::FRONT_DOOR_CLOSED_EXIT,
        },
        CommandPortError::Rejected(detail) => TypedFailure {
            code: "KERNEL_CLIENT_CONFIGURATION_REJECTED",
            detail,
            exit_code: super::FRONT_DOOR_CLOSED_EXIT,
        },
    }
}

/// Maps a transact failure onto the shared typed code and exit class.
fn transact_failure(error: KernelClientError) -> TypedFailure {
    match error {
        KernelClientError::FrontDoorClosed(contract) => TypedFailure {
            code: "KERNEL_APPLICATION_PORT_CLOSED",
            detail: contract.to_owned(),
            exit_code: super::FRONT_DOOR_CLOSED_EXIT,
        },
        KernelClientError::UnknownOutcome(detail) => TypedFailure {
            code: "CONTROLBOARD_STATUS_UNKNOWN",
            detail,
            exit_code: super::UNKNOWN_OUTCOME_EXIT,
        },
        KernelClientError::MissingRequestIdentity => TypedFailure {
            code: "CONTROLBOARD_STATUS_NOT_ADMITTED",
            detail: "no admitted EBP request identity is bound for an operator-initiated controlboard read; the identity must arrive through the admitted host request path and Ramanujan must serve controlboard.status; tracker #1213".to_owned(),
            exit_code: super::INVALID_REQUEST_EXIT,
        },
        error => TypedFailure {
            code: "CONTROLBOARD_STATUS_REJECTED",
            detail: error.to_string(),
            exit_code: super::INVALID_REQUEST_EXIT,
        },
    }
}

/// Reads exactly one board over the authenticated `controlboard.status` path.
///
/// This is the same transport and the same owner decode the JSON status
/// command uses; no second routing, no local status store, and no re-created
/// dependency on the older `eliot-controlboard` fixture. The request identity,
/// role and capability set arrive with the client binding, never from a CLI
/// flag: an unbound identity fails closed before any byte is sent.
fn fetch_snapshot() -> Result<Snapshot, TypedFailure> {
    #[cfg(windows)]
    {
        let mut port = super::AuthenticatedKernelPort::load().map_err(port_failure)?;
        let served = port
            .transact_controlboard_status()
            .map_err(transact_failure)?;
        let board =
            controlboard_status::decode_status_response(served).map_err(|error| TypedFailure {
                code: "CONTROLBOARD_STATUS_REFUSED",
                detail: error.to_string(),
                exit_code: super::UNKNOWN_OUTCOME_EXIT,
            })?;
        Snapshot::new(board).map_err(|error| TypedFailure {
            code: "CONTROLBOARD_STATUS_REFUSED",
            detail: error.to_string(),
            exit_code: super::UNKNOWN_OUTCOME_EXIT,
        })
    }
    #[cfg(not(windows))]
    {
        Err(TypedFailure {
            code: "KERNEL_APPLICATION_PORT_CLOSED",
            detail: "Windows authenticated Kernel front door".to_owned(),
            exit_code: super::FRONT_DOOR_CLOSED_EXIT,
        })
    }
}

/// Local UI state for one dashboard session. Nothing here survives the process.
struct View {
    /// Index into the navigable section list.
    section: usize,
    /// First body line drawn for the current section.
    scroll: usize,
    /// The one served snapshot in scope. A refresh replaces it atomically; it
    /// is never merged with another revision.
    snapshot: Snapshot,
    /// Freshness of the displayed snapshot.
    state: SnapshotState,
    /// The single bounded outstanding refresh, if any.
    pending: Option<JoinHandle<Result<Snapshot, TypedFailure>>>,
    /// When the outstanding refresh stops being admissible.
    deadline: Option<Instant>,
}

impl View {
    /// Number of navigable sections: the served row section plus the I11.2
    /// named sections.
    const fn section_count() -> usize {
        SECTIONS.len() + 1
    }
}

/// Runs the `dashboard` command.
///
/// Redirected or noninteractive output is answered before any terminal mode is
/// requested, so a piped or background invocation never enters raw mode and
/// never blocks on a key press.
pub fn run_dashboard() -> Result<i32> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        super::write_json_error(
            NON_TERMINAL_CODE,
            "eliot dashboard needs an interactive terminal and never enters raw mode under redirected or noninteractive output; use `eliot controlboard status` for the documented one-shot JSON projection of the same authenticated view",
        );
        return Ok(super::INVALID_REQUEST_EXIT);
    }
    let snapshot = match fetch_snapshot() {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            // Backend absence is a typed unavailable/recovery result. No raw
            // mode is entered, and nothing is installed, launched or repaired.
            super::write_json_error(failure.code, &failure.detail);
            return Ok(failure.exit_code);
        }
    };
    run_interactive(View {
        section: 0,
        scroll: 0,
        snapshot,
        state: SnapshotState::Current,
        pending: None,
        deadline: None,
    })
}

/// Enters the terminal surface, runs the session, and restores the terminal.
///
/// The primary transport/rendering error and the cleanup error are kept
/// distinct: when both fail, the primary cause is what the process reports and
/// the cleanup failure is reported alongside it rather than in its place.
fn run_interactive(mut view: View) -> Result<i32> {
    let mut guard = match TerminalGuard::enter() {
        Ok(guard) => guard,
        Err(error) => {
            super::write_json_error(
                TERMINAL_SETUP_REFUSED,
                &format!("dashboard terminal setup failed, no screen was entered: {error}"),
            );
            return Ok(super::INVALID_REQUEST_EXIT);
        }
    };
    let outcome = event_loop(&mut view);
    let cleanup = guard.restore();
    match (outcome, cleanup) {
        (Err(primary), Err(cleanup_error)) => {
            super::write_json_error(
                TERMINAL_RESTORE_FAILED,
                &format!(
                    "terminal restore failed after a primary dashboard failure ({primary}): {cleanup_error}"
                ),
            );
            Err(primary)
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_code), Err(cleanup_error)) => {
            super::write_json_error(
                TERMINAL_RESTORE_FAILED,
                &format!("dashboard ended but the terminal was not restored: {cleanup_error}"),
            );
            Ok(super::INVALID_REQUEST_EXIT)
        }
        (Ok(code), Ok(())) => Ok(code),
    }
}

/// Owns terminal mode for exactly one session.
///
/// `enter` is only reached once a board is in hand. `restore` is the ordinary
/// path and reports its own failure; `Drop` is the last-resort path for an
/// unwinding panic and is reached only when `restore` never ran.
struct TerminalGuard {
    /// Whether the surface mode is still active and must be undone.
    active: bool,
}

impl TerminalGuard {
    /// Enters raw mode and the alternate screen, undoing raw mode if the
    /// screen switch itself fails.
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        if let Err(error) = execute!(out, terminal::EnterAlternateScreen, cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(error);
        }
        Ok(Self { active: true })
    }

    /// Restores cooked mode, the cursor, and the original screen. Idempotent,
    /// so a second call is a no-op rather than a second write.
    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        terminal::disable_raw_mode()?;
        execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// The redraw loop: reap one bounded refresh, draw, and handle one key.
///
/// The IPC never runs on this thread, so a key press is always handled within
/// one bounded poll even while a read is outstanding, and `q` cancels the
/// session without waiting for the read to answer.
fn event_loop(view: &mut View) -> Result<i32> {
    loop {
        reap_refresh(view);
        let (columns, rows) = terminal::size().context("read the terminal size")?;
        draw(&screen_lines(view, rows), columns)?;
        if event::poll(INPUT_POLL).context("wait for a terminal key press")?
            && let Event::Key(key) = event::read().context("read a terminal key press")?
            && key.kind == KeyEventKind::Press
            && handle_key(view, key)
        {
            return Ok(0);
        }
    }
}

/// Admits at most one outstanding refresh, under a finite deadline.
///
/// A failed read leaves the previous snapshot in place and marks it explicitly
/// stale. An answer that arrives after the deadline is discarded rather than
/// admitted, so no redraw can turn a late observation into fresh evidence.
fn reap_refresh(view: &mut View) {
    if view
        .pending
        .as_ref()
        .is_none_or(|handle| !handle.is_finished())
    {
        if view
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            view.state = SnapshotState::DeadlineExceeded;
        }
        return;
    }
    let Some(handle) = view.pending.take() else {
        return;
    };
    view.deadline = None;
    match handle.join() {
        Ok(Ok(_late)) if matches!(view.state, SnapshotState::DeadlineExceeded) => {
            view.state = SnapshotState::Stale(REFRESH_DEADLINE_EXCEEDED.to_owned());
        }
        Ok(Ok(snapshot)) => {
            view.snapshot = snapshot;
            view.state = SnapshotState::Current;
        }
        Ok(Err(failure)) => {
            view.state = SnapshotState::Stale(failure.to_string());
        }
        Err(_) => {
            view.state = SnapshotState::Stale(REFRESH_WORKER_PANICKED.to_owned());
        }
    }
}

/// Starts one bounded refresh, or refuses a second one.
///
/// There is no queue and no renderer-owned background service: at most one read
/// of the same admitted projection is ever in flight. A request that arrives
/// while one is outstanding starts nothing and changes nothing — the snapshot
/// line already says the read is outstanding, so a refused second request is
/// visible without being reported as staleness it did not cause.
fn start_refresh(view: &mut View) {
    if view.pending.is_some() {
        return;
    }
    view.pending = Some(thread::spawn(fetch_snapshot));
    view.deadline = Some(Instant::now() + REFRESH_DEADLINE);
    view.state = SnapshotState::Refreshing;
}

/// Applies one key press and reports whether the session should end.
fn handle_key(view: &mut View, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
        KeyCode::Char('r') => {
            start_refresh(view);
            false
        }
        KeyCode::Left => {
            view.section = (view.section + View::section_count() - 1) % View::section_count();
            view.scroll = 0;
            false
        }
        KeyCode::Right => {
            view.section = (view.section + 1) % View::section_count();
            view.scroll = 0;
            false
        }
        KeyCode::Up => {
            view.scroll = view.scroll.saturating_sub(1);
            false
        }
        KeyCode::Down | KeyCode::PageDown => {
            view.scroll = (view.scroll + 1).min(body_lines(view).len().saturating_sub(1));
            false
        }
        KeyCode::PageUp => {
            view.scroll = view.scroll.saturating_sub(BODY_PAGE);
            false
        }
        KeyCode::Home => {
            view.scroll = 0;
            false
        }
        KeyCode::End => {
            view.scroll = body_lines(view).len().saturating_sub(1);
            false
        }
        _ => false,
    }
}

/// How far one page key moves the body window.
const BODY_PAGE: usize = 8;

/// Renders one untrusted payload field as bounded, escape-free display text.
///
/// Every Unicode control character — including `ESC` (U+001B), `CSI`
/// (U+009B) and `DEL` (U+007F) — is replaced by `?`, so no served field can
/// become a terminal command, and the field is truncated to
/// [`MAX_DISPLAY_CHARS`] characters so one line has a bounded width. Owner
/// text is never unescaped, re-encoded, or interpreted here; only what a
/// terminal would act on is removed.
fn display_text(value: &str) -> String {
    let mut rest = value.chars();
    let mut bounded: String = rest
        .by_ref()
        .take(MAX_DISPLAY_CHARS)
        .map(sanitize)
        .collect();
    if rest.next().is_some() {
        bounded.push_str("...");
    }
    bounded
}

/// Replaces one character a terminal would act on with a visible `?`.
fn sanitize(value: char) -> char {
    if value.is_control() { '?' } else { value }
}

/// Shortens one composed line to the drawable width.
fn clip(line: &str, width: usize) -> String {
    let mut rest = line.chars();
    let mut bounded: String = rest.by_ref().take(width).collect();
    if rest.next().is_some() {
        bounded.push('>');
    }
    bounded
}

/// Composes the complete screen: header, the current section body, and the key
/// line. The body window is bounded by the real terminal height, so the frame
/// never scrolls and never overwrites the key line.
fn screen_lines(view: &View, height: u16) -> Vec<String> {
    let header = header_lines(view);
    let body = body_lines(view);
    let available = (height as usize).saturating_sub(header.len() + 1);
    let start = view.scroll.min(body.len().saturating_sub(1));
    let end = start.saturating_add(available).min(body.len());
    let mut lines = header;
    if available > 0 {
        lines.extend_from_slice(&body[start..end]);
    }
    lines.push(KEYS_LINE.to_owned());
    lines
}

/// Composes the identity header: the catalogue row, the served board
/// bindings, the owner-stamped invalidation/expiry, and the snapshot state.
fn header_lines(view: &View) -> Vec<String> {
    let board = &view.snapshot.board;
    let mut lines = vec![
        "ELIOT dashboard - read-only terminal renderer of the served ControlBoard projection"
            .to_owned(),
        catalogue_line(),
        format!(
            "board: contract={} view_revision={} contour_digest={}",
            display_text(&board.contract),
            board.view_revision,
            display_text(&board.contour_digest)
        ),
        format!("view fence: {}", view.snapshot.view_fence),
        format!(
            "reconcile: observed_count={} missing_count={} unexpected_observed={}",
            board.observed_count,
            board.missing_count,
            board.unexpected_observed.len()
        ),
        format!("invalidation: {}", display_text(&board.invalidation)),
        format!("expiry: {}", display_text(&board.expiry)),
        format!("snapshot: {}", state_text(view)),
    ];
    if let Some(observed_at) = view.snapshot.served_observed_at() {
        lines.push(format!("served row observed_at: {observed_at}"));
    }
    lines
}

/// Composes the one catalogue identity line, resolved from the existing
/// generated catalogue rather than from a second local entry.
fn catalogue_line() -> String {
    let spec = CommandCatalogue::current()
        .commands()
        .iter()
        .find(|spec| spec.id == CommandId::Dashboard);
    match spec {
        Some(spec) => format!(
            "catalogue: {} [{}] - {}",
            spec.usage, spec.owner, spec.summary
        ),
        None => format!(
            "catalogue: {} - unavailable in the generated catalogue",
            CommandId::Dashboard.as_str()
        ),
    }
}

/// Renders the served snapshot's freshness in words.
///
/// Freshness is a statement about the read, never about the system: a current
/// snapshot is still only a projection, and a stale one keeps the observation
/// time the owner stamped on it.
fn state_text(view: &View) -> String {
    match &view.state {
        SnapshotState::Current => {
            "current read; projection only, no health or support is derived from it".to_owned()
        }
        SnapshotState::Refreshing => "a bounded refresh is outstanding".to_owned(),
        SnapshotState::DeadlineExceeded => {
            "STALE: refresh did not answer inside its finite deadline".to_owned()
        }
        SnapshotState::Stale(reason) => format!("STALE: {reason}"),
    }
}

/// Composes the body of the selected section.
///
/// The served row section reproduces each permitted row exactly: identity,
/// typed disposition label, summary, and the four observer bindings plus the
/// projection-owned revision and contour digest. Every I11.2 section renders
/// as `UNAVAILABLE` with its owner limitation.
fn body_lines(view: &View) -> Vec<String> {
    if view.section == 0 {
        return served_row_lines(view);
    }
    let section = &SECTIONS[view.section - 1];
    if section.name == "Notifications" {
        return notification_section_lines(view);
    }
    vec![
        format!("section: {}", section.name),
        "UNAVAILABLE: the served controlboard.status projection carries no section data here; it serves the un-sectioned row projection shown under \"Board rows\" and the typed Notifications section".to_owned(),
        "this is an explicit owner limitation, not an empty list; it is never evidence of health, readiness, support or absence".to_owned(),
        format!("owner limitation: {}", display_text(section.limitation)),
    ]
}

/// Renders every canonical notification row and the metrics derived from the
/// complete fetched set. Acknowledgement remains distinct from resolution,
/// critical unresolved items stay explicit, and delivery failures retain the
/// owner's failure reason.
fn notification_section_lines(view: &View) -> Vec<String> {
    let inbox = &view.snapshot.board.notifications;
    let metrics = inbox.metrics;
    let mut lines = vec![
        "section: Notifications".to_owned(),
        "canonical ControlBoard inbox; popup and quiet-hours policy do not alter these rows"
            .to_owned(),
        format!(
            "metrics: total={} unresolved={} critical_unresolved={} action_required_unresolved={} failed_delivery={} acknowledged_unresolved={}",
            metrics.total,
            metrics.unresolved,
            metrics.critical_unresolved,
            metrics.action_required_unresolved,
            metrics.failed_delivery,
            metrics.acknowledged_unresolved,
        ),
    ];
    if inbox.rows.is_empty() {
        lines.push("no canonical notification records were returned".to_owned());
        return lines;
    }

    for row in &inbox.rows {
        let mut markers = Vec::new();
        if row.is_unresolved() {
            markers.push("UNRESOLVED");
            if row.acknowledged {
                markers.push("ACKNOWLEDGED; STILL UNRESOLVED");
            }
        } else {
            markers.push("RESOLVED");
        }
        if row.delivery_failed {
            markers.push("DELIVERY FAILED");
        }
        lines.push(format!(
            "- {} [{}] {} dedup_key={}",
            display_text(&row.notification_id),
            format!("{:?}", row.severity).to_uppercase(),
            markers.join(" | "),
            display_text(&row.dedup_key),
        ));
        lines.push(format!("    subject: {}", display_text(&row.subject)));
        lines.push(format!("    summary: {}", display_text(&row.summary)));
        lines.push(format!(
            "    owner={} affected_scope={} required_action={}",
            display_text(&row.owner),
            display_text(&row.affected_scope),
            display_text(&row.required_action),
        ));
        lines.push(format!(
            "    delivery_failed={} failure_reason={} channels={}",
            row.delivery_failed,
            row.failure_reason
                .as_deref()
                .map_or("(none reported)".to_owned(), display_text),
            display_text(&format!("{:?}", row.delivery_channels)),
        ));
        lines.push(format!(
            "    occurrences={} revision={} evidence_handles={} deadline_or_review={}",
            row.occurrences,
            row.revision,
            display_text(&row.evidence_handles.join(", ")),
            notification_deadline_or_review(row.deadline_or_review.as_ref()),
        ));
    }
    lines
}

/// Renders only the deadline/review facts the canonical row supplied.
fn notification_deadline_or_review(
    boundary: Option<&eliot_kernel_core::DeadlineOrReview>,
) -> String {
    let Some(boundary) = boundary else {
        return "(none supplied)".to_owned();
    };
    let deadline = boundary
        .deadline_unix_ms
        .map_or("(none)".to_owned(), |value| value.to_string());
    let review = boundary
        .review_ref
        .as_deref()
        .map_or("(none)".to_owned(), display_text);
    format!("deadline_unix_ms={deadline} review_ref={review}")
}

/// Composes the served, role-filtered row projection.
fn served_row_lines(view: &View) -> Vec<String> {
    let board = &view.snapshot.board;
    let mut lines = vec![
        format!("section: {SERVED_ROWS_SECTION_NAME}"),
        "rows as served by the authenticated controlboard.status read; role and privacy admission happen upstream in ControlBoard::view and this renderer adds no filter".to_owned(),
    ];
    if board.rows.is_empty() {
        lines.push(
            "no row was served for this view; this is the served denominator result, not a health statement"
                .to_owned(),
        );
    }
    for row in &board.rows {
        lines.push(format!(
            "- {}  {}",
            display_text(&row.entry_id),
            row.disposition.label()
        ));
        lines.push(format!(
            "    summary: {}",
            row.summary
                .as_deref()
                .map_or("(no summary was served)".to_owned(), display_text)
        ));
        lines.push(format!(
            "    installation={} observed_at={} source_digest={} recovery_owner={} view_revision={}",
            display_text(row.installation.as_str()),
            row.observed_at.get(),
            display_text(row.source_digest.as_str()),
            display_text(row.recovery_owner.as_str()),
            row.view_revision
        ));
        // The four projection-supplied identities are bound per row. An
        // unobserved row binds none of them, which is reported as "not
        // observed" rather than as an unknown or empty value.
        lines.push(format!(
            "    capability={} owner={} generation={} evidence_handle={}",
            row.capability
                .as_ref()
                .map_or("(not observed)".to_owned(), |value| display_text(
                    value.as_str()
                )),
            row.owner
                .as_ref()
                .map_or("(not observed)".to_owned(), |value| display_text(
                    value.as_str()
                )),
            row.generation
                .as_ref()
                .map_or("(not observed)".to_owned(), |value| display_text(
                    value.as_str()
                )),
            row.evidence_handle
                .as_ref()
                .map_or("(not observed)".to_owned(), |value| display_text(
                    value.as_str()
                )),
        ));
        lines.push(format!(
            "    contour_digest={}",
            display_text(&row.contour_digest)
        ));
    }
    lines.push(format!(
        "unexpected_observed: {}",
        if board.unexpected_observed.is_empty() {
            "none served".to_owned()
        } else {
            display_text(&board.unexpected_observed.join(", "))
        }
    ));
    lines
}

/// Writes one exact frame.
///
/// The screen is cleared once and the composed lines are written in order,
/// each clipped one column short of the terminal width so no line wraps and
/// shifts the frame.
fn draw(lines: &[String], columns: u16) -> Result<()> {
    let width = (columns as usize).saturating_sub(1);
    let mut out = io::stdout();
    queue!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All)
    )
    .context("clear the dashboard screen")?;
    for line in lines {
        queue!(out, Print(clip(line, width))).context("draw a dashboard line")?;
    }
    out.flush().context("flush the dashboard frame")?;
    Ok(())
}
