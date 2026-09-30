//! Windows notifications for the interactive user's session and system power lifecycle.
//!
//! This adapter observes Win32 session and power broadcasts in the broker's
//! own interactive logon session. It carries no broker authority: consumers
//! must join each notification to their exact authenticated registration.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};

/// One lifecycle observation reported by Windows for the current logon
/// session or machine power state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserSessionLifecycleEvent {
    /// Windows reported that this exact interactive session logged off.
    SessionLogoff { session_id: u32 },
    /// Windows reported that this exact interactive session was terminated.
    SessionTerminated { session_id: u32 },
    /// Windows disconnected the current session from its remote desktop.
    SessionDisconnected { session_id: u32 },
    /// Windows is suspending system operation. Win32 does not identify which
    /// low-power state will be used, so this also covers hibernation.
    SystemSuspending,
    /// Windows restored operation after a low-power state. This event also
    /// covers recovery from a critical suspension that lacked a pre-suspend
    /// notification.
    SystemResuming,
    /// Windows confirmed that the current user session or system is ending.
    SystemSessionEnding { session_id: u32, logoff: bool },
}

/// A lifecycle event, or a failure of the registered native observer.
#[derive(Debug)]
pub enum UserSessionLifecycleNotice {
    Event(UserSessionLifecycleEvent),
    ObserverFailed(String),
}

/// Starts the current-session observer and waits until Windows has accepted
/// its session notification registration before returning.
///
/// The receiver reports only OS-delivered messages. It never accepts event
/// names or session IDs from the caller.
pub fn start() -> io::Result<Receiver<UserSessionLifecycleNotice>> {
    #[cfg(windows)]
    {
        windows::start()
    }

    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows user-session lifecycle notifications are unavailable",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::{
        Receiver, Sender, SyncSender, UserSessionLifecycleEvent, UserSessionLifecycleNotice, io,
        mpsc,
    };
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::RemoteDesktop::{
        NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
        WTSUnRegisterSessionNotification,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        ENDSESSION_LOGOFF, GWLP_USERDATA, GetMessageW, MSG, PBT_APMRESUMEAUTOMATIC,
        PBT_APMRESUMESUSPEND, PBT_APMSUSPEND, RegisterClassExW, SetWindowLongPtrW,
        TranslateMessage, UnregisterClassW, WM_ENDSESSION, WM_NCCREATE, WM_POWERBROADCAST,
        WM_QUERYENDSESSION, WM_QUIT, WM_WTSSESSION_CHANGE, WNDCLASSEXW, WTS_CONSOLE_DISCONNECT,
        WTS_REMOTE_DISCONNECT, WTS_SESSION_LOGOFF, WTS_SESSION_TERMINATE, WS_OVERLAPPED,
    };

    static CLASS_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct WindowContext {
        notices: Sender<UserSessionLifecycleNotice>,
        session_id: u32,
    }

    struct RegisteredWindow {
        hwnd: HWND,
        class_name: Vec<u16>,
        instance: windows_sys::Win32::Foundation::HINSTANCE,
        registered_for_session: bool,
    }

    impl Drop for RegisteredWindow {
        fn drop(&mut self) {
            if self.registered_for_session {
                // SAFETY: this HWND was registered by this thread and remains
                // live until this guard is dropped.
                unsafe { WTSUnRegisterSessionNotification(self.hwnd) };
            }
            if !self.hwnd.is_null() {
                // SAFETY: this hidden window was created by this thread and is
                // destroyed only after its message loop exits.
                unsafe { DestroyWindow(self.hwnd) };
            }
            if !self.class_name.is_empty() {
                // SAFETY: this unique class was registered by this thread.
                unsafe { UnregisterClassW(self.class_name.as_ptr(), self.instance) };
            }
        }
    }

    pub(super) fn start() -> io::Result<Receiver<UserSessionLifecycleNotice>> {
        let (notices_tx, notices_rx) = mpsc::channel();
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let worker_notices = notices_tx.clone();
        std::thread::Builder::new()
            .name("eliot-user-session-lifecycle".to_owned())
            .spawn(move || {
                if let Err(error) = run_message_loop(worker_notices.clone(), startup_tx) {
                    let _ = worker_notices.send(UserSessionLifecycleNotice::ObserverFailed(
                        error.to_string(),
                    ));
                }
            })?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(notices_rx),
            Ok(Err(detail)) => Err(io::Error::other(detail)),
            Err(error) => Err(io::Error::other(format!(
                "lifecycle observer stopped before startup completed: {error}"
            ))),
        }
    }

    fn run_message_loop(
        notices: Sender<UserSessionLifecycleNotice>,
        startup: SyncSender<Result<(), String>>,
    ) -> io::Result<()> {
        let session_id = match current_session_id() {
            Ok(session_id) => session_id,
            Err(error) => return fail_startup(startup, error),
        };
        let instance = unsafe { GetModuleHandleW(null()) };
        if instance.is_null() {
            return fail_startup(startup, io::Error::last_os_error());
        }

        let sequence = CLASS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        if sequence == 0 {
            return fail_startup(
                startup,
                io::Error::other("lifecycle window class sequence exhausted"),
            );
        }
        let class_name = wide(&format!(
            "Eliot.UserSessionLifecycle.{}.{}",
            std::process::id(),
            sequence
        ));
        let window_class = WNDCLASSEXW {
            cbSize: u32::try_from(size_of::<WNDCLASSEXW>())
                .map_err(|error| io::Error::other(error.to_string()))?,
            style: 0,
            lpfnWndProc: Some(user_session_window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: null_mut(),
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: null_mut(),
        };
        let atom = unsafe { RegisterClassExW(&raw const window_class) };
        if atom == 0 {
            return fail_startup(startup, io::Error::last_os_error());
        }

        let mut window = RegisteredWindow {
            hwnd: null_mut(),
            class_name,
            instance,
            registered_for_session: false,
        };
        let mut context = WindowContext {
            notices,
            session_id,
        };
        window.hwnd = unsafe {
            CreateWindowExW(
                0,
                window.class_name.as_ptr(),
                wide("Eliot User Session Lifecycle").as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                instance,
                (&raw mut context).cast(),
            )
        };
        if window.hwnd.is_null() {
            return fail_startup(startup, io::Error::last_os_error());
        }
        if unsafe { WTSRegisterSessionNotification(window.hwnd, NOTIFY_FOR_THIS_SESSION) } == 0 {
            return fail_startup(startup, io::Error::last_os_error());
        }
        window.registered_for_session = true;
        if startup.send(Ok(())).is_err() {
            return Err(io::Error::other(
                "lifecycle observer startup receiver was dropped",
            ));
        }

        loop {
            let mut message = MSG::default();
            let received = unsafe { GetMessageW(&raw mut message, null_mut(), 0, 0) };
            if received == -1 {
                return Err(io::Error::last_os_error());
            }
            if received == 0 || message.message == WM_QUIT {
                return Ok(());
            }
            unsafe {
                TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }

    fn current_session_id() -> io::Result<u32> {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;

        let process_id = unsafe { GetCurrentProcessId() };
        let mut session_id = 0_u32;
        // SAFETY: GetCurrentProcessId supplies this process's live PID and the
        // writable output pointer remains valid for the duration of the call.
        if unsafe { ProcessIdToSessionId(process_id, &raw mut session_id) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(session_id)
        }
    }

    fn fail_startup<T>(startup: SyncSender<Result<(), String>>, error: io::Error) -> io::Result<T> {
        let detail = error.to_string();
        let _ = startup.send(Err(detail.clone()));
        Err(io::Error::other(detail))
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    unsafe extern "system" fn user_session_window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_NCCREATE {
            // SAFETY: WM_NCCREATE supplies a valid CREATESTRUCTW in lParam;
            // lpCreateParams is the stack context kept alive by the message
            // loop until this window is destroyed.
            let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
            // SAFETY: the pointer is the per-window context passed to
            // CreateWindowExW and fits in the pointer-sized user-data slot.
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
            }
            return 1;
        }

        // SAFETY: the context pointer is installed only during WM_NCCREATE
        // and remains valid for the lifetime of the window.
        let context_pointer = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(hwnd, GWLP_USERDATA)
        };
        let context = if context_pointer == 0 {
            None
        } else {
            // SAFETY: the pointer was installed from the stack context above.
            Some(unsafe { &*(context_pointer as *const WindowContext) })
        };

        match message {
            WM_WTSSESSION_CHANGE => {
                if let Some(context) = context {
                    let session_id = lparam as u32;
                    if session_id == context.session_id {
                        let event = match wparam as u32 {
                            WTS_SESSION_LOGOFF => {
                                Some(UserSessionLifecycleEvent::SessionLogoff { session_id })
                            }
                            WTS_SESSION_TERMINATE => {
                                Some(UserSessionLifecycleEvent::SessionTerminated { session_id })
                            }
                            WTS_REMOTE_DISCONNECT | WTS_CONSOLE_DISCONNECT => {
                                Some(UserSessionLifecycleEvent::SessionDisconnected { session_id })
                            }
                            _ => None,
                        };
                        if let Some(event) = event {
                            let _ = context
                                .notices
                                .send(UserSessionLifecycleNotice::Event(event));
                        }
                    }
                }
                0
            }
            WM_POWERBROADCAST => {
                if let Some(context) = context {
                    let event = match wparam as u32 {
                        PBT_APMSUSPEND => Some(UserSessionLifecycleEvent::SystemSuspending),
                        PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => {
                            Some(UserSessionLifecycleEvent::SystemResuming)
                        }
                        _ => None,
                    };
                    if let Some(event) = event {
                        let _ = context
                            .notices
                            .send(UserSessionLifecycleNotice::Event(event));
                    }
                }
                1
            }
            WM_QUERYENDSESSION => 1,
            WM_ENDSESSION if wparam != 0 => {
                if let Some(context) = context {
                    let _ = context.notices.send(UserSessionLifecycleNotice::Event(
                        UserSessionLifecycleEvent::SystemSessionEnding {
                            session_id: context.session_id,
                            logoff: (lparam as u32 & ENDSESSION_LOGOFF) != 0,
                        },
                    ));
                }
                0
            }
            _ => {
                // SAFETY: unhandled messages are delegated to the standard
                // window procedure for this valid HWND.
                unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
            }
        }
    }
}
