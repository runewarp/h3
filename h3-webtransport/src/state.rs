//! State of a WebTransport session shared with its streams.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    task::{Wake, Waker},
};

use h3::error::StreamError;

/// The `WT_SESSION_GONE` HTTP/3 error code (`H3_WEBTRANSPORT_SESSION_GONE` before draft 07).
///
/// Streams of a session are reset with this code when the session terminates.
pub const WT_SESSION_GONE: u64 = 0x170d7b68;

/// The code and reason a WebTransport session was closed with
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    /// The application error code
    pub code: u32,
    /// The application error message
    pub reason: String,
}

/// A WebTransport session ended without being closed by either endpoint
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionError {
    /// The peer sent an invalid capsule, so the CONNECT stream was reset with H3_MESSAGE_ERROR
    MalformedCapsule(&'static str),
    /// The CONNECT stream failed, for example because the peer reset it or the connection closed
    Stream(Arc<StreamError>),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::MalformedCapsule(reason) => write!(f, "malformed capsule: {reason}"),
            SessionError::Stream(err) => write!(f, "CONNECT stream failed: {err}"),
        }
    }
}

impl std::error::Error for SessionError {}

#[derive(Debug, Default)]
pub(crate) struct SessionState {
    /// Set once the session has terminated
    outcome: OnceLock<Result<CloseInfo, SessionError>>,
    draining: AtomicBool,
    /// Tasks to wake when the session terminates or starts draining
    wakers: Arc<WakerSet>,
}

impl SessionState {
    pub(crate) fn is_terminated(&self) -> bool {
        self.outcome.get().is_some()
    }

    /// How the session terminated, if it has
    pub(crate) fn outcome(&self) -> Option<&Result<CloseInfo, SessionError>> {
        self.outcome.get()
    }

    /// Marks the session terminated. Returns false if it already was.
    pub(crate) fn terminate(&self, outcome: Result<CloseInfo, SessionError>) -> bool {
        let first = self.outcome.set(outcome).is_ok();
        if first {
            self.wakers.wake_all();
        }
        first
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub(crate) fn drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.wakers.wake_all();
        }
    }

    /// Wakes `waker` when the session terminates or starts draining.
    ///
    /// Callers check the state again after registering, since it may have changed before the
    /// waker was registered.
    pub(crate) fn register(&self, waker: &Waker) {
        self.wakers.register(waker);
    }

    /// A waker that wakes every registered waker.
    ///
    /// Used when polling the CONNECT stream, so that whichever task polls it, all tasks waiting on
    /// the session are woken when something arrives.
    pub(crate) fn waker(&self) -> Waker {
        Waker::from(self.wakers.clone())
    }
}

#[derive(Debug, Default)]
struct WakerSet(Mutex<Vec<Waker>>);

impl WakerSet {
    fn register(&self, waker: &Waker) {
        let mut wakers = self.0.lock().unwrap();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    fn wake_all(&self) {
        let wakers = std::mem::take(&mut *self.0.lock().unwrap());
        for waker in wakers {
            waker.wake();
        }
    }
}

impl Wake for WakerSet {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}
