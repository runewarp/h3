//! State of a WebTransport session shared with its streams.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    task::{Wake, Waker},
};

use futures_util::task::AtomicWaker;
use h3::error::StreamError;

/// Owned by the waiting future or stream, so cancellation releases its task's waker.
pub(crate) type Registration = Option<Arc<RegisteredWaker>>;

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
    /// The extension driver or session owner was dropped before orderly CONNECT completion
    OwnerDropped,
    /// The CONNECT stream failed, for example because the peer reset it or the connection closed
    Stream(Arc<StreamError>),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::OwnerDropped => write!(f, "WebTransport owner dropped"),
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
    /// Only CONNECT readers are woken for incoming capsule bytes.
    connect_wakers: Arc<WakerSet>,
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
            self.connect_wakers.wake_all();
        }
        first
    }

    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub(crate) fn drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.wakers.wake_all();
            self.connect_wakers.wake_all();
        }
    }

    /// Wakes `waker` when the session terminates or starts draining.
    ///
    /// Callers check the state again after registering, since it may have changed before the
    /// waker was registered.
    pub(crate) fn register(&self, waker: &Waker, registration: &mut Registration) {
        self.wakers.register(waker, registration);
    }

    pub(crate) fn register_connect(&self, waker: &Waker, registration: &mut Registration) {
        self.connect_wakers.register(waker, registration);
    }

    /// Incoming CONNECT data wakes readers, not idle streams or credit-blocked opens.
    pub(crate) fn connect_waker(&self) -> Waker {
        Waker::from(self.connect_wakers.clone())
    }
}

#[derive(Debug, Default)]
pub(crate) struct WakerSet(Mutex<HashMap<usize, Weak<RegisteredWaker>>>);

/// The waiter owns its entry; dropping it releases the task waker and removes the entry.
#[derive(Debug)]
pub(crate) struct RegisteredWaker {
    waker: AtomicWaker,
    set: Weak<WakerSet>,
}

impl Drop for RegisteredWaker {
    fn drop(&mut self) {
        if let Some(set) = self.set.upgrade() {
            set.0
                .lock()
                .unwrap()
                .remove(&(self as *const Self as usize));
        }
    }
}

impl WakerSet {
    pub(crate) fn register(self: &Arc<Self>, waker: &Waker, registration: &mut Registration) {
        let entry = registration.get_or_insert_with(|| {
            let entry = Arc::new(RegisteredWaker {
                waker: AtomicWaker::new(),
                set: Arc::downgrade(self),
            });
            self.0
                .lock()
                .unwrap()
                .insert(Arc::as_ptr(&entry) as usize, Arc::downgrade(&entry));
            entry
        });
        // Repeated polls update only this waiter's entry, without scanning or locking the set.
        entry.waker.register(waker);
    }

    pub(crate) fn wake_all(&self) {
        // Wake outside the lock: a task may drop its registration when woken.
        let wakers: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for entry in wakers {
            entry.waker.wake();
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
