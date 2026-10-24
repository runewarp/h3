//! Client sessions alongside ordinary HTTP/3 requests.
//!
//! Build an h3 client with WebTransport, datagrams, extended CONNECT and a session limit enabled,
//! then pass both returned handles to [`new`]. Poll [`Connection::wait_idle`] in a separate task.
//! [`Client::send_request`] returns ordinary request handles for GET, PUT and other HTTP methods.
//! No tasks are spawned by this module. Poll session [`WebTransportSession::closed`] concurrently
//! with application work to receive close/drain capsules and acknowledge peer closes.
//!
//! The supported subset uses the adopted draft 02/07/13/15 negotiation and stream formats. It
//! does not implement WebTransport flow-control capsules, application subprotocol negotiation,
//! unidirectional client dispatch, or datagram routing. Pin draft 07 on both peers for its wire
//! format. Authentication, application capacity and request authorization belong to callers.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use bytes::Buf;
use futures_util::{
    future::poll_fn, ready, stream::FuturesUnordered, task::AtomicWaker, Future, StreamExt,
};
use h3::{
    client::{IncomingStreams, RequestStream, SendRequest},
    error::{Code, ConnectionError, StreamError},
    ext::{Protocol, WebTransportDraft},
    proto::varint::VarInt,
    quic,
    stream::BufRecvStream,
    ConnectionState, Settings,
};
use http::{Method, Request, StatusCode};

use crate::{
    state::{SessionState, WakerSet},
    SessionId, WT_SESSION_GONE,
};

mod session;
pub use session::WebTransportSession;

pub use crate::state::{CloseInfo, SessionError};

const BUFFERED_STREAM_REJECTED: u64 = 0x3994bd84;
const WORK_BUDGET: usize = 32;

/// Independent memory and work limits. QUIC receive windows bound transport-owned bytes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous sessions, including CONNECTs waiting for their response.
    pub sessions: NonZeroUsize,
    /// Raw incoming streams queued by h3 before prefix parsing.
    pub incoming: NonZeroUsize,
    /// Concurrent incomplete prefixes. Excess streams are reset, without waiting for space.
    pub pending_prefixes: NonZeroUsize,
    /// Validated streams queued for each session, including before the CONNECT response.
    pub streams_per_session: NonZeroUsize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: NonZeroUsize::new(1).unwrap(),
            incoming: NonZeroUsize::new(32).unwrap(),
            pending_prefixes: NonZeroUsize::new(32).unwrap(),
            streams_per_session: NonZeroUsize::new(32).unwrap(),
        }
    }
}

/// Failure to establish a session. These errors never deliberately close the H3 connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// Bilateral SETTINGS or compatible draft negotiation failed.
    Settings(&'static str),
    /// The request must be an HTTPS CONNECT with authority and path, without a subprotocol.
    InvalidRequest,
    /// The peer or local session cap is exhausted.
    SessionLimit,
    /// The server rejected the CONNECT.
    Rejected(StatusCode),
    /// The response's draft or application subprotocol headers are incompatible.
    InvalidResponse,
    /// The HTTP/3 request failed.
    Stream(StreamError),
    /// The extension connection driver ended.
    DriverStopped,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settings(reason) => write!(f, "WebTransport SETTINGS: {reason}"),
            Self::InvalidRequest => write!(f, "invalid WebTransport CONNECT request"),
            Self::SessionLimit => write!(f, "WebTransport session limit reached"),
            Self::Rejected(status) => write!(f, "WebTransport CONNECT rejected: {status}"),
            Self::InvalidResponse => write!(f, "incompatible WebTransport CONNECT response"),
            Self::Stream(error) => error.fmt(f),
            Self::DriverStopped => write!(f, "WebTransport connection driver stopped"),
        }
    }
}
impl std::error::Error for ConnectError {}
impl From<StreamError> for ConnectError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

#[derive(Clone, Copy)]
struct Negotiated {
    draft: WebTransportDraft,
    cap: u64,
}

fn negotiate(local: &Settings, peer: &Settings) -> Result<Negotiated, &'static str> {
    if !(local.enable_webtransport()
        && peer.enable_webtransport()
        && local.enable_datagram()
        && peer.enable_datagram()
        && local.enable_extended_connect()
        && peer.enable_extended_connect())
    {
        return Err("WebTransport, datagrams and extended CONNECT must be enabled by both peers");
    }
    let draft = local
        .negotiate_webtransport_draft(peer)
        .ok_or("no compatible draft")?;
    let cap = local
        .webtransport_session_limit(draft)
        .unwrap_or(u64::MAX)
        .min(peer.webtransport_session_limit(draft).unwrap_or(u64::MAX));
    if cap == 0 {
        return Err("zero negotiated session limit");
    }
    Ok(Negotiated { draft, cap })
}

fn negotiated(local: &Settings, peer: &Settings) -> bool {
    negotiate(local, peer).is_ok()
}

struct Registry<S: quic::BidiStream<B>, B: Buf> {
    inner: Mutex<RegistryInner<S, B>>,
    settings_waker: AtomicWaker,
}
struct RegistryInner<S: quic::BidiStream<B>, B: Buf> {
    sessions: BTreeMap<SessionId, Weak<Incoming<S, B>>>,
    negotiation: Option<Result<Negotiated, &'static str>>,
    open: bool,
}

struct Incoming<S: quic::BidiStream<B>, B: Buf> {
    state: Arc<SessionState>,
    streams: Mutex<VecDeque<BufRecvStream<S, B>>>,
    wakers: Arc<WakerSet>,
    cap: usize,
}

fn abort<S: quic::SendStream<B> + quic::RecvStream, B: Buf>(stream: &mut S, code: u64) {
    stream.reset(code);
    stream.stop_sending(code);
}

impl<S: quic::BidiStream<B>, B: Buf> Incoming<S, B> {
    fn discard(&self) {
        let streams = std::mem::take(&mut *self.streams.lock().unwrap());
        for mut stream in streams {
            abort(&mut stream, WT_SESSION_GONE);
        }
        self.wakers.wake_all();
    }

    fn deliver(&self, mut stream: BufRecvStream<S, B>) {
        let mut streams = self.streams.lock().unwrap();
        if self.state.is_terminated() {
            abort(&mut stream, WT_SESSION_GONE);
        } else if streams.len() == self.cap {
            abort(&mut stream, BUFFERED_STREAM_REJECTED);
        } else {
            streams.push_back(stream);
            drop(streams);
            self.wakers.wake_all();
        }
    }
}

impl<S: quic::BidiStream<B>, B: Buf> Drop for Incoming<S, B> {
    fn drop(&mut self) {
        self.discard();
    }
}

/// Connection-scoped extension driver. Drop aborts every queued or partially parsed stream.
///
/// Keep this running alongside ordinary HTTP requests and session handles. It retains a request
/// sender so dropping the last application sender does not accidentally close the connection.
pub struct Connection<C: quic::Connection<B>, B: Buf>
where
    C::BidiStream: quic::BidiStream<B>,
{
    connection: h3::client::Connection<C, B>,
    incoming: IncomingStreams<C::BidiStream, B>,
    pending: FuturesUnordered<Prefix<C::BidiStream, B>>,
    registry: Arc<Registry<C::BidiStream, B>>,
    local: Option<Settings>,
    limits: Limits,
    _sender: SendRequest<C::OpenStreams, B>,
}

/// Session establishment handle. Ordinary request senders can be cloned independently.
pub struct Client<O: quic::OpenStreams<B>, B: Buf>
where
    O::BidiStream: quic::BidiStream<B>,
{
    sender: SendRequest<O, B>,
    registry: Arc<Registry<O::BidiStream, B>>,
    limits: Limits,
}

/// Attach WebTransport dispatch to an existing HTTP/3 client.
///
/// The two arguments must come from the same h3 builder invocation. Configure bilateral
/// WebTransport, datagrams, extended CONNECT and compatible drafts before building it. SETTINGS
/// are normalized to the encoded wire values; suppressed SETTINGS cannot establish sessions.
/// Call this before polling the h3 driver or allowing server extension streams to arrive.
pub fn new<C, B>(
    mut connection: h3::client::Connection<C, B>,
    sender: SendRequest<C::OpenStreams, B>,
    limits: Limits,
) -> (Connection<C, B>, Client<C::OpenStreams, B>)
where
    C: quic::Connection<B>,
    C::OpenStreams: Clone,
    C::BidiStream: quic::BidiStream<B>,
    B: Buf,
{
    assert!(
        std::ptr::eq(connection.shared_state(), sender.shared_state()),
        "WebTransport connection and sender must come from the same h3 client"
    );
    let local = connection.advertised_settings();
    let incoming = connection.server_initiated_streams(
        limits.incoming,
        BUFFERED_STREAM_REJECTED.into(),
        negotiated,
    );
    let registry = Arc::new(Registry {
        inner: Mutex::new(RegistryInner {
            sessions: BTreeMap::new(),
            negotiation: None,
            open: true,
        }),
        settings_waker: AtomicWaker::new(),
    });
    (
        Connection {
            connection,
            incoming,
            pending: FuturesUnordered::new(),
            registry: registry.clone(),
            local,
            limits,
            _sender: sender.clone(),
        },
        Client {
            sender,
            registry,
            limits,
        },
    )
}

impl<C: quic::Connection<B>, B: Buf> Connection<C, B>
where
    C::BidiStream: quic::BidiStream<B>,
{
    /// Drive HTTP/3 and bounded stream classification until the connection ends.
    pub async fn wait_idle(&mut self) -> ConnectionError {
        poll_fn(|cx| self.poll_close(cx)).await
    }

    /// Initiate HTTP/3 graceful shutdown while retaining extension dispatch.
    pub async fn shutdown(&mut self, max_push: usize) -> Result<(), ConnectionError> {
        self.connection.shutdown(max_push).await
    }

    /// Poll the connection. Prefix parsing never awaits another stream or application queue.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionError> {
        let result = self.connection.poll_close(cx);
        if let Poll::Ready(error) = result {
            self.stop(Some(error.clone()));
            return Poll::Ready(error);
        }
        if let Some(peer) = self.connection.peer_settings() {
            let mut registry = self.registry.inner.lock().unwrap();
            if registry.negotiation.is_none() {
                registry.negotiation = Some(
                    self.local
                        .as_ref()
                        .ok_or("local SETTINGS were not advertised")
                        .and_then(|local| negotiate(local, peer)),
                );
                drop(registry);
                self.registry.settings_waker.wake();
            }
        }
        for index in 0..WORK_BUDGET {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(mut stream)) => {
                    if self.pending.len() == self.limits.pending_prefixes.get() {
                        abort(&mut stream, BUFFERED_STREAM_REJECTED);
                    } else {
                        self.pending.push(Prefix::new(stream));
                    }
                }
                _ => break,
            }
            if index + 1 == WORK_BUDGET {
                cx.waker().wake_by_ref();
            }
        }
        // Poll ready prefix futures only; silent streams retain independent wake registrations.
        for index in 0..WORK_BUDGET {
            match self.pending.poll_next_unpin(cx) {
                Poll::Ready(Some(Some((id, stream)))) => {
                    let session = self
                        .registry
                        .inner
                        .lock()
                        .unwrap()
                        .sessions
                        .get(&id)
                        .and_then(Weak::upgrade);
                    if let Some(session) = session {
                        session.deliver(stream);
                    } else {
                        let mut stream = stream;
                        abort(&mut stream, WT_SESSION_GONE);
                    }
                }
                Poll::Ready(Some(None)) => {}
                _ => break,
            }
            if index + 1 == WORK_BUDGET {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }

    fn stop(&mut self, error: Option<ConnectionError>) {
        let mut registry = self.registry.inner.lock().unwrap();
        registry.open = false;
        for session in registry.sessions.values().filter_map(Weak::upgrade) {
            session.state.terminate(Err(error
                .clone()
                .map_or(SessionError::OwnerDropped, |error| {
                    SessionError::Stream(Arc::new(StreamError::ConnectionError(error)))
                })));
            session.discard();
        }
        registry.sessions.clear();
        drop(registry);
        self.pending = FuturesUnordered::new();
        self.registry.settings_waker.wake();
    }
}
impl<C: quic::Connection<B>, B: Buf> Drop for Connection<C, B>
where
    C::BidiStream: quic::BidiStream<B>,
{
    fn drop(&mut self) {
        self.stop(None);
    }
}

impl<O: quic::OpenStreams<B> + Clone, B: Buf> Client<O, B>
where
    O::BidiStream: quic::BidiStream<B>,
{
    /// Clone a sender for ordinary HTTP/3 requests on this connection.
    pub fn send_request(&self) -> SendRequest<O, B> {
        self.sender.clone()
    }

    /// Establish a session using an HTTPS CONNECT request. The negotiated draft selects the token.
    ///
    /// Authority, path, authorization headers and Origin are supplied by the caller. Any supplied
    /// `:protocol` must agree with the selected draft. Non-success responses and incompatible
    /// response headers reset both CONNECT directions. Cancellation while waiting for the response does
    /// the same and releases the session reservation and queued streams.
    pub async fn connect(
        &mut self,
        mut request: Request<()>,
    ) -> Result<WebTransportSession<O::BidiStream, B>, ConnectError> {
        let negotiation = poll_fn(|cx| {
            self.registry.settings_waker.register(cx.waker());
            let registry = self.registry.inner.lock().unwrap();
            if !registry.open {
                return Poll::Ready(Err(ConnectError::DriverStopped));
            }
            match registry.negotiation {
                Some(result) => Poll::Ready(result.map_err(ConnectError::Settings)),
                None => Poll::Pending,
            }
        })
        .await?;
        let protocol = if negotiation.draft >= WebTransportDraft::Draft15 {
            Protocol::WEB_TRANSPORT_H3
        } else {
            Protocol::WEB_TRANSPORT
        };
        if request.method() != Method::CONNECT
            || request.uri().scheme_str() != Some("https")
            || request.uri().authority().is_none()
            || request.uri().path().is_empty()
            || request.headers().contains_key("sec-webtransport-protocol")
            || request
                .extensions()
                .get::<Protocol>()
                .is_some_and(|p| *p != protocol)
        {
            return Err(ConnectError::InvalidRequest);
        }
        request.extensions_mut().insert(protocol);
        // connect takes &mut self, so no other establishment can consume this cap meanwhile.
        {
            let mut registry = self.registry.inner.lock().unwrap();
            registry
                .sessions
                .retain(|_, session| session.strong_count() != 0);
            if registry.sessions.len() >= self.limits.sessions.get()
                || registry.sessions.len() as u64 >= negotiation.cap
            {
                return Err(ConnectError::SessionLimit);
            }
        }
        let stream = self.sender.send_request(request).await?;
        let mut pending = PendingConnect {
            stream: Some(stream),
            incoming: Arc::new(Incoming {
                state: Arc::default(),
                streams: Mutex::default(),
                wakers: Arc::default(),
                cap: self.limits.streams_per_session.get(),
            }),
        };
        let id = SessionId::from(pending.stream.as_ref().unwrap().id());
        {
            let mut registry = self.registry.inner.lock().unwrap();
            if !registry.open {
                return Err(ConnectError::DriverStopped);
            }
            registry
                .sessions
                .insert(id, Arc::downgrade(&pending.incoming));
        }
        let stream = pending.stream.as_mut().unwrap();
        stream.disable_grease();
        let response = stream.recv_response().await?;
        if !response.status().is_success() {
            return Err(ConnectError::Rejected(response.status()));
        }
        let draft_headers = response.headers().get_all("sec-webtransport-http3-draft");
        let mut drafts = draft_headers.iter();
        let header = drafts.next();
        if (negotiation.draft == WebTransportDraft::Draft02
            && header.map(|v| v.as_bytes()) != Some(b"draft02"))
            || (negotiation.draft != WebTransportDraft::Draft02 && header.is_some())
            || drafts.next().is_some()
            || response.headers().contains_key("sec-webtransport-protocol")
            || response
                .headers()
                .contains_key(http::header::CONTENT_LENGTH)
            || response
                .headers()
                .contains_key(http::header::TRANSFER_ENCODING)
        {
            return Err(ConnectError::InvalidResponse);
        }
        if pending.incoming.state.is_terminated() {
            return Err(ConnectError::DriverStopped);
        }
        Ok(WebTransportSession::new(
            id,
            negotiation.draft,
            pending.stream.take().unwrap(),
            pending.incoming.clone(),
        ))
    }
}

struct PendingConnect<S: quic::BidiStream<B>, B: Buf> {
    stream: Option<RequestStream<S, B>>,
    incoming: Arc<Incoming<S, B>>,
}
impl<S: quic::BidiStream<B>, B: Buf> Drop for PendingConnect<S, B> {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.stream {
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            self.incoming
                .state
                .terminate(Err(SessionError::OwnerDropped));
        }
    }
}

// Only two QUIC varints are parsed, never an H3 frame length or application payload.
struct Prefix<S: quic::BidiStream<B>, B: Buf> {
    stream: Option<BufRecvStream<S, B>>,
    bytes: [u8; 8],
    len: usize,
    signal: bool,
}
impl<S: quic::BidiStream<B>, B: Buf> Prefix<S, B> {
    fn new(stream: S) -> Self {
        Self {
            stream: Some(BufRecvStream::new(stream)),
            bytes: [0; 8],
            len: 0,
            signal: false,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<SessionId, ()>> {
        let stream = self.stream.as_mut().unwrap();
        // Includes empty transport chunks; a malicious backend cannot monopolize a poll.
        for _ in 0..WORK_BUDGET {
            if let Some(chunk) = stream.take_chunk(1) {
                self.bytes[self.len] = chunk[0];
                self.len += 1;
                let needed = 1 << (self.bytes[0] >> 6);
                if self.len == needed {
                    let value = VarInt::decode(&mut &self.bytes[..self.len])
                        .map_err(|_| ())?
                        .into_inner();
                    if self.signal {
                        return Poll::Ready(SessionId::try_from(value).map_err(|_| ()));
                    }
                    if value != 0x41 {
                        return Poll::Ready(Err(()));
                    }
                    self.signal = true;
                    self.len = 0;
                }
            } else {
                match ready!(stream.poll_read(cx)) {
                    Ok(false) => {}
                    _ => return Poll::Ready(Err(())),
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
// No field is structurally pinned; transport polling takes &mut S throughout h3.
impl<S: quic::BidiStream<B>, B: Buf> Unpin for Prefix<S, B> {}
impl<S: quic::BidiStream<B>, B: Buf> Future for Prefix<S, B> {
    type Output = Option<(SessionId, BufRecvStream<S, B>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match ready!(this.poll(cx)) {
            Ok(id) => Poll::Ready(Some((id, this.stream.take().unwrap()))),
            Err(()) => Poll::Ready(None),
        }
    }
}
impl<S: quic::BidiStream<B>, B: Buf> Drop for Prefix<S, B> {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.stream {
            abort(stream, WT_SESSION_GONE);
        }
    }
}
