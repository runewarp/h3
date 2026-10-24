//! Connection-scoped Server dispatch and admission.
use super::{Session, SessionOpener};
pub use crate::client::ConnectError;
use crate::{
    client::{abort, negotiate, Incoming, Negotiated, Prefix},
    state::WakerSet,
    SessionId, WT_SESSION_GONE,
};
use bytes::Buf;
use futures_util::{future::poll_fn, ready, stream::FuturesUnordered, Future, StreamExt};
use h3::{
    error::{Code, ConnectionError, StreamError},
    ext::WebTransportDraft,
    frame::FrameStream,
    proto::varint::VarInt,
    quic::{self},
    server::{RequestResolver, RequestStream},
    stream::BufRecvStream,
    ConnectionState, Settings,
};
use http::{Request, Response, StatusCode};
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};
const WORK_BUDGET: usize = 32;
const BUFFERED_STREAM_REJECTED: u64 = 0x3994bd84;

/// Independent Server admission, parsing and queue limits. Transport windows bound chunks.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent active sessions, including CONNECT responses still being sent.
    pub sessions: NonZeroUsize,
    /// Maximum raw bidi streams accepted per poll, additionally capped at 32.
    pub incoming: NonZeroUsize,
    /// Incomplete bidi classifiers. Saturation resets newest arrivals, including requests.
    pub pending_prefixes: NonZeroUsize,
    /// Validated bidi streams queued per session, including before CONNECT succeeds.
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
struct Registry<S: quic::BidiStream<B>, B: Buf> {
    inner: Mutex<RegistryInner<S, B>>,
    settings_wakers: Arc<WakerSet>,
}
struct RegistryInner<S: quic::BidiStream<B>, B: Buf> {
    sessions: BTreeMap<SessionId, Weak<Incoming<S, B>>>,
    negotiation: Option<Result<Negotiated, &'static str>>,
    open: bool,
}
/// Ordinary H3 intake and bounded WebTransport stream dispatch. Keep `accept()` polled
/// independently of detached sessions. No task is spawned. Drop terminates all sessions.
pub struct Connection<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> {
    core: h3::server::Connection<C, B>,
    registry: Arc<Registry<C::BidiStream, B>>,
    pending: FuturesUnordered<Classify<C, B>>,
    limits: Limits,
    local: Option<Settings>,
}
/// Cloneable session admission handle, tied to one connection. Authentication and application
/// request policy belong to its caller. Admission reserves capacity before sending a response.
pub struct Acceptor<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> {
    registry: Arc<Registry<C::BidiStream, B>>,
    opener: C::OpenStreams,
    shared: Arc<h3::SharedState>,
    limits: Limits,
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Clone for Acceptor<C, B>
where
    C::OpenStreams: Clone,
{
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            opener: self.opener.clone(),
            shared: self.shared.clone(),
            limits: self.limits,
        }
    }
}
/// Attach bounded extension dispatch before driving the H3 Server. `Limits.incoming` bounds
/// raw stream intake per poll; `pending_prefixes` bounds incomplete classifiers. Ordinary
/// requests are returned directly, never stored in session queues. Configure both peers for
/// WebTransport, datagrams, extended CONNECT and compatible drafts before calling this.
pub fn new<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf>(
    core: h3::server::Connection<C, B>,
    limits: Limits,
) -> (Connection<C, B>, Acceptor<C, B>) {
    let local = core.advertised_settings();
    let opener = core.inner.conn.opener();
    let shared = core.inner.shared.clone();
    let registry = Arc::new(Registry {
        inner: Mutex::new(RegistryInner {
            sessions: BTreeMap::new(),
            negotiation: None,
            open: true,
        }),
        settings_wakers: Arc::default(),
    });
    (
        Connection {
            core,
            registry: registry.clone(),
            pending: FuturesUnordered::new(),
            limits,
            local,
        },
        Acceptor {
            registry,
            opener,
            shared,
            limits,
        },
    )
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Connection<C, B> {
    /// Accept an ordinary request resolver while dispatching session streams independently.
    /// Cancelling this future preserves incomplete prefixes. Resolve requests in application
    /// tasks with deadlines; a slow header must not prevent the next call to `accept()`.
    pub async fn accept(&mut self) -> Result<Option<RequestResolver<C, B>>, ConnectionError> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
    /// Preserve ordinary HTTP/3 GOAWAY behavior alongside active sessions.
    pub async fn shutdown(&mut self, max_requests: usize) -> Result<(), ConnectionError> {
        self.core.shutdown(max_requests).await
    }
    /// Poll ordinary request intake and bounded session prefix dispatch.
    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RequestResolver<C, B>>, ConnectionError>> {
        // poll_accept_request_stream also drives SETTINGS, GOAWAY and request completion.
        for _ in 0..self.limits.incoming.get().min(WORK_BUDGET) {
            let result = self.core.poll_accept_request_stream(cx);
            // Uni dispatch is outside this API's supported subset. Do not retain the core's
            // otherwise unconsumed WebTransport uni queue across polls.
            for (_, mut stream) in self
                .core
                .inner
                .accepted_streams_mut()
                .wt_uni_streams
                .drain(..)
            {
                quic::RecvStream::stop_sending(&mut stream, WT_SESSION_GONE);
            }
            match result {
                Poll::Ready(Ok(Some(stream))) => {
                    // Every accepted raw stream needs RequestEnd, including excess streams.
                    // Otherwise rejected streams remain in core H3's ongoing request set.
                    let mut resolver = self
                        .core
                        .create_resolver(FrameStream::new(BufRecvStream::new(stream)));
                    if self.pending.len() >= self.limits.pending_prefixes.get() {
                        abort(&mut resolver.frame_stream.stream, BUFFERED_STREAM_REJECTED);
                    } else {
                        self.pending.push(Classify::new(resolver));
                    }
                }
                Poll::Ready(Ok(None)) => {
                    self.stop(None);
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Err(error)) => {
                    self.stop(Some(error.clone()));
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => break,
            }
            cx.waker().wake_by_ref();
        }
        if let Some(peer) = self.core.inner.shared.peer_settings() {
            let mut inner = self.registry.inner.lock().unwrap();
            if inner.negotiation.is_none() {
                inner.negotiation = Some(
                    self.local
                        .as_ref()
                        .ok_or("local SETTINGS were not advertised")
                        .and_then(|local| negotiate(local, peer)),
                );
                drop(inner);
                self.registry.settings_wakers.wake_all();
            }
        }
        for _ in 0..WORK_BUDGET {
            match self.pending.poll_next_unpin(cx) {
                Poll::Ready(Some(Some(Classified::Request(stream)))) => {
                    return Poll::Ready(Ok(Some(stream)))
                }
                Poll::Ready(Some(Some(Classified::Session(id, mut stream)))) => {
                    let inner = self.registry.inner.lock().unwrap();
                    let session = inner.sessions.get(&id).and_then(Weak::upgrade);
                    if let Some(session) = session {
                        session.deliver(stream);
                    } else {
                        abort(&mut stream, WT_SESSION_GONE);
                    }
                }
                Poll::Ready(Some(None)) => {}
                _ => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn stop(&mut self, error: Option<ConnectionError>) {
        let mut inner = self.registry.inner.lock().unwrap();
        inner.open = false;
        for session in inner.sessions.values().filter_map(Weak::upgrade) {
            session.state.terminate(Err(error
                .clone()
                .map_or(super::SessionError::OwnerDropped, |e| {
                    super::SessionError::Stream(Arc::new(StreamError::ConnectionError(e)))
                })));
            session.discard();
        }
        inner.sessions.clear();
        drop(inner);
        self.pending = FuturesUnordered::new();
        self.registry.settings_wakers.wake_all();
    }
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Drop for Connection<C, B> {
    fn drop(&mut self) {
        self.stop(None);
    }
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Acceptor<C, B>
where
    C::OpenStreams: Clone,
{
    /// Validate and accept an HTTPS Extended CONNECT. Invalid requests receive 400; missing or
    /// incompatible negotiation receives 400; exhausted local/negotiated caps receive 429.
    /// Rejections never yield a session or deliberately close ordinary H3. Cancellation resets
    /// CONNECT and releases its reservation. The stream must belong to this connection.
    pub async fn accept(
        &self,
        request: Request<()>,
        stream: RequestStream<C::BidiStream, B>,
    ) -> Result<Session<C, B>, ConnectError> {
        if !std::ptr::eq(stream.shared_state(), &*self.shared) {
            let mut stream = stream;
            stream.stop_stream(Code::H3_MESSAGE_ERROR);
            stream.stop_sending(Code::H3_MESSAGE_ERROR);
            return Err(ConnectError::InvalidRequest);
        }
        let incoming = Arc::new(Incoming {
            state: Arc::default(),
            streams: Mutex::default(),
            wakers: Arc::default(),
            cap: self.limits.streams_per_session.get(),
        });
        let mut pending = Pending {
            stream: Some(stream),
            incoming: incoming.clone(),
        };
        let mut registration = None;
        let negotiation = poll_fn(|cx| {
            self.registry
                .settings_wakers
                .register(cx.waker(), &mut registration);
            let inner = self.registry.inner.lock().unwrap();
            if !inner.open {
                return Poll::Ready(Err(ConnectError::DriverStopped));
            }
            match inner.negotiation {
                Some(result) => Poll::Ready(result.map_err(ConnectError::Settings)),
                None => Poll::Pending,
            }
        })
        .await;
        let negotiation = match negotiation {
            Ok(n) => n,
            Err(e) => {
                pending.reject(StatusCode::BAD_REQUEST).await?;
                return Err(e);
            }
        };
        if !super::validate_wt_connect(&request, negotiation.draft) {
            pending.reject(StatusCode::BAD_REQUEST).await?;
            return Err(ConnectError::InvalidRequest);
        }
        let id = SessionId::from(pending.stream.as_ref().unwrap().send_id());
        let admitted = {
            let mut inner = self.registry.inner.lock().unwrap();
            inner.sessions.retain(|_, weak| {
                weak.upgrade()
                    .is_some_and(|session| !session.state.is_terminated())
            });
            if !inner.open {
                return Err(ConnectError::DriverStopped);
            }
            if inner.sessions.len() >= self.limits.sessions.get()
                || inner.sessions.len() as u64 >= negotiation.cap
                || inner.sessions.contains_key(&id)
            {
                false
            } else {
                inner.sessions.insert(id, Arc::downgrade(&incoming));
                true
            }
        };
        if !admitted {
            pending.reject(StatusCode::TOO_MANY_REQUESTS).await?;
            return Err(ConnectError::SessionLimit);
        }
        let mut response = Response::builder().status(StatusCode::OK);
        if negotiation.draft == WebTransportDraft::Draft02 {
            response = response.header("sec-webtransport-http3-draft", "draft02");
        }
        let stream = pending.stream.as_mut().unwrap();
        stream.disable_grease();
        stream.send_response(response.body(()).unwrap()).await?;
        if incoming.state.is_terminated() {
            return Err(ConnectError::DriverStopped);
        }
        Ok(Session::new(
            SessionOpener::new(
                self.opener.clone(),
                id,
                incoming.state.clone(),
                self.shared.clone(),
            ),
            id,
            negotiation.draft,
            pending.stream.take().unwrap(),
            incoming,
        ))
    }
}
struct Pending<S: quic::BidiStream<B>, B: Buf> {
    stream: Option<RequestStream<S, B>>,
    incoming: Arc<Incoming<S, B>>,
}
impl<S: quic::BidiStream<B>, B: Buf> Pending<S, B> {
    async fn reject(&mut self, status: StatusCode) -> Result<(), StreamError> {
        let stream = self.stream.as_mut().unwrap();
        stream
            .send_response(Response::builder().status(status).body(()).unwrap())
            .await?;
        stream.finish().await?;
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        self.stream.take();
        Ok(())
    }
}
impl<S: quic::BidiStream<B>, B: Buf> Drop for Pending<S, B> {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.stream {
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            self.incoming
                .state
                .terminate(Err(super::SessionError::OwnerDropped));
        }
    }
}
pub(super) enum Classified<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> {
    Request(RequestResolver<C, B>),
    Session(SessionId, BufRecvStream<C::BidiStream, B>),
}
pub(super) struct Classify<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> {
    resolver: Option<RequestResolver<C, B>>,
    prefix: Option<Prefix<C::BidiStream, B>>,
    skip: u64,
    skipped: bool,
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Classify<C, B> {
    pub(super) fn new(resolver: RequestResolver<C, B>) -> Self {
        Self {
            resolver: Some(resolver),
            prefix: None,
            skip: 0,
            skipped: false,
        }
    }
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Unpin for Classify<C, B> {}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Future for Classify<C, B> {
    type Output = Option<Classified<C, B>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        for _ in 0..WORK_BUDGET {
            if let Some(prefix) = &mut this.prefix {
                return Pin::new(prefix)
                    .poll(cx)
                    .map(|result| result.map(|(id, stream)| Classified::Session(id, stream)));
            }
            let stream = &mut this.resolver.as_mut().unwrap().frame_stream.stream;
            if this.skip > 0 {
                if let Some(chunk) = stream.take_chunk(this.skip.try_into().unwrap_or(usize::MAX)) {
                    this.skip -= chunk.len() as u64;
                    continue;
                }
            } else {
                let mut buf = stream.buffered();
                let before = buf.remaining();
                if let Ok(value) = VarInt::decode(&mut buf) {
                    match value.into_inner() {
                        // Preserve core HTTP/3 validation of known and reserved frame types.
                        0..=9 | 0xd => {
                            drop(buf);
                            return Poll::Ready(Some(Classified::Request(
                                this.resolver.take().unwrap(),
                            )));
                        }
                        0x41 if !this.skipped => {
                            drop(buf);
                            let resolver = this.resolver.take().unwrap();
                            this.prefix =
                                Some(Prefix::buffered(resolver.frame_stream.into_inner()));
                            continue;
                        }
                        0x41 => return Poll::Ready(None), // WT must start at byte zero.
                        _ => {
                            // RFC 9114 section 7.2.8: ignore unknown frames. Skip their payload
                            // incrementally, never buffer a peer-declared length in this driver.
                            if let Ok(len) = VarInt::decode(&mut buf) {
                                let mut header = before - buf.remaining();
                                drop(buf);
                                while header > 0 {
                                    header -= stream.take_chunk(header).unwrap().len();
                                }
                                this.skip = len.into_inner();
                                this.skipped = true;
                                continue;
                            }
                        }
                    }
                }
            }
            match ready!(stream.poll_read(cx)) {
                Ok(false) => {}
                _ => return Poll::Ready(None),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Drop for Classify<C, B> {
    fn drop(&mut self) {
        if let Some(resolver) = &mut self.resolver {
            abort(&mut resolver.frame_stream.stream, WT_SESSION_GONE);
        }
    }
}
