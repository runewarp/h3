//! Provides the server side WebTransport session

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, lock::Mutex as AsyncMutex, ready, Future};
use h3::{
    error::{connection_error_creators::CloseStream, Code, ConnectionError, StreamError},
    ext::{Protocol, WebTransportDraft},
    frame::FrameStream,
    quic::{self, OpenStreams, StreamId, WriteBuf},
    server::{Connection, RequestResolver, RequestStream},
    ConnectionState, SharedState,
};
use h3::{
    quic::SendStreamUnframed,
    stream::{BidiStreamHeader, BufRecvStream, UniStreamHeader},
};
use h3_datagram::{
    datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt},
    quic_traits,
};
use http::{Method, Request, Response, StatusCode};

use h3::webtransport::SessionId;

use crate::{
    capsule::{self, Capsule, CapsuleReader},
    state::{Registration, SessionState},
    stream::{BidiStream, RecvStream, SendStream},
};

pub use crate::state::{CloseInfo, SessionError};

mod detached;
mod session;
pub use detached::{new, Acceptor, ConnectError, Connection as ServerConnection, Limits};
pub use session::Session;

/// Session-specific opener independent of the ordinary H3 driver. Each open future clones
/// the backend opener, retaining its own pending transport future and waker under credit loss.
pub struct SessionOpener<C: quic::Connection<B>, B: Buf> {
    opener: C::OpenStreams,
    session_id: SessionId,
    state: Arc<SessionState>,
    shared: Arc<SharedState>,
}
impl<C: quic::Connection<B>, B: Buf> SessionOpener<C, B> {
    fn new(
        opener: C::OpenStreams,
        session_id: SessionId,
        state: Arc<SessionState>,
        shared: Arc<SharedState>,
    ) -> Self {
        Self {
            opener,
            session_id,
            state,
            shared,
        }
    }
    /// Full CONNECT stream ID fixed at session admission.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Open a stream for this session without borrowing or locking the H3 driver.
    /// Cancelling a partial prefix resets and stops the stream; blocked credit is independent
    /// for each future. Clone implementations must provide independent pending-open state.
    pub fn open_bi(&self) -> OpenBi<'_, C, B>
    where
        C::OpenStreams: Clone,
    {
        OpenBi {
            opener: self.opener.clone(),
            stream: None,
            session_id: self.session_id,
            valid_id: true,
            session: &self.state,
            registration: None,
            stream_handler: WTransportStreamHandler {
                shared: self.shared.clone(),
            },
        }
    }
    /// Open a unidirectional stream with the same per-future credit ownership.
    pub fn open_uni(&self) -> OpenUni<'_, C, B>
    where
        C::OpenStreams: Clone,
    {
        OpenUni {
            opener: self.opener.clone(),
            stream: None,
            session_id: self.session_id,
            valid_id: true,
            session: &self.state,
            registration: None,
            stream_handler: WTransportStreamHandler {
                shared: self.shared.clone(),
            },
        }
    }
}

type ConnectSendStream<C, B> =
    RequestStream<<<C as OpenStreams<B>>::BidiStream as quic::BidiStream<B>>::SendStream, B>;
type ConnectRecvStream<C, B> =
    RequestStream<<<C as OpenStreams<B>>::BidiStream as quic::BidiStream<B>>::RecvStream, B>;

/// The sending side of the CONNECT stream
struct ConnectSend<C: quic::Connection<B>, B: Buf>
where
    C::BidiStream: quic::BidiStream<B>,
{
    stream: ConnectSendStream<C, B>,
    /// The stream was finished or reset
    closed: bool,
}

/// The receiving side of the CONNECT stream
struct ConnectRecv<C: quic::Connection<B>, B: Buf>
where
    C::BidiStream: quic::BidiStream<B>,
{
    stream: ConnectRecvStream<C, B>,
    capsules: CapsuleReader,
    /// A close capsule terminates the session immediately; validate later data through FIN.
    close_received: bool,
    /// Retained so repeated closed() calls report trailing data consistently.
    end_error: Option<SessionError>,
    /// The client finished or reset its side of the CONNECT stream, or we stopped reading it
    ended: bool,
    data: Bytes,
}

const WORK_BUDGET: usize = 32;
impl<C: quic::Connection<B>, B: Buf> ConnectRecv<C, B>
where
    C::BidiStream: quic::BidiStream<B>,
{
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        if self.data.is_empty() {
            match ready!(self.stream.poll_recv_data(cx))? {
                Some(mut data) => self.data = data.copy_to_bytes(data.remaining()),
                None => return Poll::Ready(Ok(None)),
            }
        }
        let len = self.data.len().min(1024);
        Poll::Ready(Ok(Some(self.data.split_to(len))))
    }
}
struct LegacyCloseWrite<'a, C: quic::Connection<B>, B: Buf>
where
    C::BidiStream: quic::BidiStream<B>,
{
    send: &'a mut ConnectSend<C, B>,
    completed: bool,
}
impl<C: quic::Connection<B>, B: Buf> Drop for LegacyCloseWrite<'_, C, B>
where
    C::BidiStream: quic::BidiStream<B>,
{
    fn drop(&mut self) {
        if !self.completed {
            self.send.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            self.send.closed = true;
        }
    }
}

/// WebTransport session driver.
///
/// Maintains the session using the underlying HTTP/3 connection.
///
/// Similar to [`h3::server::Connection`](https://docs.rs/h3/latest/h3/server/struct.Connection.html) it is generic over the QUIC implementation and Buffer.
pub struct WebTransportSession<C, B>
where
    C: quic::Connection<B> + quic_traits::DatagramConnectionExt<B>,
    C::BidiStream: quic::BidiStream<B>,
    Connection<C, B>: HandleDatagramsExt<C, B>,
    B: Buf,
{
    // See: https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-2-3
    session_id: SessionId,
    /// The underlying HTTP/3 connection
    server_conn: Mutex<Connection<C, B>>,
    connect_stream_id: StreamId,
    // Sending can wait for flow control, so it uses an async mutex. Receiving is driven from
    // poll functions that never hold the lock across a suspension.
    connect_send: AsyncMutex<ConnectSend<C, B>>,
    connect_recv: Mutex<ConnectRecv<C, B>>,
    /// Shared with the session's streams
    state: Arc<SessionState>,
    opener: Mutex<C::OpenStreams>,
    /// The negotiated wire format
    draft: WebTransportDraft,
    /// Shared State
    ///
    /// Shared state is already in server_conn, but with this it is not necessary to lock the mutex
    shared: Arc<SharedState>,
}

impl<C, B> ConnectionState for WebTransportSession<C, B>
where
    C: quic::Connection<B> + quic_traits::DatagramConnectionExt<B>,
    C::BidiStream: quic::BidiStream<B>,
    Connection<C, B>: HandleDatagramsExt<C, B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

impl<C, B> WebTransportSession<C, B>
where
    Connection<C, B>: HandleDatagramsExt<C, B>,
    C: quic::Connection<B> + quic_traits::DatagramConnectionExt<B>,
    C::BidiStream: quic::BidiStream<B>,
    B: Buf,
{
    /// Accepts a *CONNECT* request for establishing a WebTransport session.
    ///
    /// This compatibility entry point owns the entire connection, including on rejection.
    /// Use [`new`] and [`Acceptor::accept`] to preserve ordinary intake after a rejected CONNECT
    /// and to admit multiple independently owned sessions. This path admits at most one session.
    pub async fn accept(
        request: Request<()>,
        mut stream: RequestStream<C::BidiStream, B>,
        mut conn: Connection<C, B>,
    ) -> Result<Self, StreamError> {
        let shared = conn.inner.shared.clone();

        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-7.1
        //# For this reason, the server MUST NOT process
        //# any incoming WebTransport requests until the client's SETTINGS have
        //# been received.
        poll_fn(|cx| conn.poll_peer_settings(cx))
            .await
            .map_err(StreamError::ConnectionError)?;

        let config = shared.settings();
        let negotiation = conn
            .advertised_settings()
            .as_ref()
            .ok_or("local SETTINGS were not advertised")
            .and_then(|local| crate::client::negotiate(local, &config));
        let draft = match negotiation {
            Ok(negotiation) => negotiation.draft,
            Err(reason) => {
                stream
                    .send_response(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(())
                            .unwrap(),
                    )
                    .await?;
                stream.finish().await?;
                stream.stop_sending(Code::H3_MESSAGE_ERROR);
                return Err(StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: reason.into(),
                });
            }
        };
        if !validate_wt_connect(&request, draft) {
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(())
                        .unwrap(),
                )
                .await?;
            stream.finish().await?;
            stream.stop_sending(Code::H3_MESSAGE_ERROR);
            return Err(StreamError::StreamError {
                code: Code::H3_MESSAGE_ERROR,
                reason: "invalid WebTransport CONNECT".into(),
            });
        }
        let mut response = Response::builder().status(StatusCode::OK);
        if draft == WebTransportDraft::Draft02 {
            response = response.header("sec-webtransport-http3-draft", "draft02");
        }
        let response = response.body(()).unwrap();

        stream.send_response(response).await?;

        let connect_stream_id = stream.send_id();
        let session_id = connect_stream_id.into();
        let conn_inner = &mut conn.inner.conn;
        let opener = Mutex::new(conn_inner.opener());
        // Safari 26 crashes its network process when a frame of an unknown type, such as the
        // grease frame h3 sends when finishing a stream, follows a WT_CLOSE_SESSION capsule.
        stream.disable_grease();
        let (send, recv) = stream.split();

        Ok(Self {
            session_id,
            opener,
            server_conn: Mutex::new(conn),
            connect_stream_id,
            connect_send: AsyncMutex::new(ConnectSend {
                stream: send,
                closed: false,
            }),
            connect_recv: Mutex::new(ConnectRecv {
                stream: recv,
                capsules: CapsuleReader::default(),
                close_received: false,
                end_error: None,
                ended: false,
                data: Bytes::new(),
            }),
            state: Arc::default(),
            draft,
            shared,
        })
    }

    /// Receive a datagram from the client
    pub fn datagram_reader(&self) -> DatagramReader<C::RecvDatagramHandler> {
        self.server_conn.lock().unwrap().get_datagram_reader()
    }

    /// Sends a datagram
    ///
    /// TODO: maybe make async. `quinn` does not require an async send
    pub fn datagram_sender(&self) -> DatagramSender<C::SendDatagramHandler, B> {
        self.server_conn
            .lock()
            .unwrap()
            .get_datagram_sender(self.connect_stream_id)
    }

    /// Accept an incoming unidirectional stream from the client, it reads the stream until EOF.
    pub fn accept_uni(&self) -> AcceptUni<'_, C, B> {
        AcceptUni {
            conn: &self.server_conn,
            session: &self.state,
            session_id: self.session_id,
        }
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// The returned resolver reads the first frame to determine whether the stream contains a
    /// WebTransport bidirectional stream or an HTTP/3 request.
    pub async fn accept_bi(&self) -> Result<Option<BiStreamResolver<C, B>>, ConnectionError> {
        let stream = poll_fn(|cx| {
            let mut conn = self.server_conn.lock().unwrap();
            conn.poll_accept_request_stream(cx)
        })
        .await?;

        Ok(stream.map(|stream| {
            let stream = FrameStream::new(BufRecvStream::new(stream));
            let resolver = self.server_conn.lock().unwrap().create_resolver(stream);
            BiStreamResolver {
                resolver,
                session: self.state.clone(),
                session_id: self.session_id,
            }
        }))
    }

    /// Open a new bidirectional stream
    pub fn open_bi(&self, session_id: SessionId) -> OpenBi<'_, C, B>
    where
        C::OpenStreams: Clone,
    {
        OpenBi {
            opener: self.opener.lock().unwrap().clone(),
            stream: None,
            session_id,
            valid_id: session_id == self.session_id,
            session: &self.state,
            registration: None,
            stream_handler: WTransportStreamHandler {
                shared: self.shared.clone(),
            },
        }
    }

    /// Open a new unidirectional stream
    pub fn open_uni(&self, session_id: SessionId) -> OpenUni<'_, C, B>
    where
        C::OpenStreams: Clone,
    {
        OpenUni {
            opener: self.opener.lock().unwrap().clone(),
            stream: None,
            session_id,
            valid_id: session_id == self.session_id,
            session: &self.state,
            registration: None,
            stream_handler: WTransportStreamHandler {
                shared: self.shared.clone(),
            },
        }
    }

    /// Returns the session id
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the WebTransport draft used by this session
    pub fn draft(&self) -> WebTransportDraft {
        self.draft
    }

    /// Closes the session with an application error code and message.
    ///
    /// The message is truncated to 1024 bytes. Streams of the session are reset with
    /// [`WT_SESSION_GONE`](crate::WT_SESSION_GONE) and no new streams can be opened. Does nothing
    /// if the session has already terminated.
    ///
    /// Await [`Self::closed`] with a deadline before closing the underlying connection.
    pub async fn close(&self, code: u32, reason: &str) -> Result<(), StreamError>
    where
        B: From<Bytes>,
    {
        let reason = capsule::truncate(reason, capsule::MAX_CLOSE_MESSAGE_LEN);
        if !self.state.terminate(Ok(CloseInfo {
            code,
            reason: reason.to_owned(),
        })) {
            return Ok(());
        }

        let mut send = self.connect_send.lock().await;
        if send.closed {
            return Ok(());
        }
        let mut write = LegacyCloseWrite {
            send: &mut send,
            completed: false,
        };
        write
            .send
            .stream
            .send_data(capsule::encode_close_session(code, reason).into())
            .await?;
        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
        //# An endpoint that sends a WT_CLOSE_SESSION capsule MUST immediately
        //# send a FIN on the CONNECT Stream.
        let result = write.send.stream.finish().await;
        if result.is_ok() {
            write.completed = true;
            write.send.closed = true;
        }
        result
    }

    /// Ask the peer to drain gracefully without terminating the session.
    pub async fn drain(&self) -> Result<(), StreamError>
    where
        B: From<Bytes>,
    {
        let mut send = self.connect_send.lock().await;
        if send.closed || self.state.is_terminated() {
            return Ok(());
        }
        let mut write = LegacyCloseWrite {
            send: &mut send,
            completed: false,
        };
        let result = write
            .send
            .stream
            .send_data(capsule::encode_drain_session().into())
            .await;
        write.completed = result.is_ok();
        result
    }

    /// Waits for the session to terminate and returns how it ended.
    ///
    /// The session terminates when either endpoint closes it, or when the CONNECT stream ends:
    /// a clean end without a close counts as a close with code 0 and an empty message.
    ///
    /// This returns once both sides of the CONNECT stream are closed. After [`Self::close`], that
    /// means waiting for the peer to close its side, which it does on receiving the close. Until
    /// then, closing the QUIC connection could lose the close, so wait for this first. If the
    /// client might not respond, wait with a timeout. This also applies after a client close
    /// capsule: the session terminates immediately, but this waits for FIN to reject trailing data.
    ///
    /// Closes from the peer are only noticed while this or [`Self::draining`] is being polled.
    pub async fn closed(&self) -> Result<CloseInfo, SessionError> {
        let mut registration = None;
        poll_fn(|cx| self.poll_connect_stream(cx, SessionState::is_terminated, &mut registration))
            .await;
        // After a close from this endpoint, wait for the peer to close its side of the CONNECT
        // stream. After a close from the peer, reject any further data before its FIN.
        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
        //# To avoid this, the endpoint SHOULD wait until all CONNECT streams have
        //# been closed by the peer before sending the CONNECTION_CLOSE
        let outcome = poll_fn(|cx| self.poll_connect_stream_end(cx, &mut registration))
            .await
            .and_then(|()| {
                self.state
                    .outcome()
                    .expect("session has terminated")
                    .clone()
            });

        // Then close our side in response, unless we closed the session.
        let mut send = self.connect_send.lock().await;
        if let Err(error) = &outcome {
            // Abort errors must never turn into a clean FIN, even after a local close.
            send.closed = true;
            send.stream
                .stop_stream(if matches!(error, SessionError::MalformedCapsule(_)) {
                    Code::H3_MESSAGE_ERROR
                } else {
                    Code::H3_REQUEST_CANCELLED
                });
        } else if !send.closed {
            let mut write = LegacyCloseWrite {
                send: &mut send,
                completed: false,
            };
            //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
            //# The recipient MUST either
            //# close or reset the stream in response.
            if write.send.stream.finish().await.is_ok() {
                write.completed = true;
                write.send.closed = true;
            }
        }

        outcome
    }

    /// Waits for the peer to finish or reset CONNECT, rejecting data after its close capsule.
    fn poll_connect_stream_end(
        &self,
        cx: &mut Context<'_>,
        registration: &mut Registration,
    ) -> Poll<Result<(), SessionError>> {
        self.state.register_connect(cx.waker(), registration);
        let waker = self.state.connect_waker();
        let mut stream_cx = Context::from_waker(&waker);

        if matches!(
            self.state.outcome(),
            Some(Err(SessionError::OwnerDropped | SessionError::Stream(_)))
        ) {
            let mut recv = self.connect_recv.lock().unwrap();
            recv.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            recv.ended = true;
            return Poll::Ready(Ok(()));
        }
        let mut recv = self.connect_recv.lock().unwrap();
        for _ in 0..WORK_BUDGET {
            if recv.ended {
                break;
            }
            let error = match ready!(recv.poll_chunk(&mut stream_cx)) {
                Ok(Some(data)) if recv.close_received && data.has_remaining() => {
                    //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
                    //# If any additional data is received on the CONNECT stream after receiving
                    //# a WT_CLOSE_SESSION capsule, the stream MUST be reset with H3_MESSAGE_ERROR.
                    Some(SessionError::MalformedCapsule(
                        "CONNECT stream data after WT_CLOSE_SESSION",
                    ))
                }
                Ok(Some(data)) => {
                    // A local close may have terminated the session before the peer's close
                    // arrived. Parse its capsules too, rather than discarding unchecked bytes.
                    recv.capsules.push(data);
                    let mut outcome = self.read_capsules(&mut recv.capsules);
                    if matches!(outcome, Some(Ok(_))) && !recv.data.is_empty() {
                        outcome = Some(Err(SessionError::MalformedCapsule(
                            "CONNECT stream data after WT_CLOSE_SESSION",
                        )));
                    }
                    match outcome {
                        Some(Ok(_)) => {
                            recv.close_received = true;
                            None
                        }
                        Some(Err(err)) => Some(err),
                        None => None,
                    }
                }
                Ok(None) => {
                    recv.ended = true;
                    (!recv.capsules.is_empty()).then_some(SessionError::MalformedCapsule(
                        "CONNECT stream ended within a capsule",
                    ))
                }
                Err(_) => {
                    recv.ended = true;
                    None
                }
            };
            if let Some(error) = error {
                recv.end_error = Some(error);
                recv.stream.stop_sending(Code::H3_MESSAGE_ERROR);
                recv.ended = true;
            }
        }
        if recv.ended {
            Poll::Ready(recv.end_error.clone().map_or(Ok(()), Err))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// Waits until the peer asks to close the session gracefully, or the session terminates.
    pub async fn draining(&self) {
        let mut registration = None;
        poll_fn(|cx| {
            self.poll_connect_stream(
                cx,
                |state| state.is_draining() || state.is_terminated(),
                &mut registration,
            )
        })
        .await
    }

    /// Reads capsules from the CONNECT stream until `done` returns true.
    fn poll_connect_stream(
        &self,
        cx: &mut Context<'_>,
        done: impl Fn(&SessionState) -> bool,
        registration: &mut Registration,
    ) -> Poll<()> {
        // Both closed() and draining() may drive CONNECT reads. Wake those readers together,
        // leaving streams and open futures asleep until the session changes.
        self.state.register_connect(cx.waker(), registration);
        let waker = self.state.connect_waker();
        let mut stream_cx = Context::from_waker(&waker);

        let mut recv = self.connect_recv.lock().unwrap();
        for _ in 0..WORK_BUDGET {
            if done(&self.state) {
                return Poll::Ready(());
            }
            if self.state.is_terminated() {
                // The session ended before `done` became true.
                return Poll::Ready(());
            }

            let outcome = match ready!(recv.poll_chunk(&mut stream_cx)) {
                Ok(Some(data)) => {
                    recv.capsules.push(data);
                    let mut outcome = self.read_capsules(&mut recv.capsules);
                    if matches!(outcome, Some(Ok(_))) && !recv.data.is_empty() {
                        outcome = Some(Err(SessionError::MalformedCapsule(
                            "CONNECT stream data after WT_CLOSE_SESSION",
                        )));
                    }
                    match outcome {
                        Some(outcome) => outcome,
                        None => continue,
                    }
                }
                Ok(None) if recv.capsules.is_empty() => {
                    recv.ended = true;
                    //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
                    //# Cleanly terminating a CONNECT stream without a WT_CLOSE_SESSION
                    //# capsule SHALL be semantically equivalent to terminating it with a
                    //# WT_CLOSE_SESSION capsule that has an error code of 0 and an empty
                    //# error string.
                    Ok(CloseInfo {
                        code: 0,
                        reason: String::new(),
                    })
                }
                Ok(None) => {
                    recv.ended = true;
                    Err(SessionError::MalformedCapsule(
                        "CONNECT stream ended within a capsule",
                    ))
                }
                Err(err) => {
                    recv.ended = true;
                    Err(SessionError::Stream(Arc::new(err)))
                }
            };

            match &outcome {
                Ok(_) if !recv.ended => {
                    recv.close_received = true;
                }
                Err(SessionError::MalformedCapsule(_)) => {
                    recv.end_error = outcome.clone().err();
                    recv.stream.stop_sending(Code::H3_MESSAGE_ERROR);
                    recv.ended = true;
                }
                _ => {}
            }
            self.state.terminate(outcome);
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Handles the complete capsules received so far. Returns the outcome if the session ended.
    fn read_capsules(
        &self,
        capsules: &mut CapsuleReader,
    ) -> Option<Result<CloseInfo, SessionError>> {
        loop {
            match capsules.next() {
                Ok(Some(Capsule::CloseSession { code, reason })) => {
                    if !capsules.is_empty() {
                        return Some(Err(SessionError::MalformedCapsule(
                            "CONNECT stream data after WT_CLOSE_SESSION",
                        )));
                    }
                    return Some(Ok(CloseInfo { code, reason }));
                }
                Ok(Some(Capsule::DrainSession)) => self.state.drain(),
                Ok(None) => return None,
                Err(capsule::MalformedCapsule(reason)) => {
                    return Some(Err(SessionError::MalformedCapsule(reason)))
                }
            }
        }
    }
}

impl<C, B> Drop for WebTransportSession<C, B>
where
    C: quic::Connection<B> + quic_traits::DatagramConnectionExt<B>,
    C::BidiStream: quic::BidiStream<B>,
    Connection<C, B>: HandleDatagramsExt<C, B>,
    B: Buf,
{
    fn drop(&mut self) {
        // Dropping the CONNECT stream finishes it, which ends the session like a close with code 0.
        self.state.terminate(Ok(CloseInfo {
            code: 0,
            reason: String::new(),
        }));
    }
}

/// Resolves an accepted bidirectional stream as either WebTransport or HTTP/3.
pub struct BiStreamResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    resolver: RequestResolver<C, B>,
    session_id: SessionId,
    session: Arc<SessionState>,
}

impl<C, B> BiStreamResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Reads the first frame and classifies the accepted stream.
    pub async fn resolve(self) -> Result<AcceptedBi<C, B>, StreamError>
    where
        C::BidiStream: quic::BidiStream<B>,
    {
        match detached::Classify::new(self.resolver).await {
            Some(detached::Classified::Session(id, mut stream)) => {
                if id != self.session_id || self.session.is_terminated() {
                    crate::client::abort(&mut stream, crate::WT_SESSION_GONE);
                    return Err(session_terminated());
                }
                Ok(AcceptedBi::BidiStream(
                    id,
                    BidiStream::with_session(stream, self.session),
                ))
            }
            Some(detached::Classified::Request(resolver)) => {
                let (req, resp) = resolver.resolve_request().await?;
                Ok(AcceptedBi::Request(req, resp))
            }
            None => Err(session_terminated()),
        }
    }
}

/// Streams are opened, but the initial webtransport header has not been sent
type PendingStreams<C, B> = (
    BidiStream<<C as quic::OpenStreams<B>>::BidiStream, B>,
    WriteBuf<&'static [u8]>,
);

/// Streams are opened, but the initial webtransport header has not been sent
type PendingUniStreams<C, B> = (
    SendStream<<C as quic::OpenStreams<B>>::SendStream, B>,
    WriteBuf<&'static [u8]>,
);

/// Future for opening a bidi stream
pub struct OpenBi<'a, C: quic::Connection<B>, B: Buf> {
    opener: C::OpenStreams,
    stream: Option<PendingStreams<C, B>>,
    session_id: SessionId,
    valid_id: bool,
    session: &'a Arc<SessionState>,
    registration: Registration,
    stream_handler: WTransportStreamHandler,
}
struct WTransportStreamHandler {
    shared: Arc<SharedState>,
}

impl ConnectionState for WTransportStreamHandler {
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

impl CloseStream for WTransportStreamHandler {}

impl<'a, B, C> Future for OpenBi<'a, C, B>
where
    C: quic::Connection<B>,
    B: Buf,
    C::BidiStream: SendStreamUnframed<B>,
{
    type Output = Result<BidiStream<C::BidiStream, B>, StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let p = self.get_mut();
        loop {
            match &mut p.stream {
                Some((stream, buf)) => {
                    while buf.has_remaining() {
                        ready!(stream.poll_send(cx, buf))
                            .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    }

                    let (stream, _) = p.stream.take().unwrap();
                    return Poll::Ready(Ok(stream));
                }
                None => {
                    if !p.valid_id || p.session.is_terminated() {
                        return Poll::Ready(Err(session_terminated()));
                    }
                    let opener = &mut p.opener;
                    // Open the stream first
                    let res = opener.poll_open_bidi(cx);
                    if res.is_pending() {
                        p.session.register(cx.waker(), &mut p.registration);
                        // Closing the session must also wake opens waiting for QUIC credit.
                        if !p.valid_id || p.session.is_terminated() {
                            return Poll::Ready(Err(session_terminated()));
                        }
                    }
                    let res = ready!(res)
                        .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    let stream =
                        BidiStream::with_session(BufRecvStream::new(res), (*p.session).clone());

                    let buf = WriteBuf::from(BidiStreamHeader::WebTransportBidi(p.session_id));
                    p.stream = Some((stream, buf));
                }
            }
        }
    }
}

/// Opens a unidirectional stream
pub struct OpenUni<'a, C: quic::Connection<B>, B: Buf> {
    opener: C::OpenStreams,
    stream: Option<PendingUniStreams<C, B>>,
    // Future for opening a uni stream
    session_id: SessionId,
    valid_id: bool,
    session: &'a Arc<SessionState>,
    registration: Registration,
    stream_handler: WTransportStreamHandler,
}
impl<'a, C, B> Future for OpenUni<'a, C, B>
where
    C: quic::Connection<B>,
    B: Buf,
    C::SendStream: SendStreamUnframed<B>,
{
    type Output = Result<SendStream<C::SendStream, B>, StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let p = self.get_mut();
        loop {
            match &mut p.stream {
                Some((send, buf)) => {
                    while buf.has_remaining() {
                        ready!(send.poll_send(cx, buf))
                            .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    }
                    let (send, buf) = p.stream.take().unwrap();
                    assert!(!buf.has_remaining());
                    return Poll::Ready(Ok(send));
                }
                None => {
                    if !p.valid_id || p.session.is_terminated() {
                        return Poll::Ready(Err(session_terminated()));
                    }
                    let opener = &mut p.opener;
                    let send = opener.poll_open_send(cx);
                    if send.is_pending() {
                        p.session.register(cx.waker(), &mut p.registration);
                        if !p.valid_id || p.session.is_terminated() {
                            return Poll::Ready(Err(session_terminated()));
                        }
                    }
                    let send = ready!(send)
                        .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    let send = BufRecvStream::new(send);
                    let send = SendStream::with_session(send, (*p.session).clone());

                    let buf = WriteBuf::from(UniStreamHeader::WebTransportUni(p.session_id));
                    p.stream = Some((send, buf));
                }
            }
        }
    }
}

/// An accepted incoming bidirectional stream.
///
/// Since
// Todo
#[allow(clippy::large_enum_variant)]
pub enum AcceptedBi<C: quic::Connection<B>, B: Buf> {
    /// An incoming bidirectional stream
    BidiStream(SessionId, BidiStream<C::BidiStream, B>),
    /// An incoming HTTP/3 request, passed through a webtransport session.
    ///
    /// This makes it possible to respond to multiple CONNECT requests
    Request(Request<()>, RequestStream<C::BidiStream, B>),
}

/// Future for [`WebTransportSession::accept_uni`]
pub struct AcceptUni<'a, C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    conn: &'a Mutex<Connection<C, B>>,
    session_id: SessionId,
    session: &'a Arc<SessionState>,
}

impl<'a, C, B> Future for AcceptUni<'a, C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    type Output = Result<Option<(SessionId, RecvStream<C::RecvStream, B>)>, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut conn = self.conn.lock().unwrap();
        conn.inner.poll_accept_recv(cx)?;

        // Get the currently available streams
        let streams = conn.inner.accepted_streams_mut();
        while let Some((id, mut stream)) = streams.wt_uni_streams.pop() {
            if id != self.session_id || self.session.is_terminated() {
                quic::RecvStream::stop_sending(&mut stream, crate::WT_SESSION_GONE);
                continue;
            }
            return Poll::Ready(Ok(Some((
                id,
                RecvStream::with_session(stream, self.session.clone()),
            ))));
        }

        Poll::Pending
    }
}

//= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
//# it MUST NOT send any new datagrams or open any new streams.
fn session_terminated() -> StreamError {
    StreamError::StreamError {
        code: Code::from(crate::WT_SESSION_GONE),
        reason: "WebTransport session terminated".to_string(),
    }
}

fn validate_wt_connect(request: &Request<()>, draft: WebTransportDraft) -> bool {
    let protocol = if draft >= WebTransportDraft::Draft15 {
        Protocol::WEB_TRANSPORT_H3
    } else {
        Protocol::WEB_TRANSPORT
    };
    let mut offers = request
        .headers()
        .get_all("sec-webtransport-http3-draft02")
        .iter();
    request.method() == Method::CONNECT
        && request.extensions().get::<Protocol>() == Some(&protocol)
        && request.uri().scheme_str() == Some("https")
        && request.uri().authority().is_some()
        && !request.uri().path().is_empty()
        && !request.headers().contains_key("sec-webtransport-protocol")
        && (draft != WebTransportDraft::Draft02
            || (offers.next().map(|v| v.as_bytes()) == Some(b"1") && offers.next().is_none()))
}

impl<C: quic::Connection<B>, B: Buf> Unpin for OpenBi<'_, C, B> {}
impl<C: quic::Connection<B>, B: Buf> Unpin for OpenUni<'_, C, B> {}
impl<C: quic::Connection<B>, B: Buf> Drop for OpenBi<'_, C, B> {
    fn drop(&mut self) {
        if let Some((stream, _)) = &mut self.stream {
            quic::SendStream::reset(stream, crate::WT_SESSION_GONE);
            quic::RecvStream::stop_sending(stream, crate::WT_SESSION_GONE);
        }
    }
}
impl<C: quic::Connection<B>, B: Buf> Drop for OpenUni<'_, C, B> {
    fn drop(&mut self) {
        if let Some((stream, _)) = &mut self.stream {
            quic::SendStream::reset(stream, crate::WT_SESSION_GONE);
        }
    }
}
