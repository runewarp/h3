//! Provides the server side WebTransport session

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, lock::Mutex as AsyncMutex, ready, Future};
use h3::{
    error::{
        connection_error_creators::CloseStream, internal_error::InternalConnectionError, Code,
        ConnectionError, StreamError,
    },
    ext::{Protocol, WebTransportDraft},
    frame::FrameStream,
    proto::frame::Frame,
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
use pin_project_lite::pin_project;

use crate::{
    capsule::{self, Capsule, CapsuleReader},
    state::SessionState,
    stream::{BidiStream, RecvStream, SendStream},
};

pub use crate::state::{CloseInfo, SessionError};

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
    /// The client finished or reset its side of the CONNECT stream, or we stopped reading it
    ended: bool,
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
    /// TODO: is the API or the user responsible for validating the CONNECT request?
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

        if !config.enable_webtransport() {
            return Err(StreamError::ConnectionError(
                conn.inner
                    .handle_connection_error(InternalConnectionError::new(
                        Code::H3_SETTINGS_ERROR,
                        "webtransport is not supported by client".to_string(),
                    )),
            ));
        }

        let Some(draft) = conn
            .inner
            .config
            .settings
            .negotiate_webtransport_draft(&config)
        else {
            return Err(StreamError::ConnectionError(
                conn.inner
                    .handle_connection_error(InternalConnectionError::new(
                        Code::H3_SETTINGS_ERROR,
                        format!(
                            "no webtransport draft is supported by both client ({:?}) and server ({:?})",
                            config.webtransport_drafts().collect::<Vec<_>>(),
                            conn.inner.config.settings.webtransport_drafts().collect::<Vec<_>>(),
                        ),
                    )),
            ));
        };
        tracing::debug!("Using WebTransport {draft:?}");

        if !config.enable_datagram() {
            return Err(StreamError::ConnectionError(
                conn.inner
                    .handle_connection_error(InternalConnectionError::new(
                        Code::H3_SETTINGS_ERROR,
                        "datagrams are not supported by client".to_string(),
                    )),
            ));
        }

        // The peer is responsible for validating our side of the webtransport support.
        //
        // However, it is still advantageous to show a log on the server as (attempting) to
        // establish a WebTransportSession without the proper h3 config is usually a mistake.
        if !conn.inner.config.settings.enable_webtransport() {
            tracing::warn!("Server does not support webtransport");
        }

        if !conn.inner.config.settings.enable_datagram() {
            tracing::warn!("Server does not support datagrams");
        }

        if !conn.inner.config.settings.enable_extended_connect() {
            tracing::warn!("Server does not support CONNECT");
        }

        // Respond to the CONNECT request.

        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.3
        let response = if validate_wt_connect(&request) {
            let mut response = Response::builder();
            if draft == WebTransportDraft::Draft02 {
                //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-02#section-6
                //# The server SHALL reply with a Sec-
                //# Webtransport-Http3-Draft header indicating the selected version; its
                //# value SHALL be draft02 for the version described in this draft.
                response = response.header("sec-webtransport-http3-draft", "draft02");
            }
            response.status(StatusCode::OK).body(()).unwrap()
        } else {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap()
        };

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
                ended: false,
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
            }
        }))
    }

    /// Open a new bidirectional stream
    pub fn open_bi(&self, session_id: SessionId) -> OpenBi<'_, C, B> {
        OpenBi {
            opener: &self.opener,
            stream: None,
            session_id,
            session: &self.state,
            stream_handler: WTransportStreamHandler {
                shared: self.shared.clone(),
            },
        }
    }

    /// Open a new unidirectional stream
    pub fn open_uni(&self, session_id: SessionId) -> OpenUni<'_, C, B> {
        OpenUni {
            opener: &self.opener,
            stream: None,
            session_id,
            session: &self.state,
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
    /// Await [`Self::closed`] before dropping the session: dropping it closes the connection,
    /// which can lose the close.
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
        send.closed = true;
        send.stream
            .send_data(capsule::encode_close_session(code, reason).into())
            .await?;
        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
        //# An endpoint that sends a WT_CLOSE_SESSION capsule MUST immediately
        //# send a FIN on the CONNECT Stream.
        send.stream.finish().await
    }

    /// Asks the client to close the session gracefully, for example before the server shuts down.
    ///
    /// The session stays usable. Clients see this through `WebTransport.draining`.
    pub async fn drain(&self) -> Result<(), StreamError>
    where
        B: From<Bytes>,
    {
        let mut send = self.connect_send.lock().await;
        if send.closed || self.state.is_terminated() {
            return Ok(());
        }
        send.stream
            .send_data(capsule::encode_drain_session().into())
            .await
    }

    /// Waits for the session to terminate and returns how it ended.
    ///
    /// The session terminates when either endpoint closes it, or when the CONNECT stream ends:
    /// a clean end without a close counts as a close with code 0 and an empty message.
    ///
    /// This returns once both sides of the CONNECT stream are closed. After [`Self::close`], that
    /// means waiting for the client to close its side, which it does on receiving the close. Until
    /// then, closing the QUIC connection could lose the close, so wait for this first. If the
    /// client might not respond, wait with a timeout.
    ///
    /// Closes from the client are only noticed while this or [`Self::draining`] is being polled.
    pub async fn closed(&self) -> Result<CloseInfo, SessionError> {
        poll_fn(|cx| self.poll_connect_stream(cx, SessionState::is_terminated)).await;
        let outcome = self
            .state
            .outcome()
            .expect("session has terminated")
            .clone();

        // After a close from the server, wait for the client to close its side of the CONNECT
        // stream. After a close from the client, we have stopped reading it.
        //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
        //# To avoid this, the endpoint SHOULD wait until all CONNECT streams have
        //# been closed by the peer before sending the CONNECTION_CLOSE
        poll_fn(|cx| self.poll_connect_stream_end(cx)).await;

        // Then close our side in response, unless we closed the session.
        let mut send = self.connect_send.lock().await;
        if !send.closed {
            send.closed = true;
            match outcome {
                Err(SessionError::MalformedCapsule(_)) => {
                    send.stream.stop_stream(Code::H3_MESSAGE_ERROR);
                }
                _ => {
                    //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
                    //# The recipient MUST either
                    //# close or reset the stream in response.
                    let _ = send.stream.finish().await;
                }
            }
        }

        outcome
    }

    /// Discards data on the CONNECT stream until the client finishes or resets it.
    fn poll_connect_stream_end(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.state.register(cx.waker());
        let waker = self.state.waker();
        let mut stream_cx = Context::from_waker(&waker);

        let mut recv = self.connect_recv.lock().unwrap();
        while !recv.ended {
            match ready!(recv.stream.poll_recv_data(&mut stream_cx)) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => recv.ended = true,
            }
        }
        Poll::Ready(())
    }

    /// Waits until the client asks to close the session gracefully, or the session terminates.
    pub async fn draining(&self) {
        poll_fn(|cx| {
            self.poll_connect_stream(cx, |state| state.is_draining() || state.is_terminated())
        })
        .await
    }

    /// Reads capsules from the CONNECT stream until `done` returns true.
    fn poll_connect_stream(
        &self,
        cx: &mut Context<'_>,
        done: impl Fn(&SessionState) -> bool,
    ) -> Poll<()> {
        // Every task waiting on the session is woken when the CONNECT stream has data, not only
        // the one polling it.
        self.state.register(cx.waker());
        let waker = self.state.waker();
        let mut stream_cx = Context::from_waker(&waker);

        let mut recv = self.connect_recv.lock().unwrap();
        loop {
            if done(&self.state) {
                return Poll::Ready(());
            }
            if self.state.is_terminated() {
                // The session ended before `done` became true.
                return Poll::Ready(());
            }

            let outcome = match ready!(recv.stream.poll_recv_data(&mut stream_cx)) {
                Ok(Some(data)) => {
                    recv.capsules.push(data);
                    match self.read_capsules(&mut recv.capsules) {
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
                    //= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
                    //# After receiving the WT_CLOSE_SESSION capsule, the receiver MAY send a
                    //# STOP_SENDING with error code WT_SESSION_GONE.
                    recv.stream.stop_sending(Code::from(crate::WT_SESSION_GONE));
                    recv.ended = true;
                }
                Err(SessionError::MalformedCapsule(_)) if !recv.ended => {
                    recv.stream.stop_sending(Code::H3_MESSAGE_ERROR);
                    recv.ended = true;
                }
                _ => {}
            }
            self.state.terminate(outcome);
        }
    }

    /// Handles the complete capsules received so far. Returns the outcome if the session ended.
    fn read_capsules(
        &self,
        capsules: &mut CapsuleReader,
    ) -> Option<Result<CloseInfo, SessionError>> {
        loop {
            match capsules.next() {
                Ok(Some(Capsule::CloseSession { code, reason })) => {
                    return Some(Ok(CloseInfo { code, reason }))
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
    session: Arc<SessionState>,
}

impl<C, B> BiStreamResolver<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Reads the first frame and classifies the accepted stream.
    pub async fn resolve(mut self) -> Result<AcceptedBi<C, B>, StreamError> {
        let frame = poll_fn(|cx| self.resolver.frame_stream.poll_next(cx)).await;

        match frame {
            Ok(Some(Frame::WebTransportStream(session_id))) => {
                // Take the stream out of the framed reader and split it in half like Paul Allen
                let stream = self.resolver.frame_stream.into_inner();
                Ok(AcceptedBi::BidiStream(
                    session_id,
                    BidiStream::with_session(stream, self.session),
                ))
            }
            // Make the underlying HTTP/3 connection handle the rest
            frame => {
                let (req, resp) = self.resolver.accept_with_frame(frame)?.resolve().await?;
                Ok(AcceptedBi::Request(req, resp))
            }
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

pin_project! {
    /// Future for opening a bidi stream
    pub struct OpenBi<'a, C:quic::Connection<B>, B:Buf> {
        opener: &'a Mutex<C::OpenStreams>,
        stream: Option<PendingStreams<C,B>>,
        session_id: SessionId,
        session: &'a Arc<SessionState>,
        stream_handler: WTransportStreamHandler,
    }
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
        let mut p = self.project();
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
                    if p.session.is_terminated() {
                        return Poll::Ready(Err(session_terminated()));
                    }
                    let mut opener = (*p.opener).lock().unwrap();
                    // Open the stream first
                    let res = ready!(opener.poll_open_bidi(cx))
                        .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    let stream =
                        BidiStream::with_session(BufRecvStream::new(res), (*p.session).clone());

                    let buf = WriteBuf::from(BidiStreamHeader::WebTransportBidi(*p.session_id));
                    *p.stream = Some((stream, buf));
                }
            }
        }
    }
}

pin_project! {
    /// Opens a unidirectional stream
    pub struct OpenUni<'a, C: quic::Connection<B>, B:Buf> {
        opener: &'a Mutex<C::OpenStreams>,
        stream: Option<PendingUniStreams<C, B>>,
        // Future for opening a uni stream
        session_id: SessionId,
        session: &'a Arc<SessionState>,
        stream_handler: WTransportStreamHandler
    }
}

impl<'a, C, B> Future for OpenUni<'a, C, B>
where
    C: quic::Connection<B>,
    B: Buf,
    C::SendStream: SendStreamUnframed<B>,
{
    type Output = Result<SendStream<C::SendStream, B>, StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut p = self.project();
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
                    if p.session.is_terminated() {
                        return Poll::Ready(Err(session_terminated()));
                    }
                    let mut opener = (*p.opener).lock().unwrap();
                    let send = ready!(opener.poll_open_send(cx))
                        .map_err(|err| p.stream_handler.handle_quic_stream_error(err))?;
                    let send = BufRecvStream::new(send);
                    let send = SendStream::with_session(send, (*p.session).clone());

                    let buf = WriteBuf::from(UniStreamHeader::WebTransportUni(*p.session_id));
                    *p.stream = Some((send, buf));
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
        if let Some((id, stream)) = streams.wt_uni_streams.pop() {
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

fn validate_wt_connect(request: &Request<()>) -> bool {
    let protocol = request.extensions().get::<Protocol>();
    matches!((request.method(), protocol), (&Method::CONNECT, Some(p)) if p.is_webtransport())
}
