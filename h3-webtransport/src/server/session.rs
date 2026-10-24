//! CONNECT lifecycle for detached Server sessions.

use super::*;
const WORK_BUDGET: usize = 32;
use crate::client::Incoming;
use crate::{
    capsule::{self, Capsule, CapsuleReader},
    state::Registration,
    stream::BidiStream,
};
use bytes::Bytes;
use futures_util::lock::Mutex as AsyncMutex;
use h3::server::RequestStream;

struct ConnectSend<S: quic::BidiStream<B>, B: Buf> {
    stream: RequestStream<S::SendStream, B>,
    closed: bool,
}
struct ConnectRecv<S: quic::BidiStream<B>, B: Buf> {
    stream: RequestStream<S::RecvStream, B>,
    capsules: CapsuleReader,
    close_received: bool,
    end_error: Option<SessionError>,
    ended: bool,
    // One transport-owned DATA chunk. CapsuleReader receives at most 1024 bytes at a time.
    data: Bytes,
}
impl<S: quic::BidiStream<B>, B: Buf> ConnectRecv<S, B> {
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

/// A Server session associated with exactly one CONNECT stream ID.
///
/// Streams retain independent FIN directions and inherit session termination. Keep `closed()`
/// polled to receive peer close/drain capsules. Dropping a live session aborts CONNECT and queued
/// streams; it does not close the HTTP/3 connection. Use `close()` then `closed()` with a caller
/// deadline for orderly shutdown. The peer may withhold FIN indefinitely.
pub struct Session<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> {
    opener: SessionOpener<C, B>,
    id: SessionId,
    draft: WebTransportDraft,
    incoming: Arc<Incoming<C::BidiStream, B>>,
    connect_send: AsyncMutex<ConnectSend<C::BidiStream, B>>,
    connect_recv: Mutex<ConnectRecv<C::BidiStream, B>>,
}

impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Session<C, B> {
    pub(super) fn new(
        opener: SessionOpener<C, B>,
        id: SessionId,
        draft: WebTransportDraft,
        stream: RequestStream<C::BidiStream, B>,
        incoming: Arc<Incoming<C::BidiStream, B>>,
    ) -> Self {
        let (send, recv) = stream.split();
        Self {
            opener,
            id,
            draft,
            incoming,
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
        }
    }

    /// An opener carrying this session's exact ID and termination state.
    pub fn opener(&self) -> &SessionOpener<C, B> {
        &self.opener
    }

    /// The full CONNECT stream ID, including when an ordinary request used stream zero.
    pub fn session_id(&self) -> SessionId {
        self.id
    }

    /// Negotiated draft group.
    pub fn draft(&self) -> WebTransportDraft {
        self.draft
    }

    /// Receive a validated client-opened bidirectional stream, or `None` after session termination.
    ///
    /// Cancelling this future preserves both queued and partially parsed streams. Multiple
    /// concurrent callers have independent wake registrations. Prefix validation is performed
    /// by the connection driver, so a slow malformed stream cannot block another session.
    pub async fn accept_bi(&self) -> Option<BidiStream<C::BidiStream, B>> {
        let mut registration = None;
        let mut state_registration = None;
        poll_fn(|cx| {
            self.incoming.wakers.register(cx.waker(), &mut registration);
            self.incoming
                .state
                .register(cx.waker(), &mut state_registration);
            let mut streams = self.incoming.streams.lock().unwrap();
            if self.incoming.state.is_terminated() {
                drop(streams);
                self.incoming.discard();
                Poll::Ready(None)
            } else if let Some(stream) = streams.pop_front() {
                Poll::Ready(Some(BidiStream::with_session(
                    stream,
                    self.incoming.state.clone(),
                )))
            } else {
                Poll::Pending
            }
        })
        .await
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
        if !self.incoming.state.terminate(Ok(CloseInfo {
            code,
            reason: reason.to_owned(),
        })) {
            return Ok(());
        }
        self.incoming.discard();

        let mut send = self.connect_send.lock().await;
        if send.closed {
            return Ok(());
        }
        let mut write = CloseWrite {
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
        if send.closed || self.incoming.state.is_terminated() {
            return Ok(());
        }
        let mut write = CloseWrite {
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
                self.incoming
                    .state
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
            let mut write = CloseWrite {
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
        self.incoming
            .state
            .register_connect(cx.waker(), registration);
        let waker = self.incoming.state.connect_waker();
        let mut stream_cx = Context::from_waker(&waker);

        if matches!(
            self.incoming.state.outcome(),
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
        self.incoming
            .state
            .register_connect(cx.waker(), registration);
        let waker = self.incoming.state.connect_waker();
        let mut stream_cx = Context::from_waker(&waker);

        let mut recv = self.connect_recv.lock().unwrap();
        for _ in 0..WORK_BUDGET {
            if done(&self.incoming.state) {
                return Poll::Ready(());
            }
            if self.incoming.state.is_terminated() {
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
            self.incoming.state.terminate(outcome);
            self.incoming.discard();
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
                Ok(Some(Capsule::DrainSession)) => self.incoming.state.drain(),
                Ok(None) => return None,
                Err(capsule::MalformedCapsule(reason)) => {
                    return Some(Err(SessionError::MalformedCapsule(reason)))
                }
            }
        }
    }
}

// Cancelling a capsule write or FIN must reset, never turn a partial close into a clean FIN.
struct CloseWrite<'a, S: quic::BidiStream<B>, B: Buf> {
    send: &'a mut ConnectSend<S, B>,
    completed: bool,
}
impl<S: quic::BidiStream<B>, B: Buf> Drop for CloseWrite<'_, S, B> {
    fn drop(&mut self) {
        if !self.completed {
            self.send.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            self.send.closed = true;
        }
    }
}
impl<C: quic::Connection<B, BidiStream: quic::BidiStream<B>>, B: Buf> Drop for Session<C, B> {
    fn drop(&mut self) {
        self.incoming
            .state
            .terminate(Err(SessionError::OwnerDropped));
        self.incoming.discard();
        // No concurrent methods remain when the session is dropped.
        let send = self.connect_send.get_mut();
        if !send.closed {
            send.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        let recv = self.connect_recv.get_mut().unwrap();
        if !recv.ended {
            recv.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
    }
}
