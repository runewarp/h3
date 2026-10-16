use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h3::{
    quic::{self, RecvStream as _, SendStream as _, StreamErrorIncoming},
    stream::BufRecvStream,
};
use tokio::io::ReadBuf;

use crate::state::{SessionState, WT_SESSION_GONE};

/// Aborts a stream once its session has terminated.
///
//= https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-6
//# Upon learning that the session has been terminated, the endpoint MUST
//# reset the send side and abort reading on the receive side of all
//# unidirectional and bidirectional streams associated with the session
//# (see Section 2.4 of [RFC9000]) using the WT_SESSION_GONE error code;
//
// This happens the next time the stream is used or when it is dropped. Tasks waiting on the stream
// are woken when the session terminates.
struct SessionGuard<S, B> {
    session: Option<Arc<SessionState>>,
    /// Resets the send side and/or stops the receive side, depending on the stream type
    abort: fn(&mut BufRecvStream<S, B>),
    aborted: bool,
}

impl<S, B> SessionGuard<S, B> {
    fn new(session: Option<Arc<SessionState>>, abort: fn(&mut BufRecvStream<S, B>)) -> Self {
        Self {
            session,
            abort,
            aborted: false,
        }
    }

    /// Returns true if the session has terminated, aborting the stream the first time.
    fn is_gone(&mut self, stream: &mut BufRecvStream<S, B>) -> bool {
        match &self.session {
            Some(session) if session.is_terminated() => {
                if !self.aborted {
                    self.aborted = true;
                    (self.abort)(stream);
                }
                true
            }
            _ => false,
        }
    }

    /// Polls the stream unless the session has terminated.
    ///
    /// While the stream is pending, the task is also woken when the session terminates.
    fn poll<T, E>(
        &mut self,
        stream: &mut BufRecvStream<S, B>,
        cx: &mut Context<'_>,
        gone: fn() -> E,
        poll: impl FnOnce(&mut BufRecvStream<S, B>, &mut Context<'_>) -> Poll<Result<T, E>>,
    ) -> Poll<Result<T, E>> {
        if self.is_gone(stream) {
            return Poll::Ready(Err(gone()));
        }
        let result = poll(stream, cx);
        if result.is_pending() {
            if let Some(session) = &self.session {
                session.register(cx.waker());
                // The session may have terminated before the waker was registered.
                if self.is_gone(stream) {
                    return Poll::Ready(Err(gone()));
                }
            }
        }
        result
    }

    /// The guard of one half of a split bidirectional stream
    fn half<T>(&self, abort: fn(&mut BufRecvStream<T, B>)) -> SessionGuard<T, B> {
        SessionGuard {
            session: self.session.clone(),
            abort,
            aborted: self.aborted,
        }
    }
}

fn session_gone() -> StreamErrorIncoming {
    StreamErrorIncoming::StreamTerminated {
        error_code: WT_SESSION_GONE,
    }
}

fn session_gone_io() -> std::io::Error {
    std::io::Error::other(session_gone())
}

fn reset<S: quic::SendStream<B>, B: Buf>(stream: &mut BufRecvStream<S, B>) {
    stream.reset(WT_SESSION_GONE);
}

fn stop_sending<S: quic::RecvStream, B>(stream: &mut BufRecvStream<S, B>) {
    stream.stop_sending(WT_SESSION_GONE);
}

fn reset_and_stop_sending<S: quic::SendStream<B> + quic::RecvStream, B: Buf>(
    stream: &mut BufRecvStream<S, B>,
) {
    stream.reset(WT_SESSION_GONE);
    stream.stop_sending(WT_SESSION_GONE);
}

/// WebTransport receive stream
pub struct RecvStream<S, B> {
    stream: BufRecvStream<S, B>,
    guard: SessionGuard<S, B>,
}

impl<S, B> RecvStream<S, B> {
    #[allow(missing_docs)]
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            guard: SessionGuard::new(None, |_| {}),
        }
    }
}

impl<S: quic::RecvStream, B> RecvStream<S, B> {
    pub(crate) fn with_session(stream: BufRecvStream<S, B>, session: Arc<SessionState>) -> Self {
        Self {
            stream,
            guard: SessionGuard::new(Some(session), stop_sending),
        }
    }
}

impl<S, B> Drop for RecvStream<S, B> {
    fn drop(&mut self) {
        self.guard.is_gone(&mut self.stream);
    }
}

impl<S, B> quic::RecvStream for RecvStream<S, B>
where
    S: quic::RecvStream,
    B: Buf,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.guard
            .poll(&mut self.stream, cx, session_gone, |s, cx| s.poll_data(cx))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.stream.stop_sending(error_code)
    }

    fn recv_id(&self) -> quic::StreamId {
        self.stream.recv_id()
    }
}

impl<S, B> futures_util::io::AsyncRead for RecvStream<S, B>
where
    BufRecvStream<S, B>: futures_util::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                futures_util::io::AsyncRead::poll_read(Pin::new(s), cx, buf)
            })
    }
}

impl<S, B> tokio::io::AsyncRead for RecvStream<S, B>
where
    BufRecvStream<S, B>: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                tokio::io::AsyncRead::poll_read(Pin::new(s), cx, buf)
            })
    }
}

/// WebTransport send stream
pub struct SendStream<S, B> {
    stream: BufRecvStream<S, B>,
    guard: SessionGuard<S, B>,
}

impl<S, B> std::fmt::Debug for SendStream<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStream")
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S: quic::SendStream<B>, B: Buf> SendStream<S, B> {
    pub(crate) fn with_session(stream: BufRecvStream<S, B>, session: Arc<SessionState>) -> Self {
        Self {
            stream,
            guard: SessionGuard::new(Some(session), reset),
        }
    }
}

impl<S, B> Drop for SendStream<S, B> {
    fn drop(&mut self) {
        self.guard.is_gone(&mut self.stream);
    }
}

impl<S, B> quic::SendStreamUnframed<B> for SendStream<S, B>
where
    S: quic::SendStreamUnframed<B>,
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.guard
            .poll(&mut self.stream, cx, session_gone, |s, cx| {
                s.poll_send(cx, buf)
            })
    }
}

impl<S, B> quic::SendStream<B> for SendStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.guard
            .poll(&mut self.stream, cx, session_gone, |s, cx| {
                s.poll_finish(cx)
            })
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> quic::StreamId {
        self.stream.send_id()
    }

    fn send_data<T: Into<h3::stream::WriteBuf<B>>>(
        &mut self,
        data: T,
    ) -> Result<(), StreamErrorIncoming> {
        if self.guard.is_gone(&mut self.stream) {
            return Err(session_gone());
        }
        self.stream.send_data(data)
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.guard
            .poll(&mut self.stream, cx, session_gone, |s, cx| s.poll_ready(cx))
    }
}

impl<S, B> futures_util::io::AsyncWrite for SendStream<S, B>
where
    BufRecvStream<S, B>: futures_util::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                futures_util::io::AsyncWrite::poll_write(Pin::new(s), cx, buf)
            })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                futures_util::io::AsyncWrite::poll_flush(Pin::new(s), cx)
            })
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                futures_util::io::AsyncWrite::poll_close(Pin::new(s), cx)
            })
    }
}

impl<S, B> tokio::io::AsyncWrite for SendStream<S, B>
where
    BufRecvStream<S, B>: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                tokio::io::AsyncWrite::poll_write(Pin::new(s), cx, buf)
            })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                tokio::io::AsyncWrite::poll_flush(Pin::new(s), cx)
            })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.guard
            .poll(&mut this.stream, cx, session_gone_io, |s, cx| {
                tokio::io::AsyncWrite::poll_shutdown(Pin::new(s), cx)
            })
    }
}

/// Combined send and receive stream.
///
/// Can be split into a [`RecvStream`] and [`SendStream`] if the underlying QUIC implementation
/// supports it.
pub struct BidiStream<S, B> {
    // Only `None` after `split()`, which needs to move it out despite the `Drop` impl.
    stream: Option<BufRecvStream<S, B>>,
    guard: SessionGuard<S, B>,
}

impl<S, B> BidiStream<S, B> {
    fn parts(&mut self) -> (&mut BufRecvStream<S, B>, &mut SessionGuard<S, B>) {
        (
            self.stream.as_mut().expect("stream is only taken by split"),
            &mut self.guard,
        )
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> BidiStream<S, B> {
    pub(crate) fn with_session(stream: BufRecvStream<S, B>, session: Arc<SessionState>) -> Self {
        Self {
            stream: Some(stream),
            guard: SessionGuard::new(Some(session), reset_and_stop_sending),
        }
    }
}

impl<S, B> Drop for BidiStream<S, B> {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.stream {
            self.guard.is_gone(stream);
        }
    }
}

impl<S, B> quic::SendStream<B> for BidiStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let (stream, guard) = self.parts();
        guard.poll(stream, cx, session_gone, |s, cx| s.poll_finish(cx))
    }

    fn reset(&mut self, reset_code: u64) {
        self.parts().0.reset(reset_code)
    }

    fn send_id(&self) -> quic::StreamId {
        self.stream
            .as_ref()
            .expect("stream is only taken by split")
            .send_id()
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let (stream, guard) = self.parts();
        guard.poll(stream, cx, session_gone, |s, cx| s.poll_ready(cx))
    }

    fn send_data<T: Into<h3::stream::WriteBuf<B>>>(
        &mut self,
        data: T,
    ) -> Result<(), StreamErrorIncoming> {
        let (stream, guard) = self.parts();
        if guard.is_gone(stream) {
            return Err(session_gone());
        }
        stream.send_data(data)
    }
}

impl<S, B> quic::SendStreamUnframed<B> for BidiStream<S, B>
where
    S: quic::SendStreamUnframed<B>,
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        let (stream, guard) = self.parts();
        guard.poll(stream, cx, session_gone, |s, cx| s.poll_send(cx, buf))
    }
}

impl<S: quic::RecvStream, B> quic::RecvStream for BidiStream<S, B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        let (stream, guard) = self.parts();
        guard.poll(stream, cx, session_gone, |s, cx| s.poll_data(cx))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.parts().0.stop_sending(error_code)
    }

    fn recv_id(&self) -> quic::StreamId {
        self.stream
            .as_ref()
            .expect("stream is only taken by split")
            .recv_id()
    }
}

impl<S, B> quic::BidiStream<B> for BidiStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    type SendStream = SendStream<S::SendStream, B>;

    type RecvStream = RecvStream<S::RecvStream, B>;

    fn split(mut self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self
            .stream
            .take()
            .expect("stream is only taken by split")
            .split();
        (
            SendStream {
                stream: send,
                guard: self.guard.half(reset),
            },
            RecvStream {
                stream: recv,
                guard: self.guard.half(stop_sending),
            },
        )
    }
}

impl<S, B> futures_util::io::AsyncRead for BidiStream<S, B>
where
    BufRecvStream<S, B>: futures_util::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            futures_util::io::AsyncRead::poll_read(Pin::new(s), cx, buf)
        })
    }
}

impl<S, B> futures_util::io::AsyncWrite for BidiStream<S, B>
where
    BufRecvStream<S, B>: futures_util::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            futures_util::io::AsyncWrite::poll_write(Pin::new(s), cx, buf)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            futures_util::io::AsyncWrite::poll_flush(Pin::new(s), cx)
        })
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            futures_util::io::AsyncWrite::poll_close(Pin::new(s), cx)
        })
    }
}

impl<S, B> tokio::io::AsyncRead for BidiStream<S, B>
where
    BufRecvStream<S, B>: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            tokio::io::AsyncRead::poll_read(Pin::new(s), cx, buf)
        })
    }
}

impl<S, B> tokio::io::AsyncWrite for BidiStream<S, B>
where
    BufRecvStream<S, B>: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            tokio::io::AsyncWrite::poll_write(Pin::new(s), cx, buf)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            tokio::io::AsyncWrite::poll_flush(Pin::new(s), cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let (stream, guard) = self.get_mut().parts();
        guard.poll(stream, cx, session_gone_io, |s, cx| {
            tokio::io::AsyncWrite::poll_shutdown(Pin::new(s), cx)
        })
    }
}
