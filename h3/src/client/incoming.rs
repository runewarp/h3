use std::{
    collections::VecDeque,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Buf;
use futures_util::{future::poll_fn, task::AtomicWaker};

use crate::{error::Code, quic, Settings};

/// Bounded receiver of raw server-initiated bidirectional extension streams.
///
/// The connection driver must keep running. The extension must validate each stream's
/// prefix and association before using it. Once returned, a stream belongs to the
/// caller, including responsibility for resetting and stopping abandoned streams.
/// Dropping this receiver aborts queued streams and makes the driver reject new ones.
pub struct IncomingStreams<S: quic::SendStream<B> + quic::RecvStream, B: Buf> {
    shared: Arc<Shared<S, B>>,
}

struct Shared<S: quic::SendStream<B> + quic::RecvStream, B: Buf> {
    queue: Mutex<Queue<S>>,
    waker: AtomicWaker,
    capacity: NonZeroUsize,
    rejection_code: Code,
    _buf: PhantomData<fn(B)>,
}

struct Queue<S> {
    streams: VecDeque<S>,
    open: bool,
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> Shared<S, B> {
    fn reject(&self, mut stream: S) {
        stream.reset(self.rejection_code.value());
        stream.stop_sending(self.rejection_code.value());
    }

    fn close(&self) {
        let streams = {
            let mut queue = self.queue.lock().unwrap();
            queue.open = false;
            std::mem::take(&mut queue.streams)
        };
        for stream in streams {
            self.reject(stream);
        }
        self.waker.wake();
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> IncomingStreams<S, B> {
    /// Receive the next stream, or `None` when the driver ends or registration is replaced.
    ///
    /// Cancelling this future leaves queued streams available to the next call.
    pub async fn recv(&mut self) -> Option<S> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Poll for the next stream. Only the most recent caller's waker is retained.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<S>> {
        self.shared.waker.register(cx.waker());
        let mut queue = self.shared.queue.lock().unwrap();
        if let Some(stream) = queue.streams.pop_front() {
            Poll::Ready(Some(stream))
        } else if queue.open {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> Drop for IncomingStreams<S, B> {
    fn drop(&mut self) {
        self.shared.close();
    }
}

pub(super) struct Dispatch<S: quic::SendStream<B> + quic::RecvStream, B: Buf> {
    shared: Arc<Shared<S, B>>,
    pub(super) negotiated: fn(&Settings, &Settings) -> bool,
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> Dispatch<S, B> {
    pub(super) fn new(
        capacity: NonZeroUsize,
        rejection_code: Code,
        negotiated: fn(&Settings, &Settings) -> bool,
    ) -> (Self, IncomingStreams<S, B>) {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                streams: VecDeque::new(),
                open: true,
            }),
            capacity,
            rejection_code,
            waker: AtomicWaker::new(),
            _buf: PhantomData,
        });
        (
            Self {
                shared: shared.clone(),
                negotiated,
            },
            IncomingStreams { shared },
        )
    }

    pub(super) fn send(&self, stream: S) {
        let mut queue = self.shared.queue.lock().unwrap();
        if queue.open && queue.streams.len() < self.shared.capacity.get() {
            queue.streams.push_back(stream);
            drop(queue);
            self.shared.waker.wake();
        } else {
            drop(queue);
            self.shared.reject(stream);
        }
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> Drop for Dispatch<S, B> {
    fn drop(&mut self) {
        self.shared.close();
    }
}
