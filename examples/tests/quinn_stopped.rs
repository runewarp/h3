//! Native send completion observation through the public Quinn adapter.
use bytes::Bytes;
use futures::{future::poll_fn, task::AtomicWaker, FutureExt};
use h3::quic::{OpenStreams as _, SendStream as _, SendStreamUnframed as _};
use quinn::{AsyncUdpSocket, Runtime};
use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::time::timeout;

// Tests use a current-thread runtime. Closing this gate synchronously prevents
// the endpoint from processing any more incoming packets, including ACKs.
#[derive(Debug, Default)]
struct ReceiveGate {
    closed: AtomicBool,
    reader: AtomicWaker,
}

impl ReceiveGate {
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        self.reader.wake();
    }
}

#[derive(Debug)]
struct GatedSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    gate: Arc<ReceiveGate>,
}

impl AsyncUdpSocket for GatedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.socket.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.gate.reader.register(cx.waker());
        if self.gate.closed.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        self.socket.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

struct Pair {
    _endpoints: [quinn::Endpoint; 2],
    sender: quinn::Connection,
    receiver: quinn::Connection,
    gates: [Arc<ReceiveGate>; 2],
}

impl Pair {
    async fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let cert = rustls::pki_types::CertificateDer::from(cert.cert);
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.clone()], key.into()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        let gates: [Arc<ReceiveGate>; 2] = [Arc::default(), Arc::default()];
        let endpoint = |config, gate| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let socket = quinn::TokioRuntime.wrap_udp_socket(socket).unwrap();
            quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                config,
                Arc::new(GatedSocket { socket, gate }),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap()
        };
        let server = endpoint(Some(server_config), gates[1].clone());
        let mut client = endpoint(None, gates[0].clone());
        client.set_default_client_config(client_config);
        let (receiver, sender) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            async {
                client
                    .connect(server.local_addr().unwrap(), "localhost")
                    .unwrap()
                    .await
                    .unwrap()
            }
        );
        Self {
            _endpoints: [client, server],
            sender,
            receiver,
            gates,
        }
    }

    async fn send(&self) -> h3_quinn::SendStream<Bytes> {
        let adapter = h3_quinn::Connection::new(self.sender.clone());
        let mut opener = <h3_quinn::Connection as h3::quic::Connection<Bytes>>::opener(&adapter);
        poll_fn(|cx| opener.poll_open_send(cx)).await.unwrap()
    }
}

fn native_future(
    future: impl Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>>
        + Send
        + Sync
        + 'static,
) -> impl Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>> + Send + Sync + 'static
{
    future
}

#[tokio::test]
async fn finish_enqueues_fin_while_stopped_waits_for_ack_and_outlives_adapter() {
    timeout(Duration::from_secs(5), async {
        let pair = Pair::new().await;
        let mut send = pair.send().await;
        let mut stopped = Box::pin(native_future(send.stopped()));
        pair.gates[0].close();
        let mut data = Bytes::from_static(b"tail");
        assert_eq!(
            poll_fn(|cx| send.poll_send(cx, &mut data)).await.unwrap(),
            4
        );
        // This is the transport finish operation used by ordinary H3.
        assert!(poll_fn(|cx| send.poll_finish(cx))
            .now_or_never()
            .unwrap()
            .is_ok());
        let mut recv = pair.receiver.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(16).await.unwrap(), b"tail");
        assert!(stopped.as_mut().now_or_never().is_none());
        drop(send);
        assert!(stopped.as_mut().now_or_never().is_none());
        pair.gates[0].open();
        assert_eq!(stopped.await.unwrap(), None);
    })
    .await
    .expect("FIN acknowledgment test timed out");
}

#[tokio::test]
async fn peer_stop_reports_exact_code_before_reset_can_be_acknowledged() {
    timeout(Duration::from_secs(5), async {
        let pair = Pair::new().await;
        let mut send = pair.send().await;
        let mut data = Bytes::from_static(b"x");
        poll_fn(|cx| send.poll_send(cx, &mut data)).await.unwrap();
        let mut recv = pair.receiver.accept_uni().await.unwrap();
        assert_eq!(
            recv.read_chunk(1, true).await.unwrap().unwrap().bytes,
            b"x"[..]
        );
        let mut stopped = Box::pin(native_future(send.stopped()));
        assert!(stopped.as_mut().now_or_never().is_none());

        // STOP can leave the peer, but the peer cannot receive or ACK our RESET.
        pair.gates[1].close();
        let code = quinn::VarInt::from_u32(0x12345);
        recv.stop(code).unwrap();
        assert_eq!(stopped.await.unwrap(), Some(code));
        assert_eq!(pair.sender.stats().frame_tx.reset_stream, 0);
        assert_eq!(pair.receiver.stats().frame_rx.reset_stream, 0);

        // Quinn's send-handle Drop responds to STOP with RESET. Keep its peer
        // gated until that RESET is actually transmitted, not for a guessed delay.
        drop(send);
        while pair.sender.stats().frame_tx.reset_stream == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pair.receiver.stats().frame_rx.reset_stream, 0);
        pair.gates[1].open();
        while pair.receiver.stats().frame_rx.reset_stream == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("STOP before RESET acknowledgment test timed out");
}

#[tokio::test]
async fn connection_loss_wakes_pending_observer_with_native_error() {
    timeout(Duration::from_secs(5), async {
        let pair = Pair::new().await;
        let send = pair.send().await;
        let mut stopped = Box::pin(native_future(send.stopped()));
        let mut first_poll = true;
        let result = poll_fn(|cx| {
            let result = stopped.as_mut().poll(cx);
            if first_poll {
                assert!(result.is_pending());
                first_poll = false;
                // Close only after the real task waker has been registered.
                pair.sender.close(0_u32.into(), b"observer wake test");
            }
            result
        })
        .await;
        assert!(matches!(
            result,
            Err(quinn::StoppedError::ConnectionLost(
                quinn::ConnectionError::LocallyClosed
            ))
        ));
    })
    .await
    .expect("connection-loss observer test timed out");
}

#[derive(Default)]
struct WakerProbe(AtomicBool);

impl Wake for WakerProbe {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelling_observer_releases_task_waker_and_preserves_stream() {
    timeout(Duration::from_secs(5), async {
        let pair = Pair::new().await;
        let mut send = pair.send().await;
        let mut stopped = Box::pin(native_future(send.stopped()));
        let probe = Arc::new(WakerProbe::default());
        let weak = Arc::downgrade(&probe);
        {
            let waker = Waker::from(probe);
            let mut cx = Context::from_waker(&waker);
            assert!(stopped.as_mut().poll(&mut cx).is_pending());
        }
        assert!(
            weak.upgrade().is_some(),
            "pending observer must own its task waker"
        );
        assert!(!weak.upgrade().unwrap().0.load(Ordering::SeqCst));
        drop(stopped);
        assert!(
            weak.upgrade().is_none(),
            "cancelled observer retained its task waker"
        );

        // Cancellation only removes this waiter. Quinn may retain its per-stream
        // Notify entry; a fresh observer and the send handle remain usable.
        let stopped = native_future(send.stopped());
        let mut data = Bytes::from_static(b"after cancellation");
        poll_fn(|cx| send.poll_send(cx, &mut data)).await.unwrap();
        poll_fn(|cx| send.poll_finish(cx)).await.unwrap();
        let mut recv = pair.receiver.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(32).await.unwrap(), b"after cancellation");
        assert_eq!(stopped.await.unwrap(), None);
    })
    .await
    .expect("observer cancellation test timed out");
}
