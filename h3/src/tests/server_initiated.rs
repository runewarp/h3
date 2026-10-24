use std::{num::NonZeroUsize, time::Duration};

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use http::{Request, Response};

use crate::{
    client,
    error::{Code, ConnectionError, LocalError},
    quic::RecvStream,
    server,
    shared_state::ConnectionState,
};

use super::{h3_quinn, Pair, Server};

type Driver = client::Connection<h3_quinn::Connection, Bytes>;
type Sender = client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ServerDriver = server::Connection<h3_quinn::Connection, Bytes>;
type RawStream = (quinn::SendStream, quinn::RecvStream);

const DEADLINE: Duration = Duration::from_secs(5);

async fn connect(
    local: (bool, bool),
    peer: (bool, bool),
) -> (Server, Driver, Sender, ServerDriver, quinn::Connection) {
    let mut pair = Pair::default();
    let endpoint = pair.server();
    let (transport, client) = tokio::join!(
        async { endpoint.endpoint.accept().await.unwrap().await.unwrap() },
        pair.client(),
    );
    let (driver, sender) = client::builder()
        .enable_extended_connect(local.0)
        .enable_datagram(local.1)
        .build(client)
        .await
        .unwrap();
    let server = server::builder()
        .enable_extended_connect(peer.0)
        .enable_datagram(peer.1)
        .build(h3_quinn::Connection::new(transport.clone()))
        .await
        .unwrap();
    (endpoint, driver, sender, server, transport)
}

async fn receive_settings<C: crate::quic::Connection<Bytes>>(
    driver: &mut client::Connection<C, Bytes>,
) {
    poll_fn(|cx| {
        assert!(driver.poll_close(cx).is_pending());
        if driver.peer_settings().is_some() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

async fn open(transport: &quinn::Connection) -> RawStream {
    let (mut send, recv) = transport.open_bi().await.unwrap();
    // Quinn exposes a stream to its peer only once data or FIN has been sent.
    send.write_all(b"extension bytes").await.unwrap();
    (send, recv)
}

async fn aborted(stream: &mut RawStream, code: Code) {
    assert_eq!(
        stream.0.stopped().await.unwrap().unwrap().into_inner(),
        code.value()
    );
    let mut byte = [0];
    assert!(
        matches!(stream.1.read(&mut byte).await, Err(quinn::ReadError::Reset(value)) if value.into_inner() == code.value())
    );
}

async fn drive_until<C: crate::quic::Connection<Bytes>, F: std::future::Future>(
    driver: &mut client::Connection<C, Bytes>,
    work: F,
) -> F::Output {
    tokio::select! {
        result = work => result,
        error = driver.wait_idle() => panic!("driver stopped: {error:?}"),
    }
}

async fn ordinary_request(driver: &mut Driver, sender: &mut Sender, server: &mut ServerDriver) {
    drive_until(driver, async {
        let client = async {
            let mut request = sender
                .send_request(Request::put("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            request.finish().await.unwrap();
            assert_eq!(request.recv_response().await.unwrap().status(), 204);
            assert!(request.recv_data().await.unwrap().is_none());
        };
        let server = async {
            let (request, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::PUT);
            stream
                .send_response(Response::builder().status(204).body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
        };
        tokio::join!(client, server);
    })
    .await;
}

// These settings stand in for a test extension's bilateral negotiation rules.
// Neither setting alone grants permission to open server bidirectional streams.
fn negotiated(local: &crate::Settings, peer: &crate::Settings) -> bool {
    local.enable_extended_connect()
        && local.enable_datagram()
        && peer.enable_extended_connect()
        && peer.enable_datagram()
}

#[tokio::test]
async fn negotiated_server_stream_and_ordinary_request() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default();
        let endpoint = pair.server();
        let client = async {
            let (mut driver, mut sender) = client::builder()
                .enable_extended_connect(true)
                .enable_datagram(true)
                .build::<_, _, Bytes>(pair.client().await)
                .await
                .unwrap();
            let mut incoming = driver.server_initiated_streams(
                NonZeroUsize::new(1).unwrap(),
                Code::H3_REQUEST_CANCELLED,
                negotiated,
            );
            let work = async {
                let mut request = sender
                    .send_request(Request::get("https://localhost/").body(()).unwrap())
                    .await
                    .unwrap();
                request.finish().await.unwrap();
                assert_eq!(request.recv_response().await.unwrap().status(), 200);
                let mut stream = incoming.recv().await.unwrap();
                let mut data = poll_fn(|cx| stream.poll_data(cx)).await.unwrap().unwrap();
                assert_eq!(data.copy_to_bytes(data.remaining()), "extension bytes");
            };
            tokio::select! {
                _ = work => {},
                error = driver.wait_idle() => panic!("driver stopped: {error:?}"),
            }
        };
        let server = async {
            let transport = endpoint.endpoint.accept().await.unwrap().await.unwrap();
            let mut driver = server::builder()
                .enable_extended_connect(true)
                .enable_datagram(true)
                .build::<_, Bytes>(h3_quinn::Connection::new(transport.clone()))
                .await
                .unwrap();
            let (_, mut request) = driver
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            request.send_response(Response::new(())).await.unwrap();
            request.finish().await.unwrap();
            let (mut send, mut recv) = transport.open_bi().await.unwrap();
            send.write_all(b"extension bytes").await.unwrap();
            // Keep the connection alive until the client has received the extension stream.
            let _ = recv.read_to_end(32).await;
        };
        tokio::join!(client, server);
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn server_stream_requires_local_and_peer_extension_evidence() {
    tokio::time::timeout(DEADLINE, async {
        for (local, peer) in [
            ((false, true), (true, true)),
            ((true, false), (true, true)),
            ((true, true), (false, true)),
            ((true, true), (true, false)),
        ] {
            let (_endpoint, mut driver, _sender, _server, transport) = connect(local, peer).await;
            let mut incoming = driver.server_initiated_streams(
                NonZeroUsize::new(1).unwrap(),
                Code::H3_REQUEST_CANCELLED,
                negotiated,
            );
            receive_settings(&mut driver).await;
            let _stream = open(&transport).await;
            assert!(matches!(
                driver.wait_idle().await,
                ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_STREAM_CREATION_ERROR,
                        ..
                    }
                }
            ));
            assert!(incoming.recv().await.is_none());
            assert!(matches!(
                transport.closed().await,
                quinn::ConnectionError::ApplicationClosed(close)
                    if close.error_code.into_inner() == Code::H3_STREAM_CREATION_ERROR.value()
            ));
        }
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn saturated_dispatch_rejects_newest_and_keeps_http_progress() {
    tokio::time::timeout(DEADLINE, async {
        let (_endpoint, mut driver, mut sender, mut server, transport) =
            connect((true, true), (true, true)).await;
        let mut incoming = driver.server_initiated_streams(
            NonZeroUsize::new(1).unwrap(),
            Code::H3_REQUEST_CANCELLED,
            negotiated,
        );
        receive_settings(&mut driver).await;
        let mut first = open(&transport).await;
        let mut second = open(&transport).await;
        drive_until(
            &mut driver,
            aborted(&mut second, Code::H3_REQUEST_CANCELLED),
        )
        .await;
        // A full receiver must not block ordinary request or control processing.
        ordinary_request(&mut driver, &mut sender, &mut server).await;
        let mut accepted = incoming.recv().await.unwrap();
        let mut bytes = poll_fn(|cx| accepted.poll_data(cx)).await.unwrap().unwrap();
        assert_eq!(bytes.copy_to_bytes(bytes.remaining()), "extension bytes");
        let _recovered = open(&transport).await;
        let recovered = drive_until(&mut driver, incoming.recv()).await.unwrap();
        drop(recovered);
        drop(incoming);
        // Ownership has transferred: receiver drop must not abort a delivered stream.
        first.0.write_all(b"still alive").await.unwrap();
        let mut bytes = poll_fn(|cx| accepted.poll_data(cx)).await.unwrap().unwrap();
        assert_eq!(bytes.copy_to_bytes(bytes.remaining()), "still alive");
        let mut third = open(&transport).await;
        drive_until(&mut driver, aborted(&mut third, Code::H3_REQUEST_CANCELLED)).await;
        ordinary_request(&mut driver, &mut sender, &mut server).await;
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn abandoned_queued_streams_are_reset_and_stopped() {
    tokio::time::timeout(DEADLINE, async {
        for action in ["receiver drop", "replacement", "driver drop"] {
            let (_endpoint, mut driver, _sender, _server, transport) =
                connect((true, true), (true, true)).await;
            let mut incoming = driver.server_initiated_streams(
                NonZeroUsize::new(2).unwrap(),
                Code::H3_REQUEST_CANCELLED,
                negotiated,
            );
            receive_settings(&mut driver).await;
            let mut first = open(&transport).await;
            let mut second = open(&transport).await;
            let mut excess = open(&transport).await;
            // The rejection proves both older streams reached the queue.
            drive_until(
                &mut driver,
                aborted(&mut excess, Code::H3_REQUEST_CANCELLED),
            )
            .await;
            match action {
                "receiver drop" => drop(incoming),
                "replacement" => {
                    let mut replacement = driver.server_initiated_streams(
                        NonZeroUsize::new(1).unwrap(),
                        Code::H3_REQUEST_CANCELLED,
                        negotiated,
                    );
                    assert!(incoming.recv().await.is_none());
                    let _next = open(&transport).await;
                    let accepted = drive_until(&mut driver, replacement.recv()).await.unwrap();
                    drop(accepted);
                }
                "driver drop" => {
                    drop(driver);
                    assert!(incoming.recv().await.is_none());
                }
                _ => unreachable!(),
            }
            // No driver polling is needed to abort the abandoned queue.
            aborted(&mut first, Code::H3_REQUEST_CANCELLED).await;
            aborted(&mut second, Code::H3_REQUEST_CANCELLED).await;
        }
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn cancelled_receive_can_resume_and_driver_drop_wakes_receiver() {
    tokio::time::timeout(DEADLINE, async {
        let (_endpoint, mut driver, _sender, _server, transport) =
            connect((true, true), (true, true)).await;
        let mut incoming = driver.server_initiated_streams(
            NonZeroUsize::new(1).unwrap(),
            Code::H3_REQUEST_CANCELLED,
            negotiated,
        );
        receive_settings(&mut driver).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), incoming.recv())
                .await
                .is_err()
        );
        let _stream = open(&transport).await;
        let received = drive_until(&mut driver, incoming.recv()).await.unwrap();
        drop(received);
        // Poll a new receiver wait before dropping the driver to test the wakeup.
        let mut pending = std::pin::pin!(incoming.recv());
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        let closed = async {
            tokio::task::yield_now().await;
            drop(driver);
        };
        let (stream, ()) = tokio::join!(pending, closed);
        assert!(stream.is_none());
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn peer_settings_must_arrive_before_the_predicate_is_called() {
    tokio::time::timeout(DEADLINE, async {
        let mut pair = Pair::default();
        let endpoint = pair.server();
        let (transport, client) = tokio::join!(
            async { endpoint.endpoint.accept().await.unwrap().await.unwrap() },
            pair.client(),
        );
        let (mut driver, _sender) = client::new(client).await.unwrap();
        let mut incoming = driver.server_initiated_streams(
            NonZeroUsize::new(1).unwrap(),
            Code::H3_REQUEST_CANCELLED,
            |_, _| panic!("peer SETTINGS have not arrived"),
        );
        // No control stream, but a server bidi arrives. Defaults are not negotiation evidence.
        let _stream = open(&transport).await;
        assert!(matches!(
            driver.wait_idle().await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    ..
                }
            }
        ));
        assert!(incoming.recv().await.is_none());
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn bilateral_settings_without_registration_still_reject_server_streams() {
    tokio::time::timeout(DEADLINE, async {
        let (_endpoint, mut driver, _sender, _server, transport) =
            connect((true, true), (true, true)).await;
        receive_settings(&mut driver).await;
        let _stream = open(&transport).await;
        assert!(matches!(
            driver.wait_idle().await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    ..
                }
            }
        ));
    })
    .await
    .expect("scenario timed out");
}

#[tokio::test]
async fn transport_close_is_preserved_and_ends_the_receiver() {
    tokio::time::timeout(DEADLINE, async {
        let (_endpoint, mut driver, _sender, _server, transport) =
            connect((true, true), (true, true)).await;
        let mut incoming = driver.server_initiated_streams(
            NonZeroUsize::new(1).unwrap(),
            Code::H3_REQUEST_CANCELLED,
            negotiated,
        );
        receive_settings(&mut driver).await;
        transport.close(quinn::VarInt::from_u32(0x1234), b"test close");
        assert!(matches!(
            driver.wait_idle().await,
            ConnectionError::Remote(crate::quic::ConnectionErrorIncoming::ApplicationClose {
                error_code: 0x1234
            })
        ));
        assert!(incoming.recv().await.is_none());
    })
    .await
    .expect("scenario timed out");
}

// A transport adapter makes a complete real-network burst ready in one poll,
// independent of packet timing and Quinn's own cooperative scheduling.
struct BufferedConnection {
    inner: h3_quinn::Connection,
    streams: std::collections::VecDeque<h3_quinn::BidiStream<Bytes>>,
    enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl crate::quic::OpenStreams<Bytes> for BufferedConnection {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::BidiStream, crate::quic::StreamErrorIncoming>> {
        crate::quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::SendStream, crate::quic::StreamErrorIncoming>> {
        crate::quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        crate::quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason);
    }
}

impl crate::quic::Connection<Bytes> for BufferedConnection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = h3_quinn::OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::RecvStream, crate::quic::ConnectionErrorIncoming>> {
        crate::quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::BidiStream, crate::quic::ConnectionErrorIncoming>> {
        if !self.enabled.load(std::sync::atomic::Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        if let Some(stream) = self.streams.pop_front() {
            std::task::Poll::Ready(Ok(stream))
        } else {
            crate::quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx)
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        crate::quic::Connection::<Bytes>::opener(&self.inner)
    }
}

#[derive(Default)]
struct WakeFlag(std::sync::atomic::AtomicBool);

impl futures_util::task::ArcWake for WakeFlag {
    fn wake_by_ref(arc_self: &std::sync::Arc<Self>) {
        arc_self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn ready_stream_burst_yields_and_schedules_further_progress() {
    tokio::time::timeout(DEADLINE, async {
        const STREAMS: usize = 65;
        let mut pair = Pair::default();
        let endpoint = pair.server();
        let (transport, mut client) = tokio::join!(
            async { endpoint.endpoint.accept().await.unwrap().await.unwrap() },
            pair.client(),
        );
        let _server = server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, Bytes>(h3_quinn::Connection::new(transport.clone()))
            .await
            .unwrap();
        let mut peers = Vec::new();
        let mut streams = std::collections::VecDeque::new();
        for _ in 0..STREAMS {
            peers.push(open(&transport).await);
            streams.push_back(
                poll_fn(|cx| crate::quic::Connection::<Bytes>::poll_accept_bidi(&mut client, cx))
                    .await
                    .unwrap(),
            );
        }
        let enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let buffered = BufferedConnection {
            inner: client,
            streams,
            enabled: enabled.clone(),
        };
        let (mut driver, _sender) = client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(buffered)
            .await
            .unwrap();
        let mut incoming = driver.server_initiated_streams(
            NonZeroUsize::new(STREAMS).unwrap(),
            Code::H3_REQUEST_CANCELLED,
            negotiated,
        );
        receive_settings(&mut driver).await;
        enabled.store(true, std::sync::atomic::Ordering::SeqCst);
        let flag = std::sync::Arc::new(WakeFlag::default());
        let waker = futures_util::task::waker(flag.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(driver.poll_close(&mut cx).is_pending());
        assert!(
            flag.0.load(std::sync::atomic::Ordering::SeqCst),
            "driver must arrange another poll after yielding"
        );
        let mut delivered = 0;
        for _ in 0..STREAMS {
            if incoming.poll_recv(&mut cx).is_ready() {
                delivered += 1;
            } else {
                break;
            }
        }
        assert!(
            delivered > 0 && delivered < STREAMS,
            "one poll must yield before draining the entire burst"
        );
        for _ in delivered..STREAMS {
            let stream = drive_until(&mut driver, incoming.recv()).await.unwrap();
            drop(stream);
        }
    })
    .await
    .expect("scenario timed out");
}
