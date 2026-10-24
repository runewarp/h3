//! Closing and draining WebTransport sessions.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{close_capsule, drain_capsule, read_to_end, setup};
use h3::error::{Code, StreamError};
use h3_webtransport::{
    server::{CloseInfo, SessionError},
    WT_SESSION_GONE,
};
use tokio::{io::AsyncWriteExt, time::timeout};

const TIMEOUT: Duration = Duration::from_secs(5);

fn info(code: u32, reason: &str) -> CloseInfo {
    CloseInfo {
        code,
        reason: reason.into(),
    }
}

#[tokio::test]
async fn client_closes_with_capsule() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup
            .stream
            .send_data(close_capsule(42, b"bye"))
            .await
            .unwrap();
        setup.stream.finish().await.unwrap();

        let outcome = timeout(TIMEOUT, setup.session.closed()).await.unwrap();
        assert_eq!(outcome.unwrap(), info(42, "bye"));

        // The server closes its side of the CONNECT stream in response.
        assert_eq!(read_to_end(&mut setup.stream).await, Bytes::new());
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn client_finishes_connect_stream() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup.stream.finish().await.unwrap();

        let outcome = timeout(TIMEOUT, setup.session.closed()).await.unwrap();
        assert_eq!(outcome.unwrap(), info(0, ""));
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn capsules_in_one_data_frame() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        let mut data = drain_capsule().to_vec();
        data.extend_from_slice(&close_capsule(1, b"both"));
        setup.stream.send_data(Bytes::from(data)).await.unwrap();

        timeout(TIMEOUT, setup.session.draining()).await.unwrap();
        let outcome = timeout(TIMEOUT, setup.session.closed()).await.unwrap();
        assert_eq!(outcome.unwrap(), info(1, "both"));
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn server_closes() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup.session.close(7, "done").await.unwrap();

        assert_eq!(
            read_to_end(&mut setup.stream).await,
            close_capsule(7, b"done")
        );
        setup.stream.finish().await.unwrap();
        let outcome = timeout(TIMEOUT, setup.session.closed()).await.unwrap();
        assert_eq!(outcome.unwrap(), info(7, "done"));

        // Closing again does nothing
        setup.session.close(8, "again").await.unwrap();
        assert_eq!(setup.session.closed().await.unwrap(), info(7, "done"));
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn server_drains() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup.session.drain().await.unwrap();

        let data = timeout(TIMEOUT, setup.stream.recv_data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut received = Vec::new();
        {
            use bytes::Buf;
            let mut data = data;
            while data.has_remaining() {
                let n = data.chunk().len();
                received.extend_from_slice(data.chunk());
                data.advance(n);
            }
        }
        assert_eq!(received, drain_capsule());

        // The session stays open
        assert!(timeout(Duration::from_millis(100), setup.session.closed())
            .await
            .is_err());
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn client_drains() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup.stream.send_data(drain_capsule()).await.unwrap();

        timeout(TIMEOUT, setup.session.draining()).await.unwrap();
        assert!(timeout(Duration::from_millis(100), setup.session.closed())
            .await
            .is_err());
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn closed_and_draining_wait_together() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        let session = setup.session.clone();
        let closed = tokio::spawn(async move { session.closed().await });
        let session = setup.session.clone();
        let draining = tokio::spawn(async move { session.draining().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        setup.stream.send_data(drain_capsule()).await.unwrap();
        timeout(TIMEOUT, draining).await.unwrap().unwrap();

        setup
            .stream
            .send_data(close_capsule(3, b"later"))
            .await
            .unwrap();
        let outcome = timeout(TIMEOUT, closed).await.unwrap().unwrap();
        assert_eq!(outcome.unwrap(), info(3, "later"));
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn invalid_close_message_resets_connect_stream() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup
            .stream
            .send_data(close_capsule(1, &[0xff, 0xfe]))
            .await
            .unwrap();

        let outcome = timeout(TIMEOUT, setup.session.closed()).await.unwrap();
        assert!(matches!(outcome, Err(SessionError::MalformedCapsule(_))));

        let err = timeout(TIMEOUT, setup.stream.recv_data())
            .await
            .unwrap()
            .err()
            .expect("CONNECT stream should be reset");
        assert!(
            matches!(err, StreamError::RemoteTerminate { code } if code == Code::H3_MESSAGE_ERROR),
            "{err:?}"
        );
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn streams_are_reset_when_the_session_closes() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let setup = setup().await;
        let session_id = setup.session.session_id();
        let mut uni = setup.session.open_uni(session_id).await.unwrap();
        uni.write_all(b"before").await.unwrap();

        setup.session.close(0, "").await.unwrap();

        let err = uni.write_all(b"after").await.unwrap_err();
        assert!(
            err.to_string().contains(&format!("{WT_SESSION_GONE:#x}")),
            "{err}"
        );
        assert!(setup.session.open_uni(session_id).await.is_err());
        assert!(setup.session.open_bi(session_id).await.is_err());
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn blocked_streams_wake_when_the_session_closes() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let setup = setup().await;
        let session_id = setup.session.session_id();
        let mut uni = setup.session.open_uni(session_id).await.unwrap();

        // The client never reads this stream, so the write blocks on flow control until the session
        // closes.
        let write = tokio::spawn(async move { uni.write_all(&vec![0; 64 << 20]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!write.is_finished());
        setup.session.close(0, "").await.unwrap();

        let result = timeout(TIMEOUT, write).await.unwrap().unwrap();
        assert!(result.is_err());
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn streams_are_reset_when_the_session_is_dropped() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let setup = setup().await;
        let session_id = setup.session.session_id();
        let mut uni = setup.session.open_uni(session_id).await.unwrap();
        drop(setup.session);

        let err = uni.write_all(b"after").await.unwrap_err();
        assert!(
            err.to_string().contains(&format!("{WT_SESSION_GONE:#x}")),
            "{err}"
        );
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn closed_waits_for_the_client_to_close_the_connect_stream() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut setup = setup().await;
        setup.session.close(7, "done").await.unwrap();
        // The capsule is followed by a FIN right away.
        assert_eq!(
            read_to_end(&mut setup.stream).await,
            close_capsule(7, b"done")
        );

        // Dropping the connection now could lose the close, so closed() waits for the client.
        let session = setup.session.clone();
        let closed = tokio::spawn(async move { session.closed().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!closed.is_finished());

        setup.stream.finish().await.unwrap();
        let outcome = timeout(TIMEOUT, closed).await.unwrap().unwrap();
        assert_eq!(outcome.unwrap(), info(7, "done"));
    })
    .await
    .expect("WebTransport test timed out");
}

#[tokio::test]
async fn opens_blocked_on_stream_credit_wake_when_the_session_closes() {
    timeout(TIMEOUT, async {
        let mut setup = setup().await;
        // The raw peer holds its streams open without the stock h3 client's bidi rejection.
        setup.driver.0.abort();
        let _ = (&mut setup.driver.0).await;
        let id = setup.session.session_id();
        let _bidi = setup.session.open_bi(id).await.unwrap();
        let _uni = setup.session.open_uni(id).await.unwrap();

        let session = setup.session.clone();
        let bidi = tokio::spawn(async move { session.open_bi(id).await.map(|_| ()) });
        let session = setup.session.clone();
        let uni = tokio::spawn(async move { session.open_uni(id).await.map(|_| ()) });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!bidi.is_finished());
        assert!(!uni.is_finished());

        setup.session.close(0, "done").await.unwrap();
        assert!(timeout(Duration::from_millis(500), bidi)
            .await
            .expect("blocked bidi open did not wake on close")
            .unwrap()
            .is_err());
        assert!(timeout(Duration::from_millis(500), uni)
            .await
            .expect("blocked uni open did not wake on close")
            .unwrap()
            .is_err());
    })
    .await
    .expect("WebTransport open/close test timed out");
}

#[tokio::test]
async fn cancelling_closed_releases_the_waiting_task() {
    timeout(TIMEOUT, async {
        struct WaitingTask(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for WaitingTask {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let setup = setup().await;
        let task = std::sync::Arc::new(WaitingTask(std::sync::atomic::AtomicUsize::new(0)));
        {
            let waker = std::task::Waker::from(task.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            let mut closed = Box::pin(setup.session.closed());
            assert!(std::future::Future::poll(closed.as_mut(), &mut cx).is_pending());
        }
        // A long-lived session must not retain every cancelled closed() caller.
        assert_eq!(std::sync::Arc::strong_count(&task), 1);
        setup.session.close(0, "done").await.unwrap();
        assert_eq!(task.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    })
    .await
    .expect("WebTransport cancelled-waiter test timed out");
}

#[tokio::test]
async fn unknown_capsules_do_not_wake_idle_streams() {
    timeout(TIMEOUT, async {
        use h3::quic::RecvStream;
        use h3_webtransport::server::AcceptedBi;
        use std::{
            future::Future,
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            task::{Context, Wake, Waker},
        };

        #[derive(Default)]
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut setup = setup().await;
        let mut peer_streams = Vec::new();
        let mut streams = Vec::new();
        let stream_wakes = Arc::new(CountWake::default());
        let stream_waker = Waker::from(stream_wakes.clone());
        for _ in 0..50 {
            let (mut send, recv) = setup.connection.open_bi().await.unwrap();
            // WebTransport bidi signal 0x41 and CONNECT stream ID 4.
            send.write_all(b"\x40\x41\x04").await.unwrap();
            peer_streams.push((send, recv));
            let resolver = setup.session.accept_bi().await.unwrap().unwrap();
            let AcceptedBi::BidiStream(_, mut stream) = resolver.resolve().await.unwrap() else {
                panic!("expected a WebTransport stream");
            };
            assert!(stream
                .poll_data(&mut Context::from_waker(&stream_waker))
                .is_pending());
            streams.push(stream);
        }

        let reader_wakes = Arc::new(CountWake::default());
        let reader_waker = Waker::from(reader_wakes.clone());
        let mut closed = Box::pin(setup.session.closed());
        assert!(closed
            .as_mut()
            .poll(&mut Context::from_waker(&reader_waker))
            .is_pending());
        stream_wakes.0.store(0, Ordering::SeqCst);
        for _ in 0..20 {
            let before = reader_wakes.0.load(Ordering::SeqCst);
            setup
                .stream
                .send_data(common::capsule(0x1234, b"ignored"))
                .await
                .unwrap();
            while reader_wakes.0.load(Ordering::SeqCst) == before {
                tokio::task::yield_now().await;
            }
            assert!(closed
                .as_mut()
                .poll(&mut Context::from_waker(&reader_waker))
                .is_pending());
            for stream in &mut streams {
                assert!(stream
                    .poll_data(&mut Context::from_waker(&stream_waker))
                    .is_pending());
            }
        }
        assert_eq!(
            stream_wakes.0.load(Ordering::SeqCst),
            0,
            "unknown capsules woke idle streams"
        );
        drop(closed);

        // Separating reader wakeups must preserve termination wakeups for every stream.
        setup.session.close(0, "done").await.unwrap();
        assert_eq!(stream_wakes.0.load(Ordering::SeqCst), streams.len());
        for stream in &mut streams {
            assert!(matches!(
                stream.poll_data(&mut Context::from_waker(&stream_waker)),
                std::task::Poll::Ready(Err(_))
            ));
        }
    })
    .await
    .expect("WebTransport capsule wakeup test timed out");
}
