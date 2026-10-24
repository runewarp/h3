//! Session IDs and stream headers after an ordinary HTTP/3 request.

mod common;

use std::time::Duration;

use tokio::{io::AsyncWriteExt, time::timeout};

#[tokio::test]
async fn connect_after_get_uses_its_full_stream_id_on_the_wire() {
    timeout(Duration::from_secs(5), async {
        let mut setup = common::setup().await;
        assert_eq!(setup.stream.id().into_inner(), 4);
        assert_eq!(
            setup.session.session_id(),
            h3_webtransport::SessionId::try_from(4).unwrap()
        );

        // Observe the raw peer stream without adding extension dispatch to the h3 client.
        // Keep SendRequest alive, since dropping its last handle closes the connection.
        setup.driver.0.abort();
        let _ = (&mut setup.driver.0).await;
        let mut stream = setup
            .session
            .open_bi(setup.session.session_id())
            .await
            .unwrap();
        stream.write_all(b"visitor").await.unwrap();
        stream.shutdown().await.unwrap();

        let (mut send, mut recv) = setup.connection.accept_bi().await.unwrap();
        // QUIC varint 0x41 followed by the CONNECT stream ID 4, then application bytes.
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"\x40\x41\x04visitor");

        // FIN only closes the server's write direction; the peer can still reply.
        send.write_all(b"reply").await.unwrap();
        send.finish().unwrap();
        let mut reply = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut reply)
            .await
            .unwrap();
        assert_eq!(reply, b"reply");
    })
    .await
    .expect("WebTransport session-ID test timed out");
}
