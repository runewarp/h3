use std::{num::NonZeroUsize, time::Duration};

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use http::{Request, Response};

use crate::{client, error::Code, quic::RecvStream, server};

use super::{h3_quinn, Pair};

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
