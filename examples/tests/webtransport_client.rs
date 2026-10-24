//! Client WebTransport over the same connection as ordinary HTTP/3 requests.
mod common;

use bytes::Bytes;
use h3::ext::WebTransportDraft;
use h3_webtransport::{
    client::{self, Limits},
    server::WebTransportSession,
};
use http::{Request, Response};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::Ipv6Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

type ClientSession = client::WebTransportSession<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn connections() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = CertificateDer::from(cert.cert);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).unwrap(),
    ));
    let server = quinn::Endpoint::server(server_config, (Ipv6Addr::LOCALHOST, 0).into()).unwrap();
    let addr = server.local_addr().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()).unwrap();
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(32_u32.into());
    // Three HTTP/3 control/QPACK streams leave room for one WebTransport uni stream.
    transport.max_concurrent_uni_streams(4_u32.into());
    client_config.transport_config(Arc::new(transport));
    client.set_default_client_config(client_config);
    let (server_conn, client_conn) = tokio::join!(
        async { server.accept().await.unwrap().await.unwrap() },
        async { client.connect(addr, "localhost").unwrap().await.unwrap() },
    );
    (server, client, server_conn, client_conn)
}

#[tokio::test]
async fn get_before_connect_and_independent_fins() {
    timeout(Duration::from_secs(5), async {
        let (_server, _client, server_conn, client_conn) = connections().await;
        let server = tokio::spawn(async move {
            let mut conn = h3::server::builder()
                .enable_webtransport(true)
                .enable_extended_connect(true)
                .enable_datagram(true)
                .max_webtransport_sessions(4)
                .webtransport_drafts([WebTransportDraft::Draft07])
                .build::<_, Bytes>(h3_quinn::Connection::new(server_conn))
                .await
                .unwrap();
            let (request, mut stream) = conn
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::GET);
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let (request, stream) = conn
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let session = WebTransportSession::accept(request, stream, conn)
                .await
                .unwrap();
            assert_eq!(
                session.session_id(),
                h3_webtransport::SessionId::try_from(4).unwrap()
            );
            let mut stream = session.open_bi(session.session_id()).await.unwrap();
            stream.write_all(b"visitor").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
            session.closed().await.unwrap()
        });
        let (conn, sender) = h3::client::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(4)
            .webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(client_conn))
            .await
            .unwrap();
        let mut ordinary = sender.clone();
        let (mut driver, mut client) = client::new(conn, sender, Limits::default());
        let driver = common::ClientDriver(tokio::spawn(async move {
            driver.wait_idle().await;
        }));
        let mut get = ordinary
            .send_request(Request::get("https://localhost/").body(()).unwrap())
            .await
            .unwrap();
        get.finish().await.unwrap();
        assert_eq!(get.recv_response().await.unwrap().status(), 200);
        assert!(get.recv_data().await.unwrap().is_none());
        let session: ClientSession = client
            .connect(
                Request::builder()
                    .method("CONNECT")
                    .uri("https://localhost/wt")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            session.session_id(),
            h3_webtransport::SessionId::try_from(4).unwrap()
        );
        let mut stream = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"visitor");
        // EOF from the server leaves the client write side open.
        stream.write_all(b"reply").await.unwrap();
        stream.shutdown().await.unwrap();
        session.close(42, "done").await.unwrap();
        assert_eq!(session.closed().await.unwrap().code, 42);
        assert_eq!(server.await.unwrap().code, 42);
        drop(driver);
    })
    .await
    .expect("client test timed out");
}

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type Client = client::Client<h3_quinn::OpenStreams, Bytes>;
struct Pair {
    _server: quinn::Endpoint,
    _client: quinn::Endpoint,
    raw: quinn::Connection,
    client_raw: quinn::Connection,
    server: h3::server::Connection<h3_quinn::Connection, Bytes>,
    client: Client,
    _driver: common::ClientDriver,
}
impl Pair {
    async fn new(limits: Limits, draft: WebTransportDraft, cap: u64) -> Self {
        Self::with_settings(limits, draft, draft, cap, true, true, true).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn with_settings(
        limits: Limits,
        server_draft: WebTransportDraft,
        client_draft: WebTransportDraft,
        cap: u64,
        wt: bool,
        datagrams: bool,
        extended: bool,
    ) -> Self {
        let (server, client, raw, client_raw) = connections().await;
        let server_conn = h3::server::builder()
            .enable_webtransport(wt)
            .enable_datagram(datagrams)
            .enable_extended_connect(extended)
            .max_webtransport_sessions(cap)
            .webtransport_drafts([server_draft])
            .build::<_, Bytes>(h3_quinn::Connection::new(raw.clone()))
            .await
            .unwrap();
        let (conn, sender) = h3::client::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(8)
            .webtransport_drafts([client_draft])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(client_raw.clone()))
            .await
            .unwrap();
        let (mut driver, client_handle) = client::new(conn, sender, limits);
        let driver = common::ClientDriver(tokio::spawn(async move {
            driver.wait_idle().await;
        }));
        Self {
            _server: server,
            _client: client,
            raw,
            client_raw,
            server: server_conn,
            client: client_handle,
            _driver: driver,
        }
    }
    async fn connect(&mut self) -> (ClientSession, ServerStream) {
        self.connect_with(Response::new(())).await
    }
    async fn connect_with(&mut self, response: Response<()>) -> (ClientSession, ServerStream) {
        let (session, stream) = self.try_connect_with(response).await;
        (session.unwrap(), stream)
    }
    async fn try_connect_with(
        &mut self,
        response: Response<()>,
    ) -> (Result<ClientSession, client::ConnectError>, ServerStream) {
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost/wt")
            .body(())
            .unwrap();
        let (session, stream) = tokio::join!(self.client.connect(request), async {
            let (request, mut stream) = self
                .server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert!(request
                .extensions()
                .get::<h3::ext::Protocol>()
                .unwrap()
                .is_webtransport());
            stream.send_response(response).await.unwrap();
            stream
        });
        (session, stream)
    }
    async fn ordinary(&mut self) {
        let mut sender = self.client.send_request();
        tokio::join!(
            async {
                let mut stream = sender
                    .send_request(Request::put("https://localhost/ordinary").body(()).unwrap())
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                assert_eq!(stream.recv_response().await.unwrap().status(), 204);
                assert!(stream.recv_data().await.unwrap().is_none());
            },
            async {
                let (request, mut stream) = self
                    .server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), http::Method::PUT);
                assert!(stream.recv_data().await.unwrap().is_none());
                stream
                    .send_response(Response::builder().status(204).body(()).unwrap())
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        );
    }
    async fn raw_stream(&self, prefix: &[u8]) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = self.raw.open_bi().await.unwrap();
        send.write_all(prefix).await.unwrap();
        (send, recv)
    }
}

#[tokio::test]
async fn wrong_session_invalid_and_truncated_prefixes_are_reset() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        for prefix in [&b"\x40\x41\x04wrong"[..], &b"\x00bad"[..], &b"\x40"[..], &b"\x40\x41\x40"[..], &b"\x40\x41\x01"[..]] {
            let (mut send, mut recv) = pair.raw_stream(prefix).await;
            send.finish().unwrap();
            assert!(matches!(recv.read_to_end(64).await, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code.into_inner() == h3_webtransport::WT_SESSION_GONE));
        }
        let (mut send, _recv) = pair.raw_stream(b"\x40\x41\x00valid").await;
        send.finish().unwrap();
        let mut stream = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"valid");
        pair.ordinary().await;
    }).await.expect("prefix rejection timed out");
}

#[tokio::test]
async fn slow_prefix_and_cancelled_accept_do_not_block_valid_streams() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let (_slow_send, _slow_recv) = pair.raw_stream(b"\x40").await;
        assert!(timeout(Duration::from_millis(20), session.accept_bi())
            .await
            .is_err());
        pair.ordinary().await;
        let (mut send, _recv) = pair.raw_stream(b"\x40\x41\x00valid").await;
        send.finish().unwrap();
        let mut stream = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"valid");
        // Cancelling the receiver did not abandon the partially read prefix.
        let mut slow = _slow_send;
        slow.write_all(b"\x41\x00later").await.unwrap();
        slow.finish().unwrap();
        let mut stream = session.accept_bi().await.unwrap();
        bytes.clear();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"later");
    })
    .await
    .expect("slow prefix test timed out");
}

#[tokio::test]
async fn driver_drop_resets_partially_parsed_streams() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let (send, mut recv) = pair.raw_stream(b"\x40").await;
        assert!(timeout(Duration::from_millis(20), session.accept_bi())
            .await
            .is_err());
        pair._driver.0.abort();
        let _ = (&mut pair._driver.0).await;
        assert!(matches!(
            recv.read_to_end(64).await,
            Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_)))
        ));
        assert!(send.stopped().await.unwrap().is_some());
        assert!(session.accept_bi().await.is_none());
        assert!(matches!(
            session.closed().await,
            Err(client::SessionError::OwnerDropped)
        ));
    })
    .await
    .expect("driver drop test timed out");
}

#[tokio::test]
async fn settings_mismatches_reject_sessions_and_preserve_ordinary_requests() {
    timeout(Duration::from_secs(5), async {
        use WebTransportDraft::*;
        for (server, client, cap, wt, datagrams, extended) in [
            (Draft07, Draft07, 4, false, true, true),
            (Draft07, Draft07, 4, true, false, true),
            (Draft07, Draft07, 4, true, true, false),
            (Draft02, Draft02, 0, true, true, true),
            (Draft02, Draft07, 4, true, true, true),
        ] {
            let mut pair = Pair::with_settings(
                Limits::default(),
                server,
                client,
                cap,
                wt,
                datagrams,
                extended,
            )
            .await;
            // Ordinary traffic drives peer SETTINGS before any CONNECT is attempted.
            pair.ordinary().await;
            let request = Request::builder()
                .method("CONNECT")
                .uri("https://localhost/wt")
                .body(())
                .unwrap();
            assert!(matches!(
                pair.client.connect(request).await,
                Err(client::ConnectError::Settings(_))
            ));
            pair.ordinary().await;
        }
    })
    .await
    .expect("settings tests timed out");
}

#[tokio::test]
async fn response_validation_rejects_status_and_incompatible_headers() {
    timeout(Duration::from_secs(5), async {
        use WebTransportDraft::*;
        for (draft, status, header, subprotocol) in [
            (Draft07, 403, None, None),
            (Draft07, 302, None, None),
            (Draft02, 200, None, None),
            (Draft02, 200, Some("draft07"), None),
            (Draft07, 200, Some("draft02"), None),
            (Draft15, 200, None, Some("unoffered")),
        ] {
            let mut pair = Pair::new(Limits::default(), draft, 4).await;
            let mut response = Response::builder().status(status);
            if let Some(header) = header { response = response.header("sec-webtransport-http3-draft", header); }
            if let Some(header) = subprotocol { response = response.header("sec-webtransport-protocol", header); }
            let (result, mut stream) = pair.try_connect_with(response.body(()).unwrap()).await;
            match status {
                200 => assert!(matches!(result, Err(client::ConnectError::InvalidResponse))),
                _ => assert!(matches!(result, Err(client::ConnectError::Rejected(code)) if code.as_u16() == status)),
            }
            assert!(stream.recv_data().await.is_err());
            pair.ordinary().await;
        }
    }).await.expect("response validation timed out");
}

#[tokio::test]
async fn each_adopted_draft_selects_its_connect_token_and_header() {
    timeout(Duration::from_secs(5), async {
        for draft in WebTransportDraft::ALL {
            let mut pair = Pair::new(Limits::default(), draft, 4).await;
            let mut response = Response::builder();
            if draft == WebTransportDraft::Draft02 {
                response = response.header("sec-webtransport-http3-draft", "draft02");
            }
            let request = Request::builder()
                .method("CONNECT")
                .uri("https://localhost/wt")
                .body(())
                .unwrap();
            let (session, mut stream) = tokio::join!(pair.client.connect(request), async {
                let (request, mut stream) = pair
                    .server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                let token = if draft == WebTransportDraft::Draft15 {
                    h3::ext::Protocol::WEB_TRANSPORT_H3
                } else {
                    h3::ext::Protocol::WEB_TRANSPORT
                };
                assert_eq!(
                    request.extensions().get::<h3::ext::Protocol>(),
                    Some(&token)
                );
                stream
                    .send_response(response.body(()).unwrap())
                    .await
                    .unwrap();
                stream
            });
            let session = session.unwrap();
            assert_eq!(session.draft(), draft);
            stream.finish().await.unwrap();
            assert_eq!(session.closed().await.unwrap().code, 0);
            assert!(stream.recv_data().await.unwrap().is_none());
        }
    })
    .await
    .expect("draft tests timed out");
}

#[tokio::test]
async fn live_sessions_route_exact_ids_and_enforce_the_peer_cap() {
    timeout(Duration::from_secs(5), async {
        let limits = Limits {
            sessions: 4.try_into().unwrap(),
            ..Limits::default()
        };
        let mut pair = Pair::new(limits, WebTransportDraft::Draft07, 2).await;
        let (first, _connect0) = pair.connect().await;
        let (second, _connect4) = pair.connect().await;
        assert_eq!(
            first.session_id(),
            h3_webtransport::SessionId::try_from(0).unwrap()
        );
        assert_eq!(
            second.session_id(),
            h3_webtransport::SessionId::try_from(4).unwrap()
        );
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost/wt")
            .body(())
            .unwrap();
        assert!(matches!(
            pair.client.connect(request).await,
            Err(client::ConnectError::SessionLimit)
        ));
        let (mut send4, _recv4) = pair.raw_stream(b"\x40\x41\x04second").await;
        send4.finish().unwrap();
        assert!(timeout(Duration::from_millis(20), first.accept_bi())
            .await
            .is_err());
        let mut stream = second.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"second");
        let (mut send0, _recv0) = pair.raw_stream(b"\x40\x41\x00first").await;
        send0.finish().unwrap();
        let mut stream = first.accept_bi().await.unwrap();
        bytes.clear();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"first");
        drop(first);
        let (_send, mut recv) = pair.raw_stream(b"\x40\x41\x00stale").await;
        assert!(matches!(
            recv.read_to_end(64).await,
            Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_)))
        ));
        pair.ordinary().await;
        // Releasing one session allows another CONNECT, with a new, full stream ID.
        let (_third, _connect) = pair.connect().await;
    })
    .await
    .expect("session routing timed out");
}

#[tokio::test]
async fn local_cap_and_draft13_wire_cap_are_enforced() {
    timeout(Duration::from_secs(5), async {
        for (limits, draft) in [
            (Limits::default(), WebTransportDraft::Draft07),
            (
                Limits {
                    sessions: 8.try_into().unwrap(),
                    ..Limits::default()
                },
                WebTransportDraft::Draft13,
            ),
        ] {
            let mut pair = Pair::new(limits, draft, 8).await;
            let (_session, _connect) = pair.connect().await;
            let request = Request::builder()
                .method("CONNECT")
                .uri("https://localhost/wt")
                .body(())
                .unwrap();
            assert!(matches!(
                pair.client.connect(request).await,
                Err(client::ConnectError::SessionLimit)
            ));
        }
    })
    .await
    .expect("session caps timed out");
}

#[tokio::test]
async fn pending_prefix_and_session_queue_saturation_reset_excess_streams() {
    timeout(Duration::from_secs(5), async {
        let limits = Limits { pending_prefixes: 1.try_into().unwrap(), streams_per_session: 1.try_into().unwrap(), ..Limits::default() };
        let mut pair = Pair::new(limits, WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let (slow, mut slow_recv) = pair.raw_stream(b"\x40").await;
        // Give the incomplete prefix a turn without removing any session stream.
        assert!(timeout(Duration::from_millis(20), session.accept_bi()).await.is_err());
        let (overflow_send, mut overflow_recv) = pair.raw_stream(b"\x40\x41\x00excess").await;
        assert!(matches!(overflow_recv.read_to_end(64).await, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code.into_inner() == 0x3994bd84));
        assert!(overflow_send.stopped().await.unwrap().is_some());
        pair.ordinary().await;
        let mut slow = slow;
        slow.finish().unwrap();
        assert!(slow_recv.read_to_end(64).await.is_err());
        let (mut first, mut recv) = pair.raw_stream(b"\x40\x41\x00first").await;
        first.finish().unwrap();
        // The first stream stays queued while the second is rejected with the overflow code.
        assert!(timeout(Duration::from_millis(20), recv.read_to_end(64)).await.is_err());
        let (_second, mut recv2) = pair.raw_stream(b"\x40\x41\x00second").await;
        assert!(matches!(recv2.read_to_end(64).await, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code.into_inner() == 0x3994bd84));
        let mut accepted = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        accepted.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"first");
    }).await.expect("saturation test timed out");
}

#[tokio::test]
async fn server_close_terminates_streams_before_fin_and_preserves_ordinary_h3() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, mut connect) = pair.connect().await;
        let (send, mut recv) = pair.raw_stream(b"\x40\x41\x00open").await;
        let mut accepted = session.accept_bi().await.unwrap();
        let mut open = [0; 4];
        accepted.read_exact(&mut open).await.unwrap();
        assert_eq!(&open, b"open");
        connect.send_data(common::close_capsule(7, b"server")).await.unwrap();
        assert!(timeout(Duration::from_millis(20), session.closed()).await.is_err());
        assert!(accepted.read_u8().await.is_err());
        assert!(session.accept_bi().await.is_none());
        assert!(matches!(recv.read_to_end(64).await, Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) if code.into_inner() == h3_webtransport::WT_SESSION_GONE));
        assert!(send.stopped().await.unwrap().is_some());
        pair.ordinary().await;
        connect.finish().await.unwrap();
        let outcome = session.closed().await.unwrap();
        assert_eq!((outcome.code, outcome.reason.as_str()), (7, "server"));
        assert!(connect.recv_data().await.unwrap().is_none());
        assert_eq!(session.closed().await.unwrap(), outcome);
    }).await.expect("server close test timed out");
}

#[tokio::test]
async fn client_close_sends_one_capsule_and_immediate_fin_without_grease() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, mut connect) = pair.connect().await;
        session.close(42, "client").await.unwrap();
        session.close(99, "ignored").await.unwrap();
        let mut body = Vec::new();
        while let Some(mut data) = connect.recv_data().await.unwrap() {
            use bytes::Buf;
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        assert_eq!(body, common::close_capsule(42, b"client"));
        assert!(timeout(Duration::from_millis(20), session.closed())
            .await
            .is_err());
        connect.finish().await.unwrap();
        assert_eq!(session.closed().await.unwrap().code, 42);
        pair.ordinary().await;
    })
    .await
    .expect("client close test timed out");
}

#[tokio::test]
async fn malformed_and_trailing_capsules_reset_connect_even_after_local_close() {
    timeout(Duration::from_secs(5), async {
        for local_first in [false, true] {
            for wire in [
                Bytes::from_static(b"\x68"),
                common::capsule(0x2843, b"bad"),
                { let mut bytes = common::close_capsule(7, b"bye").to_vec(); bytes.push(0); Bytes::from(bytes) },
                { let mut bytes = common::close_capsule(7, &[b'x'; 1024]).to_vec(); bytes.extend_from_slice(&[0; 2048]); Bytes::from(bytes) },
            ] {
                let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
                let (session, mut stream) = pair.connect().await;
                if local_first { session.close(1, "local").await.unwrap(); }
                stream.send_data(wire).await.unwrap();
                stream.finish().await.unwrap();
                assert!(matches!(session.closed().await, Err(client::SessionError::MalformedCapsule(_))));
                assert!(matches!(session.closed().await, Err(client::SessionError::MalformedCapsule(_))));
                // An already delivered FIN cannot be retracted by QUIC. Without a prior local
                // FIN, the peer must observe the H3_MESSAGE_ERROR reset on the wire.
                if !local_first {
                    let error = loop {
                        match stream.recv_data().await {
                            Ok(Some(_)) => continue,
                            result => break result,
                        }
                    };
                    assert!(matches!(error, Err(h3::error::StreamError::RemoteTerminate { code }) if code == h3::error::Code::H3_MESSAGE_ERROR));
                }
                pair.ordinary().await;
            }
        }
    }).await.expect("capsule validation timed out");
}

#[tokio::test]
async fn drain_unknown_capsules_and_connection_loss_are_bounded() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, mut connect) = pair.connect().await;
        connect
            .send_data(common::capsule(0x1234, &[0; 32 * 1024]))
            .await
            .unwrap();
        connect.send_data(common::drain_capsule()).await.unwrap();
        session.draining().await;
        assert!(timeout(Duration::from_millis(20), session.closed())
            .await
            .is_err());
        pair.ordinary().await;
        pair.raw.close(0x102u32.into(), b"test disconnect");
        assert!(matches!(
            session.closed().await,
            Err(client::SessionError::Stream(_))
        ));
        assert!(session.accept_bi().await.is_none());
        assert!(pair.client_raw.close_reason().is_some());
    })
    .await
    .expect("drain and connection loss timed out");
}

#[tokio::test]
async fn cancelled_connect_releases_its_reservation_and_resets_both_halves() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost/wt")
            .body(())
            .unwrap();
        let mut pending = Box::pin(pair.client.connect(request));
        let mut stream = tokio::select! {
            _ = &mut pending => panic!("CONNECT completed without a response"),
            accepted = pair.server.accept() => {
                accepted.unwrap().unwrap().resolve_request().await.unwrap().1
            }
        };
        drop(pending);
        assert!(stream.recv_data().await.is_err());
        // The reservation, rather than a hardcoded single-session policy, has been released.
        let (_session, _stream) = pair.connect().await;
    })
    .await
    .expect("CONNECT cancellation timed out");
}

#[tokio::test]
async fn dropping_session_resets_connect_and_queued_streams_without_closing_h3() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, mut connect) = pair.connect().await;
        let (send, mut recv) = pair.raw_stream(b"\x40\x41\x00queued").await;
        assert!(timeout(Duration::from_millis(20), recv.read_to_end(64))
            .await
            .is_err());
        drop(session);
        assert!(recv.read_to_end(64).await.is_err());
        assert!(send.stopped().await.unwrap().is_some());
        assert!(connect.recv_data().await.is_err());
        pair.ordinary().await;
    })
    .await
    .expect("session drop timed out");
}

#[tokio::test]
async fn driver_retains_last_request_sender_after_client_handle_drop() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let sender = pair.client.send_request();
        drop(sender);
        drop(pair.client);
        let (mut send, _recv) = pair.raw.open_bi().await.unwrap();
        send.write_all(b"\x40\x41\x00live").await.unwrap();
        send.finish().unwrap();
        let mut received = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        received.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"live");
        assert!(pair.client_raw.close_reason().is_none());
    })
    .await
    .expect("request sender retention timed out");
}

#[tokio::test]
async fn existing_server_session_can_initiate_close() {
    timeout(Duration::from_secs(5), async {
        let Pair {
            mut server,
            mut client,
            _server,
            _client,
            _driver,
            raw: _raw,
            client_raw: _client_raw,
        } = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost/wt")
            .body(())
            .unwrap();
        let (session, peer) = tokio::join!(client.connect(request), async {
            let (request, stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            WebTransportSession::accept(request, stream, server)
                .await
                .unwrap()
        });
        let session = session.unwrap();
        peer.close(73, "server session").await.unwrap();
        let (client_close, server_close) = tokio::join!(session.closed(), peer.closed());
        assert_eq!(client_close.unwrap().code, 73);
        assert_eq!(server_close.unwrap().code, 73);
    })
    .await
    .expect("existing server close timed out");
}

#[tokio::test]
async fn client_fin_does_not_end_the_server_write_direction() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let (mut send, mut recv) = pair.raw_stream(b"\x40\x41\x00first").await;
        let mut stream = session.accept_bi().await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"first");
        stream.write_all(b"reply").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"reply");
        send.write_all(b"tail").await.unwrap();
        send.finish().unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail");
    })
    .await
    .expect("client first FIN timed out");
}

#[tokio::test]
async fn server_stream_before_connect_response_is_buffered_for_that_session() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let request = Request::builder().method("CONNECT").uri("https://localhost/wt").body(()).unwrap();
        let mut pending = Box::pin(pair.client.connect(request));
        let mut connect = tokio::select! {
            _ = &mut pending => panic!("CONNECT completed without response"),
            accepted = pair.server.accept() => accepted.unwrap().unwrap().resolve_request().await.unwrap().1,
        };
        let (mut send, mut recv) = pair.raw.open_bi().await.unwrap();
        send.write_all(b"\x40\x41\x00early").await.unwrap();
        send.finish().unwrap();
        // It has not been reset or delivered while the handshake is still pending.
        assert!(timeout(Duration::from_millis(20), recv.read_to_end(64)).await.is_err());
        connect.send_response(Response::new(())).await.unwrap();
        let session = pending.await.unwrap();
        let mut stream = session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"early");
    }).await.expect("early stream buffering timed out");
}

#[tokio::test]
async fn concurrent_accept_waiters_have_independent_wakers() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        let (session, _connect) = pair.connect().await;
        let mut first = Box::pin(session.accept_bi());
        let mut second = Box::pin(session.accept_bi());
        // Poll both once before either stream is available.
        assert!(timeout(Duration::from_millis(20), &mut first)
            .await
            .is_err());
        assert!(timeout(Duration::from_millis(20), &mut second)
            .await
            .is_err());
        let (mut send1, _recv1) = pair.raw_stream(b"\x40\x41\x00one").await;
        let (mut send2, _recv2) = pair.raw_stream(b"\x40\x41\x00two").await;
        send1.finish().unwrap();
        send2.finish().unwrap();
        let (one, two) = tokio::join!(first, second);
        let (mut one, mut two) = (one.unwrap(), two.unwrap());
        let (mut a, mut b) = (Vec::new(), Vec::new());
        one.read_to_end(&mut a).await.unwrap();
        two.read_to_end(&mut b).await.unwrap();
        let mut messages = vec![a, b];
        messages.sort();
        assert_eq!(messages, [b"one".to_vec(), b"two".to_vec()]);
    })
    .await
    .expect("accept waiter test timed out");
}

#[tokio::test]
async fn invalid_request_tokens_and_forbidden_response_framing_are_rejected() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::new(Limits::default(), WebTransportDraft::Draft07, 4).await;
        pair.ordinary().await;
        for (method, uri, token) in [
            ("GET", "https://localhost/wt", None),
            ("CONNECT", "http://localhost/wt", None),
            (
                "CONNECT",
                "https://localhost/wt",
                Some(h3::ext::Protocol::WEB_TRANSPORT_H3),
            ),
        ] {
            let mut request = Request::builder().method(method).uri(uri).body(()).unwrap();
            if let Some(token) = token {
                request.extensions_mut().insert(token);
            }
            assert!(matches!(
                pair.client.connect(request).await,
                Err(client::ConnectError::InvalidRequest)
            ));
        }
        for response in [
            Response::builder()
                .header("content-length", "0")
                .body(())
                .unwrap(),
            Response::builder()
                .header("sec-webtransport-http3-draft", "draft02")
                .header("sec-webtransport-http3-draft", "draft02")
                .body(())
                .unwrap(),
        ] {
            let (result, mut stream) = pair.try_connect_with(response).await;
            assert!(matches!(result, Err(client::ConnectError::InvalidResponse)));
            assert!(stream.recv_data().await.is_err());
            pair.ordinary().await;
        }
    })
    .await
    .expect("CONNECT validation timed out");
}
