//! Detached Server sessions sharing ordinary H3 request intake.
mod common;
use bytes::Bytes;
use h3::ext::WebTransportDraft;
use h3_webtransport::{client, server};
use http::{Request, Response};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::Ipv6Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

async fn connections() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    connections_with_credit(32).await
}

async fn connections_with_credit(
    credit: u32,
) -> (
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
    transport.max_concurrent_bidi_streams(credit.into());
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
async fn detached_session_opens_while_get_and_put_continue() {
    timeout(Duration::from_secs(5), async {
        let (_se, _ce, sq, cq) = connections().await;
        let core = h3::server::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(4)
            .webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, Bytes>(h3_quinn::Connection::new(sq))
            .await
            .unwrap();
        let (mut driver, acceptor) = server::new(core, server::Limits::default());
        let (core, sender) = h3::client::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(4)
            .webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(cq))
            .await
            .unwrap();
        let (mut cd, mut client) = client::new(core, sender, client::Limits::default());
        let _cd = common::ClientDriver(tokio::spawn(async move {
            cd.wait_idle().await;
        }));
        let mut ordinary = client.send_request();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            // GET uses zero, CONNECT uses four. Ordinary requests never enter a session queue.
            let resolver = driver.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let (req, stream) = driver
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let session = acceptor.accept(req, stream).await.unwrap();
            tx.send(session).ok().unwrap();
            let (req, mut stream) = driver
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(req.method(), "PUT");
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            // Continue driving control streams while the detached session runs.
            let _ = driver.accept().await;
        });
        let mut get = ordinary
            .send_request(Request::get("https://localhost/").body(()).unwrap())
            .await
            .unwrap();
        get.finish().await.unwrap();
        assert_eq!(get.recv_response().await.unwrap().status(), 200);
        assert!(get.recv_data().await.unwrap().is_none());
        let client_session = client
            .connect(
                Request::builder()
                    .method("CONNECT")
                    .uri("https://localhost/wt")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        let session = rx.await.unwrap();
        assert_eq!(
            session.session_id(),
            h3_webtransport::SessionId::try_from(4).unwrap()
        );
        let mut opened = session.opener().open_bi().await.unwrap();
        opened.write_all(b"visitor").await.unwrap();
        opened.shutdown().await.unwrap();
        let mut received = client_session.accept_bi().await.unwrap();
        let mut bytes = Vec::new();
        received.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"visitor");
        received.write_all(b"reply").await.unwrap();
        received.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"reply");
        let mut put = ordinary
            .send_request(Request::put("https://localhost/state").body(()).unwrap())
            .await
            .unwrap();
        put.finish().await.unwrap();
        assert_eq!(put.recv_response().await.unwrap().status(), 200);
        assert!(put.recv_data().await.unwrap().is_none());
        session.close(7, "done").await.unwrap();
        let (a, b) = tokio::join!(session.closed(), client_session.closed());
        assert_eq!(a.unwrap().code, 7);
        assert_eq!(b.unwrap().code, 7);
        server_task.abort();
    })
    .await
    .expect("Server test timed out");
}

type ServerSession = server::Session<h3_quinn::Connection, Bytes>;
type ClientSession = client::WebTransportSession<h3_quinn::BidiStream<Bytes>, Bytes>;
type Resolver = h3::server::RequestResolver<h3_quinn::Connection, Bytes>;
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
struct Pair {
    _se: quinn::Endpoint,
    _ce: quinn::Endpoint,
    sq: quinn::Connection,
    cq: quinn::Connection,
    requests: tokio::sync::mpsc::Receiver<Resolver>,
    shutdown: tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<()>>,
    acceptor: server::Acceptor<h3_quinn::Connection, Bytes>,
    client: client::Client<h3_quinn::OpenStreams, Bytes>,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _sd: common::ClientDriver,
    _cd: common::ClientDriver,
}
impl Pair {
    async fn new(
        limits: server::Limits,
        cap: u64,
        sd: WebTransportDraft,
        cd: WebTransportDraft,
        flags: [bool; 3],
    ) -> Self {
        Self::with_credit(limits, cap, sd, cd, flags, 32).await
    }
    async fn with_credit(
        limits: server::Limits,
        cap: u64,
        sd: WebTransportDraft,
        cd: WebTransportDraft,
        flags: [bool; 3],
        credit: u32,
    ) -> Self {
        let (se, ce, sq, cq) = connections_with_credit(credit).await;
        let core = h3::server::builder()
            .enable_webtransport(flags[0])
            .enable_datagram(flags[1])
            .enable_extended_connect(flags[2])
            .max_webtransport_sessions(cap)
            .webtransport_drafts([sd])
            .build::<_, Bytes>(h3_quinn::Connection::new(sq.clone()))
            .await
            .unwrap();
        let (mut driver, acceptor) = server::new(core, limits);
        let (tx, requests) = tokio::sync::mpsc::channel(64);
        let (shutdown, mut shutdown_rx) =
            tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
        let sd = common::ClientDriver(tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(ack)=shutdown_rx.recv()=>{driver.shutdown(0).await.unwrap();let _=ack.send(());}
                    request=driver.accept()=>{
                        let Ok(Some(resolver))=request else {break;};
                        if tx.send(resolver).await.is_err(){break;}
                    }
                }
            }
        }));
        let (core, sender) = h3::client::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(8)
            .webtransport_drafts([cd])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(cq.clone()))
            .await
            .unwrap();
        let limits = client::Limits {
            sessions: 8.try_into().unwrap(),
            ..client::Limits::default()
        };
        let (mut driver, client) = client::new(core, sender.clone(), limits);
        let cd = common::ClientDriver(tokio::spawn(async move {
            driver.wait_idle().await;
        }));
        Self {
            _se: se,
            _ce: ce,
            sq,
            cq,
            requests,
            shutdown,
            acceptor,
            client,
            sender,
            _sd: sd,
            _cd: cd,
        }
    }
    async fn default() -> Self {
        Self::new(
            server::Limits::default(),
            4,
            WebTransportDraft::Draft07,
            WebTransportDraft::Draft07,
            [true; 3],
        )
        .await
    }
    async fn request(
        &mut self,
        request: Request<()>,
    ) -> (
        ClientStream,
        Request<()>,
        h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) {
        let client = self.sender.send_request(request).await.unwrap();
        let (req, stream) = self
            .requests
            .recv()
            .await
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        (client, req, stream)
    }
    async fn ordinary(&mut self) {
        let (mut client, req, mut stream) = self
            .request(Request::put("https://localhost/state").body(()).unwrap())
            .await;
        assert_eq!(req.method(), "PUT");
        client.finish().await.unwrap();
        stream.send_response(Response::new(())).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(client.recv_response().await.unwrap().status(), 200);
        assert!(client.recv_data().await.unwrap().is_none());
    }
    async fn session(&mut self) -> (ServerSession, ClientSession) {
        let connect = self.client.connect(
            Request::builder()
                .method("CONNECT")
                .uri("https://localhost/wt")
                .body(())
                .unwrap(),
        );
        let accept = async {
            let (req, stream) = self
                .requests
                .recv()
                .await
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            self.acceptor.accept(req, stream).await.unwrap()
        };
        let (client, server) = tokio::join!(connect, accept);
        (server, client.unwrap())
    }
    async fn raw_session(&mut self) -> (ServerSession, ClientStream) {
        let (mut client, req, stream) = self.request(connect_request()).await;
        let session = self.acceptor.accept(req, stream).await.unwrap();
        assert_eq!(client.recv_response().await.unwrap().status(), 200);
        (session, client)
    }
}
fn connect_request() -> Request<()> {
    let mut req = Request::builder()
        .method("CONNECT")
        .uri("https://localhost/wt")
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(h3::ext::Protocol::WEB_TRANSPORT);
    req
}

#[tokio::test]
async fn invalid_connects_reject_without_a_session_and_preserve_put() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default().await;
        for case in 0..5 {
            let mut req = connect_request();
            match case {
                0 => *req.method_mut() = http::Method::GET,
                1 => *req.uri_mut() = "http://localhost/wt".parse().unwrap(),
                2 => {
                    req.extensions_mut()
                        .insert(h3::ext::Protocol::WEB_TRANSPORT_H3);
                }
                3 => {
                    req.headers_mut()
                        .insert("sec-webtransport-protocol", "unoffered".parse().unwrap());
                }
                _ => {
                    req.extensions_mut().remove::<h3::ext::Protocol>();
                }
            }
            let (mut client, req, stream) = pair.request(req).await;
            assert!(matches!(
                pair.acceptor.accept(req, stream).await,
                Err(server::ConnectError::InvalidRequest)
            ));
            assert_eq!(client.recv_response().await.unwrap().status(), 400);
            assert!(client.recv_data().await.unwrap().is_none());
            pair.ordinary().await;
        }
        let (_session, _client) = pair.session().await;
    })
    .await
    .expect("invalid CONNECT test timed out");
}

#[tokio::test]
async fn missing_settings_and_draft_mismatch_preserve_ordinary_h3() {
    timeout(Duration::from_secs(5), async {
        for (flags, sd, cd) in [
            (
                [false, true, true],
                WebTransportDraft::Draft07,
                WebTransportDraft::Draft07,
            ),
            (
                [true, false, true],
                WebTransportDraft::Draft07,
                WebTransportDraft::Draft07,
            ),
            (
                [true, true, false],
                WebTransportDraft::Draft07,
                WebTransportDraft::Draft07,
            ),
            (
                [true; 3],
                WebTransportDraft::Draft07,
                WebTransportDraft::Draft15,
            ),
        ] {
            let mut pair = Pair::new(server::Limits::default(), 4, sd, cd, flags).await;
            let (mut client, req, stream) = pair.request(connect_request()).await;
            assert!(matches!(
                pair.acceptor.accept(req, stream).await,
                Err(server::ConnectError::Settings(_))
            ));
            assert_eq!(client.recv_response().await.unwrap().status(), 400);
            pair.ordinary().await;
        }
    })
    .await
    .expect("SETTINGS rejection test timed out");
}

#[tokio::test]
async fn local_and_negotiated_caps_release_on_close_and_drop() {
    timeout(Duration::from_secs(5), async {
        for (local, cap) in [(1, 4), (4, 1), (2, 4)] {
            let limits = server::Limits {
                sessions: local.try_into().unwrap(),
                ..server::Limits::default()
            };
            let mut pair = Pair::new(
                limits,
                cap,
                WebTransportDraft::Draft07,
                WebTransportDraft::Draft07,
                [true; 3],
            )
            .await;
            let (first, mut first_client) = pair.raw_session().await;
            let second = if local == 2 {
                Some(pair.raw_session().await)
            } else {
                None
            };
            let (mut client, req, stream) = pair.request(connect_request()).await;
            assert!(matches!(
                pair.acceptor.accept(req, stream).await,
                Err(server::ConnectError::SessionLimit)
            ));
            assert_eq!(client.recv_response().await.unwrap().status(), 429);
            pair.ordinary().await;
            // A close releases the slot even while its handle and peer-FIN wait still exist.
            first.close(9, "done").await.unwrap();
            let (replacement, _) = pair.raw_session().await;
            drop(replacement);
            let (_replacement, _) = pair.raw_session().await;
            first_client.finish().await.unwrap();
            assert_eq!(first.closed().await.unwrap().code, 9);
            drop(second);
        }
    })
    .await
    .expect("session cap test timed out");
}

#[tokio::test]
async fn client_close_drain_and_session_drop_leave_put_usable() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default().await;
        let (session, client) = pair.session().await;
        session.drain().await.unwrap();
        client.draining().await;
        client.close(42, "client done").await.unwrap();
        let (a, b) = tokio::join!(session.closed(), client.closed());
        assert_eq!(a.unwrap().code, 42);
        assert_eq!(b.unwrap().code, 42);
        assert!(session.opener().open_bi().await.is_err());
        pair.ordinary().await;
        let (session, client) = pair.session().await;
        drop(session);
        assert!(client.closed().await.is_err());
        pair.ordinary().await;
    })
    .await
    .expect("client close test timed out");
}

#[tokio::test]
async fn concurrent_credit_waiters_cancel_recover_and_terminate_independently() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::with_credit(
            server::Limits::default(),
            4,
            WebTransportDraft::Draft07,
            WebTransportDraft::Draft07,
            [true; 3],
            1,
        )
        .await;
        let (session, client) = pair.session().await;
        let session = Arc::new(session);
        let mut first = session.opener().open_bi().await.unwrap();
        let mut peer = client.accept_bi().await.unwrap();
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let session = session.clone();
            waiters.push(tokio::spawn(
                async move { session.opener().open_bi().await },
            ));
        }
        for task in &mut waiters {
            assert!(timeout(Duration::from_millis(10), task).await.is_err());
        }
        // Cancelling the newest waiter used to leave the shared Quinn future's only waker dead.
        let cancelled = waiters.pop().unwrap();
        cancelled.abort();
        assert!(matches!(cancelled.await,Err(e) if e.is_cancelled()));
        use h3::quic::{RecvStream as _, SendStream as _};
        first.reset(0);
        first.stop_sending(0);
        peer.reset(0);
        peer.stop_sending(0);
        drop((first, peer));
        use futures::{stream::FuturesUnordered, StreamExt};
        let mut waiters: FuturesUnordered<_> = waiters.into_iter().collect();
        while let Some(task) = waiters.next().await {
            let mut stream = task.unwrap().unwrap();
            // Do not reset before the peer receives the prefix. QUIC may elide reset streams.
            let mut received = client.accept_bi().await.unwrap();
            stream.reset(0);
            stream.stop_sending(0);
            received.reset(0);
            received.stop_sending(0);
        }
        // Re-exhaust credit and prove a session close wakes every blocked opener.
        let mut held = session.opener().open_bi().await.unwrap();
        let mut peer = client.accept_bi().await.unwrap();
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let session = session.clone();
            waiters.push(tokio::spawn(
                async move { session.opener().open_bi().await },
            ));
        }
        for task in &mut waiters {
            assert!(timeout(Duration::from_millis(10), task).await.is_err());
        }
        pair.ordinary().await;
        session.close(1, "credit blocked").await.unwrap();
        for task in waiters {
            assert!(task.await.unwrap().is_err());
        }
        held.reset(0);
        held.stop_sending(0);
        peer.reset(0);
        peer.stop_sending(0);
        let (a, b) = tokio::join!(session.closed(), client.closed());
        assert!(a.is_ok());
        assert!(b.is_ok());
        pair.ordinary().await;
    })
    .await
    .expect("credit test timed out");
}

#[tokio::test]
async fn exact_client_stream_ids_reject_wrong_stale_and_malformed_prefixes() {
    timeout(Duration::from_secs(5),async {
        let mut pair=Pair::new(server::Limits{sessions:2.try_into().unwrap(),..server::Limits::default()},4,WebTransportDraft::Draft07,WebTransportDraft::Draft07,[true;3]).await;
        pair.ordinary().await;
        let (one,_)=pair.raw_session().await;let (two,_)=pair.raw_session().await;
        assert_eq!(one.session_id(),h3_webtransport::SessionId::try_from(4).unwrap());
        assert_eq!(two.session_id(),h3_webtransport::SessionId::try_from(8).unwrap());
        // Slow prefix remains independent of ordinary intake and complete prefixes.
        let (mut slow_send,mut slow_recv)=pair.cq.open_bi().await.unwrap();slow_send.write_all(&[0x40]).await.unwrap();
        for bytes in [vec![0x40,0x41,0],vec![0x40,0x41,12],vec![0x40,0x41,1],vec![0x40,0x41,0x40],vec![0x40,0x42],vec![0x40]] {
            let (mut send,mut recv)=pair.cq.open_bi().await.unwrap();send.write_all(&bytes).await.unwrap();send.finish().unwrap();
            assert!(matches!(recv.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==h3_webtransport::WT_SESSION_GONE));
        }
        pair.ordinary().await;
        for (id,session) in [(8,&two),(4,&one)] {
            let (mut send,mut recv)=pair.cq.open_bi().await.unwrap();send.write_all(&[0x40,0x41,id,b'x']).await.unwrap();send.finish().unwrap();
            let mut accepted=session.accept_bi().await.unwrap();let mut bytes=Vec::new();accepted.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,b"x");
            accepted.write_all(b"ok").await.unwrap();accepted.shutdown().await.unwrap();assert_eq!(recv.read_to_end(8).await.unwrap(),b"ok");
        }
        drop(one);
        let (_replacement,_)=pair.raw_session().await;
        let (mut send,mut recv)=pair.cq.open_bi().await.unwrap();send.write_all(&[0x40,0x41,4]).await.unwrap();send.finish().unwrap();
        assert!(matches!(recv.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==h3_webtransport::WT_SESSION_GONE));
        slow_send.reset(0u32.into()).unwrap();slow_recv.stop(0u32.into()).unwrap();
        pair.ordinary().await;
    }).await.expect("incoming session ID test timed out");
}

#[tokio::test]
async fn bounded_server_dispatch_and_driver_drop_abort_pending_streams() {
    timeout(Duration::from_secs(5),async {
        let limits=server::Limits{pending_prefixes:2.try_into().unwrap(),streams_per_session:1.try_into().unwrap(),..server::Limits::default()};
        let mut pair=Pair::new(limits,4,WebTransportDraft::Draft07,WebTransportDraft::Draft07,[true;3]).await;
        let (session,_)=pair.raw_session().await;
        let id = 0;
        assert_eq!(session.session_id(),h3_webtransport::SessionId::try_from(0).unwrap());
        let mut queued=Vec::new();
        for _ in 0..2 {let (mut send,recv)=pair.cq.open_bi().await.unwrap();send.write_all(&[0x40,0x41,id]).await.unwrap();queued.push((send,recv));}
        let (_,mut excess)=queued.pop().unwrap();
        assert!(matches!(excess.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==0x3994bd84));
        let mut valid=session.accept_bi().await.unwrap();
        use h3::quic::{SendStream as _,RecvStream as _};valid.reset(0);valid.stop_sending(0);
        pair.ordinary().await;
        // Incomplete streams consume independent classifier slots, never a task per stream.
        let mut pending=Vec::new();
        for _ in 0..3 {let (mut send,recv)=pair.cq.open_bi().await.unwrap();send.write_all(&[0x40]).await.unwrap();pending.push((send,recv));}
        let (_,mut excess)=pending.pop().unwrap();
        assert!(matches!(excess.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==0x3994bd84));
        pair._sd.0.abort();let _=(&mut pair._sd.0).await;
        assert!(matches!(session.closed().await,Err(server::SessionError::OwnerDropped)));
        for (_,mut recv) in pending {assert!(recv.read_chunk(8,true).await.is_err());}
    }).await.expect("bounded dispatch test timed out");
}

#[tokio::test]
async fn server_capsules_reject_trailing_bytes_including_after_local_close() {
    timeout(Duration::from_secs(5), async {
        for local_first in [false, true] {
            for later_frame in [false, true] {
                let mut pair = Pair::default().await;
                let (session, mut client) = pair.raw_session().await;
                if local_first {
                    session.close(8, "local").await.unwrap();
                }
                let mut bytes = common::close_capsule(7, b"peer").to_vec();
                if later_frame {
                    client.send_data(Bytes::from(bytes)).await.unwrap();
                    client
                        .send_data(Bytes::from_static(b"trailing"))
                        .await
                        .unwrap();
                } else {
                    bytes.extend_from_slice(&[0; 2048]);
                    client.send_data(Bytes::from(bytes)).await.unwrap();
                }
                client.finish().await.unwrap();
                assert!(matches!(
                    session.closed().await,
                    Err(server::SessionError::MalformedCapsule(_))
                ));
                if !local_first {
                    assert!(client.recv_data().await.is_err());
                }
                pair.ordinary().await;
            }
        }
        let mut pair = Pair::default().await;
        let (session, mut client) = pair.raw_session().await;
        session.close(9, "FIN deadline").await.unwrap();
        let mut body = Vec::new();
        while let Some(mut chunk) = client.recv_data().await.unwrap() {
            use bytes::Buf;
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(body, common::close_capsule(9, b"FIN deadline"));
        assert!(timeout(Duration::from_millis(20), session.closed())
            .await
            .is_err());
        client.finish().await.unwrap();
        assert_eq!(session.closed().await.unwrap().code, 9);
        pair.ordinary().await;
    })
    .await
    .expect("Server capsule test timed out");
}

#[tokio::test]
async fn connection_loss_terminates_detached_session_and_credit_opens() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::with_credit(
            server::Limits::default(),
            4,
            WebTransportDraft::Draft07,
            WebTransportDraft::Draft07,
            [true; 3],
            0,
        )
        .await;
        let (session, _) = pair.session().await;
        let session = Arc::new(session);
        let owned = session.clone();
        let mut opening = tokio::spawn(async move { owned.opener().open_bi().await });
        assert!(timeout(Duration::from_millis(20), &mut opening)
            .await
            .is_err());
        pair.sq.close(0u32.into(), b"connection lost");
        assert!(opening.await.unwrap().is_err());
        assert!(session.closed().await.is_err());
    })
    .await
    .expect("connection loss test timed out");
}

#[tokio::test]
async fn unknown_frames_before_headers_preserve_ordinary_requests() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default().await;
        let (mut send, mut recv) = pair.cq.open_bi().await.unwrap();
        // Unknown frame 0x21, three payload bytes, then literal QPACK GET headers.
        // RFC 9114 requires ignoring unknown frames even before HEADERS.
        let mut wire = vec![0x21, 3, 1, 2, 3];
        let fields = h3::proto::headers::Header::request(
            http::Method::GET,
            "https://localhost/".parse().unwrap(),
            http::HeaderMap::new(),
            http::Extensions::new(),
        )
        .unwrap();
        let mut encoded = bytes::BytesMut::new();
        h3::qpack::encode_stateless(&mut encoded, fields).unwrap();
        use h3::proto::coding::BufMutExt;
        let mut frame = bytes::BytesMut::new();
        frame.write_var(1);
        frame.write_var(encoded.len() as u64);
        frame.extend_from_slice(&encoded);
        wire.extend_from_slice(&frame);
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        let resolver = pair.requests.recv().await.unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.method(), "GET");
        stream.send_response(Response::new(())).await.unwrap();
        stream.finish().await.unwrap();
        assert!(!recv.read_to_end(1024).await.unwrap().is_empty());
        pair.ordinary().await;
    })
    .await
    .expect("unknown frame test timed out");
}
// A backend adapter that stalls only selected bidi writes, keeping real Quinn control traffic
// running. This exercises cancellation at the public extension/QUIC boundary deterministically.
mod gated {
    use super::*;
    use bytes::Buf;
    use h3::quic::{self, StreamErrorIncoming, StreamId, WriteBuf};
    use std::{
        collections::BTreeMap,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };
    #[derive(Default)]
    pub struct Gate {
        writes: Mutex<BTreeMap<u64, (usize, Option<Waker>)>>,
        finishes: Mutex<BTreeMap<u64, Option<Waker>>>,
    }
    impl Gate {
        pub fn limit(&self, id: u64, bytes: usize) {
            let previous = self.writes.lock().unwrap().insert(id, (bytes, None));
            if let Some((_, Some(waker))) = previous {
                waker.wake();
            }
        }
        pub fn block_finish(&self, id: u64) {
            self.finishes.lock().unwrap().insert(id, None);
        }
        fn budget(&self, id: StreamId, cx: &Context<'_>) -> usize {
            let mut entries = self.writes.lock().unwrap();
            match entries.get_mut(&id.into_inner()) {
                Some((bytes, waker)) => {
                    if *bytes == 0 {
                        *waker = Some(cx.waker().clone());
                    }
                    *bytes
                }
                None => usize::MAX,
            }
        }
    }
    pub struct Stream<S>(S, Arc<Gate>);
    impl<S: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Stream<S> {
        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            if self.1.budget(self.0.send_id(), cx) == 0 {
                return Poll::Pending;
            }
            self.0.poll_ready(cx)
        }
        fn send_data<T: Into<WriteBuf<Bytes>>>(
            &mut self,
            data: T,
        ) -> Result<(), StreamErrorIncoming> {
            self.0.send_data(data)
        }
        fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            if let Some(waker) = self
                .1
                .finishes
                .lock()
                .unwrap()
                .get_mut(&self.0.send_id().into_inner())
            {
                *waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if self.1.budget(self.0.send_id(), cx) == 0 {
                return Poll::Pending;
            }
            self.0.poll_finish(cx)
        }
        fn reset(&mut self, code: u64) {
            self.0.reset(code)
        }
        fn send_id(&self) -> StreamId {
            self.0.send_id()
        }
    }
    impl<S: quic::SendStreamUnframed<Bytes>> quic::SendStreamUnframed<Bytes> for Stream<S> {
        fn poll_send<D: Buf>(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut D,
        ) -> Poll<Result<usize, StreamErrorIncoming>> {
            let budget = self.1.budget(self.0.send_id(), cx);
            if budget == 0 {
                return Poll::Pending;
            }
            let result = self.0.poll_send(cx, &mut buf.take(budget));
            if let Poll::Ready(Ok(written)) = result {
                if let Some((remaining, _)) = self
                    .1
                    .writes
                    .lock()
                    .unwrap()
                    .get_mut(&self.0.send_id().into_inner())
                {
                    *remaining -= written;
                }
            }
            result
        }
    }
    impl<S: quic::RecvStream> quic::RecvStream for Stream<S> {
        type Buf = S::Buf;
        fn poll_data(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.0.poll_data(cx)
        }
        fn stop_sending(&mut self, code: u64) {
            self.0.stop_sending(code)
        }
        fn recv_id(&self) -> StreamId {
            self.0.recv_id()
        }
    }
    impl<S: quic::BidiStream<Bytes>> quic::BidiStream<Bytes> for Stream<S> {
        type SendStream = Stream<S::SendStream>;
        type RecvStream = S::RecvStream;
        fn split(self) -> (Self::SendStream, Self::RecvStream) {
            let (s, r) = self.0.split();
            (Stream(s, self.1), r)
        }
    }
    pub struct Connection(pub h3_quinn::Connection, pub Arc<Gate>);
    #[derive(Clone)]
    pub struct Opener(h3_quinn::OpenStreams, Arc<Gate>);
    macro_rules! opens {
        ($t:ty) => {
            impl quic::OpenStreams<Bytes> for $t {
                type BidiStream = Stream<h3_quinn::BidiStream<Bytes>>;
                type SendStream = h3_quinn::SendStream<Bytes>;
                fn poll_open_bidi(
                    &mut self,
                    cx: &mut Context<'_>,
                ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
                    self.0
                        .poll_open_bidi(cx)
                        .map_ok(|s| Stream(s, self.1.clone()))
                }
                fn poll_open_send(
                    &mut self,
                    cx: &mut Context<'_>,
                ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
                    self.0.poll_open_send(cx)
                }
                fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
                    quic::OpenStreams::<Bytes>::close(&mut self.0, code, reason)
                }
            }
        };
    }
    opens!(Connection);
    opens!(Opener);
    impl quic::Connection<Bytes> for Connection {
        type RecvStream = h3_quinn::RecvStream;
        type OpenStreams = Opener;
        fn poll_accept_recv(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
            quic::Connection::<Bytes>::poll_accept_recv(&mut self.0, cx)
        }
        fn poll_accept_bidi(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, quic::ConnectionErrorIncoming>> {
            self.0
                .poll_accept_bidi(cx)
                .map_ok(|s| Stream(s, self.1.clone()))
        }
        fn opener(&self) -> Self::OpenStreams {
            Opener(quic::Connection::<Bytes>::opener(&self.0), self.1.clone())
        }
    }
}

struct GatedPair {
    _se: quinn::Endpoint,
    _ce: quinn::Endpoint,
    gate: Arc<gated::Gate>,
    incoming: h3::client::IncomingStreams<h3_quinn::BidiStream<Bytes>, Bytes>,
    requests: tokio::sync::mpsc::Receiver<h3::server::RequestResolver<gated::Connection, Bytes>>,
    acceptor: server::Acceptor<gated::Connection, Bytes>,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _sd: common::ClientDriver,
    _cd: common::ClientDriver,
}
impl GatedPair {
    async fn new() -> Self {
        let (se, ce, sq, cq) = connections().await;
        let gate = Arc::new(gated::Gate::default());
        let core = h3::server::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(1)
            .webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, Bytes>(gated::Connection(
                h3_quinn::Connection::new(sq),
                gate.clone(),
            ))
            .await
            .unwrap();
        let (mut driver, acceptor) = server::new(core, server::Limits::default());
        let (tx, requests) = tokio::sync::mpsc::channel(16);
        let sd = common::ClientDriver(tokio::spawn(async move {
            while let Ok(Some(resolver)) = driver.accept().await {
                if tx.send(resolver).await.is_err() {
                    break;
                }
            }
        }));
        let (mut driver, sender) = h3::client::builder()
            .enable_webtransport(true)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_webtransport_sessions(1)
            .webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(cq.clone()))
            .await
            .unwrap();
        let incoming = driver.server_initiated_streams(
            32.try_into().unwrap(),
            h3::error::Code::H3_REQUEST_CANCELLED,
            |_, _| true,
        );
        let cd = common::ClientDriver(tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        Self {
            _se: se,
            _ce: ce,
            gate,
            incoming,
            requests,
            acceptor,
            sender,
            _sd: sd,
            _cd: cd,
        }
    }
    async fn request(
        &mut self,
    ) -> (
        ClientStream,
        Request<()>,
        h3::server::RequestStream<gated::Stream<h3_quinn::BidiStream<Bytes>>, Bytes>,
    ) {
        let client = self.sender.send_request(connect_request()).await.unwrap();
        let (req, stream) = self
            .requests
            .recv()
            .await
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        (client, req, stream)
    }
}

#[tokio::test]
async fn inflight_admission_reserves_capacity_and_cancellation_releases_it() {
    timeout(Duration::from_secs(5), async {
        let mut pair = GatedPair::new().await;
        let (mut first, req, stream) = pair.request().await;
        let id = first.id().into_inner();
        pair.gate.limit(id, 0);
        let acceptor = pair.acceptor.clone();
        let mut accepting = Box::pin(acceptor.accept(req, stream));
        assert!(timeout(Duration::from_millis(20), &mut accepting)
            .await
            .is_err());
        let (mut second, req, stream) = pair.request().await;
        assert!(matches!(
            pair.acceptor.accept(req, stream).await,
            Err(server::ConnectError::SessionLimit)
        ));
        assert_eq!(second.recv_response().await.unwrap().status(), 429);
        drop(accepting);
        assert!(
            first.recv_response().await.is_err(),
            "cancelled response must be RESET, never FIN"
        );
        let (mut replacement, req, stream) = pair.request().await;
        let session = pair.acceptor.accept(req, stream).await.unwrap();
        assert_eq!(replacement.recv_response().await.unwrap().status(), 200);
        drop(session);
    })
    .await
    .expect("inflight admission test timed out");
}

#[tokio::test]
async fn cancelled_partial_stream_prefix_is_reset_and_next_open_recovers() {
    timeout(Duration::from_secs(5),async {
        let mut pair=GatedPair::new().await;
        let(mut client,req,stream)=pair.request().await;
        let session=pair.acceptor.accept(req,stream).await.unwrap();
        client.recv_response().await.unwrap();
        // Server bidi stream zero has ID 1. Stop after only the first prefix byte.
        pair.gate.limit(1,1);
        let mut opening=Box::pin(session.opener().open_bi());
        let result=timeout(Duration::from_millis(20),&mut opening).await;

        assert!(result.is_err(),"unexpected opening: {:?}",result.as_ref().map(|r|r.as_ref().err()));
        use h3::quic::{RecvStream as _,SendStreamUnframed as _};
        use futures::future::poll_fn;
        let mut peer=pair.incoming.recv().await.unwrap();
        assert_eq!(poll_fn(|cx|peer.poll_data(cx)).await.unwrap().unwrap(),vec![0x40]);
        drop(opening);
        assert!(matches!(poll_fn(|cx|peer.poll_data(cx)).await,Err(h3::quic::StreamErrorIncoming::StreamTerminated{error_code}) if error_code==h3_webtransport::WT_SESSION_GONE));
        let mut byte=&b"x"[..];
        assert!(matches!(poll_fn(|cx|peer.poll_send(cx,&mut byte)).await,Err(h3::quic::StreamErrorIncoming::StreamTerminated{error_code}) if error_code==h3_webtransport::WT_SESSION_GONE));
        let mut next=session.opener().open_bi().await.unwrap();
        next.write_all(b"ok").await.unwrap();next.shutdown().await.unwrap();
        let mut received=h3::stream::BufRecvStream::<_,Bytes>::new(pair.incoming.recv().await.unwrap());
        let mut bytes=Vec::new();received.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes,b"\x40\x41\x00ok");
    }).await.expect("partial prefix cancellation test timed out");
}

#[tokio::test]
async fn cancelled_close_write_resets_connect_and_releases_capacity() {
    timeout(Duration::from_secs(5),async {
        let mut pair=GatedPair::new().await;
        let(mut client,req,stream)=pair.request().await;
        let session=pair.acceptor.accept(req,stream).await.unwrap();
        client.recv_response().await.unwrap();
        pair.gate.limit(client.id().into_inner(),0);
        let mut closing=Box::pin(session.close(1,"blocked write"));
        assert!(timeout(Duration::from_millis(20),&mut closing).await.is_err());
        drop(closing);
        let result=client.recv_data().await;
        assert!(matches!(&result,Err(h3::error::StreamError::RemoteTerminate{code}) if *code==h3::error::Code::H3_REQUEST_CANCELLED),"unexpected close result: {:?}",result.err());
        assert!(session.opener().open_bi().await.is_err());
        let(mut replacement,req,stream)=pair.request().await;
        let _session=pair.acceptor.accept(req,stream).await.unwrap();
        assert_eq!(replacement.recv_response().await.unwrap().status(),200);
    }).await.expect("close write cancellation test timed out");
}

#[tokio::test]
async fn evicting_pending_classifiers_releases_streams_and_goaway_tracking() {
    timeout(Duration::from_secs(5), async {
        let (_se, _ce, sq, cq) = connections().await;
        let core = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(sq))
            .await
            .unwrap();
        let (mut driver, _) = server::new(core, server::Limits::default());
        let (mut client_driver, _sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(cq.clone()))
            .await
            .unwrap();
        let mut pending = Vec::new();
        for (prefix, code) in [
            (vec![0x40], h3::error::Code::H3_REQUEST_REJECTED.value()),
            (
                vec![0x21, 8, 1],
                h3::error::Code::H3_REQUEST_REJECTED.value(),
            ),
            (vec![0x40, 0x41, 0x40], h3_webtransport::WT_SESSION_GONE),
        ] {
            let (mut send, recv) = cq.open_bi().await.unwrap();
            send.write_all(&prefix).await.unwrap();
            pending.push((send, recv, code));
        }
        assert!(timeout(Duration::from_millis(20), driver.accept())
            .await
            .is_err());
        driver.shutdown(0).await.unwrap();
        assert_eq!(driver.evict_pending_streams(), 3);
        assert_eq!(driver.evict_pending_streams(), 0);
        for (send, mut recv, expected) in pending {
            assert!(matches!(recv.read_chunk(8, true).await,
                Err(quinn::ReadError::Reset(code)) if code.into_inner() == expected));
            // Quinn may drop its pending read before applying deferred STOP_SENDING.
            // The reset code is precise; the receive direction must still be stopped.
            assert!(send.stopped().await.unwrap().is_some());
        }
        client_driver.shutdown(0).await.unwrap();
        assert!(
            driver.accept().await.unwrap().is_none(),
            "evicted classifiers must release H3 request tracking"
        );
    })
    .await
    .expect("classifier eviction test timed out");
}

#[tokio::test]
async fn saturated_prefix_rejection_releases_h3_request_tracking_for_goaway() {
    timeout(Duration::from_secs(5),async {
        let(_se,_ce,sq,cq)=connections().await;
        let core=h3::server::builder().build::<_,Bytes>(h3_quinn::Connection::new(sq)).await.unwrap();
        let(mut driver,_)=server::new(core,server::Limits{pending_prefixes:1.try_into().unwrap(),..server::Limits::default()});
        let(mut client_driver,_sender)=h3::client::builder().build::<_,_,Bytes>(h3_quinn::Connection::new(cq.clone())).await.unwrap();
        let(mut first,mut first_recv)=cq.open_bi().await.unwrap();first.write_all(&[0x40]).await.unwrap();
        assert!(timeout(Duration::from_millis(20),driver.accept()).await.is_err());
        let(mut excess,mut excess_recv)=cq.open_bi().await.unwrap();excess.write_all(&[0x40]).await.unwrap();
        assert!(timeout(Duration::from_millis(20),driver.accept()).await.is_err());
        assert!(matches!(excess_recv.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==0x3994bd84));
        first.reset(0u32.into()).unwrap();first_recv.stop(0u32.into()).unwrap();
        client_driver.shutdown(0).await.unwrap();
        assert!(driver.accept().await.unwrap().is_none(),"rejected raw stream must not hold GOAWAY open forever");
    }).await.expect("GOAWAY cleanup test timed out");
}

#[tokio::test]
async fn detached_drivers_reject_unsupported_uni_streams_without_closing_h3() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default().await;
        let (_session, _client) = pair.session().await;
        for conn in [&pair.cq, &pair.sq] {
            let mut stream = conn.open_uni().await.unwrap();
            stream.write_all(&[0x40, 0x54, 0]).await.unwrap();
            assert_eq!(
                stream.stopped().await.unwrap().unwrap().into_inner(),
                h3_webtransport::WT_SESSION_GONE
            );
        }
        pair.ordinary().await;
    })
    .await
    .expect("unsupported uni test timed out");
}

#[tokio::test]
async fn detached_handshakes_select_each_supported_draft_group() {
    timeout(Duration::from_secs(5), async {
        for draft in WebTransportDraft::ALL {
            let mut pair = Pair::new(server::Limits::default(), 4, draft, draft, [true; 3]).await;
            let (session, client) = pair.session().await;
            assert_eq!(session.draft(), draft);
            assert_eq!(client.draft(), draft);
            client.close(0, "draft complete").await.unwrap();
            let (a, b) = tokio::join!(session.closed(), client.closed());
            assert!(a.is_ok());
            assert!(b.is_ok());
            pair.ordinary().await;
        }
    })
    .await
    .expect("detached draft test timed out");
}

#[tokio::test]
async fn retained_server_resolver_validates_full_session_ids_and_truncated_prefixes() {
    timeout(Duration::from_secs(5),async {
        let setup=common::setup().await;
        for prefix in [vec![0x40,0x41,0],vec![0x40,0x41,1],vec![0x40,0x41,0x40]] {
            let(mut send,mut recv)=setup.connection.open_bi().await.unwrap();send.write_all(&prefix).await.unwrap();send.finish().unwrap();
            let resolver=setup.session.accept_bi().await.unwrap().unwrap();
            assert!(resolver.resolve().await.is_err());
            assert!(matches!(recv.read_chunk(8,true).await,Err(quinn::ReadError::Reset(code)) if code.into_inner()==h3_webtransport::WT_SESSION_GONE));
        }
        let(mut send,mut recv)=setup.connection.open_bi().await.unwrap();send.write_all(&[0x40,0x41,4,b'x']).await.unwrap();send.finish().unwrap();
        let resolver=setup.session.accept_bi().await.unwrap().unwrap();
        let server::AcceptedBi::BidiStream(id,mut stream)=resolver.resolve().await.unwrap() else {panic!("expected WT stream")};
        assert_eq!(id,setup.session.session_id());let mut data=Vec::new();stream.read_to_end(&mut data).await.unwrap();assert_eq!(data,b"x");stream.shutdown().await.unwrap();assert!(recv.read_to_end(8).await.unwrap().is_empty());
    }).await.expect("retained resolver test timed out");
}

#[tokio::test]
async fn cancelled_close_fin_resets_instead_of_finishing_a_partial_close() {
    timeout(Duration::from_secs(5),async {
        let mut pair=GatedPair::new().await;
        let(mut client,req,stream)=pair.request().await;
        let session=pair.acceptor.accept(req,stream).await.unwrap();
        client.recv_response().await.unwrap();
        pair.gate.block_finish(client.id().into_inner());
        let mut closing=Box::pin(session.close(4,"FIN blocked"));
        assert!(timeout(Duration::from_millis(20),&mut closing).await.is_err());
        use bytes::Buf;
        let mut chunk=client.recv_data().await.unwrap().unwrap();
        assert_eq!(chunk.copy_to_bytes(chunk.remaining()),common::close_capsule(4,b"FIN blocked"));
        drop(closing);
        assert!(matches!(client.recv_data().await,Err(h3::error::StreamError::RemoteTerminate{code}) if code==h3::error::Code::H3_REQUEST_CANCELLED));
    }).await.expect("close FIN cancellation test timed out");
}

#[tokio::test]
async fn goaway_rejects_new_requests_while_session_streams_drain() {
    timeout(Duration::from_secs(5), async {
        let mut pair = Pair::default().await;
        let (session, client) = pair.session().await;
        let (mut sent, mut received) = (
            session.opener().open_bi().await.unwrap(),
            client.accept_bi().await.unwrap(),
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        pair.shutdown.send(tx).await.unwrap();
        rx.await.unwrap();
        match pair
            .sender
            .send_request(Request::get("https://localhost/late").body(()).unwrap())
            .await
        {
            Err(_) => {}
            Ok(mut request) => {
                let _ = request.finish().await;
                assert!(request.recv_response().await.is_err());
            }
        }
        sent.write_all(b"after GOAWAY").await.unwrap();
        sent.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        received.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"after GOAWAY");
        received.write_all(b"reply").await.unwrap();
        received.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        sent.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"reply");
        session.close(0, "drained").await.unwrap();
        let (a, b) = tokio::join!(session.closed(), client.closed());
        assert!(a.is_ok());
        assert!(b.is_ok());
    })
    .await
    .expect("session GOAWAY test timed out");
}
