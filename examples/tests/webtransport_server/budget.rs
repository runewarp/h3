use super::*;
use quinn::crypto::rustls::QuicClientConfig;
use std::net::Ipv6Addr;

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
    transport.max_concurrent_bidi_streams(64_u32.into());
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
async fn request_budget_rejects_excess_recovers_and_keeps_session_streams_moving() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_se, _ce, sq, cq) = connections().await;
        let core = h3::server::builder()
            .enable_webtransport(true).enable_datagram(true).enable_extended_connect(true)
            .max_webtransport_sessions(1).webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, Bytes>(h3_quinn::Connection::new(sq.clone())).await.unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move { let _ = handle_connection(core).await; });
        let (core, mut sender) = h3::client::builder()
            .enable_webtransport(true).enable_datagram(true).enable_extended_connect(true)
            .max_webtransport_sessions(1).webtransport_drafts([WebTransportDraft::Draft07])
            .build::<_, _, Bytes>(h3_quinn::Connection::new(cq.clone())).await.unwrap();
        let (mut driver, mut client) = h3_webtransport::client::new(core, sender.clone(), Default::default());
        tasks.spawn(async move { driver.wait_idle().await; });
        let session = client.connect(http::Request::builder().method("CONNECT")
            .uri("https://localhost/session").body(()).unwrap()).await.unwrap();
        assert_eq!(session.session_id(), h3_webtransport::SessionId::try_from(0).unwrap());
        let mut held = Vec::new();
        // CONNECT occupies one permit. These HEADERS types return resolvers whose lengths stall.
        for _ in 1..MAX_REQUEST_HANDLERS {
            let (mut send, recv) = cq.open_bi().await.unwrap();
            send.write_all(&[1]).await.unwrap();
            held.push((send, recv));
        }
        let (mut excess, mut rejected) = cq.open_bi().await.unwrap();
        excess.write_all(&[1]).await.unwrap();
        assert!(matches!(rejected.read_chunk(8, true).await,
            Err(quinn::ReadError::Reset(code)) if code.into_inner() == Code::H3_REQUEST_REJECTED.value()));
        // Full ordinary admission must not block routing or session stream workers.
        let (mut send, mut recv) = cq.open_bi().await.unwrap();
        send.write_all(&[0x40, 0x41, 0, b'h', b'i']).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"hi");
        let (mut send, mut recv) = held.pop().unwrap();
        send.reset(0_u32.into()).unwrap();
        let _ = recv.read_chunk(8, true).await;
        let mut request = sender.send_request(http::Request::builder()
            .uri("https://localhost/").body(()).unwrap()).await.unwrap();
        request.finish().await.unwrap();
        assert_eq!(request.recv_response().await.unwrap().status(), 200);
        assert!(request.recv_data().await.unwrap().is_none());
        sq.close(0_u32.into(), b"test cleanup");
        // Connection loss completes the owner task, which aborts its tracked request handlers.
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
        for (_, mut recv) in held { assert!(recv.read_chunk(8, true).await.is_err()); }
    }).await.expect("example request budget test timed out");
}
