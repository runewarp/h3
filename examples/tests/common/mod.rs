//! Sets up a WebTransport session between an h3-webtransport server and an h3 client.

#![allow(dead_code)]

use std::{net::Ipv6Addr, sync::Arc};

use bytes::{BufMut, Bytes, BytesMut};
use h3::ext::{Protocol, WebTransportDraft};
use h3_webtransport::server::WebTransportSession;
use http::{Method, Request, Response};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub type Session = WebTransportSession<h3_quinn::Connection, Bytes>;
pub type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub struct Setup {
    pub session: Arc<Session>,
    /// The client's side of the CONNECT stream
    pub stream: ClientStream,
    pub response: Response<()>,
    // Keep the client alive
    _client: quinn::Endpoint,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

pub async fn setup() -> Setup {
    setup_with(
        &WebTransportDraft::ALL,
        &WebTransportDraft::ALL,
        Protocol::WEB_TRANSPORT,
    )
    .await
}

pub async fn setup_with(
    server_drafts: &[WebTransportDraft],
    client_drafts: &[WebTransportDraft],
    protocol: Protocol,
) -> Setup {
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

    let server_drafts = server_drafts.to_vec();
    let server = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut conn = h3::server::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1)
            .webtransport_drafts(server_drafts)
            .build::<_, Bytes>(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let (request, stream) = conn
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        WebTransportSession::accept(request, stream, conn)
            .await
            .unwrap()
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).unwrap(),
    )));
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();

    let (mut driver, mut send_request) = h3::client::builder()
        .enable_webtransport(true)
        .enable_datagram(true)
        .webtransport_drafts(client_drafts.iter().copied())
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/", addr.port()))
        .body(())
        .unwrap();
    request.extensions_mut().insert(protocol);
    let mut stream = send_request.send_request(request).await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let session = server.await.unwrap();

    Setup {
        session: Arc::new(session),
        stream,
        response,
        _client: client,
        _send_request: send_request,
    }
}

pub fn write_var(buf: &mut BytesMut, x: u64) {
    match x {
        0..=0x3f => buf.put_u8(x as u8),
        0x40..=0x3fff => buf.put_u16(0x4000 | x as u16),
        0x4000..=0x3fff_ffff => buf.put_u32(0x8000_0000 | x as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | x),
    }
}

pub fn capsule(ty: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    write_var(&mut buf, ty);
    write_var(&mut buf, payload.len() as u64);
    buf.put_slice(payload);
    buf.freeze()
}

pub fn close_capsule(code: u32, reason: &[u8]) -> Bytes {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason);
    capsule(0x2843, &payload)
}

pub fn drain_capsule() -> Bytes {
    capsule(0x78ae, &[])
}

/// Reads the CONNECT stream until the server finishes it
pub async fn read_to_end(stream: &mut ClientStream) -> Bytes {
    let mut out = BytesMut::new();
    while let Some(mut data) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        while data.has_remaining() {
            let chunk = data.chunk();
            out.put_slice(chunk);
            let n = chunk.len();
            data.advance(n);
        }
    }
    out.freeze()
}
