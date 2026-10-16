//! Checks which WebTransport draft a server negotiates with clients advertising different drafts.

use std::{net::Ipv6Addr, sync::Arc, time::Duration};

use bytes::Bytes;
use h3::ext::{Protocol, WebTransportDraft};
use h3_webtransport::server::WebTransportSession;
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use WebTransportDraft::*;

struct Outcome {
    /// The draft the server's session uses
    draft: WebTransportDraft,
    status: StatusCode,
    /// The value of the sec-webtransport-http3-draft response header
    draft_header: Option<String>,
}

async fn negotiate(
    server_drafts: &[WebTransportDraft],
    client_drafts: &[WebTransportDraft],
    protocol: Protocol,
) -> Outcome {
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
        let session = WebTransportSession::accept(request, stream, conn)
            .await
            .unwrap();
        let draft = session.draft();
        // Keep the session open until the client has read the response.
        tokio::time::sleep(Duration::from_millis(200)).await;
        draft
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

    let draft = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    Outcome {
        draft,
        status: response.status(),
        draft_header: response
            .headers()
            .get("sec-webtransport-http3-draft")
            .map(|v| v.to_str().unwrap().to_owned()),
    }
}

#[tokio::test]
async fn chrome_and_firefox_use_draft02() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let outcome = negotiate(&WebTransportDraft::ALL, &[Draft02], Protocol::WEB_TRANSPORT).await;
        assert_eq!(outcome.draft, Draft02);
        assert_eq!(outcome.status, StatusCode::OK);
        assert_eq!(outcome.draft_header.as_deref(), Some("draft02"));
    })
    .await
    .expect("WebTransport negotiation timed out");
}

#[tokio::test]
async fn safari_26_uses_draft13() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let outcome = negotiate(
            &WebTransportDraft::ALL,
            &[Draft07, Draft13],
            Protocol::WEB_TRANSPORT,
        )
        .await;
        assert_eq!(outcome.draft, Draft13);
        assert_eq!(outcome.status, StatusCode::OK);
        assert_eq!(outcome.draft_header, None);
    })
    .await
    .expect("WebTransport negotiation timed out");
}

#[tokio::test]
async fn draft15_client_with_webtransport_h3() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let outcome = negotiate(
            &WebTransportDraft::ALL,
            &[Draft15],
            Protocol::WEB_TRANSPORT_H3,
        )
        .await;
        assert_eq!(outcome.draft, Draft15);
        assert_eq!(outcome.status, StatusCode::OK);
        assert_eq!(outcome.draft_header, None);
    })
    .await
    .expect("WebTransport negotiation timed out");
}

#[tokio::test]
async fn uses_latest_draft_the_server_also_supports() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let outcome = negotiate(
            &[Draft02, Draft07],
            &WebTransportDraft::ALL,
            Protocol::WEB_TRANSPORT,
        )
        .await;
        assert_eq!(outcome.draft, Draft07);
        assert_eq!(outcome.status, StatusCode::OK);
    })
    .await
    .expect("WebTransport negotiation timed out");
}
