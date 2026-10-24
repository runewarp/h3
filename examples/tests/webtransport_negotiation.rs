//! Checks which WebTransport draft a server negotiates with clients advertising different drafts.

mod common;

use h3::ext::{Protocol, WebTransportDraft};
use http::StatusCode;

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
    let setup = common::setup_with(server_drafts, client_drafts, protocol).await;
    Outcome {
        draft: setup.session.draft(),
        status: setup.response.status(),
        draft_header: setup
            .response
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
    .expect("WebTransport test timed out");
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
    .expect("WebTransport test timed out");
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
    .expect("WebTransport test timed out");
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
    .expect("WebTransport test timed out");
}
