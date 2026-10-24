# H3 Webtransport

Implementation of Webtransport protocol as extension of the h3 crate

# Status
This crate is still in experimental. The API is subject to change. It may contain bugs and is not yet complete. Use with caution.

## Client sessions

The client driver dispatches server-opened bidirectional streams while ordinary HTTP/3 requests continue on the connection. Configure both peers with WebTransport, H3 datagrams, extended CONNECT and compatible drafts. Retain the QUIC handle separately if the application needs connection close, transport credit configuration or future datagram integration.

```rust
use bytes::Bytes;
use h3::ext::WebTransportDraft;
use h3_webtransport::client::{self, Limits};
use http::Request;

let (connection, sender) = h3::client::builder()
    .enable_webtransport(true)
    .enable_datagram(true)
    .enable_extended_connect(true)
    .max_webtransport_sessions(1)
    .webtransport_drafts([WebTransportDraft::Draft07])
    .build::<_, _, Bytes>(h3_quinn::Connection::new(quic.clone()))
    .await?;
let (mut driver, mut client) = client::new(connection, sender, Limits::default());
let mut ordinary = client.send_request();
let driver_task = tokio::spawn(async move { driver.wait_idle().await });

// Ordinary GET/PUT requests use `ordinary`; finish their request bodies normally.
let session = client.connect(Request::builder()
    .method("CONNECT")
    .uri("https://example.com/session")
    .body(())?).await?;

// Poll session.closed() concurrently with application work to receive peer closes and drains.
// No task is spawned by h3-webtransport. The application owns all tasks and deadlines.
let session = std::sync::Arc::new(session);
let close_session = session.clone();
let close_task = tokio::spawn(async move { close_session.closed().await });
while let Some(stream) = session.accept_bi().await {
    // Each validated stream implements Tokio AsyncRead/AsyncWrite and quic::BidiStream.
    // Application handlers own stream admission, cancellation, and concurrency limits.
    handle(stream).await;
}
```

Call `close(code, reason)` then await `closed()` with a deadline before closing QUIC. Close sends one capsule followed by FIN without grease. A close capsule terminates session streams immediately; `closed()` also waits for peer FIN and rejects trailing data. Bare CONNECT FIN is a zero-code close. Cancellation during a close write resets the send direction. Dropping a live session resets CONNECT and queued streams; dropping the extension driver also resets incomplete prefixes. Ordinary request sender clones remain independent, and the driver retains one sender to prevent accidental connection closure when the application drops its last handle.

`Limits` bounds concurrent sessions, raw incoming streams, incomplete prefixes and queued streams per session. Session establishment also enforces the selected SETTINGS cap. Defaults allow one session as a configurable resource bound. The registry supports multiple sessions and matches the full CONNECT stream ID, including CONNECT after GET on stream 4. Known pending CONNECTs can buffer early streams until the response arrives. Unknown, stale, truncated or invalid prefixes reset both directions with `WT_SESSION_GONE`; excess queued streams use `0x3994bd84`. Prefix classification uses independent futures, an eight-byte varint scratch buffer and 32-item poll budgets. Receive cancellation preserves queued and partially parsed streams. Delivered stream termination follows the shared session guards, which reset on the next poll or drop. Applications must explicitly abort a live delivered stream when abandoning it; the ordinary stream wrapper does not change the QUIC backend's live-stream drop semantics.

## Wire subset and compatibility

The client reuses the adopted draft groups 02, 07, 13 and 15. Draft 15 selects `webtransport-h3`; earlier groups select `webtransport`. Draft 02 requires exactly one `sec-webtransport-http3-draft: draft02` response header. Later groups reject that legacy response header. Non-success responses, duplicate draft headers, forbidden CONNECT response framing headers and unoffered application subprotocols cannot create a session. Only HTTPS CONNECT requests with authority and path are accepted; callers supply authorization and Origin when needed. Application subprotocol negotiation is unsupported.

Pinning draft 07 on both peers preserves the prototype's max-sessions codepoint and wire subset. The inherited negotiation of newer draft groups does not establish full current-draft conformance: WebTransport flow-control capsules, client unidirectional stream dispatch, client-opened data streams, and datagram routing are outside this client implementation. Draft 13 advertises a cap of one to avoid enabling optional flow control. Draft 15 advertises an enable flag with no SETTINGS session cap; `Limits.sessions` remains the resource bound. Draft 02/07 caps are independent and normalized to the encoded settings before negotiation. Suppressed local SETTINGS cannot establish a client session. The `new` arguments must come from the same h3 builder invocation; mismatched connection and sender handles panic.

The constructor replaces any prior server-stream dispatch registration and must run before the h3 driver is polled. It uses the existing third-party-backend extension APIs. A custom backend must preserve bounded transport receive windows and the normal h3 SETTINGS advertisement; manual suppression or mutation after attaching the extension is unsupported. CONNECT cancellation while awaiting its response resets both directions and releases the reservation. Cancellation inside h3's initial request-header send retains that API's existing behavior.

The Server session still owns its connection in this layer. A subsequent layer must detach its opener from ordinary request intake, enforce Server CONNECT and session admission, validate inbound full session IDs, and address concurrent credit-blocked Quinn opener wakers. This client layer adds no application authentication, Tunnel, Visitor, capacity, or withdrawal policy.
