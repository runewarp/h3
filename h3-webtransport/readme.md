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
    .max_field_section_size(16 * 1024)
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

The client reuses the adopted draft groups 02, 07, 13 and 15. Draft 15 selects `webtransport-h3`; earlier groups select `webtransport`. For draft 02, the client adds `sec-webtransport-http3-draft02: 1` automatically, preserves a single caller-supplied `1`, and rejects other values or duplicate offers before sending CONNECT. This follows [draft02 section 6](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html#section-6). Its response must contain exactly one `sec-webtransport-http3-draft: draft02`; missing, wrong or duplicate values fail. Later groups ignore that legacy response header, including duplicate or unknown values, because they do not use it for negotiation. Non-success responses and unoffered application subprotocols cannot create a session. [RFC 9110 section 9.3.6](https://httpwg.org/specs/rfc9110.html#CONNECT) requires clients to ignore Content-Length and Transfer-Encoding on successful CONNECT responses; neither field controls session bytes or capsule close. Only HTTPS CONNECT requests with authority and path are accepted; callers supply authorization and Origin when needed. Application subprotocol negotiation is unsupported.

Pinning draft 07 on both peers preserves the prototype's max-sessions codepoint and wire subset. The inherited negotiation of newer draft groups does not establish full current-draft conformance: WebTransport flow-control capsules, client unidirectional stream dispatch, client-opened data streams, and datagram routing are outside this client implementation. Draft 13 advertises a cap of one to avoid enabling optional flow control. Draft 15 advertises an enable flag with no SETTINGS session cap; `Limits.sessions` remains the resource bound. Draft 02/07 caps are independent and normalized to the encoded settings before negotiation. Suppressed local SETTINGS cannot establish a client session. The `new` arguments must come from the same h3 builder invocation; mismatched connection and sender handles panic.

The constructor replaces any prior server-stream dispatch registration and must run before the h3 driver is polled. It uses the existing third-party-backend extension APIs. A custom backend must preserve bounded transport receive windows and the normal h3 SETTINGS advertisement; manual suppression or mutation after attaching the extension is unsupported. CONNECT cancellation while awaiting its response resets both directions and releases the reservation. Cancellation inside h3's initial request-header send retains that API's existing behavior.

The detached Server API below separates session admission and stream opening from ordinary request intake. These crates add no application authentication, Tunnel, Visitor, handler capacity or withdrawal policy.

## Detached Server sessions

Use `server::new(connection, Limits)` before driving the ordinary H3 Server. It returns a `ServerConnection` and a cloneable `Acceptor` tied to that connection. `accept()` returns ordinary request resolvers while independently parsing and routing WT bidi prefixes. Resolve headers and run application policy in bounded application tasks with deadlines, then pass the request and stream to `Acceptor::accept`. That call validates the CONNECT before returning a live `Session`; it reserves session capacity before sending the success response. Cancellation resets CONNECT and releases the reservation.

```rust
use bytes::Bytes;
use h3::ext::WebTransportDraft;
use h3_webtransport::server::{self, Limits};

let connection = h3::server::builder()
    .max_field_section_size(16 * 1024)
    .enable_webtransport(true)
    .enable_datagram(true)
    .enable_extended_connect(true)
    .max_webtransport_sessions(1)
    .webtransport_drafts([WebTransportDraft::Draft07])
    .build::<_, Bytes>(h3_quinn::Connection::new(quic.clone()))
    .await?;
let (mut driver, acceptor) = server::new(connection, Limits::default());
while let Some(resolver) = driver.accept().await? {
    let acceptor = acceptor.clone();
    // Spawn only after reserving the application's request-handler budget.
    spawn_request_handler(async move {
        let (request, mut stream) = resolve_with_deadline(resolver).await?;
        if request.method() == http::Method::CONNECT {
            authorize(&request)?;
            let session = acceptor.accept(request, stream).await?;
            // Drive session.closed() concurrently with stream work, with a caller deadline.
            // This opener fixes the full CONNECT ID and session state intrinsically.
            let stream = session.opener().open_bi().await?;
            handle_session(session, stream).await?;
        } else {
            handle_ordinary(request, stream).await?;
        }
        Ok(())
    });
}
```

The example uses application-owned helper functions for admission, deadlines, authorization and handlers. A compilable Quinn example is in `examples/webtransport_server.rs`. It reserves one of 32 per-connection request permits before spawning, including for long-lived CONNECT handlers, and rejects excess requests with `H3_REQUEST_REJECTED`. It never waits for a permit in a spawned task or stalls the driver on handler capacity. A task set reaps completed handlers and aborts outstanding handlers when the driver ends. WT data routing continues independently of this request budget. Session opening does not lock or borrow the ordinary driver. Independent open futures each own a cloned backend opener, so concurrent Quinn credit waiters can wake, cancel and recover independently. Backends must implement `OpenStreams::clone()` with independent pending-open state. Cancellation after opening, including a partially written WT prefix, explicitly resets and stops bidi streams; uni prefix cancellation resets the send direction. Session termination wakes pending opens.

Admission requires bilateral WebTransport, datagrams, Extended CONNECT, a common advertised draft and nonzero negotiated capacity. Invalid requests and mismatches receive 400; over-cap requests receive 429. Neither rejection yields a live session or deliberately closes H3. The effective cap is the minimum of configured `Limits.sessions` and both peers' advertised cap for the selected draft. Reservations include responses still being written. Server close, peer termination when observed, cancellation and drop release capacity even while a terminated handle remains alive. Registration weak references are pruned on admission; exact full IDs never route to replacement sessions. Peer close/drain capsules are observed only while `closed()` or `draining()` is polled.

Server defaults are one session, up to 32 raw bidi accepts per poll, 32 incomplete classifiers, and 32 queued validated streams per session. All are nonzero and configurable; per-poll work is additionally capped at 32. A silent prefix occupies only its classifier, with its own transport wake registration. Saturation resets the newest stream with `0x3994bd84`, including an ordinary request arriving while all classifier slots are occupied. Ordinary headers are parsed outside the driver; the application must bound its own resolver tasks. Unknown frames before H3 headers are skipped incrementally. Malformed, truncated, unknown-session and stale-session WT prefixes reset and stop with `WT_SESSION_GONE`; EOF before identifying WT signal `0x41` uses `H3_REQUEST_INCOMPLETE`, including an empty request or incomplete first varint. Ordinary known H3 frame errors retain core H3 validation. Dropping or losing the driver terminates sessions, drains queues and aborts incomplete streams. Rejected raw streams release H3 request tracking, including under GOAWAY.

The detached Server `Session` provides `opener()`, `accept_bi()`, `close()`, `closed()`, `drain()`, `draining()`, `session_id()` and `draft()`. Returned streams support both independent FIN directions. CLOSE terminates streams immediately through shared state, with transport reset on their next poll or drop. `closed()` validates through peer FIN, including trailing DATA after a local-first close. Close/drain writes and FIN have cancellation reset guards; orderly close uses immediate FIN without CONNECT grease. Capsule intake processes at most 32 chunks per poll, each at most 1024 bytes, plus one transport chunk retained between polls. Unknown capsules are skipped incrementally and only CONNECT readers wake for incoming capsule bytes. Applications must keep QUIC receive windows finite and use a deadline when waiting for peer FIN.

A silent or incomplete classifier can wait indefinitely and hold H3 request tracking. Call `driver.evict_pending_streams()` after an application-owned prefix deadline or during shutdown to abort all currently pending classifiers and free their slots, buffers and wakers. Unclassified ordinary/unknown streams use `H3_REQUEST_REJECTED`; already identified WT streams use `WT_SESSION_GONE`. Returned resolvers, established sessions and validated queues remain application-owned. Continue polling `accept()` to drive completions. New arrivals can require another eviction, so also impose a whole-connection deadline. Cancelling `accept()` preserves pending classifiers.

`ServerConnection::shutdown()` forwards ordinary H3 GOAWAY. GOAWAY controls requests and does not itself seal session openers or implement application withdrawal. Existing WT data streams can drain beside it; applications own placement policy and session shutdown. Tunnel gates, authentication, Visitor metadata, handler capacity and withdrawal remain outside these crates.

The retained `WebTransportSession::accept` API still owns the whole H3 connection, including on failure, so dropping it closes that connection. It now rejects invalid CONNECTs before creating a session, validates exact IDs in its bidi resolver, uses independent open futures and carries the bounded close fixes. Use the detached API for rejection recovery, concurrent ordinary intake and generic multi-session admission.

## Supported subset and security limits

Pin Draft07 on both peers to match the prototype profile from runewarp/runewarp #251: max-sessions setting `0xc671706a`, Extended CONNECT token `webtransport`, bidi signal `0x41`, full CONNECT stream ID, raw bidi data and the close/drain subset. Draft02, Draft13 and Draft15 retain the adopted negotiation groups; this does not implement every requirement of drafts 02 through 16. Draft13 advertises cap one. Draft15 uses an enable flag and remains locally bounded. Full modern flow-control capsules, subprotocol negotiation, detached uni dispatch, client-opened stream APIs and session datagram routing are deferred. Both detached drivers stop completed unsupported WT uni streams with `WT_SESSION_GONE` rather than retaining a queue. The Server opener's low-level `open_uni()` is retained for compatibility; detached peers do not deliver those streams. Retain the QUIC handle for later datagram integration; this API does not validate or demultiplex datagrams.

Set a finite `max_field_section_size`, as in these examples. This limits decoded QPACK fields but does not bound encoded HEADERS/control-frame accumulation or fix every HeaderMap overflow configuration. The core parser still has known security gaps tracked by hyperium/h3 #366, #377 and #378. Their overlapping fixes are deliberately deferred, not claimed as solved by extension queue limits, transport windows, mTLS or the example's 16 KiB decoded limit. See [the complete patch inventory and dispositions](../PATCHES.md).
