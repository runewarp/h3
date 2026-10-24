//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol, as used by drafts 00 to 14 of draft-ietf-webtrans-http3
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// WebTransport protocol, as used by draft 15 of draft-ietf-webtrans-http3 onwards
    pub const WEB_TRANSPORT_H3: Protocol = Protocol(ProtocolInner::WebTransportH3);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9484 protocol
    pub const CONNECT_IP: Protocol = Protocol(ProtocolInner::ConnectIp);
    /// RFC 9220 (WebSocket) protocol
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Returns true for either of the WebTransport upgrade tokens
    #[inline]
    pub fn is_webtransport(&self) -> bool {
        matches!(
            self.0,
            ProtocolInner::WebTransport | ProtocolInner::WebTransportH3
        )
    }

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::WebTransportH3 => "webtransport-h3",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::ConnectIp => "connect-ip",
            ProtocolInner::WebSocket => "websocket",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    WebTransportH3,
    ConnectUdp,
    ConnectIp,
    WebSocket,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "webtransport-h3" => Ok(Self(ProtocolInner::WebTransportH3)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "connect-ip" => Ok(Self(ProtocolInner::ConnectIp)),
            "websocket" => Ok(Self(ProtocolInner::WebSocket)),
            _ => Err(InvalidProtocol),
        }
    }
}

/// A wire format of WebTransport over HTTP/3.
///
/// Each variant covers the consecutive versions of
/// [draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
/// that share the SETTINGS codepoint used to negotiate them, and is named after the first of
/// those versions. When both endpoints support more than one, the latest is used.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum WebTransportDraft {
    /// Drafts 02 to 06, negotiated with `SETTINGS_ENABLE_WEBTRANSPORT` (0x2b603742).
    ///
    /// This is what Chrome and Firefox use.
    Draft02,
    /// Drafts 07 to 11, negotiated with `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` (0xc671706a).
    ///
    /// Draft 12 reuses this codepoint but makes flow control mandatory, which is not supported.
    Draft07,
    /// Drafts 13 and 14, negotiated with `SETTINGS_WT_MAX_SESSIONS` (0x14e9cd29).
    Draft13,
    /// Drafts 15 and 16, negotiated with `SETTINGS_WT_ENABLED` (0x2c7cf000).
    Draft15,
}

impl WebTransportDraft {
    /// Every supported draft, oldest first
    pub const ALL: [WebTransportDraft; 4] = [
        WebTransportDraft::Draft02,
        WebTransportDraft::Draft07,
        WebTransportDraft::Draft13,
        WebTransportDraft::Draft15,
    ];
}
