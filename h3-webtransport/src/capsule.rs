//! Capsules exchanged on the CONNECT stream of a WebTransport session.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9297#section-3.2> for the capsule format.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::proto::{coding::BufMutExt, varint::VarInt};

/// WT_CLOSE_SESSION, called CLOSE_WEBTRANSPORT_SESSION before draft 13
const CLOSE_SESSION: u64 = 0x2843;
/// WT_DRAIN_SESSION, called DRAIN_WEBTRANSPORT_SESSION before draft 13
const DRAIN_SESSION: u64 = 0x78ae;

/// The longest Application Error Message of a WT_CLOSE_SESSION capsule, in bytes
pub(crate) const MAX_CLOSE_MESSAGE_LEN: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Capsule {
    CloseSession { code: u32, reason: String },
    DrainSession,
}

/// The CONNECT stream carried an invalid capsule, so it must be reset with H3_MESSAGE_ERROR
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MalformedCapsule(pub(crate) &'static str);

pub(crate) fn encode_close_session(code: u32, reason: &str) -> Bytes {
    let reason = truncate(reason, MAX_CLOSE_MESSAGE_LEN);
    let len = 4 + reason.len();
    let mut buf = BytesMut::with_capacity(2 * VarInt::MAX_SIZE + len);
    buf.write_var(CLOSE_SESSION);
    buf.write_var(len as u64);
    buf.put_u32(code);
    buf.put_slice(reason.as_bytes());
    buf.freeze()
}

pub(crate) fn encode_drain_session() -> Bytes {
    let mut buf = BytesMut::with_capacity(2 * VarInt::MAX_SIZE);
    buf.write_var(DRAIN_SESSION);
    buf.write_var(0);
    buf.freeze()
}

/// Truncates `s` to at most `max` bytes at a character boundary
pub(crate) fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Splits the data of a CONNECT stream into capsules.
///
/// Capsules can span several HTTP/3 DATA frames and a DATA frame can hold several capsules, so
/// data is buffered until a whole capsule is available. Unknown capsules are skipped without
/// buffering them.
#[derive(Debug, Default)]
pub(crate) struct CapsuleReader {
    buf: BytesMut,
    /// Bytes left to discard of an unknown capsule
    skip: u64,
}

impl CapsuleReader {
    pub(crate) fn push(&mut self, mut data: impl Buf) {
        while data.has_remaining() {
            let chunk = data.chunk();
            if self.skip > 0 {
                let n = chunk.len().min(self.skip.try_into().unwrap_or(usize::MAX));
                self.skip -= n as u64;
                data.advance(n);
            } else {
                let n = chunk.len();
                self.buf.extend_from_slice(chunk);
                data.advance(n);
            }
        }
    }

    /// Returns the next complete capsule, if any.
    pub(crate) fn next(&mut self) -> Result<Option<Capsule>, MalformedCapsule> {
        loop {
            let Some((ty, len, header_len)) = self.header() else {
                return Ok(None);
            };
            match ty {
                CLOSE_SESSION => {
                    if !(4..=4 + MAX_CLOSE_MESSAGE_LEN as u64).contains(&len) {
                        return Err(MalformedCapsule("invalid WT_CLOSE_SESSION length"));
                    }
                    let total = header_len + len as usize;
                    if self.buf.len() < total {
                        return Ok(None);
                    }
                    let mut capsule = self.buf.split_to(total);
                    capsule.advance(header_len);
                    let code = capsule.get_u32();
                    let reason = String::from_utf8(capsule.to_vec())
                        .map_err(|_| MalformedCapsule("WT_CLOSE_SESSION message is not UTF-8"))?;
                    return Ok(Some(Capsule::CloseSession { code, reason }));
                }
                DRAIN_SESSION => {
                    self.buf.advance(header_len);
                    // The capsule has no payload; ignore one if present.
                    self.skip = len;
                    self.skip_unknown();
                    return Ok(Some(Capsule::DrainSession));
                }
                _ => {
                    //= https://www.rfc-editor.org/rfc/rfc9297#section-3.2
                    //# Endpoints that receive a Capsule with an unknown Capsule Type MUST
                    //# silently drop that Capsule and skip over it to parse the next
                    //# Capsule.
                    self.buf.advance(header_len);
                    self.skip = len;
                    self.skip_unknown();
                }
            }
        }
    }

    /// True if no partial capsule is buffered
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty() && self.skip == 0
    }

    /// Parses the type and length of the buffered capsule, if complete
    fn header(&self) -> Option<(u64, u64, usize)> {
        let mut cursor = &self.buf[..];
        let ty = VarInt::decode(&mut cursor).ok()?.into_inner();
        let len = VarInt::decode(&mut cursor).ok()?.into_inner();
        Some((ty, len, self.buf.len() - cursor.len()))
    }

    /// Discards buffered bytes of a capsule being skipped
    fn skip_unknown(&mut self) {
        let n = self
            .buf
            .len()
            .min(self.skip.try_into().unwrap_or(usize::MAX));
        self.buf.advance(n);
        self.skip -= n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(reader: &mut CapsuleReader) -> Vec<Capsule> {
        let mut capsules = Vec::new();
        while let Some(capsule) = reader.next().unwrap() {
            capsules.push(capsule);
        }
        capsules
    }

    #[test]
    fn close_session_round_trip() {
        let mut reader = CapsuleReader::default();
        reader.push(encode_close_session(0xdead_beef, "bye"));
        assert_eq!(
            read_all(&mut reader),
            [Capsule::CloseSession {
                code: 0xdead_beef,
                reason: "bye".into()
            }]
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn close_session_wire_format() {
        assert_eq!(
            &encode_close_session(7, "ok")[..],
            // varint 0x2843, length 6, code 7, "ok"
            [0x68, 0x43, 6, 0, 0, 0, 7, b'o', b'k']
        );
        assert_eq!(&encode_drain_session()[..], [0x80, 0, 0x78, 0xae, 0]);
    }

    #[test]
    fn long_reasons_are_truncated_at_a_char_boundary() {
        // 'é' is two bytes, so 1024 bytes would split the last one
        let reason = "a".to_owned() + &"é".repeat(600);
        let mut reader = CapsuleReader::default();
        reader.push(encode_close_session(1, &reason));
        let Some(Capsule::CloseSession { reason: got, .. }) = reader.next().unwrap() else {
            panic!("expected a close capsule");
        };
        assert_eq!(got.len(), 1023);
        assert!(reason.starts_with(&got));
    }

    #[test]
    fn capsules_split_across_and_within_frames() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_drain_session());
        // An unknown capsule, which must be skipped
        wire.write_var(0x1234);
        wire.write_var(3);
        wire.extend_from_slice(b"xyz");
        wire.extend_from_slice(&encode_close_session(42, "done"));

        // Feed one byte at a time
        let mut reader = CapsuleReader::default();
        let mut capsules = Vec::new();
        for byte in wire.iter() {
            reader.push(&[*byte][..]);
            capsules.extend(read_all(&mut reader));
        }
        assert_eq!(
            capsules,
            [
                Capsule::DrainSession,
                Capsule::CloseSession {
                    code: 42,
                    reason: "done".into()
                }
            ]
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn large_unknown_capsules_are_not_buffered() {
        let mut reader = CapsuleReader::default();
        let mut header = BytesMut::new();
        header.write_var(0x1234);
        header.write_var(1 << 30);
        reader.push(header);
        assert_eq!(reader.next(), Ok(None));
        reader.push(&[0u8; 4096][..]);
        assert_eq!(reader.next(), Ok(None));
        assert!(reader.buf.is_empty());
        assert_eq!(reader.skip, (1 << 30) - 4096);
    }

    #[test]
    fn invalid_close_session_capsules() {
        let mut too_short = BytesMut::new();
        too_short.write_var(CLOSE_SESSION);
        too_short.write_var(3);
        too_short.extend_from_slice(&[0, 0, 0]);

        let mut too_long = BytesMut::new();
        too_long.write_var(CLOSE_SESSION);
        too_long.write_var(4 + 1025);

        let mut not_utf8 = BytesMut::new();
        not_utf8.write_var(CLOSE_SESSION);
        not_utf8.write_var(5);
        not_utf8.extend_from_slice(&[0, 0, 0, 0, 0xff]);

        for wire in [too_short, too_long, not_utf8] {
            let mut reader = CapsuleReader::default();
            reader.push(wire);
            assert!(reader.next().is_err());
        }
    }
}
