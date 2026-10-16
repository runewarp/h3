use std::convert::TryFrom;

use crate::{
    ext::WebTransportDraft,
    proto::{frame, varint::VarInt},
};

/// Configures the HTTP/3 connection
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
    /// The WebTransport drafts advertised when `enable_webtransport` is set, or the drafts the peer
    /// advertised.
    pub(crate) webtransport_drafts: WebTransportDrafts,
}

/// A set of [`WebTransportDraft`]s
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct WebTransportDrafts(u8);

impl WebTransportDrafts {
    pub(crate) const ALL: Self = Self(0b1111);

    fn bit(draft: WebTransportDraft) -> u8 {
        match draft {
            WebTransportDraft::Draft02 => 1 << 0,
            WebTransportDraft::Draft07 => 1 << 1,
            WebTransportDraft::Draft13 => 1 << 2,
            WebTransportDraft::Draft15 => 1 << 3,
        }
    }

    pub(crate) fn insert(&mut self, draft: WebTransportDraft) {
        self.0 |= Self::bit(draft);
    }

    pub(crate) fn contains(&self, draft: WebTransportDraft) -> bool {
        self.0 & Self::bit(draft) != 0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = WebTransportDraft> {
        WebTransportDraft::ALL
            .into_iter()
            .filter(move |draft| self.contains(*draft))
    }
}

impl FromIterator<WebTransportDraft> for WebTransportDrafts {
    fn from_iter<T: IntoIterator<Item = WebTransportDraft>>(iter: T) -> Self {
        let mut drafts = Self::default();
        for draft in iter {
            drafts.insert(draft);
        }
        drafts
    }
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();

        let enabled = |id| settings.get(id).is_some_and(|value| value != 0);
        let webtransport_drafts: WebTransportDrafts = [
            (
                frame::SettingId::ENABLE_WEBTRANSPORT,
                WebTransportDraft::Draft02,
            ),
            (
                frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07,
                WebTransportDraft::Draft07,
            ),
            (
                frame::SettingId::WT_MAX_SESSIONS,
                WebTransportDraft::Draft13,
            ),
            (frame::SettingId::WT_ENABLED, WebTransportDraft::Draft15),
        ]
        .into_iter()
        .filter(|(id, _)| enabled(*id))
        .map(|(_, draft)| draft)
        .collect();

        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: !webtransport_drafts.is_empty(),
            webtransport_drafts,
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .or_else(|| settings.get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07))
                .or_else(|| settings.get(frame::SettingId::WT_MAX_SESSIONS))
                .unwrap_or(defaults.max_webtransport_sessions),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    max_field_section_size,
                    enable_webtransport,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                    webtransport_drafts,
                },
        } = value;

        if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            match settings.insert(frame::SettingId::grease(), 0) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        settings.insert(
            frame::SettingId::MAX_HEADER_LIST_SIZE,
            max_field_section_size,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_CONNECT_PROTOCOL,
            enable_extended_connect as u64,
        )?;
        settings.insert(frame::SettingId::H3_DATAGRAM, enable_datagram as u64)?;

        if enable_webtransport {
            for draft in webtransport_drafts.iter() {
                match draft {
                    WebTransportDraft::Draft02 => {
                        settings.insert(frame::SettingId::ENABLE_WEBTRANSPORT, 1)?;
                        settings.insert(
                            frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
                            max_webtransport_sessions,
                        )?;
                    }
                    // A value of 0 would mean WebTransport is not supported.
                    WebTransportDraft::Draft07 => settings.insert(
                        frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07,
                        max_webtransport_sessions.max(1),
                    )?,
                    // Draft 14 enables flow control when both endpoints send a value greater
                    // than "1" here (or a nonzero SETTINGS_WT_INITIAL_MAX_* setting). WebTransport
                    // flow control is not implemented, so this is always 1.
                    WebTransportDraft::Draft13 => {
                        settings.insert(frame::SettingId::WT_MAX_SESSIONS, 1)?
                    }
                    // Draft 16: "servers supporting WebTransport over HTTP/3 send: A
                    // SETTINGS_WT_ENABLED setting with a value of "1""
                    WebTransportDraft::Draft15 => {
                        settings.insert(frame::SettingId::WT_ENABLED, 1)?
                    }
                }
            }
        }

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
            webtransport_drafts: WebTransportDrafts::ALL,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// The WebTransport drafts that are supported, oldest first
    pub fn webtransport_drafts(&self) -> impl Iterator<Item = WebTransportDraft> {
        self.webtransport_drafts.iter()
    }

    /// Picks the WebTransport draft to use with a peer: the latest one supported by both.
    ///
    /// `self` are the local settings, `peer` the settings received from the peer.
    pub fn negotiate_webtransport_draft(&self, peer: &Settings) -> Option<WebTransportDraft> {
        self.webtransport_drafts()
            .filter(|draft| peer.webtransport_drafts.contains(*draft))
            .last()
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            settings: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(settings: &[(frame::SettingId, u64)]) -> Settings {
        let mut frame = frame::Settings::default();
        for (id, value) in settings {
            frame.insert(*id, *value).unwrap();
        }
        (&frame).into()
    }

    fn local(drafts: &[WebTransportDraft]) -> Settings {
        Settings {
            enable_webtransport: true,
            webtransport_drafts: drafts.iter().copied().collect(),
            ..Default::default()
        }
    }

    #[test]
    fn advertised_drafts_round_trip() {
        let config = Config {
            settings: local(&WebTransportDraft::ALL),
            ..Default::default()
        };
        let frame = frame::Settings::try_from(config).unwrap();
        let settings = Settings::from(&frame);

        assert!(settings.enable_webtransport());
        assert_eq!(
            settings.webtransport_drafts().collect::<Vec<_>>(),
            WebTransportDraft::ALL
        );
        assert_eq!(frame.get(frame::SettingId::ENABLE_WEBTRANSPORT), Some(1));
        assert_eq!(
            frame.get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07),
            Some(1)
        );
        assert_eq!(frame.get(frame::SettingId::WT_MAX_SESSIONS), Some(1));
        assert_eq!(frame.get(frame::SettingId::WT_ENABLED), Some(1));
    }

    #[test]
    fn only_selected_drafts_are_advertised() {
        let config = Config {
            settings: local(&[WebTransportDraft::Draft07]),
            ..Default::default()
        };
        let frame = frame::Settings::try_from(config).unwrap();

        assert_eq!(frame.get(frame::SettingId::ENABLE_WEBTRANSPORT), None);
        assert_eq!(
            frame.get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07),
            Some(1)
        );
        assert_eq!(frame.get(frame::SettingId::WT_MAX_SESSIONS), None);
        assert_eq!(frame.get(frame::SettingId::WT_ENABLED), None);
    }

    #[test]
    fn webtransport_disabled_advertises_nothing() {
        let frame = frame::Settings::try_from(Config::default()).unwrap();
        let settings = Settings::from(&frame);

        assert!(!settings.enable_webtransport());
        assert_eq!(settings.webtransport_drafts().count(), 0);
    }

    #[test]
    fn negotiates_latest_common_draft() {
        use WebTransportDraft::*;

        // Chrome and Firefox
        let legacy = peer(&[(frame::SettingId::ENABLE_WEBTRANSPORT, 1)]);
        // Safari 26
        let hybrid = peer(&[
            (frame::SettingId::WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 1),
            (frame::SettingId::WT_MAX_SESSIONS, 1),
        ]);
        let latest = peer(&[(frame::SettingId::WT_ENABLED, 1)]);
        let none = peer(&[(frame::SettingId::ENABLE_WEBTRANSPORT, 0)]);

        let all = local(&WebTransportDraft::ALL);
        assert_eq!(all.negotiate_webtransport_draft(&legacy), Some(Draft02));
        assert_eq!(all.negotiate_webtransport_draft(&hybrid), Some(Draft13));
        assert_eq!(all.negotiate_webtransport_draft(&latest), Some(Draft15));
        assert_eq!(all.negotiate_webtransport_draft(&none), None);
        assert!(!none.enable_webtransport());

        let old = local(&[Draft02, Draft07]);
        assert_eq!(old.negotiate_webtransport_draft(&hybrid), Some(Draft07));
        assert_eq!(old.negotiate_webtransport_draft(&latest), None);
    }
}
