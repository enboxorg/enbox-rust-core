//! Interface and method name constants shared across message descriptors.
//!
//! These are the on-the-wire `interface`/`method` discriminators referenced by the
//! `#[descriptor]`/`#[interface]` macros and by the descriptor unions.

use crate::descriptors::messages::MessagesMethod;
use crate::descriptors::protocols::ProtocolsMethod;
use crate::descriptors::records::RecordsMethod;
use crate::descriptors::ConcreteDescriptor;

pub const RECORDS: &str = "Records";
pub const PROTOCOLS: &str = "Protocols";
pub const MESSAGES: &str = "Messages";

pub const READ: &str = "Read";
pub const QUERY: &str = "Query";
pub const WRITE: &str = "Write";
pub const DELETE: &str = "Delete";
pub const SUBSCRIBE: &str = "Subscribe";
pub const SYNC: &str = "Sync";
pub const CONFIGURE: &str = "Configure";
pub const COUNT: &str = "Count";

/// The three DWN interfaces. The typed counterpart to the `RECORDS`/`PROTOCOLS`/`MESSAGES` wire
/// strings, used as the interface discriminant in [`MessageKind`](super::MessageKind) and (later) the
/// permission layer. `as_str` round-trips to the same wire strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Interface {
    Records,
    Protocols,
    Messages,
}

impl Interface {
    /// The on-the-wire interface string for this variant.
    pub fn as_str(&self) -> &'static str {
        match self {
            Interface::Records => RECORDS,
            Interface::Protocols => PROTOCOLS,
            Interface::Messages => MESSAGES,
        }
    }

    /// Parse a wire interface string into the typed discriminant, if recognized.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        if s == RECORDS {
            Some(Interface::Records)
        } else if s == PROTOCOLS {
            Some(Interface::Protocols)
        } else if s == MESSAGES {
            Some(Interface::Messages)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageKind {
    Records(RecordsMethod),
    Protocols(ProtocolsMethod),
    Messages(MessagesMethod),
}

impl MessageKind {
    pub fn interface(&self) -> Interface {
        match self {
            MessageKind::Records(_) => Interface::Records,
            MessageKind::Protocols(_) => Interface::Protocols,
            MessageKind::Messages(_) => Interface::Messages,
        }
    }

    /// The method's on-the-wire string (e.g. `Query`). Mirrors [`interface`](Self::interface).
    pub fn method(&self) -> &'static str {
        match self {
            MessageKind::Records(method) => method.as_str(),
            MessageKind::Protocols(method) => method.as_str(),
            MessageKind::Messages(method) => method.as_str(),
        }
    }

    /// The concatenated `interface`+`method` handler key (e.g. `RecordsQuery`). This is the DWN
    /// spec's handler identifier and must stay in the concatenated form the conformance fixtures
    /// (`fixtures/`) compare against — not a separator-delimited form.
    ///
    /// Returns a `&'static str`: each descriptor's key is concatenated at compile time
    /// (`ConcreteDescriptor::KEY`), so this is a zero-allocation lookup, not a `format!`.
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageKind::Records(method) => method.key(),
            MessageKind::Protocols(method) => method.key(),
            MessageKind::Messages(method) => method.key(),
        }
    }

    pub fn from_parts(interface: &str, method: &str) -> Option<Self> {
        match Interface::from_str_opt(interface)? {
            Interface::Records => RecordsMethod::from_str_opt(method).map(MessageKind::Records),
            Interface::Protocols => {
                ProtocolsMethod::from_str_opt(method).map(MessageKind::Protocols)
            }
            Interface::Messages => MessagesMethod::from_str_opt(method).map(MessageKind::Messages),
        }
    }

    pub fn of<D: ConcreteDescriptor>() -> Self {
        Self::from_parts(D::INTERFACE, D::METHOD)
            .expect("Descriptor interface/method should be valid")
    }
}

/// Concatenate two strings into a fixed-size byte buffer at compile time. Used by the
/// `#[descriptor]` macro to build each descriptor's `ConcreteDescriptor::KEY` const; the caller
/// fixes `N` to `interface.len() + method.len()` via the binding's array type.
pub const fn concat_key<const N: usize>(interface: &str, method: &str) -> [u8; N] {
    let mut buf = [0u8; N];
    let interface = interface.as_bytes();
    let method = method.as_bytes();
    let mut i = 0;
    while i < interface.len() {
        buf[i] = interface[i];
        i += 1;
    }
    let mut j = 0;
    while j < method.len() {
        buf[interface.len() + j] = method[j];
        j += 1;
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dwn_interface_round_trips() {
        for iface in [
            Interface::Records,
            Interface::Protocols,
            Interface::Messages,
        ] {
            assert_eq!(Interface::from_str_opt(iface.as_str()), Some(iface));
        }
    }

    #[test]
    fn dwn_interface_rejects_unknown() {
        assert_eq!(Interface::from_str_opt("Bogus"), None);
        assert_eq!(Interface::from_str_opt(""), None);
    }

    #[test]
    fn generated_method_enums_round_trip() {
        use super::super::{
            messages::MessagesMethod, protocols::ProtocolsMethod, records::RecordsMethod,
        };

        // (variant, expected wire string) — covers the `no_handler` MessagesQuery too.
        assert_eq!(RecordsMethod::Read.as_str(), READ);
        assert_eq!(RecordsMethod::Write.as_str(), WRITE);
        assert_eq!(RecordsMethod::Count.as_str(), COUNT);
        assert_eq!(
            RecordsMethod::from_str_opt(QUERY),
            Some(RecordsMethod::Query)
        );
        assert_eq!(
            RecordsMethod::from_str_opt(DELETE),
            Some(RecordsMethod::Delete)
        );
        assert_eq!(
            RecordsMethod::from_str_opt(SUBSCRIBE),
            Some(RecordsMethod::Subscribe)
        );
        assert_eq!(RecordsMethod::from_str_opt("Bogus"), None);

        assert_eq!(ProtocolsMethod::Configure.as_str(), CONFIGURE);
        assert_eq!(
            ProtocolsMethod::from_str_opt(QUERY),
            Some(ProtocolsMethod::Query)
        );
        assert_eq!(ProtocolsMethod::from_str_opt(WRITE), None);

        assert_eq!(MessagesMethod::Read.as_str(), READ);
        assert_eq!(MessagesMethod::Sync.as_str(), SYNC);
        assert_eq!(
            MessagesMethod::from_str_opt(SUBSCRIBE),
            Some(MessagesMethod::Subscribe)
        );
        assert_eq!(
            MessagesMethod::from_str_opt(QUERY),
            Some(MessagesMethod::Query)
        );
        assert_eq!(MessagesMethod::from_str_opt(DELETE), None);
    }

    #[test]
    fn message_kind_from_parts_round_trips() {
        // One representative kind per interface, including the `no_handler` MessagesQuery.
        let cases = [
            (RECORDS, WRITE, MessageKind::Records(RecordsMethod::Write)),
            (PROTOCOLS, CONFIGURE, MessageKind::Protocols(ProtocolsMethod::Configure)),
            (MESSAGES, QUERY, MessageKind::Messages(MessagesMethod::Query)),
        ];

        for (interface, method, expected) in cases {
            let kind = MessageKind::from_parts(interface, method)
                .expect("known interface/method should parse");
            assert_eq!(kind, expected);
            assert_eq!(kind.interface().as_str(), interface);
            assert_eq!(kind.method(), method);
            // `as_str()` is the concatenated handler key the conformance fixtures compare against.
            assert_eq!(kind.as_str(), format!("{interface}{method}"));
        }
    }

    #[test]
    fn message_kind_from_parts_rejects_unknown() {
        // Unknown interface.
        assert_eq!(MessageKind::from_parts("Bogus", WRITE), None);
        // Known interface, but a method not valid for it (Configure is Protocols-only).
        assert_eq!(MessageKind::from_parts(RECORDS, CONFIGURE), None);
        // Known interface, unknown method.
        assert_eq!(MessageKind::from_parts(MESSAGES, "Bogus"), None);
    }
}
