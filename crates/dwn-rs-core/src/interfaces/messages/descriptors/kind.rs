//! Interface and method name constants shared across message descriptors.
//!
//! These are the on-the-wire `interface`/`method` discriminators referenced by the
//! `#[descriptor]`/`#[interface]` macros and by the descriptor unions.

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
}
