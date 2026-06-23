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
