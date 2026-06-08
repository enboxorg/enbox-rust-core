use std::cmp::Ordering;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use rusqlite::{params, Connection, OptionalExtension};

use dwn_rs_core::errors::{DataStoreError, MessageStoreError, StoreError};
use dwn_rs_core::filters::compare_values;
use dwn_rs_core::stores::{KeyValues, MessageStore};
use dwn_rs_core::{Cursor, Descriptor, Message, MessageSort, Pagination, SortDirection, Value};

pub mod conn;
pub mod data_store;
pub mod message_store;
mod query;
pub mod store;

use self::store::sqlite_store_error;

pub use self::conn::SqliteConnection;
pub use self::store::SqliteStore;
