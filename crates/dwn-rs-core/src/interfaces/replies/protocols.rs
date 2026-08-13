use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{Descriptor, Message, Reply};

pub type Configure = ();

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct Query {
    pub entries: Option<Vec<Message<Descriptor>>>,
}

impl From<Query> for Reply {
    fn from(query: Query) -> Self {
        Reply::ProtocolsQuery(Box::new(query))
    }
}
