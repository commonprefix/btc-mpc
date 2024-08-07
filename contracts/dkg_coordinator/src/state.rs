use cw_storage_plus::Item;
use serde::{Deserialize, Serialize};

use crate::bls::{Confirmation, Message, Nodes};

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub threshold: u16,
    pub nodes: Nodes,
    pub messages: Vec<Message>,
    pub confirmations: Vec<Confirmation>,
}

pub const SESSION: Item<Option<Session>> = Item::new("session");
