use std::collections::HashMap;

use cw_storage_plus::Item;

use crate::bls::Session;

pub const SESSION: Item<HashMap<String, Session>> = Item::new("sessions");

pub const SESSION_COUNTER: Item<u64> = Item::new("session_counter");
