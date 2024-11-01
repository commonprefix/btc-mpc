use std::collections::HashMap;

use cw_storage_plus::Item;

use primitives::dkg::SigningSession;

pub const SIGNING_SESSIONS: Item<HashMap<String, SigningSession>> = Item::new("signing_sessions");

pub const SESSION_COUNTER: Item<u64> = Item::new("session_counter");
