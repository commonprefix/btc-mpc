use cw_storage_plus::Item;

use primitives::bls::Session;

pub const SESSION: Item<Option<Session>> = Item::new("session");
