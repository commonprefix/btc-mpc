use cw_storage_plus::Item;

use primitives::bls::DKGSession;

pub const DKG_SESSION: Item<Option<DKGSession>> = Item::new("session");
