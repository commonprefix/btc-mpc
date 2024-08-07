use serde::{Deserialize, Serialize};

use crate::bls::Session;

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    Session {},
    Nodes {},
    Threshold {},
    Messages {},
    Confirmations {},
}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {
    CreateSession { session: Session },
}
