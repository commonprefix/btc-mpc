use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    Session {},
    Nodes {},
    Threshold {},
    Messages {},
    Confirmations {},
}
