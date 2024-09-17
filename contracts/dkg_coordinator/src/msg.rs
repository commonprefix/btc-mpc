use serde::{Deserialize, Serialize};

use crate::bls::{Confirmation, Message, Session};

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
    PostMessage { message: Message },
    PostConfirmation { confirmation: Confirmation },
}
