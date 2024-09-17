use serde::{Deserialize, Serialize};

use crate::bls::{Confirmation, Message, Node};

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
    CreateSession { threshold: u16, nodes: Vec<Node> },
    PostMessage { message: Message },
    PostConfirmation { confirmation: Confirmation },
}
