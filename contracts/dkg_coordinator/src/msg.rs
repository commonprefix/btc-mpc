use serde::{Deserialize, Serialize};

use primitives::bls::{Confirmation, Message, Node};

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    DKGSession {},
    Nodes {},
    Threshold {},
    Messages {},
    Confirmations {},
}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {
    CreateSession {
        threshold: u16,
        nodes: Vec<Node>,
    },
    PostMessage {
        message: Message,
        signature: Vec<u8>,
        pk: Vec<u8>,
    },
    PostConfirmation {
        confirmation: Confirmation,
        signature: Vec<u8>,
        pk: Vec<u8>,
    },
}
