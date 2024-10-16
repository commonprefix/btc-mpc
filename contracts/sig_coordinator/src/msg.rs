use serde::{Deserialize, Serialize};

use primitives::bls::{Nodes, PartialSignature};

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    SigningSession { session_id: String },
    PartialSigs { session_id: String },
}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {
    CreateSigningSession {
        nodes: Nodes,
        payload: Vec<u8>,
    },
    PostPartialSig {
        session_id: String,
        partial_sigs: Vec<PartialSignature>,
        signature: Vec<u8>,
        pk: Vec<u8>,
    },
}
