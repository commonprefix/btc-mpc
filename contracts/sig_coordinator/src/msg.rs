use serde::{Deserialize, Serialize};

use primitives::bls::PartialSignature;

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    SigningSession { session_id: String },
    PartialSigs { session_id: String },
}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {
    CreateSigningSession {
        payload: Vec<u8>,
    },
    PostPartialSig {
        session_id: String,
        partial_sig: PartialSignature,
        signature: Vec<u8>,
        pk: Vec<u8>,
    },
}
