use serde::{Deserialize, Serialize};

use crate::bls::PartialSignature;

#[derive(Serialize, Deserialize)]
pub enum QueryMsg {
    Session { session_id: String },
    PartialSigs { session_id: String },
}

#[derive(Serialize, Deserialize)]
pub enum ExecuteMsg {
    CreateSession {},
    PostPartialSig {
        session_id: String,
        partial_sig: PartialSignature,
    },
}
