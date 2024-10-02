pub mod execute {
    use blst::min_sig::{PublicKey, Signature};
    use cosmwasm_std::{DepsMut, Response, StdError, StdResult};
    use primitives::{
        bls::{PartialSignature, SigningSession},
        utils::verify_signature,
    };
    use thiserror::Error;

    use crate::state::{SESSION_COUNTER, SIGNING_SESSIONS};

    #[derive(Error, Debug)]
    pub enum ExecuteError {
        #[error("{0}")]
        Std(#[from] StdError),
        #[error("Session not initialized")]
        SessionNotInitialized,
        #[error("Unknown public key")]
        UnknownPublicKey,
        #[error("Invalid signature: {0}")]
        InvalidSignature(String),
        #[error("Invalid public key")]
        InvalidPublicKey,
    }

    impl From<ExecuteError> for StdError {
        fn from(error: ExecuteError) -> Self {
            StdError::generic_err(error.to_string())
        }
    }

    pub fn create_session(deps: DepsMut, payload: Vec<u8>) -> StdResult<Response> {
        let mut counter = SESSION_COUNTER.load(deps.storage)?;
        counter += 1;
        let session_id = counter.to_string();
        let session = SigningSession {
            session_id: session_id.clone(),
            sigs: vec![],
            payload,
        };

        let mut sessions = SIGNING_SESSIONS.load(deps.storage)?;
        sessions.insert(session_id.clone(), session);
        SIGNING_SESSIONS.save(deps.storage, &sessions)?;
        SESSION_COUNTER.save(deps.storage, &counter)?;

        Ok(Response::new()
            .add_attribute("action", "create_session")
            .add_attribute("session_id", session_id))
    }

    pub fn post_partial_sig(
        deps: DepsMut,
        session_id: String,
        partial_sig: PartialSignature,
        signature: Vec<u8>,
        pk: Vec<u8>,
    ) -> StdResult<Response> {
        // Check if session exists
        let mut sessions = SIGNING_SESSIONS.load(deps.storage)?;

        let session = sessions
            .get_mut(&session_id)
            .ok_or(ExecuteError::SessionNotInitialized)?;
        let pubkey = PublicKey::from_bytes(&pk).map_err(|_| ExecuteError::InvalidPublicKey)?;
        verify_signature(
            &pubkey,
            &Signature::from_bytes(&signature)
                .map_err(|e| ExecuteError::InvalidSignature(format!("{:?}", e)))?,
            &serde_json::to_vec(&partial_sig).unwrap().as_slice(),
        )
        .map_err(|e| ExecuteError::InvalidSignature(e.to_string()))?;

        session.sigs.push(partial_sig);
        SIGNING_SESSIONS.save(deps.storage, &sessions)?;

        Ok(Response::new().add_attribute("action", "post_partial_sig"))
    }
}
