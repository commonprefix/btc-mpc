pub mod execute {
    use blst::min_sig::{PublicKey, Signature};
    use cosmwasm_std::{DepsMut, Response, StdError, StdResult};
    use thiserror::Error;

    use crate::state::DKG_SESSION;

    use primitives::{
        bls::{Confirmation, DKGSession, Message, Node, Nodes, Phase},
        utils::{calculate_total_weight, filter_known_pk, verify_signature, HasSender},
    };

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
        #[error("Duplicate message")]
        DuplicateMessage,
        #[error("Duplicate confirmation")]
        DuplicateConfirmation,
        #[error("Unknown item type")]
        UnknownItemType,
        #[error("Invalid public key")]
        InvalidPublicKey,
    }

    impl From<ExecuteError> for StdError {
        fn from(error: ExecuteError) -> Self {
            StdError::generic_err(error.to_string())
        }
    }

    fn verify_and_check_duplicate<T: serde::Serialize + HasSender>(
        deps: &DepsMut,
        item: &T,
        signature: &[u8],
        pk: &[u8],
        item_type: &str,
    ) -> Result<DKGSession, ExecuteError> {
        // Check if session exists
        let session = DKG_SESSION.load(deps.storage)?;

        if session.is_none() {
            return Err(ExecuteError::SessionNotInitialized);
        }

        let session = session.unwrap();

        let pubkey = PublicKey::from_bytes(pk).map_err(|_| ExecuteError::InvalidPublicKey)?;
        filter_known_pk(&pubkey, &session.nodes.nodes)
            .map_err(|_e| ExecuteError::UnknownPublicKey)?;

        verify_signature(
            &pubkey,
            &Signature::from_bytes(signature)
                .map_err(|e| ExecuteError::InvalidSignature(format!("{:?}", e)))?,
            &serde_json::to_string(item)
                .map_err(|e| ExecuteError::Std(StdError::serialize_err("item", e)))?
                .as_bytes(),
        )
        .map_err(|e| ExecuteError::InvalidSignature(e.to_string()))?;

        match item_type {
            "message" => {
                // Check if message is a duplicate
                let is_duplicate = session
                    .messages
                    .iter()
                    .any(|m| m.sender == *item.get_sender());

                if session.phase < Phase::Phase2 && is_duplicate {
                    return Err(ExecuteError::DuplicateMessage);
                }
                Ok(session)
            }
            "confirmation" => {
                // Check if confirmation is a duplicate
                let is_duplicate = session
                    .confirmations
                    .iter()
                    .any(|c| c.sender == *item.get_sender());

                if session.phase < Phase::Phase3 && is_duplicate {
                    return Err(ExecuteError::DuplicateConfirmation);
                }
                Ok(session)
            }
            _ => Err(ExecuteError::UnknownItemType),
        }
    }

    fn update_phase(session: &mut DKGSession) -> StdResult<()> {
        let message_weight = calculate_total_weight(&session.messages, &session.nodes.nodes);
        let confirmation_weight =
            calculate_total_weight(&session.confirmations, &session.nodes.nodes);

        match session.phase {
            Phase::Phase2 if message_weight >= session.threshold.into() => {
                session.phase = Phase::Phase3;
            }
            Phase::Phase3 if confirmation_weight >= (2 * session.threshold - 1).into() => {
                session.phase = Phase::Phase4;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn create_session(deps: DepsMut, threshold: u16, nodes: Vec<Node>) -> StdResult<Response> {
        let session = DKGSession {
            threshold,
            nodes: Nodes::new(nodes).unwrap(),
            messages: vec![],
            confirmations: vec![],
            phase: Phase::Phase2,
        };
        DKG_SESSION.save(deps.storage, &Some(session.clone()))?;

        Ok(Response::new().add_attribute("action", "create_session"))
    }

    pub fn post_message(
        deps: DepsMut,
        message: Message,
        signature: Vec<u8>,
        pk: Vec<u8>,
    ) -> StdResult<Response> {
        let result = verify_and_check_duplicate(&deps, &message, &signature, &pk, "message");

        if let Err(err) = result {
            return Err(err.into());
        }

        let mut session = result.unwrap();

        // Add message to session
        session.messages.push(message);

        update_phase(&mut session)?;

        DKG_SESSION.save(deps.storage, &Some(session))?;

        Ok(Response::new().add_attribute("action", "post_message"))
    }

    pub fn post_confirmation(
        deps: DepsMut,
        confirmation: Confirmation,
        signature: Vec<u8>,
        pk: Vec<u8>,
    ) -> StdResult<Response> {
        let result =
            verify_and_check_duplicate(&deps, &confirmation, &signature, &pk, "confirmation");

        if let Err(err) = result {
            return Err(err.into());
        }

        let mut session = result.unwrap();

        // Add confirmation to session
        session.confirmations.push(confirmation);

        update_phase(&mut session)?;

        DKG_SESSION.save(deps.storage, &Some(session))?;

        Ok(Response::new().add_attribute("action", "post_confirmation"))
    }
}
