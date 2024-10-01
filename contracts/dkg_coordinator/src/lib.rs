mod bls;
mod msg;
mod state;
mod utils;

use crate::msg::QueryMsg;
use bls::{Nodes, Phase, Session};
use blst::min_sig::{PublicKey, Signature};
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response,
    StdError, StdResult,
};
use msg::ExecuteMsg;
use serde::{Deserialize, Serialize};
use serde_json;
use state::SESSION;
use utils::{filter_known_pk, required_confirmations, required_messages, verify_signature};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> StdResult<Response> {
    SESSION.save(deps.storage, &None)?;
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::CreateSession { threshold, nodes } => {
            let session = Session {
                threshold,
                nodes: Nodes::new(nodes).unwrap(),
                messages: vec![],
                confirmations: vec![],
                phase: Phase::Phase2,
            };
            SESSION.save(deps.storage, &Some(session.clone()))?;

            Ok(Response::new().add_attribute("action", "create_session"))
        }
        ExecuteMsg::PostMessage {
            message,
            signature,
            pk,
        } => {
            // Check if session exists
            let session = SESSION.load(deps.storage)?;

            if session.is_none() {
                return Err(StdError::generic_err("Session not initialized".to_string()));
            }

            let mut session = session.unwrap();

            // Check if public key is known
            let pubkey = PublicKey::from_bytes(pk.as_slice()).unwrap();
            filter_known_pk(&pubkey, &session.nodes.nodes)
                .map_err(|e| StdError::generic_err(e.to_string()))?;

            // Verify signature on message
            verify_signature(
                &pubkey,
                &Signature::from_bytes(signature.as_slice()).unwrap(),
                &serde_json::to_string(&message).unwrap().as_bytes(),
            )
            .map_err(|e| StdError::generic_err(e.to_string()))?;

            // Check if message is a duplicate
            let is_duplicate = session.messages.iter().any(|m| m.sender == message.sender);
            if session.phase < Phase::Phase2 && is_duplicate {
                return Ok(Response::new());
            }

            // Add message to session
            session.messages.push(message);
            if session.messages.len() >= required_messages(session.nodes.nodes.len()) {
                if session.phase < Phase::Phase3 {
                    session.phase = Phase::Phase3;
                }
            }

            SESSION.save(deps.storage, &Some(session))?;

            Ok(Response::new().add_attribute("action", "post_message"))
        }
        ExecuteMsg::PostConfirmation {
            confirmation,
            signature,
            pk,
        } => {
            let session = SESSION.load(deps.storage)?;

            if session.is_none() {
                return Err(StdError::generic_err("Session not initialized".to_string()));
            }

            let mut session = session.unwrap();

            // Check if public key is known
            let pubkey = PublicKey::from_bytes(pk.as_slice()).unwrap();
            filter_known_pk(&pubkey, &session.nodes.nodes)
                .map_err(|e| StdError::generic_err(e.to_string()))?;

            // Verify signature on message
            verify_signature(
                &pubkey,
                &Signature::from_bytes(signature.as_slice()).unwrap(),
                &serde_json::to_string(&confirmation).unwrap().as_bytes(),
            )
            .map_err(|e| StdError::generic_err(e.to_string()))?;

            // Check if message is a duplicate
            let is_duplicate = session
                .confirmations
                .iter()
                .any(|c| c.sender == confirmation.sender);
            if session.phase < Phase::Phase3 && is_duplicate {
                return Ok(Response::new());
            }

            // Add confirmation to session
            session.confirmations.push(confirmation);
            if session.confirmations.len() >= required_confirmations(session.nodes.nodes.len()) {
                session.phase = Phase::Phase4;
            }

            SESSION.save(deps.storage, &Some(session))?;

            Ok(Response::new().add_attribute("action", "post_confirmation"))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct QueryResp {
    message: String,
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let session_option = SESSION.load(deps.storage)?;
    if let Some(session) = session_option {
        match msg {
            QueryMsg::Session {} => to_json_binary(&session),
            QueryMsg::Nodes {} => to_json_binary(&session.nodes),
            QueryMsg::Threshold {} => to_json_binary(&session.threshold),
            QueryMsg::Messages {} => to_json_binary(&session.messages),
            QueryMsg::Confirmations {} => to_json_binary(&session.confirmations),
        }
    } else {
        to_json_binary(&(None as Option<Session>))
    }
}
