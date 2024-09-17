mod bls;
mod msg;
mod state;

use crate::msg::QueryMsg;
use bls::Session;
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response,
    StdError, StdResult,
};
use msg::ExecuteMsg;
use serde::{Deserialize, Serialize};
use state::SESSION;

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
        ExecuteMsg::CreateSession { session } => {
            SESSION.save(deps.storage, &Some(session.clone()))?;

            Ok(Response::new().add_attribute("action", "create_session"))
        }
        ExecuteMsg::PostMessage { message } => {
            let session = SESSION.load(deps.storage)?;

            if session.is_none() {
                return Err(StdError::generic_err("Session not initialized".to_string()));
            }

            let mut session = session.unwrap();
            session.messages.push(message);

            SESSION.save(deps.storage, &Some(session))?;

            Ok(Response::new().add_attribute("action", "post_message"))
        }
        ExecuteMsg::PostConfirmation { confirmation } => {
            let session = SESSION.load(deps.storage)?;

            if session.is_none() {
                return Err(StdError::generic_err("Session not initialized".to_string()));
            }

            let mut session = session.unwrap();
            session.confirmations.push(confirmation);

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
