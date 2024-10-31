mod bls;
mod execute;
mod msg;
mod state;
mod utils;

use crate::msg::QueryMsg;
use bls::Session;
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response,
    StdResult,
};
use execute::execute::{create_session, post_confirmation, post_message};
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
        ExecuteMsg::CreateSession { threshold, nodes } => create_session(deps, threshold, nodes),
        ExecuteMsg::PostMessage {
            message,
            signature,
            pk,
        } => post_message(deps, message, signature, pk),
        ExecuteMsg::PostConfirmation {
            confirmation,
            signature,
            pk,
        } => post_confirmation(deps, confirmation, signature, pk),
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
