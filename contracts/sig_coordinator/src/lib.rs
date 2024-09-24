mod bls;
mod execute;
mod msg;
mod state;

use std::collections::HashMap;

use crate::msg::QueryMsg;
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response,
    StdResult,
};
use execute::execute::{create_session, post_partial_sig};
use msg::ExecuteMsg;
use state::{SESSION_COUNTER, SIGNING_SESSIONS};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> StdResult<Response> {
    SIGNING_SESSIONS.save(deps.storage, &HashMap::new())?;
    SESSION_COUNTER.save(deps.storage, &0)?;
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
        ExecuteMsg::CreateSigningSession { payload, nodes } => create_session(deps, nodes, payload),
        ExecuteMsg::PostPartialSig {
            session_id,
            partial_sig,
            signature,
            pk,
        } => post_partial_sig(deps, session_id, partial_sig, signature, pk),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let sessions = SIGNING_SESSIONS.load(deps.storage)?;
    match msg {
        QueryMsg::SigningSession { session_id } => {
            to_json_binary(&sessions.get(&session_id).unwrap())
        }
        QueryMsg::PartialSigs { session_id } => {
            to_json_binary(&sessions.get(&session_id).unwrap().sigs)
        }
    }
}
