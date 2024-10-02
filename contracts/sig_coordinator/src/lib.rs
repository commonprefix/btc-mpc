mod execute;
mod msg;
mod state;

use std::collections::HashMap;

use crate::msg::QueryMsg;
use blst::min_sig::PublicKey;
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response,
    StdResult,
};
use execute::execute::post_partial_sig;
use msg::ExecuteMsg;
use primitives::{bls::SigningSession, utils::verify_signature};
use state::{SESSION, SESSION_COUNTER};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> StdResult<Response> {
    SESSION.save(deps.storage, &HashMap::new())?;
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
        ExecuteMsg::CreateSigningSession { payload } => {
            let mut counter = SESSION_COUNTER.load(deps.storage)?;
            counter += 1;
            let session_id = counter.to_string();
            let session = SigningSession {
                session_id: session_id.clone(),
                sigs: vec![],
                payload,
            };

            let mut sessions = SESSION.load(deps.storage)?;
            sessions.insert(session_id.clone(), session);
            SESSION.save(deps.storage, &sessions)?;
            SESSION_COUNTER.save(deps.storage, &counter)?;

            Ok(Response::new()
                .add_attribute("action", "create_session")
                .add_attribute("session_id", session_id))
        }
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
    let sessions = SESSION.load(deps.storage)?;
    match msg {
        QueryMsg::SigningSession { session_id } => {
            to_json_binary(&sessions.get(&session_id).unwrap())
        }
        QueryMsg::PartialSigs { session_id } => {
            to_json_binary(&sessions.get(&session_id).unwrap().sigs)
        }
    }
}
