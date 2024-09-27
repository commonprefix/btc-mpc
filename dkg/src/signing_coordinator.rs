use cosm_tome::{
    chain::request::TxOptions,
    modules::{auth::model::Address, cosmwasm::model::ExecRequest},
    signing_key::key::SigningKey,
};
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto_tbls::types::IndexedValue;
use serde::Deserialize;
use serde_json::json;

use crate::{endpoints::CosmosEndpoint, error::SigningError};

#[derive(Deserialize)]
pub struct SigningSession<PartialSignature> {
    pub session_id: String,
    pub payload: String,
    pub sigs: Vec<PartialSignature>,
}

#[allow(async_fn_in_trait)]
pub trait SigningCoordinatorInterface<PartialSignature> {
    /// Create a new signing session.
    async fn create_session(
        &self,
        payload: String,
    ) -> Result<SigningSession<PartialSignature>, SigningError>;

    /// Fetch signing session by id
    async fn fetch_session(
        &self,
        id: String,
    ) -> Result<SigningSession<PartialSignature>, SigningError>;

    /// Post partial signatures for request with given id
    async fn post_partial_signatures(
        &self,
        session_id: String,
        partial_signatures: Vec<PartialSignature>,
    ) -> Result<Vec<PartialSignature>, SigningError>;
}

pub struct SigningCoordinator<C, A> {
    pub endpoint: C,
    pub contract_address: A,
    signing_key: SigningKey,
}

impl SigningCoordinator<CosmosEndpoint, Address> {
    pub fn new(
        endpoint: CosmosEndpoint,
        contract_address: Address,
        signing_key: SigningKey,
    ) -> Self {
        SigningCoordinator {
            endpoint,
            contract_address,
            signing_key,
        }
    }

    async fn get_account_sequence(&self) -> u64 {
        let account = self
            .endpoint
            .client
            .auth_query_account(self.signing_key.to_addr("osmo").await.unwrap())
            .await
            .unwrap();

        account.account.sequence
    }
}

impl SigningCoordinatorInterface<IndexedValue<G1Element>>
    for SigningCoordinator<CosmosEndpoint, Address>
{
    async fn create_session(
        &self,
        payload: String,
    ) -> Result<SigningSession<IndexedValue<G1Element>>, SigningError> {
        let message = json!({
            "CreateSession": {
                "payload": payload
            }
        });

        let request = ExecRequest {
            address: self.contract_address.clone(),
            msg: message,
            funds: vec![],
        };

        let options = TxOptions {
            timeout_height: None,
            fee: None,
            memo: String::from(""),
            sequence: self.get_account_sequence().await.into(),
        };

        let res = self
            .endpoint
            .client
            .wasm_execute(request, &self.signing_key, &options)
            .await;

        match res {
            Ok(r) => Ok(SigningSession::<IndexedValue<G1Element>> {
                session_id: "todo".to_string(), // TODO: Get session id from response
                payload,
                sigs: vec![],
            }),
            Err(_) => Err(SigningError::ErrorCreatingSession),
        }
    }

    async fn fetch_session(
        &self,
        id: String,
    ) -> Result<SigningSession<IndexedValue<G1Element>>, SigningError> {
        let query_msg = json!({
            "Session": {
                "session_id": id
            }
        });
        let res = self
            .endpoint
            .client
            .wasm_query(self.contract_address.clone(), &query_msg)
            .await;

        match res {
            Ok(r) => Ok(r.res.data().unwrap()),
            Err(_) => Err(SigningError::ErrorFetchingSession),
        }
    }

    async fn post_partial_signatures(
        &self,
        session_id: String,
        partial_signatures: Vec<IndexedValue<G1Element>>,
    ) -> Result<Vec<IndexedValue<G1Element>>, SigningError> {
        let execute_message = json!({
            "PostPartialSig": {
                "session_id": session_id,
                "partial_sig": serde_json::to_value(partial_signatures.clone()).unwrap()
            }
        });

        let request = ExecRequest {
            address: self.contract_address.clone(),
            msg: execute_message,
            funds: vec![],
        };

        let options = TxOptions {
            timeout_height: None,
            fee: None,
            memo: String::from(""),
            sequence: self.get_account_sequence().await.into(),
        };

        let res = self
            .endpoint
            .client
            .wasm_execute(request, &self.signing_key, &options)
            .await;

        match res {
            Ok(_) => Ok(partial_signatures),
            Err(_) => Err(SigningError::ErrorPostingPartialSignatures),
        }
    }
}
