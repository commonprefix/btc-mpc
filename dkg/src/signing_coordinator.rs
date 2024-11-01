use std::collections::HashMap;

use cosm_tome::{
    chain::request::TxOptions,
    modules::{auth::model::Address, cosmwasm::model::ExecRequest},
    signing_key::key::SigningKey,
};
use fastcrypto::groups::{bls12381::G1Element, secp256k1::ProjectivePoint};
use fastcrypto_tbls::{
    nodes::{Nodes, PartyId},
    types::IndexedValue,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{endpoints::CosmosEndpoint, error::SigningError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession<PartialSignature> {
    pub session_id: String,
    pub nodes: Nodes<ProjectivePoint>,
    pub sigs: HashMap<PartyId, Vec<PartialSignature>>,
    pub payload: Vec<u8>,
}

#[allow(async_fn_in_trait)]
pub trait SigningCoordinatorInterface<PartialSignature>
where
    PartialSignature: Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new signing session.
    async fn create_session(
        &self,
        nodes: Nodes<ProjectivePoint>,
        payload: Vec<u8>,
    ) -> Result<String, SigningError>;

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
        signature: k256::ecdsa::Signature,
        pk: k256::ecdsa::VerifyingKey,
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
        nodes: Nodes<ProjectivePoint>,
        payload: Vec<u8>,
    ) -> Result<String, SigningError> {
        let message = json!({
            "CreateSigningSession": {
                "nodes": serde_json::to_value(&nodes).unwrap(),
                "payload": serde_json::to_value(payload.clone()).unwrap()
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
            Ok(r) => {
                let wasm_event = r
                    .res
                    .events
                    .iter()
                    .find(|e| e.type_str == "wasm")
                    .ok_or(SigningError::ErrorCreatingSession)?;
                let session_id = wasm_event
                    .attributes
                    .iter()
                    .find(|attr| attr.key == "session_id")
                    .map(|attr| attr.value.clone())
                    .ok_or(SigningError::ErrorCreatingSession)?;

                Ok(session_id)
            }
            Err(_) => Err(SigningError::ErrorCreatingSession),
        }
    }

    async fn fetch_session(
        &self,
        id: String,
    ) -> Result<SigningSession<IndexedValue<G1Element>>, SigningError> {
        let query_msg = json!({
            "SigningSession": {
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
        signature: k256::ecdsa::Signature,
        pk: k256::ecdsa::VerifyingKey,
    ) -> Result<Vec<IndexedValue<G1Element>>, SigningError> {
        let execute_message = json!({
            "PostPartialSig": {
                "session_id": session_id,
                "partial_sigs": serde_json::to_value(partial_signatures.clone()).unwrap(),
                "pk": pk.to_sec1_bytes(),
                "signature": signature.to_bytes(),
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

#[cfg(test)]
mod test {
    use std::{collections::HashMap, num::NonZero};

    use cosm_tome::{
        modules::auth::model::Address,
        signing_key::key::{Key, SigningKey},
    };
    use fastcrypto::{
        groups::{bls12381::G1Element, secp256k1::ProjectivePoint, GroupElement},
        serde_helpers::ToFromByteArray,
    };
    use fastcrypto_tbls::{
        dkg::Party,
        ecies::{PrivateKey, PublicKey},
        nodes::{Node, Nodes, PartyId},
        random_oracle::RandomOracle,
        types::IndexedValue,
    };
    use k256::ecdsa::signature::Signer;
    use rand::thread_rng;

    use crate::{endpoints::CosmosEndpoint, signing_coordinator::SigningCoordinatorInterface};

    use super::SigningCoordinator;

    fn create_test_key() -> SigningKey {
        SigningKey {
            name: "wallet".to_string(),
            key: Key::Mnemonic("curtain shy attitude prevent lava liar card right clarify among agent harbor grass syrup accident fabric present rice forget miss hotel diagram spring wrong".to_string()),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
        }
    }

    fn create_coordinator_instance() -> SigningCoordinator<CosmosEndpoint, Address> {
        let endpoint = CosmosEndpoint::new("./config/osmosis_testnet.yaml");
        let contract_address: Address =
            "osmo1yjqr4fud2rj9vt5a5lxk98nhrsvrk0ashqf9hnmafjlmvs4dxh9s9nflrs"
                .parse()
                .unwrap();
        let key = create_test_key();
        SigningCoordinator::new(endpoint, contract_address, key)
    }

    fn create_test_key_pair() -> (PrivateKey<ProjectivePoint>, PublicKey<ProjectivePoint>) {
        let private_key: PrivateKey<ProjectivePoint> =
            PrivateKey::<ProjectivePoint>::new(&mut thread_rng());
        let public_key: PublicKey<ProjectivePoint> =
            PublicKey::<ProjectivePoint>::from_private_key(&private_key);

        (private_key, public_key)
    }

    fn create_parties(
        threshold: u16,
    ) -> (
        Vec<(PrivateKey<ProjectivePoint>, PublicKey<ProjectivePoint>)>,
        Vec<Node<ProjectivePoint>>,
        Vec<Party<ProjectivePoint, ProjectivePoint>>,
        Nodes<ProjectivePoint>,
    ) {
        let mut nodes_vec = Vec::new();
        let mut keys = Vec::new();
        let mut parties = Vec::new();
        for i in 0..5 {
            let (sk, pk) = create_test_key_pair();
            keys.push((sk, pk.clone()));
            nodes_vec.push(Node {
                id: i,
                pk: pk,
                weight: i + 1,
            });
        }

        let nodes = Nodes::new(nodes_vec.clone()).unwrap();

        for i in 0..5 {
            parties.push(
                Party::<ProjectivePoint, ProjectivePoint>::new(
                    keys[i].0.clone(),
                    nodes.clone(),
                    threshold,
                    RandomOracle::new("dkg"),
                    &mut thread_rng(),
                )
                .unwrap(),
            );
        }

        (keys, nodes_vec, parties, nodes)
    }

    #[tokio::test]
    #[ignore]
    async fn test_create_and_fetch() {
        let coordinator = create_coordinator_instance();
        let (_, _, _, nodes) = create_parties(5);
        let payload = "foobar";

        let create_session_res = coordinator
            .create_session(nodes, payload.as_bytes().to_vec())
            .await;

        assert!(create_session_res.is_ok());

        let session_id = create_session_res.unwrap();

        let fetch_session_res = coordinator.fetch_session(session_id.clone()).await;
        assert!(fetch_session_res.is_ok());

        let session = fetch_session_res.unwrap();

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.payload, payload.as_bytes().to_vec());
        assert_eq!(session.sigs, HashMap::new());
    }

    #[tokio::test]
    #[ignore]
    async fn test_post_sig() {
        let coordinator = create_coordinator_instance();
        let (keys, _, _, nodes) = create_parties(5);
        let payload = "foobar";
        let mut expected_signatures = HashMap::new();

        let session_id = coordinator
            .create_session(nodes, payload.as_bytes().to_vec())
            .await
            .unwrap();

        let partial_sigs: Vec<IndexedValue<G1Element>> = vec![
            IndexedValue {
                index: NonZero::new(1).unwrap(),
                value: G1Element::zero(),
            },
            IndexedValue {
                index: NonZero::new(2).unwrap(),
                value: G1Element::zero(),
            },
        ];

        let partial_sig_json = serde_json::to_string(&partial_sigs.clone()).unwrap();
        let partial_sig_bytes = partial_sig_json.as_bytes();
        let sk =
            k256::ecdsa::SigningKey::from_bytes(&keys[0].0.as_element().to_byte_array().into())
                .unwrap();
        let pk = sk.verifying_key();
        let signature: k256::ecdsa::Signature = sk.sign(&partial_sig_bytes);

        // pushing 2 signatures
        assert!(coordinator
            .post_partial_signatures(session_id.clone(), partial_sigs.clone(), signature, *pk,)
            .await
            .is_ok());
        expected_signatures.insert(0 as PartyId, partial_sigs);

        // prepare to push an extra signature
        let partial_sigs: Vec<IndexedValue<G1Element>> = vec![IndexedValue {
            index: NonZero::new(3).unwrap(),
            value: G1Element::zero(),
        }];
        let partial_sig_json = serde_json::to_string(&partial_sigs.clone()).unwrap();
        let partial_sig_bytes = partial_sig_json.as_bytes();
        let signature: k256::ecdsa::Signature = sk.sign(&partial_sig_bytes);

        assert!(coordinator
            .post_partial_signatures(session_id.clone(), partial_sigs.clone(), signature, *pk,)
            .await
            .is_ok());
        let stored_signatures = expected_signatures.get_mut(&(0 as PartyId)).unwrap();
        stored_signatures.push(partial_sigs[0].clone());

        let session = coordinator.fetch_session(session_id.clone()).await.unwrap();
        assert_eq!(session.sigs, expected_signatures);
    }
}
