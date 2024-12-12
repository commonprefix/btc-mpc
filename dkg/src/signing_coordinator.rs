use std::collections::BTreeMap;

use cosm_tome::{
    chain::request::TxOptions,
    modules::{auth::model::Address, cosmwasm::model::ExecRequest},
    signing_key::key::SigningKey,
};
use fastcrypto::groups::secp256k1::ProjectivePoint;
use fastcrypto_tbls::nodes::Nodes;
use frost_secp256k1::{round1::SigningCommitments, round2::SignatureShare, Identifier};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{endpoints::CosmosEndpoint, error::SigningError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd)]
pub enum SigningPhase {
    Phase1,
    Phase2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    pub session_id: String,
    pub phase: SigningPhase,
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
    pub signature_shares: BTreeMap<Identifier, SignatureShare>,
    pub payload: String,
}

#[allow(async_fn_in_trait)]
pub trait SigningCoordinatorInterface {
    /// Create a new signing session.
    async fn create_session(
        &self,
        nodes: Nodes<ProjectivePoint>,
        payload: Vec<u8>,
    ) -> Result<String, SigningError>;

    /// Fetch signing session by id
    async fn fetch_session(&self, id: String) -> Result<SigningSession, SigningError>;

    /// Post signature shares for session with given id
    async fn post_signature_shares(
        &self,
        session_id: String,
        signature_shares: BTreeMap<Identifier, SignatureShare>,
        signature: k256::ecdsa::Signature,
        pk: k256::ecdsa::VerifyingKey,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, SigningError>;

    /// Post commitements for session with given id
    async fn post_commitments(
        &self,
        session_id: String,
        commitments: BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<(), SigningError>;
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

impl SigningCoordinatorInterface for SigningCoordinator<CosmosEndpoint, Address> {
    async fn post_commitments(
        &self,
        _session_id: String,
        _commitments: BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<(), SigningError> {
        unimplemented!()
    }

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

    async fn fetch_session(&self, id: String) -> Result<SigningSession, SigningError> {
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

    async fn post_signature_shares(
        &self,
        session_id: String,
        signature_shares: BTreeMap<Identifier, SignatureShare>,
        signature: k256::ecdsa::Signature,
        pk: k256::ecdsa::VerifyingKey,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, SigningError> {
        let execute_message = json!({
            "PostPartialSig": {
                "session_id": session_id,
                "partial_sigs": serde_json::to_value(signature_shares.clone()).unwrap(),
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
            Ok(_) => Ok(signature_shares),
            Err(_) => Err(SigningError::ErrorPostingPartialSignatures),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use cosm_tome::{
        modules::auth::model::Address,
        signing_key::key::{Key, SigningKey},
    };
    use fastcrypto::{groups::secp256k1::ProjectivePoint, serde_helpers::ToFromByteArray};
    use fastcrypto_tbls::{
        dkg::Party,
        ecies::{PrivateKey, PublicKey},
        nodes::{Node, Nodes},
        random_oracle::RandomOracle,
    };
    use k256::ecdsa::signature::Signer;
    use rand::thread_rng;

    use crate::{endpoints::CosmosEndpoint, signing_coordinator::SigningCoordinatorInterface};

    use super::SigningCoordinator;
    use frost_secp256k1::{round2::SignatureShare, Identifier};

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
        assert_eq!(session.payload, payload);
        assert_eq!(session.signature_shares, BTreeMap::new());
    }

    #[tokio::test]
    #[ignore]
    async fn test_post_sig() {
        let coordinator = create_coordinator_instance();
        let (keys, _, _, nodes) = create_parties(5);
        let payload = "foobar";

        let session_id = coordinator
            .create_session(nodes, payload.as_bytes().to_vec())
            .await
            .unwrap();

        let mut partial_sigs = BTreeMap::new();
        partial_sigs.insert(
            Identifier::new((1 as u32).try_into().unwrap()).unwrap(),
            SignatureShare::deserialize(&[0; 32]).unwrap(),
        );
        partial_sigs.insert(
            Identifier::new((2 as u32).try_into().unwrap()).unwrap(),
            SignatureShare::deserialize(&[0; 32]).unwrap(),
        );

        let partial_sig_json = serde_json::to_string(&partial_sigs.clone()).unwrap();
        let partial_sig_bytes = partial_sig_json.as_bytes();
        let sk =
            k256::ecdsa::SigningKey::from_bytes(&keys[0].0.as_element().to_byte_array().into())
                .unwrap();
        let pk = sk.verifying_key();
        let signature: k256::ecdsa::Signature = sk.sign(&partial_sig_bytes);

        // pushing 2 signatures
        assert!(coordinator
            .post_signature_shares(session_id.clone(), partial_sigs.clone(), signature, *pk,)
            .await
            .is_ok());

        let mut expected_signatures = partial_sigs.clone();

        // prepare to push an extra signature
        let mut partial_sigs = BTreeMap::new();
        partial_sigs.insert(
            Identifier::new((3 as u32).try_into().unwrap()).unwrap(),
            SignatureShare::deserialize(&[0; 32]).unwrap(),
        );

        let partial_sig_json = serde_json::to_string(&partial_sigs.clone()).unwrap();
        let partial_sig_bytes = partial_sig_json.as_bytes();
        let signature: k256::ecdsa::Signature = sk.sign(&partial_sig_bytes);

        assert!(coordinator
            .post_signature_shares(session_id.clone(), partial_sigs.clone(), signature, *pk,)
            .await
            .is_ok());
        expected_signatures.insert(
            Identifier::new((3 as u32).try_into().unwrap()).unwrap(),
            partial_sigs.values().next().unwrap().clone(),
        );

        let session = coordinator.fetch_session(session_id.clone()).await.unwrap();
        assert_eq!(session.signature_shares, expected_signatures);
    }
}
