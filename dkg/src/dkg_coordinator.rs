use cosm_tome::chain::request::TxOptions;
use cosm_tome::modules::auth::model::Address;
use cosm_tome::modules::cosmwasm::model::{ExecRequest, ExecResponse};
use cosm_tome::signing_key::key::SigningKey;
use fastcrypto::bls12381::min_sig::{BLS12381PublicKey, BLS12381Signature};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::nodes::{Node, Nodes};
use fastcrypto_tbls::types::Signature;
use serde_json::json;

type Confirmation = fastcrypto_tbls::dkg::Confirmation<G2Element>;
type Confirmations = Vec<Confirmation>;

type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;
type Messages = Vec<Message>;

use crate::error::Result;
use crate::{bulletin_board::Session, endpoints::CosmosEndpoint};

#[derive(Debug)]
pub enum PostResponse {
    CosmosResponse(ExecResponse),
    GenericResponse(String),
}

pub trait DkgCoordinatorInterface {
    async fn create_session(&self, threshold: u16, nodes: Vec<Node<G2Element>>) -> PostResponse;

    async fn fetch_session(&self) -> Result<Session>;

    async fn fetch_nodes(&self) -> Result<Nodes<G2Element>>;

    async fn fetch_threshold(&self) -> Result<u16>;

    async fn post_message(
        &mut self,
        message: Message,
        signature: blst::min_sig::Signature,
        pk: blst::min_sig::PublicKey,
    ) -> PostResponse;

    async fn fetch_messages(&self) -> Result<Messages>;

    async fn post_confirmation(
        &mut self,
        confirmation: Confirmation,
        signature: blst::min_sig::Signature,
        pk: blst::min_sig::PublicKey,
    ) -> PostResponse;

    async fn fetch_confirmations(&self) -> Result<Confirmations>;
}

pub struct DkgCoordinator<C, A> {
    pub endpoint: C,
    pub contract_address: A,
    signing_key: SigningKey,
}

impl DkgCoordinator<CosmosEndpoint, Address> {
    pub fn new(
        endpoint: CosmosEndpoint,
        contract_address: Address,
        signing_key: SigningKey,
    ) -> Self {
        DkgCoordinator {
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

impl DkgCoordinatorInterface for DkgCoordinator<CosmosEndpoint, Address> {
    async fn create_session(&self, threshold: u16, nodes: Vec<Node<G2Element>>) -> PostResponse {
        let message = json!({
            "CreateSession": {
                "threshold": threshold,
                "nodes": serde_json::to_value(nodes).unwrap(),
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

        PostResponse::CosmosResponse(
            self.endpoint
                .client
                .wasm_execute(request, &self.signing_key, &options)
                .await
                .unwrap(),
        )
    }

    async fn fetch_session(&self) -> Result<Session> {
        let query_msg = json!({
            "Session": {}
        });
        let res = self
            .endpoint
            .client
            .wasm_query(self.contract_address.clone(), &query_msg)
            .await
            .unwrap();
        Ok(res.res.data().unwrap())
    }

    async fn fetch_nodes(&self) -> Result<Nodes<G2Element>> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().nodes)
    }

    async fn fetch_threshold(&self) -> Result<u16> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().threshold)
    }

    async fn post_message(
        &mut self,
        message: Message,
        signature: blst::min_sig::Signature,
        pk: blst::min_sig::PublicKey,
    ) -> PostResponse {
        let execute_message = json!({
            "PostMessage": {
                "message": serde_json::to_value(message).unwrap(),
                "pk": pk.serialize().as_slice(),
                "signature": signature.serialize().as_slice(),
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

        PostResponse::CosmosResponse(
            self.endpoint
                .client
                .wasm_execute(request, &self.signing_key, &options)
                .await
                .unwrap(),
        )
    }

    async fn fetch_messages(&self) -> Result<Messages> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().messages)
    }

    async fn post_confirmation(
        &mut self,
        confirmation: Confirmation,
        signature: blst::min_sig::Signature,
        pk: blst::min_sig::PublicKey,
    ) -> PostResponse {
        let execute_message = json!({
            "PostConfirmation": {
                "confirmation": serde_json::to_value(confirmation).unwrap(),
                "pk": pk.serialize().as_slice(),
                "signature": signature.serialize().as_slice(),
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

        PostResponse::CosmosResponse(
            self.endpoint
                .client
                .wasm_execute(request, &self.signing_key, &options)
                .await
                .unwrap(),
        )
    }

    async fn fetch_confirmations(&self) -> Result<Confirmations> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().confirmations)
    }
}

#[cfg(test)]
mod test {
    use cosm_tome::{
        modules::auth::model::Address,
        signing_key::key::{Key, SigningKey},
    };
    use fastcrypto::{
        bls12381::min_sig::{BLS12381KeyPair, BLS12381PrivateKey, BLS12381PublicKey, DST_G1},
        groups::bls12381::G2Element,
        serde_helpers::ToFromByteArray,
        traits::{Signer, ToFromBytes},
    };
    use fastcrypto_tbls::{
        dkg::Party,
        ecies::{PrivateKey, PublicKey},
        nodes::{Node, Nodes},
        random_oracle::RandomOracle,
    };
    use rand::thread_rng;
    use serial_test::serial;

    type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;

    use crate::{
        bulletin_board::Session,
        dkg_coordinator::{Confirmation, DkgCoordinator, DkgCoordinatorInterface},
        endpoints::CosmosEndpoint,
    };

    fn create_test_key() -> SigningKey {
        SigningKey {
            name: "wallet".to_string(),
            key: Key::Mnemonic("curtain shy attitude prevent lava liar card right clarify among agent harbor grass syrup accident fabric present rice forget miss hotel diagram spring wrong".to_string()),
            derivation_path: "m/44'/118'/0'/0/0".to_string(),
        }
    }

    fn create_coordinator_instance() -> DkgCoordinator<CosmosEndpoint, Address> {
        let endpoint = CosmosEndpoint::new("./config/osmosis_testnet.yaml");
        let contract_address: Address =
            "osmo1huxjrxx265emhsvpnh4ctqhdzacrldf4metwzmmmyhhmvzvs6j4ql2rltm"
                .parse()
                .unwrap();
        let key = create_test_key();
        DkgCoordinator::new(endpoint, contract_address, key)
    }

    fn create_test_key_pair() -> (PrivateKey<G2Element>, PublicKey<G2Element>) {
        let private_key: PrivateKey<G2Element> = PrivateKey::<G2Element>::new(&mut thread_rng());
        let public_key: PublicKey<G2Element> =
            PublicKey::<G2Element>::from_private_key(&private_key);

        (private_key, public_key)
    }

    fn create_parties(
        threshold: u16,
    ) -> (
        Vec<(PrivateKey<G2Element>, PublicKey<G2Element>)>,
        Vec<Node<G2Element>>,
        Vec<Party<G2Element, G2Element>>,
        Nodes<G2Element>,
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
                Party::<G2Element, G2Element>::new(
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

    fn create_messages(parties: &Vec<Party<G2Element, G2Element>>) -> Vec<Message> {
        let mut messages = Vec::new();
        for party in parties {
            messages.push(party.create_message(&mut thread_rng()).unwrap());
        }

        messages
    }

    fn create_confirmations(
        parties: &Vec<Party<G2Element, G2Element>>,
        messages: &Vec<Message>,
    ) -> Vec<Confirmation> {
        let mut confirmations = Vec::new();
        for party in parties {
            let processed_messages = messages
                .iter()
                .map(|m| party.process_message(m.clone(), &mut thread_rng()).unwrap())
                .collect::<Vec<_>>();
            confirmations.push(party.merge(&processed_messages).unwrap().0);
        }

        confirmations
    }

    fn testdata() -> (String, String, String) {
        let message = std::fs::read_to_string("./testdata/message.json")
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        let confirmation = std::fs::read_to_string("./testdata/confirmation.json")
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        let nodes = std::fs::read_to_string("./testdata/nodes.json")
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        (message, confirmation, nodes)
    }

    #[tokio::test]
    #[serial]
    async fn test_session_creation() {
        let dkg_coordinator = create_coordinator_instance();

        let (_, nodes_vec, _, nodes) = create_parties(5);

        // create new session with no nodes
        dkg_coordinator.create_session(2, nodes_vec.clone()).await;
        let expected_session = Session {
            threshold: 2,
            nodes: nodes.clone(),
            messages: vec![],
            confirmations: vec![],
        };
        let actual_session = dkg_coordinator.fetch_session().await.unwrap();
        assert_eq!(expected_session, actual_session);

        let actual_nodes = dkg_coordinator.fetch_nodes().await.unwrap();
        assert_eq!(nodes, actual_nodes);
    }

    #[tokio::test]
    #[serial]
    async fn test_message_posting() {
        let mut dkg_coordinator = create_coordinator_instance();

        let (keys, nodes_vec, parties, _) = create_parties(5);
        let party = &parties[0];

        // create message and sign it
        let message = party.create_message(&mut thread_rng()).unwrap();
        let sk = BLS12381PrivateKey::from_bytes(&keys[0].0.as_element().to_byte_array()).unwrap();
        let pk = BLS12381PublicKey::from_bytes(&keys[0].1.as_element().to_byte_array()).unwrap();
        let message_json = serde_json::to_string(&message).unwrap();
        let msg_bytes = message_json.as_bytes();
        let signature = sk.sign(msg_bytes);

        // create new session
        dkg_coordinator.create_session(5, nodes_vec.clone()).await;

        // post message
        let response_variant = dkg_coordinator
            .post_message(message.clone(), signature.sig, pk.pubkey)
            .await;
        let _ = match response_variant {
            crate::dkg_coordinator::PostResponse::CosmosResponse(res) => res,
            _ => panic!("unexpected response"),
        };

        // verify that the messages was stored
        let session_messages = dkg_coordinator.fetch_messages().await.unwrap();
        assert_eq!(session_messages.len(), 1);
        assert_eq!(session_messages[0], message);
    }

    #[tokio::test]
    #[serial]
    async fn test_confirmation_posting() {
        let mut dkg_coordinator = create_coordinator_instance();

        let (keys, nodes_vec, parties, _) = create_parties(5);
        let messages = create_messages(&parties);
        let confirmations = create_confirmations(&parties, &messages);

        // create new session
        dkg_coordinator.create_session(5, nodes_vec.clone()).await;

        // sign confirmation
        let sk = BLS12381PrivateKey::from_bytes(&keys[0].0.as_element().to_byte_array()).unwrap();
        let pk = BLS12381PublicKey::from_bytes(&keys[0].1.as_element().to_byte_array()).unwrap();
        let message_json = serde_json::to_string(&confirmations[0]).unwrap();
        let msg_bytes = message_json.as_bytes();
        let signature = sk.sign(msg_bytes);

        // post confirmation
        let response_variant = dkg_coordinator
            .post_confirmation(confirmations[0].clone(), signature.sig, pk.pubkey)
            .await;
        let _ = match response_variant {
            crate::dkg_coordinator::PostResponse::CosmosResponse(res) => res,
            _ => panic!("unexpected response"),
        };

        // verify that the confirmation was stored
        let session_confirmations = dkg_coordinator.fetch_confirmations().await.unwrap();
        assert_eq!(session_confirmations.len(), 1);
        assert_eq!(session_confirmations[0], confirmations[0]);
    }
}