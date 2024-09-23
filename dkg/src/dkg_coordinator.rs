use cosm_tome::chain::request::TxOptions;
use cosm_tome::modules::auth::model::Address;
use cosm_tome::modules::cosmwasm::model::ExecRequest;
use cosm_tome::signing_key::key::SigningKey;
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::nodes::{Node, Nodes};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub type Confirmation = fastcrypto_tbls::dkg::Confirmation<G2Element>;

pub type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;

use crate::endpoints::CosmosEndpoint;
use crate::error::DKGError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd)]
pub enum DKGPhase {
    Phase1,
    Phase2,
    Phase3,
    Phase4,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct DKGSession {
    pub phase: DKGPhase,
    pub threshold: u16,
    pub nodes: Nodes<G2Element>,
    pub messages: Vec<Message>,
    pub confirmations: Vec<Confirmation>,
}

#[allow(async_fn_in_trait)]
pub trait DkgCoordinatorInterface {
    async fn create_session(
        &self,
        threshold: u16,
        nodes: Vec<Node<G2Element>>,
    ) -> Result<DKGSession, DKGError>;

    async fn fetch_session(&self) -> Result<Option<DKGSession>, DKGError>;

    async fn post_message(&self, message: Message) -> Result<Message, DKGError>;

    async fn post_confirmation(&self, confirmation: Confirmation)
        -> Result<Confirmation, DKGError>;
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
    async fn create_session(
        &self,
        threshold: u16,
        nodes: Vec<Node<G2Element>>,
    ) -> Result<DKGSession, DKGError> {
        let message = json!({
            "CreateSession": {
                "threshold": threshold,
                "nodes": serde_json::to_value(nodes.clone()).unwrap(),
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
            Ok(_) => Ok(DKGSession {
                threshold,
                nodes: Nodes::new(nodes).unwrap(),
                messages: vec![],
                confirmations: vec![],
                phase: DKGPhase::Phase2,
            }),
            Err(_) => Err(DKGError::ErrorCreatingSession),
        }
    }

    async fn fetch_session(&self) -> Result<Option<DKGSession>, DKGError> {
        let query_msg = json!({
            "Session": {}
        });
        let res = self
            .endpoint
            .client
            .wasm_query(self.contract_address.clone(), &query_msg)
            .await;

        match res {
            Ok(r) => Ok(r.res.data().unwrap()),
            Err(_) => Err(DKGError::ErrorFetchingSession),
        }
    }

    async fn post_message(&self, message: Message) -> Result<Message, DKGError> {
        let execute_message = json!({
            "PostMessage": {
                "message": serde_json::to_value(message.clone()).unwrap()
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
            Ok(_) => Ok(message),
            Err(_) => Err(DKGError::ErrorPostingMessage),
        }
    }

    async fn post_confirmation(
        &self,
        confirmation: Confirmation,
    ) -> Result<Confirmation, DKGError> {
        let execute_message = json!({
            "PostConfirmation": {
                "confirmation": serde_json::to_value(confirmation.clone()).unwrap()
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
            Ok(_) => Ok(confirmation),
            Err(_) => Err(DKGError::ErrorPostingConfirmation),
        }
    }
}

#[cfg(test)]
mod test {
    use cosm_tome::{
        modules::auth::model::Address,
        signing_key::key::{Key, SigningKey},
    };
    use fastcrypto::groups::bls12381::G2Element;
    use fastcrypto_tbls::{
        ecies::{PrivateKey, PublicKey},
        nodes::{Node, Nodes},
    };
    use rand::thread_rng;
    use serial_test::serial;

    type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;

    use crate::{
        dkg_coordinator::{
            Confirmation, DKGPhase, DKGSession, DkgCoordinator, DkgCoordinatorInterface,
        },
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
            "osmo10nwvtnxvp042g37hdrm5jpfzmf2z0rgmfnh5dehszallnvdxj39sxzmf6n"
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

    fn create_nodes() -> Vec<Node<G2Element>> {
        let mut nodes = Vec::new();
        for i in 0..5 {
            let (_, pk) = create_test_key_pair();
            nodes.push(Node {
                id: i,
                pk: pk,
                weight: i,
            });
        }

        nodes
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

        let nodes = create_nodes();

        dkg_coordinator
            .create_session(2, nodes.clone())
            .await
            .unwrap();

        // create new session with no nodes
        assert!(dkg_coordinator
            .create_session(2, nodes.clone())
            .await
            .is_ok());
        let expected_session = DKGSession {
            threshold: 2,
            nodes: Nodes::new(nodes.clone()).unwrap(),
            messages: vec![],
            confirmations: vec![],
            phase: DKGPhase::Phase2,
        };
        let actual_session = dkg_coordinator.fetch_session().await;
        assert!(actual_session.is_ok());
        assert_eq!(expected_session, actual_session.unwrap().unwrap());
    }

    #[tokio::test]
    #[serial]
    async fn test_message_posting() {
        let dkg_coordinator = create_coordinator_instance();

        let (message, _, nodes) = testdata();
        let message_parsed: Message = serde_json::from_str(&message).unwrap();
        // create new session
        assert!(dkg_coordinator
            .create_session(5, serde_json::from_str(&nodes).unwrap())
            .await
            .is_ok());

        // post message
        assert!(dkg_coordinator
            .post_message(message_parsed.clone())
            .await
            .is_ok());

        // verify that the messages was stored
        let session_messages = dkg_coordinator
            .fetch_session()
            .await
            .unwrap()
            .unwrap()
            .messages;
        assert_eq!(session_messages.len(), 1);
        assert_eq!(session_messages[0], message_parsed);
    }

    #[tokio::test]
    #[serial]
    async fn test_confirmation_posting() {
        let dkg_coordinator = create_coordinator_instance();

        let (_, confirmation, nodes) = testdata();
        let confirmation_parsed: Confirmation = serde_json::from_str(&confirmation).unwrap();

        // create new session
        assert!(dkg_coordinator
            .create_session(5, serde_json::from_str(&nodes).unwrap())
            .await
            .is_ok());

        // post confirmation
        assert!(dkg_coordinator
            .post_confirmation(confirmation_parsed.clone())
            .await
            .is_ok());

        // verify that the confirmation was stored
        let session_confirmations = dkg_coordinator
            .fetch_session()
            .await
            .unwrap()
            .unwrap()
            .confirmations;
        assert_eq!(session_confirmations.len(), 1);
        assert_eq!(session_confirmations[0], confirmation_parsed);
    }
}
