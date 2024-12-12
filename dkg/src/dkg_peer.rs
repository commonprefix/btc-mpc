use fastcrypto::{
    groups::{secp256k1::ProjectivePoint as FastCryptoProjectivePoint, GroupElement},
    serde_helpers::ToFromByteArray,
};
use fastcrypto_tbls::{
    dkg::{Confirmation, Output, Party},
    dkg_v0::UsedProcessedMessages,
    ecies::{PrivateKey, PublicKey},
    random_oracle::RandomOracle,
};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::{
    dkg_coordinator::{DKGPhase, DKGSession, DkgCoordinatorInterface, Message},
    error::DKGError,
};
use k256::ecdsa::SigningKey as K256SigningKey;

#[derive(Debug, PartialEq, Clone)]
pub enum DKGResult {
    NoActiveSession,
    MessageAlreadyPosted,
    MessagePosted,
    ConfirmationAlreadyPosted,
    ConfirmationPosted,
    SharesAlreadyConstructed,
    OutputConstructed,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DKGPeer {
    private_key: PrivateKey<FastCryptoProjectivePoint>,
    pub public_key: PublicKey<FastCryptoProjectivePoint>,
    pub dkg_output: Option<Output<FastCryptoProjectivePoint, FastCryptoProjectivePoint>>,
    dkg_session: Option<DKGSession>,
}

impl DKGPeer {
    pub fn new(secp256k1_sk: &K256SigningKey) -> Self {
        let secp256k1_sk_bytes: [u8; 32] = secp256k1_sk.to_bytes().into();
        let private_key: PrivateKey<FastCryptoProjectivePoint> =
            PrivateKey::<FastCryptoProjectivePoint>::from(
                <FastCryptoProjectivePoint as GroupElement>::ScalarType::from_byte_array(
                    &secp256k1_sk_bytes,
                )
                .expect("Invalid private_key"),
            );
        let public_key = PublicKey::<FastCryptoProjectivePoint>::from_private_key(&private_key);

        Self {
            private_key,
            public_key,
            dkg_output: None,
            dkg_session: None,
        }
    }

    async fn update_dkg_session<DC: DkgCoordinatorInterface>(
        &mut self,
        dkg_coordinator: &DC,
    ) -> Result<Option<DKGSession>, DKGError> {
        self.dkg_session = dkg_coordinator.fetch_session().await?;
        Ok(self.dkg_session.clone())
    }

    fn get_dkg_party(
        &self,
        random_oracle: RandomOracle,
    ) -> Option<Party<FastCryptoProjectivePoint, FastCryptoProjectivePoint>> {
        if self.dkg_session.is_none() {
            return None;
        }

        Some(
            Party::<FastCryptoProjectivePoint, FastCryptoProjectivePoint>::new(
                self.private_key.clone(),
                self.dkg_session.as_ref().unwrap().nodes.clone(),
                self.dkg_session.as_ref().unwrap().threshold,
                random_oracle.clone(),
                &mut thread_rng(),
            )
            .unwrap(),
        )
    }

    fn dkg_message_posted(&self) -> Option<Message> {
        if self.dkg_session.is_none() {
            return None;
        }

        let node_id = self
            .dkg_session
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .find(|n| n.pk == self.public_key)
            .unwrap()
            .id;
        self.dkg_session
            .as_ref()
            .unwrap()
            .messages
            .iter()
            .find(|m| m.sender == node_id)
            .cloned()
    }

    async fn post_dkg_message<DC: DkgCoordinatorInterface>(
        &mut self,
        dkg_coordinator: &DC,
        random_oracle: RandomOracle,
    ) -> Result<Message, DKGError> {
        let dkg_party = self.get_dkg_party(random_oracle).unwrap();

        let message = dkg_party.create_message(&mut thread_rng()).unwrap();

        // TODO: DRY
        let sk =
            SigningKey::from_bytes(&self.private_key.as_element().to_byte_array().into()).unwrap();
        let pk = sk.verifying_key();
        let signature: Signature = sk.sign(&serde_json::to_string(&message).unwrap().as_bytes());

        dkg_coordinator
            .post_message(message.clone(), signature, *pk)
            .await?;
        Ok(message)
    }

    fn dkg_confirmation_posted(&self) -> Option<Confirmation<FastCryptoProjectivePoint>> {
        if self.dkg_session.is_none() {
            return None;
        }

        let node_id = self
            .dkg_session
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .find(|n| n.pk == self.public_key)
            .unwrap()
            .id;
        self.dkg_session
            .as_ref()
            .unwrap()
            .confirmations
            .iter()
            .find(|c| c.sender == node_id)
            .cloned()
    }

    fn create_dkg_confirmation(
        &self,
        random_oracle: RandomOracle,
    ) -> Option<(
        Confirmation<FastCryptoProjectivePoint>,
        UsedProcessedMessages<FastCryptoProjectivePoint, FastCryptoProjectivePoint>,
    )> {
        if self.dkg_session.is_none() {
            return None;
        }

        let dkg_party = self.get_dkg_party(random_oracle).unwrap();

        let processed_messages = self
            .dkg_session
            .as_ref()
            .unwrap()
            .messages
            .iter()
            .map(|m| {
                dkg_party
                    .process_message(m.clone(), &mut thread_rng())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        Some(dkg_party.merge(&processed_messages).unwrap())
    }

    async fn post_dkg_confirmation<DC: DkgCoordinatorInterface>(
        &mut self,
        dkg_coordinator: &DC,
        random_oracle: RandomOracle,
    ) -> Result<Confirmation<FastCryptoProjectivePoint>, DKGError> {
        let (confirmation, _) = self.create_dkg_confirmation(random_oracle).unwrap();

        // TODO: DRY
        let sk =
            SigningKey::from_bytes(&self.private_key.as_element().to_byte_array().into()).unwrap();
        let pk = sk.verifying_key();
        let signature: Signature =
            sk.sign(&serde_json::to_string(&confirmation).unwrap().as_bytes());

        dkg_coordinator
            .post_confirmation(confirmation.clone(), signature, *pk)
            .await?;
        Ok(confirmation)
    }

    async fn construct_dkg_shares(
        &mut self,
        random_oracle: RandomOracle,
    ) -> Result<Output<FastCryptoProjectivePoint, FastCryptoProjectivePoint>, DKGError> {
        let dkg_party = self.get_dkg_party(random_oracle.clone()).unwrap();
        let (_, used_messages) = self.create_dkg_confirmation(random_oracle).unwrap();

        let fastcrypto_dkg_output = dkg_party
            .complete(
                &used_messages,
                &self.dkg_session.as_ref().unwrap().confirmations,
                &mut thread_rng(),
            )
            .unwrap();

        self.dkg_output = Some(fastcrypto_dkg_output.clone());
        Ok(fastcrypto_dkg_output)
    }

    pub async fn dkg_step<DC: DkgCoordinatorInterface>(
        &mut self,
        dkg_coordinator: &DC,
        random_oracle: RandomOracle,
    ) -> Result<DKGResult, DKGError> {
        if self.update_dkg_session(dkg_coordinator).await?.is_none() {
            log::info!("No active DKG session.");
            return Ok(DKGResult::NoActiveSession);
        }

        match self.dkg_session.as_ref().unwrap().phase {
            DKGPhase::Phase1 => {
                log::info!("No active DKG session.");
                Ok(DKGResult::NoActiveSession)
            }
            DKGPhase::Phase2 => {
                if self.dkg_message_posted().is_none() {
                    self.post_dkg_message(dkg_coordinator, random_oracle)
                        .await?;
                    log::info!("DKG message posted.");
                    return Ok(DKGResult::MessagePosted);
                }

                log::info!("DKG message already posted. Waiting for next phase.");
                Ok(DKGResult::MessageAlreadyPosted)
            }
            DKGPhase::Phase3 => {
                if self.dkg_confirmation_posted().is_none() {
                    self.post_dkg_confirmation(dkg_coordinator, random_oracle)
                        .await?;
                    log::info!("DKG confirmation posted.");
                    return Ok(DKGResult::ConfirmationPosted);
                }

                log::info!("DKG confirmation already posted. Waiting for next phase.");
                Ok(DKGResult::ConfirmationAlreadyPosted)
            }
            DKGPhase::Phase4 => {
                if self.dkg_output.is_none() {
                    self.construct_dkg_shares(random_oracle).await?;
                    log::info!("DKG output constructed.");
                    return Ok(DKGResult::OutputConstructed);
                }

                log::info!("DKG output already constructed.");
                Ok(DKGResult::SharesAlreadyConstructed)
            }
        }
    }

    pub fn get_weight(&self) -> Result<u16, DKGError> {
        if self.dkg_output.is_none() {
            return Err(DKGError::DKGPending);
        }

        Ok(self
            .dkg_output
            .as_ref()
            .unwrap()
            .shares
            .as_ref()
            .unwrap()
            .len() as u16)
    }

    pub fn dkg_completed(&self) -> bool {
        self.dkg_output.is_some()
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use fastcrypto::groups::secp256k1::ProjectivePoint as FastcryptoProjectivePoint;
    use fastcrypto_tbls::{
        ecies::PublicKey,
        nodes::{Node, Nodes},
        random_oracle::RandomOracle,
    };
    use k256::ecdsa::{Signature, SigningKey as K256SigningKey, VerifyingKey};

    use crate::{
        dkg_coordinator::{Confirmation, DKGPhase, DKGSession, DkgCoordinatorInterface, Message},
        dkg_peer::{DKGPeer, DKGResult},
        error::DKGError,
    };

    pub struct TestDkgCoordinator {
        session: Arc<Mutex<Option<DKGSession>>>,
    }

    impl DkgCoordinatorInterface for TestDkgCoordinator {
        async fn create_session(
            &self,
            threshold: u16,
            nodes: Vec<Node<FastcryptoProjectivePoint>>,
        ) -> Result<DKGSession, DKGError> {
            let mut session = self.session.lock().unwrap();
            *session = Some(DKGSession {
                threshold,
                nodes: Nodes::new(nodes).unwrap(),
                messages: vec![],
                confirmations: vec![],
                phase: DKGPhase::Phase2,
            });
            return Ok(session.clone().unwrap());
        }

        async fn fetch_session(&self) -> Result<Option<DKGSession>, DKGError> {
            Ok(self.session.lock().unwrap().clone())
        }

        // TODO: verify signature
        async fn post_message(
            &self,
            message: Message,
            _signature: Signature,
            _pk: VerifyingKey,
        ) -> Result<Message, DKGError> {
            let mut session = self.session.lock().unwrap();
            let session = session.as_mut().unwrap();

            if session.phase > DKGPhase::Phase2 {
                return Err(DKGError::MessagePostingCompleted);
            }

            let is_duplicate = session.messages.iter().any(|m| m.sender == message.sender);
            if session.phase < DKGPhase::Phase2 && is_duplicate {
                return Err(DKGError::ErrorPostingMessage {
                    e: String::from("Message is duplicate or out of phase."),
                });
            }

            session.messages.push(message.clone());

            let total_weight = session
                .messages
                .iter()
                .map(|m| {
                    session
                        .nodes
                        .iter()
                        .find(|n| n.id == m.sender)
                        .unwrap()
                        .weight
                })
                .sum::<u16>();

            if total_weight >= session.threshold {
                session.phase = DKGPhase::Phase3;
            }

            Ok(message)
        }

        // TODO: verify signature
        async fn post_confirmation(
            &self,
            confirmation: Confirmation,
            _signature: Signature,
            _pk: VerifyingKey,
        ) -> Result<Confirmation, DKGError> {
            let mut session = self.session.lock().unwrap();
            let session = session.as_mut().unwrap();

            if session.phase > DKGPhase::Phase3 {
                return Err(DKGError::ConfirmationPostingCompleted);
            }

            let is_duplicate = session
                .confirmations
                .iter()
                .any(|c| c.sender == confirmation.sender);
            if session.phase < DKGPhase::Phase2 && is_duplicate {
                return Err(DKGError::ErrorPostingConfirmation {
                    e: String::from("Confirmation is duplicate or out of phase."),
                });
            }

            session.confirmations.push(confirmation.clone());

            let total_weight = session
                .confirmations
                .iter()
                .map(|c| {
                    session
                        .nodes
                        .iter()
                        .find(|n| n.id == c.sender)
                        .unwrap()
                        .weight
                })
                .sum::<u16>();

            let required_threshold = 2 * session.threshold - 1;
            if total_weight >= required_threshold {
                session.phase = DKGPhase::Phase4;
            }

            Ok(confirmation)
        }
    }

    pub fn create_nodes(
        nodes: Vec<(PublicKey<FastcryptoProjectivePoint>, u16)>,
    ) -> Vec<Node<FastcryptoProjectivePoint>> {
        nodes
            .iter()
            .enumerate()
            .map(|(id, (pk, w))| Node {
                id: id as u16,
                pk: pk.clone(),
                weight: *w,
            })
            .collect()
    }

    fn get_private_keys() -> (K256SigningKey, K256SigningKey, K256SigningKey) {
        let file_path = "testdata/peer_secp256k1_sk/peer_1.json";
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        let secp256k1_bytes_1: [u8; 32] =
            serde_json::from_str(&file_content).expect("JSON was not well-formatted");
        let secp256k1_sk_1: K256SigningKey =
            K256SigningKey::from_bytes(&secp256k1_bytes_1.into()).unwrap();

        let file_path = "testdata/peer_secp256k1_sk/peer_2.json";
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        let secp256k1_bytes_2: [u8; 32] =
            serde_json::from_str(&file_content).expect("JSON was not well-formatted");
        let secp256k1_sk_2: K256SigningKey =
            K256SigningKey::from_bytes(&secp256k1_bytes_2.into()).unwrap();

        let file_path = "testdata/peer_secp256k1_sk/peer_3.json";
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        let secp256k1_bytes_3: [u8; 32] =
            serde_json::from_str(&file_content).expect("JSON was not well-formatted");
        let secp256k1_sk_3: K256SigningKey =
            K256SigningKey::from_bytes(&secp256k1_bytes_3.into()).unwrap();

        (secp256k1_sk_1, secp256k1_sk_2, secp256k1_sk_3)
    }

    #[tokio::test]
    async fn successful_dkg() {
        let (private_key_1, private_key_2, private_key_3) = get_private_keys();
        let mut node_1 = DKGPeer::new(&private_key_1);
        let mut node_2 = DKGPeer::new(&private_key_2);
        let mut node_3 = DKGPeer::new(&private_key_3);

        let session = Arc::new(Mutex::new(None));
        let dkg_coordinator_1 = TestDkgCoordinator {
            session: session.clone(),
        };
        let dkg_coordinator_2 = TestDkgCoordinator {
            session: session.clone(),
        };
        let dkg_coordinator_3 = TestDkgCoordinator {
            session: session.clone(),
        };

        // Check that there is no active session yet.
        let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::NoActiveSession)
        );
        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::NoActiveSession)
        );
        assert_eq!(
            node_3
                .dkg_step(&dkg_coordinator_3, random_oracle.clone())
                .await,
            Ok(DKGResult::NoActiveSession)
        );

        // Create a DKG session.
        let nodes = create_nodes(vec![
            (node_1.clone().public_key, 4_u16),
            (node_2.clone().public_key, 5_u16),
            (node_3.clone().public_key, 7_u16),
        ]);
        assert!(dkg_coordinator_1.create_session(6_u16, nodes).await.is_ok());

        // Message phase.
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::MessagePosted)
        );
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::MessageAlreadyPosted)
        );

        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::MessagePosted)
        );

        // Confirmation phase.
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::ConfirmationPosted)
        );
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::ConfirmationAlreadyPosted)
        );

        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::ConfirmationPosted)
        );
        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::ConfirmationAlreadyPosted)
        );

        assert_eq!(
            node_3
                .dkg_step(&dkg_coordinator_3, random_oracle.clone())
                .await,
            Ok(DKGResult::ConfirmationPosted)
        );

        // Output phase.
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::OutputConstructed)
        );
        assert_eq!(
            node_1
                .dkg_step(&dkg_coordinator_1, random_oracle.clone())
                .await,
            Ok(DKGResult::SharesAlreadyConstructed)
        );

        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::OutputConstructed)
        );
        assert_eq!(
            node_2
                .dkg_step(&dkg_coordinator_2, random_oracle.clone())
                .await,
            Ok(DKGResult::SharesAlreadyConstructed)
        );

        assert_eq!(
            node_3
                .dkg_step(&dkg_coordinator_3, random_oracle.clone())
                .await,
            Ok(DKGResult::OutputConstructed)
        );
        assert_eq!(
            node_3
                .dkg_step(&dkg_coordinator_3, random_oracle.clone())
                .await,
            Ok(DKGResult::SharesAlreadyConstructed)
        );

        assert_eq!(node_1.get_weight().unwrap(), 4);
        assert_eq!(node_2.get_weight().unwrap(), 5);
        assert_eq!(node_3.get_weight().unwrap(), 7);
    }
}
