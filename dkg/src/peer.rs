use crate::dkg_coordinator::{DKGPhase, DKGSession, DkgCoordinatorInterface, Message};
use crate::error::{DKGError, SigningError, VerificationError};
use crate::signing_coordinator::SigningCoordinatorInterface;
use fastcrypto::bls12381::min_sig::{BLS12381PrivateKey, BLS12381PublicKey};
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{Signer, ToFromBytes};
use fastcrypto_tbls::dkg::{Confirmation, Output, Party};
use fastcrypto_tbls::dkg_v0::UsedProcessedMessages;
use fastcrypto_tbls::ecies::{PrivateKey, PublicKey};
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::tbls::ThresholdBls;
use fastcrypto_tbls::types::{IndexedValue, ThresholdBls12381MinSig};
use rand::thread_rng;

#[derive(Debug, PartialEq)]
pub enum DKGResult {
    NoActiveSession,
    MessageAlreadyPosted,
    MessagePosted,
    ConfirmationAlreadyPosted,
    ConfirmationPosted,
    OutputAlreadyConstructed,
    OutputConstructed,
}

#[derive(Debug)]
pub enum SigningResult {
    SignedOutstandingSessions,
    SessionNotFound,
}

#[derive(Debug)]
pub enum VerificationResult {
    VerifiedSignature,
    VerificationFailed,
}

pub struct Peer {
    private_key: PrivateKey<G2Element>,
    pub public_key: PublicKey<G2Element>,
    dkg_output: Option<Output<G2Element, G2Element>>,
    dkg_session: Option<DKGSession>,
}

impl Peer {
    pub fn new(private_key: PrivateKey<G2Element>) -> Self {
        let public_key = PublicKey::<G2Element>::from_private_key(&private_key);

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

    fn get_dkg_party(&self, random_oracle: RandomOracle) -> Option<Party<G2Element, G2Element>> {
        if self.dkg_session.is_none() {
            return None;
        }

        Some(
            Party::<G2Element, G2Element>::new(
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
            BLS12381PrivateKey::from_bytes(&self.private_key.as_element().to_byte_array()).unwrap();
        let public_key = PublicKey::<G2Element>::from_private_key(&self.private_key);
        let pk = BLS12381PublicKey::from_bytes(&public_key.as_element().to_byte_array()).unwrap();
        let signature = sk.sign(&serde_json::to_string(&message).unwrap().as_bytes());

        dkg_coordinator
            .post_message(message.clone(), signature.sig, pk.pubkey)
            .await?;
        Ok(message)
    }

    fn dkg_confirmation_posted(&self) -> Option<Confirmation<G2Element>> {
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
        Confirmation<G2Element>,
        UsedProcessedMessages<G2Element, G2Element>,
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
    ) -> Result<Confirmation<G2Element>, DKGError> {
        let (confirmation, _) = self.create_dkg_confirmation(random_oracle).unwrap();

        // TODO: DRY
        let sk =
            BLS12381PrivateKey::from_bytes(&self.private_key.as_element().to_byte_array()).unwrap();
        let public_key = PublicKey::<G2Element>::from_private_key(&self.private_key);
        let pk = BLS12381PublicKey::from_bytes(&public_key.as_element().to_byte_array()).unwrap();
        let signature = sk.sign(&serde_json::to_string(&confirmation).unwrap().as_bytes());

        dkg_coordinator
            .post_confirmation(confirmation.clone(), signature.sig, pk.pubkey)
            .await?;
        Ok(confirmation)
    }

    async fn construct_dkg_output(
        &mut self,
        random_oracle: RandomOracle,
    ) -> Result<Output<G2Element, G2Element>, DKGError> {
        let dkg_party = self.get_dkg_party(random_oracle.clone()).unwrap();
        let (_, used_messages) = self.create_dkg_confirmation(random_oracle).unwrap();

        self.dkg_output = Some(
            dkg_party
                .complete(
                    &used_messages,
                    &self.dkg_session.as_ref().unwrap().confirmations,
                    &mut thread_rng(),
                )
                .unwrap(),
        );

        Ok(self.dkg_output.clone().unwrap())
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
                    self.construct_dkg_output(random_oracle).await?;
                    log::info!("DKG output constructed.");
                    return Ok(DKGResult::OutputConstructed);
                }

                log::info!("DKG output already constructed.");
                Ok(DKGResult::OutputAlreadyConstructed)
            }
        }
    }

    pub fn get_weight(&self) -> Result<u16, SigningError> {
        if self.dkg_output.is_none() {
            return Err(SigningError::DKGPending);
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

    pub fn partial_sign(
        &self,
        payload: &[u8],
    ) -> Result<Vec<IndexedValue<G1Element>>, SigningError> {
        if self.dkg_output.is_none() {
            return Err(SigningError::DKGPending);
        }

        Ok(ThresholdBls12381MinSig::partial_sign_batch(
            self.dkg_output
                .as_ref()
                .unwrap()
                .shares
                .as_ref()
                .unwrap()
                .iter(),
            payload,
        ))
    }

    // TODO: receive partial signatures and check if I have signed or not
    pub async fn sign<SC: SigningCoordinatorInterface<IndexedValue<G1Element>>>(
        &mut self,
        signing_coordinator: &SC,
        session_id: &String,
    ) -> Result<SigningResult, SigningError> {
        let session = signing_coordinator.fetch_session(session_id.clone()).await;
        if session.is_err() {
            log::info!("Cannot find session {}", session_id);
            return Err(SigningError::ErrorFetchingSession);
        }
        let session = session.unwrap();

        let payload_bytes = session.payload.as_slice();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
        log::info!("Signing '{}'", payload_str);
        let partial_signatures = self.partial_sign(&payload_bytes).unwrap();
        // TODO: DRY
        let sk =
            BLS12381PrivateKey::from_bytes(&self.private_key.as_element().to_byte_array()).unwrap();
        let public_key = PublicKey::<G2Element>::from_private_key(&self.private_key);
        let pk = BLS12381PublicKey::from_bytes(&public_key.as_element().to_byte_array()).unwrap();
        let signature = sk.sign(
            &serde_json::to_string(&partial_signatures)
                .unwrap()
                .as_bytes(),
        );

        signing_coordinator
            .post_partial_signatures(
                session.session_id.clone(),
                partial_signatures,
                signature.sig,
                pk.pubkey,
            )
            .await?;
        Ok(SigningResult::SignedOutstandingSessions)
    }

    pub async fn verify<SC: SigningCoordinatorInterface<IndexedValue<G1Element>>>(
        &mut self,
        random_oracle: RandomOracle,
        signing_coordinator: &SC,
        session_id: &String,
    ) -> Result<VerificationResult, VerificationError> {
        let session = signing_coordinator.fetch_session(session_id.clone()).await;
        if session.is_err() {
            log::info!("Cannot find session {}", session_id);
            return Err(VerificationError::ErrorFetchingSession);
        }
        let session = session.unwrap();
        let signatures = session.sigs.values().cloned().flatten().collect::<Vec<_>>();
        let dkg_party = self.get_dkg_party(random_oracle.clone());
        if dkg_party.is_none() || self.dkg_output.is_none() {
            return Err(VerificationError::DKGPending);
        }
        let dkg_party = dkg_party.unwrap();
        let dkg_output = self.dkg_output.clone().unwrap();

        let aggregated_signature =
            ThresholdBls12381MinSig::aggregate(dkg_party.t(), signatures.iter());
        if aggregated_signature.is_err() {
            log::error!("Failed to aggregate signatures for session {}", session_id);
            return Err(VerificationError::ErrorAggregatingSignatures {
                e: aggregated_signature.err().unwrap().to_string(),
            });
        }
        let aggregated_signature = aggregated_signature.unwrap();

        let verification_result = ThresholdBls12381MinSig::verify(
            dkg_output.vss_pk.c0(),
            session.payload.as_slice(),
            &aggregated_signature,
        );

        match verification_result {
            Ok(_) => Ok(VerificationResult::VerifiedSignature),
            Err(_) => Ok(VerificationResult::VerificationFailed),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use fastcrypto::groups::bls12381::G2Element;
    use fastcrypto_tbls::{
        ecies::{PrivateKey, PublicKey},
        nodes::{Node, Nodes},
        random_oracle::RandomOracle,
    };
    use rand::thread_rng;

    use crate::{
        dkg_coordinator::{Confirmation, DKGPhase, DKGSession, DkgCoordinatorInterface, Message},
        error::DKGError,
        peer::{DKGResult, Peer},
    };

    pub struct TestDkgCoordinator {
        session: Arc<Mutex<Option<DKGSession>>>,
    }

    impl DkgCoordinatorInterface for TestDkgCoordinator {
        async fn create_session(
            &self,
            threshold: u16,
            nodes: Vec<Node<G2Element>>,
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
            signature: blst::min_sig::Signature,
            pk: blst::min_sig::PublicKey,
        ) -> Result<Message, DKGError> {
            let mut session = self.session.lock().unwrap();
            let session = session.as_mut().unwrap();

            if session.phase > DKGPhase::Phase2 {
                return Err(DKGError::MessagePostingCompleted);
            }

            let is_duplicate = session.messages.iter().any(|m| m.sender == message.sender);
            if session.phase < DKGPhase::Phase2 && is_duplicate {
                return Err(DKGError::ErrorPostingMessage);
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
            signature: blst::min_sig::Signature,
            pk: blst::min_sig::PublicKey,
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
                return Err(DKGError::ErrorPostingConfirmation);
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

    pub fn create_test_key_pair() -> (PrivateKey<G2Element>, PublicKey<G2Element>) {
        let private_key: PrivateKey<G2Element> = PrivateKey::<G2Element>::new(&mut thread_rng());
        let public_key: PublicKey<G2Element> =
            PublicKey::<G2Element>::from_private_key(&private_key);

        (private_key, public_key)
    }

    pub fn create_nodes(nodes: Vec<(PublicKey<G2Element>, u16)>) -> Vec<Node<G2Element>> {
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

    #[tokio::test]
    async fn successful_dkg() {
        let (private_key_1, public_key_1) = create_test_key_pair();
        let (private_key_2, public_key_2) = create_test_key_pair();
        let (private_key_3, public_key_3) = create_test_key_pair();
        let mut node_1 = Peer::new(private_key_1);
        let mut node_2 = Peer::new(private_key_2);
        let mut node_3 = Peer::new(private_key_3);

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
            (public_key_1, 4 as u16),
            (public_key_2, 5 as u16),
            (public_key_3, 7 as u16),
        ]);
        assert!(dkg_coordinator_1
            .create_session(6 as u16, nodes)
            .await
            .is_ok());

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
            Ok(DKGResult::OutputAlreadyConstructed)
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
            Ok(DKGResult::OutputAlreadyConstructed)
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
            Ok(DKGResult::OutputAlreadyConstructed)
        );

        assert_eq!(node_1.get_weight().unwrap(), 4);
        assert_eq!(node_2.get_weight().unwrap(), 5);
        assert_eq!(node_3.get_weight().unwrap(), 7);
    }
}
