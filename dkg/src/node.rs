use crate::dkg_coordinator::DkgCoordinatorInterface;
use crate::error::{Error, Result};
use fastcrypto::bls12381::min_sig::{BLS12381PrivateKey, BLS12381PublicKey};
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{Signer, ToFromBytes};
use fastcrypto_tbls::dkg::{Output, Party};
use fastcrypto_tbls::ecies::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::tbls::ThresholdBls;
use fastcrypto_tbls::types::{IndexedValue, ThresholdBls12381MinSig};
use rand::thread_rng;

struct Node {
    private_key: PrivateKey<G2Element>,
    pub public_key: PublicKey<G2Element>,
    dkg_party: Option<Party<G2Element, G2Element>>,
    dkg_nodes: Option<Nodes<G2Element>>,
    dkg_output: Option<Output<G2Element, G2Element>>,
    pub threshold: Option<u16>,
}

impl Node {
    pub fn new(private_key: PrivateKey<G2Element>) -> Self {
        let public_key = PublicKey::<G2Element>::from_private_key(&private_key);

        Self {
            private_key,
            public_key,
            dkg_party: None,
            dkg_nodes: None,
            dkg_output: None,
            threshold: None,
        }
    }

    pub async fn dkg<BB: DkgCoordinatorInterface>(
        &mut self,
        bulletin_board: &mut BB,
        random_oracle: RandomOracle,
    ) -> Result<()> {
        self.threshold = Some(bulletin_board.fetch_threshold().await?);
        if self.threshold.unwrap() < 2 {
            return Err(Error::InsufficientThreshold);
        }

        self.dkg_nodes = Some(bulletin_board.fetch_nodes().await?);

        self.dkg_party = Some(
            Party::<G2Element, G2Element>::new(
                self.private_key.clone(),
                self.dkg_nodes.clone().unwrap(),
                self.threshold.unwrap(),
                random_oracle.clone(),
                &mut thread_rng(),
            )
            .unwrap(),
        );

        let message = self
            .dkg_party
            .as_ref()
            .unwrap()
            .create_message(&mut thread_rng())
            .unwrap();

        let sk =
            BLS12381PrivateKey::from_bytes(&self.private_key.as_element().to_byte_array()).unwrap();
        let public_key = PublicKey::<G2Element>::from_private_key(&self.private_key);
        let pk = BLS12381PublicKey::from_bytes(&public_key.as_element().to_byte_array()).unwrap();
        let signature = sk.sign(&serde_json::to_string(&message).unwrap().as_bytes());

        bulletin_board
            .post_message(message.clone(), signature.sig, pk.pubkey)
            .await;

        let all_messages = bulletin_board.fetch_messages().await?;
        let processed_messages = &all_messages
            .iter()
            .map(|m| {
                self.dkg_party
                    .as_ref()
                    .unwrap()
                    .process_message(m.clone(), &mut thread_rng())
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let (confirmation, used_messages) = self
            .dkg_party
            .as_ref()
            .unwrap()
            .merge(processed_messages)
            .unwrap();
        let signature = sk.sign(&serde_json::to_string(&confirmation).unwrap().as_bytes());
        bulletin_board
            .post_confirmation(confirmation, signature.sig, pk.pubkey)
            .await;

        let all_confirmations = bulletin_board.fetch_confirmations().await?;

        self.dkg_output = Some(
            self.dkg_party
                .as_ref()
                .unwrap()
                .complete(&used_messages, &all_confirmations, &mut thread_rng())
                .unwrap(),
        );

        Ok(())
    }

    pub fn partial_sign(&mut self, message: &[u8]) -> Vec<IndexedValue<G1Element>> {
        self.dkg_output
            .as_ref()
            .unwrap()
            .shares
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| ThresholdBls12381MinSig::partial_sign(s, &message))
            .collect::<Vec<_>>()
    }

    pub fn verify(&mut self, signature: G1Element, message: &[u8]) -> Result<()> {
        match ThresholdBls12381MinSig::verify(
            self.dkg_output.as_ref().unwrap().vss_pk.c0(),
            &message,
            &signature,
        ) {
            Ok(_) => Ok(()),
            Err(_) => panic!("Signature verification failed"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bulletin_board::TestBulletinBoard;

    use super::*;

    fn create_test_key_pair() -> (PrivateKey<G2Element>, PublicKey<G2Element>) {
        let private_key: PrivateKey<G2Element> = PrivateKey::<G2Element>::new(&mut thread_rng());
        let public_key: PublicKey<G2Element> =
            PublicKey::<G2Element>::from_private_key(&private_key);

        (private_key, public_key)
    }

    #[tokio::test]
    async fn dkg() {
        let (private_key_1, public_key_1) = create_test_key_pair();
        let (_, public_key_2) = create_test_key_pair();
        let mut node = Node::new(private_key_1);

        let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?
        let mut bulletin_board = TestBulletinBoard::new(
            vec![(public_key_1, 4 as u16), (public_key_2, 2 as u16)],
            2 as u16,
        );
        assert!(node.dkg(&mut bulletin_board, random_oracle).await.is_ok());
    }

    #[tokio::test]
    async fn insufficient_threshold() {
        let (private_key_1, public_key_1) = create_test_key_pair();
        let (_, public_key_2) = create_test_key_pair();
        let mut node = Node::new(private_key_1);

        let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?
        let mut bulletin_board = TestBulletinBoard::new(
            vec![(public_key_1, 4 as u16), (public_key_2, 2 as u16)],
            1 as u16,
        );
        assert_eq!(
            node.dkg(&mut bulletin_board, random_oracle).await,
            Err(Error::InsufficientThreshold)
        );
    }

    #[tokio::test]
    async fn threshold_signing() {
        let (private_key_1, public_key_1) = create_test_key_pair();
        let (_, public_key_2) = create_test_key_pair();
        let mut node = Node::new(private_key_1);

        let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?
        let mut bulletin_board = TestBulletinBoard::new(
            vec![(public_key_1, 4 as u16), (public_key_2, 2 as u16)],
            2 as u16,
        );
        node.dkg(&mut bulletin_board, random_oracle).await.unwrap();

        // Use the shares to sign the message.
        const MSG: [u8; 4] = [1, 2, 3, 4];
        let partial_signatures = node.partial_sign(&MSG);

        let collective_signature =
            ThresholdBls12381MinSig::aggregate(node.threshold.unwrap(), partial_signatures.iter())
                .unwrap();

        assert!(node.verify(collective_signature, &MSG).is_ok());
    }
}
