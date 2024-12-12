use std::collections::BTreeMap;

use crate::error::{DKGError, SigningError, VerificationError};
use crate::signing_coordinator::{SigningCoordinatorInterface, SigningPhase};
use fastcrypto::groups::secp256k1::ProjectivePoint as FastCryptoProjectivePoint;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::dkg::Output;
use fastcrypto_tbls::nodes::Nodes;
use frost_secp256k1::keys::{SigningShare, VerifyingShare};
use frost_secp256k1::round1::SigningNonces;
use frost_secp256k1::Identifier;
use k256::ecdsa::{signature::Signer, Signature, SigningKey as K256SigningKey};
use k256::elliptic_curve::group::GroupEncoding;
use k256::{AffinePoint, ProjectivePoint as SecpProjectivePoint};

use rand::thread_rng;

use frost_secp256k1::{self as frost, SigningPackage};

#[derive(Debug, PartialEq)]
pub enum SigningResult {
    CommitmentPosted,
    SessionNotFound,
    PartiallySignedSession,
}

#[derive(Debug, PartialEq)]
pub enum VerificationResult {
    VerifiedSignature,
    VerificationFailed,
}

#[derive(Debug)]
pub struct SigningPeer {
    secp256k1_sk: K256SigningKey,
    key_packages: Vec<frost::keys::KeyPackage>,
    pubkey_package: frost::keys::PublicKeyPackage,
    nonces_per_session: BTreeMap<String, BTreeMap<Identifier, SigningNonces>>,
    pub nodes: Nodes<FastCryptoProjectivePoint>,
}

impl SigningPeer {
    /// Creates a new signing peer from a DKG peer.
    pub fn new(
        secp256k1_sk: &K256SigningKey,
        dkg_output: &Output<FastCryptoProjectivePoint, FastCryptoProjectivePoint>,
    ) -> Result<SigningPeer, DKGError> {
        let mut key_packages = Vec::new();

        let verifying_key_element = SecpProjectivePoint::from(
            AffinePoint::from_bytes(&dkg_output.vss_pk.c0().to_byte_array().into()).unwrap(),
        );

        for share in dkg_output.shares.as_ref().unwrap().iter() {
            let share_index = share.index.get().try_into().unwrap();
            let signing_share = SigningShare::deserialize(&share.value.to_byte_array()).unwrap();

            let verifying_share_element =
                SecpProjectivePoint::from(secp256k1_sk.verifying_key().as_affine());

            let key_package = frost::keys::KeyPackage::new(
                share_index,
                signing_share,
                frost::keys::VerifyingShare::new(verifying_share_element.clone()),
                frost_secp256k1::VerifyingKey::new(verifying_key_element.clone()),
                (dkg_output.vss_pk.degree() + 1) as u16,
            );
            key_packages.push(key_package);
        }

        let mut verifying_shares: BTreeMap<Identifier, VerifyingShare> = BTreeMap::new();
        let mut share_index = 1 as u16;
        for node in dkg_output.nodes.iter() {
            let verifying_share_element: &SecpProjectivePoint =
                unsafe { &*(&node.pk as *const _ as *const SecpProjectivePoint) };

            for _ in 0..node.weight {
                verifying_shares.insert(
                    share_index.try_into().unwrap(),
                    frost::keys::VerifyingShare::new(verifying_share_element.clone()),
                );
                share_index += 1;
            }
        }

        Ok(SigningPeer {
            secp256k1_sk: secp256k1_sk.clone(),
            key_packages: key_packages.clone(),
            pubkey_package: frost::keys::PublicKeyPackage::new(
                verifying_shares,
                frost_secp256k1::VerifyingKey::new(verifying_key_element.clone()),
            ),
            nonces_per_session: BTreeMap::new(),
            nodes: dkg_output.nodes.clone(),
        })
    }

    pub async fn commit_to_signing_session<SC: SigningCoordinatorInterface>(
        &mut self,
        signing_coordinator: &SC,
        session_id: &String,
    ) -> Result<SigningResult, SigningError> {
        let session = signing_coordinator
            .fetch_session(session_id.clone())
            .await?;

        if session.phase != SigningPhase::Phase1 {
            log::info!("Signing session not in commit phase");
            return Err(SigningError::NotInCommitPhase);
        }

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for key_package in self.key_packages.iter() {
            let (nonces, commitments) =
                frost::round1::commit(&key_package.signing_share(), &mut thread_rng());
            nonces_map.insert(key_package.identifier().clone(), nonces);
            commitments_map.insert(key_package.identifier().clone(), commitments);
        }

        self.nonces_per_session
            .insert(session_id.clone(), nonces_map);

        signing_coordinator
            .post_commitments(session_id.clone(), commitments_map.clone())
            .await?;
        Ok(SigningResult::CommitmentPosted)
    }

    pub async fn partially_sign<SC: SigningCoordinatorInterface>(
        &self,
        signing_coordinator: &SC,
        session_id: &String,
    ) -> Result<SigningResult, SigningError> {
        let session = signing_coordinator
            .fetch_session(session_id.clone())
            .await?;

        if session.phase != SigningPhase::Phase2 {
            log::info!("Signing session not in signing phase");
            return Err(SigningError::NotInSigningPhase);
        }

        let signing_commitments = session.commitments.clone();
        let payload = session.payload.clone();

        let signing_package = SigningPackage::new(signing_commitments, payload.as_bytes());

        let mut signature_shares = BTreeMap::new();

        for key_package in self.key_packages.iter() {
            let nonces = &self.nonces_per_session[session_id][key_package.identifier()].clone();

            let signature_share =
                frost::round2::sign(&signing_package, nonces, key_package).unwrap();

            signature_shares.insert(*key_package.identifier(), signature_share);
        }

        let signature: Signature = self
            .secp256k1_sk
            .sign(&serde_json::to_string(&signature_shares).unwrap().as_bytes());

        signing_coordinator
            .post_signature_shares(
                session_id.clone(),
                signature_shares.clone(),
                signature,
                *self.secp256k1_sk.verifying_key(),
            )
            .await?;

        Ok(SigningResult::PartiallySignedSession)
    }

    pub async fn verify<SC: SigningCoordinatorInterface>(
        &mut self,
        signing_coordinator: &SC,
        session_id: &String,
    ) -> Result<VerificationResult, VerificationError> {
        let session = signing_coordinator.fetch_session(session_id.clone()).await;

        if session.is_err() {
            log::info!("Cannot find session {}", session_id);
            return Err(VerificationError::ErrorFetchingSession);
        }
        let session = session.unwrap();

        let signing_commitments = session.commitments.clone();
        let payload = session.payload.clone();

        let signing_package = SigningPackage::new(signing_commitments, payload.as_bytes());

        let signature_shares = session.signature_shares.clone();

        let aggregate_result =
            frost::aggregate(&signing_package, &signature_shares, &self.pubkey_package);
        if aggregate_result.is_err() {
            return Err(VerificationError::ErrorAggregatingSignatures {
                e: aggregate_result.err().unwrap().to_string(),
            });
        }
        let group_signature = aggregate_result.unwrap();

        let is_signature_valid = self
            .pubkey_package
            .verifying_key()
            .verify(payload.as_bytes(), &group_signature)
            .is_ok();

        if !is_signature_valid {
            log::info!("Aggregate signature is not valid");
            return Ok(VerificationResult::VerificationFailed);
        }
        log::info!("Aggregate signature is valid");
        Ok(VerificationResult::VerifiedSignature)
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use fastcrypto::groups::secp256k1::ProjectivePoint as FastcryptoProjectivePoint;
    use fastcrypto_tbls::{dkg::Output, nodes::Nodes};
    use frost_secp256k1::{round1::SigningCommitments, round2::SignatureShare, Identifier};
    use k256::ecdsa::SigningKey as K256SigningKey;

    use crate::{
        error::{SigningError, VerificationError},
        signing_coordinator::{SigningCoordinatorInterface, SigningPhase, SigningSession},
        signing_peer::{SigningPeer, VerificationResult},
    };

    pub struct TestSigningCoordinator {
        session: Arc<Mutex<Option<SigningSession>>>,
    }

    impl SigningCoordinatorInterface for TestSigningCoordinator {
        async fn create_session(
            &self,
            _nodes: Nodes<FastcryptoProjectivePoint>,
            _payload: Vec<u8>,
        ) -> Result<String, SigningError> {
            unimplemented!()
        }

        async fn fetch_session(&self, _id: String) -> Result<SigningSession, SigningError> {
            return Ok(self.session.lock().unwrap().clone().unwrap());
        }

        async fn post_signature_shares(
            &self,
            _session_id: String,
            signature_shares: BTreeMap<Identifier, SignatureShare>,
            _signature: k256::ecdsa::Signature,
            _pk: k256::ecdsa::VerifyingKey,
        ) -> Result<BTreeMap<Identifier, SignatureShare>, crate::error::SigningError> {
            let mut locked_session = self.session.lock().unwrap();
            let locked_session = locked_session.as_mut().unwrap();

            locked_session
                .signature_shares
                .extend(signature_shares.clone());
            Ok(signature_shares)
        }

        async fn post_commitments(
            &self,
            _session_id: String,
            commitments: BTreeMap<Identifier, SigningCommitments>,
        ) -> Result<(), SigningError> {
            let mut locked_session = self.session.lock().unwrap();
            let locked_session = locked_session.as_mut().unwrap();

            locked_session.commitments.extend(commitments);
            Ok(())
        }
    }

    fn get_dkg_output(
        group_id: u8,
        peer_id: u8,
    ) -> Output<FastcryptoProjectivePoint, FastcryptoProjectivePoint> {
        let file_path = format!(
            "testdata/dkg_output/group_{}/peer_{}.json",
            group_id, peer_id
        );
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        let output: Output<FastcryptoProjectivePoint, FastcryptoProjectivePoint> =
            serde_json::from_str(&file_content).expect("JSON was not well-formatted");
        output
    }

    fn get_private_key(peer_id: u8) -> K256SigningKey {
        let file_path = format!("testdata/peer_secp256k1_sk/peer_{}.json", peer_id);
        let file_content = std::fs::read_to_string(file_path).expect("Unable to read file");
        let secp256k1_bytes: [u8; 32] =
            serde_json::from_str(&file_content).expect("JSON was not well-formatted");
        let secp256k1_sk: K256SigningKey =
            K256SigningKey::from_bytes(&secp256k1_bytes.into()).unwrap();
        secp256k1_sk
    }

    #[tokio::test]
    async fn successful_signing() {
        // Initialization
        let secp256k1_sk_1 = get_private_key(1);
        let secp256k1_sk_2 = get_private_key(2);
        let secp256k1_sk_3 = get_private_key(3);
        let output_1 = get_dkg_output(1, 1);
        let output_2 = get_dkg_output(1, 2);
        let output_3 = get_dkg_output(1, 3);

        let mut signing_peer_1 = SigningPeer::new(&secp256k1_sk_1, &output_1).unwrap();
        let mut signing_peer_2 = SigningPeer::new(&secp256k1_sk_2, &output_2).unwrap();
        let mut signing_peer_3 = SigningPeer::new(&secp256k1_sk_3, &output_3).unwrap();

        let signing_session = Arc::new(Mutex::new(Some(SigningSession {
            session_id: "session1".to_string(),
            phase: SigningPhase::Phase1,
            commitments: BTreeMap::new(),
            payload: "message to sign".to_string(),
            signature_shares: BTreeMap::new(),
        })));

        let signing_coordinator_1 = TestSigningCoordinator {
            session: signing_session.clone(),
        };
        let signing_coordinator_2 = TestSigningCoordinator {
            session: signing_session.clone(),
        };
        let signing_coordinator_3 = TestSigningCoordinator {
            session: signing_session.clone(),
        };

        // Phase 1: Commit Phase
        signing_peer_1
            .commit_to_signing_session(&signing_coordinator_1, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_2
            .commit_to_signing_session(&signing_coordinator_2, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_3
            .commit_to_signing_session(&signing_coordinator_3, &"session1".to_string())
            .await
            .unwrap();

        // Coordinator determines that required commitments have been posted
        {
            let mut locked_session = signing_session.lock().unwrap();
            let locked_session = locked_session.as_mut().unwrap();

            locked_session.phase = SigningPhase::Phase2;
        }

        // Phase 2: Signing Phase
        signing_peer_1
            .partially_sign(&signing_coordinator_1, &"session1".to_string())
            .await
            .unwrap();
        assert_eq!(
            signing_peer_1
                .verify(&signing_coordinator_1, &"session1".to_string())
                .await,
            Err(VerificationError::ErrorAggregatingSignatures {
                e: "Unknown identifier.".to_string()
            })
        );
        signing_peer_2
            .partially_sign(&signing_coordinator_2, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_3
            .partially_sign(&signing_coordinator_3, &"session1".to_string())
            .await
            .unwrap();

        assert_eq!(
            signing_peer_1
                .verify(&signing_coordinator_1, &"session1".to_string())
                .await,
            Ok(VerificationResult::VerifiedSignature)
        );
    }

    #[tokio::test]
    async fn unsuccessful_signing() {
        // Initialization
        let secp256k1_sk_1 = get_private_key(1);
        let secp256k1_sk_2 = get_private_key(2);
        let secp256k1_sk_6 = get_private_key(6);
        let output_1 = get_dkg_output(1, 1);
        let output_2 = get_dkg_output(1, 2);
        // Peer 6 is part of the dkg group 2, not 1.
        let output_6 = get_dkg_output(2, 6);

        let mut signing_peer_1 = SigningPeer::new(&secp256k1_sk_1, &output_1).unwrap();
        let mut signing_peer_2 = SigningPeer::new(&secp256k1_sk_2, &output_2).unwrap();
        let mut signing_peer_6 = SigningPeer::new(&secp256k1_sk_6, &output_6).unwrap();

        let signing_session = Arc::new(Mutex::new(Some(SigningSession {
            session_id: "session1".to_string(),
            phase: SigningPhase::Phase1,
            commitments: BTreeMap::new(),
            payload: "message to sign".to_string(),
            signature_shares: BTreeMap::new(),
        })));

        let signing_coordinator_1 = TestSigningCoordinator {
            session: signing_session.clone(),
        };
        let signing_coordinator_2 = TestSigningCoordinator {
            session: signing_session.clone(),
        };
        let signing_coordinator_3 = TestSigningCoordinator {
            session: signing_session.clone(),
        };

        // Phase 1: Commit Phase
        signing_peer_1
            .commit_to_signing_session(&signing_coordinator_1, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_2
            .commit_to_signing_session(&signing_coordinator_2, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_6
            .commit_to_signing_session(&signing_coordinator_3, &"session1".to_string())
            .await
            .unwrap();

        // Coordinator determines that required commitments have been posted
        {
            let mut locked_session = signing_session.lock().unwrap();
            let locked_session = locked_session.as_mut().unwrap();

            locked_session.phase = SigningPhase::Phase2;
        }

        // Phase 2: Signing Phase
        signing_peer_1
            .partially_sign(&signing_coordinator_1, &"session1".to_string())
            .await
            .unwrap();
        assert_eq!(
            signing_peer_1
                .verify(&signing_coordinator_1, &"session1".to_string())
                .await,
            Err(VerificationError::ErrorAggregatingSignatures {
                e: "Unknown identifier.".to_string()
            })
        );
        signing_peer_2
            .partially_sign(&signing_coordinator_2, &"session1".to_string())
            .await
            .unwrap();
        signing_peer_6
            .partially_sign(&signing_coordinator_3, &"session1".to_string())
            .await
            .unwrap();

        assert_eq!(
            signing_peer_1
                .verify(&signing_coordinator_1, &"session1".to_string())
                .await,
            Err(VerificationError::ErrorAggregatingSignatures {
                e: "Invalid signature share.".to_string()
            })
        );
    }
}
