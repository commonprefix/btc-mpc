use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::{
    ecies::PublicKey,
    nodes::{Node, Nodes},
};
use serde::{Deserialize, Serialize};

use crate::dkg_coordinator::DkgCoordinatorInterface;
use crate::error::Result;

type Confirmation = fastcrypto_tbls::dkg::Confirmation<G2Element>;
type Confirmations = Vec<Confirmation>;

type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;
type Messages = Vec<Message>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub threshold: u16,
    pub nodes: Nodes<G2Element>,
    pub messages: Vec<Message>,
    pub confirmations: Vec<Confirmation>,
}

pub struct TestBulletinBoard {
    messages: Option<Messages>,
    confirmations: Option<Confirmations>,
    nodes: Nodes<G2Element>,
    threshold: u16,
}

impl DkgCoordinatorInterface for TestBulletinBoard {
    async fn fetch_session(&self) -> Result<Session> {
        Ok(Session {
            threshold: self.threshold,
            nodes: self.nodes.clone(),
            messages: self.messages.clone().unwrap(),
            confirmations: self.confirmations.clone().unwrap(),
        })
    }

    async fn fetch_nodes(&self) -> Result<Nodes<G2Element>> {
        Ok(self.nodes.clone())
    }

    async fn fetch_threshold(&self) -> Result<u16> {
        Ok(self.threshold)
        // Err(Error::InsufficientThreshold)
    }

    async fn post_message(&mut self, message: Message) -> Result<()> {
        self.messages = Some(vec![message.clone()]);
        Ok(())
    }

    async fn fetch_messages(&self) -> Result<Messages> {
        Ok(self.messages.clone().unwrap())
    }

    async fn post_confirmation(&mut self, confirmation: Confirmation) -> Result<()> {
        self.confirmations = Some(vec![confirmation.clone()]);
        Ok(())
    }

    async fn fetch_confirmations(&self) -> Result<Confirmations> {
        Ok(self.confirmations.clone().unwrap())
    }
}

impl TestBulletinBoard {
    pub fn new(test_nodes: Vec<(PublicKey<G2Element>, u16)>, threshold: u16) -> Self {
        let nodes = &test_nodes
            .iter()
            .enumerate()
            .map(|(id, (public_key, weight))| Node::<G2Element> {
                id: id.try_into().unwrap(),
                pk: public_key.clone(),
                weight: weight.clone(),
            })
            .collect::<Vec<_>>();

        Self {
            messages: None,
            confirmations: None,
            nodes: Nodes::new(nodes.clone()).unwrap(),
            threshold,
        }
    }
}
