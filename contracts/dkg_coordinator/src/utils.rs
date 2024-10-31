use blst::{
    min_sig::{PublicKey, Signature},
    BLST_ERROR,
};
use eyre::{eyre, Result};

use crate::bls::{Confirmation, Message, Node, PartyId, DST_G1};
pub trait HasSender {
    fn get_sender(&self) -> &PartyId;
}

// Implement the trait for Message
impl HasSender for Message {
    fn get_sender(&self) -> &PartyId {
        &self.sender
    }
}

// Implement the trait for Confirmation
impl HasSender for Confirmation {
    fn get_sender(&self) -> &PartyId {
        &self.sender
    }
}

fn calculate_f(n: usize) -> usize {
    let mut f = (n - 1) / 3;
    let remainder = (n - 1) % 3;
    if remainder > 0 {
        f += 1;
    }
    f
}

pub fn required_messages(n: usize) -> usize {
    let f = calculate_f(n);
    f + 1
}

pub fn required_confirmations(n: usize) -> usize {
    let f = calculate_f(n);
    2 * f + 1
}

pub fn verify_signature(pk: &PublicKey, signature: &Signature, message: &[u8]) -> Result<()> {
    let verification_result = signature.verify(true, message, &DST_G1, &[], &pk, false);

    if verification_result != BLST_ERROR::BLST_SUCCESS {
        return Err(eyre!(format!("{:?}", verification_result)));
    }
    Ok(())
}

pub fn filter_known_pk(pk: &PublicKey, nodes: &Vec<Node>) -> Result<()> {
    for node in nodes {
        let candidate_pk = PublicKey::from_bytes(node.pk.bytes.as_slice()).unwrap();
        if candidate_pk == *pk {
            return Ok(());
        }
    }

    Err(eyre!("Unknown public key"))
}

pub fn calculate_total_weight<T: HasSender>(items: &[T], nodes: &[Node]) -> u64 {
    items
        .iter()
        .map(|item| {
            nodes
                .iter()
                .find(|node| node.id == *item.get_sender())
                .map(|node| node.weight as u64)
                .unwrap_or(0)
        })
        .sum()
}
