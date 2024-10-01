use blst::{
    min_sig::{PublicKey, Signature},
    BLST_ERROR,
};
use eyre::{eyre, Result};

use crate::bls::{Node, DST_G1};

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
        return Err(eyre!(format!(
            "Invalid signature: {:?}",
            verification_result
        )));
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
