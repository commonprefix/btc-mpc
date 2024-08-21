use clap::Parser;
use dkg::peer::Peer;
use env_logger::Env;
use fastcrypto::{
    encoding::{Encoding, Hex},
    groups::{bls12381::G2Element, GroupElement},
    serde_helpers::ToFromByteArray,
};
use fastcrypto_tbls::ecies::PrivateKey;
use log;
use serde_json::error::Error;
use std::result::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The private key of the node
    #[arg(long, value_parser = parse_private_key)]
    private_key: PrivateKey<G2Element>,
}

fn parse_private_key(pk: &str) -> Result<PrivateKey<G2Element>, Error> {
    let decoded = Hex::decode(pk).expect("Invalid private_key");
    let bytes: &[u8; 32] = &decoded.try_into().expect("Invalid private_key");
    let private_key: PrivateKey<G2Element> = PrivateKey::<G2Element>::from(
        <G2Element as GroupElement>::ScalarType::from_byte_array(bytes)
            .expect("Invalid private_key"),
    );

    Ok(private_key)
}

pub struct MyPrivateKey<G: GroupElement>(pub G::ScalarType);

fn main() {
    env_logger::init();
    log::info!("Starting peer...");

    let args = Args::parse();

    let private_key = args.private_key;
    let peer = Peer::new(private_key);
    log::info!("Peer created with public key: {:?}", peer.public_key);
}
