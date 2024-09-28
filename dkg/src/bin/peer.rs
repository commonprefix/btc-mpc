use clap::Parser;
use cosm_tome::modules::auth::model::Address;
use cosm_tome::signing_key::key::{Key, SigningKey};
use dkg::endpoints::CosmosEndpoint;
use dkg::peer::DKGResult;
use dkg::{dkg_coordinator, peer::Peer};
use fastcrypto::{
    encoding::{Encoding, Hex},
    groups::{bls12381::G2Element, GroupElement},
    serde_helpers::ToFromByteArray,
};
use fastcrypto_tbls::ecies::PrivateKey;
use fastcrypto_tbls::random_oracle::RandomOracle;
use log;
use serde_json::error::Error;
use std::path::PathBuf;
use std::result::Result;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The private key of the node
    #[arg(long, value_parser = parse_private_key)]
    private_key: [u8; 32],
    #[arg(long)]
    dkg_coordinator: Address,
    #[arg(long)]
    cosmos_config_path: PathBuf,
}

fn parse_private_key(pk: &str) -> Result<[u8; 32], Error> {
    let decoded = Hex::decode(pk).expect("Invalid private_key");
    let bytes: [u8; 32] = decoded.try_into().expect("Invalid private_key");

    Ok(bytes)
}

pub struct MyPrivateKey<G: GroupElement>(pub G::ScalarType);

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("Starting peer...");

    let args = Args::parse();

    let private_key: PrivateKey<G2Element> = PrivateKey::<G2Element>::from(
        <G2Element as GroupElement>::ScalarType::from_byte_array(&args.private_key)
            .expect("Invalid private_key"),
    );
    let mut peer = Peer::new(private_key);
    log::info!("Peer created with public key: {:?}", peer.public_key);

    let endpoint = CosmosEndpoint::new(args.cosmos_config_path.to_str().unwrap());
    let key = SigningKey {
        name: "wallet".to_string(),
        key: Key::Raw(args.private_key.to_vec()),
        derivation_path: "m/44'/118'/0'/0/0".to_string(),
    };

    let dkg_coordinator = dkg_coordinator::DkgCoordinator::new(endpoint, args.dkg_coordinator, key);
    let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?

    loop {
        match peer.dkg_step(&dkg_coordinator, random_oracle.clone()).await {
            Ok(DKGResult::OutputConstructed) => {
                log::info!("DKG completed");
                break;
            }
            _ => (),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    // TODO: Signing phase...
}
