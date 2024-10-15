use clap::Parser;
use cosm_tome::modules::auth::model::Address;
use cosm_tome::signing_key::key::{Key, SigningKey};
use dkg::dkg_coordinator::DkgCoordinatorInterface;
use dkg::endpoints::CosmosEndpoint;
use dkg::peer::DKGResult;
use dkg::{dkg_coordinator, peer::Peer};
use fastcrypto::{
    encoding::{Encoding, Hex},
    groups::{bls12381::G2Element, GroupElement},
    serde_helpers::ToFromByteArray,
};
use fastcrypto_tbls::ecies::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::Node;
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
    /// Flag to initialize a new DKG session
    #[arg(long, action = clap::ArgAction::SetTrue)]
    init_session: bool,
}

fn parse_private_key(pk: &str) -> Result<[u8; 32], Error> {
    let decoded = Hex::decode(pk).expect("Invalid private_key");
    let bytes: [u8; 32] = decoded.try_into().expect("Invalid private_key");

    Ok(bytes)
}

fn create_parties() -> Vec<Node<G2Element>> {
    // Private Keys:
    //      25c33b7bf154cb1e5b55334ca693704c3b1bcbcfdb313502d145d6ebbe327171
    //      00aa92acd0ab7ea3e55a2366526b83c5584528fdb8e2e88a824f0133a3360e5f
    //      39213bd714d9420efeeff90d2fda1a87ebc428e5537387e79043f308f497ed50
    //      66a1a9411f6c7df69aec280260dfa4d7b983d6d806809826eb70251af54bb783
    //      0f5a6e50f44eefe9aee5b8516f2715f29112c74231f3f6d0738d06b48c353a22
    let public_keys_hex = vec![
        "a5a7070a8c12cecefea675e10ddadc921c4443afa8d9cdab95c2cb0d8707ca2c793995b392f3ecded68a895b13065ab7038ddc97989538bdb44129e6000a099bc85cb8236c0b7219f5ef0ec15f3758d84814a3d9521f60f9f80f29a7c9a345c6",
        "a569e75f1efd390764b4c825ceaf136cd96a0201a4b8fc6d32ca401cb1b5d47a492944441bebe748989704fc4561dda90c44f6e1a2e057c5c40f2e4af062df9e2d46a45db71eaac75b8df0f918a5c86ebd4ff97315dc59586b5b9976f7c7dcc2",
        "90270663e9ca11269f82877aff962ed727a3a546e1b1d36209e0af34253b56c016ee2cc9661b4e6f137d7dcc47a6023205821de80244621d6c8472d34e5df0861c9a6533b4b4bd46ab29a2961bfa42f0ba37d94cd110f75870ee336d33e23fe9",
        "b0e64d37fbfde8ba53930ceb5e4f1ca1fa4242c362407cc35f8639b2e9f615e585fb01f90993bc9b5ae204421e502df6153d5ddf16e4a49162bd8ee1e09ced42343c16c15c5e90aafc2dcb662407058f4de05763c2cd69a0ea599e5849c45965",
        "84e8f9742f79a299e396c031ccad282fc6f47824751cf3e21a1ae051f84d800c63d84b3b869518b22283a56174b36b5f119c1a1ab3bb41634e8b4cf7b8dc15bb4e93c79f1b466ee6d7b25c09475d59a5b82d466fbe2b9d77507595f2ba340052",
    ];
    let mut public_keys = Vec::new();
    for hex in public_keys_hex {
        let decoded = Hex::decode(hex).expect("Invalid public_key_hex");
        let element = G2Element::from_byte_array(decoded.as_slice().try_into().unwrap())
            .expect("Invalid public_key_hex");
        let public_key = PublicKey::<G2Element>::from(element);
        public_keys.push(public_key);
    }

    let mut nodes_vec = Vec::new();
    for i in 0..5 {
        nodes_vec.push(Node {
            id: i,
            pk: public_keys[i as usize].clone(),
            weight: i + 1,
        });
    }

    nodes_vec
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
        key: Key::Mnemonic("curtain shy attitude prevent lava liar card right clarify among agent harbor grass syrup accident fabric present rice forget miss hotel diagram spring wrong".to_string()),
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
            Err(e) => {
                log::error!("{}", e)
            }
            Ok(DKGResult::NoActiveSession) => {
                if args.init_session {
                    log::info!("Creating new DKG session");
                    let threshold = 3;
                    let nodes = create_parties();
                    dkg_coordinator
                        .create_session(threshold, nodes)
                        .await
                        .unwrap();
                }
            }
            _ => (),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    // TODO: Signing phase...
}
