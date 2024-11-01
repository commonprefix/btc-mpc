use clap::Parser;
use cosm_tome::modules::auth::model::Address;
use cosm_tome::signing_key::key::{Key, SigningKey};
use dkg::dkg_coordinator::DkgCoordinatorInterface;
use dkg::endpoints::CosmosEndpoint;
use dkg::peer::{DKGResult, SigningResult, VerificationResult};
use dkg::signing_coordinator::{self, SigningCoordinatorInterface};
use dkg::{dkg_coordinator, peer::Peer};
use fastcrypto::{
    encoding::{Encoding, Hex},
    groups::{secp256k1::ProjectivePoint, GroupElement},
    serde_helpers::ToFromByteArray,
};
use fastcrypto_tbls::ecies::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::{Node, Nodes};
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
    signing_coordinator: Address,
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

fn create_parties() -> Vec<Node<ProjectivePoint>> {
    // Private Keys:
    //      ada2ba5d35f55819093db528ef25470a21419adb010e63a92c99f4a07b898a4b
    //      8ca89e6c9589e18846d740b0115f5a7c954b0e3fa75c86f8f76a24e0786b7b1e
    //      863553c5aad53faa72d5f6855715b76c0056ac7e266e5cfee2cead7a98d7edc5
    //      2ade1e3c547c98075680cc2959f656699c3da1d7b8bef2ac6413fd961219bc98
    //      7f0b291c0db44983658c7bacb06753d24d374c33524dc0a3bfc4088b7a78736c
    let public_keys_hex = vec![
        "03be0482e96470dbfc781a24343be978e13d06ef9d2621324ceccf2e46daed4be3",
        "03d22cd806fd76a77f565fc76378dbe919c06cbf888e9408df69fe2b8e46b70d9b",
        "03c7b17b2c8df9c82b6f8d19e96ad4f879a6e53a9e3f2d86eec6c07a0006662bb0",
        "03d911b9a999b84f8ef0d4feb172045f44ecfe584b20c4ed89e5e003429b0f5e0c",
        "039b69c7d1b657b145592b4591e5f3fa77e299aadb38b2c93a25d6da062f5e764e",
    ];
    let mut public_keys = Vec::new();
    for hex in public_keys_hex {
        let decoded = Hex::decode(hex).expect("Invalid public_key_hex");
        let element = ProjectivePoint::from_byte_array(decoded.as_slice().try_into().unwrap())
            .expect("Invalid public_key_hex");
        let public_key = PublicKey::<ProjectivePoint>::from(element);
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

async fn create_dkg_session(
    dkg_coordinator: &dkg_coordinator::DkgCoordinator<CosmosEndpoint, Address>,
) {
    log::info!("Creating new DKG session");
    let threshold = 5;
    let nodes = create_parties();
    dkg_coordinator
        .create_session(threshold, nodes)
        .await
        .unwrap();
    log::info!("DKG session created.");
}

async fn join_dkg_session(
    peer: &mut Peer,
    dkg_coordinator: &dkg_coordinator::DkgCoordinator<CosmosEndpoint, Address>,
    random_oracle: &RandomOracle,
) {
    loop {
        match peer.dkg_step(dkg_coordinator, random_oracle.clone()).await {
            Ok(DKGResult::OutputConstructed) => {
                log::info!("DKG completed");
                break;
            }
            Err(e) => {
                log::error!("{}", e)
            }
            _ => (),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

async fn create_signing_session(
    signing_coordinator: &signing_coordinator::SigningCoordinator<CosmosEndpoint, Address>,
) {
    log::info!("Creating new Signing Session");
    println!("Enter the message to be signed:");
    let mut payload = String::new();
    std::io::stdin()
        .read_line(&mut payload)
        .expect("Failed to read line");
    let payload = payload.trim();

    let nodes = Nodes::new(create_parties()).unwrap();
    let session_id = signing_coordinator
        .create_session(nodes, payload.as_bytes().to_vec())
        .await
        .unwrap();
    log::info!("Created Signing Session with ID: {}", session_id);
}

async fn join_signing_session(
    peer: &mut Peer,
    signing_coordinator: &signing_coordinator::SigningCoordinator<CosmosEndpoint, Address>,
) {
    println!("Enter a session ID for signing:");
    let mut session_id = String::new();
    std::io::stdin()
        .read_line(&mut session_id)
        .expect("Failed to read line");
    session_id = session_id.trim().to_string();

    match peer.sign(signing_coordinator, &session_id).await {
        Ok(SigningResult::SignedOutstandingSessions) => {
            log::info!("Successfully signed for session {}.", session_id)
        }
        Ok(SigningResult::SessionNotFound) => {
            log::info!("Session {} not found.", session_id)
        }
        Err(e) => log::error!("Failed to sign the session: {}", e),
    }
}

async fn verify_signing_session(
    peer: &mut Peer,
    signing_coordinator: &signing_coordinator::SigningCoordinator<CosmosEndpoint, Address>,
    random_oracle: &RandomOracle,
) {
    println!("Enter a session ID to verify:");
    let mut session_id = String::new();
    std::io::stdin()
        .read_line(&mut session_id)
        .expect("Failed to read line");
    session_id = session_id.trim().to_string();

    match peer
        .verify(random_oracle.clone(), signing_coordinator, &session_id)
        .await
    {
        Ok(VerificationResult::VerifiedSignature) => {
            log::info!(
                "Successfully verified signatures for session {}.",
                session_id
            )
        }
        Ok(VerificationResult::VerificationFailed) => {
            log::info!("Failed to verify signatures for session {}.", session_id)
        }
        Err(e) => log::error!("Failed to verify signatures for session: {}", e),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!("Starting peer...");

    let args = Args::parse();

    let private_key: PrivateKey<ProjectivePoint> = PrivateKey::<ProjectivePoint>::from(
        <ProjectivePoint as GroupElement>::ScalarType::from_byte_array(&args.private_key)
            .expect("Invalid private_key"),
    );
    let mut peer = Peer::new(private_key);
    log::info!("Peer created with public key: {:?}", peer.public_key); // TODO: pretty print

    let endpoint = CosmosEndpoint::new(args.cosmos_config_path.to_str().unwrap());
    let key = SigningKey {
        name: "wallet".to_string(),
        key: Key::Mnemonic("curtain shy attitude prevent lava liar card right clarify among agent harbor grass syrup accident fabric present rice forget miss hotel diagram spring wrong".to_string()),
        derivation_path: "m/44'/118'/0'/0/0".to_string(),
    };

    let dkg_coordinator =
        dkg_coordinator::DkgCoordinator::new(endpoint.clone(), args.dkg_coordinator, key.clone());
    let signing_coordinator = signing_coordinator::SigningCoordinator::new(
        endpoint.clone(),
        args.signing_coordinator,
        key.clone(),
    );
    let random_oracle = RandomOracle::new("dkg"); // TODO: What should be the initial prefix?

    loop {
        println!("Make a wish (dkg:create-session | dkg:join-session | sign:create-session | sign:join-session | sign:verify-session):");
        let mut command = String::new();
        std::io::stdin()
            .read_line(&mut command)
            .expect("Failed to read line");
        let command = command.trim();
        log::info!("Granting wish..");
        match command {
            "dkg:create-session" => create_dkg_session(&dkg_coordinator).await,
            "dkg:join-session" => {
                join_dkg_session(&mut peer, &dkg_coordinator, &random_oracle).await
            }
            "sign:create-session" => create_signing_session(&signing_coordinator).await,
            "sign:join-session" => join_signing_session(&mut peer, &signing_coordinator).await,
            "sign:verify-session" => {
                verify_signing_session(&mut peer, &signing_coordinator, &random_oracle).await
            }
            _ => log::error!("Genie doesn't know what to do."),
        }
    }
}
