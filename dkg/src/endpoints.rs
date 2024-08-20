use std::fs;

use cosm_tome::clients::{client::CosmTome, cosmos_grpc::CosmosgRPC};
use cosm_tome::config::cfg::ChainConfig;

pub struct CosmosEndpoint {
    pub client: CosmTome<CosmosgRPC>,
}

impl CosmosEndpoint {
    pub fn new(config: &str) -> Self {
        let yaml_content = fs::read_to_string(config).unwrap();
        let config: ChainConfig = serde_yaml::from_str(&yaml_content).unwrap();
        let client = CosmTome::with_cosmos_grpc(config).unwrap();

        Self { client }
    }
}
