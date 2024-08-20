use fastcrypto::groups::bls12381::G2Element;
use fastcrypto_tbls::nodes::Nodes;
use serde_json::json;

type Confirmation = fastcrypto_tbls::dkg::Confirmation<G2Element>;
type Confirmations = Vec<Confirmation>;

type Message = fastcrypto_tbls::dkg_v0::Message<G2Element, G2Element>;
type Messages = Vec<Message>;

use crate::error::Result;
use crate::{bulletin_board::Session, endpoints::CosmosEndpoint};

pub trait DkgCoordinatorInterface {
    async fn fetch_session(&self) -> Result<Session>;

    async fn fetch_nodes(&self) -> Result<Nodes<G2Element>>;

    async fn fetch_threshold(&self) -> Result<u16>;

    async fn post_message(&mut self, message: Message) -> Result<()>;

    async fn fetch_messages(&self) -> Result<Messages>;

    async fn post_confirmation(&mut self, confirmation: Confirmation) -> Result<()>;

    async fn fetch_confirmations(&self) -> Result<Confirmations>;
}

pub struct DkgCoordinator<C> {
    pub endpoint: C,
}

impl DkgCoordinator<CosmosEndpoint> {
    pub fn new(endpoint: CosmosEndpoint) -> Self {
        DkgCoordinator { endpoint }
    }
}

impl DkgCoordinatorInterface for DkgCoordinator<CosmosEndpoint> {
    async fn fetch_session(&self) -> Result<Session> {
        let query_msg = json!({
            "Session": {}
        });
        let res = self
            .endpoint
            .client
            .wasm_query(
                "osmo1pczrfcdrwqlla5njcntj9tdygaq75grkp8xc8zwdr54wf060nuaqr9lcx0"
                    .parse()
                    .unwrap(),
                &query_msg,
            )
            .await
            .unwrap();
        Ok(res.res.data().unwrap())
    }

    async fn fetch_nodes(&self) -> Result<Nodes<G2Element>> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().nodes)
    }

    async fn fetch_threshold(&self) -> Result<u16> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().threshold)
    }

    async fn post_message(&mut self, message: Message) -> Result<()> {
        Ok(())
    }

    async fn fetch_messages(&self) -> Result<Messages> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().messages)
    }

    async fn post_confirmation(&mut self, confirmation: Confirmation) -> Result<()> {
        Ok(())
    }

    async fn fetch_confirmations(&self) -> Result<Confirmations> {
        let session = self.fetch_session().await;
        Ok(session.unwrap().confirmations)
    }
}

#[cfg(test)]
mod test {
    use crate::{dkg_coordinator::{DkgCoordinator, DkgCoordinatorInterface}, endpoints::CosmosEndpoint};

    #[tokio::test]
    async fn foobar() {
        let endpoint = CosmosEndpoint::new("./config/osmosis_testnet.yaml");
        let dkg_coordinator = DkgCoordinator::<CosmosEndpoint>::new(endpoint);
        let session = dkg_coordinator.fetch_session().await;
        println!("{:?}", session);
        assert!(false);
    }
}
