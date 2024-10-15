# btc-mpc

How to run a peer:
```
RUST_LOG=trace cargo run --bin peer -- --private-key {HEX_PRIVATE_KEY} --dkg-coordinator {DKG_COORDINATOR_CONTRACT} --cosmos-config-path {COSMOS_CONFIG_PATH}
```

How to run a peer that initializes the DKG session:
```
RUST_LOG=trace cargo run --bin peer -- --private-key {HEX_PRIVATE_KEY} --dkg-coordinator {DKG_COORDINATOR_CONTRACT} --cosmos-config-path {COSMOS_CONFIG_PATH} --init-session
```