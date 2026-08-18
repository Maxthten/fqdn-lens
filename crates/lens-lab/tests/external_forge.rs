//! Opt-in black-box integration test. Start FQDN Forge separately with
//! `cargo run -p lab-cli -- serve --port 18080`, then set
//! `FQDN_FORGE_BASE_URL=http://127.0.0.1:18080` to run it. The test touches no
//! scenario/truth/fixture file and exercises only the public HTTP contract.

use lens_core::Store;
use lens_lab::{LabRunOptions, run};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn external_basic_certificate_contract() {
    let Ok(base_url) = std::env::var("FQDN_FORGE_BASE_URL") else {
        eprintln!("skipping: FQDN_FORGE_BASE_URL is not set");
        return;
    };
    let store = Store::open_in_memory().expect("store");
    let result = run(
        &store,
        LabRunOptions::new(base_url, "001-basic-certificate".to_owned(), Some(1)),
        CancellationToken::new(),
    )
    .await
    .expect("external FQDN Forge integration");
    assert_eq!(result.status, "succeeded");
}
