use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use fabric_client::{CredentialAttributes, CredentialManager, FabricClient, SchemaAttribute};
use dzta_gramine_prover::runner::ExecutionMode;
use dzta_gramine_prover::tee_runner::GramineExecutionProxy;
use shared::zkp_core::ProverOutputResponse;
use tokio::time::sleep;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing required SGX E2E environment variable {name}"))
}

fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    Path::new(&manifest_dir).parent().unwrap().to_path_buf()
}

fn start_broker(root: &Path) -> ChildGuard {
    let broker_binary = root.join("target/debug/attestation-broker");
    assert!(
        broker_binary.exists(),
        "attestation broker is missing at {}. Build it with `cargo build -p dzta-attestation-broker --bin attestation-broker`",
        broker_binary.display()
    );

    let child = Command::new(&broker_binary)
        .env("DZTA_ATTESTATION_BIND", "127.0.0.1:18443")
        .spawn()
        .expect("failed to start dZTA attestation broker");
    ChildGuard(child)
}

async fn create_live_credential() -> (Arc<CredentialManager>, String) {
    let config_path = required_env("DZTA_FABRIC_CONFIG");
    let fabric = FabricClient::new(
        &config_path,
        "dzta",
        "dztac",
        "Org1MSP",
        "org1-peer1",
    )
    .await
    .expect("failed to connect to Fabric");

    let db_path = workspace_root().join("target/debug/test_full_sgx_askar.db");
    let _ = fs::remove_file(&db_path);
    let manager = Arc::new(CredentialManager::new(fabric.clone(), db_path.to_str().unwrap()));
    manager
        .initialize_askar_store(&required_env("DZTA_WALLET_PASSPHRASE"))
        .await
        .expect("failed to initialize Askar wallet");

    let issuer = manager.fabric_client.generate_did();
    let subject = required_env("DZTA_TEST_SUBJECT_DID");
    let pubkey = "sgx-e2e-test-public-key";
    manager.fabric_client.register_did(&issuer, &issuer, pubkey).await.expect("failed to register issuer");
    manager.fabric_client.register_did(&subject, &issuer, pubkey).await.expect("failed to register subject");

    let schema_id = manager
        .register_schema(
            &issuer,
            "SecurityClearanceTemplate",
            "1.0.0",
            &[
                SchemaAttribute { name: "userRoleId".into(), attr_type: "string".into(), predicate: false },
                SchemaAttribute { name: "orgId".into(), attr_type: "string".into(), predicate: false },
                SchemaAttribute { name: "clearanceLevel".into(), attr_type: "integer".into(), predicate: true },
                SchemaAttribute { name: "timestamp".into(), attr_type: "timestamp".into(), predicate: false },
            ],
        )
        .await
        .expect("failed to register schema");

    let credential = manager
        .create_credential(
            &schema_id,
            &issuer,
            &subject,
            &CredentialAttributes {
                user_role_id: "systems-engineer".into(),
                org_id: "sgx-e2e".into(),
                clearance_level: 5,
                timestamp: chrono::Utc::now().timestamp(),
            },
            chrono::Utc::now().timestamp() + 3600,
        )
        .await
        .expect("failed to create credential");

    (manager, credential.credential_id)
}

#[tokio::test]
#[ignore = "requires SGX, PCCS, Fabric, broker, and Vault/KMS deployment"]
async fn test_full_sgx_e2e_pipeline() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert!(
        Path::new("/dev/attestation/attestation_type").exists(),
        "SGX attestation device is unavailable; refusing to run a direct-mode test"
    );
    assert_eq!(ExecutionMode::Auto.resolve(), "gramine-sgx");

    required_env("PCCS_URL");
    required_env("DZTA_MRENCLAVE");
    required_env("DZTA_MRSIGNER");
    required_env("DZTA_SECRET_PROVIDER");
    required_env("DZTA_FABRIC_CONFIG");
    required_env("DZTA_WALLET_PASSPHRASE");
    required_env("DZTA_TEST_SUBJECT_DID");

    let root = workspace_root();
    let _broker = start_broker(&root);
    sleep(Duration::from_millis(500)).await;
    std::env::set_var(
        "DZTA_ATTESTATION_BROKER_URL",
        "http://127.0.0.1:18443/v1/key-release",
    );

    let (manager, credential_id) = create_live_credential().await;
    let raw_ciphertext = manager
        .fetch_raw_encrypted_record(&credential_id)
        .await
        .expect("failed to fetch encrypted credential envelope");
    assert!(raw_ciphertext.starts_with(b"DZTA1"));

    let prover = root.join("target/release/dzta-gramine-prover");
    let manifest = root.join("target/release/dzta-gramine-prover.manifest");
    assert!(prover.exists(), "release prover is missing; build it first");
    assert!(manifest.exists(), "release Gramine manifest is missing");

    let proxy = GramineExecutionProxy::new(prover.to_str().unwrap(), ExecutionMode::Sgx);
    let response: ProverOutputResponse = proxy
        .prove_confidential_wallet_record_in_gramine(
            raw_ciphertext,
            Some(credential_id),
            3,
        )
        .expect("confidential SGX proving failed");

    assert!(!response.x_dzta_proof.is_empty());
    assert!(!response.x_dzta_public_inputs.is_empty());
    assert!(response.sgx_dcap_quote_hex.is_some());
}
