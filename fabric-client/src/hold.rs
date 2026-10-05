use std::path::PathBuf;
use tokio::process::Command;

#[tokio::test]
async fn test_explicit_release_binary() {
    // Manually specify path to target/release/attestation-broker
    let mut bin_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin_path.push("target/release/attestation-broker");

    let mut child = Command::new(&bin_path)
    .env("DZTA_SECRET_PROVIDER", "https")
    .env("DZTA_KMS_ENDPOINT", "https://mock-kms.local")
    .env("DZTA_MRENCLAVE", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    .env("DZTA_MRSIGNER", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
    .env("DZTA_ATTESTATION_BIND", "127.0.0.1:0")
    .spawn()
    .expect("Failed to spawn release binary. Ensure 'cargo build --release --bin attestation-broker' was run.");

    // ... test logic ...

    child.kill().await.ok();
}


let vault_addr = std::env::var("DZTA_VAULT_ADDR")
.unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
let vault_token = std::env::var("DZTA_VAULT_TOKEN")
.unwrap_or_else(|_| "root".to_string());
let transit_key = std::env::var("DZTA_SECRET_RELEASE_KEY")
.unwrap_or_else(|_| "key-v1".to_string());

let mut child = Command::new(bin_path)
.env("DZTA_SECRET_PROVIDER", "vault")
.env("VAULT_ADDR", &vault_addr)
.env("VAULT_TOKEN", &vault_token)
.env("DZTA_VAULT_TRANSIT_KEY", &transit_key)
.env("DZTA_MRENCLAVE", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
.env("DZTA_MRSIGNER", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
.env("DZTA_ATTESTATION_BIND", "127.0.0.1:0")
.spawn()
.expect("Failed to spawn attestation-broker binary");

let rogue_release_payload = serde_json::json!({
    "credential_key_id": "test-credential-id-001",
    "quote": base64::engine::general_purpose::STANDARD.encode(vec![1, 2, 3, 4]),
                                              "report_data": base64::engine::general_purpose::STANDARD.encode(vec![5, 6, 7, 8]),
                                              "enclave_public_key": enclave_pub_pem,
                                              "mrenclave": "bad000000000000000000000000000000000000000000000000000000000dead",
                                              "mrsigner": expected_mrsigner,
                                              "wallet_ciphertext": "vault:v1:mock_wallet_ciphertext",
                                              "seed_ciphertext": "vault:v1:mock_seed_ciphertext"
});
