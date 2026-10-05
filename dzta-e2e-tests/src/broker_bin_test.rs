// use std::path::Path;
// use std::path::PathBuf;
// use std::process::Stdio;
// use std::time::Duration;
// use tokio::process::Command;
// use tokio::time::sleep;
//
// #[tokio::test]
// async fn test_binary_health_and_endpoints() {
//     let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
//     let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
//     let target_dir = workspace_root.join("target/release");
//     let broker_target_binary = target_dir.join("attestation-broker");
//     let broker_target_str = broker_target_binary.to_str().unwrap();
//     let test_port = "127.0.0.1:18443";
//
//     let vault_addr = std::env::var("DZTA_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
//     let vault_token = std::env::var("DZTA_VAULT_TOKEN").unwrap_or_else(|_| "root".to_string());
//     let transit_key = std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "key-v1".to_string());
//
//     let mut child = Command::new(broker_target_str)
//         .env("DZTA_SECRET_PROVIDER", "vault")
//         .env("VAULT_ADDR", &vault_addr)
//         .env("VAULT_TOKEN", &vault_token)
//         .env("DZTA_VAULT_TRANSIT_KEY", &transit_key)
//         .env(
//             "DZTA_MRENCLAVE",
//             "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
//         )
//         .env(
//             "DZTA_MRSIGNER",
//             "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
//         )
//         .env("DZTA_ATTESTATION_BIND", test_port)
//         .spawn()
//         .expect("Failed to spawn attestation-broker binary");
//
//     // Wait briefly for the server listener to open
//     sleep(Duration::from_millis(500)).await;
//
//     // Execute HTTP request against the live running binary
//     let client = reqwest::Client::new();
//     let response = client
//         .post(format!("http://{}/v1/datakey/provision", test_port))
//         .send()
//         .await;
//
//     // Clean up child process
//     child.kill().await.ok();
//
//     // Verify response was received from network service
//     assert!(response.is_ok());
// }


use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;
use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey};
use serde_json::json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use axum::{routing::get, Router, Json};
use std::net::SocketAddr;
use sha2::Digest;
/*
#[tokio::test]
async fn test_binary_health_and_endpoints() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let target_dir = workspace_root.join("target/release");
    let broker_target_binary = target_dir.join("attestation-broker");
    let broker_target_str = broker_target_binary.to_str().unwrap();
    let test_port = "127.0.0.1:18443";

    let vault_addr = std::env::var("DZTA_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let vault_token = std::env::var("DZTA_VAULT_TOKEN").unwrap_or_else(|_| "root".to_string());
    let transit_key = std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "key-v1".to_string());

    let mut child = Command::new(broker_target_str)
    .env("DZTA_SECRET_PROVIDER", "vault")
    .env("VAULT_ADDR", &vault_addr)
    .env("VAULT_TOKEN", &vault_token)
    .env("DZTA_VAULT_TRANSIT_KEY", &transit_key)
    .env("DZTA_MRENCLAVE", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    .env("DZTA_MRSIGNER", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
    .env("DZTA_ATTESTATION_BIND", test_port)
    .spawn()
    .expect("Failed to spawn attestation-broker binary");

    sleep(Duration::from_millis(500)).await;

    // Generate an RSA key to pass in the provisioning request
    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let enclave_pub_pem = enclave_priv_key
    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
    .expect("Failed to export enclave public key");

    let client = reqwest::Client::new();
    let response = client
    .post(format!("http://{}/v1/datakey/provision", test_port))
    .json(&json!({
        "enclave_public_key": enclave_pub_pem
    }))
    .send()
    .await;

    // Clean up child process
    child.kill().await.ok();

    let res = response.expect("Failed to communicate with HTTP server");
    let status = res.status();
    let body = res.text().await.unwrap_or_default();

    println!("Response Status: {}", status);
    println!("Response Body: {}", body);

    assert!(status.is_success(), "HTTP request failed with status: {status}");
}*/


#[tokio::test]
async fn test_binary_fails_on_invalid_mrenclave_config() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let broker_target_binary = workspace_root.join("target/release/attestation-broker");

    let mut child = Command::new(&broker_target_binary)
    .env("DZTA_SECRET_PROVIDER", "vault")
    .env("VAULT_ADDR", "http://127.0.0.1:8200")
    .env("VAULT_TOKEN", "root")
    .env("DZTA_VAULT_TRANSIT_KEY", "key-v1")
    // Pass invalid hex for MRENCLAVE (simulating corrupted/invalid measurement config)
    .env("DZTA_MRENCLAVE", "invalid_non_hex_measurement_string")
    .env("DZTA_MRSIGNER", "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
    .env("DZTA_ATTESTATION_BIND", "127.0.0.1:18444")
    .spawn()
    .expect("Failed to spawn process");

    // Give it a brief window to attempt startup and crash
    sleep(Duration::from_millis(300)).await;

    // Check that the process exited immediately with an error
    let exit_status = child.try_wait().expect("Failed to check child status");

    assert!(
        exit_status.is_some(),
            "Broker should have crashed and exited due to invalid MRENCLAVE configuration"
    );

    let status = exit_status.unwrap();
    assert!(!status.success(), "Broker exit status should indicate failure");
    println!(" Broker correctly refused to boot with invalid MRENCLAVE config!");
}

/*

// Simple mock PCCS server returning 200 OK empty/mock collateral JSON
async fn start_mock_pccs() -> SocketAddr {
    let app = Router::new()
    .route("/sgx/certification/v4/pckcrl", get(|| async { "[]" }))
    .route("/sgx/certification/v4/tcb", get(|| async { "{}" }))
    .route("/sgx/certification/v4/qe/identity", get(|| async { "{}" }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

pub fn create_mock_sgx_quote(mrenclave_hex: &str, mrsigner_hex: &str, report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = vec![0u8; 1020];

    // Quote Header
    quote[0..2].copy_from_slice(&3u16.to_le_bytes()); // Version 3
    quote[2..4].copy_from_slice(&2u16.to_le_bytes()); // Sign Type (ECDSA P-256)

    // ISV Enclave Report starts at offset 48
    let report_offset = 48;

    // MRENCLAVE (32 bytes at offset 48 + 64 = 112)
    let mrenclave_bytes = hex::decode(mrenclave_hex).expect("Invalid mrenclave hex");
    quote[report_offset + 64..report_offset + 96].copy_from_slice(&mrenclave_bytes);

    // MRSIGNER (32 bytes at offset 48 + 128 = 176)
    let mrsigner_bytes = hex::decode(mrsigner_hex).expect("Invalid mrsigner hex");
    quote[report_offset + 128..report_offset + 160].copy_from_slice(&mrsigner_bytes);

    // REPORT DATA (64 bytes at offset 48 + 320 = 368)
    quote[report_offset + 320..report_offset + 384].copy_from_slice(report_data);

    quote
}

#[tokio::test]
async fn test_broker_rejects_unauthorized_mrenclave_on_release() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new("."));
    let broker_target_binary = workspace_root.join("target/release/attestation-broker");

    // 1. Dynamic port selection & Mock PCCS
    let test_port_num = 18000 + (rand::random::<u16>() % 1000);
    let test_port = format!("127.0.0.1:{}", test_port_num);
    let mock_pccs_addr = start_mock_pccs().await;
    let pccs_url = format!("http://{}", mock_pccs_addr);

    // 2. Expected values configured in the Broker State
    let expected_mrenclave = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let expected_mrsigner = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    // Rogue MRENCLAVE that should trigger the security rejection
    let rogue_mrenclave = "bad000000000000000000000000000000000000000000000000000000000dead";

    let vault_addr = std::env::var("DZTA_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let vault_token = std::env::var("DZTA_VAULT_TOKEN").unwrap_or_else(|_| "root".to_string());
    let transit_key = std::env::var("DZTA_SECRET_RELEASE_KEY").unwrap_or_else(|_| "key-v1".to_string());

    // 3. Spawn broker process with DZTA_PCCS_URL (or PCCS_URL depending on your env config)
    let child = Command::new(&broker_target_binary)
    .env("DZTA_SECRET_PROVIDER", "vault")
    .env("VAULT_ADDR", &vault_addr)
    .env("VAULT_TOKEN", &vault_token)
    .env("DZTA_VAULT_TRANSIT_KEY", &transit_key)
    .env("DZTA_MRENCLAVE", expected_mrenclave)
    .env("DZTA_MRSIGNER", expected_mrsigner)
    .env("PCCS_URL", &pccs_url) // Pass local mock PCCS
    .env("DZTA_ATTESTATION_BIND", &test_port)
    .spawn()
    .expect("Failed to spawn attestation-broker binary");

    struct ChildGuard(tokio::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.start_kill();
        }
    }
    let _guard = ChildGuard(child);

    sleep(Duration::from_millis(500)).await;

    // 4. Generate Enclave Keys and compute matching report_data binding
    let mut rng = rand::thread_rng();
    let enclave_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let enclave_pub_pem = enclave_priv_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let clearance_level: u64 = 5;

    let mut binding = enclave_pub_pem.as_bytes().to_vec();
    binding.extend_from_slice(&clearance_level.to_be_bytes());
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"dZTA_SGX_SESSION_v1");
    hasher.update(&binding);
    let session_hash = hasher.finalize();

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&session_hash);

    // 5. Construct structurally valid SGX Quote using your helper
    let mock_quote_bytes = create_mock_sgx_quote(
        rogue_mrenclave,     // Rogue MRENCLAVE
        expected_mrsigner,   // Valid MRSIGNER
        &report_data,        // Valid session report data
    );
    let mock_quote_b64 = base64::engine::general_purpose::STANDARD.encode(mock_quote_bytes);

    // 6. Build request payload
    let rogue_release_payload = serde_json::json!({
        "quote": mock_quote_b64,
        "enclave_public_key": enclave_pub_pem,
        "credential_key_id": "key-v1",
        "required_clearance_level": clearance_level,
        "wallet_ciphertext": "vault:v1:mock_wallet_ciphertext",
        "seed_ciphertext": "vault:v1:mock_seed_ciphertext"
    });

    let client = reqwest::Client::new();
    let url = format!("http://{}/v1/datakey/release", test_port);

    let response = client
    .post(&url)
    .json(&rogue_release_payload)
    .send()
    .await
    .expect("Failed to send release request");

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    println!("Release Endpoint Response Status: {}", status);
    println!("Release Endpoint Response Body: {}", body);

    // 7. Verify HTTP 400 or 500 error response
    assert_ne!(status, reqwest::StatusCode::NOT_FOUND, "Endpoint returned 404!");
    assert!(
        status.is_client_error() || status.is_server_error(),
            "Broker MUST refuse key release for rogue MRENCLAVE! Got status: {}",
            status
    );

    println!("Zero-Trust Security Verification Passed: Broker rejected unauthorized MRENCLAVE!");
}*/
